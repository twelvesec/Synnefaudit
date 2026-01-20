package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.cloudformation.CloudFormationAsyncClient;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksRequest;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksResponse;
import software.amazon.awssdk.services.cloudformation.model.Stack;
import software.amazon.awssdk.services.cloudformation.model.StackSummary;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class CloudFormationCheck implements CloudCheck {
    private List<StackSummary> allStacks;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final CloudFormationAsyncClient cloudformation;

    public CloudFormationCheck(DataWriter writer, SharedDataProvider sharedDataProvider, CloudFormationAsyncClient cloudformation) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.cloudformation = cloudformation;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllStacks()
            .thenCompose(stacks -> {
                this.allStacks = stacks;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkCloudFormationStacksWithoutTerminationProtection, AWSFinding.CLOUDFORMATION_STACKS_WITHOUT_TERMINATION_PROTECTION, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkCloudFormationStacksWithoutTerminationProtection() {
        if (allStacks.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDFORMATION_STACKS_WITHOUT_TERMINATION_PROTECTION,
                            Text.NO_CLOUDFORMATION_STACKS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allStacks.stream()
            .map(summary -> {
                String stackName = summary.stackName();
                Status s;
                ObjectNode r;
                
                try {
                    DescribeStacksResponse response = cloudformation.describeStacks(
                        DescribeStacksRequest.builder().stackName(stackName).build()
                    ).join();
                    
                    Stack stack = response.stacks().getFirst();
                    boolean protectionEnabled = stack.enableTerminationProtection() != null 
                                            && stack.enableTerminationProtection();
                    s = protectionEnabled ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(stack.toBuilder());
                    
                    if (r instanceof ObjectNode) {
                        r.put("terminationProtectionEnabled", protectionEnabled);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode()
                        .put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(stackName, inner);
            })
            .toList();

        Status status = result.isEmpty() ? Status.PASS : Status.FAIL;
        writer.addToBuffer(AWSFinding.CLOUDFORMATION_STACKS_WITHOUT_TERMINATION_PROTECTION, result, status);
        return status;
    }
}
