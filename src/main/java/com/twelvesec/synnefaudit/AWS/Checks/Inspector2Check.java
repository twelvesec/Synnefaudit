package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.inspector2.Inspector2AsyncClient;
import software.amazon.awssdk.services.inspector2.model.*;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Supplier;

public class Inspector2Check implements CloudCheck {
    private final DataWriter writer;
    private final Inspector2AsyncClient inspector2;
    private final StsAsyncClient sts;
    private boolean inspector2enabled;

    public Inspector2Check(DataWriter writer, Inspector2AsyncClient inspector2, StsAsyncClient sts) {
        this.writer = writer;
        this.inspector2 = inspector2;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        List<Supplier<CheckResult>> checksList = List.of(
            wrapCheck(this::checkInspector2Disabled,    AWSFinding.INSPECTOR2_NOT_ENABLED, this::reportError),
            wrapCheck(this::checkInspector2Findings,    AWSFinding.INSPECTOR2_FINDINGS_FOUND, this::reportError)
        );
        return runChecksInList(checksList, writer);
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkInspector2Disabled() { 
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
        BatchGetAccountStatusResponse response = inspector2.batchGetAccountStatus(
            BatchGetAccountStatusRequest.builder().accountIds(accountId).build()
        ).join();

        Optional<AccountState> accountOpt = response.accounts().stream().findFirst();
        if (accountOpt.isEmpty()) {
            writer.addToBuffer(AWSFinding.INSPECTOR2_NOT_ENABLED,
                            Text.NO_ACCOUNT_STATUS_FROM_INSPECTOR2, Status.FAIL_EXCEPTION);
            return Status.FAIL_EXCEPTION;
        }
        AccountState account = accountOpt.get();

        Map<String, Function<AccountState, Object>> extractors = Map.of(
            "ec2",        acc -> acc.resourceState().ec2(),
            "ecr",        acc -> acc.resourceState().ecr(),
            "lambda",     acc -> acc.resourceState().lambda(),
            "lambdaCode", acc -> acc.resourceState().lambdaCode(),
            "state",      acc -> acc.state()
        );

        List<Map<String,Object>> result = extractors.entrySet().stream()
            .map(entry -> {
                String key = entry.getKey();
                State state = (State) entry.getValue().apply(account);
                String stateStatus = state.status().toString();
                boolean violation = "DISABLED".equalsIgnoreCase(stateStatus);

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), stateStatus.isEmpty() ? Text.NO_STATUS_FOUND.toString() : stateStatus);
                return Map.<String, Object>of(key, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        
        ObjectNode resultNode = MAPPER.createObjectNode();
        ObjectNode resourceStateNode = resultNode.putObject("resourceState");
        resourceStateNode.putObject("ec2").put("status", account.resourceState().ec2().status().toString());
        resourceStateNode.putObject("ecr").put("status", account.resourceState().ecr().status().toString());
        resourceStateNode.putObject("lambda").put("status", account.resourceState().lambda().status().toString());
        resourceStateNode.putObject("lambdaCode").put("status", account.resourceState().lambdaCode().status().toString());
        resultNode.putObject("state").put("status", account.state().status().toString());

        inspector2enabled = !status.equals(Status.PASS);
        writer.addToBuffer(AWSFinding.INSPECTOR2_NOT_ENABLED, resultNode, status);
        return status;
    }

    private Status checkInspector2Findings() {
        if (!inspector2enabled) {
            writer.addToBuffer(AWSFinding.INSPECTOR2_FINDINGS_FOUND, 
                            Text.INSPECTOR2_NOT_ENABLED.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        ListFindingsResponse findResponse = inspector2.listFindings(
            ListFindingsRequest.builder().maxResults(100).build()
        ).join();
        List<Finding> findings = findResponse.findings();

        if (findings.isEmpty()) {
            writer.addToBuffer(AWSFinding.INSPECTOR2_FINDINGS_FOUND,
                        Text.INPSECTOR2_NO_FINDINGS.toString(), Status.PASS);
            return Status.PASS;
        }

        List<Map<String,Object>> result = findings.stream()
            .map(finding -> {
                String arn = finding.findingArn();
                ObjectNode r = MAPPER.valueToTree(finding.toBuilder());

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), Status.FAIL.toString());
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
                })
            .toList();

        Status status = Status.FAIL;
        writer.addToBuffer(AWSFinding.INSPECTOR2_FINDINGS_FOUND, result, status);
        return status;
    }
}
