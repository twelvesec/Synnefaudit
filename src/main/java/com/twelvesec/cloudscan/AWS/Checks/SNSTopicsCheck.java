package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.sns.SnsAsyncClient;
import software.amazon.awssdk.services.sns.model.GetTopicAttributesRequest;
import software.amazon.awssdk.services.sns.model.GetTopicAttributesResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class SNSTopicsCheck implements CloudCheck {
    private List<String> allSNSArns;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final SnsAsyncClient sns;

    public SNSTopicsCheck(DataWriter writer, SharedDataProvider sharedDataProvider, SnsAsyncClient sns) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.sns = sns;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllSNSTopicArns()
            .thenCompose(snsArns -> {
                this.allSNSArns = snsArns;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::SNSTopicsEncryptedWithoutAWSKMS, AWSFinding.SNS_ENCRYPTION_WITHOUT_AWS_KMS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status SNSTopicsEncryptedWithoutAWSKMS() {
        if (allSNSArns.isEmpty()) {
            writer.addToBuffer(AWSFinding.SNS_ENCRYPTION_WITHOUT_AWS_KMS, 
                            Text.NO_SNS_TOPICS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allSNSArns.stream()
            .map(arn -> {
                Status s;
                ObjectNode r;
                try {
                    GetTopicAttributesResponse response = sns.getTopicAttributes(
                        GetTopicAttributesRequest.builder().topicArn(arn).build()
                    ).join();
                    Map<String, String> attributes = new HashMap<>(response.attributes());
                    if (attributes.containsKey("Policy")) {
                        JsonNode policyNode = MAPPER.readTree(attributes.get("Policy"));
                        attributes.put("Policy", MAPPER.writeValueAsString(policyNode));
                    }
                    String kmsKeyId = attributes.get("KmsMasterKeyId");
                    boolean violation = (kmsKeyId == null || kmsKeyId.isBlank());
                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder().attributes(attributes).build());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.SNS_ENCRYPTION_WITHOUT_AWS_KMS, result, status);
        return status;
    }
}
