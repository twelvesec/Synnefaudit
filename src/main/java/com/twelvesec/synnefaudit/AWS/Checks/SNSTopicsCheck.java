package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.sns.SnsAsyncClient;
import software.amazon.awssdk.services.sns.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.StreamSupport;

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
        CompletableFuture<List<String>> snsArns = sharedDataProvider.getAllSNSTopicArns()
                .exceptionally(ex -> null);

        return snsArns.thenCompose(arns -> {
            this.allSNSArns = arns;

            List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::SNSTopicsEncryptedWithoutAWSKMS, AWSFinding.SNS_ENCRYPTION_WITHOUT_AWS_KMS, this::reportError),
                    wrapCheck(this::checkSNSTopicsWithPublicPolicy,  AWSFinding.SNS_PUBLIC_TOPIC_POLICY, this::reportError),
                    wrapCheck(this::checkSNSSubscriptionsUsingHttp,  AWSFinding.SNS_HTTP_SUBSCRIPTIONS, this::reportError)
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

    private Status checkSNSTopicsWithPublicPolicy() {
        if (allSNSArns.isEmpty()) {
            writer.addToBuffer(AWSFinding.SNS_PUBLIC_TOPIC_POLICY, 
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
                    String policyJson = attributes.get("Policy");
                    
                    if (policyJson == null || policyJson.isBlank()) {
                        s = Status.PASS;
                        r = MAPPER.valueToTree(response.toBuilder().attributes(attributes).build());
                    } else {
                        JsonNode policyNode = MAPPER.readTree(policyJson);
                        attributes.put("Policy", MAPPER.writeValueAsString(policyNode));
                        
                        boolean isPublic = isPolicyPublic(policyNode);
                        s = isPublic ? Status.FAIL : Status.PASS;
                        r = MAPPER.valueToTree(response.toBuilder().attributes(attributes).build());
                    }
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
        writer.addToBuffer(AWSFinding.SNS_PUBLIC_TOPIC_POLICY, result, status);
        return status;
    }

    private boolean isPolicyPublic(JsonNode policyNode) {
        try {
            return StreamSupport.stream(policyNode.path("Statement").spliterator(), false)
                .filter(statement -> "Allow".equalsIgnoreCase(statement.path("Effect").asText()))
                .anyMatch(statement -> {
                    JsonNode principal = statement.path("Principal");
                    boolean isWildcardPrincipal = principal.isTextual() && "*".equals(principal.asText());
                    boolean isAWSWildcardPrincipal = principal.isObject() && "*".equals(principal.path("AWS").asText());
                    return isWildcardPrincipal || isAWSWildcardPrincipal;
                });
        } catch (Exception e) {
            return false;
        }
    }

    private Status checkSNSSubscriptionsUsingHttp() {
        if (allSNSArns.isEmpty()) {
            writer.addToBuffer(AWSFinding.SNS_HTTP_SUBSCRIPTIONS, 
                            Text.NO_SNS_TOPICS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allSNSArns.stream()
            .map(topicArn -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                ArrayNode httpSubscriptions = MAPPER.createArrayNode();
                
                try {
                    ListSubscriptionsByTopicResponse response = sns.listSubscriptionsByTopic(
                        ListSubscriptionsByTopicRequest.builder().topicArn(topicArn).build()
                    ).join();
                    
                    List<Subscription> httpSubs = response.subscriptions().stream()
                        .filter(sub -> "http".equalsIgnoreCase(sub.protocol()))
                        .toList();
                    
                    boolean hasHttpSubscriptions = !httpSubs.isEmpty();
                    s = hasHttpSubscriptions ? Status.FAIL : Status.PASS;
                    
                    GetTopicAttributesResponse attributesResponse = sns.getTopicAttributes(
                        GetTopicAttributesRequest.builder().topicArn(topicArn).build()
                    ).join();
                    
                    Map<String, String> attributes = new HashMap<>(attributesResponse.attributes());
                    if (attributes.containsKey("Policy")) {
                        JsonNode policyNode = MAPPER.readTree(attributes.get("Policy"));
                        attributes.put("Policy", MAPPER.writeValueAsString(policyNode));
                    }
                    
                    r.put("topicAttributes", MAPPER.valueToTree(attributes));
                    
                    httpSubs.forEach(sub -> {
                        ObjectNode subNode = MAPPER.createObjectNode();
                        subNode.put("subscriptionArn", sub.subscriptionArn());
                        subNode.put("endpoint", sub.endpoint());
                        subNode.put("protocol", sub.protocol());
                        httpSubscriptions.add(subNode);
                    });
                    
                    if (httpSubscriptions.isEmpty()) {
                        r.put("httpSubscriptions", Text.NO_HTTP_SUBSCRIPTIONS_FOUND.toString());
                    } else {
                        r.put("httpSubscriptions", httpSubscriptions);
                    }
                    
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(topicArn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.SNS_HTTP_SUBSCRIPTIONS, result, status);
        return status;
    }
}
