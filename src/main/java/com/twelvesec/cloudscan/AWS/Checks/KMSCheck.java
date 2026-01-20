package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatch.model.*;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class KMSCheck implements CloudCheck {
    private List<String> keyIds;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final KmsAsyncClient kms;
    private final CloudWatchAsyncClient cloudWatch;

    public KMSCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    KmsAsyncClient kms, CloudWatchAsyncClient cloudWatch) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.kms = kms;
        this.cloudWatch = cloudWatch;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllKeyIds()
            .thenCompose(keyIds -> {
                this.keyIds = keyIds;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkKMSKeysNotRotated, AWSFinding.KMS_KEYS_NOT_ROTATED, this::reportError),
                    wrapCheck(this::checkExposedKmsKeys,    AWSFinding.PUBLICLY_EXPOSED_KMS_KEYS, this::reportError),
                    wrapCheck(this::checkUnusedCMKKmsKeys,  AWSFinding.KMS_UNUSED_CMK_KEYS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkKMSKeysNotRotated() {
        if (keyIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.KMS_KEYS_NOT_ROTATED, 
                            Text.NO_KMS_KEYS_FOUND_TO_INSPECT.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = keyIds.stream()
            .map(keyId -> {
                Status s;
                ObjectNode r;
                try {
                    GetKeyRotationStatusResponse kmsRotation = kms.getKeyRotationStatus(
                        GetKeyRotationStatusRequest.builder().keyId(keyId).build()
                    ).join();
                    s = !kmsRotation.keyRotationEnabled() ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(kmsRotation.toBuilder());

                    DescribeKeyResponse keyDescription = kms.describeKey(
                        DescribeKeyRequest.builder().keyId(keyId).build()
                    ).join();
                    ObjectNode awsAccountId = MAPPER.valueToTree(keyDescription.keyMetadata().awsAccountId());
                    r.put(Text.AWSACCOUNTID.getText(), awsAccountId);
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(keyId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KMS_KEYS_NOT_ROTATED, result, status);
        return status;
    }

    private Status checkExposedKmsKeys() {
        if (keyIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.PUBLICLY_EXPOSED_KMS_KEYS,
                            Text.NO_KMS_KEYS_FOUND_TO_INSPECT.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = keyIds.stream()
            .map(keyId -> {
                Status status;
                ObjectNode resultNode = MAPPER.createObjectNode();
                
                try {
                    GetKeyPolicyResponse policyResponse = kms.getKeyPolicy(b -> b.keyId(keyId)
                        .policyName("default")).join();                    
                    DescribeKeyResponse keyDesc = kms.describeKey(b -> b.keyId(keyId)).join();

                    ObjectNode policyNode = MAPPER.valueToTree(policyResponse.toBuilder());
                    ObjectNode keyNode = MAPPER.valueToTree(keyDesc.toBuilder());
                    
                    resultNode.put(Text.POLICY.toString(), policyNode);
                    resultNode.put("keyDetails", keyNode);
                    
                    boolean isExposed = policyResponse.policy() != null 
                                    && policyResponse.policy().contains("\"Principal\":\"*\"");
                    status = isExposed ? Status.FAIL : Status.PASS;
                    
                } catch (Exception e) {
                    status = Status.FAIL_EXCEPTION;
                    resultNode.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status.toString());
                inner.put(Text.RESULT.toString(), resultNode);
                return Map.<String, Object>of(keyId, inner);
            })
            .toList();
        
        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.PUBLICLY_EXPOSED_KMS_KEYS, result, status);
        return status;
    }

    private Status checkUnusedCMKKmsKeys() {
        if (keyIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.KMS_UNUSED_CMK_KEYS, 
                            Text.NO_KMS_KEYS_FOUND_TO_INSPECT.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(90, ChronoUnit.DAYS);
        
        List<Map<String, Object>> result = keyIds.stream()
            .map(keyId -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    DescribeKeyResponse keyResponse = kms.describeKey(
                        DescribeKeyRequest.builder().keyId(keyId).build()
                    ).join();
                    
                    KeyMetadata keyMetadata = keyResponse.keyMetadata();
                    r.put("keyMetadata", MAPPER.valueToTree(keyMetadata));
                    
                    if (!keyMetadata.keyState().equals(KeyState.ENABLED)) {
                        s = Status.NOT_APPLICABLE;
                    } else {
                        GetKeyRotationStatusResponse rotationResponse = kms.getKeyRotationStatus(
                            GetKeyRotationStatusRequest.builder().keyId(keyId).build()
                        ).join();
                        r.put("keyRotationEnabled", rotationResponse.keyRotationEnabled());
                        
                        long keyAgeDays = ChronoUnit.DAYS.between(keyMetadata.creationDate(), Instant.now());
                        r.put("keyAgeDays", keyAgeDays);
                        
                        try {
                            GetMetricDataResponse metricsResponse = cloudWatch.getMetricData(
                                GetMetricDataRequest.builder()
                                    .metricDataQueries(MetricDataQuery.builder()
                                        .id("keyUsage")
                                        .metricStat(MetricStat.builder()
                                            .metric(Metric.builder()
                                                .namespace("AWS/KMS")
                                                .metricName("KeyUsageCount")
                                                .dimensions(Dimension.builder()
                                                    .name("KeyId").value(keyId).build())
                                                .build())
                                            .period(86400).stat("Sum").build())
                                        .build())
                                    .startTime(cutoff).endTime(Instant.now()).build()
                            ).join();
                            
                            boolean hasRecentUsage = metricsResponse.metricDataResults().stream()
                                .anyMatch(metricResult -> metricResult.values().stream()
                                    .anyMatch(value -> value > 0));
                            
                            s = hasRecentUsage ? Status.PASS : Status.FAIL;
                            
                        } catch (Exception e) {
                            boolean isLikelyUnused = keyAgeDays > 90;
                            s = isLikelyUnused ? Status.FAIL : Status.PASS;
                            r.put(Text.ERROR.getText(), Text.EXCEPTION.toString().concat(e.getMessage()));
                        }
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), 
                        Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(keyId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KMS_UNUSED_CMK_KEYS, result, status);
        return status;
    }
}
