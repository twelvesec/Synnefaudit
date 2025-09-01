package com.twelvesec.cloudscan.AWS.Checks;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.GetKeyPolicyResponse;
import software.amazon.awssdk.services.kms.model.GetKeyRotationStatusRequest;
import software.amazon.awssdk.services.kms.model.GetKeyRotationStatusResponse;

public class KMSCheck implements CloudCheck {
    private List<String> keyIds;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final KmsAsyncClient kms;

    public KMSCheck(DataWriter writer, SharedDataProvider sharedDataProvider, KmsAsyncClient kms) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.kms = kms;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllKeyIds()
            .thenCompose(keyIds -> {
                this.keyIds = keyIds;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkKMSKeysNotRotated, AWSFinding.KMS_KEYS_NOT_ROTATED, this::reportError),
                    wrapCheck(this::checkExposedKmsKeys,    AWSFinding.PUBLICLY_EXPOSED_KMS_KEYS, this::reportError)
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
                    r.set(Text.AWSACCOUNTID.getText(), awsAccountId);
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
                    
                    resultNode.set(Text.POLICY.toString(), policyNode);
                    resultNode.set("keyDetails", keyNode);
                    
                    boolean isExposed = policyResponse.policy() != null 
                                    && policyResponse.policy().contains("\"Principal\":\"*\"");
                    status = isExposed ? Status.FAIL : Status.PASS;
                    
                } catch (Exception e) {
                    status = Status.FAIL_EXCEPTION;
                    resultNode.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), status.toString());
                inner.set(Text.RESULT.toString(), resultNode);
                return Map.<String, Object>of(keyId, inner);
            })
            .toList();
        
        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.PUBLICLY_EXPOSED_KMS_KEYS, result, status);
        return status;
    }
}
