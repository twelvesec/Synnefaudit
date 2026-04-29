package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSDependencyFactory;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.s3control.S3ControlAsyncClient;
import software.amazon.awssdk.services.s3control.model.GetPublicAccessBlockRequest;
import software.amazon.awssdk.services.s3control.model.GetPublicAccessBlockResponse;
import software.amazon.awssdk.services.s3control.model.PublicAccessBlockConfiguration;
import software.amazon.awssdk.services.s3control.model.S3ControlException;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class S3BucketsCheck implements CloudCheck {
    private List<String> allS3BucketNames;
    private final DataWriter writer;
    private final AWSDependencyFactory awsDependencyFactory;
    private final SharedDataProvider sharedDataProvider;
    private final S3AsyncClient s3;
    private final S3ControlAsyncClient s3control;
    private final StsAsyncClient sts;
    
    public S3BucketsCheck(DataWriter writer, AWSDependencyFactory awsDependencyFactory, SharedDataProvider sharedDataProvider, 
                        S3AsyncClient s3, S3ControlAsyncClient s3control, StsAsyncClient sts) {
        this.writer = writer;
        this.awsDependencyFactory = awsDependencyFactory;
        this.sharedDataProvider = sharedDataProvider;
        this.s3 = s3;
        this.s3control = s3control;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllS3BucketNames()
            .thenCompose(s3Buckets -> {
                this.allS3BucketNames = s3Buckets;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::S3BucketsWithMFADeleteDisabled,             AWSFinding.S3_BUCKETS_MFA_DELETE_DISABLED, this::reportError),
                    wrapCheck(this::S3BucketsEncryptedWithoutSSEKMS,            AWSFinding.S3_BUCKETS_ENCRYPTED_WITHOUT_SSE_KMS, this::reportError),
                    wrapCheck(this::S3BucketsWithNoSecureTransportPolicySet,    AWSFinding.S3_BUCKETS_WITH_NO_SECURE_TRANSPORT_POLICY_SET, this::reportError),
                    wrapCheck(this::S3BucketsWithObjectLockDisabled,            AWSFinding.S3_BUCKETS_WITH_OBJECT_LOCK_DISABLED, this::reportError),
                    wrapCheck(this::S3BucketsWithBucketVersioningDisabled,      AWSFinding.S3_BUCKETS_WITH_BUCKET_VERSIONING_DISABLED, this::reportError),
                    wrapCheck(this::S3BucketsWithServerAccessLoggingDisabled,   AWSFinding.S3_BUCKETS_WITH_SERVER_ACCESS_LOGGING_DISABLED, this::reportError),
                    wrapCheck(this::S3BucketsWithACLsEnabled,                   AWSFinding.S3_BUCKETS_WITH_ACL_ENABLED, this::reportError),
                    wrapCheck(this::BlockPublicAccessForS3NotEnabled,           AWSFinding.BLOCK_PUBLIC_ACCESS_S3_DISABLED, this::reportError),
                    wrapCheck(this::S3BucketsWithDefaultEncryptionDisabled,     AWSFinding.S3_BUCKETS_WITH_DEFAULT_ENCRYPTION_DISABLED, this::reportError),
                    wrapCheck(this::S3BucketsWithWriteAccessAllowed,            AWSFinding.S3_BUCKETS_WITH_WRITE_ACCESS_ALLOWED, this::reportError),
                    wrapCheck(this::checkS3AccountLevelPublicAccessBlock,       AWSFinding.S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCK, this::reportError),
                    wrapCheck(this::S3BucketsListableByPublic,                  AWSFinding.S3_BUCKETS_LISTABLE_BY_PUBLIC, this::reportError),
                    wrapCheck(this::S3BucketsOpenToPublic,                      AWSFinding.S3_BUCKETS_OPEN_TO_PUBLIC, this::reportError),
                    wrapCheck(this::S3BucketsWritableByPublic,                  AWSFinding.S3_BUCKETS_WRITABLE_BY_PUBLIC, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private S3AsyncClient getCorrectRegionClient(String bucket) {
        return awsDependencyFactory.getCorrectRegionClient(bucket, s3);
    }

    private Status S3BucketsWithMFADeleteDisabled() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_MFA_DELETE_DISABLED,
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);

                    GetBucketVersioningResponse versioningResp = regionalS3.getBucketVersioning(
                            GetBucketVersioningRequest.builder().bucket(bucket).build()
                    ).join();

                    s = "Enabled".equalsIgnoreCase(versioningResp.mfaDeleteAsString()) ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(versioningResp.toBuilder());
                    regionalS3.close();
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_MFA_DELETE_DISABLED, result, status);
        return status;
    }

    private Status S3BucketsEncryptedWithoutSSEKMS() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_ENCRYPTED_WITHOUT_SSE_KMS, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);

                    GetBucketEncryptionResponse response = regionalS3.getBucketEncryption(
                            GetBucketEncryptionRequest.builder().bucket(bucket).build()).join();
                    boolean usesSSEKMS = response.serverSideEncryptionConfiguration().rules().stream()
                            .anyMatch(rule -> "aws:kms".equalsIgnoreCase(
                                    rule.applyServerSideEncryptionByDefault().sseAlgorithmAsString()
                            ));

                    s = usesSSEKMS ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (S3Exception e) {
                    if ("ServerSideEncryptionConfigurationNotFoundError".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.FAIL;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                        Text.NO_ENCRYPTION_CONFIGURATION_FOUND.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_ENCRYPTED_WITHOUT_SSE_KMS, result, status);
        return status;
    }

    private Status S3BucketsWithNoSecureTransportPolicySet() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_NO_SECURE_TRANSPORT_POLICY_SET, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                JsonNode policyNode;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketPolicyResponse response = regionalS3.getBucketPolicy(
                        GetBucketPolicyRequest.builder().bucket(bucket).build()
                    ).join();
                    String policyText = response.policy();
                    policyNode = MAPPER.readTree(policyText);

                    boolean enforced = StreamSupport.stream(
                            policyNode.get("Statement").spliterator(), false
                        )
                        .anyMatch(stmt -> {
                            boolean isDeny = "Deny".equalsIgnoreCase(((JsonNode) stmt).path("Effect").asText());
                        JsonNode cond = stmt.path("Condition").path("Bool")
                                            .path("aws:SecureTransport");
                        return isDeny && cond.asText().equalsIgnoreCase("false");
                        });
                    s = enforced ? Status.PASS : Status.FAIL;
                } catch (S3Exception e) {
                    s = Status.FAIL;
                    policyNode = MAPPER.createObjectNode()
                        .put(Text.ERROR.toString(), String.format("%s : %s", Text.NO_BUCKET_POLICY_FOUND.toString(), e.getMessage()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    policyNode = MAPPER.createObjectNode()
                        .put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), policyNode);

                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_NO_SECURE_TRANSPORT_POLICY_SET, result, status);
        return status;
    }

    private Status S3BucketsWithObjectLockDisabled() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_OBJECT_LOCK_DISABLED, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                JsonNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetObjectLockConfigurationResponse response = regionalS3.getObjectLockConfiguration(
                        GetObjectLockConfigurationRequest.builder().bucket(bucket).build()
                    ).join();
                    boolean isEnabled = response.objectLockConfiguration() != null &&
                                        "Enabled".equalsIgnoreCase(response.objectLockConfiguration().objectLockEnabledAsString());
                    s = isEnabled ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (S3Exception e) {
                    if ("ObjectLockConfigurationNotFoundError".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.FAIL;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                        Text.NO_OBJECT_LOCK_CONFIGURATION_FOUND.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_OBJECT_LOCK_DISABLED, result, status);
        return status;
    }

    private Status S3BucketsWithBucketVersioningDisabled() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_BUCKET_VERSIONING_DISABLED, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketVersioningResponse response = regionalS3.getBucketVersioning(
                        GetBucketVersioningRequest.builder().bucket(bucket).build()
                    ).join();
                    boolean isEnabled = "Enabled".equalsIgnoreCase(response.statusAsString());
                    s = isEnabled ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_BUCKET_VERSIONING_DISABLED, result, status);
        return status;
    }

    private Status S3BucketsWithServerAccessLoggingDisabled() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_SERVER_ACCESS_LOGGING_DISABLED,
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketLoggingResponse response = regionalS3.getBucketLogging(
                        GetBucketLoggingRequest.builder().bucket(bucket).build()
                    ).join();
                    boolean isEnabled = response.loggingEnabled() != null;
                    s = isEnabled ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_SERVER_ACCESS_LOGGING_DISABLED, result, status);
        return status;
    }

    private Status S3BucketsWithACLsEnabled() { 
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_ACL_ENABLED, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketAclResponse response = regionalS3.getBucketAcl(
                        GetBucketAclRequest.builder()
                            .bucket(bucket)
                            .build()
                    ).join();
                    boolean onlyOwner = response.grants().stream()
                        .allMatch(grant -> "CanonicalUser".equalsIgnoreCase(grant.grantee().typeAsString())
                    );

                    s = onlyOwner ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (S3Exception e) {
                    if ("AccessControlListNotSupported".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.PASS;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                        Text.ACLS_DISABLED.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_ACL_ENABLED, result, status);
        return status;
    }

    private Status BlockPublicAccessForS3NotEnabled() {
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
        Status status;
        ObjectNode result;
        try {
            GetPublicAccessBlockResponse response = s3control.getPublicAccessBlock(
                GetPublicAccessBlockRequest.builder().accountId(accountId).build()
            ).join();
            PublicAccessBlockConfiguration cfg = response.publicAccessBlockConfiguration();
            boolean allBlocked = cfg.blockPublicAcls()
                            && cfg.ignorePublicAcls()
                            && cfg.blockPublicPolicy()
                            && cfg.restrictPublicBuckets();

            status = allBlocked ? Status.PASS : Status.FAIL;
            result = MAPPER.valueToTree(cfg.toBuilder());
        } catch (S3ControlException e) {
            if ("NoSuchPublicAccessBlockConfiguration".equals(e.awsErrorDetails().errorCode())) {
                status = Status.FAIL;
                result = MAPPER.createObjectNode()
                        .put(Text.ERROR.toString(), Text.NO_PUBLIC_ACCESS_BLOCK_CONFIGURATION_FOUND.toString().concat(e.getMessage()));
            } else {
                status = Status.FAIL_EXCEPTION;
                result = MAPPER.createObjectNode()
                        .put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
            }
        }

        writer.addToBuffer(AWSFinding.BLOCK_PUBLIC_ACCESS_S3_DISABLED, result, status);
        return status;
    }

    private Status S3BucketsWithDefaultEncryptionDisabled() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_DEFAULT_ENCRYPTION_DISABLED, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    
                    boolean hasDirectEncryption = false;
                    try {
                        GetBucketEncryptionResponse encryptionResponse = regionalS3.getBucketEncryption(
                            GetBucketEncryptionRequest.builder().bucket(bucket).build()).join();
                        hasDirectEncryption = !encryptionResponse.serverSideEncryptionConfiguration().rules().isEmpty();
                        r = MAPPER.valueToTree(encryptionResponse.toBuilder());
                    } catch (S3Exception e) {
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                            Text.NO_ENCRYPTION_CONFIGURATION_FOUND.toString().concat(e.getMessage()));
                    }
                    
                    boolean hasPolicyEnforcement = false;
                    try {
                        GetBucketPolicyResponse policyResponse = regionalS3.getBucketPolicy(
                            GetBucketPolicyRequest.builder().bucket(bucket).build()).join();
                        String policyText = policyResponse.policy();
                        JsonNode policyNode = MAPPER.readTree(policyText);
                        
                        hasPolicyEnforcement = StreamSupport.stream(policyNode.get("Statement").spliterator(), false)
                            .anyMatch(stmt -> {
                                boolean isDeny = "Deny".equalsIgnoreCase(((JsonNode) stmt).path("Effect").asText());
                                JsonNode condition = stmt.path("Condition");
                                
                                boolean requiresEncryption = 
                                    condition.path("Null").path("s3:x-amz-server-side-encryption").asText().equalsIgnoreCase("false") 
                                    || condition.path("StringNotEquals").path("s3:x-amz-server-side-encryption").asText() != null;
                                
                                return isDeny && requiresEncryption;
                            });
                        
                        if (r == null) {
                            r = MAPPER.createObjectNode();
                        }
                        r.put("Policy", MAPPER.readTree(policyText));
                    } catch (S3Exception e) {
                        if (r == null) {
                            r = MAPPER.createObjectNode();
                        }
                        r.put(Text.EXCEPTION.toString(), 
                            Text.NO_BUCKET_POLICY_FOUND.toString().concat(e.getMessage()));
                    }
                    s = (hasDirectEncryption || hasPolicyEnforcement) ? Status.PASS : Status.FAIL;
                    
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                            Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_DEFAULT_ENCRYPTION_DISABLED, result, status);
        return status;
    }

    private Status S3BucketsWithWriteAccessAllowed() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_WRITE_ACCESS_ALLOWED, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketPolicyResponse response = regionalS3.getBucketPolicy(
                        GetBucketPolicyRequest.builder().bucket(bucket).build()
                    ).join();
                    
                    String policyText = response.policy();
                    JsonNode policyNode = MAPPER.readTree(policyText);
                    
                    boolean allowsWriteAccess = StreamSupport.stream(
                        policyNode.path("Statement").spliterator(), false)
                        .anyMatch(stmt -> {
                            String effect = stmt.path("Effect").asText("");
                            String action = stmt.path("Action").asText("");
                            JsonNode actions = stmt.path("Action");
                            
                            boolean hasWriteAction;
                            if (actions.isArray()) {
                                hasWriteAction = StreamSupport.stream(actions.spliterator(), false)
                                    .anyMatch(a -> isWriteAction(a.asText("")));
                            } else {
                                hasWriteAction = isWriteAction(action);
                            }
                            
                            return "Allow".equalsIgnoreCase(effect) && hasWriteAction;
                        });
                    
                    s = allowsWriteAccess ? Status.FAIL : Status.PASS;
                    r.put("Policy", policyNode);
                    
                } catch (S3Exception e) {
                    if ("NoSuchBucketPolicy".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.PASS;
                        r.put(Text.ERROR.toString(), 
                            Text.NO_BUCKET_POLICY_FOUND.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r.put(Text.ERROR.toString(),
                            Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(),
                        Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(bucket, inner);
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WITH_WRITE_ACCESS_ALLOWED, result, status);
        return status;
    }

    private boolean isWriteAction(String action) {
        if (action == null || action.isEmpty()) {
            return false;
        }

        String normalizedAction = action.toLowerCase();
        
        return normalizedAction.equals("s3:*") 
            || normalizedAction.startsWith("s3:put")
            || normalizedAction.startsWith("s3:delete")
            || normalizedAction.equals("s3:putobject")
            || normalizedAction.equals("s3:deleteobject")
            || normalizedAction.equals("*")
            || normalizedAction.equals("s3:putobjectacl")
            || normalizedAction.equals("s3:putobjectversionacl")
            || normalizedAction.equals("s3:putbucketpolicy")
            || normalizedAction.equals("s3:putbucketacl");
    }

    private Status checkS3AccountLevelPublicAccessBlock() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCK, 
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Status status;
        ObjectNode result = MAPPER.createObjectNode();
        String accountId = Text.NO_ACCOUNT_ID_FOUND.getText();

        try {
            accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
            
            GetPublicAccessBlockResponse response = s3control.getPublicAccessBlock(
                GetPublicAccessBlockRequest.builder().accountId(accountId).build()
            ).join();
            
            PublicAccessBlockConfiguration config = response.publicAccessBlockConfiguration();
            
            boolean allBlocked = config.blockPublicAcls()
                               && config.ignorePublicAcls()
                               && config.blockPublicPolicy()
                               && config.restrictPublicBuckets();
            status = allBlocked ? Status.PASS : Status.FAIL;
            
            result.put("accountId", accountId);
            result = MAPPER.valueToTree(config.toBuilder());
            
            if (!allBlocked) {
                List<String> missingSettings = new ArrayList<>();
                if (!config.blockPublicAcls()) missingSettings.add("BlockPublicAcls");
                if (!config.ignorePublicAcls()) missingSettings.add("IgnorePublicAcls");
                if (!config.blockPublicPolicy()) missingSettings.add("BlockPublicPolicy");
                if (!config.restrictPublicBuckets()) missingSettings.add("RestrictPublicBuckets");
                
                result.put("reason", "Missing settings: " + String.join(", ", missingSettings));
            }
            
        } catch (S3ControlException e) {
            if ("NoSuchPublicAccessBlockConfiguration".equals(e.awsErrorDetails().errorCode())) {
                status = Status.FAIL;
                result.put("reason", "No public access block configuration found for account");
                result.put("accountId", accountId);
            } else {
                status = Status.FAIL_EXCEPTION;
                result.put(Text.ERROR.toString(), Text.EXCEPTION.getText().concat(e.getMessage()));
            }
        } catch (Exception e) {
            status = Status.FAIL_EXCEPTION;
            result.put(Text.ERROR.toString(), Text.EXCEPTION.getText().concat(e.getMessage()));
        }
        
        writer.addToBuffer(AWSFinding.S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCK, result, status);
        return status;
    }

    private Status S3BucketsListableByPublic() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_LISTABLE_BY_PUBLIC,
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketPolicyResponse response = regionalS3.getBucketPolicy(
                        GetBucketPolicyRequest.builder().bucket(bucket).build()
                    ).join();
                    
                    String policyText = response.policy();
                    JsonNode policyNode = MAPPER.readTree(policyText);
                    
                    boolean isListable = StreamSupport.stream(policyNode.path("Statement").spliterator(), false)
                        .anyMatch(statement -> {
                            JsonNode effect = statement.path("Effect");
                            JsonNode principal = statement.path("Principal");
                            JsonNode action = statement.path("Action");
                            
                            boolean isAllow = "Allow".equalsIgnoreCase(effect.asText());
                            boolean hasPublicPrincipal = checkPrincipalForPublicAccess(principal);
                            boolean hasListAction = hasListAction(action);
                            
                            return isAllow && hasPublicPrincipal && hasListAction;
                        });
                    
                    s = isListable ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                    
                } catch (S3Exception e) {
                    if ("NoSuchBucketPolicy".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.PASS;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                        Text.NO_BUCKET_POLICY_FOUND.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(bucket, inner);
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_LISTABLE_BY_PUBLIC, result, status);
        return status;
    }

    private Status S3BucketsOpenToPublic() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_OPEN_TO_PUBLIC,
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketPolicyResponse response = regionalS3.getBucketPolicy(
                        GetBucketPolicyRequest.builder().bucket(bucket).build()
                    ).join();
                    
                    String policyText = response.policy();
                    JsonNode policyNode = MAPPER.readTree(policyText);
                    
                    boolean isOpen = StreamSupport.stream(policyNode.path("Statement").spliterator(), false)
                        .anyMatch(statement -> {
                            JsonNode effect = statement.path("Effect");
                            JsonNode principal = statement.path("Principal");
                            JsonNode action = statement.path("Action");
                            JsonNode resource = statement.path("Resource");
                            
                            boolean isAllow = "Allow".equalsIgnoreCase(effect.asText());
                            boolean hasPublicPrincipal = checkPrincipalForPublicAccess(principal);
                            boolean hasReadAction = hasReadAction(action);
                            boolean affectsBucket = affectsBucket(resource, bucket);
                            
                            return isAllow && hasPublicPrincipal && hasReadAction && affectsBucket;
                        });
                    
                    s = isOpen ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                    
                } catch (S3Exception e) {
                    if ("NoSuchBucketPolicy".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.PASS;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                        Text.NO_BUCKET_POLICY_FOUND.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(bucket, inner);
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_OPEN_TO_PUBLIC, result, status);
        return status;
    }

    private Status S3BucketsWritableByPublic() {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.S3_BUCKETS_WRITABLE_BY_PUBLIC,
                            Text.NO_S3_BUCKETS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r;
                try {
                    S3AsyncClient regionalS3 = getCorrectRegionClient(bucket);
                    GetBucketPolicyResponse response = regionalS3.getBucketPolicy(
                        GetBucketPolicyRequest.builder().bucket(bucket).build()
                    ).join();
                    
                    String policyText = response.policy();
                    JsonNode policyNode = MAPPER.readTree(policyText);
                    
                    boolean isWritable = StreamSupport.stream(policyNode.path("Statement").spliterator(), false)
                        .anyMatch(statement -> {
                            JsonNode effect = statement.path("Effect");
                            JsonNode principal = statement.path("Principal");
                            JsonNode action = statement.path("Action");
                            JsonNode resource = statement.path("Resource");
                            
                            boolean isAllow = "Allow".equalsIgnoreCase(effect.asText());
                            boolean hasPublicPrincipal = checkPrincipalForPublicAccess(principal);
                            boolean hasWriteAction = hasWriteAction(action);
                            boolean affectsBucket = affectsBucket(resource, bucket);
                            
                            return isAllow && hasPublicPrincipal && hasWriteAction && affectsBucket;
                        });
                    
                    s = isWritable ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                    
                } catch (S3Exception e) {
                    if ("NoSuchBucketPolicy".equals(e.awsErrorDetails().errorCode())) {
                        s = Status.PASS;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                        Text.NO_BUCKET_POLICY_FOUND.toString().concat(e.getMessage()));
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(bucket, inner);
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.S3_BUCKETS_WRITABLE_BY_PUBLIC, result, status);
        return status;
    }

    private boolean checkPrincipalForPublicAccess(JsonNode principalNode) {
        if (principalNode.isTextual()) {
            String principal = principalNode.asText();
            return "*".equals(principal)
                || "arn:aws:iam::*:root".equals(principal)
                || principal.contains("AWS:*");
        } else if (principalNode.isObject()) {
            JsonNode aws = principalNode.path("AWS");
            if (aws.isTextual()) {
                return "*".equals(aws.asText())
                     || "arn:aws:iam::*:root".equals(aws.asText());
            } else if (aws.isArray()) {
                return StreamSupport.stream(aws.spliterator(), false)
                    .anyMatch(awsPrincipal -> 
                        "*".equals(awsPrincipal.asText())
                        || "arn:aws:iam::*:root".equals(awsPrincipal.asText())
                    );
            }
        }
        return false;
    }

    private boolean hasListAction(JsonNode actionNode) {
        if (actionNode.isTextual()) {
            String action = actionNode.asText();
            return "s3:ListBucket".equals(action)
                || "s3:ListBucketVersions".equals(action)
                || "s3:GetBucket".equals(action)
                || "s3:*".equals(action)
                || "*".equals(action);
        } else if (actionNode.isArray()) {
            return StreamSupport.stream(actionNode.spliterator(), false)
                .anyMatch(this::hasListAction);
        }
        return false;
    }

    private boolean hasReadAction(JsonNode actionNode) {
        if (actionNode.isTextual()) {
            String action = actionNode.asText();
            return "s3:GetObject".equals(action)
                || "s3:GetObjectVersion".equals(action)
                || "s3:GetObjectAcl".equals(action)
                || "s3:GetObjectVersionAcl".equals(action)
                || "s3:*".equals(action)
                || "*".equals(action);
        } else if (actionNode.isArray()) {
            return StreamSupport.stream(actionNode.spliterator(), false)
                .anyMatch(this::hasReadAction);
        }
        return false;
    }

    private boolean hasWriteAction(JsonNode actionNode) {
        if (actionNode.isTextual()) {
            String action = actionNode.asText();
            return "s3:PutObject".equals(action)
                || "s3:PutObjectAcl".equals(action)
                || "s3:DeleteObject".equals(action)
                || "s3:DeleteObjectVersion".equals(action)
                || "s3:RestoreObject".equals(action)
                || "s3:*".equals(action)
                || "*".equals(action);
        } else if (actionNode.isArray()) {
            return StreamSupport.stream(actionNode.spliterator(), false)
                .anyMatch(this::hasWriteAction);
        }
        return false;
    }

    private boolean affectsBucket(JsonNode resourceNode, String bucketName) {
        if (resourceNode.isTextual()) {
            String resource = resourceNode.asText();
            return resource.contains(bucketName) || resource.equals("*");
        } else if (resourceNode.isArray()) {
            return StreamSupport.stream(resourceNode.spliterator(), false)
                .anyMatch(resource -> affectsBucket(resource, bucketName));
        }
        return false;
    }
}
