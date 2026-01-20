package com.twelvesec.cloudscan.AWS.Checks;

import java.time.*;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.AccessKeyLastUsed;
import software.amazon.awssdk.services.iam.model.AccessKeyMetadata;
import software.amazon.awssdk.services.iam.model.AttachedPolicy;
import software.amazon.awssdk.services.iam.model.GenerateCredentialReportResponse;
import software.amazon.awssdk.services.iam.model.GetAccessKeyLastUsedRequest;
import software.amazon.awssdk.services.iam.model.GetAccessKeyLastUsedResponse;
import software.amazon.awssdk.services.iam.model.GetCredentialReportResponse;
import software.amazon.awssdk.services.iam.model.GetLoginProfileRequest;
import software.amazon.awssdk.services.iam.model.GetLoginProfileResponse;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysResponse;
import software.amazon.awssdk.services.iam.model.ListAttachedUserPoliciesRequest;
import software.amazon.awssdk.services.iam.model.ReportStateType;
import software.amazon.awssdk.services.iam.model.User;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.GetKeyRotationStatusRequest;
import software.amazon.awssdk.services.kms.model.GetKeyRotationStatusResponse;
import software.amazon.awssdk.services.kms.model.KeyManagerType;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.KeyState;

public class AccessKeysCheck implements CloudCheck {
    private List<User> allUsers;
    private List<String> allKeyIds;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;
    private final KmsAsyncClient kms;

    public AccessKeysCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    IamAsyncClient iam, KmsAsyncClient kms) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.iam = iam;
        this.kms = kms;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllUsers()
            .thenCompose(users -> {
                this.allUsers = users;
                return sharedDataProvider.getAllKeyIds();
            })
            .thenCompose(keyIds -> {
                this.allKeyIds = keyIds;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkIAMUsersWithMultipleActiveAccessKeys,                  AWSFinding.IAM_USERS_WITH_MULTIPLE_ACTIVE_ACCESS_KEYS, this::reportError),
                    wrapCheck(this::checkAccessKeysNotRotated90Days,                            AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED, this::reportError),
                    wrapCheck(this::checkAccessKeysNotRotatedForUsersWithNonIAMorSTSPolicies,   AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED_PRIVILEGED, this::reportError),
                    wrapCheck(this::checkNoAccessKeysDuringUserSetup,                           AWSFinding.IAM_NO_ACCESS_KEYS_DURING_SETUP, this::reportError),
                    wrapCheck(this::checkUnusedAccessKeys,                                      AWSFinding.IAM_UNUSED_ACCESS_KEYS, this::reportError),
                    wrapCheck(this::checkKmsKeyRotationEnabled,                                 AWSFinding.KMS_KEY_ROTATION_ENABLED, this::reportError),
                    wrapCheck(this::checkKmsKeyDeletionProtection,                              AWSFinding.KMS_DELETION_PROTECTION, this::reportError),
                    wrapCheck(this::checkKmsKeyNotMultiRegion,                                  AWSFinding.KMS_MULTI_REGION, this::reportError),
                    wrapCheck(this::checkNoRootAccountAccessKey,                                AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkIAMUsersWithMultipleActiveAccessKeys() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_USERS_WITH_MULTIPLE_ACTIVE_ACCESS_KEYS, 
                        Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allUsers.stream()
            .map(user -> {
                String username = user.userName();
                Status s;
                String r;
                try {
                    ListAccessKeysResponse response = iam.listAccessKeys(
                        ListAccessKeysRequest.builder().userName(username).build()
                    ).join();
                    List<String> active = response.accessKeyMetadata().stream()
                        .filter(k -> "Active".equalsIgnoreCase(k.statusAsString()))
                        .map(AccessKeyMetadata::accessKeyId)
                        .toList();
                    s = active.size() > 1 ? Status.FAIL : Status.PASS;
                    r = active.isEmpty() ? Text.NO_ACTIVE_ACCESS_KEYS_FOR_USER.toString() : String.join(", ", active);
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(username, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_USERS_WITH_MULTIPLE_ACTIVE_ACCESS_KEYS, result, status);
        return status;
    }

    private Status checkAccessKeysNotRotated90Days() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED,
                            Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(90, ChronoUnit.DAYS);
        List<Map<String,Object>> result = allUsers.stream()
            .map(user -> {
                Status s = Status.PASS;
                ObjectNode r;
                try {
                    List<AccessKeyMetadata> keys = iam.listAccessKeys(
                        ListAccessKeysRequest.builder().userName(user.userName()).build()
                    ).join().accessKeyMetadata();

                    if (keys.isEmpty()) {
                        r = MAPPER.createObjectNode().put(Text.RESULT.toString(), 
                                                    Text.NO_ACCESS_KEYS_FOUND.toString());
                        s = Status.PASS;
                    } else {
                        ArrayNode keyArr = MAPPER.createArrayNode();
                        for (AccessKeyMetadata key : keys) {
                            boolean oldKey = key.createDate().isBefore(cutoff);
                            if (oldKey) { s = Status.FAIL; }

                            ObjectNode keyNode = (ObjectNode) MAPPER.valueToTree(key.toBuilder());
                            long daysOld = ChronoUnit.DAYS.between(key.createDate(), Instant.now());
                            keyNode.put(Text.AGEINDAYS.toString(), daysOld);
                            keyArr.add(keyNode);
                        }
                        r = MAPPER.createObjectNode().set(Text.RESULT.toString(), keyArr);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(user.userName(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED, result, status);
        return status;
    }

    private Status checkAccessKeysNotRotatedForUsersWithNonIAMorSTSPolicies() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED_PRIVILEGED,
                            Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(90, ChronoUnit.DAYS);
        List<Map<String, Object>> result = allUsers.stream()
            .map(user -> {
                String userName = user.userName();
                ObjectNode r = MAPPER.createObjectNode();
                Status s;
                try {
                    List<String> privilegedPolicies = iam.listAttachedUserPolicies(
                            ListAttachedUserPoliciesRequest.builder().userName(userName).build()
                        ).join()
                        .attachedPolicies().stream()
                        .map(AttachedPolicy::policyName)
                        .filter(name -> {
                            String up = name.toUpperCase(Locale.ROOT);
                            return !up.contains("IAM") && !up.contains("STS");
                        })
                        .toList();

                    List<ObjectNode> keyNodes = iam.listAccessKeys(
                            ListAccessKeysRequest.builder().userName(userName).build()
                        ).join()
                        .accessKeyMetadata().stream()
                        .map(key -> {
                            ObjectNode keyNode = (ObjectNode) MAPPER.valueToTree(key.toBuilder());
                            long ageDays = ChronoUnit.DAYS.between(key.createDate(), Instant.now());
                            keyNode.put(Text.AGEINDAYS.toString(), ageDays);
                            keyNode.put(Text.AGESTATUS.toString(), (key.createDate().isBefore(cutoff) ? Status.FAIL : Status.PASS).toString());
                            return keyNode;
                        })
                        .toList();
                    
                    ArrayNode policiesArray = r.putArray(Text.ATTACHEDPOLICIES.toString());
                    if (privilegedPolicies.isEmpty()) {
                        r.put(Text.ATTACHEDPOLICIES.toString(), Text.NO_NON_IAM_STS_POLICIES_ATTACHED.toString());
                    } else {
                        privilegedPolicies.forEach(policiesArray::add);
                    }
                    
                    ArrayNode keysArray = r.putArray(Text.ACCESSKEYS.toString());
                    if (keyNodes.isEmpty()) {
                        r.put(Text.ACCESSKEYS.toString(), Text.NO_ACCESS_KEYS_FOUND.toString());
                    } else {
                        keyNodes.forEach(keysArray::add);
                    }

                    boolean hasPrivilegedPolicies = !privilegedPolicies.isEmpty();
                    boolean hasOldKey = keyNodes.stream()
                        .anyMatch(kn -> Status.valueOf(kn.get(Text.AGESTATUS.toString()).asText()) == Status.FAIL);
                    
                    s = (hasPrivilegedPolicies && hasOldKey) ? Status.FAIL : Status.PASS;
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(userName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED_PRIVILEGED, result, status);
        return status;
    }

    private Status checkNoAccessKeysDuringUserSetup() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_NO_ACCESS_KEYS_DURING_SETUP,
                            Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allUsers.stream()
            .filter(user -> {
                try {
                    GetLoginProfileResponse loginProfile = iam.getLoginProfile(
                        GetLoginProfileRequest.builder().userName(user.userName()).build())
                        .join();
                    return loginProfile != null;
                } catch (Exception e) {
                    return false;
                }
            })
            .map(user -> {
                String username = user.userName();
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    ListAccessKeysResponse keysResponse = iam.listAccessKeys(
                        ListAccessKeysRequest.builder().userName(username).build())
                        .join();
                    
                    boolean hasEarlyKeys = false;
                    ArrayNode accessKeysArray = MAPPER.createArrayNode();

                    hasEarlyKeys = keysResponse.accessKeyMetadata().stream()
                        .map(key -> {
                            ObjectNode keyNode = MAPPER.valueToTree(key.toBuilder());
                            accessKeysArray.add(keyNode);
                            return key;
                        })
                        .anyMatch(key -> Duration.between(user.createDate(), key.createDate()).toDays() <= 1);
                    
                    s = hasEarlyKeys ? Status.FAIL : Status.PASS;
                    r.put(Text.USERCREATIONDATE.toString(), user.createDate().toString());
                    r.put(Text.ACCESSKEYS.toString(), accessKeysArray); 
                    
                }  catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(username, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_NO_ACCESS_KEYS_DURING_SETUP, result, status);
        return status;
    }
    
    private Status checkUnusedAccessKeys() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_UNUSED_ACCESS_KEYS,
                    Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(45, ChronoUnit.DAYS);

        List<Map<String, Object>> result = allUsers.stream()
            .map(user -> {
                String username = user.userName();
                Status s = Status.PASS;
                ObjectNode r;
                try {
                    List<AccessKeyMetadata> keys = iam.listAccessKeys(
                            ListAccessKeysRequest.builder().userName(user.userName()).build()
                        ).join().accessKeyMetadata();

                    if (keys.isEmpty()) {
                        r = MAPPER.valueToTree(Map.of(
                            Text.RESULT.toString(), Text.NO_ACCESS_KEYS_FOUND.toString()
                        ));
                    } else {
                        List<ObjectNode> keyNodes = keys.stream()
                            .map(key -> {
                                ObjectNode kn = MAPPER.valueToTree(key.toBuilder());
                                try {
                                    GetAccessKeyLastUsedResponse lastUsedResp = iam.getAccessKeyLastUsed(
                                            GetAccessKeyLastUsedRequest.builder().accessKeyId(key.accessKeyId()).build()
                                        ).join();

                                    AccessKeyLastUsed lastUsed = lastUsedResp.accessKeyLastUsed();

                                    if (lastUsed == null || lastUsed.lastUsedDate() == null) {
                                        kn.put(Text.STATUS.toString(), Status.FAIL.toString());
                                    } else {
                                        Instant lastUsedInstant = lastUsed.lastUsedDate();
                                        long days = ChronoUnit.DAYS.between(lastUsedInstant, Instant.now());
                                        Status keyStatus = lastUsedInstant.isBefore(cutoff) ? Status.FAIL : Status.PASS;
                                        kn.put(Text.LAST_USED_DATE.toString(), lastUsedInstant.toString());
                                        kn.put(Text.AGEINDAYS.toString(), days);
                                        kn.put(Text.STATUS.toString(), keyStatus.toString());
                                    }
                                } catch (Exception e) {
                                    kn.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                                }
                                return kn;
                            })
                            .toList();

                        r = MAPPER.valueToTree(Map.of(Text.ACCESSKEYS.toString(), keyNodes));
                        s = getOverallStatus(keyNodes);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.valueToTree(Map.of(
                        Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage())
                    ));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(username, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_UNUSED_ACCESS_KEYS, result, status);
        return status;
    }

    private Status checkKmsKeyRotationEnabled() {
        if (allKeyIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.KMS_KEY_ROTATION_ENABLED,
                            Text.NO_KMS_KEYS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allKeyIds.stream()
            .map(keyId -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                try {
                    DescribeKeyResponse describeResponse = kms.describeKey(
                            DescribeKeyRequest.builder().keyId(keyId).build()
                    ).join();
                    
                    if (KeyManagerType.AWS.equals(describeResponse.keyMetadata().keyManager())) {
                        s = Status.NOT_APPLICABLE;
                        r.put(Text.MESSAGE.toString(), Text.KEY_IS_AWS_MANAGED.toString());
                    } else {
                        GetKeyRotationStatusResponse rotationResponse = kms.getKeyRotationStatus(
                                GetKeyRotationStatusRequest.builder().keyId(keyId).build()
                        ).join();
                        
                        boolean rotationEnabled = rotationResponse.keyRotationEnabled();
                        s = rotationEnabled ? Status.PASS : Status.FAIL;
                    }
                    r.set(Text.KEY_METADATA.toString(), MAPPER.valueToTree(describeResponse.keyMetadata().toBuilder()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(keyId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KMS_KEY_ROTATION_ENABLED, result, status);
        return status;
    }

    private Status checkKmsKeyDeletionProtection() {
        if (allKeyIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.KMS_DELETION_PROTECTION,
                            Text.NO_KMS_KEYS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allKeyIds.stream()
            .map(keyId -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    DescribeKeyResponse describeResponse = kms.describeKey(
                        DescribeKeyRequest.builder().keyId(keyId).build()
                    ).join();
                    
                    KeyMetadata keyMetadata = describeResponse.keyMetadata();
                    if (KeyManagerType.CUSTOMER.equals(keyMetadata.keyManager())) {
                        if (!KeyState.DISABLED.equals(keyMetadata.keyState())) {
                            s = Status.PASS;
                            r.put(Text.MESSAGE.toString(), Text.KMS_KEY_NOT_SCHEDULED_FOR_DELETION.toString());
                            
                            if (KeyState.PENDING_DELETION.equals(keyMetadata.keyState())) {
                                s = Status.FAIL;
                                r.put(Text.MESSAGE.toString(), Text.KMS_KEY_SCHEDULED_FOR_DELETION.toString());
                            }
                        } else {
                            s = Status.NOT_APPLICABLE;
                            r.put(Text.MESSAGE.toString(), Text.KMS_KEY_IS_DISABLED.toString());
                        }
                    } else {
                        s = Status.NOT_APPLICABLE;
                        r.put(Text.MESSAGE.toString(), Text.KMS_KEY_NOT_CUSTOMER_MANAGED.toString());
                    }
                    r.set(Text.KEY_METADATA.toString(), MAPPER.valueToTree(describeResponse.keyMetadata().toBuilder()));
                } catch (Exception e) { 
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(keyId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KMS_DELETION_PROTECTION, result, status);
        return status;
    }

    private Status checkKmsKeyNotMultiRegion() {
        if (allKeyIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.KMS_MULTI_REGION,
                            Text.NO_KMS_KEYS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allKeyIds.stream()
            .map(keyId -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    DescribeKeyResponse describeResponse = kms.describeKey(
                        DescribeKeyRequest.builder().keyId(keyId).build()
                    ).join();
                    
                    KeyMetadata keyMetadata = describeResponse.keyMetadata();
                    
                    if (KeyManagerType.AWS.equals(keyMetadata.keyManager())) {
                        s = Status.NOT_APPLICABLE;
                        r.put(Text.MESSAGE.toString(), Text.KEY_IS_AWS_MANAGED.toString());
                    } else {
                        boolean isMultiRegion = Boolean.TRUE.equals(keyMetadata.multiRegion());
                        s = isMultiRegion ? Status.FAIL : Status.PASS;
                    }
                    r.set(Text.KEY_METADATA.toString(), MAPPER.valueToTree(describeResponse.keyMetadata().toBuilder()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(keyId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KMS_MULTI_REGION, result, status);
        return status;
    }

    private Status checkNoRootAccountAccessKey() {
        try {
            CompletableFuture<GetCredentialReportResponse> reportFuture =
                iam.generateCredentialReport()
                    .thenCompose(response -> pollForCredentialReport())
                    .thenCompose(response -> iam.getCredentialReport());

            GetCredentialReportResponse reportResponse = reportFuture.orTimeout(30, TimeUnit.SECONDS).join();

            SdkBytes contentBytes = reportResponse.content();
            if (contentBytes == null) {
                writer.addToBuffer(AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY,
                        Text.CREDENTIAL_REPORT_NO_CONTENT.toString(), Status.FAIL_EXCEPTION);
                return Status.FAIL_EXCEPTION;
            }

            String reportContent = contentBytes.asUtf8String();
            String[] lines = reportContent.split("\\r?\\n");

            if (lines.length < 2) {
                writer.addToBuffer(AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY,
                        Text.INVALID_CREDENTIAL_REPORT_FORMAT.toString() + lines.length,
                        Status.FAIL_EXCEPTION);
                return Status.FAIL_EXCEPTION;
            }

            return Arrays.stream(lines)
                .skip(1)
                .map(this::parseCSVLine)
                .filter(columns -> columns.length > 0
                        && "<root_account>".equals(columns[0].replace("\"", "")))
                .findFirst()
                .map(this::analyzeRootAccountRecord)
                .orElseGet(() -> {
                    writer.addToBuffer(AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY,
                                    Text.ROOT_NOT_IN_CREDENTIAL_REPORT.toString(), Status.FAIL_EXCEPTION);
                    return Status.FAIL_EXCEPTION;
                });

        } catch (Exception e) {
            writer.addToBuffer(AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY,
                            Text.EXCEPTION.toString().concat(e.getMessage()), Status.FAIL_EXCEPTION);
            return Status.FAIL_EXCEPTION;
        }
    }

    private CompletableFuture<GenerateCredentialReportResponse> pollForCredentialReport() {
        return IntStream.rangeClosed(1, 30)
            .mapToObj(attempt ->
                CompletableFuture
                    .runAsync(() -> {
                        try {
                            if (attempt > 1) Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new RuntimeException(e);
                        }
                    })
                    .thenCompose(__ -> iam.generateCredentialReport())
            )
            .reduce(
                CompletableFuture.completedFuture(null),
                (prev, current) -> prev.thenCompose(prevResponse ->
                    (prevResponse != null && ReportStateType.COMPLETE.equals(prevResponse.state()))
                        ? CompletableFuture.completedFuture(prevResponse)
                        : current
                )
            )
            .thenCompose(response -> {
                if (response != null && ReportStateType.COMPLETE.equals(response.state())) {
                    return CompletableFuture.completedFuture(response);
                } else {
                    return CompletableFuture.failedFuture(
                        new RuntimeException(Text.CREDENTIAL_REPORT_GEN_TIMEOUT.toString())
                    );
                }
            });
    }

    private String[] parseCSVLine(String line) {
        String[] parts = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
        return Arrays.stream(parts)
            .map(s -> s.replaceAll("^\"|\"$", ""))
            .toArray(String[]::new);
    }

    private Status analyzeRootAccountRecord(String[] columns) {
        try {
            String accessKey1Active = columns.length > 8 ? columns[8].replace("\"", "") : "";
            String accessKey2Active = columns.length > 13 ? columns[13].replace("\"", "") : "";

            boolean rootHasAccessKey = "true".equalsIgnoreCase(accessKey1Active)
                || "true".equalsIgnoreCase(accessKey2Active);

            int rootAccessKeyAge = -1;
            if (rootHasAccessKey) {
                if ("true".equalsIgnoreCase(accessKey1Active) && columns.length > 10) {
                    String lastRotatedStr = columns[10].replace("\"", "");
                    if (!lastRotatedStr.isEmpty() && !"N/A".equals(lastRotatedStr)) {
                        try {
                            ZonedDateTime lastRotated = ZonedDateTime.parse(lastRotatedStr);
                            rootAccessKeyAge = (int) ChronoUnit.DAYS.between(
                                lastRotated.toLocalDate(),
                                ZonedDateTime.now().toLocalDate()
                            );
                        } catch (DateTimeParseException e) {
                            try {
                                LocalDateTime lastRotated = LocalDateTime.parse(lastRotatedStr);
                                rootAccessKeyAge = (int) ChronoUnit.DAYS.between(lastRotated.toLocalDate(),  LocalDate.now());
                            } catch (Exception _) {}
                        }
                    }
                }
            }

            Status status = !rootHasAccessKey ? Status.PASS : Status.FAIL;
            String message;
            if (!rootHasAccessKey) {
                message = Text.NO_ROOT_ACCOUNT_ACCESS_KEY.toString();
            } else {
                message = Text.ROOT_ACCOUNT_ACCESS_KEY_PRESENT.toString();
                if (rootAccessKeyAge > 0) {
                    message += String.format(Text.AGE_NUM_DAYS.toString(), rootAccessKeyAge);
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("root_has_access_key", rootHasAccessKey);
            result.put("access_key_1_active", accessKey1Active);
            result.put("access_key_2_active", accessKey2Active);
            result.put("access_key_age_days", rootAccessKeyAge);
            result.put("message", message);

            writer.addToBuffer(AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY, result, status);
            return status;
        } catch (Exception e) {
            writer.addToBuffer(AWSFinding.NO_ROOT_ACCOUNT_ACCESS_KEY,
                            Text.EXCEPTION.toString().concat(e.getMessage()), Status.FAIL_EXCEPTION);
            return Status.FAIL_EXCEPTION;
        }
    }
}
