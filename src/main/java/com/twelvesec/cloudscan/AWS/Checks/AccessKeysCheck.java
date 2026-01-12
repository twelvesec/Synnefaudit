package com.twelvesec.cloudscan.AWS.Checks;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.CloudCheck.CheckResult;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.AccessKeyLastUsed;
import software.amazon.awssdk.services.iam.model.AccessKeyMetadata;
import software.amazon.awssdk.services.iam.model.AttachedPolicy;
import software.amazon.awssdk.services.iam.model.GetAccessKeyLastUsedRequest;
import software.amazon.awssdk.services.iam.model.GetAccessKeyLastUsedResponse;
import software.amazon.awssdk.services.iam.model.GetLoginProfileRequest;
import software.amazon.awssdk.services.iam.model.GetLoginProfileResponse;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysResponse;
import software.amazon.awssdk.services.iam.model.ListAttachedUserPoliciesRequest;
import software.amazon.awssdk.services.iam.model.User;

public class AccessKeysCheck implements CloudCheck {
    private List<User> allUsers;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;

    public AccessKeysCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    IamAsyncClient iam) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.iam = iam;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllUsers()
            .thenCompose(users -> {
                this.allUsers = users;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkIAMUsersWithMultipleActiveAccessKeys,                  AWSFinding.IAM_USERS_WITH_MULTIPLE_ACTIVE_ACCESS_KEYS, this::reportError),
                    wrapCheck(this::checkAccessKeysNotRotated90Days,                            AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED, this::reportError),
                    wrapCheck(this::checkAccessKeysNotRotatedForUsersWithNonIAMorSTSPolicies,   AWSFinding.IAM_ACCESS_KEYS_NOT_ROTATED_PRIVILEGED, this::reportError),
                    wrapCheck(this::checkNoAccessKeysDuringUserSetup,                           AWSFinding.IAM_NO_ACCESS_KEYS_DURING_SETUP, this::reportError),
                    wrapCheck(this::checkUnusedAccessKeys,                                      AWSFinding.IAM_UNUSED_ACCESS_KEYS, this::reportError)
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
}
