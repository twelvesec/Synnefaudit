package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.PaginatorHelper;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;
import java.util.function.Supplier;

public class IAMUserSecurityCheck implements CloudCheck {
    private static final int MAX_KEY_AGE_DAYS = 90;
    private static final int MIN_PASSWD_LENGTH = 14;
    private static final int MIN_PASSWD_REUSE = 24;

    private PasswordPolicy cachedPasswordPolicy = null;
    private boolean passwordPolicyRetrieved = false;
    private ObjectNode cachedPasswordPolicyResult = null;
    private Status passwordPolicyRetrievalStatus = null;

    private List<User> allUsers;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;

    public IAMUserSecurityCheck(DataWriter writer, SharedDataProvider sharedDataProvider, IamAsyncClient iam) {
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
                    wrapCheck(this::checkIAMPasswordPolicyIsNotSet,                     AWSFinding.IAM_PASSWORD_POLICY_NOT_SET, this::reportError),
                    wrapCheck(this::checkShortIAMPasswordPolicyReuse,                   AWSFinding.IAM_SHORT_PASSWORD_POLICY_REUSE, this::reportError),
                    wrapCheck(this::checkIamUsersWithLongTermCredentials,               AWSFinding.IAM_USERS_WITH_LONG_TERM_CREDENTIALS, this::reportError),
                    wrapCheck(this::checkIamUsersWithAttachedPolicies,                  AWSFinding.IAM_USERS_WITH_ATTACHED_POLICIES, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyMaxAge,                       AWSFinding.IAM_PASSWORD_POLICY_MAX_AGE, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyRequireLowercase,             AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_LOWERCASE, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyRequireNumber,                AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_NUMBER, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyRequireSymbol,                AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_SYMBOL, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyRequireUppercase,             AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_UPPERCASE, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyMinimumLength,                AWSFinding.IAM_PASSWORD_POLICY_MINIMUM_LENGTH, this::reportError),
                    wrapCheck(this::checkUnusedUserConsoleAccessDisabled,               AWSFinding.UNUSED_CONSOLE_ACCESS_ENABLED, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private boolean retrievePasswordPolicy() {
        if (!passwordPolicyRetrieved) {
            try {
                GetAccountPasswordPolicyResponse response = iam.getAccountPasswordPolicy(
                        GetAccountPasswordPolicyRequest.builder().build()
                ).join();

                cachedPasswordPolicy = response.passwordPolicy();
                cachedPasswordPolicyResult = MAPPER.valueToTree(cachedPasswordPolicy.toBuilder());
                passwordPolicyRetrievalStatus = Status.PASS;
            } catch (Exception e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                if (cause instanceof NoSuchEntityException) {
                    cachedPasswordPolicyResult = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                            Text.PASSWORD_POLICY_NOT_SET.toString().concat(cause.getMessage()));
                    passwordPolicyRetrievalStatus = Status.FAIL;
                } else {
                    cachedPasswordPolicyResult = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                            Text.EXCEPTION.toString().concat(e.getMessage()));
                    passwordPolicyRetrievalStatus = Status.FAIL_EXCEPTION;
                }
            }
            passwordPolicyRetrieved = true;
        }
        return passwordPolicyRetrievalStatus == Status.PASS;
    }

    private Status checkIAMPasswordPolicyIsNotSet() {
        Status status = retrievePasswordPolicy() ? passwordPolicyRetrievalStatus : Status.FAIL;
        writer.addToBuffer(AWSFinding.IAM_PASSWORD_POLICY_NOT_SET, cachedPasswordPolicyResult, status);
        return status;
    }

    private Status checkShortIAMPasswordPolicyReuse() {
        Status status;
        Object result;

        if (!retrievePasswordPolicy()) {
            status = passwordPolicyRetrievalStatus;
            result = cachedPasswordPolicyResult != null
                    ? cachedPasswordPolicyResult
                    : Text.FAILED_TO_RETRIEVE_PASSWORD_POLICY.getText();
        } else {
            Integer reusePrevention = cachedPasswordPolicy.passwordReusePrevention();
            result = Text.PASSWORD_REUSE_PREVENTION.getText().concat(reusePrevention != null ? reusePrevention.toString() : "null");
            status = reusePrevention != null && reusePrevention >= MIN_PASSWD_REUSE ? Status.PASS : Status.FAIL;
        }
        writer.addToBuffer(AWSFinding.IAM_SHORT_PASSWORD_POLICY_REUSE, result, status);
        return status;
    }

    private Status checkPasswordPolicyProperty(AWSFinding finding, Function<PasswordPolicy, Boolean> rulePredicate) {
        Status status;
        ObjectNode result;
        if (!retrievePasswordPolicy()) {
            status = passwordPolicyRetrievalStatus;
        } else {
            Boolean passes = rulePredicate.apply(cachedPasswordPolicy);
            status = (passes != null && passes) ? Status.PASS : Status.FAIL;
        }
        result = cachedPasswordPolicyResult;
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Status checkIAMPasswordPolicyMaxAge() {
        return checkPasswordPolicyProperty(AWSFinding.IAM_PASSWORD_POLICY_MAX_AGE,
                policy -> policy.maxPasswordAge() != null && policy.maxPasswordAge() <= MAX_KEY_AGE_DAYS);
    }

    private Status checkIAMPasswordPolicyMinimumLength() {
        return checkPasswordPolicyProperty(AWSFinding.IAM_PASSWORD_POLICY_MINIMUM_LENGTH,
                policy -> policy.minimumPasswordLength() != null && policy.minimumPasswordLength() >= MIN_PASSWD_LENGTH);
    }

    private Status checkIAMPasswordPolicyRequireUppercase() {
        return checkPasswordPolicyProperty(AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_UPPERCASE,
                policy -> policy.requireUppercaseCharacters() != null && policy.requireUppercaseCharacters());
    }

    private Status checkIAMPasswordPolicyRequireLowercase() {
        return checkPasswordPolicyProperty(AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_LOWERCASE,
                policy -> policy.requireLowercaseCharacters() != null && policy.requireLowercaseCharacters());
    }

    private Status checkIAMPasswordPolicyRequireNumber() {
        return checkPasswordPolicyProperty(AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_NUMBER,
                policy -> policy.requireNumbers() != null && policy.requireNumbers());
    }

    private Status checkIAMPasswordPolicyRequireSymbol() {
        return checkPasswordPolicyProperty(AWSFinding.IAM_PASSWORD_POLICY_REQUIRE_SYMBOL,
                policy -> policy.requireSymbols() != null && policy.requireSymbols());
    }

    private Status checkIamUsersWithLongTermCredentials() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_USERS_WITH_LONG_TERM_CREDENTIALS,
                    Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(MAX_KEY_AGE_DAYS, ChronoUnit.DAYS);
        List<Map<String, Object>> result = allUsers.stream()
            .flatMap(user -> {
                List<AccessKeyMetadata> keys = PaginatorHelper.collectPaginatedItems(
                    iam.listAccessKeysPaginator(ListAccessKeysRequest.builder().userName(user.userName()).build()),
                    ListAccessKeysResponse::accessKeyMetadata
                ).join();

                return keys.stream()
                    .map(meta -> {
                        boolean isOld = meta.createDate().isBefore(cutoff);
                        Status s = isOld ? Status.FAIL : Status.PASS;
                        ObjectNode metaNode = MAPPER.valueToTree(meta.toBuilder());

                        Map<String, Object> inner = new HashMap<>();
                        inner.put(Text.STATUS.toString(), s);
                        inner.put(Text.RESULT.toString(), metaNode);
                        return Map.<String, Object>of(user.userName(), inner);
                    });
            })
            .toList();

        if (result.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_USERS_WITH_LONG_TERM_CREDENTIALS,
                    Text.NO_ACCESS_KEYS_FOUND.toString(), Status.PASS);
            return Status.PASS;
        }

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_USERS_WITH_LONG_TERM_CREDENTIALS, result, status);
        return status;
    }

    private Status checkIamUsersWithAttachedPolicies() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_USERS_WITH_ATTACHED_POLICIES,
                    Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allUsers.stream()
            .map(user -> {
                String userName = user.userName();
                Status status;
                ObjectNode outputNode;

                try {
                    ListAttachedUserPoliciesResponse response = iam.listAttachedUserPolicies(
                            ListAttachedUserPoliciesRequest.builder().userName(userName).build()
                    ).join();
                    boolean hasAttachedPolicies = !response.attachedPolicies().isEmpty();
                    status = hasAttachedPolicies ? Status.FAIL : Status.PASS;
                    outputNode = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    status = Status.FAIL_EXCEPTION;
                    outputNode = MAPPER.createObjectNode()
                            .put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status);
                inner.put(Text.RESULT.toString(), outputNode);
                return Map.<String, Object>of(userName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_USERS_WITH_ATTACHED_POLICIES, result, status);
        return status;
    }

    private Status checkUnusedUserConsoleAccessDisabled() {
        if (allUsers.isEmpty()) {
            writer.addToBuffer(AWSFinding.UNUSED_CONSOLE_ACCESS_ENABLED,
                    Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allUsers.stream()
            .map(user -> {
                Status s;
                JsonNode r;
                try {
                    GetLoginProfileResponse loginProfile = iam.getLoginProfile(
                            GetLoginProfileRequest.builder().userName(user.userName()).build()
                    ).join();

                    GetUserResponse userDetail = iam.getUser(
                            GetUserRequest.builder().userName(user.userName()).build()
                    ).join();

                    boolean isUnused;
                    if (userDetail.user().passwordLastUsed() == null) {
                        if (loginProfile.loginProfile().createDate() != null) {
                            long daysSinceCreation = ChronoUnit.DAYS.between(loginProfile.loginProfile().createDate(), Instant.now());
                            isUnused = daysSinceCreation > MAX_KEY_AGE_DAYS;
                        } else {
                            isUnused = true;
                        }
                    } else {
                        long daysSinceLastUse = ChronoUnit.DAYS.between(
                                userDetail.user().passwordLastUsed(), Instant.now());
                        isUnused = daysSinceLastUse > MAX_KEY_AGE_DAYS;
                    }

                    s = !isUnused ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(Map.of(
                            Text.USER.toString(), userDetail.user().toBuilder(),
                            Text.LOGIN_PROFILE.toString(), loginProfile.loginProfile().toBuilder()
                    ));
                } catch (CompletionException e) {
                    if (e.getCause() instanceof NoSuchEntityException) {
                        s = Status.PASS;
                        r = MAPPER.createObjectNode().put(Text.MESSAGE.toString(), Text.NO_CONSOLE_ACCESS.toString());
                    } else {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getCause().getMessage()));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(user.userName(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.UNUSED_CONSOLE_ACCESS_ENABLED, result, status);
        return status;
    }
}