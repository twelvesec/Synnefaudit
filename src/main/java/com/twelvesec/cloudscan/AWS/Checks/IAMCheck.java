package com.twelvesec.cloudscan.AWS.Checks;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.PaginatorHelper;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.accessanalyzer.AccessAnalyzerAsyncClient;
import software.amazon.awssdk.services.accessanalyzer.model.AnalyzerSummary;
import software.amazon.awssdk.services.accessanalyzer.model.ListFindingsRequest;
import software.amazon.awssdk.services.accessanalyzer.model.ListFindingsResponse;
import software.amazon.awssdk.services.accessanalyzer.model.FindingSummary;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.AccessKeyMetadata;
import software.amazon.awssdk.services.iam.model.AttachedPolicy;
import software.amazon.awssdk.services.iam.model.GetAccountPasswordPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetAccountPasswordPolicyResponse;
import software.amazon.awssdk.services.iam.model.GetLoginProfileRequest;
import software.amazon.awssdk.services.iam.model.GetLoginProfileResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionRequest;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysResponse;
import software.amazon.awssdk.services.iam.model.ListAttachedRolePoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedUserPoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedUserPoliciesResponse;
import software.amazon.awssdk.services.iam.model.ListEntitiesForPolicyRequest;
import software.amazon.awssdk.services.iam.model.ListEntitiesForPolicyResponse;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.Policy;
import software.amazon.awssdk.services.iam.model.PolicyGroup;
import software.amazon.awssdk.services.iam.model.PolicyRole;
import software.amazon.awssdk.services.iam.model.PolicyUser;
import software.amazon.awssdk.services.iam.model.Role;
import software.amazon.awssdk.services.iam.model.User;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

public class IAMCheck implements CloudCheck {
    private static final long MAX_KEY_AGE_DAYS = 90;

    private List<AnalyzerSummary> allAnalyzers;
    private List<Role> allRoles;
    private List<User> allUsers;
    private List<Policy> allPolicies;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;
    private final AccessAnalyzerAsyncClient accessAnalyzer;
    private final StsAsyncClient sts;

    public IAMCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    IamAsyncClient iam, AccessAnalyzerAsyncClient accessAnalyzer,
                    StsAsyncClient sts) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.iam = iam;
        this.accessAnalyzer = accessAnalyzer;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllAnalyzers()
            .thenCompose(analyzers -> {
                this.allAnalyzers = analyzers;
                return sharedDataProvider.getAllRoles();
            })
            .thenCompose(roles -> {
                this.allRoles = roles;
                return sharedDataProvider.getAllUsers();
            })
            .thenCompose(users -> {
                this.allUsers = users;
                return sharedDataProvider.getAllPolicies();
            })
            .thenCompose(policies -> {
                this.allPolicies = policies;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkIAMRolesWithAdministratorAccessPolicyAttached, AWSFinding.IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED, this::reportError),
                    wrapCheck(this::checkIAMAccessAnalyzerDisabled,                     AWSFinding.IAM_ACCESS_ANALYZER_DISABLED, this::reportError),
                    wrapCheck(this::checkIAMAccessAnalyzerWithFindings,                 AWSFinding.IAM_ACCESS_ANALYZER_WITH_FINDINGS, this::reportError),
                    wrapCheck(this::checkIAMPasswordPolicyIsNotSet,                     AWSFinding.IAM_PASSWORD_POLICY_NOT_SET, this::reportError),
                    wrapCheck(this::checkShortIAMPasswordPolicyReuse,                   AWSFinding.IAM_SHORT_PASSWORD_POLICY_REUSE, this::reportError),
                    wrapCheck(this::checkIAMPolicyAllowsPrivilegeEscalation,            AWSFinding.IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION, this::reportError),
                    wrapCheck(this::checkCrossAccountRoleAssumption,                    AWSFinding.IAM_CROSS_ACCOUNT_READ_ONLY_ROLES, this::reportError),
                    wrapCheck(this::checkOverlyPermissiveManagedPolicies,               AWSFinding.IAM_OVERLY_PERMISSIVE_MANAGED_POLICIES, this::reportError),
                    wrapCheck(this::checkIamUsersWithLongTermCredentials,               AWSFinding.IAM_USERS_WITH_LONG_TERM_CREDENTIALS, this::reportError),
                    wrapCheck(this::checkIamUsersWithAttachedPolicies,                  AWSFinding.IAM_USERS_WITH_ATTACHED_POLICIES, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkIAMRolesWithAdministratorAccessPolicyAttached() {
        if (allRoles.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED, 
                            Text.NO_IAM_ROLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allRoles.stream()
            .map(role -> {
                String roleName = role.roleName();
                Status s;
                ArrayNode policiesArray = MAPPER.createArrayNode();
                try {
                    List<AttachedPolicy> policies = iam
                        .listAttachedRolePolicies(ListAttachedRolePoliciesRequest.builder()
                            .roleName(roleName)
                            .build())
                        .join()
                        .attachedPolicies();

                    boolean hasAdmin = policies.stream().anyMatch(p -> "AdministratorAccess".equals(p.policyName()));
                    s = hasAdmin ? Status.FAIL : Status.PASS;
                    policies.forEach(p -> policiesArray.add(MAPPER.valueToTree(p.toBuilder())));

                    if (policies.isEmpty()) {
                        policiesArray.add(Text.NO_IAM_ROLE_POLICIES_FOUND.toString());
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    policiesArray.add(Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), policiesArray);
                return Map.<String, Object>of(roleName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED, result, status);
        return status;
    }

    private Status checkIAMAccessAnalyzerDisabled() {
        if (allAnalyzers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_DISABLED, 
                        Text.NO_IAM_ACCESS_ANALYZER_FOUND.toString(), Status.FAIL);
            return Status.FAIL;
        }

        List<Map<String, Object>> result = allAnalyzers.stream()
            .map((AnalyzerSummary summary) -> {
                String name = summary.name();
                ObjectNode summanyNode = MAPPER.valueToTree(summary.toBuilder());

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), Status.PASS);
                inner.put(Text.RESULT.toString(), summanyNode);
                return Map.<String, Object>of(name, inner);
            })
            .toList();

        Status status = Status.PASS;
        writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_DISABLED, result, status);
        return status;
    }

    private Status checkIAMAccessAnalyzerWithFindings() { 
        if (allAnalyzers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_WITH_FINDINGS, 
                        Text.NO_IAM_ACCESS_ANALYZER_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }
        
        List<String> activeArns = allAnalyzers.stream()
            .filter(a -> "ACTIVE".equalsIgnoreCase(a.statusAsString()))
            .map(AnalyzerSummary::arn)
            .toList();

        List<Map<String,Object>> result = activeArns.stream()
            .map(arn -> {
                Status s;
                String r;
                try {
                    ListFindingsResponse response = accessAnalyzer.listFindings(
                        ListFindingsRequest.builder().analyzerArn(arn).build()
                    ).join();
                    String findings = response.findings().stream()
                        .map(FindingSummary::id)
                        .collect(Collectors.joining(","));
                    boolean hasFindings = !findings.isEmpty();
                    s = hasFindings ? Status.FAIL : Status.PASS;
                    r = hasFindings ? findings : Text.NO_FINDINGS.toString();
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_WITH_FINDINGS, result, status);
        return status;
    }

    private Status checkIAMPasswordPolicyIsNotSet() {
        Status status = Status.FAIL;
        ObjectNode result;

        try {
            GetAccountPasswordPolicyResponse response = iam.getAccountPasswordPolicy(
                GetAccountPasswordPolicyRequest.builder().build()
            ).join();
            status = Status.PASS;
            result = MAPPER.valueToTree(response.passwordPolicy().toBuilder());
        } catch (NoSuchEntityException e) {
            status = Status.FAIL;
            result = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                Text.PASSWORD_POLICY_NOT_SET.toString().concat(e.getMessage()));
        }

        writer.addToBuffer(AWSFinding.IAM_PASSWORD_POLICY_NOT_SET, result, status);
        return status;
    }

    private Status checkShortIAMPasswordPolicyReuse() { 
        Status status = Status.FAIL;
        String result;

        try {
            GetAccountPasswordPolicyResponse response = iam.getAccountPasswordPolicy(
                GetAccountPasswordPolicyRequest.builder().build()
            ).join();
            int reusePrevention = response.passwordPolicy().passwordReusePrevention();
            result = Text.PASSWORD_REUSE_PREVENTION.getText().concat(String.valueOf(reusePrevention));
            status = reusePrevention >= 24 ? Status.PASS : Status.FAIL;
        } catch (NoSuchEntityException e) {
            status = Status.FAIL;
            result = Text.PASSWORD_POLICY_NOT_SET.toString().concat(e.getMessage());
        }

        writer.addToBuffer(AWSFinding.IAM_SHORT_PASSWORD_POLICY_REUSE, result, status);
        return status;
    }

    private Status checkIAMPolicyAllowsPrivilegeEscalation() {
        if (allPolicies.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION, 
                        Text.NO_IAM_POLICIES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> dangerousActions = Set.of(
            "iam:PassRole",
            "iam:CreatePolicyVersion",
            "iam:PutUserPolicy",
            "iam:PutGroupPolicy",
            "iam:PutRolePolicy",
            "iam:AttachUserPolicy",
            "iam:DetachUserPolicy",
            "iam:AddUserToGroup",
            "iam:CreateAccessKey",
            "iam:UpdateAccessKey",
            "iam:DeleteAccessKey",
            "iam:UpdateAssumeRolePolicy",
            "iam:*"
        );

        List<Map<String, Object>> result = allPolicies.stream()
            .map(policy -> {
                String arn = policy.arn();
                Status s;
                String r;
                JsonNode policyNode;
                try {
                    String defaultVersion = iam.getPolicy(
                        GetPolicyRequest.builder().policyArn(arn).build()
                    ).join().policy().defaultVersionId();

                    String rawPolicy = iam.getPolicyVersion(
                        GetPolicyVersionRequest.builder().policyArn(arn).versionId(defaultVersion).build()
                    ).join().policyVersion().document();

                    policyNode = MAPPER.readTree(URLDecoder.decode(rawPolicy, StandardCharsets.UTF_8));

                    JsonNode stmtsNode = policyNode.get("Statement");
                    ArrayNode statements = stmtsNode == null
                        ? MAPPER.createArrayNode()
                        : (stmtsNode.isArray()
                            ? (ArrayNode) stmtsNode
                            : MAPPER.createArrayNode().add(stmtsNode));
                    
                    List<String> actionsInPolicy = StreamSupport.stream(statements.spliterator(), false)
                        .filter(stmt -> "Allow".equalsIgnoreCase(stmt.get("Effect").asText()))
                        .flatMap(stmt -> {
                            JsonNode act = stmt.get("Action");
                            if (act == null) {
                                return Stream.of(Text.NULL_VALUE.getText());
                            } else if (act.isArray()) {
                                return StreamSupport.stream(((ArrayNode)act).spliterator(), false)
                                                    .map(JsonNode::asText);
                            }
                            return Stream.of(act.asText());
                        })
                        .toList();

                    boolean hasDangerousActions = actionsInPolicy.stream().anyMatch(dangerousActions::contains);

                    if (hasDangerousActions) {
                        s = Status.FAIL;
                        r = String.format("%s%s",
                                Text.ALLOWED_DANGEROUS_ACTIONS.toString(),
                                actionsInPolicy.stream()
                                    .filter(dangerousActions::contains)
                                    .distinct()
                                    .collect(Collectors.joining(", "))
                            );
                    } else {
                        s = Status.PASS;
                        r = Text.NO_DANGEROUS_ACTIONS_FOUND.toString();
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                    policyNode = MAPPER.createObjectNode().put(Text.ERROR.toString(), r);
                }

                ObjectNode resultNode = MAPPER.createObjectNode();
                resultNode.put(Text.MESSAGE.toString(), r);
                resultNode.put(Text.POLICY.toString(), policyNode);

                ObjectNode innerNode = MAPPER.createObjectNode();
                innerNode.put(Text.STATUS.toString(), s.toString());
                innerNode.put(Text.RESULT.toString(), resultNode);
                return Map.<String,Object>of(arn, innerNode);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION, result, status);
        return status;
    }

    private Status checkCrossAccountRoleAssumption() {
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();

        if (allRoles.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_CROSS_ACCOUNT_READ_ONLY_ROLES, 
                        Text.NO_IAM_ROLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allRoles.stream()
            .map(role -> {
                String roleName = role.roleName();
                Status s;
                String r;
                ObjectNode policyNode;
                try {
                    String raw = iam.getRole(
                            GetRoleRequest.builder().roleName(roleName).build()
                        ).join()
                        .role()
                        .assumeRolePolicyDocument();

                    policyNode = (ObjectNode) MAPPER.readTree(URLDecoder.decode(raw, StandardCharsets.UTF_8));

                    ArrayNode statements = Optional.ofNullable(policyNode.get("Statement"))
                        .map(n -> n.isArray() ? (ArrayNode)n : MAPPER.createArrayNode().add(n))
                        .orElseGet(() -> MAPPER.createArrayNode());

                    List<String> principals = StreamSupport.stream(statements.spliterator(), false)
                        .flatMap(stmt -> {
                            JsonNode p = stmt.at("/Principal/AWS");
                            if (p.isArray()) {
                                return StreamSupport.stream(((ArrayNode)p).spliterator(), false)
                                                    .map(JsonNode::asText);
                            } else if (p.isTextual()) {
                                return Stream.of(p.asText());
                            } else {
                                return Stream.empty();
                            }
                        })
                        .toList();

                    boolean hasCrossAccount = principals.stream().anyMatch(arn -> {
                        boolean isOwnRoot = arn.equals(String.format("arn:aws:iam::%s:root", accountId));
                        boolean isAWSService = arn.endsWith(".amazonaws.com");
                        return !(isOwnRoot || isAWSService);
                    });

                    if (hasCrossAccount) {
                        s = Status.FAIL;
                        r = Text.CROSS_ACCOUNT_PRINCIPALS_FOUND.toString().concat(
                            principals.stream()
                                .filter(arn -> {
                                    boolean isOwnRoot = arn.equals(String.format("arn:aws:iam::%s:root", accountId));
                                    boolean isAWSService = arn.endsWith(".amazonaws.com");
                                    return !(isOwnRoot || isAWSService);
                                })
                                .distinct()
                                .collect(Collectors.joining(", ")));
                    } else {
                        s = Status.PASS;
                        r = Text.ONLY_SAME_ACCOUNT_OR_AWS_SERVICE_PRINCIPALS.toString();
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                    policyNode = MAPPER.createObjectNode().put(Text.ERROR.toString(), r);
                }

                ObjectNode resultNode = MAPPER.createObjectNode();
                resultNode.put(Text.MESSAGE.toString(), r);
                resultNode.put(Text.POLICY.toString(), policyNode);

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), resultNode);
                return Map.<String,Object>of(roleName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_CROSS_ACCOUNT_READ_ONLY_ROLES, result, status);
        return status;
    }

    private Status checkOverlyPermissiveManagedPolicies() {
        if (allPolicies.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_OVERLY_PERMISSIVE_MANAGED_POLICIES, 
                        Text.NO_MANAGED_POLICIES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allPolicies.stream()
            .map(policy -> {
                String arn = policy.arn();
                Status s;
                String msg;
                JsonNode versionNode;
                ObjectNode entitiesNode = MAPPER.createObjectNode();
                try {
                    String vid = iam.getPolicy(
                            GetPolicyRequest.builder().policyArn(arn).build()
                        ).join()
                        .policy().defaultVersionId();

                    String rawVersion = iam.getPolicyVersion(
                            GetPolicyVersionRequest.builder().policyArn(arn).versionId(vid).build()
                        ).join()
                        .policyVersion().document();

                    String jsonVersion = URLDecoder.decode(rawVersion, StandardCharsets.UTF_8);
                    versionNode = MAPPER.readTree(jsonVersion);

                    JsonNode stmtsNode = versionNode.get("Statement");
                    ArrayNode statements = (stmtsNode == null)
                        ? MAPPER.createArrayNode()
                        : (stmtsNode.isArray()
                            ? (ArrayNode) stmtsNode
                            : MAPPER.createArrayNode().add(stmtsNode));

                    boolean wild = StreamSupport.stream(statements.spliterator(), false)
                        .filter(stmt -> "Allow".equalsIgnoreCase(stmt.path("Effect").asText()))
                        .flatMap(stmt -> {
                            JsonNode r = stmt.get("Resource");
                            if (r == null) return Stream.empty();
                            if (r.isArray()) {
                                return StreamSupport.stream(((ArrayNode) r).spliterator(), false)
                                                    .map(JsonNode::asText);
                            }
                            return Stream.of(r.asText());
                        })
                        .anyMatch(resource -> "*".equals(resource));

                    ListEntitiesForPolicyResponse entities = iam.listEntitiesForPolicy(
                        ListEntitiesForPolicyRequest.builder().policyArn(arn).build()
                    ).join();

                    ArrayNode usersNode = MAPPER.valueToTree(
                        entities.policyUsers().stream().map(PolicyUser::toString).toList()
                    );
                    ArrayNode rolesNode = MAPPER.valueToTree(
                        entities.policyRoles().stream().map(PolicyRole::toString).toList()
                    );
                    ArrayNode groupsNode = MAPPER.valueToTree(
                        entities.policyGroups().stream().map(PolicyGroup::toString).toList()
                    );

                    entitiesNode.set(Text.POLICYUSERS.toString(), usersNode);
                    entitiesNode.set(Text.POLICYROLES.toString(), rolesNode);
                    entitiesNode.set(Text.POLICYGROUPS.toString(), groupsNode);

                    boolean attached = !usersNode.isEmpty()
                                    || !rolesNode.isEmpty()
                                    || !groupsNode.isEmpty();

                    if (wild && attached) {
                        s = Status.FAIL;
                        msg = Text.POLICY_OVERSCOPED_AND_ATTACHED.toString();
                    } else {
                        s = Status.PASS;
                        msg = wild
                            ? Text.POLICY_OVERSCOPED_BUT_UNATTACHED.toString()
                            : Text.POLICY_NOT_OVERSCOPED.toString();
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    msg = Text.EXCEPTION.toString().concat(e.getMessage());
                    versionNode = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString());
                }

                ObjectNode policyNode = MAPPER.createObjectNode();
                policyNode.put(Text.MESSAGE.toString(), msg);
                policyNode.put(Text.POLICY.toString(), versionNode);
                policyNode.put(Text.ENTITIES.toString(), entitiesNode);

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), policyNode);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_OVERLY_PERMISSIVE_MANAGED_POLICIES, result, status);
        return status;
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
                        iam.listAccessKeysPaginator(
                            ListAccessKeysRequest.builder().userName(user.userName()).build()
                        ),
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
        writer.addToBuffer( AWSFinding.IAM_USERS_WITH_LONG_TERM_CREDENTIALS, result, status);
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
                inner.put(Text.STATUS.toString(), status.toString());
                inner.put(Text.RESULT.toString(), outputNode);
                return Map.<String, Object>of(userName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_USERS_WITH_ATTACHED_POLICIES, result, status);
        return status;
    }

}
