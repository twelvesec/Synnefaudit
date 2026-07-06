package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class IAMPolicyCheck implements CloudCheck {
    private List<Role> allRoles;
    private List<User> allUsers;
    private List<Policy> allPolicies;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;

    public IAMPolicyCheck(DataWriter writer, SharedDataProvider sharedDataProvider, IamAsyncClient iam) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.iam = iam;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllRoles()
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
                    wrapCheck(this::checkIAMPolicyAllowsPrivilegeEscalation,                    AWSFinding.IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION, this::reportError),
                    wrapCheck(this::checkOverlyPermissiveManagedPolicies,                       AWSFinding.IAM_OVERLY_PERMISSIVE_MANAGED_POLICIES, this::reportError),
                    wrapCheck(this::checkIAMInlinePoliciesCloudTrailFullAccess,                 AWSFinding.IAM_INLINE_POLICY_CLOUDTRAIL_FULL_ACCESS, this::reportError),
                    wrapCheck(this::checkIAMInlinePoliciesKMSFullAccess,                        AWSFinding.IAM_INLINE_POLICY_KMS_FULL_ACCESS, this::reportError),
                    wrapCheck(this::checkIAMInlinePoliciesAdminAccess,                          AWSFinding.IAM_INLINE_POLICY_ADMIN_ACCESS, this::reportError),
                    wrapCheck(this::checkIAMCustomerManagedPoliciesAdminAccess,                 AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_ADMIN_ACCESS, this::reportError),
                    wrapCheck(this::checkIAMCustomerManagedPoliciesCloudTrailFullAccess,        AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_CLOUDTRAIL_FULL_ACCESS, this::reportError),
                    wrapCheck(this::checkIAMCustomerManagedPoliciesKMSFullAccess,               AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_KMS_FULL_ACCESS, this::reportError),
                    wrapCheck(this::checkIAMCustomerManagedPoliciesPermissiveRoleAssumption,    AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_PERMISSIVE_ROLE_ASSUMPTION, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkIAMPolicyAllowsPrivilegeEscalation() {
        if (allPolicies.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION,
                    Text.NO_IAM_POLICIES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> dangerousActions = Set.of(
            "iam:PassRole", "iam:CreatePolicyVersion", "iam:PutUserPolicy", "iam:PutGroupPolicy",
            "iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:AddUserToGroup",
            "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAssumeRolePolicy", "iam:*"
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
                            : (stmtsNode.isArray() ? (ArrayNode) stmtsNode : MAPPER.createArrayNode().add(stmtsNode));

                    List<String> actionsInPolicy = StreamSupport.stream(statements.spliterator(), false)
                        .filter(stmt -> "Allow".equalsIgnoreCase(stmt.get("Effect").asText()))
                        .flatMap(stmt -> {
                            JsonNode act = stmt.get("Action");
                            if (act == null) return Stream.of(Text.NULL_VALUE.getText());
                            if (act.isArray()) return StreamSupport.stream(act.spliterator(), false).map(JsonNode::asText);
                            return Stream.of(act.asText());
                        })
                        .toList();

                    boolean hasDangerousActions = actionsInPolicy.stream().anyMatch(dangerousActions::contains);

                    if (hasDangerousActions) {
                        s = Status.FAIL;
                        r = String.format("%s%s", Text.ALLOWED_DANGEROUS_ACTIONS.toString(),
                                actionsInPolicy.stream().filter(dangerousActions::contains).distinct().collect(Collectors.joining(", ")));
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

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), resultNode);
                return Map.<String, Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION, result, status);
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
                    String vid = iam.getPolicy(GetPolicyRequest.builder().policyArn(arn).build()).join().policy().defaultVersionId();
                    String rawVersion = iam.getPolicyVersion(GetPolicyVersionRequest.builder().policyArn(arn).versionId(vid).build()).join().policyVersion().document();

                    String jsonVersion = URLDecoder.decode(rawVersion, StandardCharsets.UTF_8);
                    versionNode = MAPPER.readTree(jsonVersion);

                    JsonNode stmtsNode = versionNode.get("Statement");
                    ArrayNode statements = (stmtsNode == null) ? MAPPER.createArrayNode() : (stmtsNode.isArray() ? (ArrayNode) stmtsNode : MAPPER.createArrayNode().add(stmtsNode));

                    boolean wild = StreamSupport.stream(statements.spliterator(), false)
                        .filter(stmt -> "Allow".equalsIgnoreCase(stmt.path("Effect").asText()))
                        .flatMap(stmt -> {
                            JsonNode r = stmt.get("Resource");
                            if (r == null) return Stream.empty();
                            if (r.isArray()) return StreamSupport.stream(r.spliterator(), false).map(JsonNode::asText);
                            return Stream.of(r.asText());
                        })
                        .anyMatch("*"::equals);

                    ListEntitiesForPolicyResponse entities = iam.listEntitiesForPolicy(ListEntitiesForPolicyRequest.builder().policyArn(arn).build()).join();

                    ArrayNode usersNode = MAPPER.valueToTree(entities.policyUsers().stream().map(PolicyUser::toString).toList());
                    ArrayNode rolesNode = MAPPER.valueToTree(entities.policyRoles().stream().map(PolicyRole::toString).toList());
                    ArrayNode groupsNode = MAPPER.valueToTree(entities.policyGroups().stream().map(PolicyGroup::toString).toList());

                    entitiesNode.set(Text.POLICYUSERS.toString(), usersNode);
                    entitiesNode.set(Text.POLICYROLES.toString(), rolesNode);
                    entitiesNode.set(Text.POLICYGROUPS.toString(), groupsNode);

                    boolean attached = !usersNode.isEmpty() || !rolesNode.isEmpty() || !groupsNode.isEmpty();

                    if (wild && attached) {
                        s = Status.FAIL;
                        msg = Text.POLICY_OVERSCOPED_AND_ATTACHED.toString();
                    } else {
                        s = Status.PASS;
                        msg = wild ? Text.POLICY_OVERSCOPED_BUT_UNATTACHED.toString() : Text.POLICY_NOT_OVERSCOPED.toString();
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

    private Status checkIAMInlinePoliciesCloudTrailFullAccess() { return checkInlinePolicyPrivileges(AWSFinding.IAM_INLINE_POLICY_CLOUDTRAIL_FULL_ACCESS, "cloudtrail:*"); }
    private Status checkIAMInlinePoliciesKMSFullAccess() { return checkInlinePolicyPrivileges(AWSFinding.IAM_INLINE_POLICY_KMS_FULL_ACCESS, "kms:*"); }
    private Status checkIAMInlinePoliciesAdminAccess() { return checkInlinePolicyPrivileges(AWSFinding.IAM_INLINE_POLICY_ADMIN_ACCESS, "*"); }

    private Status checkInlinePolicyPrivileges(AWSFinding finding, String targetAction) {
        if (allRoles.isEmpty() && allUsers.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_IAM_USERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Stream<Map<String, Object>> roleStream = allRoles.stream().map(role ->
            processIdentityInlinePolicies(role.roleName(), role.arn(), targetAction,
                name -> iam.listRolePolicies(ListRolePoliciesRequest.builder().roleName(name).build()).join().policyNames(),
                (roleName, polName) -> iam.getRolePolicy(GetRolePolicyRequest.builder().roleName(roleName).policyName(polName).build()).join().policyDocument()
            )
        );

        Stream<Map<String, Object>> userStream = allUsers.stream().map(user ->
            processIdentityInlinePolicies(user.userName(), user.arn(), targetAction,
                name -> iam.listUserPolicies(ListUserPoliciesRequest.builder().userName(name).build()).join().policyNames(),
                (userName, polName) -> iam.getUserPolicy(GetUserPolicyRequest.builder().userName(userName).policyName(polName).build()).join().policyDocument()
            )
        );

        List<Map<String, Object>> result = Stream.concat(roleStream, userStream).toList();
        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Map<String, Object> processIdentityInlinePolicies(
            String identityName, String identityArn, String targetAction,
            java.util.function.Function<String, List<String>> policyLister,
            java.util.function.BiFunction<String, String, String> policyFetcher) {

        Status identityStatus = Status.PASS;
        ArrayNode policiesArray = MAPPER.createArrayNode();

        try {
            List<String> policyNames = policyLister.apply(identityName);

            if (policyNames.isEmpty()) {
                policiesArray.add(MAPPER.createObjectNode().put(Text.MESSAGE.toString(), Text.No_INLINE_POLICIES.toString()));
            } else {
                for (String policyName : policyNames) {
                    ObjectNode policyNode = MAPPER.createObjectNode();
                    policyNode.put(Text.POLICY.toString(), policyName);

                    try {
                        String doc = policyFetcher.apply(identityName, policyName);
                        String decodedDoc = URLDecoder.decode(doc, StandardCharsets.UTF_8);
                        policyNode.set(Text.POLICYDOC.toString(), MAPPER.readTree(decodedDoc));

                        if (hasFullAccess(doc, targetAction)) {
                            identityStatus = Status.FAIL;
                            policyNode.put(Text.STATUS.toString(), Status.FAIL.toString());
                        } else {
                            policyNode.put(Text.STATUS.toString(), Status.PASS.toString());
                        }
                    } catch (Exception e) {
                        identityStatus = Status.FAIL_EXCEPTION;
                        policyNode.put(Text.STATUS.toString(), Status.FAIL_EXCEPTION.toString());
                        policyNode.put(Text.ERROR.toString(), e.getMessage());
                    }
                    policiesArray.add(policyNode);
                }
            }
        } catch (Exception e) {
            identityStatus = Status.FAIL_EXCEPTION;
            policiesArray.add(MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage())));
        }

        Map<String, Object> inner = new HashMap<>();
        inner.put(Text.STATUS.toString(), identityStatus);
        inner.put(Text.RESULT.toString(), policiesArray);
        return Map.of(identityArn, inner);
    }

    private boolean hasFullAccess(String policyDocJson, String targetAction) throws JsonProcessingException {
        String decoded = URLDecoder.decode(policyDocJson, StandardCharsets.UTF_8);
        JsonNode root = MAPPER.readTree(decoded);
        JsonNode statementNode = root.get("Statement");
        if (statementNode == null) return false;
        if (statementNode.isArray()) {
            for (JsonNode statement : statementNode) {
                if (checkStatementForAction(statement, targetAction)) return true;
            }
        } else if (statementNode.isObject()) {
            return checkStatementForAction(statementNode, targetAction);
        }
        return false;
    }

    private boolean checkStatementForAction(JsonNode statement, String targetAction) {
        JsonNode effectNode = statement.get("Effect");
        if (effectNode == null || !"Allow".equalsIgnoreCase(effectNode.asText())) return false;
        JsonNode actionNode = statement.get("Action");
        JsonNode resourceNode = statement.get("Resource");
        if (actionNode == null || resourceNode == null) return false;
        return jsonNodeContains(actionNode, targetAction) && jsonNodeContains(resourceNode, "*");
    }

    private boolean jsonNodeContains(JsonNode node, String value) {
        if (node.isTextual()) return value.equalsIgnoreCase(node.asText());
        if (node.isArray()) {
            for (JsonNode element : node) {
                if (element.isTextual() && value.equalsIgnoreCase(element.asText())) return true;
            }
        }
        return false;
    }

    private Status checkIAMCustomerManagedPoliciesAdminAccess() { return checkManagedPolicyPrivileges(AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_ADMIN_ACCESS, "*"); }
    private Status checkIAMCustomerManagedPoliciesCloudTrailFullAccess() { return checkManagedPolicyPrivileges(AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_CLOUDTRAIL_FULL_ACCESS, "cloudtrail:*"); }
    private Status checkIAMCustomerManagedPoliciesKMSFullAccess() { return checkManagedPolicyPrivileges(AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_KMS_FULL_ACCESS, "kms:*"); }
    private Status checkIAMCustomerManagedPoliciesPermissiveRoleAssumption() { return checkManagedPolicyPrivileges(AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_PERMISSIVE_ROLE_ASSUMPTION, "sts:AssumeRole"); }

    private Status checkManagedPolicyPrivileges(AWSFinding finding, String targetAction) {
        List<Policy> customPolicies = allPolicies.stream()
            .filter(p -> p.arn() != null && !p.arn().startsWith("arn:aws:iam::aws:policy"))
            .toList();

        if (customPolicies.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_IAM_CUSTOMER_MANAGED_POLICIES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = customPolicies.stream().map(policy -> {
            String policyArn = policy.arn();
            Status policyStatus = Status.PASS;
            ObjectNode policyNode = MAPPER.createObjectNode();
            policyNode.put(Text.POLICY.toString(), policy.policyName());

            try {
                String doc = iam.getPolicyVersion(GetPolicyVersionRequest.builder().policyArn(policyArn).versionId(policy.defaultVersionId()).build()).join().policyVersion().document();
                String decodedDoc = URLDecoder.decode(doc, StandardCharsets.UTF_8);
                JsonNode policyJsonNode = MAPPER.readTree(decodedDoc);
                policyNode.set(Text.POLICYDOC.toString(), policyJsonNode);

                boolean isOverlyPermissive = (finding == AWSFinding.IAM_CUSTOMER_MANAGED_POLICY_PERMISSIVE_ROLE_ASSUMPTION)
                        ? hasPermissiveRoleAssumption(policyJsonNode) : hasFullAccess(doc, targetAction);

                if (isOverlyPermissive) {
                    policyStatus = Status.FAIL;
                    policyNode.put(Text.STATUS.toString(), Status.FAIL.toString());
                } else {
                    policyNode.put(Text.STATUS.toString(), Status.PASS.toString());
                }
            } catch (Exception e) {
                policyStatus = Status.FAIL_EXCEPTION;
                policyNode.put(Text.STATUS.toString(), Status.FAIL_EXCEPTION.toString());
                policyNode.put(Text.ERROR.toString(), e.getMessage());
            }
            Map<String, Object> inner = new HashMap<>();
            inner.put(Text.STATUS.toString(), policyStatus);
            inner.put(Text.RESULT.toString(), MAPPER.createArrayNode().add(policyNode));
            return Map.<String, Object>of(policyArn, inner);
        }).toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private boolean hasPermissiveRoleAssumption(JsonNode policyJson) {
        JsonNode statementNode = policyJson.path("Statement");
        if (statementNode.isMissingNode()) return false;
        if (statementNode.isArray()) {
            for (JsonNode statement : statementNode) {
                if (evaluateStatementForPermissiveRoleAssumption(statement)) return true;
            }
        } else {
            return evaluateStatementForPermissiveRoleAssumption(statementNode);
        }
        return false;
    }

    private boolean evaluateStatementForPermissiveRoleAssumption(JsonNode statement) {
        if (!"Allow".equalsIgnoreCase(statement.path("Effect").asText())) return false;
        JsonNode resourceNode = statement.path("Resource");
        if (resourceNode.isMissingNode() || !hasWildcard(resourceNode)) return false;
        JsonNode actionNode = statement.path("Action");
        if (actionNode.isMissingNode()) return false;

        Set<String> targetActions = Set.of("sts:assumerole", "sts:*", "*");
        if (actionNode.isArray()) {
            for (JsonNode action : actionNode) {
                if (targetActions.contains(action.asText().toLowerCase())) return true;
            }
        } else {
            return targetActions.contains(actionNode.asText().toLowerCase());
        }
        return false;
    }

    private boolean hasWildcard(JsonNode resourceNode) {
        if (resourceNode.isArray()) {
            for (JsonNode res : resourceNode) {
                if (res.asText().contains("*")) return true;
            }
        } else {
            return resourceNode.asText().contains("*");
        }
        return false;
    }
}