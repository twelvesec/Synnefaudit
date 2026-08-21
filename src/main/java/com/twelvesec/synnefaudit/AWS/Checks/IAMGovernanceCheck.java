package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.PaginatorHelper;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.accessanalyzer.AccessAnalyzerAsyncClient;
import software.amazon.awssdk.services.accessanalyzer.model.*;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.*;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class IAMGovernanceCheck implements CloudCheck {
    private List<AnalyzerSummary> allAnalyzers;
    private List<Role> allRoles;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final IamAsyncClient iam;
    private final AccessAnalyzerAsyncClient accessAnalyzer;
    private final StsAsyncClient sts;

    public IAMGovernanceCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                              IamAsyncClient iam, AccessAnalyzerAsyncClient accessAnalyzer, StsAsyncClient sts) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.iam = iam;
        this.accessAnalyzer = accessAnalyzer;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<AnalyzerSummary>> analyzers = sharedDataProvider.getAllAnalyzers()
                .exceptionally(ex -> null);
        CompletableFuture<List<Role>> roles = sharedDataProvider.getAllRoles()
                .exceptionally(ex -> null);

        return CompletableFuture.allOf(analyzers, roles)
                .thenCompose(v -> {
                    this.allAnalyzers = analyzers.join();
                    this.allRoles = roles.join();

                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkIAMRolesWithAdministratorAccessPolicyAttached, AWSFinding.IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED, this::reportError),
                            wrapCheck(this::checkIAMAccessAnalyzerDisabled,                     AWSFinding.IAM_ACCESS_ANALYZER_DISABLED, this::reportError),
                            wrapCheck(this::checkIAMAccessAnalyzerWithFindings,                 AWSFinding.IAM_ACCESS_ANALYZER_WITH_FINDINGS, this::reportError),
                            wrapCheck(this::checkCrossAccountRoleAssumption,                    AWSFinding.IAM_CROSS_ACCOUNT_READ_ONLY_ROLES, this::reportError),
                            wrapCheck(this::checkSecurityAuditRole,                             AWSFinding.SECURITY_AUDIT_ROLE_NOT_FOUND, this::reportError),
                            wrapCheck(this::checkSupportRole,                                   AWSFinding.SUPPORT_ROLE_NOT_FOUND, this::reportError)
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
            writer.addToBuffer(AWSFinding.IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED, Text.NO_IAM_ROLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allRoles.stream()
                .map(role -> {
                    String roleName = role.roleName();
                    Status s;
                    ArrayNode policiesArray = MAPPER.createArrayNode();
                    try {
                        List<AttachedPolicy> policies = iam.listAttachedRolePolicies(ListAttachedRolePoliciesRequest.builder().roleName(roleName).build()).join().attachedPolicies();
                        boolean hasAdmin = policies.stream().anyMatch(p -> "AdministratorAccess".equals(p.policyName()));
                        s = hasAdmin ? Status.FAIL : Status.PASS;
                        policies.forEach(p -> policiesArray.add(MAPPER.valueToTree(p.toBuilder())));
                        if (policies.isEmpty()) policiesArray.add(Text.NO_IAM_ROLE_POLICIES_FOUND.toString());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        policiesArray.add(Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), policiesArray);
                    return Map.<String, Object>of(roleName, inner);
                }).toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED, result, status);
        return status;
    }

    private Status checkIAMAccessAnalyzerDisabled() {
        if (allAnalyzers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_DISABLED, Text.NO_IAM_ACCESS_ANALYZER_FOUND.toString(), Status.FAIL);
            return Status.FAIL;
        }
        List<Map<String, Object>> result = allAnalyzers.stream().map(summary -> {
            Map<String,Object> inner = new HashMap<>();
            inner.put(Text.STATUS.toString(), Status.PASS);
            inner.put(Text.RESULT.toString(), MAPPER.valueToTree(summary.toBuilder()));
            return Map.<String, Object>of(summary.name(), inner);
        }).toList();

        writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_DISABLED, result, Status.PASS);
        return Status.PASS;
    }

    private Status checkIAMAccessAnalyzerWithFindings() {
        if (allAnalyzers.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_WITH_FINDINGS, Text.NO_IAM_ACCESS_ANALYZER_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }
        List<String> activeArns = allAnalyzers.stream().filter(a -> "ACTIVE".equalsIgnoreCase(a.statusAsString())).map(AnalyzerSummary::arn).toList();

        List<Map<String,Object>> result = activeArns.stream().map(arn -> {
            Status s;
            String r;
            try {
                ListFindingsResponse response = accessAnalyzer.listFindings(ListFindingsRequest.builder().analyzerArn(arn).build()).join();
                String findings = response.findings().stream().map(FindingSummary::id).collect(Collectors.joining(","));
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
        }).toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_ACCESS_ANALYZER_WITH_FINDINGS, result, status);
        return status;
    }

    private Status checkCrossAccountRoleAssumption() {
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
        if (allRoles.isEmpty()) {
            writer.addToBuffer(AWSFinding.IAM_CROSS_ACCOUNT_READ_ONLY_ROLES, Text.NO_IAM_ROLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allRoles.stream().map(role -> {
            String roleName = role.roleName();
            Status s;
            String r;
            ObjectNode policyNode;
            try {
                String raw = iam.getRole(GetRoleRequest.builder().roleName(roleName).build()).join().role().assumeRolePolicyDocument();
                policyNode = (ObjectNode) MAPPER.readTree(URLDecoder.decode(raw, StandardCharsets.UTF_8));
                ArrayNode statements = Optional.ofNullable(policyNode.get("Statement")).map(n -> n.isArray() ? (ArrayNode)n : MAPPER.createArrayNode().add(n)).orElseGet(MAPPER::createArrayNode);

                List<String> principals = StreamSupport.stream(statements.spliterator(), false).flatMap(stmt -> {
                    JsonNode p = stmt.at("/Principal/AWS");
                    if (p.isArray()) return StreamSupport.stream(p.spliterator(), false).map(JsonNode::asText);
                    return p.isTextual() ? Stream.of(p.asText()) : Stream.empty();
                }).toList();

                boolean hasCrossAccount = principals.stream().anyMatch(arn -> !arn.equals(String.format("arn:aws:iam::%s:root", accountId)) && !arn.endsWith(".amazonaws.com"));

                if (hasCrossAccount) {
                    s = Status.FAIL;
                    r = Text.CROSS_ACCOUNT_PRINCIPALS_FOUND.toString().concat(principals.stream()
                            .filter(arn -> !arn.equals(String.format("arn:aws:iam::%s:root", accountId)) && !arn.endsWith(".amazonaws.com"))
                            .distinct().collect(Collectors.joining(", "))
                    );
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
        }).toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.IAM_CROSS_ACCOUNT_READ_ONLY_ROLES, result, status);
        return status;
    }

    private Status checkSecurityAuditRole() {
        if (allRoles.isEmpty()) {
            writer.addToBuffer(AWSFinding.SECURITY_AUDIT_ROLE_NOT_FOUND,
                    Text.NO_IAM_ROLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allRoles.stream()
                .map(role -> {
                    Status s;
                    Object r;
                    try {
                        GetRoleResponse roleResponse = iam.getRole(
                                GetRoleRequest.builder().roleName(role.roleName()).build()
                        ).join();

                        List<AttachedPolicy> attachedPolicies = PaginatorHelper.collectPaginatedItems(
                                iam.listAttachedRolePoliciesPaginator(
                                        ListAttachedRolePoliciesRequest.builder().roleName(role.roleName()).build()
                                ),
                                ListAttachedRolePoliciesResponse::attachedPolicies
                        ).join();

                        boolean hasSecurityAuditPolicy = attachedPolicies.stream()
                                .anyMatch(policy ->
                                        "arn:aws:iam::aws:policy/SecurityAudit".equals(policy.policyArn()) ||
                                                policy.policyName().contains("SecurityAudit")
                                );
                        String trustPolicy = roleResponse.role().assumeRolePolicyDocument();
                        boolean hasProperTrust = isTrustPolicyValidForAudit(trustPolicy);
                        boolean isSecurityAuditRole = hasSecurityAuditPolicy && hasProperTrust;

                        if (role.roleName().toLowerCase().contains("security") ||
                                role.roleName().toLowerCase().contains("audit")) {
                            s = isSecurityAuditRole ? Status.PASS : Status.FAIL;

                            ObjectNode resultNode = MAPPER.createObjectNode();

                            ArrayNode policiesArray = resultNode.putArray("attachedPolicies");
                            attachedPolicies.forEach(policy -> {
                                ObjectNode policyNode = MAPPER.createObjectNode();
                                policyNode.put("policyArn", policy.policyArn());
                                policyNode.put("policyName", policy.policyName());
                                policiesArray.add(policyNode);
                            });

                            if (trustPolicy != null) {
                                try {
                                    String decodedTrustPolicy = URLDecoder.decode(trustPolicy, StandardCharsets.UTF_8);
                                    JsonNode trustPolicyNode = MAPPER.readTree(decodedTrustPolicy);
                                    resultNode.put("trustPolicy", trustPolicyNode);
                                } catch (Exception e) {
                                    resultNode.put("trustPolicy", trustPolicy);
                                }
                            } else {
                                resultNode.putNull("trustPolicy");
                            }

                            resultNode.put("hasSecurityAuditPolicy", hasSecurityAuditPolicy);
                            resultNode.put("hasProperTrust", hasProperTrust);
                            r = resultNode;
                        } else {
                            s = Status.NOT_APPLICABLE;
                            r = role.roleName();
                        }

                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        ObjectNode errorNode = MAPPER.createObjectNode();
                        errorNode.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                        r = errorNode;
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(role.roleName(), inner);
                })
                .toList();

        boolean hasException = false;
        boolean hasFail = false;
        boolean hasPass = false;

        for (Map<String, Object> map : result) {
            Map<String, Object> inner = (Map<String, Object>) map.values().iterator().next();
            Status s = (Status) inner.get(Text.STATUS.toString());
            if (s == Status.FAIL_EXCEPTION) {
                hasException = true;
            } else if (s == Status.FAIL) {
                hasFail = true;
            } else if (s == Status.PASS) {
                hasPass = true;
            }
        }

        Status status;
        if (hasException) {
            status = Status.FAIL_EXCEPTION;
        } else if (hasFail) {
            status = Status.FAIL;
        } else if (hasPass) {
            status = Status.PASS;
        } else {
            status = Status.FAIL;
        }
        writer.addToBuffer(AWSFinding.SECURITY_AUDIT_ROLE_NOT_FOUND, result, status);
        return status;
    }

    private boolean isTrustPolicyValidForAudit(String trustPolicy) throws JsonProcessingException {
        if (trustPolicy == null || trustPolicy.isEmpty()) return false;
        JsonNode policyNode = MAPPER.readTree(URLDecoder.decode(trustPolicy, StandardCharsets.UTF_8));
        JsonNode statements = policyNode.path("Statement");
        if (statements.isArray()) {
            for (JsonNode stmt : statements) {
                if (stmt.path("Action").asText("").contains("sts:AssumeRole") && (stmt.path("Principal").has("AWS") || stmt.path("Principal").has("Service"))) return true;
            }
        }
        return false;
    }

    private Status checkSupportRole() {
        if (allRoles.isEmpty()) {
            writer.addToBuffer(AWSFinding.SUPPORT_ROLE_NOT_FOUND,
                    Text.NO_IAM_ROLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allRoles.stream()
                .map(role -> {
                    Status s;
                    Object r;
                    try {
                        List<AttachedPolicy> attachedPolicies = PaginatorHelper.collectPaginatedItems(
                                iam.listAttachedRolePoliciesPaginator(
                                        ListAttachedRolePoliciesRequest.builder().roleName(role.roleName()).build()
                                ),
                                ListAttachedRolePoliciesResponse::attachedPolicies
                        ).join();

                        boolean hasSupportPolicy = attachedPolicies.stream()
                                .anyMatch(policy ->
                                        "arn:aws:iam::aws:policy/AWSSupportAccess".equals(policy.policyArn()) ||
                                                policy.policyName().contains("AWSSupportAccess")
                                );
                        GetRoleResponse roleResponse = iam.getRole(
                                GetRoleRequest.builder().roleName(role.roleName()).build()
                        ).join();

                        String trustPolicy = roleResponse.role().assumeRolePolicyDocument();
                        boolean hasSupportTrust = isTrustPolicyValidForSupport(trustPolicy);
                        boolean isSupportRole = hasSupportPolicy && hasSupportTrust;

                        if (role.roleName().toLowerCase().contains("support") ||
                                role.roleName().toLowerCase().contains("aws-support")) {
                            s = isSupportRole ? Status.PASS : Status.FAIL;

                            ObjectNode resultNode = MAPPER.createObjectNode();

                            ArrayNode policiesArray = resultNode.putArray("attachedPolicies");
                            attachedPolicies.forEach(policy -> {
                                ObjectNode policyNode = MAPPER.createObjectNode();
                                policyNode.put("policyArn", policy.policyArn());
                                policyNode.put("policyName", policy.policyName());
                                policiesArray.add(policyNode);
                            });

                            if (trustPolicy != null) {
                                try {
                                    String decodedTrustPolicy = URLDecoder.decode(trustPolicy, StandardCharsets.UTF_8);
                                    JsonNode trustPolicyNode = MAPPER.readTree(decodedTrustPolicy);
                                    resultNode.set("trustPolicy", trustPolicyNode);
                                } catch (Exception e) {
                                    resultNode.put("trustPolicy", trustPolicy);
                                }
                            } else {
                                resultNode.putNull("trustPolicy");
                            }

                            resultNode.put("hasAWSSupportAccessPolicy", hasSupportPolicy);
                            resultNode.put("hasProperTrustForSupport", hasSupportTrust);
                            r = resultNode;
                        } else {
                            s = Status.NOT_APPLICABLE;
                            r = role.roleName();
                        }

                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        ObjectNode errorResult = MAPPER.createObjectNode();
                        errorResult.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                        r = errorResult;
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(role.roleName(), inner);
                })
                .toList();

        boolean hasException = false;
        boolean hasFail = false;
        boolean hasPass = false;

        for (Map<String, Object> map : result) {
            Map<String, Object> inner = (Map<String, Object>) map.values().iterator().next();
            Status s = (Status) inner.get(Text.STATUS.toString());
            if (s == Status.FAIL_EXCEPTION) {
                hasException = true;
            } else if (s == Status.FAIL) {
                hasFail = true;
            } else if (s == Status.PASS) {
                hasPass = true;
            }
        }

        Status status;
        if (hasException) {
            status = Status.FAIL_EXCEPTION;
        } else if (hasFail) {
            status = Status.FAIL;
        } else if (hasPass) {
            status = Status.PASS;
        } else {
            status = Status.FAIL;
        }

        writer.addToBuffer(AWSFinding.SUPPORT_ROLE_NOT_FOUND, result, status);
        return status;
    }

    private boolean isTrustPolicyValidForSupport(String trustPolicy) throws JsonProcessingException {
        if (trustPolicy == null || trustPolicy.isEmpty()) return false;
        JsonNode policyNode = MAPPER.readTree(URLDecoder.decode(trustPolicy, StandardCharsets.UTF_8));
        JsonNode statements = policyNode.path("Statement");
        if (statements.isArray()) {
            for (JsonNode stmt : statements) {
                if (stmt.path("Action").asText("").contains("sts:AssumeRole") && stmt.path("Principal").has("Service")) {
                    JsonNode servicePrincipal = stmt.path("Principal").path("Service");
                    if (servicePrincipal.isTextual() && servicePrincipal.asText().equals("support.amazonaws.com")) return true;
                    if (servicePrincipal.isArray()) {
                        for (JsonNode service : servicePrincipal) {
                            if (service.asText("").equals("support.amazonaws.com")) return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}