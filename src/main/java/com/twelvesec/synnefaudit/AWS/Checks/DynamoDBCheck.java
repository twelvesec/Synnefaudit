package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.applicationautoscaling.ApplicationAutoScalingAsyncClient;
import software.amazon.awssdk.services.applicationautoscaling.model.DescribeScalableTargetsRequest;
import software.amazon.awssdk.services.applicationautoscaling.model.DescribeScalableTargetsResponse;
import software.amazon.awssdk.services.applicationautoscaling.model.ServiceNamespace;
import software.amazon.awssdk.services.backup.BackupAsyncClient;
import software.amazon.awssdk.services.backup.model.ListProtectedResourcesRequest;
import software.amazon.awssdk.services.backup.model.ListProtectedResourcesResponse;
import software.amazon.awssdk.services.backup.model.ProtectedResource;
import software.amazon.awssdk.services.dax.model.Cluster;
import software.amazon.awssdk.services.dax.model.Node;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class DynamoDBCheck implements CloudCheck {
    private List<String> allTableNames;
    private List<Cluster> allDaxClusters;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final DynamoDbAsyncClient dynamodb;
    private static BackupAsyncClient backup;
    private static StsAsyncClient sts;
    private static ApplicationAutoScalingAsyncClient appAutoScaling;

    public DynamoDBCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                         DynamoDbAsyncClient dynamodb, BackupAsyncClient backup, StsAsyncClient sts,
                         ApplicationAutoScalingAsyncClient appAutoScaling) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.dynamodb = dynamodb;
        DynamoDBCheck.backup = backup;
        DynamoDBCheck.sts = sts;
        DynamoDBCheck.appAutoScaling = appAutoScaling;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllTableNames()
            .thenCompose(tableNames -> {
                this.allTableNames = tableNames;
                return sharedDataProvider.getAllDaxClusters();
            })
            .thenCompose(daxClusters -> {
                this.allDaxClusters = daxClusters;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkDynamoDBTableWithPointInTimeRecoveryDisabled,  AWSFinding.DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED, this::reportError),
                    wrapCheck(this::checkDynamoDBTableWithDefaultEncryptionEnabled,     AWSFinding.DYNAMODB_TABLE_DEFAULT_ENCRYPTION_ENABLED, this::reportError),
                    wrapCheck(this::checkDynamoDBEncryptionWithCMK,                     AWSFinding.DYNAMODB_ENCRYPTION_WITH_CMK, this::reportError),
                    wrapCheck(this::checkDaxEncryptionAtRest,                           AWSFinding.DAX_ENCRYPTION_AT_REST_ENABLED, this::reportError),
                    wrapCheck(this::checkDaxClustersEncryptionInTransitDisabled,        AWSFinding.DAX_ENCRYPTION_IN_TRANSIT_ENABLED, this::reportError),
                    wrapCheck(this::checkDaxClustersMultiAzDisabled,                    AWSFinding.DAX_CLUSTERS_MULTI_AZ, this::reportError),
                    wrapCheck(this::checkDynamoDBTablesAutoScalingDisabled,             AWSFinding.DYNAMODB_TABLE_AUTO_SCALING_ENABLED, this::reportError),
                    wrapCheck(this::checkDynamoDBTableDeletionProtectionDisabled,       AWSFinding.DYNAMODB_TABLE_DELETION_PROTECTION_ENABLED, this::reportError),
                    wrapCheck(this::checkDynamoDBTableInBackupPlan,                     AWSFinding.DYNAMODB_TABLE_IN_BACKUP_PLAN, this::reportError),
                    wrapCheck(this::checkDynamoDBTableCrossAccountAccess,               AWSFinding.DYNAMODB_TABLE_CROSS_ACCOUNT_ACCESS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkDynamoDBTableWithPointInTimeRecoveryDisabled() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED, 
                            Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allTableNames.stream()
            .map(tableName -> {
                Status s;
                ObjectNode r;
                try {
                    DescribeContinuousBackupsResponse response = dynamodb.describeContinuousBackups(
                        DescribeContinuousBackupsRequest.builder().tableName(tableName).build()
                    ).join();
                    String statusStr = response
                        .continuousBackupsDescription()
                        .pointInTimeRecoveryDescription() != null
                        ? response.continuousBackupsDescription()
                                .pointInTimeRecoveryDescription()
                                .pointInTimeRecoveryStatusAsString()
                        : "DISABLED";

                    s = !"ENABLED".equalsIgnoreCase(statusStr) ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(tableName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED, result, status);
        return status;
    }

    private Status checkDynamoDBTableWithDefaultEncryptionEnabled() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_DEFAULT_ENCRYPTION_ENABLED, 
                            Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allTableNames.stream()
            .map(tableName -> {
                Status s;
                ObjectNode r;
                try {
                    DescribeTableResponse response = dynamodb.describeTable(
                        DescribeTableRequest.builder().tableName(tableName).build()
                    ).join();
                    SSEDescription sse = response.table().sseDescription();
                    boolean violation = (sse == null
                                        || sse.statusAsString() == null
                                        || "DISABLED".equalsIgnoreCase(sse.statusAsString()));
                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(tableName, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_DEFAULT_ENCRYPTION_ENABLED, result, status);
        return status;
    }

    private Status checkDynamoDBEncryptionWithCMK() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_ENCRYPTION_WITH_CMK, 
                            Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allTableNames.stream()
            .map(tableName -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    DescribeTableResponse response = dynamodb.describeTable(
                        DescribeTableRequest.builder().tableName(tableName).build()
                    ).join();
                    
                    TableDescription table = response.table();
                    SSEDescription sseDescription = table.sseDescription();
                    boolean hasEncryptionEnabled = sseDescription != null 
                        && "ENABLED".equals(sseDescription.statusAsString());
                    
                    boolean usesCMK = hasEncryptionEnabled 
                        && "KMS".equals(sseDescription.sseTypeAsString())
                        && sseDescription.kmsMasterKeyArn() != null
                        && !sseDescription.kmsMasterKeyArn().contains("aws/dynamodb");
                    
                    s = usesCMK ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                    
                    if (!usesCMK) {
                        if (!hasEncryptionEnabled) {
                            r.put("reason", "Encryption not enabled for this table");
                        } else if (sseDescription.kmsMasterKeyArn() != null && sseDescription.kmsMasterKeyArn().contains("aws/dynamodb")) {
                            r.put("reason", "Using AWS managed key instead of CMK");
                        } else {
                            r.put("reason", "Not using CMK for encryption");
                        }
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.getText().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(tableName, inner);
            })
            .collect(Collectors.toList());
        
        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_ENCRYPTION_WITH_CMK, result, status);
        return status;
    }

    private Status checkDaxEncryptionAtRest() {
        if (allDaxClusters == null || allDaxClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.DAX_ENCRYPTION_AT_REST_ENABLED,
                    Text.NO_DAX_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDaxClusters.stream()
                .map(cluster -> {
                    boolean isEncrypted = cluster.sseDescription() != null
                            && "ENABLED".equalsIgnoreCase(cluster.sseDescription().statusAsString());
                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(cluster.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DAX_ENCRYPTION_AT_REST_ENABLED, result, status);
        return status;
    }

    private Status checkDaxClustersEncryptionInTransitDisabled() {
        if (allDaxClusters == null || allDaxClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.DAX_ENCRYPTION_IN_TRANSIT_ENABLED,
                    Text.NO_DAX_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDaxClusters.stream()
                .map(cluster -> {
                    String encryptionType = cluster.clusterEndpointEncryptionTypeAsString();
                    boolean isTlsEnabled = "TLS".equalsIgnoreCase(encryptionType);
                    Status s = isTlsEnabled ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(cluster.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DAX_ENCRYPTION_IN_TRANSIT_ENABLED, result, status);
        return status;
    }

    private Status checkDaxClustersMultiAzDisabled() {
        if (allDaxClusters == null || allDaxClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.DAX_CLUSTERS_MULTI_AZ,
                    Text.NO_DAX_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDaxClusters.stream()
                .map(cluster -> {
                    long uniqueAzCount = Optional.ofNullable(cluster.nodes())
                            .orElse(List.of())
                            .stream()
                            .map(Node::availabilityZone)
                            .filter(Objects::nonNull)
                            .distinct()
                            .count();
                    Status s = uniqueAzCount > 1 ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(cluster.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DAX_CLUSTERS_MULTI_AZ, result, status);
        return status;
    }

    private Status checkDynamoDBTablesAutoScalingDisabled() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_AUTO_SCALING_ENABLED,
                    Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allTableNames.stream()
                .map(tableName -> {
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeTableResponse response = dynamodb.describeTable(
                                DescribeTableRequest.builder().tableName(tableName).build()
                        ).join();
                        TableDescription table = response.table();

                        boolean isOnDemand = table.billingModeSummary() != null
                                && "PAY_PER_REQUEST".equalsIgnoreCase(table.billingModeSummary().billingModeAsString());
                        boolean isAutoScaled = isOnDemand;

                        if (!isOnDemand) {
                            DescribeScalableTargetsResponse targetsResponse = appAutoScaling.describeScalableTargets(
                                    DescribeScalableTargetsRequest.builder()
                                            .serviceNamespace(ServiceNamespace.DYNAMODB)
                                            .resourceIds("table/" + tableName)
                                            .build()
                            ).join();
                            isAutoScaled = targetsResponse.hasScalableTargets() && !targetsResponse.scalableTargets().isEmpty();
                        }
                        s = isAutoScaled ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(response.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(tableName, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_AUTO_SCALING_ENABLED, result, status);
        return status;
    }

    private Status checkDynamoDBTableDeletionProtectionDisabled() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_DELETION_PROTECTION_ENABLED,
                    Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allTableNames.stream()
                .map(tableName -> {
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeTableResponse response = dynamodb.describeTable(
                                DescribeTableRequest.builder().tableName(tableName).build()
                        ).join();
                        boolean isProtected = Boolean.TRUE.equals(response.table().deletionProtectionEnabled());

                        s = isProtected ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(response.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(tableName, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_DELETION_PROTECTION_ENABLED, result, status);
        return status;
    }

    private Status checkDynamoDBTableInBackupPlan() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_IN_BACKUP_PLAN,
                    Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> protectedResourceArns;
        try {
            ListProtectedResourcesResponse protectedResourcesResponse = backup.listProtectedResources(
                    ListProtectedResourcesRequest.builder().build()
            ).join();
            protectedResourceArns = protectedResourcesResponse.results().stream()
                    .filter(resource -> "DynamoDB".equalsIgnoreCase(resource.resourceType()))
                    .map(ProtectedResource::resourceArn)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_IN_BACKUP_PLAN,
                    Text.NO_PROTECTED_RESOURCES_FOUND.toString(), Status.FAIL_EXCEPTION);
            return Status.FAIL_EXCEPTION;
        }

        final Set<String> finalProtectedArns = protectedResourceArns;

        List<Map<String, Object>> result = allTableNames.stream()
                .map(tableName -> {
                    Status s;
                    ObjectNode r = MAPPER.createObjectNode();
                    try {
                        DescribeTableResponse response = dynamodb.describeTable(
                                DescribeTableRequest.builder().tableName(tableName).build()
                        ).join();
                        String tableArn = response.table().tableArn();
                        boolean isProtected = finalProtectedArns.contains(tableArn);
                        s = isProtected ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(response.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(tableName, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_IN_BACKUP_PLAN, result, status);
        return status;
    }

    private Status checkDynamoDBTableCrossAccountAccess() {
        if (allTableNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_CROSS_ACCOUNT_ACCESS,
                    Text.NO_DYNAMODB_TABLES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allTableNames.stream()
                .map(tableName -> {
                    Status s;
                    ObjectNode r = MAPPER.createObjectNode();
                    try {
                        DescribeTableResponse tableResponse = dynamodb.describeTable(
                                DescribeTableRequest.builder().tableName(tableName).build()
                        ).join();
                        String tableArn = tableResponse.table().tableArn();

                        try {
                            GetResourcePolicyResponse policyResponse = dynamodb.getResourcePolicy(
                                    GetResourcePolicyRequest.builder().resourceArn(tableArn).build()
                            ).join();
                            String policyJson = policyResponse.policy();
                            String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
                            boolean hasCrossAccountAccess = isCrossAccountPolicy(policyJson, accountId);

                            s = hasCrossAccountAccess ? Status.FAIL : Status.PASS;
                            r.put(Text.POLICY.toString(), policyJson != null ? policyJson : Text.NO_RESOURCE_POLICY_ATTACHED.toString());
                        } catch (PolicyNotFoundException | ResourceNotFoundException e) {
                            s = Status.PASS;
                            r.put(Text.POLICY.toString(), Text.NO_RESOURCE_POLICY_ATTACHED.toString());
                        }
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(tableName, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.DYNAMODB_TABLE_CROSS_ACCOUNT_ACCESS, result, status);
        return status;
    }

    private boolean isCrossAccountPolicy(String policyJson, String currentAccountId) {
        if (policyJson == null || policyJson.isBlank()) {
            return false;
        }
        try {
            JsonNode statements = MAPPER.readTree(policyJson).path("Statement");
            Iterator<JsonNode> iterator = statements.isArray() ? statements.elements() : List.of(statements).iterator();

            while (iterator.hasNext()) {
                JsonNode stmt = iterator.next();
                if ("Allow".equalsIgnoreCase(stmt.path("Effect").asText())) {
                    String principal = stmt.path("Principal").toString();
                    String accountRegex = ".*\\b(?!" + (currentAccountId != null ? currentAccountId : "") + ")\\d{12}\\b.*";
                    if (principal.contains("*") || principal.matches(accountRegex)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            return true; // Fail safe: flag unparseable policies for manual review
        }
        return false;
    }
}

