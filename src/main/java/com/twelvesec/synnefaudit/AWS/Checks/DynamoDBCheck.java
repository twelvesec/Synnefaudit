package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.dax.model.Cluster;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class DynamoDBCheck implements CloudCheck {
    private List<String> allTableNames;
    private List<Cluster> allDaxClusters;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final DynamoDbAsyncClient dynamodb;

    public DynamoDBCheck(DataWriter writer, SharedDataProvider sharedDataProvider, DynamoDbAsyncClient dynamodb) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.dynamodb = dynamodb;
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
                    wrapCheck(this::checkDaxEncryptionAtRest,                           AWSFinding.DAX_ENCRYPTION_AT_REST_ENABLED, this::reportError)
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
                        } else if (sseDescription != null && sseDescription.kmsMasterKeyArn() != null
                                && sseDescription.kmsMasterKeyArn().contains("aws/dynamodb")) {
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
        AWSFinding finding = AWSFinding.DAX_ENCRYPTION_AT_REST_ENABLED;
        if (allDaxClusters == null || allDaxClusters.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_DAX_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDaxClusters.stream()
                .map(cluster -> {
                    String clusterName = cluster.clusterName();
                    Status s;
                    ObjectNode resultNode = MAPPER.createObjectNode();
                    resultNode.put("clusterName", clusterName);

                    boolean isEncrypted = cluster.sseDescription() != null
                            && "ENABLED".equalsIgnoreCase(String.valueOf(cluster.sseDescription().status()));

                    if (cluster.sseDescription() != null) {
                        resultNode.put("sseStatus", MAPPER.valueToTree(cluster.toBuilder()));
                    } else {
                        resultNode.putNull("sseStatus");
                    }
                    s = isEncrypted ? Status.PASS : Status.FAIL;

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), resultNode);
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }
}

