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

import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeContinuousBackupsRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeContinuousBackupsResponse;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.SSEDescription;

public class DynamoDBCheck implements CloudCheck {
    private List<String> allTableNames;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final DynamoDbAsyncClient dynamodb;

    public DynamoDBCheck(DataWriter writer, SharedDataProvider sharedDataProvider, DynamoDbAsyncClient dynamodb) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.dynamodb = dynamodb;
    }

    @Override
    public void runAllChecks() {
        allTableNames = sharedDataProvider.getAllTableNames().join();

        subCheckResults.clear();
        subCheckResults.addAll(
            Stream.of(
                wrapCheck(this::checkDynamoDBTableWithPointInTimeRecoveryDisabled,    AWSFinding.DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED, this::reportError),
                wrapCheck(this::checkDynamoDBTableWithDefaultEncryptionEnabled,       AWSFinding.DYNAMODB_TABLE_DEFAULT_ENCRYPTION_ENABLED, this::reportError)
            )
            .map(Supplier::get)
            .toList()
        );
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllTableNames()
            .thenCompose(tableNames -> {
                this.allTableNames = tableNames;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkDynamoDBTableWithPointInTimeRecoveryDisabled,    AWSFinding.DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED, this::reportError),
                    wrapCheck(this::checkDynamoDBTableWithDefaultEncryptionEnabled,       AWSFinding.DYNAMODB_TABLE_DEFAULT_ENCRYPTION_ENABLED, this::reportError)
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
}

