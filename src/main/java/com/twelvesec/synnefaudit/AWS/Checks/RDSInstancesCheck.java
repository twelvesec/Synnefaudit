package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.PaginatorHelper;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.rds.RdsAsyncClient;
import software.amazon.awssdk.services.rds.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class RDSInstancesCheck implements CloudCheck {
    private List<DBInstance> allDbInstances;
    private List<DBSnapshot> allDbSnapshots;
    private List<DBClusterSnapshot> allDbClusterSnapshots;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final RdsAsyncClient rds;
    private final JsonNode config;
    private static Map<String, String> ENGINE_DEFAULT_USERNAMES = new HashMap<>();

    public RDSInstancesCheck(DataWriter writer, SharedDataProvider sharedDataProvider, RdsAsyncClient rds, JsonNode config) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.rds = rds;
        this.config = config;
        ENGINE_DEFAULT_USERNAMES = getStringMap(config.path("engine_default_usernames"));
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<DBInstance>> dbInstances = sharedDataProvider.getAllDBInstances()
                .exceptionally(ex -> null);
        CompletableFuture<List<DBSnapshot>> dbSnapshots = sharedDataProvider.getAllDBSnapshots()
                .exceptionally(ex -> null);
        CompletableFuture<List<DBClusterSnapshot>> dbClusterSnapshots = sharedDataProvider.getAllDBClusterSnapshots()
                .exceptionally(ex -> null);

        return CompletableFuture.allOf(dbInstances, dbSnapshots, dbClusterSnapshots)
                .thenCompose(v -> {
                    this.allDbInstances = dbInstances.join();
                    this.allDbSnapshots = dbSnapshots.join();
                    this.allDbClusterSnapshots = dbClusterSnapshots.join();

                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkRDSInstancesWithMultiAvailabilityZoneDisabled, AWSFinding.RDS_MULTI_AZ_DISABLED, this::reportError),
                            wrapCheck(this::checkRDSInstancesWithIAMAuthenticationDisabled,    AWSFinding.RDS_IAM_AUTHENTICATION_DISABLED, this::reportError),
                            wrapCheck(this::checkRDSInstancesWithAutomatedBackupsDisabled,     AWSFinding.RDS_AUTOMATED_BACKUPS_DISABLED, this::reportError),
                            wrapCheck(this::checkRDSInstancesWithDeletionProtectionDisabled,    AWSFinding.RDS_DELETION_PROTECTION_DISABLED, this::reportError),
                            wrapCheck(this::checkRDSInstancesWithEnhancedMonitoringDisabled,    AWSFinding.RDS_ENHANCED_MONITORING_DISABLED, this::reportError),
                            wrapCheck(this::checkRDSDeprecatedEngineVersions,                   AWSFinding.RDS_DEPRECATED_ENGINE_VERSIONS, this::reportError),
                            wrapCheck(this::checkRDSMissingEventCategories,                     AWSFinding.RDS_EVENT_SUBSCRIPTIONS_MISSING_CATEGORIES, this::reportError),
                            wrapCheck(this::checkRDSInstancesUsingDefaultMasterUsername,        AWSFinding.RDS_INSTANCES_USING_DEFAULT_MASTER_USERNAME, this::reportError),
                            wrapCheck(this::checkRDSClientConnectionEncryption,                 AWSFinding.RDS_CLIENT_CONNECTION_ENCRYPTION, this::reportError),
                            wrapCheck(this::checkRDSCloudWatchLogsIntegration,                  AWSFinding.RDS_CLOUDWATCH_LOGS_INTEGRATION, this::reportError),
                            wrapCheck(this::checkRDSSnapshotsEncryption,                        AWSFinding.RDS_SNAPSHOTS_ENCRYPTION, this::reportError),
                            wrapCheck(this::checkRDSClusterSnapshotsEncryption,                 AWSFinding.RDS_CLUSTER_SNAPSHOTS_ENCRYPTION, this::reportError)
                    );
                    return runChecksInList(checksList, writer);
                });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkRDSInstancesWithMultiAvailabilityZoneDisabled() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_MULTI_AZ_DISABLED, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceArn", db.dbInstanceArn())
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("availabilityZone", db.availabilityZone())
                    .put("dbClusterIdentifier", db.dbClusterIdentifier())
                    .put("dbInstanceStatus", db.dbInstanceStatus());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), !db.multiAZ() ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_MULTI_AZ_DISABLED, result, status);
        return status;
    }

    private Status checkRDSInstancesWithIAMAuthenticationDisabled() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_IAM_AUTHENTICATION_DISABLED, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                Status s = !db.iamDatabaseAuthenticationEnabled() ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceArn", db.dbInstanceArn())
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("iamDatabaseAuthenticationEnabled", db.iamDatabaseAuthenticationEnabled())
                    .put("dbInstanceStatus", db.dbInstanceStatus());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_IAM_AUTHENTICATION_DISABLED, result, status);
        return status;
    }

    private Status checkRDSInstancesWithAutomatedBackupsDisabled() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_AUTOMATED_BACKUPS_DISABLED, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                Status s = db.backupRetentionPeriod() == 0 ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceArn", db.dbInstanceArn())
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("backupRetentionPeriod", db.backupRetentionPeriod())
                    .put("dbInstanceStatus", db.dbInstanceStatus());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_AUTOMATED_BACKUPS_DISABLED, result, status);
        return status;
    }

    private Status checkRDSInstancesWithDeletionProtectionDisabled() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_DELETION_PROTECTION_DISABLED, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                Status s = !db.deletionProtection() ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceArn", db.dbInstanceArn())
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("backupRetentionPeriod", db.backupRetentionPeriod())
                    .put("dbInstanceStatus", db.dbInstanceStatus());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_DELETION_PROTECTION_DISABLED, result, status);
        return status;
    }

    private Status checkRDSInstancesWithEnhancedMonitoringDisabled() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_ENHANCED_MONITORING_DISABLED, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                Status s = db.monitoringInterval() == 0 ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceArn", db.dbInstanceArn())
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("monitoringInterval", db.monitoringInterval())
                    .put("dbInstanceStatus", db.dbInstanceStatus());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_ENHANCED_MONITORING_DISABLED, result, status);
        return status;
    }

    private Status checkRDSDeprecatedEngineVersions() { 
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_DEPRECATED_ENGINE_VERSIONS, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> deprecatedVersions = PaginatorHelper.collectPaginatedItems(
                rds.describeDBEngineVersionsPaginator(
                        DescribeDbEngineVersionsRequest.builder().build()),
                DescribeDbEngineVersionsResponse::dbEngineVersions
            ).join()
            .stream()
            .filter(ver -> "DEPRECATED".equalsIgnoreCase(ver.status()))
            .map(DBEngineVersion::engineVersion)
            .collect(Collectors.toSet());

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                boolean isDeprecated = deprecatedVersions.contains(db.engineVersion());
                Status s = isDeprecated ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceArn", db.dbInstanceArn())
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("engine", db.engine())
                    .put("engineVersion", db.engineVersion())
                    .put("dbInstanceStatus", db.dbInstanceStatus());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_DEPRECATED_ENGINE_VERSIONS, result, status);
        return status;
    }

    private Status checkRDSMissingEventCategories() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_EVENT_SUBSCRIPTIONS_MISSING_CATEGORIES, 
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<String> required = List.of("configuration change", "failure");
        DescribeEventSubscriptionsResponse response = rds.describeEventSubscriptions().join();
        List<EventSubscription> subscriptions = response.eventSubscriptionsList();
        
        if (subscriptions.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_EVENT_SUBSCRIPTIONS_MISSING_CATEGORIES,
                            Text.NO_RDS_EVENT_SUBSCRIPTIONS_FOUND, Status.FAIL);
            return Status.FAIL;
        }

        List<Map<String,Object>> result = subscriptions.stream()
            .map(subscription -> {
                List<String> subscribed = subscription.eventCategoriesList();
                List<String> missing = required.stream()
                    .filter(cat -> !subscribed.contains(cat))
                    .toList();

                Status s = missing.isEmpty() ? Status.PASS : Status.FAIL;
                ObjectNode r = MAPPER.valueToTree(subscription.toBuilder());

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.MESSAGE.toString(), Text.MISSING_EVENT_SUBSCRIPTIONS.toString().concat(String.join(", ", missing)));
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(subscription.custSubscriptionId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_EVENT_SUBSCRIPTIONS_MISSING_CATEGORIES, result,  status);
        return status;
    }

    private Status checkRDSInstancesUsingDefaultMasterUsername() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_INSTANCES_USING_DEFAULT_MASTER_USERNAME,
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Map<String, String> engineDefaults = allDbInstances.stream()
            .map(DBInstance::engine)
            .distinct()
            .collect(Collectors.toMap(
                Function.identity(),
                engine -> ENGINE_DEFAULT_USERNAMES.getOrDefault(engine, "admin")
            ));

        List<Map<String,Object>> result = allDbInstances.stream()
            .map(db -> {
                String engine = db.engine();
                String defaultUsername = engineDefaults.get(engine);
                boolean violation = defaultUsername.equals(db.masterUsername());
                Status s = violation ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("dbInstanceIdentifier", db.dbInstanceIdentifier())
                    .put("defaultUsername", defaultUsername)
                    .put("engine", engine)
                    .put("masterUsername", db.masterUsername())
                    .put("dbName", db.dbName())
                    .put("availabilityZone", db.availabilityZone());
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_INSTANCES_USING_DEFAULT_MASTER_USERNAME, result, status);
        return status;
    }

    private Status checkRDSClientConnectionEncryption() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_CLIENT_CONNECTION_ENCRYPTION,
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<String> enginesToCheck = getStringList(config.path("engines_to_check"));

        List<Map<String, Object>> result = allDbInstances.stream()
            .filter(instance -> enginesToCheck.contains(instance.engine()))
            .map(db -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                try {
                    DescribeDbParametersRequest paramsRequest = DescribeDbParametersRequest.builder()
                        .dbParameterGroupName(db.dbParameterGroups().getFirst().dbParameterGroupName())
                        .build();
                    DescribeDbParametersResponse paramsResponse = rds.describeDBParameters(paramsRequest).join();
                    boolean isEncrypted = isConnectionEncrypted(db.engine(), paramsResponse);

                    s = isEncrypted ? Status.PASS : Status.FAIL;
                    r.put("dbInstanceIdentifier", db.dbInstanceIdentifier());
                    r.put("engine", db.engine());
                    r.put("DbParameters", MAPPER.valueToTree(paramsResponse.toBuilder()));
                    r.put("masterUsername", db.masterUsername());
                    r.put("dbName", db.dbName());
                    r.put("availabilityZone", db.availabilityZone());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.getText(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_CLIENT_CONNECTION_ENCRYPTION, result, status);
        return status;
    }

    private boolean isConnectionEncrypted(String engine, DescribeDbParametersResponse paramsResponse) {
        return switch (engine) {
            case "sqlserver" -> paramsResponse.parameters().stream()
                    .anyMatch(p -> "rds.force_ssl".equals(p.parameterName())
                            && "1".equals(p.parameterValue()));
            case "postgres", "aurora-postgresql" -> paramsResponse.parameters().stream()
                    .anyMatch(p -> "rds.force_ssl".equals(p.parameterName())
                            && "1".equals(p.parameterValue()));
            case "mysql", "mariadb", "aurora-mysql" -> paramsResponse.parameters().stream()
                    .anyMatch(p -> "require_secure_transport".equals(p.parameterName())
                            && "ON".equalsIgnoreCase(p.parameterValue()));
            default -> false;
        };
    }

    private Status checkRDSCloudWatchLogsIntegration() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_CLOUDWATCH_LOGS_INTEGRATION,
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    boolean hasLogsExport = db.enabledCloudwatchLogsExports() != null 
                        && !db.enabledCloudwatchLogsExports().isEmpty();

                    s = hasLogsExport ? Status.PASS : Status.FAIL;
                    r.put("dbInstanceIdentifier", db.dbInstanceIdentifier());
                    r.put("engine", db.engine());
                    r.put("enabledCloudwatchLogsExports", String.join(", ", db.enabledCloudwatchLogsExports()));
                    r.put("masterUsername", db.masterUsername());
                    r.put("dbName", db.dbName());
                    r.put("availabilityZone", db.availabilityZone());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.getText(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_CLOUDWATCH_LOGS_INTEGRATION, result, status);
        return status;
    }

    private Status checkRDSStorageEncryption() {
        if (allDbInstances.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_STORAGE_ENCRYPTION,
                            Text.NO_RDS_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbInstances.stream()
            .map(db -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    boolean isEncrypted = db.storageEncrypted() != null 
                        && db.storageEncrypted();
                    
                    s = isEncrypted ? Status.PASS : Status.FAIL;
                    r.put("dbInstanceIdentifier", db.dbInstanceIdentifier());
                    r.put("engine", db.engine());
                    r.put("enabledCloudwatchLogsExports", String.join(", ", db.enabledCloudwatchLogsExports()));
                    r.put("masterUsername", db.masterUsername());
                    r.put("dbName", db.dbName());
                    r.put("availabilityZone", db.availabilityZone());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.getText(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(db.dbInstanceIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_STORAGE_ENCRYPTION, result, status);
        return status;
    }

    private Status checkRDSSnapshotsEncryption() {
        if (allDbSnapshots.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_SNAPSHOTS_ENCRYPTION, 
                            Text.NO_RDS_SNAPSHOTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbSnapshots.stream()
            .map(snapshot -> {
                Status s = !snapshot.encrypted() ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("snapshotArn", snapshot.dbSnapshotArn())
                    .put("snapshotIdentifier", snapshot.dbSnapshotIdentifier())
                    .put("dbInstanceIdentifier", snapshot.dbInstanceIdentifier())
                    .put("encrypted", snapshot.encrypted())
                    .put("snapshotType", snapshot.snapshotType())
                    .put("snapshotCreateTime", snapshot.snapshotCreateTime().toString());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(snapshot.dbSnapshotIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_SNAPSHOTS_ENCRYPTION, result, status);
        return status;
    }

    private Status checkRDSClusterSnapshotsEncryption() {
        if (allDbClusterSnapshots.isEmpty()) {
            writer.addToBuffer(AWSFinding.RDS_CLUSTER_SNAPSHOTS_ENCRYPTION, 
                            Text.NO_RDS_CLUSTER_SNAPSHOTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDbClusterSnapshots.stream()
            .map(snapshot -> {
                Status s = !snapshot.storageEncrypted() ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.createObjectNode()
                    .put("snapshotArn", snapshot.dbClusterSnapshotArn())
                    .put("snapshotIdentifier", snapshot.dbClusterSnapshotIdentifier())
                    .put("dbClusterIdentifier", snapshot.dbClusterIdentifier())
                    .put("storageEncrypted", snapshot.storageEncrypted())
                    .put("snapshotType", snapshot.snapshotType())
                    .put("snapshotCreateTime", snapshot.snapshotCreateTime().toString());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(snapshot.dbClusterSnapshotIdentifier(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RDS_CLUSTER_SNAPSHOTS_ENCRYPTION, result, status);
        return status;
    }

}
