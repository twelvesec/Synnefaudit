package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.ec2.model.Subnet;
import software.amazon.awssdk.services.elasticache.ElastiCacheAsyncClient;
import software.amazon.awssdk.services.elasticache.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class ElastiCacheCheck implements CloudCheck {
    private List<ReplicationGroup> allReplicationGroups;
    private List<CacheCluster> allCacheClusters;
    private List<ServerlessCache> allServerlessCaches;
    private List<Subnet> allVPCSubnets;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final ElastiCacheAsyncClient elasticache;

    public ElastiCacheCheck(DataWriter writer, SharedDataProvider sharedDataProvider, ElastiCacheAsyncClient elasticache) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.elasticache = elasticache;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllReplicationGroups()
                .thenCompose(replGroups -> {
                    this.allReplicationGroups = replGroups;
                    return sharedDataProvider.getAllCacheClusters();
                })
                .thenCompose(cacheClusters -> {
                    this.allCacheClusters = cacheClusters;
                    return sharedDataProvider.getAllVPCSubnets();
                })
                .thenCompose(subnets -> {
                    this.allVPCSubnets = subnets;
                    return sharedDataProvider.getAllServerlessCaches();
                })
                .thenCompose(serverlesscaches -> {
                    this.allServerlessCaches = serverlesscaches;
                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkElastiCacheRedisAtRestEncryptionDisabled,          AWSFinding.ELASTICACHE_REDIS_AT_REST_ENCRYPTION_ENABLED, this::reportError),
                            wrapCheck(this::checkElastiCacheRedisInTransitEncryptionDisabled,       AWSFinding.ELASTICACHE_REDIS_IN_TRANSIT_ENCRYPTION_ENABLED, this::reportError),
                            wrapCheck(this::checkElastiCacheClusterInPublicSubnets,                 AWSFinding.ELASTICACHE_CLUSTER_NOT_IN_PUBLIC_SUBNETS, this::reportError),
                            wrapCheck(this::checkElastiCacheServerlessInPublicSubnets,              AWSFinding.ELASTICACHE_SERVERLESS_NOT_IN_PUBLIC_SUBNETS, this::reportError),
                            wrapCheck(this::checkElastiCacheRedisAutoMinorVersionUpgradesDisabled,  AWSFinding.ELASTICACHE_REDIS_AUTO_MINOR_VERSION_UPGRADES_ENABLED, this::reportError),
                            wrapCheck(this::checkElastiCacheRedisAutomaticFailoverDisabled,         AWSFinding.ELASTICACHE_REDIS_AUTOMATIC_FAILOVER_ENABLED, this::reportError),
                            wrapCheck(this::checkElastiCacheRedisAutomatedSnapshots,                AWSFinding.ELASTICACHE_REDIS_AUTOMATED_SNAPSHOTS, this::reportError),
                            wrapCheck(this::checkElastiCacheRedisMultiAzDisabled,                   AWSFinding.ELASTICACHE_REDIS_MULTI_AZ_ENABLED, this::reportError),
                            wrapCheck(this::checkElastiCacheRedisAuthDisabledForLegacyVersions,     AWSFinding.ELASTICACHE_REDIS_AUTH_ENABLED_LEGACY, this::reportError)
                    );
                    return runChecksInList(checksList, writer);
                });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkElastiCacheRedisAtRestEncryptionDisabled() {
        if (allReplicationGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AT_REST_ENCRYPTION_ENABLED,
                    Text.NO_REPLICATION_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allReplicationGroups.stream()
                .map(rg -> {
                    boolean isEncrypted = Boolean.TRUE.equals(rg.atRestEncryptionEnabled());
                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(rg.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(rg.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AT_REST_ENCRYPTION_ENABLED, result, status);
        return status;
    }

    private Status checkElastiCacheRedisInTransitEncryptionDisabled() {
        if (allReplicationGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_IN_TRANSIT_ENCRYPTION_ENABLED,
                    Text.NO_REPLICATION_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allReplicationGroups.stream()
                .map(rg -> {
                    boolean isEncrypted = Boolean.TRUE.equals(rg.transitEncryptionEnabled());
                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(rg.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(rg.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_IN_TRANSIT_ENCRYPTION_ENABLED, result, status);
        return status;
    }

    private Status checkElastiCacheClusterInPublicSubnets() {
        if (allCacheClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_CLUSTER_NOT_IN_PUBLIC_SUBNETS,
                    Text.NO_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> publicSubnetIds = allVPCSubnets.stream()
                .filter(subnet -> Boolean.TRUE.equals(subnet.mapPublicIpOnLaunch()))
                .map(software.amazon.awssdk.services.ec2.model.Subnet::subnetId)
                .collect(Collectors.toSet());

        List<Map<String, Object>> result = allCacheClusters.stream()
                .map(cluster -> {
                    Status s;
                    ObjectNode r = MAPPER.createObjectNode();
                    try {
                        String subnetGroupName = cluster.cacheSubnetGroupName();
                        boolean isPublic = false;

                        if (subnetGroupName != null) {
                            DescribeCacheSubnetGroupsResponse response = elasticache.describeCacheSubnetGroups(
                                    DescribeCacheSubnetGroupsRequest.builder().cacheSubnetGroupName(subnetGroupName).build()
                            ).join();

                            List<software.amazon.awssdk.services.elasticache.model.Subnet> cacheSubnets = response.cacheSubnetGroups().stream()
                                    .flatMap(group -> group.subnets().stream())
                                    .toList();

                            isPublic = cacheSubnets.stream()
                                    .map(software.amazon.awssdk.services.elasticache.model.Subnet::subnetIdentifier)
                                    .anyMatch(publicSubnetIds::contains);
                        }
                        s = isPublic ? Status.FAIL : Status.PASS;
                        r = MAPPER.valueToTree(cluster.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cluster.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_CLUSTER_NOT_IN_PUBLIC_SUBNETS, result, status);
        return status;
    }

    private Status checkElastiCacheServerlessInPublicSubnets() {
        if (allServerlessCaches.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_SERVERLESS_NOT_IN_PUBLIC_SUBNETS,
                    Text.NO_SERVERLESS_CACHES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> publicSubnetIds = allVPCSubnets.stream()
                .filter(subnet -> Boolean.TRUE.equals(subnet.mapPublicIpOnLaunch()))
                .map(software.amazon.awssdk.services.ec2.model.Subnet::subnetId)
                .collect(Collectors.toSet());

        List<Map<String, Object>> result = allServerlessCaches.stream()
                .map(cache -> {
                    boolean isPublic = cache.subnetIds().stream().anyMatch(publicSubnetIds::contains);
                    Status s = isPublic ? Status.FAIL : Status.PASS;
                    ObjectNode r = MAPPER.valueToTree(cache.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cache.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_SERVERLESS_NOT_IN_PUBLIC_SUBNETS, result, status);
        return status;
    }

    private Status checkElastiCacheRedisAutoMinorVersionUpgradesDisabled() {
        if (allCacheClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTO_MINOR_VERSION_UPGRADES_ENABLED,
                    Text.NO_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allCacheClusters.stream()
                .map(cluster -> {
                    boolean autoUpgrade = Boolean.TRUE.equals(cluster.autoMinorVersionUpgrade());
                    Status s = autoUpgrade ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(cluster.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cluster.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTO_MINOR_VERSION_UPGRADES_ENABLED, result, status);
        return status;
    }

    private Status checkElastiCacheRedisAutomaticFailoverDisabled() {
        if (allReplicationGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTOMATIC_FAILOVER_ENABLED,
                    Text.NO_REPLICATION_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allReplicationGroups.stream()
                .map(rg -> {
                    String failoverStatus = rg.automaticFailoverAsString();
                    boolean isEnabled = "ENABLED".equalsIgnoreCase(failoverStatus) || "ENABLING".equalsIgnoreCase(failoverStatus);
                    Status s = isEnabled ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(rg.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(rg.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTOMATIC_FAILOVER_ENABLED, result, status);
        return status;
    }

    private Status checkElastiCacheRedisAutomatedSnapshots() {
        if (allCacheClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTOMATED_SNAPSHOTS,
                    Text.NO_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allCacheClusters.stream()
                .filter(cluster -> "redis".equalsIgnoreCase(cluster.engine()))
                .map(cluster -> {
                    Integer retentionLimit = cluster.snapshotRetentionLimit();
                    boolean isSufficient = retentionLimit != null && retentionLimit >= 7;
                    Status s = isSufficient ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(cluster.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(cluster.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTOMATED_SNAPSHOTS, result, status);
        return status;
    }

    private Status checkElastiCacheRedisMultiAzDisabled() {
        if (allReplicationGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_MULTI_AZ_ENABLED,
                    Text.NO_REPLICATION_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allReplicationGroups.stream()
                .map(rg -> {
                    String multiAz = rg.multiAZAsString();
                    boolean isMultiAz = "ENABLED".equalsIgnoreCase(multiAz) || "ENABLING".equalsIgnoreCase(multiAz);
                    Status s = isMultiAz ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(rg.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(rg.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_MULTI_AZ_ENABLED, result, status);
        return status;
    }

    private Status checkElastiCacheRedisAuthDisabledForLegacyVersions() {
        if (allReplicationGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTH_ENABLED_LEGACY,
                    Text.NO_REPLICATION_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Map<String, String> rgToEngineVersion = allCacheClusters.stream()
                .filter(c -> c.replicationGroupId() != null && c.engineVersion() != null)
                .collect(Collectors.toMap(
                        CacheCluster::replicationGroupId,
                        CacheCluster::engineVersion,
                        (v1, v2) -> v1
                ));

        List<Map<String, Object>> result = allReplicationGroups.stream()
                .map(rg -> {
                    String engineVersion = rgToEngineVersion.getOrDefault(rg.replicationGroupId(), "0.0");
                    double majorVersion = parseMajorVersion(engineVersion);
                    Status s;
                    if (majorVersion > 0.0 && majorVersion < 6.0) {
                        boolean authEnabled = Boolean.TRUE.equals(rg.authTokenEnabled());
                        s = authEnabled ? Status.PASS : Status.FAIL;
                    } else {
                        s = Status.PASS; // Version 6.0+ uses RBAC / User Groups
                    }
                    ObjectNode r = MAPPER.valueToTree(rg.toBuilder());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(rg.arn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELASTICACHE_REDIS_AUTH_ENABLED_LEGACY, result, status);
        return status;
    }

    private double parseMajorVersion(String version) {
        try {
            String[] parts = version.split("\\.");
            if (parts.length >= 2) {
                return Double.parseDouble(parts[0] + "." + parts[1]);
            }
            return Double.parseDouble(parts[0]);
        } catch (Exception e) {
            return 0.0;
        }
    }
}
