package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;
import software.amazon.awssdk.services.kafka.model.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class KafkaCheck implements CloudCheck {
    private List<ClusterInfo> allClusters;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final KafkaAsyncClient kafka;

    public KafkaCheck(DataWriter writer, SharedDataProvider sharedDataProvider, KafkaAsyncClient kafka) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.kafka = kafka;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllKafkaClusters()
            .thenCompose(clusters -> {
                this.allClusters = clusters;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::KafkaBrokersWithEnhancedMonitoringDisabled,     AWSFinding.KAFKA_BROKERS_WITHOUT_ENHANCED_MONITORING, this::reportError),
                    wrapCheck(this::KafkaClustersWithMTLSAuthenticationDisabled,    AWSFinding.KAFKA_CLUSTERS_WITHOUT_MTLS, this::reportError),
                    wrapCheck(this::KafkaClustersUsingOutdatedVersion,              AWSFinding.KAFKA_CLUSTERS_USING_OUTDATED_VERSION, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status KafkaBrokersWithEnhancedMonitoringDisabled() { 
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_BROKERS_WITHOUT_ENHANCED_MONITORING, 
                            Text.NO_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allClusters.stream()
            .map(cluster -> {
                boolean disabled = cluster.enhancedMonitoring() == EnhancedMonitoring.DEFAULT;
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), disabled ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), cluster.enhancedMonitoringAsString());

                return Map.<String, Object>of(cluster.clusterArn(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_BROKERS_WITHOUT_ENHANCED_MONITORING, result, status);
        return status;
    }

    private Status KafkaClustersWithMTLSAuthenticationDisabled() { 
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_WITHOUT_MTLS, 
                            Text.NO_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allClusters.stream()
            .map(cluster -> {
                Status s;
                ObjectNode r;
                try {
                    DescribeClusterResponse response = kafka.describeCluster(
                        DescribeClusterRequest.builder().clusterArn(cluster.clusterArn()).build()
                    ).join();
                    ClusterInfo info = response.clusterInfo();
                    ClientAuthentication auth = info.clientAuthentication();
                    boolean tls = auth != null 
                            && auth.tls() != null 
                            && Boolean.TRUE.equals(auth.tls().enabled());
                    s = tls ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(auth.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(cluster.clusterArn(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_WITHOUT_MTLS, result, status);
        return status;
    }

    private Status KafkaClustersUsingOutdatedVersion() { 
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_USING_OUTDATED_VERSION, 
                            Text.NO_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }
        
        String latest = kafka.listKafkaVersions(ListKafkaVersionsRequest.builder().build()).join()
            .kafkaVersions().stream()
            .map(KafkaVersion::version)
            .max(Comparator.naturalOrder())
            .orElse("");

        List<Map<String, Object>> result = allClusters.stream()
            .map(cluster -> {
                String current = Optional.ofNullable(cluster.currentBrokerSoftwareInfo())
                                        .map(BrokerSoftwareInfo::kafkaVersion)
                                        .orElse("");

                boolean outdated = !current.equals(latest);
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), outdated ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), current.isEmpty() ? "unknown" : current);

                return Map.<String, Object>of(cluster.clusterArn(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_USING_OUTDATED_VERSION, result, status);
        return status;
    }
}
