package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;
import software.amazon.awssdk.services.kafka.model.*;
import software.amazon.awssdk.services.kafkaconnect.KafkaConnectAsyncClient;
import software.amazon.awssdk.services.kafkaconnect.model.DescribeConnectorRequest;
import software.amazon.awssdk.services.kafkaconnect.model.DescribeConnectorResponse;
import software.amazon.awssdk.services.kafkaconnect.model.KafkaClusterEncryptionInTransitDescription;
import software.amazon.awssdk.services.kafkaconnect.model.ListConnectorsRequest;
import software.amazon.awssdk.services.kafkaconnect.model.ConnectorSummary;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class KafkaCheck implements CloudCheck {
    private List<ClusterInfo> allClusters;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final KafkaAsyncClient kafka;
    private final KafkaConnectAsyncClient kafkaconnect;

    public KafkaCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                      KafkaAsyncClient kafka, KafkaConnectAsyncClient kafkaconnect) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.kafka = kafka;
        this.kafkaconnect = kafkaconnect;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<ClusterInfo>> clusters = sharedDataProvider.getAllKafkaClusters()
                .exceptionally(ex -> null);

        return clusters.thenCompose(c -> {
            this.allClusters = c;

            List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::KafkaBrokersWithEnhancedMonitoringDisabled,     AWSFinding.KAFKA_BROKERS_WITHOUT_ENHANCED_MONITORING, this::reportError),
                    wrapCheck(this::KafkaClustersWithMTLSAuthenticationDisabled,    AWSFinding.KAFKA_CLUSTERS_WITHOUT_MTLS, this::reportError),
                    wrapCheck(this::KafkaClustersUsingOutdatedVersion,              AWSFinding.KAFKA_CLUSTERS_USING_OUTDATED_VERSION, this::reportError),
                    wrapCheck(this::KafkaClustersEncryptionAtRestWithCMKDisabled,   AWSFinding.KAFKA_CLUSTERS_WITHOUT_CMK_ENCRYPTION_AT_REST, this::reportError),
                    wrapCheck(this::KafkaClustersEncryptionInTransitDisabled,       AWSFinding.KAFKA_CLUSTERS_WITHOUT_IN_TRANSIT_ENCRYPTION, this::reportError),
                    wrapCheck(this::KafkaClustersUnrestrictedAccessEnabled,         AWSFinding.KAFKA_CLUSTERS_UNRESTRICTED_ACCESS, this::reportError),
                    wrapCheck(this::KafkaClustersExposedToPublic,                   AWSFinding.KAFKA_CLUSTERS_EXPOSED_TO_PUBLIC, this::reportError),
                    wrapCheck(this::MskConnectConnectorsWithoutEncryptionInTransit, AWSFinding.MSK_CONNECT_WITHOUT_ENCRYPTION_IN_TRANSIT, this::reportError)
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
                            Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
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
                            Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
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
                            Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
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

    private Status KafkaClustersEncryptionAtRestWithCMKDisabled() {
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_WITHOUT_CMK_ENCRYPTION_AT_REST,
                    Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allClusters.stream()
                .map(cluster -> {
                    String kmsKeyId = Optional.ofNullable(cluster.encryptionInfo())
                            .map(EncryptionInfo::encryptionAtRest)
                            .map(EncryptionAtRest::dataVolumeKMSKeyId)
                            .orElse("");
                    boolean isCmk = !kmsKeyId.isBlank() && !kmsKeyId.contains("alias/aws/kafka");

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), isCmk ? Status.PASS : Status.FAIL);
                    inner.put(Text.RESULT.toString(), MAPPER.valueToTree(cluster.toBuilder()));
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_WITHOUT_CMK_ENCRYPTION_AT_REST, result, status);
        return status;
    }

    private Status KafkaClustersEncryptionInTransitDisabled() {
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_WITHOUT_IN_TRANSIT_ENCRYPTION,
                    Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allClusters.stream()
                .map(cluster -> {
                    EncryptionInTransit transit = Optional.ofNullable(cluster.encryptionInfo())
                            .map(EncryptionInfo::encryptionInTransit)
                            .orElse(null);
                    boolean inClusterEncrypted = transit != null && Boolean.TRUE.equals(transit.inCluster());
                    boolean clientBrokerTls = transit != null && ClientBroker.TLS.equals(transit.clientBroker());
                    boolean isFullyEncrypted = inClusterEncrypted && clientBrokerTls;

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), isFullyEncrypted ? Status.PASS : Status.FAIL);
                    inner.put(Text.RESULT.toString(), MAPPER.valueToTree(cluster.toBuilder()));
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_WITHOUT_IN_TRANSIT_ENCRYPTION, result, status);
        return status;
    }

    private Status KafkaClustersUnrestrictedAccessEnabled() {
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_UNRESTRICTED_ACCESS,
                    Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allClusters.stream()
                .map(cluster -> {
                    boolean unauthenticatedEnabled = Optional.ofNullable(cluster.clientAuthentication())
                            .map(ClientAuthentication::unauthenticated)
                            .map(Unauthenticated::enabled)
                            .orElse(false);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), unauthenticatedEnabled ? Status.FAIL : Status.PASS);
                    inner.put(Text.RESULT.toString(), MAPPER.valueToTree(cluster.toBuilder()));
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_UNRESTRICTED_ACCESS, result, status);
        return status;
    }

    private Status KafkaClustersExposedToPublic() {
        if (allClusters.isEmpty()) {
            writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_EXPOSED_TO_PUBLIC,
                    Text.NO_KAFKA_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allClusters.stream()
                .map(cluster -> {
                    String publicAccessType = Optional.ofNullable(cluster.brokerNodeGroupInfo())
                            .map(BrokerNodeGroupInfo::connectivityInfo)
                            .map(ConnectivityInfo::publicAccess)
                            .map(PublicAccess::type)
                            .orElse("DISABLED");
                    boolean isPublic = "SERVICE_PROVIDED_EIPS".equalsIgnoreCase(publicAccessType);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), isPublic ? Status.FAIL : Status.PASS);
                    inner.put(Text.RESULT.toString(), MAPPER.valueToTree(cluster.toBuilder()));
                    return Map.<String, Object>of(cluster.clusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.KAFKA_CLUSTERS_EXPOSED_TO_PUBLIC, result, status);
        return status;
    }

    private Status MskConnectConnectorsWithoutEncryptionInTransit() {
        List<ConnectorSummary> connectors = kafkaconnect.listConnectors(
                ListConnectorsRequest.builder().build()
        ).join().connectors();

        if (connectors.isEmpty()) {
            writer.addToBuffer(AWSFinding.MSK_CONNECT_WITHOUT_ENCRYPTION_IN_TRANSIT,
                    Text.NO_CONNECTORS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = connectors.stream()
                .map(connector -> {
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeConnectorResponse response = kafkaconnect.describeConnector(
                                DescribeConnectorRequest.builder().connectorArn(connector.connectorArn()).build()
                        ).join();
                        KafkaClusterEncryptionInTransitDescription transit = response.kafkaClusterEncryptionInTransit();
                        boolean tlsEnabled = transit != null && "TLS".equalsIgnoreCase(transit.encryptionTypeAsString());
                        s = tlsEnabled ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(transit != null ? transit.toBuilder() : connector.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(connector.connectorArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.MSK_CONNECT_WITHOUT_ENCRYPTION_IN_TRANSIT, result, status);
        return status;
    }
}
