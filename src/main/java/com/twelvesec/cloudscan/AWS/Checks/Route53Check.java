package com.twelvesec.cloudscan.AWS.Checks;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.route53.Route53AsyncClient;
import software.amazon.awssdk.services.route53.model.GetQueryLoggingConfigRequest;
import software.amazon.awssdk.services.route53.model.GetQueryLoggingConfigResponse;
import software.amazon.awssdk.services.route53.model.HostedZone;
import software.amazon.awssdk.services.route53.model.ListResourceRecordSetsRequest;
import software.amazon.awssdk.services.route53.model.ListResourceRecordSetsResponse;
import software.amazon.awssdk.services.route53.model.NoSuchQueryLoggingConfigException;
import software.amazon.awssdk.services.route53.model.ResourceRecord;

public class Route53Check implements CloudCheck {
    private List<HostedZone> allHostedZones;
    private List<Instance> allEC2Instances;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final Route53AsyncClient route53;

    public Route53Check(DataWriter writer, SharedDataProvider sharedDataProvider,
            Route53AsyncClient route53) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.route53 = route53;
    }

    @Override
    public void runAllChecks() {
        throw new UnsupportedOperationException("Unimplemented method 'runAllChecks'");
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllRoute53HostedZones()
            .thenCompose(allHostedZones -> {
                this.allHostedZones = allHostedZones;
                return sharedDataProvider.getAllEC2Instances();
            })
            .thenCompose(allEC2Instances -> {
                this.allEC2Instances = allEC2Instances;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkRoute53PublicHostedZonesWithQueryLoggingDisabled,  AWSFinding.ROUTE53_PUBLIC_HOSTED_ZONES_QUERY_LOGGING_DISABLED, this::reportError),
                    wrapCheck(this::checkRoute53RecordsWithDanglingIPs,                     AWSFinding.ROUTE53_RECORDS_WITH_DANGLING_IPS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkRoute53PublicHostedZonesWithQueryLoggingDisabled() {
        if (allHostedZones.isEmpty()) {
            writer.addToBuffer(AWSFinding.ROUTE53_PUBLIC_HOSTED_ZONES_QUERY_LOGGING_DISABLED,
                    Text.NO_HOSTED_ZONES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<String> publicZones = allHostedZones.stream()
            .filter(zone -> !zone.config().privateZone())
            .map(HostedZone::id)
            .collect(Collectors.toList());

        if (publicZones.isEmpty()) {
            writer.addToBuffer(AWSFinding.ROUTE53_PUBLIC_HOSTED_ZONES_QUERY_LOGGING_DISABLED,
                            Text.NO_PUBLIC_HOSTED_ZONES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = publicZones.stream()
            .map(zoneId -> {
                Status s;
                ObjectNode r;
                try {
                    GetQueryLoggingConfigResponse configResponse = route53.getQueryLoggingConfig(
                        GetQueryLoggingConfigRequest.builder().id(zoneId).build()
                    ).join();
                    s = Status.PASS;
                    r = MAPPER.valueToTree(configResponse.toBuilder());
                } catch (NoSuchQueryLoggingConfigException e) {
                    s = Status.FAIL;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.ROUTE53_PUBLIC_HOSTED_ZONE_QUERY_LOGGING_DISABLED.toString().concat(e.getMessage()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(zoneId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ROUTE53_PUBLIC_HOSTED_ZONES_QUERY_LOGGING_DISABLED, result, status);
        return status;
    }

    private Status checkRoute53RecordsWithDanglingIPs() {
        if (allHostedZones.isEmpty()) {
            writer.addToBuffer(AWSFinding.ROUTE53_RECORDS_WITH_DANGLING_IPS,
                    Text.NO_HOSTED_ZONES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> activePublicIps = allEC2Instances.stream()
                .map(Instance::publicIpAddress)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        List<Map<String, Object>> result = allHostedZones.stream().<Map<String, Object>>flatMap(zone -> {
            String zoneId = zone.id();
            String zoneName = zone.name();
            
            try {
                ListResourceRecordSetsResponse recordsResponse = route53.listResourceRecordSets(
                        ListResourceRecordSetsRequest.builder().hostedZoneId(zoneId).build()
                ).join();

                return recordsResponse.resourceRecordSets().stream()
                    .filter(record -> "A".equals(record.type()))
                    .<Map<String, Object>>map(record -> {
                        String recordName = record.name();
                        List<String> recordIps = record.resourceRecords().stream()
                                .map(ResourceRecord::value)
                                .collect(Collectors.toList());

                        boolean hasDanglingIp = recordIps.stream()
                                .anyMatch(ip -> !activePublicIps.contains(ip));

                        ObjectNode recordNode = MAPPER.valueToTree(record.toBuilder());
                        ObjectNode zoneNode = MAPPER.createObjectNode();
                        zoneNode.put("hostedZoneId", zoneId);
                        zoneNode.put("hostedZoneName", zoneName);

                        ObjectNode inner = MAPPER.createObjectNode();
                        Status s = hasDanglingIp ? Status.FAIL : Status.PASS;
                        inner.put(Text.STATUS.toString(), s.toString());
                        inner.set("record", recordNode);
                        inner.set("zone", zoneNode);
                        return Collections.<String, Object>singletonMap(recordName, inner);
                    });
            } catch (Exception e) {
                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), Status.FAIL_EXCEPTION.toString());
                inner.put(Text.RESULT.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                return Stream.<Map<String, Object>>of(Collections.singletonMap(zoneId, inner));
            }
        })
        .collect(Collectors.toList());

        Status status = getOverallStatus(result);

        if (result.stream().noneMatch(m -> m.values().stream()
                .anyMatch(v -> v instanceof ObjectNode && ((ObjectNode)v).has("ipsChecked")))) {

            List<String> zoneIds = allHostedZones.stream()
                .map(HostedZone::id)
                .collect(Collectors.toList());

            ObjectNode resultNode = MAPPER.createObjectNode();
            resultNode.put(Text.MESSAGE.getText(), Text.NO_A_RECORDS_FOUND_IN_HOSTED_ZONES.getText());
            resultNode.put("hostedZonesChecked", String.join(", ", zoneIds));
            writer.addToBuffer(AWSFinding.ROUTE53_RECORDS_WITH_DANGLING_IPS, resultNode, status);
            return status;
        }
        writer.addToBuffer(AWSFinding.ROUTE53_RECORDS_WITH_DANGLING_IPS, result, status);
        return status;
    }
    
}
