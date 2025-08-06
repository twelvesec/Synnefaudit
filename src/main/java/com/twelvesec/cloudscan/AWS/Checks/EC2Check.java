package com.twelvesec.cloudscan.AWS.Checks;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.InstanceMetadataOptionsResponse;
import software.amazon.awssdk.services.ec2.model.IpRange;
import software.amazon.awssdk.services.ec2.model.Ipv6Range;
import software.amazon.awssdk.services.ec2.model.MonitoringState;
import software.amazon.awssdk.services.ec2.model.SecurityGroup;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationRequest;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationResponse;
import software.amazon.awssdk.services.ssm.model.InstanceInformationStringFilter;

public class EC2Check implements CloudCheck {
    List<Instance> allEC2Instances;
    List<String> allGroupIds;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final Ec2AsyncClient ec2;
    private final SsmAsyncClient ssm;

    public EC2Check(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    Ec2AsyncClient ec2, SsmAsyncClient ssm) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.ec2 = ec2;
        this.ssm = ssm;
    }

    @Override
    public void runAllChecks() {
        allEC2Instances = sharedDataProvider.getAllEC2Instances().join();
        allGroupIds = sharedDataProvider.getAllSecurityGroupIds().join();

        subCheckResults.clear();
        subCheckResults.addAll(
            Stream.of(
                wrapCheck(this::checkEC2InstancesWithPublicIPs,                         AWSFinding.EC2_INSTANCES_WTH_PUBLIC_IPS, this::reportError),
                wrapCheck(this::checkEC2InstancesWithDetailedMonitoringDisabled,        AWSFinding.EC2_INSTANCES_WITH_DETAILED_MONITORING_DISABLED, this::reportError),
                wrapCheck(this::checkEC2InstancesNotManagedBySystemsManager,            AWSFinding.EC2_INSTANCES_NOT_MANAGED_BY_SYSTEM_MANAGER, this::reportError),
                wrapCheck(this::checkSecurityGroupAllowIngressFromNonRFC1918Address,    AWSFinding.EC2_SECURITY_GROUP_NON_RFC1918_INGRESS, this::reportError),
                wrapCheck(this::checkPublicInstancesWithIamProfilesAttached,            AWSFinding.PUBLIC_INSTANCES_WITH_IAM_PROFILES_ATTACHED, this::reportError),
                wrapCheck(this::checkEC2InstancesOlderThan180Days,                      AWSFinding.EC2_INSTANCES_OLDER_THAN_180_DAYS, this::reportError),
                wrapCheck(this::checkSecurityGroupsNotUsed,                             AWSFinding.SECURITY_GROUPS_NOT_USED, this::reportError),
                wrapCheck(this::checkEC2IMDSv2Configuration,                            AWSFinding.EC2_IMDSV2_CONFIGURATION, this::reportError)
            )
            .map(Supplier::get)
            .toList()
        );
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllEC2Instances()
            .thenCompose(instances -> {
                this.allEC2Instances = instances;
                return sharedDataProvider.getAllSecurityGroupIds();
            })
            .thenCompose(securityGroupIds -> {
                this.allGroupIds = securityGroupIds;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkEC2InstancesWithPublicIPs,                         AWSFinding.EC2_INSTANCES_WTH_PUBLIC_IPS, this::reportError),
                    wrapCheck(this::checkEC2InstancesWithDetailedMonitoringDisabled,        AWSFinding.EC2_INSTANCES_WITH_DETAILED_MONITORING_DISABLED, this::reportError),
                    wrapCheck(this::checkEC2InstancesNotManagedBySystemsManager,            AWSFinding.EC2_INSTANCES_NOT_MANAGED_BY_SYSTEM_MANAGER, this::reportError),
                    wrapCheck(this::checkSecurityGroupAllowIngressFromNonRFC1918Address,    AWSFinding.EC2_SECURITY_GROUP_NON_RFC1918_INGRESS, this::reportError),
                    wrapCheck(this::checkPublicInstancesWithIamProfilesAttached,            AWSFinding.PUBLIC_INSTANCES_WITH_IAM_PROFILES_ATTACHED, this::reportError),
                    wrapCheck(this::checkEC2InstancesOlderThan180Days,                      AWSFinding.EC2_INSTANCES_OLDER_THAN_180_DAYS, this::reportError),
                    wrapCheck(this::checkSecurityGroupsNotUsed,                             AWSFinding.SECURITY_GROUPS_NOT_USED, this::reportError),
                    wrapCheck(this::checkEC2IMDSv2Configuration,                            AWSFinding.EC2_IMDSV2_CONFIGURATION, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkEC2InstancesWithPublicIPs() { 
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_INSTANCES_WTH_PUBLIC_IPS, 
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allEC2Instances.stream()
            .map(inst -> {
                boolean violation = inst.publicIpAddress() != null;
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), inst);
                return Map.<String,Object>of(inst.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_WTH_PUBLIC_IPS, result, status);
        return status;
    }

    private Status checkEC2InstancesWithDetailedMonitoringDisabled() { 
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_INSTANCES_WITH_DETAILED_MONITORING_DISABLED, 
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allEC2Instances.stream()
            .map(instance -> {
                boolean violation = instance.monitoring().state() == MonitoringState.DISABLED;
                Status s = violation ? Status.FAIL : Status.PASS;
                ObjectNode r = MAPPER.valueToTree(instance.toBuilder());
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(instance.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_WITH_DETAILED_MONITORING_DISABLED, result, status);
        return status;
    }

    private Status checkEC2InstancesNotManagedBySystemsManager() { 
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_INSTANCES_NOT_MANAGED_BY_SYSTEM_MANAGER, 
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allEC2Instances.stream()
            .map(inst -> {
                Status s;
                ObjectNode r;
                try {
                    DescribeInstanceInformationResponse response = ssm.describeInstanceInformation(
                        DescribeInstanceInformationRequest.builder()
                            .filters(InstanceInformationStringFilter.builder()
                                .key("InstanceIds")
                                .values(inst.instanceId())
                                .build())
                            .build()
                    ).join();
                    s = response.instanceInformationList().isEmpty() ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(inst.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_NOT_MANAGED_BY_SYSTEM_MANAGER, result, status);
        return status;
    }

    private Status checkSecurityGroupAllowIngressFromNonRFC1918Address() { 
        if (allGroupIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_SECURITY_GROUP_NON_RFC1918_INGRESS,
                            Text.NO_SECURITY_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allGroupIds.stream()
            .map(groupId -> {
                Status s;
                String r;
                try {
                    SecurityGroup sg = ec2.describeSecurityGroups(
                        DescribeSecurityGroupsRequest.builder().groupIds(groupId).build()
                    ).join().securityGroups().get(0);

                    List<String> badCidrs = sg.ipPermissions().stream()
                        .flatMap(perm -> {
                            Stream<String> v4 = perm.ipRanges().stream()
                                .map(IpRange::cidrIp)
                                .filter(cidr -> !isRfc1918(cidr));

                            Stream<String> v6 = perm.ipv6Ranges().stream()
                                .map(Ipv6Range::cidrIpv6)
                                .filter(cidr -> "::/0".equals(cidr));

                            return Stream.concat(v4, v6);
                        })
                        .distinct()
                        .toList();

                    if (badCidrs.isEmpty()) {
                        s = Status.PASS;
                        r = Text.NO_NON_RFV1918_INGRESS_FOUND.toString();
                    } else {
                        s = Status.FAIL;
                        r = Text.INGRESS_FROM_NON_PRIVATE_CIDRS.toString().concat(String.join(", ", badCidrs));
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(groupId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_SECURITY_GROUP_NON_RFC1918_INGRESS, result, status);
        return status;
    }

    private boolean isRfc1918(String cidr) {
        if (cidr.startsWith("10.")) return true;
        if (cidr.startsWith("192.168.")) return true;
        if (cidr.startsWith("172.")) {
            String secondOctet = cidr.split("\\.")[1];
            int s = Integer.parseInt(secondOctet);
            return s >= 16 && s <= 31;
        }
        return false;
    }

    private Status checkPublicInstancesWithIamProfilesAttached() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.PUBLIC_INSTANCES_WITH_IAM_PROFILES_ATTACHED, 
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(instance -> {
                String instanceId = instance.instanceId();
                boolean hasPublicIp = instance.publicIpAddress() != null;
                boolean hasIamProfile = instance.iamInstanceProfile() != null;

                ObjectNode instanceNode = MAPPER.valueToTree(instance.toBuilder());

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), (hasPublicIp && hasIamProfile) ? Status.FAIL.toString() : Status.PASS.toString());
                inner.set(Text.RESULT.toString(), instanceNode);
                return Map.<String, Object>of(instanceId, inner);
            })
            .toList();

        Status overall = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.PUBLIC_INSTANCES_WITH_IAM_PROFILES_ATTACHED, result, overall);
        return overall;
    }

    private Status checkEC2InstancesOlderThan180Days() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_INSTANCES_OLDER_THAN_180_DAYS,
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(instance -> {
                Instant launchTime = instance.launchTime();
                boolean isOld = launchTime.isBefore(Instant.now().minus(180, ChronoUnit.DAYS));

                ObjectNode instanceNode = MAPPER.valueToTree(instance.toBuilder());

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), isOld ? Status.FAIL.toString() : Status.PASS.toString());
                inner.set(Text.RESULT.toString(), instanceNode);

                return Map.<String, Object>of(instance.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_OLDER_THAN_180_DAYS, result, status);
        return status;
    }

    private Status checkSecurityGroupsNotUsed() {
        if (allGroupIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.SECURITY_GROUPS_NOT_USED,
                            Text.NO_SECURITY_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allGroupIds.stream()
            .map(groupId -> {
                Status s;
                ObjectNode r;
                try {
                    DescribeInstancesResponse resp = ec2.describeInstances(
                        DescribeInstancesRequest.builder()
                            .filters(Filter.builder().name("instance.group-id").values(groupId).build()).build()
                    ).join();
                    List<String> instanceIds = resp.reservations().stream()
                        .flatMap(res -> res.instances().stream())
                        .map(Instance::instanceId)
                        .toList();

                    if (instanceIds.isEmpty()) {
                        s = Status.FAIL;
                        r = MAPPER.createObjectNode().put(Text.MESSAGE.toString(), Text.NO_INSTANCES_USING_GROUP.toString());
                    } else {
                        s = Status.PASS;
                        r = MAPPER.valueToTree(instanceIds);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.set(Text.RESULT.toString(), r);
                return Map.<String, Object>of(groupId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.SECURITY_GROUPS_NOT_USED, result, status);
        return status;
    }

    private Status checkEC2IMDSv2Configuration() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_IMDSV2_CONFIGURATION,
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(instance -> {
                String instanceId = instance.instanceId();
                InstanceMetadataOptionsResponse metadataOptions = instance.metadataOptions();

                Status s = metadataOptions != null 
                        && "required".equalsIgnoreCase(metadataOptions.httpTokens().toString()) 
                        && "enabled".equalsIgnoreCase(metadataOptions.httpEndpoint().toString())
                    ? Status.PASS
                    : Status.FAIL;
                ObjectNode r = MAPPER.valueToTree(instance.toBuilder());

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(instanceId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_IMDSV2_CONFIGURATION, result, status);
        return status;
    }
}
