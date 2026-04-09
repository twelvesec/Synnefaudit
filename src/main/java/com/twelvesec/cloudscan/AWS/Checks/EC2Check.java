package com.twelvesec.cloudscan.AWS.Checks;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.Address;
import software.amazon.awssdk.services.ec2.model.DescribeImageAttributeRequest;
import software.amazon.awssdk.services.ec2.model.DescribeImageAttributeResponse;
import software.amazon.awssdk.services.ec2.model.DescribeLaunchTemplateVersionsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeLaunchTemplateVersionsResponse;
import software.amazon.awssdk.services.ec2.model.GetInstanceMetadataDefaultsRequest;
import software.amazon.awssdk.services.ec2.model.GetInstanceMetadataDefaultsResponse;
import software.amazon.awssdk.services.ec2.model.HttpTokensState;
import software.amazon.awssdk.services.ec2.model.Image;
import software.amazon.awssdk.services.ec2.model.ImageAttributeName;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.InstanceMetadataOptionsResponse;
import software.amazon.awssdk.services.ec2.model.LaunchTemplate;
import software.amazon.awssdk.services.ec2.model.LaunchTemplateVersion;
import software.amazon.awssdk.services.ec2.model.MonitoringState;
import software.amazon.awssdk.services.ec2.model.NetworkInterface;
import software.amazon.awssdk.services.ec2.model.TransitGateway;
import software.amazon.awssdk.services.ec2.model.VpcEndpoint;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationRequest;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationResponse;
import software.amazon.awssdk.services.ssm.model.InstanceInformationStringFilter;
import software.amazon.awssdk.services.ssm.model.ListComplianceItemsRequest;
import software.amazon.awssdk.services.ssm.model.ListComplianceItemsResponse;

public class EC2Check implements CloudCheck {
    private List<Instance> allEC2Instances;
    private List<VpcEndpoint> allVPCEndpoints;
    private List<LaunchTemplate> allLaunchTemplates;
    private List<TransitGateway> allTransitGateways;
    private List<Address> allElasticIPs;
    private List<NetworkInterface> allNetworkInterfaces;
    private List<Image> allAMIs;
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
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllEC2Instances()
            .thenCompose(instances -> {
                this.allEC2Instances = instances;
                return sharedDataProvider.getAllVPCEndpoints();
            })
            .thenCompose(VPCEndpoints -> {
                this.allVPCEndpoints = VPCEndpoints;
                return sharedDataProvider.getAllLaunchTemplates();
            })
            .thenCompose(LaunchTemplates -> {
                this.allLaunchTemplates = LaunchTemplates;
                return sharedDataProvider.getAllTransitGateways();
            })
            .thenCompose(TransitGateways -> {
                this.allTransitGateways = TransitGateways;
                return sharedDataProvider.getAllAMIs();
            })
            .thenCompose(AMIs -> {
                this.allAMIs = AMIs;
                return sharedDataProvider.getAllElasticIPs();
            })
            .thenCompose(elasticIPs -> {
                this.allElasticIPs = elasticIPs;
                return sharedDataProvider.getAllNetworkInterfaces();
            })
            .thenCompose(networkInterfaces -> {
                this.allNetworkInterfaces = networkInterfaces;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkEC2InstancesWithPublicIPs,                         AWSFinding.EC2_INSTANCES_WTH_PUBLIC_IPS, this::reportError),
                    wrapCheck(this::checkEC2InstancesWithDetailedMonitoringDisabled,        AWSFinding.EC2_INSTANCES_WITH_DETAILED_MONITORING_DISABLED, this::reportError),
                    wrapCheck(this::checkEC2InstancesNotManagedBySystemsManager,            AWSFinding.EC2_INSTANCES_NOT_MANAGED_BY_SYSTEM_MANAGER, this::reportError),
                    wrapCheck(this::checkPublicInstancesWithIamProfilesAttached,            AWSFinding.PUBLIC_INSTANCES_WITH_IAM_PROFILES_ATTACHED, this::reportError),
                    wrapCheck(this::checkEC2InstancesOlderThan180Days,                      AWSFinding.EC2_INSTANCES_OLDER_THAN_180_DAYS, this::reportError),
                    wrapCheck(this::checkEC2IMDSv2Configuration,                            AWSFinding.EC2_IMDSV2_CONFIGURATION, this::reportError),
                    wrapCheck(this::checkEC2ParavirtualVirtualization,                      AWSFinding.EC2_PARAVIRTUAL_VIRTUALIZATION_USED, this::reportError),
                    wrapCheck(this::checkEC2InstancesWithMultipleENIs,                      AWSFinding.EC2_INSTANCES_WITH_MULTIPLE_ENIS, this::reportError),
                    wrapCheck(this::checkLaunchTemplatesIMDSv2,                             AWSFinding.LAUNCH_TEMPLATES_IMDSV2_REQUIRED, this::reportError),
                    wrapCheck(this::checkLaunchTemplatesPublicIPs,                          AWSFinding.LAUNCH_TEMPLATES_NETWORK_INTERFACES_PUBLIC_IPS, this::reportError),
                    wrapCheck(this::checkTransitGatewaysAutoAccept,                         AWSFinding.TRANSIT_GATEWAYS_AUTO_ACCEPT_VPC_ATTACH, this::reportError),
                    wrapCheck(this::checkSSMPatchCompliance,                                AWSFinding.EC2_SSM_PATCH_COMPLIANCE, this::reportError),
                    wrapCheck(this::checkEC2VpcEndpoints,                                   AWSFinding.EC2_USE_VPC_ENDPOINTS, this::reportError),
                    wrapCheck(this::checkAccountLevelIMDSv2,                                AWSFinding.ACCOUNT_LEVEL_IMDSV2, this::reportError),
                    wrapCheck(this::checkEC2InstancesTags,                                  AWSFinding.EC2_INSTANCES_WITHOUT_TAGS, this::reportError),
                    wrapCheck(this::checkPublicAMIs,                                        AWSFinding.EC2_WITH_PUBLIC_AMIS, this::reportError),
                    wrapCheck(this::checkUnusedElasticIPsDeleted,                           AWSFinding.UNUSED_ELASTIC_IPS_EXIST, this::reportError),
                    wrapCheck(this::checkUnusedNetworkInterfacesDeleted,                    AWSFinding.UNUSED_NETWORK_INTERFACES_EXIST, this::reportError)
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

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), (hasPublicIp && hasIamProfile) ? Status.FAIL.toString() : Status.PASS.toString());
                inner.put(Text.RESULT.toString(), instanceNode);
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

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), isOld ? Status.FAIL.toString() : Status.PASS.toString());
                inner.put(Text.RESULT.toString(), instanceNode);

                return Map.<String, Object>of(instance.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_OLDER_THAN_180_DAYS, result, status);
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

    private Status checkEC2ParavirtualVirtualization() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_PARAVIRTUAL_VIRTUALIZATION_USED,
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(inst -> {
                boolean violation = "paravirtual".equalsIgnoreCase(String.valueOf(inst.virtualizationType()));
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), inst);
                return Map.<String, Object>of(inst.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_PARAVIRTUAL_VIRTUALIZATION_USED, result, status);
        return status;
    }

    private Status checkEC2InstancesWithMultipleENIs() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_INSTANCES_WITH_MULTIPLE_ENIS,
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(inst -> {
                boolean violation = inst.networkInterfaces() != null
                                && inst.networkInterfaces().size() > 1;
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), inst);
                return Map.<String, Object>of(inst.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_WITH_MULTIPLE_ENIS, result, status);
        return status;
    }

    private Status checkLaunchTemplatesIMDSv2() {
        if (allLaunchTemplates.isEmpty()) {
            writer.addToBuffer(AWSFinding.LAUNCH_TEMPLATES_IMDSV2_REQUIRED,
                            Text.NO_LAUNCH_TEMPLATES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLaunchTemplates.stream()
            .map(lt -> {
                Status s;
                ObjectNode r;

                try {
                    DescribeLaunchTemplateVersionsResponse versionResponse = ec2
                        .describeLaunchTemplateVersions(DescribeLaunchTemplateVersionsRequest.builder()
                            .launchTemplateId(lt.launchTemplateId())
                            .versions("$Latest")
                            .build())
                        .join();

                    if (versionResponse.launchTemplateVersions().isEmpty()) {
                        s = Status.FAIL;
                        r = MAPPER.createObjectNode().put(Text.MESSAGE.toString(),
                                                        Text.NO_LAUNCH_TEMPLATE_VERSIONS_FOUND.toString());
                    } else {
                        LaunchTemplateVersion version = versionResponse.launchTemplateVersions().getFirst();

                        if (version.launchTemplateData() != null
                        && version.launchTemplateData().metadataOptions() != null) {
                            String httpTokens = version.launchTemplateData().metadataOptions().httpTokensAsString();
                            boolean imdsv2Required = "required".equals(httpTokens);
                            boolean violation = !imdsv2Required;
                            s = violation ? Status.FAIL : Status.PASS;
                        } else {
                            s = Status.FAIL;
                        }
                        r = MAPPER.valueToTree(version);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                            Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(lt.launchTemplateId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.LAUNCH_TEMPLATES_IMDSV2_REQUIRED, result, status);
        return status;
    }

    private Status checkLaunchTemplatesPublicIPs() {
        if (allLaunchTemplates.isEmpty()) {
            writer.addToBuffer(AWSFinding.LAUNCH_TEMPLATES_NETWORK_INTERFACES_PUBLIC_IPS,
                            Text.NO_LAUNCH_TEMPLATES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLaunchTemplates.stream()
            .map(lt -> {
                Status s;
                ObjectNode r;

                try {
                    DescribeLaunchTemplateVersionsResponse versionResponse = ec2
                        .describeLaunchTemplateVersions(DescribeLaunchTemplateVersionsRequest.builder()
                            .launchTemplateId(lt.launchTemplateId())
                            .versions("$Latest")
                            .build())
                        .join();

                    if (versionResponse.launchTemplateVersions().isEmpty()) {
                        s = Status.FAIL;
                        r = MAPPER.createObjectNode().put(Text.MESSAGE.toString(),
                                                        Text.NO_LAUNCH_TEMPLATE_VERSIONS_FOUND.toString());
                    } else {
                        LaunchTemplateVersion version = versionResponse.launchTemplateVersions().getFirst();
                        boolean violation = false;

                        if (version.launchTemplateData() != null
                        && version.launchTemplateData().networkInterfaces() != null) {
                            violation = version.launchTemplateData().networkInterfaces().stream()
                                .anyMatch(ni -> ni.associatePublicIpAddress() != null
                                        && ni.associatePublicIpAddress());
                        }

                        s = violation ? Status.FAIL : Status.PASS;
                        r = MAPPER.valueToTree(version);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(lt.launchTemplateId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.LAUNCH_TEMPLATES_NETWORK_INTERFACES_PUBLIC_IPS, result, status);
        return status;
    }

    private Status checkTransitGatewaysAutoAccept() {
        if (allTransitGateways.isEmpty()) {
            writer.addToBuffer(AWSFinding.TRANSIT_GATEWAYS_AUTO_ACCEPT_VPC_ATTACH,
                            Text.NO_TRANSIT_GATEWAYS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allTransitGateways.stream()
            .map(tg -> {
                boolean violation = tg.options() != null
                        && tg.options().autoAcceptSharedAttachments() != null
                        && tg.options().autoAcceptSharedAttachments().toString().equals("ENABLE");
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), tg);
                return Map.<String, Object>of(tg.transitGatewayId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.TRANSIT_GATEWAYS_AUTO_ACCEPT_VPC_ATTACH, result, status);
        return status;
    }

    private Status checkSSMPatchCompliance() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_SSM_PATCH_COMPLIANCE,
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(inst -> {
                Status s;
                ObjectNode r;
                try {
                    ListComplianceItemsResponse complianceResponse = ssm.listComplianceItems(
                        ListComplianceItemsRequest.builder()
                            .resourceIds(inst.instanceId())
                            .resourceTypes("ManagedInstance")
                            .build()
                    ).join();

                    if (complianceResponse.complianceItems().isEmpty()) {
                        s = Status.NOT_APPLICABLE;
                        r = MAPPER.createObjectNode().put(Text.MESSAGE.toString(), Text.NO_COMPLIANCE_DATA_FOUND.toString());
                    } else {
                        boolean hasNonCompliant = complianceResponse.complianceItems().stream()
                            .anyMatch(item -> item.complianceType() != null
                                    && item.complianceType().equals("NonCompliant"));

                        s = hasNonCompliant ? Status.FAIL : Status.PASS;
                        r = MAPPER.valueToTree(complianceResponse);
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(inst.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_SSM_PATCH_COMPLIANCE, result, status);
        return status;
    }

    private Status checkEC2VpcEndpoints() {
        if (allVPCEndpoints.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_USE_VPC_ENDPOINTS,
                            Text.NO_VPC_ENDPOINTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allVPCEndpoints.stream()
            .map(vpce -> {
                boolean violation = !"com.amazonaws.ec2".equals(vpce.serviceName());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), vpce);
                return Map.<String, Object>of(vpce.vpcEndpointId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_USE_VPC_ENDPOINTS, result, status);
        return status;
    }

    private Status checkAccountLevelIMDSv2() {
        Status status;
        ObjectNode result = MAPPER.createObjectNode();

        try {
            GetInstanceMetadataDefaultsResponse response = ec2.getInstanceMetadataDefaults(
                    GetInstanceMetadataDefaultsRequest.builder().build()
            ).join();

            boolean imdsv2Required = false;
            if (response.accountLevel() != null) {
                imdsv2Required = response.accountLevel().httpTokens() == HttpTokensState.REQUIRED;
                result = MAPPER.valueToTree(response.accountLevel().toBuilder());
            } else {
                result.put(Text.MESSAGE.toString(), Text.NO_ACCOUNT_LEVEL_IMDS_DEFAULTS.toString());
            }
            status = imdsv2Required ? Status.PASS : Status.FAIL;
        } catch (Exception e) {
            status = Status.FAIL_EXCEPTION;
            result = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
        }

        writer.addToBuffer(AWSFinding.ACCOUNT_LEVEL_IMDSV2, result, status);
        return status;
    }

    private Status checkEC2InstancesTags() {
        if (allEC2Instances.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_INSTANCES_WITHOUT_TAGS,
                            Text.NO_EC2_INSTANCES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEC2Instances.stream()
            .map(inst -> {
                boolean violation = inst.tags() == null || inst.tags().isEmpty();
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), inst);
                return Map.<String, Object>of(inst.instanceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_INSTANCES_WITHOUT_TAGS, result, status);
        return status;
    }

    private Status checkPublicAMIs() {
        if (allAMIs.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_WITH_PUBLIC_AMIS,
                            Text.NO_AMIS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allAMIs.stream()
            .map(ami -> {
                boolean violation;
                try {
                    DescribeImageAttributeResponse response = ec2.describeImageAttribute(
                        DescribeImageAttributeRequest.builder()
                            .imageId(ami.imageId())
                            .attribute(ImageAttributeName.LAUNCH_PERMISSION)
                            .build()
                    ).join();

                    violation = response.launchPermissions() != null
                            && response.launchPermissions().stream()
                                .anyMatch(perm -> "all".equals(perm.group()));
                } catch (Exception e) {
                    violation = false;
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), ami);
                return Map.<String, Object>of(ami.imageId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EC2_WITH_PUBLIC_AMIS, result, status);
        return status;
    }

    private Status checkUnusedElasticIPsDeleted() {
        if (allElasticIPs.isEmpty()) {
            writer.addToBuffer(AWSFinding.UNUSED_ELASTIC_IPS_EXIST,
                            Text.NO_ELASTIC_IPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allElasticIPs.stream()
            .map(eip -> {
                Status s;
                ObjectNode r;
                try {
                    boolean hasInstanceAssociation = eip.associationId() != null && !eip.associationId().isEmpty();
                    boolean hasNetworkInterfaceAssociation = eip.networkInterfaceId() != null && !eip.networkInterfaceId().isEmpty();
                    s = hasInstanceAssociation || hasNetworkInterfaceAssociation ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(eip.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(eip.allocationId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.UNUSED_ELASTIC_IPS_EXIST, result, status);
        return status;
    }

    private Status checkUnusedNetworkInterfacesDeleted() {
        if (allNetworkInterfaces.isEmpty()) {
            writer.addToBuffer(AWSFinding.UNUSED_NETWORK_INTERFACES_EXIST,
                            Text.NO_NETWORK_INTERFACES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allNetworkInterfaces.stream()
            .map(ni -> {
                Status s;
                ObjectNode r;
                try {
                    boolean isUnused = "available".equals(ni.statusAsString());
                    boolean passes = !isUnused;
                    s = passes ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(ni.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(ni.networkInterfaceId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.UNUSED_NETWORK_INTERFACES_EXIST, result, status);
        return status;
    }
}
