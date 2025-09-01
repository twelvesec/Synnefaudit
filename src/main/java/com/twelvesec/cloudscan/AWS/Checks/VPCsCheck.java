package com.twelvesec.cloudscan.AWS.Checks;

import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.PaginatorHelper;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.DescribeFlowLogsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeFlowLogsResponse;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.FlowLog;
import software.amazon.awssdk.services.ec2.model.RouteTable;
import software.amazon.awssdk.services.ec2.model.RouteTableAssociation;
import software.amazon.awssdk.services.ec2.model.Subnet;
import software.amazon.awssdk.services.ec2.model.Vpc;
import software.amazon.awssdk.services.ec2.model.VpcEndpoint;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.GetPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyResponse;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionResponse;
import software.amazon.awssdk.services.networkfirewall.NetworkFirewallAsyncClient;
import software.amazon.awssdk.services.networkfirewall.model.DescribeFirewallRequest;
import software.amazon.awssdk.services.networkfirewall.model.Firewall;
import software.amazon.awssdk.services.networkfirewall.model.FirewallMetadata;
import software.amazon.awssdk.services.networkfirewall.model.ListFirewallsRequest;
import software.amazon.awssdk.services.networkfirewall.model.ListFirewallsResponse;

public class VPCsCheck implements CloudCheck {
    private List<Vpc> allVPCs;
    private List<VpcEndpoint> allVPCEndpoints;
    private List<Subnet> allVPCSubnets;
    private Map<String, List<Subnet>> subnetsByVpc;
    private List<RouteTable> allRouteTables;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final Ec2AsyncClient ec2;
    private final NetworkFirewallAsyncClient networkFirewall;
    private final IamAsyncClient iam;

    public VPCsCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    Ec2AsyncClient ec2, NetworkFirewallAsyncClient networkFirewall, IamAsyncClient iam) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.ec2 = ec2;
        this.networkFirewall = networkFirewall;
        this.iam = iam;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllVPCs()
            .thenCompose(vpcs -> {
                this.allVPCs = vpcs;
                return sharedDataProvider.getAllVPCEndpoints();
            })
            .thenCompose(endpoints -> {
                this.allVPCEndpoints = endpoints;
                return sharedDataProvider.getAllVPCSubnets();
            })
            .thenCompose(subnets -> {
                this.allVPCSubnets = subnets;
                this.subnetsByVpc = subnets.stream()
                    .collect(Collectors.groupingBy(Subnet::vpcId));
                return sharedDataProvider.getAllRouteTables();
            })
            .thenCompose(routeTables -> {
                this.allRouteTables = routeTables;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::VPCFirewallDisabled,            AWSFinding.VPC_FIREWALL_DISABLED, this::reportError),
                    wrapCheck(this::VPCFlowLoggingDisabled,         AWSFinding.VPC_FLOW_LOGGING_DISABLED, this::reportError),
                    wrapCheck(this::VPCSubnetsAssignPublicIP,       AWSFinding.VPC_SUBNETS_PUBLIC_IP_ON_LAUNCH, this::reportError),
                    wrapCheck(this::VPCEndpointsAllowFullAccess,    AWSFinding.VPC_ENDPOINTS_ALLOW_FULL_ACCESS, this::reportError),
                    wrapCheck(this::checkVpcsWithOnlyPublicSubnets, AWSFinding.VPCS_WITH_ONLY_PUBLIC_SUBNETS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status VPCFirewallDisabled() {
        if (allVPCs.isEmpty()) {
            writer.addToBuffer(AWSFinding.VPC_FIREWALL_DISABLED, 
                            Text.NO_VPCS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allVPCs.stream()
            .map(vpc -> {
                String vpcId = vpc.vpcId(); 
                List<FirewallMetadata> allFirewalls = PaginatorHelper.collectPaginatedItems(
                    networkFirewall.listFirewallsPaginator(ListFirewallsRequest.builder().build()),
                    ListFirewallsResponse::firewalls
                ).join();
                
                List<String> matching = allFirewalls.stream()
                    .filter(meta -> {
                        Firewall fw = networkFirewall.describeFirewall(
                            DescribeFirewallRequest.builder().firewallArn(meta.firewallArn()).build()
                        ).join().firewall();
                        return vpcId.equals(fw.vpcId());
                    })
                    .map(FirewallMetadata::firewallArn)
                    .toList();

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), matching.isEmpty() ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), matching.isEmpty() ? Text.NO_FIREWALLS_ASSOCIATED_WITH_VPC.toString() : String.join(", ", matching));
                return Map.<String,Object>of(vpcId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.VPC_FIREWALL_DISABLED, result, status);
        return status;
    }

    private Status VPCFlowLoggingDisabled() {
        if (allVPCs.isEmpty()) {
            writer.addToBuffer(AWSFinding.VPC_FLOW_LOGGING_DISABLED, 
                            Text.NO_VPCS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allVPCs.stream()
            .map(vpc -> {
                String vpcId = vpc.vpcId();
                List<FlowLog> flowLogs = PaginatorHelper.collectPaginatedItems(
                    ec2.describeFlowLogsPaginator(
                        DescribeFlowLogsRequest.builder()
                            .filter(Filter.builder().name("resource-id").values(vpcId).build()).build()
                    ),
                    DescribeFlowLogsResponse::flowLogs
                ).join();
                
                List<Map<String,Object>> serializedLogs = flowLogs.stream()
                    .<Map<String,Object>>map(log -> Map.of(
                        "flowLogId", log.flowLogId(),
                        "resourceId", log.resourceId(),
                        "trafficType", log.trafficTypeAsString(),
                        "logGroupName", log.logGroupName(),
                        "flowLogStatus", log.flowLogStatus(),
                        "creationTime", log.creationTime()
                    ))
                    .toList();

                Map<String,Object> inner = new HashMap<>();
                Status s = serializedLogs.isEmpty() ? Status.FAIL : Status.PASS;
                Object r = serializedLogs.isEmpty()
                    ? Text.FLOW_LOGGING_DISABLED_FOR_VPC.toString()
                    : serializedLogs;

                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(vpcId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.VPC_FLOW_LOGGING_DISABLED, result, status);
        return status;
    }

    private Status VPCSubnetsAssignPublicIP() {
        if (allVPCSubnets.isEmpty()) {
            writer.addToBuffer(AWSFinding.VPC_SUBNETS_PUBLIC_IP_ON_LAUNCH, 
                            Text.NO_VPC_SUBNETS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allVPCSubnets.stream()
            .map(sub -> {
                boolean violation = sub.mapPublicIpOnLaunch();
                ObjectNode r = MAPPER.valueToTree(sub.toBuilder());
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(sub.subnetId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.VPC_SUBNETS_PUBLIC_IP_ON_LAUNCH, result, status);
        return status;
    }

    private Status VPCEndpointsAllowFullAccess() {
        if (allVPCEndpoints.isEmpty()) {
            writer.addToBuffer(AWSFinding.VPC_ENDPOINTS_ALLOW_FULL_ACCESS, 
                            Text.NO_VPC_ENDPOINTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        final String fullAccessArn = Text.POLICY_AMAZON_VPC_ENDPOINT_FULL_ACCESS.toString();
        
        GetPolicyResponse policyResp = iam.getPolicy(
            GetPolicyRequest.builder().policyArn(fullAccessArn).build()
        ).join();
        String versionId = policyResp.policy().defaultVersionId();
        GetPolicyVersionResponse versionResp = iam.getPolicyVersion(
            GetPolicyVersionRequest.builder().policyArn(fullAccessArn).versionId(versionId).build()
        ).join();
        String managedDocJson = URLDecoder.decode(
            versionResp.policyVersion().document(),
            StandardCharsets.UTF_8
        );

        String targetCanonical;
        try {
            JsonNode targetNode = MAPPER.readTree(managedDocJson);
            targetCanonical = MAPPER.writeValueAsString(targetNode);
        } catch (Exception e) {
            writer.addToBuffer(AWSFinding.VPC_ENDPOINTS_ALLOW_FULL_ACCESS, 
                            Text.EXCEPTION.toString().concat(e.getMessage()), Status.FAIL_EXCEPTION);
            return Status.FAIL_EXCEPTION;
        }

        List<Map<String,Object>> result = allVPCEndpoints.stream()
            .map(ep -> {
                Status s;
                ObjectNode r;
                try {
                    JsonNode policyNode = MAPPER.readTree(ep.policyDocument());
                    String actualCanonical = MAPPER.writeValueAsString(policyNode);
                    s = actualCanonical.equals(targetCanonical) ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(policyNode);
                } catch (IOException e) {
                    s = Status.FAIL;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(ep.vpcEndpointId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer( AWSFinding.VPC_ENDPOINTS_ALLOW_FULL_ACCESS, result, status);
        return status;
    }

    private Status checkVpcsWithOnlyPublicSubnets() {
        if (allVPCs.isEmpty()) {
            writer.addToBuffer(AWSFinding.VPCS_WITH_ONLY_PUBLIC_SUBNETS, 
                            Text.NO_VPCS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> publicSubnetIds = allRouteTables.stream()
            .flatMap(rt -> {
                boolean hasIGW = rt.routes().stream()
                    .anyMatch(route -> route.gatewayId() != null && route.gatewayId().startsWith("igw-"));
                if (!hasIGW) return Stream.empty();

                return rt.associations().stream()
                    .filter(assoc -> assoc.subnetId() != null)
                    .map(RouteTableAssociation::subnetId);
            })
            .collect(Collectors.toSet());

        List<Map<String, Object>> result = allVPCs.stream()
            .map(vpc -> {
                String vpcId = vpc.vpcId();
                List<Subnet> subnets = subnetsByVpc.getOrDefault(vpcId, List.of());
                boolean allPublic = !subnets.isEmpty() && subnets.stream()
                    .allMatch(subnet -> publicSubnetIds.contains(subnet.subnetId()));

                Status s = allPublic ? Status.FAIL : Status.PASS;

                ArrayNode subnetArray = MAPPER.createArrayNode();
                subnets.forEach(subnet ->
                    subnetArray.add(MAPPER.valueToTree(subnet.toBuilder()))
                );

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.set(Text.RESULT.toString(), subnetArray);

                return Map.<String, Object>of(vpcId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.VPCS_WITH_ONLY_PUBLIC_SUBNETS, result, status);
        return status;
    }
}
