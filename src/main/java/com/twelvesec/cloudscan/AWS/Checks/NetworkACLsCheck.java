package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import software.amazon.awssdk.services.ec2.model.NetworkAcl;
import software.amazon.awssdk.services.ec2.model.RuleAction;

public class NetworkACLsCheck implements CloudCheck {
    private List<NetworkAcl> allNetworkACLs;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;

    public NetworkACLsCheck(DataWriter writer, SharedDataProvider sharedDataProvider) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
    }

    @Override
    public void runAllChecks() {
        allNetworkACLs = sharedDataProvider.getAllNetworkACLs().join();

        subCheckResults.clear();
        subCheckResults.addAll(
            Stream.of(
                wrapCheck(this::NetworkACLWithAllPortsOpenToTheInternet,        AWSFinding.NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET, this::reportError),
                wrapCheck(this::NetworkACLAllowIngressFromTheInternetToPorts,   AWSFinding.NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET, this::reportError)
            )
            .map(Supplier::get)
            .toList()
        );
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllNetworkACLs()
            .thenCompose(NetworkACLs -> {
                this.allNetworkACLs = NetworkACLs;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::NetworkACLWithAllPortsOpenToTheInternet,        AWSFinding.NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET, this::reportError),
                    wrapCheck(this::NetworkACLAllowIngressFromTheInternetToPorts,   AWSFinding.NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status NetworkACLWithAllPortsOpenToTheInternet() {
        if (allNetworkACLs.isEmpty()) {
            writer.addToBuffer(AWSFinding.NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET, 
                            Text.NO_NETWORK_ACLS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allNetworkACLs.stream()
            .map(acl -> {
                LinkedHashMap<String,Object> rulesMap = acl.entries().stream()
                    .collect(Collectors.toMap(
                        entry -> String.format("%s - %d", (entry.egress() ? Text.EGRESS.toString() : Text.INGRESS.toString()), entry.ruleNumber()),
                        entry -> {
                            boolean violation =
                                entry.ruleAction() == RuleAction.ALLOW &&
                                !entry.egress() &&
                                (
                                    (entry.cidrBlock() != null && entry.cidrBlock().equals("0.0.0.0/0")) ||
                                    (entry.ipv6CidrBlock() != null && entry.ipv6CidrBlock().equals("::/0"))
                                ) &&
                                (
                                    "-1".equals(entry.protocol()) ||
                                    (entry.portRange() != null &&
                                    entry.portRange().from() == 0 &&
                                    entry.portRange().to() == 65535)
                                );
                            ObjectNode entryNode = MAPPER.valueToTree(entry.toBuilder());
                            Map<String,Object> inner = new HashMap<>();
                            inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                            inner.put(Text.RESULT.toString(), entryNode);
                            return inner;
                        },
                        (first, second) -> first, LinkedHashMap<String,Object>::new 
                    ));
                return Map.<String,Object>of(acl.networkAclId(), rulesMap);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET, result, status);
        return status;
    }

    private Status NetworkACLAllowIngressFromTheInternetToPorts() {
        if (allNetworkACLs.isEmpty()) {
            writer.addToBuffer(AWSFinding.NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET, 
                            Text.NO_NETWORK_ACLS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allNetworkACLs.stream()
            .map(acl -> {
                LinkedHashMap<String,Object> rulesMap = acl.entries().stream()
                    .collect(Collectors.toMap(
                        entry -> String.format("%s - %d", (entry.egress() ? Text.EGRESS.toString() : Text.INGRESS.toString()), entry.ruleNumber()),
                        entry -> {
                            boolean violation =
                                entry.ruleAction() == RuleAction.ALLOW &&
                                !entry.egress() &&
                                (
                                    (entry.cidrBlock() != null && entry.cidrBlock().equals("0.0.0.0/0")) ||
                                    (entry.ipv6CidrBlock() != null && entry.ipv6CidrBlock().equals("::/0"))
                                ) &&
                                (
                                    !"-1".equals(entry.protocol()) &&
                                    (entry.portRange() == null ||
                                    entry.portRange().from() != 0 ||
                                    entry.portRange().to() != 65535)
                                );
                            ObjectNode entryNode = MAPPER.valueToTree(entry.toBuilder());
                            Map<String,Object> inner = new HashMap<>();
                            inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
                            inner.put(Text.RESULT.toString(), entryNode);
                            return inner;
                        },
                        (first, second) -> first, LinkedHashMap<String,Object>::new 
                    ));
                return Map.<String,Object>of(acl.networkAclId(), rulesMap);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET, result, status);
        return status;
    }
}
