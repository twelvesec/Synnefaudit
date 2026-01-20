package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.ec2.model.NetworkAcl;
import software.amazon.awssdk.services.ec2.model.NetworkAclEntry;
import software.amazon.awssdk.services.ec2.model.RuleAction;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class NetworkACLsCheck implements CloudCheck {
    private List<NetworkAcl> allNetworkACLs;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;

    public NetworkACLsCheck(DataWriter writer, SharedDataProvider sharedDataProvider) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllNetworkACLs()
            .thenCompose(NetworkACLs -> {
                this.allNetworkACLs = NetworkACLs;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::NetworkACLWithAllPortsOpenToTheInternet,        AWSFinding.NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET, this::reportError),
                    wrapCheck(this::NetworkACLAllowIngressFromTheInternetToPorts,   AWSFinding.NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET, this::reportError),
                    wrapCheck(this::NetworkACLAllowIngressFromInternetToRDP,        AWSFinding.NETWORK_ACL_WITH_RDP_OPEN_TO_INTERNET, this::reportError),
                    wrapCheck(this::NetworkACLAllowIngressFromInternetToSSH,        AWSFinding.NETWORK_ACL_WITH_SSH_OPEN_TO_INTERNET, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkNetworkACL(Predicate<NetworkAclEntry> violationCondition, AWSFinding finding) {
        if (allNetworkACLs.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_NETWORK_ACLS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allNetworkACLs.stream()
            .map(acl -> Map.<String, Object>of(
                acl.networkAclId(),
                acl.entries().stream()
                    .collect(Collectors.toMap(
                        entry -> String.format("%s - %d", 
                            (entry.egress() ? Text.EGRESS.toString() : Text.INGRESS.toString()), 
                            entry.ruleNumber()),
                        entry -> createEntryResult(entry, violationCondition),
                        (first, _) -> first,
                        LinkedHashMap<String, Object>::new
                    ))
            ))
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Map<String, Object> createEntryResult(NetworkAclEntry entry, Predicate<NetworkAclEntry> violationCondition) {
        boolean violation = violationCondition.test(entry);
        ObjectNode entryNode = MAPPER.valueToTree(entry.toBuilder());
        
        Map<String, Object> inner = new HashMap<>();
        inner.put(Text.STATUS.toString(), violation ? Status.FAIL : Status.PASS);
        inner.put(Text.RESULT.toString(), entryNode);
        return inner;
    }

    private Predicate<NetworkAclEntry> isIngressFromInternet() {
        return entry -> !entry.egress() && 
            ((entry.cidrBlock() != null && entry.cidrBlock().equals("0.0.0.0/0")) ||
                (entry.ipv6CidrBlock() != null && entry.ipv6CidrBlock().equals("::/0")));
    }

    private Predicate<NetworkAclEntry> isAllowRule() {
        return entry -> entry.ruleAction() == RuleAction.ALLOW;
    }

    private Predicate<NetworkAclEntry> allPortsCondition() {
        return entry -> "-1".equals(entry.protocol())
            || (entry.portRange() != null
                && entry.portRange().from() == 0
                && entry.portRange().to() == 65535);
    }

    private Predicate<NetworkAclEntry> somePortsCondition() {
        return entry -> !"-1".equals(entry.protocol())
            && (entry.portRange() == null
                || entry.portRange().from() != 0
                || entry.portRange().to() != 65535);
    }

    private Predicate<NetworkAclEntry> portCondition(int port) {
        return entry -> "-1".equals(entry.protocol())
            || ("6".equals(entry.protocol())
                && (entry.portRange() == null
                || (entry.portRange().from() <= port && entry.portRange().to() >= port)));
    }

    private Status NetworkACLWithAllPortsOpenToTheInternet() {
        Predicate<NetworkAclEntry> condition = isAllowRule()
            .and(isIngressFromInternet())
            .and(allPortsCondition());
        return checkNetworkACL(condition, AWSFinding.NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET);
    }

    private Status NetworkACLAllowIngressFromTheInternetToPorts() {
        Predicate<NetworkAclEntry> condition = isAllowRule()
            .and(isIngressFromInternet())
            .and(somePortsCondition());
        return checkNetworkACL(condition, AWSFinding.NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET);
    }

    private Status NetworkACLAllowIngressFromInternetToRDP() {
        Predicate<NetworkAclEntry> condition = isAllowRule()
            .and(isIngressFromInternet())
            .and(portCondition(3389));
        return checkNetworkACL(condition, AWSFinding.NETWORK_ACL_WITH_RDP_OPEN_TO_INTERNET);
    }

    private Status NetworkACLAllowIngressFromInternetToSSH() {
        Predicate<NetworkAclEntry> condition = isAllowRule()
            .and(isIngressFromInternet())
            .and(portCondition(22));
        return checkNetworkACL(condition, AWSFinding.NETWORK_ACL_WITH_SSH_OPEN_TO_INTERNET);
    }
}
