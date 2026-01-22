package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.ssm.model.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class EC2SecurityGroupCheck implements CloudCheck {
    private List<String> allGroupIds;
    private List<SecurityGroup> allGroups;
    private List<SecurityGroup> allEC2Groups;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final Ec2AsyncClient ec2;

    public EC2SecurityGroupCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                    Ec2AsyncClient ec2) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.ec2 = ec2;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllSecurityGroupIds()
            .thenCompose(securityGroupIds -> {
                this.allGroupIds = securityGroupIds;
                return sharedDataProvider.getAllSecurityGroups();
            })
            .thenCompose(securityGroups -> {
                this.allGroups = securityGroups;
                return sharedDataProvider.getEC2AttachedSecurityGroups();
            })
            .thenCompose(EC2SecurityGroups -> {
                this.allEC2Groups = EC2SecurityGroups;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkSecurityGroupAllowIngressFromNonRFC1918Address,    AWSFinding.EC2_SECURITY_GROUP_NON_RFC1918_INGRESS, this::reportError),
                    wrapCheck(this::checkSecurityGroupsNotUsed,                             AWSFinding.SECURITY_GROUPS_NOT_USED, this::reportError),

                    wrapCheck(this::checkAllSecurityGroupsAllPortsPublic,                   AWSFinding.SECURITY_GROUP_ALL_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsAnyPortPublic,                    AWSFinding.SECURITY_GROUP_ANY_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsCassandraPortsPublic,             AWSFinding.SECURITY_GROUP_CASSANDRA_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsElasticsearchKibanaPortsPublic,   AWSFinding.SECURITY_GROUP_ELASTICSEARCH_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsFTPPortsPublic,                   AWSFinding.SECURITY_GROUP_FTP_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsKafkaPortPublic,                  AWSFinding.SECURITY_GROUP_KAFKA_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsMemcachedPortPublic,              AWSFinding.SECURITY_GROUP_MEMCACHED_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsMongoDBPortsPublic,               AWSFinding.SECURITY_GROUP_MONGODB_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsMySQLPortPublic,                  AWSFinding.SECURITY_GROUP_MYSQL_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsOraclePortsPublic,                AWSFinding.SECURITY_GROUP_ORACLE_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsRDPPortPublic,                    AWSFinding.SECURITY_GROUP_RDP_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsRedisPortPublic,                  AWSFinding.SECURITY_GROUP_POSTGRES_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsSSHPortPublic,                    AWSFinding.SECURITY_GROUP_REDIS_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsTelnetPortPublic,                 AWSFinding.SECURITY_GROUP_SSH_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsWindowsSQLServerPortsPublic,      AWSFinding.SECURITY_GROUP_TELNET_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsPostgreSQLPortPublic,             AWSFinding.SECURITY_GROUP_SQLSERVER_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkAllSecurityGroupsHighRiskPortsPublic,              AWSFinding.SECURITY_GROUP_HIGH_RISK_PORTS_PUBLIC, this::reportError),

                    wrapCheck(this::checkEC2AttachedCassandraPorts,                         AWSFinding.EC2_CASSANDRA_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedElasticsearchKibanaPorts,               AWSFinding.EC2_ELASTICSEARCH_KIBANA_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedMemcachedPort,                          AWSFinding.EC2_MEMCACHED_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedCIFSPorts,                              AWSFinding.EC2_CIFS_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedMicrosoftSQLServerPorts,                AWSFinding.EC2_WINDOWS_SQL_SERVER_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedOraclePorts,                            AWSFinding.EC2_ORACLE_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedFtpPorts,                               AWSFinding.EC2_FTP_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedSshPort,                                AWSFinding.EC2_SSH_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedTelnetPort,                             AWSFinding.EC2_TELNET_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedMongoDBPorts,                           AWSFinding.EC2_MONGODB_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedMySQLPort,                              AWSFinding.EC2_MYSQL_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedRdpPort,                                AWSFinding.EC2_RDP_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedLDAPPorts,                              AWSFinding.EC2_LDAP_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedPostgreSQLPort,                         AWSFinding.EC2_POSTGRESQL_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedRedisPort,                              AWSFinding.EC2_REDIS_PORT_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedKerberosPorts,                          AWSFinding.EC2_KERBEROS_PORTS_PUBLIC, this::reportError),
                    wrapCheck(this::checkEC2AttachedKafkaPort,                              AWSFinding.EC2_KAFKA_PORT_PUBLIC, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkSecurityGroupAllowIngressFromNonRFC1918Address() {
        if (allGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.EC2_SECURITY_GROUP_NON_RFC1918_INGRESS,
                            Text.NO_SECURITY_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allGroups.stream()
            .map(sg -> {
                Status s;
                String r;
                try {
                    List<String> badCidrs = sg.ipPermissions().stream()
                        .flatMap(perm -> {
                            Stream<String> v4 = perm.ipRanges().stream()
                                .map(IpRange::cidrIp)
                                .filter(cidr -> !isRfc1918(cidr));

                            Stream<String> v6 = perm.ipv6Ranges().stream()
                                .map(Ipv6Range::cidrIpv6)
                                .filter("::/0"::equals);

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

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(sg.securityGroupArn(), inner);
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
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(groupId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.SECURITY_GROUPS_NOT_USED, result, status);
        return status;
    }

    private boolean isPortInRange(int port, Integer fromPort, Integer toPort) {
        if (fromPort == null || toPort == null) return false;
        return port >= fromPort && port <= toPort;
    }

    private enum SecGroupPortMode {
        ALL_PORTS,
        ANY_PORT,
        HIGH_RISK,
        SPECIFIC_PORTS
    }

    private boolean hasPublicAccessToPorts(IpPermission permission, Set<Integer> targetPorts, SecGroupPortMode mode) {
        boolean hasPublicIPv4 = permission.ipRanges().stream().anyMatch(range -> "0.0.0.0/0".equals(range.cidrIp()));
        boolean hasPublicIPv6 = permission.ipv6Ranges().stream().anyMatch(range -> "::/0".equals(range.cidrIpv6()));

        if (!hasPublicIPv4 && !hasPublicIPv6) {
            return false;
        }

        String protocol = permission.ipProtocol();
        boolean isTCP = "tcp".equalsIgnoreCase(protocol) || "6".equals(protocol);
        boolean isAllProtocols = "-1".equals(protocol);

        if (!isTCP && !isAllProtocols) {
            return false;
        }

        Integer permissionFromPort = permission.fromPort();
        Integer permissionToPort = permission.toPort();

        final int fromPort;
        final int toPort;

        if (isAllProtocols && (permissionFromPort == null || permissionToPort == null)) {
            fromPort = 0;
            toPort = 65535;
        } else if (permissionFromPort == null || permissionToPort == null) {
            return false;
        } else {
            fromPort = permissionFromPort;
            toPort = permissionToPort;
        }

        return switch (mode) {
            case SecGroupPortMode.ALL_PORTS ->
                fromPort == 0 && toPort == 65535;
            case SecGroupPortMode.ANY_PORT ->
                true;
            case SecGroupPortMode.HIGH_RISK ->
                fromPort <= 1024 && toPort >= 1;
            default ->
                targetPorts.stream().anyMatch(port -> isPortInRange(port, fromPort, toPort));
        };
    }

    private Status runSecurityGroupPortCheck(List<SecurityGroup> securityGroups, AWSFinding finding,
                                             Set<Integer> ports, SecGroupPortMode mode) {
        if (securityGroups.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_SECURITY_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = securityGroups.stream()
            .map(sg -> {
                boolean hasViolation = sg.ipPermissions().stream()
                        .anyMatch(permission -> hasPublicAccessToPorts(permission, ports, mode));
                Status status = hasViolation ? Status.FAIL : Status.PASS;

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status);
                inner.put(Text.RESULT.toString(), sg.toBuilder());

                switch (mode) {
                    case SecGroupPortMode.ALL_PORTS ->
                            inner.put(Text.MESSAGE.toString(), "All ports (0-65535) open to public internet");
                    case SecGroupPortMode.ANY_PORT ->
                            inner.put(Text.MESSAGE.toString(), "One or more ports open to public internet");
                    case SecGroupPortMode.HIGH_RISK ->
                            inner.put(Text.MESSAGE.toString(), "High-risk ports (1-1024) open to public internet");
                    default -> {
                        String portsStr = ports.stream()
                                .sorted()
                                .map(String::valueOf)
                                .collect(Collectors.joining(", "));
                        String message = hasViolation ?
                                String.format("Public Ports (%s) found.", portsStr) :
                                String.format("Not Public Ports (%s) found.", portsStr);
                        inner.put(Text.MESSAGE.toString(), message);
                    }
                }
                return Map.<String, Object>of(sg.groupId(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Status checkAllSecurityGroupsAllPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_ALL_PORTS_PUBLIC,
                Collections.emptySet(), SecGroupPortMode.ALL_PORTS);
    }

    private Status checkAllSecurityGroupsAnyPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_ANY_PORT_PUBLIC,
                Collections.emptySet(), SecGroupPortMode.ANY_PORT);
    }

    private Status checkAllSecurityGroupsCassandraPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_CASSANDRA_PORTS_PUBLIC,
                Set.of(7199, 9160, 8888), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsElasticsearchKibanaPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_ELASTICSEARCH_PORTS_PUBLIC,
                Set.of(9200, 9300, 5601), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsFTPPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_FTP_PORTS_PUBLIC,
                Set.of(20, 21), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsKafkaPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_KAFKA_PORT_PUBLIC,
                Set.of(9092), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsMemcachedPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_MEMCACHED_PORT_PUBLIC,
                Set.of(11211), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsMongoDBPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_MONGODB_PORTS_PUBLIC,
                Set.of(27017, 27018), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsMySQLPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_MYSQL_PORT_PUBLIC,
                Set.of(3306), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsOraclePortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_ORACLE_PORTS_PUBLIC,
                Set.of(1521, 2483), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsRDPPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_RDP_PORT_PUBLIC,
                Set.of(3389), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsPostgreSQLPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_POSTGRES_PORT_PUBLIC,
                Set.of(5432), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsRedisPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_REDIS_PORT_PUBLIC,
                Set.of(6379), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsSSHPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_SSH_PORT_PUBLIC,
                Set.of(22), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsTelnetPortPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_TELNET_PORT_PUBLIC,
                Set.of(23), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsWindowsSQLServerPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_SQLSERVER_PORTS_PUBLIC,
                Set.of(1433, 1434), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkAllSecurityGroupsHighRiskPortsPublic() {
        return runSecurityGroupPortCheck(allGroups, AWSFinding.SECURITY_GROUP_HIGH_RISK_PORTS_PUBLIC,
                Collections.emptySet(), SecGroupPortMode.HIGH_RISK);
    }

    private Status checkEC2AttachedCassandraPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_CASSANDRA_PORTS_PUBLIC,
                Set.of(7000, 7001, 7199, 9042, 9160), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedElasticsearchKibanaPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_ELASTICSEARCH_KIBANA_PORTS_PUBLIC,
                Set.of(9200, 9300, 5601), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedMemcachedPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_MEMCACHED_PORT_PUBLIC,
                Set.of(11211), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedCIFSPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_CIFS_PORTS_PUBLIC,
                Set.of(139, 445), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedMicrosoftSQLServerPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_WINDOWS_SQL_SERVER_PORTS_PUBLIC,
                Set.of(1433, 1434), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedOraclePorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_ORACLE_PORTS_PUBLIC,
                Set.of(1521, 2483, 2484), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedFtpPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_FTP_PORTS_PUBLIC,
                Set.of(20, 21), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedSshPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_SSH_PORT_PUBLIC,
                Set.of(22), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedTelnetPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_TELNET_PORT_PUBLIC,
                Set.of(23), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedMongoDBPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_MONGODB_PORTS_PUBLIC,
                Set.of(27017, 27018), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedMySQLPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_MYSQL_PORT_PUBLIC,
                Set.of(3306), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedRdpPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_RDP_PORT_PUBLIC,
                Set.of(3389), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedLDAPPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_LDAP_PORTS_PUBLIC,
                Set.of(389, 636), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedPostgreSQLPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_POSTGRESQL_PORT_PUBLIC,
                Set.of(5432), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedRedisPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_REDIS_PORT_PUBLIC,
                Set.of(6379), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedKerberosPorts() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_KERBEROS_PORTS_PUBLIC,
                Set.of(88, 464, 749, 750), SecGroupPortMode.SPECIFIC_PORTS);
    }

    private Status checkEC2AttachedKafkaPort() {
        return runSecurityGroupPortCheck(allEC2Groups, AWSFinding.EC2_KAFKA_PORT_PUBLIC,
                Set.of(9092), SecGroupPortMode.SPECIFIC_PORTS);
    }
}
