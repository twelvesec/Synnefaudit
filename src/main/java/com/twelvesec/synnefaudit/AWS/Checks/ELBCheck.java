package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2AsyncClient;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.*;
import software.amazon.awssdk.services.wafv2.Wafv2AsyncClient;
import software.amazon.awssdk.services.wafv2.model.GetWebAclForResourceRequest;
import software.amazon.awssdk.services.wafv2.model.GetWebAclForResourceResponse;
import software.amazon.awssdk.services.wafv2.model.WafNonexistentItemException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class ELBCheck implements CloudCheck {
    private List<LoadBalancer> allLoadBalancers;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final ElasticLoadBalancingV2AsyncClient elb;
    private final Wafv2AsyncClient waf;
    private final JsonNode config;

    private final Map<String, String> TLS_1_2_OR_HIGHER_POLICIES;

    public ELBCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                    ElasticLoadBalancingV2AsyncClient elb, Wafv2AsyncClient waf, JsonNode config) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.elb = elb;
        this.waf = waf;
        this.config = config;

        TLS_1_2_OR_HIGHER_POLICIES = getStringMap(config.path("tls_1_2_or_higher_policies"));
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<LoadBalancer>> loadBalancers = sharedDataProvider.getAllLoadBalancers()
                .exceptionally(ex -> null);

        return loadBalancers.thenCompose(lb -> {
            this.allLoadBalancers = lb;

            List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkELBWithNoWAFACLAttached,                            AWSFinding.ELB_WITHOUT_WAF_ACL_ATTACHED, this::reportError),
                    wrapCheck(this::checkELBALBWithAccessLoggingDisabled,                    AWSFinding.ELB_ALBS_ACCESS_LOGGING_DISABLED, this::reportError),
                    wrapCheck(this::checkELBWithDeletionProtectionDisabled,                  AWSFinding.ELB_DELETION_PROTECTION_DISABLED, this::reportError),
                    wrapCheck(this::checkELBListenerWithoutSSLFound,                         AWSFinding.ELB_LISTENER_WITHOUT_SSL, this::reportError),
                    wrapCheck(this::checkPubliclyAccessibleLoadBalancers,                    AWSFinding.PUBLICLY_ACCESSIBLE_LOAD_BALANCERS, this::reportError),
                    wrapCheck(this::checkAlbsDefensiveMitigationButNotDroppingInvalidHeaders,AWSFinding.ELB_ALBS_DEFENSIVE_MITIGATION_NOT_DROPPING_HEADERS, this::reportError),
                    wrapCheck(this::checkELBWithoutListeners,                                AWSFinding.ELB_WITHOUT_LISTENERS, this::reportError),
                    wrapCheck(this::checkUnusedElasticLoadBalancersDeleted,                  AWSFinding.UNUSED_ELASTIC_LOAD_BALANCERS_EXIST, this::reportError),
                    wrapCheck(this::checkELBSecureSSLPolicies,                               AWSFinding.ELB_SECURE_SSL_POLICIES, this::reportError),
                    wrapCheck(this::checkELBAccessLogsS3Enabled,                             AWSFinding.ELB_ACCESS_LOGS_S3_ENABLED, this::reportError),
                    wrapCheck(this::checkELBOnlyHttpsOrSslListeners,                         AWSFinding.ELB_ONLY_HTTPS_OR_SSL_LISTENERS, this::reportError)
            );
            return runChecksInList(checksList, writer);
        });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkELBWithNoWAFACLAttached() { 
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_WITHOUT_WAF_ACL_ATTACHED, 
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allLoadBalancers.stream()
            .map(lb -> {
                String arn = lb.loadBalancerArn();
                Status s;
                ObjectNode r;
                try {
                    GetWebAclForResourceResponse response = waf.getWebACLForResource(
                        GetWebAclForResourceRequest.builder().resourceArn(arn).build()
                    ).join();
                    s = Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (WafNonexistentItemException e) {
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
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_WITHOUT_WAF_ACL_ATTACHED, result, status);
        return status;
    }

    private Status checkELBALBWithAccessLoggingDisabled() { 
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_ALBS_ACCESS_LOGGING_DISABLED, 
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allLoadBalancers.stream()
            .filter(lb -> lb.type() == LoadBalancerTypeEnum.APPLICATION)
            .map(lb -> {
                Status s;
                ObjectNode r;
                String arn = lb.loadBalancerArn();
                try {
                    DescribeLoadBalancerAttributesResponse response =
                        elb.describeLoadBalancerAttributes(
                            DescribeLoadBalancerAttributesRequest.builder().loadBalancerArn(arn).build()
                        ).join();

                    boolean violation = response.attributes().stream()
                        .filter(attr -> "access_logs.s3.enabled".equals(attr.key()))
                        .anyMatch(attr -> "false".equalsIgnoreCase(attr.value()));
                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_ALBS_ACCESS_LOGGING_DISABLED, result, status);
        return status;
    }

    private Status checkELBWithDeletionProtectionDisabled() { 
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_DELETION_PROTECTION_DISABLED, 
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allLoadBalancers.stream()
            .map(lb -> {
                Status s;
                ObjectNode r;
                String arn;
                try {
                    arn = lb.loadBalancerArn();
                    DescribeLoadBalancerAttributesResponse response =
                        elb.describeLoadBalancerAttributes(
                            DescribeLoadBalancerAttributesRequest.builder().loadBalancerArn(arn).build()
                        ).join();
                    boolean violation = response.attributes().stream()
                        .filter(attribute -> "deletion_protection.enabled".equals(attribute.key()))
                        .anyMatch(attribute -> "false".equalsIgnoreCase(attribute.value()));
                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    arn = "UNKNOWN";
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_DELETION_PROTECTION_DISABLED, result, status);
        return status;
    }

    private Status checkELBListenerWithoutSSLFound() { 
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_LISTENER_WITHOUT_SSL, 
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allLoadBalancers.stream()
            .map(lb -> {
                Status s;
                ObjectNode r;
                String arn = lb.loadBalancerArn();
                try {
                    DescribeListenersResponse response = elb.describeListeners(
                            DescribeListenersRequest.builder().loadBalancerArn(arn).build()
                        ).join();

                    boolean violation = response.listeners().stream()
                        .anyMatch(listener -> {
                            String protocol = listener.protocolAsString();
                            boolean isSecure = "HTTPS".equalsIgnoreCase(protocol) 
                                            || "TLS".equalsIgnoreCase(protocol);
                            boolean hasCerts = listener.certificates() != null
                                            && !listener.certificates().isEmpty();
                            return !(isSecure && hasCerts);
                        });
                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_LISTENER_WITHOUT_SSL, result, status);
        return status;
    }

    private Status checkPubliclyAccessibleLoadBalancers() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.PUBLICLY_ACCESSIBLE_LOAD_BALANCERS, 
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLoadBalancers.stream()
            .map(lb -> {
                Status s;
                ObjectNode r;
                String name= lb.loadBalancerName();
                try {
                    String scheme = lb.scheme().toString();
                    s = "internet-facing".equalsIgnoreCase(scheme) ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(lb.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(name, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.PUBLICLY_ACCESSIBLE_LOAD_BALANCERS, result, status);
        return status;
    }

    private Status checkAlbsDefensiveMitigationButNotDroppingInvalidHeaders() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_ALBS_DEFENSIVE_MITIGATION_NOT_DROPPING_HEADERS,
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allLoadBalancers.stream()
            .map(lb -> {
                String arn = lb.loadBalancerArn();
                Status s;
                ObjectNode r;
                try {
                    DescribeLoadBalancerAttributesResponse response = elb.describeLoadBalancerAttributes(
                        DescribeLoadBalancerAttributesRequest.builder().loadBalancerArn(arn).build()
                    ).join();
                    Map<String,String> attrs = response.attributes().stream()
                        .collect(Collectors.toMap(LoadBalancerAttribute::key, LoadBalancerAttribute::value));

                    String desyncMode = attrs.getOrDefault(
                        "routing.http.desync_mitigation_mode",
                        "NONE"
                    );
                    boolean dropInvalid = Boolean.parseBoolean(
                        attrs.getOrDefault(
                            "routing.http.drop_invalid_header_fields.enabled",
                            "false"
                        )
                    );
                    boolean violation = "defensive".equalsIgnoreCase(desyncMode) && !dropInvalid;

                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_ALBS_DEFENSIVE_MITIGATION_NOT_DROPPING_HEADERS, result, status);
        return status;
    }

    private Status checkELBWithoutListeners() {
        if (allLoadBalancers == null || allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_WITHOUT_LISTENERS, 
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLoadBalancers.stream()
            .map(loadBalancer -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    DescribeListenersResponse listenersResponse = elb.describeListeners(
                        DescribeListenersRequest.builder()
                            .loadBalancerArn(loadBalancer.loadBalancerArn())
                            .build()
                    ).join();

                    List<Listener> listeners = listenersResponse.listeners();
                    boolean hasListeners = !listeners.isEmpty();
                    
                    s = hasListeners ? Status.PASS : Status.FAIL;
                    
                    r.put("loadBalancerArn", loadBalancer.loadBalancerArn());
                    r.put("loadBalancerName", loadBalancer.loadBalancerName());
                    r.put("loadBalancerType", loadBalancer.typeAsString());
                    r.put("scheme", loadBalancer.scheme().toString());
                    r.put("hasListeners", hasListeners);
                    r.put("listenerCount", listeners.size());
                    
                    if (!listeners.isEmpty()) {
                        ArrayNode listenersNode = MAPPER.valueToTree(
                            listeners.stream()
                                .map(listener -> Map.of(
                                    "listenerArn", listener.listenerArn(),
                                    "port", listener.port(),
                                    "protocol", listener.protocolAsString()
                                ))
                                .collect(Collectors.toList())
                        );
                        r.put("listeners", listenersNode);
                    }
                    
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    r.put("loadBalancerArn", loadBalancer.loadBalancerArn());
                    r.put("loadBalancerName", loadBalancer.loadBalancerName());
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(loadBalancer.loadBalancerArn(), inner);
            })
            .collect(Collectors.toList());
        
        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_WITHOUT_LISTENERS, result, status);
        return status;
    }

    private Status checkUnusedElasticLoadBalancersDeleted() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.UNUSED_ELASTIC_LOAD_BALANCERS_EXIST,
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allLoadBalancers.stream()
            .map(lb -> {
                String arn = lb.loadBalancerArn();
                Status s;
                ObjectNode r;
                try {
                    DescribeTargetGroupsResponse tgResponse = elb.describeTargetGroups(
                        DescribeTargetGroupsRequest.builder().loadBalancerArn(arn).build()
                    ).join();

                    boolean hasActiveTargets = tgResponse.targetGroups().stream()
                        .anyMatch(tg -> {
                            DescribeTargetHealthResponse healthResponse = elb.describeTargetHealth(
                                DescribeTargetHealthRequest.builder().targetGroupArn(tg.targetGroupArn()).build()
                            ).join();
                            return healthResponse.targetHealthDescriptions().stream()
                                .anyMatch(thd -> "healthy".equals(thd.targetHealth().stateAsString()));
                        });

                    s = hasActiveTargets ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(lb.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.UNUSED_ELASTIC_LOAD_BALANCERS_EXIST, result, status);
        return status;
    }

    private Status checkELBSecureSSLPolicies() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_SECURE_SSL_POLICIES,
                    Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLoadBalancers.stream()
                .map(lb -> {
                    String arn = lb.loadBalancerArn();
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeListenersResponse response = elb.describeListeners(
                                DescribeListenersRequest.builder().loadBalancerArn(arn).build()
                        ).join();

                        boolean violation = response.listeners().stream()
                                .filter(listener -> {
                                    String protocol = listener.protocolAsString();
                                    return "HTTPS".equalsIgnoreCase(protocol) || "TLS".equalsIgnoreCase(protocol);
                                })
                                .anyMatch(listener -> !isTls12OrHigherPolicy(listener.sslPolicy()));

                        s = violation ? Status.FAIL : Status.PASS;
                        r = MAPPER.valueToTree(response.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(arn, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_SECURE_SSL_POLICIES, result, status);
        return status;
    }

    private boolean isTls12OrHigherPolicy(String sslPolicy) {
        if (sslPolicy == null || sslPolicy.isEmpty() || TLS_1_2_OR_HIGHER_POLICIES == null) {
            return false;
        }
        return TLS_1_2_OR_HIGHER_POLICIES.values().stream()
                .anyMatch(policies -> policies != null && policies.contains(sslPolicy));
    }

    private Status checkELBAccessLogsS3Enabled() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_ACCESS_LOGS_S3_ENABLED,
                    Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLoadBalancers.stream()
                .map(lb -> {
                    String arn = lb.loadBalancerArn();
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeLoadBalancerAttributesResponse response = elb.describeLoadBalancerAttributes(
                                DescribeLoadBalancerAttributesRequest.builder().loadBalancerArn(arn).build()
                        ).join();

                        boolean logsEnabled = response.attributes().stream()
                                .filter(attr -> "access_logs.s3.enabled".equals(attr.key()))
                                .anyMatch(attr -> "true".equalsIgnoreCase(attr.value()));

                        s = logsEnabled ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(response.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(arn, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_ACCESS_LOGS_S3_ENABLED, result, status);
        return status;
    }

    private Status checkELBOnlyHttpsOrSslListeners() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_ONLY_HTTPS_OR_SSL_LISTENERS,
                    Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLoadBalancers.stream()
                .map(lb -> {
                    String arn = lb.loadBalancerArn();
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeListenersResponse response = elb.describeListeners(
                                DescribeListenersRequest.builder().loadBalancerArn(arn).build()
                        ).join();

                        List<Listener> listeners = response.listeners();

                        if (listeners.isEmpty()) {
                            s = Status.FAIL;
                        } else {
                            boolean allSecure = listeners.stream().allMatch(listener -> {
                                String protocol = listener.protocolAsString();
                                return "HTTPS".equalsIgnoreCase(protocol)
                                        || "SSL".equalsIgnoreCase(protocol)
                                        || "TLS".equalsIgnoreCase(protocol);
                            });
                            s = allSecure ? Status.PASS : Status.FAIL;
                        }

                        r = MAPPER.valueToTree(response.toBuilder());
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                Text.EXCEPTION.toString().concat(e.getMessage()));
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(arn, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_ONLY_HTTPS_OR_SSL_LISTENERS, result, status);
        return status;
    }
}
