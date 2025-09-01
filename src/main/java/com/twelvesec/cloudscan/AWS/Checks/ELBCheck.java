package com.twelvesec.cloudscan.AWS.Checks;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2AsyncClient;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeListenersRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeListenersResponse;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeLoadBalancerAttributesRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeLoadBalancerAttributesResponse;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancer;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerAttribute;
import software.amazon.awssdk.services.wafv2.Wafv2AsyncClient;
import software.amazon.awssdk.services.wafv2.model.GetWebAclForResourceRequest;
import software.amazon.awssdk.services.wafv2.model.GetWebAclForResourceResponse;
import software.amazon.awssdk.services.wafv2.model.WafNonexistentItemException;


public class ELBCheck implements CloudCheck {
    private List<LoadBalancer> allLoadBalancers;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final ElasticLoadBalancingV2AsyncClient elb;
    private final Wafv2AsyncClient waf;

    public ELBCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    ElasticLoadBalancingV2AsyncClient elb, Wafv2AsyncClient waf) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.elb = elb;
        this.waf = waf;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllLoadBalancers()
            .thenCompose(loadBalancers -> {
                this.allLoadBalancers = loadBalancers;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkELBWithNoWAFACLAttached,                               AWSFinding.ELB_WITHOUT_WAF_ACL_ATTACHED, this::reportError),
                    wrapCheck(this::checkELBALBWithAccessLoggingDisabled,                       AWSFinding.ELB_ALBS_ACCESS_LOGGING_DISABLED, this::reportError),
                    wrapCheck(this::checkELBWithDeletionProtectionDisabled,                     AWSFinding.ELB_DELETION_PROTECTION_DISABLED, this::reportError),
                    wrapCheck(this::checkELBListenerWithoutSSLFound,                            AWSFinding.ELB_LISTENER_WITHOUT_SSL, this::reportError),
                    wrapCheck(this::checkPubliclyAccessibleLoadBalancers,                       AWSFinding.PUBLICLY_ACCESSIBLE_LOAD_BALANCERS, this::reportError),
                    wrapCheck(this::checkAlbsDefensiveMitigationButNotDroppingInvalidHeaders,   AWSFinding.ELB_ALBS_DEFENSIVE_MITIGATION_NOT_DROPPING_HEADERS, this::reportError),
                    wrapCheck(this::checkELBInsecureSSLCiphers,                                 AWSFinding.ELB_INSECURE_SSL_CIPHERS, this::reportError)
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
                String arn;
                try {
                    arn = lb.loadBalancerArn();
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
                String name;
                try {
                    name = lb.loadBalancerName();
                    String scheme = lb.scheme().toString();
                    s = "internet-facing".equalsIgnoreCase(scheme) ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(lb.toBuilder());
                } catch (Exception e) {
                    name = "UNKNOWN";
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.set(Text.RESULT.toString(), r);
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

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.set(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_ALBS_DEFENSIVE_MITIGATION_NOT_DROPPING_HEADERS, result, status);
        return status;
    }

    private Status checkELBInsecureSSLCiphers() {
        if (allLoadBalancers.isEmpty()) {
            writer.addToBuffer(AWSFinding.ELB_INSECURE_SSL_CIPHERS,
                            Text.NO_ELBS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allLoadBalancers.stream()
            .flatMap(lb -> {
                DescribeListenersResponse listenersResponse = elb.describeListeners(
                    DescribeListenersRequest.builder().loadBalancerArn(lb.loadBalancerArn()).build()
                ).join();
                
                return listenersResponse.listeners().stream()
                    .filter(listener -> "HTTPS".equalsIgnoreCase(listener.protocol().toString()))
                    .map(listener -> {
                        String policy = listener.sslPolicy();
                        Status s = evaluateSSLPolicy(policy);
                        String nameArn = lb.loadBalancerName() + ":" + listener.listenerArn();
                        
                        Map<String, Object> inner = new HashMap<>();
                        inner.put(Text.STATUS.toString(), s);
                        inner.put(Text.RESULT.toString(), listener);
                        inner.put("ssl_policy", policy);
                        return Map.<String, Object>of(nameArn, inner);
                    });
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ELB_INSECURE_SSL_CIPHERS, result, status);
        return status;
    }

    private Status evaluateSSLPolicy(String sslPolicy) {
        if (sslPolicy == null || sslPolicy.isEmpty()) {
            return Status.FAIL;
        }

        Set<String> securePolicies = Set.of(
            "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
            "ELBSecurityPolicy-FS-1-2-Res-2020-10",
            "ELBSecurityPolicy-FS-1-2-2019-08",
            "ELBSecurityPolicy-FS-1-1-2019-08"
        );

        Set<String> insecurePolicies = Set.of(
            "ELBSecurityPolicy-2016-08",
            "ELBSecurityPolicy-2015-05",
            "ELBSecurityPolicy-2015-03",
            "ELBSecurityPolicy-2015-02",
            "ELBSecurityPolicy-2014-10",
            "ELBSecurityPolicy-2014-01",
            "ELBSecurityPolicy-2011-08"
        );

        if (insecurePolicies.stream().anyMatch(sslPolicy::contains)) {
            return Status.FAIL;
        }
        if (securePolicies.stream().anyMatch(sslPolicy::contains)) {
            return Status.PASS;
        }
        return Status.FAIL;
    }
}
