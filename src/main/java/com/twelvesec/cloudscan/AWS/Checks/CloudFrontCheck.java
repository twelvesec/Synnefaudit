package com.twelvesec.cloudscan.AWS.Checks;

import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;
import software.amazon.awssdk.services.cloudfront.model.DistributionConfig;
import software.amazon.awssdk.services.cloudfront.model.DistributionSummary;
import software.amazon.awssdk.services.cloudfront.model.GeoRestriction;
import software.amazon.awssdk.services.cloudfront.model.GeoRestrictionType;
import software.amazon.awssdk.services.cloudfront.model.GetDistributionConfigRequest;
import software.amazon.awssdk.services.cloudfront.model.GetDistributionConfigResponse;
import software.amazon.awssdk.services.wafv2.Wafv2AsyncClient;
import software.amazon.awssdk.services.wafv2.model.GetWebAclForResourceRequest;
import software.amazon.awssdk.services.wafv2.model.GetWebAclForResourceResponse;

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

public class CloudFrontCheck implements CloudCheck {
    private List<DistributionSummary> allDistributions;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final CloudFrontAsyncClient cf;
    private final Wafv2AsyncClient waf;

    public CloudFrontCheck(DataWriter writer, SharedDataProvider sharedDataProvider, CloudFrontAsyncClient cf, Wafv2AsyncClient waf) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.cf = cf;
        this.waf = waf;
    }

    @Override
    public void runAllChecks() {
        allDistributions = sharedDataProvider.getAllDistributions().join();
                            
        subCheckResults.clear();
        subCheckResults.addAll(
            Stream.of(
                wrapCheck(this::checkCloudFrontIsNotConfigured,                                 AWSFinding.CLOUDFRONT_NOT_CONFIGURED, this::reportError),
                wrapCheck(this::checkCloudFrontDistributionsNotUsingAWAFWebACL,                 AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITHOUT_WAF_WEB_ACL, this::reportError),
                wrapCheck(this::checkCloudFrontDistributionsWithFieldLevelEncryptionDisabled,   AWSFinding.CLOUDFRONT_DISTRIBUTIONS_FIELDLEVELENCRYPTION_DISABLED, this::reportError),
                wrapCheck(this::checkCloudFrontDistributionsWithNoGeoRestrictions,              AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITH_NO_GEO_RESTRICTIONS, this::reportError)
            )
            .map(Supplier::get)
            .toList()
        );
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllDistributions()
            .thenCompose(distributions -> {
                this.allDistributions = distributions;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkCloudFrontIsNotConfigured,                                 AWSFinding.CLOUDFRONT_NOT_CONFIGURED, this::reportError),
                    wrapCheck(this::checkCloudFrontDistributionsNotUsingAWAFWebACL,                 AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITHOUT_WAF_WEB_ACL, this::reportError),
                    wrapCheck(this::checkCloudFrontDistributionsWithFieldLevelEncryptionDisabled,   AWSFinding.CLOUDFRONT_DISTRIBUTIONS_FIELDLEVELENCRYPTION_DISABLED, this::reportError),
                    wrapCheck(this::checkCloudFrontDistributionsWithNoGeoRestrictions,              AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITH_NO_GEO_RESTRICTIONS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkCloudFrontIsNotConfigured() {
        List<String> result = allDistributions.stream().map(d -> d.id()).toList();
        Status status = (result != null && !result.isEmpty()) ? Status.PASS : Status.FAIL;
        result = (result == null || result.isEmpty()) ? List.of(Text.NO_DISTRIBUTIONS_FOUND.toString()) : result;
        writer.addToBuffer(AWSFinding.CLOUDFRONT_NOT_CONFIGURED, result, status);
        return status;
    }

    private Status checkCloudFrontDistributionsNotUsingAWAFWebACL() { 
        if (allDistributions.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITHOUT_WAF_WEB_ACL, 
                            Text.NO_DISTRIBUTIONS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allDistributions.stream()
            .map(distribution -> {
                String arn = distribution.arn();
                Status s;
                ObjectNode r;
                try {
                    GetWebAclForResourceResponse response = waf.getWebACLForResource(
                        GetWebAclForResourceRequest.builder().resourceArn(arn).build()
                    ).join();
                    s = (response.webACL() == null) ? Status.FAIL : Status.PASS;
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
        writer.addToBuffer(AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITHOUT_WAF_WEB_ACL, result, status);
        return status;
    }

    private Status checkCloudFrontDistributionsWithFieldLevelEncryptionDisabled() { 
        if (allDistributions.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDFRONT_DISTRIBUTIONS_FIELDLEVELENCRYPTION_DISABLED, 
                            Text.NO_DISTRIBUTIONS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allDistributions.stream()
            .map(distribution -> {
                String id = distribution.id();
                Status s;
                ObjectNode r;
                try {
                    GetDistributionConfigResponse cfg = cf.getDistributionConfig(
                        GetDistributionConfigRequest.builder().id(id).build()
                    ).join();
                    String fleId = cfg.distributionConfig()
                                    .defaultCacheBehavior()
                                    .fieldLevelEncryptionId();
                    s = (fleId == null || fleId.isBlank()) ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(cfg.distributionConfig().toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(id, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDFRONT_DISTRIBUTIONS_FIELDLEVELENCRYPTION_DISABLED, result, status);
        return status;
    }

    private Status checkCloudFrontDistributionsWithNoGeoRestrictions() {
        if (allDistributions.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITH_NO_GEO_RESTRICTIONS,
                            Text.NO_DISTRIBUTIONS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allDistributions.stream()
            .map(dist -> {
                String distId = dist.id();
                Status s;
                ObjectNode r;
                try {
                    GetDistributionConfigResponse cfgResp = cf.getDistributionConfig(
                        GetDistributionConfigRequest.builder().id(distId).build()
                    ).join();
                    DistributionConfig cfg = cfgResp.distributionConfig();
                    GeoRestriction geo = cfg.restrictions().geoRestriction();

                    boolean noGeo = geo.restrictionType() == GeoRestrictionType.NONE;
                    s = noGeo ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(cfgResp.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.set(Text.RESULT.toString(), r);
                return Map.<String,Object>of(distId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDFRONT_DISTRIBUTIONS_WITH_NO_GEO_RESTRICTIONS, result, status);
        return status;
    }

}
