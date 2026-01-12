package com.twelvesec.cloudscan.AWS.Checks;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.support.SupportAsyncClient;
import software.amazon.awssdk.services.support.model.DescribeSeverityLevelsRequest;
import software.amazon.awssdk.services.support.model.DescribeSeverityLevelsResponse;
import software.amazon.awssdk.services.support.model.DescribeTrustedAdvisorCheckSummariesRequest;
import software.amazon.awssdk.services.support.model.DescribeTrustedAdvisorChecksRequest;
import software.amazon.awssdk.services.support.model.SeverityLevel;
import software.amazon.awssdk.services.support.model.TrustedAdvisorCheckDescription;
import software.amazon.awssdk.services.support.model.TrustedAdvisorCheckSummary;

public class SupportCheck implements CloudCheck {
    private final DataWriter writer;
    private final SupportAsyncClient support;

    public SupportCheck(DataWriter writer, SupportAsyncClient support) {
        this.writer = writer;
        this.support = support;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        List<Supplier<CheckResult>> checksList = List.of(
            wrapCheck(this::checkAmazonWebServicesPremiumSupportPlanIsNotSubscribed,    AWSFinding.WEB_SERVICES_PREMIUM_SUPPORT_PLAN_NOT_SUBSCRIBED, this::reportError),
            wrapCheck(this::checkTrustedAdvisorWarnings,                                AWSFinding.TRUSTED_ADVISOR_WARNINGS, this::reportError)
        );
        return runChecksInList(checksList, writer);
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkAmazonWebServicesPremiumSupportPlanIsNotSubscribed() {        
        Status status = Status.FAIL;
        List<String> result = new ArrayList<>();

        try {
            DescribeSeverityLevelsResponse sevResponse = support.describeSeverityLevels(
                DescribeSeverityLevelsRequest.builder().build()
            ).join();
            result = sevResponse.severityLevels().stream()
                    .map(SeverityLevel::code)
                    .toList();
            status = !result.isEmpty() ? Status.PASS : Status.FAIL;
            result = !result.isEmpty() ? result : List.of(Text.NO_PREMIUM_SUPPORT_SUBSCRIPTION_FOUND.toString());            
        } catch (AwsServiceException e) {
            if ("SubscriptionRequiredException".equals(e.awsErrorDetails().errorCode())) {
                status = Status.FAIL;
                result = List.of(Text.PREMIUM_SUPPORT_NOT_SUBSCRIBED.toString().concat(e.getMessage()));
            } else {
                status = Status.FAIL_EXCEPTION;
                result = List.of(Text.EXCEPTION.toString().concat(e.getMessage()));
            }
        }

        writer.addToBuffer(AWSFinding.WEB_SERVICES_PREMIUM_SUPPORT_PLAN_NOT_SUBSCRIBED, result, status);
        return status;
    }
    
    private Status checkTrustedAdvisorWarnings() {
        final Map<String, Status> TA_STATUS_MAP = Map.of(
            "ok",       Status.PASS,
            "warning",  Status.FAIL,
            "error",    Status.FAIL
            );

        List<TrustedAdvisorCheckSummary> allSummaries;
        try {
            List<String> allCheckIds = support.describeTrustedAdvisorChecks(
                DescribeTrustedAdvisorChecksRequest.builder().language("en").build()
            ).join().checks()
            .stream()
            .map(TrustedAdvisorCheckDescription::id)
            .toList();

            allSummaries = support.describeTrustedAdvisorCheckSummaries(
                DescribeTrustedAdvisorCheckSummariesRequest.builder().checkIds(allCheckIds).build()
            ).join().summaries();
        } catch (AwsServiceException e) {
            if ("SubscriptionRequiredException".equals(e.awsErrorDetails().errorCode())) {
                writer.addToBuffer(AWSFinding.TRUSTED_ADVISOR_WARNINGS, 
                            Text.EXCEPTION.toString().concat(e.getMessage()), Status.PASS);
                return Status.PASS;
            } else {
                writer.addToBuffer(AWSFinding.TRUSTED_ADVISOR_WARNINGS, 
                            Text.EXCEPTION.toString().concat(e.getMessage()), Status.FAIL_EXCEPTION);
                return Status.FAIL_EXCEPTION;
            }
        }

        List<Map<String,Object>> result = allSummaries.stream()
            .map(summary -> {
                Status status = TA_STATUS_MAP.getOrDefault(
                    summary.status().toLowerCase(),
                    Status.FAIL
                );

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status.toString());
                inner.put(Text.RESULT.toString(), MAPPER.valueToTree(summary.toBuilder()));
                return Map.<String,Object>of(summary.checkId(), inner);
            })
            .toList();

        Status status = result.isEmpty() ? Status.PASS : Status.FAIL;
        writer.addToBuffer(AWSFinding.TRUSTED_ADVISOR_WARNINGS, result, status);
        return status;
    }

}
