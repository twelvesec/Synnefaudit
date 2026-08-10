package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.guardduty.GuardDutyAsyncClient;
import software.amazon.awssdk.services.guardduty.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class GuardDutyCheck implements CloudCheck {
    private List<String> allDetectorIds;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final GuardDutyAsyncClient guardDuty;

    public GuardDutyCheck(DataWriter writer, SharedDataProvider sharedDataProvider, GuardDutyAsyncClient guardDuty) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.guardDuty = guardDuty;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllDetectorIds()
            .thenCompose(detectorIds -> {
                this.allDetectorIds = detectorIds;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkGuardDutyNotEnabled,                       AWSFinding.GUARDDUTY_NOT_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyDetectorIsNotCetrallyManaged,     AWSFinding.GUARDDUTY_DETECTOR_NOT_CENTRALLY_MANAGED, this::reportError),
                    wrapCheck(this::checkGuardDutyMalwareProtectionForEC2Enabled,   AWSFinding.GUARDDUTY_EC2_MALWARE_PROTECTION_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyEKSAuditLogMonitoringEnabled,     AWSFinding.GUARDDUTY_EKS_AUDIT_LOGS_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyEKSRuntimeMonitoringEnabled,      AWSFinding.GUARDDUTY_EKS_RUNTIME_MONITORING_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyLambdaProtectionEnabled,          AWSFinding.GUARDDUTY_LAMBDA_PROTECTION_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyRDSProtectionEnabled,             AWSFinding.GUARDDUTY_RDS_PROTECTION_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyS3ProtectionEnabled,              AWSFinding.GUARDDUTY_S3_PROTECTION_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyNoHighSeverityFindings,           AWSFinding.GUARDDUTY_NO_HIGH_SEVERITY_FINDINGS, this::reportError),
                    wrapCheck(this::checkGuardDutyNotEnabled,                       AWSFinding.GUARDDUTY_NOT_ENABLED, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkGuardDutyNotEnabled() {
        Status status = !allDetectorIds.isEmpty() ? Status.PASS : Status.FAIL;
        String result = !allDetectorIds.isEmpty() 
                        ? Text.GUARDDUTY_DETECTORS_FOUND.getText().concat(String.join(", ",allDetectorIds)) 
                        : Text.NO_GUARDDUTY_DETECTORS_FOUND.toString();
        writer.addToBuffer(AWSFinding.GUARDDUTY_NOT_ENABLED, result, status);
        return status;
    }

    private Status checkGuardDutyDetectorIsNotCetrallyManaged() { 
        if (allDetectorIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.GUARDDUTY_DETECTOR_NOT_CENTRALLY_MANAGED, 
                            Text.NO_GUARDDUTY_DETECTORS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allDetectorIds.stream()
            .map(detectorId -> {
                Status s;
                ObjectNode r;
                try {
                    GetAdministratorAccountResponse response = guardDuty.getAdministratorAccount(
                        GetAdministratorAccountRequest.builder().detectorId(detectorId).build()
                    ).join();
                    Administrator admin = response.administrator();

                    if (admin != null && admin.accountId() != null) {
                        s = Status.PASS;
                        r = MAPPER.valueToTree(admin.accountId());
                    } else {
                        s = Status.FAIL;
                        r = MAPPER.valueToTree(response.toBuilder());
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(detectorId, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.GUARDDUTY_DETECTOR_NOT_CENTRALLY_MANAGED, result, status);
        return status;
    }

    private Status checkGuardDutyMalwareProtectionForEC2Enabled() {
        return checkFeatureStatus(AWSFinding.GUARDDUTY_EC2_MALWARE_PROTECTION_ENABLED, "EBS_MALWARE_PROTECTION");
    }

    private Status checkGuardDutyEKSAuditLogMonitoringEnabled() {
        return checkFeatureStatus(AWSFinding.GUARDDUTY_EKS_AUDIT_LOGS_ENABLED,"EKS_AUDIT_LOGS");
    }

    private Status checkGuardDutyEKSRuntimeMonitoringEnabled() {
        return checkFeatureStatus(AWSFinding.GUARDDUTY_EKS_RUNTIME_MONITORING_ENABLED, "EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING");
    }

    private Status checkGuardDutyLambdaProtectionEnabled() {
        return checkFeatureStatus(AWSFinding.GUARDDUTY_LAMBDA_PROTECTION_ENABLED, "LAMBDA_NETWORK_LOGS");
    }

    private Status checkGuardDutyRDSProtectionEnabled() {
        return checkFeatureStatus(AWSFinding.GUARDDUTY_RDS_PROTECTION_ENABLED,"RDS_LOGIN_EVENTS");
    }

    private Status checkGuardDutyS3ProtectionEnabled() {
        return checkFeatureStatus(AWSFinding.GUARDDUTY_S3_PROTECTION_ENABLED,"S3_DATA_EVENTS");
    }

    private Status checkFeatureStatus(AWSFinding finding, String... featureNames) {
        if (allDetectorIds.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_GUARDDUTY_DETECTORS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDetectorIds.stream()
                .map(detectorId -> {
                    Status s;
                    ObjectNode r;
                    try {
                        GetDetectorResponse response = guardDuty.getDetector(
                                GetDetectorRequest.builder().detectorId(detectorId).build()
                        ).join();
                        boolean isEnabled = isFeatureEnabled(response, featureNames);

                        s = isEnabled ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(response);
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(detectorId, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Status checkGuardDutyNoHighSeverityFindings() {
        if (allDetectorIds.isEmpty()) {
            writer.addToBuffer(AWSFinding.GUARDDUTY_NO_HIGH_SEVERITY_FINDINGS,
                    Text.NO_GUARDDUTY_DETECTORS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDetectorIds.stream()
                .map(detectorId -> {
                    Status s;
                    ObjectNode r;
                    try {
                        FindingCriteria criteria = FindingCriteria.builder()
                                .criterion(Map.of(
                                        "severity", Condition.builder().greaterThanOrEqual(7L).build(),
                                        "service.archived", Condition.builder().equalsValue("false").build()
                                ))
                                .build();
                        ListFindingsResponse response = guardDuty.listFindings(
                                ListFindingsRequest.builder()
                                        .detectorId(detectorId)
                                        .findingCriteria(criteria)
                                        .build()
                        ).join();

                        List<String> findingIds = response.findingIds();
                        boolean hasHighSeverityFindings = findingIds != null && !findingIds.isEmpty();

                        s = !hasHighSeverityFindings ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(Map.of(
                                "HighSeverityFindingsCount", findingIds != null ? findingIds.size() : 0,
                                "FindingIds", findingIds != null ? findingIds : List.of()
                        ));
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(detectorId, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.GUARDDUTY_NO_HIGH_SEVERITY_FINDINGS, result, status);
        return status;
    }

    private boolean isFeatureEnabled(GetDetectorResponse response, String... featureNames) {
        if (response.hasFeatures()) {
            List<String> targets = List.of(featureNames);
            return response.features().stream()
                    .anyMatch(f -> targets.contains(f.nameAsString()) && "ENABLED".equalsIgnoreCase(f.statusAsString()));
        }
        return false;
    }
}
