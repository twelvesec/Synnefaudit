package com.twelvesec.cloudscan.AWS.Checks;

import software.amazon.awssdk.services.guardduty.GuardDutyAsyncClient;
import software.amazon.awssdk.services.guardduty.model.Administrator;
import software.amazon.awssdk.services.guardduty.model.GetAdministratorAccountRequest;
import software.amazon.awssdk.services.guardduty.model.GetAdministratorAccountResponse;

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
                    wrapCheck(this::checkGuardDutyNotEnabled,                   AWSFinding.GUARDDUTY_NOT_ENABLED, this::reportError),
                    wrapCheck(this::checkGuardDutyDetectorIsNotCetrallyManaged, AWSFinding.GUARDDUTY_DETECTOR_NOT_CENTRALLY_MANAGED, this::reportError)
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
}
