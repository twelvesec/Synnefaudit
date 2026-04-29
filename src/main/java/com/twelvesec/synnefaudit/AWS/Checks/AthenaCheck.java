package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.athena.AthenaAsyncClient;
import software.amazon.awssdk.services.athena.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class AthenaCheck implements CloudCheck {
    private List<WorkGroupSummary> allWorkGroups;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final AthenaAsyncClient athena;

    public AthenaCheck(DataWriter writer, SharedDataProvider sharedDataProvider, AthenaAsyncClient athena) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.athena = athena;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllWorkGroups()
            .thenCompose(workgroups -> {
                this.allWorkGroups = workgroups;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkAthenaWorkGroupEncryption,             AWSFinding.ATHENA_WORKGROUPS_WITHOUT_ENCRYPTION, this::reportError),
                    wrapCheck(this::checkAthenaWorkgroupsEnforceConfiguration,  AWSFinding.ATHENA_WORKGROUPS_ENFORCE_CONFIGURATION_DISABLED, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }
    
    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkAthenaWorkGroupEncryption() {
        if (allWorkGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ATHENA_WORKGROUPS_WITHOUT_ENCRYPTION,
                            Text.NO_ATHENA_WORKGROUPS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allWorkGroups.stream()
            .map(summary -> {
                String name = summary.name();
                Status s;
                ObjectNode r;
                try {
                    GetWorkGroupResponse response = athena.getWorkGroup(
                        GetWorkGroupRequest.builder().workGroup(summary.name()).build()
                    ).join();
                    WorkGroup wg = response.workGroup();

                    EncryptionConfiguration enc = wg.configuration()
                                                    .resultConfiguration()
                                                    .encryptionConfiguration();
                    boolean encrypted = enc != null && enc.encryptionOption() != null;
                    s = encrypted ? Status.PASS : Status.FAIL;

                    r = MAPPER.valueToTree(wg.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(name, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.ATHENA_WORKGROUPS_WITHOUT_ENCRYPTION, result, status);
        return status;
    }

    private Status checkAthenaWorkgroupsEnforceConfiguration() {
        if (allWorkGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.ATHENA_WORKGROUPS_ENFORCE_CONFIGURATION_DISABLED,
                            Text.NO_ATHENA_WORKGROUPS_FOUND, Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allWorkGroups.stream()
            .map(summary -> {
                String name = summary.name();
                Status s;
                ObjectNode r;
                try {
                    GetWorkGroupResponse response = athena.getWorkGroup(
                        GetWorkGroupRequest.builder().workGroup(summary.name()).build()
                    ).join();
                    WorkGroupConfiguration configuration = response.workGroup().configuration();
                    boolean enforceEnabled = configuration.enforceWorkGroupConfiguration();
                    s = enforceEnabled ? Status.PASS : Status.FAIL;
                    r = MAPPER.valueToTree(configuration.toBuilder());
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
        writer.addToBuffer(AWSFinding.ATHENA_WORKGROUPS_ENFORCE_CONFIGURATION_DISABLED, result, status);
        return status;
    }

}
