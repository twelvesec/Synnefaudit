package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.account.AccountAsyncClient;
import software.amazon.awssdk.services.backup.BackupAsyncClient;
import software.amazon.awssdk.services.backup.model.*;
import software.amazon.awssdk.services.codebuild.CodeBuildAsyncClient;
import software.amazon.awssdk.services.organizations.OrganizationsAsyncClient;
import software.amazon.awssdk.services.resourceexplorer2.model.Index;
import software.amazon.awssdk.services.sts.StsAsyncClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class BackupCheck implements CloudCheck {
    private List<Index> allIndexes;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final BackupAsyncClient backup;

    public BackupCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                       BackupAsyncClient backup) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.backup = backup;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllIndexes()
                .thenCompose(indexes -> {
                    this.allIndexes = indexes;
                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkNoBackupReportPlanExists,      AWSFinding.NO_BACKUP_REPORT_PLAN_EXISTS, this::reportError),
                            wrapCheck(this::checkNoBackupVaultsExist,           AWSFinding.NO_BACKUP_VAULTS_EXIST, this::reportError),
                            wrapCheck(this::checkNoBackupPlanExists,            AWSFinding.NO_BACKUP_PLAN_EXISTS, this::reportError),
                            wrapCheck(this::checkBackupVaultsEncryptedWithKms,  AWSFinding.BACKUP_VAULTS_ENCRYPTED_WITH_KMS, this::reportError)
                    );
                    return runChecksInList(checksList, writer);
                });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkNoBackupReportPlanExists() {
        ListReportPlansResponse listResponse = backup.listReportPlans(ListReportPlansRequest.builder().build()).join();
        List<String> result = listResponse.reportPlans().stream()
                .map(ReportPlan::reportPlanName)
                .toList();

        Status status = !result.isEmpty() ? Status.PASS : Status.FAIL;
        result = result.isEmpty() ? List.of(Text.NO_REPORT_PLANS_FOUND.toString()) : result;
        writer.addToBuffer(AWSFinding.NO_BACKUP_REPORT_PLAN_EXISTS, result, status);
        return status;
    }

    private Status checkNoBackupVaultsExist() {
        ListBackupVaultsResponse listResponse = backup.listBackupVaults(ListBackupVaultsRequest.builder().build()).join();
        List<String> result = listResponse.backupVaultList().stream()
                .map(BackupVaultListMember::backupVaultName)
                .toList();

        Status status = !result.isEmpty() ? Status.PASS : Status.FAIL;
        result = result.isEmpty() ? List.of(Text.NO_BACKUP_VAULTS_FOUND.toString()) : result;
        writer.addToBuffer(AWSFinding.NO_BACKUP_VAULTS_EXIST, result, status);
        return status;
    }

    private Status checkNoBackupPlanExists() {
        ListBackupPlansResponse listResponse = backup.listBackupPlans(ListBackupPlansRequest.builder().build()).join();
        List<String> result = listResponse.backupPlansList().stream()
                .map(BackupPlansListMember::backupPlanName)
                .toList();

        Status status = !result.isEmpty() ? Status.PASS : Status.FAIL;
        result = result.isEmpty() ? List.of(Text.NO_BACKUP_PLANS_FOUND.toString()) : result;
        writer.addToBuffer(AWSFinding.NO_BACKUP_PLAN_EXISTS, result, status);
        return status;
    }

    private Status checkBackupVaultsEncryptedWithKms() {
        List<BackupVaultListMember> vaults = backup.listBackupVaults(ListBackupVaultsRequest.builder().build()).join().backupVaultList();
        if (vaults.isEmpty()) {
            writer.addToBuffer( AWSFinding.BACKUP_VAULTS_ENCRYPTED_WITH_KMS,
                    Text.NO_BACKUP_VAULTS_FOUND.toString(), Status.NOT_APPLICABLE
            );
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = vaults.stream()
                .map(vault -> {
                    boolean isEncrypted = vault.encryptionKeyArn() != null && !vault.encryptionKeyArn().isBlank();
                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(vault);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(vault.backupVaultArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.BACKUP_VAULTS_ENCRYPTED_WITH_KMS, result, status);
        return status;
    }
}