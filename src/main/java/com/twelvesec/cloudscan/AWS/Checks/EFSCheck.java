package com.twelvesec.cloudscan.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.messages.Text;
import software.amazon.awssdk.services.backup.model.BackupException;
import software.amazon.awssdk.services.efs.EfsAsyncClient;
import software.amazon.awssdk.services.efs.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class EFSCheck implements CloudCheck {
    private List<FileSystemDescription> allFileSystems;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final EfsAsyncClient efs;

    public EFSCheck(DataWriter writer, SharedDataProvider sharedDataProvider, EfsAsyncClient efs) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.efs = efs;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllFileSystems()
            .thenCompose(fileSystems -> {
                this.allFileSystems = fileSystems;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkEFSFileSystemsWithBackupDisabled, AWSFinding.EFS_FILE_SYSTEMS_WITH_BACKUP_DISABLED, this::reportError),
                    wrapCheck(this::checkEFSFileSystemWithNoPolicy,        AWSFinding.EFS_WITHOUT_POLICY, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkEFSFileSystemsWithBackupDisabled() { 
        if (allFileSystems.isEmpty()) {
            writer.addToBuffer(AWSFinding.EFS_FILE_SYSTEMS_WITH_BACKUP_DISABLED, 
                            Text.NO_EFS_FILE_SYSTEM_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allFileSystems.stream()
            .map(fs -> {
                String id = fs.fileSystemId();
                Status s;
                ObjectNode r;
                try {
                    BackupPolicy bp = efs.describeBackupPolicy(
                        DescribeBackupPolicyRequest.builder().fileSystemId(id).build()
                    ).join().backupPolicy();
                    s = "DISABLED".equalsIgnoreCase(bp.statusAsString()) ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(bp.toBuilder());
                } catch (BackupException e) {
                    s = Status.FAIL;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.EFS_FILE_SYSTEM_WITH_BACKUP_DISABLED.toString().concat(e.getMessage()));
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
        writer.addToBuffer(AWSFinding.EFS_FILE_SYSTEMS_WITH_BACKUP_DISABLED, result, status);
        return status;
    }

    private Status checkEFSFileSystemWithNoPolicy() {
        if (allFileSystems.isEmpty()) {
            writer.addToBuffer(AWSFinding.EFS_WITHOUT_POLICY, 
                            Text.NO_EFS_FILE_SYSTEM_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allFileSystems.stream()
            .map(fs -> {
                String id = fs.fileSystemId();
                Status s;
                ObjectNode r;
                try {
                    DescribeFileSystemPolicyResponse response = efs.describeFileSystemPolicy(
                            DescribeFileSystemPolicyRequest.builder().fileSystemId(id).build()
                    ).join();
                    s = Status.FAIL;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (PolicyNotFoundException e) {
                    s = Status.PASS;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.EFS_NO_POLICY_FOUND.toString().concat(e.getMessage()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(id, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EFS_WITHOUT_POLICY, result, status);
        return status;
    }
}
