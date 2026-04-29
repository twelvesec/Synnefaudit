package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class EBSCheck implements CloudCheck {
    private List<Volume> allVolumes;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final Ec2AsyncClient ec2;

    public EBSCheck(DataWriter writer, SharedDataProvider sharedDataProvider, Ec2AsyncClient ec2) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.ec2 = ec2;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllVolumes()
            .thenCompose(volumes -> {
                this.allVolumes = volumes;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkNoSnapshotsForEBSVolumes,              AWSFinding.NO_SNAPSHOTS_FOR_EBS_VOLUMES, this::reportError),
                    wrapCheck(this::checkEBSDefaultEncryptionIsNotActivated,    AWSFinding.EBS_DEFAULT_ENCRYPTION_NOT_ACTIVATED, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkNoSnapshotsForEBSVolumes() { 
        if (allVolumes.isEmpty()) {
            writer.addToBuffer(AWSFinding.NO_SNAPSHOTS_FOR_EBS_VOLUMES, 
                            Text.EBS_NO_VOLUMES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allVolumes.stream()
            .map(volume -> {
                String id = volume.volumeId();
                Status s;
                String r;
                try {
                    DescribeSnapshotsRequest request = DescribeSnapshotsRequest.builder()
                        .filters(Filter.builder().name("volume-id").values(id).build())
                        .build();

                    List<Snapshot> snapshots = new ArrayList<>();
                    ec2.describeSnapshotsPaginator(request)
                        .subscribe(response -> snapshots.addAll(response.snapshots()))
                        .join();
                    boolean hasSnapshots = !snapshots.isEmpty();

                    s = !hasSnapshots ? Status.FAIL : Status.PASS;
                    r = snapshots.toString();
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = Text.EXCEPTION.toString().concat(e.getMessage());
                }
                
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(id, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.NO_SNAPSHOTS_FOR_EBS_VOLUMES, result, status);
        return status;
    }

    private Status checkEBSDefaultEncryptionIsNotActivated() {
        GetEbsEncryptionByDefaultResponse response = ec2.getEbsEncryptionByDefault(
            GetEbsEncryptionByDefaultRequest.builder().build()
        ).join();
        boolean encryptionEnabled = response.ebsEncryptionByDefault();

        Status status = encryptionEnabled ? Status.PASS : Status.FAIL;
        ObjectNode result = MAPPER.valueToTree(response.toBuilder());
        
        writer.addToBuffer(AWSFinding.EBS_DEFAULT_ENCRYPTION_NOT_ACTIVATED, result, status);
        return status;
    }
}
