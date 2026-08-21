package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.autoscaling.model.LaunchConfiguration;
import software.amazon.awssdk.services.backup.model.ProtectedResource;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class EBSCheck implements CloudCheck {
    private List<Volume> allVolumes;
    private List<Snapshot> allSnapshots;
    private List<LaunchConfiguration> allLaunchConfigurations;
    private List<ProtectedResource> allProtectedResources;
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
        CompletableFuture<List<Volume>> volumes = sharedDataProvider.getAllVolumes()
                .exceptionally(ex -> null);
        CompletableFuture<List<Snapshot>> snapshots = sharedDataProvider.getAllSnapshots()
                .exceptionally(ex -> null);
        CompletableFuture<List<LaunchConfiguration>> lauchconfig = sharedDataProvider.getAllLaunchConfigurations()
                .exceptionally(ex -> null);
        CompletableFuture<List<ProtectedResource>> protectedResources = sharedDataProvider.getAllProtectedResources()
                .exceptionally(ex -> null);
        return CompletableFuture.allOf(volumes, snapshots, lauchconfig, protectedResources)
                .thenCompose(v -> {
                    this.allVolumes = volumes.join();
                    this.allSnapshots = snapshots.join();
                    this.allLaunchConfigurations = lauchconfig.join();
                    this.allProtectedResources = protectedResources.join();

                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkNoSnapshotsForEBSVolumes,              AWSFinding.NO_SNAPSHOTS_FOR_EBS_VOLUMES, this::reportError),
                            wrapCheck(this::checkEBSDefaultEncryptionIsNotActivated,    AWSFinding.EBS_DEFAULT_ENCRYPTION_NOT_ACTIVATED, this::reportError),
                            wrapCheck(this::checkEBSSnapshotsEncrypted,                 AWSFinding.EBS_SNAPSHOTS_ENCRYPTED, this::reportError),
                            wrapCheck(this::checkNoPublicEBSSnapshots,                  AWSFinding.EBS_SNAPSHOTS_NOT_PUBLIC, this::reportError),
                            wrapCheck(this::checkEBSSnapshotPublicAccessDisabled,       AWSFinding.EBS_SNAPSHOT_PUBLIC_ACCESS_DISABLED, this::reportError),
                            wrapCheck(this::checkEBSVolumesEncrypted,                   AWSFinding.EBS_VOLUMES_ENCRYPTED, this::reportError),
                            wrapCheck(this::checkEBSVolumesProtectedByBackupPlan,       AWSFinding.EBS_VOLUMES_PROTECTED_BY_BACKUP_PLAN, this::reportError)
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

    private Status checkEBSSnapshotsEncrypted() {
        if (allSnapshots.isEmpty()) {
            writer.addToBuffer(AWSFinding.EBS_SNAPSHOTS_ENCRYPTED,
                    Text.EBS_NO_SNAPSHOTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allSnapshots.stream()
                .map(snapshot -> {
                    String snapshotId = snapshot.snapshotId();
                    boolean isEncrypted = Boolean.TRUE.equals(snapshot.encrypted());
                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(snapshot);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(snapshotId, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EBS_SNAPSHOTS_ENCRYPTED, result, status);
        return status;
    }

    private Status checkNoPublicEBSSnapshots() {
        if (allSnapshots.isEmpty()) {
            writer.addToBuffer(AWSFinding.EBS_SNAPSHOTS_NOT_PUBLIC,
                    Text.EBS_NO_SNAPSHOTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allSnapshots.stream()
                .map(snapshot -> {
                    String snapshotId = snapshot.snapshotId();
                    Status s;
                    ObjectNode r;
                    try {
                        DescribeSnapshotAttributeResponse response = ec2.describeSnapshotAttribute(
                                DescribeSnapshotAttributeRequest.builder()
                                        .snapshotId(snapshotId)
                                        .attribute(SnapshotAttributeName.CREATE_VOLUME_PERMISSION)
                                        .build()
                        ).join();
                        boolean isPublic = response.createVolumePermissions().stream()
                                .anyMatch(permission -> "all".equalsIgnoreCase(permission.groupAsString()));

                        s = !isPublic ? Status.PASS : Status.FAIL;
                        r = MAPPER.valueToTree(snapshot);
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(snapshotId, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EBS_SNAPSHOTS_NOT_PUBLIC, result, status);
        return status;
    }

    private Status checkEBSSnapshotPublicAccessDisabled() {
        try {
            GetSnapshotBlockPublicAccessStateResponse response = ec2.getSnapshotBlockPublicAccessState(
                    GetSnapshotBlockPublicAccessStateRequest.builder().build()
            ).join();
            boolean isBlockAllSharing = "block-all-sharing".equalsIgnoreCase(response.stateAsString());
            Status status = isBlockAllSharing ? Status.PASS : Status.FAIL;
            ObjectNode result = MAPPER.valueToTree(response.toBuilder());

            writer.addToBuffer(AWSFinding.EBS_SNAPSHOT_PUBLIC_ACCESS_DISABLED, result, status);
            return status;
        } catch (Exception e) {
            Status status = Status.FAIL_EXCEPTION;
            ObjectNode result = MAPPER.createObjectNode().put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
            writer.addToBuffer(AWSFinding.EBS_SNAPSHOT_PUBLIC_ACCESS_DISABLED, result, status);
            return status;
        }
    }

    private Status checkEBSVolumesEncrypted() {
        if (allVolumes.isEmpty()) {
            writer.addToBuffer(AWSFinding.EBS_VOLUMES_ENCRYPTED,
                    Text.EBS_NO_VOLUMES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allVolumes.stream()
                .map(volume -> {
                    String volumeId = volume.volumeId();
                    boolean isEncrypted = Boolean.TRUE.equals(volume.encrypted());
                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(volume);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(volumeId, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EBS_VOLUMES_ENCRYPTED, result, status);
        return status;
    }

    private Status checkEBSVolumesProtectedByBackupPlan() {
        if (allVolumes.isEmpty()) {
            writer.addToBuffer(AWSFinding.EBS_VOLUMES_PROTECTED_BY_BACKUP_PLAN,
                    Text.EBS_NO_VOLUMES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> protectedResourceArns = allProtectedResources.stream()
                .map(ProtectedResource::resourceArn)
                .collect(Collectors.toSet());

        List<Map<String, Object>> result = allVolumes.stream()
                .map(volume -> {
                    String volumeId = volume.volumeId();
                    String volumeArnSuffix = ":volume/" + volumeId;
                    boolean isProtected = protectedResourceArns.stream()
                            .anyMatch(arn -> arn.endsWith(volumeArnSuffix));
                    Status s = isProtected ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(volume);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(volumeId, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EBS_VOLUMES_PROTECTED_BY_BACKUP_PLAN, result, status);
        return status;
    }
}
