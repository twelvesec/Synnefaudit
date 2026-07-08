package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.neptune.model.DBCluster;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class NeptuneDBCheck implements CloudCheck {
    private List<DBCluster> allNeptuneClusters;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;

    public NeptuneDBCheck(DataWriter writer, SharedDataProvider sharedDataProvider) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllNeptuneClusters()
                .thenCompose(neptuneClutsers -> {
                    this.allNeptuneClusters = neptuneClutsers;
                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkNeptuneStorageEncrypted,  AWSFinding.NEPTUNE_STORAGE_ENCRYPTION_ENABLED, this::reportError)
                    );
                    return runChecksInList(checksList, writer);
                });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkNeptuneStorageEncrypted() {
        AWSFinding finding = AWSFinding.NEPTUNE_STORAGE_ENCRYPTION_ENABLED;
        if (allNeptuneClusters == null || allNeptuneClusters.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_NEPTUNE_CLUSTERS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allNeptuneClusters.stream()
                .map(cluster -> {
                    Status s;
                    if (cluster.storageEncrypted() != null && cluster.storageEncrypted()) {
                        s = Status.PASS;
                    } else {
                        s = Status.FAIL;
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), MAPPER.valueToTree(cluster.toBuilder()));
                    return Map.<String, Object>of(cluster.dbClusterArn(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }
}

