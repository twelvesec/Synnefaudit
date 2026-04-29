package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.glue.GlueAsyncClient;
import software.amazon.awssdk.services.glue.model.*;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class GlueCheck implements CloudCheck {
    private final DataWriter writer;
    private final GlueAsyncClient glue;
    private boolean glueDataCatalogUsed;

    public GlueCheck(DataWriter writer, GlueAsyncClient glue) {
        this.writer = writer;
        this.glue = glue;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        glueDataCatalogUsed = isGlueDataCatalogUsed();
        List<Supplier<CheckResult>> checksList = List.of(
            wrapCheck(this::checkGlueDataCatalogEncryption, AWSFinding.GLUE_DATA_CATALOG_UNENCRYPTED_PASSWORDS, this::reportError),
            wrapCheck(this::checkGlueMetadataEncryption,    AWSFinding.GLUE_METADATA_NOT_ENCRYPTED, this::reportError)
        );
        return runChecksInList(checksList, writer);
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    public boolean isGlueDataCatalogUsed() {
        try{
            GetDatabasesRequest dbRequest = GetDatabasesRequest.builder()
                .maxResults(1)
                .build();
            
            List<Database> databases = glue.getDatabases(dbRequest).get().databaseList();
            if (databases.isEmpty()) {
                return false;
            }

            String firstDatabaseName = databases.getFirst().name();
            
            GetTablesRequest tablesRequest = GetTablesRequest.builder()
                .databaseName(firstDatabaseName)
                .maxResults(1)
                .build();

            return !glue.getTables(tablesRequest)
                .get()
                .tableList()
                .isEmpty();
        } catch (Exception e) {
            System.err.println(Text.EXCEPTION.getText().concat(e.getMessage()));
            return false;
        }
    }

    private Status checkGlueDataCatalogEncryption() {
        if (!glueDataCatalogUsed){
            writer.addToBuffer(AWSFinding.GLUE_DATA_CATALOG_UNENCRYPTED_PASSWORDS, 
                            Text.GLUE_DATA_CATALOG_NOT_USED.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        GetDataCatalogEncryptionSettingsResponse response = glue.getDataCatalogEncryptionSettings(
            GetDataCatalogEncryptionSettingsRequest.builder().build()
        ).join();

        DataCatalogEncryptionSettings encryptionSettings = response.dataCatalogEncryptionSettings();
        EncryptionAtRest encryptionAtRest = encryptionSettings.encryptionAtRest();
        ConnectionPasswordEncryption connectionEncryption = encryptionSettings.connectionPasswordEncryption();

        ObjectNode result = MAPPER.valueToTree(encryptionSettings.toBuilder());

        boolean isCompliant = (connectionEncryption != null && connectionEncryption.returnConnectionPasswordEncrypted())
            && (encryptionAtRest != null && encryptionAtRest.catalogEncryptionMode() != CatalogEncryptionMode.DISABLED);

        Status status = isCompliant ? Status.PASS : Status.FAIL;
        writer.addToBuffer(AWSFinding.GLUE_DATA_CATALOG_UNENCRYPTED_PASSWORDS, result, status);
        return status;
    }

    private Status checkGlueMetadataEncryption() {
        if (!glueDataCatalogUsed){
            writer.addToBuffer(AWSFinding.GLUE_METADATA_NOT_ENCRYPTED, 
                            Text.GLUE_DATA_CATALOG_NOT_USED.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        GetDataCatalogEncryptionSettingsResponse response = glue.getDataCatalogEncryptionSettings(
            GetDataCatalogEncryptionSettingsRequest.builder().build()
        ).join();

        DataCatalogEncryptionSettings encryptionSettings = response.dataCatalogEncryptionSettings();
        EncryptionAtRest encryptionAtRest = encryptionSettings.encryptionAtRest();

        ObjectNode result = MAPPER.valueToTree(encryptionAtRest.toBuilder());

        boolean isEncrypted = encryptionAtRest.catalogEncryptionMode() != CatalogEncryptionMode.DISABLED;

        Status status = isEncrypted ? Status.PASS : Status.FAIL;
        writer.addToBuffer(AWSFinding.GLUE_METADATA_NOT_ENCRYPTED, result, status);
        return isEncrypted ? Status.PASS : Status.FAIL;
    }
}
