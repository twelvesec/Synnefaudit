package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.model.DescribeDocumentPermissionRequest;
import software.amazon.awssdk.services.ssm.model.DescribeDocumentPermissionResponse;
import software.amazon.awssdk.services.ssm.model.DocumentIdentifier;
import software.amazon.awssdk.services.ssmincidents.SsmIncidentsAsyncClient;
import software.amazon.awssdk.services.ssmincidents.model.ListResponsePlansRequest;
import software.amazon.awssdk.services.ssmincidents.model.ListResponsePlansResponse;
import software.amazon.awssdk.services.ssmincidents.model.ResponsePlanSummary;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class SSMCheck implements CloudCheck {
    private List<DocumentIdentifier> allDocuments;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final SsmAsyncClient ssm;
    private final SsmIncidentsAsyncClient ssmIncidents;

    public SSMCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                    SsmAsyncClient ssm, SsmIncidentsAsyncClient ssmIncidents) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.ssm = ssm;
        this.ssmIncidents = ssmIncidents;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<DocumentIdentifier>> documents = sharedDataProvider.getAllSSMDocuments()
                .exceptionally(ex -> null);

        return documents.thenCompose(docs -> {
            this.allDocuments = docs;

            List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkSSMIncidentsWithNoResponsePlans, AWSFinding.SSM_INCIDENTS_WITHOUT_RESPONSE_PLANS, this::reportError),
                    wrapCheck(this::checkPublicSSMDocuments,              AWSFinding.PUBLIC_SSM_DOCUMENTS, this::reportError)
            );
            return runChecksInList(checksList, writer);
        });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkSSMIncidentsWithNoResponsePlans() {
        List<String> result;
        Status status;

        ListResponsePlansResponse listResponse = ssmIncidents.listResponsePlans(
            ListResponsePlansRequest.builder().build()
        ).join();
        List<String> arnList = listResponse.responsePlanSummaries().stream()
            .map(ResponsePlanSummary::arn)
            .toList();

        if (arnList.isEmpty()) {
            status = Status.FAIL;
            result = List.of(Text.NO_RESPONSE_PLANS.toString());
        } else {
            status = Status.PASS;
            result = arnList;
        }
        writer.addToBuffer(AWSFinding.SSM_INCIDENTS_WITHOUT_RESPONSE_PLANS, result, status);
        return status;
    }

    private Status checkPublicSSMDocuments() {
        if (allDocuments.isEmpty()) {
            writer.addToBuffer(AWSFinding.PUBLIC_SSM_DOCUMENTS, 
                            Text.NO_SSM_DOCUMENTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allDocuments.stream()
            .map(document -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    DescribeDocumentPermissionResponse permissionResponse = ssm.describeDocumentPermission(
                        DescribeDocumentPermissionRequest.builder()
                            .name(document.name())
                            .permissionType("Share")
                            .build()
                    ).join();

                    ObjectNode permissionNode = MAPPER.valueToTree(permissionResponse.toBuilder());
                    r.put("permissions", permissionNode);
                    
                    boolean isPublic = permissionResponse.accountIds() != null && 
                                     permissionResponse.accountIds().contains("*");
                    s = isPublic ? Status.FAIL : Status.PASS;
                    
                    ObjectNode documentNode = MAPPER.valueToTree(document);
                    r.put("document", documentNode);
                    
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), 
                                 Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(document.name(), inner);
            })
            .toList();
        
        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.PUBLIC_SSM_DOCUMENTS, result, status);
        return status;
    }    
}
