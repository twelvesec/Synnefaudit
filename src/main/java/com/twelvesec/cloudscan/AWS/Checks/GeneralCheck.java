package com.twelvesec.cloudscan.AWS.Checks;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.account.AccountAsyncClient;
import software.amazon.awssdk.services.account.model.GetAlternateContactRequest;
import software.amazon.awssdk.services.account.model.GetAlternateContactResponse;
import software.amazon.awssdk.services.account.model.ResourceNotFoundException;
import software.amazon.awssdk.services.backup.BackupAsyncClient;
import software.amazon.awssdk.services.backup.model.ListReportPlansRequest;
import software.amazon.awssdk.services.backup.model.ListReportPlansResponse;
import software.amazon.awssdk.services.backup.model.ReportPlan;
import software.amazon.awssdk.services.codebuild.CodeBuildAsyncClient;
import software.amazon.awssdk.services.codebuild.model.BatchGetBuildsRequest;
import software.amazon.awssdk.services.codebuild.model.BatchGetBuildsResponse;
import software.amazon.awssdk.services.codebuild.model.Build;
import software.amazon.awssdk.services.codebuild.model.ListBuildsForProjectRequest;
import software.amazon.awssdk.services.codebuild.model.ListBuildsForProjectResponse;
import software.amazon.awssdk.services.codebuild.model.ListProjectsRequest;
import software.amazon.awssdk.services.codebuild.model.SortOrderType;
import software.amazon.awssdk.services.iam.model.OrganizationNotFoundException;
import software.amazon.awssdk.services.organizations.OrganizationsAsyncClient;
import software.amazon.awssdk.services.organizations.model.AwsOrganizationsNotInUseException;
import software.amazon.awssdk.services.organizations.model.DescribeAccountRequest;
import software.amazon.awssdk.services.organizations.model.DescribeAccountResponse;
import software.amazon.awssdk.services.resourceexplorer2.model.Index;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

public class GeneralCheck implements CloudCheck {
    private List<Index> allIndexes;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final AccountAsyncClient accountClient;
    private final BackupAsyncClient backup;
    private final CodeBuildAsyncClient codeBuild;
    private final OrganizationsAsyncClient orgs;
    private final StsAsyncClient sts;

    public GeneralCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                        AccountAsyncClient accountClient, 
                        BackupAsyncClient backup, CodeBuildAsyncClient codeBuild, 
                        OrganizationsAsyncClient orgs, StsAsyncClient sts) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.accountClient = accountClient;
        this.backup = backup;
        this.codeBuild = codeBuild;
        this.orgs = orgs;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllIndexes()
            .thenCompose(indexes -> {
                this.allIndexes = indexes;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkNoAlternateContactsFound,              AWSFinding.NO_ALTERNATE_CONTACTS_FOUND, this::reportError),
                    wrapCheck(this::checkNoBackupReportPlanExists,              AWSFinding.NO_BACKUP_REPORT_PLAN_EXISTS, this::reportError),
                    wrapCheck(this::checkResourceExplorerIndexes,               AWSFinding.RESOURCE_EXPLORER_NO_INDEXES_FOUND, this::reportError),
                    wrapCheck(this::checkCodeBuildProjectsNotInvokedLast90Days, AWSFinding.CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS, this::reportError),
                    wrapCheck(this::checkAccountInOrganizations,                AWSFinding.ACCOUNT_IS_NOT_PART_OF_ORGANIZATIONS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkNoAlternateContactsFound() {
        List<String> types = List.of("BILLING","OPERATIONS","SECURITY");
        List<Map<String,Object>> result = types.stream()
            .map(type -> {
                Status s;
                ObjectNode r;
                try {
                    GetAlternateContactResponse response = accountClient.getAlternateContact(
                        GetAlternateContactRequest.builder().alternateContactType(type).build()
                    ).join();
                    s = Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (ResourceNotFoundException e) {
                    s = Status.FAIL;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.NO_ALTERNATE_CONTACTS_FOUND.toString().concat(e.getMessage()));
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(type, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.NO_ALTERNATE_CONTACTS_FOUND, result, status);
        return status;
    }

    private Status checkNoBackupReportPlanExists() {
        ListReportPlansResponse listResponse = backup.listReportPlans(ListReportPlansRequest.builder().build()).join();
        List<String> result = listResponse.reportPlans().stream()
            .map(ReportPlan::reportPlanName)
            .toList();

        Status status = !result.isEmpty() ? Status.PASS : Status.FAIL;
        result = result.isEmpty()? List.of(Text.NO_REPORT_PLANS_FOUND.toString()) : result;
        writer.addToBuffer(AWSFinding.NO_BACKUP_REPORT_PLAN_EXISTS, result, status);
        return status;
    }

    private Status checkResourceExplorerIndexes() {
        if (allIndexes.isEmpty()) {
            writer.addToBuffer(AWSFinding.RESOURCE_EXPLORER_NO_INDEXES_FOUND,
                            Text.NO_RESOURCE_EXPLORER_INDEXES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allIndexes.stream()
            .map(index -> {
                ObjectNode indexNode = MAPPER.valueToTree(index);

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), Status.PASS.toString());
                inner.set(Text.RESULT.toString(), indexNode);
                return Map.<String,Object>of(index.arn(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RESOURCE_EXPLORER_NO_INDEXES_FOUND, result, status);
        return status;
    }

    private Status checkCodeBuildProjectsNotInvokedLast90Days() {
        List<String> projectNames = codeBuild.listProjects(
            ListProjectsRequest.builder().build()
        ).join().projects();

        if (projectNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS,
                            Text.NO_CODEBUILD_PROJECTS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(Duration.ofDays(90));
        List<Map<String, Object>> results = projectNames.stream()
            .map(name -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();

                try {
                    ListBuildsForProjectResponse buildsResp = codeBuild.listBuildsForProject(
                        ListBuildsForProjectRequest.builder()
                            .projectName(name)
                            .sortOrder(SortOrderType.DESCENDING)
                            .build()
                    ).join();

                    Optional<String> latestId = buildsResp.ids().stream().findFirst();
                    if (latestId.isEmpty()) {
                        s = Status.FAIL;
                        r = MAPPER.createObjectNode()
                                .put(Text.ERROR.toString(), Text.NO_BUILDS_FOUND.toString());
                    } else {
                        BatchGetBuildsResponse batch = codeBuild.batchGetBuilds(
                            BatchGetBuildsRequest.builder().ids(latestId.get()).build()
                        ).join();
                        Build b = batch.builds().get(0);
                        s = b.endTime().isBefore(cutoff) ? Status.FAIL : Status.PASS;

                        r.put("id", b.id());
                        r.put("arn", b.arn());
                        r.put("buildNumber", b.buildNumber());
                        r.put("startTime", b.startTime().toString());
                        r.put("endTime", b.endTime().toString());
                        r.put("currentPhase", b.currentPhase());
                        r.put("buildStatus", b.buildStatusAsString());
                        r.put("sourceVersion", b.sourceVersion());
                        r.put("resolvedSourceVersion", b.resolvedSourceVersion());
                        r.put("projectName", b.projectName());                      
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode()
                        .put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(name, inner);
            })
            .toList();

        Status status = getOverallStatus(results);
        writer.addToBuffer(AWSFinding.CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS, results, status);
        return status;
    }

    private Status checkAccountInOrganizations() {
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();

        Status status;
        ObjectNode result = MAPPER.createObjectNode();
        try {
            DescribeAccountResponse orgResponse = orgs.describeAccount(
                DescribeAccountRequest.builder().accountId(accountId).build()
            ).join();
            ObjectNode orgNode = MAPPER.valueToTree(orgResponse.toBuilder());
            
            status = orgResponse.account() != null ? Status.PASS : Status.FAIL;
            
            ObjectNode inner = MAPPER.createObjectNode();
            inner.put(Text.STATUS.toString(), status.toString());
            inner.set(Text.RESULT.toString(), orgNode);
            result = inner;
        } catch (OrganizationNotFoundException|AwsOrganizationsNotInUseException e) {
            status = Status.FAIL;
            result.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
        }
        
        writer.addToBuffer(AWSFinding.ACCOUNT_IS_NOT_PART_OF_ORGANIZATIONS, result, status);
        return Status.FAIL;
    }
}
