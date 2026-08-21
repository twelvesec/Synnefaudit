package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.account.AccountAsyncClient;
import software.amazon.awssdk.services.account.model.GetAlternateContactRequest;
import software.amazon.awssdk.services.account.model.GetAlternateContactResponse;
import software.amazon.awssdk.services.account.model.ResourceNotFoundException;
import software.amazon.awssdk.services.codebuild.CodeBuildAsyncClient;
import software.amazon.awssdk.services.codebuild.model.*;
import software.amazon.awssdk.services.iam.model.OrganizationNotFoundException;
import software.amazon.awssdk.services.organizations.OrganizationsAsyncClient;
import software.amazon.awssdk.services.organizations.model.AwsOrganizationsNotInUseException;
import software.amazon.awssdk.services.organizations.model.DescribeAccountRequest;
import software.amazon.awssdk.services.organizations.model.DescribeAccountResponse;
import software.amazon.awssdk.services.resourceexplorer2.model.Index;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class GeneralCheck implements CloudCheck {
    private List<Index> allIndexes;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final AccountAsyncClient accountClient;
    private final OrganizationsAsyncClient orgs;
    private final StsAsyncClient sts;
    private final JsonNode config;

    public GeneralCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                        AccountAsyncClient accountClient,
                        OrganizationsAsyncClient orgs, StsAsyncClient sts, JsonNode config) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.accountClient = accountClient;
        this.orgs = orgs;
        this.sts = sts;
        this.config = config;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<Index>> indexes = sharedDataProvider.getAllIndexes()
                .exceptionally(ex -> null);

        return indexes.thenCompose(i -> {
            this.allIndexes = i;

            List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkNoAlternateContactsFound, AWSFinding.NO_ALTERNATE_CONTACTS_FOUND, this::reportError),
                    wrapCheck(this::checkResourceExplorerIndexes,  AWSFinding.RESOURCE_EXPLORER_NO_INDEXES_FOUND, this::reportError),
                    wrapCheck(this::checkAccountInOrganizations,   AWSFinding.ACCOUNT_IS_NOT_PART_OF_ORGANIZATIONS, this::reportError)
            );
            return runChecksInList(checksList, writer);
        });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkNoAlternateContactsFound() {
        List<String> types = getStringList(config.path("contact_types"));
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

    private Status checkResourceExplorerIndexes() {
        if (allIndexes.isEmpty()) {
            writer.addToBuffer(AWSFinding.RESOURCE_EXPLORER_NO_INDEXES_FOUND,
                            Text.NO_RESOURCE_EXPLORER_INDEXES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allIndexes.stream()
            .map(index -> {
                ObjectNode indexNode = MAPPER.valueToTree(index);

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), Status.PASS.toString());
                inner.put(Text.RESULT.toString(), indexNode);
                return Map.<String,Object>of(index.arn(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.RESOURCE_EXPLORER_NO_INDEXES_FOUND, result, status);
        return status;
    }

    private Status checkAccountInOrganizations() {
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();

        Status status;
        Map<String, Object> result = new HashMap<>();
        try {
            DescribeAccountResponse orgResponse = orgs.describeAccount(
                DescribeAccountRequest.builder().accountId(accountId).build()
            ).join();
            ObjectNode orgNode = MAPPER.valueToTree(orgResponse.toBuilder());
            
            status = orgResponse.account() != null ? Status.PASS : Status.FAIL;
            
            result.put(Text.STATUS.toString(), status.toString());
            result.put(Text.RESULT.toString(), orgNode);
        } catch (OrganizationNotFoundException|AwsOrganizationsNotInUseException e) {
            status = Status.FAIL;
            result.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
        }
        
        writer.addToBuffer(AWSFinding.ACCOUNT_IS_NOT_PART_OF_ORGANIZATIONS, result, status);
        return Status.FAIL;
    }
}
