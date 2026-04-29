package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.drs.DrsAsyncClient;
import software.amazon.awssdk.services.drs.model.DescribeJobsRequest;
import software.amazon.awssdk.services.drs.model.DescribeJobsResponse;
import software.amazon.awssdk.services.drs.model.Job;
import software.amazon.awssdk.services.drs.model.UninitializedAccountException;
import software.amazon.awssdk.services.macie2.Macie2AsyncClient;
import software.amazon.awssdk.services.macie2.model.AccessDeniedException;
import software.amazon.awssdk.services.macie2.model.GetMacieSessionRequest;
import software.amazon.awssdk.services.macie2.model.GetMacieSessionResponse;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretListEntry;
import software.amazon.awssdk.services.securityhub.SecurityHubAsyncClient;
import software.amazon.awssdk.services.securityhub.model.DescribeHubRequest;
import software.amazon.awssdk.services.securityhub.model.DescribeHubResponse;
import software.amazon.awssdk.services.securityhub.model.InvalidAccessException;
import software.amazon.awssdk.services.wafv2.Wafv2AsyncClient;
import software.amazon.awssdk.services.wafv2.model.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class EnabledServicesCheck implements CloudCheck {
    private List<SecretListEntry> allSecrets;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final SecretsManagerAsyncClient secretsManager;
    private final DrsAsyncClient drs;
    private final Macie2AsyncClient macie2;
    private final SecurityHubAsyncClient securityHub;
    private final Wafv2AsyncClient waf;

    public EnabledServicesCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
            SecretsManagerAsyncClient secretsManager, DrsAsyncClient drs, Macie2AsyncClient macie2,
            SecurityHubAsyncClient securityHub, Wafv2AsyncClient waf) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.secretsManager = secretsManager;
        this.drs = drs;
        this.macie2 = macie2;
        this.securityHub = securityHub;
        this.waf = waf;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllSecrets()
            .thenCompose(secrets -> {
                this.allSecrets = secrets;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkSecretManagerSecretsWithRotationDisabled,          AWSFinding.SECRETS_MANAGER_SECRETS_ROTATION_DISABLED, this::reportError),
                    wrapCheck(this::checkDRSDisabled,                                       AWSFinding.DRS_NOT_ENABLED, this::reportError),
                    wrapCheck(this::checkMacieIsDisabled,                                   AWSFinding.MACIE_NOT_ENABLED, this::reportError),
                    wrapCheck(this::checkSecurityHubIsDisabled,                             AWSFinding.SECURITY_HUB_NOT_ENABLED, this::reportError),
                    wrapCheck(this::checkWafv2WebAclLoggingEnabled,                         AWSFinding.WAFV2_WEB_ACL_LOGGING_ENABLED, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }
    
    private Status checkSecretManagerSecretsWithRotationDisabled() { 
        if (allSecrets.isEmpty()) {
            writer.addToBuffer(AWSFinding.SECRETS_MANAGER_SECRETS_ROTATION_DISABLED, 
                Text.NO_SECRETS_MANAGER_SECRETS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allSecrets.stream()
            .map(secret -> {
                String name = secret.name();
                Status s;
                ObjectNode r;
                try {
                    DescribeSecretResponse response = secretsManager.describeSecret(
                        DescribeSecretRequest.builder().secretId(name).build()
                    ).join();
                    boolean violation = response.rotationEnabled() == null || !response.rotationEnabled();
                    s = violation ? Status.FAIL : Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(name, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.SECRETS_MANAGER_SECRETS_ROTATION_DISABLED, result, status);
        return status;
    }

    private Status checkDRSDisabled() {
        Status status;
        List<String> result;

        try {
            DescribeJobsRequest describeJobsRequest = DescribeJobsRequest.builder().build();
            DescribeJobsResponse describeJobsResponse = drs.describeJobs(describeJobsRequest).join();
            List<String> jobIds = describeJobsResponse.items().stream()
                .map(Job::jobID)
                .toList();

            status = Status.PASS;
            result = jobIds;
        } catch (UninitializedAccountException e) {
            status = Status.FAIL;
            result = List.of(Text.EXCEPTION.toString().concat(e.getMessage()));
        }

        writer.addToBuffer(AWSFinding.DRS_NOT_ENABLED, result, status);
        return status;
    }

    private Status checkMacieIsDisabled() {
        Status status;
        ObjectNode result;
        try {
            GetMacieSessionResponse response = macie2.getMacieSession(
                GetMacieSessionRequest.builder().build()
            ).join();

            status = Status.PASS;
            result = MAPPER.valueToTree(response.toBuilder());
        } catch (AccessDeniedException e) {
            status = e.getMessage().contains("Macie is not enabled") ? Status.FAIL : Status.FAIL_EXCEPTION;
            result = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                Text.EXCEPTION.toString().concat(e.getMessage()));
        }
        writer.addToBuffer(AWSFinding.MACIE_NOT_ENABLED, result, status);
        return status;
    }

    private Status checkSecurityHubIsDisabled() {
        Status status;
        String result;
        try {
            DescribeHubResponse response = securityHub.describeHub(
                DescribeHubRequest.builder().build()
            ).join();

            status = Status.PASS;
            result = response.toString();
        } catch (InvalidAccessException e) {
            status = e.getMessage().contains("is not subscribed to AWS Security Hub") ? Status.FAIL : Status.FAIL_EXCEPTION;
            result = Text.EXCEPTION.toString().concat(e.getMessage());
        }
        writer.addToBuffer(AWSFinding.SECURITY_HUB_NOT_ENABLED, result, status);
        return status;
    }

    private Status checkWafv2WebAclLoggingEnabled() { 
        Scope scope = Scope.REGIONAL;
        List<WebACLSummary> webAcls = waf.listWebACLs(
            ListWebAcLsRequest.builder().scope(scope).build()
        ).join().webACLs();

        if (webAcls.isEmpty()) {
            writer.addToBuffer(AWSFinding.WAFV2_WEB_ACL_LOGGING_ENABLED,
                            Text.NO_WAF_WEB_ACLS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Set<String> loggedArns = waf.listLoggingConfigurations(
            ListLoggingConfigurationsRequest.builder().scope(scope).build()
        ).join()
            .loggingConfigurations().stream()
            .map(LoggingConfiguration::resourceArn)
            .collect(Collectors.toSet());

        List<Map<String,Object>> result = webAcls.stream()
            .map(acl -> {
                String arn = acl.arn();
                Status s;
                String r;
                if (loggedArns.contains(arn)) {
                    s = Status.PASS;
                    r = Text.LOGGING_ENABLED_FOR_WEBACL.toString().concat(String.join(", ",loggedArns));
                } else {
                    s = Status.FAIL;
                    r = Text.NO_LOGGING_CONFIGURATION_FOUND.toString().concat(String.join(", ",loggedArns));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(arn, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.WAFV2_WEB_ACL_LOGGING_ENABLED, result, status);
        return status;
    }
}
