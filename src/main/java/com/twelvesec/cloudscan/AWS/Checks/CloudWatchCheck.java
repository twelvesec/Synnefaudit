package com.twelvesec.cloudscan.AWS.Checks;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.CloudCheck.CheckResult;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.cloudwatch.model.MetricAlarm;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeMetricFiltersRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeMetricFiltersResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.LogGroup;
import software.amazon.awssdk.services.cloudwatchlogs.model.MetricFilter;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

public class CloudWatchCheck implements CloudCheck {
    private static final long LOW_RETENTION_THRESHOLD = 365;

    private List<LogGroup> allGroups;
    private List<MetricAlarm> allAlarms;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final StsAsyncClient sts;
    private final CloudWatchLogsAsyncClient cloudWatchLogs;
    
    public CloudWatchCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                        StsAsyncClient sts, CloudWatchLogsAsyncClient cloudWatchLogs) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.sts = sts;
        this.cloudWatchLogs = cloudWatchLogs;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllLogGroups()
            .thenCompose(logGroups -> {
                this.allGroups = logGroups;
                return sharedDataProvider.getAllAlarms();
            })
            .thenCompose(allAlarms -> {
                this.allAlarms = allAlarms;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkCloudWatchAlarmsForSensitiveOperations,    AWSFinding.CLOUDWATCH_ALARMS_FOR_SENSITIVE_OPERATIONS, this::reportError),
                    wrapCheck(this::checkLogGroupsWithNoAWSKMSKeysAssociated,       AWSFinding.CLOUDWATCH_LOG_GROUPS_WITH_NO_KMS_KEYS_ASSOCIATED, this::reportError),
                    wrapCheck(this::checkLogGroupsWithLowRetentionPolicy,           AWSFinding.CLOUDWATCH_LOG_GROUPS_WITH_LOW_RETENTION_POLICY, this::reportError),
                    wrapCheck(this::checkCloudWatchCrossAccountSharing,             AWSFinding.CLOUDWATCH_CROSS_ACCOUNT_SHARING, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForAWSConfigChanges,        AWSFinding.LOG_METRIC_FILTER_AWS_CONFIG_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForConsoleAuthFailures,     AWSFinding.LOG_METRIC_FILTER_CONSOLE_AUTH_FAILURES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForOrganizationsChanges,    AWSFinding.LOG_METRIC_FILTER_ORGANIZATIONS_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForNACLChanges,             AWSFinding.LOG_METRIC_FILTER_NACL_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForNetworkGatewayChanges,   AWSFinding.LOG_METRIC_FILTER_NETWORK_GATEWAY_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForCloudTrailChanges,       AWSFinding.LOG_METRIC_FILTER_CLOUDTRAIL_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForKMSKeyDeletion,          AWSFinding.LOG_METRIC_FILTER_KMS_KEY_DELETION, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForIAMPolicyChanges,        AWSFinding.LOG_METRIC_FILTER_IAM_POLICY_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForConsoleSigninWithoutMFA, AWSFinding.LOG_METRIC_FILTER_CONSOLE_SIGNIN_NO_MFA, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForS3BucketPolicyChanges,   AWSFinding.LOG_METRIC_FILTER_S3_BUCKET_POLICY_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForSecurityGroupChanges,    AWSFinding.LOG_METRIC_FILTER_SECURITY_GROUP_CHANGES, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForUnauthorizedAPICalls,    AWSFinding.LOG_METRIC_FILTER_UNAUTHORIZED_API_CALLS, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForRootAccountUsage,        AWSFinding.LOG_METRIC_FILTER_ROOT_ACCOUNT_USAGE, this::reportError),
                    wrapCheck(this::checkLogMetricFilterForVPCChanges,              AWSFinding.LOG_METRIC_FILTER_VPC_CHANGES, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkCloudWatchAlarmsForSensitiveOperations() {
        if (allAlarms.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDWATCH_ALARMS_FOR_SENSITIVE_OPERATIONS, 
                            Text.NO_CLOUDWATCH_ALARMS_CONFIGURED.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allAlarms.stream()
            .map(alarm -> {
                Object s = switch (alarm.metricName()) {
                    case "CPUUtilization", "MemoryUtilization" -> Status.PASS;
                    default -> Status.FAIL;
                };
                ObjectNode r = MAPPER.valueToTree(alarm.toBuilder());
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String,Object>of(alarm.alarmName(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDWATCH_ALARMS_FOR_SENSITIVE_OPERATIONS, result, status);
        return status;
    }

    private Status checkLogGroupsWithNoAWSKMSKeysAssociated() {
        if (allGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDWATCH_LOG_GROUPS_WITH_NO_KMS_KEYS_ASSOCIATED, 
                            Text.NO_LOG_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allGroups.stream()
            .map(group -> {
                boolean hasKey = group.kmsKeyId() != null && !group.kmsKeyId().isEmpty();
                Map<String,Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), hasKey ? Status.PASS.toString() : Status.FAIL.toString());
                inner.put(Text.RESULT.toString(), group);
                return Map.<String,Object>of(group.arn(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDWATCH_LOG_GROUPS_WITH_NO_KMS_KEYS_ASSOCIATED, result, status);
        return status;
    }

    private Status checkLogGroupsWithLowRetentionPolicy() {
        if (allGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDWATCH_LOG_GROUPS_WITH_LOW_RETENTION_POLICY, 
                            Text.NO_LOG_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allGroups.stream()
            .map(logGroup -> {
                String name = logGroup.logGroupName();
                Integer retention = logGroup.retentionInDays();

                Status s = retention == null || retention < LOW_RETENTION_THRESHOLD ? Status.FAIL : Status.PASS;
                ObjectNode logGroupNode = MAPPER.valueToTree(logGroup.toBuilder());

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), logGroupNode);
                return Map.<String, Object>of(name, inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDWATCH_LOG_GROUPS_WITH_LOW_RETENTION_POLICY, result, status);
        return status;
    }

    private Status checkCloudWatchCrossAccountSharing() {
        String accountId = sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();

        if (allAlarms.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDWATCH_CROSS_ACCOUNT_SHARING, 
                            Text.NO_CLOUDWATCH_ALARMS_CONFIGURED.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allAlarms.stream()
            .map(alarm -> {
                boolean hasCrossAccountSharing = alarm.alarmActions() != null 
                    && alarm.alarmActions().stream()
                        .anyMatch(action -> action.contains("arn:aws:sns:") 
                                        && !action.contains(accountId));

                Status status = hasCrossAccountSharing ? Status.FAIL : Status.PASS;
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status);
                inner.put(Text.RESULT.toString(), MAPPER.valueToTree(alarm.toBuilder()));
                return Map.<String, Object>of(alarm.alarmName(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDWATCH_CROSS_ACCOUNT_SHARING, result, status);
        return status;
    }

    private Status checkLogMetricFilterAndAlarm(
        AWSFinding finding,
        String filterPattern,
        String expectedMetricName,
        List<String> expectedAlarmNames
    ) {
        if (allGroups.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_LOG_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allGroups.stream()
            .map(logGroup -> {
                String logGroupName = logGroup.logGroupName();
                Status s;
                ObjectNode resultNode = MAPPER.createObjectNode();
                
                try {
                    DescribeMetricFiltersResponse metricFiltersResponse = cloudWatchLogs.describeMetricFilters(
                        DescribeMetricFiltersRequest.builder()
                            .logGroupName(logGroupName)
                            .build()
                    ).join();
                    
                    List<MetricFilter> matchingFilters = metricFiltersResponse.metricFilters().stream()
                        .filter(filter -> filter.filterPattern().contains(filterPattern))
                        .collect(Collectors.toList());
                    
                    if (matchingFilters.isEmpty()) {
                        s = Status.FAIL;
                        resultNode.put(Text.MESSAGE.toString(), Text.NO_METRIC_FILTER_FOUND.toString() + filterPattern);
                        resultNode.put(Text.RESULT.toString(), metricFiltersResponse.metricFilters().toString());
                    } else {
                        boolean hasExpectedMetric = matchingFilters.stream()
                            .flatMap(filter -> filter.metricTransformations().stream())
                            .anyMatch(transformation -> transformation.metricName().equals(expectedMetricName));
                        
                        if (!hasExpectedMetric) {
                            s = Status.FAIL;
                            resultNode.put(Text.MESSAGE.toString(), Text.METRIC_FILTER_FOUND_WRONG_METRIC.toString() + expectedMetricName);
                            resultNode.put(Text.RESULT.toString(), matchingFilters.toString());
                        } else {
                            List<MetricAlarm> matchingAlarms = allAlarms.stream()
                                .filter(alarm -> expectedAlarmNames.contains(alarm.alarmName()))
                                .collect(Collectors.toList());
                            
                            if (matchingAlarms.isEmpty()) {
                                s = Status.FAIL;
                                resultNode.put(Text.MESSAGE.toString(), Text.NO_MATCHING_ALARMS_FOUND.getText());
                            } else {
                                boolean hasAlarmingAlarm = matchingAlarms.stream()
                                    .anyMatch(alarm -> "ALARM".equals(alarm.stateValue()));
                                
                                if (hasAlarmingAlarm) {
                                    s = Status.FAIL; 
                                    resultNode.put(Text.MESSAGE.toString(), Text.ALARM_IN_ALARM_STATE.toString() + matchingAlarms);
                                } else {
                                    s = Status.PASS;
                                    resultNode.put(Text.MESSAGE.toString(), Text.ALARM_ACTIVE_AND_OK.toString() + matchingAlarms);
                                }
                                resultNode.set(Text.ALARMS.toString(), 
                                    MAPPER.valueToTree(matchingAlarms.stream()
                                        .map(MetricAlarm::toBuilder)
                                        .collect(Collectors.toList())));
                            }
                            resultNode.set(Text.METRIC_FILTERS.toString(), 
                                MAPPER.valueToTree(matchingFilters.stream()
                                    .map(MetricFilter::toBuilder)
                                    .collect(Collectors.toList())));
                        }
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    resultNode.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }

                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), resultNode);
                return Map.<String, Object>of(logGroupName, inner);
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Status checkLogMetricFilterForAWSConfigChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_AWS_CONFIG_CHANGES,
            "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }",
            "AWSConfigChanges",
            Arrays.asList("AWSConfigChangesAlarm", "ConfigChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForConsoleAuthFailures() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_CONSOLE_AUTH_FAILURES,
            "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }",
            "ConsoleSigninFailureCount",
            Arrays.asList("ConsoleAuthFailuresAlarm", "ConsoleSigninFailureAlarm")
        );
    }

    private Status checkLogMetricFilterForOrganizationsChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_ORGANIZATIONS_CHANGES,
            "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }",
            "OrganizationsChanges",
            Arrays.asList("OrganizationsChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForNACLChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_NACL_CHANGES,
            "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }",
            "NACLChanges",
            Arrays.asList("NACLChangesAlarm", "NetworkAclChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForNetworkGatewayChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_NETWORK_GATEWAY_CHANGES,
            "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }",
            "NetworkGatewayChanges",
            Arrays.asList("NetworkGatewayChangesAlarm", "GatewayChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForCloudTrailChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_CLOUDTRAIL_CHANGES,
            "{ ($.eventSource = cloudtrail.amazonaws.com) && (($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)) }",
            "CloudTrailChanges",
            Arrays.asList("CloudTrailChangesAlarm", "TrailChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForKMSKeyDeletion() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_KMS_KEY_DELETION,
            "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }",
            "KMSKeyDeletion",
            Arrays.asList("KMSKeyDeletionAlarm", "KeyDisableDeletionAlarm")
        );
    }

    private Status checkLogMetricFilterForIAMPolicyChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_IAM_POLICY_CHANGES,
            "{ ($.eventSource = iam.amazonaws.com) && (($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy)) }",
            "IAMPolicyChanges",
            Arrays.asList("IAMPolicyChangesAlarm", "PolicyChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForConsoleSigninWithoutMFA() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_CONSOLE_SIGNIN_NO_MFA,
            "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }",
            "ConsoleSigninWithoutMFA",
            Arrays.asList("ConsoleSigninWithoutMFAAlarm", "NoMFASigninAlarm")
        );
    }

    private Status checkLogMetricFilterForS3BucketPolicyChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_S3_BUCKET_POLICY_CHANGES,
            "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }",
            "S3BucketPolicyChanges",
            Arrays.asList("S3BucketPolicyChangesAlarm", "BucketPolicyChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForSecurityGroupChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_SECURITY_GROUP_CHANGES,
            "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }",
            "SecurityGroupChanges",
            Arrays.asList("SecurityGroupChangesAlarm", "SGChangesAlarm")
        );
    }

    private Status checkLogMetricFilterForUnauthorizedAPICalls() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_UNAUTHORIZED_API_CALLS,
            "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }",
            "UnauthorizedAPICalls",
            Arrays.asList("UnauthorizedAPICallsAlarm", "AccessDeniedAlarm")
        );
    }

    private Status checkLogMetricFilterForRootAccountUsage() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_ROOT_ACCOUNT_USAGE,
            "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }",
            "RootAccountUsage",
            Arrays.asList("RootAccountUsageAlarm", "RootUserActivityAlarm")
        );
    }

    private Status checkLogMetricFilterForVPCChanges() {
        return checkLogMetricFilterAndAlarm(
            AWSFinding.LOG_METRIC_FILTER_VPC_CHANGES,
            "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }",
            "VPCChanges",
            Arrays.asList("VPCChangesAlarm", "VPCModificationsAlarm")
        );
    }

}
