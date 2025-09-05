package com.twelvesec.cloudscan.AWS.Checks;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.cloudwatch.model.MetricAlarm;
import software.amazon.awssdk.services.cloudwatchlogs.model.LogGroup;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

public class CloudWatchCheck implements CloudCheck {
    private static final long LOW_RETENTION_THRESHOLD = 365;

    private List<LogGroup> allGroups;
    private List<MetricAlarm> allAlarms;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final StsAsyncClient sts;
    
    public CloudWatchCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                        StsAsyncClient sts) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.sts = sts;
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
                    wrapCheck(this::checkCloudWatchCrossAccountSharing,             AWSFinding.CLOUDWATCH_CROSS_ACCOUNT_SHARING, this::reportError)
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

                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), s.toString());
                inner.set(Text.RESULT.toString(), logGroupNode);
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

}
