package com.twelvesec.cloudscan.AWS.Checks;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.cloudtrail.CloudTrailAsyncClient;
import software.amazon.awssdk.services.cloudtrail.model.DescribeTrailsRequest;
import software.amazon.awssdk.services.cloudtrail.model.DescribeTrailsResponse;
import software.amazon.awssdk.services.cloudtrail.model.Event;
import software.amazon.awssdk.services.cloudtrail.model.EventSelector;
import software.amazon.awssdk.services.cloudtrail.model.GetEventSelectorsResponse;
import software.amazon.awssdk.services.cloudtrail.model.GetInsightSelectorsRequest;
import software.amazon.awssdk.services.cloudtrail.model.GetInsightSelectorsResponse;
import software.amazon.awssdk.services.cloudtrail.model.InsightNotEnabledException;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttribute;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttributeKey;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsRequest;
import software.amazon.awssdk.services.cloudtrail.model.ReadWriteType;
import software.amazon.awssdk.services.cloudtrail.model.Trail;
import software.amazon.awssdk.services.cloudtrail.model.TrailInfo;
import software.amazon.awssdk.services.cloudwatch.model.DescribeAlarmsRequest;
import software.amazon.awssdk.services.cloudwatch.model.DescribeAlarmsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeMetricFiltersRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeMetricFiltersResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilterLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilterLogEventsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.FilteredLogEvent;
import software.amazon.awssdk.services.cloudwatchlogs.model.LogGroup;
import software.amazon.awssdk.services.cloudwatchlogs.model.MetricFilter;

public class CloudTrailCheck implements CloudCheck {
    private List<TrailInfo> allTrails;
    private List<String> allS3BucketNames;
    private List<LogGroup> allLogGroups;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final CloudTrailAsyncClient cloudTrail;
    private final CloudWatchLogsAsyncClient cloudWatchLogs;

    public CloudTrailCheck(DataWriter writer, SharedDataProvider sharedDataProvider, 
                        CloudTrailAsyncClient cloudTrail, CloudWatchLogsAsyncClient cloudWatchLogs) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.cloudTrail = cloudTrail;
        this.cloudWatchLogs = cloudWatchLogs; 
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllTrails()
            .thenCompose(trails -> {
                this.allTrails = trails;
                return sharedDataProvider.getAllS3BucketNames();
            })
            .thenCompose(s3Buckets -> {
                this.allS3BucketNames = s3Buckets;
                return sharedDataProvider.getAllLogGroups();
            })
            .thenCompose(logGroups -> {
                this.allLogGroups = logGroups;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkTrailWithNoInsightSelectors,           AWSFinding.CLOUDTRAIL_WITH_NO_INSIGHT_SELECTORS, this::reportError),
                    wrapCheck(this::checkRecentRootAccountUsage,                AWSFinding.CLOUDTRAIL_RECENT_ROOT_ACCOUNT_USAGE, this::reportError),
                    wrapCheck(this::checkS3ObjectLevelReadLogging,              AWSFinding.S3_OBJECT_LEVEL_READ_LOGGING, this::reportError),
                    wrapCheck(this::checkS3ObjectLevelWriteLogging,             AWSFinding.S3_OBJECT_LEVEL_WRITE_LOGGING, this::reportError),
                    wrapCheck(this::checkCloudTrailCloudWatchIntegration,       AWSFinding.CLOUDTRAIL_CLOUDWATCH_INTEGRATION, this::reportError),
                    wrapCheck(this::checkLogGroupsWithSecretsInCloudWatchLogs,  AWSFinding.CLOUDTRAIL_LOG_GROUPS_WITH_SECRETS_IN_CLOUDWATCH_LOGS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private Status checkTrailWithNoInsightSelectors() {
        if (allTrails.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDTRAIL_WITH_NO_INSIGHT_SELECTORS, 
                        Text.NO_CLOUDTRAIL_TRAILS_CONFIGURED_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String,Object>> result = allTrails.stream()
            .map(trail -> {
                String name = trail.name();
                Status s;
                ObjectNode r;
                try {
                    GetInsightSelectorsResponse response = cloudTrail.getInsightSelectors(
                        GetInsightSelectorsRequest.builder().trailName(name).build()
                    ).join();
                    s = Status.PASS;
                    r = MAPPER.valueToTree(response.toBuilder());
                } catch (InsightNotEnabledException e) {
                    s = Status.FAIL;
                    r = MAPPER.createObjectNode().put(Text.ERROR.toString(),
                                                    Text.NO_INSIGHT_SELECTORS.toString().concat(e.getMessage()));
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
        writer.addToBuffer(AWSFinding.CLOUDTRAIL_WITH_NO_INSIGHT_SELECTORS, result, status);
        return status;
    }

    private Status checkRecentRootAccountUsage() {
        Instant endTime = Instant.now();
        Instant startTime = endTime.minus(1, ChronoUnit.DAYS);
        
        LookupEventsRequest request = LookupEventsRequest.builder()
            .lookupAttributes(
                LookupAttribute.builder().attributeKey(
                    LookupAttributeKey.USERNAME).attributeValue("root").build()
                )
            .startTime(startTime)
            .endTime(endTime)
            .build();

        List<Event> rootEvents = new ArrayList<>();
        cloudTrail.lookupEventsPaginator(request)
            .subscribe(response -> rootEvents.addAll(response.events()))
            .join();

        ArrayNode resultNode = MAPPER.createArrayNode();
        if (rootEvents.isEmpty()) {
            resultNode.add(Text.NO_ROOT_ACTIVITY_FOUND.toString());
        } else {
            resultNode.addAll((ArrayNode)MAPPER.valueToTree(rootEvents));
        }

        Status status = rootEvents.isEmpty() ? Status.PASS : Status.FAIL;
        writer.addToBuffer(AWSFinding.CLOUDTRAIL_RECENT_ROOT_ACCOUNT_USAGE, resultNode, status);
        return status;
    }

    private Status checkS3ObjectLevelLogging(boolean checkReadEvents, AWSFinding finding) {
        if (allS3BucketNames.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_S3_BUCKETS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        if (allTrails.isEmpty()) {
            writer.addToBuffer(finding, Text.NO_CLOUDTRAIL_TRAILS_CONFIGURED_FOUND.toString(), Status.FAIL);
            return Status.FAIL;
        }

        List<Map<String, Object>> result = allS3BucketNames.stream()
            .map(bucket -> {
                Status s;
                ObjectNode r = MAPPER.createObjectNode();
                
                try {
                    boolean hasLogging = allTrails.stream()
                        .anyMatch(trail -> {
                            try {
                                GetEventSelectorsResponse eventSelectorsResponse = 
                                    sharedDataProvider.getEventSelectorsForTrail(trail.name()).join();
                                return eventSelectorsResponse.eventSelectors().stream()
                                    .anyMatch(selector -> 
                                        hasS3ObjectLoggingConfigured(selector, bucket, checkReadEvents)
                                    );
                            } catch (Exception e) {
                                return false;
                            }
                        });
                    
                    s = hasLogging ? Status.PASS : Status.FAIL;                    
                    if (hasLogging) {
                        ArrayNode trailsNode = MAPPER.valueToTree(
                            getTrailsWithObjectLevelLoggingForBucket(bucket, checkReadEvents)
                        );
                        r.set("loggingTrails", trailsNode);
                    } else {
                        r.put("reason", "No CloudTrail trail found with " 
                                      + (checkReadEvents ? "read" : "write")
                                      + " object-level logging enabled for this bucket");
                    }
                } catch (Exception e) {
                    s = Status.FAIL_EXCEPTION;
                    r.put(Text.ERROR.toString(), Text.EXCEPTION.getText().concat(e.getMessage()));
                }
                r.put("logType", checkReadEvents ? "READ" : "WRITE");
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), s);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(bucket, inner);
            })
            .collect(Collectors.toList());
        
        Status status = getOverallStatus(result);
        writer.addToBuffer(finding, result, status);
        return status;
    }

    private Status checkS3ObjectLevelReadLogging() {
        return checkS3ObjectLevelLogging(true, AWSFinding.S3_OBJECT_LEVEL_READ_LOGGING);
    }

    private Status checkS3ObjectLevelWriteLogging() {
        return checkS3ObjectLevelLogging(false, AWSFinding.S3_OBJECT_LEVEL_WRITE_LOGGING);
    }

    private boolean hasS3ObjectLoggingConfigured(EventSelector selector, String bucketName, boolean checkReadEvents) {
        boolean hasS3ObjectResources = selector.dataResources().stream()
            .anyMatch(dataResource -> 
                dataResource.type().equals("AWS::S3::Object") &&
                dataResource.values().stream()
                    .anyMatch(value -> 
                        value.equals("arn:aws:s3:::" + bucketName + "/") ||
                        value.equals("arn:aws:s3:::" + bucketName + "/*")
                    )
            );
        
        if (!hasS3ObjectResources) {
            return false;
        }

        return checkReadEvents
            ? selector.readWriteType() == ReadWriteType.READ_ONLY || selector.readWriteType() == ReadWriteType.ALL
            : selector.readWriteType() == ReadWriteType.WRITE_ONLY || selector.readWriteType() == ReadWriteType.ALL;
    }

    private List<String> getTrailsWithObjectLevelLoggingForBucket(String bucketName, boolean checkReadEvents) {
        return allTrails.stream()
            .filter(trail -> {
                try {
                    GetEventSelectorsResponse eventSelectorsResponse = sharedDataProvider
                        .getEventSelectorsForTrail(trail.name()).join();
                    return eventSelectorsResponse.eventSelectors().stream()
                        .anyMatch(selector -> 
                            hasS3ObjectLoggingConfigured(selector, bucketName, checkReadEvents)
                        );
                } catch (Exception e) {
                    return false;
                }
            })
            .map(TrailInfo::name)
            .collect(Collectors.toList());
    }

    private Status checkCloudTrailCloudWatchIntegration() {
        if (allTrails.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDTRAIL_CLOUDWATCH_INTEGRATION, 
                            Text.NO_CLOUDTRAIL_TRAILS_CONFIGURED_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allTrails.stream()
            .map(trail -> {
                DescribeTrailsResponse describeResponse = cloudTrail.describeTrails(
                    DescribeTrailsRequest.builder().trailNameList(trail.trailARN()).build()
                ).join();
                                
                Trail trailDetails = describeResponse.trailList().get(0);
                
                boolean hasCloudWatchIntegration = trailDetails.cloudWatchLogsLogGroupArn() != null
                                                && !trailDetails.cloudWatchLogsLogGroupArn().isEmpty();
                boolean hasProperIAMRole = trailDetails.cloudWatchLogsRoleArn() != null
                                        && !trailDetails.cloudWatchLogsRoleArn().isEmpty();
                
                Status status = !hasCloudWatchIntegration || !hasProperIAMRole ? Status.FAIL : Status.PASS;

                ObjectNode r = MAPPER.valueToTree(trailDetails.toBuilder());
                r.put("hasCloudwatchLogsIntegration", hasCloudWatchIntegration);
                r.put("hasIAMRole", hasProperIAMRole);
                
                Map<String, Object> inner = new HashMap<>();
                inner.put(Text.STATUS.toString(), status);
                inner.put(Text.RESULT.toString(), r);
                return Map.<String, Object>of(trail.name(), inner);
            })
            .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDTRAIL_CLOUDWATCH_INTEGRATION, result, status);
        return status;
    }

    private Status checkLogGroupsWithSecretsInCloudWatchLogs() {
        if (allLogGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.CLOUDTRAIL_LOG_GROUPS_WITH_SECRETS_IN_CLOUDWATCH_LOGS, 
                            Text.NO_LOG_GROUPS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<String> secretPatterns = Arrays.asList(
            "accessKeyId", "secretKey", "password", "apiKey", "token",
            "credential", "privateKey", "aws_secret", "aws_access", "client_secret"
        );

        List<Map<String, Object>> result = allLogGroups.stream()
            .map(logGroup -> {
                String logGroupName = logGroup.logGroupName();
                
                try {
                    AtomicBoolean secretsFound = new AtomicBoolean(false);
                    List<String> matchedPattern = new ArrayList<>();
                    List<FilteredLogEvent> foundEvents = new ArrayList<>();

                    secretPatterns.stream()
                        .takeWhile(pattern -> !secretsFound.get())
                        .forEach(pattern -> {
                            FilterLogEventsRequest filterRequest = FilterLogEventsRequest.builder()
                                .logGroupName(logGroupName)
                                .filterPattern(pattern)
                                .limit(5)
                                .build();

                            FilterLogEventsResponse filterResponse = cloudWatchLogs.filterLogEvents(filterRequest).join();
                            if (!filterResponse.events().isEmpty()) {
                                secretsFound.set(true);
                                matchedPattern.add(pattern);
                                foundEvents.addAll(filterResponse.events());
                            }
                        });

                    Map<String, Object> inner = new HashMap<>();
                    
                    if (secretsFound.get()) {
                        inner.put(Text.STATUS.toString(), Status.FAIL);
                        inner.put("pattern_matched", String.join(", ",matchedPattern));
                        inner.put("events_found", foundEvents.size());
                        
                        List<Map<String, String>> sampleEvents = foundEvents.stream()
                            .limit(2)
                            .map(event -> Map.of(
                                "eventId", event.eventId() != null ? event.eventId() : "unknown",
                                "timestamp", String.valueOf(event.timestamp()),
                                "message_preview", event.message() != null ? 
                                    event.message().substring(0, Math.min(30, event.message().length())) + "..." : "null"
                            ))
                            .collect(Collectors.toList());
                        
                        inner.put("sample_events", sampleEvents);
                    } else {
                        inner.put(Text.STATUS.toString(), Status.PASS);
                    }
                    inner.put(Text.RESULT.toString(), MAPPER.valueToTree(logGroup.toBuilder()));
                    return Map.<String, Object>of(logGroupName, inner);

                } catch (Exception e) {
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), Status.FAIL_EXCEPTION);
                    inner.put(Text.RESULT.toString(), Text.EXCEPTION.getText().concat(e.getMessage()));
                    return Map.<String, Object>of(logGroupName, inner);
                }
            })
            .collect(Collectors.toList());

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CLOUDTRAIL_LOG_GROUPS_WITH_SECRETS_IN_CLOUDWATCH_LOGS, result, status);
        return status;
    }
}
