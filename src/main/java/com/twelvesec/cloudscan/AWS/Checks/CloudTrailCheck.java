package com.twelvesec.cloudscan.AWS.Checks;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
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
import software.amazon.awssdk.services.cloudtrail.model.TrailInfo;

public class CloudTrailCheck implements CloudCheck {
    private List<TrailInfo> allTrails;
    private List<String> allS3BucketNames;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final CloudTrailAsyncClient cloudTrail;

    public CloudTrailCheck(DataWriter writer, SharedDataProvider sharedDataProvider, CloudTrailAsyncClient cloudTrail) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.cloudTrail = cloudTrail;
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
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkTrailWithNoInsightSelectors,   AWSFinding.CLOUDTRAIL_WITH_NO_INSIGHT_SELECTORS, this::reportError),
                    wrapCheck(this::checkRecentRootAccountUsage,        AWSFinding.CLOUDTRAIL_RECENT_ROOT_ACCOUNT_USAGE, this::reportError),
                    wrapCheck(this::checkS3ObjectLevelReadLogging,      AWSFinding.S3_OBJECT_LEVEL_READ_LOGGING, this::reportError),
                    wrapCheck(this::checkS3ObjectLevelWriteLogging,     AWSFinding.S3_OBJECT_LEVEL_WRITE_LOGGING, this::reportError)
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
}
