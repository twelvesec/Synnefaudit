package com.twelvesec.synnefaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.messages.Text;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public interface CloudCheck {

    enum Status {
        PASS,
        FAIL,
        FAIL_EXCEPTION,
        NOT_APPLICABLE
    }

    enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO,
        UNKNOWN
    }

    enum Provider {
        AWS
    }

    record CheckResult(
        AWSFinding title,
        Status status,
        String category
    ) {}

    record CheckSummary(
        String category,
        int passCount,
        int failCount,
        int exceptionCount,
        int napplicableCount,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        int infoCount
    ) {}
    
    record ErrorReport(
        AWSFinding finding, 
        String message, 
        Status status,
        String category
    ) {}

    ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    List<CheckResult> subCheckResults = new CopyOnWriteArrayList<>();

    default List<CheckResult> getResults() {
        return Collections.synchronizedList(new ArrayList<>());
    }
    
    CompletableFuture<Void> runAllChecksAsync();

    void reportError(CloudCheck.ErrorReport report);

    default CheckSummary summary() {
        String category = this.getClass().getSimpleName().replace("Check", "");
        
        List<CheckResult> filteredResults = subCheckResults.stream()
            .filter(checkresult -> category.equals(checkresult.category()))
            .toList();

        int pass = (int) filteredResults.stream()
                    .filter(r -> r.status() == Status.PASS)
                    .count();
        int fail = (int) filteredResults.stream()
                    .filter(r -> r.status() == Status.FAIL)
                    .count();
        int exc  = (int) filteredResults.stream()
                    .filter(r -> r.status() == Status.FAIL_EXCEPTION)
                    .count();
        int napp = (int) filteredResults.stream()
                    .filter(r -> r.status() == Status.NOT_APPLICABLE)
                    .count();

        Map<Severity, Long> bySev = filteredResults.stream()
            .filter(checkresult -> !Status.NOT_APPLICABLE.equals(checkresult.status()))
            .map(CheckResult::title)
            .map(findingEnum -> {
                CheckMetadata meta = MetadataLoader.get(findingEnum.name());
                return meta.toSeverityEnum();
            })
            .collect(Collectors.groupingBy(Function.identity(),
                                        () -> new EnumMap<>(Severity.class),
                                        Collectors.counting()));
        
        return new CheckSummary(
            category, 
            pass, 
            fail, 
            exc,
            napp,
            bySev.getOrDefault(Severity.CRITICAL, 0L).intValue(),
            bySev.getOrDefault(Severity.HIGH, 0L).intValue(),
            bySev.getOrDefault(Severity.MEDIUM, 0L).intValue(),
            bySev.getOrDefault(Severity.LOW, 0L).intValue(),
            bySev.getOrDefault(Severity.INFO, 0L).intValue()
        );
    }

    default Status getOverallStatus(List<?> data) {
        if (data.isEmpty()) {
            return Status.NOT_APPLICABLE;
        }
        
        return data.stream()
            .map(item -> {
                if (item instanceof ObjectNode on) {
                    return Status.valueOf(on.get(Text.STATUS.toString()).asText());
                } else if (item instanceof Map<?, ?> outerMap) {
                    Object outerValue = outerMap.values().iterator().next();
                    
                    if (outerValue instanceof Map<?, ?> innerMap) {
                        Object statusObj = innerMap.get(Text.STATUS.toString());
                        if (statusObj instanceof Status) {
                            return (Status) statusObj;
                        }
                    }
                    return Status.FAIL_EXCEPTION;
                } else {
                    return Status.FAIL_EXCEPTION;
                }
            })
            .reduce(Status.PASS, (overall, current) -> current == Status.FAIL_EXCEPTION
                ? Status.FAIL_EXCEPTION
                : (current == Status.FAIL
                    ? Status.FAIL
                    : overall));
    }

    default Supplier<CheckResult> wrapCheck(Supplier<Status> check, AWSFinding title, Consumer<ErrorReport> errorReporter) {
        return () -> {
            String category = this.getClass().getSimpleName().replace("Check", "");
            Status result;
            try {
                result = check.get();
            } catch (Exception e) {
                errorReporter.accept(
                    new ErrorReport(title, Text.EXCEPTION.toString().concat(e.getMessage()), Status.FAIL_EXCEPTION, category)
                );
                result = Status.FAIL_EXCEPTION;
            }
            return new CheckResult(title, result, category);
        };
    }

    default CompletableFuture<Void> runChecksInList(List<Supplier<CheckResult>> checksList, DataWriter writer) {
        List<CompletableFuture<CheckResult>> checkFutures = checksList.stream()
                .map(supplier ->
                        CompletableFuture.supplyAsync(supplier)
                                .handle((result, throwable) -> {
                                    if (throwable != null) {
                                        Throwable cause = throwable.getCause() != null ? throwable.getCause() : throwable;
                                        String msg = cause.getMessage() != null ? cause.getMessage() : cause.toString();

                                        System.err.printf("[ERROR] Check failed with exception: %s%n", msg);
                                        cause.printStackTrace();

                                        AWSFinding title = (result != null && result.title() != null)
                                                ? result.title()
                                                : AWSFinding.ERROR_WITH_FINDING;
                                        String category = this.getClass().getSimpleName().replace("Check", "");

                                        try {
                                            writer.addToBuffer(title, Text.EXCEPTION + msg, Status.FAIL_EXCEPTION);
                                        } catch (Exception e) {
                                            System.err.println("[ERROR] Failed to write exception to output file buffer: " + e.getMessage());
                                        }

                                        return new CheckResult(title, Status.FAIL_EXCEPTION, category);
                                    }
                                    return result;
                                })
                )
                .toList();

        return CompletableFuture
                .allOf(checkFutures.toArray(CompletableFuture[]::new))
                .thenAccept(_ -> {
                    subCheckResults.clear();
                    for (CompletableFuture<CheckResult> cf : checkFutures) {
                        try {
                            CheckResult res = cf.join();
                            if (res != null) {
                                subCheckResults.add(res);
                            }
                        } catch (Exception ignored) {
                            // Ensures an individual check failure never halts the pipeline
                        }
                    }
                });
    }

    default List<String> getStringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        return StreamSupport.stream(node.spliterator(), false)
                .map(JsonNode::asText)
                .toList();
    }

    default List<Integer> getIntList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        return StreamSupport.stream(node.spliterator(), false)
                .map(JsonNode::asInt)
                .toList();
    }

    default Map<String, String> getStringMap(JsonNode node) {
        if (node == null || !node.isObject()) {
            return Map.of();
        }
        Map<String, String> map = new HashMap<>();
        node.fields().forEachRemaining(entry ->
                map.put(entry.getKey(), entry.getValue().asText())
        );
        return Map.copyOf(map);
    }

    default Set<String> getLowercaseStringSet(JsonNode node) {
        if (node == null || !node.isArray()) {
            return Set.of();
        }
        return StreamSupport.stream(node.spliterator(), false)
                .map(JsonNode::asText)
                .map(String::toLowerCase)
                .collect(Collectors.toUnmodifiableSet());
    }
}
