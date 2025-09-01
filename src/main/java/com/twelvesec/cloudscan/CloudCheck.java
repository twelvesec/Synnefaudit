package com.twelvesec.cloudscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public interface CloudCheck {

    public enum Status {
        PASS,
        FAIL,
        FAIL_EXCEPTION,
        NOT_APPLICABLE
    }

    public enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO,
        UNKNOWN
    }

    public record CheckResult(
        AWSFinding title,
        Status status,
        String category
    ) {}

    public record CheckSummary(
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

    public static final ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    
    public final List<CheckResult> subCheckResults = new ArrayList<>();

    default List<CheckResult> getResults() {
        return Collections.synchronizedList(new ArrayList<>());
    }
    
    public CompletableFuture<Void> runAllChecksAsync();

    public void reportError(CloudCheck.ErrorReport report);

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
            .map(AWSFinding::getSeverity)
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

    default Status getOverallStatus(List<Map<String,Object>> data) {
        return data.stream()
            .flatMap(bucketMap -> bucketMap.values().stream())
            .map(inner -> {
                if (inner instanceof ObjectNode on) {
                    return Status.valueOf(on.get(Text.STATUS.toString()).asText());
                } else if (inner instanceof Map<?,?> m) {
                    return (Status) m.get(Text.STATUS.toString());
                } else {
                    return Status.FAIL_EXCEPTION;
                }
            })
            .anyMatch(s -> s == Status.FAIL || s == Status.FAIL_EXCEPTION) ? Status.FAIL : Status.PASS;
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

    default CompletableFuture<Void> runChecksInList(List<Supplier<CheckResult>> checksList, DataWriter writer){
        List<CompletableFuture<CheckResult>> checkFutures = checksList.stream()
            .map(supplier ->
                CompletableFuture.supplyAsync(supplier::get)
                .handle((result, throwable) -> {
                    if (throwable != null) {
                        AWSFinding title = (result != null ? result.title() : AWSFinding.ERROR_WITH_FINDING);
                        writer.addToBuffer(title, Text.EXCEPTION + throwable.getCause().getMessage(), Status.FAIL_EXCEPTION);
                        return new CheckResult(
                            title,
                            Status.FAIL_EXCEPTION,
                            result != null ? result.category() : this.getClass().getSimpleName()
                        );
                    }
                    return result;
                })
            )
            .toList();
        return CompletableFuture
            .allOf(checkFutures.toArray(CompletableFuture[]::new))
            .thenAccept(__ -> {
                subCheckResults.clear();
                checkFutures.forEach(cf -> subCheckResults.add(cf.join()));
            });
    }
}
