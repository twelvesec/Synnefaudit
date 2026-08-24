package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.eventbridge.model.Endpoint;
import software.amazon.awssdk.services.eventbridge.model.EventBus;
import software.amazon.awssdk.services.eventbridge.model.ReplicationState;
import software.amazon.awssdk.services.schemas.SchemasAsyncClient;
import software.amazon.awssdk.services.schemas.model.*;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class EventBridgeCheck implements CloudCheck {

    private List<EventBus> allEventBuses;
    private List<Endpoint> allEndpoints;
    private List<RegistrySummary> allRegistries;

    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final SchemasAsyncClient schemas;
    private final StsAsyncClient sts;

    public EventBridgeCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                            SchemasAsyncClient schemas, StsAsyncClient sts) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.schemas = schemas;
        this.sts = sts;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<EventBus>> busesFuture = sharedDataProvider.getAllEventBuses()
                .exceptionally(ex -> List.of());
        CompletableFuture<List<Endpoint>> endpointsFuture = sharedDataProvider.getAllEventBridgeEndpoints()
                .exceptionally(ex -> List.of());
        CompletableFuture<List<RegistrySummary>> registriesFuture = sharedDataProvider.getAllSchemaRegistries()
                .exceptionally(ex -> List.of());

        return CompletableFuture.allOf(busesFuture, endpointsFuture, registriesFuture)
                .thenCompose(_ -> {
                    this.allEventBuses = busesFuture.join();
                    this.allEndpoints = endpointsFuture.join();
                    this.allRegistries = registriesFuture.join();

                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkEventBusCrossAccountAccess,        AWSFinding.EVENTBRIDGE_BUS_CROSS_ACCOUNT_ACCESS, this::reportError),
                            wrapCheck(this::checkEventBusPublicAccess,              AWSFinding.EVENTBRIDGE_BUS_PUBLIC_ACCESS, this::reportError),
                            wrapCheck(this::checkGlobalEndpointReplicationEnabled,  AWSFinding.EVENTBRIDGE_GLOBAL_ENDPOINT_REPLICATION_ENABLED, this::reportError),
                            wrapCheck(this::checkSchemaRegistryCrossAccountAccess,  AWSFinding.EVENTBRIDGE_SCHEMA_REGISTRY_CROSS_ACCOUNT_ACCESS, this::reportError)
                    );

                    return runChecksInList(checksList, writer);
                });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private String getAccountId() {
        return sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).join().account();
    }

    private Status checkEventBusCrossAccountAccess() {
        if (allEventBuses == null || allEventBuses.isEmpty()) {
            writer.addToBuffer(AWSFinding.EVENTBRIDGE_BUS_CROSS_ACCOUNT_ACCESS,
                    Text.NO_EVENT_BUSSES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        String currentAccountId = getAccountId();
        List<Map<String, Object>> result = allEventBuses.stream()
                .map(bus -> {
                    Status s = Status.PASS;
                    ObjectNode r = MAPPER.valueToTree(bus.toBuilder());

                    String policy = bus.policy();
                    if (policy != null && !policy.isBlank() && isCrossAccountPolicy(policy, currentAccountId)) {
                        s = Status.FAIL;
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(bus.name(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EVENTBRIDGE_BUS_CROSS_ACCOUNT_ACCESS, result, status);
        return status;
    }

    private Status checkEventBusPublicAccess() {
        if (allEventBuses == null || allEventBuses.isEmpty()) {
            writer.addToBuffer(AWSFinding.EVENTBRIDGE_BUS_PUBLIC_ACCESS,
                    Text.NO_EVENT_BUSSES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEventBuses.stream()
                .map(bus -> {
                    Status s = Status.PASS;
                    ObjectNode r = MAPPER.valueToTree(bus.toBuilder());

                    String policy = bus.policy();
                    if (policy != null && !policy.isBlank() && isPublicPolicy(policy)) {
                        s = Status.FAIL;
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(bus.name(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EVENTBRIDGE_BUS_PUBLIC_ACCESS, result, status);
        return status;
    }

    private Status checkGlobalEndpointReplicationEnabled() {
        if (allEndpoints == null || allEndpoints.isEmpty()) {
            writer.addToBuffer(AWSFinding.EVENTBRIDGE_GLOBAL_ENDPOINT_REPLICATION_ENABLED,
                    Text.NO_EVENT_BUSSES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allEndpoints.stream()
                .map(endpoint -> {
                    ObjectNode r = MAPPER.valueToTree(endpoint.toBuilder());
                    boolean isReplicationEnabled = endpoint.replicationConfig() != null
                            && ReplicationState.ENABLED.equals(endpoint.replicationConfig().state());

                    Status s = isReplicationEnabled ? Status.PASS : Status.FAIL;

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(endpoint.name(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EVENTBRIDGE_GLOBAL_ENDPOINT_REPLICATION_ENABLED, result, status);
        return status;
    }

    private Status checkSchemaRegistryCrossAccountAccess() {
        if (allRegistries == null || allRegistries.isEmpty()) {
            writer.addToBuffer(AWSFinding.EVENTBRIDGE_SCHEMA_REGISTRY_CROSS_ACCOUNT_ACCESS,
                    Text.NO_EVENT_BUSSES_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        String currentAccountId = getAccountId();
        List<Map<String, Object>> result = allRegistries.stream()
                .map(registry -> {
                    Status s = Status.PASS;
                    ObjectNode r = MAPPER.valueToTree(registry.toBuilder());

                    try {
                        GetResourcePolicyResponse policyResp = schemas.getResourcePolicy(
                                GetResourcePolicyRequest.builder().registryName(registry.registryName()).build()
                        ).join();

                        String policy = policyResp.policy();
                        if (policy != null && isCrossAccountPolicy(policy, currentAccountId)) {
                            s = Status.FAIL;
                        }
                    } catch (NotFoundException e) {
                        s = Status.PASS;
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                    }

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(registry.registryName(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.EVENTBRIDGE_SCHEMA_REGISTRY_CROSS_ACCOUNT_ACCESS, result, status);
        return status;
    }

    private boolean isCrossAccountPolicy(String policyJson, String currentAccountId) {
        try {
            JsonNode root = MAPPER.readTree(policyJson);
            JsonNode statements = root.path("Statement");

            if (statements.isArray()) {
                for (JsonNode stmt : statements) {
                    if ("Allow".equalsIgnoreCase(stmt.path("Effect").asText())) {
                        JsonNode principal = stmt.path("Principal");
                        if (hasCrossAccountPrincipal(principal, currentAccountId)) {
                            return true;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean isPublicPolicy(String policyJson) {
        try {
            JsonNode root = MAPPER.readTree(policyJson);
            JsonNode statements = root.path("Statement");

            if (statements.isArray()) {
                for (JsonNode stmt : statements) {
                    if ("Allow".equalsIgnoreCase(stmt.path("Effect").asText())) {
                        JsonNode principal = stmt.path("Principal");
                        if ("*".equals(principal.asText()) || "*".equals(principal.path("AWS").asText())) {
                            return true;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean hasCrossAccountPrincipal(JsonNode principal, String currentAccountId) {
        if (principal.isTextual()) {
            return isExternalAccount(principal.asText(), currentAccountId);
        }
        if (principal.isObject()) {
            JsonNode awsNode = principal.path("AWS");
            if (awsNode.isTextual() && isExternalAccount(awsNode.asText(), currentAccountId)) {
                return true;
            }
            if (awsNode.isArray()) {
                for (JsonNode item : awsNode) {
                    if (isExternalAccount(item.asText(), currentAccountId)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean isExternalAccount(String principalStr, String currentAccountId) {
        if ("*".equals(principalStr)) {
            return true;
        }
        if (principalStr.contains(":iam::")) {
            String accountInArn = principalStr.split(":")[4];
            return !accountInArn.equals(currentAccountId);
        }
        if (principalStr.matches("\\d{12}")) {
            return !principalStr.equals(currentAccountId);
        }
        return false;
    }
}