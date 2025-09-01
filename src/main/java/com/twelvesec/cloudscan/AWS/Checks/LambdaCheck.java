package com.twelvesec.cloudscan.AWS.Checks;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.cloudscan.CloudCheck;
import com.twelvesec.cloudscan.DataWriter;
import com.twelvesec.cloudscan.SharedDataProvider;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.messages.Text;

import software.amazon.awssdk.services.lambda.model.GetFunctionRequest;
import software.amazon.awssdk.services.lambda.model.GetFunctionResponse;
import software.amazon.awssdk.services.lambda.LambdaAsyncClient;
import software.amazon.awssdk.services.lambda.model.EnvironmentResponse;

public class LambdaCheck implements CloudCheck {
    private List<String> AllLambdaFunctionNames;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final LambdaAsyncClient lambda;

    public LambdaCheck(DataWriter writer, SharedDataProvider sharedDataProvider, LambdaAsyncClient lambda) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.lambda = lambda;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        return sharedDataProvider.getAllLambdaFunctionNames()
            .thenCompose(lambdaFunctionNames -> {
                this.AllLambdaFunctionNames = lambdaFunctionNames;
                List<Supplier<CheckResult>> checksList = List.of(
                    wrapCheck(this::checkLambdaFunctionSecrets, AWSFinding.LAMBDA_FUNCTIONS_WITH_POTENTIAL_SECRETS, this::reportError)
                );
                return runChecksInList(checksList, writer);
            });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }
    
    private Status checkLambdaFunctionSecrets() {
        if (AllLambdaFunctionNames.isEmpty()) {
            writer.addToBuffer(AWSFinding.LAMBDA_FUNCTIONS_WITH_POTENTIAL_SECRETS,
                            Text.NO_LAMBDA_FUNCTIONS_FOUND.toString(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> results = AllLambdaFunctionNames.stream()
            .map(functionName -> {
                Status status = Status.PASS;
                ObjectNode resultNode = MAPPER.createObjectNode();
                
                try {
                    GetFunctionResponse response = lambda.getFunction(
                        GetFunctionRequest.builder().functionName(functionName).build()
                    ).join();
                    EnvironmentResponse env = response.configuration().environment();
                    resultNode = MAPPER.valueToTree(response.toBuilder());

                    if (env != null && env.variables() != null && !env.variables().isEmpty()) {                        
                        boolean hasSecrets = env.variables().entrySet().stream()
                            .anyMatch(entry -> isPotentialSecret(entry.getKey(), entry.getValue()));
                        status = hasSecrets ? Status.FAIL : Status.PASS;
                    }
                } catch (Exception e) {
                    status = Status.FAIL_EXCEPTION;
                    resultNode.put(Text.ERROR.toString(), Text.EXCEPTION.toString().concat(e.getMessage()));
                }
                ObjectNode inner = MAPPER.createObjectNode();
                inner.put(Text.STATUS.toString(), status.toString());
                inner.set(Text.RESULT.toString(), resultNode);
                return Map.<String, Object>of(functionName, inner);
            })
            .toList();
        
        Status status = getOverallStatus(results);
        writer.addToBuffer(AWSFinding.LAMBDA_FUNCTIONS_WITH_POTENTIAL_SECRETS, results, status);
        return status;
    }

    private boolean isPotentialSecret(String key, String value) {
        String lowerKey = key.toLowerCase();
        return lowerKey.contains("secret") 
            || lowerKey.contains("password") 
            || lowerKey.contains("key")
            || lowerKey.contains("token")
            || value.length() > 32;
    }
}
