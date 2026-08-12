package com.twelvesec.synnefaudit.AWS.Checks;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck;
import com.twelvesec.synnefaudit.DataWriter;
import com.twelvesec.synnefaudit.SharedDataProvider;
import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.services.codebuild.CodeBuildAsyncClient;
import software.amazon.awssdk.services.codebuild.model.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.regex.Pattern;

public class CodeBuildCheck implements CloudCheck {
    private List<Project> allProjects;
    private List<ReportGroup> allReportGroups;
    private final DataWriter writer;
    private final SharedDataProvider sharedDataProvider;
    private final CodeBuildAsyncClient codeBuild;

    public CodeBuildCheck(DataWriter writer, SharedDataProvider sharedDataProvider,
                          CodeBuildAsyncClient codeBuild) {
        this.writer = writer;
        this.sharedDataProvider = sharedDataProvider;
        this.codeBuild = codeBuild;
    }

    @Override
    public CompletableFuture<Void> runAllChecksAsync() {
        CompletableFuture<List<Project>> projectsFuture = sharedDataProvider.getAllCodeBuildProjects()
                .exceptionally(ex -> null);
        CompletableFuture<List<ReportGroup>> reportGroupsFuture = sharedDataProvider.getAllReportGroups()
                .exceptionally(ex -> null);
        return CompletableFuture.allOf(projectsFuture, reportGroupsFuture)
                .thenCompose(v -> {
                    this.allProjects = projectsFuture.join();
                    this.allReportGroups = reportGroupsFuture.join();

                    List<Supplier<CheckResult>> checksList = List.of(
                            wrapCheck(this::checkCodeBuildProjectsNotInvokedLast90Days,     AWSFinding.CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS, this::reportError),
                            wrapCheck(this::checkCodeBuildLoggingEnabled,                   AWSFinding.CODEBUILD_PROJECT_LOGGING_ENABLED, this::reportError),
                            wrapCheck(this::checkCodeBuildNoSecretsInPlaintextEnvVars,      AWSFinding.CODEBUILD_NO_SECRETS_IN_PLAINTEXT_ENV_VARS, this::reportError),
                            wrapCheck(this::checkCodeBuildProjectsNotPublic,                AWSFinding.CODEBUILD_PROJECTS_NOT_PUBLIC, this::reportError),
                            wrapCheck(this::checkCodeBuildS3LogsEncrypted,                  AWSFinding.CODEBUILD_S3_LOGS_ENCRYPTED, this::reportError),
                            wrapCheck(this::checkCodeBuildSourceRepoUrlsNoCredentials,      AWSFinding.CODEBUILD_SOURCE_REPO_URL_NO_CREDENTIALS, this::reportError),
                            wrapCheck(this::checkCodeBuildGithubConnectedToAllowedOrgs,     AWSFinding.CODEBUILD_GITHUB_ALLOWED_ORGS, this::reportError),
                            wrapCheck(this::checkCodeBuildReportGroupExportsEncrypted,      AWSFinding.CODEBUILD_REPORT_GROUP_EXPORTS_ENCRYPTED, this::reportError),
                            wrapCheck(this::checkCodeBuildProjectUsesControlledBuildspec,   AWSFinding.CODEBUILD_PROJECT_USES_CONTROLLED_BUILDSPEC, this::reportError)
                    );
                    return runChecksInList(checksList, writer);
                });
    }

    @Override
    public void reportError(CloudCheck.ErrorReport report) {
        writer.addToBuffer(report.finding(), report.message(), report.status());
    }

    private List<String> getAllowedGithubOrganizations() {
        return new ArrayList<>(); // TODO
    }

    private Status checkCodeBuildProjectsNotInvokedLast90Days() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        Instant cutoff = Instant.now().minus(Duration.ofDays(90));
        List<Map<String, Object>> results = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    Status s;
                    ObjectNode r;

                    try {
                        ListBuildsForProjectResponse buildsResp = codeBuild.listBuildsForProject(
                                ListBuildsForProjectRequest.builder()
                                        .projectName(name)
                                        .sortOrder(SortOrderType.DESCENDING)
                                        .build()
                        ).join();

                        Optional<String> latestId = buildsResp.ids().stream().findFirst();
                        if (latestId.isEmpty()) {
                            s = Status.FAIL;
                            r = MAPPER.createObjectNode()
                                    .put(Text.ERROR.getText(), Text.NO_BUILDS_FOUND.getText());
                        } else {
                            BatchGetBuildsResponse batch = codeBuild.batchGetBuilds(
                                    BatchGetBuildsRequest.builder().ids(latestId.get()).build()
                            ).join();
                            Build b = batch.builds().getFirst();
                            s = b.endTime().isBefore(cutoff) ? Status.FAIL : Status.PASS;
                            r = MAPPER.valueToTree(b.toBuilder());
                        }
                    } catch (Exception e) {
                        s = Status.FAIL_EXCEPTION;
                        r = MAPPER.createObjectNode()
                                .put(Text.ERROR.getText(), Text.EXCEPTION.getText().concat(e.getMessage()));
                    }
                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(results);
        writer.addToBuffer(AWSFinding.CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS, results, status);
        return status;
    }

    private Status checkCodeBuildLoggingEnabled() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_PROJECT_LOGGING_ENABLED,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    LogsConfig logsConfig = project.logsConfig();

                    boolean cwEnabled = logsConfig != null && logsConfig.cloudWatchLogs() != null
                            && "ENABLED".equalsIgnoreCase(logsConfig.cloudWatchLogs().statusAsString());
                    boolean s3Enabled = logsConfig != null && logsConfig.s3Logs() != null
                            && "ENABLED".equalsIgnoreCase(logsConfig.s3Logs().statusAsString());

                    boolean isLoggingEnabled = cwEnabled || s3Enabled;
                    Status s = isLoggingEnabled ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_PROJECT_LOGGING_ENABLED, result, status);
        return status;
    }

    private Status checkCodeBuildNoSecretsInPlaintextEnvVars() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_NO_SECRETS_IN_PLAINTEXT_ENV_VARS,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }
        List<String> sensitiveKeywords = List.of("AWS_SECRET_ACCESS_KEY", "PASSWORD", "SECRET", "TOKEN", "API_KEY", "ACCESS_KEY");

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    List<EnvironmentVariable> envVars = project.environment() != null ? project.environment().environmentVariables() : List.of();

                    List<String> suspiciousVars = envVars.stream()
                            .filter(env -> env.type() == EnvironmentVariableType.PLAINTEXT || env.typeAsString() == null)
                            .map(EnvironmentVariable::name)
                            .filter(varName -> varName != null && sensitiveKeywords.stream().anyMatch(k -> varName.toUpperCase().contains(k)))
                            .toList();

                    Status s = suspiciousVars.isEmpty() ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);
                    r.put("SuspiciousPlaintextVars", suspiciousVars.toString());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_NO_SECRETS_IN_PLAINTEXT_ENV_VARS, result, status);
        return status;
    }

    private Status checkCodeBuildProjectsNotPublic() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_PROJECTS_NOT_PUBLIC,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    boolean isPublic = project.projectVisibility() == ProjectVisibilityType.PUBLIC_READ;
                    Status s = !isPublic ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_PROJECTS_NOT_PUBLIC, result, status);
        return status;
    }

    private Status checkCodeBuildS3LogsEncrypted() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_S3_LOGS_ENCRYPTED,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    LogsConfig logsConfig = project.logsConfig();
                    S3LogsConfig s3Logs = logsConfig != null ? logsConfig.s3Logs() : null;

                    boolean s3LoggingEnabled = s3Logs != null && "ENABLED".equalsIgnoreCase(s3Logs.statusAsString());
                    boolean encryptionDisabled = s3Logs != null && Boolean.TRUE.equals(s3Logs.encryptionDisabled());
                    boolean isCompliant = !s3LoggingEnabled || !encryptionDisabled;

                    Status s = isCompliant ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_S3_LOGS_ENCRYPTED, result, status);
        return status;
    }

    private Status checkCodeBuildSourceRepoUrlsNoCredentials() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_SOURCE_REPO_URL_NO_CREDENTIALS,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        // Pattern matching inline credentials in URLs (e.g. https://user:pass@github.com/org/repo.git)
        Pattern urlCredentialsPattern = Pattern.compile("https?://[^:]+:[^@]+@");

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    List<ProjectSource> sources = new ArrayList<>();
                    if (project.source() != null) sources.add(project.source());
                    if (project.secondarySources() != null) sources.addAll(project.secondarySources());

                    List<String> suspiciousLocations = sources.stream()
                            .map(ProjectSource::location)
                            .filter(loc -> loc != null && urlCredentialsPattern.matcher(loc).find())
                            .toList();

                    boolean hasCredentialsInUrl = !suspiciousLocations.isEmpty();
                    Status s = !hasCredentialsInUrl ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_SOURCE_REPO_URL_NO_CREDENTIALS, result, status);
        return status;
    }

    private Status checkCodeBuildGithubConnectedToAllowedOrgs() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_GITHUB_ALLOWED_ORGS,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }
        List<String> allowedOrgs = getAllowedGithubOrganizations();

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    String name = project.name();
                    List<ProjectSource> sources = new ArrayList<>();
                    if (project.source() != null) sources.add(project.source());
                    if (project.secondarySources() != null) sources.addAll(project.secondarySources());

                    List<String> unapprovedSources = sources.stream()
                            .filter(src -> src.type() == SourceType.GITHUB || src.type() == SourceType.GITHUB_ENTERPRISE)
                            .map(ProjectSource::location)
                            .filter(loc -> loc != null && !isGithubLocationAllowed(loc, allowedOrgs))
                            .toList();

                    boolean hasUnapprovedSource = !unapprovedSources.isEmpty();
                    Status s = !hasUnapprovedSource ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);
                    r.put("AllowedOrgsConfigured", allowedOrgs.toString());
                    r.put("UnapprovedSources", unapprovedSources.toString());

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.toString(), s);
                    inner.put(Text.RESULT.toString(), r);
                    return Map.<String, Object>of(name, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_GITHUB_ALLOWED_ORGS, result, status);
        return status;
    }

    private boolean isGithubLocationAllowed(String location, List<String> allowedOrgs) {
        if (allowedOrgs == null || allowedOrgs.isEmpty()) {
            return false;
        }
        String lowerLoc = location.toLowerCase();
        for (String org : allowedOrgs) {
            String targetOrgPath = "github.com/" + org.toLowerCase() + "/";
            if (lowerLoc.contains(targetOrgPath)) {
                return true;
            }
        }
        return false;
    }

    private Status checkCodeBuildReportGroupExportsEncrypted() {
        if (allReportGroups.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_REPORT_GROUP_EXPORTS_ENCRYPTED,
                    Text.NO_CODEBUILD_REPORT_GROUPS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allReportGroups.stream()
                .map(rg -> {
                    String arn = rg.arn();
                    ReportExportConfig exportConfig = rg.exportConfig();

                    boolean isS3Export = exportConfig != null
                            && exportConfig.exportConfigType() == ReportExportConfigType.S3;
                    boolean encryptionDisabled = isS3Export && exportConfig.s3Destination() != null
                            && Boolean.TRUE.equals(exportConfig.s3Destination().encryptionDisabled());
                    boolean isEncrypted = !isS3Export || !encryptionDisabled;

                    Status s = isEncrypted ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(rg);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(arn, inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_REPORT_GROUP_EXPORTS_ENCRYPTED, result, status);
        return status;
    }

    private Status checkCodeBuildProjectUsesControlledBuildspec() {
        if (allProjects.isEmpty()) {
            writer.addToBuffer(AWSFinding.CODEBUILD_PROJECT_USES_CONTROLLED_BUILDSPEC,
                    Text.NO_CODEBUILD_PROJECTS_FOUND.getText(), Status.NOT_APPLICABLE);
            return Status.NOT_APPLICABLE;
        }

        List<Map<String, Object>> result = allProjects.stream()
                .map(project -> {
                    ProjectSource source = project.source();
                    String buildspec = source != null ? source.buildspec() : null;
                    boolean isInlineBuildspec = buildspec != null && (buildspec.contains("\n") || buildspec.startsWith("version:"));
                    boolean isControlled = !isInlineBuildspec;

                    Status s = isControlled ? Status.PASS : Status.FAIL;
                    ObjectNode r = MAPPER.valueToTree(project);

                    Map<String, Object> inner = new HashMap<>();
                    inner.put(Text.STATUS.getText(), s);
                    inner.put(Text.RESULT.getText(), r);
                    return Map.<String, Object>of(project.name(), inner);
                })
                .toList();

        Status status = getOverallStatus(result);
        writer.addToBuffer(AWSFinding.CODEBUILD_PROJECT_USES_CONTROLLED_BUILDSPEC, result, status);
        return status;
    }
}
