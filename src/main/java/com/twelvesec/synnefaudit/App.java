package com.twelvesec.synnefaudit;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.twelvesec.synnefaudit.AWS.Checks.*;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.twelvesec.synnefaudit.AWS.AWSDependencyFactory;
import com.twelvesec.synnefaudit.CloudCheck.CheckSummary;
import com.twelvesec.synnefaudit.CloudCheck.Provider;
import com.twelvesec.synnefaudit.messages.Text;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.accessanalyzer.AccessAnalyzerAsyncClient;
import software.amazon.awssdk.services.account.AccountAsyncClient;
import software.amazon.awssdk.services.acm.AcmAsyncClient;
import software.amazon.awssdk.services.applicationautoscaling.ApplicationAutoScalingAsyncClient;
import software.amazon.awssdk.services.athena.AthenaAsyncClient;
import software.amazon.awssdk.services.autoscaling.AutoScalingAsyncClient;
import software.amazon.awssdk.services.backup.BackupAsyncClient;
import software.amazon.awssdk.services.cloudformation.CloudFormationAsyncClient;
import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;
import software.amazon.awssdk.services.cloudtrail.CloudTrailAsyncClient;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.codebuild.CodeBuildAsyncClient;
import software.amazon.awssdk.services.dax.DaxAsyncClient;
import software.amazon.awssdk.services.drs.DrsAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ecr.EcrAsyncClient;
import software.amazon.awssdk.services.efs.EfsAsyncClient;
import software.amazon.awssdk.services.elasticache.ElastiCacheAsyncClient;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2AsyncClient;
import software.amazon.awssdk.services.eventbridge.EventBridgeAsyncClient;
import software.amazon.awssdk.services.glue.GlueAsyncClient;
import software.amazon.awssdk.services.guardduty.GuardDutyAsyncClient;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.inspector2.Inspector2AsyncClient;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;
import software.amazon.awssdk.services.kafkaconnect.KafkaConnectAsyncClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.lambda.LambdaAsyncClient;
import software.amazon.awssdk.services.macie2.Macie2AsyncClient;
import software.amazon.awssdk.services.neptune.NeptuneAsyncClient;
import software.amazon.awssdk.services.networkfirewall.NetworkFirewallAsyncClient;
import software.amazon.awssdk.services.organizations.OrganizationsAsyncClient;
import software.amazon.awssdk.services.rds.RdsAsyncClient;
import software.amazon.awssdk.services.resourceexplorer2.ResourceExplorer2AsyncClient;
import software.amazon.awssdk.services.route53.Route53AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3control.S3ControlAsyncClient;
import software.amazon.awssdk.services.schemas.SchemasAsyncClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.securityhub.SecurityHubAsyncClient;
import software.amazon.awssdk.services.sns.SnsAsyncClient;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssmincidents.SsmIncidentsAsyncClient;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.support.SupportAsyncClient;
import software.amazon.awssdk.services.wafv2.Wafv2AsyncClient;

public class App {
    private static Provider PROVIDER;
    private static Region region;
    private static String profileInput;
    private static Path outfilePath;
    private static boolean useEnv;

    private static String outputFormat = "all";
    private static String fromJsonPath = null;

    private static AWSDependencyFactory awsDependencyFactory;

    private static IamAsyncClient iam;
    private static CloudFrontAsyncClient cf;
    private static Wafv2AsyncClient waf;
    private static DaxAsyncClient dax;
    private static DynamoDbAsyncClient dynamodb;
    private static Ec2AsyncClient ec2;
    private static SsmAsyncClient ssm;
    private static SsmIncidentsAsyncClient ssm_inc;
    private static EcrAsyncClient ecr;
    private static ElasticLoadBalancingV2AsyncClient elb;
    private static ElastiCacheAsyncClient elasticache;
    private static DrsAsyncClient drs;
    private static SecretsManagerAsyncClient secretsmanager;
    private static Inspector2AsyncClient inspector2;
    private static StsAsyncClient sts;
    private static Macie2AsyncClient macie2;
    private static CloudWatchAsyncClient cloudWatch;
    private static SupportAsyncClient support;
    private static CloudWatchLogsAsyncClient cloudWatchLogs;
    private static KmsAsyncClient kms;
    private static Route53AsyncClient route53;
    private static AccountAsyncClient accountClient;
    private static BackupAsyncClient backup;
    private static SecurityHubAsyncClient securityHub;
    private static CloudTrailAsyncClient cloudTrail;
    private static EfsAsyncClient efs;
    private static GuardDutyAsyncClient guardduty;
    private static AccessAnalyzerAsyncClient accessAnalyzer;
    private static KafkaAsyncClient kafka;
    private static KafkaConnectAsyncClient kafkaconnect;
    private static NeptuneAsyncClient neptune;
    private static RdsAsyncClient rds;
    private static S3AsyncClient s3;
    private static S3ControlAsyncClient s3control;
    private static SnsAsyncClient sns;
    private static NetworkFirewallAsyncClient networkFirewall;
    private static AthenaAsyncClient athena;
    private static ResourceExplorer2AsyncClient resourceexplorer2;
    private static CodeBuildAsyncClient codeBuild;
    private static CloudFormationAsyncClient cloudformation;
    private static GlueAsyncClient glue;
    private static LambdaAsyncClient lambda;
    private static OrganizationsAsyncClient orgs;
    private static AcmAsyncClient acm;
    private static ApplicationAutoScalingAsyncClient appAutoScaling;
    private static AutoScalingAsyncClient autoscaling;
    private static EventBridgeAsyncClient eventBridge;
    private static SchemasAsyncClient schemas;

    private static DataWriter writer;
    private static ReportPrinter printer;
    private static SharedDataProvider sharedDataProvider;
    private static JsonNode config;

    private static final String CONFIG_FILE_PATH = "config.yaml";

    private static ExecutorService executor;

    private static int exitCode = 0;

    static void main(String[] args) {
        Instant start = Instant.now();
        printer = new ReportPrinter();
        PROVIDER = Provider.AWS;

        retrieveUserParameters(args);
        config = AuditConfig.load(CONFIG_FILE_PATH);

        printer.printLogo();

        if (fromJsonPath != null) {
            System.out.println("Executing local standalone translation from historical source payload: " + fromJsonPath);
            Path inputSource = Paths.get(fromJsonPath);
            Path outputDestinationHtml;

            if (outfilePath != null) {
                outputDestinationHtml = outfilePath.resolve(
                        inputSource.getFileName().toString().replace(".json", "") + "-compiled.html"
                );
            } else {
                outputDestinationHtml = inputSource.resolveSibling(
                        inputSource.getFileName().toString().replace(".json", "") + "-compiled.html"
                );
            }
            HtmlReportGenerator.generate(inputSource, outputDestinationHtml);
            System.exit(0);
        }

        writer = new DataWriter(outfilePath);
        setAWSClients();
        executor = Executors.newVirtualThreadPerTaskExecutor();

        try {
            sharedDataProvider = new SharedDataProvider(
                    accessAnalyzer, acm, autoscaling, athena, backup, cloudformation, cf, cloudTrail, cloudWatch, cloudWatchLogs, codeBuild, dax, dynamodb, ec2, ecr, efs, elasticache,
                    elb, eventBridge, secretsmanager, guardduty, iam, kafka, kms, lambda, neptune, schemas, rds, route53, resourceexplorer2, s3, sns, ssm, sts, support);

            List<CloudCheck> checks = getAWSChecks();
            printer.printSectionHeader(ReportPrinter.CHECKS_SUMMARY);

            List<CompletableFuture<CheckSummary>> futures = checks.stream()
                    .map(check -> check.runAllChecksAsync()
                            .thenApply(_ -> {
                                CheckSummary summary = check.summary();
                                synchronized (System.out) {
                                    printer.printIndividualStatus(summary);
                                }
                                return summary;
                            }))
                    .toList();

            CompletableFuture<Void> allChecks = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .thenAccept(_ -> {
                        List<CheckSummary> summaries = futures.stream()
                                .map(CompletableFuture::join)
                                .collect(Collectors.toList());
                        writer.flush();
                        printer.printOverallStatus(summaries);
                    });

            allChecks.join();

            if ("html".equalsIgnoreCase(outputFormat) || "all".equalsIgnoreCase(outputFormat)) {
                Path generatedJson = writer.getOutputFilePath();
                Path targetHtml = generatedJson.resolveSibling(
                        generatedJson.getFileName().toString().replace(".json", ".html")
                );
                HtmlReportGenerator.generate(generatedJson, targetHtml);

                if ("html".equalsIgnoreCase(outputFormat)) {
                    try {
                        Files.deleteIfExists(generatedJson);
                        Files.deleteIfExists(generatedJson.resolveSibling(generatedJson.getFileName().toString().replace(".json", "-summary.json")));
                    } catch (IOException ignored) {}
                }
            }

            exitCode = 0;
        } catch (Exception e) {
            System.err.println(Text.EXCEPTION.toString() + e.getMessage());
            e.printStackTrace(System.err);
            exitCode = 1;
        } finally {
            executor.shutdown();
            if (awsDependencyFactory != null) {
                awsDependencyFactory.closeAllClients();
            }
            Instant end = Instant.now();
            Duration elapsed = Duration.between(start, end);
            printer.printRuntime(elapsed);
            System.exit(exitCode);
        }
    }

    public static Provider getProvider() {
        return PROVIDER;
    }

    private static void retrieveUserParameters(String[] args) {
        Options options = new Options();
        options.addOption(Option.builder("h").longOpt("help").desc("Show this help message").build());
        options.addOption(Option.builder().longOpt("region").hasArg().argName("REGION").desc("AWS region").build());
        options.addOption(Option.builder().longOpt("outdir").hasArg().argName("OUTDIR").desc("Output directory path").build());
        options.addOption(Option.builder().longOpt("profile").hasArg().argName("PROFILE").desc("AWS CLI profile name").build());
        options.addOption(Option.builder().longOpt("env").desc("Use AWS credentials from environment variables").build());
        options.addOption(Option.builder().longOpt("format").hasArg().argName("FORMAT").desc("Output formats: json | html | all (default)").build());
        options.addOption(Option.builder().longOpt("from-json").hasArg().argName("JSON_PATH").desc("Compile HTML directly from a previously generated JSON file").build());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printGroupedHelp();
            System.exit(1);
            return;
        }

        if (cmd.hasOption("help")) {
            printGroupedHelp();
            System.exit(0);
        }

        if (cmd.hasOption("format")) {
            outputFormat = cmd.getOptionValue("format").toLowerCase();
        }

        if (cmd.hasOption("from-json")) {
            fromJsonPath = cmd.getOptionValue("from-json");
            String outdirInput = cmd.getOptionValue("outdir");
            if (outdirInput != null) {
                try {
                    Path dirPath = Paths.get(outdirInput);
                    if (!Files.exists(dirPath) || !Files.isDirectory(dirPath)) {
                        System.err.println("Error: The path specified in --outdir does not exist or is not a directory.");
                        System.exit(4);
                    }
                    outfilePath = dirPath;
                } catch (InvalidPathException ipe) {
                    System.err.println("Error: The path specified in --outdir is structurally invalid.");
                    System.exit(5);
                }
            }
            return;
        }

        String regionInput = cmd.getOptionValue("region");
        String outdirInput = cmd.getOptionValue("outdir");
        profileInput = cmd.getOptionValue("profile");
        useEnv = cmd.hasOption("env");

        if (regionInput == null || outdirInput == null) {
            System.err.println("Error: Live security scans require BOTH --region and --outdir specifications.");
            printGroupedHelp();
            System.exit(1);
        }

        if ((profileInput == null && !useEnv) || (profileInput != null && useEnv)) {
            System.err.println("Error: You must specify exactly ONE authentication method: --profile OR --env.");
            printGroupedHelp();
            System.exit(2);
        }

        try {
            region = Region.of(regionInput);
        } catch (IllegalArgumentException iae) {
            System.err.println("Error: Please provide a valid AWS region (e.g., us-east-1).");
            System.exit(3);
        }

        try {
            Path dirPath = Paths.get(outdirInput);
            if (!Files.exists(dirPath) || !Files.isDirectory(dirPath)) {
                System.err.println("Error: The path specified in --outdir does not exist or is not a directory.");
                System.exit(4);
            }
            outfilePath = dirPath;
        } catch (InvalidPathException ipe) {
            System.err.println("Error: The path specified in --outdir is structurally invalid.");
            System.exit(5);
        }
    }

    private static void printGroupedHelp() {
        HelpFormatter formatter = new HelpFormatter();
        PrintWriter pw = new PrintWriter(System.out);

        formatter.printUsage(pw, 100, "synnefaudit [options]");
        pw.println();
        pw.println("=================================================================================");
        pw.println(" SYNNEFAUDIT SECURITY DASHBOARD CLI ");
        pw.println("=================================================================================");
        pw.println("This program executes live AWS architecture scans or builds HTML reports locally.");
        pw.println();

        pw.println("GLOBAL OPTIONS (Optional):");
        Options generalOpts = new Options();
        generalOpts.addOption(Option.builder("h").longOpt("help").desc("Show this grouped help menu context.").build());
        generalOpts.addOption(Option.builder().longOpt("format").hasArg().argName("FORMAT").desc("Output strategy variations: json | html | all (default value)").build());
        formatter.printOptions(pw, 100, generalOpts, 2, 4);
        pw.println();

        pw.println("LIVE SCAN MODE OPTIONS (Requires target destination properties):");
        Options liveCoreOpts = new Options();
        liveCoreOpts.addOption(Option.builder().longOpt("region").hasArg().argName("REGION").desc("Target cloud scope deployment geography").build());
        liveCoreOpts.addOption(Option.builder().longOpt("outdir").hasArg().argName("OUTDIR").desc("Target path where audit assets drop").build());
        formatter.printOptions(pw, 100, liveCoreOpts, 2, 4);
        pw.println();

        pw.println("LIVE SCAN AUTHENTICATION (Specify exactly ONE option below):");
        Options authOpts = new Options();
        authOpts.addOption(Option.builder().longOpt("profile").hasArg().argName("PROFILE").desc("Named credential map stored via local AWS config file").build());
        authOpts.addOption(Option.builder().longOpt("env").desc("Pulls active execution variables straight out of environmental runtime memory environment").build());
        formatter.printOptions(pw, 100, authOpts, 2, 4);
        pw.println();

        pw.println("REPORT COMPILATION MODE OPTIONS (Isolated processing path):");
        Options compileOpts = new Options();
        compileOpts.addOption(Option.builder().longOpt("from-json").hasArg().argName("JSON_PATH").desc("Skips live network requests entirely to forge HTML visualizations directly from a local log source").build());
        formatter.printOptions(pw, 100, compileOpts, 2, 4);
        pw.println("_________________________________________________________________________________");

        pw.flush();
    }

    private static List<CloudCheck> getAWSChecks() {
        return List.of(
                new AccessKeysCheck(writer, sharedDataProvider, iam, kms),
                new ACMCertificatesCheck(writer, sharedDataProvider, acm, config.path("aws").path("acmCertificates")),
                new AthenaCheck(writer, sharedDataProvider, athena),
                new BackupCheck(writer, sharedDataProvider, backup),
                new CloudFormationCheck(writer, sharedDataProvider, cloudformation),
                new CloudFrontCheck(writer, sharedDataProvider, cf, waf),
                new CloudTrailCheck(writer, sharedDataProvider, cloudTrail, cloudWatchLogs,config.path("aws").path("cloudtrail")),
                new CloudWatchCheck(writer, sharedDataProvider, sts, cloudWatchLogs),
                new CodeBuildCheck(writer, sharedDataProvider, codeBuild, config.path("aws").path("codebuild")),
                new DynamoDBCheck(writer, sharedDataProvider, dynamodb, backup, sts, appAutoScaling),
                new EBSCheck(writer, sharedDataProvider, ec2),
                new EC2Check(writer, sharedDataProvider, ec2, ssm),
                new EC2SecurityGroupCheck(writer, sharedDataProvider, ec2, config.path("aws").path("ec2securitygroup")),
                new ECRCheck(writer, sharedDataProvider, ecr),
                new EFSCheck(writer, sharedDataProvider, efs),
                new ElastiCacheCheck(writer, sharedDataProvider, elasticache),
                new ELBCheck(writer, sharedDataProvider, elb, waf, config.path("aws").path("elb")),
                new EnabledServicesCheck(writer, sharedDataProvider, secretsmanager, drs,
                        macie2, securityHub, waf),
                new EventBridgeCheck(writer, sharedDataProvider, schemas, sts),
                new GeneralCheck(writer, sharedDataProvider, accountClient, orgs, sts, config.path("aws").path("general")),
                new GlueCheck(writer, glue),
                new GuardDutyCheck(writer, sharedDataProvider, guardduty),
                new IAMGovernanceCheck(writer, sharedDataProvider, iam, accessAnalyzer, sts),
                new IAMPolicyCheck(writer, sharedDataProvider, iam, config.path("aws").path("iamPolicy")),
                new IAMUserSecurityCheck(writer, sharedDataProvider, iam),
                new Inspector2Check(writer, inspector2, sts),
                new KafkaCheck(writer, sharedDataProvider, kafka, kafkaconnect),
                new KMSCheck(writer, sharedDataProvider, kms, cloudWatch),
                new LambdaCheck(writer, sharedDataProvider, lambda),
                new MFACheck(writer, sharedDataProvider, iam, sts),
                new NeptuneDBCheck(writer, sharedDataProvider),
                new NetworkACLsCheck(writer, sharedDataProvider),
                new RDSInstancesCheck(writer, sharedDataProvider, rds, config.path("aws").path("rds")),
                new Route53Check(writer, sharedDataProvider, route53),
                new S3BucketsCheck(writer, awsDependencyFactory, sharedDataProvider, s3, s3control, sts, config.path("aws").path("s3")),
                new SNSTopicsCheck(writer, sharedDataProvider, sns),
                new SSMCheck(writer, sharedDataProvider, ssm, ssm_inc),
                new SupportCheck(writer, support),
                new VPCsCheck(writer, sharedDataProvider, ec2, networkFirewall, iam)
        );
    }

    private static void setAWSClients() {
        if (useEnv) {
            awsDependencyFactory = new AWSDependencyFactory(region);
        } else {
            awsDependencyFactory = new AWSDependencyFactory(region, profileInput);
        }

        s3                  = awsDependencyFactory.getClient(S3AsyncClient.class);
        s3control           = awsDependencyFactory.getClient(S3ControlAsyncClient.class);
        iam                 = awsDependencyFactory.getClient(IamAsyncClient.class);
        cf                  = awsDependencyFactory.getClient(CloudFrontAsyncClient.class);
        waf                 = awsDependencyFactory.getClient(Wafv2AsyncClient.class);
        dax                 = awsDependencyFactory.getClient(DaxAsyncClient.class);
        dynamodb            = awsDependencyFactory.getClient(DynamoDbAsyncClient.class);
        ec2                 = awsDependencyFactory.getClient(Ec2AsyncClient.class);
        ssm                 = awsDependencyFactory.getClient(SsmAsyncClient.class);
        ssm_inc             = awsDependencyFactory.getClient(SsmIncidentsAsyncClient.class);
        ecr                 = awsDependencyFactory.getClient(EcrAsyncClient.class);
        elb                 = awsDependencyFactory.getClient(ElasticLoadBalancingV2AsyncClient.class);
        elasticache         = awsDependencyFactory.getClient(ElastiCacheAsyncClient.class);
        drs                 = awsDependencyFactory.getClient(DrsAsyncClient.class);
        secretsmanager      = awsDependencyFactory.getClient(SecretsManagerAsyncClient.class);
        inspector2          = awsDependencyFactory.getClient(Inspector2AsyncClient.class);
        sts                 = awsDependencyFactory.getClient(StsAsyncClient.class);
        macie2              = awsDependencyFactory.getClient(Macie2AsyncClient.class);
        cloudWatch          = awsDependencyFactory.getClient(CloudWatchAsyncClient.class);
        support             = awsDependencyFactory.getClient(SupportAsyncClient.class);
        cloudWatchLogs      = awsDependencyFactory.getClient(CloudWatchLogsAsyncClient.class);
        kms                 = awsDependencyFactory.getClient(KmsAsyncClient.class);
        route53             = awsDependencyFactory.getClient(Route53AsyncClient.class);
        accountClient       = awsDependencyFactory.getClient(AccountAsyncClient.class);
        backup              = awsDependencyFactory.getClient(BackupAsyncClient.class);
        securityHub         = awsDependencyFactory.getClient(SecurityHubAsyncClient.class);
        cloudTrail          = awsDependencyFactory.getClient(CloudTrailAsyncClient.class);
        efs                 = awsDependencyFactory.getClient(EfsAsyncClient.class);
        guardduty           = awsDependencyFactory.getClient(GuardDutyAsyncClient.class);
        accessAnalyzer      = awsDependencyFactory.getClient(AccessAnalyzerAsyncClient.class);
        kafka               = awsDependencyFactory.getClient(KafkaAsyncClient.class);
        kafkaconnect        = awsDependencyFactory.getClient(KafkaConnectAsyncClient.class);
        neptune             = awsDependencyFactory.getClient(NeptuneAsyncClient.class);
        rds                 = awsDependencyFactory.getClient(RdsAsyncClient.class);
        sns                 = awsDependencyFactory.getClient(SnsAsyncClient.class);
        networkFirewall     = awsDependencyFactory.getClient(NetworkFirewallAsyncClient.class);
        athena              = awsDependencyFactory.getClient(AthenaAsyncClient.class);
        resourceexplorer2   = awsDependencyFactory.getClient(ResourceExplorer2AsyncClient.class);
        codeBuild           = awsDependencyFactory.getClient(CodeBuildAsyncClient.class);
        cloudformation      = awsDependencyFactory.getClient(CloudFormationAsyncClient.class);
        glue                = awsDependencyFactory.getClient(GlueAsyncClient.class);
        lambda              = awsDependencyFactory.getClient(LambdaAsyncClient.class);
        orgs                = awsDependencyFactory.getClient(OrganizationsAsyncClient.class);
        acm                 = awsDependencyFactory.getClient(AcmAsyncClient.class);
        appAutoScaling      = awsDependencyFactory.getClient(ApplicationAutoScalingAsyncClient.class);
        autoscaling         = awsDependencyFactory.getClient(AutoScalingAsyncClient.class);
        eventBridge         = awsDependencyFactory.getClient(EventBridgeAsyncClient.class);
        schemas             = awsDependencyFactory.getClient(SchemasAsyncClient.class);
    }
}