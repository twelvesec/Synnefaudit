package com.twelvesec.synnefaudit;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

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
import static com.twelvesec.synnefaudit.ReportPrinter.CHECKS_SUMMARY;
import com.twelvesec.synnefaudit.messages.Text;

import software.amazon.awssdk.profiles.Profile;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.accessanalyzer.AccessAnalyzerAsyncClient;
import software.amazon.awssdk.services.account.AccountAsyncClient;
import software.amazon.awssdk.services.acm.AcmAsyncClient;
import software.amazon.awssdk.services.athena.AthenaAsyncClient;
import software.amazon.awssdk.services.backup.BackupAsyncClient;
import software.amazon.awssdk.services.cloudformation.CloudFormationAsyncClient;
import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;
import software.amazon.awssdk.services.cloudtrail.CloudTrailAsyncClient;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.codebuild.CodeBuildAsyncClient;
import software.amazon.awssdk.services.drs.DrsAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ecr.EcrAsyncClient;
import software.amazon.awssdk.services.efs.EfsAsyncClient;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2AsyncClient;
import software.amazon.awssdk.services.glue.GlueAsyncClient;
import software.amazon.awssdk.services.guardduty.GuardDutyAsyncClient;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.inspector2.Inspector2AsyncClient;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.lambda.LambdaAsyncClient;
import software.amazon.awssdk.services.macie2.Macie2AsyncClient;
import software.amazon.awssdk.services.networkfirewall.NetworkFirewallAsyncClient;
import software.amazon.awssdk.services.organizations.OrganizationsAsyncClient;
import software.amazon.awssdk.services.rds.RdsAsyncClient;
import software.amazon.awssdk.services.resourceexplorer2.ResourceExplorer2AsyncClient;
import software.amazon.awssdk.services.route53.Route53AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3control.S3ControlAsyncClient;
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
    private static AWSDependencyFactory awsDependencyFactory;
    
    private static IamAsyncClient iam;
    private static CloudFrontAsyncClient cf;
    private static Wafv2AsyncClient waf;
    private static DynamoDbAsyncClient dynamodb;
    private static Ec2AsyncClient ec2;
    private static SsmAsyncClient ssm;
    private static SsmIncidentsAsyncClient ssm_inc;
    private static EcrAsyncClient ecr;
    private static ElasticLoadBalancingV2AsyncClient elb;
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

    private static DataWriter writer;
    private static ReportPrinter printer;
    private static SharedDataProvider sharedDataProvider;

    private static ExecutorService executor;

    private static int exitCode = 0;

    static void main(String[] args) {
        Instant start = Instant.now();
        printer = new ReportPrinter();

        PROVIDER = Provider.AWS; 

        retrieveUserParameters(args);
        writer = new DataWriter(outfilePath);
        
        setAWSClients();
        
        executor = Executors.newVirtualThreadPerTaskExecutor();

        try {
            sharedDataProvider = new SharedDataProvider(
                accessAnalyzer, acm, athena, cloudformation, cf, cloudTrail, cloudWatch, cloudWatchLogs, dynamodb, ec2, ecr, efs, 
                elb, secretsmanager, guardduty, iam, kafka, kms, lambda, rds, route53, resourceexplorer2, s3, sns, ssm, sts, support);

            List<CloudCheck> checks = getAWSChecks();

            printer.printSectionHeader(CHECKS_SUMMARY);

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

            exitCode = 0;
        } catch (Exception e) {
            System.err.println(Text.EXCEPTION.toString() + e.getMessage());
            e.printStackTrace(System.err);
            exitCode = 1;
        } finally {
            executor.shutdown();
            awsDependencyFactory.closeAllClients();
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

        options.addOption(Option.builder()
                .longOpt("region")
                .hasArg()
                .argName("REGION")
                .desc("AWS region (e.g. us-east-1)")
                .required()
                .build());
        options.addOption(Option.builder()
                .longOpt("outdir")
                .hasArg()
                .argName("OUTDIR")
                .desc("Output directory path")
                .required()
                .build());
        options.addOption(Option.builder()
                .longOpt("profile")
                .hasArg()
                .argName("PROFILE")
                .desc("AWS CLI profile name")
                .build());
        options.addOption(Option.builder()
                .longOpt("env")
                .desc("Use AWS credentials from environment variables")
                .hasArg(false)
                .build());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            new HelpFormatter().printHelp("java -jar synnefaudit.jar", options);
            System.exit(1);
            return;
        }

        String regionInput  = cmd.getOptionValue("region");
        String outdirInput  = cmd.getOptionValue("outdir");
        profileInput        = cmd.getOptionValue("profile");
        useEnv              = cmd.hasOption("env");

        if ((profileInput == null && !useEnv) || (profileInput != null && useEnv)) {
            System.err.println("Error: You must specify exactly one of --profile or --env.");
            new HelpFormatter().printHelp("java -jar synnefaudit.jar", options);
            System.exit(2);
            return;
        }

        try {
            region = Region.of(regionInput);
        } catch (IllegalArgumentException iae) {
            System.err.print("Error: please provide a valid AWS region.\n");
            System.exit(3);
            return;
        }

        try {
            Path dirPath = Paths.get(outdirInput);
            if (!Files.exists(dirPath) || !Files.isDirectory(dirPath)) {
                System.err.print("Error: path in outdir parameter does not exist or is not a directory.\n");
                System.exit(4);
                return;
            }
            outfilePath = dirPath;
        } catch (InvalidPathException ipe) {
            System.err.print("Error: path in outdir parameter is not a valid directory path.\n");
            System.exit(5);
            return;
        }

        if (!useEnv) {
            ProfileFile credentials = ProfileFile.builder()
                .content(Paths.get(System.getProperty("user.home"), ".aws", "credentials"))
                .type(ProfileFile.Type.CREDENTIALS)
                .build();

            ProfileFile configs = ProfileFile.builder()
                .content(Paths.get(System.getProperty("user.home"), ".aws", "config"))
                .type(ProfileFile.Type.CONFIGURATION)
                .build();

            ProfileFile combined = ProfileFile.aggregator()
                .addFile(credentials)
                .addFile(configs)
                .build();

            Map<String, Profile> profileMap = combined.profiles();
            if (!profileMap.containsKey(profileInput)) {
                System.err.print("Error: AWS profile was not found in ~/.aws/credentials.\n");
                System.exit(6);
            }
        }
    }

    private static List<CloudCheck> getAWSChecks() {
        return List.of(
            new AccessKeysCheck(writer, sharedDataProvider, iam, kms),
            new ACMCertificatesCheck(writer, sharedDataProvider, acm),
            new AthenaCheck(writer, sharedDataProvider, athena),
            new CloudFormationCheck(writer, sharedDataProvider, cloudformation),
            new CloudFrontCheck(writer, sharedDataProvider, cf, waf),
            new CloudTrailCheck(writer, sharedDataProvider, cloudTrail, cloudWatchLogs),
            new CloudWatchCheck(writer, sharedDataProvider, sts, cloudWatchLogs),
            new DynamoDBCheck(writer, sharedDataProvider, dynamodb),
            new EBSCheck(writer, sharedDataProvider, ec2),
            new EC2Check(writer, sharedDataProvider, ec2, ssm),
            new EC2SecurityGroupCheck(writer, sharedDataProvider, ec2),
            new ECRCheck(writer, sharedDataProvider, ecr),
            new EFSCheck(writer, sharedDataProvider, efs),
            new ELBCheck(writer, sharedDataProvider, elb, waf),
            new EnabledServicesCheck(writer, sharedDataProvider, secretsmanager, drs,
                                    macie2, securityHub, waf),
            new GeneralCheck(writer, sharedDataProvider, accountClient, backup, codeBuild, orgs, sts),
            new GlueCheck(writer, glue),
            new GuardDutyCheck(writer, sharedDataProvider, guardduty),
            new IAMCheck(writer, sharedDataProvider, iam, accessAnalyzer, sts),
            new Inspector2Check(writer, inspector2, sts),
            new KafkaCheck(writer, sharedDataProvider, kafka),
            new KMSCheck(writer, sharedDataProvider, kms, cloudWatch),
            new LambdaCheck(writer, sharedDataProvider, lambda),
            new MFACheck(writer, sharedDataProvider, iam, sts),
            new NetworkACLsCheck(writer, sharedDataProvider),
            new RDSInstancesCheck(writer, sharedDataProvider, rds),
            new Route53Check(writer, sharedDataProvider, route53),
            new S3BucketsCheck(writer, awsDependencyFactory, sharedDataProvider, s3, s3control, sts),
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
        dynamodb            = awsDependencyFactory.getClient(DynamoDbAsyncClient.class);
        ec2                 = awsDependencyFactory.getClient(Ec2AsyncClient.class);
        ssm                 = awsDependencyFactory.getClient(SsmAsyncClient.class);
        ssm_inc             = awsDependencyFactory.getClient(SsmIncidentsAsyncClient.class);
        ecr                 = awsDependencyFactory.getClient(EcrAsyncClient.class);
        elb                 = awsDependencyFactory.getClient(ElasticLoadBalancingV2AsyncClient.class);
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
    }
}
