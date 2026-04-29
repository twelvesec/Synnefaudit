package com.twelvesec.synnefaudit.AWS;

import com.twelvesec.synnefaudit.messages.Text;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.awscore.client.builder.AwsAsyncClientBuilder;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
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
import software.amazon.awssdk.services.s3.model.BucketLocationConstraint;
import software.amazon.awssdk.services.s3.model.GetBucketLocationRequest;
import software.amazon.awssdk.services.s3.model.GetBucketLocationResponse;
import software.amazon.awssdk.services.s3control.S3ControlAsyncClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.securityhub.SecurityHubAsyncClient;
import software.amazon.awssdk.services.sns.SnsAsyncClient;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssmincidents.SsmIncidentsAsyncClient;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.support.SupportAsyncClient;
import software.amazon.awssdk.services.wafv2.Wafv2AsyncClient;

import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

public class AWSDependencyFactory {
    private final Region region;
    private final AwsCredentialsProvider customChain;
    private final Map<Class<?>, Object> clients = new ConcurrentHashMap<>();
    private final List<AutoCloseable> toClose = new CopyOnWriteArrayList<>();
    private final SdkAsyncHttpClient crtAsyncHttpClient = AwsCrtAsyncHttpClient.builder().build();

    private final Map<Class<?>, Supplier<?>> BUILDERS = Map.ofEntries(
        Map.entry(S3AsyncClient.class,                       builderFor(S3AsyncClient::builder)),
        Map.entry(S3ControlAsyncClient.class,                builderFor(S3ControlAsyncClient::builder)),
        Map.entry(IamAsyncClient.class,                      builderFor(IamAsyncClient::builder)),
        Map.entry(CloudFrontAsyncClient.class,               builderFor(CloudFrontAsyncClient::builder)),
        Map.entry(Wafv2AsyncClient.class,                    builderFor(Wafv2AsyncClient::builder)),
        Map.entry(DynamoDbAsyncClient.class,                 builderFor(DynamoDbAsyncClient::builder)),
        Map.entry(Ec2AsyncClient.class,                      builderFor(Ec2AsyncClient::builder)),
        Map.entry(SsmAsyncClient.class,                      builderFor(SsmAsyncClient::builder)),
        Map.entry(SsmIncidentsAsyncClient.class,             builderFor(SsmIncidentsAsyncClient::builder)),
        Map.entry(EcrAsyncClient.class,                      builderFor(EcrAsyncClient::builder)),
        Map.entry(ElasticLoadBalancingV2AsyncClient.class,   builderFor(ElasticLoadBalancingV2AsyncClient::builder)),
        Map.entry(DrsAsyncClient.class,                      builderFor(DrsAsyncClient::builder)),
        Map.entry(SecretsManagerAsyncClient.class,           builderFor(SecretsManagerAsyncClient::builder)),
        Map.entry(Inspector2AsyncClient.class,               builderFor(Inspector2AsyncClient::builder)),
        Map.entry(StsAsyncClient.class,                      builderFor(StsAsyncClient::builder)),
        Map.entry(Macie2AsyncClient.class,                   builderFor(Macie2AsyncClient::builder)),
        Map.entry(CloudWatchAsyncClient.class,               builderFor(CloudWatchAsyncClient::builder)),
        Map.entry(SupportAsyncClient.class,                  builderFor(SupportAsyncClient::builder)),
        Map.entry(CloudWatchLogsAsyncClient.class,           builderFor(CloudWatchLogsAsyncClient::builder)),
        Map.entry(KmsAsyncClient.class,                      builderFor(KmsAsyncClient::builder)),
        Map.entry(Route53AsyncClient.class,                  builderFor(Route53AsyncClient::builder)),
        Map.entry(AccountAsyncClient.class,                  builderFor(AccountAsyncClient::builder)),
        Map.entry(BackupAsyncClient.class,                   builderFor(BackupAsyncClient::builder)),
        Map.entry(SecurityHubAsyncClient.class,              builderFor(SecurityHubAsyncClient::builder)),
        Map.entry(CloudTrailAsyncClient.class,               builderFor(CloudTrailAsyncClient::builder)),
        Map.entry(EfsAsyncClient.class,                      builderFor(EfsAsyncClient::builder)),
        Map.entry(GuardDutyAsyncClient.class,                builderFor(GuardDutyAsyncClient::builder)),
        Map.entry(AccessAnalyzerAsyncClient.class,           builderFor(AccessAnalyzerAsyncClient::builder)),
        Map.entry(KafkaAsyncClient.class,                    builderFor(KafkaAsyncClient::builder)),
        Map.entry(RdsAsyncClient.class,                      builderFor(RdsAsyncClient::builder)),
        Map.entry(SnsAsyncClient.class,                      builderFor(SnsAsyncClient::builder)),
        Map.entry(NetworkFirewallAsyncClient.class,          builderFor(NetworkFirewallAsyncClient::builder)),
        Map.entry(AthenaAsyncClient.class,                   builderFor(AthenaAsyncClient::builder)),
        Map.entry(ResourceExplorer2AsyncClient.class,        builderFor(ResourceExplorer2AsyncClient::builder)),
        Map.entry(CodeBuildAsyncClient.class,                builderFor(CodeBuildAsyncClient::builder)),
        Map.entry(CloudFormationAsyncClient.class,           builderFor(CloudFormationAsyncClient::builder)),
        Map.entry(GlueAsyncClient.class,                     builderFor(GlueAsyncClient::builder)),
        Map.entry(LambdaAsyncClient.class,                   builderFor(LambdaAsyncClient::builder)),
        Map.entry(OrganizationsAsyncClient.class,            builderFor(OrganizationsAsyncClient::builder)),
        Map.entry(AcmAsyncClient.class,                      builderFor(AcmAsyncClient::builder))
    );

    public AWSDependencyFactory(Region region) {
        this(region, null);
    }

    public AWSDependencyFactory(Region region, String profileName) {
        this.region = region;
        this.customChain = createCredentialsProvider(profileName);
    }
    
    @SuppressWarnings("unchecked")
    public <T> T getClient(Class<T> cls) {
        return (T) clients.computeIfAbsent(cls, key -> {
            Supplier<?> supplier = BUILDERS.get(key);
            if (supplier == null) {
                System.err.println(Text.UNSUPPORTED_CLIENT.toString().concat(key.getName()));
            }
            return supplier.get();
        });
    }

    public void closeAllClients() {
        toClose.forEach((AutoCloseable client) -> {
               try {
                   client.close();
               } catch (Exception e) {
                   System.err.println(Text.FAILED_TO_CLOSE_CLIENT.toString().concat(e.getMessage()));
               }
            });
        toClose.clear();
        crtAsyncHttpClient.close();
    }
    
    public S3AsyncClient getCorrectRegionClient(String bucket, S3AsyncClient s3) {
        GetBucketLocationResponse locationResp = s3.getBucketLocation(
            GetBucketLocationRequest.builder().bucket(bucket).build()
        ).join();
        BucketLocationConstraint locationConstraint = locationResp.locationConstraint();
        Region region = (locationConstraint == null || locationConstraint == BucketLocationConstraint.UNKNOWN_TO_SDK_VERSION)
                ? Region.US_EAST_1
                : Region.of(locationConstraint.toString());

        return S3AsyncClient.builder()
                .httpClient(crtAsyncHttpClient)
                .region(region)
                .credentialsProvider(this.customChain)
                .build();
    }

    private <B extends AwsAsyncClientBuilder<B,T> & AwsClientBuilder<B,T>, T> Supplier<T> builderFor(Supplier<B> rawBuilder) {
        return () -> rawBuilder.get()
            .httpClient(crtAsyncHttpClient)
            .credentialsProvider(this.customChain)
            .region(this.region)
            .build();
    }

    private AwsCredentialsProvider createCredentialsProvider(String profileName) {
        if (profileName == null) {
            return DefaultCredentialsProvider.create();
        }

        ProfileFile profiles = ProfileFile.aggregator()
            .addFile(ProfileFile.defaultProfileFile())
            .build();

        Profile profile = profiles.profile(profileName)
            .orElseThrow(() -> new IllegalArgumentException("Profile not found: " + profileName));

        if (profile.property("role_arn").isPresent()) {
            return createRoleBasedProvider(profileName, profile);
        } else {
            return ProfileCredentialsProvider.builder()
                .profileName(profileName)
                .build();
        }
    }

    private AwsCredentialsProvider createRoleBasedProvider(String profileName, Profile profile) {
        String roleArn = profile.property("role_arn").get();
        String sourceProfile = profile.property("source_profile").orElse(null);
        String mfaSerial = profile.property("mfa_serial").orElse(null);
        String externalId = profile.property("external_id").orElse(null);
        String roleSessionName = profile.property("role_session_name")
            .orElse("java-session-" + System.currentTimeMillis());

        AwsCredentialsProvider baseProvider = sourceProfile != null
            ? ProfileCredentialsProvider.create(sourceProfile)
            : DefaultCredentialsProvider.create();

        AssumeRoleRequest.Builder requestBuilder = AssumeRoleRequest.builder()
            .roleArn(roleArn)
            .roleSessionName(roleSessionName);

        if (externalId != null) {
            requestBuilder.externalId(externalId);
        }

        if (mfaSerial != null) {
            String mfaToken = getMfaToken(mfaSerial);
            requestBuilder.serialNumber(mfaSerial).tokenCode(mfaToken);
        }

        StsClient stsClient = StsClient.builder()
            .credentialsProvider(baseProvider)
            .region(region)
            .build();
        toClose.add(stsClient);

        return StsAssumeRoleCredentialsProvider.builder()
            .stsClient(stsClient)
            .refreshRequest(requestBuilder.build())
            .build();
    }

    private String getMfaToken(String mfaSerial) {
        System.out.printf("Enter MFA token code for %s : ", mfaSerial);
        try (Scanner scanner = new Scanner(System.in)) {
            return scanner.nextLine().trim();
        } catch (Exception e) {
            throw new RuntimeException("Failed to read MFA token from console", e);
        }
    }
}
