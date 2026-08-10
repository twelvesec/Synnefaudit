package com.twelvesec.synnefaudit;

import software.amazon.awssdk.services.accessanalyzer.AccessAnalyzerAsyncClient;
import software.amazon.awssdk.services.accessanalyzer.model.AnalyzerSummary;
import software.amazon.awssdk.services.accessanalyzer.model.ListAnalyzersRequest;
import software.amazon.awssdk.services.accessanalyzer.model.ListAnalyzersResponse;
import software.amazon.awssdk.services.acm.AcmAsyncClient;
import software.amazon.awssdk.services.acm.model.CertificateSummary;
import software.amazon.awssdk.services.acm.model.ListCertificatesRequest;
import software.amazon.awssdk.services.acm.model.ListCertificatesResponse;
import software.amazon.awssdk.services.athena.AthenaAsyncClient;
import software.amazon.awssdk.services.athena.model.ListWorkGroupsRequest;
import software.amazon.awssdk.services.athena.model.ListWorkGroupsResponse;
import software.amazon.awssdk.services.athena.model.WorkGroupSummary;
import software.amazon.awssdk.services.cloudformation.CloudFormationAsyncClient;
import software.amazon.awssdk.services.cloudformation.model.ListStacksRequest;
import software.amazon.awssdk.services.cloudformation.model.ListStacksResponse;
import software.amazon.awssdk.services.cloudformation.model.StackSummary;
import software.amazon.awssdk.services.cloudfront.CloudFrontAsyncClient;
import software.amazon.awssdk.services.cloudfront.model.DistributionList;
import software.amazon.awssdk.services.cloudfront.model.DistributionSummary;
import software.amazon.awssdk.services.cloudfront.model.ListDistributionsRequest;
import software.amazon.awssdk.services.cloudfront.model.ListDistributionsResponse;
import software.amazon.awssdk.services.cloudtrail.CloudTrailAsyncClient;
import software.amazon.awssdk.services.cloudtrail.model.*;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatch.model.DescribeAlarmsRequest;
import software.amazon.awssdk.services.cloudwatch.model.DescribeAlarmsResponse;
import software.amazon.awssdk.services.cloudwatch.model.MetricAlarm;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeLogGroupsResponse;
import software.amazon.awssdk.services.cloudwatchlogs.model.LogGroup;
import software.amazon.awssdk.services.dax.DaxAsyncClient;
import software.amazon.awssdk.services.dax.model.Cluster;
import software.amazon.awssdk.services.dax.model.DescribeClustersRequest;
import software.amazon.awssdk.services.dax.model.DescribeClustersResponse;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.ListTablesRequest;
import software.amazon.awssdk.services.dynamodb.model.ListTablesResponse;
import software.amazon.awssdk.services.ec2.Ec2AsyncClient;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.ec2.model.DescribeSnapshotsRequest;
import software.amazon.awssdk.services.ec2.model.DescribeSnapshotsResponse;
import software.amazon.awssdk.services.ec2.model.Snapshot;
import software.amazon.awssdk.services.ec2.model.Subnet;
import software.amazon.awssdk.services.ecr.EcrAsyncClient;
import software.amazon.awssdk.services.ecr.model.Repository;
import software.amazon.awssdk.services.efs.EfsAsyncClient;
import software.amazon.awssdk.services.efs.model.DescribeFileSystemsRequest;
import software.amazon.awssdk.services.efs.model.DescribeFileSystemsResponse;
import software.amazon.awssdk.services.efs.model.FileSystemDescription;
import software.amazon.awssdk.services.elasticache.ElastiCacheAsyncClient;
import software.amazon.awssdk.services.elasticache.model.*;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2AsyncClient;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeLoadBalancersResponse;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancer;
import software.amazon.awssdk.services.guardduty.GuardDutyAsyncClient;
import software.amazon.awssdk.services.guardduty.model.ListDetectorsResponse;
import software.amazon.awssdk.services.iam.IamAsyncClient;
import software.amazon.awssdk.services.iam.model.*;
import software.amazon.awssdk.services.iam.model.User;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;
import software.amazon.awssdk.services.kafka.model.ClusterInfo;
import software.amazon.awssdk.services.kafka.model.ListClustersRequest;
import software.amazon.awssdk.services.kafka.model.ListClustersResponse;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.KeyListEntry;
import software.amazon.awssdk.services.kms.model.ListKeysRequest;
import software.amazon.awssdk.services.lambda.LambdaAsyncClient;
import software.amazon.awssdk.services.lambda.model.FunctionConfiguration;
import software.amazon.awssdk.services.neptune.NeptuneAsyncClient;
import software.amazon.awssdk.services.neptune.model.DBCluster;
import software.amazon.awssdk.services.neptune.model.DescribeDbClustersRequest;
import software.amazon.awssdk.services.neptune.model.DescribeDbClustersResponse;
import software.amazon.awssdk.services.rds.RdsAsyncClient;
import software.amazon.awssdk.services.rds.model.*;
import software.amazon.awssdk.services.resourceexplorer2.ResourceExplorer2AsyncClient;
import software.amazon.awssdk.services.resourceexplorer2.model.Index;
import software.amazon.awssdk.services.resourceexplorer2.model.ListIndexesRequest;
import software.amazon.awssdk.services.resourceexplorer2.model.ListIndexesResponse;
import software.amazon.awssdk.services.route53.Route53AsyncClient;
import software.amazon.awssdk.services.route53.model.HostedZone;
import software.amazon.awssdk.services.route53.model.ListHostedZonesRequest;
import software.amazon.awssdk.services.route53.model.ListHostedZonesResponse;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsRequest;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretListEntry;
import software.amazon.awssdk.services.sns.SnsAsyncClient;
import software.amazon.awssdk.services.sns.model.ListTopicsRequest;
import software.amazon.awssdk.services.sns.model.Topic;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.model.DocumentIdentifier;
import software.amazon.awssdk.services.ssm.model.ListDocumentsRequest;
import software.amazon.awssdk.services.ssm.model.ListDocumentsResponse;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.support.SupportAsyncClient;
import software.amazon.awssdk.services.support.model.DescribeTrustedAdvisorCheckResultRequest;
import software.amazon.awssdk.services.support.model.DescribeTrustedAdvisorCheckResultResponse;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class SharedDataProvider {
    private final ConcurrentMap<String, CompletableFuture<?>> cache = new ConcurrentHashMap<>();

    private final AccessAnalyzerAsyncClient accessAnalyzer;
    private final AcmAsyncClient acm;
    private final AthenaAsyncClient athena;
    private final CloudFormationAsyncClient cloudformation;
    private final CloudFrontAsyncClient cf;
    private final CloudTrailAsyncClient cloudTrail;
    private final CloudWatchAsyncClient cloudWatch;
    private final CloudWatchLogsAsyncClient cloudwatchlogs;
    private final DaxAsyncClient dax;
    private final NeptuneAsyncClient neptune;
    private final DynamoDbAsyncClient dynamodb;
    private final Ec2AsyncClient ec2;
    private final EcrAsyncClient ecr;
    private final EfsAsyncClient efs;
    private final ElastiCacheAsyncClient elasticache;
    private final ElasticLoadBalancingV2AsyncClient elb;
    private final SecretsManagerAsyncClient secretsmanager;
    private final GuardDutyAsyncClient guardduty;
    private final IamAsyncClient iam;
    private final KafkaAsyncClient kafka;
    private final KmsAsyncClient kms;
    private final LambdaAsyncClient lambda;
    private final RdsAsyncClient rds;
    private final Route53AsyncClient route53;
    private final ResourceExplorer2AsyncClient resourceexplorer2;
    private final S3AsyncClient s3;
    private final SnsAsyncClient sns;
    private final SsmAsyncClient ssm;
    private final StsAsyncClient sts;
    private final SupportAsyncClient support;

    public SharedDataProvider(AccessAnalyzerAsyncClient accessAnalyzer, AcmAsyncClient acm, AthenaAsyncClient athena,
              CloudFormationAsyncClient cloudformation, CloudFrontAsyncClient cf, CloudTrailAsyncClient cloudTrail,
              CloudWatchAsyncClient cloudWatch, CloudWatchLogsAsyncClient cloudwatchlogs, DaxAsyncClient dax, DynamoDbAsyncClient dynamodb,
              Ec2AsyncClient ec2, EcrAsyncClient ecr, EfsAsyncClient efs, ElastiCacheAsyncClient elasticache, ElasticLoadBalancingV2AsyncClient elb,
              SecretsManagerAsyncClient secretsmanager, GuardDutyAsyncClient guardduty, IamAsyncClient iam,
              KafkaAsyncClient kafka, KmsAsyncClient kms, LambdaAsyncClient lambda, NeptuneAsyncClient neptune, RdsAsyncClient rds,
              Route53AsyncClient route53, ResourceExplorer2AsyncClient resourceexplorer2, S3AsyncClient s3, SnsAsyncClient sns,
              SsmAsyncClient ssm, StsAsyncClient sts, SupportAsyncClient support) {
        this.accessAnalyzer = accessAnalyzer;
        this.acm = acm;
        this.athena = athena;
        this.cloudformation = cloudformation;
        this.cf = cf;
        this.cloudTrail = cloudTrail;
        this.cloudWatch = cloudWatch;
        this.cloudwatchlogs = cloudwatchlogs;
        this.dax = dax;
        this.dynamodb = dynamodb;
        this.ec2 = ec2;
        this.ecr = ecr;
        this.efs = efs;
        this.elasticache = elasticache;
        this.elb = elb;
        this.secretsmanager = secretsmanager;
        this.guardduty = guardduty;
        this.iam = iam;
        this.kafka = kafka;
        this.kms = kms;
        this.lambda = lambda;
        this.neptune = neptune;
        this.rds = rds;
        this.route53 = route53;
        this.resourceexplorer2 = resourceexplorer2;
        this.s3 = s3;
        this.sns = sns;
        this.ssm = ssm;
        this.sts = sts;
        this.support = support;
    }

    private <T> CompletableFuture<T> getCachedData(String cacheKey, Supplier<CompletableFuture<T>> loader) {
        while (true) {
            CompletableFuture<?> existing = cache.get(cacheKey);
            
            if (existing != null && !existing.isCompletedExceptionally()) {
                return (CompletableFuture<T>) existing;
            }
            
            CompletableFuture<T> newFuture = loader.get();
            CompletableFuture<T> futureWithCleanup = newFuture.whenComplete((result, ex) -> {
                if (ex != null) {
                    cache.remove(cacheKey, newFuture);
                }
            });
            
            if (existing == null) {
                if (cache.putIfAbsent(cacheKey, futureWithCleanup) == null) {
                    return futureWithCleanup;
                }
            } else {
                if (cache.replace(cacheKey, existing, futureWithCleanup)) {
                    return futureWithCleanup;
                }
            }
        }
    }

    public CompletableFuture<List<CertificateSummary>> getAllACMCertificates() {
        String cacheKey = "acm:certificates";
        Supplier<CompletableFuture<List<CertificateSummary>>> loader = () ->
            acm.listCertificates(ListCertificatesRequest.builder().build())
                .thenApply(ListCertificatesResponse::certificateSummaryList);
        return getCachedData(cacheKey, loader);
    }

    public CompletableFuture<List<WorkGroupSummary>> getAllWorkGroups() {
        String cacheKey = "athena:workgroups";
        Supplier<CompletableFuture<List<WorkGroupSummary>>> loader = () -> 
            athena.listWorkGroups(ListWorkGroupsRequest.builder().build())
                .thenApply(ListWorkGroupsResponse::workGroups);
        return getCachedData(cacheKey, loader);
    }

    public CompletableFuture<List<StackSummary>> getAllStacks() {
        String key = "cloudformation:stacks";
        Supplier<CompletableFuture<List<StackSummary>>> loader = () -> 
            PaginatorHelper.collectPaginatedItems(
                cloudformation.listStacksPaginator(ListStacksRequest.builder().build()),
                ListStacksResponse::stackSummaries
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<DistributionSummary>> getAllDistributions() {
        String key = "cloudfront:distributions";
        Supplier<CompletableFuture<List<DistributionSummary>>> loader = () ->
            cf.listDistributions(ListDistributionsRequest.builder().build())
                .thenApply(ListDistributionsResponse::distributionList)
                .thenApply(DistributionList::items);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<TrailInfo>> getAllTrails() {
        String key = "cloudtrail:trails";
        Supplier<CompletableFuture<List<TrailInfo>>> loader = () ->
            cloudTrail.listTrails(ListTrailsRequest.builder().build())
                .thenApply(ListTrailsResponse::trails);
        return getCachedData(key, loader);
    }

    public CompletableFuture<GetEventSelectorsResponse> getEventSelectorsForTrail(String trailName) {
        String key = "cloudtrail:eventselectors:" + trailName;
        Supplier<CompletableFuture<GetEventSelectorsResponse>> loader = () ->
            cloudTrail.getEventSelectors(
                GetEventSelectorsRequest.builder()
                    .trailName(trailName)
                    .build()
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<MetricAlarm>> getAllAlarms() {
        String key = "cloudwatch:alarms";
        Supplier<CompletableFuture<List<MetricAlarm>>> loader = () ->
            cloudWatch.describeAlarms(DescribeAlarmsRequest.builder().build())
                .thenApply(DescribeAlarmsResponse::metricAlarms);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<LogGroup>> getAllLogGroups() {
        String key = "cloudwatchlogs:loggroups";
        Supplier<CompletableFuture<List<LogGroup>>> loader = () ->
            cloudwatchlogs.describeLogGroups()
                .thenApply(DescribeLogGroupsResponse::logGroups);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllTableNames() {
        String key = "dynamodb:tables";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            dynamodb.listTables(ListTablesRequest.builder().build())
                .thenApply(ListTablesResponse::tableNames);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Cluster>> getAllDaxClusters() {
        String key = "dax:clusters";
        Supplier<CompletableFuture<List<Cluster>>> loader = () ->
                dax.describeClusters(DescribeClustersRequest.builder().build())
                        .thenApply(DescribeClustersResponse::clusters);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<DBCluster>> getAllNeptuneClusters() {
        String key = "neptune:clusters";
        Supplier<CompletableFuture<List<DBCluster>>> loader = () ->
                neptune.describeDBClusters(DescribeDbClustersRequest.builder().build())
                        .thenApply(DescribeDbClustersResponse::dbClusters);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Volume>> getAllVolumes() {
        String key = "ec2:volumes";
        Supplier<CompletableFuture<List<Volume>>> loader = () ->
            ec2.describeVolumes(DescribeVolumesRequest.builder().build())
                .thenApply(DescribeVolumesResponse::volumes);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Snapshot>> getAllSnapshots() {
        String key = "ec2:snapshots";
        Supplier<CompletableFuture<List<Snapshot>>> loader = () ->
                PaginatorHelper.collectPaginatedItems(
                        ec2.describeSnapshotsPaginator(DescribeSnapshotsRequest.builder().ownerIds("self").build()),
                        DescribeSnapshotsResponse::snapshots
                );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Instance>> getAllEC2Instances() {
        String key = "ec2:instances";
        Supplier<CompletableFuture<List<Instance>>> loader = () -> 
            PaginatorHelper.collectPaginatedItems(
                ec2.describeInstancesPaginator(DescribeInstancesRequest.builder().build()),
                page -> page.reservations().stream()
                    .flatMap(res -> res.instances().stream())
                    .collect(Collectors.toList())
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllSecurityGroupIds() {
        String key = "ec2:securitygroupids";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            ec2.describeSecurityGroups()
                .thenApply(r -> r.securityGroups().stream()
                    .map(SecurityGroup::groupId)
                    .collect(Collectors.toList()));
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<SecurityGroup>> getAllSecurityGroups() {
        String key = "ec2:securitygroups";
        Supplier<CompletableFuture<List<SecurityGroup>>> loader = () ->
            ec2.describeSecurityGroups()
                .thenApply(DescribeSecurityGroupsResponse::securityGroups);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<SecurityGroup>> getEC2AttachedSecurityGroups() {
        String key = "ec2:attachedsecuritygroups";
        Supplier<CompletableFuture<List<SecurityGroup>>> loader = () ->
            ec2.describeInstances(DescribeInstancesRequest.builder().build())
                .thenApply(describeInstancesResponse -> {
                    Set<String> attachedGroupIds = describeInstancesResponse.reservations().stream()
                        .flatMap(reservation -> reservation.instances().stream())
                        .flatMap(instance -> instance.securityGroups().stream())
                        .map(GroupIdentifier::groupId)
                        .collect(Collectors.toSet());
                    
                    return ec2.describeSecurityGroups().join().securityGroups().stream()
                        .filter(sg -> attachedGroupIds.contains(sg.groupId()))
                        .collect(Collectors.toList());
                });
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<NetworkAcl>> getAllNetworkACLs() {
        String key = "ec2:networkacls";
        Supplier<CompletableFuture<List<NetworkAcl>>> loader = () ->
            ec2.describeNetworkAcls()
                .thenApply(DescribeNetworkAclsResponse::networkAcls);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<LaunchTemplate>> getAllLaunchTemplates() {
        String key = "ec2:launchtemplates";
        Supplier<CompletableFuture<List<LaunchTemplate>>> loader = () ->
            ec2.describeLaunchTemplates(DescribeLaunchTemplatesRequest.builder().build())
                .thenApply(DescribeLaunchTemplatesResponse::launchTemplates);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<TransitGateway>> getAllTransitGateways() {
        String key = "ec2:transitgateways";
        Supplier<CompletableFuture<List<TransitGateway>>> loader = () ->
            ec2.describeTransitGateways(DescribeTransitGatewaysRequest.builder().build())
                .thenApply(DescribeTransitGatewaysResponse::transitGateways);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Image>> getAllAMIs() {
        String key = "ec2:amis";
        Supplier<CompletableFuture<List<Image>>> loader = () -> sts.getCallerIdentity(GetCallerIdentityRequest.builder().build())
            .thenCompose(identity -> {
                String accountId = identity.account();
                return ec2.describeImages(DescribeImagesRequest.builder()
                    .owners(Collections.singletonList(accountId))
                    .build())
                    .thenApply(DescribeImagesResponse::images);
        });
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Address>> getAllElasticIPs() {
        String key = "ec2:elasticips";
        Supplier<CompletableFuture<List<Address>>> loader = () ->
                ec2.describeAddresses(DescribeAddressesRequest.builder().build())
                        .thenApply(DescribeAddressesResponse::addresses);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<NetworkInterface>> getAllNetworkInterfaces() {
        String key = "ec2:networkinterfaces";
        Supplier<CompletableFuture<List<NetworkInterface>>> loader = () ->
                ec2.describeNetworkInterfaces(DescribeNetworkInterfacesRequest.builder().build())
                        .thenApply(DescribeNetworkInterfacesResponse::networkInterfaces);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllRepositoryNames() {
        String key = "ecr:repositorynames";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            ecr.describeRepositories()
                .thenApply(r -> r.repositories().stream()
                    .map(Repository::repositoryName)
                    .collect(Collectors.toList()));
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<FileSystemDescription>> getAllFileSystems() {
        String key = "efs:filesystems";
        Supplier<CompletableFuture<List<FileSystemDescription>>> loader = () ->
            efs.describeFileSystems(DescribeFileSystemsRequest.builder().build())
                .thenApply(DescribeFileSystemsResponse::fileSystems);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<ReplicationGroup>> getAllReplicationGroups() {
        String key = "elasticache:replicationgroups";
        Supplier<CompletableFuture<List<ReplicationGroup>>> loader = () ->
                elasticache.describeReplicationGroups(DescribeReplicationGroupsRequest.builder().build())
                        .thenApply(DescribeReplicationGroupsResponse::replicationGroups);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<CacheCluster>> getAllCacheClusters() {
        String key = "elasticache:cacheclusters";
        Supplier<CompletableFuture<List<CacheCluster>>> loader = () ->
                elasticache.describeCacheClusters(DescribeCacheClustersRequest.builder().build())
                        .thenApply(DescribeCacheClustersResponse::cacheClusters);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<ServerlessCache>> getAllServerlessCaches() {
        String key = "elasticache:serverlesscaches";
        Supplier<CompletableFuture<List<ServerlessCache>>> loader = () ->
                elasticache.describeServerlessCaches(DescribeServerlessCachesRequest.builder().build())
                        .thenApply(DescribeServerlessCachesResponse::serverlessCaches);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<LoadBalancer>> getAllLoadBalancers() {
        String key = "elb:loadbalancers";
        Supplier<CompletableFuture<List<LoadBalancer>>> loader = () ->
            elb.describeLoadBalancers()
                .thenApply(DescribeLoadBalancersResponse::loadBalancers);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<SecretListEntry>> getAllSecrets() {
        String key = "secretsmanager:secrets";
        Supplier<CompletableFuture<List<SecretListEntry>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                secretsmanager.listSecretsPaginator(ListSecretsRequest.builder().build()),
                ListSecretsResponse::secretList
            );
        return getCachedData(key, loader);
    }
    
    public CompletableFuture<List<Index>> getAllIndexes() {
        String key = "resourceexplorer2:indexes";
        Supplier<CompletableFuture<List<Index>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                resourceexplorer2.listIndexesPaginator(ListIndexesRequest.builder().build()),
                ListIndexesResponse::indexes
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllDetectorIds() {
        String key = "guardduty:detectorids";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            guardduty.listDetectors()
                .thenApply(ListDetectorsResponse::detectorIds);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<AnalyzerSummary>> getAllAnalyzers() {
        String key = "accessanalyzer:analyzers";
        Supplier<CompletableFuture<List<AnalyzerSummary>>> loader = () ->
            accessAnalyzer.listAnalyzers(ListAnalyzersRequest.builder().build())
                .thenApply(ListAnalyzersResponse::analyzers);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Role>> getAllRoles() {
        String key = "iam:roles";
        Supplier<CompletableFuture<List<Role>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                iam.listRolesPaginator(ListRolesRequest.builder().build()),
                ListRolesResponse::roles
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<User>> getAllUsers() {
        String key = "iam:users";
        Supplier<CompletableFuture<List<User>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                iam.listUsersPaginator(ListUsersRequest.builder().build()),
                ListUsersResponse::users
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Policy>> getAllPolicies() {
        String key = "iam:policies";
        Supplier<CompletableFuture<List<Policy>>> loader = () ->
            iam.listPolicies(ListPoliciesRequest.builder().scope(PolicyScopeType.ALL).build())
                .thenApply(ListPoliciesResponse::policies);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Group>> getAllGroups() {
        String key = "iam:groups";
        Supplier<CompletableFuture<List<Group>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                iam.listGroupsPaginator(ListGroupsRequest.builder().build()),
                ListGroupsResponse::groups
            );
        return getCachedData(key, loader);
    }
    
    public CompletableFuture<List<ClusterInfo>> getAllKafkaClusters() {
        String key = "kafka:clusters";
        Supplier<CompletableFuture<List<ClusterInfo>>> loader = () ->
            kafka.listClusters(ListClustersRequest.builder().build())
                .thenApply(ListClustersResponse::clusterInfoList);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllKeyIds() {
        String key = "kms:keyids";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            kms.listKeys(ListKeysRequest.builder().build())
                .thenApply(r -> r.keys().stream()
                    .map(KeyListEntry::keyId)
                    .collect(Collectors.toList()));
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllLambdaFunctionNames() {
        String key = "lambda:functions";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                lambda.listFunctionsPaginator(),
                page -> page.functions().stream()
                    .map(FunctionConfiguration::functionName)
                    .collect(Collectors.toList())
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<DBInstance>> getAllDBInstances() {
        String key = "rds:dbinstances";
        Supplier<CompletableFuture<List<DBInstance>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                rds.describeDBInstancesPaginator(DescribeDbInstancesRequest.builder().build()),
                DescribeDbInstancesResponse::dbInstances
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<DBSnapshot>> getAllDBSnapshots() {
        String key = "rds:dbsnapshots";
        Supplier<CompletableFuture<List<DBSnapshot>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                rds.describeDBSnapshotsPaginator(DescribeDbSnapshotsRequest.builder().build()),
                DescribeDbSnapshotsResponse::dbSnapshots
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<DBClusterSnapshot>> getAllDBClusterSnapshots() {
        String key = "rds:dbclustersnapshots";
        Supplier<CompletableFuture<List<DBClusterSnapshot>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                rds.describeDBClusterSnapshotsPaginator(DescribeDbClusterSnapshotsRequest.builder().build()),
                DescribeDbClusterSnapshotsResponse::dbClusterSnapshots
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<HostedZone>> getAllRoute53HostedZones() {
        String key = "route53:hostedzones";
        Supplier<CompletableFuture<List<HostedZone>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                route53.listHostedZonesPaginator(ListHostedZonesRequest.builder().build()),
                ListHostedZonesResponse::hostedZones
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllS3BucketNames() {
        String key = "s3:bucketnames";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            s3.listBuckets()
                .thenApply(r -> r.buckets().stream()
                    .map(Bucket::name)
                    .collect(Collectors.toList()));
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<String>> getAllSNSTopicArns() {
        String key = "sns:topicarns";
        Supplier<CompletableFuture<List<String>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                sns.listTopicsPaginator(ListTopicsRequest.builder().build()),
                page -> page.topics().stream()
                    .map(Topic::topicArn)
                    .collect(Collectors.toList())
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<DocumentIdentifier>> getAllSSMDocuments() {
        String key = "ssm:documents";
        Supplier<CompletableFuture<List<DocumentIdentifier>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                ssm.listDocumentsPaginator(ListDocumentsRequest.builder().build()),
                ListDocumentsResponse::documentIdentifiers
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<DescribeTrustedAdvisorCheckResultResponse> getTrustedAdvisorCheckResults(String id) {
        String cacheKey = "support:trustedAdvisorResults";
        Supplier<CompletableFuture<DescribeTrustedAdvisorCheckResultResponse>> loader = () ->
            support.describeTrustedAdvisorCheckResult(DescribeTrustedAdvisorCheckResultRequest.builder()
                .checkId(id)
                .build());
        return getCachedData(cacheKey, loader);
    }

    public CompletableFuture<List<Vpc>> getAllVPCs() {
        String key = "ec2:vpcs";
        Supplier<CompletableFuture<List<Vpc>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                ec2.describeVpcsPaginator(DescribeVpcsRequest.builder().build()),
                DescribeVpcsResponse::vpcs
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<VpcEndpoint>> getAllVPCEndpoints() {
        String key = "ec2:vpcendpoints";
        Supplier<CompletableFuture<List<VpcEndpoint>>> loader = () ->
            PaginatorHelper.collectPaginatedItems(
                ec2.describeVpcEndpointsPaginator(DescribeVpcEndpointsRequest.builder().build()),
                DescribeVpcEndpointsResponse::vpcEndpoints
            );
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<Subnet>> getAllVPCSubnets() {
        String key = "ec2:subnets";
        Supplier<CompletableFuture<List<Subnet>>> loader = () ->
            ec2.describeSubnets()
                .thenApply(DescribeSubnetsResponse::subnets);
        return getCachedData(key, loader);
    }

    public CompletableFuture<List<RouteTable>> getAllRouteTables() {
        String key = "ec2:routetables";
        Supplier<CompletableFuture<List<RouteTable>>> loader = () ->
            ec2.describeRouteTables()
                .thenApply(DescribeRouteTablesResponse::routeTables);
        return getCachedData(key, loader);
    }

    public void clearCache() {
        cache.clear();
    }

    public void clearCacheEntry(String key) {
        cache.remove(key);
    }
}