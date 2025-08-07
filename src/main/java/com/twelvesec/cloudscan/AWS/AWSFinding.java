package com.twelvesec.cloudscan.AWS;

import com.twelvesec.cloudscan.CloudCheck.Severity;

public enum AWSFinding {
    ERROR_WITH_FINDING("ERROR WITH FINDING", Severity.UNKNOWN),

    CLOUDFRONT_NOT_CONFIGURED("CloudFront is not Configured", Severity.MEDIUM),
    CLOUDFRONT_DISTRIBUTIONS_WITHOUT_WAF_WEB_ACL("CloudFront Distributions not using a WAF web ACL", Severity.LOW),
    CLOUDFRONT_DISTRIBUTIONS_FIELDLEVELENCRYPTION_DISABLED("CloudFront Distributions with FieldLevelEncryption disabled", Severity.LOW),
    CLOUDFRONT_DISTRIBUTIONS_WITH_NO_GEO_RESTRICTIONS("Cloudfront distribution with no Geo Restrictions", Severity.INFO),

    CLOUDFORMATION_STACKS_WITHOUT_TERMINATION_PROTECTION("CloudFormation stacks with Termination Protection disabled", Severity.LOW),

    DYNAMODB_POINT_IN_TIME_RECOVERY_DISABLED("DynamoDB table with point-in-time recovery disabled", Severity.MEDIUM),
    DYNAMODB_TABLE_DEFAULT_ENCRYPTION_ENABLED("DynamoDB table with Default Encryption enabled", Severity.LOW),

    NO_SNAPSHOTS_FOR_EBS_VOLUMES("No Snapshots for EBS volumes", Severity.LOW),
    EBS_DEFAULT_ENCRYPTION_NOT_ACTIVATED("EBS Default Encryption is not Activated", Severity.LOW),

    EC2_INSTANCES_WTH_PUBLIC_IPS("EC2 instances with Public IPs", Severity.MEDIUM),
    EC2_INSTANCES_WITH_DETAILED_MONITORING_DISABLED("EC2 instances with Detailed Monitoring Disabled", Severity.LOW),
    EC2_INSTANCES_NOT_MANAGED_BY_SYSTEM_MANAGER("EC2 instances not managed by Systems Manager", Severity.LOW),
    EC2_SECURITY_GROUP_NON_RFC1918_INGRESS("Security Group allow ingress traffic from non-RFC1918 address", Severity.MEDIUM),
    PUBLIC_INSTANCES_WITH_IAM_PROFILES_ATTACHED("Public EC2 Instances with Instance Profiles attached", Severity.MEDIUM),
    EC2_INSTANCES_OLDER_THAN_180_DAYS("EC2 Instance older than 180 days", Severity.LOW),
    SECURITY_GROUPS_NOT_USED("Security Groups Not being Used", Severity.INFO),
    EC2_IMDSV2_CONFIGURATION("EC2 Instance Metadata Service Version 2 (IMDSv2) is disabled", Severity.MEDIUM),
    
    ECR_REGISTRY_WITHOUT_SCAN_ON_PUSH("ECR registry with Basic Scanning without scan on push enabled [DEPRECATED in favor of registry-level scan configurations]", Severity.MEDIUM),
    ECR_REGISTRY_WITHOUT_LIFECYCLE_POLICY("ECR registries with no lifecycle policy configured", Severity.LOW),
    ECR_LATEST_IMAGE_WITH_FINDINGS("ECR repositories with latest imageTag with findings found", Severity.HIGH),

    ELB_WITHOUT_WAF_ACL_ATTACHED("ELB with no WAF ACL attached", Severity.LOW),
    ELB_ALBS_ACCESS_LOGGING_DISABLED("ELB ALBs with Access Logging disabled", Severity.LOW),
    ELB_DELETION_PROTECTION_DISABLED("ELBs with Deletion Protection disabled",Severity.LOW),
    ELB_LISTENER_WITHOUT_SSL("ELB Listener without SSL found", Severity.LOW),
    PUBLICLY_ACCESSIBLE_LOAD_BALANCERS("Publicly Accessible Load Balancers found", Severity.MEDIUM),
    ELB_ALBS_DEFENSIVE_MITIGATION_NOT_DROPPING_HEADERS("ELB ALB with mitigation mode defensive and not dropping invalid header fields", Severity.INFO),
    ELB_INSECURE_SSL_CIPHERS("ELBs have insecure SSL ciphers", Severity.MEDIUM),

    ROOT_ACCOUNT_WITHOUT_HARDWARE_MFA("Root Account without Hardware MFA", Severity.MEDIUM),
    ROOT_ACCOUNT_WITH_VIRTUAL_MFA("Root Account with Virtual MFA", Severity.MEDIUM),
    USERS_WITH_NO_MFA("Users with no MFA", Severity.MEDIUM),
    USERS_WITHOUT_HARDWARE_MFA("Users without Hardware MFA", Severity.LOW),

    INSPECTOR2_NOT_ENABLED("Inspector2 not enabled", Severity.MEDIUM),
    INSPECTOR2_FINDINGS_FOUND("Inspector2 with findings found", Severity.MEDIUM),

    SECRETS_MANAGER_SECRETS_ROTATION_DISABLED("Secret Manager secrets with rotation disabled", Severity.MEDIUM),
    
    DRS_NOT_ENABLED("DRS not Enabled", Severity.MEDIUM),

    SSM_INCIDENTS_WITHOUT_RESPONSE_PLANS("SSM Incidents with no Response Plans", Severity.MEDIUM),

    MACIE_NOT_ENABLED("Macie is not enabled", Severity.LOW),

    CLOUDWATCH_ALARMS_FOR_SENSITIVE_OPERATIONS("CloudWatch Alarms for Sensitive Operations", Severity.LOW),
    CLOUDWATCH_LOG_GROUPS_WITH_NO_KMS_KEYS_ASSOCIATED("Log Groups with no AWS KMS keys associated", Severity.LOW),
    CLOUDWATCH_LOG_GROUPS_WITH_LOW_RETENTION_POLICY("CloudWatch log groups with low retention policy", Severity.MEDIUM),

    WEB_SERVICES_PREMIUM_SUPPORT_PLAN_NOT_SUBSCRIBED("Amazon Web Services Premium Support Plan is not subscribed", Severity.LOW),
    TRUSTED_ADVISOR_WARNINGS("Trusted Advisor checks in warning state", Severity.INFO),

    KMS_KEYS_NOT_ROTATED("KMS Keys not rotated", Severity.LOW),
    PUBLICLY_EXPOSED_KMS_KEYS("Publicly exposed KMS keys", Severity.MEDIUM),

    ROUTE53_PUBLIC_HOSTED_ZONES_QUERY_LOGGING_DISABLED("Route53 Public Hosted Zones with query logging disabled", Severity.LOW),
    ROUTE53_RECORDS_WITH_DANGLING_IPS("Route53 Records containing dangling IPs", Severity.HIGH),
    
    NO_ALTERNATE_CONTACTS_FOUND("No Alternate Contacts Found", Severity.LOW),

    NO_BACKUP_REPORT_PLAN_EXISTS("No Backup Report Plan Exists", Severity.LOW),

    SECURITY_HUB_NOT_ENABLED("Security Hub is not enabled", Severity.LOW),

    WAFV2_WEB_ACL_LOGGING_ENABLED("AWS WAFv2 WebACL logging not enabled", Severity.MEDIUM),

    CLOUDTRAIL_WITH_NO_INSIGHT_SELECTORS("Trail with no Insight selectors", Severity.LOW),
    CLOUDTRAIL_RECENT_ROOT_ACCOUNT_USAGE("Root account usage found", Severity.MEDIUM),

    RESOURCE_EXPLORER_NO_INDEXES_FOUND("No Resource Explorer Indexes found", Severity.LOW),

    CODEBUILD_PROJECTS_NOT_INVOKED_90_DAYS("Codebuild Projects not invoked in the last 90 days", Severity.LOW),

    ACCOUNT_IS_NOT_PART_OF_ORGANIZATIONS("Account is not part of AWS Organization", Severity.LOW),

    ACM_CERTIFICATES_EXPIRING_SOON("ACM Certificates about to expire", Severity.MEDIUM),
    ACM_CERTIFICATE_TRANSPARENCY_LOGGING_DISABLED("ACM certificates have Certificate Transparency logging disabled", Severity.MEDIUM),

    ATHENA_WORKGROUPS_WITHOUT_ENCRYPTION("Amazon Athena Workgroups with no Encryption", Severity.LOW),
    ATHENA_WORKGROUPS_ENFORCE_CONFIGURATION_DISABLED("Athena Workgroups with EnforceWorkGroupConfiguration disabled", Severity.LOW),

    EFS_FILE_SYSTEMS_WITH_BACKUP_DISABLED("EFS file systems with Backup disabled", Severity.LOW),
    EFS_WITHOUT_POLICY("EFS file systems with no Policy", Severity.LOW),

    GLUE_DATA_CATALOG_UNENCRYPTED_PASSWORDS("Glue Data catalogue with connection password not encrypted", Severity.LOW),
    GLUE_METADATA_NOT_ENCRYPTED("Glue Data Catalog's Metadata not Encrypted", Severity.LOW),

    GUARDDUTY_NOT_ENABLED("GuardDuty is not enabled", Severity.MEDIUM),
    GUARDDUTY_DETECTOR_NOT_CENTRALLY_MANAGED("GuardDuty detector is not centrally managed", Severity.LOW),

    IAM_ROLES_WITH_ADMINISTRATORACCESS_POLICY_ATTACHED("IAM Roles with AdministratorAccess policy attached", Severity.MEDIUM),
    IAM_ACCESS_ANALYZER_DISABLED("IAM Access Analyzer Disabled", Severity.LOW),
    IAM_ACCESS_ANALYZER_WITH_FINDINGS("IAM Access Analyzer with Findings", Severity.LOW),
    IAM_USERS_WITH_MULTIPLE_ACTIVE_ACCESS_KEYS("IAM Users with Multiple Active Access Keys", Severity.LOW),
    IAM_PASSWORD_POLICY_NOT_SET("IAM Password Policy is not set", Severity.HIGH),
    IAM_SHORT_PASSWORD_POLICY_REUSE("Short IAM Password Policy Reuse", Severity.LOW),
    IAM_POLICY_ALLOWS_PRIVILEGE_ESCALATION("IAM Policy Allows Privilege Escalation", Severity.HIGH),
    IAM_CROSS_ACCOUNT_READ_ONLY_ROLES("IAM Role gives cross account read-only access", Severity.HIGH),
    IAM_OVERLY_PERMISSIVE_MANAGED_POLICIES("Overly Permissive Managed Policies", Severity.MEDIUM),
    IAM_USERS_WITH_LONG_TERM_CREDENTIALS("Users having long-term credentials", Severity.LOW),
    IAM_USERS_WITH_ATTACHED_POLICIES("Users with Policies attached to them found", Severity.LOW),
    IAM_ACCESS_KEYS_NOT_ROTATED("Access Keys not Rotated in the last 90 days", Severity.INFO),
    IAM_ACCESS_KEYS_NOT_ROTATED_PRIVILEGED("Access Keys not rotated for users with access to services different than IAM or STS", Severity.MEDIUM),
    IAM_NO_ACCESS_KEYS_DURING_SETUP("Access Keys set up during initial user setup", Severity.LOW),

    KAFKA_BROKERS_WITHOUT_ENHANCED_MONITORING("MSK (Kafka) Brokers with enhanced monitoring disabled", Severity.LOW),
    KAFKA_CLUSTERS_WITHOUT_MTLS("MSK (Kafka) clusters with mutual TLS Authentication disabled", Severity.LOW),
    KAFKA_CLUSTERS_USING_OUTDATED_VERSION("MSK (Kafka) Clusters using outdated version", Severity.LOW),

    LAMBDA_FUNCTIONS_WITH_POTENTIAL_SECRETS("Secrets found in Lambda function config", Severity.CRITICAL),

    NETWORK_ACL_WITH_ALL_PORTS_OPEN_TO_INTERNET("Network ACL with every port open to the Internet", Severity.HIGH),
    NETWORK_ACL_WITH_SOME_PORTS_OPEN_TO_INTERNET("Network ACL Allow Ingress from the Internet", Severity.MEDIUM),

    RDS_MULTI_AZ_DISABLED("RDS instances with Multi-Availability Zone (Multi-AZ) disabled", Severity.LOW),
    RDS_IAM_AUTHENTICATION_DISABLED("RDS instances with IAM authentication disabled", Severity.LOW),
    RDS_AUTOMATED_BACKUPS_DISABLED("RDS Instances with automated Backups disabled", Severity.LOW),
    RDS_DELETION_PROTECTION_DISABLED("RDS instances with deletion protection disabled", Severity.LOW),
    RDS_ENHANCED_MONITORING_DISABLED("RDS Instances with enhanced monitoring disabled", Severity.LOW),
    RDS_DEPRECATED_ENGINE_VERSIONS("Deprecated Engine Version used by RDS Instances", Severity.MEDIUM),
    RDS_EVENT_SUBSCRIPTIONS_MISSING_CATEGORIES("Amazon RDS event notifications not subscribed", Severity.LOW),
    RDS_INSTANCES_USING_DEFAULT_MASTER_USERNAME("RDS Instances using default master username", Severity.INFO),
    RDS_CLIENT_CONNECTION_ENCRYPTION("RDS Instances client connections not encrypted", Severity.HIGH),
    RDS_CLOUDWATCH_LOGS_INTEGRATION("RDS Instances not integrated with CloudWatch Logs", Severity.LOW),
    RDS_STORAGE_ENCRYPTION("RDS Instances storage not encrypted", Severity.MEDIUM),
    RDS_SNAPSHOTS_ENCRYPTION("RDS Snapshots not encrypted", Severity.MEDIUM),
    RDS_CLUSTER_SNAPSHOTS_ENCRYPTION("RDS Cluster Snapshots not encrypted", Severity.MEDIUM),

    S3_BUCKETS_MFA_DELETE_DISABLED("S3 Buckets with MFA Delete Disabled", Severity.MEDIUM),
    S3_BUCKETS_ENCRYPTED_WITHOUT_SSE_KMS("S3 Buckets encrypted without SSE-KMS", Severity.MEDIUM),
    S3_BUCKETS_WITH_NO_SECURE_TRANSPORT_POLICY_SET("S3 Buckets with no Secure Transport policy set", Severity.MEDIUM),
    S3_BUCKETS_WITH_OBJECT_LOCK_DISABLED("S3 Buckets with Object Lock disabled", Severity.LOW),
    S3_BUCKETS_WITH_BUCKET_VERSIONING_DISABLED("S3 Buckets with Bucket Versioning disabled", Severity.LOW),
    S3_BUCKETS_WITH_SERVER_ACCESS_LOGGING_DISABLED("S3 Buckets with Server Access Logging disabled", Severity.LOW),
    S3_BUCKETS_WITH_ACL_ENABLED("S3 Buckets with ACL enabled", Severity.LOW),
    BLOCK_PUBLIC_ACCESS_S3_DISABLED("Block Public Access for S3 not Enabled", Severity.LOW),

    SNS_ENCRYPTION_WITHOUT_AWS_KMS("SNS Topics Encrypted without AWS KMS", Severity.HIGH),
    
    VPC_FIREWALL_DISABLED("VPCs without Network Firewall enabled", Severity.MEDIUM),
    VPC_FLOW_LOGGING_DISABLED("VPCs with Flow Logging disabled", Severity.LOW),
    VPC_SUBNETS_PUBLIC_IP_ON_LAUNCH("VPC Subnets Assign Public IPs by default", Severity.LOW),
    VPC_ENDPOINTS_ALLOW_FULL_ACCESS("VPC Endpoints Allow Full Access", Severity.LOW),
    VPCS_WITH_ONLY_PUBLIC_SUBNETS("VPCs with only Public subnets found", Severity.LOW)
    ;

    private final String title;
    private final Severity severity;

    AWSFinding(String title, Severity severity) {
        this.title = title;
        this.severity = severity;
    }

    public String getTitle() {
        return title;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getName() {
        return name();
    }

    @Override
    public String toString() {
        return title;
    }
}
