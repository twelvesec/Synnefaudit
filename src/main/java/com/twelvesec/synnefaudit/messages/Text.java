package com.twelvesec.synnefaudit.messages;

public enum Text {
    NO_DISTRIBUTIONS_FOUND("No distributions were found."),

    NO_CLOUDFORMATION_STACKS_FOUND("No CloudFormation stacks found."),

    EBS_NO_VOLUMES_FOUND("No EBS volumes found."),

    NO_EC2_INSTANCES_FOUND("No EC2 instances found."),
    NO_SECURITY_GROUPS_FOUND("No Security Groups found"),
    NO_NON_RFV1918_INGRESS_FOUND("No non-RFC1918 ingress rules."),
    INGRESS_FROM_NON_PRIVATE_CIDRS("Ingress from non-private CIDRs : "),
    NO_INSTANCES_USING_GROUP("No instances found using the group."),
    NO_LAUNCH_TEMPLATES_FOUND("No Launch Templates found."),
    NO_LAUNCH_TEMPLATE_VERSIONS_FOUND("No launch template versions found"),
    NO_TRANSIT_GATEWAYS_FOUND("No Transit Gateways found."),
    NO_AMIS_FOUND("No AMIs found."),
    NO_ACCOUNT_LEVEL_IMDS_DEFAULTS("No account-level IMDS defaults configured."),
    NO_COMPLIANCE_DATA_FOUND("No compliance data found."),
    NO_ELASTIC_IPS_FOUND("No Elastic IPs found."),
    NO_NETWORK_INTERFACES_FOUND("No Network Interfaces found."),
    NO_INSTANCES_ASSOCIATED_WITH_ADDRESS("No instances associated with this address."),
    INSTANCES_ASSOCIATED_WITH_ADDRESS("Instances found associated with this address."),

    ECR_NO_REPOSITORIES_FOUND("No repositories found."),
    ECR_NO_TAGGED_IMAGES_FOUND_IN_REPOSITORY("No tagged images found in repository."),
    ECR_NO_TAGGED_IMAGE_WITH_TIMESTAMP_FOUND("No tagged image with timestamp found."),
    ECR_LATEST_IMAGE_TAG_NO_FINDINGS("Most recent image tag '%s' has no findings."),
    ECR_FINDINGS_FOUND_FOR_IMAGE_TAG("Findings found for image tag '%s'."),

    NO_ELBS_FOUND("No ELBs found."),
    
    NO_VIRTUAL_MFA_FOR_ROOT("No virtual MFAs found for root account."),
    NO_MFA_DEVICES_FOR_USER("No MFA devices found for user."),
    NO_HARDWARE_MFA_DEVICES_FOR_ROOT("No Hardware MFA devices found for root account."),
    NO_GROUPS_FOUND("No groups found."),
    GROUP_WITHOUT_ADMINISTRATOR_ACCESS("Group does not have AdministratorAccess attached."),
    NO_USERS_IN_ADMINISTRATORACCESS_GROUPS("No users found in AdministratorAccess groups."),
    USERS_IN_ADMINISTRATORACCESS_GROUPS("Users found in groups with AdministratorAccess attached."),
    NO_USERS_WITH_CONSOLE_PASSWORD_FOUND("No users found with Console Password enabled."),

    NO_ACCOUNT_STATUS_FROM_INSPECTOR2("No account status returned from Inspector2."),
    INPSECTOR2_NO_FINDINGS("No findings found from Inspector2."),
    NO_STATUS_FOUND("No status found."),
    INSPECTOR2_NOT_ENABLED("Inspector2 is not enabled."),

    NO_SECRETS_MANAGER_SECRETS_FOUND("No Secrets Manager secrets found in account/region."),
    
    NO_RESPONSE_PLANS("No response plans found."),

    NO_CLOUDWATCH_ALARMS_CONFIGURED("No alarms have been configured."),
    NO_METRIC_FILTER_FOUND("No metric filter found for pattern: "),
    METRIC_FILTER_FOUND_WRONG_METRIC("Metric filter found but wrong metric name. Expected: "),
    NO_MATCHING_ALARMS_FOUND("No matching alarms found."),
    ALARM_IN_ALARM_STATE("Alarm found in alarm state: "),
    ALARM_ACTIVE_AND_OK("Alarm is active and ok: "),
        
    NO_PREMIUM_SUPPORT_SUBSCRIPTION_FOUND("No Premium Support Subscription found."),
    PREMIUM_SUPPORT_NOT_SUBSCRIBED("Amazon Web Services Premium Support Plan not subscribed: "),

    NO_LOG_GROUPS_FOUND("No CloudWatch Log Groups defined."),

    NO_KMS_KEYS_FOUND("No KMS Keys found."),
    KEY_IS_AWS_MANAGED("Key is AWS Managed."),
    KMS_KEY_SCHEDULED_FOR_DELETION("KMS key has been scheduled for deletion."),
    KMS_KEY_NOT_SCHEDULED_FOR_DELETION("KMS key has not been scheduled for deletion,"),
    KMS_KEY_IS_DISABLED("KMS key has been disabled."),
    KMS_KEY_NOT_CUSTOMER_MANAGED("KMS key is not customer managed."),
    NO_ROOT_ACCOUNT_ACCESS_KEY("No root account access key found."),
    ROOT_ACCOUNT_ACCESS_KEY_PRESENT("Root account access key found."),
    AGE_NUM_DAYS(" (Age: %d days)"),
    CREDENTIAL_REPORT_NO_CONTENT("Credential report has no content."),
    INVALID_CREDENTIAL_REPORT_FORMAT("Invalid credential report format: Expected at least 2 lines (header + data), got "),
    ROOT_NOT_IN_CREDENTIAL_REPORT("Root account not found in credential report."),

    NO_KMS_KEYS_FOUND_TO_INSPECT("No keys were found to inspect."),
    NO_PUBLIC_HOSTED_ZONES_FOUND("No public hosted zones found."),

    NO_REPORT_PLANS_FOUND("No report plans found."),

    NO_CLOUDTRAIL_TRAILS_CONFIGURED_FOUND("No CloudTrail trails found configured for account/region."),
    NO_ROOT_ACTIVITY_FOUND("No root activity found."),

    NO_RESOURCE_EXPLORER_INDEXES_FOUND("No Resource Explorer indexes found."),

    NO_CODEBUILD_PROJECTS_FOUND("No CodeBuild projects found."),
    NO_BUILDS_FOUND("No Builds found."),

    NO_ACM_CERTIFICATES_FOUND("No ACM Certificates found."),

    NO_ATHENA_WORKGROUPS_FOUND("No Athena Workgroups found."),

    NO_EFS_FILE_SYSTEM_FOUND("No EFS File Systems found."),

    GLUE_DATA_CATALOG_NOT_USED("Glue Data Catalog is not being used."),

    GUARDDUTY_DETECTORS_FOUND("GuardDuty detectors found: "),
    NO_GUARDDUTY_DETECTORS_FOUND("No GuardDuty detectors found."),

    NO_IAM_ACCESS_ANALYZER_FOUND("No IAM Access Analyzers found."),
    NO_IAM_ROLES_FOUND("No IAM roles found."),
    NO_IAM_ROLE_POLICIES_FOUND("No policies found for this role."),
    NO_IAM_USERS_FOUND("No IAM users found."),
    NO_FINDINGS("No findings."),
    NO_ACTIVE_ACCESS_KEYS_FOR_USER("No active access keys found for user."),
    PASSWORD_POLICY_NOT_SET("Password policy not set : "),
    PASSWORD_REUSE_PREVENTION("Password reuse prevention : "),
    NO_IAM_POLICIES_FOUND("No IAM Policies found."),
    ALLOWED_DANGEROUS_ACTIONS("Allowed Dangerous Actions : "),
    CROSS_ACCOUNT_PRINCIPALS_FOUND("Cross-account principals found : "),
    ONLY_SAME_ACCOUNT_OR_AWS_SERVICE_PRINCIPALS("Only same-account root or AWS service principals."),
    POLICY_OVERSCOPED_AND_ATTACHED("Policy is overscoped and attached."),
    POLICY_OVERSCOPED_BUT_UNATTACHED("Policy is overscoped but not attached."),
    POLICY_NOT_OVERSCOPED("Policy is not overscoped."),
    NO_ACCESS_KEYS_FOUND("No Access keys found."),
    NO_DANGEROUS_ACTIONS_FOUND("No Dangerous Actions found."),
    NO_MANAGED_POLICIES_FOUND("No managed policies found."),
    NO_NON_IAM_STS_POLICIES_ATTACHED("No non-IAM/STS policies attached."),
    FAILED_TO_RETRIEVE_PASSWORD_POLICY("Failed to retrieve password policy"),
    NO_CONSOLE_ACCESS("No console access."),
    No_INLINE_POLICIES("No inline policies found."),
    NO_IAM_CUSTOMER_MANAGED_POLICIES_FOUND("No customer-managed IAM policies found."),

    NO_SECURITY_AUDIT_ROLE_FOUND("No Security Audit role found."),
    NO_SUPPORT_ROLE_FOUND("No Support role found."),

    NO_CLUSTERS_FOUND("No Kafka Clusters found."),

    NO_LAMBDA_FUNCTIONS_FOUND("No Lambda Functions found."),

    NO_NETWORK_ACLS_FOUND("No Network ACLs found."),

    NO_RDS_INSTANCES_FOUND("No RDS Instances found."),
    NO_RDS_EVENT_SUBSCRIPTIONS_FOUND("No RDS event subscription found."),
    MISSING_EVENT_SUBSCRIPTIONS("Missing event subscriptions : "),
    NO_RDS_SNAPSHOTS_FOUND("No RDS Snapshots found."),
    NO_RDS_CLUSTER_SNAPSHOTS_FOUND("No RDS Cluster Snapshots found."),

    NO_S3_BUCKETS_FOUND("No S3 buckets found."),
    NO_ENCRYPTION_CONFIGURATION_FOUND("No encryption configuration found : "),
    NO_BUCKET_POLICY_FOUND("No bucket policy found : "),
    NO_OBJECT_LOCK_CONFIGURATION_FOUND("No Object Lock configuration found : "),
    ACLS_DISABLED("ACLs disabled (Bucket owner enforced) : "),
    NO_PUBLIC_ACCESS_BLOCK_CONFIGURATION_FOUND("No public access block configuration found : "),

    NO_ACCOUNT_ID_FOUND("Account Id could not be retrieved."),

    NO_SNS_TOPICS_FOUND("No SNS Topics found."),
    NO_HTTP_SUBSCRIPTIONS_FOUND("No HTTP Subscriptions found."),

    NO_SSM_DOCUMENTS_FOUND("No SSM Documents found."),

    NO_VPCS_FOUND("No VPCs found."),
    NO_VPC_SUBNETS_FOUND("No VPC subnets found."),
    NO_VPC_ENDPOINTS_FOUND("No VPC Endpoints found."),
    NO_FIREWALLS_ASSOCIATED_WITH_VPC("No Firewalls associated with VPC."),
    FLOW_LOGGING_DISABLED_FOR_VPC("Flow logging disabled for VPC."),

    NO_DYNAMODB_TABLES_FOUND("No DynamodDB tables were found."),

    NO_LIFECYCLE_POLICY_FOUND("No Lifecycle Policy found : "),

    ROUTE53_PUBLIC_HOSTED_ZONE_QUERY_LOGGING_DISABLED("Public Hosted Zone with query logging disabled : "),
    NO_HOSTED_ZONES_FOUND("No hosted zones found."),
    NO_A_RECORDS_FOUND_IN_HOSTED_ZONES("No A records found in any hosted zone"),

    NO_WAF_WEB_ACLS_FOUND("No WAF WebACLs found"),
    LOGGING_ENABLED_FOR_WEBACL("Logging enabled for WebACL : "),
    NO_LOGGING_CONFIGURATION_FOUND("No logging configuration found : "),

    EFS_FILE_SYSTEM_WITH_BACKUP_DISABLED("EFS File System with backup disabled : "),
    EFS_NO_POLICY_FOUND("No policy found : "),

    NO_ALTERNATE_CONTACTS_FOUND("No alternate contacts found : "),

    NO_INSIGHT_SELECTORS("No Insight Selectors : "),

    POLICY_AMAZON_VPC_ENDPOINT_FULL_ACCESS("arn:aws:iam::aws:policy/AmazonVPCEndpointFullAccess"),

    UNSUPPORTED_CLIENT("Unsupported client : "),
    FAILED_TO_CLOSE_CLIENT("Failed to close client : "),

    EXCEPTION("Exception : "),
    CREDENTIAL_REPORT_GEN_TIMEOUT("Credential report generation timeout."),
    
    CHECKNAME("check-name"),
    STATUS("status"),
    RESULT("result"),
    DATA("data"),
    SEVERITY("severity"),
    EGRESS("Egress"),
    INGRESS("Ingress"),
    MESSAGE("message"),
    ERROR("error"),
    POLICY("policy"),
    POLICYUSERS("PolicyUsers"),
    POLICYROLES("PolicyRoles"),
    POLICYGROUPS("PolicyGroups"),
    POLICYDOC("policyDocument"),
    ENTITIES("entities"),
    FINDINGS("findings"),
    AGEINDAYS("ageInDays"),
    AGESTATUS("ageStatus"),
    ATTACHEDPOLICIES("attachedPolicies"),
    ACCESSKEYS("accessKeys"),
    LOGIN_PROFILE("loginProfile"),
    USER("user"),
    USERCREATIONDATE("userCreationDate"),
    USERS_WITH_MFA("usersWithMFA"),
    USERS_WITHOUT_MFA("usersWithoutMFA"),
    AWSACCOUNTID("AWSAccountId"),
    LAST_USED_DATE("lastUsedDate"),
    ALARMS("alarms"),
    METRIC_FILTERS("metricFilters"),
    KEY_METADATA("keyMetadata"),

    NULL_VALUE("Value is null.")
    ;

    private final String text;

    Text(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

    public String getName() {
        return name();
    }

    @Override
    public String toString() {
        return text;
    }
}
