# Create enum for each Label type.
enum LabelType {
    # Below Labels are for building Signals for automated background events that we
    # want to mark as "handled" but do not want to contribute to other Signal mappings
    # and that we likely want to easily hide from final view.
    SuppressAutomatedBackgroundEvent
    SuppressAutomatedBackgroundEvent_CloudShell_Heartbeat
    SuppressAutomatedBackgroundEvent_EC2_EC2Dashboard
    SuppressAutomatedBackgroundEvent_EC2_LoadBalancing_TrustStores
    SuppressAutomatedBackgroundEvent_SecretsManager_Secrets_SPECIFICSECRET
    #
    # Below generic Labels are for extremely simple definitions (read "single-event")
    # that are defined once and then copied to be used by more specific Signals.
    # This approach is generally to avoid clobbering scenarios.
    Generic_CloudTrail_ListEventDataStores
    Generic_EC2_ApplicationAndOSImages_Search
    Generic_EC2_ApplicationAndOSImages_Select
    Generic_EC2_KeyPair_Create
    Generic_EC2_KeyPair_Select
    Generic_EC2_List_SecurityGroups
    Generic_Organizations_ListDelegatedAdministrators
    Generic_S3_List_Buckets
    #
    # Remaining Labels are listed below.
    AWSMarketplace
    AWSMarketplace_Suboption
    Billing_Home
    CloudShell_Actions_DownloadFile
    CloudShell_Actions_UploadFile
    CloudShell_ExitSession
    CloudShell_InteractiveCommand_AWSCLI
    CloudShell_InteractiveCommand_AWSPowerShell
    CloudShell_InteractiveCommand_Boto
    CloudShell_InteractiveCommand_Generic
    CloudShell_NewSession
    CloudShell_RenewSession
    CloudTrail_Dashboard
    CloudTrail_Dashboard_CreateTrail_Step1
    CloudTrail_Dashboard_CreateTrail_Step2
    CloudTrail_EventHistory
    CloudTrail_EventHistory_SPECIFICEVENT
    CloudTrail_Insights
    CloudTrail_Insights_Scenario2
    CloudTrail_Insights_SPECIFICINSIGHT
    CloudTrail_Lake_Dashboard
    CloudTrail_Lake_EventDataStores
    CloudTrail_Lake_EventDataStores_Create_Step1
    CloudTrail_Lake_Integrations
    CloudTrail_Lake_Query
    CloudTrail_Settings
    CloudTrail_Settings_Scenario2
    CloudTrail_Trails
    CloudTrail_Trails_SPECIFICTRAIL
    CloudTrail_Trails_SPECIFICTRAIL_Delete
    CloudTrail_Trails_SPECIFICTRAIL_StopLogging
    ConsoleHome
    ConsoleLogin
    EC2_AutoScaling_AutoScalingGroups
    EC2_BrowserRefresh
    EC2_ConsoleToCode
    EC2_EC2Dashboard
    EC2_EC2Dashboard_AccountAttributes_Refresh
    EC2_EC2Dashboard_Resources_Refresh
    EC2_EC2Dashboard_Resources_Settings
    EC2_EC2Dashboard_ScheduledEvents_Refresh
    EC2_EC2Dashboard_ServiceHealth_Refresh
    EC2_EC2Dashboard_Settings_DefaultCreditSpecification
    EC2_EC2Dashboard_Settings_EBSEncryption
    EC2_EC2Dashboard_Settings_EC2SerialConsole
    EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Allow
    EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Disallow
    EC2_EC2Dashboard_Settings_Zones
    EC2_EC2GlobalView_RegionExplorer
    EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
    EC2_ElasticBlockStore_Lifecycle
    EC2_ElasticBlockStore_Snapshots
    EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details
    EC2_ElasticBlockStore_Volumes
    EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
    EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_StatusChecks
    EC2_Events
    EC2_Images_AMICatalog
    EC2_Images_AMICatalog_SearchBySystemsManagerParameter
    EC2_Images_AMIs
    EC2_Images_AMIs_SPECIFICIMAGE_Details
    EC2_Images_AMIs_SPECIFICIMAGE_Storage
    EC2_Instances_CapacityReservations
    EC2_Instances_CapacityReservations_CreateCapacityReservation_Step1
    EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2
    EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION
    EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
    EC2_Instances_DedicatedHosts
    EC2_Instances_Instances
    EC2_Instances_Instances_LaunchInstance_Step1
    EC2_Instances_Instances_LaunchInstance_Step1_ApplicationAndOSImages_Search
    EC2_Instances_Instances_LaunchInstance_Step1_ApplicationAndOSImages_Select
    EC2_Instances_Instances_LaunchInstance_Step1_ConfigureStorage_ViewBackupInformation
    EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Create
    EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Select
    EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Key
    EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Value
    EC2_Instances_Instances_LaunchInstance_Step1_NetworkSettings_FirewallSecurityGroup_Select
    EC2_Instances_Instances_LaunchInstance_Step2
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Terminate
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
    EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Terminate
    EC2_Instances_Instances_SPECIFICINSTANCE_Details
    EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
    EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance
    EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
    EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance
    EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
    EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance
    EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1
    EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step1
    EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
    EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2
    EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring
    EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring
    EC2_Instances_Instances_SPECIFICINSTANCE_Security
    EC2_Instances_Instances_SPECIFICINSTANCE_Storage
    EC2_Instances_InstanceTypes
    EC2_Instances_LaunchTemplates
    EC2_Instances_LaunchTemplates_Scenario2
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_ApplicationAndOSImages_Search
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_ApplicationAndOSImages_Select
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_InstanceType
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Select
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Create
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_CreateSecurityGroup
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_SelectExistingSecurityGroup
    EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step2
    EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete
    EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Details
    EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Versions
    EC2_Instances_ReservedInstances
    EC2_Instances_SpotRequests
    EC2_Instances_SpotRequests_PlacementScore_Step1
    EC2_Instances_SpotRequests_PlacementScore_Step2
    EC2_Instances_SpotRequests_PricingHistory
    EC2_Instances_SpotRequests_SavingsSummary
    EC2_Instances_SpotRequests_SpotBlueprints
    EC2_Limits
    EC2_LoadBalancing_LoadBalancers
    EC2_LoadBalancing_TargetGroups
    EC2_LoadBalancing_TrustStores
    EC2_LoadBalancing_TrustStores_CreateTrustStore_Step1_BrowseS3
    EC2_NetworkSecurity_ElasticIPs
    EC2_NetworkSecurity_KeyPairs
    EC2_NetworkSecurity_NetworkInterfaces
    EC2_NetworkSecurity_PlacementGroups
    EC2_NetworkSecurity_SecurityGroups
    EC2_NetworkSecurity_SecurityGroups_SPECIFICGROUP
    Expanded_SPECIFICMANAGEDPOLICY
    Expanded_SPECIFICINLINEUSERPOLICY
    GuardDuty_Accounts
    GuardDuty_Findings
    GuardDuty_MalwareScans
    GuardDuty_ProtectionPlans_MalwareProtection
    GuardDuty_ProtectionPlans_MalwareProtection_GeneralSettings_RetainScannedSnapshots_Disable
    GuardDuty_ProtectionPlans_MalwareProtection_GeneralSettings_RetainScannedSnapshots_Enable
    GuardDuty_ProtectionPlans_Suboption_ConfigurationNotAvailable
    GuardDuty_Settings
    GuardDuty_Settings_GenerateSampleFindings
    GuardDuty_Settings_Lists
    GuardDuty_Summary
    GuardDuty_Usage
    IAM
    IAM_AccountSettings
    IAM_BrowserRefresh
    IAM_IdentityCenter
    IAM_Policies
    IAM_Policies_NextPage
    IAM_Roles
    IAM_Roles_SPECIFICROLE_Permissions
    IAM_UserGroups
    IAM_UserGroups_CreateUserGroup
    IAM_UserGroups_DeleteUserGroup
    IAM_Users
    IAM_Users_CreateUser_Step1
    IAM_Users_CreateUser_Step2
    IAM_Users_SPECIFICUSER_AccessAdvisor
    IAM_Users_SPECIFICUSER_Delete
    IAM_Users_SPECIFICUSER_Permissions
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CopyPermissions
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step2
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3
    IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
    IAM_Users_SPECIFICUSER_Permissions_RemoveInlinePolicyForUser
    IAM_Users_SPECIFICUSER_Permissions_RemoveManagedPolicyForUser
    IAM_Users_SPECIFICUSER_SecurityCredentials
    IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Activate
    IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_CreateAccessKey
    IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Deactivate
    IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Delete
    IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess
    IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Disable
    IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable
    IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Update
    IAM_Users_SPECIFICUSER_Tags
    KMS
    KMS_AWSManagedKeys
    KMS_CustomerManagedKeys
    KMS_CustomerManagedKeys_CreateKey_Step1
    KMS_CustomerManagedKeys_CreateKey_Step2
    KMS_CustomerManagedKeys_CreateKey_Step3
    KMS_CustomerManagedKeys_CreateKey_Step4
    KMS_CustomerManagedKeys_SPECIFICKEY_CryptographicConfiguration
    KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy
    KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation
    KMS_CustomerManagedKeys_SPECIFICKEY_Tags
    KMS_CustomKeyStores_AWSCloudHSMKeyStores
    KMS_CustomKeyStores_ExternalKeyStores
    S3_AccessPoints
    S3_BatchOperations
    S3_BlockPublicAccessSettings
    S3_Buckets
    S3_Buckets_CreateBucket_Step1
    S3_Buckets_CreateBucket_Step1B
    S3_Buckets_CreateBucket_Step2
    S3_Buckets_DeleteBucket_Step1
    S3_Buckets_DeleteBucket_Step2
    S3_Buckets_EmptyBucket
    S3_Buckets_SPECIFICBUCKET_AccessPoints
    S3_Buckets_SPECIFICBUCKET_Management
    S3_Buckets_SPECIFICBUCKET_Metrics
    S3_Buckets_SPECIFICBUCKET_Objects
    S3_Buckets_SPECIFICBUCKET_Permissions
    S3_Buckets_SPECIFICBUCKET_Properties
    S3_IAMAccessAnalyzer
    S3_MultiRegionAccessPoints
    S3_ObjectLambdaAccessPoints
    S3_StorageLens_AWSOrganizationsSettings
    S3_StorageLens_Dashboards
    SearchBar
    SecretsManager_Secrets
    SecretsManager_Secrets_Create_Step1
    SecretsManager_Secrets_Create_Step2
    SecretsManager_Secrets_Create_Step3
    SecretsManager_Secrets_Create_Step4
    SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
    SecretsManager_Secrets_SPECIFICSECRET_Delete
    SecretsManager_Secrets_SPECIFICSECRET_Overview
    SecretsManager_Secrets_SPECIFICSECRET_Overview_RetrieveSecretValue
    SecretsManager_Secrets_SPECIFICSECRET_Versions
    VPC_VirtualPrivateCloud_Endpoints
    VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1
    VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B
    VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
    VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
    VPC_VPCDashboard
    VPC_VPCDashboard_CustomerGateways_Refresh
    VPC_VPCDashboard_DHCPOptionSets_Refresh
    VPC_VPCDashboard_EgressOnlyInternetGateways_Refresh
    VPC_VPCDashboard_ElasticIPs_Refresh
    VPC_VPCDashboard_Endpoints_Refresh
    VPC_VPCDashboard_EndpointServices_Refresh
    VPC_VPCDashboard_InternetGateways_Refresh
    VPC_VPCDashboard_NATGateways_Refresh
    VPC_VPCDashboard_NetworkACLs_Refresh
    VPC_VPCDashboard_RouteTables_Refresh
    VPC_VPCDashboard_RunningInstances_Refresh
    VPC_VPCDashboard_SecurityGroups_Refresh
    VPC_VPCDashboard_SiteToSiteVPNConnections_Refresh
    VPC_VPCDashboard_Subnets_Refresh
    VPC_VPCDashboard_VirtualPrivateGateways_Refresh
    VPC_VPCDashboard_VPCPeeringConnections_Refresh
    VPC_VPCDashboard_VPCs_Refresh
}



# Define class for storing Enrichment metadata to be added to each input raw event.
class Enrichment
{
    # Create required properties.
    #
    # List of labels for which current event matches.
    [LabelType[]] $Labels
    # Set to $true if any applied labels are defined as a RequiredEvent in any of the
    # corresponding Signal definitions.
    [System.Boolean] $IsAnchor = $false
    # Instance of modified Signal class added here if a Signal is successfully mapped
    # (with any customized values defined during evaluation process).
    [Signal] $Signal = $null
    # Set to $true for all events that have contributed to generating a Signal.
    [System.Boolean] $IsSignalContributor = $false
    # Updated to eventID of AnchorEvent if Signal is generated.
    [System.String] $CorrelationId = $null
    # Single string value for readability and precision (e.g. combining eventSource and
    # eventName in AWS events so 'iam:CreateAccessKey' instead of separate
    # 'iam.amazonaws.com' and 'CreateAccessKey' values).
    [ValidateNotNullOrEmpty()] [System.String] $EventNameFull
    #
    # Additional statistics updated if Signal successfully mapped.
    [System.Int16] $EventCount = $null
    [System.DateTime] $FirstEventTime
    [System.DateTime] $LastEventTime
    [System.Int64] $DurationInSeconds = $null
}

# Define class for storing Signal metadata.
class Signal
{
    # Create required properties.
    [ValidateNotNullOrEmpty()] [LabelType] $Label
    [ValidateNotNullOrEmpty()] [System.String] $Service
    [ValidateNotNullOrEmpty()] [System.String] $Name
    [ValidateNotNullOrEmpty()] [System.String] $Summary
    [ValidateNotNullOrEmpty()] [System.String] $Url
    [ValidateNotNullOrEmpty()] [System.Collections.Hashtable] $AdditionalData
    [ValidateNotNullOrEmpty()] [System.String[]] $AnchorEvents
    [ValidateNotNullOrEmpty()] [System.String[]] $RequiredEvents
                               [System.String[]] $OptionalEvents = @()
    [ValidateNotNullOrEmpty()] [System.Double] $LookbackInSeconds = 3
    [ValidateNotNullOrEmpty()] [System.Double] $LookaheadInSeconds = 3

    # Constructor mapping input LabelType enum value to Signal definition.
    Signal ([LabelType] $LabelType)
    {
        $this.Label = $LabelType

        switch ($LabelType)
        {
            # Below Signals are for automated background events that we want to mark as "handled"
            # but do not want to contribute to other Signal mappings and that we likely want to
            # easily hide from final view.
            ([LabelType]::SuppressAutomatedBackgroundEvent) {
                $this.Service        = 'N/A'
                $this.Name           = 'Suppressing automated background event'
                $this.Summary        = 'Suppressing automated background event not contributing to any mapping scenario.'
                $this.Url            = 'N/A'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('health:DescribeEventAggregates','logs:DescribeMetricFilters','monitoring:DescribeAlarms','notifications:ListNotificationEvents','notifications:ListNotificationHubs')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('health:DescribeEventAggregates','logs:DescribeMetricFilters','monitoring:DescribeAlarms','notifications:ListNotificationEvents','notifications:ListNotificationHubs')
            }
            ([LabelType]::SuppressAutomatedBackgroundEvent_CloudShell_Heartbeat) {
                $this.Service        = 'N/A'
                $this.Name           = 'Suppressing automated background event'
                $this.Summary        = 'Suppressing automated background event not contributing to any mapping scenario.'
                $this.Url            = 'N/A'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('cloudshell:SendHeartBeat')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('cloudshell:SendHeartBeat')
            }
            ([LabelType]::SuppressAutomatedBackgroundEvent_EC2_EC2Dashboard) {
                $this.Service        = 'N/A'
                $this.Name           = 'Suppressing automated background event'
                $this.Summary        = 'Suppressing automated background event not contributing to any mapping scenario.'
                $this.Url            = 'N/A'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('health:DescribeEvents','monitoring:DescribeAlarms')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('health:DescribeEvents','monitoring:DescribeAlarms')
            }
            ([LabelType]::SuppressAutomatedBackgroundEvent_EC2_LoadBalancing_TrustStores) {
                $this.Service        = 'N/A'
                $this.Name           = 'Suppressing automated background event'
                $this.Summary        = 'Suppressing automated background event not contributing to any mapping scenario.'
                $this.Url            = 'N/A'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('elasticloadbalancing:DescribeTrustStores')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('elasticloadbalancing:DescribeTrustStores')
            }
            ([LabelType]::SuppressAutomatedBackgroundEvent_SecretsManager_Secrets_SPECIFICSECRET) {
                $this.Service        = 'N/A'
                $this.Name           = 'Suppressing automated background event'
                $this.Summary        = 'Suppressing automated background event not contributing to any mapping scenario.'
                $this.Url            = 'N/A'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('secretsmanager:DescribeSecret')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('secretsmanager:DescribeSecret')
            }
            #
            # Below generic Signals are for extremely simple definitions (read "single-event")
            # that are defined once and then copied to be used by more specific Signals.
            # This approach is generally to avoid clobbering scenarios.
            ([LabelType]::Generic_CloudTrail_ListEventDataStores) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('cloudtrail:ListEventDataStores')
                $this.RequiredEvents = @('cloudtrail:ListEventDataStores')
            }
            ([LabelType]::Generic_EC2_ApplicationAndOSImages_Search) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('ec2:DescribeImages','ec2:DescribeInstanceTypeOfferings')
                $this.RequiredEvents = @('discovery-marketplace:GetSearchFacets','discovery-marketplace:SearchListings','ec2:DescribeImages','ec2:DescribeInstances','ec2:DescribeInstanceTypeOfferings','ec2:DescribeSecurityGroups')
            }
            ([LabelType]::Generic_EC2_ApplicationAndOSImages_Select) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('ec2:DescribeSecurityGroups','ec2:DescribeInstanceTypeOfferings')
                $this.RequiredEvents = @('ec2:DescribeImages','ec2:DescribeInstances','ec2:DescribeInstanceTypeOfferings','ec2:DescribeSecurityGroups','ec2:DescribeSnapshots','ec2:DescribeSubnets')
                $this.OptionalEvents = @('ec2:DescribeVpcs')
            }
            ([LabelType]::Generic_EC2_KeyPair_Create) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('ec2:DescribeKeyPairs')
                $this.RequiredEvents = @('ec2:CreateKeyPair','ec2:DescribeKeyPairs')
            }
            ([LabelType]::Generic_EC2_KeyPair_Select) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('ec2:DescribeKeyPairs')
                $this.RequiredEvents = @('ec2:DescribeKeyPairs')
            }
            ([LabelType]::Generic_EC2_List_SecurityGroups) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('ec2:DescribeSecurityGroups')
                $this.RequiredEvents = @('ec2:DescribeSecurityGroups')
            }
            ([LabelType]::Generic_Organizations_ListDelegatedAdministrators) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('organizations:ListDelegatedAdministrators')
                $this.RequiredEvents = @('organizations:ListDelegatedAdministrators')
            }
            ([LabelType]::Generic_S3_List_Buckets) {
                $this.Service        = 'N/A'
                $this.Name           = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Summary        = 'GENERIC SIGNAL - meant to be mapped and modified by more specific scenarios.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('s3:ListBuckets')
                $this.RequiredEvents = @('s3:ListBuckets')
            }
            #
            # Remaining Signals are listed below.
            ([LabelType]::AWSMarketplace) {
                $this.Service        = 'N/A'
                $this.Name           = 'Clicked AWS Marketplace'
                $this.Summary        = 'Clicked AWS Marketplace to search all AWS Marketplace products.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/marketplace?region={{awsRegion}}'
                $this.AnchorEvents   = @('discovery-marketplace:SearchListings')
                $this.RequiredEvents = @('discovery-marketplace:SearchListings')
            }
            ([LabelType]::AWSMarketplace_Suboption) {
                $this.Service        = 'N/A'
                $this.Name           = 'Clicked AWS Marketplace->Suboption'
                $this.Summary        = 'Clicked AWS Marketplace->Suboption to search specific subset of AWS Marketplace products.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/marketplace?region={{awsRegion}}'
                $this.AnchorEvents   = @('discovery-marketplace:SearchListings')
                $this.RequiredEvents = @('discovery-marketplace:SearchListings')
            }
            ([LabelType]::Billing_Home) {
                $this.Service        = 'N/A'
                $this.Name           = 'Clicked Billing->Home'
                $this.Summary        = 'Clicked Billing->Home which displays an overview of AWS costs and key metrics for account.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/billing/home?region={{awsRegion}}#/'
                $this.AnchorEvents   = @('billingconsole:GetBillingNotifications','ec2:DescribeRegions')
                $this.RequiredEvents = @('billingconsole:GetBillingNotifications','ec2:DescribeRegions')
            }
            ([LabelType]::CloudShell_Actions_DownloadFile) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Clicked CloudShell->Actions->Download File'
                $this.Summary        = "Clicked CloudShell->Actions->Download File to download '{{fileDownloadPath}}' file from interactive CloudShell session with '{{environmentId}}' Environment ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudshell/home?region={{awsRegion}}#{{environmentId}}'
                $this.AnchorEvents   = @('cloudshell:GetFileDownloadUrls')
                $this.RequiredEvents = @('cloudshell:CreateSession','cloudshell:GetEnvironmentStatus','cloudshell:GetFileDownloadUrls')
                $this.OptionalEvents = @('cloudshell:DeleteSession')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 5
            }
            ([LabelType]::CloudShell_Actions_UploadFile) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Clicked CloudShell->Actions->Upload File'
                $this.Summary        = "Clicked CloudShell->Actions->Upload File to upload '{{fileUploadPath}}' file to interactive CloudShell session with '{{environmentId}}' Environment ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudshell/home?region={{awsRegion}}#{{environmentId}}'
                $this.AnchorEvents   = @('cloudshell:GetFileUploadUrls')
                $this.RequiredEvents = @('cloudshell:CreateSession','cloudshell:DeleteSession','cloudshell:GetEnvironmentStatus','cloudshell:GetFileUploadUrls')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 5
            }
            ([LabelType]::CloudShell_ExitSession) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Clicked CloudShell->Exit'
                $this.Summary        = "Clicked CloudShell->Exit to exit interactive CloudShell session with '{{environmentId}}' Environment ID and '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudshell/home?region={{awsRegion}}#{{environmentId}}'
                $this.AnchorEvents   = @('cloudshell:DeleteSession')
                $this.RequiredEvents = @('cloudshell:DeleteSession')
                $this.OptionalEvents = @('cloudshell:GetEnvironmentStatus')
            }
            ([LabelType]::CloudShell_InteractiveCommand_AWSCLI) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Executed interactive command in CloudShell via AWS CLI'
                $this.Summary        = "Interactively executed '{{EventNameFull}}' in CloudShell session via AWS CLI."
                $this.Url            = 'N/A'
                # This is a unique scenario since it is based solely on userAgent and not on particular eventName value.
                $this.AnchorEvents   = @('*')
                $this.RequiredEvents = @('*')
            }
            ([LabelType]::CloudShell_InteractiveCommand_AWSPowerShell) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Executed interactive command in CloudShell via AWS Tools for PowerShell'
                $this.Summary        = "Interactively executed '{{EventNameFull}}' in CloudShell session via AWS Tools for PowerShell."
                $this.Url            = 'N/A'
                # This is a unique scenario since it is based solely on userAgent and not on particular eventName value.
                $this.AnchorEvents   = @('*')
                $this.RequiredEvents = @('*')
            }
            ([LabelType]::CloudShell_InteractiveCommand_Boto) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Executed interactive command in CloudShell via Boto Python SDK'
                $this.Summary        = "Interactively executed '{{EventNameFull}}' in CloudShell session via Boto Python SDK."
                $this.Url            = 'N/A'
                # This is a unique scenario since it is based solely on userAgent and not on particular eventName value.
                $this.AnchorEvents   = @('*')
                $this.RequiredEvents = @('*')
            }
            ([LabelType]::CloudShell_InteractiveCommand_Generic) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Executed interactive command in CloudShell via generic SDK'
                $this.Summary        = "Interactively executed '{{EventNameFull}}' in CloudShell session via generic SDK."
                $this.Url            = 'N/A'
                # This is a unique scenario since it is based solely on userAgent and not on particular eventName value.
                $this.AnchorEvents   = @('*')
                $this.RequiredEvents = @('*')
            }
            ([LabelType]::CloudShell_NewSession) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Clicked CloudShell (to create new session)'
                $this.Summary        = "Clicked CloudShell which launched pre-authenticated browser-based interactive shell with '{{environmentId}}' Environment ID and '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudshell/home?region={{awsRegion}}#{{environmentId}}'
                $this.AnchorEvents   = @('cloudshell:CreateSession')
                $this.RequiredEvents = @('cloudshell:CreateEnvironment','cloudshell:CreateSession','cloudshell:GetEnvironmentStatus','cloudshell:GetLayout','cloudshell:PutCredentials','cloudshell:RedeemCode','cloudshell:UpdateLayout')
                $this.OptionalEvents = @('cloudshell:StartEnvironment','sts:GetCallerIdentity')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 10
                $this.LookaheadInSeconds = 10
            }
            ([LabelType]::CloudShell_RenewSession) {
                $this.Service        = 'CloudShell'
                $this.Name           = 'Automatically renewed existing CloudShell session'
                $this.Summary        = "Automatically renewed existing CloudShell session with '{{environmentId}}' Environment ID and '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudshell/home?region={{awsRegion}}#{{environmentId}}'
                $this.AnchorEvents   = @('cloudshell:CreateSession','cloudshell:DeleteSession')
                $this.RequiredEvents = @('cloudshell:CreateSession','cloudshell:DeleteSession','cloudshell:GetEnvironmentStatus','cloudshell:GetLayout','cloudshell:PutCredentials','cloudshell:RedeemCode','cloudshell:UpdateLayout')
                $this.OptionalEvents = @('cloudshell:CreateEnvironment','sts:GetCallerIdentity')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 10
            }
            ([LabelType]::CloudTrail_Dashboard) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Dashboard'
                $this.Summary        = 'Clicked CloudTrail->Dashboard which displays a summary of all CloudTrail components (e.g. Trails statuses, Insights and last 5 Events).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/dashboard'
                $this.AnchorEvents   = @('cloudtrail:DescribeTrails','cloudtrail:LookupEvents')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetTrailStatus','cloudtrail:LookupEvents')
                $this.OptionalEvents = @('ec2:DescribeRegions','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','s3:ListBuckets')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 10
                $this.LookaheadInSeconds = 3
            }
            ([LabelType]::CloudTrail_Dashboard_CreateTrail_Step1) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Dashboard->CreateTrail (Step 1 of 2)'
                $this.Summary        = 'Clicked CloudTrail->Dashboard->CreateTrail (Step 1 of 2) to create a CloudTrail Trail.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/create'
                $this.AnchorEvents   = @('cloudtrail:DescribeTrails')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetEventSelectors','cloudtrail:GetTrailStatus')
            }
            ([LabelType]::CloudTrail_Dashboard_CreateTrail_Step2) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Dashboard->CreateTrail (Step 2 of 2)'
                $this.Summary        = "Clicked CloudTrail->Dashboard->CreateTrail (Step 2 of 2) to create '{{trailName}}' CloudTrail Trail with ARN '{{trailArn}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/create'
                $this.AnchorEvents   = @('cloudtrail:DescribeTrails')
                $this.RequiredEvents = @('cloudtrail:CreateTrail','cloudtrail:DescribeTrails','cloudtrail:GetTrailStatus','cloudtrail:PutEventSelectors','cloudtrail:PutInsightSelectors','cloudtrail:StartLogging')
                $this.OptionalEvents = @('kms:CreateAlias','kms:CreateKey','s3:CreateBucket','s3:GetBucketLocation','s3:PutBucketPolicy','s3:PutBucketPublicAccessBlock')
            }
            ([LabelType]::CloudTrail_EventHistory) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Event History'
                $this.Summary        = 'Clicked CloudTrail->Event History which displays all CloudTrail Events in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/events'
                $this.AnchorEvents   = @('cloudtrail:LookupEvents','config:DescribeConfigurationRecorders')
                $this.RequiredEvents = @('cloudtrail:LookupEvents')
                # config:DescribeConfigurationRecorders and config:DescribeConfigurationRecorderStatus events are only executed for default Event history filter
                # with default attribute lookup values and no time filter applied.
                # config:ListDiscoveredResources event is only executed if displayed results contain populated value in 'Resource type' column.
                $this.OptionalEvents = $this.OptionalEvents = @('config:DescribeConfigurationRecorders','config:DescribeConfigurationRecorderStatus','config:ListDiscoveredResources','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators')
                # Current mapping scenario can generate numerous single-event scenarios in close proximity, so decreasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 1
                $this.LookaheadInSeconds = 1
            }
            ([LabelType]::CloudTrail_EventHistory_SPECIFICEVENT) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Event History->SPECIFICEVENT'
                $this.Summary        = 'Clicked CloudTrail->Event History->SPECIFICEVENT which displays all details for specific CloudTrail Event.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/events'
                $this.AnchorEvents   = @('config:DescribeConfigurationRecorders')
                $this.RequiredEvents = @('config:DescribeConfigurationRecorders','config:DescribeConfigurationRecorderStatus')
                # config:ListDiscoveredResources event is only executed if specific CloudTrail event has a 'Resource type' value populated in the 'Resources referenced' section.
                $this.OptionalEvents = @('config:ListDiscoveredResources')
                # Current mapping scenario can generate numerous single-event scenarios in close proximity, so decreasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 1
                $this.LookaheadInSeconds = 1
            }
            ([LabelType]::CloudTrail_Insights) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Insights'
                $this.Summary        = "Clicked CloudTrail->Insights which displays all CloudTrail Logging Insights events (if enabled)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/insights'
                $this.AnchorEvents   = @('cloudtrail:LookupEvents','cloudtrail:DescribeTrails')
                $this.RequiredEvents = @('cloudtrail:LookupEvents')
                $this.OptionalEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetTrailStatus')
            }
            ([LabelType]::CloudTrail_Insights_Scenario2) {
                # This mapping scenario will only be used as a secondary Signal definition for [LabelType]::CloudTrail_Insights
                # so it will always replicate its Service, Name, Summary and Url properties.
                $this.Service        = [Signal]::new([LabelType]::CloudTrail_Insights).Service
                $this.Name           = [Signal]::new([LabelType]::CloudTrail_Insights).Name
                $this.Summary        = [Signal]::new([LabelType]::CloudTrail_Insights).Summary
                $this.Url            = [Signal]::new([LabelType]::CloudTrail_Insights).Url
                $this.AnchorEvents   = @('organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','cloudtrail:DescribeTrails','cloudtrail:LookupEvents')
                $this.RequiredEvents = @('cloudtrail:GetTrail','cloudtrail:GetTrailStatus','cloudtrail:ListTrails','cloudtrail:LookupEvents','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators')
            }
            ([LabelType]::CloudTrail_Insights_SPECIFICINSIGHT) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Insights->SPECIFICINSIGHT'
                $this.Summary        = "Clicked CloudTrail->Insights->SPECIFICINSIGHT to view CloudTrail Logging Insight details for '{{eventName}}' Event Name with '{{eventId}}' Event ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/insights/{{eventId}}'
                $this.AnchorEvents   = @('organizations:DescribeOrganization')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:LookupEvents','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','s3:ListBuckets')
            }
            ([LabelType]::CloudTrail_Lake_Dashboard) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Lake->Dashboard'
                $this.Summary        = 'Clicked CloudTrail->Lake->Dashboard which displays steps for getting started with using CloudTrail Lake.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrailv2/home?region={{awsRegion}}#/lake'
                $this.AnchorEvents   = @('cloudtrail:ListEventDataStores','organizations:ListDelegatedAdministrators')
                $this.RequiredEvents = @('cloudtrail:ListEventDataStores','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators')
            }
            ([LabelType]::CloudTrail_Lake_EventDataStores) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Lake->Event Data Stores'
                $this.Summary        = 'Clicked CloudTrail->Lake->Event Data Stores which displays all CloudTrail Event Data Stores in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrailv2/home?region={{awsRegion}}#/lake/eventDataStores'
                $this.AnchorEvents   = @('cloudtrail:ListEventDataStores','organizations:ListDelegatedAdministrators')
                $this.RequiredEvents = @('cloudtrail:GetTrail','cloudtrail:GetTrailStatus','cloudtrail:ListEventDataStores','cloudtrail:ListTrails','iam:ListRoles','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators')
            }
            ([LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Lake->Event Data Stores->Create (Step 1 of 2)'
                $this.Summary        = 'Clicked CloudTrail->Lake->Event Data Stores->Create (Step 1 of 2) to create a new CloudTrail Event Data Store.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrailv2/home?region={{awsRegion}}#/lake/create'
                $this.AnchorEvents   = @('cloudtrail:ListEventDataStores')
                $this.RequiredEvents = @('cloudtrail:GetTrail','cloudtrail:GetTrailStatus','cloudtrail:ListEventDataStores','cloudtrail:ListTrails','iam:ListRoles','kms:ListAliases','kms:ListKeys')
            }
            ([LabelType]::CloudTrail_Lake_Integrations) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Lake->Integrations'
                $this.Summary        = "Clicked CloudTrail->Lake->Integrations which displays steps for adding integrations to CloudTrail Lake."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrailv2/home?region={{awsRegion}}#/lake/integrations'
                $this.AnchorEvents   = @('cloudtrail:ListChannels','cloudtrail:ListEventDataStores')
                $this.RequiredEvents = @('cloudtrail:ListChannels')
                $this.OptionalEvents = @('cloudtrail:ListEventDataStores')
            }
            ([LabelType]::CloudTrail_Lake_Query) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Lake->Query'
                $this.Summary        = 'Clicked CloudTrail->Lake->Query which displays steps for getting started with writing queries for events in CloudTrail Lake.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrailv2/home?region={{awsRegion}}#/lake/query'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_CloudTrail_ListEventDataStores
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_CloudTrail_ListEventDataStores).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_CloudTrail_ListEventDataStores).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_CloudTrail_ListEventDataStores).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_CloudTrail_ListEventDataStores).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_CloudTrail_ListEventDataStores).LookaheadInSeconds
            }
            ([LabelType]::CloudTrail_Settings) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Settings'
                $this.Summary        = "Clicked CloudTrail->Settings which displays the list of Delegated Administrators registered to manage CloudTrail resources."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrailv2/home?region={{awsRegion}}#/settings'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_Organizations_ListDelegatedAdministrators
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_Organizations_ListDelegatedAdministrators).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_Organizations_ListDelegatedAdministrators).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_Organizations_ListDelegatedAdministrators).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_Organizations_ListDelegatedAdministrators).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_Organizations_ListDelegatedAdministrators).LookaheadInSeconds
            }
            ([LabelType]::CloudTrail_Settings_Scenario2) {
                # This mapping scenario will only be used as a secondary Signal definition for [LabelType]::CloudTrail_Settings
                # so it will always replicate its Service, Name, Summary, Url and RequiredEvents properties and mostly replicated AnchorEvent and OptionalEvents properties.
                $this.Service            = [Signal]::new([LabelType]::CloudTrail_Settings).Service
                $this.Name               = [Signal]::new([LabelType]::CloudTrail_Settings).Name
                $this.Summary            = [Signal]::new([LabelType]::CloudTrail_Settings).Summary
                $this.Url                = [Signal]::new([LabelType]::CloudTrail_Settings).Url
                $this.AnchorEvents       = [Signal]::new([LabelType]::CloudTrail_Settings).AnchorEvents + @('cloudtrail:ListChannels') | Sort-Object
                $this.RequiredEvents     = [Signal]::new([LabelType]::CloudTrail_Settings).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::CloudTrail_Settings).OptionalEvents + @('cloudtrail:GetChannel','cloudtrail:ListChannels','organizations:DescribeOrganization') | Sort-Object
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::CloudTrail_Settings).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::CloudTrail_Settings).LookaheadInSeconds
            }
            ([LabelType]::CloudTrail_Trails) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Trails'
                $this.Summary        = "Clicked CloudTrail->Trails which displays all CloudTrail Trails and their high-level properties (e.g. Region, S3 Bucket, Status, etc.)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/trails'
                $this.AnchorEvents   = @('cloudtrail:DescribeTrails')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetTrailStatus')
                $this.OptionalEvents = @('organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','s3:ListBuckets')
            }
            ([LabelType]::CloudTrail_Trails_SPECIFICTRAIL) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Trails->SPECIFICTRAIL'
                $this.Summary        = "Clicked CloudTrail->Trails->'{{trailName}}' which displays all details for '{{trailName}}' CloudTrail Trail with ARN '{{trailArn}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/trails/{{trailArn}}'
                $this.AnchorEvents   = @('cloudtrail:DescribeTrails')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetEventSelectors','cloudtrail:GetInsightSelectors','cloudtrail:GetTrailStatus','s3:GetBucketLocation')
                $this.OptionalEvents = @('cloudtrail:ListTags','kms:ListAliases','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','s3:ListBuckets')
            }
            ([LabelType]::CloudTrail_Trails_SPECIFICTRAIL_Delete) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Trails->SPECIFICTRAIL->Delete'
                $this.Summary        = "Clicked CloudTrail->Trails->'{{trailName}}'->Delete to delete '{{trailName}}' CloudTrail Trail with ARN '{{trailArn}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/trails/{{trailArn}}'
                $this.AnchorEvents   = @('cloudtrail:DeleteTrail')
                $this.RequiredEvents = @('cloudtrail:DeleteTrail')
            }
            ([LabelType]::CloudTrail_Trails_SPECIFICTRAIL_StopLogging) {
                $this.Service        = 'CloudTrail'
                $this.Name           = 'Clicked CloudTrail->Trails->SPECIFICTRAIL->Stop Logging'
                $this.Summary        = "Clicked CloudTrail->Trails->'{{trailName}}'->Stop Logging to stop logging events for '{{trailName}}' CloudTrail Trail with ARN '{{trailArn}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/cloudtrail/home?region={{awsRegion}}#/trails/{{trailArn}}'
                $this.AnchorEvents   = @('cloudtrail:DescribeTrails')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetTrailStatus','cloudtrail:StopLogging')
            }
            ([LabelType]::ConsoleHome) {
                $this.Service        = 'N/A'
                $this.Name           = 'Console Home'
                $this.Summary        = 'Visited Console Home dashboard which displays general overview information for account (e.g. Recently Visited services, AWS Health, Cost and Usage, etc.).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/console/home?region={{awsRegion}}#'
                $this.AnchorEvents   = @('ce:GetCostAndUsage')
                $this.RequiredEvents = @('ce:GetCostAndUsage')
                $this.OptionalEvents = @('ce:GetCostForecast','cost-optimization-hub:ListEnrollmentStatuses','cost-optimization-hub:ListRecommendationSummaries','ec2:DescribeAccountAttributes','ec2:DescribeRegions','ram:ListResources','securityhub:DescribeHub','securityhub:GetAdministratorAccount','securityhub:GetControlFindingSummary','securityhub:GetFindingAggregator','securityhub:GetInsightResults','securityhub:ListFindingAggregators','securityhub:ListMembers','servicecatalog-appregistry:ListApplications','support:DescribeTrustedAdvisorChecks','support:DescribeTrustedAdvisorCheckSummaries')
            }
            ([LabelType]::ConsoleLogin) {
                $this.Service        = 'N/A'
                $this.Name           = 'Console Login'
                $this.Summary        = 'Logged into AWS Console.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('signin:ConsoleLogin')
                $this.RequiredEvents = @('signin:ConsoleLogin')
                $this.OptionalEvents = @('signin:GetSigninToken')
            }
            ([LabelType]::EC2_AutoScaling_AutoScalingGroups) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Auto Scaling->Auto Scaling Groups'
                $this.Summary        = 'Clicked EC2->Auto Scaling->Auto Scaling Groups which displays a summary of EC2 Auto Scaling features.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#AutoScalingGroups:'
                $this.AnchorEvents   = @('autoscaling:DescribeAutoScalingGroups')
                $this.RequiredEvents = @('autoscaling:DescribeAutoScalingGroups','ec2:DescribeAccountAttributes','ec2:DescribeInstanceTypes')
            }
            ([LabelType]::EC2_BrowserRefresh) {
                $this.Service        = 'EC2'
                $this.Name           = 'Refreshed Browser in EC2'
                $this.Summary        = 'Refreshed Browser in EC2 section of AWS Console.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('ec2:DescribeImages')
                $this.RequiredEvents = @('ec2:DescribeAddresses','ec2:DescribeImages','ec2:DescribeInstanceConnectEndpoints','ec2:DescribeInstances','ec2:DescribeInstanceTypes','ec2:DescribeRegions','ec2:DescribeSecurityGroups')
            }
            ([LabelType]::EC2_ConsoleToCode) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Console-to-Code'
                $this.Summary        = 'Clicked EC2->Console-to-Code which records your actions and uses generative AI to generate and suggest optimal code in your desired infrastructure as code (IaC) format for deploying your workloads.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#console-to-code:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes','ec2:DescribeInstanceTypes')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeInstanceTypes')
            }
            ([LabelType]::EC2_EC2Dashboard) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard which displays all EC2 compute resources (e.g. instances, volumes, snapshots, load balancers, etc.).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes','ec2:DescribeAddresses','ec2:DescribeAvailabilityZones','ec2:DescribeInstances','ec2:DescribeInstanceStatus','ec2:DescribeKeyPairs','ec2:DescribeSecurityGroups','ec2:DescribeSnapshots')
                $this.RequiredEvents = @('autoscaling:DescribeAutoScalingGroups','ec2:DescribeAccountAttributes','ec2:DescribeAddresses','ec2:DescribeAvailabilityZones','ec2:DescribeHosts','ec2:DescribeInstances','ec2:DescribeInstanceStatus','ec2:DescribeKeyPairs','ec2:DescribeLaunchTemplates','ec2:DescribePlacementGroups','ec2:DescribeSecurityGroups','ec2:DescribeSnapshots','ec2:DescribeVolumes','ec2:DescribeVolumeStatus','elasticloadbalancing:DescribeLoadBalancers')
                $this.OptionalEvents = @('ec2:DescribeRegions','ec2:DescribeReservedInstances')
            }
            ([LabelType]::EC2_EC2Dashboard_AccountAttributes_Refresh) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Account Attributes->Refresh'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Account Attributes->Refresh button to refresh EC2 Account Attributes summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes')
            }
            ([LabelType]::EC2_EC2Dashboard_Resources_Refresh) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Resources->Refresh'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Resources->Refresh button to refresh EC2 Resources summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeInstances','ec2:DescribeSnapshots','ec2:DescribeKeyPairs')
                $this.RequiredEvents = @('autoscaling:DescribeAutoScalingGroups','ec2:DescribeAddresses','ec2:DescribeHosts','ec2:DescribeInstances','ec2:DescribeKeyPairs','ec2:DescribePlacementGroups','ec2:DescribeSecurityGroups','ec2:DescribeSnapshots','ec2:DescribeVolumes','elasticloadbalancing:DescribeLoadBalancers')
            }
            ([LabelType]::EC2_EC2Dashboard_Resources_Settings) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Resource Settings'
                $this.Summary        = "Clicked EC2->EC2 Dashboard->Resource Settings and clicked 'Ok' to confirm selection of resources to be visible in EC2 dashboard."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeLaunchTemplates')
                $this.RequiredEvents = @('ec2:DescribeLaunchTemplates','ec2:DescribeReservedInstances')
            }
            ([LabelType]::EC2_EC2Dashboard_ScheduledEvents_Refresh) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Scheduled Events->Refresh'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Scheduled Events->Refresh button to refresh EC2 Scheduled Events summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Home:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Events based on what
                # Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Events).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Events).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Events).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Events).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Events).LookaheadInSeconds
            }
            ([LabelType]::EC2_EC2Dashboard_ServiceHealth_Refresh) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Service Health->Refresh'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Service Health->Refresh button to refresh EC2 Service Health summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones')
                $this.RequiredEvents = @('ec2:DescribeAvailabilityZones')
            }
            ([LabelType]::EC2_EC2Dashboard_Settings_DefaultCreditSpecification) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Settings->Default Credit Specification'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Settings->Default Credit Specification tab which displays default credit options for CPU usage of burstable performance instances.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Settings:tab=defaultCreditSpecification'
                $this.AnchorEvents   = @('ec2:GetDefaultCreditSpecification')
                $this.RequiredEvents = @('ec2:DescribeInstanceTypes','ec2:GetDefaultCreditSpecification')
            }
            ([LabelType]::EC2_EC2Dashboard_Settings_EBSEncryption) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Settings->EBS Encryption'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Settings->EBS Encryption tab which displays the default encryption status of all new EBS volumes and copies of snapshots created in current account.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Settings:tab=ebsEncryption'
                $this.AnchorEvents   = @('ec2:GetEbsEncryptionByDefault')
                $this.RequiredEvents = @('ec2:GetEbsDefaultKmsKeyId','ec2:GetEbsEncryptionByDefault')
            }
            ([LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Settings->EC2 Serial Console'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Settings->EC2 Serial Console tab which allows or prevents EC2 Serial Console access to EC2 Instances in current account.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Settings:tab=ec2SerialConsole'
                $this.AnchorEvents   = @('ec2:GetSerialConsoleAccessStatus')
                $this.RequiredEvents = @('ec2:GetSerialConsoleAccessStatus')
            }
            ([LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Allow) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Settings->EC2 Serial Console->Manage Access->Allow'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Settings->EC2 Serial Console->Manage Access->Allow checkbox and clicked Update to allow EC2 Serial Console access to EC2 Instances in current account.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Settings:tab=ec2SerialConsole'
                $this.AnchorEvents   = @('ec2:GetSerialConsoleAccessStatus')
                $this.RequiredEvents = @('ec2:EnableSerialConsoleAccess','ec2:GetSerialConsoleAccessStatus')
            }
            ([LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Disallow) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Settings->EC2 Serial Console->Manage Access->Disallow'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Settings->EC2 Serial Console->Manage Access->Disallow checkbox (by unchecking Allow) and clicked Update to prevent EC2 Serial Console access to EC2 Instances in current account.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Settings:tab=ec2SerialConsole'
                $this.AnchorEvents   = @('ec2:GetSerialConsoleAccessStatus')
                $this.RequiredEvents = @('ec2:DisableSerialConsoleAccess','ec2:GetSerialConsoleAccessStatus')
            }
            ([LabelType]::EC2_EC2Dashboard_Settings_Zones) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Dashboard->Settings->Zones'
                $this.Summary        = 'Clicked EC2->EC2 Dashboard->Settings->Zones tab which displays management options for Zones in current AWS Region.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Settings:tab=zones'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones')
                $this.RequiredEvents = @('ec2:DescribeAvailabilityZones')
            }
            ([LabelType]::EC2_EC2GlobalView_RegionExplorer) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Global View->Region Explorer'
                $this.Summary        = "Clicked EC2->EC2 Global View->Region Explorer which displays a summary of all EC2 resources per region and resource type (e.g. instances, subnets, security groups, etc.)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2globalview/home?region={{awsRegion}}#'
                $this.AnchorEvents   = @('ec2:DescribeRegions')
                $this.RequiredEvents = @('autoscaling:DescribeAutoScalingGroups','ec2:DescribeEgressOnlyInternetGateways','ec2:DescribeInstances','ec2:DescribeInternetGateways','ec2:DescribeNatGateways','ec2:DescribeRegions','ec2:DescribeRouteTables','ec2:DescribeSecurityGroups','ec2:DescribeSubnets','ec2:DescribeVolumes','ec2:DescribeVpcEndpoints','ec2:DescribeVpcs')
                $this.OptionalEvents = @('ec2:DescribeAddresses','ec2:DescribeDhcpOptions','ec2:DescribeManagedPrefixLists','ec2:DescribeNetworkAcls','ec2:DescribeNetworkInterfaces','ec2:DescribeVpcEndpointServiceConfigurations','ec2:DescribeVpcPeeringConnections')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 15
            }
            ([LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->EC2 Global View->Region Explorer->Resource Region Counts->Refresh'
                $this.Summary        = "Clicked EC2->EC2 Global View->Region Explorer->Resource Region Counts->Refresh button to refresh Resource Region Counts dashboard tile."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2globalview/home?region={{awsRegion}}#'
                $this.AnchorEvents   = @('ec2:DescribeAddresses')
                $this.RequiredEvents = @('autoscaling:DescribeAutoScalingGroups','ec2:DescribeAddresses','ec2:DescribeDhcpOptions','ec2:DescribeEgressOnlyInternetGateways','ec2:DescribeInstances','ec2:DescribeInternetGateways','ec2:DescribeManagedPrefixLists','ec2:DescribeNatGateways','ec2:DescribeNetworkAcls','ec2:DescribeNetworkInterfaces','ec2:DescribeRouteTables','ec2:DescribeSecurityGroups','ec2:DescribeSubnets','ec2:DescribeVolumes','ec2:DescribeVpcEndpoints','ec2:DescribeVpcEndpointServiceConfigurations','ec2:DescribeVpcPeeringConnections','ec2:DescribeVpcs')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 15
            }
            ([LabelType]::EC2_ElasticBlockStore_Lifecycle) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Elastic Block Store->Lifecycle Manager'
                $this.Summary        = 'Clicked EC2->Elastic Block Store->Lifecycle Manager which displays a general overview of how to get started using Lifecycle Manager to automate backing up data stored on Amazon EBS (Elastic Block Store) volumes.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Lifecycle:'
                $this.AnchorEvents   = @('dlm:GetLifecyclePolicies')
                $this.RequiredEvents = @('dlm:GetLifecyclePolicies')
            }
            ([LabelType]::EC2_ElasticBlockStore_Snapshots) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Elastic Block Store->Snapshots'
                $this.Summary        = 'Clicked EC2->Elastic Block Store->Snapshots which displays all EC2 Snapshots in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Snapshots:'
                $this.AnchorEvents   = @('ec2:DescribeSnapshots')
                $this.RequiredEvents = @('ec2:DescribeSnapshots')
                $this.OptionalEvents = @('ec2:DescribeRegions','ec2:DescribeTags','kms:ListAliases')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 20
            }
            ([LabelType]::EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Elastic Block Store->Snapshots->SPECIFICSNAPSHOT->Details'
                $this.Summary        = "Clicked EC2->Elastic Block Store->Snapshots->'{{snapshotId}}'->Details which displays a summary of all details for '{{snapshotId}}' EC2 Snapshot."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SnapshotDetails:snapshotId={{snapshotId}}'
                $this.AnchorEvents   = @('ec2:DescribeSnapshotAttribute')
                $this.RequiredEvents = @('ec2:DescribeFastSnapshotRestores','ec2:DescribeSnapshotAttribute','kms:ListAliases')
                $this.OptionalEvents = @('ec2:DescribeSnapshots')
            }
            ([LabelType]::EC2_ElasticBlockStore_Volumes) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Elastic Block Store->Volumes'
                $this.Summary        = 'Clicked EC2->Elastic Block Store->Volumes which displays all EC2 Volumes in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Volumes:'
                $this.AnchorEvents   = @('ec2:DescribeVolumes')
                $this.RequiredEvents = @('ec2:DescribeTags','ec2:DescribeVolumes','ec2:DescribeVolumesModifications','ec2:DescribeVolumeStatus')
                $this.OptionalEvents = @('ec2:DescribeAvailabilityZones','kms:ListAliases')
            }
            ([LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Elastic Block Store->Volumes->SPECIFICVOLUME->Details'
                $this.Summary        = "Clicked EC2->Elastic Block Store->Volumes->'{{volumeId}}'->Details which displays a summary of all details for '{{volumeId}}' EC2 Volume."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#VolumeDetails:volumeId=:{{volumeId}}'
                $this.AnchorEvents   = @('compute-optimizer:GetEBSVolumeRecommendations')
                $this.RequiredEvents = @('compute-optimizer:GetEBSVolumeRecommendations','kms:ListAliases')
                $this.OptionalEvents = @('ec2:DescribeRegions','ec2:DescribeTags','ec2:DescribeVolumeAttribute','ec2:DescribeVolumes','ec2:DescribeVolumesModifications','ec2:DescribeVolumeStatus')
            }
            ([LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_StatusChecks) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Elastic Block Store->Volumes->SPECIFICVOLUME->Status Checks'
                $this.Summary        = "Clicked EC2->Elastic Block Store->Volumes->'{{volumeId}}'->Status Checks which displays a summary of all status checks for '{{volumeId}}' EC2 Volume."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#VolumeDetails:volumeId=:{{volumeId}}'
                $this.AnchorEvents   = @('ec2:DescribeVolumeAttribute')
                $this.RequiredEvents = @('ec2:DescribeVolumeAttribute')
            }
            ([LabelType]::EC2_Events) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Events'
                $this.Summary        = 'Clicked EC2->Events which displays all EC2 Instance Events and EC2 Volume Events in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Events:'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_EC2Dashboard_ScheduledEvents_Refresh based on
                # what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:DescribeInstanceStatus')
                $this.RequiredEvents = @('ec2:DescribeInstanceStatus','ec2:DescribeVolumeStatus')
            }
            ([LabelType]::EC2_Images_AMICatalog) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Images->AMI Catalog'
                $this.Summary        = 'Clicked EC2->Images->AMI Catalog which displays all EC2 AMIs (Amazon Machine Images) in the AWS AMI catalog in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#AMICatalog:'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('discovery-marketplace:SearchListings','ec2:DescribeImages')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('discovery-marketplace:GetSearchFacets','discovery-marketplace:SearchListings','ec2:DescribeImages')
            }
            ([LabelType]::EC2_Images_AMICatalog_SearchBySystemsManagerParameter) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Images->AMI Catalog->Search by Systems Manager Parameter'
                $this.Summary        = 'Clicked EC2->Images->AMI Catalog->Search by Systems Manager Parameter dropdown which enables searching for an EC2 AMI (Amazon Machine Image) in the AWS AMI catalog by selecting a Systems Manager parameter that resolves to desired AMI ID.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#AMICatalog:'
                $this.AnchorEvents   = @('ssm:DescribeParameters')
                $this.RequiredEvents = @('ssm:DescribeParameters')
            }
            ([LabelType]::EC2_Images_AMIs) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Images->AMIs'
                $this.Summary        = 'Clicked EC2->Images->AMIs which displays all EC2 AMIs (Amazon Machine Images) in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Images:'
                # This is a unique scenario since any Anchor Event can exist by itself, so none are defined as Required but all are listed as Optional.
                $this.AnchorEvents   = @('ec2:DescribeImages','ec2:DescribeTags')
                $this.RequiredEvents = @('*')
                $this.OptionalEvents = @('ec2:DescribeImages','ec2:DescribeRegions','ec2:DescribeTags')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 15
            }
            ([LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Details) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Images->AMIs->SPECIFICIMAGE->Details'
                $this.Summary        = "Clicked EC2->Images->AMIs->'{{imageId}}'->Details which displays a summary of all details for '{{imageId}}' EC2 AMI (Amazon Machine Image)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#ImageDetails:imageId={{imageId}}'
                $this.AnchorEvents   = @('ec2:DescribeImages')
                $this.RequiredEvents = @('ec2:DescribeImages')
            }
            ([LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Storage) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Images->AMIs->SPECIFICIMAGE->Storage'
                $this.Summary        = "Clicked EC2->Images->AMIs->'{{imageId}}'->Storage which displays storage device details for '{{imageId}}' EC2 AMI (Amazon Machine Image)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#ImageDetails:imageId={{imageId}}'
                $this.AnchorEvents   = @('ec2:DescribeSnapshots')
                $this.RequiredEvents = @('ec2:DescribeSnapshots')
            }
            ([LabelType]::EC2_Instances_CapacityReservations) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Capacity Reservations'
                $this.Summary        = 'Clicked EC2->Instances->Capacity Reservations which displays all EC2 Instance Capacity Reservations in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CapacityReservations:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones','ec2:DescribeCapacityReservations')
                $this.RequiredEvents = @('ec2:DescribeCapacityReservations','ec2:DescribeTags')
                $this.OptionalEvents = @('ec2:DescribeAvailabilityZones','ec2:DescribeInstanceTypes','ec2:GetCapacityReservationAccountAttribute')
            }
            ([LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step1) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Capacity Reservations->Create Capacity Reservation (Step 1 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Capacity Reservations->Create Capacity Reservation (Step 1 of 2) which reserves EC2 Instance Capacity in a specific Availability Zone for any duration.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateCapacityReservation:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones')
                $this.RequiredEvents = @('ec2:DescribeAvailabilityZones','ec2:DescribePlacementGroups')
            }
            ([LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Capacity Reservations->Create Capacity Reservation (Step 2 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Capacity Reservations->Create Capacity Reservation (Step 2 of 2) which reserves EC2 Instance Capacity in a specific Availability Zone for any duration.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateCapacityReservation:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones','ec2:DescribeCapacityReservations')
                $this.RequiredEvents = @('ec2:CreateCapacityReservation','ec2:DescribeAvailabilityZones','ec2:DescribeCapacityReservations','ec2:DescribeTags','ec2:GetCapacityReservationAccountAttribute')
            }
            ([LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Capacity Reservations->SPECIFICCAPACITYRESERVATION'
                $this.Summary        = "Clicked EC2->Instances->Capacity Reservations->'{{capacityReservationId}}' which displays a summary of details for existing '{{capacityReservationId}}' EC2 Instance Capacity Reservation."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CapacityReservationDetails:crId={{capacityReservationId}}'
                $this.AnchorEvents   = @('ec2:DescribeCapacityReservations')
                $this.RequiredEvents = @('ec2:DescribeCapacityReservations','ec2:GetCapacityReservationUsage','ec2:GetGroupsForCapacityReservation','ram:GetResourceShareAssociations')
            }
            ([LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Capacity Reservations->SPECIFICCAPACITYRESERVATION->Cancel Capacity Reservation'
                $this.Summary        = "Clicked EC2->Instances->Capacity Reservations->'{{capacityReservationId}}'->Cancel Capacity Reservation which cancels existing '{{capacityReservationId}}' EC2 Instance Capacity Reservation."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CapacityReservationDetails:crId={{capacityReservationId}}'
                $this.AnchorEvents   = @('ec2:DescribeCapacityReservations')
                $this.RequiredEvents = @('ec2:CancelCapacityReservation','ec2:DescribeCapacityReservations')
                $this.OptionalEvents = @('ec2:DescribeTags','ec2:GetCapacityReservationUsage','ec2:GetGroupsForCapacityReservation','ram:GetResourceShareAssociations')
            }
            ([LabelType]::EC2_Instances_DedicatedHosts) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Dedicated Hosts'
                $this.Summary        = 'Clicked EC2->Instances->Dedicated Hosts which displays all EC2 Dedicated Hosts in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Hosts:'
                $this.AnchorEvents   = @('config:DescribeConfigurationRecorders')
                $this.RequiredEvents = @('config:DescribeConfigurationRecorders','ec2:DescribeHosts','ec2:DescribeRegions','ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_Instances) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances'
                $this.Summary        = 'Clicked EC2->Instances->Instances which displays all EC2 Instances in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes','ec2:DescribeInstances','ec2:DescribeInstanceAttribute','ec2:DescribeInstanceTypes')
                $this.RequiredEvents = @('ec2:DescribeInstances')
                $this.OptionalEvents = @('compute-optimizer:GetEnrollmentStatus','ec2:DescribeAccountAttributes','ec2:DescribeAddresses','ec2:DescribeInstanceAttribute','ec2:DescribeInstanceCreditSpecifications','ec2:DescribeInstanceStatus','ec2:DescribeInstanceTypes','ec2:DescribeNetworkInterfaces','ec2:DescribeRegions','ec2:DescribeTags','iam:GetInstanceProfile','ssm:DescribeInstanceInformation','tagging:GetResources')
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1 of 2) which launches an EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones','ec2:DescribeImages','ec2:DescribeInstanceTypeOfferings','ec2:DescribeSecurityGroups')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeAvailabilityZones','ec2:DescribeImages','ec2:DescribeInstances','ec2:DescribeInstanceTypeOfferings','ec2:DescribeInstanceTypes','ec2:DescribeSecurityGroups','ec2:DescribeSnapshots','ec2:DescribeSubnets','ec2:DescribeVpcs','ec2:GetEbsEncryptionByDefault')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 5
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ApplicationAndOSImages_Search) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Application and OS Images->Search'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Application and OS Images->Search to search for EC2 AMI (Amazon Machine Image) to configure for soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ApplicationAndOSImages_Select) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Application and OS Images->Search->Select'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Application and OS Images->Search->Select to select EC2 AMI (Amazon Machine Image) to configure for soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ConfigureStorage_ViewBackupInformation) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Configure Storage->Click Refresh to View Backup Information'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Configure Storage->Click Refresh to View Backup Information to determine if assigned tags will trigger any Data Lifecycle Manager policies to back up soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                $this.AnchorEvents   = @('dlm:GetLifecyclePolicies')
                $this.RequiredEvents = @('dlm:GetLifecyclePolicies')
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Create) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Key Pair (Login)->Create New Key Pair'
                $this.Summary        = "Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Key Pair (Login)->Create New Key Pair to create '{{keyName}}' key pair to configure for remote access to soon-to-be-launched EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_KeyPair_Create
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Select) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Key Pair (Login)'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Key Pair (Login) dropdown to select key pair to configure for remote access to soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_KeyPair_Select
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Key) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Name and Tags->Add Additional Tags->Key'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Name and Tags->Add Additional Tags->Key dropdown to define Key in Key-Value pair for tag to be added to soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                $this.AnchorEvents   = @('ec2:DescribeTags')
                $this.RequiredEvents = @('ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Value) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Name and Tags->Add Additional Tags->Value'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Name and Tags->Add Additional Tags->Value dropdown to define Value in Key-Value pair for tag to be added to soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                $this.AnchorEvents   = @('ec2:DescribeTags')
                $this.RequiredEvents = @('ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NetworkSettings_FirewallSecurityGroup_Select) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Network Settings->Firewall (Security Groups)->Select Existing Security Group'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 1.5 of 2)->Network Settings->Firewall (Security Groups)->Select Existing Security Group dropdown to select from list of existing Security Groups to configure for soon-to-be-launched EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_List_SecurityGroups
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, LookbackInSeconds
                # and LookaheadInSeconds properties and a mostly replicated OptionalEvents property.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).OptionalEvents + @('ec2:DescribeManagedPrefixLists') | Sort-Object
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step2) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->Launch Instance (Step 2 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Instances->Launch Instance (Step 2 of 2) which launches an EC2 Instance.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchInstances:'
                $this.AnchorEvents   = @('ec2:RunInstances','ec2:DescribeSecurityGroups','ec2:DescribeTags')
                $this.RequiredEvents = @('ec2:RunInstances')
                # ec2:AuthorizeSecurityGroupIngress event is only executed if 1+ Network Ingress rules are created for newly created EC2 Instance(s).
                # ec2:CreateSecurityGroup event is only executed if 1+ Security Groups are created for newly created EC2 Instance(s).
                # ec2:DescribeTags event is only executed if 1+ Tags are added to newly created EC2 Instance(s).
                $this.OptionalEvents = @('ec2:AuthorizeSecurityGroupIngress','ec2:CreateSecurityGroup','ec2:DescribeSecurityGroups','ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->EC2 Instance Connect->Connect'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->EC2 Instance Connect->Connect to remotely connect to '{{instanceId}}' EC2 Instance with '{{instanceOSUser}}' user via EC2 Instance Connect option."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2-instance-connect/ssh?connType=standard&instanceId={{instanceId}}&osUser={{instanceOSUser}}&region={{awsRegion}}&sshPort=22#/'
                $this.AnchorEvents   = @('ec2-instance-connect:SendSSHPublicKey')
                $this.RequiredEvents = @('ec2-instance-connect:SendSSHPublicKey','ec2:DescribeInstances','ec2:DescribeRegions')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2) {
                # This mapping scenario will only be used as a secondary Signal definition for [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect
                # so it will always replicate its Service, Name, Summary and Url properties.
                $this.Service        = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect).Service
                $this.Name           = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect).Name
                $this.Summary        = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect).Summary
                $this.Url            = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect).Url
                $this.AnchorEvents   = @('ec2:DescribeImages')
                $this.RequiredEvents = @('ec2:DescribeAddresses','ec2:DescribeImages','ec2:DescribeInstanceConnectEndpoints','ec2:DescribeSecurityGroups')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->EC2 Serial Console'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->EC2 Serial Console to configure settings to remotely connect to '{{instanceId}}' EC2 Instance via EC2 Serial Console option."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#ConnectToInstance:instanceId={{instanceId}}'
                $this.AnchorEvents   = @('ec2:GetSerialConsoleAccessStatus','ssm:GetConnectionStatus')
                $this.RequiredEvents = @('ec2:DescribeImages','ec2:DescribeInstanceConnectEndpoints','ec2:DescribeSecurityGroups','ec2:GetSerialConsoleAccessStatus','ssm:GetConnectionStatus')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->RDP Client->Fleet Manager Remote Desktop'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->RDP Client->Fleet Manager Remote Desktop to configure settings to remotely connect to '{{instanceId}}' EC2 Instance via Fleet Manager Remote Desktop option."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/systems-manager/managed-instances/rdp-connect?region={{awsRegion}}&instances={{instanceId}}'
                $this.AnchorEvents   = @('ec2:DescribeInstances')
                $this.RequiredEvents = @('ec2:DescribeInstances','ec2:DescribeRegions','ssm:DescribeInstanceProperties','ssm:GetDocument','sso:ListDirectoryAssociations')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->RDP Client->Fleet Manager Remote Desktop->Connect'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->RDP Client->Fleet Manager Remote Desktop->Connect to remotely connect to '{{instanceId}}' EC2 Instance via Fleet Manager Remote Desktop option by creating '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/systems-manager/managed-instances/rdp-connect?region={{awsRegion}}&instances={{instanceId}}'
                $this.AnchorEvents   = @('ssm-guiconnect:StartConnection')
                $this.RequiredEvents = @('ssm-guiconnect:StartConnection','ssm:StartSession')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->RDP Client->Fleet Manager Remote Desktop->Interactive Usage'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->RDP Client->Fleet Manager Remote Desktop->Interactive Usage to continue interactive usage of remote connection to '{{instanceId}}' EC2 Instance via Fleet Manager Remote Desktop option by using '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/systems-manager/managed-instances/rdp-connect?region={{awsRegion}}&instances={{instanceId}}'
                $this.AnchorEvents   = @('ssm-guiconnect:GetConnection')
                $this.RequiredEvents = @('ssm-guiconnect:GetConnection')
                $this.OptionalEvents = @('identitystore:DescribeUser','ssm:GetCommandInvocation','ssm:SendCommand','ssm:StartSession','ssm:TerminateSession','sso:ListDirectoryAssociations')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 60
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Terminate) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->RDP Client->Fleet Manager Remote Desktop->Terminate'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->RDP Client->Fleet Manager Remote Desktop->Terminate to terminate remote connection to '{{instanceId}}' EC2 Instance via Fleet Manager Remote Desktop option by terminating '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/systems-manager/managed-instances/rdp-connect?region={{awsRegion}}&instances={{instanceId}}'
                $this.AnchorEvents   = @('ssm-guiconnect:CancelConnection','ssm:TerminateSession')
                $this.RequiredEvents = @('ssm-guiconnect:CancelConnection','ssm:TerminateSession')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->Session Manager'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->Session Manager to configure settings to remotely connect to '{{instanceId}}' EC2 Instance via Session Manager option."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#ConnectToInstance:instanceId={{instanceId}}'
                $this.AnchorEvents   = @('ssm:GetConnectionStatus','ec2:DescribeImages','ec2:GetSerialConsoleAccessStatus')
                $this.RequiredEvents = @('ssm:GetConnectionStatus')
                $this.OptionalEvents = @('ec2:DescribeImages','ec2:DescribeInstanceConnectEndpoints','ec2:DescribeSecurityGroups','ec2:GetSerialConsoleAccessStatus','ssm:DescribeInstanceInformation')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2) {
                # This mapping scenario will only be used as a secondary Signal definition for [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                # so it will always replicate its Service, Name, Summary, Url and AnchorEvent properties and mostly replicated RequiredEvents and OptionalEvents properties.
                $this.Service            = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).Service
                $this.Name               = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).Name
                $this.Summary            = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).Summary
                $this.Url                = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).Url
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).RequiredEvents + @('ssm:DescribeInstanceInformation') | Sort-Object
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).OptionalEvents.Where( { $_ -cne 'ssm:DescribeInstanceInformation' } )
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->Session Manager->Connect'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->Session Manager->Connect to remotely connect to '{{instanceId}}' EC2 Instance via Session Manager option by creating '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/systems-manager/session-manager/{{instanceId}}?region={{awsRegion}}'
# DBO - 2023-11-28 11:56pm EST DBO - should we REMOVE label for ec2:DescribeImages???
                $this.AnchorEvents   = @('ssm:StartSession','ec2:DescribeImages','ec2:DescribeInstances','ec2:DescribeInstanceAttribute')
                $this.RequiredEvents = @('compute-optimizer:GetEnrollmentStatus','ec2:DescribeAddresses','ec2:DescribeInstanceAttribute','ec2:DescribeInstanceCreditSpecifications','ec2:DescribeInstances','ec2:DescribeInstanceStatus','ec2:DescribeNetworkInterfaces','ec2:DescribeRegions','iam:GetInstanceProfile','ssm:DescribeInstanceInformation','ssm:DescribeSessions','ssm:StartSession','tagging:GetResources')
                $this.OptionalEvents = @('ec2:DescribeImages')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Terminate) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Connect to Instance->Session Manager->Terminate'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Connect to Instance->Session Manager->Terminate to terminate remote connection to '{{instanceId}}' EC2 Instance via Session Manager option by terminating '{{sessionId}}' Session ID."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/systems-manager/session-manager/{{instanceId}}?region={{awsRegion}}'
                $this.AnchorEvents   = @('ssm:TerminateSession')
                $this.RequiredEvents = @('ssm:TerminateSession')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Details'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Details which displays a summary of all details for '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                $this.AnchorEvents   = @('ec2:DescribeImages','ec2:DescribeInstanceAttribute','ec2:DescribeInstances')
                $this.RequiredEvents = @('ec2:DescribeAddresses','ec2:DescribeInstanceAttribute','ec2:DescribeInstanceCreditSpecifications','ec2:DescribeInstances','ec2:DescribeInstanceStatus','ec2:DescribeNetworkInterfaces')
                # ec2:DescribeImages event is only executed if an AMI is defined for currently selected EC2 Instance.
                # ec2:DescribeSubnets event is only executed if 1+ EC2 Subnets defined for currently selected EC2 Instance.
                # ec2:DescribeVpcs event is only executed if 1+ EC2 VPCs defined for currently selected EC2 Instance.
                # iam:GetInstanceProfile event is only executed if 1+ IAM Roles defined for currently selected EC2 Instance.
                $this.OptionalEvents = @('compute-optimizer:GetEnrollmentStatus','ec2:DescribeImages','ec2:DescribeInstanceTypes','ec2:DescribeRegions','ec2:DescribeSubnets','ec2:DescribeVpcs','iam:GetInstanceProfile','ssm:DescribeInstanceInformation','tagging:GetResources')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Instance State->Reboot Instance'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Instance State->Reboot Instance to reboot existing '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance
                # based on what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:DescribeInstances','ec2:RebootInstances')
                $this.RequiredEvents = @('ec2:DescribeInstances','ec2:RebootInstances')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Reboot Instance'
                $this.Summary        = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Reboot Instance to reboot existing.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
                # based on the number of instanceIds present in ec2:RebootInstances, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Instance State->Start Instance'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Instance State->Start Instance to start existing '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance
                # based on what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:DescribeInstances','ec2:StartInstances')
                $this.RequiredEvents = @('ec2:DescribeInstances','ec2:StartInstances')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Start Instance'
                $this.Summary        = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Start Instance to start existing.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
                # based on the number of instanceIds present in ec2:StartInstances, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Instance State->Stop Instance'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Instance State->Stop Instance to stop existing '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance
                # based on what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:StopInstances')
                $this.RequiredEvents = @('ec2:DescribeInstances','ec2:StopInstances')
                $this.OptionalEvents = @('ssm:DescribeInstanceInformation')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Stop Instance'
                $this.Summary        = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Stop Instance to stop existing.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                # based on the number of instanceIds present in ec2:StopInstances, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Instance State->Terminate Instance (Step 1 of 2)'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Instance State->Terminate Instance (Step 1 of 2) to terminate existing '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step1
                # based on what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:DescribeInstanceAttribute')
                $this.RequiredEvents = @('ec2:DescribeAddresses','ec2:DescribeInstanceAttribute')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step1) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Terminate Instance (Step 1 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Terminate Instance (Step 1 of 2) to terminate existing.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1
                # based on the number of instanceIds present in ec2:TerminateInstances, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Instance State->Terminate Instance (Step 2 of 2)'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Instance State->Terminate Instance (Step 2 of 2) to terminate existing '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2
                # based on what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:DescribeInstances','ec2:TerminateInstances')
                $this.RequiredEvents = @('ec2:DescribeInstances','ec2:TerminateInstances')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Terminate Instance (Step 2 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Instance State->Terminate Instance (Step 2 of 2) to terminate existing.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
                # based on the number of instanceIds present in ec2:TerminateInstances, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Monitoring'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Monitoring which displays a summary of all monitoring metrics for '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring based on
                # what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('ec2:DescribeTags')
                $this.RequiredEvents = @('ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Monitoring'
                $this.Summary        = "Clicked EC2->Instances->Instances->SPECIFICINSTANCES->Monitoring which displays a summary of all monitoring metrics."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Instances:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring based on
                # the number of instanceIds present in ec2:DescribeTags, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Security) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Security'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Security which displays a summary of all security details for '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                $this.AnchorEvents   = @('ec2:DescribeSecurityGroupRules')
                $this.RequiredEvents = @('ec2:DescribeSecurityGroupRules','ec2:DescribeSecurityGroups')
            }
            ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Storage) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instances->SPECIFICINSTANCE->Storage'
                $this.Summary        = "Clicked EC2->Instances->Instances->'{{instanceId}}'->Storage which displays a summary of all storage details for '{{instanceId}}' EC2 Instance."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceDetails:instanceId={{instanceId}}'
                $this.AnchorEvents   = @('ec2:DescribeReplaceRootVolumeTasks')
                $this.RequiredEvents = @('ec2:DescribeReplaceRootVolumeTasks','ec2:DescribeVolumes')
            }
            ([LabelType]::EC2_Instances_InstanceTypes) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Instance Types'
                $this.Summary        = 'Clicked EC2->Instances->Instance Types which displays all EC2 Instance Types in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#InstanceTypes:'
                $this.AnchorEvents   = @('ec2:DescribeInstanceTypeOfferings')
                $this.RequiredEvents = @('ec2:DescribeInstanceTypeOfferings','ec2:DescribeInstanceTypes')
                $this.OptionalEvents = @('ec2:DescribeRegions')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates which displays all EC2 Launch Templates in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchTemplates:'
                $this.AnchorEvents   = @('ec2:DescribeTags','ec2:DescribeAvailabilityZones')
                $this.RequiredEvents = @('ec2:DescribeLaunchTemplates','ec2:DescribeTags')
                $this.OptionalEvents = @('ec2:DescribeAvailabilityZones','ec2:DescribeInstanceTypes')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_Scenario2) {
                # This mapping scenario will only be used as a secondary Signal definition for [LabelType]::EC2_Instances_LaunchTemplates
                # so it will always replicate its Service, Name, Summary and Url properties.
                $this.Service        = [Signal]::new([LabelType]::EC2_Instances_LaunchTemplates).Service
                $this.Name           = [Signal]::new([LabelType]::EC2_Instances_LaunchTemplates).Name
                $this.Summary        = [Signal]::new([LabelType]::EC2_Instances_LaunchTemplates).Summary
                $this.Url            = [Signal]::new([LabelType]::EC2_Instances_LaunchTemplates).Url
                $this.AnchorEvents   = @('ec2:DescribeLaunchTemplates')
                $this.RequiredEvents = @('ec2:DescribeLaunchTemplates')
                $this.OptionalEvents = @('ec2:DescribeInstanceTypes','ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1 of 2) to create a new EC2 Launch Template.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                $this.AnchorEvents   = @('ec2:DescribeImages','ec2:DescribeInstanceTypeOfferings','ec2:DescribeSecurityGroups')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeImages','ec2:DescribeInstances','ec2:DescribeInstanceTypeOfferings','ec2:DescribeInstanceTypes','ec2:DescribeSecurityGroups','ec2:DescribeSubnets','ec2:GetEbsEncryptionByDefault')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_ApplicationAndOSImages_Search) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Application and OS Images->Search'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Application and OS Images->Search to search for EC2 AMI (Amazon Machine Image) to configure for EC2 Instance(s) created from soon-to-be-created EC2 Launch Template.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Search).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_ApplicationAndOSImages_Select) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Application and OS Images->Search->Select'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Application and OS Images->Search->Select to select EC2 AMI (Amazon Machine Image) to configure for EC2 Instance(s) created from soon-to-be-created EC2 Launch Template.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_ApplicationAndOSImages_Select).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_InstanceType) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Instance Type'
                $this.Summary        = "Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Instance Type and selected '{{instanceType}}' EC2 Instance Type."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                $this.AnchorEvents   = @('ec2:DescribeInstanceTypeOfferings')
                $this.RequiredEvents = @('ec2:DescribeInstanceTypeOfferings')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Create) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Key Pair (Login)->Create New Key Pair'
                $this.Summary        = "Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Key Pair (Login)->Create New Key Pair to create '{{keyName}}' key pair to configure for remote access to EC2 Instance(s) created from soon-to-be-created EC2 Launch Template."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_KeyPair_Create
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Create).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Select) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Key Pair (Login)'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Key Pair (Login) dropdown to select key pair to configure for remote access to EC2 Instance(s) created from soon-to-be-created EC2 Launch Template.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_KeyPair_Select
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_KeyPair_Select).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_CreateSecurityGroup) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Network Settings->Firewall (Security Groups)->Create Security Group'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Network Settings->Firewall (Security Groups)->Create Security Group to specify new Security Group to configure for soon-to-be-created EC2 Launch Template.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                $this.AnchorEvents   = @('ec2:DescribeVpcs')
                $this.RequiredEvents = @('ec2:DescribeVpcs')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_SelectExistingSecurityGroup) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Network Settings->Firewall (Security Groups)->Select Existing Security Group'
                $this.Summary        = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 1.5 of 2)->Network Settings->Firewall (Security Groups)->Select Existing Security Group dropdown to select from list of existing Security Groups to configure for soon-to-be-created EC2 Launch Template.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_EC2_List_SecurityGroups
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_EC2_List_SecurityGroups).LookaheadInSeconds
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step2) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 2 of 2)'
                $this.Summary        = "Clicked EC2->Instances->Launch Templates->Create Launch Template (Step 2 of 2) to create '{{launchTemplateId}}' EC2 Launch Template named '{{launchTemplateName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTemplate:'
                $this.AnchorEvents   = @('ec2:CreateLaunchTemplate')
                $this.RequiredEvents = @('ec2:CreateLaunchTemplate')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->SPECIFICLAUNCHTEMPLATE->Delete'
                $this.Summary        = "Clicked EC2->Instances->Launch Templates->SPECIFICLAUNCHTEMPLATE->Delete to delete '{{launchTemplateId}}' EC2 Launch Template."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchTemplateDetails:launchTemplateId={{launchTemplateId}}'
                $this.AnchorEvents   = @('ec2:DescribeLaunchTemplateVersions','ec2:DescribeTags')
                $this.RequiredEvents = @('ec2:DeleteLaunchTemplate','ec2:DescribeLaunchTemplates','ec2:DescribeLaunchTemplateVersions','ec2:DescribeTags')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Details) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->SPECIFICLAUNCHTEMPLATE->Details'
                $this.Summary        = "Clicked EC2->Instances->Launch Templates->SPECIFICLAUNCHTEMPLATE->Details which displays a summary of all details for '{{launchTemplateId}}' EC2 Launch Template."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchTemplateDetails:launchTemplateId={{launchTemplateId}}'
                $this.AnchorEvents   =  @('ec2:DescribeLaunchTemplates','ec2:DescribeLaunchTemplateVersions')
                $this.RequiredEvents = @('ec2:DescribeLaunchTemplates','ec2:DescribeLaunchTemplateVersions')
            }
            ([LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Versions) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Launch Templates->SPECIFICLAUNCHTEMPLATE->Versions'
                $this.Summary        = "Clicked EC2->Instances->Launch Templates->SPECIFICLAUNCHTEMPLATE->Versions which displays a summary of all versions of '{{launchTemplateId}}' EC2 Launch Template."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LaunchTemplateDetails:launchTemplateId={{launchTemplateId}}'
                $this.AnchorEvents   = @('ec2:DescribeLaunchTemplateVersions')
                $this.RequiredEvents = @('ec2:DescribeLaunchTemplateVersions')
            }
            ([LabelType]::EC2_Instances_ReservedInstances) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Reserved Instances'
                $this.Summary        = "Clicked EC2->Instances->Reserved Instances which displays all Reserved Instances (EC2 and RDS) in a searchable paged format."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#ReservedInstances:'
                $this.AnchorEvents   = @('ec2:DescribeReservedInstances','ec2:DescribeAvailabilityZones','ec2:DescribeAccountAttributes')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeAvailabilityZones','ec2:DescribeInstanceTypes','ec2:DescribeReservedInstances','ec2:DescribeReservedInstancesModifications')
            }
            ([LabelType]::EC2_Instances_SpotRequests) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Spot Requests'
                $this.Summary        = 'Clicked EC2->Instances->Spot Requests which displays all EC2 Spot Instances in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SpotInstances:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes','ec2:DescribeSpotInstanceRequests')
                $this.RequiredEvents = @('ec2:DescribeSpotFleetRequests','ec2:DescribeSpotInstanceRequests')
                $this.OptionalEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeAvailabilityZones','ec2:DescribeImages','ec2:DescribeInstanceTypes','ec2:DescribeVpcs')
            }
            ([LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step1) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Spot Requests->Placement Score (Step 1 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Spot Requests->Placement Score (Step 1 of 2) which scores AWS Regions to help identify optimal Region or Availability Zones in which to run EC2 Spot Instance workloads.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SpotPlacementScore:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeImages','ec2:GetInstanceTypesFromInstanceRequirements')
            }
            ([LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step2) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Spot Requests->Placement Score (Step 2 of 2)'
                $this.Summary        = 'Clicked EC2->Instances->Spot Requests->Placement Score (Step 2 of 2) which scores AWS Regions to help identify optimal Region or Availability Zones in which to run EC2 Spot Instance workloads.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SpotPlacementScore:'
                $this.AnchorEvents   = @('ec2:GetSpotPlacementScores')
                $this.RequiredEvents = @('ec2:GetSpotPlacementScores')
            }
            ([LabelType]::EC2_Instances_SpotRequests_PricingHistory) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Spot Requests->Pricing History'
                $this.Summary        = 'Clicked EC2->Instances->Spot Requests->Pricing History which displays a summary of EC2 Spot Instance costs over time.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SpotInstances:'
                $this.AnchorEvents   = @('ec2:DescribeSpotPriceHistory')
                $this.RequiredEvents = @('ec2:DescribeSpotPriceHistory')
            }
            ([LabelType]::EC2_Instances_SpotRequests_SavingsSummary) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Spot Requests->Savings Summary'
                $this.Summary        = 'Clicked EC2->Instances->Spot Requests->Savings Summary which displays a summary of cost savings from running EC2 Spot Instances versus EC2 Instances.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SpotInstances:'
                $this.AnchorEvents   = @('ec2:DescribeSpotInstanceRequests')
                $this.RequiredEvents = @('ec2:DescribeSpotInstanceRequests')
            }
            ([LabelType]::EC2_Instances_SpotRequests_SpotBlueprints) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Instances->Spot Requests->Spot Blueprints'
                $this.Summary        = 'Clicked EC2->Instances->Spot Requests->Spot Blueprints which displays all EC2 Spot Instance templates (as CloudFormation or Terraform).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SpotBlueprints:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones','ec2:DescribeSpotPriceHistory')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeAvailabilityZones','ec2:DescribeImages','ec2:DescribeSpotPriceHistory','iam:ListInstanceProfiles','iam:ListRoles')
            }
            ([LabelType]::EC2_Limits) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Limits'
                $this.Summary        = "Clicked EC2->Limits which displays limit information for all EC2 resources in a searchable paged format."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Limits:'
                $this.AnchorEvents   = @('elasticloadbalancing:DescribeAccountLimits')
                $this.RequiredEvents = @('autoscaling:DescribeAccountLimits','elasticloadbalancing:DescribeAccountLimits')
            }
            ([LabelType]::EC2_LoadBalancing_LoadBalancers) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Load Balancing->Load Balancers'
                $this.Summary        = 'Clicked EC2->Load Balancing->Load Balancers which displays all EC2 Load Balancers in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#LoadBalancers:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones')
                $this.RequiredEvents = @('arc-zonal-shift:ListZonalShifts','ec2:DescribeAccountAttributes','ec2:DescribeAvailabilityZones','elasticloadbalancing:DescribeAccountLimits','elasticloadbalancing:DescribeLoadBalancers','tagging:GetResources')
            }
            ([LabelType]::EC2_LoadBalancing_TargetGroups) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Load Balancing->Target Groups'
                $this.Summary        = 'Clicked EC2->Load Balancing->Target Groups which displays all EC2 Load Balancing Target Groups in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#TargetGroups:'
                $this.AnchorEvents   = @('elasticloadbalancing:DescribeTargetGroups')
                $this.RequiredEvents = @('elasticloadbalancing:DescribeTargetGroups','tagging:GetResources')
            }
            ([LabelType]::EC2_LoadBalancing_TrustStores) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Load Balancing->Trust Stores'
                $this.Summary        = 'Clicked EC2->Load Balancing->Trust Stores which displays all Trust Stores (for offloading client authentication to the Application Load Balancer) in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#TrustStores:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes','elasticloadbalancing:DescribeTrustStores')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','elasticloadbalancing:DescribeAccountLimits','elasticloadbalancing:DescribeTrustStores')
            }
            ([LabelType]::EC2_LoadBalancing_TrustStores_CreateTrustStore_Step1_BrowseS3) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Load Balancing->Trust Stores->Create Trust Store (Step 1.5 of 2)->Browse S3'
                $this.Summary        = 'Clicked EC2->Load Balancing->Trust Stores->Create Trust Store (Step 1.5 of 2)->Browse S3 to specify location of certificate authority (CA) PEM formatted file to configure for soon-to-be-created Trust Store.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#CreateTrustStore'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::Generic_S3_List_Buckets
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents,
                # LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::Generic_S3_List_Buckets).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::Generic_S3_List_Buckets).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::Generic_S3_List_Buckets).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::Generic_S3_List_Buckets).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::Generic_S3_List_Buckets).LookaheadInSeconds
            }
            ([LabelType]::EC2_NetworkSecurity_ElasticIPs) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Network & Security->Elastic IPs'
                $this.Summary        = 'Clicked EC2->Network & Security->Elastic IPs which displays all static EC2 Elastic IPs in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#Addresses:'
                $this.AnchorEvents   = @('ec2:DescribeAddressesAttribute')
                $this.RequiredEvents = @('ec2:DescribeAddresses','ec2:DescribeAddressesAttribute','ec2:DescribeAddressTransfers','ec2:DescribeNatGateways','ec2:DescribeTags')
            }
            ([LabelType]::EC2_NetworkSecurity_KeyPairs) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Network & Security->Key Pairs'
                $this.Summary        = 'Clicked EC2->Network & Security->Key Pairs which displays all EC2 Key Pairs in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#KeyPairs:'
                $this.AnchorEvents   = @('ec2:DescribeKeyPairs')
                $this.RequiredEvents = @('ec2:DescribeKeyPairs','ec2:DescribeTags')
            }
            ([LabelType]::EC2_NetworkSecurity_NetworkInterfaces) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Network & Security->Network Interfaces'
                $this.Summary        = 'Clicked EC2->Network & Security->Network Interfaces which displays all EC2 Network Interfaces in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#NIC:'
                $this.AnchorEvents   = @('ec2:DescribeNetworkInterfaces')
                $this.RequiredEvents = @('ec2:DescribeNetworkInterfaces','ec2:DescribeTags')
            }
            ([LabelType]::EC2_NetworkSecurity_PlacementGroups) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Network & Security->Placement Groups'
                $this.Summary        = 'Clicked EC2->Network & Security->Placement Groups which displays all EC2 Placement Groups in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#PlacementGroups:'
                $this.AnchorEvents   = @('ec2:DescribePlacementGroups')
                $this.RequiredEvents = @('ec2:DescribePlacementGroups','ec2:DescribeRegions','ec2:DescribeTags')
            }
            ([LabelType]::EC2_NetworkSecurity_SecurityGroups) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Network & Security->Security Groups'
                $this.Summary        = 'Clicked EC2->Network & Security->Security Groups which displays all EC2 Security Groups in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SecurityGroups:'
                $this.AnchorEvents   = @('ec2:DescribeSecurityGroups')
                $this.RequiredEvents = @('ec2:DescribeManagedPrefixLists','ec2:DescribeSecurityGroups','ec2:DescribeTags')
            }
            ([LabelType]::EC2_NetworkSecurity_SecurityGroups_SPECIFICGROUP) {
                $this.Service        = 'EC2'
                $this.Name           = 'Clicked EC2->Network & Security->Security Groups->SPECIFICGROUP'
                $this.Summary        = "Clicked EC2->Network & Security->Security Groups->'{{groupId}}' which displays summary information for current Security Group including Inbound/Outbound rules in a searchable paged format."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/ec2/home?region={{awsRegion}}#SecurityGroup:groupId={{groupId}}'
                $this.AnchorEvents   = @('ec2:DescribeSecurityGroups')
                $this.RequiredEvents = @('ec2:DescribeSecurityGroupRules','ec2:DescribeSecurityGroups','ec2:DescribeTags')
            }
            ([LabelType]::Expanded_SPECIFICMANAGEDPOLICY) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked [+]->SPECIFICMANAGEDPOLICY'
                $this.Summary        = "Clicked [+] to expand contents of managed IAM Policy ARN '{{policyArn}}' ({{versionId}})."
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('iam:GetPolicyVersion')
                $this.RequiredEvents = @('iam:GetPolicy','iam:GetPolicyVersion')
            }
            ([LabelType]::Expanded_SPECIFICINLINEUSERPOLICY) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked [+]->SPECIFICINLINEUSERPOLICY'
                $this.Summary        = "Clicked [+] to expand contents of inline user IAM Policy '{{policyName}}'."
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('iam:GetUserPolicy')
                $this.RequiredEvents = @('iam:GetUserPolicy')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::GuardDuty_Accounts) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Accounts'
                $this.Summary        = 'Clicked GuardDuty->Accounts which displays all AWS accounts associated with current GuardDuty administrator account in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/linked-accounts'
                $this.AnchorEvents   = @('organizations:DescribeOrganization')
                $this.RequiredEvents = @('guardduty:GetMasterAccount','organizations:DescribeOrganization','organizations:ListAWSServiceAccessForOrganization','organizations:ListDelegatedAdministrators')
            }
            ([LabelType]::GuardDuty_Findings) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Findings'
                $this.Summary        = 'Clicked GuardDuty->Findings which displays all GuardDuty findings in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/findings?macros=current'
                $this.AnchorEvents   = @('guardduty:ListFindings')
                $this.RequiredEvents = @('guardduty:GetFindingsStatistics','guardduty:GetMasterAccount','guardduty:ListFilters','guardduty:ListFindings','guardduty:ListMembers','guardduty:ListPublishingDestinations')
            }
            ([LabelType]::GuardDuty_MalwareScans) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Malware Scans'
                $this.Summary        = 'Clicked GuardDuty->Malware Scans which displays all GuardDuty malware scans in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/scans'
                $this.AnchorEvents   = @('guardduty:DescribeMalwareScans')
                $this.RequiredEvents = @('guardduty:DescribeMalwareScans')
            }
            ([LabelType]::GuardDuty_ProtectionPlans_MalwareProtection) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Protection Plans->Malware Protection'
                $this.Summary        = 'Clicked GuardDuty->Protection Plans->Malware Protection to configure on-demand malware scans for EC2 Instances and container workloads.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/malware-scan'
                $this.AnchorEvents   = @('organizations:DescribeOrganization')
                $this.RequiredEvents = @('guardduty:GetMalwareScanSettings','organizations:DescribeOrganization','organizations:ListAWSServiceAccessForOrganization')
                $this.OptionalEvents = @('guardduty:GetRemainingFreeTrialDays')
            }
            ([LabelType]::GuardDuty_ProtectionPlans_MalwareProtection_GeneralSettings_RetainScannedSnapshots_Disable) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Protection Plans->Malware Protection->General Settings->Retain Scanned Snapshots->Disable'
                $this.Summary        = 'Clicked GuardDuty->Protection Plans->Malware Protection->General Settings->Retain Scanned Snapshots->Disable to disable retention of scanned snapshots when malware is detected.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/malware-scan'
                $this.AnchorEvents   = @('guardduty:UpdateMalwareScanSettings')
                $this.RequiredEvents = @('guardduty:UpdateMalwareScanSettings')
            }
            ([LabelType]::GuardDuty_ProtectionPlans_MalwareProtection_GeneralSettings_RetainScannedSnapshots_Enable) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Protection Plans->Malware Protection->General Settings->Retain Scanned Snapshots->Enable'
                $this.Summary        = 'Clicked GuardDuty->Protection Plans->Malware Protection->General Settings->Retain Scanned Snapshots->Enable to enable retention of scanned snapshots when malware is detected.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/malware-scan'
                $this.AnchorEvents   = @('guardduty:UpdateMalwareScanSettings')
                $this.RequiredEvents = @('guardduty:UpdateMalwareScanSettings')
            }
            ([LabelType]::GuardDuty_ProtectionPlans_Suboption_ConfigurationNotAvailable) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Protection Plans->Suboption (Configuration Not Available)'
                $this.Summary        = 'Clicked GuardDuty->Protection Plans->Suboption but configuration is not available (e.g. if current account is managed by a delegated administrator account).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#'
                $this.AnchorEvents   = @('guardduty:GetRemainingFreeTrialDays')
                $this.RequiredEvents = @('guardduty:GetRemainingFreeTrialDays')
            }
            ([LabelType]::GuardDuty_Settings) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Settings'
                $this.Summary        = 'Clicked GuardDuty->Settings which displays all GuardDuty settings for current account (e.g. detector ID, service roles and findings export options).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/settings'
                $this.AnchorEvents   = @('guardduty:ListPublishingDestinations')
                $this.RequiredEvents = @('guardduty:ListPublishingDestinations','guardduty:ListTagsForResource','iam:GetPolicy','iam:GetPolicyVersion','iam:ListAttachedRolePolicies','iam:ListRolePolicies','organizations:DescribeOrganization')
            }
            ([LabelType]::GuardDuty_Settings_GenerateSampleFindings) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Settings->Generate Sample Findings'
                $this.Summary        = 'Clicked GuardDuty->Settings->Generate Sample Findings to populate current findings list with one sample finding for each finding type.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/settings'
                $this.AnchorEvents   = @('guardduty:CreateSampleFindings')
                $this.RequiredEvents = @('guardduty:CreateSampleFindings')
            }
            ([LabelType]::GuardDuty_Settings_Lists) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Lists'
                $this.Summary        = 'Clicked GuardDuty->Lists to configure trusted IP address lists and threat intel lists of known malicious IP addresses for which GuardDuty will ignore and generate findings, respectively.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/lists'
                $this.AnchorEvents   = @('guardduty:ListIPSets')
                $this.RequiredEvents = @('guardduty:ListIPSets','guardduty:ListThreatIntelSets')
            }
            ([LabelType]::GuardDuty_Summary) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Summary'
                $this.Summary        = 'Clicked GuardDuty->Summary which displays a summary of latest findings for GuardDuty service.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/summary'
                $this.AnchorEvents   = @('guardduty:ListFindings')
                $this.RequiredEvents = @('guardduty:ListFindings')
                $this.OptionalEvents = @('ec2:DescribeRegions','guardduty:DescribeOrganizationConfiguration','guardduty:GetDetector','guardduty:GetInvitationsCount','guardduty:GetMasterAccount','guardduty:ListDetectors','guardduty:ListMembers','organizations:DescribeOrganization')
            }
            ([LabelType]::GuardDuty_Usage) {
                $this.Service        = 'GuardDuty'
                $this.Name           = 'Clicked GuardDuty->Usage'
                $this.Summary        = 'Clicked GuardDuty->Usage which displays a summary of all GuardDuty costs by AWS service data source.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/guardduty/home?region={{awsRegion}}#/usage'
                $this.AnchorEvents   = @('guardduty:ListMembers')
                $this.RequiredEvents = @('guardduty:DescribeOrganizationConfiguration','guardduty:GetMasterAccount','guardduty:GetRemainingFreeTrialDays','guardduty:GetUsageStatistics','guardduty:ListMembers')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 5
            }
            ([LabelType]::IAM) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM'
                $this.Summary        = 'Clicked IAM which displays IAM (Identity and Access Management) dashboard.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/home'
                $this.AnchorEvents   = @('iam:GetAccountSummary','iam:ListGroups')
                $this.RequiredEvents = @('iam:GetAccountSummary','organizations:DescribeOrganization')
                $this.OptionalEvents = $this.OptionalEvents = @('iam:ListAccessKeys','iam:ListAccountAliases','iam:ListGroups','iam:ListOpenIDConnectProviders','iam:ListPolicies','iam:ListRoles','iam:ListSAMLProviders','iam:ListUsers')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::IAM_AccountSettings) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Account Settings'
                $this.Summary        = 'Clicked IAM->Account Settings which displays Password Policy and Security Token Service (STS) information.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/account_settings'
                $this.AnchorEvents   = @('iam:ListSTSRegionalEndpointsStatus')
                $this.RequiredEvents = @('ec2:DescribeRegions','iam:GetAccountPasswordPolicy','iam:ListSTSRegionalEndpointsStatus')
            }
            ([LabelType]::IAM_BrowserRefresh) {
                $this.Service        = 'IAM'
                $this.Name           = 'Refreshed Browser in IAM'
                $this.Summary        = 'Refreshed Browser in IAM section of AWS Console.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('iam:ListUserTags','iam:ListAccessKeys')
                $this.RequiredEvents = @('iam:GetAccountSummary','iam:GetLoginProfile','iam:GetUser','iam:ListAccessKeys','iam:ListAccountAliases','iam:ListGroups','iam:ListGroupsForUser','iam:ListMFADevices','iam:ListOpenIDConnectProviders','iam:ListPolicies','iam:ListRoles','iam:ListSAMLProviders','iam:ListUsers','iam:ListUserTags','organizations:DescribeOrganization')
                $this.OptionalEvents = @('iam:GetPolicy','iam:ListAttachedGroupPolicies','iam:ListAttachedUserPolicies','iam:ListGroupPolicies','iam:ListPolicyGenerations','iam:ListUserPolicies')
            }
            ([LabelType]::IAM_IdentityCenter) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Identity Center (successor to AWS Single Sign-On)'
                $this.Summary        = 'Clicked IAM Identity Center (successor to AWS Single Sign-On).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/singlesignon/home?region={{awsRegion}}#/'
                $this.AnchorEvents   = @('organizations:ListDelegatedAdministrators')
                $this.RequiredEvents = @('iam:GetAccountPasswordPolicy','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','sso:DescribeRegisteredRegions')
            }
            ([LabelType]::IAM_Policies) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Policies'
                $this.Summary        = 'Clicked IAM->Policies which displays all IAM Policies in paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/policies'
                $this.AnchorEvents   = @('iam:ListPolicies')
                $this.RequiredEvents = @('iam:ListPolicies')
                # iam:GetPolicy event is only executed if 1+ Policies defined.
                $this.OptionalEvents = @('iam:GetPolicy')
            }
            ([LabelType]::IAM_Policies_NextPage) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Policies (Next Page)'
                $this.Summary        = 'Clicked IAM->Policies->Next Page which displays an additional page of IAM Policies.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/policies'
                $this.AnchorEvents   = @('iam:ListPolicies')
                $this.RequiredEvents = @('iam:ListPolicies')
            }
            ([LabelType]::IAM_Roles) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Roles'
                $this.Summary        = 'Clicked IAM->Roles which displays all IAM Roles in paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/roles'
                $this.AnchorEvents   = @('iam:GetRole')
                $this.RequiredEvents = @('iam:GetRole')
                $this.OptionalEvents = @('iam:GetServiceLinkedRoleDeletionStatus')
            }
            ([LabelType]::IAM_Roles_SPECIFICROLE_Permissions) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Roles>SPECIFICROLE->Permissions'
                $this.Summary        = "Clicked IAM->Roles->'{{roleName}}'->Permissions which displays all permissions for '{{roleName}}' IAM Role."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/roles/details/{{roleName}}'
                $this.AnchorEvents   = @('iam:ListPolicies')
                $this.RequiredEvents = @('access-analyzer:ListPolicyGenerations','iam:GetRole','iam:ListAttachedRolePolicies','iam:ListInstanceProfilesForRole','iam:ListPolicies','iam:ListRolePolicies','iam:ListRoleTags')
            }
            ([LabelType]::IAM_UserGroups) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->User Groups'
                $this.Summary        = 'Clicked IAM->User Groups which displays all IAM User Groups in paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/groups'
                $this.AnchorEvents   = @('iam:ListGroups','iam:GetGroup')
                $this.RequiredEvents = @('iam:ListGroups')
                # Below events are only executed if 1+ IAM User Groups defined.
                $this.OptionalEvents = @('iam:GetAccountSummary','iam:GetGroup','iam:ListAccessKeys','iam:ListAccountAliases','iam:ListAttachedGroupPolicies','iam:ListGroupPolicies','iam:ListOpenIDConnectProviders','iam:ListPolicies','iam:ListRoles','iam:ListSAMLProviders','iam:ListUsers','organizations:DescribeOrganization')
            }
            ([LabelType]::IAM_UserGroups_CreateUserGroup) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->User Groups->Create User Group'
                $this.Summary        = "Clicked IAM->User Groups->Create User Group to create a new IAM User Group '{{groupName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/groups/create'
                $this.AnchorEvents   = @('iam:CreateGroup')
                $this.RequiredEvents = @('iam:CreateGroup','iam:ListGroups')
                # iam:AttachGroupPolicy and iam:ListPolicies events are only executed if 1+ IAM Policies are attached to newly-created IAM Group.
                # iam:AddUserToGroup and iam:ListGroupsForUser events are only executed if 1+ IAM Users are attached to newly-created IAM Group.
                $this.OptionalEvents = @('iam:AddUserToGroup','iam:AttachGroupPolicy'<#,'iam:GetGroup','iam:ListAttachedGroupPolicies','iam:ListGroupPolicies'#>,'iam:ListGroupsForUser','iam:ListPolicies')
            }
            ([LabelType]::IAM_UserGroups_DeleteUserGroup) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->User Groups->Delete User Group'
                $this.Summary        = "Clicked IAM->User Groups->Delete User Group to delete the existing IAM User Group '{{groupName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/groups'
                $this.AnchorEvents   = @('iam:GetGroup')
                $this.RequiredEvents = @('iam:DeleteGroup','iam:GetGroup','iam:ListAttachedGroupPolicies','iam:ListGroupPolicies','iam:ListGroups','iam:ListPolicies')
                # iam:RemoveUserFromGroup event is only executed if current IAM User Group has 1+ IAM Users defined as members.
                # iam:DetachGroupPolicy event is only executed if current IAM User Group has 1+ Policies attached.
                $this.OptionalEvents = @('iam:DetachGroupPolicy','iam:RemoveUserFromGroup')
            }
            ([LabelType]::IAM_Users) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users'
                $this.Summary        = 'Clicked IAM->Users which displays all IAM Users in paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users'
                $this.AnchorEvents   = @('iam:ListMFADevices','iam:ListUsers')
                $this.RequiredEvents = @('iam:GetLoginProfile','iam:ListAccessKeys','iam:ListGroupsForUser','iam:ListMFADevices')
                # iam:GetAccessKeyLastUsed event is only executed if 1+ IAM Users are defined and have 1+ Access Keys defined.
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed','iam:ListSigningCertificates','iam:ListUsers')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing
                # default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 35
            }
            ([LabelType]::IAM_Users_CreateUser_Step1) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->Add User (Step 1 of 2)'
                $this.Summary        = 'Clicked IAM->Users->Add User (Step 1 of 2) to create a new IAM User.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/create'
                $this.AnchorEvents   = @('sso:DescribeRegisteredRegions')
                $this.RequiredEvents = @('iam:GetAccountPasswordPolicy','organizations:DescribeOrganization','organizations:ListDelegatedAdministrators','sso:DescribeRegisteredRegions')
                $this.OptionalEvents = @('iam:ListAccountAliases')
            }
            ([LabelType]::IAM_Users_CreateUser_Step2) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->Add User (Step 2 of 2)'
                $this.Summary        = "Clicked IAM->Users->Add User (Step 2 of 2) to create a new IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/create'
                $this.AnchorEvents   = @('iam:CreateUser','iam:ListMFADevices')
                $this.RequiredEvents = @('iam:CreateUser')
                # iam:AttachUserPolicy event is only executed if created IAM User has 1+ IAM Policies attached.
                $this.OptionalEvents = @('iam:AddUserToGroup','iam:AttachUserPolicy','iam:CreateLoginProfile','iam:GetLoginProfile','iam:ListAccessKeys','iam:ListGroupsForUser','iam:ListMFADevices','iam:ListUsers','iam:PutUserPolicy')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 10
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_AccessAdvisor) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Access Advisor'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Access Advisor which displays all services that IAM User '{{userName}}' can access and when they were last accessed."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=access_advisor'
                $this.AnchorEvents   = @('iam:GenerateServiceLastAccessedDetails')
                $this.RequiredEvents = @('iam:GenerateServiceLastAccessedDetails','iam:GetServiceLastAccessedDetails')
                # iam:ListPoliciesGrantingServiceAccess event is only executed if current IAM User has 1+ Allowed Services defined.
                $this.OptionalEvents = @('iam:ListPoliciesGrantingServiceAccess')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 10
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Delete) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Delete'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Delete to delete existing IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=permissions'
                $this.AnchorEvents   = @('iam:DeleteUser')
                $this.RequiredEvents = @('iam:DeleteUser','iam:ListAccessKeys','iam:ListAttachedUserPolicies','iam:ListGroupsForUser','iam:ListMFADevices','iam:ListServiceSpecificCredentials','iam:ListSigningCertificates','iam:ListSSHPublicKeys','iam:ListUserPolicies')
                # iam:DeleteAccessKey event is only executed if current IAM User has 1+ Access Keys defined.
                # iam:DetachUserPolicy event is only executed if current IAM User has 1+ IAM Policy defined.
                $this.OptionalEvents = @('iam:DeleteAccessKey','iam:DetachUserPolicy')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions which displays all permissions for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=permissions'
                $this.AnchorEvents   = @('iam:ListAccessKeys','iam:ListUserTags')
                $this.RequiredEvents = @('iam:ListAccessKeys','iam:ListUserTags')
                $this.OptionalEvents = @('access-analyzer:ListPolicyGenerations','iam:GetAccessKeyLastUsed','iam:GetLoginProfile','iam:GetPolicy','iam:GetUser','iam:ListAttachedGroupPolicies','iam:ListAttachedUserPolicies','iam:ListGroupPolicies','iam:ListMFADevices','iam:ListPolicies','iam:ListUserPolicies')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->AddUserToGroup'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions->AddUserToGroup to select IAM Group(s) in which to add IAM User '{{userName}}' in order to inherit all IAM Policies associated with selected IAM Group(s)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('iam:GetGroup','iam:ListAttachedGroupPolicies')
                $this.RequiredEvents = @('iam:GetGroup')
                # iam:ListAttachedGroupPolicies event is only executed if any listed IAM Group has 1+ IAM Policies attached.
                $this.OptionalEvents = @('iam:ListAttachedGroupPolicies')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->AttachPoliciesDirectly'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions and selected 'Attach Policies Directly' button."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('iam:ListUserTags')
                $this.RequiredEvents = @('iam:AttachUserPolicy','iam:ListAccessKeys','iam:ListUserTags')
                # iam:GetAccessKeyLastUsed event is only executed if current IAM User has 1+ Access Keys defined.
                # iam:ListAttachedUserPolicies event is only executed if current IAM User has 1+ IAM Policies attached.
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed','iam:ListAttachedUserPolicies')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CopyPermissions) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->CopyPermissions'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions->CopyPermissions to select existing IAM User(s) from which to copy all IAM Group memberships, attached Managed IAM Policies, Inline IAM Policies and Permission Boundaries and apply to IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('iam:ListAttachedUserPolicies')
                $this.RequiredEvents = @('iam:ListAttachedUserPolicies')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->CreateInlinePolicy (Step 1 of 4)'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions->Create Inline Policy (Step 1 of 4) to create Inline IAM Policy for IAM User '{{userName}}' (Step 1 is 'Create Inline Policy' to configure Inline IAM Policy)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('iam:ListPolicies','iam:ListUserTags')
                $this.RequiredEvents = @('access-analyzer:ListPolicyGenerations','iam:GenerateServiceLastAccessedDetails','iam:GetAccessKeyLastUsed','iam:GetAccountPasswordPolicy','iam:GetAccountSummary','iam:GetLoginProfile','iam:GetServiceLastAccessedDetails','iam:GetUser','iam:ListAccessKeys','iam:ListAccountAliases','iam:ListAttachedUserPolicies','iam:ListGroups','iam:ListGroupsForUser','iam:ListMFADevices','iam:ListSigningCertificates','iam:ListUserPolicies','iam:ListUsers','iam:ListUserTags')
                # iam:GetUserPolicy event is only executed if current IAM User has 1+ Inline IAM Policies defined.
                $this.OptionalEvents = @('iam:GetGroup','iam:GetPolicy','iam:GetPolicyVersion','iam:GetUserPolicy','iam:ListGroupPolicies','iam:ListPolicies','iam:ListPolicyVersions')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step2) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->CreateInlinePolicy (Step 2 of 4)'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions->Create Inline Policy (Step 2 of 4) to create Inline IAM Policy for IAM User '{{userName}}' (Step 2 is automatic validation of each edit to newly configured Inline IAM Policy)."            
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('access-analyzer:ValidatePolicy')
                $this.RequiredEvents = @('access-analyzer:ValidatePolicy')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->CreateInlinePolicy (Step 3 of 4)'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions->Create Inline Policy (Step 3 of 4) to create Inline IAM Policy for IAM User '{{userName}}' (Step 3 is 'Review Policy' which reviews validity of newly configured Inline IAM Policy)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('iam:ListPolicies')
                $this.RequiredEvents = @('iam:ListPolicies')
                # iam:GetPolicy event is only executed if current AWS Account has 1+ IAM Users with a Managed IAM Policy directly attached.
                $this.OptionalEvents = @('iam:GetPolicy')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Add Permissions->CreateInlinePolicy (Step 4 of 4)'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Add Permissions->Create Inline Policy (Step 4 of 4) to create Inline IAM Policy '{{policyName}}' for IAM User '{{userName}}' (Step 4 is 'Create Policy' which finally creates newly configured Inline IAM Policy)."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home#/users/details/{{userName}}/add-permissions'
                $this.AnchorEvents   = @('iam:ListAccessKeys','iam:ListGroups')
                $this.RequiredEvents = @('access-analyzer:ListPolicyGenerations','iam:GetAccountSummary','iam:GetLoginProfile','iam:GetUser','iam:ListAccessKeys','iam:ListAccountAliases','iam:ListAttachedUserPolicies','iam:ListGroups','iam:ListGroupsForUser','iam:ListMFADevices','iam:ListOpenIDConnectProviders','iam:ListPolicies','iam:ListRoles','iam:ListSAMLProviders','iam:ListSigningCertificates','iam:ListUserPolicies','iam:ListUsers','iam:ListUserTags','iam:PutUserPolicy','organizations:DescribeOrganization')
                # iam:GetAccessKeyLastUsed event is only executed if current IAM User has 1+ Access Keys defined.
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed','iam:GetPolicy','iam:ListAttachedGroupPolicies','iam:ListGroupPolicies')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 6
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveInlinePolicyForUser) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Remove Policy for User (Inline Policy)'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Remove Policy for User to remove Inline IAM Policy '{{policyName}}' from IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=permissions'
                $this.AnchorEvents   = @('iam:GetUserPolicy')
                $this.RequiredEvents = @('iam:DeleteUserPolicy','iam:GetUserPolicy')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveManagedPolicyForUser) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Permissions->Remove Policy for User (Managed Policy)'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Permissions->Remove Policy for User to remove Managed IAM Policy ARN '{{policyArn}}' from IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=permissions'
                $this.AnchorEvents   = @('iam:DetachUserPolicy')
                $this.RequiredEvents = @('iam:DetachUserPolicy')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials which displays all credential information for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:ListAccessKeys')
                $this.RequiredEvents = @('iam:ListAccessKeys','iam:ListServiceSpecificCredentials','iam:ListSigningCertificates','iam:ListSSHPublicKeys')
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Activate) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Access Keys->Activate'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Access Keys->Activate to activate Access Key '{{accessKeyId}}' for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:UpdateAccessKey','iam:ListAccessKeys')
                $this.RequiredEvents = @('iam:UpdateAccessKey')
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed','iam:ListAccessKeys')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_CreateAccessKey) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Access Keys->Create Access Key'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Access Keys->Create Access Key to create Access Key '{{accessKeyId}}' for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iam/home?region={{awsRegion}}#/users/details/{{userName}}/create-access-key'
                $this.AnchorEvents   = @('iam:CreateAccessKey')
                $this.RequiredEvents = @('iam:CreateAccessKey')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Deactivate) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Access Keys->Deactivate'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Access Keys->Deactivate to deactivate Access Key '{{accessKeyId}}' for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:UpdateAccessKey','iam:ListAccessKeys')
                $this.RequiredEvents = @('iam:UpdateAccessKey')
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed','iam:ListAccessKeys')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Delete) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Access Keys->Delete'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Access Keys->Delete to delete Access Key '{{accessKeyId}}' for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:DeleteAccessKey','iam:ListAccessKeys')
                $this.RequiredEvents = @('iam:DeleteAccessKey')
                $this.OptionalEvents = @('iam:GetAccessKeyLastUsed','iam:ListAccessKeys')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Manage Console Access'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Manage Console Access to add, remove or update AWS Console access for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:GetAccountPasswordPolicy')
                $this.RequiredEvents = @('iam:GetAccountPasswordPolicy')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Disable) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Manage Console Access->Disable'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Manage Console Access->Disable to remove AWS Console access from IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:DeleteLoginProfile','iam:ListUsers')
                $this.RequiredEvents = @('iam:DeleteLoginProfile','iam:GetLoginProfile')
                $this.OptionalEvents = @('iam:ListUsers')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Manage Console Access->Enable'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Manage Console Access->Enable to grant AWS Console access to IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:CreateLoginProfile','iam:ListUsers')
                $this.RequiredEvents = @('iam:CreateLoginProfile','iam:GetLoginProfile')
                # iam:AttachUserPolicy event is only executed if 'User must create new password at next sign-in' checkbox is selected during Console Access enablement prompts.
                # E.g. 'Users automatically get the IAMUserChangePassword policy to allow them to change their own password.'
                $this.OptionalEvents = @('iam:AttachUserPolicy','iam:ListUsers')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Update) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Security Credentials->Manage Console Access->Update'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Security Credentials->Manage Console Access->Update to update password for AWS Console access for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=security_credentials'
                $this.AnchorEvents   = @('iam:UpdateLoginProfile','iam:ListUsers')
                $this.RequiredEvents = @('iam:GetLoginProfile','iam:UpdateLoginProfile')
                # iam:AttachUserPolicy event is only executed if 'User must create new password at next sign-in' checkbox is selected during Console Access update prompts.
                # E.g. 'Users automatically get the IAMUserChangePassword policy to allow them to change their own password.'
                $this.OptionalEvents = @('iam:AttachUserPolicy','iam:ListUsers')
            }
            ([LabelType]::IAM_Users_SPECIFICUSER_Tags) {
                $this.Service        = 'IAM'
                $this.Name           = 'Clicked IAM->Users->SPECIFICUSER->Tags'
                $this.Summary        = "Clicked IAM->Users->'{{userName}}'->Tags which displays all potential tags for IAM User '{{userName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/iamv2/home?region={{awsRegion}}#/users/details/{{userName}}?section=tags'
                $this.AnchorEvents   = @('iam:ListUserTags')
                $this.RequiredEvents = @('iam:ListUserTags')
            }
            ([LabelType]::KMS) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS'
                $this.Summary        = 'Clicked KMS dashboard which displays a general overview of how to get started using KMS.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/home'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::KMS_CustomKeyStores_ExternalKeyStores
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::KMS_CustomKeyStores_ExternalKeyStores).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::KMS_CustomKeyStores_ExternalKeyStores).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::KMS_CustomKeyStores_ExternalKeyStores).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::KMS_CustomKeyStores_ExternalKeyStores).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::KMS_CustomKeyStores_ExternalKeyStores).LookaheadInSeconds
            }
            ([LabelType]::KMS_AWSManagedKeys) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->AWS Managed Keys'
                $this.Summary        = 'Clicked KMS->AWS Managed Keys which displays all AWS managed KMS keys in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/defaultKeys'
                $this.AnchorEvents   = @('kms:ListAliases')
                $this.RequiredEvents = @('kms:ListAliases','tagging:GetResources')
            }
            ([LabelType]::KMS_CustomerManagedKeys) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys'
                $this.Summary        = 'Clicked KMS->Customer Managed Keys which displays all customer managed KMS keys in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1 based on
                # what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('kms:ListAliases')
                $this.RequiredEvents = @('kms:DescribeKey','kms:ListAliases','tagging:GetResources')
                $this.OptionalEvents = @('kms:DescribeCustomKeyStores')
            }
            ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->Create Key (Step 1 of 4)'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->Create Key (Step 1 of 4) to create a new KMS Key in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/create'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::KMS_CustomerManagedKeys
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::KMS_CustomerManagedKeys).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::KMS_CustomerManagedKeys).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::KMS_CustomerManagedKeys).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::KMS_CustomerManagedKeys).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::KMS_CustomerManagedKeys).LookaheadInSeconds
            }
            ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->Create Key (Step 2 of 4)'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->Create Key (Step 2 of 4) to create a new KMS Key in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/create'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step3
                # based on what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('iam:ListRoles')
                $this.RequiredEvents = @('iam:ListRoles','iam:ListUsers')
            }
            ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step3) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->Create Key (Step 3 of 4)'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->Create Key (Step 3 of 4) to create a new KMS Key in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/create'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2).LookaheadInSeconds
            }
            ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->Create Key (Step 4 of 4)'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->Create Key (Step 4 of 4) to create a new KMS Key '{{aliasName}}' with Key ID '{{keyId}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/create'
                $this.AnchorEvents   = @('kms:ListAliases')
                $this.RequiredEvents = @('kms:CreateAlias','kms:CreateKey','kms:DescribeKey','kms:ListAliases','tagging:GetResources')
            }
            ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_CryptographicConfiguration) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->SPECIFICKEY->Cryptographic Configuration'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->'{{keyId}}'->Cryptographic Configuration which displays cryptographic configuration details for KMS Key ID '{{keyId}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/{{keyId}}/cryptographicConfiguration'
                $this.AnchorEvents   = @('kms:ListAliases')
                $this.RequiredEvents = @('kms:DescribeKey','kms:ListAliases')
            }
            ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->SPECIFICKEY->Key Policy'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->'{{keyId}}'->Key Policy which displays IAM Users, IAM Roles and AWS Accounts granted access to use and/or administer KMS Key ID '{{keyId}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/{{keyId}}/keyPolicy'
                $this.AnchorEvents   = @('iam:ListRoles','kms:GetKeyPolicy','kms:ListAliases')
                $this.RequiredEvents = @('iam:ListRoles','iam:ListUsers','kms:GetKeyPolicy')
                $this.OptionalEvents = @('kms:DescribeKey','kms:ListAliases')
            }
            ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->SPECIFICKEY->Key Rotation'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->'{{keyId}}'->Key Rotation which displays checkbox to automatically perform annual rotation of KMS Key ID '{{keyId}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/{{keyId}}/keyRotation'
                $this.AnchorEvents   = @('kms:ListAliases')
                $this.RequiredEvents = @('kms:DescribeKey','kms:GetKeyRotationStatus','kms:ListAliases','kms:ListResourceTags')
            }
            ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_Tags) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Customer Managed Keys->SPECIFICKEY->Tags'
                $this.Summary        = "Clicked KMS->Customer Managed Keys->'{{keyId}}'->Tags which displays all potential tags for KMS Key ID '{{keyId}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/keys/{{keyId}}/tags'
                $this.AnchorEvents   = @('kms:ListAliases')
                $this.RequiredEvents = @('kms:DescribeKey','kms:ListAliases','kms:ListResourceTags')
            }
            ([LabelType]::KMS_CustomKeyStores_AWSCloudHSMKeyStores) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Custom Key Stores->AWS CloudHSM Key Stores'
                $this.Summary        = 'Clicked KMS->Custom Key Stores->AWS CloudHSM Key Stores which displays all customer managed KMS keys stored in custom key store in AWS CloudHSM cluster in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/custom-key-stores/cloudhsm'
                $this.AnchorEvents   = @('kms:DescribeCustomKeyStores')
                $this.RequiredEvents = @('cloudhsm:DescribeClusters','kms:DescribeCustomKeyStores')
            }
            ([LabelType]::KMS_CustomKeyStores_ExternalKeyStores) {
                $this.Service        = 'KMS'
                $this.Name           = 'Clicked KMS->Custom Key Stores->External Key Stores'
                $this.Summary        = 'Clicked KMS->Custom Key Stores->External Key Stores which displays all customer managed KMS keys stored in an external (i.e. outside of AWS) key manager in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/kms/home?region={{awsRegion}}#/kms/custom-key-stores/external'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::KMS based on what Signal follows it,
                # so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('kms:DescribeCustomKeyStores')
                $this.RequiredEvents = @('kms:DescribeCustomKeyStores')
            }
            ([LabelType]::S3_AccessPoints) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Access Points'
                $this.Summary        = "Clicked S3->Access Points to show all Access Points in AWS Region '{{awsRegionArr}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/ap?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:ListAccessPoints')
                $this.RequiredEvents = @('s3:ListAccessPoints')
            }
            ([LabelType]::S3_BatchOperations) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Batch Operations'
                $this.Summary        = "Clicked S3->Batch Operations to show all jobs in AWS Region '{{awsRegionArr}}' with Status Type '{{jobStatusesArr}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/jobs?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:ListJobs')
                $this.RequiredEvents = @('s3:ListJobs')
            }
            ([LabelType]::S3_BlockPublicAccessSettings) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Block Public Access Settings For This Account'
                $this.Summary        = 'Clicked S3->Block Public Access Settings For This Account to show and control the settings that allow public access to data in S3 Buckets.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/settings?region={{awsRegion}}'
                # This mapping scenario is linked to and can potentially be replaced by [LabelType]::S3_Buckets_CreateBucket_Step1 based on
                # what Signal follows it, so ensure any changes to event properties below do not cause unexpected results for these mapping scenarios.
                $this.AnchorEvents   = @('s3:GetAccountPublicAccessBlock')
                $this.RequiredEvents = @('s3:GetAccountPublicAccessBlock')
            }
            ([LabelType]::S3_Buckets) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets'
                $this.Summary        = "Clicked S3->Buckets to show all S3 Buckets in all AWS Regions."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:GetStorageLensConfiguration')
                $this.RequiredEvents = @('s3:GetStorageLensConfiguration','s3:GetStorageLensDashboardDataInternal')
                $this.OptionalEvents = @('s3:GetAccountPublicAccessBlock','s3:GetBucketAcl','s3:GetBucketPolicyStatus','s3:GetBucketPublicAccessBlock','s3:ListAccessPoints','s3:ListBuckets')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 7
            }
            ([LabelType]::S3_Buckets_CreateBucket_Step1) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->Create Bucket (Step 1 of 2)'
                $this.Summary        = "Clicked S3->Buckets->Create Bucket (Step 1 of 2) to create a new S3 Bucket in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/bucket/create?region={{awsRegion}}'
                # This mapping scenario will only be used as a potential replacement of [LabelType]::S3_BlockPublicAccessSettings
                # based on what Signal follows it, so it will always replicate its AnchorEvents, RequiredEvents, OptionalEvents, LookbackInSeconds and LookaheadInSeconds properties.
                $this.AnchorEvents       = [Signal]::new([LabelType]::S3_BlockPublicAccessSettings).AnchorEvents
                $this.RequiredEvents     = [Signal]::new([LabelType]::S3_BlockPublicAccessSettings).RequiredEvents
                $this.OptionalEvents     = [Signal]::new([LabelType]::S3_BlockPublicAccessSettings).OptionalEvents
                $this.LookbackInSeconds  = [Signal]::new([LabelType]::S3_BlockPublicAccessSettings).LookbackInSeconds
                $this.LookaheadInSeconds = [Signal]::new([LabelType]::S3_BlockPublicAccessSettings).LookaheadInSeconds
            }
            ([LabelType]::S3_Buckets_CreateBucket_Step1B) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->Create Bucket (Step 1.5 of 2)->Copy Settings From Existing Bucket'
                $this.Summary        = "Clicked S3->Buckets->Create Bucket (Step 1.5 of 2)->Copy Settings From Existing Bucket to copy permissions from existing S3 Bucket '{{bucketNameForPermissionsCopy}}' in AWS Region '{{awsRegionForPermissionsCopy}}' to apply when creating a new S3 Bucket in AWS Region '{{awsRegionForBucketCreation}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/bucket/create?region={{awsRegionForBucketCreation}}'
                $this.AnchorEvents   = @('s3:GetBucketVersioning')
                $this.RequiredEvents = @('s3:GetBucketEncryption','s3:GetBucketObjectLockConfiguration','s3:GetBucketPublicAccessBlock','s3:GetBucketTagging','s3:GetBucketVersioning')
            }
            ([LabelType]::S3_Buckets_CreateBucket_Step2) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->Create Bucket (Step 2 of 2)'
                $this.Summary        = "Clicked S3->Buckets->Create Bucket (Step 2 of 2) to create a new S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/bucket/create?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:CreateBucket')
                $this.RequiredEvents = @('s3:CreateBucket','s3:GetAccountPublicAccessBlock','s3:GetBucketAcl','s3:GetBucketEncryption','s3:GetBucketObjectLockConfiguration','s3:GetBucketOwnershipControls','s3:GetBucketPolicyStatus','s3:GetBucketPublicAccessBlock','s3:GetBucketTagging','s3:GetBucketVersioning','s3:GetStorageLensConfiguration','s3:GetStorageLensDashboardDataInternal','s3:ListAccessPoints','s3:ListBuckets','s3:PutBucketEncryption')
                # s3:PutBucketPublicAccessBlock event is only executed if 'Block all public access' checkbox is selected for newly created S3 Bucket.
                # s3:PutBucketTagging event is only executed if newly created S3 Bucket has 1+ Tags added.
                $this.OptionalEvents = @('s3:PutBucketPublicAccessBlock','s3:PutBucketTagging')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 8
            }
            ([LabelType]::S3_Buckets_DeleteBucket_Step1) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->Delete Bucket (Step 1 of 2)'
                $this.Summary        = "Clicked S3->Buckets->Delete Bucket (Step 1 of 2) to delete the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/bucket/{{bucketName}}/delete?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:GetBucketWebsite')
                $this.RequiredEvents = @('s3:GetBucketPolicy','s3:GetBucketWebsite','s3:ListAccessPoints','s3:ListMultiRegionAccessPoints')
            }
            ([LabelType]::S3_Buckets_DeleteBucket_Step2) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->Delete Bucket (Step 2 of 2)'
                $this.Summary        = "Clicked S3->Buckets->Delete Bucket (Step 2 of 2) to delete the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/bucket/{{bucketName}}/delete?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:DeleteBucket')
                $this.RequiredEvents = @('s3:DeleteBucket','s3:ListBuckets')
            }
            ([LabelType]::S3_Buckets_EmptyBucket) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->Empty Bucket'
                $this.Summary        = "Clicked S3->Buckets->Empty Bucket to empty all items from the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/bucket/{{bucketName}}/empty?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:GetBucketVersioning')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetEventSelectors','s3:GetBucketObjectLockConfiguration','s3:GetBucketVersioning')
            }
            ([LabelType]::S3_Buckets_SPECIFICBUCKET_AccessPoints) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->SPECIFICBUCKET->Access Points'
                $this.Summary        = "Clicked S3->Buckets->'{{bucketName}}'->Access Points which displays all S3 Access Points attached to the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets/{{bucketName}}?region={{awsRegion}}&tab=accesspoint'
                $this.AnchorEvents   = @('s3:ListAccessPoints')
                $this.RequiredEvents = @('s3:ListAccessPoints')
            }
            ([LabelType]::S3_Buckets_SPECIFICBUCKET_Management) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->SPECIFICBUCKET->Management'
                $this.Summary        = "Clicked S3->Buckets->'{{bucketName}}'->Management which displays management options (Lifecycle Rules, Replication Rules and Inventory Configurations) for the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets/{{bucketName}}?region={{awsRegion}}&tab=management'
                $this.AnchorEvents   = @('s3:GetBucketReplication')
                $this.RequiredEvents = @('s3:GetBucketInventoryConfiguration','s3:GetBucketLifecycle','s3:GetBucketReplication')
            }
            ([LabelType]::S3_Buckets_SPECIFICBUCKET_Metrics) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->SPECIFICBUCKET->Metrics'
                $this.Summary        = "Clicked S3->Buckets->'{{bucketName}}'->Metrics which displays metrics (Bucket Metrics, Replication Metrics and Storage Class Analysis) for the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets/{{bucketName}}?region={{awsRegion}}&tab=metrics'
                $this.AnchorEvents   = @('s3:GetBucketReplication')
                $this.RequiredEvents = @('s3:GetBucketAnalyticsConfiguration','s3:GetBucketReplication')
            }
            ([LabelType]::S3_Buckets_SPECIFICBUCKET_Objects) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->SPECIFICBUCKET->Objects'
                $this.Summary        = "Clicked S3->Buckets->'{{bucketName}}'->Objects to list all objects in the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets/{{bucketName}}?region={{awsRegion}}&tab=objects'
                $this.AnchorEvents   = @('s3:GetBucketVersioning','s3:GetAccountPublicAccessBlock')
                $this.RequiredEvents = @('s3:GetBucketOwnershipControls','s3:GetBucketVersioning')
                $this.OptionalEvents = @('s3:GetAccountPublicAccessBlock','s3:GetBucketAcl','s3:GetBucketPolicyStatus','s3:GetBucketPublicAccessBlock','s3:ListAccessPoints')
            }
            ([LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->SPECIFICBUCKET->Permissions'
                $this.Summary        = "Clicked S3->Buckets->'{{bucketName}}'->Permissions which displays all permissions for the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets/{{bucketName}}?region={{awsRegion}}&tab=permissions'
                $this.AnchorEvents   = @('s3:GetBucketAcl','s3:GetAccountPublicAccessBlock')
                $this.RequiredEvents = @('s3:GetAccountPublicAccessBlock','s3:GetBucketAcl','s3:GetBucketCors','s3:GetBucketOwnershipControls','s3:GetBucketPolicy','s3:GetBucketPublicAccessBlock','s3:ListBuckets')
            }
            ([LabelType]::S3_Buckets_SPECIFICBUCKET_Properties) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Buckets->SPECIFICBUCKET->Properties'
                $this.Summary        = "Clicked S3->Buckets->'{{bucketName}}'->Properties to list all properties of the existing S3 Bucket '{{bucketName}}' in AWS Region '{{awsRegion}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/buckets/{{bucketName}}?region={{awsRegion}}&tab=properties'
                $this.AnchorEvents   = @('s3:GetBucketVersioning')
                $this.RequiredEvents = @('cloudtrail:DescribeTrails','cloudtrail:GetEventSelectors','s3:GetAccelerateConfiguration','s3:GetBucketEncryption','s3:GetBucketIntelligentTieringConfiguration','s3:GetBucketLogging','s3:GetBucketNotification','s3:GetBucketObjectLockConfiguration','s3:GetBucketRequestPayment','s3:GetBucketTagging','s3:GetBucketVersioning','s3:GetBucketWebsite')
            }
            ([LabelType]::S3_IAMAccessAnalyzer) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->IAM Access Analyzer'
                $this.Summary        = 'Clicked S3->IAM Access Analyzer to show all S3 Buckets configured to allow access by anyone using the Internet or authenticated AWS users.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/access?region={{awsRegion}}'
                $this.AnchorEvents   = @('access-analyzer:ListAnalyzers')
                $this.RequiredEvents = @('access-analyzer:ListAnalyzers')
            }
            ([LabelType]::S3_MultiRegionAccessPoints) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Multi-Region Access Points'
                $this.Summary        = 'Clicked S3->Multi-Region Access Points to show all Multi-Region Access Points.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/mraps?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:ListMultiRegionAccessPoints')
                $this.RequiredEvents = @('s3:ListMultiRegionAccessPoints')
            }
            ([LabelType]::S3_ObjectLambdaAccessPoints) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Object Lambda Access Points'
                $this.Summary        = "Clicked S3->Object Lambda Access Points to show all Object Lambda Access Points in AWS Region '{{awsRegionArr}}'."
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/olap?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:ListAccessPointsForObjectLambda')
                $this.RequiredEvents = @('s3:ListAccessPointsForObjectLambda')
            }
            ([LabelType]::S3_StorageLens_AWSOrganizationsSettings) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Storage Lens->AWS Organizations settings'
                $this.Summary        = 'Clicked S3->Storage Lens->AWS Organizations settings to show and control the settings that authorize Storage Lens access and registration of member accounts as delegated administrators.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/lens/organization-settings?region={{awsRegion}}'
                $this.AnchorEvents   = @('organizations:ListDelegatedAdministrators')
                $this.RequiredEvents = @('organizations:DescribeOrganization','organizations:ListAWSServiceAccessForOrganization','organizations:ListDelegatedAdministrators')
            }
            ([LabelType]::S3_StorageLens_Dashboards) {
                $this.Service        = 'S3'
                $this.Name           = 'Clicked S3->Storage Lens->Dashboards'
                $this.Summary        = 'Clicked S3->Storage Lens->Dashboards to provide visibility into storage usage and activity trends for S3 Buckets.'
                $this.Url            = 'https://s3.console.aws.amazon.com/s3/lens?region={{awsRegion}}'
                $this.AnchorEvents   = @('s3:ListStorageLensConfigurations')
                $this.RequiredEvents = @('s3:ListStorageLensConfigurations')
            }
            ([LabelType]::SearchBar) {
                $this.Service        = 'N/A'
                $this.Name           = 'Typed into Search Bar'
                $this.Summary        = 'Typed content into AWS Console Search Bar.'
                $this.Url            = 'N/A'
                $this.AnchorEvents   = @('resource-explorer-2:ListIndexes')
                $this.RequiredEvents = @('resource-explorer-2:ListIndexes')
            }
            ([LabelType]::SecretsManager_Secrets) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Secrets'
                $this.Summary        = 'Clicked Secrets Manager->Secrets which displays all Secrets in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/listsecrets?region={{awsRegion}}'
                $this.AnchorEvents   = @('secretsmanager:ListSecrets')
                $this.RequiredEvents = @('secretsmanager:ListSecrets')
            }
            ([LabelType]::SecretsManager_Secrets_Create_Step1) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Store a New Secret (Step 1 of 4)'
                $this.Summary        = 'Clicked Secrets Manager->Store a New Secret (Step 1 of 4) to configure type, Key-Value pair and encryption key for soon-to-be-created Secret.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/newsecret?region={{awsRegion}}'
                $this.AnchorEvents   = @('docdb-elastic:ListClusters')
                $this.RequiredEvents = @('docdb-elastic:ListClusters','rds:DescribeDBClusters','rds:DescribeDBInstances','redshift:DescribeClusters')
                $this.OptionalEvents = @('kms:ListAliases')
            }
            ([LabelType]::SecretsManager_Secrets_Create_Step2) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Store a New Secret (Step 2 of 4)'
                $this.Summary        = 'Clicked Secrets Manager->Store a New Secret (Step 2 of 4) to configure name and optional description, tags, permissions and replication for soon-to-be-created Secret.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/newsecret?region={{awsRegion}}'
                $this.AnchorEvents   = @('ec2:DescribeRegions')
                $this.RequiredEvents = @('ec2:DescribeRegions')
            }
            ([LabelType]::SecretsManager_Secrets_Create_Step3) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Store a New Secret (Step 3 of 4)'
                $this.Summary        = 'Clicked Secrets Manager->Store a New Secret (Step 3 of 4) to configure optional rotation schedule for soon-to-be-created Secret.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/newsecret?region={{awsRegion}}'
                $this.AnchorEvents   = @('lambda:ListFunctions20150331')
                $this.RequiredEvents = @('lambda:ListFunctions20150331')
            }
            ([LabelType]::SecretsManager_Secrets_Create_Step4) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Store a New Secret (Step 4 of 4)'
                $this.Summary        = "Clicked Secrets Manager->Store a New Secret (Step 4 of 4) to create a new Secret '{{secretArn}}' named '{{secretName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/newsecret?region={{awsRegion}}'
                $this.AnchorEvents   = @('secretsmanager:ListSecrets')
                $this.RequiredEvents = @('kms:GenerateDataKey','secretsmanager:CreateSecret','secretsmanager:ListSecrets')
                $this.OptionalEvents = @('secretsmanager:RotateSecret')
            }
            ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Secrets->SPECIFICSECRET->Cancel Deletion'
                $this.Summary        = "Clicked Secrets Manager->Secrets->'{{secretName}}'->Cancel Deletion to cancel scheduled deletion of Secret '{{secretArn}}' named '{{secretName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/secret?name={{secretName}}&region={{awsRegion}}'
                $this.AnchorEvents   = @('kms:ListAliases','secretsmanager:DescribeSecret')
                $this.RequiredEvents = @('kms:ListAliases','secretsmanager:DescribeSecret','secretsmanager:GetResourcePolicy','secretsmanager:RestoreSecret')
            }
            ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Delete) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Secrets->SPECIFICSECRET->Delete Secret'
                $this.Summary        = "Clicked Secrets Manager->Secrets->'{{secretName}}'->Delete Secret to schedule deletion of Secret '{{secretArn}}' named '{{secretName}}' on '{{deletionDate}}' (due to recovery window of '{{recoveryWindowInDays}}')."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/secret?name={{secretName}}&region={{awsRegion}}'
                $this.AnchorEvents   = @('secretsmanager:DescribeSecret')
                $this.RequiredEvents = @('kms:ListAliases','secretsmanager:DeleteSecret','secretsmanager:DescribeSecret')
            }
            ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Secrets->SPECIFICSECRET->Overview'
                $this.Summary        = "Clicked Secrets Manager->Secrets->'{{secretName}}'->Overview which displays a summary of all details for Secret '{{secretArn}}' named '{{secretName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/secret?name={{secretName}}&region={{awsRegion}}'
                $this.AnchorEvents   = @('kms:ListAliases','secretsmanager:DescribeSecret')
                $this.RequiredEvents = @('kms:ListAliases','secretsmanager:DescribeSecret','secretsmanager:GetResourcePolicy')
            }
            ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview_RetrieveSecretValue) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Secrets->SPECIFICSECRET->Overview->Retrieve Secret Value'
                $this.Summary        = "Clicked Secrets Manager->Secrets->'{{secretName}}'->Overview->Retrieve Secret Value to display value of Secret '{{secretArn}}' named '{{secretName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/secret?name={{secretName}}&region={{awsRegion}}'
                $this.AnchorEvents   = @('secretsmanager:GetSecretValue')
                $this.RequiredEvents = @('secretsmanager:GetSecretValue')
                $this.OptionalEvents = @('kms:Decrypt')
            }
            ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Versions) {
                $this.Service        = 'SecretsManager'
                $this.Name           = 'Clicked Secrets Manager->Secrets->SPECIFICSECRET->Versions'
                $this.Summary        = "Clicked Secrets Manager->Secrets->'{{secretName}}'->Versions which displays all versions of Secret '{{secretArn}}' named '{{secretName}}'."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/secretsmanager/secret?name={{secretName}}&region={{awsRegion}}'
                $this.AnchorEvents   = @('secretsmanager:ListSecretVersionIds')
                $this.RequiredEvents = @('secretsmanager:ListSecretVersionIds')
            }
            ([LabelType]::VPC_VirtualPrivateCloud_Endpoints) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->Virtual Private Cloud->Endpoints'
                $this.Summary        = 'Clicked VPC->Virtual Private Cloud->Endpoints which displays all VPC Endpoints in a searchable paged format.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpcconsole/home?region={{awsRegion}}#Endpoints:'
                $this.AnchorEvents   = @('ec2:DescribeVpcs')
                $this.RequiredEvents = @('ec2:DescribeInstanceConnectEndpoints','ec2:DescribeVpcEndpoints','ec2:DescribeVpcEndpointServices','ec2:DescribeVpcs')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 5
            }
            ([LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->Virtual Private Cloud->Endpoints->Create Endpoint (Step 1 of 2)'
                $this.Summary        = 'Clicked VPC->Virtual Private Cloud->Endpoints->Create Endpoint (Step 1 of 2) to create a new VPC Endpoint.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpcconsole/home?region={{awsRegion}}#CreateVpcEndpoint:'
                $this.AnchorEvents   = @('ec2:DescribeVpcs')
                $this.RequiredEvents = @('ec2:DescribeVpcEndpointServices','ec2:DescribeVpcs')
                $this.OptionalEvents = @('ec2:DescribeRegions')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 5
            }
            ([LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->Virtual Private Cloud->Endpoints->Create Endpoint (Step 1.5 of 2)->VPC'
                $this.Summary        = "Clicked VPC->Virtual Private Cloud->Endpoints->Create Endpoint (Step 1.5 of 2)->VPC to select the existing VPC '{{vpcId}}' in which to create a new VPC Endpoint."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpcconsole/home?region={{awsRegion}}#CreateVpcEndpoint:'
                $this.AnchorEvents   = @('ec2:DescribeAvailabilityZones')
                $this.RequiredEvents = @('ec2:DescribeAvailabilityZones','ec2:DescribeRouteTables','ec2:DescribeSecurityGroups','ec2:DescribeSubnets')
            }
            ([LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->Virtual Private Cloud->Endpoints->Create Endpoint (Step 2 of 2)'
                $this.Summary        = "Clicked VPC->Virtual Private Cloud->Endpoints->Create Endpoint (Step 2 of 2) to create a new VPC Endpoint '{{vpcEndpointId}}' named '{{vpcName}}' for '{{serviceName}}' service."
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpcconsole/home?region={{awsRegion}}#CreateVpcEndpoint:'
                $this.AnchorEvents   = @('ec2:DescribeVpcs')
                $this.RequiredEvents = @('ec2:CreateVpcEndpoint','ec2:DescribeInstanceConnectEndpoints','ec2:DescribeVpcEndpoints','ec2:DescribeVpcEndpointServices','ec2:DescribeVpcs')
                # Current mapping scenario generates events over a longer-than-normal timespan, so increasing default lookback and/or lookahead values when aggregating nearby events surrounding AnchorEvents.
                $this.LookbackInSeconds  = 5
                $this.LookaheadInSeconds = 7
            }
            ([LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->Virtual Private Cloud->Subnets->Create Subnet (Step 1 of 2)'
                $this.Summary        = 'Clicked VPC->Virtual Private Cloud->Subnets->Create Subnet (Step 1 of 2) to create a new VPC Subnet.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpcconsole/home?region={{awsRegion}}#CreateSubnet:'
                $this.AnchorEvents   = @('ec2:DescribeVpcs')
                $this.RequiredEvents = @('ec2:DescribeAvailabilityZones','ec2:DescribeCarrierGateways','ec2:DescribeIpamPools','ec2:DescribeRegions','ec2:DescribeVpcs')
            }
            ([LabelType]::VPC_VPCDashboard) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard'
                $this.Summary        = 'Clicked VPC->VPC Dashboard which displays counts of all VPC resources (e.g. VPCs, subnets, route tables, etc.).'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeAccountAttributes','ec2:DescribeAddresses','ec2:DescribeCustomerGateways','ec2:DescribeDhcpOptions','ec2:DescribeEgressOnlyInternetGateways','ec2:DescribeInstances','ec2:DescribeInternetGateways','ec2:DescribeNatGateways','ec2:DescribeNetworkAcls','ec2:DescribeRouteTables','ec2:DescribeSecurityGroups','ec2:DescribeSubnets','ec2:DescribeVpcEndpoints','ec2:DescribeVpcEndpointServiceConfigurations','ec2:DescribeVpcPeeringConnections','ec2:DescribeVpcs','ec2:DescribeVpnConnections','ec2:DescribeVpnGateways')
                $this.RequiredEvents = @('ec2:DescribeAccountAttributes','ec2:DescribeAddresses','ec2:DescribeCustomerGateways','ec2:DescribeDhcpOptions','ec2:DescribeEgressOnlyInternetGateways','ec2:DescribeInstances','ec2:DescribeInternetGateways','ec2:DescribeNetworkAcls','ec2:DescribeRegions','ec2:DescribeRouteTables','ec2:DescribeSecurityGroups','ec2:DescribeSubnets','ec2:DescribeVpcEndpoints','ec2:DescribeVpcEndpointServiceConfigurations','ec2:DescribeVpcPeeringConnections','ec2:DescribeVpcs','ec2:DescribeVpnConnections','ec2:DescribeVpnGateways')
                $this.OptionalEvents = @('ec2:DescribeNatGateways')
            }
            ([LabelType]::VPC_VPCDashboard_CustomerGateways_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Customer Gateways->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Customer Gateways->Refresh button to refresh Customer Gateways summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeCustomerGateways')
                $this.RequiredEvents = @('ec2:DescribeCustomerGateways')
            }
            ([LabelType]::VPC_VPCDashboard_DHCPOptionSets_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->DHCP Option Sets->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->DHCP Option Sets->Refresh button to refresh DHCP Option Sets summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeDhcpOptions')
                $this.RequiredEvents = @('ec2:DescribeDhcpOptions')
            }
            ([LabelType]::VPC_VPCDashboard_EgressOnlyInternetGateways_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Egress-Only Internet Gateways->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Egress-Only Internet Gateways->Refresh button to refresh Egress-Only Internet Gateways summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeEgressOnlyInternetGateways')
                $this.RequiredEvents = @('ec2:DescribeEgressOnlyInternetGateways')
            }
            ([LabelType]::VPC_VPCDashboard_ElasticIPs_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Elastic IPs->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Elastic IPs->Refresh button to refresh Elastic IPs summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeAddresses')
                $this.RequiredEvents = @('ec2:DescribeAddresses')
            }
            ([LabelType]::VPC_VPCDashboard_Endpoints_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Endpoints->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Endpoints->Refresh button to refresh Endpoints summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeVpcEndpoints')
                $this.RequiredEvents = @('ec2:DescribeVpcEndpoints')
            }
            ([LabelType]::VPC_VPCDashboard_EndpointServices_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Endpoint Services->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Endpoint Services->Refresh button to refresh Endpoint Services summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeVpcEndpointServiceConfigurations')
                $this.RequiredEvents = @('ec2:DescribeVpcEndpointServiceConfigurations')
            }
            ([LabelType]::VPC_VPCDashboard_InternetGateways_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Internet Gateways->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Internet Gateways->Refresh button to refresh Internet Gateways summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeInternetGateways')
                $this.RequiredEvents = @('ec2:DescribeInternetGateways')
            }
            ([LabelType]::VPC_VPCDashboard_NATGateways_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->NAT Gateways->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->NAT Gateways->Refresh button to refresh NAT Gateways summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeNatGateways')
                $this.RequiredEvents = @('ec2:DescribeNatGateways')
            }
            ([LabelType]::VPC_VPCDashboard_NetworkACLs_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Network ACLs->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Network ACLs->Refresh button to refresh Network ACLs summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeNetworkAcls')
                $this.RequiredEvents = @('ec2:DescribeNetworkAcls')
            }
            ([LabelType]::VPC_VPCDashboard_RouteTables_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Route Tables->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Route Tables->Refresh button to refresh Route Tables summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeRouteTables')
                $this.RequiredEvents = @('ec2:DescribeRouteTables')
            }
            ([LabelType]::VPC_VPCDashboard_RunningInstances_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Running Instances->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Running Instances->Refresh button to refresh Running Instances summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeInstances')
                $this.RequiredEvents = @('ec2:DescribeInstances')
            }
            ([LabelType]::VPC_VPCDashboard_SecurityGroups_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Security Groups->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Security Groups->Refresh button to refresh Security Groups summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeSecurityGroups')
                $this.RequiredEvents = @('ec2:DescribeSecurityGroups')
            }
            ([LabelType]::VPC_VPCDashboard_SiteToSiteVPNConnections_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Site-to-Site VPN Connections->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Site-to-Site VPN Connections->Refresh button to refresh Site-to-Site VPN Connections summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeVpnConnections')
                $this.RequiredEvents = @('ec2:DescribeVpnConnections')
            }
            ([LabelType]::VPC_VPCDashboard_Subnets_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Subnets->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Subnets->Refresh button to refresh Subnets summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeSubnets')
                $this.RequiredEvents = @('ec2:DescribeSubnets')
            }
            ([LabelType]::VPC_VPCDashboard_VirtualPrivateGateways_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->Virtual Private Gateways->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->Virtual Private Gateways->Refresh button to refresh Virtual Private Gateways summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeVpnGateways')
                $this.RequiredEvents = @('ec2:DescribeVpnGateways')
            }
            ([LabelType]::VPC_VPCDashboard_VPCPeeringConnections_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->VPC Peering Connections>Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->VPC Peering Connections>Refresh button to refresh VPC Peering Connections summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeVpcPeeringConnections')
                $this.RequiredEvents = @('ec2:DescribeVpcPeeringConnections')
            }
            ([LabelType]::VPC_VPCDashboard_VPCs_Refresh) {
                $this.Service        = 'VPC'
                $this.Name           = 'Clicked VPC->VPC Dashboard->VPCs->Refresh'
                $this.Summary        = 'Clicked VPC->VPC Dashboard->VPCs->Refresh button to refresh VPCs summary dashboard tile.'
                $this.Url            = 'https://{{awsRegion}}.console.aws.amazon.com/vpc/home?region={{awsRegion}}#Home:'
                $this.AnchorEvents   = @('ec2:DescribeVpcs')
                $this.RequiredEvents = @('ec2:DescribeVpcs')
            }
            default {
                Write-Warning "Unhandled LabelType ($LabelType) in Signal constructor switch block."
            }
        }
    }
}



function Confirm-ValidSignalDefinition
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Confirm-ValidSignalDefinition
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Confirm-ValidSignalDefinition validates correct ordering and absence of duplicates of fully qualified event names in specific event properties for all Signal definitions.

.PARAMETER SignalDict

Specifies Dictionary containing all Signal definitions.

.PARAMETER Property

(Optional) Specifies event property or properties to include in validation checks.

.EXAMPLE

PS C:\> $signalDict = @{ }
PS C:\> [LabelType].GetEnumNames().ForEach( { $signalDict.Add([LabelType] $_,[Signal]::new([LabelType] $_)) } )
PS C:\> Confirm-ValidSignalDefinition -Signal $signalDict -Property RequiredEvents,OptionalEvents

WARNING: [Confirm-ValidSignalDefinition] The following 1 duplicate event found in RequiredEvents and OptionalEvents properties in [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1's Signal definition: 'iam:ListAttachedUserPolicies'
WARNING: [Confirm-ValidSignalDefinition] Incorrect ordering of events (or duplicate events) found in 'OptionalEvents' property in [LabelType]::S3_StorageLens_AWSOrganizationsSettings' Signal definition:
         INCORRECT :: $this.OptionalEvents = @('organizations:ListAWSServiceAccessForOrganization','organizations:ListAWSServiceAccessForOrganization')
         CORRECT   :: $this.OptionalEvents = @('organizations:ListAWSServiceAccessForOrganization')
False

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Boolean])] 
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Hashtable]
        $SignalDict,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('RequiredEvents','OptionalEvents')]
        [System.String[]]
        $Property = @('RequiredEvents','OptionalEvents')
    )

    # Define Boolean to capture final cumulative validation state of user input -Signal object.
    $isValid = $true

    # Remove any potential duplicate values from user input -Property parameter.
    $Property = $Property | Select-Object -Unique

    # Enumerate all LabelType enum names in user input -Signal object.
    foreach ($label in [LabelType[]] [LabelType].GetEnumNames())
    {
        # Check for potential duplicate event values in RequiredEvents and OptionalEvents
        # properties if both are defined in user input -Property parameter.
        if ($Property -icontains 'RequiredEvents' -and $Property -icontains 'OptionalEvents')
        {
            # Retrieve any duplicate event values existing in both RequiredEvents and
            # OptionalEvents properties in current Label's Signal definition.
            $duplicateEventArr = (
                [System.Array] `
                ($SignalDict[$label].RequiredEvents | Select-Object -Unique) + `
                ($SignalDict[$label].OptionalEvents | Select-Object -Unique)
            ) | Group-Object | Where-Object { $_.Count -gt 1 }

            # Output warning message if any duplicate event values exist in both RequiredEvents
            # and OptionalEvents properties in current Label's Signal definition.
            if ($duplicateEventArr)
            {
                $isValid = $false

                Write-Warning "[$($MyInvocation.MyCommand.Name)] The following $(($duplicateEventArr | Measure-Object).Count) duplicate event$(($duplicateEventArr | Measure-Object).Count -eq 1 ? '' : 's') found in RequiredEvents and OptionalEvents properties in [LabelType]::$label'$(([System.String] $label).EndsWith('s') ? '' : 's') Signal definition: $($duplicateEventArr.ForEach( { "'$($_.Name)'" } ) -join ',')"
            }
        }

        # Iterate over each user input -Property parameter and check for any out-of-order
        # array elements in current Label's Signal definition.
        foreach ($curProperty in $Property)
        {
            # Continue validation checks if current Label has current user input -Property defined.
            if ($SignalDict[$label].$curProperty.Count -gt 0)
            {
                # Compare current ordering and sorted ordering of current label's -Property value.
                # Output warning message if ordering mismatch exists (can also occur if duplicate
                # values exist in same property).
                $curPropertyOrig = $SignalDict[$label].$curProperty
                $curPropertySort = $SignalDict[$label].$curProperty | Sort-Object -Unique
                if ([System.String] $curPropertyOrig -cne [System.String] $curPropertySort)
                {
                    $isValid = $false

                    # Generate incorrect and correct syntaxes of current property array for more
                    # actionable warning message.
                    $incorrectArrSyntax = "`$this.$curProperty = @(" + ($curPropertyOrig.ForEach( { "'$_'" } ) -join ',') + ')'
                    $correctArrSyntax   = "`$this.$curProperty = @(" + ($curPropertySort.ForEach( { "'$_'" } ) -join ',') + ')'

                    Write-Warning "[$($MyInvocation.MyCommand.Name)] Incorrect ordering of events (or duplicate events) found in '$curProperty' property in [LabelType]::$label'$(([System.String] $label).EndsWith('s') ? '' : 's') Signal definition:`n         INCORRECT :: $incorrectArrSyntax`n         CORRECT   :: $correctArrSyntax"
                }
            }
        }
    }

    # Return final cumulative validation state.
    $isValid
}



# Define single Hashtable (i.e. Dictionary) to store instances of Signal definitions for
# all Labels in LabelType enum.
$signalDict = @{ }
[LabelType].GetEnumNames().ForEach( { $signalDict.Add([LabelType] $_,[Signal]::new([LabelType] $_)) } )



# Perform temporary validation checks to ensure non-duplciate, alphabetical ordering of
# all event properties in Signal object definitions above.
Confirm-ValidSignalDefinition -Signal $signalDict -Property RequiredEvents,OptionalEvents | Out-Null