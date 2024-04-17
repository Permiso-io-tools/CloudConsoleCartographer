function Add-Label
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Add-Label
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Get-UserAgentFamily
Optional Dependencies: None

.DESCRIPTION

Add-Label adds Labels to Enrichment property for input events as a pre-requisite for full mapping evaluation in Add-Signal function.

.PARAMETER Event

Specifies events onto which to add Labels.

.EXAMPLE

PS C:\> aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 | Format-EventObject | Add-Label | Select-Object -First 5

Enrichment Event
---------- -----
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}

.EXAMPLE

PS C:\> aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 > awsCliOutput.json
PS C:\> dir awsCliOutput.json | Format-EventObject | Add-Label | Select-Object -First 5

Enrichment Event
---------- -----
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([PSCustomObject[]])] 
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $Event
    )

    begin
    {
        # Create ArrayList to store all pipelined input Events before beginning final processing.
        $eventArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input Events to ArrayList before beginning final processing.
        if ($Event.Count -gt 1)
        {
            # Add all -Event objects to ArrayList.
            if ($Event -is [System.Collections.Hashtable])
            {
                # Add single -Event Hashtable object to ArrayList.
                $eventArr.Add($Event) | Out-Null
            }
            else
            {
                # Add all -Event objects to ArrayList.
                $eventArr.AddRange($Event)
            }
        }
        else
        {
            # Add single -Event object to ArrayList.
            $eventArr.Add($Event) | Out-Null
        }
    }

    end
    {
        # Iterate over each event and store in separate array, potentially adding Label(s)
        # to each event in separate Enrichment object.
        foreach ($event in $eventArr)
        {
            # Extract normalized UserAgentFamily object for more efficient evaluations
            # throughout current function.
            $userAgentFamily = Get-UserAgentFamily -UserAgent $event.userAgent

            # Standardize format of requestParameters JSON object as simple string for
            # more efficient evaluations throughout current function.
            $requestParametersStr = [System.String]::IsNullOrEmpty($event.requestParameters) ? $null : (ConvertTo-Json -InputObject $event.requestParameters -Depth 25 -Compress)

            # Standardize format of requestParameters JSON object's sorted base level key
            # name(s) as string for more efficient evaluations throughout current function.
            # Separately extract all sorted keys as well as keys with empty values.
            $requestParametersKeyStr         = ($event.requestParameters.Keys | Sort-Object) -join ','                                                                             
            $requestParametersKeyEmptyValStr = ($event.requestParameters.Keys.Where( { (ConvertTo-Json -InputObject $event.requestParameters.$_ -Depth 25 -Compress) -cin @('{}','""') } ) | Sort-Object) -join ','

            # Set fully qualified eventSource+eventName value for more accurate and efficient
            # evaluations throughout current function (e.g. combining eventSource and
            # eventName in AWS events so 'iam:CreateAccessKey' instead of separate
            # 'iam.amazonaws.com' and 'CreateAccessKey' values).
            $eventNameFull = $event.eventSource.Split('.')[0] + ':' + $event.eventName

            # Add any potential Label(s) to Label array for current event.
            $labelArr = @(switch ($event.eventSource)
            {
                'access-analyzer.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'ListAnalyzers' {
                            # E.g. {"maxResults":"1","type":"ACCOUNT"}
                            if (
                                $requestParametersKeyStr -ceq 'maxResults,type' -and `
                                $event.requestParameters.maxResults -ceq '1' -and `
                                $event.requestParameters.type -ceq 'ACCOUNT' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_IAMAccessAnalyzer
                            }
                        }
                        'ListPolicyGenerations' {
                            # E.g. {"principalArn":"arn:aws:iam::012345678900:user/userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'principalArn' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                            }
                        }
                        'ValidatePolicy' {
                            # E.g. {"policyDocument":"{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"VisualEditor0\",\n            \"Effect\": \"Allow\",\n            \"Action\": \"forecast:QueryForecast\",\n            \"Resource\": \"*\"\n        }\n    ]\n}","locale":"EN","policyType":"IDENTITY_POLICY"}
                            if (
                                $requestParametersKeyStr -ceq 'locale,policyDocument,policyType' -and `
                                $event.requestParameters.policyType -ceq 'IDENTITY_POLICY' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step2
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'arc-zonal-shift.amazonaws.com' {
                    switch($event.eventName)
                    {
                        'ListZonalShifts' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                            }
                        }
                    }
                }
                'autoscaling.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeAccountLimits' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Limits
                            }
                        }
                        'DescribeAutoScalingGroups' {
                            # E.g. {"maxRecords":100}
                            if (
                                $requestParametersStr -ceq '{"maxRecords":100}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                            }
                            # E.g. {"maxRecords":100}
                            elseif ($requestParametersStr -ceq '{"maxRecords":100}')
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::EC2_AutoScaling_AutoScalingGroups
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'billingconsole.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'GetBillingNotifications' {
                            # E.g. {"messageType":"Banner","consoleType":"Billing"}
                            if (
                                $requestParametersKeyStr -ceq 'consoleType,messageType' -and `
                                $event.requestParameters.messageType -ceq 'Banner' -and `
                                $event.requestParameters.consoleType -ceq 'Billing' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::Billing_Home
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'ce.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'GetCostAndUsage' {
                            # E.g. {"Filter":{"Not":{"Or":[{"Dimensions":{"Values":["Credit"],"Key":"RECORD_TYPE"}},{"Dimensions":{"Values":["Refund"],"Key":"RECORD_TYPE"}}]}},"Granularity":"MONTHLY","GroupBy":[{"Key":"SERVICE","Type":"DIMENSION"}],"Metrics":["UnblendedCost"],"TimePeriod":{"End":"2023-05-01T00:00:00.0000000Z","Start":"2023-03-01T00:00:00.0000000Z"}}
                            # E.g. {"TimePeriod":{"End":"2024-03-05T00:00:00Z","Start":"2024-03-01T00:00:00Z"},"Metrics":["NetUnblendedCost"],"Granularity":"MONTHLY","Filter":{"Not":{"Or":[{"Dimensions":{"Key":"RECORD_TYPE","Values":["Credit"]}},{"Dimensions":{"Key":"RECORD_TYPE","Values":["Refund"]}}]}}}
                            if (
                                $requestParametersKeyStr -cin@('Filter,Granularity,GroupBy,Metrics,TimePeriod','Filter,Granularity,Metrics,TimePeriod') -and `
                                $event.requestParameters.Granularity -ceq 'MONTHLY' -and `
                                [System.String] $event.requestParameters.Metrics -cin @('UnblendedCost','NetUnblendedCost') -and `
                                $requestParametersStr.Contains('"Filter":{"Not":{"Or":[{"Dimensions":{"') -and `
                                $requestParametersStr.Contains('"Values":["Credit"]') -and `
                                $requestParametersStr.Contains('"Values":["Refund"]')
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::ConsoleHome
                            }
                        }
                        'GetCostForecast' {
                            # E.g. {"Filter":{"Not":{"Or":[{"Dimensions":{"Key":"RECORD_TYPE","Values":["Credit"]}},{"Dimensions":{"Key":"RECORD_TYPE","Values":["Refund"]}}]}},"Granularity":"MONTHLY","Metric":"NET_UNBLENDED_COST","TimePeriod":{"End":"2023-12-01T00:00:00.0000000Z","Start":"2023-11-25T00:00:00.0000000Z"}}
                            if (
                                $requestParametersKeyStr -ceq 'Filter,Granularity,Metric,TimePeriod' -and `
                                $event.requestParameters.Granularity -ceq 'MONTHLY' -and `
                                $event.requestParameters.Metric -ceq 'NET_UNBLENDED_COST' -and `
                                $requestParametersStr.Contains('"Filter":{"Not":{"Or":[{"Dimensions":{"') -and `
                                $requestParametersStr.Contains('"Values":["Credit"]') -and `
                                $requestParametersStr.Contains('"Values":["Refund"]')
                            )
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'cloudhsm.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeClusters' {
                            # E.g. {"limit":50}
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::KMS_CustomKeyStores_AWSCloudHSMKeyStores
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'cloudshell.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'CreateEnvironment' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                        }
                        'CreateSession' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                            [LabelType]::CloudShell_Actions_DownloadFile
                            [LabelType]::CloudShell_Actions_UploadFile
                        }
                        'DeleteSession' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_Actions_DownloadFile
                            [LabelType]::CloudShell_Actions_UploadFile
                            [LabelType]::CloudShell_ExitSession
                        }
                        'GetEnvironmentStatus' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                            [LabelType]::CloudShell_Actions_DownloadFile
                            [LabelType]::CloudShell_Actions_UploadFile
                            [LabelType]::CloudShell_ExitSession
                        }
                        'GetFileDownloadUrls' {
                            [LabelType]::CloudShell_Actions_DownloadFile
                        }
                        'GetFileUploadUrls' {
                            [LabelType]::CloudShell_Actions_UploadFile
                        }
                        'GetLayout' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                        }
                        'PutCredentials' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                        }
                        'RedeemCode' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                        }
                        'SendHeartBeat' {
                            [LabelType]::SuppressAutomatedBackgroundEvent_CloudShell_Heartbeat
                        }
                        'StartEnvironment' {
                            [LabelType]::CloudShell_NewSession
                        }
                        'UpdateLayout' {
                            [LabelType]::CloudShell_RenewSession
                            [LabelType]::CloudShell_NewSession
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'cloudtrail.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'CreateTrail' {
                            # E.g. {"name":"myTrailName","kmsKeyId":"arn:aws:kms:us-east-2:012345678900:key/db014773-abcd-1234-5678-133337c0ffee","s3BucketName":"aws-cloudtrail-logs-012345678900-c0ffeeee","s3KeyPrefix":"","includeGlobalServiceEvents":true,"isMultiRegionTrail":true,"enableLogFileValidation":true,"isOrganizationTrail":false}
                            if (
                                $requestParametersKeyStr -ceq 'enableLogFileValidation,includeGlobalServiceEvents,isMultiRegionTrail,isOrganizationTrail,kmsKeyId,name,s3BucketName,s3KeyPrefix' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'DeleteTrail' {
                            # E.g. {"name":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName"}
                            if (
                                $requestParametersKeyStr -ceq 'name' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL_Delete
                            }
                        }
                        'DescribeTrails' {
                            # E.g. {"includeShadowTrails":true,"trailNameList":[]}
                            if (
                                $requestParametersKeyStr -ceq 'includeShadowTrails,trailNameList' -and `
                                $event.requestParameters.includeShadowTrails -eq $true -and `
                                $requestParametersStr.Contains('"trailNameList":[]') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::S3_Buckets_EmptyBucket
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step1
                                [LabelType]::CloudTrail_Dashboard
                                [LabelType]::CloudTrail_Insights
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL_StopLogging
                                [LabelType]::CloudTrail_Trails
                            }
                        }
                        'GetChannel' {
                            # E.g. {"channel":"arn:aws:cloudtrail:us-east-2:012345678900:channel/aws-service-channel/inspector2/db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'channel' -and `
                                $event.requestParameters.channel.Contains(':channel/aws-service-channel/inspector2/')
                            )
                            {
                                [LabelType]::CloudTrail_Settings_Scenario2
                            }
                        }
                        'GetEventSelectors' {
                            # E.g. {"trailName":"arn:aws:cloudtrail:us-east-2:012345678900:trail/management-events"}
                            if (
                                $requestParametersKeyStr -ceq 'trailName' -and `
                                $event.requestParameters.trailName.Contains(':trail/') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::S3_Buckets_EmptyBucket
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step1
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                            }
                        }
                        'GetInsightSelectors' {
                            # E.g. {"trailName":"arn:aws:cloudtrail:us-east-2:012345678900:trail/management-events"}
                            if (
                                $requestParametersKeyStr -ceq 'trailName' -and `
                                $event.requestParameters.trailName.Contains(':trail/') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                            }
                        }
                        'GetTrail' {
                            # E.g. {"name":"arn:aws:cloudtrail:us-east-2:012345678900:trail/management-events"}
                            if (
                                $requestParametersKeyStr -ceq 'name' -and `
                                $event.requestParameters.name.Contains(':trail/')
                            )
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::CloudTrail_Insights_Scenario2
                            }
                        }
                        'GetTrailStatus' {
                            # E.g. {"name":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName"}
                            # E.g. {"name":"arn:aws:cloudtrail:us-east-2:012345678900:trail/management-events"}
                            if (
                                $requestParametersKeyStr -ceq 'name' -and `
                                $event.requestParameters.name.Contains(':trail/')
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step1
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::CloudTrail_Dashboard
                                [LabelType]::CloudTrail_Insights_Scenario2
                                [LabelType]::CloudTrail_Insights
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL_StopLogging
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                                [LabelType]::CloudTrail_Trails
                            }
                        }
                        'ListChannels' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Settings_Scenario2
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::CloudTrail_Lake_Integrations
                            }
                        }
                        'ListEventDataStores' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::CloudTrail_Lake_Dashboard
                                [LabelType]::CloudTrail_Lake_Integrations
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::Generic_CloudTrail_ListEventDataStores
                            }
                        }
                        'ListTags' {
                            # E.g. {"resourceIdList":["arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName"]}
                            if (
                                $requestParametersKeyStr -ceq 'resourceIdList' -and `
                                $requestParametersStr.Contains(':trail/') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                            }
                        }
                        'ListTrails' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::CloudTrail_Insights_Scenario2
                            }
                        }
                        'LookupEvents' {
                            # E.g. {"maxResults":50,"lookupAttributes":[{"attributeKey":"EventName","attributeValue":"CreateUser"}]}
                            # E.g. {"maxResults":50,"lookupAttributes":[{"attributeKey":"ReadOnly","attributeValue":"false"}]}
                            # E.g. {"startTime":"Feb 17, 2008, 5:17:55 AM","endTime":"Feb 17, 2008, 6:17:55 AM","lookupAttributes":[{"attributeKey":"ReadOnly","attributeValue":"false"}],"maxResults":50}
                            # E.g. {"startTime":"Feb 17, 2008, 5:17:55 AM","endTime":"Feb 17, 2008, 6:17:55 AM","lookupAttributes":[{"attributeKey":"ReadOnly","attributeValue":"false"}],"maxResults":50,"nextToken":"HyQs<REDACTED>W6td"}
                            if (
                                $requestParametersKeyStr -cin @(
                                    'lookupAttributes,maxResults'
                                    'lookupAttributes,maxResults,nextToken'
                                    'endTime,lookupAttributes,maxResults,startTime'
                                    'endTime,lookupAttributes,maxResults,nextToken,startTime'
                                ) -and `
                                $requestParametersStr.Contains('"attributeKey":"') -and `
                                $requestParametersStr.Contains('"attributeValue":"') -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::CloudTrail_EventHistory
                            }
                            # E.g. {"startTime":"Feb 17, 2008, 5:17:55 AM","endTime":"Feb 17, 2008, 6:17:55 AM","maxResults":50}
                            elseif (
                                $requestParametersKeyStr -ceq 'endTime,maxResults,startTime' -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::CloudTrail_EventHistory
                            }
                            # E.g. {"maxResults":5,"lookupAttributes":[{"attributeKey":"ReadOnly","attributeValue":"false"}]}
                            elseif (
                                $requestParametersKeyStr -ceq 'lookupAttributes,maxResults' -and `
                                $requestParametersStr.Contains('"attributeKey":"ReadOnly"') -and `
                                $requestParametersStr.Contains('"attributeValue":"false"') -and `
                                $event.requestParameters.maxResults -eq 5 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard
                            }
                            # E.g. {"maxResults":25,"eventCategory":"insight"}
                            # E.g. {"maxResults":25,"eventCategory":"insight","nextToken":"HyQs<REDACTED>W6td"}
                            elseif (
                                $requestParametersKeyStr -cin @('eventCategory,maxResults','eventCategory,maxResults,nextToken') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 25 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard
                            }
                            # E.g. {"maxResults":20,"startTime":"Feb 17, 2008, 2:39:00 AM","endTime":"Feb 17, 2008, 2:43:00 AM","lookupAttributes":[{"attributeKey":"EventName","attributeValue":"CreateSession"}]}
                            elseif (
                                $requestParametersKeyStr -cin @('endTime,lookupAttributes,maxResults,startTime','endTime,lookupAttributes,maxResults,nextToken,startTime') -and `
                                $requestParametersStr.Contains('"attributeKey":') -and `
                                $requestParametersStr.Contains('"attributeValue":') -and `
                                $event.requestParameters.maxResults -eq 20 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                            }
                            # E.g. {"maxResults":50,"startTime":"Feb 17, 2008, 1:11:00 AM","endTime":"Feb 17, 2008, 4:11:00 AM","lookupAttributes":[{"attributeKey":"EventName","attributeValue":"CreateSession"}],"eventCategory":"insight"}
                            elseif (
                                $requestParametersKeyStr -cin @('endTime,eventCategory,lookupAttributes,maxResults,startTime','endTime,eventCategory,lookupAttributes,maxResults,nextToken,startTime') -and `
                                $requestParametersStr.Contains('"attributeKey":') -and `
                                $requestParametersStr.Contains('"attributeValue":') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 50 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                            }
                            # E.g. {"maxResults":50,"lookupAttributes":[{"attributeKey":"EventName","attributeValue":"CreateSession"}],"eventCategory":"insight"}
                            # E.g. {"maxResults":50,"lookupAttributes":[{"attributeKey":"EventId","attributeValue":"db014773-abcd-1234-5678-133337c0ffee"}],"eventCategory":"insight"}
                            elseif (
                                $requestParametersKeyStr -cin @('eventCategory,lookupAttributes,maxResults','eventCategory,lookupAttributes,maxResults,nextToken') -and `
                                $requestParametersStr.Contains('"attributeKey":') -and `
                                $requestParametersStr.Contains('"attributeValue":') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 50 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                            }
                            # E.g. {"maxResults":50,"lookupAttributes":[{"attributeKey":"EventId","attributeValue":"db014773-abcd-1234-5678-133337c0ffee"}],"eventCategory":"insight"}
                            elseif (
                                $requestParametersKeyStr -cin @('eventCategory,lookupAttributes,maxResults','eventCategory,lookupAttributes,maxResults,nextToken') -and `
                                $requestParametersStr.Contains('"attributeKey":') -and `
                                $requestParametersStr.Contains('"attributeValue":') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::CloudTrail_Insights
                            }
                            # E.g. {"maxResults":50,"eventCategory":"insight"}
                            elseif (
                                $requestParametersKeyStr -cin @('eventCategory,maxResults','eventCategory,maxResults,nextToken') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::CloudTrail_Insights_Scenario2
                                [LabelType]::CloudTrail_Insights
                            }
                            # E.g. {"maxResults":50,"startTime":"Feb 17, 2008, 5:15:20 AM","endTime":"Feb 18, 2008, 5:15:20 AM","eventCategory":"insight"}
                            elseif (
                                $requestParametersKeyStr -cin @('endTime,eventCategory,maxResults,startTime','endTime,eventCategory,maxResults,nextToken,startTime') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::CloudTrail_Insights
                            }
                            # E.g. {"maxResults":50,"startTime":"Feb 17, 2008, 5:15:42 AM","endTime":"Apr 17, 2008, 5:15:42 AM","lookupAttributes":[{"attributeKey":"EventName","attributeValue":"CreateSession"}],"eventCategory":"insight"}
                            elseif (
                                $requestParametersKeyStr -cin @('endTime,eventCategory,lookupAttributes,maxResults,startTime','endTime,eventCategory,lookupAttributes,maxResults,nextToken,startTime') -and `
                                $requestParametersStr.Contains('"attributeKey":') -and `
                                $requestParametersStr.Contains('"attributeValue":') -and `
                                $event.requestParameters.eventCategory -ceq 'insight' -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::CloudTrail_Insights
                            }
                            # E.g. {"maxResults":5,"lookupAttributes":[{"attributeKey":"ReadOnly","attributeValue":"false"}],"endTime":"Feb 17, 2008, 2:36:08 AM"}
                            elseif (
                                $requestParametersKeyStr -ceq 'endTime,lookupAttributes,maxResults' -and `
                                $requestParametersStr.Contains('"attributeKey":"ReadOnly"') -and `
                                $requestParametersStr.Contains('"attributeValue":"false"') -and `
                                $event.requestParameters.maxResults -eq 5 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard
                            }
                            elseif (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $event.errorCode -ceq 'ThrottlingException' -and `
                                $event.errorMessage -ceq 'Rate exceeded' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard
                            }
                            # E.g. {"maxResults":1}
                            elseif (
                                $requestParametersKeyStr -ceq 'maxResults' -and `
                                $event.requestParameters.maxResults -eq 1)
                            {
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                            }
                        }
                        'PutEventSelectors' {
                            # E.g. {"trailName":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName","advancedEventSelectors":[{"name":"Management events selector","fieldSelectors":[{"field":"eventCategory","equals":["Management"]}]}]}
                            if (
                                $requestParametersKeyStr -ceq 'advancedEventSelectors,trailName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'PutInsightSelectors' {
                            # E.g. {"trailName":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName","insightSelectors":[]}
                            if (
                                $requestParametersKeyStr -ceq 'insightSelectors,trailName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'StartLogging' {
                            # E.g. {"name":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName"}
                            if (
                                $requestParametersKeyStr -ceq 'name' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'StopLogging' {
                            # E.g. {"name":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName"}
                            if (
                                $requestParametersKeyStr -ceq 'name' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL_StopLogging
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'compute-optimizer.amazonaws.com' {
                    switch ($event.eventName) {
                        # E.g. {"maxResults":0,"accountIds":["012345678900"],"volumeArns":["arn:aws:ec2:us-east-1:012345678900:volume/vol-01234567890abcdef"]}
                        'GetEBSVolumeRecommendations' {
                            if (
                                $requestParametersKeyStr -ceq 'accountIds,maxResults,volumeArns' -and `
                                $requestParametersStr.Contains(':volume/vol-') -and `
                                $event.requestParameters.maxResults -eq 0 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                            }
                        }
                        'GetEnrollmentStatus' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances
                            }
                        }
                    }
                }
                'config.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeConfigurationRecorders' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_EventHistory
                                [LabelType]::CloudTrail_EventHistory_SPECIFICEVENT
                            }
                            # E.g. {"configurationRecorderNames":[]}
                            elseif ($requestParametersStr -ceq '{"configurationRecorderNames":[]}')
                            {
                                [LabelType]::EC2_Instances_DedicatedHosts
                            }
                        }
                        'DescribeConfigurationRecorderStatus' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_EventHistory
                                [LabelType]::CloudTrail_EventHistory_SPECIFICEVENT
                            }
                        }
                        'ListDiscoveredResources' {
                            # E.g. {"limit":0,"resourceType":"AWS::SecretsManager::Secret","includeDeletedResources":true}
                            if (
                                $requestParametersKeyStr -ceq 'includeDeletedResources,limit,resourceType' -and `
                                $event.requestParameters.includeDeletedResources -eq $true -and `
                                $event.requestParameters.limit -eq 0
                            )
                            {
                                [LabelType]::CloudTrail_EventHistory
                                [LabelType]::CloudTrail_EventHistory_SPECIFICEVENT
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'cost-optimization-hub.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'ListEnrollmentStatuses' {
                            if (
                                $requestParametersKeyStr -ceq 'includeOrganizationInfo' -and `
                                $event.requestParameters.includeOrganizationInfo -eq $false
                            )
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'ListRecommendationSummaries' {
                            # E.g. {"limit":0,"resourceType":"AWS::SecretsManager::Secret","includeDeletedResources":true}
                            if (
                                $requestParametersKeyStr -ceq 'filter,groupBy' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filter' -and `
                                $event.requestParameters.groupBy -ceq 'Region'
                            )
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'discovery-marketplace.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'GetSearchFacets' {
                            # E.g. {"filters":[{"values":["eu-north-1"],"type":"REGION"}],"requestContext":{"integrationId":"HIDDEN_DUE_TO_SECURITY_REASONS"},"facetTypes":["AMI_ARCHITECTURE","AMI_INSTANCE_TYPE","AMI_OPERATING_SYSTEM","AVERAGE_CUSTOMER_RATING","CATEGORY","CREATOR","FULFILLMENT_OPTION_TYPE","PRICING_MODEL","PRICING_UNIT","PROMOTION","PROCUREMENT","REGION","CONTRACT_TYPE"],"maxResultsPerFacet":1000}
                            # E.g. {"filters":[{"type":"REGION","values":["us-east-1"]}],"requestContext":{"integrationId":"HIDDEN_DUE_TO_SECURITY_REASONS"},"searchText":"kali","facetTypes":["AMI_ARCHITECTURE","AMI_INSTANCE_TYPE","AMI_OPERATING_SYSTEM","AVERAGE_CUSTOMER_RATING","CATEGORY","CREATOR","FULFILLMENT_OPTION_TYPE","PRICING_MODEL","PRICING_UNIT","PROMOTION","PROCUREMENT","REGION","CONTRACT_TYPE"],"maxResultsPerFacet":1000}
                            if (
                                $requestParametersKeyStr -cin @('facetTypes,filters,maxResultsPerFacet,requestContext','facetTypes,filters,maxResultsPerFacet,requestContext,searchText') -and `
                                $event.requestParameters.requestContext.integrationId -ceq 'HIDDEN_DUE_TO_SECURITY_REASONS' -and `
                                $event.requestParameters.maxResultsPerFacet -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMICatalog
                            }
                        }
                        'SearchListings' {
                            # E.g. {"maxResults":6,"requestContext":{"integrationId":"HIDDEN_DUE_TO_SECURITY_REASONS"}}
                            if (
                                $requestParametersKeyStr -ceq 'maxResults,requestContext' -and `
                                $event.requestParameters.requestContext.integrationId -ceq 'HIDDEN_DUE_TO_SECURITY_REASONS' -and `
                                $event.requestParameters.maxResults -eq 6 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::AWSMarketplace
                            }
                            # E.g. {"maxResults":12,"requestContext":{"integrationId":"HIDDEN_DUE_TO_SECURITY_REASONS"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'maxResults,requestContext' -and `
                                $event.requestParameters.requestContext.integrationId -ceq 'HIDDEN_DUE_TO_SECURITY_REASONS' -and `
                                $event.requestParameters.maxResults -eq 12 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::AWSMarketplace_Suboption
                            }
                            # E.g. {"maxResults":50,"filters":[{"values":["eu-north-1"],"type":"REGION"}],"requestContext":{"integrationId":"HIDDEN_DUE_TO_SECURITY_REASONS"},"sort":{"sortBy":"RELEVANT","sortOrder":"DESCENDING"}}
                            # E.g. {"maxResults":50,"filters":[{"type":"REGION","values":["us-east-1"]}],"requestContext":{"integrationId":"HIDDEN_DUE_TO_SECURITY_REASONS"},"searchText":"kali","sort":{"sortBy":"RELEVANT","sortOrder":"DESCENDING"}}
                            elseif (
                                $requestParametersKeyStr -cin @('filters,maxResults,requestContext,sort','filters,maxResults,requestContext,searchText,sort') -and `
                                $event.requestParameters.requestContext.integrationId -ceq 'HIDDEN_DUE_TO_SECURITY_REASONS' -and `
                                $event.requestParameters.maxResults -eq 50 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMICatalog
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'dlm.amazonaws.com' {
                    switch ($event.eventName) {
                        'GetLifecyclePolicies' {
                            # E.g. {"resourceTypes":"INSTANCE","state":"ENABLED","targetTags":"Name=myTagGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'resourceTypes,state,targetTags' -and `
                                $event.requestParameters.resourceTypes -ceq 'INSTANCE' -and `
                                $event.requestParameters.state -ceq 'ENABLED' -and `
                                $userAgentFamily -eq [UserAgentFamily]::EC2_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ConfigureStorage_ViewBackupInformation
                            }
                            # E.g. {"resourceTypes":"INSTANCE","defaultPolicyType":"INSTANCE"}
                            elseif (
                                $requestParametersKeyStr -ceq 'defaultPolicyType,resourceTypes' -and `
                                $event.requestParameters.resourceTypes -ceq 'INSTANCE' -and `
                                $event.requestParameters.defaultPolicyType -ceq 'INSTANCE' -and `
                                $userAgentFamily -eq [UserAgentFamily]::EC2_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ConfigureStorage_ViewBackupInformation
                            }
                            elseif (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::EC2_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_ElasticBlockStore_Lifecycle
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'docdb-elastic.amazonaws.com' {
                    switch ($event.eventName) {
                        'ListClusters' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step1
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'ec2-instance-connect.amazonaws.com' {
                    switch ($event.eventName) {
                        'SendSSHPublicKey' {
                            # E.g. {"instanceId":"i-01234567890abcdef","instanceOSUser":"ubuntu","sSHPublicKey":"ssh-ed25519 AAAAC3Nz........dMBipE4n\n"}
                            if ($requestParametersKeyStr -ceq 'instanceId,instanceOSUser,sSHPublicKey')
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect
                            }
                        }
                    }
                }
                'ec2.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'AuthorizeSecurityGroupIngress' {
                            # E.g. {"groupId":"sg-01234567890abcdef","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"groups":{},"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]},"ipv6Ranges":{},"prefixListIds":{}}]}}
                            if (
                                $requestParametersKeyStr -ceq 'groupId,ipPermissions' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step2
                            }
                        }
                        'CancelCapacityReservation' {
                            # E.g. {"GetGroupsForCapacityReservationRequest":{"CapacityReservationId":"cr-01234567890abcdef"}}
                            # E.g. {"CancelCapacityReservationRequest":{"CapacityReservationId":"cr-01234567890abcdef"}}
                            if (
                                $requestParametersKeyStr -ceq 'CancelCapacityReservationRequest' -and `
                                $event.requestParameters.CancelCapacityReservationRequest.CapacityReservationId.StartsWith('cr-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                            }
                        }
                        'CreateCapacityReservation' {
                            # E.g. {"CreateCapacityReservationRequest":{"InstanceType":"a1.medium","EndDateType":"limited","Tenancy":"default","InstanceCount":1,"AvailabilityZone":"us-east-1a","InstancePlatform":"Linux/UNIX","EphemeralStorage":false,"InstanceMatchCriteria":"open","EndDate":"2023-08-08T17:37:37.0000000Z","EbsOptimized":false}}
                            if (
                                $requestParametersKeyStr -ceq 'CreateCapacityReservationRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2
                            }
                        }
                        'CreateKeyPair' {
                            # E.g. {"keyName":"myKeyPairName","keyType":"rsa","keyFormat":"pem"}
                            if (
                                $requestParametersKeyStr -ceq 'keyFormat,keyName,keyType' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal                               
                            )
                            {
                                [LabelType]::Generic_EC2_KeyPair_Create
                            }
                        }
                        'CreateLaunchTemplate' {
                            # E.g. {"CreateLaunchTemplateRequest":{"LaunchTemplateName":"minimalistLaunchTemplate","LaunchTemplateData":{"InstanceType":"t2.nano"}}}
                            # E.g. {"CreateLaunchTemplateRequest":{"LaunchTemplateName":"myCustomTemplateName","LaunchTemplateData":{"InstanceType":"t2.micro","KeyName":"myNewKeyPair","ImageId":"ami-01234567890abcdef","NetworkInterface":{"tag":1,"SubnetId":"subnet-01234567890abcdef","DeviceIndex":0,"SecurityGroupId":{"tag":1,"content":"sg-01234567890abcdef"}}}}}
                            if (
                                $requestParametersKeyStr -ceq 'CreateLaunchTemplateRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal                               
                            )
                            {
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step2
                            }
                        }
                        'CreateSecurityGroup' {
                            # E.g. {"vpcId":"vpc-01234567890abcdef","groupName":"launch-wizard-1","groupDescription":"launch-wizard-1 created 2023-11-25T15:14:31.510Z"}
                            if (
                                $requestParametersKeyStr -ceq 'groupDescription,groupName,vpcId' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step2
                            }
                        }
                        'CreateVpcEndpoint' {
                            # E.g. {"CreateVpcEndpointRequest":{"TagSpecification":{"tag":1,"ResourceType":"vpc-endpoint","Tag":{"tag":1,"Value":"myVPCEndpoint1","Key":"Name"}},"IpAddressType":"ipv4","PrivateDnsEnabled":true,"VpcId":"vpc-01234567890abcdef","ServiceName":"aws.api.us-east-1.kendra-ranking","DnsOptions":{"DnsRecordIpType":"ipv4"},"VpcEndpointType":"Interface"}}
                            if (
                                $requestParametersKeyStr -ceq 'CreateVpcEndpointRequest' -and `
                                $event.requestParameters.CreateVpcEndpointRequest.TagSpecification.ResourceType -ceq 'vpc-endpoint'
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                            }
                        }
                        'DeleteLaunchTemplate' {
                            # E.g. {"DeleteLaunchTemplateRequest":{"LaunchTemplateId":"lt-01234567890abcdef"}}
                            if (
                                $requestParametersKeyStr -ceq 'DeleteLaunchTemplateRequest' -and `
                                $event.requestParameters.DeleteLaunchTemplateRequest.LaunchTemplateId.StartsWith('lt-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete
                            }
                        }
                        'DescribeAccountAttributes' {
                            # E.g. {"filterSet":{},"accountAttributeNameSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'accountAttributeNameSet,filterSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'accountAttributeNameSet,filterSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_Instances_SpotRequests
                                [LabelType]::EC2_Instances_ReservedInstances
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                                [LabelType]::EC2_LoadBalancing_TrustStores
                                [LabelType]::EC2_AutoScaling_AutoScalingGroups
                                [LabelType]::EC2_Instances_Instances
                                [LabelType]::EC2_Instances_SpotRequests_SpotBlueprints
                                [LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step1
                                [LabelType]::EC2_ConsoleToCode
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.  
                                [LabelType]::EC2_EC2Dashboard_AccountAttributes_Refresh
                            }
                            # E.g. {"filterSet":{},"accountAttributeNameSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'accountAttributeNameSet,filterSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'accountAttributeNameSet,filterSet' -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                            # E.g. {"filterSet":{},"accountAttributeNameSet":{"items":[{"attributeName":"supported-platforms"}]}}
                            # E.g. {"filterSet":{},"accountAttributeNameSet":{"items":[{"attributeName":"default-vpc"},{"attributeName":"supported-platforms"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'accountAttributeNameSet,filterSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $requestParametersStr.Contains('"attributeName":"supported-platforms"')
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                                [LabelType]::ConsoleHome
                                [LabelType]::VPC_VPCDashboard
                            }
                        }
                        'DescribeAddressTransfers' {
                            # E.g. {"DescribeAddressTransfersRequest":{"MaxResults":10}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeAddressTransfersRequest' -and `
                                $event.requestParameters.DescribeAddressTransfersRequest.MaxResults -eq 10
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_ElasticIPs
                            }
                        }
                        'DescribeAddresses' {
                            # E.g. {"filterSet":{},"publicIpsSet":{},"allocationIdsSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'allocationIdsSet,filterSet,publicIpsSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'allocationIdsSet,filterSet,publicIpsSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                                [LabelType]::EC2_NetworkSecurity_ElasticIPs
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_ElasticIPs_Refresh
                            }
                            # E.g. {"filterSet":{},"publicIpsSet":{},"allocationIdsSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'allocationIdsSet,filterSet,publicIpsSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'allocationIdsSet,filterSet,publicIpsSet'
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"filterSet":{"items":[{"name":"instance-id","valueSet":{"items":[{"value":"i-01234567890abcdef"}]}}]},"publicIpsSet":{},"allocationIdsSet":{}}
                            # E.g. {"filterSet":{"items":[{"name":"instance-id","valueSet":{"items":[{"value":"i-01234567890abcdef"},{"value":"i-01234567890abcdef"}]}}]},"publicIpsSet":{},"allocationIdsSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'allocationIdsSet,filterSet,publicIpsSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'allocationIdsSet,publicIpsSet' -and `
                                $event.requestParameters.filterSet.items.valueSet.items.value.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances
                                [LabelType]::EC2_BrowserRefresh
                            }
                        }
                        'DescribeAddressesAttribute' {
                            # E.g. {"DescribeAddressesAttributeRequest":{"MaxResults":100,"Attribute":"domain-name"}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeAddressesAttributeRequest' -and `
                                $event.requestParameters.DescribeAddressesAttributeRequest.MaxResults -eq 100 -and `
                                $event.requestParameters.DescribeAddressesAttributeRequest.Attribute -ceq 'domain-name' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_ElasticIPs
                            }
                        }
                        'DescribeAvailabilityZones' {
                            # E.g. {"availabilityZoneSet":{},"availabilityZoneIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'availabilityZoneIdSet,availabilityZoneSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'availabilityZoneIdSet,availabilityZoneSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step1
                                [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2
                                [LabelType]::EC2_Instances_CapacityReservations
                                [LabelType]::EC2_Instances_LaunchTemplates
                                [LabelType]::EC2_Instances_SpotRequests
                                [LabelType]::EC2_Instances_SpotRequests_SpotBlueprints
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                                [LabelType]::EC2_Instances_ReservedInstances
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.  
                                [LabelType]::EC2_EC2Dashboard_ServiceHealth_Refresh
                            }
                            # E.g. {"availabilityZoneSet":{},"availabilityZoneIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'availabilityZoneIdSet,availabilityZoneSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'availabilityZoneIdSet,availabilityZoneSet'
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B
                                [LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
                            }
                            # E.g. {"availabilityZoneSet":{},"availabilityZoneIdSet":{},"allAvailabilityZones":true}
                            elseif (
                                $requestParametersKeyStr -ceq 'allAvailabilityZones,availabilityZoneIdSet,availabilityZoneSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'availabilityZoneIdSet,availabilityZoneSet' -and `
                                $event.requestParameters.allAvailabilityZones -eq $true -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.  
                                [LabelType]::EC2_EC2Dashboard_Settings_Zones
                            }
                        }
                        'DescribeCapacityReservations' {
                            # E.g. {"DescribeCapacityReservationsRequest":{"MaxResults":1000}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeCapacityReservationsRequest' -and `
                                $event.requestParameters.DescribeCapacityReservationsRequest.MaxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                                [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2
                                [LabelType]::EC2_Instances_CapacityReservations
                            }
                            # E.g. {"DescribeCapacityReservationsRequest":{"CapacityReservationId":{"tag":1,"content":"cr-01234567890abcdef"}}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeCapacityReservationsRequest' -and `
                                $event.requestParameters.DescribeCapacityReservationsRequest.CapacityReservationId.tag -eq 1 -and `
                                $event.requestParameters.DescribeCapacityReservationsRequest.CapacityReservationId.content.StartsWith('cr-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION
                            }
                        }
                        'DescribeCarrierGateways' {
                            # E.g. {"DescribeCarrierGatewaysRequest":{"MaxResults":1000}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeCarrierGatewaysRequest' -and `
                                $event.requestParameters.DescribeCarrierGatewaysRequest.MaxResults -eq 1000
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
                            }
                        }
                        'DescribeCustomerGateways' {
                            # E.g. {"filterSet":{},"customerGatewaySet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'customerGatewaySet,filterSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'customerGatewaySet,filterSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_CustomerGateways_Refresh
                            }
                        }
                        'DescribeDhcpOptions' {
                            # E.g. {"filterSet":{},"maxResults":1000,"dhcpOptionsSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'dhcpOptionsSet,filterSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'dhcpOptionsSet,filterSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_DHCPOptionSets_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"dhcpOptionsSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'dhcpOptionsSet,filterSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'dhcpOptionsSet,filterSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeEgressOnlyInternetGateways' {
                            # E.g. {"DescribeEgressOnlyInternetGatewaysRequest":{"MaxResults":250}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeEgressOnlyInternetGatewaysRequest' -and `
                                $event.requestParameters.DescribeEgressOnlyInternetGatewaysRequest.MaxResults -eq 250
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"DescribeEgressOnlyInternetGatewaysRequest":{"MaxResults":255}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeEgressOnlyInternetGatewaysRequest' -and `
                                $event.requestParameters.DescribeEgressOnlyInternetGatewaysRequest.MaxResults -eq 255 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_EgressOnlyInternetGateways_Refresh
                            }
                        }
                        'DescribeFastSnapshotRestores' {
                            # E.g. {"DescribeFastSnapshotRestoresRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":"snap-01234567890abcdef"},"Name":"snapshot-id"}}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeFastSnapshotRestoresRequest' -and `
                                $event.requestParameters.DescribeFastSnapshotRestoresRequest.Filter.Name -ceq 'snapshot-id' -and `
                                $event.requestParameters.DescribeFastSnapshotRestoresRequest.Filter.tag -eq 1 -and `
                                $event.requestParameters.DescribeFastSnapshotRestoresRequest.Filter.Value.tag -eq 1 -and `
                                $event.requestParameters.DescribeFastSnapshotRestoresRequest.Filter.Value.content.StartsWith('snap-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details
                            }
                        }
                        'DescribeHosts' {
                            # E.g. {"DescribeHostsRequest":{"MaxResults":500}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeHostsRequest' -and `
                                $event.requestParameters.DescribeHostsRequest.MaxResults -eq 500 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                                [LabelType]::EC2_Instances_DedicatedHosts
                            }
                            # E.g. {"DescribeHostsRequest":{"MaxResults":500}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeHostsRequest' -and `
                                $event.requestParameters.DescribeHostsRequest.MaxResults -eq 500 -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                        }
                        'DescribeImages' {
                            # E.g. {"filterSet":{},"executableBySet":{},"imagesSet":{"items":[{"imageId":"ami-01234567890abcdef"}]},"ownersSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'executableBySet,filterSet,imagesSet,ownersSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'executableBySet,filterSet,ownersSet' -and `
                                $event.requestParameters.imagesSet.items.imageId.StartsWith('ami-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                                [LabelType]::EC2_BrowserRefresh
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Details
                            }
                            # E.g. {"filterSet":{},"maxResults":200,"executableBySet":{},"imagesSet":{},"ownersSet":{"items":[{"owner":"self"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'executableBySet,filterSet,imagesSet,maxResults,ownersSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'executableBySet,filterSet,imagesSet' -and `
                                $event.requestParameters.maxResults -eq 200 -and `
                                $event.requestParameters.ownersSet.items[0].owner -ceq 'self' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                            }
                            # E.g. {"filterSet":{"items":[{"name":"image-id","valueSet":{"items":[{"value":"ami-01234567890abcde1"},{"value":"ami-01234567890abcde2"}]}}]},"ownersSet":{},"executableBySet":{},"imagesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'executableBySet,filterSet,imagesSet,ownersSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'executableBySet,imagesSet,ownersSet' -and `
                                $requestParametersStr.Contains('"name":"image-id"') -and `
                                $requestParametersStr.Contains('"value":"ami-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests
                                [LabelType]::EC2_Instances_SpotRequests_SpotBlueprints
                                [LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step1
                            }
                            # E.g. {"filterSet":{},"ownersSet":{"items":[{"owner":"self"}]},"executableBySet":{},"imagesSet":{}}
                            # E.g. {"filterSet":{"items":[{"name":"is-public","valueSet":{"items":[{"value":"false"}]}}]},"ownersSet":{},"executableBySet":{},"imagesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'executableBySet,filterSet,imagesSet,ownersSet' -and `
                                $requestParametersKeyEmptyValStr -cin @('executableBySet,filterSet,imagesSet','executableBySet,imagesSet,ownersSet') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                # Below Labels have single-event Signal definitions, so ensure they remain last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMICatalog
                                [LabelType]::EC2_Images_AMIs
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"executableBySet":{},"imagesSet":{},"ownersSet":{"items":[{"owner":"self"}]}}
                            # E.g. {"maxResults":1000,"filterSet":{},"executableBySet":{},"imagesSet":{},"ownersSet":{}}
                            # E.g. {"filterSet":{},"nextToken":"HyQs<REDACTED>W6td","maxResults":1000,"ownersSet":{},"executableBySet":{},"imagesSet":{}}
                            elseif (
                                $requestParametersKeyStr -cin @('executableBySet,filterSet,imagesSet,maxResults,ownersSet','executableBySet,filterSet,imagesSet,maxResults,nextToken,ownersSet') -and `
                                $requestParametersKeyEmptyValStr -cin @('executableBySet,filterSet,imagesSet','executableBySet,filterSet,imagesSet,ownersSet','executableBySet,imagesSet,ownersSet','executableBySet,imagesSet') -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMIs
                            }
                        }
                        'DescribeInstanceAttribute' {
                            # E.g. {"instanceId":"i-01234567890abcdef","attribute":"disableApiStop"}
                            # E.g. {"instanceId":"i-01234567890abcdef","attribute":"disableApiTermination"}
                            if (
                                $requestParametersKeyStr -ceq 'attribute,instanceId' -and `
                                $event.requestParameters.attribute -cin @('disableApiStop','disableApiTermination') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1
                            }
                        }
                        'DescribeInstanceConnectEndpoints' {
                            # E.g. {"DescribeInstanceConnectEndpointsRequest":{"MaxResults":50}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeInstanceConnectEndpointsRequest' -and `
                                $event.requestParameters.DescribeInstanceConnectEndpointsRequest.MaxResults -eq 50 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                                [LabelType]::EC2_BrowserRefresh
                            }
                            # E.g. {"DescribeInstanceConnectEndpointsRequest":{"MaxResults":50}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceConnectEndpointsRequest' -and `
                                $event.requestParameters.DescribeInstanceConnectEndpointsRequest.MaxResults -eq 50
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints
                            }
                        }
                        'DescribeInstanceCreditSpecifications' {
                            # E.g. {"DescribeInstanceCreditSpecificationsRequest":{"InstanceId":{"tag":1,"content":"i-01234567890abcdef"}}}
                                if (
                                $requestParametersKeyStr -ceq 'DescribeInstanceCreditSpecificationsRequest' -and `
                                $event.requestParameters.DescribeInstanceCreditSpecificationsRequest.InstanceId.tag -eq 1 -and `
                                $event.requestParameters.DescribeInstanceCreditSpecificationsRequest.InstanceId.content.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                                )
                                {
                                    [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                    [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                    [LabelType]::EC2_Instances_Instances
                                }
                        }
                        'DescribeInstanceStatus' {
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"},{"instanceId":"i-01234567890abcde2"}]},"filterSet":{},"includeAllInstances":false}
                            # E.g. {"filterSet":{},"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]},"includeAllInstances":false}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,includeAllInstances,instancesSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $event.requestParameters.instancesSet.items.instanceId.StartsWith('i-') -and `
                                $event.requestParameters.includeAllInstances -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances
                            }
                            # E.g. {"instancesSet":{},"filterSet":{},"includeAllInstances":false,"maxResults":1000}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,includeAllInstances,instancesSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,instancesSet' -and `
                                $event.requestParameters.includeAllInstances -eq $false -and `
                                $event.requestParameters.maxResults -eq 1000
                            ) 
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_Events
                                [LabelType]::EC2_EC2Dashboard_ScheduledEvents_Refresh
                            }
                        }
                        'DescribeInstanceTypeOfferings' {
                            # E.g. {"DescribeInstanceTypeOfferingsRequest":{"Filter":{"tag":1,"Value":{"tag":1},"Name":"instance-type"},"LocationType":"availability-zone"}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypeOfferingsRequest' -and `
                                $event.requestParameters.DescribeInstanceTypeOfferingsRequest.Filter.Name -ceq 'instance-type' -and `
                                $event.requestParameters.DescribeInstanceTypeOfferingsRequest.LocationType -ceq 'availability-zone' -and `
                                $event.requestParameters.DescribeInstanceTypeOfferingsRequest.Filter.tag -eq 1
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_InstanceType
                            }
                            # E.g. {"DescribeInstanceTypeOfferingsRequest":{"LocationType":"availability-zone"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypeOfferingsRequest' -and `
                                $event.requestParameters.DescribeInstanceTypeOfferingsRequest.LocationType -ceq 'availability-zone' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_InstanceTypes
                            }
                        }
                        'DescribeInstanceTypes' {
                            # E.g. {"DescribeInstanceTypesRequest":{"MaxResults":100}}
                            # E.g. {"DescribeInstanceTypesRequest":{"MaxResults":100,"NextToken":"HyQs<REDACTED>W6td"}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypesRequest' -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.MaxResults -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_InstanceTypes
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                                [LabelType]::EC2_Instances_ReservedInstances
                                [LabelType]::EC2_AutoScaling_AutoScalingGroups
                                [LabelType]::EC2_Instances_Instances
                                [LabelType]::EC2_ConsoleToCode
                            }
                            # E.g. {"DescribeInstanceTypesRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":true},"Name":"burstable-performance-supported"}}}
                            # E.g. {"DescribeInstanceTypesRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":true},"Name":"burstable-performance-supported"},"NextToken":"HyQs<REDACTED>W6td"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypesRequest' -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.tag -eq 1 -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.Value.tag -eq 1 -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.Value.content -eq $true -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.Name -ceq 'burstable-performance-supported' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations
                                [LabelType]::EC2_EC2Dashboard_Settings_DefaultCreditSpecification
                            }
                            # E.g. {"DescribeInstanceTypesRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":"on-demand"},"Name":"supported-usage-class"}}}
                            # E.g. {"DescribeInstanceTypesRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":"on-demand"},"Name":"supported-usage-class"},"NextToken":"HyQs<REDACTED>W6td"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypesRequest' -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.tag -eq 1 -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.Value.tag -eq 1 -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.Value.content -eq 'on-demand' -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.Filter.Name -ceq 'supported-usage-class' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations
                            }
                            # E.g. {"DescribeInstanceTypesRequest":{"InstanceType":[{"tag":1,"content":"t2.2xlarge"},{"tag":2,"content":"t2.large"},{"tag":3,"content":"t2.medium"},{"tag":4,"content":"t2.micro"},{"tag":5,"content":"t2.nano"},{"tag":6,"content":"t2.small"},{"tag":7,"content":"t2.xlarge"},{"tag":8,"content":"t3.2xlarge"},{"tag":9,"content":"t3.large"},{"tag":10,"content":"t3.medium"},{"tag":11,"content":"t3.micro"},{"tag":12,"content":"t3.nano"},{"tag":13,"content":"t3.small"},{"tag":14,"content":"t3.xlarge"},{"tag":15,"content":"t4g.2xlarge"},{"tag":16,"content":"t4g.large"},{"tag":17,"content":"t4g.medium"},{"tag":18,"content":"t4g.micro"},{"tag":19,"content":"t4g.nano"},{"tag":20,"content":"t4g.small"},{"tag":21,"content":"t4g.xlarge"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypesRequest' -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.InstanceType.Count -gt 20 -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.InstanceType[0].tag -eq 1 -and `
                                $requestParametersStr.Contains('"content":"') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            ) 
                            {
                                [LabelType]::EC2_Instances_LaunchTemplates
                                [LabelType]::EC2_Instances_LaunchTemplates_Scenario2
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                            }
                            # E.g. {"DescribeInstanceTypesRequest":{"InstanceType":{"tag":1,"content":"t3.micro"}}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypesRequest' -and `
                                $event.requestParameters.DescribeInstanceTypesRequest.InstanceType.tag -eq 1 -and `
                                $requestParametersStr.Contains('"content":"')
                            ) 
                            {
                                [LabelType]::EC2_BrowserRefresh
                            }
                            # E.g. {"DescribeInstanceTypesRequest":""}
                            # E.g. {"DescribeInstanceTypesRequest":{"NextToken":"HyQs<REDACTED>W6td"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeInstanceTypesRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests
                                [LabelType]::EC2_Instances_ReservedInstances
                            }
                        }
                        'DescribeInstances' {
                            # E.g. {"maxResults":1000,"filterSet":{},"instancesSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,instancesSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                                [LabelType]::EC2_Instances_Instances
                            }
                            # E.g. {"maxResults":1000,"instancesSet":{},"filterSet":{"items":[{"name":"instance-state-name","valueSet":{"items":[{"value":"running"}]}}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'instancesSet' -and `
                                $requestParametersStr.Contains('"name":"instance-state-name"') -and `
                                $requestParametersStr.Contains('"value":"running"') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_RunningInstances_Refresh
                            }
                            # E.g. {"maxResults":100,"filterSet":{},"instancesSet":{}}
                            # E.g. {"maxResults":100,"filterSet":{"items":[{"name":"instance-state-name","valueSet":{"items":[{"value":"running"}]}}]},"instancesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                (
                                    ($requestParametersKeyEmptyValStr -ceq 'filterSet,instancesSet') -or `
                                    (
                                        $requestParametersKeyEmptyValStr -ceq 'instancesSet' -and `
                                        $requestParametersStr.Contains('"name":"instance-state-name"') -and `
                                        $requestParametersStr.Contains('"value":"running"')
                                    )
                                ) -and `
                                $event.requestParameters.maxResults -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                            }
                            # E.g. {"maxResults":200,"filterSet":{"items":[{"name":"instance-state-name","valueSet":{"items":[{"value":"running"}]}}]},"instancesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                (
                                    ($requestParametersKeyEmptyValStr -ceq 'filterSet,instancesSet') -or `
                                    (
                                        $requestParametersKeyEmptyValStr -ceq 'instancesSet' -and `
                                        $requestParametersStr.Contains('"name":"instance-state-name"') -and `
                                        $requestParametersStr.Contains('"value":"running"')
                                    )
                                ) -and `
                                $event.requestParameters.maxResults -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                            }
                            # E.g. {"filterSet":{"items":[{"name":"instance-type","valueSet":{"items":[{"value":"t2.micro"}]}}]},"maxResults":100,"instancesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'instancesSet' -and `
                                $requestParametersStr.Contains('"name":"instance-type"') -and `
                                $event.requestParameters.maxResults -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"instancesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,instancesSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]},"filterSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $requestParametersStr.Contains('"items":[{"instanceId":"i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::EC2_Instances_Instances
                            }
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]},"filterSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $requestParametersStr.Contains('"items":[{"instanceId":"i-')
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect
                            }
                            # E.g. {"filterSet":{"items":[{"name":"instance-state-name","valueSet":{"items":[{"value":"pending"},{"value":"running"},{"value":"stopped"},{"value":"stopping"}]}}]},"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"},{"instanceId":"i-01234567890abcde2"},{"instanceId":"i-01234567890abcde3"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet' -and `
                                $requestParametersStr.Contains('"value":"pending"') -and `
                                $requestParametersStr.Contains('"value":"running"') -and `
                                $requestParametersStr.Contains('"value":"stopped"') -and `
                                $requestParametersStr.Contains('"value":"stopping"') -and `
                                $requestParametersStr.Contains('"name":"instance-state-name"') -and `
                                $requestParametersStr.Contains('"items":[{"instanceId":"i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
                            }
                        }
                        'DescribeInternetGateways' {
                            # E.g. {"filterSet":{},"maxResults":1000,"internetGatewayIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,internetGatewayIdSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,internetGatewayIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_InternetGateways_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"internetGatewayIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,internetGatewayIdSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,internetGatewayIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeIpamPools' {
                            # E.g. {"DescribeIpamPoolsRequest":{"MaxResults":100}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeIpamPoolsRequest' -and `
                                $event.requestParameters.DescribeIpamPoolsRequest.MaxResults -eq 100
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
                            }
                        }
                        'DescribeKeyPairs' {
                            # E.g. {"filterSet":{},"keySet":{},"keyPairIdSet":{},"includePublicKey":false}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,includePublicKey,keyPairIdSet,keySet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,keyPairIdSet,keySet' -and `
                                $event.requestParameters.includePublicKey -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal                               
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                                [LabelType]::EC2_NetworkSecurity_KeyPairs
                                [LabelType]::Generic_EC2_KeyPair_Create
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::Generic_EC2_KeyPair_Select
                            }
                            # E.g. {"filterSet":{},"keySet":{},"keyPairIdSet":{},"includePublicKey":false}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,includePublicKey,keyPairIdSet,keySet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,keyPairIdSet,keySet' -and `
                                $event.requestParameters.includePublicKey -eq $false -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal                               
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                        }
                        'DescribeLaunchTemplateVersions' {
                            # E.g. {"DescribeLaunchTemplateVersionsRequest":{"MaxResults":200,"LaunchTemplateId":"lt-01234567890abcdef"}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeLaunchTemplateVersionsRequest' -and `
                                $event.requestParameters.DescribeLaunchTemplateVersionsRequest.MaxResults -eq 200 -and `
                                $event.requestParameters.DescribeLaunchTemplateVersionsRequest.LaunchTemplateId.StartsWith('lt-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete
                                [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Details
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Versions
                            }
                        }
                        'DescribeLaunchTemplates' {
                            # E.g. {"DescribeLaunchTemplatesRequest":{"MaxResults":1}}
                            if (
                                $requestParametersStr -ceq '{"DescribeLaunchTemplatesRequest":{"MaxResults":1}}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                            # E.g. {"DescribeLaunchTemplatesRequest":{"MaxResults":1}}
                            elseif (
                                $requestParametersStr -ceq '{"DescribeLaunchTemplatesRequest":{"MaxResults":1}}' -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                            # E.g. {"DescribeLaunchTemplatesRequest":{"MaxResults":200,"Filter":{"tag":1,"Value":{"tag":1,"content":"myTemplateName"},"Name":"LaunchTemplateName"}}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeLaunchTemplatesRequest' -and `
                                $event.requestParameters.DescribeLaunchTemplatesRequest.MaxResults -eq 200 -and `
                                $event.requestParameters.DescribeLaunchTemplatesRequest.Filter.Name -ceq 'LaunchTemplateName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_LaunchTemplates_Scenario2
                            }
                            # E.g. {"DescribeLaunchTemplatesRequest":{"MaxResults":200}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeLaunchTemplatesRequest' -and `
                                $event.requestParameters.DescribeLaunchTemplatesRequest.MaxResults -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete
                                [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Details
                                [LabelType]::EC2_Instances_LaunchTemplates_Scenario2
                                [LabelType]::EC2_Instances_LaunchTemplates
                                [LabelType]::EC2_EC2Dashboard_Resources_Settings
                            }
                        }
                        'DescribeManagedPrefixLists' {
                            # E.g. {"DescribeManagedPrefixListsRequest":{"MaxResults":100}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeManagedPrefixListsRequest' -and `
                                $event.requestParameters.DescribeManagedPrefixListsRequest.MaxResults -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_SecurityGroups
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NetworkSettings_FirewallSecurityGroup_Select
                            }
                            # E.g. {"DescribeManagedPrefixListsRequest":{"MaxResults":100}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeManagedPrefixListsRequest' -and `
                                $event.requestParameters.DescribeManagedPrefixListsRequest.MaxResults -eq 100
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeNatGateways' {
                            # E.g. {"DescribeNatGatewaysRequest":{"MaxResults":1000}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeNatGatewaysRequest' -and `
                                $event.requestParameters.DescribeNatGatewaysRequest.MaxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_ElasticIPs
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_NATGateways_Refresh
                            }
                            # E.g. {"DescribeNatGatewaysRequest":{"MaxResults":1000}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeNatGatewaysRequest' -and `
                                $event.requestParameters.DescribeNatGatewaysRequest.MaxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeNetworkAcls' {
                            # E.g. {"filterSet":{},"maxResults":1000,"networkAclIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,networkAclIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,networkAclIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_NetworkACLs_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"networkAclIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,networkAclIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,networkAclIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeNetworkInterfaces' {
                            # E.g. {"networkInterfaceIdSet":{},"filterSet":{"items":[{"name":"attachment.instance-id","valueSet":{"items":[{"value":"i-01234567890abcdef"}]}}]}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,networkInterfaceIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'networkInterfaceIdSet' -and `
                                $event.requestParameters.filterSet.items.name -ceq 'attachment.instance-id' -and `
                                $event.requestParameters.filterSet.items.valueSet.items.value.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"networkInterfaceIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,networkInterfaceIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,networkInterfaceIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_NetworkInterfaces
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"networkInterfaceIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,networkInterfaceIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,networkInterfaceIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribePlacementGroups' {
                            # E.g. {"filterSet":{},"placementGroupSet":{},"placementGroupIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,placementGroupIdSet,placementGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,placementGroupIdSet,placementGroupSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_PlacementGroups
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                            }
                            # E.g. {"filterSet":{},"placementGroupSet":{},"placementGroupIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,placementGroupIdSet,placementGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,placementGroupIdSet,placementGroupSet' -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                            # E.g. {"filterSet":{"items":[{"name":"strategy","valueSet":{"items":[{"value":"cluster"}]}}]},"placementGroupSet":{},"placementGroupIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,placementGroupIdSet,placementGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'placementGroupIdSet,placementGroupSet' -and `
                                $requestParametersStr.Contains('"name":"strategy"') -and `
                                $requestParametersStr.Contains('"value":"cluster"') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step1
                            }
                        }
                        'DescribeRegions' {
                            # E.g. {"regionSet":{},"allRegions":true}
                            if (
                                $requestParametersKeyStr -ceq 'allRegions,regionSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'regionSet' -and `
                                $event.requestParameters.allRegions -eq $true -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_AccountSettings
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                            }
                            # E.g. {"regionSet":{},"allRegions":true}
                            elseif (
                                $requestParametersKeyStr -ceq 'allRegions,regionSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'regionSet' -and `
                                $event.requestParameters.allRegions -eq $true
                            )
                            {
                                [LabelType]::Billing_Home
                                [LabelType]::ConsoleHome
                                [LabelType]::CloudTrail_Dashboard
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                [LabelType]::EC2_Instances_DedicatedHosts
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_InstanceTypes
                                [LabelType]::EC2_BrowserRefresh
                                [LabelType]::EC2_MigrateServer
                                [LabelType]::EC2_ElasticBlockStore_Snapshots
                                [LabelType]::EC2_NetworkSecurity_PlacementGroups
                                [LabelType]::GuardDuty_Summary
                                [LabelType]::VPC_VPCDashboard
                                [LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMIs
                                [LabelType]::SecretsManager_Secrets_Create_Step2
                            }
                            # E.g. {"regionSet":{}}
                            elseif (
                                $requestParametersStr -ceq '{"regionSet":{}}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1
                                [LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
                                [LabelType]::VPC_VPCDashboard
                            }
                        }
                        'DescribeReplaceRootVolumeTasks' {
                            # E.g. {"DescribeReplaceRootVolumeTasksRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":"i-01234567890abcdef"},"Name":"instance-id"},"MaxResults":50}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeReplaceRootVolumeTasksRequest' -and `
                                $event.requestParameters.DescribeReplaceRootVolumeTasksRequest.Filter.tag -eq 1 -and `
                                $event.requestParameters.DescribeReplaceRootVolumeTasksRequest.Filter.Name -ceq 'instance-id' -and `
                                $event.requestParameters.DescribeReplaceRootVolumeTasksRequest.Filter.Value.tag -eq 1 -and `
                                $event.requestParameters.DescribeReplaceRootVolumeTasksRequest.Filter.Value.content.StartsWith('i-') -and `
                                $event.requestParameters.DescribeReplaceRootVolumeTasksRequest.MaxResults -eq 50 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Storage
                            }
                        }
                        'DescribeReservedInstances' {
                            # E.g. {"filterSet":{},"reservedInstancesSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,reservedInstancesSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,reservedInstancesSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Settings
                                [LabelType]::EC2_Instances_ReservedInstances
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"instancesSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet,maxResults' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,instancesSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                            }
                            # E.g. {"filterSet":{},"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]}}
                            elseif (
                               $requestParametersKeyStr -ceq 'filterSet,instancesSet' -and `
                               $event.requestParameters.instancesSet.items.instanceId.StartsWith('i-')
                            )
                            {
                                [LabelType]::EC2_BrowserRefresh
                            }
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]},"filterSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,instancesSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $event.requestParameters.items.instanceId.StartsWith('i-')
                            )
                            {
                                [LabelType]::EC2_BrowserRefresh
                            }
                        }
                        'DescribeReservedInstancesModifications' {
                            # E.g. {"filterSet":{"items":[{"name":"status","valueSet":{"items":[{"value":"processing"}]}}]},"reservedInstancesModificationSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,reservedInstancesModificationSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'reservedInstancesModificationSet' -and `
                                $requestParametersStr.Contains('{"items":[{"value":"') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_ReservedInstances
                            }
                        }
                        'DescribeRouteTables' {
                            # E.g. {"filterSet":{},"maxResults":100,"routeTableIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,routeTableIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,routeTableIdSet' -and `
                                $event.requestParameters.maxResults -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_RouteTables_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":100,"routeTableIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,routeTableIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,routeTableIdSet' -and `
                                $event.requestParameters.maxResults -eq 100
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"filterSet":{"items":[{"name":"vpc-id","valueSet":{"items":[{"value":"vpc-01234567890abcdef"}]}}]},"routeTableIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,routeTableIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'routeTableIdSet' -and `
                                $requestParametersStr.Contains('"name":"vpc-id"') -and `
                                $requestParametersStr.Contains('"value":"vpc-')                              
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B
                            }
                        }
                        'DescribeSecurityGroupRules' {
                            # E.g. {"DescribeSecurityGroupRulesRequest":{"Filter":{"tag":1,"Value":{"tag":1,"content":"sg-01234567890abcdef"},"Name":"group-id"},"MaxResults":1000}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeSecurityGroupRulesRequest' -and `
                                $event.requestParameters.DescribeSecurityGroupRulesRequest.Filter.Name -ceq 'group-id' -and `
                                $event.requestParameters.DescribeSecurityGroupRulesRequest.Filter.tag -eq 1 -and `
                                $event.requestParameters.DescribeSecurityGroupRulesRequest.Filter.Value.content.StartsWith('sg-') -and `
                                $event.requestParameters.DescribeSecurityGroupRulesRequest.Filter.Value.tag -eq 1 -and `
                                $event.requestParameters.DescribeSecurityGroupRulesRequest.MaxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_SecurityGroups_SPECIFICGROUP
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Security
                            }
                        }
                        'DescribeSecurityGroups' {
                            # E.g. {"maxResults":1000,"filterSet":{},"securityGroupSet":{},"securityGroupIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,securityGroupIdSet,securityGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,securityGroupIdSet,securityGroupSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step2
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                                [LabelType]::EC2_NetworkSecurity_SecurityGroups
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_SecurityGroups_Refresh
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"securityGroupSet":{},"securityGroupIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,securityGroupIdSet,securityGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,securityGroupIdSet,securityGroupSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":200,"securityGroupSet":{},"securityGroupIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,securityGroupIdSet,securityGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,securityGroupIdSet,securityGroupSet' -and `
                                $event.requestParameters.maxResults -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Labels have single-event Signal definitions, so ensure they remain last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NetworkSettings_FirewallSecurityGroup_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_SelectExistingSecurityGroup
                            }
                            # E.g. {"filterSet":{},"securityGroupSet":{},"securityGroupIdSet":{"items":[{"groupId":"sg-01234567890abcdef"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,securityGroupIdSet,securityGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,securityGroupSet' -and `
                                $requestParametersStr.Contains('"securityGroupIdSet":{"items":[{"groupId":"') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_NetworkSecurity_SecurityGroups
                                [LabelType]::EC2_NetworkSecurity_SecurityGroups_SPECIFICGROUP
                                [LabelType]::EC2_BrowserRefresh
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Security
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                            }
                            # E.g. {"filterSet":{"items":[{"name":"vpc-id","valueSet":{"items":[{"value":"vpc-01234567890abcdef"}]}}]},"maxResults":1000,"securityGroupSet":{},"securityGroupIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,securityGroupIdSet,securityGroupSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'securityGroupIdSet,securityGroupSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $requestParametersStr.Contains('"name":"vpc-id"') -and `
                                $requestParametersStr.Contains('"value":"vpc-')                              
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B
                            }
                        }
                        'DescribeSnapshotAttribute' {
                            # E.g. {"attributeType":"PRODUCT_CODES","snapshotId":"snap-01234567890abcdef"}
                            if (
                                $requestParametersKeyStr -ceq 'attributeType,snapshotId' -and `
                                $event.requestParameters.attributeType -ceq 'PRODUCT_CODES' -and `
                                $event.requestParameters.snapshotId.StartsWith('snap-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details
                            }
                        }
                        'DescribeSnapshots' {
                            # E.g. {"maxResults":1000,"filterSet":{},"ownersSet":{"items":[{"owner":"012345678900"}]},"snapshotSet":{},"sharedUsersSet":{}}
                            if (
                                $requestParametersKeyStr -cin @('filterSet,maxResults,ownersSet,sharedUsersSet,snapshotSet','filterSet,maxResults,nextToken,ownersSet,sharedUsersSet,snapshotSet') -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,sharedUsersSet,snapshotSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $event.requestParameters.ownersSet.items.owner -cmatch '^\d{12}$' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"ownersSet":{"items":[{"owner":"012345678900"}]},"snapshotSet":{},"sharedUsersSet":{}}
                            elseif (
                                $requestParametersKeyStr -cin @('filterSet,maxResults,ownersSet,sharedUsersSet,snapshotSet','filterSet,maxResults,nextToken,ownersSet,sharedUsersSet,snapshotSet') -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,sharedUsersSet,snapshotSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $event.requestParameters.ownersSet.items.owner -cmatch '^\d{12}$' -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"ownersSet":{"items":[{"owner":"self"}]},"snapshotSet":{},"sharedUsersSet":{}}
                            # E.g. {"filterSet":{},"maxResults":1000,"ownersSet":{},"snapshotSet":{},"sharedUsersSet":{"items":[{"user":"self"}]}}
                            # E.g. {"filterSet":{},"maxResults":1000,"ownersSet":{},"snapshotSet":{},"sharedUsersSet":{"items":[{"user":"all"}]}}
                            # E.g. {"filterSet":{},"maxResults":1000,"nextToken":"HyQs<REDACTED>W6td","ownersSet":{},"snapshotSet":{},"sharedUsersSet":{"items":[{"user":"all"}]}}
                            elseif (
                                $requestParametersKeyStr -cin @('filterSet,maxResults,ownersSet,sharedUsersSet,snapshotSet','filterSet,maxResults,nextToken,ownersSet,sharedUsersSet,snapshotSet') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                (
                                    (
                                        $requestParametersKeyEmptyValStr -cin @('filterSet,sharedUsersSet,snapshotSet','sharedUsersSet,snapshotSet') -and `
                                        $requestParametersStr.Contains('"owner":"self"')
                                    ) -or `
                                    (
                                        $requestParametersKeyEmptyValStr -cin @('filterSet,ownersSet,snapshotSet','ownersSet,snapshotSet') -and `
                                        (
                                            $requestParametersStr.Contains('"user":"self"') -or `
                                            $requestParametersStr.Contains('"user":"all"')
                                        )
                                    )
                                ) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Snapshots
                            }
                            # E.g. {"ownersSet":{},"filterSet":{},"snapshotSet":{"items":[{"snapshotId":"snap-01234567890abcdef"}]},"sharedUsersSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,ownersSet,sharedUsersSet,snapshotSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,ownersSet,sharedUsersSet' -and `
                                $requestParametersStr.Contains('"snapshotId":"snap-')
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Storage
                            }
                        }
                        'DescribeSpotFleetRequests' {
                            # E.g. {"DescribeSpotFleetRequestsRequest":{"MaxResults":100,"NextToken":""}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeSpotFleetRequestsRequest' -and `
                                $event.requestParameters.DescribeSpotFleetRequestsRequest.MaxResults -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests
                            }
                        }
                        'DescribeSpotInstanceRequests' {
                            # E.g. {"maxResults":1000,"spotInstanceRequestIdSet":{},"filterSet":{}}
                            # E.g. {"maxResults":1000,"spotInstanceRequestIdSet":{},"filterSet":{"items":[{"name":"state","valueSet":{"items":[{"value":"open"}]}}]}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,spotInstanceRequestIdSet' -and `
                                $requestParametersKeyEmptyValStr -cin @('filterSet,spotInstanceRequestIdSet','spotInstanceRequestIdSet') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests
                            }
                            # E.g. {"maxResults":500,"spotInstanceRequestIdSet":{},"filterSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,spotInstanceRequestIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,spotInstanceRequestIdSet' -and `
                                $event.requestParameters.maxResults -eq 500 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_SpotRequests_SavingsSummary
                            }
                        }
                        'DescribeSpotPriceHistory' {
                            # E.g. {"maxResults":1000,"startTime":1690853587000,"endTime":1690853587000,"instanceTypeSet":{},"productDescriptionSet":{}}
                            # E.g. {"maxResults":1000,"startTime":1690853587000,"endTime":1690853587000,"instanceTypeSet":{},"productDescriptionSet":{},"nextToken":"HyQs<REDACTED>W6td"}
                            if (
                                $requestParametersKeyStr -cin @('endTime,instanceTypeSet,maxResults,productDescriptionSet,startTime','endTime,instanceTypeSet,maxResults,nextToken,productDescriptionSet,startTime') -and `
                                $requestParametersKeyEmptyValStr -ceq 'instanceTypeSet,productDescriptionSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests_SpotBlueprints
                            }
                            # E.g. {"startTime":1690248891000,"endTime":1690853691000,"instanceTypeSet":{"items":[{"instanceType":"c3.large"}]},"productDescriptionSet":{"items":[{"productDescription":"Linux/UNIX"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'endTime,instanceTypeSet,maxResults,productDescriptionSet,startTime' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_SpotRequests_PricingHistory
                            }
                            # E.g. {"startTime":1690549894000,"endTime":1691154694000,"instanceTypeSet":{"items":[{"instanceType":"c3.large"}]},"productDescriptionSet":{"items":[{"productDescription":"Linux/UNIX"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'endTime,instanceTypeSet,productDescriptionSet,startTime' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_SpotRequests_PricingHistory
                            }
                            # E.g. {"startTime":1690549894000,"endTime":1691154694000,"availabilityZone":"us-east-1d","instanceTypeSet":{"items":[{"instanceType":"c3.large"},{"instanceType":"a1.xlarge"},{"instanceType":"g5.2xlarge"}]},"productDescriptionSet":{"items":[{"productDescription":"Linux/UNIX"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'availabilityZone,endTime,instanceTypeSet,productDescriptionSet,startTime' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_SpotRequests_PricingHistory
                            }
                        }
                        'DescribeSubnets' {
                            # E.g. {"filterSet":{},"maxResults":1000,"subnetSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,subnetSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,subnetSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_Subnets_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"subnetSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,subnetSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,subnetSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":200,"subnetSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,subnetSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,subnetSet' -and `
                                $event.requestParameters.maxResults -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                            }
                            # E.g. {"filterSet":{},"maxResults":5,"subnetSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,subnetSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,subnetSet' -and `
                                $event.requestParameters.maxResults -eq 5 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                            }
                            # E.g. {"filterSet":{},"subnetSet":{"items":[{"subnetId":"subnet-01234567890abcdef"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,subnetSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $event.requestParameters.subnetSet.items.subnetId.StartsWith('subnet-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                            }
                            # E.g. {"filterSet":{"items":[{"name":"vpc-id","valueSet":{"items":[{"value":"vpc-01234567890abcdef"}]}}]},"subnetSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,subnetSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'subnetSet' -and `
                                $requestParametersStr.Contains('"name":"vpc-id"') -and `
                                $requestParametersStr.Contains('"value":"vpc-')
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B
                            }
                        }
                        'DescribeTags' {
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults' -and `
                                $requestParametersStr.Contains('"name":"resource-type"') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                if ($event.requestParameters.maxResults -eq 1000)
                                {
                                    # E.g. {"maxResults":1000,"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"security-group"}]}}]}}
                                    if ($requestParametersStr.Contains('"value":"security-group"'))
                                    {
                                        [LabelType]::EC2_NetworkSecurity_SecurityGroups
                                    }
                                    # E.g. {"maxResults":1000,"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"security-group-rule"}]}}]}}
                                    elseif ($requestParametersStr.Contains('"value":"security-group-rule"'))
                                    {
                                        [LabelType]::EC2_NetworkSecurity_SecurityGroups_SPECIFICGROUP
                                    }
                                }
                                elseif ($event.requestParameters.maxResults -eq 200)
                                {
                                    # E.g. {"maxResults":200,"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"image"}]}}]}}
                                    if ($requestParametersStr.Contains('"value":"image"'))
                                    {
                                        # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                        [LabelType]::EC2_Images_AMIs
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"network-interface"}]}}]},"maxResults":200}
                                    if ($requestParametersStr.Contains('"value":"network-interface"'))
                                    {
                                        [LabelType]::EC2_NetworkSecurity_NetworkInterfaces
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"dedicated-host"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"dedicated-host"'))
                                    {
                                        [LabelType]::EC2_Instances_DedicatedHosts
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"key-pair"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"key-pair"'))
                                    {
                                        [LabelType]::EC2_NetworkSecurity_KeyPairs
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"placement-group"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"placement-group"'))
                                    {
                                        [LabelType]::EC2_NetworkSecurity_PlacementGroups
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"snapshot"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"snapshot"'))
                                    {
                                        [LabelType]::EC2_ElasticBlockStore_Snapshots
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"volume"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"volume"'))
                                    {
                                        [LabelType]::EC2_ElasticBlockStore_Volumes
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"instance"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"instance"'))
                                    {
                                        [LabelType]::EC2_Instances_Instances
                                    }
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"launch-template"}]}}]},"maxResults":200}
                                    elseif ($requestParametersStr.Contains('"value":"launch-template"'))
                                    {
                                        [LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete
                                        [LabelType]::EC2_Instances_LaunchTemplates
                                        [LabelType]::EC2_Instances_LaunchTemplates_Scenario2
                                    }
                                }
                                elseif ($event.requestParameters.maxResults -eq 500)
                                {
                                    # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"elastic-ip"}]}}]},"maxResults":500}
                                    if ($requestParametersStr.Contains('"value":"elastic-ip"'))
                                    {
                                        [LabelType]::EC2_NetworkSecurity_ElasticIPs
                                    }
                                }
                            }
                            # E.g. {"maxResults":1000,"filterSet":{"items":[{"name":"resource-id","valueSet":{"items":[{"value":"i-01234567890abcdef"}]}},{"name":"key","valueSet":{"items":[{"value":"Name"}]}}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults' -and `
                                $requestParametersStr.Contains('"name":"resource-id"') -and `
                                $requestParametersStr.Contains('"name":"key"') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring
                            }
                            # E.g. {"maxResults":1000,"filterSet":{"items":[{"name":"key","valueSet":{"items":[{"value":"*"}]}},{"name":"value","valueSet":{"items":[{"value":"*"}]}}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults' -and `
                                $event.requestParameters.filterSet.items.Count -gt 1 -and `
                                $requestParametersStr.Contains('"value":"*"') -and `
                                $requestParametersStr.Contains('"name":"key"') -and `
                                $requestParametersStr.Contains('"name":"value"') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Value
                            }
                            # E.g. {"maxResults":1000,"filterSet":{"items":[{"name":"key","valueSet":{"items":[{"value":"*"}]}}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults' -and `
                                $requestParametersStr.Contains('"value":"*"') -and `
                                $requestParametersStr.Contains('"name":"key"') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Key
                            }
                            # E.g. {"maxResults":1000,"filterSet":{"items":[{"name":"key","valueSet":{"items":[{"value":"*MyCustomTagName*"}]}}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults' -and `
                                $requestParametersStr.Contains('"value":"*') -and `
                                $requestParametersStr.Contains('"name":"key"') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step2
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NameAndTags_AddAdditionalTags_Key
                            }
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # E.g. {"filterSet":{"items":[{"name":"resource-id","valueSet":{"items":[{"value":"i-01234567890abcdef"},{"value":"i-01234567890abcde2"}]}},{"name":"key","valueSet":{"items":[{"value":"Name"}]}}]}}
                                if (
                                    $requestParametersStr.Contains('"name":"resource-id"') -and `
                                    $requestParametersStr.Contains('"value":"Name"') -and `
                                    $requestParametersStr.Contains('"value":"i-')
                                )
                                {
                                    [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                    [LabelType]::EC2_ElasticBlockStore_Volumes
                                }
                                # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"image"}]}}]}}
                                elseif (
                                    $requestParametersStr.Contains('"name":"resource-type"') -and `
                                    $requestParametersStr.Contains('"value":"image"')
                                )
                                {
                                    # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                    [LabelType]::EC2_Images_AMIs
                                }
                                # E.g. {"filterSet":{"items":[{"name":"resource-type","valueSet":{"items":[{"value":"capacity-reservation"}]}}]}}
                                elseif (
                                    $requestParametersKeyStr -ceq 'filterSet' -and `
                                    $requestParametersStr.Contains('"name":"resource-type"') -and `
                                    $requestParametersStr.Contains('"value":"capacity-reservation"') -and `
                                    $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                                )
                                {
                                    [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                                    [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2
                                    [LabelType]::EC2_Instances_CapacityReservations
                                }
                            }
                        }
                        'DescribeVolumeAttribute' {
                            # E.g. {"volumeId":"vol-01234567890abcdef"}
                            if (
                                $requestParametersKeyStr -ceq 'volumeId' -and `
                                $event.requestParameters.volumeId.StartsWith('vol-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.  
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_StatusChecks
                            }
                        }
                        'DescribeVolumeStatus' {
                            # E.g. {"maxResults":1000,"filterSet":{},"volumeSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,volumeSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_Events
                                [LabelType]::EC2_EC2Dashboard_ScheduledEvents_Refresh
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"volumeSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,volumeSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                            # E.g. {"filterSet":{},"volumeSet":{"items":[{"volumeId":"vol-01234567890abcdef"}]}}
                            # E.g. {"filterSet":{},"volumeSet":{"items":[{"volumeId":"vol-01234567890abcdef"},{"volumeId":"vol-01234567890abcde2"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $requestParametersStr.Contains('{"volumeId":"vol-')
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                            }
                        }
                        'DescribeVolumes' {
                            # E.g. {"maxResults":1000,"filterSet":{},"volumeSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,volumeSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                            }
                            # E.g. {"maxResults":1000,"filterSet":{},"volumeSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,volumeSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                            # E.g. {"filterSet":{"items":[{"name":"volume-id","valueSet":{"items":[{"value":"*vol-01234567890abcdef*"}]}}]},"maxResults":1000,"volumeSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'volumeSet' -and `
                                $requestParametersStr.Contains('"name":"volume-id"') -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                            }
                            # E.g. {"filterSet":{},"volumeSet":{"items":[{"volumeId":"vol-01234567890abcdef"}]}}
                            # E.g. {"filterSet":{},"volumeSet":{"items":[{"volumeId":"vol-01234567890abcdef"},{"volumeId":"vol-01234567890abcde2"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,volumeSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $event.requestParameters.volumeSet.items.volumeId.StartsWith('vol-')
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Storage
                            }
                        }
                        'DescribeVolumesModifications' {
                            # E.g. {"DescribeVolumesModificationsRequest":{"MaxResults":500}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeVolumesModificationsRequest' -and `
                                $event.requestParameters.DescribeVolumesModificationsRequest.MaxResults -eq 500
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                            }
                        }
                        'DescribeVpcEndpointServiceConfigurations' {
                            # E.g. {"DescribeVpcEndpointServiceConfigurationsRequest":{"MaxResults":1000}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeVpcEndpointServiceConfigurationsRequest' -and `
                                $event.requestParameters.DescribeVpcEndpointServiceConfigurationsRequest.MaxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_EndpointServices_Refresh
                            }
                            # E.g. {"DescribeVpcEndpointServiceConfigurationsRequest":{"MaxResults":1000}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeVpcEndpointServiceConfigurationsRequest' -and `
                                $event.requestParameters.DescribeVpcEndpointServiceConfigurationsRequest.MaxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeVpcEndpointServices' {
                            # E.g. {"DescribeVpcEndpointServicesRequest":""}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeVpcEndpointServicesRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'DescribeVpcEndpointServicesRequest'
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1
                            }
                            # E.g. {"DescribeVpcEndpointServicesRequest":{"ServiceName":{"tag":1,"content":"aws.api.us-east-1.kendra-ranking"}}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeVpcEndpointServicesRequest'
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                            }
                        }
                        'DescribeVpcEndpoints' {
                            # E.g. {"DescribeVpcEndpointsRequest":{"MaxResults":1000}}
                            if (
                                $requestParametersKeyStr -ceq 'DescribeVpcEndpointsRequest' -and `
                                $event.requestParameters.DescribeVpcEndpointsRequest.MaxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_Endpoints_Refresh
                            }
                            # E.g. {"DescribeVpcEndpointsRequest":{"MaxResults":1000}}
                            elseif (
                                $requestParametersKeyStr -ceq 'DescribeVpcEndpointsRequest' -and `
                                $event.requestParameters.DescribeVpcEndpointsRequest.MaxResults -eq 1000
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeVpcPeeringConnections' {
                            # E.g. {"filterSet":{},"maxResults":1000,"vpcPeeringConnectionIdSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcPeeringConnectionIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpcPeeringConnectionIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_VPCPeeringConnections_Refresh
                            }
                            # E.g. {"filterSet":{},"maxResults":1000,"vpcPeeringConnectionIdSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcPeeringConnectionIdSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpcPeeringConnectionIdSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                            }
                        }
                        'DescribeVpcs' {
                            # E.g. {"filterSet":{"items":[{"name":"owner-id","valueSet":{"items":[{"value":"012345678900"}]}}]},"maxResults":1000,"vpcSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'vpcSet' -and `
                                $requestParametersStr.Contains('"name":"owner-id"') -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Subnets_CreateSubnet_Step1
                            }
                            # E.g. {"maxResults":1000,"vpcSet":{},"filterSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpcSet' -and `
                                $event.requestParameters.maxResults -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_VPCs_Refresh
                            }
                            # E.g. {"maxResults":1000,"vpcSet":{},"filterSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpcSet' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer
                                [LabelType]::EC2_EC2GlobalView_RegionExplorer_ResourceRegionCounts_Refresh
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1
                            }
                            # E.g. {"filterSet":{},"maxResults":200,"vpcSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpcSet' -and `
                                $event.requestParameters.maxResults -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_CreateSecurityGroup
                            }
                            # E.g. {"maxResults":200,"filterSet":{"items":[{"name":"vpc-id","valueSet":{"items":[{"value":"vpc-01234567890abcdef"}]}}]},"vpcSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,maxResults,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'vpcSet' -and `
                                $requestParametersStr.Contains('"name":"vpc-id"') -and `
                                $requestParametersStr.Contains('"value":"vpc-') -and `
                                $event.requestParameters.maxResults -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                            }
                            # E.g. {"filterSet":{},"vpcSet":{}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpcSet'
                            )
                            {
                                [LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2
                                [LabelType]::EC2_Instances_SpotRequests
                            }
                            # E.g. {"filterSet":{},"vpcSet":{"items":[{"vpcId":"vpc-01234567890abcdef"}]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'filterSet,vpcSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet' -and `
                                $event.requestParameters.vpcSet.items.vpcId.StartsWith('vpc-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                            }
                        }
                        'DescribeVpnConnections' {
                            # E.g. {"filterSet":{},"vpnConnectionSet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,vpnConnectionSet' -and `
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpnConnectionSet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_SiteToSiteVPNConnections_Refresh
                            }
                        }
                        'DescribeVpnGateways' {
                            # E.g. {"filterSet":{},"vpnGatewaySet":{}}
                            if (
                                $requestParametersKeyStr -ceq 'filterSet,vpnGatewaySet' -and 
                                $requestParametersKeyEmptyValStr -ceq 'filterSet,vpnGatewaySet' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::VPC_VPCDashboard
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::VPC_VPCDashboard_VirtualPrivateGateways_Refresh
                            }
                        }
                        'DisableSerialConsoleAccess' {
                            # E.g. {"DisableSerialConsoleAccessRequest":""}
                            if (
                                $requestParametersKeyStr -ceq 'DisableSerialConsoleAccessRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'DisableSerialConsoleAccessRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Disallow
                            }
                        }
                        'EnableSerialConsoleAccess' {
                            # E.g. {"EnableSerialConsoleAccessRequest":""}
                            if (
                                $requestParametersKeyStr -ceq 'EnableSerialConsoleAccessRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'EnableSerialConsoleAccessRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Allow
                            }
                        }
                        'GetCapacityReservationAccountAttribute' {
                            # E.g. {"GetCapacityReservationAccountAttributeRequest":{"PropertyName":"auto-accept"}}
                            if (
                                $requestParametersKeyStr -ceq 'GetCapacityReservationAccountAttributeRequest' -and `
                                $event.requestParameters.GetCapacityReservationAccountAttributeRequest.PropertyName -ceq 'auto-accept' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_CreateCapacityReservation_Step2
                                [LabelType]::EC2_Instances_CapacityReservations
                            }
                        }
                        'GetCapacityReservationUsage' {
                            # E.g. {"GetCapacityReservationUsageRequest":{"CapacityReservationId":"cr-01234567890abcdef"}}
                            if (
                                $requestParametersKeyStr -ceq 'GetCapacityReservationUsageRequest' -and `
                                $event.requestParameters.GetCapacityReservationUsageRequest.CapacityReservationId.StartsWith('cr-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION
                            }
                        }
                        'GetDefaultCreditSpecification' {
                            # E.g. {"GetDefaultCreditSpecificationRequest":{"InstanceFamily":"t4g"}}
                            if (
                                $requestParametersKeyStr -ceq 'GetDefaultCreditSpecificationRequest' -and `
                                $requestParametersStr.Contains('"InstanceFamily"')
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard_Settings_DefaultCreditSpecification
                            }
                            # E.g. {"GetSerialConsoleAccessStatusRequest":""}
                            elseif (
                                $requestParametersKeyStr -ceq 'GetSerialConsoleAccessStatusRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'GetSerialConsoleAccessStatusRequest'
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard_Settings_DefaultCreditSpecification
                            }
                        }
                        'GetEbsDefaultKmsKeyId' {
                            # E.g. {"GetEbsDefaultKmsKeyIdRequest":""}
                            if (
                                $requestParametersKeyStr -ceq 'GetEbsDefaultKmsKeyIdRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'GetEbsDefaultKmsKeyIdRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard_Settings_EBSEncryption
                            }
                        }
                        'GetEbsEncryptionByDefault' {
                            # E.g. {"GetEbsEncryptionByDefaultRequest":""}
                            if (
                                $requestParametersKeyStr -ceq 'GetEbsEncryptionByDefaultRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'GetEbsEncryptionByDefaultRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard_Settings_EBSEncryption
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1
                                [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1
                            }
                        }
                        'GetGroupsForCapacityReservation' {
                            # E.g. {"GetGroupsForCapacityReservationRequest":{"CapacityReservationId":"cr-01234567890abcdef"}}
                            if (
                                $requestParametersKeyStr -ceq 'GetGroupsForCapacityReservationRequest' -and `
                                $event.requestParameters.GetGroupsForCapacityReservationRequest.CapacityReservationId.StartsWith('cr-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION
                            }
                        }
                        'GetInstanceTypesFromInstanceRequirements' {
                            # E.g. {"GetInstanceTypesFromInstanceRequirementsRequest":{"ArchitectureType":{"tag":1,"content":"x86_64"},"InstanceRequirements":{"VCpuCount":{"Min":0},"MemoryMiB":{"Min":0}},"VirtualizationType":[{"tag":1,"content":"hvm"},{"tag":2,"content":"paravirtual"}]}}
                            # E.g. {"GetSpotPlacementScoresRequest":{"InstanceRequirementsWithMetadata":{"ArchitectureType":{"tag":1,"content":"x86_64"},"InstanceRequirements":{"VCpuCount":{"Min":0},"MemoryMiB":{"Min":0}}},"SingleAvailabilityZone":false,"RegionName":[{"tag":1,"content":"ap-southeast-2"},{"tag":2,"content":"ap-south-1"}],"TargetCapacityUnitType":"units","TargetCapacity":10}}
                            if (
                                $requestParametersKeyStr -cin @('GetInstanceTypesFromInstanceRequirementsRequest','GetSpotPlacementScoresRequest') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step1
                            }
                        }
                        'GetSerialConsoleAccessStatus' {
                            # E.g. {"GetSerialConsoleAccessStatusRequest":""}
                            if (
                                $requestParametersKeyStr -ceq 'GetSerialConsoleAccessStatusRequest' -and `
                                $requestParametersKeyEmptyValStr -ceq 'GetSerialConsoleAccessStatusRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                                [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Allow
                                [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Disallow
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole
                            }
                        }
                        'GetSpotPlacementScores' {
                            # E.g. {"GetSpotPlacementScoresRequest":{"InstanceRequirementsWithMetadata":{"ArchitectureType":{"tag":1,"content":"x86_64"},"InstanceRequirements":{"VCpuCount":{"Min":0},"MemoryMiB":{"Min":0}}},"SingleAvailabilityZone":false,"RegionName":[{"tag":1,"content":"ap-southeast-2"},{"tag":2,"content":"ap-south-1"}],"TargetCapacityUnitType":"units","TargetCapacity":10}}
                            if (
                                $requestParametersKeyStr -ceq 'GetSpotPlacementScoresRequest' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step2
                            }
                        }
                        'RebootInstances' {
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"},{"instanceId":"i-01234567890abcde1"},{"instanceId":"i-01234567890abcde2"}]}}
                            if (
                                $requestParametersKeyStr -ceq 'instancesSet' -and `
                                $event.requestParameters.instancesSet.items.instanceId.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
                            }
                        }
                        'RunInstances' {
                            # E.g. {"instancesSet":{"items":[{"imageId":"ami-01234567890abcdef","minCount":1,"maxCount":1}]},"instanceType":"t2.micro","blockDeviceMapping":{},"monitoring":{"enabled":false},"disableApiTermination":false,"disableApiStop":false,"clientToken":"db014773-abcd-1234-5678-133337c0ffee","networkInterfaceSet":{"items":[{"deviceIndex":0,"associatePublicIpAddress":true,"groupSet":{"items":[{"groupId":"sg-01234567890abcdef"}]}}]},"ebsOptimized":false,"metadataOptions":{"httpTokens":"required","httpPutResponseHopLimit":2,"httpEndpoint":"enabled"},"privateDnsNameOptions":{"hostnameType":"ip-name","enableResourceNameDnsARecord":true,"enableResourceNameDnsAAAARecord":false}}
                            # E.g. {"instancesSet":{"items":[{"imageId":"ami-01234567890abcdef","minCount":3,"maxCount":3}]},"instanceType":"t2.micro","blockDeviceMapping":{},"monitoring":{"enabled":false},"disableApiTermination":false,"disableApiStop":false,"clientToken":"db014773-abcd-1234-5678-133337c0ffee","tagSpecificationSet":{"items":[{"tags":[{"value":"myCustomTagValue","key":"Name"}],"resourceType":"instance"}]},"networkInterfaceSet":{"items":[{"groupSet":{"items":[{"groupId":"sg-01234567890abcdef"}]},"deviceIndex":0,"associatePublicIpAddress":true}]},"ebsOptimized":false,"privateDnsNameOptions":{"hostnameType":"ip-name","enableResourceNameDnsARecord":true,"enableResourceNameDnsAAAARecord":false}}
                            if (
                                # Look for presence of subset of top-level requestParameters keys that are always present.
                                ($event.requestParameters.Keys.Where( { $_ -cin @('blockDeviceMapping','clientToken','disableApiStop','disableApiTermination','instancesSet','monitoring') } ) | Sort-Object -Unique).Count -eq 6 -and `
                                # Ensure no errors are present.
                                [System.String]::IsNullOrEmpty($event.errorCode) -and `
                                [System.String]::IsNullOrEmpty($event.errorMessage) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_LaunchInstance_Step2
                            }
                        }
                        'StartInstances' {
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]}}
                            if (
                                $requestParametersKeyStr -ceq 'instancesSet' -and `
                                $event.requestParameters.instancesSet.items.instanceId.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
                            }
                        }
                        'StopInstances' {
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]},"force":false}
                            if (
                                $requestParametersKeyStr -ceq 'force,instancesSet' -and `
                                $event.requestParameters.instancesSet.items.instanceId.StartsWith('i-') -and `
                                $event.requestParameters.force -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                            }
                        }
                        'TerminateInstances' {
                            # E.g. {"instancesSet":{"items":[{"instanceId":"i-01234567890abcdef"}]}}
                            if (
                                $requestParametersKeyStr -ceq 'instancesSet' -and `
                                $event.requestParameters.instancesSet.items.instanceId.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'elasticloadbalancing.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeAccountLimits' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Limits
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                                [LabelType]::EC2_LoadBalancing_TrustStores
                            }
                        }
                        'DescribeLoadBalancers' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                            }
                            # E.g. {"pageSize":200}
                            elseif (
                                $requestParametersStr.Contains('{"pageSize":200}') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                                [LabelType]::EC2_EC2Dashboard_Resources_Refresh
                            }
                            # E.g. {"pageSize":200}
                            elseif (
                                $requestParametersStr.Contains('{"pageSize":200}') -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_EC2Dashboard
                            }
                             # E.g. {"pageSize":300}
                             elseif (
                                $requestParametersStr -ceq '{"pageSize":300}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                            }
                        }
                        'DescribeTargetGroups' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_TargetGroups
                            }
                        }
                        'DescribeTrustStores' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_TrustStores
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent_EC2_LoadBalancing_TrustStores
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'guardduty.amazonaws.com' {
                    switch ($event.eventName) {
                        'CreateSampleFindings' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Settings_GenerateSampleFindings
                            }
                        }
                        'DescribeMalwareScans' {
                            # E.g. {"maxResults":50,"detectorId":"db014773abcd12345678133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,maxResults' -and `
                                $event.requestParameters.maxResults -eq 50
                            )
                            {
                                [LabelType]::GuardDuty_MalwareScans
                            }
                        }
                        'DescribeOrganizationConfiguration' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Summary
                                [LabelType]::GuardDuty_Usage
                            }
                        }
                        'GetDetector' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Summary
                            }
                        }
                        'GetFindingsStatistics' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","findingCriteria":{"criterion":{"service.archived":{"eq":["false","false"]}}},"findingStatisticTypes":["COUNT_BY_SEVERITY"]}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,findingCriteria,findingStatisticTypes' -and `
                                $event.requestParameters.findingStatisticTypes -ccontains 'COUNT_BY_SEVERITY'
                            )
                            {
                                [LabelType]::GuardDuty_Findings
                            }
                        }
                        'GetInvitationsCount' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::GuardDuty_Summary
                            }
                        }
                        'GetMalwareScanSettings' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_ProtectionPlans_MalwareProtection
                            }
                        }
                        'GetMasterAccount' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Summary
                                [LabelType]::GuardDuty_Findings
                                [LabelType]::GuardDuty_Usage
                                [LabelType]::GuardDuty_Accounts
                            }
                        }
                        'GetRemainingFreeTrialDays' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","accountIds":["012345678900"]}
                            if ($requestParametersKeyStr -ceq 'accountIds,detectorId')
                            {
                                [LabelType]::GuardDuty_Usage
                                [LabelType]::GuardDuty_ProtectionPlans_MalwareProtection
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::GuardDuty_ProtectionPlans_Suboption_ConfigurationNotAvailable
                            }
                        }
                        'GetUsageStatistics' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","maxResults":6,"usageStatisticsType":"TOP_RESOURCES","usageCriteria":{"dataSources":["S3_LOGS"]}}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,maxResults,usageCriteria,usageStatisticsType' -and `
                                $event.requestParameters.usageStatisticsType -ceq 'TOP_RESOURCES' -and `
                                $event.requestParameters.maxResults -eq 6
                            )
                            {
                                [LabelType]::GuardDuty_Usage
                            }
                            # E.g. {"detectorId":"80c22c8f53143342747de6fa22786e28","usageStatisticsType":"SUM_BY_DATA_SOURCE","usageCriteria":{"accountIds":["012345678900"],"dataSources":["CLOUD_TRAIL","DNS_LOGS","FLOW_LOGS","S3_LOGS","KUBERNETES_AUDIT_LOGS","EC2_MALWARE_SCAN"]}}
                            elseif (
                                $requestParametersKeyStr -ceq 'detectorId,usageCriteria,usageStatisticsType' -and `
                                $event.requestParameters.usageStatisticsType -ceq 'SUM_BY_DATA_SOURCE'
                            )
                            {
                                [LabelType]::GuardDuty_Usage
                            }
                        }
                        'ListDetectors' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::GuardDuty_Summary
                            }
                        }
                        'ListFilters' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","maxResults":"50"}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '50'
                            )
                            {
                                [LabelType]::GuardDuty_Findings
                            }
                        }
                        'ListFindings' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","maxResults":25,"findingCriteria":{"criterion":{"service.archived":{"eq":["false","false"]}}},"sortCriteria":{"attributeName":"service.eventLastSeen","orderBy":"DESC"}}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,findingCriteria,maxResults,sortCriteria' -and `
                                $event.requestParameters.maxResults -eq 25
                            )
                            {
                                [LabelType]::GuardDuty_Findings
                            }
                            # E.g. {"maxResults":1000,"detectorId":"db014773abcd12345678133337c0ffee","findingCriteria":{"criterion":{"updatedAt":{"gt":1701838799999,"lt":1701925199999},"service.archived":{"eq":["false","false"]}}},"consoleOnly":true,"sortCriteria":{"attributeName":"service.eventLastSeen","orderBy":"DESC"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'consoleOnly,detectorId,findingCriteria,maxResults,sortCriteria' -and `
                                $event.requestParameters.maxResults -eq 1000
                            )
                            {
                                [LabelType]::GuardDuty_Summary
                            }
                        }
                        'ListIPSets' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Settings_Lists
                            }
                        }
                        'ListMembers' {
                            # E.g. {"maxResults":"50","detectorId":"db014773abcd12345678133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '50'
                            )
                            {
                                [LabelType]::GuardDuty_Summary
                                [LabelType]::GuardDuty_Findings
                                [LabelType]::GuardDuty_Usage
                            }
                            # E.g. {"maxResults":"50","detectorId":"db014773abcd12345678133337c0ffee","onlyAssociated":"false"}
                            elseif (
                                $requestParametersKeyStr -ceq 'detectorId,maxResults,onlyAssociated' -and `
                                $event.requestParameters.maxResults -ceq '50' -and `
                                $event.requestParameters.onlyAssociated -eq $false
                            )
                            {
                                [LabelType]::GuardDuty_Summary
                            }
                        }
                        'ListPublishingDestinations' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Findings
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'ListTagsForResource' {
                            # E.g. {"resourceArn":"arn:aws:guardduty:us-east-1:012345678900:detector/db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'resourceArn')
                            {
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'ListThreatIntelSets' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'detectorId')
                            {
                                [LabelType]::GuardDuty_Settings_Lists
                            }
                        }
                        'UpdateMalwareScanSettings' {
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","ebsSnapshotPreservation":"RETENTION_WITH_FINDING"}
                            if (
                                $requestParametersKeyStr -ceq 'detectorId,ebsSnapshotPreservation' -and `
                                $event.requestParameters.ebsSnapshotPreservation -ceq 'RETENTION_WITH_FINDING'
                            )
                            {
                                [LabelType]::GuardDuty_ProtectionPlans_MalwareProtection_GeneralSettings_RetainScannedSnapshots_Enable
                            }
                            # E.g. {"detectorId":"db014773abcd12345678133337c0ffee","ebsSnapshotPreservation":"NO_RETENTION"}
                            elseif (
                                $requestParametersKeyStr -ceq 'detectorId,ebsSnapshotPreservation' -and `
                                $event.requestParameters.ebsSnapshotPreservation -ceq 'NO_RETENTION'
                            )
                            {
                                [LabelType]::GuardDuty_ProtectionPlans_MalwareProtection_GeneralSettings_RetainScannedSnapshots_Disable
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'health.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeEventAggregates' {
                            # E.g. {"filter":{"eventStatusCodes":["open","upcoming"],"startTimes":[{"from":"Feb 17, 2008, 12:01:09 AM"}]},"aggregateField":"eventTypeCategory"}
                            if (
                                $requestParametersKeyStr -ceq 'aggregateField,filter' -and `
                                $event.requestParameters.aggregateField -ceq 'eventTypeCategory' -and `
                                (($event.requestParameters.filter.eventStatusCodes | Sort-Object) -join ',') -cin @('open,upcoming','open')
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent
                            }
                        }
                        'DescribeEvents' {
                            # E.g. {"filter":{"services":["EC2","MULTIPLE_SERVICES"],"eventStatusCodes":["open"],"lastUpdatedTimes":[{"from":"Feb 17, 2008, 6:17:55 AM"}],"regions":["us-east-1","global"],"eventTypeCategories":["issue"]},"maxResults":100}
                            if (
                                $requestParametersKeyStr -ceq 'filter,maxResults' -and `
                                $event.requestParameters.maxResults -eq 100 -and `
                                (($event.requestParameters.filter.services            | Sort-Object) -join ',') -ceq 'EC2,MULTIPLE_SERVICES' -and `
                                (($event.requestParameters.filter.eventStatusCodes    | Sort-Object) -join ',') -ceq 'open' -and `
                                (($event.requestParameters.filter.eventTypeCategories | Sort-Object) -join ',') -ceq 'issue'
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent_EC2_EC2Dashboard
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'iam.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'AddUserToGroup' {
                            # E.g. {"userName":"userNameGoesHere","groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_CreateUserGroup
                                [LabelType]::IAM_Users_CreateUser_Step2
                            }
                        }
                        'AttachGroupPolicy' {
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup","groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName,policyArn' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_CreateUserGroup
                            }
                        }
                        'AttachUserPolicy' {
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/IAMUserChangePassword","userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'policyArn,userName' -and `
                                $event.requestParameters.policyArn -ceq 'arn:aws:iam::aws:policy/IAMUserChangePassword' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Update
                                [LabelType]::IAM_Users_CreateUser_Step2
                            }
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup","userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'policyArn,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_CreateUser_Step2
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly
                            }
                        }
                        'CreateAccessKey' {
                            # E.g. {"userName": "userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_CreateAccessKey
                            }
                        }
                        'CreateGroup' {
                            # E.g. {"groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_CreateUserGroup
                            }
                        }
                        'CreateLoginProfile' {
                            # E.g. {"userName":"userNameGoesHere","passwordResetRequired":true}
                            # E.g. {"userName":"userNameGoesHere","passwordResetRequired":false}
                            if (
                                $requestParametersKeyStr -ceq 'passwordResetRequired,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable
                                [LabelType]::IAM_Users_CreateUser_Step2
                            }
                        }
                        'CreateUser' {
                            # E.g. {"userName":"userNameGoesHere"}
                            # E.g. {"userName":"userNameGoesHere","tags":[{"value":"tagValue1","key":"tagKey1"},{"value":"","key":"tagKey2NoValue"},{"value":"tagValue3","key":"tagKey3"}]}
                            # E.g. {"userName":"userNameGoesHere","tags":[{"value":"tagValue1","key":"tagKey1"},{"value":"","key":"tagKey2NoValue"},{"value":"tagValue3","key":"tagKey3"}],"permissionsBoundary":"arn:aws:iam::aws:policy/aws-service-role/AccessAnalyzerServiceRolePolicy"}
                            if (
                                $requestParametersKeyStr.Contains('userName') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_CreateUser_Step2
                            }
                        }
                        'DeleteAccessKey' {
                            # E.g. {"userName":"userNameGoesHere","accessKeyId":"AKIA12345678ABCDEFGH"}
                            if (
                                $requestParametersKeyStr -ceq 'accessKeyId,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Delete
                            }
                        }
                        'DeleteGroup' {
                            # E.g. {"groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                        }
                        'DeleteLoginProfile' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Disable
                            }
                        }
                        'DeleteUser' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                            }
                        }
                        'DeleteUserPolicy' {
                            # E.g. {"policyName":"inlinePolicyNameGoesHere","userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'policyName,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveInlinePolicyForUser
                            }
                        }
                        'DetachGroupPolicy' {
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup","groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName,policyArn' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                        }
                        'DetachUserPolicy' {
                            # E.g. {"userName":"userNameGoesHere","policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup"}
                            if (
                                $requestParametersKeyStr -ceq 'policyArn,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveManagedPolicyForUser
                            }
                        }
                        'GenerateServiceLastAccessedDetails' {
                            # E.g. {"arn":"arn:aws:iam::012345678900:user/userNameGoesHere","granularity":"ACTION_LEVEL"}
                            if (
                                $requestParametersKeyStr -ceq 'arn,granularity' -and `
                                $event.requestParameters.granularity -ceq 'ACTION_LEVEL' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_AccessAdvisor
                            }
                            # E.g. {"arn":"arn:aws:iam::012345678900:user/userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'arn' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'GetAccessKeyLastUsed' {
                            # E.g. {"accessKeyId":"AKIA12345678ABCDEFGH"}
                            if (
                                $requestParametersKeyStr -ceq 'accessKeyId' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Users
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Activate
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Deactivate
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Delete
                            }
                            # E.g. {"accessKeyId":"AKIA12345678ABCDEFGH"}
                            elseif (
                                $requestParametersKeyStr -ceq 'accessKeyId' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                            }
                            # E.g. {"accessKeyId":"AKIA12345678ABCDEFGH"}
                            elseif (
                                $requestParametersKeyStr -ceq 'accessKeyId' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'GetAccountPasswordPolicy' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_CreateUser_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_IdentityCenter
                                [LabelType]::IAM_AccountSettings
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess
                            }
                        }
                        'GetAccountSummary' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'GetGroup' {
                            # E.g. {"groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup
                            }
                            # E.g. {"groupName":"groupNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                            # E.g. {"groupName":"groupNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'GetInstanceProfile' {
                            # E.g. {"instanceProfileName":"AmazonSSMRoleForInstancesQuickSetup"}
                            if (
                                $requestParametersKeyStr -ceq 'instanceProfileName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances
                            }
                        }
                        'GetLoginProfile' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_CreateUser_Step2
                                [LabelType]::IAM_Users
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Disable
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Update
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'GetPolicy' {
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup"}
                            if (
                                $requestParametersKeyStr -ceq 'policyArn' -and `
                                $event.requestParameters.policyArn.StartsWith('arn:aws:iam::') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Policies
                                [LabelType]::IAM_Policies_NextPage
                            }
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/service-role/AWSQuickSightListIAM"}
                            elseif (
                                $requestParametersKeyStr -ceq 'policyArn' -and `
                                $event.requestParameters.policyArn.StartsWith('arn:aws:iam::') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::Expanded_SPECIFICMANAGEDPOLICY
                            }
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup"}
                            elseif (
                                $requestParametersKeyStr -ceq 'policyArn' -and `
                                $event.requestParameters.policyArn.StartsWith('arn:aws:iam::') -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3
                            }
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/aws-service-role/AmazonGuardDutyServiceRolePolicy"}
                            elseif (
                                $requestParametersKeyStr -ceq 'policyArn' -and `
                                $event.requestParameters.policyArn -ceq 'arn:aws:iam::aws:policy/aws-service-role/AmazonGuardDutyServiceRolePolicy'
                            )
                            {
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'GetPolicyVersion' {
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup","versionId":"v1"}
                            if (
                                $requestParametersKeyStr -ceq 'policyArn,versionId' -and `
                                $event.requestParameters.policyArn.StartsWith('arn:aws:iam::') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::Expanded_SPECIFICMANAGEDPOLICY
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                            # E.g. {"policyArn":"arn:aws:iam::aws:policy/aws-service-role/AmazonGuardDutyServiceRolePolicy","versionId":"v7"}
                            elseif (
                                $requestParametersKeyStr -ceq 'policyArn,versionId' -and `
                                $event.requestParameters.policyArn -ceq 'arn:aws:iam::aws:policy/aws-service-role/AmazonGuardDutyServiceRolePolicy'
                            )
                            {
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'GetRole' {
                            # E.g. {"roleName":"roleNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                            }
                            elseif (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Roles
                            }
                        }
                        'GetServiceLastAccessedDetails' {
                            # E.g. {"maxItems":200,"jobId":"db014773-abcd-1234-5678-133337c0ffee"}
                            # E.g. {"maxItems":200,"marker":"AYAB<REDACTED>GtPA==QWNj<REDACTED>a2Vu","jobId":"db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -cin @('jobId,maxItems','jobId,marker,maxItems') -and `
                                $event.requestParameters.maxItems -eq 200 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_AccessAdvisor
                            }
                            # E.g. {"jobId":"db014773-abcd-1234-5678-133337c0ffee"}
                            elseif (
                                $requestParametersKeyStr -ceq 'jobId' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'GetServiceLinkedRoleDeletionStatus' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::IAM_Roles
                            }
                        }
                        'GetUser' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                            }
                        }
                        'GetUserPolicy' {
                            # E.g. {"policyName":"inlinePolicyNameGoesHere","groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'policyName,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveInlinePolicyForUser
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::Expanded_SPECIFICINLINEUSERPOLICY
                            }
                        }
                        'ListAccessKeys' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_CreateUser_Step2
                                [LabelType]::IAM_Users
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Activate
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Deactivate
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Delete
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'ListAccountAliases' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_Users_CreateUser_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_UserGroups
                            }
                        }
                        'ListAttachedGroupPolicies' {
                            # E.g. {"groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup
                            }
                            # E.g. {"groupName":"groupNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                        }
                        'ListAttachedRolePolicies' {
                            # E.g. {"roleName":"roleNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                            }
                            # E.g. {"roleName":"AWSServiceRoleForAmazonGuardDuty"}
                            elseif (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $event.requestParameters.roleName -ceq 'AWSServiceRoleForAmazonGuardDuty'
                            )
                            {
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'ListAttachedUserPolicies' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CopyPermissions
                            }
                        }
                        'ListGroupPolicies' {
                            # E.g. {"groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                            # E.g. {"groupName":"groupNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                            # E.g. {"groupName":"groupNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'groupName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'ListGroups' {
                            # E.g. {"maxItems":1000}
                            if (
                                $requestParametersStr -ceq '{"maxItems":1000}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                                [LabelType]::IAM_UserGroups_CreateUserGroup
                            }
                        }
                        'ListGroupsForUser' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Users_CreateUser_Step2
                                [LabelType]::IAM_Users
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_UserGroups_CreateUserGroup
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                            # E.g. {"maxItems":1000,"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'maxItems,userName' -and `
                                $event.requestParameters.maxItems -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'ListInstanceProfiles' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_SpotRequests_SpotBlueprints
                            }
                        }
                        'ListInstanceProfilesForRole' {
                            # E.g. {"roleName":"roleNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                            }
                        }
                        'ListMFADevices' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Users_CreateUser_Step2
                                [LabelType]::IAM_Users
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'ListOpenIDConnectProviders' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'ListPolicies' {
                            # E.g. {"maxItems":1000,"onlyAttached":false}
                            # E.g. {"maxItems":1000,"onlyAttached":false,"marker":"ABxM<REDACTED>rICg=="}
                            # E.g. {"maxItems":1000,"marker":"ABj3<REDACTED>rKeA==","onlyAttached":false}
                            if (
                                $requestParametersKeyStr -cin @('maxItems,onlyAttached','marker,maxItems,onlyAttached') -and `
                                $event.requestParameters.maxItems -eq 1000 -and `
                                $event.requestParameters.onlyAttached -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                                [LabelType]::IAM_UserGroups_CreateUserGroup
                            }
                            # E.g. {"maxItems":200,"onlyAttached":false}
                            # E.g. {"maxItems":200,"onlyAttached":false,"marker":"ABxM<REDACTED>rICg=="}
                            # E.g. {"maxItems":200,"marker":"ABj3<REDACTED>rKeA==","onlyAttached":false}
                            elseif (
                                $requestParametersKeyStr -cin @('maxItems,onlyAttached','marker,maxItems,onlyAttached') -and `
                                $event.requestParameters.maxItems -eq 200 -and `
                                $event.requestParameters.onlyAttached -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3
                            }
                            # E.g. {"maxItems":200,"onlyAttached":false}
                            elseif (
                                $requestParametersKeyStr -ceq 'maxItems,onlyAttached' -and `
                                $event.requestParameters.maxItems -ceq 200 -and `
                                $event.requestParameters.onlyAttached -eq $false -and `
                                $userAgentFamily -cin @([UserAgentFamily]::AWS_Internal,[UserAgentFamily]::Coral_Netty_4)
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Policies_NextPage
                            }
                            # E.g. {"scope":"AWS","onlyAttached":false,"pathPrefix":"/"}
                            elseif (
                                $requestParametersKeyStr -ceq 'onlyAttached,pathPrefix,scope' -and `
                                $event.requestParameters.pathPrefix -ceq '/' -and `
                                $event.requestParameters.scope -ceq 'AWS' -and `
                                $event.requestParameters.onlyAttached -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Policies
                            }
                            # E.g. {"scope":"AWS","onlyAttached":false,"pathPrefix":"/"}
                            elseif (
                                $requestParametersKeyStr -ceq 'onlyAttached,pathPrefix,scope' -and `
                                $event.requestParameters.pathPrefix -ceq '/' -and `
                                $event.requestParameters.scope -ceq 'AWS' -and `
                                $event.requestParameters.onlyAttached -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3
                            }
                        }
                        'ListPoliciesGrantingServiceAccess' {
                            # E.g. {"arn":"arn:aws:iam::012345678900:user/userNameGoesHere","serviceNamespaces":["access-analyzer","account","REDACTED"]}
                            if (
                                $requestParametersKeyStr -ceq 'arn,serviceNamespaces' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_AccessAdvisor
                            }
                        }
                        'ListPolicyVersions' {
                            # E.g. {"maxItems":1000,"policyArn":"arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup"}
                            if (
                                $requestParametersKeyStr -ceq 'maxItems,policyArn' -and `
                                $event.requestParameters.maxItems -eq 1000 -and `
                                $event.requestParameters.policyArn.StartsWith('arn:aws:iam::aws:policy/') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                            }
                        }
                        'ListRolePolicies' {
                            # E.g. {"roleName":"roleNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                            }
                            # E.g. {"roleName":"AWSServiceRoleForAmazonGuardDuty"}
                            elseif (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $event.requestParameters.roleName -ceq 'AWSServiceRoleForAmazonGuardDuty'
                            )
                            {
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'ListRoleTags' {
                            # E.g. {"roleName":"roleNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'roleName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Roles_SPECIFICROLE_Permissions
                            }
                        }
                        'ListRoles' {
                            # E.g. {"maxItems":1000}
                            if (
                                $requestParametersStr -ceq '{"maxItems":1000}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::EC2_Instances_SpotRequests_SpotBlueprints
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step3
                            }
                        }
                        'ListSAMLProviders' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'ListSSHPublicKeys' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials
                            }
                        }
                        'ListSTSRegionalEndpointsStatus' {
                            # E.g. {"regionFilter":["us-east-1","us-east-2","us-west-1","us-east-1","af-south-1","ap-east-1","ap-south-2","ap-southeast-3","ap-southeast-4","ap-south-1","ap-northeast-3","ap-northeast-2","ap-southeast-1","ap-southeast-2","ap-northeast-1","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-south-1","eu-west-3","eu-south-2","eu-north-1","eu-central-2","me-south-1","me-central-1","sa-east-1"]}
                            if (
                                $requestParametersKeyStr -ceq 'regionFilter' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_AccountSettings
                            }
                        }
                        'ListServiceSpecificCredentials' {
                            # E.g. {"userName":"userNameGoesHere","serviceName":"cassandra.amazonaws.com"}
                            # E.g. {"userName":"userNameGoesHere","serviceName":"codecommit.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'serviceName,userName' -and `
                                $event.requestParameters.serviceName -cin @('cassandra.amazonaws.com','codecommit.amazonaws.com') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                            }
                        }
                        'ListSigningCertificates' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::IAM_Users
                            }
                        }
                        'ListUserPolicies' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                [LabelType]::IAM_Users_SPECIFICUSER_Delete
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                            # E.g. {"userName":"userNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::Coral_Netty_4
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                            }
                        }
                        'ListUserTags' {
                            # E.g. {"userName":"userNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::IAM_Users_SPECIFICUSER_Tags
                            }
                        }
                        'ListUsers' {
                            # E.g. {"maxItems":1000}
                            if (
                                $requestParametersStr -ceq '{"maxItems":1000}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_Users_CreateUser_Step2
                                [LabelType]::IAM_Users
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Disable
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable
                                [LabelType]::IAM_Users_CreateUser
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step3
                            }
                        }
                        'PutUserPolicy' {
                            # E.g. {"userName":"userNameGoesHere","policyName":"inlinePolicyNameGoesHere","policyDocument":"{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"VisualEditor0\",\n            \"Effect\": \"Allow\",\n            \"Action\": \"forecast:QueryForecast\",\n            \"Resource\": \"*\"\n        }\n    ]\n}"}
                            if (
                                $requestParametersKeyStr -ceq 'policyDocument,policyName,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::IAM_Users_CreateUser_Step2
                            }
                        }
                        'RemoveUserFromGroup' {
                            # E.g. {"userName":"userNameGoesHere","groupName":"groupNameGoesHere"}
                            if (
                                $requestParametersKeyStr -ceq 'groupName,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_UserGroups_DeleteUserGroup
                            }
                        }
                        'UpdateAccessKey' {
                            # E.g. {"status":"Inactive","userName":"userNameGoesHere","accessKeyId":"AKIA12345678ABCDEFGH"}
                            if (
                                $requestParametersKeyStr -ceq 'accessKeyId,status,userName' -and `
                                $event.requestParameters.status -ceq 'Inactive' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Deactivate
                            }
                            # E.g. {"status":"Active","userName":"userNameGoesHere","accessKeyId":"AKIA12345678ABCDEFGH"}
                            elseif (
                                $requestParametersKeyStr -ceq 'accessKeyId,status,userName' -and `
                                $event.requestParameters.status -ceq 'Active' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Activate
                            }
                        }
                        'UpdateLoginProfile' {
                            # E.g. {"userName":"userNameGoesHere","passwordResetRequired":true}
                            # E.g. {"userName":"userNameGoesHere","passwordResetRequired":false}
                            if (
                                $requestParametersKeyStr -ceq 'passwordResetRequired,userName' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Update
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'identitystore.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeUser' {
                            # E.g. {"userId":"db014773-abcd-1234-5678-133337c0ffee","identityStoreId":"d-0123456789"}
                            if (
                                $requestParametersKeyStr -ceq 'identityStoreId,userId' -and `
                                $event.requestParameters.identityStoreId.StartsWith('d-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                        }
                    }
                }
                'kms.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'CreateAlias' {
                            # E.g. {"aliasName":"alias/aliasNameGoesHere","targetKeyId":"db014773-abcd-1234-5678-133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'aliasName,targetKeyId')
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4
                            }
                        }
                        'CreateKey' {
                            # E.g. {"keySpec":"SYMMETRIC_DEFAULT","policy":"{\n    \"Id\": \"key-consolepolicy-3\",\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"Enable IAM User Permissions\",\n            \"Effect\": \"Allow\",\n            \"Principal\": {\n                \"AWS\": \"arn:aws:iam::012345678900:root\"\n            },\n            \"Action\": \"kms:*\",\n            \"Resource\": \"*\"\n        }\n    ]\n}","tags":[],"description":"","customerMasterKeySpec":"SYMMETRIC_DEFAULT","bypassPolicyLockoutSafetyCheck":false,"multiRegion":false,"origin":"AWS_KMS","keyUsage":"ENCRYPT_DECRYPT"}
                            if ($requestParametersKeyStr -ceq 'bypassPolicyLockoutSafetyCheck,customerMasterKeySpec,description,keySpec,keyUsage,multiRegion,origin,policy,tags')
                            {
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4
                            }
                            # E.g. {"policy":"{\n  \"Version\": \"2012-10-17\",\n  \"Id\": \"Key policy created by CloudTrail\",\n  \"Statement\": [\n    {\n      \"Sid\": \"Enable IAM User Permissions\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": [\"arn:aws:iam::012345678900:root\", \"AROA0C0FFEE4DB0C0FFEE:andi.ahmeti@permiso.io\"]\n      },\n      \"Action\": \"kms:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"Allow CloudTrail to encrypt logs\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\"Service\":\"cloudtrail.amazonaws.com\"},\n      \"Action\": \"kms:GenerateDataKey*\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringLike\": {\n          \"kms:EncryptionContext:aws:cloudtrail:arn\": [\n            \"arn:aws:cloudtrail:*:012345678900:trail/*\"\n          ]\n        },\n        \"StringEquals\": {\n          \"AWS:SourceArn\": \"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"Allow CloudTrail to describe key\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\"Service\":\"cloudtrail.amazonaws.com\"},\n      \"Action\": \"kms:DescribeKey\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Sid\": \"Allow principals in the account to decrypt log files\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Action\": [\n        \"kms:Decrypt\",\n        \"kms:ReEncryptFrom\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"kms:CallerAccount\": \"012345678900\"\n        },\n        \"StringLike\": {\n          \"kms:EncryptionContext:aws:cloudtrail:arn\": [\n            \"arn:aws:cloudtrail:*:012345678900:trail/*\"\n          ]\n        }\n      }\n    },\n    {\n      \"Sid\": \"Allow alias creation during setup\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Action\": [\n        \"kms:CreateAlias\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"kms:CallerAccount\": \"012345678900\",\n          \"kms:ViaService\": \"ec2.us-east-2.amazonaws.com\"\n        }\n      }\n    },\n    {\n      \"Sid\": \"Enable cross account log decryption\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Action\": [\n        \"kms:Decrypt\",\n        \"kms:ReEncryptFrom\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"kms:CallerAccount\": \"012345678900\"\n        },\n        \"StringLike\": {\n          \"kms:EncryptionContext:aws:cloudtrail:arn\": [\n            \"arn:aws:cloudtrail:*:012345678900:trail/*\"\n          ]\n        }\n      }\n    }\n  ]\n}\n","keySpec":"SYMMETRIC_DEFAULT","description":"The key created by CloudTrail to encrypt log files. Created Fri Dec 22 02:14:39 UTC 2023","customerMasterKeySpec":"SYMMETRIC_DEFAULT","origin":"AWS_KMS","bypassPolicyLockoutSafetyCheck":false,"keyUsage":"ENCRYPT_DECRYPT"}
                            elseif (
                                $requestParametersKeyStr -ceq 'bypassPolicyLockoutSafetyCheck,customerMasterKeySpec,description,keySpec,keyUsage,origin,policy' -and `
                                $requestParametersStr.Contains('Key policy created by CloudTrail') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'Decrypt' {
                            # E.g. {"encryptionContext":{"SecretARN":"arn:aws:secretsmanager:us-east-1:012345678900:secret:myNewSecretName-b2Ul9D","SecretVersionId":"db014773-abcd-1234-5678-133337c0ffee"},"encryptionAlgorithm":"SYMMETRIC_DEFAULT"}
                            if (
                                $requestParametersKeyStr -ceq 'encryptionAlgorithm,encryptionContext' -and `
                                $event.userAgent -ceq 'secretsmanager.amazonaws.com'
                            )
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview_RetrieveSecretValue
                            }
                        }
                        'DescribeCustomKeyStores' {
                            # E.g. {"limit":50}
                            if (
                                $requestParametersKeyStr -ceq 'limit' -and `
                                $event.requestParameters.limit -eq 50
                            )
                            {
                                [LabelType]::KMS_CustomerManagedKeys
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1
                                # Below Labels have single-event Signal definitions, so ensure they remain last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::KMS_CustomKeyStores_ExternalKeyStores
                                [LabelType]::KMS
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::KMS_CustomKeyStores_AWSCloudHSMKeyStores
                            }
                        }
                        'DescribeKey' {
                            # E.g. {"keyId":"db014773-abcd-1234-5678-133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'keyId')
                            {
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4
                                [LabelType]::KMS_CustomerManagedKeys
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_Tags
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_CryptographicConfiguration
                            }
                        }
                        'GenerateDataKey' {
                            # E.g. {"encryptionContext":{"SecretARN":"arn:aws:secretsmanager:us-east-1:012345678900:secret:myNewSecretName-b2Ul9D","SecretVersionId":"db014773-abcd-1234-5678-133337c0ffee"},"keyId":"alias/aws/secretsmanager","keySpec":"AES_256"}
                            if (
                                $requestParametersKeyStr -ceq 'encryptionContext,keyId,keySpec' -and `
                                $event.requestParameters.encryptionContext.Keys -ccontains 'SecretARN' -and `
                                $event.requestParameters.encryptionContext.Keys -ccontains 'SecretVersionId' -and `
                                $event.userAgent -ceq 'secretsmanager.amazonaws.com'
                            )
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step4
                            }
                        }
                        'GetKeyPolicy' {
                            # E.g. {"keyId":"db014773-abcd-1234-5678-133337c0ffee","policyName":"default"}
                            if (
                                $requestParametersKeyStr -ceq 'keyId,policyName' -and `
                                $event.requestParameters.policyName -ceq 'default'
                            )
                            {
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy
                            }
                        }
                        'GetKeyRotationStatus' {
                            # E.g. {"keyId":"db014773-abcd-1234-5678-133337c0ffee"}
                            if ($requestParametersKeyStr -ceq 'keyId')
                            {
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation
                            }
                        }
                        'ListAliases' {
                            # E.g. {"limit":100}
                            # E.g. {"limit":100,"keyId":"db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -cin @('limit','keyId,limit') -and `
                                $event.requestParameters.limit -eq 100
                            )
                            {
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4
                                [LabelType]::KMS_CustomerManagedKeys
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1
                                [LabelType]::KMS_AWSManagedKeys
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_Tags
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_CryptographicConfiguration
                            }
                            # E.g. {"limit":1000}
                            elseif (
                                $requestParametersKeyStr -ceq 'limit' -and `
                                $event.requestParameters.limit -eq 1000 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details
                                [LabelType]::EC2_ElasticBlockStore_Volumes
                                [LabelType]::EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details
                                [LabelType]::EC2_ElasticBlockStore_Snapshots
                            }
                            # E.g. {"marker":"db014773-abcd-1234-5678-133337c0ffee"}
                            elseif ($requestParametersKeyStr -ceq 'marker')
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                                [LabelType]::SecretsManager_Secrets_Create_Step1
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Delete
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview
                                [LabelType]::KMS_CustomerManagedKeys
                            }
                        }
                        'ListKeys' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores_Create_Step1
                            }
                        }
                        'ListResourceTags' {
                            # E.g. {"keyId":"db014773-abcd-1234-5678-133337c0ffee","limit":50}
                            if (
                                $requestParametersKeyStr -ceq 'keyId,limit' -and `
                                $event.requestParameters.limit -eq 50
                            )
                            {
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation
                                [LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_Tags
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'lambda.amazonaws.com' {
                    switch ($event.eventName) {
                        'ListFunctions20150331' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SecretsManager_Secrets_Create_Step3
                            }
                        }
                    }
                }
                'logs.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeMetricFilters' {
                            # E.g. {"limit":50}
                            if (
                                $requestParametersStr -ceq '{"limit":50}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent
                            }
                        }
                    }
                }
                'mgn.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeReplicationConfigurationTemplates' {
                            # E.g. {"replicationConfigurationTemplateIDs":[]}
                            if (
                                $requestParametersKeyStr -ceq 'replicationConfigurationTemplateIDs' -and `
                                $requestParametersKeyEmptyValStr -ceq 'replicationConfigurationTemplateIDs'
                            )
                            {
                                [LabelType]::EC2_MigrateServer
                            }
                        }
                    }
                }
                'monitoring.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeAlarms' {
                            # E.g. {"maxRecords":100}
                            # E.g. {"nextToken":"some-random-api-staging-alarm","maxRecords":100}
                            if (
                                $requestParametersKeyStr -cin @('maxRecords','maxRecords,nextToken') -and `
                                $event.requestParameters.maxRecords -eq 100 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent
                            }
                            # E.g. {"stateValue":"OK","maxRecords":100}
                            # E.g. {"stateValue":"INSUFFICIENT_DATA","maxRecords":100}
                            elseif (
                                $requestParametersKeyStr -eq 'maxRecords,stateValue' -and `
                                $event.requestParameters.stateValue -cin @('ALARM','INSUFFICIENT_DATA','OK') -and `
                                $event.requestParameters.maxRecords -eq 100 -and `
                                $userAgentFamily -ne [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent_EC2_EC2Dashboard
                            }
                        }
                    }
                }
                'notifications.amazonaws.com' {
                    switch ($event.eventName) {
                        'ListNotificationEvents' {
                            # E.g. {"maxResults":"100","locale":"en_US"}
                            if (
                                $requestParametersKeyStr -ceq 'locale,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '100'
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent
                            }
                        }
                        'ListNotificationHubs' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'organizations.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeOrganization' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_BrowserRefresh
                                [LabelType]::IAM
                                [LabelType]::IAM_UserGroups
                                [LabelType]::IAM_Users_CreateUser_Step1
                                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4
                                [LabelType]::S3_StorageLens_AWSOrganizationsSettings
                                [LabelType]::CloudTrail_Dashboard
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                                [LabelType]::CloudTrail_Trails
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::CloudTrail_Lake_Dashboard
                                [LabelType]::CloudTrail_EventHistory
                                [LabelType]::CloudTrail_Insights_Scenario2
                                [LabelType]::CloudTrail_Settings_Scenario2
                                [LabelType]::GuardDuty_Summary
                                [LabelType]::GuardDuty_ProtectionPlans_MalwareProtection
                                [LabelType]::GuardDuty_Accounts
                                [LabelType]::GuardDuty_Settings
                            }
                        }
                        'ListAWSServiceAccessForOrganization' {
                            # In all testing this event generated an error causing requestParameters property to be undefined, but not filtering on
                            # requestParameters logic here in case more privileged user does not generate an error and this property is defined.
                            if ($userAgentFamily -eq [UserAgentFamily]::AWS_Internal)
                            {
                                [LabelType]::S3_StorageLens_AWSOrganizationsSettings
                            }
                            else
                            {
                                [LabelType]::GuardDuty_ProtectionPlans_MalwareProtection
                                [LabelType]::GuardDuty_Accounts
                            }
                        }
                        'ListDelegatedAdministrators' {
                            # In all testing this event generated an error causing requestParameters property to be undefined, but not filtering on
                            # requestParameters logic here in case more privileged user does not generate an error and this property is defined.
                            if ($userAgentFamily -eq [UserAgentFamily]::AWS_Internal)
                            {
                                [LabelType]::IAM_Users_CreateUser_Step1
                                [LabelType]::S3_StorageLens_AWSOrganizationsSettings
                                [LabelType]::CloudTrail_Dashboard
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                                [LabelType]::CloudTrail_Trails
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                            }
                            else
                            {
                                [LabelType]::GuardDuty_Accounts
                                [LabelType]::CloudTrail_Lake_EventDataStores
                                [LabelType]::CloudTrail_Lake_Dashboard
                                [LabelType]::CloudTrail_EventHistory
                                [LabelType]::CloudTrail_Insights_Scenario2
                                [LabelType]::CloudTrail_Settings_Scenario2
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::Generic_Organizations_ListDelegatedAdministrators
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'ram.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'GetResourceShareAssociations' {
                            # E.g. {"resourceArn":"arn:aws:ec2:us-east-1:012345678900:capacity-reservation/cr-01234567890abcdef","associationType":"RESOURCE"}
                            if (
                                $requestParametersKeyStr -ceq 'associationType,resourceArn' -and `
                                $event.requestParameters.associationType -ceq 'RESOURCE' -and `
                                $event.requestParameters.resourceArn.Contains(':capacity-reservation/cr-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::EC2_Console
                            )
                            {
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation
                                [LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION
                            }
                        }
                        'ListResources' {
                            # E.g. {"maxResults":100,"resourceType":"servicecatalog:Applications","resourceOwner":"SELF"}
                            # E.g. {"maxResults":100,"resourceOwner":"SELF","resourceType":"servicecatalog:Applications"}
                            # E.g. {"nextToken":"HyQs<REDACTED>W6td","maxResults":100,"resourceOwner":"SELF","resourceType":"servicecatalog:Applications"}
                            if (
                                $requestParametersKeyStr -cin @('maxResults,resourceOwner,resourceType','maxResults,nextToken,resourceOwner,resourceType') -and `
                                $event.requestParameters.maxResults -eq 100 -and `
                                $event.requestParameters.resourceOwner -ceq 'SELF' -and `
                                $event.requestParameters.resourceType -ceq 'servicecatalog:Applications'
                            )
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'rds.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeDBClusters' {
                            # E.g. {"includeShared":false}
                            if (
                                $requestParametersKeyStr -ceq 'includeShared' -and `
                                $event.requestParameters.includeShared -eq $false
                            )
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step1
                            }
                            # E.g. {"includeShared":false,"filters":[{"name":"engine","values":["docdb"]}]}
                            elseif (
                                $requestParametersKeyStr -ceq 'filters,includeShared' -and `
                                $event.requestParameters.includeShared -eq $false -and `
                                $requestParametersStr.Contains('"name":"engine"') -and `
                                $requestParametersStr.Contains('"values":["docdb"]')
                            )
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step1
                            }
                        }
                        'DescribeDBInstances' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step1
                            }
                        }
                    }
                }
                'redshift.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeClusters' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step1
                            }
                        }
                    }
                }
                'resource-explorer-2.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'ListIndexes' {
                            # E.g. {"Type":"AGGREGATOR"}
                            if ($requestParametersStr -ceq '{"Type":"AGGREGATOR"}')
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SearchBar
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                's3.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'CreateBucket' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.amazonaws.com"}
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","CreateBucketConfiguration":{"LocationConstraint":"us-east-1","xmlns":"http://s3.amazonaws.com/doc/2006-03-01/"},"x-amz-object-ownership":"BucketOwnerEnforced"}
                            if (
                                $requestParametersKeyStr -cin @('bucketName,Host','bucketName,CreateBucketConfiguration,Host,x-amz-object-ownership') -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                            }
                            # E.g. {"bucketName":"aws-cloudtrail-logs-012345678900-c0ffeeee","Host":"s3.us-east-2.amazonaws.com","CreateBucketConfiguration":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/","LocationConstraint":"us-east-2"}}
                            elseif (
                                $requestParametersKeyStr -ceq 'bucketName,CreateBucketConfiguration,Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_CloudTrail
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'DeleteBucket' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step2
                            }
                        }
                        'GetAccelerateConfiguration' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","accelerate":""}
                            if (
                                $requestParametersKeyStr -ceq 'accelerate,bucketName,Host' -and `
                                $requestParametersKeyEmptyValStr -ceq 'accelerate' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetAccountPublicAccessBlock' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                                # Below Labels have single-event Signal definitions, so ensure they remain last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_BlockPublicAccessSettings
                                [LabelType]::S3_Buckets_CreateBucket_Step1
                            }
                        }
                        'GetBucketAcl' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","acl":""}
                            if (
                                $requestParametersKeyStr -ceq 'acl,bucketName,Host' -and `
                                $requestParametersKeyEmptyValStr -ceq 'acl' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                            }
                        }
                        'GetBucketAnalyticsConfiguration' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","analytics":""}
                            if (
                                $requestParametersKeyStr -ceq 'analytics,bucketName,Host' -and `
                                $requestParametersKeyEmptyValStr -ceq 'analytics' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Metrics
                            }
                        }
                        'GetBucketCors' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","cors":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,cors,Host' -and `
                                $requestParametersKeyEmptyValStr -ceq 'cors' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                            }
                        }
                        'GetBucketEncryption' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","encryption":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,encryption,Host' -and `
                                $requestParametersKeyEmptyValStr -ceq 'encryption' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets_CreateBucket_Step1B
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketIntelligentTieringConfiguration' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","intelligent-tiering":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,intelligent-tiering' -and `
                                $requestParametersKeyEmptyValStr -ceq 'intelligent-tiering' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketInventoryConfiguration' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","inventory":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,inventory' -and `
                                $requestParametersKeyEmptyValStr -ceq 'inventory' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Management
                            }
                        }
                        'GetBucketLifecycle' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","lifecycle":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,lifecycle' -and `
                                $requestParametersKeyEmptyValStr -ceq 'lifecycle' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Management
                            }
                        }
                        'GetBucketLocation' {
                            # E.g. {"bucketName":"aws-cloudtrail-logs-012345678900-c0ffeeee","location":"","Host":"s3.us-east-2.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,location' -and `
                                $requestParametersKeyEmptyValStr -ceq 'location' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_CloudTrail
                            )
                            {
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'GetBucketLogging' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","logging":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,logging' -and `
                                $requestParametersKeyEmptyValStr -ceq 'logging' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketNotification' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","notification":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,notification' -and `
                                $requestParametersKeyEmptyValStr -ceq 'notification' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketObjectLockConfiguration' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","object-lock":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,object-lock' -and `
                                $requestParametersKeyEmptyValStr -ceq 'object-lock' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets_CreateBucket_Step1B
                                [LabelType]::S3_Buckets_EmptyBucket
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketOwnershipControls' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","ownershipControls":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,ownershipControls' -and `
                                $requestParametersKeyEmptyValStr -ceq 'ownershipControls' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                            }
                        }
                        'GetBucketPolicy' {
                            # E.g. {"policy":"","bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,policy' -and `
                                $requestParametersKeyEmptyValStr -ceq 'policy' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step1
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                            }
                        }
                        'GetBucketPolicyStatus' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","policyStatus":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,policyStatus' -and `
                                $requestParametersKeyEmptyValStr -ceq 'policyStatus' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                            }
                        }
                        'GetBucketPublicAccessBlock' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","publicAccessBlock":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,publicAccessBlock' -and `
                                $requestParametersKeyEmptyValStr -ceq 'publicAccessBlock' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets_CreateBucket_Step1B
                                [LabelType]::S3_Buckets
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                            }
                        }
                        'GetBucketReplication' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","replication":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,replication' -and `
                                $requestParametersKeyEmptyValStr -ceq 'replication' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Management
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Metrics
                            }
                        }
                        'GetBucketRequestPayment' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","requestPayment":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,requestPayment' -and `
                                $requestParametersKeyEmptyValStr -ceq 'requestPayment' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketTagging' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","tagging":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,tagging' -and `
                                $requestParametersKeyEmptyValStr -ceq 'tagging' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets_CreateBucket_Step1B
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetBucketVersioning' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","versioning":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,versioning' -and `
                                $requestParametersKeyEmptyValStr -ceq 'versioning' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets_CreateBucket_Step1B
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                                [LabelType]::S3_Buckets_EmptyBucket
                            }
                        }
                        'GetBucketWebsite' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","website":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,website' -and `
                                $requestParametersKeyEmptyValStr -ceq 'website' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step1
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                        }
                        'GetStorageLensConfiguration' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                            }
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com"}
                            elseif (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                            }
                        }
                        'GetStorageLensDashboardDataInternal' {
                            # E.g. {"configurationARN":"arn:aws:s3:us-east-1:012345678900:storage-lens/default-account-dashboard"}
                            if (
                                $requestParametersKeyStr -ceq 'configurationARN' -and `
                                $event.requestParameters.configurationARN.EndsWith(':storage-lens/default-account-dashboard') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                            }
                        }
                        'ListAccessPoints' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com","maxResults":"1000"}
                            if (
                                $requestParametersKeyStr -ceq 'Host,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '1000' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_AccessPoints
                            }
                            # E.g. {"maxResults":"1","Host":"012345678900.s3-control.us-east-1.amazonaws.com","bucket":"bucketNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'bucket,Host,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '1' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step1
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Objects
                            }
                            # E.g. {"maxResults":"1000","Host":"012345678900.s3-control.us-east-1.amazonaws.com","bucket":"bucketNameGoesHere"}
                            elseif (
                                $requestParametersKeyStr -ceq 'bucket,Host,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '1000' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_AccessPoints
                            }
                        }
                        'ListAccessPointsForObjectLambda' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com","maxResults":"1000"}
                            if (
                                $requestParametersKeyStr -ceq 'Host,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '1000' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_ObjectLambdaAccessPoints
                            }
                        }
                        'ListBuckets' {
                            # E.g. {"Host":"s3.amazonaws.com"}
                            if (
                                $requestParametersStr -ceq '{"Host":"s3.amazonaws.com"}' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step2
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                                [LabelType]::S3_Buckets
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions
                            }
                            # E.g. {"Host":"s3.us-east-1.amazonaws.com"}
                            elseif (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $event.requestParameters.Host -ceq "s3.$($event.awsRegion).amazonaws.com" -and `
                                $userAgentFamily -eq [UserAgentFamily]::EC2_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::Generic_S3_List_Buckets
                            }
                            # E.g. {"Host":"s3-external-1.amazonaws.com"}
                            # E.g. {"Host":"s3.us-west-1.amazonaws.com"}
                            elseif (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $event.requestParameters.Host.StartsWith('s3') -and `
                                $event.requestParameters.Host.EndsWith('.amazonaws.com') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_CloudTrail
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard
                                [LabelType]::CloudTrail_Insights_SPECIFICINSIGHT
                                [LabelType]::CloudTrail_Trails
                                [LabelType]::CloudTrail_Trails_SPECIFICTRAIL
                            }
                        }
                        'ListJobs' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com","maxResults":"1000","jobStatuses":["Active","Cancelled","Cancelling","Complete","Completing","Failed","Failing","New","Paused","Pausing","Preparing","Ready","Suspended"]}
                            if (
                                $requestParametersKeyStr -ceq 'Host,jobStatuses,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '1000' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_BatchOperations
                            }
                        }
                        'ListMultiRegionAccessPoints' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com","maxResults":"1000"}
                            if (
                                $requestParametersKeyStr -ceq 'Host,maxResults' -and `
                                $event.requestParameters.maxResults -ceq '1000' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_MultiRegionAccessPoints
                            }
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com"}
                            elseif (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step1
                            }
                        }
                        'ListStorageLensConfigurations' {
                            # E.g. {"Host":"012345678900.s3-control.us-east-1.amazonaws.com"}
                            # E.g. {"Host":"012345678900.s3-control.eu-west-3.amazonaws.com"}
                            # E.g. {"Host":"012345678900.s3-control.ap-northeast-1.amazonaws.com"}
                            if (
                                $requestParametersKeyStr -ceq 'Host' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::S3_StorageLens_Dashboards
                            }
                        }
                        'PutBucketEncryption' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","encryption":"","ServerSideEncryptionConfiguration":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/","Rule":{"BucketKeyEnabled":true,"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}}}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,encryption,Host,ServerSideEncryptionConfiguration' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                            }
                        }
                        'PutBucketPolicy' {
                            # E.g. {"policy":"","bucketName":"aws-cloudtrail-logs-012345678900-c0ffeeee","Host":"s3.us-east-2.amazonaws.com","bucketPolicy":{"Version":"2012-10-17T00:00:00.0000000Z","Statement":[{"Sid":"AWSCloudTrailAclCheck20150319","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::aws-cloudtrail-logs-012345678900-c0ffeeee","Condition":{"StringEquals":{"AWS:SourceArn":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName"}}},{"Sid":"AWSCloudTrailWrite20150319","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::aws-cloudtrail-logs-012345678900-c0ffeeee/AWSLogs/012345678900/*","Condition":{"StringEquals":{"AWS:SourceArn":"arn:aws:cloudtrail:us-east-2:012345678900:trail/myTrailName","s3:x-amz-acl":"bucket-owner-full-control"}}}]}}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,bucketPolicy,Host,policy' -and `
                                $requestParametersKeyEmptyValStr -ceq 'policy' -and `
                                $requestParametersStr.Contains('"Sid":"AWSCloudTrailWrite') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_CloudTrail
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'PutBucketPublicAccessBlock' {
                            # E.g. {"bucketName":"aws-cloudtrail-logs-012345678900-c0ffeeee","Host":"s3.us-east-2.amazonaws.com","publicAccessBlock":"","PublicAccessBlockConfiguration":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/","RestrictPublicBuckets":true,"BlockPublicPolicy":true,"BlockPublicAcls":true,"IgnorePublicAcls":true}}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,publicAccessBlock,PublicAccessBlockConfiguration' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                            }
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","publicAccessBlock":"","PublicAccessBlockConfiguration":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/","RestrictPublicBuckets":true,"BlockPublicPolicy":true,"BlockPublicAcls":true,"IgnorePublicAcls":true}}
                            elseif (
                                $requestParametersKeyStr -ceq 'bucketName,Host,publicAccessBlock,PublicAccessBlockConfiguration' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_CloudTrail
                            )
                            {
                                [LabelType]::CloudTrail_Dashboard_CreateTrail_Step2
                            }
                        }
                        'PutBucketTagging' {
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.us-east-1.amazonaws.com","website":""}
                            if (
                                $requestParametersKeyStr -ceq 'bucketName,Host,website' -and `
                                $requestParametersKeyEmptyValStr -ceq 'website' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_DeleteBucket_Step1
                                [LabelType]::S3_Buckets_SPECIFICBUCKET_Properties
                            }
                            # E.g. {"bucketName":"bucketNameGoesHere","Host":"s3.amazonaws.com","Tagging":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/","TagSet":{"Tag":[{"Value":"tag1ValueGoesHere","Key":"tag1NameGoesHere"},{"Value":"","Key":"tag2NameGoesHere"},{"Value":"tag3ValueGoesHere","Key":"tag3NameGoesHere"}]}}}
                            elseif (
                                $requestParametersKeyStr -ceq 'bucketName,Host,Tagging' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                            }
                            # E.g. {"bucketName":"bucketNameGoesHere","tagging":"","Host":"s3.amazonaws.com","Tagging":{"xmlns":"http://s3.amazonaws.com/doc/2006-03-01/","TagSet":{"Tag":[{"Key":"tag1NameGoesHere","Value":"tag1ValueGoesHere"},{"Key":"tag2NameGoesHere","Value":""},{"Key":"tag3NameGoesHere","Value":"tag3ValueGoesHere"}]}}}
                            elseif (
                                $requestParametersKeyStr -cin @('bucketName,Host,Tagging,tagging','bucketName,Host,tagging,Tagging') -and `
                                $requestParametersKeyEmptyValStr -ceq 'tagging' -and `
                                $userAgentFamily -eq [UserAgentFamily]::S3_Console
                            )
                            {
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'secretsmanager.amazonaws.com' {
                    switch ($event.eventName) {
                        'CreateSecret' {
                            # E.g. {"name":"myNewSecretName","description":"myOptionalDescription","clientRequestToken":"db014773-abcd-1234-5678-133337c0ffee","forceOverwriteReplicaSecret":false}
                            if ($requestParametersKeyStr -ceq 'clientRequestToken,description,forceOverwriteReplicaSecret,name')
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step4
                            }
                        }
                        'DeleteSecret' {
                            # E.g. {"secretId":"myNewSecretName","recoveryWindowInDays":30}
                            if ($requestParametersKeyStr -ceq 'recoveryWindowInDays,secretId')
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Delete
                            }
                        }
                        'DescribeSecret' {
                            # E.g. {"secretId":"myNewSecretName"}
                            if ($requestParametersKeyStr -ceq 'secretId')
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Delete
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SuppressAutomatedBackgroundEvent_SecretsManager_Secrets_SPECIFICSECRET
                            }
                        }
                        'GetResourcePolicy' {
                            # E.g. {"secretId":"arn:aws:secretsmanager:us-east-1:012345678900:secret:myNewSecretName-b2Ul9D"}
                            if ($requestParametersKeyStr -ceq 'secretId')
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview
                            }
                        }
                        'GetSecretValue' {
                            # E.g. {"secretId":"arn:aws:secretsmanager:us-east-1:012345678900:secret:myNewSecretName-b2Ul9D"}
                            if ($requestParametersKeyStr -ceq 'secretId')
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview_RetrieveSecretValue
                            }
                        }
                        'ListSecrets' {
                            # E.g. {"maxResults":100,"sortOrder":"desc","includePlannedDeletion":false}
                            if (
                                $requestParametersKeyStr -ceq 'includePlannedDeletion,maxResults,sortOrder' -and `
                                $event.requestParameters.maxResults -eq 100
                            )
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step4
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SecretsManager_Secrets
                            }
                            # E.g. {"maxResults":100,"filters":[],"sortOrder":"desc","includePlannedDeletion":false}
                            # E.g. {"maxResults":100,"filters":[{"values":["best"],"key":"name"}],"sortOrder":"desc","includePlannedDeletion":false}
                            # E.g. {"maxResults":100,"filters":[{"values":"nameValue","key":"name"},{"values":"descriptionValue","key":"description"},{"values":"tagKeyValue","key":"tag-key"},{"values":"tagValueValue","key":"tag-value"},{"values":"replicatedSecretsValue","key":"primary-region"},{"values":"managedByValue","key":"owning-service"},{"values":"nameValue2","key":"name"},{"values":"descriptionValue2","key":"description"},{"values":"tagKeyValue2","key":"tag-key"},{"values":"tagValueValue2","key":"tag-value"},{"values":"replicatedSecretsValue2","key":"primary-region"},{"values":"managedByValue2","key":"owning-service"}],"includePlannedDeletion":false,"sortOrder":"desc"}
                            elseif (
                                $requestParametersKeyStr -ceq 'filters,includePlannedDeletion,maxResults,sortOrder' -and `
                                $event.requestParameters.maxResults -eq 100
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SecretsManager_Secrets
                            }
                            elseif ($requestParametersKeyStr -ceq 'nextToken')
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SecretsManager_Secrets
                            }
                            elseif ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::SecretsManager_Secrets
                            }
                        }
                        'ListSecretVersionIds' {
                            # E.g. {"maxResults":100,"secretId":"arn:aws:secretsmanager:us-east-1:012345678900:secret:myNewSecretName-b2Ul9D"}
                            if (
                                $requestParametersKeyStr -ceq 'maxResults,secretId' -and `
                                $event.requestParameters.maxResults -eq 100
                            )
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Versions
                            }
                        }
                        'RestoreSecret' {
                            # E.g. {"secretId":"arn:aws:secretsmanager:us-east-1:012345678900:secret:myNewSecretName-b2Ul9D"}
                            if ($requestParametersKeyStr -ceq 'secretId')
                            {
                                [LabelType]::SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                            }
                        }
                        'RotateSecret' {
                            # E.g. {"secretId":"myNewSecretName","clientRequestToken":"db014773-abcd-1234-5678-133337c0ffee","rotationLambdaARN":"arn:aws:lambda:us-east-1:012345678900:function:functionNameGoesHere","rotationRules":{"scheduleExpression":"rate(23 hours)"},"rotateImmediately":true}
                            if ($requestParametersKeyStr -ceq 'clientRequestToken,rotateImmediately,rotationLambdaARN,rotationRules,secretId')
                            {
                                [LabelType]::SecretsManager_Secrets_Create_Step4
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'securityhub.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeHub' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'GetAdministratorAccount' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'GetControlFindingSummary' {
                            # E.g. {"Accounts":"CURRENT_ACCOUNT","Regions":"CURRENT_REGION"}
                            # E.g. {"Regions":"ALL_LINKED_REGIONS","Accounts":"CURRENT_ACCOUNT"}
                            if (
                                $requestParametersKeyStr -ceq 'Accounts,Regions' -and `
                                $event.requestParameters.Accounts -ceq 'CURRENT_ACCOUNT' -and `
                                $event.requestParameters.Regions -cin('ALL_LINKED_REGIONS','CURRENT_REGION')
                            )
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'GetFindingAggregator' {
                            # E.g. {"FindingAggregatorArn":"arn%3Aaws%3Asecurityhub%3Aus-east-1%3A785721329856%3Afinding-aggregator/db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'FindingAggregatorArn' -and `
                                $requestParametersStr.StartsWith('{"FindingAggregatorArn":"arn%3Aaws%3Asecurityhub%3A') -and `
                                $requestParametersStr.Contains('%3Afinding-aggregator/')
                            )
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'GetInsightResults' {
                            # E.g. {"InsightArn":"arn%3Aaws%3Asecurityhub%3A%3A%3Ainsight/securityhub/default/29"}
                            if ($requestParametersStr -ceq '{"InsightArn":"arn%3Aaws%3Asecurityhub%3A%3A%3Ainsight/securityhub/default/29"}')
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'ListFindingAggregators' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'ListMembers' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'servicecatalog-appregistry.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'ListApplications' {
                            # E.g. {"maxResults":"100"}
                            if ($requestParametersStr -ceq '{"maxResults":"100"}')
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'signin.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'ConsoleLogin' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $event.responseElements.ConsoleLogin -ceq 'Success'
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::ConsoleLogin
                            }
                        }
                        'GetSigninToken' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and
                                $event.responseElements.GetSigninToken -ceq 'Success' -and
                                $event.userAgent.StartsWith('Jersey/${project.version} (HttpUrlConnection ')
                            )
                            {
                                [LabelType]::ConsoleLogin
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'ssm-guiconnect.amazonaws.com' {
                    switch ($event.eventName) {
                        'CancelConnection' {
                            # E.g. {"ConnectionArn":"arn:aws:ssm-guiconnect:us-east-1:012345678900:connection/db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'ConnectionArn' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Terminate
                            }
                        }
                        'GetConnection' {
                            # E.g. {"ConnectionToken":"db014773-abcd-1234-5678-133337c0ffee_db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'ConnectionToken' -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                            elseif ($requestParametersKeyStr -ceq 'ConnectionToken')
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                        }
                        'StartConnection' {
                            # E.g. {"InstanceId":"i-01234567890abcdef","ConnectionParameters":{"SupportGraphicsPipeline":true},"AuthType":"SSO","Protocol":"RDP","ConnectionType":"SessionManager"}
                            if (
                                $requestParametersKeyStr -ceq 'AuthType,ConnectionParameters,ConnectionType,InstanceId,Protocol' -and `
                                $event.requestParameters.AuthType -ceq 'SSO' -and `
                                $event.requestParameters.Protocol -ceq 'RDP' -and `
                                $event.requestParameters.ConnectionType -ceq 'SessionManager' -and `
                                $event.requestParameters.ConnectionParameters.SupportGraphicsPipeline -eq $true -and `
                                $event.requestParameters.InstanceId.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal_2
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect
                            }
                        }
                    }
                }
                'ssm.amazonaws.com' {
                    switch ($event.eventName) {
                        'DescribeInstanceInformation' {
                            # E.g. {"filters":[{"key":"InstanceIds","values":["i-01234567890abcdef"]}]}
                            if (
                                $requestParametersKeyStr -ceq 'filters' -and `
                                $event.requestParameters.filters.key -ceq 'InstanceIds' -and `
                                $event.requestParameters.filters.values.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                                [LabelType]::EC2_Instances_Instances
                            }
                        }
                        'DescribeInstanceProperties' {
                            # E.g. {"maxResults":50,"filtersWithOperator":[{"key":"AWS:InstanceInformation.InstanceStatus","values":["Terminated"],"operator":"NotEqual"}]}
                            if (
                                $requestParametersKeyStr -ceq 'filtersWithOperator,maxResults' -and `
                                $requestParametersStr.Contains('"key":"AWS:InstanceInformation.InstanceStatus"') -and `
                                $requestParametersStr.Contains('"values":["Terminated"]') -and `
                                $requestParametersStr.Contains('"operator":"NotEqual"') -and `
                                $event.requestParameters.maxResults -eq 50 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
                            }
                        }
                        'DescribeParameters' {
                            # E.g. {"maxResults":50,"shared":false,"parameterFilters":[{"key":"DataType","values":["aws:ec2:image"]}]}
                            if (
                                $requestParametersKeyStr -ceq 'maxResults,parameterFilters,shared' -and `
                                $requestParametersStr.Contains('"key":"DataType"') -and `
                                $requestParametersStr.Contains('"aws:ec2:image"') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Images_AMICatalog_SearchBySystemsManagerParameter
                            }
                        }
                        'DescribeSessions' {
                            # E.g. {"maxResults":50,"filters":[{"value":"Connected","key":"Status"},{"value":"andi.ahmeti@permiso.io-043f464cef7300f02","key":"SessionId"}],"state":"Active"}
                            # E.g. {"maxResults":50,"filters":[{"key":"Status","value":"Connected"},{"key":"SessionId","value":"andi.ahmeti@permiso.io-043f464cef7300f02"}],"state":"Active"}
                            # E.g. {"maxResults":50,"filters":[{"key":"Status","value":"Connected"},{"key":"SessionId","value":"andi.ahmeti@permiso.io-043f464cef7300f02"}],"state":"Active"}
                            if (
                                $requestParametersKeyStr -ceq 'filters,maxResults,state' -and `
                                $event.requestParameters.maxResults -eq 50 -and `
                                $event.requestParameters.state -ceq 'Active' -and `
                                $requestParametersStr.Contains('"key":"Status"') -and `
                                $requestParametersStr.Contains('"value":"Connected"')
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                            }
                        }
                        'GetCommandInvocation' {
                            # E.g. {"instanceId":"i-01234567890abcdef","commandId":"db014773-abcd-1234-5678-133337c0ffee"}
                            if (
                                $requestParametersKeyStr -ceq 'commandId,instanceId' -and `
                                $event.requestParameters.instanceId.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                        }
                        'GetConnectionStatus' {
                            # E.g. {"target":"i-01234567890abcdef"}
                            if (
                                $requestParametersKeyStr -ceq 'target' -and `
                                $event.requestParameters.target.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                            }
                        }
                        'GetDocument' {
                            # E.g. {"name":"SSM-SessionManagerRunShell","documentVersion":"$LATEST","allowInvalidContent":false}
                            if (
                                $requestParametersKeyStr -ceq 'allowInvalidContent,documentVersion,name' -and `
                                $event.requestParameters.name -ceq 'SSM-SessionManagerRunShell' -and `
                                $event.requestParameters.documentVersion -ceq '$LATEST' -and `
                                $event.requestParameters.allowInvalidContent -eq $false -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
                            }
                        }
                        'SendCommand' {
                            # E.g. {"instanceIds":["i-01234567890abcdef"],"documentName":"AWSSSO-CreateSSOUser","parameters":"HIDDEN_DUE_TO_SECURITY_REASONS","interactive":false}
                            if (
                                $requestParametersKeyStr -ceq 'documentName,instanceIds,interactive,parameters' -and `
                                $event.requestParameters.parameters -ceq 'HIDDEN_DUE_TO_SECURITY_REASONS' -and `
                                $event.requestParameters.documentName -ceq 'AWSSSO-CreateSSOUser' -and `
                                $event.requestParameters.interactive -eq $false -and `
                                $event.requestParameters.instanceIds.Where( { $_.StartsWith('i-') } ).Count -gt 0 -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                        }
                        'StartSession' {
                            # E.g. {"target":"i-01234567890abcdef"}
                            if (
                                $requestParametersKeyStr -ceq 'target' -and `
                                $event.requestParameters.target.StartsWith('i-')
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                            }
                            # E.g. {"documentName":"AWS-StartPortForwardingSession","parameters":{"localPortNumber":["9000"],"portNumber":["3389"]},"reason":"Used for SSM Fleet Manager Remote Desktop","target":"i-01234567890abcdef"}
                            elseif (
                                $requestParametersKeyStr -ceq 'documentName,parameters,reason,target' -and `
                                $event.requestParameters.documentName -ceq 'AWS-StartPortForwardingSession' -and `
                                $event.requestParameters.reason -ceq 'Used for SSM Fleet Manager Remote Desktop' -and `
                                $event.requestParameters.target.StartsWith('i-') -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                        }
                        'TerminateSession' {
                            # E.g. {"sessionId":"andi.ahmeti@permiso.io-01234567890abcdef"}
                            if ($requestParametersKeyStr -ceq 'sessionId')
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Terminate
                                # Below Label has single-event Signal definition, so ensure it remains last to avoid clobbering any potential multi-event Signal definitions.
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Terminate
                            }
                        }
                    }
                }
                'sso.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeRegisteredRegions' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and`
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::IAM_Users_CreateUser_Step1
                            }
                        }
                        'ListDirectoryAssociations' {
                            if (
                                [System.String]::IsNullOrEmpty($event.requestParameters) -and `
                                $userAgentFamily -eq [UserAgentFamily]::AWS_Internal
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'sts.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'GetCallerIdentity' {
                            if ([System.String]::IsNullOrEmpty($event.requestParameters))
                            {
                                [LabelType]::CloudShell_NewSession
                                [LabelType]::CloudShell_RenewSession
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'support.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'DescribeTrustedAdvisorChecks' {
                            # E.g. {"language"="en"}
                            if ($requestParametersKeyStr -ceq 'language')
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        'DescribeTrustedAdvisorCheckSummaries' {
                            # E.g. {"checkIds":["s9rS3217a1","<REDACTED>","Ha3s4MGHQw"]}
                            if ($requestParametersKeyStr -ceq 'checkIds')
                            {
                                [LabelType]::ConsoleHome
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                'tagging.amazonaws.com' {
                    switch ($event.eventName)
                    {
                        'GetResources' {
                            # E.g. {"paginationToken":"","resourcesPerPage":100,"resourceTypeFilters":["kms"]}
                            if (
                                $requestParametersKeyStr -ceq 'paginationToken,resourcesPerPage,resourceTypeFilters' -and `
                                $requestParametersKeyEmptyValStr -ceq 'paginationToken' -and `
                                $event.requestParameters.resourcesPerPage -eq 100 -and `
                                $requestParametersStr.Contains('"resourceTypeFilters":["kms"]')
                            )
                            {
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4
                                [LabelType]::KMS_CustomerManagedKeys
                                [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1
                                [LabelType]::KMS_AWSManagedKeys
                            }
                            # E.g. {"paginationToken":"","resourcesPerPage":50,"resourceTypeFilters":["elasticloadbalancing:loadbalancer"]}
                            elseif (
                                $requestParametersKeyStr -ceq 'paginationToken,resourcesPerPage,resourceTypeFilters' -and `
                                $requestParametersKeyEmptyValStr -ceq 'paginationToken' -and `
                                $requestParametersStr.Contains('"elasticloadbalancing:loadbalancer"') -and `
                                $event.requestParameters.resourcesPerPage -eq 50
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_LoadBalancers
                            }
                            # E.g. {"paginationToken":"","resourcesPerPage":50,"resourceTypeFilters":["elasticloadbalancing:targetgroup"]}
                            elseif (
                                $requestParametersKeyStr -ceq 'paginationToken,resourcesPerPage,resourceTypeFilters' -and `
                                $requestParametersKeyEmptyValStr -ceq 'paginationToken' -and `
                                $requestParametersStr.Contains('"elasticloadbalancing:targetgroup"') -and `
                                $event.requestParameters.resourcesPerPage -eq 50
                            )
                            {
                                [LabelType]::EC2_LoadBalancing_TargetGroups
                            }
                            # E.g. {"paginationToken":"","resourcesPerPage":50,"tagFilters":[{"key":"cloudwatch:datasource"}]}
                            elseif (
                                $requestParametersKeyStr -ceq 'paginationToken,resourcesPerPage,tagFilters' -and `
                                $requestParametersKeyEmptyValStr -ceq 'paginationToken' -and `
                                $requestParametersStr.Contains('"key":"cloudwatch:datasource"') -and `
                                $event.requestParameters.resourcesPerPage -eq 50
                            )
                            {
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect
                                [LabelType]::EC2_Instances_Instances
                            }
                        }
                        default {
                            Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventName ('$($event.eventName)') in current eventSource ('$($event.eventSource)') in switch block."
                        }
                    }
                }
                default {
                    Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled eventSource ('$($event.eventSource)') in switch block."
                }
            }).Where( { $null -ne $_ } )
            # Above null check is needed since first LabelType enum value is 0 which
            # PowerShell evaluates to $false, so typical '.Where( { $_ } )' syntax would
            # still skip a value of 0 (which is not the desired behavior for this script).

            # Prepend any potential userAgent-based Label(s) to Label array so they
            # take precedence over any potential existing Label(s).
            $labelArr = [System.Array] @(switch ($userAgentFamily)
            {
                ([UserAgentFamily]::CloudShell_AWSCLI) {
                    [LabelType]::CloudShell_InteractiveCommand_AWSCLI
                }
                ([UserAgentFamily]::CloudShell_AWSPowerShell) {
                    [LabelType]::CloudShell_InteractiveCommand_AWSPowerShell
                }
                ([UserAgentFamily]::CloudShell_Boto) {
                    [LabelType]::CloudShell_InteractiveCommand_Boto
                }
                ([UserAgentFamily]::CloudShell_Generic) {
                    [LabelType]::CloudShell_InteractiveCommand_Generic
                }
            }) + $labelArr

            # Add new Enrichment object to contain all new properties for later reference.
            $enrichmentObj = [Enrichment] @{
                Labels        = [LabelType[]] $labelArr
                EventNameFull = [System.String] $eventNameFull
            }

            # Add above Enrichment object as new property for current event for later reference.
            $eventObj = [PSCustomObject] @{
                Enrichment = [Enrichment] $enrichmentObj
                Event      = $event
            }

            # Return current event object.
            $eventObj
        }
    }
}