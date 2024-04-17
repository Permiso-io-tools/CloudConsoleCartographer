function Add-Signal
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Add-Signal
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Format-EventObject, Add-Label, New-Signal, Update-Signal, Merge-Signal
Optional Dependencies: None

.DESCRIPTION

Add-Signal performs full mapping evaluation, adding a Signal to each corresponding event's Enrichment property after updating all potentially affected aggregated events when successful mapping identified.

.PARAMETER Event

Specifies events for which to perform full mapping evaluation for potential addition of Signal(s).

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Select-Object -First 5

Enrichment Event
---------- -----
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}

.EXAMPLE

PS C:\> aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 | Add-Signal | Select-Object -First 5

Enrichment Event
---------- -----
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}
Enrichment {System.Collections.Hashtable}

.EXAMPLE

PS C:\> aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 > awsCliOutput.json
PS C:\> dir awsCliOutput.json | Add-Signal -Verbose | Select-Object -First 5

[*] [00:00:00.5071890] Added 2991 Label(s) to 1101 of 1101 Events
[*] [00:00:00.4101001] Added 156 Signal(s) to 1100 of 1101 Events

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
        # Purposefully not defining parameter type since mixture of Event formats allowed.
        $Event,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Quiet
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
        # Ensure input events are parsed and formatted correctly regardless of input format.
        $eventArr = Format-EventObject -InputObject $eventArr

        # Ensure input events are sorted by eventTime property.
        $eventArr = $eventArr | Sort-Object -Property eventTime

        # Add Labels to input events for use in later Signal evaluation, tracking elapsed
        # time for Add-Label function invocation.
        [System.TimeSpan] $elapsedTime = Measure-Command {
            $eventObjArr = Add-Label -Event $eventArr
        }

        # Output Label statistics from above function invocation if user input -Verbose
        # switch parameter is defined.
        if ($PSBoundParameters['Verbose'].IsPresent)
        {
            $labelCount = ($eventObjArr.Enrichment.ForEach( { $_.Labels.Count } ) | Measure-Object -Sum).Sum
            $eventWithLabelCount = $eventObjArr.Enrichment.Where( { $_.Labels.Count -gt 0 } ).Count
            Write-Host '[*] ['              -NoNewline -ForegroundColor Cyan
            Write-Host $elapsedTime         -NoNewline -ForegroundColor Yellow
            Write-Host '] Added '           -NoNewline -ForegroundColor Cyan
            Write-Host $labelCount          -NoNewline -ForegroundColor Yellow
            Write-Host ' Label(s) to '      -NoNewline -ForegroundColor Cyan
            Write-Host $eventWithLabelCount -NoNewline -ForegroundColor Yellow
            Write-Host ' of '               -NoNewline -ForegroundColor Cyan
            Write-Host $eventObjArr.Count   -NoNewline -ForegroundColor Yellow
            Write-Host ' Events'                       -ForegroundColor Cyan

            # Set stopwatch to track elapsed time of remaining Signal evaluation logic below.
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }

        # Define single Hashtable (i.e. Dictionary) to store instances of Signal definitions
        # for all Labels in LabelType enum.
        $signalDict = @{ }
        [LabelType].GetEnumNames().ForEach( { $signalDict.Add([LabelType] $_,[Signal]::new([LabelType] $_)) } )

        # Set IsAnchor Boolean property for all event objects that are defined as an anchor
        # event in at least one of their Labels' Signal definitions.
        foreach ($eventObj in $eventObjArr)
        {
            $eventObj.Enrichment.IsAnchor = $eventObj.Enrichment.Labels.Where(
            {
                $eventObj.Enrichment.EventNameFull -cin $signalDict[$_].AnchorEvents -or `
                [System.String] $signalDict[$_].AnchorEvents -ceq '*'
            } ).Count -gt 0 ? $true : $false
        }

        # Separately track all previous event objects that triggered a Signal for more
        # efficient future reference by a small subset of Signals that rely on previous
        # Signal context for increased accuracy.
        $prevEventWithSignalObjArr = @()

        # Iterate over input event objects, performing Signal evaluation logic for anchor
        # events (e.g. those containing a Label and also defined as anchor event in $signalDict
        # definition) and any nearby events with a matching Label.
        for ($i = 0; $i -lt $eventObjArr.Count; $i++)
        {
            $eventObj = $eventObjArr[$i]

            # Skip current event object if it is not defined as an anchor event for any of its Labels.
            if ($eventObj.Enrichment.IsAnchor -eq $false)
            {
                continue
            }

            # Skip current event object if it has already contributed to generating a Signal.
            if ($eventObj.Enrichment.IsSignalContributor -eq $true)
            {
                continue
            }

            # Iterate over each Label added to current event object.
            foreach ($label in $eventObj.Enrichment.Labels)
            {
                # Skip current event object if it is not defined as an anchor event according
                # to current Label's Signal definition unless current Label's Signal definition
                # purposefully does not define a specific anchor event (e.g. userAgent-based labels).
                if (
                    $eventObj.Enrichment.EventNameFull -cnotin $signalDict[$label].AnchorEvents -and `
                    [System.String] $signalDict[$label].AnchorEvents -cne '*'
                )
                {
                    continue
                }

                # Define bookend timestamps relative to current event for retrieving eligible
                # event objects for current Signal evaluation.
                $eventTimeMinBound = $eventObj.Event.eventTime.AddSeconds($signalDict[$label].LookbackInSeconds * -1.0)
                $eventTimeMaxBound = $eventObj.Event.eventTime.AddSeconds($signalDict[$label].LookaheadInSeconds)

                # Retrieve nearby preceding and proceeding event objects containing current
                # Label found in current anchor event object and store in separate array.
                $j = $i - 1
                $prevEventObjArr = @(while ($j -ge 0 -and $eventObjArr[$j].Event.eventTime -ge $eventTimeMinBound)
                {
                    # Retain current event object if it contains current Label and has not
                    # already contributed to a previous Signal.
                    if (
                            $eventObjArr[$j].Enrichment.Labels -ccontains $label -and `
                            $eventObjArr[$j].Enrichment.IsSignalContributor -eq $false
                    )
                    {
                        $eventObjArr[$j]
                    }

                    # Decrement index for next while loop iteration.
                    $j--
                })
                $j = $i + 1
                $postEventObjArr = @(while ($j -lt $eventObjArr.Count -and  $eventObjArr[$j].Event.eventTime -le $eventTimeMaxBound)
                {
                    # Retain current event object if it contains current Label and has not
                    # already contributed to a previous Signal.
                    if (
                        $eventObjArr[$j].Enrichment.Labels -ccontains $label -and `
                        $eventObjArr[$j].Enrichment.IsSignalContributor -eq $false
                    )
                    {
                        $eventObjArr[$j]
                    }

                    # Increment index for next while loop iteration.
                    $j++
                })

                # Reverse array of previous event objects since it was assembled in reverse order.
                [System.Array]::Reverse($prevEventObjArr)

                # Join previous, current and post event objects into a single array of related
                # event objects for final Signal evaluation.
                $relatedEventObjArr = [System.Array] $prevEventObjArr + $eventObj + $postEventObjArr

                # Extract full event names from array of related event objects and store as
                # sorted and uniqued values in separate arrays based on if event is required
                # or only optional based on current Label's Signal definition.
                $relatedRequiredEventObjArr = $relatedEventObjArr.Enrichment.EventNameFull.Where( { $_ -cin $signalDict[$label].RequiredEvents } ) | Sort-Object -Unique

                # If any related event objects containing current Label are not defined in
                # current Label's Signal definition (if any are defined) then output warning
                # message and remove unhandled event objects from array of related event
                # objects to avoid them contributing to Signal generation until modifying
                # current Label's Signal definition.
                $relatedUnhandledEventObjArr = ($relatedEventObjArr.Enrichment.EventNameFull.Where(
                {
                    $_ -cnotin ([System.Array] $signalDict[$label].AnchorEvents + `
                                               $signalDict[$label].RequiredEvents + `
                                               $signalDict[$label].OptionalEvents)
                } )) | Sort-Object -Unique
                if (
                    $relatedUnhandledEventObjArr.Count -gt 0 -and `
                    [System.String] $signalDict[$label].RequiredEvents -cne '*'
                )
                {
                    Write-Warning "[$($MyInvocation.MyCommand.Name)] The following $($relatedUnhandledEventObjArr.Count) $($relatedUnhandledEventObjArr.Count -eq 1 ? 'event contains' : 'events contain') '[LabelType]::$label' Label but $($relatedUnhandledEventObjArr.Count -eq 1 ? 'is' : 'are') not defined in AnchorEvents, RequiredEvents or OptionalEvents properties in [LabelType]::$label'$(([System.String] $label).EndsWith('s') ? '' : 's') Signal definition: ($($relatedUnhandledEventObjArr.ForEach( { "'$_'" } ) -join ','))"

                    # Remove any unhandled events from array of related event objects to
                    # avoid them contributing to Signal generation until modifying current
                    # Label's Signal definition.
                    $relatedEventObjArr = $relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -cnotin $relatedUnhandledEventObjArr } )
                }

                # If all required events (if any are defined) are present then generate Signal.
                if (
                    (
                        [System.String] $signalDict[$label].RequiredEvents -ceq [System.String] $relatedRequiredEventObjArr -or `
                        [System.String] $signalDict[$label].RequiredEvents -ceq '*'
                    )
                )
                {
                    # Potentially filter current selection of related events based on
                    # RequiredEvents or OptionalEvents properties.
                    if (
                        [System.String] $signalDict[$label].AnchorEvents -ceq '*' -and `
                        [System.String] $signalDict[$label].RequiredEvents -ceq '*' -and `
                        ([System.String] $label).StartsWith('CloudShell_InteractiveCommand_')
                    )
                    {
                        # Handle CloudShell scenario separately so each event is shown
                        # as its own mapped interactive event.
                        $relatedEventObjArr = $relatedEventObjArr | Select-Object -First 1
                    }
                    else
                    {
                        # Remove any related events that are not defined in RequiredEvents
                        # or OptionalEvents (e.g. an AnchorEvent only) to avoid it
                        # contributing to Signal generation.
                        $relatedEventObjArr = $relatedEventObjArr.Where(
                        {
                            $_.Enrichment.EventNameFull -cin ([System.Array] $signalDict[$label].RequiredEvents + `
                                                                             $signalDict[$label].OptionalEvents)
                        } )

                        # Remove current event from array of related event objects (and
                        # replace with next eligible anchor event) if current event is
                        # defined in AnchorEvents but not in RequiredEvents or OptionalEvents.
                        # This scenario occurs when an AnchorEvent is defined solely for
                        # reordering priority of another Signal that has no shared required event.
                        if ($eventObj.Enrichment.EventNameFull -cnotin $relatedEventObjArr)
                        {
                            # Reassign $eventObj variable to be the next remaining eligible
                            # anchor event in related events following current event while
                            # keeping copy in $prevEventObj for error handling if no remaining
                            # eligible anchor events are found.
                            $prevEventObj = $eventObj
                            $eventObj = $relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -cin $signalDict[$label].AnchorEvents } ) | Select-Object -First 1

                            # Output warning message if no eligible anchor event is found in
                            # related event object array.
                            if ($null -eq $eventObj)
                            {
                                Write-Warning "[$($MyInvocation.MyCommand.Name)] Neither the current Anchor Event '$($prevEventObj.Enrichment.EventNameFull)' nor any surrounding event is not defined in RequiredEvents or OptionalEvents properties in [LabelType]::$label'$(([System.String] $label).EndsWith('s') ? '' : 's') Signal definition, so skipping Signal generation. Ensure that at least one AnchorEvent is also defined in RequiredEvents (or all events in OptionalEvents if RequiredEvents is '*')."

                                # Set label to $null to avoid a Signal being generated.
                                $label = $null
                                $prevEventObj = $null
                            }
                        }
                    }

                    # Define lookback scenarios where adjacent or nearby Signals add context to
                    # override LabelType value for current to-be-created Signal when multiple
                    # mapping scenarios have identical definitions and appear identically in event logs.
                    if (
                        $label -eq [LabelType]::KMS_CustomKeyStores_ExternalKeyStores -and `
                        -not ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('KMS')
                    )
                    {
                        # Override current [LabelType]::KMS_CustomKeyStores_ExternalKeyStores
                        # LabelType value if the Signal that precedes it is not another KMS* Signal.
                        $label = [LabelType]::KMS
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NetworkSettings_FirewallSecurityGroup_Select -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1')
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_NetworkSettings_FirewallSecurityGroup_Select
                        # LabelType value if the Signal that precedes it is an EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_NetworkSettings_FirewallSecurityGroup_SelectExistingSecurityGroup
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Events -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_EC2Dashboard_') -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).EndsWith('_Refresh')
                    )
                    {
                        # Override current [LabelType]::EC2_Events LabelType value if the
                        # Signal that precedes it is an EC2_EC2Dashboard_*_Refresh Signal.
                        $label = [LabelType]::EC2_EC2Dashboard_ScheduledEvents_Refresh
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole -and `
                        @(for ($reverseIndex = $prevEventWithSignalObjArr.Length - 1; $reverseIndex -ge 0; $reverseIndex--)
                        {
                            # Break if current lookback Signal occurred more than 5 minutes
                            # before current Signal; however, the latest 3 Signals are
                            # considered valid no matter their age.
                            if (
                                $prevEventWithSignalObjArr[$reverseIndex].Event.eventTime -lt $eventObj.Event.eventTime.AddMinutes(-5) -and `
                                ($reverseIndex -lt $prevEventWithSignalObjArr.Length - 3)
                            )
                            {
                                break
                            }

                            # Break if any lookback Signal is an EC2_EC2Dashboard_Settings_* Signal
                            # (excluding EC2_EC2Dashboard_Settings_EC2SerialConsole* Signals).
                            if (
                                ([System.String] $prevEventWithSignalObjArr[$reverseIndex].Enrichment.Signal.Label).StartsWith('EC2_EC2Dashboard_Settings_') -and -not `
                                ([System.String] $prevEventWithSignalObjArr[$reverseIndex].Enrichment.Signal.Label).StartsWith('EC2_EC2Dashboard_Settings_EC2SerialConsole')
                            )
                            {
                                break
                            }

                            # Return $true and break if any lookback Signal is an
                            # EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_* Signal.
                            if (([System.String] $prevEventWithSignalObjArr[$reverseIndex].Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_'))
                            {
                                $true
                                break
                            }
                        })
                    )
                    {
                        # Override current [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole
                        # LabelType value if any Signal that precedes it in the last 5 minutes
                        # (or any of the last 3 Signals regardless of their age) is an
                        # EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_* Signal.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                    }
                    elseif ($label -eq [LabelType]::SuppressAutomatedBackgroundEvent_EC2_LoadBalancing_TrustStores)
                    {
                        # Override current [LabelType]::SuppressAutomatedBackgroundEvent_EC2_LoadBalancing_TrustStores
                        # LabelType value since it only serves as a more specific version
                        # of [LabelType]::SuppressAutomatedBackgroundEvent.
                        $label = [LabelType]::SuppressAutomatedBackgroundEvent
                    }
                    #
                    # Normalization of multi-scenario Signals requiring multiple
                    # definitions based on context.
                    #
                    elseif ($label -eq [LabelType]::CloudTrail_Insights_Scenario2)
                    {
                        # Override current [LabelType]::CloudTrail_Insights_Scenario2
                        # LabelType value since it only serves as a necessary secondary
                        # Signal definition for [LabelType]::CloudTrail_Insights.
                        $label = [LabelType]::CloudTrail_Insights
                    }
                    elseif ($label -eq [LabelType]::CloudTrail_Settings_Scenario2)
                    {
                        # Override current [LabelType]::CloudTrail_Settings_Scenario2
                        # LabelType value since it only serves as a necessary secondary
                        # Signal definition for [LabelType]::CloudTrail_Settings.
                        $label = [LabelType]::CloudTrail_Settings
                    }
                    elseif ($label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2)
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Scenario2
                        # LabelType value since it only serves as a necessary secondary
                        # Signal definition for [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager
                    }
                    elseif ($label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2)
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect_Scenario2
                        # LabelType value since it only serves as a necessary secondary
                        # Signal definition for [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect
                    }
                    elseif ($label -eq [LabelType]::EC2_Instances_LaunchTemplates_Scenario2)
                    {
                        # Override current [LabelType]::EC2_Instances_LaunchTemplates_Scenario2
                        # LabelType value since it only serves as a necessary secondary
                        # Signal definition for [LabelType]::EC2_Instances_LaunchTemplates.
                        $label = [LabelType]::EC2_Instances_LaunchTemplates
                    }
                    #
                    # Plural version Signal overrides.
                    #
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring -and `
                        ($relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeTags' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).Where( { $_.name -ceq 'resource-id' } ).ForEach( { $_.valueSet.items.value } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique).Count -gt 1
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring
                        # LabelType value to plural version if more than one instanceId
                        # present in ec2:DescribeTags events.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance -and `
                        ($relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:RebootInstances' } ).ForEach( { $_.Event.requestParameters.instancesSet.items.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique).Count -gt 1
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
                        # LabelType value to plural version if more than one instanceId
                        # present in ec2:RebootInstances events.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance -and `
                        ($relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:StartInstances' } ).ForEach( { $_.Event.requestParameters.instancesSet.items.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique).Count -gt 1
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
                        # LabelType value to plural version if more than one instanceId
                        # present in ec2:StartInstances events.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance -and `
                        ($relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:StopInstances' } ).ForEach( { $_.Event.requestParameters.instancesSet.items.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique).Count -gt 1
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                        # LabelType value to plural version if more than one instanceId
                        # present in ec2:StopInstances events.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1 -and `
                        ($relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeInstanceAttribute' } ).ForEach( { $_.Event.requestParameters.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique).Count -gt 1
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1
                        # LabelType value to plural version if more than one instanceId
                        # present in ec2:DescribeInstanceAttribute events.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step1
                    }
                    elseif (
                        $label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2 -and `
                        ($relatedEventObjArr.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:TerminateInstances' } ).ForEach( { $_.Event.requestParameters.instancesSet.items.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique).Count -gt 1
                    )
                    {
                        # Override current [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
                        # LabelType value to plural version if more than one instanceId
                        # present in ec2:TerminateInstances events.
                        $label = [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2
                    }
                    #
                    # GENERIC_* Signal overrides.
                    #
                    elseif (
                        $label -eq [LabelType]::Generic_CloudTrail_ListEventDataStores -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('CloudTrail_')
                    )
                    {
                        # Override current [LabelType]::Generic_CloudTrail_ListEventDataStores
                        # LabelType value if the Signal that precedes it is a CloudTrail_* Signal.
                        $label = [LabelType]::CloudTrail_Lake_Query
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_ApplicationAndOSImages_Search -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_LaunchInstance_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                        # LabelType value if the Signal that precedes it is an
                        # EC2_Instances_Instances_LaunchInstance_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ApplicationAndOSImages_Search
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_ApplicationAndOSImages_Search -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_ApplicationAndOSImages_Search
                        # LabelType value if the Signal that precedes it is an
                        # EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_ApplicationAndOSImages_Search
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_ApplicationAndOSImages_Select -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_LaunchInstance_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                        # LabelType value if the Signal that precedes it is an
                        # EC2_Instances_Instances_LaunchInstance_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_ApplicationAndOSImages_Select
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_ApplicationAndOSImages_Select -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_ApplicationAndOSImages_Select
                        # LabelType value if the Signal that precedes it is an
                        # EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_ApplicationAndOSImages_Select
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_KeyPair_Select -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_LaunchInstance_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_KeyPair_Select LabelType
                        # value if the Signal that precedes it is an EC2_Instances_Instances_LaunchInstance_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Select
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_KeyPair_Select -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_KeyPair_Select LabelType
                        # value if the Signal that precedes it is an EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Select
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_KeyPair_Create -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_LaunchInstance_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_KeyPair_Create LabelType
                        # value if the Signal that precedes it is an EC2_Instances_Instances_LaunchInstance_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Create
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_EC2_KeyPair_Create -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1')
                    )
                    {
                        # Override current [LabelType]::Generic_EC2_KeyPair_Create LabelType
                        # value if the Signal that precedes it is an EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1* Signal.
                        $label = [LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Create
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_S3_List_Buckets -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('EC2_LoadBalancing_TrustStores')
                    )
                    {
                        # Override current [LabelType]::Generic_S3_List_Buckets LabelType
                        # value if the Signal that precedes it is an EC2_LoadBalancing_TrustStores* Signal.
                        $label = [LabelType]::EC2_LoadBalancing_TrustStores_CreateTrustStore_Step1_BrowseS3
                    }
                    elseif (
                        $label -eq [LabelType]::Generic_Organizations_ListDelegatedAdministrators -and `
                        ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('CloudTrail')
                    )
                    {
                        # Override current [LabelType]::Generic_Organizations_ListDelegatedAdministrators
                        # LabelType value if the Signal that precedes it is an CloudTrail* Signal.
                        $label = [LabelType]::CloudTrail_Settings
                    }

                    # Define lookback scenarios where adjacent or nearby Signals add context
                    # to avoid creating current Signal.
                    if (
                        $label -eq [LabelType]::SecretsManager_Secrets_Create_Step2 -and `
                        -not ([System.String] $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label).StartsWith('SecretsManager_Secrets_Create_Step')
                    )
                    {
                        # Set label to $null to avoid a Signal being generated for
                        # [LabelType]::SecretsManager_Secrets_Create_Step2 LabelType value
                        # if the Signal that precedes it is not a SecretsManager_Secrets_Create_Step* Signal.
                        $label = $null
                    }

                    # Create new Signal (unless $label has been overridden and set to $null).
                    if ($null -ne $label)
                    {
                        # Create new instance of Signal object corresponding with current
                        # Label and store in current event object's Enrichment property.
                        $eventObj.Enrichment = New-Signal -Label $label -AnchorEvent $eventObj -RelatedEvents $relatedEventObjArr -PreviousSignals $prevEventWithSignalObjArr

                        # Define lookback scenarios where adjacent or nearby Signals add
                        # context to override a previous or current Signal when multiple
                        # mapping scenarios have identical definitions and appear
                        # identically in event logs.
                        if (
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::S3_BlockPublicAccessSettings -and `
                            $eventObj.Enrichment.Signal.Label -in @(
                                [LabelType]::S3_Buckets_CreateBucket_Step1B
                                [LabelType]::S3_Buckets_CreateBucket_Step2
                            )
                        )
                        {
                            # Override previous [LabelType]::S3_BlockPublicAccessSettings
                            # Signal if the Signal that follows it (i.e. the current Signal) is
                            # [LabelType]::S3_Buckets_CreateBucket_Step1B or
                            # [LabelType]::S3_Buckets_CreateBucket_Step2.

                            # Extract Signal object to override and define new LabelType
                            # value to which Signal object will be overridden.
                            $overrideEventObj = $prevEventWithSignalObjArr[-1]
                            $overrideLabel = [LabelType]::S3_Buckets_CreateBucket_Step1

                            # Update Signal with new LabelType value defined above.
                            Update-Signal -Label $overrideLabel -AnchorEvent $overrideEventObj -EventIndex $i -AllEvents $eventObjArr -PreviousSignals $prevEventWithSignalObjArr
                        }
                        elseif (
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::KMS_CustomerManagedKeys -and `
                            $eventObj.Enrichment.Signal.Label -eq [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2
                        )
                        {
                            # Override previous [LabelType]::KMS_CustomerManagedKeys Signal
                            # if the Signal that follows it (i.e. the current Signal) is
                            # [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2.

                            # Extract Signal object to override and define new LabelType value to which Signal object will be overridden.
                            $overrideEventObj = $prevEventWithSignalObjArr[-1]
                            $overrideLabel = [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1

                            # Update Signal with new LabelType value defined above.
                            Update-Signal -Label $overrideLabel -AnchorEvent $overrideEventObj -EventIndex $i -AllEvents $eventObjArr -PreviousSignals $prevEventWithSignalObjArr
                        }
                        elseif (
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2 -and `
                            $eventObj.Enrichment.Signal.Label -eq [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4
                        )
                        {
                            # Override previous [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2
                            # Signal if the Signal that follows it (i.e. the current Signal)
                            # is [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4.

                            # Extract Signal object to override and define new LabelType value to which Signal object will be overridden.
                            $overrideEventObj = $prevEventWithSignalObjArr[-1]
                            $overrideLabel = [LabelType]::KMS_CustomerManagedKeys_CreateKey_Step3

                            # Update Signal with new LabelType value defined above.
                            Update-Signal -Label $overrideLabel -AnchorEvent $overrideEventObj -EventIndex $i -AllEvents $eventObjArr -PreviousSignals $prevEventWithSignalObjArr
                        }
                        elseif (
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole -and `
                            $eventObj.Enrichment.Signal.Label -in @([LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Allow,[LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Disallow)
                        )
                        {
                            # Override previous [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole
                            # Signal if the Signal that follows it (i.e. the current Signal)
                            # is [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Allow
                            # or [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole_ManageAccess_Disallow.

                            # Extract Signal object to override and define new LabelType value to which Signal object will be overridden.
                            $overrideEventObj = $prevEventWithSignalObjArr[-1]
                            $overrideLabel = [LabelType]::EC2_EC2Dashboard_Settings_EC2SerialConsole

                            # Update Signal with new LabelType value defined above.
                            Update-Signal -Label $overrideLabel -AnchorEvent $overrideEventObj -EventIndex $i -AllEvents $eventObjArr -PreviousSignals $prevEventWithSignalObjArr
                        }

                        # Append current event object to array tracking all previous event
                        # objects that triggered a Signal.
                        # Ignore adding if current event object contains suppression Signal.
                        if ($eventObj.Enrichment.Signal.Label -ne [LabelType]::SuppressAutomatedBackgroundEvent)
                        {
                            $prevEventWithSignalObjArr += $eventObj
                        }

                        # Define lookback scenarios where current Signal should be merged
                        # with previous Signal when AWS discretely performs an additional
                        # defined mapping before the actual action performed by the user.
                        if (
                            $prevEventWithSignalObjArr[-2].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details -and `
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring -and `
                            ($prevEventWithSignalObjArr[-1].Event.eventTime - $prevEventWithSignalObjArr[-2].Event.eventTime).TotalSeconds -le 5
                        )
                        {
                            # Merge next-to-last [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                            # Signal into last [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring
                            # Signal if it occurred within five (5) seconds.

                            # Extract Signal object to merge into current anchor Signal object.
                            $anchorEvent = $prevEventWithSignalObjArr[-1]
                            $mergeEvent = $prevEventWithSignalObjArr[-2]

                            # Remove to-be-merged Signal object from array of event objects
                            # that triggered a Signal.
                            $prevEventWithSignalObjArr = $prevEventWithSignalObjArr.Where( { $_.Enrichment.CorrelationId -cne $mergeEvent.Enrichment.CorrelationId } )

                            # Merge both Signal objects into a single Signal object.
                            Merge-Signal -AnchorEvent $anchorEvent -MergeEvent $mergeEvent -AllEvents $eventObjArr
                        }
                        elseif (
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances -and `
                            (
                                $prevEventWithSignalObjArr[-1].Enrichment.EventCount -in @(1,2) -and `
                                $prevEventWithSignalObjArr[-1].Enrichment.EventNameFull -ceq 'ec2:DescribeInstances' -and `
                                (($prevEventWithSignalObjArr[-1].Event.requestParameters.get_Keys() | Sort-Object -Unique) -join ',') -ceq 'filterSet,instancesSet' -and `
                                $prevEventWithSignalObjArr[-1].Event.requestParameters.instancesSet.items.Where( { $_.instanceId.StartsWith('i-') } ).Count -gt 0
                            ) -and `
                            (
                                (
                                    $prevEventWithSignalObjArr[-2].Enrichment.Signal.Label -in @(
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2
                                    ) -and `
                                    ($prevEventWithSignalObjArr[-1].Enrichment.FirstEventTime - $prevEventWithSignalObjArr[-2].Enrichment.LastEventTime).TotalSeconds -le 15
                                ) -or `
                                (
                                    $prevEventWithSignalObjArr[-2].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances -and `
                                    $prevEventWithSignalObjArr[-3].Enrichment.Signal.Label -in @(
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2
                                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2
                                    ) -and `
                                    ($prevEventWithSignalObjArr[-1].Enrichment.FirstEventTime - $prevEventWithSignalObjArr[-3].Enrichment.LastEventTime).TotalSeconds -le 30
                                )
                            )
                        )
                        {
                            # Merge last [LabelType]::EC2_Instances_Instances Signal (if
                            # it is only composed of 1-2 ec2:DescribeInstances events)
                            # into previous [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_*
                            # Signal if it occurred within fifteen (15) seconds of the
                            # previous Signal.
                            # This occurs when an Instance State change is made and AWS
                            # polls the state in the background.

                            # Extract previous Signal object into which to merge current
                            # anchor Signal object.
                            $anchorEvent = $prevEventWithSignalObjArr[-2].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances ? $prevEventWithSignalObjArr[-3] : $prevEventWithSignalObjArr[-2]
                            $mergeEvent = $prevEventWithSignalObjArr[-1]

                            # Remove to-be-merged Signal object from array of event objects
                            # that triggered a Signal.
                            $prevEventWithSignalObjArr = $prevEventWithSignalObjArr.Where( { $_.Enrichment.CorrelationId -cne $mergeEvent.Enrichment.CorrelationId } )

                            # Merge both Signal objects into a single Signal object.
                            Merge-Signal -AnchorEvent $anchorEvent -MergeEvent $mergeEvent -AllEvents $eventObjArr
                        }
                        elseif (
                            ([System.String] $prevEventWithSignalObjArr[-2].Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_LaunchInstance_') -and `
                            $prevEventWithSignalObjArr[-1].Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances -and `
                            ($prevEventWithSignalObjArr[-1].Enrichment.FirstEventTime - $prevEventWithSignalObjArr[-2].Enrichment.LastEventTime).TotalSeconds -le 15 -and `
                            (
                                $prevEventWithSignalObjArr[-1].Enrichment.EventCount -in @(1,2) -and `
                                $prevEventWithSignalObjArr[-1].Enrichment.EventNameFull -ceq 'ec2:DescribeInstances' -and `
                                (($prevEventWithSignalObjArr[-1].Event.requestParameters.get_Keys() | Sort-Object -Unique) -join ',') -ceq 'filterSet,instancesSet' -and `
                                $prevEventWithSignalObjArr[-1].Event.requestParameters.instancesSet.items.Where( { $_.instanceId.StartsWith('i-') } ).Count -gt 0
                            )
                        )
                        {
                            # Merge last [LabelType]::EC2_Instances_Instances Signal into
                            # previous [LabelType]::EC2_Instances_Instances_LaunchInstance_*
                            # Signal if it occurred within fifteen (15) seconds of the
                            # previous Signal.
                            # This occurs when a Launch Instance configuration change is
                            # made and AWS polls the state in the background.

                            # Extract previous Signal object into which to merge current
                            # anchor Signal object.
                            $anchorEvent = $prevEventWithSignalObjArr[-2]
                            $mergeEvent = $prevEventWithSignalObjArr[-1]

                            # Remove to-be-merged Signal object from array of event objects
                            # that triggered a Signal.
                            $prevEventWithSignalObjArr = $prevEventWithSignalObjArr.Where( { $_.Enrichment.CorrelationId -cne $mergeEvent.Enrichment.CorrelationId } )

                            # Merge both Signal objects into a single Signal object.
                            Merge-Signal -AnchorEvent $anchorEvent -MergeEvent $mergeEvent -AllEvents $eventObjArr
                        }
                    }

                    # Break out of current foreach loop since no additional Labels need to be evaluated for current anchor event object due to current Signal generation.
                    break
                }
            }
        }

        # Output Signal statistics from above logic if user input -Verbose switch parameter is defined.
        if ($PSBoundParameters['Verbose'].IsPresent)
        {
            # Stop stopwatch and capture elapsed time of Signal evaluation logic above.
            $stopwatch.stop()
            $elapsedTime = $stopwatch.Elapsed

            $signalCount = ($eventObjArr.Enrichment.ForEach( { $null -ne $_.Signal } ) | Measure-Object -Sum).Sum
            $eventWithSignalCount = $eventObjArr.Enrichment.Where( { $_.IsSignalContributor } ).Count
            Write-Host '[*] ['               -NoNewline -ForegroundColor Cyan
            Write-Host $elapsedTime          -NoNewline -ForegroundColor Yellow
            Write-Host '] Added '            -NoNewline -ForegroundColor Cyan
            Write-Host $signalCount          -NoNewline -ForegroundColor Yellow
            Write-Host ' Signal(s) to '      -NoNewline -ForegroundColor Cyan
            Write-Host $eventWithSignalCount -NoNewline -ForegroundColor Yellow
            Write-Host ' of '                -NoNewline -ForegroundColor Cyan
            Write-Host $eventObjArr.Count    -NoNewline -ForegroundColor Yellow
            Write-Host ' Events'                        -ForegroundColor Cyan
        }

        # Return all input event objects.
        $eventObjArr
    }
}