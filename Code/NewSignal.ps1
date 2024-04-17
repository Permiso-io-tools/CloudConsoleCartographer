function New-Signal
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: New-Signal
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-MinimalUrlEncoded
Optional Dependencies: None

.DESCRIPTION

New-Signal creates new instance of Signal object based on corresponding input Label and extracts relevant properties from input related events to potentially update Signal's properties (e.g. Summary, Url, etc.) for increased readability.

.PARAMETER Label

Specifies specific type of Signal to create.

.PARAMETER AnchorEvent

Specifies anchor event onto which new Signal will be added.

.PARAMETER RelatedEvents

Specifies related events to set as contributing events for Signal creation.

.PARAMETER PreviousSignals

Specifies previous Signals for specific look-back scenarios where information from a previous Signal needs to be extracted and added to current Signal.

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [LabelType]
        $Label,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $AnchorEvent,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject[]]
        $RelatedEvents,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]
        $PreviousSignals
    )

    # Store last Signal in separate variable for more efficient referencing in function.
    $lastEventWithSignalObj = $PreviousSignals | Select-Object -Last 1

    # Create new instance of Signal object corresponding with current Label and store in
    # current event object's Enrichment property.
    $AnchorEvent.Enrichment.Signal = [Signal]::new($Label)

    # Define correlation ID as earliest RelatedEvent's eventID property value.
    # This avoids unit tests breaking if a Signal definition changes its AnchorEvent property.
    $correlationId = $RelatedEvents[0].Event.eventID

    # Update Enrichment object for all events contributing to current Signal with above
    # correlation ID and set IsSignalContributor Boolean to $true so these events will not be
    # evaluated as contributing to more than one Signal.
    $RelatedEvents.ForEach(
    {
        $_.Enrichment.CorrelationId = $correlationId
        $_.Enrichment.IsSignalContributor = $true
    } )

    # Add additional Signal metadata to current anchor event's Enrichment property.
    $AnchorEvent.Enrichment.EventCount        = $RelatedEvents.Count
    $AnchorEvent.Enrichment.FirstEventTime    = $RelatedEvents[0].Event.eventTime
    $AnchorEvent.Enrichment.LastEventTime     = $RelatedEvents[-1].Event.eventTime
    $AnchorEvent.Enrichment.DurationInSeconds = ($AnchorEvent.Enrichment.LastEventTime - $AnchorEvent.Enrichment.FirstEventTime).TotalSeconds

    # Perform cosmetic substitutions and potential modifications to current Signal's
    # Url and Summary properties while also storing any raw AdditionalData values
    # potentially extracted from aggregate events.

    # Substitute awsRegion value placeholder (with minimal Url encoding) in current Signal's
    # Url property.
    $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{awsRegion}}',(ConvertTo-MinimalUrlEncoded -InputObject $AnchorEvent.Event.awsRegion))

    # Perform additional Summary and/or Url property substitutions for subset of Signals
    # based on current Label.
    switch ($Label)
    {
        ([LabelType]::CloudShell_Actions_DownloadFile) {
            $fileDownloadPath = $AnchorEvent.Event.requestParameters.FileDownloadPath
            $environmentId = $AnchorEvent.Event.requestParameters.EnvironmentId

            # Substitute fileDownloadPath and environmentId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{fileDownloadPath}}',$fileDownloadPath).Replace('{{environmentId}}',$environmentId)

            # Substitute environmentId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{environmentId}}',(ConvertTo-MinimalUrlEncoded -InputObject $environmentId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                fileDownloadPath = $fileDownloadPath
                environmentId = $environmentId
            }
        }
        ([LabelType]::CloudShell_Actions_UploadFile) {
            $fileUploadPath = $AnchorEvent.Event.requestParameters.FileUploadPath
            $environmentId = $AnchorEvent.Event.requestParameters.EnvironmentId

            # Substitute fileUploadPath and environmentId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{fileUploadPath}}',$fileUploadPath).Replace('{{environmentId}}',$environmentId)

            # Substitute environmentId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{environmentId}}',(ConvertTo-MinimalUrlEncoded -InputObject $environmentId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                fileUploadPath = $fileUploadPath
                environmentId = $environmentId
            }
        }
        ([LabelType]::CloudShell_ExitSession) {
            $environmentId = $AnchorEvent.Event.requestParameters.EnvironmentId
            $sessionId = $AnchorEvent.Event.requestParameters.SessionId

            # Substitute environmentId and sessionId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{environmentId}}',$environmentId).Replace('{{sessionId}}',$sessionId)

            # Substitute environmentId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{environmentId}}',(ConvertTo-MinimalUrlEncoded -InputObject $environmentId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                environmentId = $environmentId
                sessionId = $sessionId
            }
        }
        ([LabelType]::CloudShell_InteractiveCommand_AWSCLI) {
            $eventNameFull = $AnchorEvent.Enrichment.EventNameFull

            # Substitute eventNameFull value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{EventNameFull}}',$eventNameFull)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $requestParameters = $AnchorEvent.Event.requestParameters
            if ($null -ne $requestParameters)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with request parameters: '$($requestParameters | ConvertTo-Json -Depth 25 -Compress)'."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                eventNameFull = $eventNameFull
                requestParameters = $requestParameters
            }
        }
        ([LabelType]::CloudShell_InteractiveCommand_AWSPowerShell) {
            $eventNameFull = $AnchorEvent.Enrichment.EventNameFull

            # Substitute eventNameFull value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{EventNameFull}}',$eventNameFull)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $requestParameters = $AnchorEvent.Event.requestParameters
            if ($null -ne $requestParameters)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with request parameters: '$($requestParameters | ConvertTo-Json -Depth 25 -Compress)'."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                eventNameFull = $eventNameFull
                requestParameters = $requestParameters
            }
        }
        ([LabelType]::CloudShell_InteractiveCommand_Boto) {
            $eventNameFull = $AnchorEvent.Enrichment.EventNameFull

            # Substitute eventNameFull value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{EventNameFull}}',$eventNameFull)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $requestParameters = $AnchorEvent.Event.requestParameters
            if ($null -ne $requestParameters)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with request parameters: '$($requestParameters | ConvertTo-Json -Depth 25 -Compress)'."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                eventNameFull = $eventNameFull
                requestParameters = $requestParameters
            }
        }
        ([LabelType]::CloudShell_InteractiveCommand_Generic) {
            $eventNameFull = $AnchorEvent.Enrichment.EventNameFull

            # Substitute eventNameFull value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{EventNameFull}}',$eventNameFull)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $requestParameters = $AnchorEvent.Event.requestParameters
            if ($null -ne $requestParameters)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with request parameters: '$($requestParameters | ConvertTo-Json -Depth 25 -Compress)'."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                eventNameFull = $eventNameFull
                requestParameters = $requestParameters
            }
        }
        ([LabelType]::CloudShell_NewSession) {
            $environmentId = $AnchorEvent.Event.responseElements.EnvironmentId
            $sessionId = $AnchorEvent.Event.responseElements.SessionId

            # Substitute environmentId and sessionId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{environmentId}}',$environmentId).Replace('{{sessionId}}',$sessionId)

            # Substitute environmentId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{environmentId}}',(ConvertTo-MinimalUrlEncoded -InputObject $environmentId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                environmentId = $environmentId
                sessionId = $sessionId
            }
        }
        ([LabelType]::CloudShell_RenewSession) {
            $environmentId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudshell:CreateSession' } )[0].Event.responseElements.EnvironmentId
            $sessionId     = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudshell:CreateSession' } )[0].Event.responseElements.SessionId

            # Substitute environmentId and sessionId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{environmentId}}',$environmentId).Replace('{{sessionId}}',$sessionId)

            # Substitute environmentId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{environmentId}}',(ConvertTo-MinimalUrlEncoded -InputObject $environmentId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                environmentId = $environmentId
                sessionId = $sessionId
            }
        }
        ([LabelType]::CloudTrail_Dashboard_CreateTrail_Step2) {
            $trailName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:CreateTrail' } )[0].Event.requestParameters.name
            $trailArn  = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:StartLogging' } )[0].Event.requestParameters.name

            # Substitute trailName and trailArn value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{trailName}}',$trailName).Replace('{{trailArn}}',$trailArn)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                trailName = $trailName
                trailArn = $trailArn
            }
        }
        ([LabelType]::CloudTrail_EventHistory) {
            # This is a special case where event(s) in current mapping scenario can contain duplicate values overlapping with previous mapping,
            # so previous mapping scenario's context (if expected mapping scenario) will be queried and supplied below to apply as filter
            # for current values to remove any duplicate overlapping values.
            # For this case look beyond only the last signal since a CloudTrail Event History
            # mapping can carry over its value even after a long time.
            $lastEventWithSignalObj = $PreviousSignals.Where(
            {
                $_.Enrichment.Signal.Label -eq [LabelType]::CloudTrail_EventHistory -and `
                $null -ne $_.Enrichment.Signal.AdditionalData.attributeKey -and `
                $null -ne $_.Enrichment.Signal.AdditionalData.attributeValue
            } )[-1]

            # Extract all key-value filter values from current mapping.
            $attributeKeyValueObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } ).Event.requestParameters.lookupAttributes.ForEach( {
                [PSCustomObject] @{
                    attributeKey = $_.attributeKey
                    attributeValue = $_.attributeValue
                }
            } ) | Select-Object attributeKey,attributeValue -Unique

            # Filter out any potential key-value filter value from previous mapping (if it exists) from current mapping.
            $attributeKeyValueObjArrFiltered = $attributeKeyValueObjArr.Where(
            {
                -not (
                    $_.attributeKey -ceq $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.attributeKey -and `
                    $_.attributeValue -ceq $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.attributeValue
                )
            } )

            # Keep filtered list of key-value filter values unless it is empty and extract
            # final key-value filter values for current mapping.
            $attributeKeyValueObjArr = $attributeKeyValueObjArrFiltered.Count -gt 0 ? $attributeKeyValueObjArrFiltered : $attributeKeyValueObjArr
            $attributeKey   = $attributeKeyValueObjArr.Count -gt 0 ? $attributeKeyValueObjArr[0].attributeKey   : $null
            $attributeValue = $attributeKeyValueObjArr.Count -gt 0 ? $attributeKeyValueObjArr[0].attributeValue : $null
            if ($attributeKey -ceq 'ReadOnly' -and $attributeValue -ceq 'false')
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by default attribute $attributeKey='$attributeValue'."
            }
            elseif ($null -ne $attributeKey -and $null -ne $attributeValue)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by custom attribute $attributeKey='$attributeValue'."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently with no filter defined."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $startTime = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } )[0].Event.requestParameters.startTime
            $endTime   = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } )[0].Event.requestParameters.endTime
            $timespanStr = $null
            if ($null -ne $startTime -and $null -ne $endTime)
            {
                # Convert raw date string values to DateTime objects.
                $startTime = [System.DateTime] $startTime
                $endTime   = [System.DateTime] $endTime

                # Calculate string format of timespan by the highest even denomination.
                $timespanStr = Out-TimeSpanStr -StartTime $startTime -EndTime $endTime

                # Potentially append additional optional value(s) to current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " and custom date range of '$timespanStr' ('$($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))' to '$($endTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))')."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $resourceTypeArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'config:ListDiscoveredResources' } ).ForEach( { $_.Event.requestParameters.resourceType } ) | Sort-Object -Unique
            if ($resourceTypeArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " and containing event(s) referencing $($resourceTypeArr.Count) Resource Type$($resourceTypeArr.Count -eq 1 ? '' : 's') ($($resourceTypeArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($null -ne $attributeKey -and $null -ne $attributeValue)
            {
                # Add lookup attribute value to Uri array (with minimal Url encoding).
                $uriArr += ((ConvertTo-MinimalUrlEncoded -InputObject $attributeKey) + '=' + (ConvertTo-MinimalUrlEncoded -InputObject $attributeValue))
            }
            if ($null -ne $startTime -and $null -ne $endTime)
            {
                # Calculate total number of milliseconds in defined time range filter.
                $timeRangeInMilliseconds = ($endTime - $startTime).TotalMilliseconds

                # Add time range filter to Uri array.
                $uriArr += ('CustomTime=' + $timeRangeInMilliseconds)
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Url += ('?' + ($uriArr -join '&'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                attributeKey = $attributeKey
                attributeValue = $attributeValue
                startTime = $startTime
                endTime = $endTime
                timespanStr = $timespanStr
            }
        }
        ([LabelType]::CloudTrail_EventHistory_SPECIFICEVENT) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $resourceTypeArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'config:ListDiscoveredResources' } ).ForEach( { $_.Event.requestParameters.resourceType } ) | Sort-Object -Unique
            if ($resourceTypeArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", which currently references $($resourceTypeArr.Count) Resource Type$($resourceTypeArr.Count -eq 1 ? '' : 's') ($($resourceTypeArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                resourceTypeArr = $resourceTypeArr
            }
        }
        ([LabelType]::CloudTrail_Insights) {
            # This is a special case where event(s) in current mapping scenario can contain
            # duplicate values overlapping with previous mapping, so previous mapping scenario's
            # context (if expected mapping scenario) will be queried and supplied below to apply
            # as filter for current values to remove any duplicate overlapping values.
            # For this case look beyond only the last signal since a CloudTrail Insights
            # mapping can carry over its value even after a long time.
            $lastEventWithSignalObj = $PreviousSignals.Where(
            {
                $_.Enrichment.Signal.Label -eq [LabelType]::CloudTrail_Insights -and `
                $null -ne $_.Enrichment.Signal.AdditionalData.attributeKey -and `
                $null -ne $_.Enrichment.Signal.AdditionalData.attributeValue
            } )[-1]

            # Extract all key-value filter values from current mapping.
            $attributeKeyValueObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } ).Event.requestParameters.lookupAttributes.ForEach( {
                [PSCustomObject] @{
                    attributeKey = $_.attributeKey
                    attributeValue = $_.attributeValue
                }
            } ) | Select-Object attributeKey,attributeValue -Unique

            # Filter out any potential key-value filter value from previous mapping (if it exists) from current mapping.
            $attributeKeyValueObjArrFiltered = $attributeKeyValueObjArr.Where(
            {
                -not (
                    $_.attributeKey -ceq $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.attributeKey -and `
                    $_.attributeValue -ceq $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.attributeValue
                )
            } )

            # Keep filtered list of key-value filter values unless it is empty and extract
            # final key-value filter values for current mapping.
            $attributeKeyValueObjArr = $attributeKeyValueObjArrFiltered.Count -gt 0 ? $attributeKeyValueObjArrFiltered : $attributeKeyValueObjArr
            $attributeKey   = $attributeKeyValueObjArr.Count -gt 0 ? $attributeKeyValueObjArr[0].attributeKey   : $null
            $attributeValue = $attributeKeyValueObjArr.Count -gt 0 ? $attributeKeyValueObjArr[0].attributeValue : $null
            if ($attributeKey -ceq 'ReadOnly' -and $attributeValue -ceq 'false')
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by default attribute $attributeKey='$attributeValue'."
            }
            elseif ($null -ne $attributeKey -and $null -ne $attributeValue)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by custom attribute $attributeKey='$attributeValue'."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently with no filter defined."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $startTime = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } ).Where( { $null -ne $_.Event.requestParameters.startTime } )[0].Event.requestParameters.startTime
            $endTime   = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } ).Where( { $null -ne $_.Event.requestParameters.endTime   } )[0].Event.requestParameters.endTime
            $timespanStr = $null
            if ($null -ne $startTime -and $null -ne $endTime)
            {
                # Convert raw date values to UTC DateTime objects.
                $startTime = ([System.DateTime] $startTime).ToUniversalTime()
                $endTime   = ([System.DateTime]   $endTime).ToUniversalTime()

                # Calculate string format of timespan by the highest even denomination.
                $timespanStr = Out-TimeSpanStr -StartTime $startTime -EndTime $endTime

                # Potentially append additional optional value(s) to current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " and custom date range of '$timespanStr' ('$($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))' to '$($endTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))')."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $resourceTypeArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'config:ListDiscoveredResources' } ).ForEach( { $_.Event.requestParameters.resourceType } ) | Sort-Object -Unique
            if ($resourceTypeArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " and containing event(s) referencing $($resourceTypeArr.Count) Resource Type$($resourceTypeArr.Count -eq 1 ? '' : 's') ($($resourceTypeArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($null -ne $attributeKey -and $null -ne $attributeValue)
            {
                # Add lookup attribute value to Uri array (with minimal Url encoding).
                $uriArr += ((ConvertTo-MinimalUrlEncoded -InputObject $attributeKey) + '=' + (ConvertTo-MinimalUrlEncoded -InputObject $attributeValue))
            }
            if ($null -ne $startTime -and $null -ne $endTime)
            {
                # Calculate total number of milliseconds in defined time range filter.
                $timeRangeInMilliseconds = ($endTime - $startTime).TotalMilliseconds

                # Add time range filter to Uri array.
                $uriArr += ('CustomTime=' + $timeRangeInMilliseconds)
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Url += ('?' + ($uriArr -join '&'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                attributeKey = $attributeKey
                attributeValue = $attributeValue
                startTime = $startTime
                endTime = $endTime
                timespanStr = $timespanStr
            }
        }
        ([LabelType]::CloudTrail_Insights_SPECIFICINSIGHT) {
            $eventId   = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } ).Event.requestParameters.lookupAttributes.Where( { $_.attributeKey -ceq 'EventId'   } ).attributeValue | Sort-Object | Select-Object -First 1
            $eventName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:LookupEvents' } ).Event.requestParameters.lookupAttributes.Where( { $_.attributeKey -ceq 'EventName' } ).attributeValue | Sort-Object | Select-Object -First 1

            # Substitute eventId and eventName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{eventId}}',$eventId).Replace('{{eventName}}',$eventName)

            # Substitute eventId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{eventId}}',(ConvertTo-MinimalUrlEncoded -InputObject $eventId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                eventId = $eventId
                eventName = $eventName
            }
        }
        ([LabelType]::CloudTrail_Trails) {
            $trailArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:GetTrailStatus' } ).ForEach( { $_.Event.requestParameters.name } ).Where( { $_ } ) | Sort-Object -Unique
            $trailNameArr = $trailArnArr.ForEach( { $_.Split(':trail/')[-1] } ).Where( { $_ } ) | Sort-Object -Unique

            # Append additional values to current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently displaying $($trailNameArr.Count) CloudTrail Trail$($trailNameArr.Count -eq 1 ? '' : 's') ($($trailNameArr.ForEach( { "'$_'" } ) -join ','))."

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                trailArnArr = $trailArnArr
                trailNameArr = $trailNameArr
            }
        }
        ([LabelType]::CloudTrail_Trails_SPECIFICTRAIL) {
            $trailArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:GetInsightSelectors' } )[0].Event.requestParameters.trailName
            $trailName = $trailArn.Split(':trail/')[-1]

            # Substitute trailArn and trailName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{trailArn}}',$trailArn).Replace('{{trailName}}',$trailName)

            # Substitute trailArn value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{trailArn}}',(ConvertTo-MinimalUrlEncoded -InputObject $trailArn -Exclude @('/',':')))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                trailArn = $trailArn
                trailName = $trailName
            }
        }
        ([LabelType]::CloudTrail_Trails_SPECIFICTRAIL_Delete) {
            $trailArn = $AnchorEvent.Event.requestParameters.name
            $trailName = $trailArn.Split(':trail/')[-1]

            # Substitute trailArn and trailName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{trailArn}}',$trailArn).Replace('{{trailName}}',$trailName)

            # Substitute trailArn value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{trailArn}}',(ConvertTo-MinimalUrlEncoded -InputObject $trailArn -Exclude @('/',':')))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                trailArn = $trailArn
                trailName = $trailName
            }
        }
        ([LabelType]::CloudTrail_Trails_SPECIFICTRAIL_StopLogging) {
            $trailArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'cloudtrail:StopLogging' } )[0].Event.requestParameters.name
            $trailName = $trailArn.Split(':trail/')[-1]

            # Substitute trailArn and trailName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{trailArn}}',$trailArn).Replace('{{trailName}}',$trailName)

            # Substitute trailArn value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{trailArn}}',(ConvertTo-MinimalUrlEncoded -InputObject $trailArn -Exclude @('/',':')))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                trailArn = $trailArn
                trailName = $trailName
            }
        }
        ([LabelType]::EC2_ElasticBlockStore_Snapshots) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $requestParametersJsonArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSnapshots' } ).ForEach( { ConvertTo-Json -Depth 25 -Compress -InputObject $_.Event.requestParameters } )

            # Define single object to store visibility UI dropdown value and Uri value in below switch block.
            $visibilityObj = [PSCustomObject] @{
                Dropdown = $null
                Uri = $null
            }

            # Set visibilityObj values above based on any single ec2:DescribeSnapshots event extracted above matching specified criteria below.
            # E.g. {"filterSet":{},"maxResults":1000,"ownersSet":{"items":[{"owner":"self"}]},"snapshotSet":{},"sharedUsersSet":{}}
            if ($requestParametersJsonArr.Where( { $_.Contains('"sharedUsersSet":{}') -and -not $_.Contains('"ownersSet":{}') -and $_.Contains('"owner":"self"') } ))
            {
                $visibilityObj.Dropdown = 'Owned by me'
                $visibilityObj.Uri = 'owned-by-me'
            }
            # E.g. {"filterSet":{},"maxResults":1000,"ownersSet":{},"snapshotSet":{},"sharedUsersSet":{"items":[{"user":"self"}]}}
            elseif ($requestParametersJsonArr.Where( { $_.Contains('"ownersSet":{}') -and -not $_.Contains('"sharedUsersSet":{}') -and $_.Contains('"user":"self"') } ))
            {
                $visibilityObj.Dropdown = 'Private snapshots'
                $visibilityObj.Uri = 'private'
            }
            # E.g. {"filterSet":{},"maxResults":1000,"ownersSet":{},"snapshotSet":{},"sharedUsersSet":{"items":[{"user":"all"}]}}
            # E.g. {"filterSet":{},"maxResults":1000,"nextToken":"HyQs<REDACTED>W6td","ownersSet":{},"snapshotSet":{},"sharedUsersSet":{"items":[{"user":"all"}]}}
            elseif ($requestParametersJsonArr.Where( { $_.Contains('"ownersSet":{}') -and -not $_.Contains('"sharedUsersSet":{}') -and $_.Contains('"user":"all"') } ))
            {
                $visibilityObj.Dropdown = 'Public snapshots'
                $visibilityObj.Uri = 'public'
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            if ($null -ne $visibilityObj.Dropdown)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($visibilityObj.Dropdown -ceq 'Owned by me' ? 'default ' : '')'$($visibilityObj.Dropdown)' dropdown selected."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # Since only a subset of search filter terms populate in CloudTrail logs there is no else block to modify
            # the Summary property with a 'no filter applied' message since it cannot accurately be determined.
            $attributeKeyAndValueObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSnapshots' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).ForEach(
            {
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $key = $_.name
                $valueArr = $_.valueSet.items.value.Count -eq 0 ? @($null) : $_.valueSet.items.value

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Different operators in AWS Console are not specifically populated in CloudTrail logs, so defaulting
                # to '=' operator in Summary property below.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($null -ne $visibilityObj.Uri)
            {
                $uriArr += ('visibility=' + $visibilityObj.Uri)
            }
            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Add lookup attribute value(s) to Uri array (with minimal Url encoding).
                $uriArr += $attributeKeyAndValueObjArr.ForEach(
                {
                    # Convert key from kebab-case to camelCase.
                    $_.Key = $_.Key.Substring(0,1) + (-join$_.Key.Split('-').ForEach( { $_.Substring(0,1).ToUpper() + $_.Substring(1) } )).Substring(1)

                    $key = ConvertTo-MinimalUrlEncoded -InputObject $_.Key
                    $operator = '='
                    $value = ConvertTo-MinimalUrlEncoded -InputObject $_.Value

                    # Update operator and value if Contains filter syntax is used.
                    if ($null -ne $value -and $value.StartsWith('*') -and $value.EndsWith('*'))
                    {
                        $operator += ':'
                        $value = -join([System.Char[]] $value | Select-Object -Skip 1 | Select-Object -SkipLast 1)
                    }

                    # Return current concatenated Uri result.
                    $key + $operator + $value
                } )

                # Add Uri parameter for version number (only required if additional lookup attribute value(s) are defined).
                $uriArr += 'v=3'
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Url += ($uriArr -join ';')
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                visibilityObj = $visibilityObj
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::EC2_ElasticBlockStore_Snapshots_SPECIFICSNAPSHOT_Details) {
            $snapshotId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSnapshotAttribute' } )[0].Event.requestParameters.snapshotId

            # Substitute snapshotId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{snapshotId}}',$snapshotId)

            # Substitute snapshotId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{snapshotId}}',(ConvertTo-MinimalUrlEncoded -InputObject $snapshotId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                snapshotId = $snapshotId
            }
        }
        ([LabelType]::EC2_ElasticBlockStore_Volumes) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # Since only a subset of search filter terms populate in CloudTrail logs there is no else block to modify
            # the Summary property with a 'no filter applied' message since it cannot accurately be determined.
            $attributeKeyAndValueObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeVolumes' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).ForEach(
            {
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $key = $_.name
                $valueArr = $_.valueSet.items.value.Count -eq 0 ? @($null) : $_.valueSet.items.value

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Different operators in AWS Console are not specifically populated in CloudTrail logs, so defaulting
                # to '=' operator in Summary property below.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # ec2:DescribeVolumeStatus event is only executed if current AWS Account has 1+ EC2 Volumes defined.
            $volumeIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeVolumeStatus' } ).ForEach( { $_.Event.requestParameters.volumeSet.items.volumeId } ).Where( { $_.StartsWith('vol-') } ) | Sort-Object -Unique
            if ($volumeIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", with current page displaying the current AWS Account's first $($volumeIdArr.Count) EC2 Volume$($volumeIdArr.Count -eq 1 ? '' : 's') ($($volumeIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although the current AWS Account has 0 EC2 Volumes defined."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # ec2:DescribeTags event is only executed if current AWS Account has 1+ EC2 Instances defined.
            $instanceIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeTags' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).Where( { $_.name -ceq 'resource-id' } ).ForEach( { $_.valueSet.items.value } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " for $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " since 0 EC2 Instances are defined."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Add lookup attribute value(s) to Uri array (with minimal Url encoding).
                $uriArr += $attributeKeyAndValueObjArr.ForEach(
                {
                    # Convert key from kebab-case to camelCase.
                    $_.Key = $_.Key.Substring(0,1) + (-join$_.Key.Split('-').ForEach( { $_.Substring(0,1).ToUpper() + $_.Substring(1) } )).Substring(1)

                    $key = ConvertTo-MinimalUrlEncoded -InputObject $_.Key
                    $operator = '='
                    $value = ConvertTo-MinimalUrlEncoded -InputObject $_.Value

                    # Update operator and value if Contains filter syntax is used.
                    if ($null -ne $value -and $value.StartsWith('*') -and $value.EndsWith('*'))
                    {
                        $operator += ':'
                        $value = -join([System.Char[]] $value | Select-Object -Skip 1 | Select-Object -SkipLast 1)
                    }

                    # Return current concatenated Uri result.
                    $key + $operator + $value
                } )
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                # Add Uri parameter for version number (only required if additional Uri parameters are defined).
                $uriArr += 'v=3'

                $AnchorEvent.Enrichment.Signal.Url += ($uriArr -join ';')
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
                volumeIdArr = $volumeIdArr
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_Details) {
            $volumeArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'compute-optimizer:GetEBSVolumeRecommendations' } ).ForEach( { $_.Event.requestParameters.volumeArns } ) | Select-Object -First 1
            $volumeId = $volumeArn.Split('/')[-1]

            # Substitute volumeId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{volumeId}}',$volumeId)

            # Substitute volumeId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{volumeId}}',(ConvertTo-MinimalUrlEncoded -InputObject $volumeId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                volumeArn = $volumeArn
                volumeId = $volumeId
            }
        }
        ([LabelType]::EC2_ElasticBlockStore_Volumes_SPECIFICVOLUME_StatusChecks) {
            $volumeId = $AnchorEvent.Event.requestParameters.volumeId

            # Substitute volumeId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{volumeId}}',$volumeId)

            # Substitute volumeId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{volumeId}}',(ConvertTo-MinimalUrlEncoded -InputObject $volumeId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                volumeId = $volumeId
            }
        }
        ([LabelType]::EC2_Images_AMICatalog) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $checkboxFilterArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'discovery-marketplace:SearchListings' } ).Event.requestParameters.filters.Where( { $_.type -cne 'REGION' } ).values | Sort-Object -Unique
            if ($checkboxFilterArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($checkboxFilterArr.Count) checkbox filter$($checkboxFilterArr.Count -eq 1 ? '' : 's') applied ($($checkboxFilterArr.ForEach( { "'$_'" } ) -join ','))"
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with no checkbox filters applied"
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $searchText = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'discovery-marketplace:SearchListings' } ).Event.requestParameters.searchText
            if ($null -ne $searchText)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary + " and filtered by search text '$searchText'."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary + " and with no search text applied."
            }

            # Search text filtering does not propagate into AWS Console Url, so no need to modify default Url property.

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                checkboxFilterArr = $checkboxFilterArr
                searchText = $searchText
            }
        }
        ([LabelType]::EC2_Images_AMIs) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $requestParametersJsonArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeImages' } ).ForEach( { ConvertTo-Json -Depth 25 -Compress -InputObject $_.Event.requestParameters } )

            # Define single object to store visibility UI dropdown value and Uri value in below switch block.
            $visibilityObj = [PSCustomObject] @{
                Dropdown = $null
                Uri = $null
            }

            # Set visibilityObj values above based on any single ec2:DescribeImages event extracted above matching specified criteria below.
            # E.g. {"maxResults":1000,"executableBySet":{},"imagesSet":{},"ownersSet":{"items":[{"owner":"self"}]},"filterSet":{}}
            if ($requestParametersJsonArr.Where( { -not $_.Contains('"ownersSet":{}') -and $_.Contains('"owner":"self"') } ))
            {
                $visibilityObj.Dropdown = 'Owned by me'
                $visibilityObj.Uri = 'owned-by-me'
            }
            # E.g. {"maxResults":1000,"executableBySet":{},"imagesSet":{},"ownersSet":{},"filterSet":{"items":[{"name":"is-public","valueSet":{"items":[{"value":"false"}]}}]}}
            elseif ($requestParametersJsonArr.Where( { $_.Contains('"ownersSet":{}') -and $_.Contains('"name":"is-public"') -and $_.Contains('"value":"false"') } ))
            {
                $visibilityObj.Dropdown = 'Private images'
                $visibilityObj.Uri = 'private'
            }
            # E.g. {"maxResults":1000,"executableBySet":{},"imagesSet":{},"ownersSet":{},"filterSet":{}}
            elseif ($requestParametersJsonArr.Where( { $_.Contains('"ownersSet":{}') } ))
            {
                $visibilityObj.Dropdown = 'Public images'
                $visibilityObj.Uri = 'public-images'
            }
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            elseif ($lastEventWithSignalObj.Enrichment.Signal.Label -ceq [LabelType]::EC2_Images_AMIs)
            {
                # Extract visibilityObj value from previous Signal's AdditionalData property.
                $visibilityObj = $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.visibilityObj
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            if ($null -ne $visibilityObj.Dropdown)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($visibilityObj.Dropdown -ceq 'Owned by me' ? 'default ' : '')'$($visibilityObj.Dropdown)' dropdown selected."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # Since only a subset of search filter terms populate in CloudTrail logs there is no else block to modify
            # the Summary property with a 'no filter applied' message since it cannot accurately be determined.
            $attributeKeyAndValueObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeImages' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).Where( { $_.name -cnotin @('is-public','image-id') } ).ForEach(
            {
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $key = $_.name
                $valueArr = $_.valueSet.items.value.Count -eq 0 ? @($null) : $_.valueSet.items.value

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Different operators in AWS Console are not specifically populated in
                # CloudTrail logs, so defaulting to '=' operator in Summary property below.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }

            # Potentially append additional optional values to temporary Uri array to add
            # to current Signal's Url property.
            $uriArr = @()
            if ($null -ne $visibilityObj.Uri)
            {
                $uriArr += ('visibility=' + $visibilityObj.Uri)
            }
            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Add lookup attribute value(s) to Uri array (with minimal Url encoding).
                $uriArr += $attributeKeyAndValueObjArr.ForEach(
                {
                    # Convert key from kebab-case to camelCase.
                    $_.Key = $_.Key.Substring(0,1) + (-join$_.Key.Split('-').ForEach( { $_.Substring(0,1).ToUpper() + $_.Substring(1) } )).Substring(1)

                    $key = ConvertTo-MinimalUrlEncoded -InputObject $_.Key
                    $operator = '='
                    $value = ConvertTo-MinimalUrlEncoded -InputObject $_.Value

                    # Update operator and value if Contains filter syntax is used.
                    if ($null -ne $value -and $value.StartsWith('*') -and $value.EndsWith('*'))
                    {
                        $operator += ':'
                        $value = -join([System.Char[]] $value | Select-Object -Skip 1 | Select-Object -SkipLast 1)
                    }

                    # Return current concatenated Uri result.
                    $key + $operator + $value
                } )

                # Add Uri parameter for version number (only required if additional lookup attribute value(s) are defined).
                $uriArr += 'v=3'
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Url += ($uriArr -join ';')
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                visibilityObj = $visibilityObj
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Details) {
            $imageId = $AnchorEvent.Event.requestParameters.imagesSet.items.imageId | Select-Object -First 1

            # Substitute imageId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{imageId}}',$imageId)

            # Substitute imageId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{imageId}}',(ConvertTo-MinimalUrlEncoded -InputObject $imageId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                imageId = $imageId
            }
        }
        ([LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Storage) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Extract imageId value from previous Signal's AdditionalData property.
            $imageId = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Details
                [LabelType]::EC2_Images_AMIs_SPECIFICIMAGE_Storage
            ) ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.imageId : $null
            if ($null -ne $imageId)
            {
                # Substitute imageId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{imageId}}',$imageId)

                # Substitute imageId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{imageId}}',(ConvertTo-MinimalUrlEncoded -InputObject $imageId))
            }
            else
            {
                # Substitute imageId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{imageId}}'",'->SPECIFICIMAGE').Replace(" '{{imageId}}' ",' current ')

                # Override current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('imageId={{imageId}}','')
            }

            # Extract potential snapshotId values to store in AdditionalData below in case useful for later Signals
            # since values are not used in current Signal's Summary or Url properties.
            $snapshotIdArr = $AnchorEvent.Event.requestParameters.snapshotSet.items.snapshotId | Sort-Object -Unique

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                imageId = $imageId
                snapshotIdArr = $snapshotIdArr
            }
        }
        ([LabelType]::EC2_Instances_CapacityReservations) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $attributeKeyAndValueObjArr = $AnchorEvent.Event.requestParameters.DescribeCapacityReservationsRequest.Filter.ForEach(
            {
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $key = $_.Name
                $valueArr = $_.Value.content.Count -eq 0 ? @($null) : $_.Value.content

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with no filter applied."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Add lookup attribute value(s) to Uri array (with minimal Url encoding).
                $uriArr += $attributeKeyAndValueObjArr.ForEach(
                {
                    # Convert key from kebab-case to camelCase.
                    $_.Key = $_.Key.Substring(0,1) + (-join$_.Key.Split('-').ForEach( { $_.Substring(0,1).ToUpper() + $_.Substring(1) } )).Substring(1)

                    $key = ConvertTo-MinimalUrlEncoded -InputObject $_.Key
                    $operator = '='
                    $value = ConvertTo-MinimalUrlEncoded -InputObject $_.Value

                    # Update operator and value if Contains filter syntax is used.
                    if ($null -ne $value -and $value.StartsWith('*') -and $value.EndsWith('*'))
                    {
                        $operator += ':'
                        $value = -join([System.Char[]] $value | Select-Object -Skip 1 | Select-Object -SkipLast 1)
                    }

                    # Return current concatenated Uri result.
                    $key + $operator + $value
                } )
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Url += ($uriArr -join ';')
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION) {
            $capacityReservationId = $AnchorEvent.Event.requestParameters.DescribeCapacityReservationsRequest.CapacityReservationId.content

            # Substitute capacityReservationId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{capacityReservationId}}',$capacityReservationId)

            # Substitute capacityReservationId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{capacityReservationId}}',(ConvertTo-MinimalUrlEncoded -InputObject $capacityReservationId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                capacityReservationId = $capacityReservationId
            }
        }
        ([LabelType]::EC2_Instances_CapacityReservations_SPECIFICCAPACITYRESERVATION_CancelCapacityReservation) {
            $capacityReservationId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:CancelCapacityReservation' } )[0].Event.requestParameters.CancelCapacityReservationRequest.CapacityReservationId

            # Substitute capacityReservationId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{capacityReservationId}}',$capacityReservationId)

            # Substitute capacityReservationId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{capacityReservationId}}',(ConvertTo-MinimalUrlEncoded -InputObject $capacityReservationId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                capacityReservationId = $capacityReservationId
            }
        }
        ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step1_KeyPair_Create) {
            $keyName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:CreateKeyPair' } )[0].Event.requestParameters.keyName

            # Substitute keyName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{keyName}}',$keyName)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyName = $keyName
            }
        }
        ([LabelType]::EC2_Instances_Instances_LaunchInstance_Step2) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instancesSetItemsArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:RunInstances' } ).Event.responseElements.instancesSet.items
            $instanceIdArr = $instancesSetItemsArr.ForEach( { $_.instanceId } ) | Sort-Object -Unique
            $imageIdArr = $instancesSetItemsArr.ForEach( { $_.imageId } ) | Sort-Object -Unique
            $instanceTypeArr = $instancesSetItemsArr.ForEach( { $_.instanceType } ) | Sort-Object -Unique
            $securityGroupIdArr = $instancesSetItemsArr.ForEach( { $_.groupSet.items.groupId.Where( { $_.StartsWith('sg-') } ) } ) | Sort-Object -Unique

            # Create single array to store all potential Summary suffixes to append.
            $appendSummaryArr = @()
            if ($instanceIdArr.Count -gt 0)
            {
                $appendSummaryArr += " $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))"

                if ($imageIdArr.Count -gt 0)
                {
                    $appendSummaryArr += " configured with $($imageIdArr.Count) EC2 AMI$($imageIdArr.Count -eq 1 ? '' : 's') ($($imageIdArr.ForEach( { "'$_'" } ) -join ','))"
                }
                if ($instanceTypeArr.Count -gt 0)
                {
                    $appendSummaryArr += " built on $($instanceTypeArr.Count) EC2 Instance Type$($instanceTypeArr.Count -eq 1 ? '' : 's') ($($instanceTypeArr.ForEach( { "'$_'" } ) -join ','))"
                }
                if ($securityGroupIdArr.Count -gt 0)
                {
                    $appendSummaryArr += " deployed into $($securityGroupIdArr.Count) Security Group$($securityGroupIdArr.Count -eq 1 ? '' : 's') ($($securityGroupIdArr.ForEach( { "'$_'" } ) -join ','))"
                }
            }

            # Append all potential Summary suffixes.
            if ($appendSummaryArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ', specifically' +  $appendSummaryArr[0] + (($appendSummaryArr | Select-Object -Skip 1) -join ' and') + '.'
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
                imageIdArr = $imageIdArr
                instanceTypeArr = $instanceTypeArr
                securityGroupIdArr = $securityGroupIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2InstanceConnect_Connect) {
            $instanceId = (
                [System.Array] `
                $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2-instance-connect:SendSSHPublicKey' } )[0].Event.requestParameters.instanceId + `
                $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeAddresses' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).Where( { $_.name -ceq 'instance-id' } ).ForEach( { $_.valueSet.items.value } ).Where( { $_.StartsWith('i-') } )
            ).Where( { $_ } )[0]
            $instanceOSUser = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2-instance-connect:SendSSHPublicKey' } )[0].Event.requestParameters.instanceOSUser

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceOSUser value placeholder in current Signal's Summary property.
            if ($null -ne $instanceOSUser)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceOSUser}}',$instanceOSUser)
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("with '{{instanceOSUser}}' user ",'')
            }

            # Do not append below instance profile value(s) to current Signal's Summary property for brevity and clarity,
            # but store in AdditionalData for potential later enrichment.
            $sshPublicKey = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2-instance-connect:SendSSHPublicKey' } )[0].Event.requestParameters.sSHPublicKey

            # Substitute instanceId and instanceOSUser value placeholders (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId)).Replace('{{instanceOSUser}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceOSUser))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                instanceOSUser = $instanceOSUser
                sshPublicKey = $sshPublicKey
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_EC2SerialConsole) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:GetConnectionStatus' } )[0].Event.requestParameters.target

            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # For this case look beyond only the last signal since an EC2 remote connection session
            # can last a long time and be filled with other mappings.
            if ($null -eq $instanceId)
            {
                $lastEventWithSignalObj = $PreviousSignals.Where(
                {
                    ([System.String] $_.Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_') -and `
                    $null -ne $_.Enrichment.Signal.AdditionalData.instanceId
                } )[-1]
                if ($lastEventWithSignalObj)
                {
                    # Extract instanceId value from previous Signal's AdditionalData property.
                    $instanceId = $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.instanceId
                }
            }

            if ($null -ne $instanceId)
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))
            }
            else
            {
                # Set default instanceId value to null so not inaccurately represented in current Signal's AdditionalData property.
                $instanceId = $null

                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{instanceId}}'",'->SPECIFICINSTANCE').Replace(" '{{instanceId}}' EC2 Instance",' current EC2 Instance')

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject 'instanceId'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # For this case look beyond only the last signal since an EC2 remote connection session
            # can last a long time and be filled with other mappings.
            $lastEventWithSignalObj = $PreviousSignals.Where(
            {
                ([System.String] $_.Enrichment.Signal.Label).StartsWith('EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_') -and `
                $null -ne $_.Enrichment.Signal.AdditionalData.instanceId
            } )[-1]
            if ($lastEventWithSignalObj)
            {
                # Extract instanceId value from previous Signal's AdditionalData property.
                $instanceId = $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.instanceId

                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))
            }
            else
            {
                # Set default instanceId value to null so not inaccurately represented in current Signal's AdditionalData property.
                $instanceId = $null

                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{instanceId}}'",'->SPECIFICINSTANCE').Replace(" '{{instanceId}}' EC2 Instance",' current EC2 Instance')

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject 'instanceId'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:StartSession' } )[0].Event.requestParameters.target
            $sessionId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:StartSession' } )[0].Event.responseElements.sessionId

            # Substitute instanceId and sessionId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId).Replace('{{sessionId}}',$sessionId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                sessionId = $sessionId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage) {
            $instanceIdArr = @(
                (
                    [System.Array] `
                    $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:GetCommandInvocation' } ).Event.requestParameters.instanceId + `
                    $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:StartSession' } ).Event.requestParameters.target
                ).Where( { $_ } ) | Select-Object -Unique
            )
            $sessionIdArr = @(
                (
                    [System.Array] `
                    $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:TerminateSession' } ).Event.responseElements.sessionId + `
                    $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:StartSession' } ).Event.responseElements.sessionId
                ).Where( { $_ } ) | Select-Object -Unique
            )
            $instanceId = $instanceIdArr[-1]
            $sessionId = $sessionIdArr[-1]

            # This is a special case where event(s) in current mapping scenario might not contain sufficient information, so previous mapping
            # scenario's context (if expected mapping scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # For this case look beyond only the last signal since an EC2 remote connection session
            # can last a long time and be filled with other mappings.
            if ($null -eq $instanceId)
            {
                $lastEventWithSignalObj = $PreviousSignals.Where(
                {
                    $_.Enrichment.Signal.Label -cin @(
                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect
                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                    ) -and `
                    $null -ne $_.Enrichment.Signal.AdditionalData.instanceId
                } )[-1]

                # Extract instanceId value from previous Signal's AdditionalData property if it is defined.
                # Otherwise set default instanceId value to null so not inaccurately represented in current Signal's AdditionalData property.
                $instanceId = $lastEventWithSignalOb ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.instanceId : $null
            }
            if ($null -eq $sessionId)
            {
                $lastEventWithSignalObj = $PreviousSignals.Where(
                {
                    $_.Enrichment.Signal.Label -cin @(
                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect
                        [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                    ) -and `
                    $null -ne $_.Enrichment.Signal.AdditionalData.sessionId
                } )[-1]

                # Extract sessionId value from previous Signal's AdditionalData property if it is defined.
                # Otherwise set default sessionId value to null so not inaccurately represented in current Signal's AdditionalData property.
                $sessionId = $lastEventWithSignalOb ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.sessionId : $null
            }

            # Substitute instanceId value placeholder in current Signal's Summary and Url properties.
            if ($instanceId)
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))
            }
            else
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{instanceId}}'",'->SPECIFICINSTANCE').Replace(" '{{instanceId}}' EC2 Instance",' current EC2 Instance')

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject 'instanceId'))
            }

            # Substitute instanceId value placeholder in current Signal's Summary property.
            if ($sessionId)
            {
                # Substitute sessionId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{sessionId}}',$sessionId)
            }
            else
            {
                # Substitute sessionId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace(" '{{sessionId}}' Session ID",' current Session ID')
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                sessionId = $sessionId
                instanceIdArr = $instanceIdArr
                sessionIdArr = $sessionIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Terminate) {
            $sessionId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:TerminateSession' } )[0].Event.requestParameters.sessionId

            # Substitute sessionId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{sessionId}}',$sessionId)

            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # For this case look beyond only the last signal since an EC2 remote connection session
            # can last a long time and be filled with other mappings.
            $lastEventWithSignalObj = $PreviousSignals.Where(
            {
                $_.Enrichment.Signal.Label -cin @(
                    [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_Connect
                    [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_RDPClient_FleetManagerRemoteDesktop_InteractiveUsage
                ) -and `
                $null -ne $_.Enrichment.Signal.AdditionalData.instanceId
            } )[-1]
            if ($lastEventWithSignalObj)
            {
                # Extract instanceId value from previous Signal's AdditionalData property.
                $instanceId = $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.instanceId

                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))
            }
            else
            {
                # Set default instanceId value to null so not inaccurately represented in current Signal's AdditionalData property.
                $instanceId = $null

                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{instanceId}}'",'->SPECIFICINSTANCE').Replace(" '{{instanceId}}' EC2 Instance",' current EC2 Instance')

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject 'instanceId'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                sessionId = $sessionId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:GetConnectionStatus' } )[0].Event.requestParameters.target

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $imageId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeImages' } ).ForEach( { $_.Event.requestParameters.imagesSet.items.imageId } ).Where( { $_ } ) | Select-Object -First 1
            $securityGroupIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSecurityGroups' } ).ForEach( { $_.Event.requestParameters.securityGroupIdSet.items.groupId } ).Where( { $_ } ) | Sort-Object -Unique

            # In this case do not append additional optional values extracted above for brevity and clarity,
            # but store below for potential later enrichments.

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                imageId = $imageId
                securityGroupIdArr = $securityGroupIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:StartSession' } )[0].Event.requestParameters.target
            $sessionId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:StartSession' } )[0].Event.responseElements.sessionId

            # Substitute instanceId and sessionId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId).Replace('{{sessionId}}',$sessionId)

            # Do not append below instance profile value(s) to current Signal's Summary property for brevity and clarity,
            # but store in AdditionalData for potential later enrichment.
            $instanceProfileArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetInstanceProfile' } ).ForEach( { $_.Event.requestParameters.instanceProfileName } ).Where( { $_ } ) | Sort-Object -Unique

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                sessionId = $sessionId
                instanceProfileArr = $instanceProfileArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Terminate) {
            $sessionId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ssm:TerminateSession' } )[0].Event.requestParameters.sessionId

            # Substitute sessionId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{sessionId}}',$sessionId)

            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # For this case look beyond only the last signal since an EC2 remote connection session
            # can last a long time and be filled with other mappings.
            # Extract instanceId value from previous Signal's AdditionalData property.
            $lastEventWithSignalObj = $PreviousSignals.Where( { $_.Enrichment.Signal.Label -eq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect } )[-1]
            $instanceId = $lastEventWithSignalObj.Enrichment.Signal.Label -ceq [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_ConnectToInstance_SessionManager_Connect ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.instanceId : $null
            if ($null -ne $instanceId)
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))
            }
            else
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{instanceId}}'",'->SPECIFICINSTANCE').Replace(" '{{instanceId}}' EC2 Instance",' current EC2 Instance')

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject 'instanceId'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                sessionId = $sessionId
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeInstanceAttribute' } )[0].Event.requestParameters.instanceId

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # ec2:DescribeImages event is only executed if an AMI is defined for currently selected EC2 Instance.
            # ec2:DescribeSubnets event is only executed if 1+ EC2 Subnets defined for currently selected EC2 Instance.
            # ec2:DescribeVpcs event is only executed if 1+ EC2 VPCs defined for currently selected EC2 Instance.
            # iam:GetInstanceProfile event is only executed if 1+ IAM Roles defined for currently selected EC2 Instance.
            $imageId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeImages' } ).ForEach( { $_.Event.requestParameters.imagesSet.items.imageId } ).Where( { $_ } ) | Select-Object -First 1
            $subnetIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSubnets' } ).ForEach( { $_.Event.requestParameters.subnetSet.items.subnetId } ).Where( { $_ } ) | Sort-Object -Unique
            $vpcIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeVpcs' } ).ForEach( { $_.Event.requestParameters.vpcSet.items.vpcId } ).Where( { $_ } ) | Sort-Object -Unique
            $instanceProfileArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetInstanceProfile' } ).ForEach( { $_.Event.requestParameters.instanceProfileName } ).Where( { $_ } ) | Sort-Object -Unique

            # Create single array to store all potential Summary suffixes to append.
            $appendSummaryArr = @()
            if ($null -ne $imageId)
            {
                $appendSummaryArr += " is configured with '$imageId' EC2 AMI"
            }
            if ($subnetIdArr.Count -gt 0)
            {
                $appendSummaryArr += " has $($subnetIdArr.Count) EC2 Subnet$($subnetIdArr.Count -eq 1 ? '' : 's') ($($subnetIdArr.ForEach( { "'$_'" } ) -join ',')) configured"
            }
            if ($vpcIdArr.Count -gt 0)
            {
                $appendSummaryArr += " has $($vpcIdArr.Count) EC2 VPC$($vpcIdArr.Count -eq 1 ? '' : 's') ($($vpcIdArr.ForEach( { "'$_'" } ) -join ',')) configured"
            }
            if ($instanceProfileArr.Count -gt 0)
            {
                $appendSummaryArr += " has $($instanceProfileArr.Count) EC2 Instance Profile$($instanceProfileArr.Count -eq 1 ? '' : 's') ($($instanceProfileArr.ForEach( { "'$_'" } ) -join ',')) attached"
            }

            # Append all potential Summary suffixes.
            if ($appendSummaryArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ' which' +  ($appendSummaryArr -join ' and') + '.'
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                imageId = $imageId
                subnetIdArr = $subnetIdArr
                vpcIdArr = $vpcIdArr
                instanceProfileArr = $instanceProfileArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_RebootInstance) {
            $instanceId = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_RebootInstance) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instanceIdArr = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " selected EC2 Instance(s)."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StartInstance) {
            $instanceId = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StartInstance) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instanceIdArr = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " selected EC2 Instance(s)."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_StopInstance) {
            $instanceId = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_StopInstance) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instanceIdArr = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " selected EC2 Instance(s)."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step1) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeInstanceAttribute' } ).ForEach( { $_.Event.requestParameters.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step1) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instanceIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeInstanceAttribute' } ).ForEach( { $_.Event.requestParameters.instanceId } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " selected EC2 Instance(s)."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_InstanceState_TerminateInstance_Step2) {
            $instanceId = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_InstanceState_TerminateInstance_Step2) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instanceIdArr = $AnchorEvent.Event.requestParameters.instancesSet.items.instanceId.Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " selected EC2 Instance(s)."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring) {
            $instanceId = $AnchorEvent.Event.requestParameters.filterSet.items.Where( { $_.name -ceq 'resource-id' } ).ForEach( { $_.valueSet.items.value } ).Where( { $_.StartsWith('i-') } ) | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCES_Monitoring) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # ec2:DescribeTags event is only executed if 2+ EC2 Instances are selected.
            $instanceIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeTags' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).Where( { $_.name -ceq 'resource-id' } ).ForEach( { $_.valueSet.items.value } ).Where( { $_.StartsWith('i-') } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 1)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " for $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Security) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Extract instanceId value from previous Signal's AdditionalData property.
            $instanceId = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Details
                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Security
                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Storage
                [LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Monitoring
            ) ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.instanceId : $null
            if ($null -ne $instanceId)
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

                # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))
            }
            else
            {
                # Substitute instanceId value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{instanceId}}'",'->SPECIFICINSTANCE').Replace(" '{{instanceId}}' EC2 Instance",' current EC2 Instance')

                # Override current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = 'N/A'
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # ec2:DescribeSecurityGroupRules event is only executed if current EC2 Instance has 1+ EC2 Security Groups defined.
            $securityGroupIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSecurityGroupRules' } ).Event.requestParameters.DescribeSecurityGroupRulesRequest.Filter.Where( { $_.Name -ceq 'group-id' } ).ForEach( { $_.Value.content } ).Where( { $_.StartsWith('sg-') } ) | Sort-Object -Unique
            if ($securityGroupIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", including its first $($securityGroupIdArr.Count) EC2 Security Group$($securityGroupIdArr.Count -eq 1 ? '' : 's') ($($securityGroupIdArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                securityGroupIdArr = $securityGroupIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances_SPECIFICINSTANCE_Storage) {
            $instanceId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeReplaceRootVolumeTasks' } ).Event.requestParameters.DescribeReplaceRootVolumeTasksRequest.Filter.Where( { $_.Name -ceq 'instance-id' } ).ForEach( { $_.Value.content } ).Where( { $_.StartsWith('i-') } ) | Select-Object -First 1

            # Substitute instanceId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceId}}',$instanceId)

            # Substitute instanceId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{instanceId}}',(ConvertTo-MinimalUrlEncoded -InputObject $instanceId))

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # ec2:DescribeVolumes event is only executed if current EC2 Instance has 1+ EC2 Volumes defined.
            $volumeIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeVolumes' } ).ForEach( { $_.Event.requestParameters.volumeSet.items.volumeId } ).Where( { $_.StartsWith('vol-') } ) | Sort-Object -Unique
            if ($volumeIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", including its first $($volumeIdArr.Count) EC2 Volume$($volumeIdArr.Count -eq 1 ? '' : 's') ($($volumeIdArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceId = $instanceId
                volumeIdArr = $volumeIdArr
            }
        }
        ([LabelType]::EC2_Instances_Instances) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $instanceIdArr = (
                # Using ec2:DescribeInstances instead of ec2:DescribeInstanceStatus since some instances
                # of EC2_Instances_Instances mapping include ec2:DescribeInstances and not ec2:DescribeInstanceStatus.
                # Also including non-required ec2:DescribeAddresses since it contains all EC2 Instances
                # even if current EC2_Instances_Instances mapping is only showing a single EC2 Instance
                # from previous SPECIFICINSTANCE Signal.
                [System.Array] `
                $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeInstances' } ).ForEach( { $_.Event.requestParameters.instancesSet.items.instanceId } ) + `
                $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeAddresses' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).Where( { $_.name -ceq 'instance-id' } ).ForEach( { $_.valueSet.items.value } ).Where( { $_.StartsWith('i-') } )

            ).Where( { $_ } ) | Sort-Object -Unique
            if ($instanceIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently displaying $($instanceIdArr.Count) EC2 Instance$($instanceIdArr.Count -eq 1 ? '' : 's') ($($instanceIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although currently 0 EC2 Instances are displayed."
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $attributeKeyAndValueObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeInstances' } ).ForEach( { $_.Event.requestParameters.filterSet.items } ).ForEach(
            {
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $key = $_.name
                $valueArr = $_.valueSet.items.value.Count -eq 0 ? @($null) : $_.valueSet.items.value

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if (
                $attributeKeyAndValueObjArr.Count -eq 1 -and `
                $attributeKeyAndValueObjArr[0].Key -ceq 'instance-state-name' -and `
                $attributeKeyAndValueObjArr[0].Value -ceq 'running'
            )
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by default attribute $($attributeKeyAndValueObjArr[0].Key)='$($attributeKeyAndValueObjArr[0].Value)' (default when clicking 'Instances (running)' from EC2->EC2 Dashboard)."
            }
            elseif ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with no filter applied."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Add lookup attribute value(s) to Uri array (with minimal Url encoding).
                $uriArr += $attributeKeyAndValueObjArr.ForEach(
                {
                    # Convert key from kebab-case to camelCase.
                    $_.Key = $_.Key.Substring(0,1) + (-join$_.Key.Split('-').ForEach( { $_.Substring(0,1).ToUpper() + $_.Substring(1) } )).Substring(1)

                    $key = ConvertTo-MinimalUrlEncoded -InputObject $_.Key
                    $operator = '='
                    $value = ConvertTo-MinimalUrlEncoded -InputObject $_.Value

                    # Update operator and value if Contains filter syntax is used.
                    if ($null -ne $value -and $value.StartsWith('*') -and $value.EndsWith('*'))
                    {
                        $operator += ':'
                        $value = -join([System.Char[]] $value | Select-Object -Skip 1 | Select-Object -SkipLast 1)
                    }

                    # Return current concatenated Uri result.
                    $key + $operator + $value
                } )
            }

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                # Add Uri parameter for version number (only required if additional Uri parameters are defined).
                $uriArr += 'v=3'

                $AnchorEvent.Enrichment.Signal.Url += ($uriArr -join ';')
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceIdArr = $instanceIdArr
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates) {
            $launchTemplateName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeLaunchTemplates' -and $_.Event.requestParameters.DescribeLaunchTemplatesRequest.Filter.Name -ceq 'LaunchTemplateName' } )[0].Event.requestParameters.DescribeLaunchTemplatesRequest.Filter.Value.content

            # Potentially append additional optional value(s) to current Signal's Summary property.
            if ($null -ne $launchTemplateName)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by LaunchTemplateName='$launchTemplateName'."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                launchTemplateName = $launchTemplateName
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_InstanceType) {
            $instanceType = $AnchorEvent.Event.requestParameters.DescribeInstanceTypeOfferingsRequest.Filter.Value.content

            # Substitute instanceType value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{instanceType}}',$instanceType)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                instanceType = $instanceType
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step1_KeyPair_Create) {
            $keyName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:CreateKeyPair' } )[0].Event.requestParameters.keyName

            # Substitute keyName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{keyName}}',$keyName)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyName = $keyName
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates_CreateLaunchTemplate_Step2) {
            $launchTemplateId = $AnchorEvent.Event.responseElements.CreateLaunchTemplateResponse.launchTemplate.launchTemplateId
            $launchTemplateName = $AnchorEvent.Event.requestParameters.CreateLaunchTemplateRequest.LaunchTemplateName

            # Substitute launchTemplateId and launchTemplateName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{launchTemplateId}}',$launchTemplateId)
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{launchTemplateName}}',$launchTemplateName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $imageId = $AnchorEvent.Event.requestParameters.CreateLaunchTemplateRequest.LaunchTemplateData.ImageId
            $instanceType = $AnchorEvent.Event.requestParameters.CreateLaunchTemplateRequest.LaunchTemplateData.InstanceType
            $securityGroupId = $AnchorEvent.Event.requestParameters.CreateLaunchTemplateRequest.LaunchTemplateData.NetworkInterface.SecurityGroupId.content
            $subnetId = $AnchorEvent.Event.requestParameters.CreateLaunchTemplateRequest.LaunchTemplateData.NetworkInterface.SubnetId
            $keyName = $AnchorEvent.Event.requestParameters.CreateLaunchTemplateRequest.LaunchTemplateData.KeyName

            # Create single array to store all potential Summary suffixes to append.
            $appendSummaryArr = @()
            if ($null -ne $imageId)
            {
                $appendSummaryArr += " configured with '$imageId' EC2 AMI"
            }
            if ($null -ne $instanceType)
            {
                $appendSummaryArr += " built on '$instanceType' EC2 Instance Type"
            }
            if ($null -ne $securityGroupId -or $null -ne $subnetId)
            {
                $appendSummaryArr += " deployed into " + (@(($securityGroupId ? "'$securityGroupId' Security Group" : $null),($subnetId ? "'$subnetId' Subnet" : $null)).Where( { $_ } ) -join ' and ')
            }
            if ($null -ne $keyName)
            {
                $appendSummaryArr += " configured with '$keyName' key pair"
            }

            # Append all potential Summary suffixes.
            if ($appendSummaryArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ', specifically' +  $appendSummaryArr[0] + (($appendSummaryArr | Select-Object -Skip 1) -join ' and') + '.'
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                launchTemplateName = $launchTemplateName
                imageId = $imageId
                instanceType = $instanceType
                securityGroupId = $securityGroupId
                subnetId = $subnetId
                keyName = $keyName
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Delete) {
            $launchTemplateId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeLaunchTemplateVersions' } )[0].Event.requestParameters.DescribeLaunchTemplateVersionsRequest.LaunchTemplateId

            # Substitute launchTemplateId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{launchTemplateId}}',$launchTemplateId)

            # Substitute launchTemplateId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{launchTemplateId}}',(ConvertTo-MinimalUrlEncoded -InputObject $launchTemplateId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                launchTemplateId = $launchTemplateId
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Details) {
            $launchTemplateId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeLaunchTemplateVersions' } )[0].Event.requestParameters.DescribeLaunchTemplateVersionsRequest.LaunchTemplateId

            # Substitute launchTemplateId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{launchTemplateId}}',$launchTemplateId)

            # Substitute launchTemplateId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{launchTemplateId}}',(ConvertTo-MinimalUrlEncoded -InputObject $launchTemplateId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                launchTemplateId = $launchTemplateId
            }
        }
        ([LabelType]::EC2_Instances_LaunchTemplates_SPECIFICLAUNCHTEMPLATE_Versions) {
            $launchTemplateId = $AnchorEvent.Event.requestParameters.DescribeLaunchTemplateVersionsRequest.LaunchTemplateId

            # Substitute launchTemplateId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{launchTemplateId}}',$launchTemplateId)

            # Substitute launchTemplateId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{launchTemplateId}}',(ConvertTo-MinimalUrlEncoded -InputObject $launchTemplateId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                launchTemplateId = $launchTemplateId
            }
        }
        ([LabelType]::EC2_Instances_SpotRequests) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # Since only a subset of search filter terms populate in CloudTrail logs there is no else block to modify
            # the Summary property with a 'no filter applied' message since it cannot accurately be determined.
            $attributeKeyAndValueObjArr = $AnchorEvent.Event.requestParameters.filterSet.items.ForEach(
            {
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $key = $_.name
                $valueArr = $_.valueSet.items.value.Count -eq 0 ? @($null) : $_.valueSet.items.value

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::EC2_Instances_SpotRequests_PlacementScore_Step2) {
            $regionNameArr = $AnchorEvent.Event.requestParameters.GetSpotPlacementScoresRequest.RegionName.content.Where( { $_ } ) | Sort-Object -Unique

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by Regions To Score=$($regionNameArr.ForEach( { "'$_'" } ) -join ',')."

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                regionNameArr = $regionNameArr
            }
        }
        ([LabelType]::EC2_Instances_SpotRequests_PricingHistory) {
            $graph = $null -eq $AnchorEvent.Event.requestParameters.availabilityZone ? 'Availability Zones' : 'Instance Types'
            $instanceTypeArr = $AnchorEvent.Event.requestParameters.instanceTypeSet.items.instanceType.Where( { $_ } ) | Sort-Object -Unique
            $availabilityZone = $AnchorEvent.Event.requestParameters.availabilityZone
            $platform = $AnchorEvent.Event.requestParameters.productDescriptionSet.items.productDescription | Select-Object -First 1
            $startTime = $AnchorEvent.Event.requestParameters.startTime
            $endTime   = $AnchorEvent.Event.requestParameters.endTime

            # Convert raw date values to UTC DateTime objects.
            $startTime = [System.DateTimeOffset]::FromUnixTimeMilliseconds($startTime).UtcDateTime
            $endTime   = [System.DateTimeOffset]::FromUnixTimeMilliseconds(  $endTime).UtcDateTime

            # Calculate string format of timespan by the highest even denomination.
            $timespanStr = Out-TimeSpanStr -StartTime $startTime -EndTime $endTime

            # Set string value to output if filter value is default or custom.
            $defaultOrCustomTimeFilterStr = $timespanStr -ceq '1 week' ? 'default' : 'custom'
            $defaultOrCustomFilterValuesStr = (
                $graph -ceq 'Availability Zones' -and `
                $instanceTypeArr.Count -eq 1 -and `
                $instanceTypeArr -ceq 'c3.large' -and `
                $platform -ceq 'Linux/UNIX' -and `
                $timespanStr -ceq '1 week'
            ) ? 'default' : 'custom'

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by $defaultOrCustomFilterValuesStr values Graph='$graph', Instance Type$($instanceTypeArr.Count -gt 1 ? 's' : '')=$($instanceTypeArr.ForEach( { "'$_'" } ) -join ','), $($null -eq $availabilityZone ? '' : "Availability Zone='$availabilityZone', ")Platform='$platform' and $defaultOrCustomTimeFilterStr Date Range='$timespanStr' ('$($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))' to '$($endTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))')."

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                graph = $graph
                instanceTypeArr = $instanceTypeArr
                availabilityZone = $availabilityZone
                platform = $platform
                timespanStr = $timespanStr
            }
        }
        ([LabelType]::EC2_NetworkSecurity_SecurityGroups) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:DescribeSecurityGroups event is only executed if 1+ Security Groups defined.
            $groupIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSecurityGroups' } ).ForEach( { $_.Event.requestParameters.securityGroupIdSet.items.ForEach( { $_.groupId } ) } ).Where( { $_ } ) | Sort-Object -Unique
            if ($groupIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " including $($groupIdArr.Count) Security Group$($groupIdArr.Count -eq 1 ? '' : 's') ($($groupIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ', although currently 0 Security Groups are defined.'
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                groupIdArr = $groupIdArr
            }
        }
        ([LabelType]::EC2_NetworkSecurity_SecurityGroups_SPECIFICGROUP) {
            $groupId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSecurityGroupRules' } )[0].Event.requestParameters.DescribeSecurityGroupRulesRequest.Filter.Value.content

            # Substitute groupId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{groupId}}',$groupId)

            # Substitute groupId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{groupId}}',(ConvertTo-MinimalUrlEncoded -InputObject $groupId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                groupId = $groupId
            }
        }
        ([LabelType]::Expanded_SPECIFICINLINEUSERPOLICY) {
            $policyName = $AnchorEvent.Event.requestParameters.policyName

            # Substitute policyName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{policyName}}',$policyName)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                policyName = $policyName
            }
        }
        ([LabelType]::Expanded_SPECIFICMANAGEDPOLICY) {
            $policyArn = $AnchorEvent.Event.requestParameters.policyArn
            $versionId = $AnchorEvent.Event.requestParameters.versionId

            # Substitute policyArn and policyVersionId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{policyArn}}',$policyArn).Replace('{{versionId}}',$versionId)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                policyArn = $policyArn
                versionId = $versionId
            }
        }
        ([LabelType]::GuardDuty_Summary) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $startTime = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'guardduty:ListFindings' } )[0].Event.requestParameters.findingCriteria.criterion.updatedAt.gt
            $endTime   = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'guardduty:ListFindings' } )[0].Event.requestParameters.findingCriteria.criterion.updatedAt.lt
            $timespanStr = $null
            if ($null -ne $startTime -and $null -ne $endTime)
            {
                # Convert raw date values to UTC DateTime objects.
                $startTime = [System.DateTimeOffset]::FromUnixTimeMilliseconds($startTime).UtcDateTime
                $endTime   = [System.DateTimeOffset]::FromUnixTimeMilliseconds(  $endTime).UtcDateTime

                # Calculate string format of timespan by the highest even denomination.
                $timespanStr = Out-TimeSpanStr -StartTime $startTime -EndTime $endTime -Exclude month,week

                # Set string value to output if filter value is default or custom.
                $defaultOrCustomTimeFilterStr = $timespanStr -ceq '1 day' ? 'default' : 'custom'

                # Potentially append additional optional value(s) to current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently filtered by $defaultOrCustomTimeFilterStr date range of '$timespanStr' ('$($startTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))' to '$($endTime.ToString('yyyy-MM-ddTHH:mm:ssZ'))')."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                startTime = $startTime
                endTime = $endTime
                timespanStr = $timespanStr
            }
        }
        ([LabelType]::IAM_Roles) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:GetRole event is only executed if 1+ IAM Roles defined.
            $roleNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetRole' } ).ForEach( { $_.Event.requestParameters.roleName } ).Where( { $_ } ) | Sort-Object -Unique
            if ($roleNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently displaying $($roleNameArr.Count) IAM Role$($roleNameArr.Count -eq 1 ? '' : 's') ($($roleNameArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although currently 0 IAM Roles are defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                roleNameArr = $roleNameArr
            }
        }
        ([LabelType]::IAM_Roles_SPECIFICROLE_Permissions) {
            $roleName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:ListAttachedRolePolicies' } )[0].Event.requestParameters.roleName

            # Substitute roleName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{roleName}}',$roleName)

            # Substitute roleName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{roleName}}',(ConvertTo-MinimalUrlEncoded -InputObject $roleName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                roleName = $roleName
            }
        }
        ([LabelType]::IAM_UserGroups) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:GetGroup event is only executed if 1+ IAM User Groups defined.
            $groupNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetGroup' } ).ForEach( { $_.Event.requestParameters.groupName } ).Where( { $_ } ) | Sort-Object -Unique
            if ($groupNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently displaying $($groupNameArr.Count) IAM User Group$($groupNameArr.Count -eq 1 ? '' : 's') ($($groupNameArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although currently 0 IAM User Groups are defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                groupNameArr = $groupNameArr
            }
        }
        ([LabelType]::IAM_UserGroups_CreateUserGroup) {
            $groupName = $AnchorEvent.Event.requestParameters.groupName

            # Substitute groupName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{groupName}}',$groupName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:AddUserToGroup event is only executed if created IAM User Group has 1+ IAM Users added as members.
            # iam:AttachGroupPolicy event is only executed if created IAM User Group has 1+ IAM Policies attached.
            $userNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:AddUserToGroup' } ).ForEach( { $_.Event.requestParameters.userName } ).Where( { $_ } ) | Sort-Object -Unique
            $policyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:AttachGroupPolicy' } ).ForEach( { $_.Event.requestParameters.policyArn } ).Where( { $_ } ) | Sort-Object -Unique
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($userNameArr.Count) IAM User$($userNameArr.Count -eq 1 ? '' : 's') added as members$($userNameArr.Count -eq 0 ? '' : " ($($userNameArr.ForEach( { "'$_'" } ) -join ','))") and $($policyArnArr.Count) IAM Polic$($policyArnArr.Count -eq 1 ? 'y' : 'ies') attached$($policyArnArr.Count -eq 0 ? '' : " ($($policyArnArr.ForEach( { "'$_'" } ) -join ','))")."

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                groupName = $groupName
                userNameArr = $userNameArr
                policyArnArr = $policyArnArr
            }
        }
        ([LabelType]::IAM_UserGroups_DeleteUserGroup) {
            $groupName = $AnchorEvent.Event.requestParameters.groupName

            # Substitute groupName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{groupName}}',$groupName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:RemoveUserFromGroup event is only executed if current IAM User Group being deleted has 1+ IAM Users defined as members.
            # iam:DetachGroupPolicy event is only executed if current IAM User Group being deleted has 1+ IAM Policies attached.
            $userNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:RemoveUserFromGroup' } ).ForEach( { $_.Event.requestParameters.userName } ).Where( { $_ } ) | Sort-Object -Unique
            $policyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:DetachGroupPolicy' } ).ForEach( { $_.Event.requestParameters.policyArn } ).Where( { $_ } ) | Sort-Object -Unique
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " after removing $($userNameArr.Count) IAM User$($userNameArr.Count -eq 1 ? '' : 's') as members$($userNameArr.Count -eq 0 ? '' : " ($($userNameArr.ForEach( { "'$_'" } ) -join ','))") and detaching $($policyArnArr.Count) IAM Polic$($policyArnArr.Count -eq 1 ? 'y' : 'ies')$($policyArnArr.Count -eq 0 ? '' : " ($($policyArnArr.ForEach( { "'$_'" } ) -join ','))")."

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                groupName = $groupName
                userNameArr = $userNameArr
                policyArnArr = $policyArnArr
            }
        }
        ([LabelType]::IAM_Users) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:ListMFADevices event is only executed if 1+ IAM Users defined.
            # iam:GetAccessKeyLastUsed event is only executed if 1+ IAM Users defined also have 1+ Access Keys defined.
            $userNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:ListMFADevices' } ).ForEach( { $_.Event.requestParameters.userName } ).Where( { $_ } ) | Sort-Object -Unique
            $accessKeyIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetAccessKeyLastUsed' } ).ForEach( { $_.Event.requestParameters.accessKeyId } ).Where( { $_ } ) | Sort-Object -Unique
            if ($userNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", currently displaying $($userNameArr.Count) IAM User$($userNameArr.Count -eq 1 ? '' : 's') ($($userNameArr.ForEach( { "'$_'" } ) -join ',')) which $($userNameArr.Count -eq 1 ? 'has' : 'have') $($accessKeyIdArr.Count) Access Key$($accessKeyIdArr.Count -eq 1 ? '' : 's') defined$($accessKeyIdArr.Count -eq 0 ? '' : " ($($accessKeyIdArr.ForEach( { "'$_'" } ) -join ','))")."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although currently 0 IAM Users are defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userNameArr = $userNameArr
                accessKeyIdArr = $accessKeyIdArr
            }
        }
        ([LabelType]::IAM_Users_CreateUser_Step2) {
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $loginProfileCreated = $RelatedEvents.Enrichment.EventNameFull.Contains('iam:CreateLoginProfile')
            $passwordResetRequired = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:CreateLoginProfile' } )[0].Event.requestParameters.passwordResetRequired
            $permissionsBoundary = $AnchorEvent.Event.requestParameters.permissionsBoundary
            $tagsArr = $AnchorEvent.Event.requestParameters.tags.Where( { $_ } )
            $policyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:AttachUserPolicy' } ).ForEach( { $_.Event.requestParameters.policyArn } ).Where( { $_ } ) | Sort-Object -Unique
            # The arn:aws:iam::aws:policy/IAMUserChangePassword policy is automatically added if
            # login profile with required password change is defined, so in this scenario remove
            # this policy from being displayed as explicitly added by the user.
            $policyArnArr = $loginProfileCreated -and $passwordResetRequired ? $policyArnArr.Where( { $_ -cne 'arn:aws:iam::aws:policy/IAMUserChangePassword' } ) : $policyArnArr
            $inlinePolicyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:PutUserPolicy' } ).ForEach( { $_.Event.requestParameters.policyName } ).Where( { $_ } ) | Sort-Object -Unique
            $groupNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:AddUserToGroup' } ).ForEach( { $_.Event.requestParameters.groupName } ).Where( { $_ } ) | Sort-Object -Unique
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($loginProfileCreated -eq $false ? 'no ' : 'a ')login profile created$($loginProfileCreated -eq $true ? " (password reset $($passwordResetRequired -eq $false ? 'NOT ' : '')required)" : ''), $($null -eq $permissionsBoundary ? 'no ' : 'a ')Permissions Boundary set$($null -eq $permissionsBoundary ? '' : " ('$permissionsBoundary')"), $($tagsArr.ForEach( { $_ } ).Count) Tag$($tagsArr.ForEach( { $_ } ).Count -eq 1 ? '' : 's') defined$($tagsArr.Count -eq 0 ? '' : " ($($tagsArr.ForEach( { "$($_.key)='$($_.value)'" } ) -join ','))"), $($inlinePolicyArnArr.Count) Inline Polic$($inlinePolicyArnArr.Count -eq 1 ? 'y' : 'ies') directly attached$($inlinePolicyArnArr.Count -eq 0 ? '' : " ($($inlinePolicyArnArr.ForEach( { "'$_'" } ) -join ','))"), $($policyArnArr.Count) IAM Polic$($policyArnArr.Count -eq 1 ? 'y' : 'ies') attached$($policyArnArr.Count -eq 0 ? '' : " ($($policyArnArr.ForEach( { "'$_'" } ) -join ','))") and added to $($groupNameArr.Count) IAM Group$($groupNameArr.Count -eq 1 ? '' : 's')$($groupNameArr.Count -eq 0 ? '' : " ($($groupNameArr.ForEach( { "'$_'" } ) -join ','))")."

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                loginProfileCreated = $loginProfileCreated
                passwordResetRequired = $passwordResetRequired
                permissionsBoundary = $permissionsBoundary
                tagsArr = $tagsArr
                policyArnArr = $policyArnArr
                inlinePolicyArnArr = $inlinePolicyArnArr
                groupNameArr = $groupNameArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_AccessAdvisor) {
            $userArn = $AnchorEvent.Event.requestParameters.arn
            $userName = $userArn.Split('/')[-1]

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userArn = $userArn
                userName = $userName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Delete) {
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:DeleteAccessKey event is only executed if current IAM User has 1+ Access Keys defined.
            # iam:DetachUserPolicy event is only executed if current IAM User has 1+ IAM Policy defined.
            $accessKeyIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:DeleteAccessKey' } ).ForEach( { $_.Event.requestParameters.accessKeyId } ).Where( { $_ } ) | Sort-Object -Unique
            $policyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:DetachUserPolicy' } ).ForEach( { $_.Event.requestParameters.policyArn } ).Where( { $_ } ) | Sort-Object -Unique
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " after removing $($accessKeyIdArr.Count) Access Key$($accessKeyIdArr.Count -eq 1 ? '' : 's')$($accessKeyIdArr.Count -eq 0 ? '' : " ($($accessKeyIdArr.ForEach( { "'$_'" } ) -join ','))") and detaching $($policyArnArr.Count) IAM Polic$($policyArnArr.Count -eq 1 ? 'y' : 'ies')$($policyArnArr.Count -eq 0 ? '' : " ($($policyArnArr.ForEach( { "'$_'" } ) -join ','))")."

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyIdArr = $accessKeyIdArr
                policyArnArr = $policyArnArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions) {
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:GetAccessKeyLastUsed event is only executed if current IAM User has 1+ Access Keys defined.
            $accessKeyIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetAccessKeyLastUsed' } ).ForEach( { $_.Event.requestParameters.accessKeyId } ).Where( { $_ } ) | Sort-Object -Unique
            # iam:GetPolicy event is only executed if current IAM User has 1+ IAM Policies defined.
            $policyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetPolicy' } ).ForEach( { $_.Event.requestParameters.policyArn } ).Where( { $_ } ) | Sort-Object -Unique
            # iam:ListAttachedGroupPolicies event is only executed if current IAM User has 1+ IAM Policies
            # attached via membership in 1+ IAM User Groups.
            # iam:ListGroupPolicies event is only executed if current IAM User is a member of 1+ IAM Groups.
            $groupNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -cin @('iam:ListAttachedGroupPolicies','iam:ListGroupPolicies') } ).ForEach( { $_.Event.requestParameters.groupName } ).Where( { $_ } ) | Sort-Object -Unique
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " which has $($accessKeyIdArr.Count) Access Key$($accessKeyIdArr.Count -eq 1 ? '' : 's') defined$($accessKeyIdArr.Count -eq 0 ? '' : " ($($accessKeyIdArr.ForEach( { "'$_'" } ) -join ','))"), $($policyArnArr.Count) IAM Polic$($policyArnArr.Count -eq 1 ? 'y' : 'ies') directly attached$($policyArnArr.Count -eq 0 ? '' : " ($($policyArnArr.ForEach( { "'$_'" } ) -join ','))") and is a member of $($groupNameArr.Count) IAM Group$($groupNameArr.Count -eq 1 ? '' : 's')$($groupNameArr.Count -eq 0 ? '' : " ($($groupNameArr.ForEach( { "'$_'" } ) -join ','))")."

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyIdArr = $accessKeyIdArr
                policyArnArr = $policyArnArr
                groupNameArr = $groupNameArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Extract userName value from previous Signal's AdditionalData property.
            $userName = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CopyPermissions
            ) ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.userName : $null
            if ($null -ne $userName)
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))
            }
            else
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{userName}}'",'->SPECIFICUSER').Replace(" '{{userName}}' IAM User",' current IAM User')

                # Override current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = 'N/A'
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:GetGroup event is only executed if current AWS Account has 1+ IAM User Groups defined.
            $groupNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetGroup' } ).ForEach( { $_.Event.requestParameters.groupName } ).Where( { $_ } ) | Sort-Object -Unique
            if ($groupNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", with current page displaying the current AWS Account's first $($groupNameArr.Count) existing IAM User Group$($groupNameArr.Count -eq 1 ? '' : 's') ($($groupNameArr.ForEach( { "'$_'" } ) -join ',')) in a searchable paged format."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although the current AWS Account has 0 IAM User Groups defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                groupNameArr = $groupNameArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AttachPoliciesDirectly) {
            $userName = $AnchorEvent.Event.requestParameters.userName
            $policyArnArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:AttachUserPolicy' } ).ForEach( { $_.Event.requestParameters.policyArn } ).Where( { $_ } ) | Sort-Object -Unique

            # Substitute userName and policyArnArr value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " to directly attach $($policyArnArr.Count) IAM Polic$($policyArnArr.Count -eq 1 ? 'y' : 'ies') ($($policyArnArr.ForEach( { "'$_'" } ) -join ',')) to '$userName' IAM User."

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                policyArnArr = $policyArnArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CopyPermissions) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Extract userName value from previous Signal's AdditionalData property.
            $userName = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_AddUserToGroup
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CopyPermissions
            ) ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.userName : $null
            if ($null -ne $userName)
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))
            }
            else
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{userName}}'",'->SPECIFICUSER').Replace(" '{{userName}}' IAM User",' current IAM User')

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = 'N/A'
            }

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:ListAttachedUserPolicies event is only executed if current AWS Account has 1+ IAM User Users defined.
            $userNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:ListAttachedUserPolicies' } ).ForEach( { $_.Event.requestParameters.userName } ).Where( { $_ } ) | Sort-Object -Unique
            if ($userNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", with current page displaying the current AWS Account's first $($userNameArr.Count) additional existing IAM User$($userNameArr.Count -eq 1 ? '' : 's') ($($userNameArr.ForEach( { "'$_'" } ) -join ',')) in a searchable paged format."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although the current AWS Account has 0 additional IAM Users defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                userNameArr = $userNameArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:GetUserPolicy event is only executed if current IAM User has 1+ Inline IAM Policies defined.
            $policyNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetUserPolicy' } ).ForEach( { $_.Event.requestParameters.policyName } ).Where( { $_ } ) | Sort-Object -Unique
            if ($policyNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " in addition to its $($policyNameArr.Count) existing Inline IAM Polic$($policyNameArr.Count -eq 1 ? 'y' : 'ies') ($($policyNameArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although currently it has 0 Inline IAM Policies defined."
            }

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                policyNameArr = $policyNameArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step2) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Extract userName value from previous Signal's AdditionalData property.
            $userName = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step2
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3
            ) ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.userName : $null
            if ($null -ne $userName)
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))
            }
            else
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{userName}}'",'->SPECIFICUSER').Replace(" '{{userName}}' IAM User",' current IAM User')

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = 'N/A'
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step3) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Extract userName value from previous Signal's AdditionalData property.
            $userName = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step1
                [LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step2
            ) ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.userName : $null
            if ($null -ne $userName)
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))
            }
            else
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace("->'{{userName}}'",'->SPECIFICUSER').Replace(" '{{userName}}' IAM User",' current IAM User')

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = 'N/A'
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_AddPermissions_CreateInlinePolicy_Step4) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $userName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:PutUserPolicy' } )[0].Event.requestParameters.userName
            $policyName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:PutUserPolicy' } )[0].Event.requestParameters.policyName

            # Substitute userName and policyName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{policyName}}',$policyName)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                policyName = $policyName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveInlinePolicyForUser) {
            $userName = $AnchorEvent.Event.requestParameters.userName
            $policyName = $AnchorEvent.Event.requestParameters.policyName

            # Substitute userName and policyName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{policyName}}',$policyName)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                policyName = $policyName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Permissions_RemoveManagedPolicyForUser) {
            $userName = $AnchorEvent.Event.requestParameters.userName
            $policyArn = $AnchorEvent.Event.requestParameters.policyArn

            # Substitute userName and policyArn value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{policyArn}}',$policyArn)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                policyArn = $policyArn
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials) {
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # iam:GetAccessKeyLastUsed event is only executed if current IAM User has 1+ Access Keys defined.
            $accessKeyIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:GetAccessKeyLastUsed' } ).ForEach( { $_.Event.requestParameters.accessKeyId } ).Where( { $_ } ) | Sort-Object -Unique
            if ($accessKeyIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " including its $($accessKeyIdArr.Count) corresponding Access Key$($accessKeyIdArr.Count -eq 1 ? '' : 's') ($($accessKeyIdArr.ForEach( { "'$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + ", although currently it has 0 Access Keys defined."
            }

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyIdArr = $accessKeyIdArr
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Activate) {
            $userName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:UpdateAccessKey' } )[0].Event.requestParameters.userName
            $accessKeyId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:UpdateAccessKey' } )[0].Event.requestParameters.accessKeyId

            # Substitute userName and accessKeyId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{accessKeyId}}',$accessKeyId)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyId = $accessKeyId
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_CreateAccessKey) {
            $userName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:CreateAccessKey' } )[0].Event.responseElements.accessKey.userName
            $accessKeyId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:CreateAccessKey' } )[0].Event.responseElements.accessKey.accessKeyId

            # Substitute userName and accessKeyId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{accessKeyId}}',$accessKeyId)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyId = $accessKeyId
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Deactivate) {
            $userName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:UpdateAccessKey' } )[0].Event.requestParameters.userName
            $accessKeyId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:UpdateAccessKey' } )[0].Event.requestParameters.accessKeyId

            # Substitute userName and accessKeyId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{accessKeyId}}',$accessKeyId)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyId = $accessKeyId
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_AccessKeys_Delete) {
            $userName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:DeleteAccessKey' } )[0].Event.requestParameters.userName
            $accessKeyId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'iam:DeleteAccessKey' } )[0].Event.requestParameters.accessKeyId

            # Substitute userName and accessKeyId value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName).Replace('{{accessKeyId}}',$accessKeyId)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                accessKeyId = $accessKeyId
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess) {
            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            $userName = ([System.String] $lastEventWithSignalObj.Enrichment.Signal.Label).StartsWith('IAM_Users_SPECIFICUSER_SecurityCredentials') ? $lastEventWithSignalObj.Enrichment.Signal.AdditionalData.userName : $null
            if ($null -ne $userName)
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))
            }
            else
            {
                # Substitute userName value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace(" IAM User '{{userName}}'",' current IAM User')

                # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject 'CurrentIAMUser'))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Disable) {
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Enable) {
            $userName = $AnchorEvent.Event.requestParameters.userName
            $passwordResetRequired = $AnchorEvent.Event.requestParameters.passwordResetRequired

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            if ($passwordResetRequired -eq $true)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while requiring the newly generated password to be reset upon first logon."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while NOT requiring the newly generated password to be reset upon first logon."
            }

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                passwordResetRequired = $passwordResetRequired
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_SecurityCredentials_ManageConsoleAccess_Update) {
            $userName = $AnchorEvent.Event.requestParameters.userName
            $passwordResetRequired = $AnchorEvent.Event.requestParameters.passwordResetRequired

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            if ($passwordResetRequired -eq $true)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while requiring the newly generated password to be reset upon first logon."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while NOT requiring the newly generated password to be reset upon first logon."
            }

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
                passwordResetRequired = $passwordResetRequired
            }
        }
        ([LabelType]::IAM_Users_SPECIFICUSER_Tags) {
            $userName = $AnchorEvent.Event.requestParameters.userName

            # Substitute userName value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{userName}}',$userName)

            # Substitute userName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{userName}}',(ConvertTo-MinimalUrlEncoded -InputObject $userName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                userName = $userName
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            # kms:DescribeKey event is only executed if 1+ KMS Keys defined.
            $keyIdArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'kms:DescribeKey' } ).ForEach( { $_.Event.requestParameters.keyId } ).Where( { $_ } ) | Sort-Object -Unique
            if ($keyIdArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($keyIdArr.Count) KMS Key$($keyIdArr.Count -eq 1 ? '' : 's') defined ($($keyIdArr.ForEach( { "$_'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with 0 KMS Keys defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyIdArr = $keyIdArr
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step1) {
            # Substitute awsRegion value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step2) {
            # Substitute awsRegion value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step3) {
            # Substitute awsRegion value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_CreateKey_Step4) {
            $aliasName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'kms:CreateAlias' } )[0].Event.requestParameters.aliasName -creplace '^alias/',''
            $keyId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'kms:CreateKey' } )[0].Event.responseElements.keyMetadata.keyId

            # Substitute aliasName, keyId and awsRegion value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{aliasName}}',$aliasName).Replace('{{keyId}}',$keyId).Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                aliasName = $aliasName
                keyId = $keyId
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_CryptographicConfiguration) {
            $keyId = $AnchorEvent.Event.requestParameters.keyId

            # Substitute keyId and awsRegion value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{keyId}}',$keyId).Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Substitute keyId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{keyId}}',(ConvertTo-MinimalUrlEncoded -InputObject $keyId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyId = $keyId
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyPolicy) {
            $keyId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'kms:GetKeyPolicy' } )[0].Event.requestParameters.keyId

            # Substitute keyId and awsRegion value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{keyId}}',$keyId).Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Substitute keyId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{keyId}}',(ConvertTo-MinimalUrlEncoded -InputObject $keyId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyId = $keyId
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_KeyRotation) {
            $keyId = $AnchorEvent.Event.requestParameters.keyId

            # Substitute keyId and awsRegion value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{keyId}}',$keyId).Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Substitute keyId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{keyId}}',(ConvertTo-MinimalUrlEncoded -InputObject $keyId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyId = $keyId
            }
        }
        ([LabelType]::KMS_CustomerManagedKeys_SPECIFICKEY_Tags) {
            $keyId = $AnchorEvent.Event.requestParameters.keyId

            # Substitute keyId and awsRegion value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{keyId}}',$keyId).Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Substitute keyId value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{keyId}}',(ConvertTo-MinimalUrlEncoded -InputObject $keyId))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                keyId = $keyId
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_AccessPoints) {
            $awsRegionArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:ListAccessPoints' } ).ForEach( { $_.Event.awsRegion } ).Where( { $_ } ) | Sort-Object -Unique

            # Substitute awsRegionArr value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegionArr}}',($awsRegionArr.ForEach( { "'$_'" } ) -join ',').Trim("'"))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegionArr = $awsRegionArr
            }
        }
        ([LabelType]::S3_BatchOperations) {
            $awsRegionArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:ListJobs' } ).ForEach( { $_.Event.awsRegion } ).Where( { $_ } ) | Sort-Object -Unique
            $jobStatusesArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:ListJobs' } ).ForEach(
            {
                # Map each array of jobStatuses to corresponding value in job status filter dropdown in AWS Console.
                $jobStatusesArrStr = ($_.Event.requestParameters.jobStatuses.Where( { $_ } ) | Sort-Object -Unique) -join ','

                switch ($jobStatusesArrStr)
                {
                    'Active,Cancelled,Cancelling,Complete,Completing,Failed,Failing,New,Paused,Pausing,Preparing,Ready,Suspended' {
                        'All status types'
                    }
                    'New,Preparing,Ready,Suspended' {
                        'Not started'
                    }
                    'Active,Cancelling,Completing,Failing,Paused,Pausing' {
                        'In-progress'
                    }
                    'Cancelled,Complete,Failed' {
                        'Finished'
                    }
                    'Suspended' {
                        'Awaiting your confirmation to run'
                    }
                    'Complete' {
                        'Completed'
                    }
                    'Cancelled' {
                        'Cancelled'
                    }
                    'Failed' {
                        'Failed'
                    }
                    default {
                        # Include encapsulating curly brace placeholder string syntax so warning message
                        # will be generated at end of current function.
                        '{{UNKNOWN}}'
                    }
                }
            } )

            # Substitute awsRegionArr and jobStatusesArr value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegionArr}}',($awsRegionArr.ForEach( { "'$_'" } ) -join ',').Trim("'")).Replace('{{jobStatusesArr}}',($jobStatusesArr.ForEach( { "'$_'" } ) -join ',').Trim("'"))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegionArr = $awsRegionArr
                jobStatusesArr = $jobStatusesArr
            }
        }
        ([LabelType]::S3_Buckets) {
            $bucketNameArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:GetBucketAcl' } ).ForEach( { $_.Event.requestParameters.bucketName } ).Where( { $_ } ) | Sort-Object -Unique

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # Excluding else logic for summary modification since sometimes s3:GetBucketAcl is not executed even though S3 Buckets are present.
            if ($bucketNameArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " including $($bucketNameArr.Count) S3 Bucket$($bucketNameArr.Count -eq 1 ? '' : 's') ($($bucketNameArr.ForEach( { "'$_'" } ) -join ','))."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketNameArr = $bucketNameArr
            }
        }
        ([LabelType]::S3_Buckets_CreateBucket_Step1) {
            # Substitute awsRegion value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_CreateBucket_Step1B) {
            $awsRegionForPermissionsCopy = $AnchorEvent.Event.awsRegion
            $bucketNameForPermissionsCopy = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegionForPermissionsCopy and bucketNameForPermissionsCopy value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegionForPermissionsCopy}}',$awsRegionForPermissionsCopy).Replace('{{bucketNameForPermissionsCopy}}',$bucketNameForPermissionsCopy)

            # This is a special case where event(s) in current mapping scenario do not contain
            # sufficient information, so previous mapping scenario's context (if expected mapping
            # scenario) will be queried and supplied below; otherwise generic value(s) will be used.
            # Below is looking for previous [LabelType]::S3_Buckets_CreateBucket_Step1 Signal
            # scenario, but currently it will actually be looking for previous
            # [LabelType]::S3_BlockPublicAccessSettings Signal scenario since after current Signal is
            # generated then previous Signal will be updated to [LabelType]::S3_Buckets_CreateBucket_Step1
            # since both share identical event definitions.
            # For now leaving both Signal LabelType values in below logic in case Signal update logic
            # ordering is ever changed.
            # Extract awsRegionForBucketCreation value from previous Signal's AdditionalData property.
            $awsRegionForBucketCreation = $lastEventWithSignalObj.Enrichment.Signal.Label -cin @(
                [LabelType]::S3_Buckets_CreateBucket_Step1
                [LabelType]::S3_BlockPublicAccessSettings
            ) ? $lastEventWithSignalObj.Event.awsRegion : $null
            if ($null -ne $awsRegionForBucketCreation)
            {
                # Substitute awsRegionForBucketCreation value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegionForBucketCreation}}',$awsRegionForBucketCreation)

                # Substitute awsRegionForBucketCreation value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{awsRegionForBucketCreation}}',(ConvertTo-MinimalUrlEncoded -InputObject $awsRegionForBucketCreation))
            }
            else
            {
                # Substitute awsRegionForBucketCreation value placeholder in current Signal's Summary property.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace(" in AWS Region '{{awsRegionForBucketCreation}}'",'')

                # Substitute awsRegionForBucketCreation value placeholder (with minimal Url encoding) in current Signal's Url property.
                $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{awsRegionForBucketCreation}}',(ConvertTo-MinimalUrlEncoded -InputObject $AnchorEvent.Event.awsRegion))
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegionForBucketCreation = $awsRegionForBucketCreation
                awsRegionForPermissionsCopy = $awsRegionForPermissionsCopy
                bucketNameForPermissionsCopy = $bucketNameForPermissionsCopy
            }
        }
        ([LabelType]::S3_Buckets_CreateBucket_Step2) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Potentially append additional optional value(s) to current Signal's Summary property.
            # s3:PutBucketTagging event is only executed if newly created S3 Bucket has 1+ Tags added.
            $tagObjArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:PutBucketTagging' } ).ForEach( { $_.Event.requestParameters.Tagging.TagSet.Tag } ) | Select-Object -Property Key,Value -Unique
            if ($tagObjArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with $($tagObjArr.Count) Tag$($tagObjArr.Count -eq 1 ? '' : 's') defined ($($tagObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ','))."
            }
            else
            {
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " with 0 Tags defined."
            }

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                tagObjArr = $tagObjArr
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_DeleteBucket_Step1) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_DeleteBucket_Step2) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_EmptyBucket) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_SPECIFICBUCKET_AccessPoints) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucket

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_SPECIFICBUCKET_Management) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_SPECIFICBUCKET_Metrics) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_SPECIFICBUCKET_Objects) {
            $bucketName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:GetBucketVersioning' } )[0].Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_SPECIFICBUCKET_Permissions) {
            $bucketName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:GetBucketAcl' } )[0].Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_Buckets_SPECIFICBUCKET_Properties) {
            $bucketName = $AnchorEvent.Event.requestParameters.bucketName

            # Substitute awsRegion and bucketName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegion}}',$AnchorEvent.Event.awsRegion).Replace('{{bucketName}}',$bucketName)

            # Substitute bucketName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{bucketName}}',(ConvertTo-MinimalUrlEncoded -InputObject $bucketName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                bucketName = $bucketName
                awsRegion = $AnchorEvent.Event.awsRegion
            }
        }
        ([LabelType]::S3_ObjectLambdaAccessPoints) {
            $awsRegionArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 's3:ListAccessPointsForObjectLambda' } ).ForEach( { $_.Event.awsRegion } ).Where( { $_ } ) | Sort-Object -Unique

            # Substitute awsRegionArr value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{awsRegionArr}}',($awsRegionArr.ForEach( { "'$_'" } ) -join ',').Trim("'"))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                awsRegionArr = $awsRegionArr
            }
        }
        ([LabelType]::SecretsManager_Secrets) {
            # Potentially append additional optional value(s) to current Signal's Summary property.
            $attributeKeyAndValueObjArr = $AnchorEvent.Event.requestParameters.filters.ForEach(
            {
                # Map key names from CloudTrail event to corresponding values in AWS Console dropdown.
                $key = switch ($_.key) {
                    'name'           { 'Name'               }
                    'description'    { 'Description'        }
                    'tag-key'        { 'Tag key'            }
                    'tag-value'      { 'Tag value'          }
                    'primary-region' { 'Replicated secrets' }
                    'owning-service' { 'Managed by'         }
                    default          { $_                   }
                }
                # If value is not defined then set to an array containing a single null value so single key
                # is still extracted in foreach loop.
                $valueArr = $_.values.Count -eq 0 ? @($null) : $_.values

                foreach ($value in $valueArr)
                {
                    [PSCustomObject] @{
                        Key = $key
                        Value = $value
                    }
                }
            } ).Where( { $_.Key } ) | Select-Object Key,Value -Unique

            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Only operator defined in AWS Console for SecretsManager listing is Contains operator, so defaulting
                # to '=' operator in Summary property below.
                $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.TrimEnd('.') + " while filtered by $($attributeKeyAndValueObjArr.Count) custom attribute$($attributeKeyAndValueObjArr.Count -eq 1 ? '' : 's') ($($attributeKeyAndValueObjArr.ForEach( { "$($_.Key)='$($_.Value)'" } ) -join ', '))."
            }

            # Potentially append additional optional values to temporary Uri array to add to current Signal's Url property.
            $uriArr = @()
            if ($attributeKeyAndValueObjArr.Count -gt 0)
            {
                # Add lookup attribute value(s) to Uri array (with minimal Url encoding).
                $uriArr += $attributeKeyAndValueObjArr.ForEach(
                {
                    # Map AWS Console dropdown values to Uri values for SecretsManager Uri.
                    $key = switch ($_.Key) {
                        'Name'               { 'name'                   }
                        'Description'        { 'description'            }
                        'Tag key'            { 'tag-key'                }
                        'Tag value'          { 'tag-value'              }
                        'Replicated secrets' { 'Replicated%2520secrets' }
                        'Managed by'         { 'owning-service'         }
                        default              { ConvertTo-MinimalUrlEncoded -InputObject $_ }
                    }
                    $operator = '%3D'
                    $value = ConvertTo-MinimalUrlEncoded -InputObject $_.Value

                    # Return current concatenated Uri result.
                    $key + $operator + $value
                } )
            }

            # To match SecretsManager specific ordering of filters in Uri, reorder by
            # alphabetical order giving precedence to upper-case alpha characters.
            $uriArr = [System.Array] `
                ($uriArr.Where( { $_[0] -cmatch    '[A-Z]' } ) | Sort-Object) + `
                ($uriArr.Where( { $_[0] -cnotmatch '[A-Z]' } ) | Sort-Object)

            # If Uri value(s) defined above then append to current Signal's Url property.
            if ($uriArr.Count -gt 0)
            {
                $AnchorEvent.Enrichment.Signal.Url += '&search=' + ($uriArr -join '%26')
            }    

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                attributeKeyAndValueObjArr = $attributeKeyAndValueObjArr
            }
        }
        ([LabelType]::SecretsManager_Secrets_Create_Step4) {
            $secretArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:CreateSecret' } )[0].Event.responseElements.arn
            $secretName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:CreateSecret' } )[0].Event.requestParameters.name

            # Substitute secretArn and secretName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{secretArn}}',$secretArn).Replace('{{secretName}}',$secretName)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                secretArn = $secretArn
                secretName = $secretName
            }
        }
        ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion) {
            $secretArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:RestoreSecret' } )[0].Event.requestParameters.secretId
            $secretName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:RestoreSecret' } )[0].Event.requestParameters.secretId -creplace '^.*?:secret:','' -creplace '-[A-Za-z0-9]+',''

            # Substitute secretArn and secretName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{secretArn}}',$secretArn).Replace('{{secretName}}',$secretName)

            # Substitute secretName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{secretName}}',(ConvertTo-MinimalUrlEncoded -InputObject $secretName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                secretArn = $secretArn
                secretName = $secretName
            }
        }
        ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Delete) {
            $secretArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:DescribeSecret' } )[0].Event.requestParameters.secretId
            $secretName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:DeleteSecret' } )[0].Event.requestParameters.secretId -creplace '^.*?:secret:','' -creplace '-[A-Za-z0-9]+',''
            $deletionDate = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:DeleteSecret' } )[0].Event.responseElements.deletionDate
            $recoveryWindowInDays = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:DeleteSecret' } )[0].Event.requestParameters.recoveryWindowInDays

            # Substitute secretArn, secretName, deletionDate and recoveryWindowInDays value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{secretArn}}',$secretArn).Replace('{{secretName}}',$secretName).Replace('{{deletionDate}}',$deletionDate).Replace('{{recoveryWindowInDays}}',"$recoveryWindowInDays day$($recoveryWindowInDays -cne '1' ? 's' : '')")

            # Substitute secretName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{secretName}}',(ConvertTo-MinimalUrlEncoded -InputObject $secretName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                secretArn = $secretArn
                secretName = $secretName
                deletionDate = $deletionDate
                recoveryWindowInDays = $recoveryWindowInDays
            }
        }
        ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview) {
            $secretArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:GetResourcePolicy' } )[0].Event.requestParameters.secretId
            $secretName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:DescribeSecret' } )[0].Event.requestParameters.secretId -creplace '^.*?:secret:','' -creplace '-[A-Za-z0-9]+',''

            # Substitute secretArn and secretName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{secretArn}}',$secretArn).Replace('{{secretName}}',$secretName)

            # Substitute secretName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{secretName}}',(ConvertTo-MinimalUrlEncoded -InputObject $secretName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                secretArn = $secretArn
                secretName = $secretName
            }
        }
        ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Overview_RetrieveSecretValue) {
            $secretArn = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:GetSecretValue' } )[0].Event.requestParameters.secretId
            $secretName = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'secretsmanager:GetSecretValue' } )[0].Event.requestParameters.secretId -creplace '^.*?:secret:','' -creplace '-[A-Za-z0-9]+',''

            # Substitute secretArn and secretName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{secretArn}}',$secretArn).Replace('{{secretName}}',$secretName)

            # Substitute secretName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{secretName}}',(ConvertTo-MinimalUrlEncoded -InputObject $secretName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                secretArn = $secretArn
                secretName = $secretName
            }
        }
        ([LabelType]::SecretsManager_Secrets_SPECIFICSECRET_Versions) {
            $secretArn = $AnchorEvent.Event.requestParameters.secretId
            $secretName = $AnchorEvent.Event.requestParameters.secretId -creplace '^.*?:secret:','' -creplace '-[A-Za-z0-9]+',''

            # Substitute secretArn and secretNameexit value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{secretArn}}',$secretArn).Replace('{{secretName}}',$secretName)

            # Substitute secretName value placeholder (with minimal Url encoding) in current Signal's Url property.
            $AnchorEvent.Enrichment.Signal.Url = $AnchorEvent.Enrichment.Signal.Url.Replace('{{secretName}}',(ConvertTo-MinimalUrlEncoded -InputObject $secretName))

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                secretArn = $secretArn
                secretName = $secretName
            }
        }
        ([LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step1B) {
            $vpcId = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:DescribeSubnets' } )[0].Event.requestParameters.filterSet.items.valueSet.items.value.Where( { $_.StartsWith('vpc-') } )[0]

            # Substitute vpcId value placeholder in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{vpcId}}',$vpcId)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                vpcId = $vpcId
            }
        }
        ([LabelType]::VPC_VirtualPrivateCloud_Endpoints_CreateEndpoint_Step2) {
            $createVpcEndpointEventArr = $RelatedEvents.Where( { $_.Enrichment.EventNameFull -ceq 'ec2:CreateVpcEndpoint' } )[0]
            $vpcId = $createVpcEndpointEventArr.Event.responseElements.CreateVpcEndpointResponse.vpcEndpoint.vpcId
            $vpcEndpointId = $createVpcEndpointEventArr.Event.responseElements.CreateVpcEndpointResponse.vpcEndpoint.vpcEndpointId
            $vpcName = $createVpcEndpointEventArr.Event.responseElements.CreateVpcEndpointResponse.vpcEndpoint.tagSet.item.Where( { $_.key -ceq 'Name' } )[0].value
            $serviceName = $createVpcEndpointEventArr.Event.responseElements.CreateVpcEndpointResponse.vpcEndpoint.serviceName

            # Substitute vpcEndpointId, vpcName and serviceName value placeholders in current Signal's Summary property.
            $AnchorEvent.Enrichment.Signal.Summary = $AnchorEvent.Enrichment.Signal.Summary.Replace('{{vpcEndpointId}}',$vpcEndpointId).Replace('{{vpcName}}',$vpcName).Replace('{{serviceName}}',$serviceName)

            # Store extracted value(s) in current Signal's AdditionalData property for later retrieval.
            $AnchorEvent.Enrichment.Signal.AdditionalData = @{
                vpcId = $vpcId
                vpcEndpointId = $vpcEndpointId
                vpcName = $vpcName
                serviceName = $serviceName
            }
        }
        default {
            # Do nothing if current instance of Signal object is simple, i.e. not configured
            # to perform any substitutions or modifications to its properties.
        }
    }

    # Output warning message if current Signal Summary contains a placeholder string not
    # properly replaced in above logic.
    if ($AnchorEvent.Enrichment.Signal.Summary.Contains('{{'))
    {
        # Extract all remaining placeholder values in current Signal Summary.
        $summaryTemp = $AnchorEvent.Enrichment.Signal.Summary
        $placeholderArr = @(while ($summaryTemp -cmatch '\{\{[^}]+\}\}')
        {
            # Return current placeholder string and remove it from temporary Summary value.
            $matches[0]
            $summaryTemp = $summaryTemp.Replace($matches[0],'')
        })

        Write-Warning "[$($MyInvocation.MyCommand.Name)] Summary property for [LabelType]::$Label'$(([System.String] $Label).EndsWith('s') ? '' : 's') Signal contains $($placeholderArr.Count) placeholder value$($placeholderArr.Count -eq 1 ? '' : 's') ($(($placeholderArr.ForEach( { "'$_'" } ) -join ','))) that $($placeholderArr.Count -eq 1 ? 'was' : 'were') not properly substituted: $($AnchorEvent.Enrichment.Signal.Summary)"
    }

    # Output warning message if current Signal Summary contains a placeholder string replaced
    # by a null value in above logic.
    if ($AnchorEvent.Enrichment.Signal.Summary.Contains("''"))
    {
        # Calculate count of placeholder strings in current Signal Summary replaced by a null value.
        $placeholderCount = $AnchorEvent.Enrichment.Signal.Summary.Split("''").Count - 1

        Write-Warning "[$($MyInvocation.MyCommand.Name)] Summary property for [LabelType]::$Label'$(([System.String] $Label).EndsWith('s') ? '' : 's') Signal contains $placeholderCount placeholder value$($placeholderCount -eq 1 ? '' : 's') substituted with a null value: $($AnchorEvent.Enrichment.Signal.Summary)"
    }

    # Return final Enrichment object added to input AnchorEvent.
    $AnchorEvent.Enrichment
}