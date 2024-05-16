function Out-SortedHashtable
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Out-SortedHashtable
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-SortedHashtable outputs ordered key-value pairs from input hashtable for accurate comparisons in unit tests.

.PARAMETER InputObject

Specifies input hashtable or nested hashtable to order and output for accurate comparisons in unit tests.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Select-Object -First 1 | ForEach-Object { $_.Event } | Out-SortedHashtable

Name                           Value
----                           -----
awsRegion                      us-east-1
errorCode                      
errorMessage                   
eventID                        2df05a9f-0f79-42d3-b5d5-f5cc6c312fb1
eventName                      GetSigninToken
eventSource                    signin.amazonaws.com
eventTime                      4/13/2024 5:11:21AM
requestParameters              
responseElements               {System.Collections.Hashtable, System.Collections.Hashtable}
userAgent                      Jersey/${project.version} (HttpUrlConnection 11.0.22)

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of Event formats allowed.
        [AllowNull()]
        $InputObject
    )

    begin
    {

    }

    process
    {
        # If input object is a Hashtable, enumerate and return all items after recursively sorting by key.
        # Otherwise return input object as-is if not a Hashtable.
        if ($InputObject -is [System.Collections.Hashtable])
        {
            foreach ($curInputObject in $InputObject.GetEnumerator() | Sort-Object Key)
            {
                @{ $curInputObject.Key = ($curInputObject.Value -is [System.Collections.Hashtable] ? (Out-SortedHashtable -InputObject $curInputObject.Value) : $curInputObject.Value) }
            }
        }
        else
        {
            $InputObject
        }
    }

    end
    {

    }
}



function Out-SignalSummary
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Out-SignalSummary
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-SignalSummary generates Signal summary format by grouping all events contributing to each Signal generation to enable precise unit testing.

.PARAMETER Event

Specifies enriched events (i.e. with Labels and potential Signals added via Add-Signal function) for which to generate Signal summary.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Out-SignalSummary

Name                           Value
----                           -----
dfa75df4-e3a1-45f4-a844-95fff… {CorrelationId, Name, Url, EventCount…}
22a1f210-9d0a-4139-a558-f6326… {CorrelationId, Name, Url, EventCount…}
5f8f0dc8-14ea-43fa-8d2d-c49ea… {CorrelationId, Name, Url, EventCount…}
13a644b6-7924-40c4-b0b7-39c98… {CorrelationId, Name, Url, EventCount…}
05e0bb10-4360-4996-adac-55535… {CorrelationId, Name, Url, EventCount…}
d1fead08-1fa9-4528-942c-c11a4… {CorrelationId, Name, Url, EventCount…}
4d9dde9d-dfa2-41a5-8645-6deda… {CorrelationId, Name, Url, EventCount…}
2df05a9f-0f79-42d3-b5d5-f5cc6… {CorrelationId, Name, Url, EventCount…}
11944b2a-d4a9-4bba-a893-ea729… {CorrelationId, Name, Url, EventCount…}
aab96040-78e0-4316-a354-3ab10… {CorrelationId, Name, Url, EventCount…}
2cb9218b-8f36-43e5-8eaa-bae9e… {CorrelationId, Name, Url, EventCount…}
1a57b169-c7d0-42d4-b7e1-bb34f… {CorrelationId, Name, Url, EventCount…}
e421fc9a-5761-4c65-9960-8f21f… {CorrelationId, Name, Url, EventCount…}
ee155c6e-24c7-4929-8ab8-b2630… {CorrelationId, Name, Url, EventCount…}
86df6177-ff0b-4b99-87d3-d1b4e… {CorrelationId, Name, Url, EventCount…}
23606e64-2799-41d7-8249-015cc… {CorrelationId, Name, Url, EventCount…}
1be4c190-b63c-4830-b8e7-a1bd5… {CorrelationId, Name, Url, EventCount…}
23d0aff7-4fae-49c4-be70-ef5bc… {CorrelationId, Name, Url, EventCount…}
3ee99b7a-df6b-499b-b7fb-ad15e… {CorrelationId, Name, Url, EventCount…}
09f4444a-a696-4b9a-be31-11f55… {CorrelationId, Name, Url, EventCount…}
9e0182c8-8c7b-461f-93db-830bf… {CorrelationId, Name, Url, EventCount…}
5a4d4e18-f690-41c3-b397-b6c9f… {CorrelationId, Name, Url, EventCount…}
2176b388-eafb-45cb-896c-05609… {CorrelationId, Name, Url, EventCount…}
58c94d96-7ab2-4520-b2dc-a4d7f… {CorrelationId, Name, Url, EventCount…}
a6ff1b28-54db-48d9-91c3-b90ee… {CorrelationId, Name, Url, EventCount…}
7be28003-5170-431f-b2e6-8d706… {CorrelationId, Name, Url, EventCount…}
3b84fbb3-32eb-4344-a826-2b277… {CorrelationId, Name, Url, EventCount…}
092c2523-7bee-463a-9295-875e7… {CorrelationId, Name, Url, EventCount…}
5972f294-7900-45ae-91b0-48c47… {CorrelationId, Name, Url, EventCount…}
f28bc29e-13ed-492e-98f5-d31d4… {CorrelationId, Name, Url, EventCount…}
16e2bb59-b83c-48e6-afce-aff61… {CorrelationId, Name, Url, EventCount…}
970e4399-78d6-4fc0-9b74-9ab18… {CorrelationId, Name, Url, EventCount…}
03863fdf-4d24-4bb0-81cc-d9518… {CorrelationId, Name, Url, EventCount…}
428e4e83-8094-40ff-9e4b-e10a8… {CorrelationId, Name, Url, EventCount…}
4743d783-4f24-490e-988a-34d6d… {CorrelationId, Name, Url, EventCount…}
0db021c3-1a43-4457-9054-bc8de… {CorrelationId, Name, Url, EventCount…}
07352bda-7c22-4e72-a7d8-7270d… {CorrelationId, Name, Url, EventCount…}
8df74d48-d608-4352-890c-bcc86… {CorrelationId, Name, Url, EventCount…}
13d607c0-f266-40ba-a065-4ec24… {CorrelationId, Name, Url, EventCount…}
297ccc8e-fb76-42ae-aaa3-727bf… {CorrelationId, Name, Url, EventCount…}

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $Event
    )

    begin
    {
        # Define Dictionary to store all Signal summary objects extracted from input events.
        $signalObjDict = @{ }

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
        # Query all events contributing to produce a Signal object and group on CorrelationId
        # (the eventId of the anchor event).
        $eventObjArrGroupedByCorrelationId = $eventArr.Where( { $_.Enrichment.IsSignalContributor } ) `
            | Select-Object -Property `
                @{ name = 'CorrelationId'; expr = { $_.Enrichment.CorrelationId } },
                @{ name = 'EventID'      ; expr = { $_.Event.eventID            } },
                @{ name = 'EventNameFull'; expr = { $_.Enrichment.EventNameFull } } `
            | Group-Object -Property CorrelationId

        # Define single Hashtable to store EventId and EventNameFull summaries for each CorrelationId grouping.
        $eventSummaryHashtable = @{ }
        $eventObjArrGroupedByCorrelationId.ForEach(
        {
            $correlationId = $_.Name

            # Define single PSCustomObject to store EventId and EventNameFull summaries for current CorrelationId.
            $signalSummaryObj = [PSCustomObject] @{
                CorrelationId       = $correlationId
                EventIdArrStr       = $_.Group.EventId -join ','
                EventNameFullArrStr = ($_.Group.EventNameFull | Select-Object -Unique) -join ','
            }

            # Add above Signal summary object to event summary Hashtable.
            $eventSummaryHashtable.Add($correlationId,$signalSummaryObj)
        } )

        # Extract subset of properties from each event containing a Signal object.
        # This will be the first anchor event in each multi-event grouping that produces a Signal object.
        $eventArr.Where( { $_.Enrichment.Signal } ).ForEach(
        {
            $signalDict = @{
                Label          = [System.String] $_.Enrichment.Signal.Label
                Name           = $_.Enrichment.Signal.Name
                Url            = $_.Enrichment.Signal.Url
                Summary        = $_.Enrichment.Signal.Summary
                AdditionalData = $_.Enrichment.Signal.AdditionalData
                FirstEventTime = $_.Enrichment.FirstEventTime
                LastEventTime  = $_.Enrichment.LastEventTime
                CorrelationId  = $_.Enrichment.CorrelationId
                EventCount     = $_.Enrichment.EventCount
                AllEventArr    = $eventSummaryHashtable[$_.Enrichment.CorrelationId].EventNameFullArrStr
                AllEventIdArr  = $eventSummaryHashtable[$_.Enrichment.CorrelationId].EventIdArrStr
            }

            # Add current Signal summary to final Dictionary for more efficient lookups.
            $signalObjDict.Add($signalDict.CorrelationId,$signalDict)
        } )

        # Return final Dictionary containing all Signal summary objects extracted from input event objects.
        $signalObjDict
    }
}



function Out-MinimizedEvent
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Out-MinimizedEvent
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Format-EventObject
Optional Dependencies: None

.DESCRIPTION

Out-MinimizedEvent minimizes input events by removing all unnecessary properties for more efficient storage of sessions (e.g. for unit test purposes).

.PARAMETER Event

Specifies events for which to minimize by removing all unnecessary properties.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Out-MinimizedEvent | Select-Object -First 2

eventTime         : 4/13/2024 5:11:21AM
eventID           : 2df05a9f-0f79-42d3-b5d5-f5cc6c312fb1
eventSource       : signin.amazonaws.com
eventName         : GetSigninToken
requestParameters : 
responseElements  : {GetSigninToken, credentials}
errorCode         : 
errorMessage      : 
userAgent         : Jersey/${project.version} (HttpUrlConnection 11.0.22)
awsRegion         : us-east-1

eventTime         : 4/13/2024 5:11:23AM
eventID           : 45e81da9-0c13-4d01-b818-eba1513be8b0
eventSource       : signin.amazonaws.com
eventName         : ConsoleLogin
requestParameters : 
responseElements  : {ConsoleLogin}
errorCode         : 
errorMessage      : 
userAgent         : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0
awsRegion         : us-east-1

.EXAMPLE

PS C:\> aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 | Out-MinimizedEvent | Select-Object -First 2

eventTime         : 4/13/2024 5:11:21AM
eventID           : 2df05a9f-0f79-42d3-b5d5-f5cc6c312fb1
eventSource       : signin.amazonaws.com
eventName         : GetSigninToken
requestParameters : 
responseElements  : {GetSigninToken, credentials}
errorCode         : 
errorMessage      : 
userAgent         : Jersey/${project.version} (HttpUrlConnection 11.0.22)
awsRegion         : us-east-1

eventTime         : 4/13/2024 5:11:23AM
eventID           : 45e81da9-0c13-4d01-b818-eba1513be8b0
eventSource       : signin.amazonaws.com
eventName         : ConsoleLogin
requestParameters : 
responseElements  : {ConsoleLogin}
errorCode         : 
errorMessage      : 
userAgent         : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0
awsRegion         : us-east-1

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
        $Event
    )

    begin
    {
        # Define subset of properties for minimization for storage efficiency purposes.
        $minimizedPropArr = @('eventTime','eventID','eventSource','eventName','requestParameters','responseElements','errorCode','errorMessage','userAgent','awsRegion')

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

        # Filter input events to minimized subset of properties used in Add-Signal functions
        # for storage efficiency purposes in unit test process.
        $minimizedEventArr = $eventArr | Select-Object $minimizedPropArr

        # Return final result.
        $minimizedEventArr
    }
}



function New-UnitTest
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: New-UnitTest
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Format-EventObject, Out-MinimizedEvent, Add-Signal, Out-SignalSummary
Optional Dependencies: Get-StringHash

.DESCRIPTION

New-UnitTest generates necessary unit test files by converting input events to minimized event file and expected Signal summary file in a new folder in ./Tests/Sessions/ to be included in Pester unit test invocations (e.g. Invoke-Pester -TagFilter FullEvent).

.PARAMETER Event

Specifies events for which to generate necessary unit test files.

.PARAMETER Force

(Optional) Specifies that prompt be skipped if overwriting existing unit test files.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | New-UnitTest -Verbose

VERBOSE: [+] Creating directory for sessionId: /Users/krileva/Projects/CloudConsoleCartographer-main/Tests/Sessions/654a03c3b2ca8995712ec4064676170f23b7f96ced6b9e9f9c89a120465b6026
VERBOSE: [+] Writing minimized event array to: /Users/krileva/Projects/CloudConsoleCartographer-main/Tests/Sessions/654a03c3b2ca8995712ec4064676170f23b7f96ced6b9e9f9c89a120465b6026/InputEvents.json
VERBOSE: [+] Writing Signal summary results object to: /Users/krileva/Projects/CloudConsoleCartographer-main/Tests/Sessions/654a03c3b2ca8995712ec4064676170f23b7f96ced6b9e9f9c89a120465b6026/ExpectedSignals.json

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
        $Force
    )

    begin
    {
        # Create ArrayList to store all pipelined input Events before beginning final processing.
        $eventArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Create Boolean to capture if current invocation is recursive.
        $isRecursive = $MyInvocation.MyCommand.Name -eq (Get-Variable -Scope 1 -Name MyInvocation -ValueOnly).MyCommand.Name ? $true : $false

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
        elseif ($Event -is [System.IO.FileInfo] -and -not $isRecursive)
        {
            # If input is file then recursively invoke function for current file.
            $optionalParameters = $PSBoundParameters['Force'].IsPresent ? @{ 'Force' = $true } : @{ }
            New-UnitTest -Event $Event @optionalParameters
        }
        else
        {
            # Add single -Event object to ArrayList.
            $eventArr.Add($Event) | Out-Null
        }
    }

    end
    {
        # Return if no events are input (e.g. if after recursive call for input file name).
        if ($eventArr.Count -eq 0)
        {
            return
        }

        # Capture full file path if input was file path instead of raw events.
        # This will be used to potentially extract session ID if present in file path.
        $inputFilePath = $eventArr.Count -eq 1 -and $eventArr[0] -is [System.IO.FileInfo] ? $eventArr[0] : $null

        # Ensure input events are parsed and formatted correctly regardless of input format.
        $eventArr = Format-EventObject -InputObject $eventArr

        # Ensure input events are sorted by eventTime property.
        $eventArr = $eventArr | Sort-Object -Property eventTime

        # Minimize input events to subset of properties used in Add-Signal functions for
        # storage efficiency purposes in unit test process.
        $minimizedEventArr = Out-MinimizedEvent -Event $eventArr

        # Extract session ID if present in input file path.
        # Otherwise generate session ID as SHA256 hash of formatted session events.
        if ($inputFilePath -imatch '[^a-f0-9](?<sessionId>[a-f0-9]{64})[^a-f0-9]')
        {
            $sessionId = $Matches['sessionId'].ToLower()
        }
        else
        {
            $sessionId = (Get-StringHash -InputObject ($minimizedEventArr -join "`n") -Algorithm SHA256).Hash.ToLower()
        }

        # Retrieve current directory of script location (regardless of CWD during execution)
        # and define test directory for current sessionId.
        $scriptDir = Split-Path -Parent $PSCommandPath
        $sessionPath = Join-Path -Path $scriptDir -ChildPath 'Sessions'
        $curSessionPath = Join-Path -Path $sessionPath -ChildPath $sessionId

        # Create directory for current session if not already present.
        if (-not (Test-Path $curSessionPath))
        {
            Write-Verbose "[+] Creating directory for sessionId: $curSessionPath"
            New-Item -ItemType Directory -Path $curSessionPath | Out-Null
        }

        # Write out minimized event(s) to test session directory if not already present.
        # Overwrite file if user input -Force switch parameter is defined or if interactive
        # prompt is successfully defined.
        $minimizedEventPath = Join-Path -Path $curSessionPath -ChildPath 'InputEvents.json'
        if (-not (Test-Path -Path $minimizedEventPath) -or $PSBoundParameters['Force'].IsPresent -or (Read-Host "Enter 'Y' or 'YES' (or re-run with '-Force' parameter defined) to overwrite $minimizedEventPath") -iin @('Y','YES'))
        {
            # Write out minimized event(s) to test session directory.
            Write-Verbose "[+] Writing minimized event array to: $minimizedEventPath"
            Set-Content -Path $minimizedEventPath -Value ($minimizedEventArr | ConvertTo-Json -Depth 25)
        }
        else
        {
            Write-Host '[*] Skipped writing minimized event array to: ' -NoNewline -ForegroundColor Cyan
            Write-Host $minimizedEventPath -ForegroundColor Yellow
        }

        # Write out Signal summary result(s) to test session directory if not already present.
        # Overwrite file if user input -Force switch parameter is defined or if interactive
        # prompt is successfully defined.
        $signalEventPath = Join-Path -Path $curSessionPath -ChildPath 'ExpectedSignals.json'
        if (-not (Test-Path -Path $signalEventPath) -or $PSBoundParameters['Force'].IsPresent -or (Read-Host "Enter 'Y' or 'YES' (or re-run with '-Force' parameter defined) to overwrite $signalEventPath") -iin @('Y','YES'))
        {
            # Perform Signal evaluation for input raw events.
            $eventObjArr = Add-Signal -Event $eventArr

            # Convert all Signals into a single Dictionary containing summaries of each Signal
            # along with all potential contributing events.
            $signalObjDict = Out-SignalSummary -Event $eventObjArr

            # Write out Signal summary result(s) to test session directory.
            Write-Verbose "[+] Writing Signal summary results object to: $signalEventPath`n"
            Set-Content -Path $signalEventPath -Value ($signalObjDict | ConvertTo-Json -Depth 25)
        }
        else
        {
            Write-Host '[*] Skipped writing Signal summary results object to: ' -NoNewline -ForegroundColor Cyan
            Write-Host $signalEventPath -ForegroundColor Yellow
        }
    }
}