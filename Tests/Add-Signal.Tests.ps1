BeforeAll {
    Import-Module ./CloudConsoleCartographer.psd1
}

Describe 'Add-Signal' {
    # Retrieve current directory of script location (regardless of CWD during execution) and define Sessions directory.
    $scriptDir = Split-Path -Parent $PSCommandPath
    $sessionDir = Join-Path -Path $scriptDir -ChildPath 'Sessions'

    # Extract sessionId values from directory names to be filterable via user input -TagFilter value(s).
    $testSessionObjArr = (Get-ChildItem $sessionDir).Where( { $_.Name -cmatch '^[a-f0-9]{64}$' } ).ForEach(
    {
        $sessionId = $_.Name
        @{
            SessionId = $sessionId
            CurSessionPath =  Join-Path -Path $sessionDir -ChildPath $sessionId
        }
    } )

    # Iterate over each test session.
    Context 'SessionId=<SessionId>' -ForEach $testSessionObjArr -Tag $_.SessionId {
        # Perform Signal evaluation for input raw events.
        $eventObjArr = Get-ChildItem -Path (Join-Path -Path $_.CurSessionPath -ChildPath 'InputEvents.json') | Add-Signal

        # Convert all Signals into a single Dictionary containing summaries of each Signal along with all potential contributing events.
        # Perform JSON conversion as Hashtable to match key ordering of expected Signal results.
        $signalObjDict = Out-SignalSummary -Event $eventObjArr | ConvertTo-Json -Depth 25 | ConvertFrom-Json -Depth 25 -AsHashtable

        # Import expected Signal results.
        $expectedSignalObjHashtable = Get-Content -Path (Join-Path -Path $_.CurSessionPath -ChildPath 'ExpectedSignals.json') | ConvertFrom-Json -Depth 25 -AsHashtable

        # Retrieve time-sorted array of CorrelationId values from expected Signal results.
        $expectedCorrelationIdArr = ($expectedSignalObjHashtable.Values | Sort-Object FirstEventTime).CorrelationId 

        # Generate array of test case objects from expected Signal results for below Context's -ForEach parameter.
        $testCaseObjArr = $expectedCorrelationIdArr.ForEach( { @{ CorrelationId = $_; Label = $expectedSignalObjHashtable.$_.Label } } )

        Context 'CorrelationId=<CorrelationId> Label=<Label>' -ForEach $testCaseObjArr -Tag $_.SessionId,$_.CorrelationId,$_.Label,$_.Prop {
            It 'Checks full Signal result as a whole for CorrelationId=<CorrelationId> Label=<Label>' -Tag $_.SessionId,$_.CorrelationId,$_.Label,'FullEvent' {
                # Ensure consistent ordering of keys in input and expected Signal results for accurate comparison
                # before converting to JSON string for simplified evaluation of nested objects.
                $inputSignal    =              $signalObjDict.($_.CorrelationId) | Out-SortedHashtable | ConvertTo-Json -Depth 25 -Compress
                $expectedSignal = $expectedSignalObjHashtable.($_.CorrelationId) | Out-SortedHashtable | ConvertTo-Json -Depth 25 -Compress

                $inputSignal | Should -BeExactly $expectedSignal
            }

            # Extract array of property names and convert to array of Hashtables for -Tag parameter in next It block.
            $expectedPropObjArr = $expectedSignalObjHashtable.($_.CorrelationId).Keys.ForEach( { @{ Prop = $_; CorrelationId = $CorrelationId } } )

            It 'Prop=<Prop>' -ForEach $expectedPropObjArr -Tag $_.SessionId,$CorrelationId,$Label,$_.Prop,'FullEventPerProperty' {
                # Ensure consistent ordering of keys in input and expected Signal results for current property for
                # accurate comparison before converting to JSON string for simplified evaluation of nested objects.
                $inputSignalCurProp    =              $signalObjDict.($_.CorrelationId).($_.Prop) | Out-SortedHashtable | ConvertTo-Json -Depth 25 -Compress
                $expectedSignalCurProp = $expectedSignalObjHashtable.($_.CorrelationId).($_.Prop) | Out-SortedHashtable | ConvertTo-Json -Depth 25 -Compress

                $inputSignalCurProp | Should -BeExactly $expectedSignalCurProp
            }

            Context 'Prop=<Prop>' -ForEach $expectedPropObjArr -Tag $_.SessionId,$CorrelationId,$Label,$_.Prop,'PerEventProperty' {
                It 'Prop=<Prop>' -Tag $SessionId,$CorrelationId,$Label,$_.Prop {
                    # Ensure consistent ordering of keys in input and expected Signal results for current property for
                    # accurate comparison before converting to JSON string for simplified evaluation of nested objects.
                    $inputSignalCurProp    =              $signalObjDict.($_.CorrelationId).($_.Prop) | Out-SortedHashtable | ConvertTo-Json -Depth 25 -Compress
                    $expectedSignalCurProp = $expectedSignalObjHashtable.($_.CorrelationId).($_.Prop) | Out-SortedHashtable | ConvertTo-Json -Depth 25 -Compress

                    $inputSignalCurProp | Should -BeExactly $expectedSignalCurProp
                }
            }
        }
    }
}