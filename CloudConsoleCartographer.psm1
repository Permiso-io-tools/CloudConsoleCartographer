#   This file is part of Cloud Console Cartographer.
#
#   Copyright 2024 Permiso Security <https://permiso.io>
#         Andi Ahmeti <@SecEagleAnd1>
#         Daniel Bohannon <@danielhbohannon>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



# Retrieve current directory of script location (regardless of CWD during execution).
$scriptDir = Split-Path -Parent $PSCommandPath

# Set default parameter value for Invoke-Pester cmdlet's -TagFilter input parameter
# to the most efficient version of the unit test.
$PSDefaultParameterValues = @{ 'Invoke-Pester:TagFilter' = 'FullEvent' }



# Import additional functions intentionally left in separate files for easier
# additions of new rules and tuning existing rules.
Import-Module $scriptDir/Code/SignalDefinitions.ps1
Import-Module $scriptDir/Code/AddLabel.ps1
Import-Module $scriptDir/Code/NewSignal.ps1
Import-Module $scriptDir/Code/AddSignal.ps1



function Show-AsciiArt
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Show-AsciiArt
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-AsciiArt displays ASCII art title banner for Cloud Console Cartographer.

.EXAMPLE

C:\PS> Show-AsciiArt

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param ()

    # Define output foreground colors for multi-colored ASCII art title banner below.
    $colorObj = [PSCustomObject] @{
        Default   = [System.ConsoleColor]::Grey
        Primary   = [System.ConsoleColor]::Magenta
        Secondary = [System.ConsoleColor]::Green
        Map       = [System.ConsoleColor]::Yellow
        Direction = [System.ConsoleColor]::DarkRed
        Cloud     = [System.ConsoleColor]::Cyan
        Permiso   = [System.ConsoleColor]::Blue
    }

    # Create ASCII art title banner.
    # Credit (Title): https://patorjk.com/software/taag-v1/
    # Credit (Scroll): https://ascii.co.uk/art/scroll
    $padding = '    '
    $cloudConsoleCartographerAscii = @'
  _________                                                     
 / ________|           _                     .-------------,    
| | | |               | |                   /     N      /_)    
| | | | ___  _   _  __| |                  |     /\     |       
| | | |/ _ \| | | |/ _` |                  | W <(  )> E |_      
| | | | (_) | |_| | (_| |  _              _|     \/     | )__   
| | |_|\___/ \__,_|\__,_| | |          __( |      S     |__  )_ 
| |   ___  _ __  ___  ___ | | ___    _(     \____________\_)   )
| |  / _ \| '_ \/ __|/ _ \| |/ _ \  (__________________________)
| | | (_) | | | \__ \ (_) | |  __/              _               
| |  \___/|_| |_|___/\___/|_|\___|             | |              
| |   __ _ _ __| |_  ___   __ _ _ __ __ _ _ __ | |__   ___ _ __ 
| |  / _` | '__| __|/ _ \ / _` | '__/ _` | '_ \| '_ \ / _ \ '__|
| | | (_| | |  | |_| (_) | (_| | | | (_| | |_) | | | |  __/ |   
| |  \__,_|_|   \__|\___/ \__, |_|  \__,_| .__/|_| |_|\___|_|   
| |________                __/ |         | |                    
 \_________|              |___/          |_|                    

       __  ___ __     . __   __     __  __             __  __   
      |__)|__ |__)|\/||/__` /  \   |__)/ /\   |    /\ |__)/__`  
FROM: |   |___|  \|  ||.__/ \__/   |   \/_/   |___/~~\|__).__/  
'@.Split("`n").ForEach( { $padding + $_ } )

    # Create array of index objects for color-coding above ASCII art title banner.
    $indexObj = [PSCustomObject] @{
        0 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 12; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart = 12; Length = 52; ForegroundColor = $colorObj.Secondary }
        )
        1 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 12; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart = 12; Length = 30; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 42; Length = 22; ForegroundColor = $colorObj.Map       }
        )
        2 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 39; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 42; Length =  8; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 50; Length =  1; ForegroundColor = $colorObj.Direction }
            [PSCustomObject] @{ IndexStart = 51; Length = 13; ForegroundColor = $colorObj.Map       }
        )
        3 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 38; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 41; Length = 23; ForegroundColor = $colorObj.Map       }
        )
        4 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 40; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 43; Length =  2; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 45; Length =  1; ForegroundColor = $colorObj.Direction }
            [PSCustomObject] @{ IndexStart = 46; Length =  8; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 54; Length =  1; ForegroundColor = $colorObj.Direction }
            [PSCustomObject] @{ IndexStart = 55; Length =  2; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 57; Length =  7; ForegroundColor = $colorObj.Cloud     }
        )
        5 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 39; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 42; Length =  1; ForegroundColor = $colorObj.Cloud     }
            [PSCustomObject] @{ IndexStart = 43; Length = 14; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 57; Length =  7; ForegroundColor = $colorObj.Cloud     }
        )
        6 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 36; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 39; Length =  4; ForegroundColor = $colorObj.Cloud     }
            [PSCustomObject] @{ IndexStart = 43; Length =  7; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 50; Length =  1; ForegroundColor = $colorObj.Direction }
            [PSCustomObject] @{ IndexStart = 51; Length =  8; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 59; Length =  5; ForegroundColor = $colorObj.Cloud     }
        )
        7 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 34; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 37; Length =  6; ForegroundColor = $colorObj.Cloud     }
            [PSCustomObject] @{ IndexStart = 43; Length = 17; ForegroundColor = $colorObj.Map       }
            [PSCustomObject] @{ IndexStart = 60; Length =  4; ForegroundColor = $colorObj.Cloud     }
        )
        8 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 33; ForegroundColor = $colorObj.Secondary }
            [PSCustomObject] @{ IndexStart = 36; Length = 28; ForegroundColor = $colorObj.Cloud     }
        )
        9 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 61; ForegroundColor = $colorObj.Secondary }
        )
        10 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 61; ForegroundColor = $colorObj.Secondary }
        )
        11 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 61; ForegroundColor = $colorObj.Secondary }
        )
        12 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 61; ForegroundColor = $colorObj.Secondary }
        )
        13 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 61; ForegroundColor = $colorObj.Secondary }
        )
        14 = @(
            [PSCustomObject] @{ IndexStart =  0; Length =  3; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart =  3; Length = 61; ForegroundColor = $colorObj.Secondary }
        )
        15 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 12; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart = 12; Length = 52; ForegroundColor = $colorObj.Secondary }
        )
        16 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 12; ForegroundColor = $colorObj.Primary   }
            [PSCustomObject] @{ IndexStart = 12; Length = 52; ForegroundColor = $colorObj.Secondary }
        )
        17 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 0; ForegroundColor = $colorObj.Default    }
        )
        18 = @(
            [PSCustomObject] @{ IndexStart = 0; Length =  5; ForegroundColor = $colorObj.Default    }
            [PSCustomObject] @{ IndexStart = 5; Length = 59; ForegroundColor = $colorObj.Permiso    }
        )
        19 = @(
            [PSCustomObject] @{ IndexStart = 0; Length =  5; ForegroundColor = $colorObj.Default    }
            [PSCustomObject] @{ IndexStart = 5; Length = 59; ForegroundColor = $colorObj.Permiso    }
        )
        20 = @(
            [PSCustomObject] @{ IndexStart = 0; Length =  5; ForegroundColor = $colorObj.Default    }
            [PSCustomObject] @{ IndexStart = 5; Length = 59; ForegroundColor = $colorObj.Permiso    }
        )
    }

    # Display ASCII art title banner based on previously defined array of index objects for color-coding.
    # Iterate over each line's array of index objects.
    foreach ($curLineIndex in $indexObj.PSObject.Properties.Name)
    {
        Write-Host $padding -NoNewline

        # Iterate over each substring index object for current line.
        foreach ($curLineIndexObj in $indexObj.$curLineIndex)
        {
            $optionalForegroundColor = $curLineIndexObj.ForegroundColor ? @{ ForegroundColor = $curLineIndexObj.ForegroundColor } : @{ }
            Write-Host $cloudConsoleCartographerAscii[$curLineIndex].Substring(($padding.Length + $curLineIndexObj.IndexStart),$curLineIndexObj.Length) -NoNewline @optionalForegroundColor
        }

        # Output newline after outputting all substrings for current line above.
        Write-Host '' 
    }

    # Output final newline after outputting all lines for ASCII art title banner.
    Write-Host '' 
}



# Output ASCII art once at beginning of module loading.
Show-AsciiArt



function Format-EventObject
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Format-EventObject
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Format-EventObject reads input file paths or file contents containing cloud logs and iteratively parses logs into flattened format.

.PARAMETER InputObject

Specifies cloud logs to be iteratively parsed into flattened format.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Format-EventObject | Select-Object -First 5 | Select-Object eventTime,eventSource,eventName,userAgent

eventTime           eventSource                              eventName              userAgent
---------           -----------                              ---------              ---------
4/13/2024 5:11:21AM signin.amazonaws.com                     GetSigninToken         Jersey/${project.version} (HttpUrlConnection 11.0.22)
4/13/2024 5:11:23AM signin.amazonaws.com                     ConsoleLogin           Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…
4/13/2024 5:11:29AM servicecatalog-appregistry.amazonaws.com ListApplications       Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…
4/13/2024 5:11:29AM ce.amazonaws.com                         GetCostAndUsage        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…
4/13/2024 5:11:29AM cost-optimization-hub.amazonaws.com      ListEnrollmentStatuses Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…

.EXAMPLE

PS C:\> cat ./Demo/InputEvents.json | Format-EventObject -Verbose | Select-Object -First 5 | Select-Object eventTime,eventSource,eventName,userAgent
[*] [00:00:00.1609061] Processed 1000 event(s)

eventTime           eventSource                              eventName              userAgent
---------           -----------                              ---------              ---------
4/13/2024 5:11:21AM signin.amazonaws.com                     GetSigninToken         Jersey/${project.version} (HttpUrlConnection 11.0.22)
4/13/2024 5:11:23AM signin.amazonaws.com                     ConsoleLogin           Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…
4/13/2024 5:11:29AM servicecatalog-appregistry.amazonaws.com ListApplications       Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…
4/13/2024 5:11:29AM ce.amazonaws.com                         GetCostAndUsage        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…
4/13/2024 5:11:29AM cost-optimization-hub.amazonaws.com      ListEnrollmentStatuses Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.…

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Collections.Hashtable[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of Event formats allowed.
        $InputObject
    )

    begin
    {
        # Set stopwatch to track elapsed time of event formatting in current function
        # if user input -Verbose switch parameter is defined.
        if ($PSBoundParameters['Verbose'].IsPresent)
        {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to ArrayList before beginning final processing.
        if ($InputObject.Count -gt 1)
        {
            # Add all -InputObject objects to ArrayList.
            if ($InputObject -is [System.Collections.Hashtable])
            {
                # Add single -InputObject Hashtable object to ArrayList.
                $inputObjectArr.Add($InputObject) | Out-Null
            }
            else
            {
                # Add all -InputObject objects to ArrayList.
                $inputObjectArr.AddRange($InputObject)
            }
        }
        else
        {
            # Add single -InputObject object to ArrayList.
            $inputObjectArr.Add($InputObject) | Out-Null
        }
    }

    end
    {
        # Iteratively unwrap nested input ArrayLists until non-ArrayList is extracted.
        # This scenario can occur from duplicative pipelining packaging from other functions.
        while (
            $inputObjectArr.Count -eq 1 -and `
            $inputObjectArr -is [System.Collections.ArrayList] -and `
            $inputObjectArr[0] -is [System.Collections.ArrayList]
        )
        {
            $inputObjectArr = $inputObjectArr[0]
        }

        # If input is array of strings (e.g. line-by-line raw JSON) then join into single string.
        if (($inputObjectArr.Count -gt 1) -and ($inputObjectArr[0] -is [System.String]))
        {
            $inputObjectArr = $inputObjectArr -join "`n"
        }

        # Format input into array of extracted and parsed events.
        $eventObjArr = @(foreach ($curInputObject in $inputObjectArr)
        {
            # Return current input object as-is and continue if an already-processed Hashtable
            # (e.g. if running previous function results through function again).
            if ($curInputObject.GetType().Name -ceq 'Hashtable')
            {
                $curInputObject

                continue
            }

            # Extract current input based on format type.
            $curInputObjectContent = switch ($curInputObject.GetType().Name)
            {
                'FileInfo' {
                    # Read in current file path content.
                    Get-Content -Path $executionContext.SessionState.Path.GetResolvedProviderPathFromProviderPath($curInputObject, 'FileSystem') -Raw
                }
                'String' {
                    # Return current content as-is.
                    $curInputObject
                }
                default {
                    Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled input format ('$($curInputObject.GetType().Name)') in switch block."

                    $curInputObject
                }
            }

            # Perform first layer of parsing for current input object content based on format type.
            try
            {
                # Attempt to convert input as JSON events, parsing as Hashtable to handle
                # scenarios where duplicate keys exist (differing only by case.)
                $json = $curInputObjectContent | ConvertFrom-Json -Depth 25 -AsHashtable
                $curInputObjectContent = $json
            }
            catch {
                try
                {
                    # If previous JSON conversion was unsuccessful then try CSV-with-
                    # -nested-JSON conversion, parsing as Hashtable to handle scenarios
                    # where duplicate keys exist (differing only by case.)
                    $json = ($curInputObjectContent | ConvertFrom-Csv).data | ConvertFrom-Json -Depth 25 -AsHashtable
                    $curInputObjectContent = $json
                }
                catch
                {
                    Write-Warning "[$($MyInvocation.MyCommand.Name)] Unknown format of input object (e.g. not JSON or CSV)."
                }
            }

            # Perform second layer of parsing for current input object content based on format type.
            if ($curInputObjectContent.Events.CloudTrailEvent)
            {
                # Attempt to convert nested JSON strings as JSON events, parsing as Hashtable
                # to handle scenarios where duplicate keys exist (differing only by case.)
                $curInputObjectContent = $curInputObjectContent.Events.CloudTrailEvent | ConvertFrom-Json -Depth 25 -AsHashtable
            }
            elseif ($curInputObjectContent.Records)
            {
                $curInputObjectContent = $curInputObjectContent.Records
            }
            elseif ($curInputObjectContent -is [System.Object[]] -and $curInputObjectContent[0] -is [System.Collections.Hashtable])
            {
                # Do nothing since already expected unit test formatting scenario.
            }
            else
            {
                Write-Warning "[$($MyInvocation.MyCommand.Name)] Unhandled nested event format with the following keys: $(($curInputObjectContent | Get-Member -MemberType NoteProperty).Name -join ', ')"
            }

            # Return current extracted and parsed array of events.
            $curInputObjectContent
        })

        # Output event processing statistics if user input -Verbose switch parameter is defined.
        if ($PSBoundParameters['Verbose'].IsPresent)
        {
            # Stop stopwatch and capture elapsed time of event formatting in current function.
            $stopwatch.stop()
            $elapsedTime = $stopwatch.Elapsed

            Write-Host '[*] ['            -NoNewline -ForegroundColor Cyan
            Write-Host $elapsedTime       -NoNewline -ForegroundColor Yellow
            Write-Host '] Processed '     -NoNewline -ForegroundColor Cyan
            Write-Host $eventObjArr.Count -NoNewline -ForegroundColor Yellow
            Write-Host ' event(s)'                   -ForegroundColor Cyan
        }

        # Return final result.
        $eventObjArr
    }
}



function ConvertTo-MinimalUrlEncoded
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: ConvertTo-MinimalUrlEncoded
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

ConvertTo-MinimalUrlEncoded applies minimal required encoding to input Urls based on observed rules of AWS Console Urls (as opposed to full Url encoding which does not resolve correctly for AWS Console Urls).

.PARAMETER InputObject

Specifies Urls to minimally encode.

.PARAMETER Exclude

(Optional) Specifies character(s) to exclude from encoding.

.EXAMPLE

PS C:\> ConvertTo-MinimalUrlEncoded -InputObject 'valid-User-Name+Valid-Special-Chars=Good-Example'

valid-User-Name+Valid-Special-Chars=Good-Example

.EXAMPLE

PS C:\> ConvertTo-MinimalUrlEncoded -InputObject 'invalid?User!Name+Invalid/Special~Chars:Better$Example'

invalid%3fUser!Name+Invalid%2fSpecial%7eChars%3aBetter%24Example

.EXAMPLE

PS C:\> ConvertTo-MinimalUrlEncoded -InputObject 'invalid?User!Name+Invalid/Special~Chars:Better$Example' -Exclude @('/',':')

invalid%3fUser!Name+Invalid/Special%7eChars:Better%24Example

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.String[]])] 
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [AllowEmptyCollection()]
        [System.Char[]]
        $Exclude
    )

    begin
    {

    }

    process
    {
        # Iterate over each user input -InputObject parameter.
        foreach ($curInputObject in $InputObject)
        {
            # Perform minimal Url encoding of current user input -InputObject parameter.
            $curInputObjectUrlEncoded = -join([System.Char[]] $curInputObject).ForEach( { $_ -cmatch "[A-Za-z0-9-+=,._$(-join$Exclude.ForEach( { [regex]::Escape($_) } ))]" ? $_ : [System.Web.HttpUtility]::UrlEncode($_) } )

            # Return minimally encoded Url.
            $curInputObjectUrlEncoded
        }
    }

    end
    {
        
    }
}



function Get-StringHash
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Get-StringHash
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-StringHash generates hash of input string to avoid needing to write contents to disk before calling native Get-FileHash cmdlet.

.PARAMETER InputObject

Specifies string contents to hash.

.PARAMETER Algorithm

(Optional) Specifies hash algorithm.

.EXAMPLE

PS C:\> Get-Content -Path ./Demo/InputEvents.json | Get-StringHash

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855       

.EXAMPLE

PS C:\> (cat ./Demo/InputEvents.json | Get-StringHash).Hash

E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([Microsoft.PowerShell.Commands.FileHashInfo])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [System.String]
        $Algorithm = 'SHA256'
    )

    # Convert input string into memory stream and stream writer.
    $msObj = New-Object System.IO.MemoryStream
    $swObj = New-Object System.IO.StreamWriter $msObj
    $swObj.Write($InputObject)
    $swObj.Flush()
    $swObj.BaseStream.Position = 0

    # Generate and return hash object.
    Get-FileHash -InputStream $swObj.BaseStream -Algorithm $Algorithm
}



function Out-TimeSpanStr
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Out-TimeSpanStr
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-TimeSpanStr converts input DateTime values into a TimeSpan string formatted as the highest even denomination. E.g. '1 week' instead of '7 days', '2 days' instead of '48 hours', '60 hours' instead of '2.5 days'.

.PARAMETER StartTime

Specifies DateTime for beginning of to-be-calculated TimeSpan.

.PARAMETER EndTime

Specifies DateTime for end of to-be-calculated TimeSpan.

.PARAMETER Exclude

(Optional) Specifies TimeSpan denomination(s) to exclude from formatting consideration. E.g. -Exclude 'month' would return '30 days' instead of '1 month'.

.EXAMPLE

PS C:\> $endTime = [System.DateTime] '2008-02-17 13:37'
PS C:\> $startTime = $endTime.AddDays(-30)
PS C:\> Out-TimeSpanStr -StartTime $startTime -EndTime $endTime

1 month

.EXAMPLE

PS C:\> $endTime = [System.DateTime] '2008-02-17 13:37'
PS C:\> $startTime = $endTime.AddDays(-30)
PS C:\> Out-TimeSpanStr -StartTime $startTime -EndTime $endTime -Exclude month

30 days

.EXAMPLE

PS C:\> $endTime   = [System.DateTime] '2008-02-17 13:37'
PS C:\> $startTime = [System.DateTime] '2006-02-17 13:37'
PS C:\> Out-TimeSpanStr -StartTime $startTime -EndTime $endTime

2 years

PS C:\> Out-TimeSpanStr -StartTime $startTime -EndTime $endTime -Exclude year

24 months

PS C:\> Out-TimeSpanStr -StartTime $startTime -EndTime $endTime -Exclude year,month

730 days

.EXAMPLE

PS C:\> $endTime = [System.DateTime] '2008-02-17 13:37'
PS C:\> $startTime = $endTime.AddHours(-25)
PS C:\> Out-TimeSpanStr -StartTime $startTime -EndTime $endTime

25 hours

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.String])] 
    param (
        [Parameter(Mandatory = $true)]
        [System.DateTime]
        $StartTime,

        [Parameter(Mandatory = $true)]
        [System.DateTime]
        $EndTime,

        [Parameter(Mandatory = $false)]
        [ValidateSet('year','month','week','day','hour','minute','second')]
        [System.String[]]
        $Exclude = @()
    )

    # Calculate Timespan between input StartTime and EndTime DateTime values.
    $timeSpan = $endTime - $startTime

    # Calculate even months and years separately since based on same day number even though TotalDays varies since every months varies in total day count.
    $totalCompleteMonthsEven = ($StartTime.Day -eq $EndTime.Day) ? (($endTime.Month + ($endTime.Year * 12)) - ($startTime.Month + ($startTime.Year * 12))) : 0
    $totalCompleteYearsEven  = ($totalCompleteMonthsEven % 12) -eq 0 ? ($totalCompleteMonthsEven / 12) : 0

    # Calculate string format of TimeSpan factoring in optional -Exclude input parameter.
    $timeSpanStr = switch ($timeSpan)
    {
        { $Exclude -inotcontains 'year'   -and $totalCompleteYearsEven  -gt 0                         } { "$totalCompleteYearsEven year$(  $totalCompleteYearsEven  -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'month'  -and $totalCompleteMonthsEven -gt 0                         } { "$totalCompleteMonthsEven month$($totalCompleteMonthsEven -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'month'  -and -not ([System.String] ($timeSpan.TotalDays / 30)).Contains('.') } { "$($_.TotalDays / 30) month$(($_.TotalDays / 30) -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'week'   -and -not ([System.String] ($timeSpan.TotalDays /  7)).Contains('.') } { "$($_.TotalDays /  7) week$( ($_.TotalDays /  7) -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'day'    -and -not ([System.String]  $timeSpan.TotalDays      ).Contains('.') } { "$($_.TotalDays     ) day$(   $_.TotalDays       -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'hour'   -and -not ([System.String]  $timeSpan.TotalHours     ).Contains('.') } { "$($_.TotalHours    ) hour$(  $_.TotalHours      -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'minute' -and -not ([System.String]  $timeSpan.TotalMinutes   ).Contains('.') } { "$($_.TotalMinutes  ) minute$($_.TotalMinutes    -eq 1 ? '' : 's')"; break }
        { $Exclude -inotcontains 'second' -and -not ([System.String]  $timeSpan.TotalSeconds   ).Contains('.') } { "$($_.TotalSeconds  ) second$($_.TotalSeconds    -eq 1 ? '' : 's')"; break }
        default {
            # Default to Days property (not TotalDays) if no scenario above occurs.
            "$($_.Days) day$($_.Days -eq 1 ? '' : 's')"
        }
    }

    # Return string format of TimeSpan.
    $timeSpanStr
}



function Show-StringWithTags
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Show-StringWithTags
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-StringWithTags displays input string with color-coded formatting for tag values encapsulated with single quotes.

.PARAMETER InputObject

Specifies string to display with color-coded formatting for tag values encapsulated with single quotes.

.PARAMETER PrimaryColor

(Optional) Specifies primary color for displaying input string substrings that are not tag values.

.PARAMETER SecondaryFailureColor

(Optional) Specifies secondary color for displaying input string substrings that are improperly substituted tag values.

.PARAMETER SecondarySuccessColor

(Optional) Specifies secondary color for displaying input string substrings that are properly substituted tag values.

.PARAMETER NoNewline

(Optional) Specifies that final newline not be displayed.

.PARAMETER ShowStats

(Optional) Specifies that session statistics be calculated and output at end of function.

.EXAMPLE

PS C:\> "Clicked S3->Buckets->'{{bucketName}}'->Permissions which displays all permissions for the existing S3 Bucket '' in AWS Region 'us-east-1'." | Show-StringWithTags

Clicked S3->Buckets->{{bucketName}}->Permissions which displays all permissions for the existing S3 Bucket {{UNDEFINED}} in AWS Region us-east-1.

.EXAMPLE

PS C:\> "Clicked S3->Buckets->'{{bucketName}}'->Permissions which displays all permissions for the existing S3 Bucket '' in AWS Region 'us-east-1'." | Show-StringWithTags -PrimaryColor Blue -SecondaryFailureColor Yellow -SecondarySuccessColor Magenta

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.ConsoleColor]
        $PrimaryColor = [System.ConsoleColor]::DarkCyan,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.ConsoleColor]
        $SecondaryFailureColor = [System.ConsoleColor]::DarkRed,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.ConsoleColor]
        $SecondarySuccessColor = [System.ConsoleColor]::DarkGreen,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $NoNewline
    )

    # Create GUID to be temporary placeholder for potential possessive "'s"
    # instances before splitting input string on single-quote placeholder wrappers.
    $singleQuotePlaceholderGuid = (New-Guid).Guid

    # Split input string on single-quote placeholder wrappers and display
    # color-coded output.
    $index = 0
    $InputObject.Replace("'s ","$singleQuotePlaceholderGuid`s ").Split("'").ForEach(
    {
        # Undo temporary placeholder substitution for possessive "'s" instances
        $_ = $_.Replace("$singleQuotePlaceholderGuid`s ","'s ")

        # Update current placeholder value for error handling output purposes
        # if null value substituted for placeholder.
        $_ = $_.Length -eq 0 ? '{{UNDEFINED}}' : $_

        # Set current line's output colors based on user input -PrimaryColor,
        # -SecondaryFailureColor and -SecondarySuccessColor parameters.
        $lineColor = $index % 2 -eq 0 ? $PrimaryColor : ($_.StartsWith('{{') -and $_.EndsWith('}}') ? $SecondaryFailureColor : $SecondarySuccessColor)
        Write-Host $_ -NoNewline -ForegroundColor $lineColor
        $index++
    } )

    # Output final newline unless user input -NoNewline switch parameter is defined.
    if (-not $PSBoundParameters['NoNewline'].IsPresent)
    {
        Write-Host ''
    }
}



# Create enum for each UserAgentFamily type (defined in Get-UserAgentFamily function
# and referenced in Add-Label function).
enum UserAgentFamily {
    Undefined
    CloudShell_AWSCLI
    CloudShell_AWSPowerShell
    CloudShell_Boto
    CloudShell_Generic
    AWS_Internal
    AWS_Internal_2
    Coral_Netty_4
    EC2_Console
    S3_Console
    AWS_CloudTrail
}



function Get-UserAgentFamily
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Get-UserAgentFamily
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-UserAgentFamily returns a UserAgentFamily object as a normalized version of input UserAgent string for simplified and consistent referencing.

.PARAMETER UserAgent

Specifies UserAgent string to normalize into UserAgentFamily object.

.EXAMPLE

PS C:\> Get-UserAgentFamily -UserAgent 'aws-cli/2.11.9 Python/3.11.2 Linux/4.14.255-291-231.527.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/iam.create-access-key'

CloudShell_AWSCLI

.EXAMPLE

PS C:\> Get-UserAgentFamily -UserAgent 'S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.238-155.347.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.362-b10 java/1.8.0_362 vendor/Oracle_Corporation cfg/retry-mode/standard'

S3_Console

.EXAMPLE

PS C:\> $userAgent = '[AWSCloudTrail, aws-internal/3 aws-sdk-java/1.12.597 Linux/5.10.201-168.748.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.392-b09 java/1.8.0_392 vendor/Oracle_Corporation cfg/retry-mode/standard]'
PS C:\> (Get-UserAgentFamily -UserAgent $userAgent) -eq [UserAgentFamily]::AWS_CloudTrail

True

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([UserAgentFamily])] 
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserAgent
    )

    # Initialize UserAgentFamily to Undefined.
    $userAgentFamily = [UserAgentFamily]::Undefined

    # Trim potential square brackets encapsulating entire UserAgent string.
    if ($UserAgent.StartsWith('[') -and $UserAgent.EndsWith(']'))
    {
        $UserAgent = $UserAgent.Substring(1,$UserAgent.Length - 2)
    }

    # Set UserAgentFamily if known UserAgent pattern found in Console sessions.
    if ($UserAgent.Contains(' exec-env/CloudShell '))
    {
        if ($UserAgent.StartsWith('aws-cli/') -and $UserAgent.Contains(' exec-env/CloudShell exe/') -and $UserAgent.Contains(' prompt/off command/'))
        {
            # E.g. [aws-cli/2.11.9 Python/3.11.2 Linux/4.14.255-291-231.527.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/s3.ls]
            # E.g. aws-cli/2.11.9 Python/3.11.2 Linux/4.14.255-291-231.527.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/ec2.describe-instances
            # E.g. aws-cli/2.11.9 Python/3.11.2 Linux/4.14.255-291-231.527.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/iam.create-access-key
            $userAgentFamily = [UserAgentFamily]::CloudShell_AWSCLI
        }
        elseif ($UserAgent.StartsWith('AWSPowerShell.Common/') -and $UserAgent.Contains(' exec-env/CloudShell PowerShellCore/') -and $UserAgent.EndsWith(' ClientAsync'))
        {
            # E.g. AWSPowerShell.Common/4.1.268.0 .NET_Core/7.0.2 OS/Linux_4.14.255-291-231.527.amzn2.x86_64_#1_SMP_Fri_Sep_9_17:34:07_UTC_2022 exec-env/CloudShell PowerShellCore/7.-1 ClientAsync
            $userAgentFamily = [UserAgentFamily]::CloudShell_AWSPowerShell
        }
        elseif ($UserAgent.StartsWith('Boto3') -and $UserAgent.Contains(' exec-env/CloudShell Botocore/'))
        {
            # E.g. Boto3/1.26.95 Python/3.7.16 Linux/5.10.179-166.674.amzn2.x86_64 exec-env/CloudShell Botocore/1.29.95
            $userAgentFamily = [UserAgentFamily]::CloudShell_Boto
        }
        else
        {
            # Not-yet-defined CloudShell UserAgent.
            $userAgentFamily = [UserAgentFamily]::CloudShell_Generic
        }
    }
    elseif ($UserAgent -ceq 'AWS Internal')
    {
        $userAgentFamily = [UserAgentFamily]::AWS_Internal
    }
    elseif ($UserAgent.StartsWith('aws-internal/'))
    {
        $userAgentFamily = [UserAgentFamily]::AWS_Internal_2
    }
    elseif ($UserAgent -ceq 'Coral/Netty4')
    {
        $userAgentFamily = [UserAgentFamily]::Coral_Netty_4
    }
    elseif ($UserAgent.StartsWith('EC2ConsoleFrontend'))
    {
        # Strange scenario where two (2) UserAgent strings are stored comma-separated in a single property.
        # E.g. [EC2ConsoleFrontend, aws-internal/3 aws-sdk-java/1.12.582 Linux/5.10.199-167.747.amzn2int.aarch64 OpenJDK_64-Bit_Server_VM/17.0.9+9-LTS java/1.8.0_392 vendor/N/A cfg/retry-mode/standard]
        $userAgentFamily = [UserAgentFamily]::EC2_Console
    }
    elseif ($UserAgent.StartsWith('S3Console/') -or $UserAgent.StartsWith('AWS Console S3, S3Console/'))
    {
        # Strange scenario where two (2) UserAgent strings are stored comma-separated in a single property.
        # E.g. S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.238-155.347.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.362-b10 java/1.8.0_362 vendor/Oracle_Corporation cfg/retry-mode/standard
        # E.g. [S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.1030 Linux/5.4.238-155.347.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.362-b10 java/1.8.0_362 vendor/Oracle_Corporation cfg/retry-mode/standard]
        # E.g. [AWS Console S3, S3Console/0.4 cfg/retry-mode/legacy]
        $userAgentFamily = [UserAgentFamily]::S3_Console
    }
    elseif ($UserAgent.StartsWith('AWSCloudTrail, aws-internal/'))
    {
        # E.g. [AWSCloudTrail, aws-internal/3 aws-sdk-java/1.12.597 Linux/5.10.201-168.748.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.392-b09 java/1.8.0_392 vendor/Oracle_Corporation cfg/retry-mode/standard]
        $userAgentFamily = [UserAgentFamily]::AWS_CloudTrail
    }

    # Return UserAgentFamily value.
    $userAgentFamily
}



function Merge-Signal
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Merge-Signal
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Merge-Signal merges two Signals into one by removing the Signal stored in MergeEvent and combining it with the Signal stored in AnchorEvent.

.PARAMETER AnchorEvent

Specifies Signal-bearing event into which MergeEvent's Signal will be merged.

.PARAMETER MergeEvent

Specifies event whose Signal will be merged with AnchorEvent's Signal.

.PARAMETER AllEvents

Specifies all events in current session so the events contributing to MergeEvent's Signal can be updated to reference AnchorEvent's newly-merged Signal.

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $AnchorEvent,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $MergeEvent,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject[]]
        $AllEvents
    )

    # Update bookend FirstEventTime and LastEventTime properties for user input
    # -AnchorEvent and -MergeEvent.
    $AnchorEvent.Enrichment.FirstEventTime = @($MergeEvent,$AnchorEvent).Enrichment.FirstEventTime | Sort-Object | Select-Object -First 1
    $AnchorEvent.Enrichment.LastEventTime = @($MergeEvent,$AnchorEvent).Enrichment.LastEventTime | Sort-Object | Select-Object -Last 1
    $MergeEvent.Enrichment.FirstEventTime = [System.DateTime] 0
    $MergeEvent.Enrichment.LastEventTime = [System.DateTime] 0

    # Update EventCount property for user input -AnchorEvent and -MergeEvent.
    $MergeEvent.Enrichment.EventCount = 0
    $AnchorEvent.Enrichment.EventCount += $MergeEvent.Enrichment.EventCount

    # Update CorrelationId property for each of -MergeEvent's events with
    # -AnchorEvent's CorrelationId property.
    $AllEvents.Where( { $_.Enrichment.CorrelationId -ceq $MergeEvent.Enrichment.CorrelationId } ).ForEach( { $_.Enrichment.CorrelationId = $AnchorEvent.Enrichment.CorrelationId } )

    # Remove any remaining properties from -MergeEvent that previously signified
    # the anchor event of a Signal.
    $MergeEvent.Enrichment.Signal = $null
    $MergeEvent.Enrichment.DurationInSeconds = 0
}



function Update-Signal
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Update-Signal
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: New-Signal
Optional Dependencies: None

.DESCRIPTION

Update-Signal updates Signal in AnchorEvent to support context-specific overrides of previously generated Signals.

.PARAMETER Label

Specifies specific type of Signal to create and with which to replace AnchorEvent's existing Signal.

.PARAMETER AnchorEvent

Specifies event whose existing Signal will be updated to specific type of Signal specified by Label.

.PARAMETER EventIndex

Specifies index of AnchorEvent in all events in current session for efficient retrieval of all events contributing to AnchorEvent's existing Signal.

.PARAMETER AllEvents

Specifies all events in current session so the events contributing to AnchorEvent's existing Signal can be referenced during new Signal generation process.

.PARAMETER PreviousSignals

Specifies previous Signals so subset of previous Signals existing at the time of AnchorEvent's Signal generation can be accurately referenced during new Signal generation process.

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [LabelType]
        $Label,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $AnchorEvent,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.Int16]
        $EventIndex,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject[]]
        $AllEvents,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]
        $PreviousSignals
    )

    # Define minimum bookend timestamp for retrieving contributing event objects for previous
    # Signal in user input -AnchorEvent parameter.
    $prevEventTimeMinBound = $AnchorEvent.Enrichment.FirstEventTime

    # Retrieve contributing event objects for previous Signal and store in separate array.
    $i = $EventIndex - 1
    $relatedEventObjArr = @(while ($i -ge 0 -and $AllEvents[$i].Event.eventTime -ge $prevEventTimeMinBound)
    {
        # Retain current event object if it contributed to previous Signal.
        if ($AllEvents[$i].Enrichment.CorrelationId -ceq $AnchorEvent.Enrichment.CorrelationId)
        {
            $AllEvents[$i]
        }

        # Decrement index for next while loop iteration.
        $i--
    })

    # Reverse array of contributing event objects since it was assembled in reverse order.
    [System.Array]::Reverse($relatedEventObjArr)

    # Extract array of previous events with Signals excluding all events after and including
    # previous Signal in user input -AnchorEvent parameter.
    # This is so New-Signal invocation in next step can access the specific previous Signals
    # that would have existed at that time.
    $previousSignalIndex = $PreviousSignals.Enrichment.CorrelationId.IndexOf($AnchorEvent.Enrichment.CorrelationId)
    $previousSignalsFiltered = $PreviousSignals | Select-Object -First $previousSignalIndex

    # Update user input -AnchorEvent parameter with new Signal and Enrichment object based on
    # user input -Label parameter.
    $AnchorEvent.Enrichment = New-Signal -Label $Label -AnchorEvent $AnchorEvent -RelatedEvents $relatedEventObjArr -PreviousSignals $previousSignalsFiltered
}



function Out-SessionStats
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Out-SessionStats
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-SessionStats calculates and outputs session statistics based on input events.

.PARAMETER Event

Specifies enriched events (i.e. with Labels and potential Signals added via Add-Signal function) for which to generate statistics.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Out-SessionStats

EventCount                : 1000
LabeledEventStats         : 100.000% (1000 labeled, 0 unlabeled)
MappedEventStats          : 99.500% (995 mapped, 5 unmapped across 5 timestamps)
SignalCount               : 40 (27 distinct Signals)
SignalEventStats          : avg=24.875, min=1, max=484
SignalServiceStats        : 6 services (CloudShell [8], EC2 [2], IAM [10], N/A [13], S3 [4], SecretsManager [3])
UnmappedEventServiceStats : 1 service (kms [5])
SessionDuration           : 00:06:38 (start=04/13/2024 05:11:21, end=04/13/2024 05:17:59)

.EXAMPLE

PS C:\> cat ./Demo/InputEvents.json | Add-Signal | Out-SessionStats

EventCount                : 1000
LabeledEventStats         : 100.000% (1000 labeled, 0 unlabeled)
MappedEventStats          : 99.500% (995 mapped, 5 unmapped across 5 timestamps)
SignalCount               : 40 (27 distinct Signals)
SignalEventStats          : avg=24.875, min=1, max=484
SignalServiceStats        : 6 services (CloudShell [8], EC2 [2], IAM [10], N/A [13], S3 [4], SecretsManager [3])
UnmappedEventServiceStats : 1 service (kms [5])
SessionDuration           : 00:06:38 (start=04/13/2024 05:11:21, end=04/13/2024 05:17:59)

.EXAMPLE

PS C:\> aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 | Add-Signal -Verbose | Out-SessionStats

[*] [00:00:00.1851498] Added 1250 Label(s) to 357 of 357 Events
[*] [00:00:00.2190119] Added 76 Signal(s) to 357 of 357 Events

EventCount                : 357
LabeledEventStats         : 100.000% (357 labeled, 0 unlabeled)
MappedEventStats          : 100.000% (357 mapped, 0 unmapped)
SignalCount               : 76 (19 distinct Signals)
SignalEventStats          : avg=4.69736842105263, min=1, max=30
SignalServiceStats        : 3 services (EC2 [30], N/A [45], VPC [1])
UnmappedEventServiceStats : 0 services
SessionDuration           : 01:10:30 (start=11/28/2023 18:09:19, end=11/28/2023 19:19:49)

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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]
        $Event
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $eventArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to ArrayList before beginning final processing.
        if ($Event.Count -gt 1)
        {
            # Add all -Event objects to ArrayList.
            $eventArr.AddRange($Event)
        }
        else
        {
            # Add single -Event object to ArrayList.
            $eventArr.Add($Event) | Out-Null
        }
    }

    end
    {
        # Output warning message and break if no events are input.
        if ($eventArr.Count -eq 0)
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] No events were input so no statistics can be generated."
            
            break
        }

        # Calculate session summary statistics to be used in final result object creation.
        #
        # LabeledEventStats
        $eventWithLabelCount = $eventArr.Where( { $_.Enrichment.Labels.Count -gt 0 } ).Count
        $eventWithoutLabelCount = $eventArr.Count - $eventWithLabelCount
        $eventWithLabelPercent = $eventWithLabelCount / $eventArr.Count
        #
        # MappedEventStats
        $eventMappedCount = $eventArr.Where( { $_.Enrichment.IsSignalContributor } ).Count
        $eventUnmappedCount = $eventArr.Count - $eventMappedCount
        $eventMappedPercent = $eventMappedCount -eq $eventArr.Count ? 1.0 : $eventMappedCount / $eventArr.Count
        $eventUnmappedDistinctEventTimeCount = ($eventArr.Where( { -not $_.Enrichment.IsSignalContributor } ).Event.eventTime | Group-Object | Measure-Object).Count
        #
        # SignalCount
        $signalArr = $eventArr.Where( { $_.Enrichment.Signal } )
        $signalCount         = ($signalArr.Enrichment.CorrelationId | Sort-Object -Unique).Count
        $distinctSignalCount = ($signalArr.Enrichment.Signal.Name   | Sort-Object -Unique).Count
        #
        # SignalEventStats
        $signalEventCountAvg = ($signalArr.Enrichment.EventCount | Measure-Object -Average).Average
        $signalEventCountMin = ($signalArr.Enrichment.EventCount | Measure-Object -Minimum).Minimum
        $signalEventCountMax = ($signalArr.Enrichment.EventCount | Measure-Object -Maximum).Maximum
        #
        # SignalServiceStats
        $signalServiceGroupedArr = $eventArr.Where( { $_.Enrichment.Signal } ).Enrichment.Signal.Service | Group-Object | Sort-Object Name
        $signalServiceGroupedCount = ($signalServiceGroupedArr | Measure-Object).Count
        $signalServiceSummary = $signalServiceGroupedArr.ForEach( { "$($_.Name) [$($_.Count)]" } ) -join ', '
        #
        # UnmappedEventServiceStats
        $unmappedEventServiceTopCount = 3
        $unmappedEventServiceGroupedArr = $eventArr.Where( { -not $_.Enrichment.IsSignalContributor } ).Event.eventSource.Where( { $_ } ) -ireplace '.amazonaws.com','' | Group-Object | Sort-Object Count -Descending
        $unmappedEventServiceCount = ($unmappedEventServiceGroupedArr | Measure-Object).Count
        $unmappedEventServiceSummary = ($unmappedEventServiceGroupedArr | Select -First $unmappedEventServiceTopCount).ForEach( { "$($_.Name) [$($_.Count)]" } ) -join ', '
        #
        # SessionDuration
        $sessionTimeObj = $eventArr.Event.eventTime | Measure-Object -Minimum -Maximum
        $sessionStartTime = $sessionTimeObj.Minimum
        $sessionEndTime = $sessionTimeObj.Maximum

        # Create and return final statistics object.
        [PSCustomObject] @{
            EventCount                = $eventArr.Count
            LabeledEventStats         = "$($eventWithLabelPercent.ToString('P')) ($eventWithLabelCount labeled, $eventWithoutLabelCount unlabeled)"
            MappedEventStats          = "$($eventMappedPercent.ToString('P')) ($eventMappedCount mapped, $eventUnmappedCount unmapped$($eventUnmappedCount -eq 0 ? '' : " across $eventUnmappedDistinctEventTimeCount timestamp$($eventUnmappedDistinctEventTimeCount -eq 1 ? '' : 's')"))"
            SignalCount               = "$signalCount ($distinctSignalCount distinct Signal$($distinctSignalCount -eq 1 ? '' : 's'))"
            SignalEventStats          = "avg=$signalEventCountAvg, min=$signalEventCountMin, max=$signalEventCountMax"
            SignalServiceStats        = "$signalServiceGroupedCount service$($signalServiceGroupedCount -eq 1 ? '' : 's') ($signalServiceSummary)"
            UnmappedEventServiceStats = "$unmappedEventServiceCount service$($unmappedEventServiceCount -eq 1 ? '' : 's')$($unmappedEventServiceCount -eq 0 ? '' : " ($($unmappedEventServiceCount -eq 1 ? '' : 'top ' + ($unmappedEventServiceCount -ge $unmappedEventServiceTopCount ? $unmappedEventServiceTopCount : $unmappedEventServiceCount)+ ': ')$unmappedEventServiceSummary)")"
            SessionDuration           = "$($sessionEndTime - $sessionStartTime) (start=$sessionStartTime, end=$sessionEndTime)"
        }
    }
}



function Out-SessionSummary
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Out-SessionSummary
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-SessionSummary merges and returns unmapped events and mapped Signal-bearing events, normalizing event values and mapped Signal values to support simultaneous display.

.PARAMETER Event

Specifies enriched events (i.e. with Labels and potential Signals added via Add-Signal function) to merge and normalize.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Out-SessionSummary | Select-Object -First 3

EventTime      : 4/13/2024 5:11:23AM
EventCount     : 2
Service        : N/A
Name           : Console Login
Summary        : Logged into AWS Console.
Url            : N/A
Label          : ConsoleLogin
IsMapped       : True
IsSuppressed   : False

EventTime      : 4/13/2024 5:11:29AM
EventCount     : 7
Service        : N/A
Name           : Console Home
Summary        : Visited Console Home dashboard which displays general overview information for account (e.g. Recently Visited services, AWS Health, Cost and Usage, etc.).
Url            : https://us-east-1.console.aws.amazon.com/console/home?region=us-east-1#
Label          : ConsoleHome
IsMapped       : True
IsSuppressed   : False

EventTime      : 4/13/2024 5:11:30AM
EventCount     : 9
Service        : N/A
Name           : Suppressing automated background event
Summary        : Suppressing automated background event not contributing to any mapping scenario.
Url            : N/A
Label          : SuppressAutomatedBackgroundEvent
IsMapped       : True
IsSuppressed   : True

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Out-SessionSummary | Where-Object { $_.Service -eq 'SecretsManager' } | Select-Object EventTime,EventCount,Summary

EventTime           EventCount Summary
---------           ---------- -------
4/13/2024 5:14:28AM          2 Clicked Secrets Manager->Secrets which displays all Secrets in a searchable paged format.
4/13/2024 5:14:39AM          4 Clicked Secrets Manager->Secrets->'op_njeri'->Overview which displays a summary of all details for Secret 'arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG' name…
4/13/2024 5:14:46AM          2 Clicked Secrets Manager->Secrets->'op_njeri'->Overview->Retrieve Secret Value to display value of Secret 'arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG' named…

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Out-SessionSummary | Where-Object { $_.EventTime -eq [System.DateTime] '4/13/2024 5:15:10AM' } | Select-Object EventTime,EventCount,Name,Summary

EventTime           EventCount Name                                                   Summary
---------           ---------- ----                                                   -------
4/13/2024 5:15:10AM          1 kms:Decrypt                                            N/A
4/13/2024 5:15:10AM          1 Executed interactive command in CloudShell via AWS CLI Interactively executed 'secretsmanager:GetSecretValue' in CloudShell session vi…
4/13/2024 5:15:10AM          1 Suppressing automated background event                 Suppressing automated background event not contributing to any mapping scenario.

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
        # Merge and return unmapped events and mapped Signal-bearing events, normalizing
        # event values and mapped Signal values to support simultaneous display.
        $eventArr.ForEach(
        {
            if ($_.Enrichment.IsSignalContributor -eq $false)
            {
                [PSCustomObject] @{
                    EventTime      = $_.Event.eventTime
                    EventCount     = 1
                    Service        = $_.Event.eventSource.ToLower().Replace('.amazonaws.com','')
                    Name           = $_.Enrichment.EventNameFull
                    Summary        = 'N/A'
                    Url            = 'N/A'
                    Label          = 'N/A'
                    IsMapped       = $false
                    IsSuppressed   = $false
                }
            }
            elseif ($_.Enrichment.IsSignalContributor -eq $true -and $_.Enrichment.Signal)
            {
                [PSCustomObject] @{
                    EventTime      = $_.Event.eventTime
                    EventCount     = $_.Enrichment.EventCount
                    Service        = $_.Enrichment.Signal.Service
                    Name           = $_.Enrichment.Signal.Name
                    Summary        = $_.Enrichment.Signal.Summary
                    Url            = $_.Enrichment.Signal.Url
                    Label          = $_.Enrichment.Signal.Label
                    IsMapped       = $true
                    IsSuppressed   = ([System.String] $_.Enrichment.Signal.Label).StartsWith('SuppressAutomatedBackgroundEvent') ? $true : $false
                }
            }
        } )
    }
}



function Show-EventSummary
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Show-EventSummary
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-SessionStats, Show-StringWithTags
Optional Dependencies: None

.DESCRIPTION

Show-EventSummary displays summary of session at the event level with optional detailing of Label, Signal and raw event information relevant to debugging and coding new Signal logic.

.PARAMETER Event

Specifies enriched events (i.e. with Labels and potential Signals added via Add-Signal function) to summarize at the event level.

.PARAMETER Property

(Optional) Specifies custom ordering of eligible properties for summary result.

.PARAMETER Detail

(Optional) Specifies that one or more additional details be displayed per Signal or per event.

.PARAMETER IncludeSuppressed

(Optional) Specifies that suppressed Signal events be included in summary.

.PARAMETER ExcludeMappedEvents

(Optional) Specifies that mapped events be excluded from summary.

.PARAMETER ExcludeUnmappedEvents

(Optional) Specifies that unmapped events be excluded from summary.

.PARAMETER ShowStats

(Optional) Specifies that session statistics be calculated and output at end of function.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Where-Object { $_.Event.eventTime -ge [System.DateTime] '4/13/2024 5:14:39AM' -and $_.Event.eventTime -le [System.DateTime] '4/13/2024 5:14:40AM' } | Show-EventSummary -ShowStats

EventTime           IsAnchor CorrelationId                        EventNameFull                    LabelCount Labels
---------           -------- -------------                        -------------                    ---------- ------
4/13/2024 5:14:39AM     True 4743d783-4f24-490e-988a-34d6dd6d9704 secretsmanager:DescribeSecret             4 {SecretsManager_Secrets_SPECIFICSECRET_Delete, SecretsMa…
4/13/2024 5:14:39AM    False 4743d783-4f24-490e-988a-34d6dd6d9704 secretsmanager:GetResourcePolicy          2 {SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion, S…
4/13/2024 5:14:40AM     True 4743d783-4f24-490e-988a-34d6dd6d9704 kms:ListAliases                           7 {CloudTrail_Lake_EventDataStores_Create_Step1, CloudTrai…
4/13/2024 5:14:40AM     True 4743d783-4f24-490e-988a-34d6dd6d9704 kms:ListAliases                           7 {CloudTrail_Lake_EventDataStores_Create_Step1, CloudTrai…

EventCount                : 4
LabeledEventStats         : 100.000% (4 labeled, 0 unlabeled)
MappedEventStats          : 100.000% (4 mapped, 0 unmapped)
SignalCount               : 1 (1 distinct Signal)
SignalEventStats          : avg=4, min=4, max=4
SignalServiceStats        : 1 service (SecretsManager [1])
UnmappedEventServiceStats : 0 services
SessionDuration           : 00:00:01 (start=04/13/2024 05:14:39, end=04/13/2024 05:14:40)

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Where-Object { $_.Event.eventTime -ge [System.DateTime] '4/13/2024 5:14:39AM' -and $_.Event.eventTime -le [System.DateTime] '4/13/2024 5:14:40AM' } | Show-EventSummary -Detail signal,event_mapped -Property EventTime,EventNameFull,LabelCount,Labels

EventTime           EventNameFull                    LabelCount Labels
---------           -------------                    ---------- ------
  |--## S ## 
  |  ## I ##  Name: Clicked Secrets Manager->Secrets->SPECIFICSECRET->Overview
  |  ## G ##  Summary: Clicked Secrets Manager->Secrets->op_njeri->Overview which displays a summary of all details for Secret arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG named op_njeri.
  |  ## N ##  URL: https://us-east-1.console.aws.amazon.com/secretsmanager/secret?name=op_njeri&region=us-east-1
 \|/ ## A ##  EventCount: 4
  V  ## L ## 
4/13/2024 5:14:39AM secretsmanager:DescribeSecret             4 {SecretsManager_Secrets_SPECIFICSECRET_Delete, SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion, S…
  ^  ## D ##  EventNameFull: secretsmanager:DescribeSecret
 /|\ ## E ##  UserAgentFamily: Undefined
  |  ## T ##  UserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0
  |  ## A ##  RequestParameters: {"secretId":"op_njeri"}
  |  ## I ##  RequestParametersKeyStr: secretId
  |  ## L ##  RequestParametersKeyEmptyValStr: 
  |--## S ##  Labels: SecretsManager_Secrets_SPECIFICSECRET_Delete
                      SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                      SecretsManager_Secrets_SPECIFICSECRET_Overview
                      SuppressAutomatedBackgroundEvent_SecretsManager_Secrets_SPECIFICSECRET

4/13/2024 5:14:39AM secretsmanager:GetResourcePolicy          2 {SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion, SecretsManager_Secrets_SPECIFICSECRET_Overview}
  ^  ## D ##  EventNameFull: secretsmanager:GetResourcePolicy
 /|\ ## E ##  UserAgentFamily: Undefined
  |  ## T ##  UserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0
  |  ## A ##  RequestParameters: {"secretId":"arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG"}
  |  ## I ##  RequestParametersKeyStr: secretId
  |  ## L ##  RequestParametersKeyEmptyValStr: 
  |--## S ##  Labels: SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                      SecretsManager_Secrets_SPECIFICSECRET_Overview

4/13/2024 5:14:40AM kms:ListAliases                           7 {CloudTrail_Lake_EventDataStores_Create_Step1, CloudTrail_Trails_SPECIFICTRAIL, SecretsManager_Secrets…
  ^  ## D ##  EventNameFull: kms:ListAliases
 /|\ ## E ##  UserAgentFamily: Undefined
  |  ## T ##  UserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0
  |  ## A ##  RequestParameters: 
  |  ## I ##  RequestParametersKeyStr: 
  |  ## L ##  RequestParametersKeyEmptyValStr: 
  |--## S ##  Labels: CloudTrail_Lake_EventDataStores_Create_Step1
                      CloudTrail_Trails_SPECIFICTRAIL
                      SecretsManager_Secrets_Create_Step1
                      SecretsManager_Secrets_SPECIFICSECRET_Delete
                      SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                      SecretsManager_Secrets_SPECIFICSECRET_Overview
                      KMS_CustomerManagedKeys

4/13/2024 5:14:40AM kms:ListAliases                           7 {CloudTrail_Lake_EventDataStores_Create_Step1, CloudTrail_Trails_SPECIFICTRAIL, SecretsManager_Secrets…
  ^  ## D ##  EventNameFull: kms:ListAliases
 /|\ ## E ##  UserAgentFamily: Undefined
  |  ## T ##  UserAgent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0
  |  ## A ##  RequestParameters: 
  |  ## I ##  RequestParametersKeyStr: 
  |  ## L ##  RequestParametersKeyEmptyValStr: 
  |--## S ##  Labels: CloudTrail_Lake_EventDataStores_Create_Step1
                      CloudTrail_Trails_SPECIFICTRAIL
                      SecretsManager_Secrets_Create_Step1
                      SecretsManager_Secrets_SPECIFICSECRET_Delete
                      SecretsManager_Secrets_SPECIFICSECRET_CancelDeletion
                      SecretsManager_Secrets_SPECIFICSECRET_Overview
                      KMS_CustomerManagedKeys

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $Event,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('EventTime','IsAnchor','CorrelationId','EventNameFull','LabelCount','Labels')]
        [System.String[]]
        $Property = @(('EventTime','IsAnchor','CorrelationId','EventNameFull','LabelCount','Labels')),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('signal','event_unmapped','event_mapped')]
        [System.String[]]
        $Detail,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $IncludeSuppressed,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ExcludeMappedEvents,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ExcludeUnmappedEvents,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ShowStats
    )

    begin
    {
        # Output warning message and break if combination of incompatible input parameters is defined.
        if ($PSBoundParameters['ExcludeMappedEvents'].IsPresent -and $PSBoundParameters['ExcludeUnmappedEvents'].IsPresent)
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] Both -ExcludeMappedEvents and -ExcludeUnmappedEvents input parameters are defined meaning no events will be processed. Please select only one (or none) of these input parameters."
            
            break
        }

        # Create ArrayList to store all pipelined input before beginning final processing.
        $eventArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to ArrayList before beginning final processing.
        if ($Event.Count -gt 1)
        {
            # Add all -Event objects to ArrayList.
            $eventArr.AddRange($Event)
        }
        else
        {
            # Add single -Event object to ArrayList.
            $eventArr.Add($Event) | Out-Null
        }
    }

    end
    {
        # Generate pre-filtered session statistics if user input -ShowStats parameter is defined.
        if ($PSBoundParameters['ShowStats'].IsPresent)
        {
            $sessionStatsObj =  Out-SessionStats -Event $eventArr
        }

        # Extract array of correlationIds from Signal-bearing events.
        $suppressedSignalIdArr = $PSBoundParameters['IncludeSuppressed'].IsDefined ? @() : $eventArr.Where( { ([System.String] $_.Enrichment.Signal.Label).StartsWith('SuppressAutomatedBackgroundEvent') } ).Enrichment.CorrelationId

        # Potentially exclude events based on Signal-contribution status and user input
        # parameters -IncludeSuppressed, -ExcludeMappedEvents and -ExcludeUnmappedEvents.
        $eventArr = $eventArr.Where(
        {
            -not (
                ($PSBoundParameters['ExcludeMappedEvents'].IsPresent -and $_.Enrichment.IsSignalContributor -eq $true) -or `
                ($PSBoundParameters['ExcludeUnmappedEvents'].IsPresent -and $_.Enrichment.IsSignalContributor -eq $false) -or `
                (-not $PSBoundParameters['IncludeSuppressed'].IsPresent -and $_.Enrichment.IsSignalContributor -eq $true -and $_.Enrichment.CorrelationId -cin $suppressedSignalIdArr)
            )
        } )

        # Simplify events by normalizing subset of nested event and enrichment properties.
        $eventNormalizedArr = $eventArr.ForEach(
        {
            [PSCustomObject] @{
                EventTime     = $_.Event.eventTime
                IsAnchor      = $_.Enrichment.IsAnchor
                CorrelationId = $_.Enrichment.CorrelationId
                EventNameFull = $_.Enrichment.EventNameFull
                LabelCount    = $_.Enrichment.Labels.Count
                Labels        = $_.Enrichment.Labels
            }
        } )

        # Select properties and order defined by user input -Property parameter value.
        $eventNormalizedArr = $eventNormalizedArr | Select-Object $Property

        # Extract Signal-bearing events into separate array.
        $eventWithSignalArr = $eventArr.Where( { $_.Enrichment.Signal } )

        # Format normalized events into array of non-empty strings for output purposes.
        $outputStrArr = ($eventNormalizedArr | Format-Table | Out-String).Split("`n").Where( { $_ } )

        # Define Out-String function header line count and separate table header from body.
        $headerLineCount = 2
        $outputStrHeaderArr = $outputStrArr | Select-Object -First $headerLineCount
        $outputStrBodyArr   = $outputStrArr | Select-Object -Skip  $headerLineCount

        # Create array to track CorrelationIds of Signals that have been output if
        # user input -Detail parameter has 'signal' value defined.
        $outputSignalIdArr = @()

        # Output table contents according to Signal-dependent colors.
        Write-Host ''
        Write-Host ($outputStrHeaderArr -join "`n")
        for ($i = 0; $i -lt $outputStrBodyArr.Count; $i++)
        {
            $curEvent = $eventArr[$i]

            # Extract information from current Signal for output purposes.
            $signalEvent = $eventWithSignalArr.Where( { $_.Enrichment.CorrelationId -ceq $curEvent.Enrichment.CorrelationId } )[0]

            # Output current Signal information if user input -Detail parameter has 'signal' value defined.
            if (
                $PSBoundParameters['Detail'] -icontains 'signal' -and `
                $signalEvent -and `
                $signalEvent.Enrichment.CorrelationId -cnotin $outputSignalIdArr -and `
                $signalEvent.Enrichment.CorrelationId -cin $eventWithSignalArr.Enrichment.CorrelationId
            )
            {
                # Add current Signal's CorrelationId to array to avoid displaying the same
                # Signal's information again.
                $outputSignalIdArr += $signalEvent.Enrichment.CorrelationId

                # Output ASCII arrow Signal banner and current Signal information.
                Write-Host '  |--## S ## '            -ForegroundColor DarkCyan
                Write-Host '  |  ## I ## ' -NoNewline -ForegroundColor DarkCyan; Write-Host ' Name: '       -NoNewline -ForegroundColor DarkGray; Write-Host $signalEvent.Enrichment.Signal.Name -ForegroundColor DarkCyan
                Write-Host '  |  ## G ## ' -NoNewline -ForegroundColor DarkCyan; Write-Host ' Summary: '    -NoNewline -ForegroundColor DarkGray

                # Output Signal Summary with color-coded placeholder value(s).
                Show-StringWithTags -InputObject $signalEvent.Enrichment.Signal.Summary

                Write-Host '  |  ## N ## ' -NoNewline -ForegroundColor DarkCyan; Write-Host ' URL: '        -NoNewline -ForegroundColor DarkGray; Write-Host $signalEvent.Enrichment.Signal.URL -ForegroundColor DarkCyan
                Write-Host ' \|/ ## A ## ' -NoNewline -ForegroundColor DarkCyan; Write-Host ' EventCount: ' -NoNewline -ForegroundColor DarkGray; Write-Host $signalEvent.Enrichment.EventCount -ForegroundColor DarkCyan
                Write-Host '  V  ## L ## '            -ForegroundColor DarkCyan
            }

            # Set current line and additional details used for output formatting.
            $curLine = $outputStrBodyArr[$i]
            $curLineIsSignalContributor = $curEvent.Enrichment.IsSignalContributor
            $curLineColor = $curLineIsSignalContributor -eq $true ? [System.ConsoleColor]::Green : [System.ConsoleColor]::Yellow

            # Output current line with appropriate color based on Signal-contribution status.
            Write-Host $curLine -ForegroundColor $curLineColor

            # Output additional details for event if user input -Detail parameter has
            # 'event_mapped' or 'event_unmapped' value defined that corresponds to Signal-
            # contributing status of current event.
            if (
                ($PSBoundParameters['Detail'] -icontains 'event_mapped' -and $curLineIsSignalContributor) -or `
                ($PSBoundParameters['Detail'] -icontains 'event_unmapped' -and -not $curLineIsSignalContributor)
            )
            {
                # Extract extra details from current event.
                $extraDetailObj = [PSCustomObject] @{
                    eventNameFull = $curEvent.Enrichment.EventNameFull
                    userAgent = $curEvent.Event.userAgent
                    userAgentFamily = Get-UserAgentFamily -UserAgent $curEvent.Event.userAgent
                    requestParametersStr = [System.String]::IsNullOrEmpty($curEvent.Event.requestParameters) ? '' : (ConvertTo-Json -InputObject $curEvent.Event.requestParameters -Depth 25 -Compress)
                    requestParametersKeyStr = ($curEvent.Event.requestParameters.Keys | Sort-Object) -join ','
                    requestParametersKeyEmptyValStr = ($curEvent.Event.requestParameters.Keys.Where( { (ConvertTo-Json -InputObject $curEvent.EventrequestParameters.$_ -Depth 25 -Compress) -cin @('{}','""') } ) | Sort-Object) -join ','
                    labelArr = $curEvent.Enrichment.Labels
                }

                # Dynamically determine ASCII arrow Details banner color based on current event's
                # Signal-contribution status.
                $headerAsciiColor = $curLineIsSignalContributor ? [System.ConsoleColor]::DarkGreen : [System.ConsoleColor]::DarkYellow

                # Output extracted extra details in color-coded format.
                Write-Host '  ^  ## D ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' EventNameFull: '                   -NoNewline -ForegroundColor DarkGray; Write-Host $extraDetailObj.eventNameFull                   -ForegroundColor DarkMagenta
                Write-Host ' /|\ ## E ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' UserAgentFamily: '                 -NoNewline -ForegroundColor DarkGray; Write-Host $extraDetailObj.userAgentFamily                 -ForegroundColor DarkMagenta
                Write-Host '  |  ## T ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' UserAgent: '                       -NoNewline -ForegroundColor DarkGray; Write-Host $extraDetailObj.userAgent                       -ForegroundColor DarkMagenta
                Write-Host '  |  ## A ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' RequestParameters: '               -NoNewline -ForegroundColor DarkGray; Write-Host $extraDetailObj.requestParametersStr            -ForegroundColor DarkMagenta
                Write-Host '  |  ## I ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' RequestParametersKeyStr: '         -NoNewline -ForegroundColor DarkGray; Write-Host $extraDetailObj.requestParametersKeyStr         -ForegroundColor DarkMagenta
                Write-Host '  |  ## L ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' RequestParametersKeyEmptyValStr: ' -NoNewline -ForegroundColor DarkGray; Write-Host $extraDetailObj.requestParametersKeyEmptyValStr -ForegroundColor DarkMagenta
                Write-Host '  |--## S ## ' -NoNewline -ForegroundColor $headerAsciiColor; Write-Host ' Labels: '                          -NoNewline -ForegroundColor DarkGray

                # Output all Labels for current event according to the following color rules:
                # 1) Red - Label was not Signal match.
                # 2) Green - Label was Signal match.
                # 3) Gray - Skipped since a previous Label was Signal match.
                $hasPreviousLabelMatched = $false
                for ($j = 0; $j -lt $extraDetailObj.labelArr.Count; $j++)
                {
                    $label = $extraDetailObj.labelArr[$j]

                    # Dynamically determine Label output color based on if matching Signal
                    # or if Signal match occurred for some previous Label.
                    if ($hasPreviousLabelMatched)
                    {
                        $labelColor = [System.ConsoleColor]::DarkGray
                    }
                    elseif ($label -ceq $signalEvent.Enrichment.Signal.Label)
                    {
                        $labelColor = [System.ConsoleColor]::DarkGreen
                        $hasPreviousLabelMatched = $true
                    }
                    else
                    {
                        $labelColor = [System.ConsoleColor]::DarkRed
                    }

                    # Handle proper indentation for non-first Label to output.
                    if ($j -gt 0)
                    {
                        Write-Host '                      ' -NoNewline
                    }
                    Write-Host $label -ForegroundColor $labelColor
                }
                Write-Host ''
            }
        }
        Write-Host "`n"

        # Output pre-filtered session statistics generated at beginning of function
        # if user input -ShowStats parameter is defined.
        if ($PSBoundParameters['ShowStats'].IsPresent)
        {
            $sessionStatsObj
        }
    }
}



function Show-SessionSummary
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Show-SessionSummary
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-SessionStats, Out-SessionSummary, Show-StringWithTags
Optional Dependencies: None

.DESCRIPTION

Show-SessionSummary displays summary of session at the Signal level by merging unmapped events and Signal-bearing events, normalizing event values and mapped Signal values to support simultaneous display.

.PARAMETER Event

Specifies enriched events (i.e. with Labels and potential Signals added via Add-Signal function) to summarize at the Signal level.

.PARAMETER Property

(Optional) Specifies custom ordering of eligible properties for summary result.

.PARAMETER IncludeSuppressed

(Optional) Specifies that suppressed Signals be included in summary.

.PARAMETER ExcludeMappedEvents

(Optional) Specifies that mapped events (i.e. Signals) be excluded from summary.

.PARAMETER ExcludeUnmappedEvents

(Optional) Specifies that unmapped events be excluded from summary.

.PARAMETER ShowStats

(Optional) Specifies that session statistics be calculated and output at end of function.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Where-Object { $_.Event.eventTime -ge [System.DateTime] '4/13/2024 5:14:20AM' -and $_.Event.eventTime -le [System.DateTime] '4/13/2024 5:15:00AM' } | Show-SessionSummary -ShowStats

EventTime           EventCount Summary
---------           ---------- -------                                                                                                                                                                                
4/13/2024 5:14:21AM          1 Typed content into AWS Console Search Bar.                                                                                                                                             
4/13/2024 5:14:28AM          2 Clicked Secrets Manager->Secrets which displays all Secrets in a searchable paged format.                                                                                              
4/13/2024 5:14:39AM          4 Clicked Secrets Manager->Secrets->op_njeri->Overview which displays a summary of all details for Secret arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG named…
4/13/2024 5:14:46AM          2 Clicked Secrets Manager->Secrets->op_njeri->Overview->Retrieve Secret Value to display value of Secret arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG named …

EventCount                : 12
LabeledEventStats         : 100.000% (12 labeled, 0 unlabeled)
MappedEventStats          : 100.000% (12 mapped, 0 unmapped)
SignalCount               : 5 (5 distinct Signals)
SignalEventStats          : avg=2.4, min=1, max=4
SignalServiceStats        : 2 services (N/A [2], SecretsManager [3])
UnmappedEventServiceStats : 0 services
SessionDuration           : 00:00:25 (start=04/13/2024 05:14:21, end=04/13/2024 05:14:46)

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Where-Object { $_.Enrichment.Signal.Service -match 'CloudShell' -or $_.Enrichment.Signal.Summary -match 'op_njeri' } | Show-SessionSummary -Property EventTime,Service,Summary

EventTime           Service        Summary
---------           -------        -------
4/13/2024 5:14:39AM SecretsManager Clicked Secrets Manager->Secrets->op_njeri->Overview which displays a summary of all details for Secret arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG n…
4/13/2024 5:14:46AM SecretsManager Clicked Secrets Manager->Secrets->op_njeri->Overview->Retrieve Secret Value to display value of Secret arn:aws:secretsmanager:us-east-1:012345678900:secret:op_njeri-hhUEvG na…
4/13/2024 5:15:04AM CloudShell     Automatically renewed existing CloudShell session with 72d5b773-f7ae-4807-8074-42a4ff32e8ca Environment ID and 1712979380231299212-04a6453e05e15817c Session ID.
4/13/2024 5:15:10AM CloudShell     Interactively executed secretsmanager:GetSecretValue in CloudShell session via AWS CLI with request parameters: {"secretId":"op_njeri"}.
4/13/2024 5:15:12AM CloudShell     Interactively executed secretsmanager:GetSecretValue in CloudShell session via AWS CLI with request parameters: {"secretId":"ckemi"}.
4/13/2024 5:15:13AM CloudShell     Interactively executed secretsmanager:GetSecretValue in CloudShell session via AWS CLI with request parameters: {"secretId":"tung"}.
4/13/2024 5:15:14AM CloudShell     Interactively executed secretsmanager:GetSecretValue in CloudShell session via AWS CLI with request parameters: {"secretId":"pershendetje"}.
4/13/2024 5:15:16AM CloudShell     Interactively executed secretsmanager:GetSecretValue in CloudShell session via AWS CLI with request parameters: {"secretId":"faleminderit"}.
4/13/2024 5:15:35AM CloudShell     Clicked CloudShell->Actions->Download File to download /home/cloudshell-user/secrets.json file from interactive CloudShell session with 72d5b773-f7ae-4807-8074-42a4ff32e8ca E…
4/13/2024 5:15:43AM CloudShell     Clicked CloudShell->Exit to exit interactive CloudShell session with 72d5b773-f7ae-4807-8074-42a4ff32e8ca Environment ID and 1712984899221468522-0bee9bd98261fd9bb Session ID.

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $Event,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('EventTime','EventCount','Summary','Service','Name','Url','Label','IsMapped','IsSuppressed')]
        [System.String[]]
        $Property = @(('EventTime','EventCount','Summary','Service','Name',,'Url','Label','IsMapped','IsSuppressed')),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $IncludeSuppressed,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ExcludeMappedEvents,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ExcludeUnmappedEvents,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ShowStats
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $eventArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to ArrayList before beginning final processing.
        if ($Event.Count -gt 1)
        {
            # Add all -Event objects to ArrayList.
            $eventArr.AddRange($Event)
        }
        else
        {
            # Add single -Event object to ArrayList.
            $eventArr.Add($Event) | Out-Null
        }
    }

    end
    {
        # Generate pre-filtered session statistics if user input -ShowStats parameter is defined.
        if ($PSBoundParameters['ShowStats'].IsPresent)
        {
            $sessionStatsObj =  Out-SessionStats -Event $eventArr
        }

        # Merge unmapped events and mapped Signal-bearing events, normalizing event values
        # and mapped Signal values to support simultaneous display.
        $eventNormalizedArr = Out-SessionSummary -Event $eventArr

        # Potentially exclude events based on Signal-contribution status and user input
        # parameters -IncludeSuppressed, -ExcludeMappedEvents and -ExcludeUnmappedEvents.
        $eventNormalizedArr = $eventNormalizedArr.Where(
        {
            -not (
                ($PSBoundParameters['ExcludeMappedEvents'].IsPresent -and $_.IsMapped -eq $true) -or `
                ($PSBoundParameters['ExcludeUnmappedEvents'].IsPresent -and $_.IsMapped -eq $false) -or `
                (-not $PSBoundParameters['IncludeSuppressed'].IsPresent -and $_.IsSuppressed -eq $true)
            )
        } )

        # Format normalized events into array of non-empty strings for output purposes,
        # selecting properties and order defined by user input -Property parameter value.
        $outputStrArr = ($eventNormalizedArr | Select-Object $Property | Format-Table | Out-String).Split("`n").Where( { $_ } )

        # Define Out-String function header line count and separate table header from body.
        $headerLineCount = 2
        $outputStrHeaderArr = @($outputStrArr | Select-Object -First $headerLineCount)
        $outputStrBodyArr   = @($outputStrArr | Select-Object -Skip  $headerLineCount)

        # Output table contents according to Signal-dependent colors.
        Write-Host ''
        Write-Host ($outputStrHeaderArr -join "`n")
        for ($i = 0; $i -lt $outputStrBodyArr.Count; $i++)
        {
            $curEvent = $eventNormalizedArr[$i]

            # Set current line.
            $curLine = $outputStrBodyArr[$i]

            # Output current line with appropriate color based on Signal-contribution status.
            if ($curEvent.IsMapped -eq $true)
            {
                # Output current line with color-coded placeholder value(s).
                Show-StringWithTags -InputObject $curLine -PrimaryColor Green -SecondarySuccessColor Cyan
            }
            else
            {
                # Output current line as unmapped event.
                Write-Host $curLine -ForegroundColor Yellow
            }
        }
        Write-Host "`n"

        # Output pre-filtered session statistics generated at beginning of function
        # if user input -ShowStats parameter is defined.
        if ($PSBoundParameters['ShowStats'].IsPresent)
        {
            $sessionStatsObj
        }
    }
}



function Show-SessionSummaryUI
{
<#
.SYNOPSIS

Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the explicit user input actions in the UI console for simplified analysis and explainability.

Cloud Console Cartographer Function: Show-SessionSummaryUI
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-SessionSummary
Optional Dependencies: None

.DESCRIPTION

Show-SessionSummaryUI displays summary of session at the Signal level by merging unmapped events and Signal-bearing events, normalizing event values and mapped Signal values to support simultaneous display. The UI portion is a Python Flask app that uses Dash AG Grid.

.PARAMETER Event

Specifies enriched events (i.e. with Labels and potential Signals added via Add-Signal function) to summarize at the Signal level.

.PARAMETER Force

(Optional) Specifies that consent check and prompt be skipped even if first time running this function.

.EXAMPLE

PS C:\> dir ./Demo/InputEvents.json | Add-Signal | Show-SessionSummaryUI

[*] Executing Python visualizer via the following command: /opt/homebrew/bin/python3.11 "/Users/krileva/Projects/CloudConsoleCartographer-main/UI/Code/visualizer.py" "/Users/krileva/Projects/CloudConsoleCartographer-main/UI/Sessions/session_summary.csv"
Dash is running on http://127.0.0.1:8050/

 * Serving Flask app 'visualizer'
 * Debug mode: on

.NOTES

This is a project developed by Permiso Security's P0 Labs research team.
Authors: Andi Ahmeti (@SecEagleAnd1) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/CloudConsoleCartographer
https://twitter.com/SecEagleAnd1
https://twitter.com/danielhbohannon
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
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
        # Set default Flask app port for consistent output and error handling purposes.
        # NOTE: Changing below variable does NOT change port used by Flask (this would
        #       require updating ./UI/Code/Visualizer.py) but below variable should
        #       match ./UI/Code/Visualizer.py's defined port (8050 is the default).
        $flaskPort = 8050

        # Define all directories and file paths related to Python visualizer.
        $uiPath               = Join-Path -Path $scriptDir     -ChildPath 'UI'
        $uiScriptPath         = Join-Path -Path $uiPath        -ChildPath 'Code'
        $uiCodeVisualizerPath = Join-Path -Path $uiScriptPath  -ChildPath 'visualizer.py'
        $uiRequirementsPath   = Join-Path -Path $uiScriptPath  -ChildPath 'requirements.txt'
        $uiSessionPath        = Join-Path -Path $uiPath        -ChildPath 'Sessions'
        $uiSessionFilePath    = Join-Path -Path $uiSessionPath -ChildPath 'session_summary.csv'

        # Create ./UI/Sessions folder if it does not exist.
        if (-not (Test-Path -Path $uiSessionPath))
        {
            New-Item -ItemType Directory $uiSessionPath | Out-Null
        }

        # Merge unmapped events and mapped Signal-bearing events, normalizing event values
        # and mapped Signal values to support simultaneous display.
        $eventNormalizedArr = Out-SessionSummary -Event $eventArr

        # Convert normalized session summary of events to CSV and write to ./UI/Sessions
        # folder to be ingested by visualizer.
        $eventNormalizedArr | ConvertTo-Csv | Set-Content -Path $uiSessionFilePath

        Write-Verbose "Normalized session summary converted to CSV and output to $uiSessionFilePath"

        # Check for "accept flag" from any previous invocation.
        # If not found then prompt user for consent before executing Python visualizer.
        $uiConsentFlagPath = Join-Path -Path $uiScriptPath -ChildPath 'consent.txt'
        if (-not (Test-Path -Path $uiConsentFlagPath) -and -not $PSBoundParameters['Force'].IsPresent)
        {
            Write-Warning "This is your first time running the $($MyInvocation.MyCommand.Name) function which will execute a Python-based visualizer located at $uiCodeVisualizerPath and then launch a Flask app hosted as a local web server on port $flaskPort."

            # Request consent from user before continuing.
            $consentResponse = Read-Host -Prompt "[*] Please enter 'Y' or 'YES' if you consent to continuing execution of this function"

            # If consent was given then write consent file and output additional information
            # about Python requirements.
            # Otherwise do not continue with Python execution.
            if ($consentResponse -iin @('Y','YES'))
            {
                $uiConsentMessage = "Consent given at $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
                Set-Content -Path $uiConsentFlagPath -Value $uiConsentMessage

                Write-Host "[*] Consent has been recorded at " -NoNewline -ForegroundColor Cyan
                Write-Host $uiConsentFlagPath                  -NoNewline -ForegroundColor Yellow
                Write-Host " with the following message: "     -NoNewline -ForegroundColor Cyan
                Write-Host $uiConsentMessage                              -ForegroundColor Green

                Write-Host "[*] Ensure Python packages defined in " -NoNewline -ForegroundColor Cyan
                Write-Host $uiRequirementsPath                      -NoNewline -ForegroundColor Yellow
                Write-Host " are installed (e.g. python3 -m pip3 install -r ./UI/Code/requirements.txt)." -ForegroundColor Cyan
            }
            else
            {
                Write-Error 'Consent was not given to complete execution, so exiting now.'

                break
            }
        }

        # Check if existing Flask app is already listening on port 8050.
        # Is previous invocation of this project is already listening then attempt to
        # stop previous processes before continuing to avoid errors.
        # Utilities are OS-dependent for PowerShell versus pwsh, so split logic based on OS.
        if ($IsLinux -or $IsMacOS)
        {
            # Query PIDs of any existing processes already listening on localhost:8050.
            $pidsListeningOnFlaskPort = $IsLinux -or $IsMacOS ? `
                ((lsof -i "tcp@localhost:$flaskPort" -F pcn).Where( { $_ -cmatch 'p\d+' } ).ForEach( { ([System.String] $_).TrimStart('p') } ) | Select-Object -Unique) : `
                (Get-NetTCPConnection -LocalPort $flaskPort).OwningProcess | Select-Object -Unique

            if ($pidsListeningOnFlaskPort.Count -gt 0)
            {
                # Check process arguments for each PID listening on port 8050.
                # If process arguments match current project then attempt to stop process.
                foreach ($curPID in $pidsListeningOnFlaskPort)
                {
                    $curPIDProcArgs = $IsLinux -or $IsMacOS ? `
                        (ps -o args -p $curPID).Where( { $_.ToLower().Contains('python') -and $_.Contains($uiCodeVisualizerPath.Replace($scriptDir,'')) } ) : `
                        (Get-WmiObject Win32_Process -Filter "ProcessId = $curPid").CommandLine.Where( { $_.ToLower().Contains('python') -and $_.Contains($uiCodeVisualizerPath.Replace($scriptDir,'')) } )

                    # If process arguments match current project then attempt to stop process.
                    if ($curPIDProcArgs)
                    {
                        Write-Verbose "Stopping process: PID=$curPID, ARGS=$curPIDProcArgs"
                        Stop-Process -Id $curPID
                    }
                }
            }
        }

        # Identify path to python3.11 or greater (giving preference to lower versions).
        $pythonPath = ((Get-Command -CommandType Application -Name python3*).Where( { $_.Name.ToLower() -ge 'python3.11' -and $_.Name.ToLower() -cmatch '^python3\.[.\d]+$' } ) | Select-Object -First 1).Source

        # Execute Python UI Visualizer.
        Write-Host "[*] Executing Python visualizer via the following command: " -NoNewline -ForegroundColor Cyan
        Write-Host "$($pythonPath.Replace(' ','\ ')) `"$uiCodeVisualizerPath`" `"$uiSessionFilePath`"" -ForegroundColor Magenta
        Start-Process -FilePath $pythonPath -ArgumentList $uiCodeVisualizerPath,$uiSessionFilePath

        # Automatically open default web browser to current visualizer web app Url,
        # first checking that application successfully launched listener.
        for ($i = 0; $i -lt 10; $i++)
        {
            # Query PIDs of processes already listening on flask port.
            $pidsListeningOnFlaskPort = $IsLinux -or $IsMacOS ? `
                ((lsof -i "tcp@localhost:$flaskPort" -F pcn).Where( { $_ -cmatch 'p\d+' } ).ForEach( { ([System.String] $_).TrimStart('p') } ) | Select-Object -Unique) : `
                (Get-NetTCPConnection -LocalPort $flaskPort).OwningProcess | Select-Object -Unique

            # Sleep and continue to next for loop iteration if newly-launched Flask
            # app is not yet ready and listening.
            if ($pidsListeningOnFlaskPort.Count -eq 0)
            {
                Start-Sleep -Milliseconds 500

                continue
            }

            # Launch web browser since Flask app is now ready and listening.
            # Utilities are OS-dependent for PowerShell versus pwsh, so split logic based on OS.
            $visualizerUrl = "http://127.0.0.1:$flaskPort/"
            Write-Host "[*] Open your web browser and navigate to " -NoNewline -ForegroundColor Cyan
            Write-Host $visualizerUrl -ForegroundColor Green
            if ($IsLinux -or $IsMacOS)
            {
                open -u $visualizerUrl
            }

            # Break out of current for loop since web browser already launched.
            break
        }
    }
}
