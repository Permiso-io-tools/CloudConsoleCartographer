![CloudConsoleCartographer](https://github.com/Permiso-io-tools/CloudConsoleCartographer/blob/main/Images/Cloud-Console-Cartographer.svg "Cloud Console Cartographer Logo")

# Cloud Console Cartographer

Released at Black Hat Asia on April 18, 2024, Cloud Console Cartographer is a framework for condensing groupings of cloud events (e.g. CloudTrail logs) and mapping them to the original user input actions in the management console UI for simplified analysis and explainability. This is extremely beneficial for defenders since numerous input actions in management console sessions can generate 10's and even many 100's of events originating from a single interactive click by the end user.

An additional capability that Cloud Console Cartographer provides defenders is the parsing of relevant data from all events related to each mapping. For example, when a user clicks on IAM->Users in the AWS Management Console and 100+ events are generated, this framework parses these logs and extracts all IAM users and long-lived access keys that were active at the time the logs were generated. This leads to point-in-time context of the environment and increased levels of visibility into what the user was seeing in the UI at the time of their activity.

An example of this IAM->Users scenario is shown below:
![CloudConsoleCartographer](https://github.com/Permiso-io-tools/CloudConsoleCartographer/blob/main/Images/IAM_Users_Screenshot.png "IAM Users Screenshot")

Lastly, what framework would be complete without some ASCII art:
![CloudConsoleCartographer](https://github.com/Permiso-io-tools/CloudConsoleCartographer/blob/main/Images/CLI_ASCII_Art.png "Cloud Console Cartographer ASCII Art")

## Installation

>```PowerShell
>Import-Module ./CloudConsoleCartographer.psd1
>```

## Requirements (main functionality)

>```bash
>pwsh 6+
>```

## Requirements (UI Visualizer)

>```bash
>python3.11
>python3 -m pip3 install -r ./UI/Code/requirements.txt
>```

## Usage

This tool offers a CLI (Command Line Interface) for processing cloud logs and simple displaying of results on the command line. More interactive analysis is better served using the Python UI Visualizer. Let's review its most common use cases:

## Example 1 - Running the tool with local CloudTrail logs and event-level CLI summary

Use the demo CloudTrail session stored in ./Demo to quickly see the power of the framework's aggregation and enhanced explainability, though as later examples will show logs can be piped into this framework's functions without requiring anything being written to disk.

### Note

First invoke `Add-Signal` to apply Labels and to perform Signal/mapping evaluation. Then pass these results to one of many output functions.

Run command:

```dir ./Demo/InputEvents.json | Add-Signal -Verbose | Show-EventSummary -Detail signal```

![CloudConsoleCartographer](https://github.com/Permiso-io-tools/CloudConsoleCartographer/blob/main/Images/Show-EventSummary_Screenshot.png "Show-EventSummary Screenshot")

## Example 2 - Running the tool with CloudTrail logs queried directly from CloudTrail API and session-level CLI summary

```aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIAPERSHENDETJEMIQ1 | Add-Signal | Show-SessionSummary```

![CloudConsoleCartographer](https://github.com/Permiso-io-tools/CloudConsoleCartographer/blob/main/Images/Show-SessionSummary_Screenshot.png "Show-EventSummary Screenshot")

## Example 3 - Using Python-based UI Visualizer

```cat ./Demo/InputEvents.json | Add-Signal | Show-SessionSummaryUI```

![CloudConsoleCartographer](https://github.com/Permiso-io-tools/CloudConsoleCartographer/blob/main/Images/Show-SessionSummaryUI_Screenshot.png "Show-SessionSummaryUI Screenshot")
