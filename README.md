# Yara IR Scanner v1.0

## Warning & Disclaimer

I do not suggest running this without validating and testing it for yourself. This is not currently production ready.

## Prerequisites

1. If you want to scan against specific live Processes, edit the processes.json to add specific running processID's you want to scan.

2. Add Yara Rule files you want to use for scanning to the /YaraRules Dir

## Usage

This is intended for use in Microsoft Defender Live Response sessions. Upload the files you require and run using the following args.

YaraIRScanner.ps1 [-ScanType 1|2|3] [options]

Scan Types:  
  1  Scan all processes on the system  
  2  Scan processes from a JSON list  
  3  Scan files in a folder  

Parameters:  
  -ScanType <1|2|3>&emsp;&emsp;&emsp;           Required. Scan mode to execute  
  -FolderToScan <path> &emsp;&emsp;&emsp;       Required for ScanType 3. Folder containing files to scan  
  -RuleFolder <path>&emsp;&emsp;&emsp;          Custom YARA rules folder (default: .\YaraRules)  
  -OutputPath <path>&emsp;&emsp;&emsp;          Custom output directory (default: script directory)  
  -JsonPath <path>&emsp;&emsp;&emsp;            Custom JSON file path for ScanType 2 (default: .\processes.json)  
  -MaxThreads <int>&emsp;&emsp;&emsp;           Maximum concurrent scans (default: 10)  
  -IncludeSystemProcesses&emsp;&emsp;&emsp;     Include system processes in scan (use with caution)  
  -LogLevel <level>&emsp;&emsp;&emsp;           Logging verbosity: Critical, High, Medium, Low (default: Medium)  
  -ExportCsv&emsp;&emsp;&emsp;                  Export results to CSV format  
  -Help&emsp;&emsp;&emsp;                       Show this help message  

Examples:  
  .\Enhanced-YaraScanner.ps1 -ScanType 1 -LogLevel High  
  .\Enhanced-YaraScanner.ps1 -ScanType 3 -FolderToScan C:\Suspect -ExportCsv  
  .\Enhanced-YaraScanner.ps1 -ScanType 2 -JsonPath C:\IR\targets.json -MaxThreads 10  

Notes:  
  - Requires PowerShell 5.1 or later  
  - Administrator privileges recommended for process scanning  
  - Large scans may consume significant system resources

## Future Improvements

- Provide functionality to download yara rules to /YaraRules Dir from the web.
