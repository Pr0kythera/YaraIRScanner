# YaraIRScanner

Yara IR Scanner v1.0

Usage: YaraIRScanner.ps1 [-ScanType 1|2|3] [options]

Scan Types:  
  1  Scan all processes on the system  
  2  Scan processes from a JSON list  
  3  Scan files in a folder  

Parameters:  
  -ScanType <1|2|3>           Required. Scan mode to execute  
  -FolderToScan <path>        Required for ScanType 3. Folder containing files to scan  
  -RuleFolder <path>          Custom YARA rules folder (default: .\YaraRules)  
  -OutputPath <path>          Custom output directory (default: script directory)  
  -JsonPath <path>            Custom JSON file path for ScanType 2 (default: .\processes.json)  
  -MaxThreads <int>           Maximum concurrent scans (default: 10)  
  -IncludeSystemProcesses     Include system processes in scan (use with caution)  
  -LogLevel <level>           Logging verbosity: Critical, High, Medium, Low (default: Medium)  
  -ExportCsv                  Export results to CSV format  
  -Help                       Show this help message  

Examples:  
  .\Enhanced-YaraScanner.ps1 -ScanType 1 -LogLevel High  
  .\Enhanced-YaraScanner.ps1 -ScanType 3 -FolderToScan C:\Suspect -ExportCsv  
  .\Enhanced-YaraScanner.ps1 -ScanType 2 -JsonPath C:\IR\targets.json -MaxThreads 10  

Notes:  
  - Requires PowerShell 5.1 or later  
  - Administrator privileges recommended for process scanning  
  - Large scans may consume significant system resources  
