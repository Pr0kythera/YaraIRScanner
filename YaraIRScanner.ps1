# ==============================================================================
# Script Name:    YaraIRScanner.ps1
# Author:         Prokythera
# Date:           2025-06-01
# Description:    PowerShell script for YARA-based malware scanning
# Usage:          .\YaraIRScanner.ps1 -ScanType 1|2|3 [options]
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$Help,
    [ValidateSet(1,2,3)]
    [int]$ScanType,
    [string]$FolderToScan,
    [string]$RuleFolder,
    [string]$OutputPath,
    [string]$JsonPath,
    [int]$MaxThreads = 10,
    [switch]$IncludeSystemProcesses,
    [ValidateSet("Critical", "High", "Medium", "Low")]
    [string]$LogLevel = "Medium",
    [switch]$ExportCsv,
    [switch]$SkipDownload
)

# Script-level variables
$Script:Config = @{
    WorkingDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
    MaxRetries     = 3
    TimeoutSeconds = 30
    ChunkSize      = 100
}

$Script:Config.YaraZipPath    = Join-Path $Script:Config.WorkingDir "yara64.zip"
$Script:Config.YaraExtractDir = Join-Path $Script:Config.WorkingDir "yara64"
$Script:Config.DefaultRuleFolder = Join-Path $Script:Config.WorkingDir "YaraRules"
$Script:Config.DefaultJsonPath = Join-Path $Script:Config.WorkingDir "processes.json"

# Initialize collections for results
$Script:ScanResults = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
$Script:Errors = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()

function Show-Help {
    Write-Host @"
YARA IR Scanner v1.0
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
"@ -ForegroundColor Green
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("Critical", "High", "Medium", "Low", "Debug")]
        [string]$Level = "Medium",
        [string]$Component = "Main"
    )
    
    $levelPriority = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4; "Debug" = 5 }
    $currentPriority = $levelPriority[$LogLevel]
    $messagePriority = $levelPriority[$Level]
    
    if ($messagePriority -le $currentPriority) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] [$Component] $Message"
        
        $color = switch ($Level) {
            "Critical" { "Red" }
            "High"     { "Yellow" }
            "Medium"   { "White" }
            "Low"      { "Gray" }
            "Debug"    { "DarkGray" }
        }
        
        Write-Host $logEntry -ForegroundColor $color
        Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}

function Ensure-Yara-Exists {
    if (Test-Path (Join-Path $Script:Config.YaraExtractDir "yara64.exe")) {
        Write-Host "Skipping YARA download - using existing installation"
        Write-Log "Skipping YARA download - using existing installation" -Level "Medium" -Component "Setup"
        return $true
    }
    
    if (-not (Test-Path $Script:Config.YaraExtractDir)) {
        Write-Host "YARA not found. Downloading"
        Write-Log "YARA not found. Downloading" -Level "Medium" -Component "Setup"
        
        for ($retry = 1; $retry -le $Script:Config.MaxRetries; $retry++) {
            try {
                # Use specific version instead of latest for consistency
                $zipUri = "https://api.github.com/repos/VirusTotal/yara/releases/latest"
                
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($zipUri, $Script:Config.YaraZipPath)
                
                if (Test-Path $Script:Config.YaraZipPath) {
                    Expand-Archive -Path $Script:Config.YaraZipPath -DestinationPath $Script:Config.YaraExtractDir -Force
                    Remove-Item $Script:Config.YaraZipPath -Force -ErrorAction SilentlyContinue
                    Write-Log "YARA downloaded and extracted successfully" -Level "Medium" -Component "Setup"
                    break
                }
            } catch {
                Write-Log "Download attempt $retry failed: $_" -Level "High" -Component "Setup"
                if ($retry -eq $Script:Config.MaxRetries) {
                    Write-Log "Failed to download YARA after $($Script:Config.MaxRetries) attempts" -Level "Critical" -Component "Setup"
                    return $false
                }
                Start-Sleep -Seconds (2 * $retry)
            }
        }
    }
    
    $yaraExe = Join-Path $Script:Config.YaraExtractDir "yara64.exe"
    if (-not (Test-Path $yaraExe)) {
        Write-Log "yara64.exe not found at expected location: $yaraExe" -Level "Critical" -Component "Setup"
        return $false
    }
    
    # Verify YARA executable
    try {
        $version = & $yaraExe --version 2>&1
        Write-Log "YARA version verified: $version" -Level "Low" -Component "Setup"
    } catch {
        Write-Log "Failed to verify YARA executable: $_" -Level "Critical" -Component "Setup"
        return $false
    }
    
    return $true
}

function Get-SafeProcesses {
    param([switch]$IncludeSystem)
    
    $processes = Get-Process -ErrorAction SilentlyContinue
    
    if (-not $IncludeSystem) {
        # Filter out critical system processes to avoid issues
        $systemProcesses = @('System', 'Registry', 'smss', 'csrss', 'wininit', 'winlogon', 'lsass', 'services')
        $processes = $processes | Where-Object { $_.Name -notin $systemProcesses }
    }
    
    return $processes
}

function Invoke-YaraScan {
    param(
        [Parameter(Mandatory)]
        [string]$RuleFilePath,
        [Parameter(Mandatory)]
        [string]$Target,
        [string]$TargetType = "Unknown"
    )
    
    $yaraExe = Join-Path $Script:Config.YaraExtractDir "yara64.exe"
    $startTime = Get-Date
    
    try {
        # Use timeout to prevent hanging scans
        $job = Start-Job -ScriptBlock {
            param($exe, $rule, $target)
            & $exe -r $rule $target -D -p 10 2>&1
        } -ArgumentList $yaraExe, $RuleFilePath, $Target
        
        $result = Wait-Job $job -Timeout $Script:Config.TimeoutSeconds | Receive-Job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        
        $endTime = Get-Date
        $scanDuration = ($endTime - $startTime).TotalMilliseconds
        
        $scanResult = [PSCustomObject]@{
            Timestamp = $startTime
            Target = $Target
            TargetType = $TargetType
            Rule = (Split-Path $RuleFilePath -Leaf)
            RulePath = $RuleFilePath
            Result = $result
            HasMatch = $null -ne $result -and $result.Count -gt 0 -and $result -ne ""
            ScanDuration = $scanDuration
            Status = "Completed"
        }
        
        if ($scanResult.HasMatch) {
            Write-Log "MATCH FOUND: $Target -> $($scanResult.Rule)" -Level "High" -Component "Scanner"
        } else {
            Write-Log "No match: $Target -> $($scanResult.Rule)" -Level "Debug" -Component "Scanner"
        }
        
        $Script:ScanResults.Add($scanResult)
        return $scanResult
        
    } catch {
        $errorResult = [PSCustomObject]@{
            Timestamp = Get-Date
            Target = $Target
            TargetType = $TargetType
            Rule = (Split-Path $RuleFilePath -Leaf)
            Error = $_.Exception.Message
            Status = "Error"
        }
        
        Write-Log "Scan error for $Target with rule $((Split-Path $RuleFilePath -Leaf)): $_" -Level "High" -Component "Scanner"
        $Script:Errors.Add($errorResult)
        return $errorResult
    }
}

function Scan-AllProcesses {
    param(
        [string]$RuleFolder,
        [string]$OutputFile
    )
    
    $rules = Get-ChildItem -Path $RuleFolder -Filter *.yar* -File -ErrorAction SilentlyContinue
    if ($rules.Count -eq 0) {
        Write-Log "No YARA rules found in $RuleFolder" -Level "Critical" -Component "ProcessScan"
        return
    }
    
    $processes = Get-SafeProcesses -IncludeSystem:$IncludeSystemProcesses
    Write-Log "Scanning $($processes.Count) processes with $($rules.Count) rules" -Level "Medium" -Component "ProcessScan"
    
    $totalScans = $processes.Count * $rules.Count
    $completedScans = 0
    
    # Process in chunks to manage memory
    $processChunks = for ($i = 0; $i -lt $processes.Count; $i += $Script:Config.ChunkSize) {
        $processes[$i..([Math]::Min($i + $Script:Config.ChunkSize - 1, $processes.Count - 1))]
    }
    
    foreach ($chunk in $processChunks) {
        $jobs = @()
        
        foreach ($proc in $chunk) {
            foreach ($rule in $rules) {
                $jobs += Start-Job -ScriptBlock {
                    param($processId, $processName, $rulePath, $functionDef)
                    
                    # Recreate function in job scope
                    Invoke-Expression $functionDef
                    
                    return Invoke-YaraScan -RuleFilePath $rulePath -Target $processId -TargetType "Process"
                } -ArgumentList $proc.Id, $proc.Name, $rule.FullName, ${function:Invoke-YaraScan}.ToString()
                
                # Limit concurrent jobs
                while ((Get-Job -State Running).Count -ge $MaxThreads) {
                    Start-Sleep -Milliseconds 100
                }
            }
        }
        
        # Wait for chunk completion
        $jobs | Wait-Job | Receive-Job | Out-Null
        $jobs | Remove-Job -Force
        
        $completedScans += $chunk.Count * $rules.Count
        $percentComplete = [Math]::Round(($completedScans / $totalScans) * 100, 2)
        Write-Log "Progress: $percentComplete% ($completedScans/$totalScans scans completed)" -Level "Low" -Component "ProcessScan"
    }
}

function Scan-ProcessesFromJson {
    param(
        [string]$JsonPath,
        [string]$RuleFolder,
        [string]$OutputFile
    )
    
    if (-not (Test-Path $JsonPath)) {
        Write-Log "JSON file not found: $JsonPath" -Level "Critical" -Component "JsonScan"
        return
    }
    
    try {
        $jsonContent = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
        Write-Log "Loaded $($jsonContent.Count) targets from JSON" -Level "Medium" -Component "JsonScan"
    } catch {
        Write-Log "Failed to parse JSON file: $_" -Level "Critical" -Component "JsonScan"
        return
    }
    
    $rules = Get-ChildItem -Path $RuleFolder -Filter *.yar* -File -ErrorAction SilentlyContinue
    if ($rules.Count -eq 0) {
        Write-Log "No YARA rules found in $RuleFolder" -Level "Critical" -Component "JsonScan"
        return
    }
    
    foreach ($target in $jsonContent) {
        foreach ($rule in $rules) {
            Invoke-YaraScan -RuleFilePath $rule.FullName -Target $target.pid -TargetType "Process"
        }
    }
}

function Scan-FilesInFolder {
    param(
        [string]$FolderToScan,
        [string]$RuleFolder,
        [string]$OutputFile
    )
    
    if (-not (Test-Path $FolderToScan -PathType Container)) {
        Write-Log "Scan folder not found: $FolderToScan" -Level "Critical" -Component "FileScan"
        return
    }
    
    $files = Get-ChildItem -Path $FolderToScan -File -Recurse -ErrorAction SilentlyContinue
    Write-Log "Found $($files.Count) files to scan" -Level "Medium" -Component "FileScan"
    
    $rules = Get-ChildItem -Path $RuleFolder -Filter *.yar* -File -ErrorAction SilentlyContinue
    if ($rules.Count -eq 0) {
        Write-Log "No YARA rules found in $RuleFolder" -Level "Critical" -Component "FileScan"
        return
    }
    
    foreach ($file in $files) {
        foreach ($rule in $rules) {
            Invoke-YaraScan -RuleFilePath $rule.FullName -Target "`"$($file.FullName)`"" -TargetType "File"
        }
    }
}

function Export-Results {
    param(
        [string]$OutputPath,
        [switch]$ExportCsv
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $baseFileName = "YaraScanResults_$timestamp"
    
    # Export detailed results
    $resultsFile = Join-Path $OutputPath "$baseFileName.json"
    $Script:ScanResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultsFile -Encoding UTF8
    Write-Log "Detailed results exported to: $resultsFile" -Level "Medium" -Component "Export"
    
    # Export matches only
    $matches = $Script:ScanResults | Where-Object { $_.HasMatch }
    if ($matches) {
        $matchesFile = Join-Path $OutputPath "$baseFileName`_matches.json"
        $matches | ConvertTo-Json -Depth 3 | Out-File -FilePath $matchesFile -Encoding UTF8
        Write-Log "Matches exported to: $matchesFile" -Level "Medium" -Component "Export"
        
        if ($ExportCsv) {
            $csvFile = Join-Path $OutputPath "$baseFileName`_matches.csv"
            $matches | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Log "CSV export created: $csvFile" -Level "Medium" -Component "Export"
        }
    }
    
    # Export errors if any
    if ($Script:Errors.Count -gt 0) {
        $errorsFile = Join-Path $OutputPath "$baseFileName`_errors.json"
        $Script:Errors | ConvertTo-Json -Depth 3 | Out-File -FilePath $errorsFile -Encoding UTF8
        Write-Log "Errors exported to: $errorsFile" -Level "Medium" -Component "Export"
    }
    
    return $resultsFile
}

function Show-Summary {
    $totalScans = $Script:ScanResults.Count
    $matches = ($Script:ScanResults | Where-Object { $_.HasMatch }).Count
    $errors = $Script:Errors.Count
    $avgScanTime = if ($totalScans -gt 0) { 
        [Math]::Round(($Script:ScanResults | Measure-Object -Property ScanDuration -Average).Average, 2) 
    } else { 0 }
    
    Write-Host "`n" -NoNewline
    Write-Host "=== SCAN SUMMARY ===" -ForegroundColor Green
    Write-Host "Total Scans: $totalScans" -ForegroundColor White
    Write-Host "Matches Found: $matches" -ForegroundColor $(if ($matches -gt 0) { "Red" } else { "Green" })
    Write-Host "Errors: $errors" -ForegroundColor $(if ($errors -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Average Scan Time: $avgScanTime ms" -ForegroundColor White
    
    if ($matches -gt 0) {
        Write-Host "`nMATCHES DETECTED - REVIEW IMMEDIATELY" -ForegroundColor Red -BackgroundColor Yellow
    }
}

# Main execution
try {
    if ($Help) {
        Show-Help
        exit 0
    }
    
    if (-not $ScanType) {
        Write-Host "Error: ScanType parameter is required" -ForegroundColor Red
        Show-Help
        exit 1
    }
    
    # Initialize paths
    $outputDir = if ($OutputPath) { $OutputPath } else { $Script:Config.WorkingDir }
    $ruleDir = if ($RuleFolder) { $RuleFolder } else { $Script:Config.DefaultRuleFolder }
    $jsonFile = if ($JsonPath) { $JsonPath } else { $Script:Config.DefaultJsonPath }
    
    # Create log file
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $Script:LogFile = Join-Path $outputDir "YaraScan_$timestamp.log"
    
    Write-Log "Enhanced YARA Scanner v2.0 Starting" -Level "Medium" -Component "Main"
    Write-Log "Scan Type: $ScanType" -Level "Medium" -Component "Main"
    
    # Validate parameters
    if ($ScanType -eq 3 -and (-not $FolderToScan -or -not (Test-Path $FolderToScan))) {
        Write-Log "Valid FolderToScan required for ScanType 3" -Level "Critical" -Component "Main"
        exit 1
    }
    
    
    # Ensure YARA is available
    if (-not (Ensure-Yara-Exists)) {
        Write-Log "Failed to setup YARA environment" -Level "Critical" -Component "Main"
        exit 1
    }
    
    # Execute scan based on type
    $scanStart = Get-Date
    switch ($ScanType) {
        1 { Scan-AllProcesses -RuleFolder $ruleDir -OutputFile $Script:LogFile }
        2 { Scan-ProcessesFromJson -JsonPath $jsonFile -RuleFolder $ruleDir -OutputFile $Script:LogFile }
        3 { Scan-FilesInFolder -FolderToScan $FolderToScan -RuleFolder $ruleDir -OutputFile $Script:LogFile }
    }
    $scanEnd = Get-Date
    
    Write-Log "Scan completed in $([Math]::Round(($scanEnd - $scanStart).TotalMinutes, 2)) minutes" -Level "Medium" -Component "Main"
    
    # Export results
    $resultsFile = Export-Results -OutputPath $outputDir -ExportCsv:$ExportCsv
    
    # Show summary
    Show-Summary
    
    Write-Log "Scan process completed successfully" -Level "Medium" -Component "Main"
    
} catch {
    Write-Log "Fatal error: $_" -Level "Critical" -Component "Main"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "Debug" -Component "Main"
    exit 1
}
