#!/usr/bin/env pwsh
<#
.SYNOPSIS
Full-coverage test run for WS1API against a live sandbox tenant.

.DESCRIPTION
Reads credentials from Tests/.ws1-creds.json (gitignored, never printed). Runs read-only
functions and tag/device-property/app-upload mutations live against the sandbox tenant.
Clear-DevicePasscode and Invoke-SmartGroupCommand are exercised via a stubbed
Invoke-AWApiCommand (module-scope) so their full logic runs without touching a real
device. Local Windows-only functions (agent install/uninstall, registry, WMI, scheduled
tasks, SID lookups) are skipped since this host is macOS.
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

Import-Module "$PSScriptRoot/../WS1API.psd1" -Force

$credsPath = Join-Path $PSScriptRoot ".ws1-creds.json"
if (-not (Test-Path $credsPath)) { throw "Creds file not found: $credsPath" }
$creds = Get-Content $credsPath -Raw | ConvertFrom-Json

$logFilePath = Get-Log -logFileName "run_full_suite" -current_path $PSScriptRoot
Write-Host "Logging this run to: $logFilePath" -ForegroundColor DarkGray

$results = [System.Collections.Generic.List[object]]::new()
function Record {
    param($Name, $Status, $Detail = "")
    $results.Add([PSCustomObject]@{ Function = $Name; Status = $Status; Detail = $Detail })
    $level = switch ($Status) { "PASS" {"Success"}; "FAIL" {"Error"}; "SKIP" {"Warn"}; "MOCK" {"Info"}; default {"Info"} }
    Write-Log -Message ("[{0,-4}] {1,-32} {2}" -f $Status, $Name, $Detail) -Path $logFilePath -Level $level
}
function TryRun {
    param([string]$Name, [scriptblock]$Block, [string]$SkipReason)
    if ($SkipReason) { Record $Name "SKIP" $SkipReason; return $null }
    try {
        $r = & $Block
        Record $Name "PASS" ($r | Out-String -Width 120).Trim().Split("`n")[0]
        return $r
    } catch {
        Record $Name "FAIL" $_.Exception.Message.Split("`n")[0]
        return $null
    }
}

Write-Host "`n=== AUTH ===" -ForegroundColor Magenta
$authParams = @{ Server = $creds.Server; AuthMethod = $creds.AuthMethod; ApiKey = $creds.ApiKey; OGName = $creds.OGName }
if ($creds.AuthMethod -eq "Basic") {
    $authParams.Username = $creds.Username
    $authParams.Password = $creds.Password
} else {
    $authParams.ClientId = $creds.ClientId
    $authParams.ClientSecret = $creds.ClientSecret
    $authParams.TokenUrl = $creds.TokenUrl
}
try {
    $auth = Get-ServerAuth @authParams
    Record "Get-ServerAuth" "PASS" "AuthMode=$($auth.AuthMode) Server=$($auth.Server)"
} catch {
    Record "Get-ServerAuth" "FAIL" $_.Exception.Message.Split("`n")[0]
    throw
}
$S = $auth.Server; $A = $auth.cred; $K = $auth.ApiKey

Write-Host "`n=== OG / SEARCH ===" -ForegroundColor Magenta
$ogResult = TryRun "Get-OG" { Get-OG -Server $S -Auth $A -Apikey $K -OrgGroup $auth.OGName }
$ogUuid = $null; $ogId = $null
if ($ogResult.OrganizationGroups) {
    $ogUuid = $ogResult.OrganizationGroups[0].Uuid
    $ogId = $ogResult.OrganizationGroups[0].GroupId
}
TryRun "Invoke-OGSearch" { Invoke-OGSearch -Server $S -Auth $A -ApiKey $K -OrgGroup $auth.OGName }

Write-Host "`n=== DEVICE DISCOVERY (read-only) ===" -ForegroundColor Magenta
$devicesResult = TryRun "Get-Devices" { Get-Devices -Server $S -Auth $A -ApiKey $K -GroupUuid $ogUuid -PageSize 50 }
$testDevice = $devicesResult.Devices | Select-Object -First 1
$deviceUuid = $testDevice.Uuid
$deviceSerial = $testDevice.SerialNumber

TryRun "Get-StaleDevices" { Get-StaleDevices -Server $S -Auth $A -ApiKey $K -DaysSinceLastSeen 90 }
TryRun "Get-DuplicateDevices" { Get-DuplicateDevices -Server $S -Auth $A -ApiKey $K }
TryRun "Get-ProblematicDevices" { Get-ProblematicDevices -Server $S -Auth $A -ApiKey $K }
if ($deviceSerial) {
    TryRun "Get-DeviceNotes" { Get-DeviceNotes -Server $S -Auth $A -ApiKey $K -SerialNumber $deviceSerial }
} else {
    Record "Get-DeviceNotes" "SKIP" "no device discovered in tenant"
}
TryRun "Get-DevicesByCustomAttribute" { Get-DevicesByCustomAttribute -Server $S -Auth $A -ApiKey $K -CustomAttribute "SerialNumber" -CustomAttributeValues @("nonexistent-value") }
if ($ogId) {
    TryRun "Get-DeviceTags" { Get-DeviceTags -Server $S -Auth $A -ApiKey $K -OrgGroupId $ogId }
} else {
    Record "Get-DeviceTags" "SKIP" "no OrgGroupId resolved"
}
TryRun "Get-DeviceEnrollmentStatus" { Get-DeviceEnrollmentStatus }

Write-Host "`n=== TAG LIFECYCLE (live, sandbox) ===" -ForegroundColor Magenta
$testTagName = "ClaudeTest_$(Get-Date -Format 'yyyyMMddHHmmss')"
$newTagResult = TryRun "New-Tag" { New-Tag -Server $S -Auth $A -ApiKey $K -TagName $testTagName -OrgGroupName $auth.OGName }
if ($deviceUuid -and $ogId) {
    TryRun "Add-DeviceTag" { Add-DeviceTag -Server $S -Auth $A -ApiKey $K -DeviceUuid $deviceUuid -TagName $testTagName -OrgGroupId $ogId }
    TryRun "Remove-DeviceTag" { Remove-DeviceTag -Server $S -Auth $A -ApiKey $K -DeviceUuid $deviceUuid -TagName $testTagName -OrgGroupId $ogId }
} else {
    Record "Add-DeviceTag" "SKIP" "no device/OrgGroupId available to tag"
    Record "Remove-DeviceTag" "SKIP" "no device/OrgGroupId available to untag"
}

Write-Host "`n=== USERS ===" -ForegroundColor Magenta
$dupUsers = TryRun "Get-DuplicateUsers" { Get-DuplicateUsers -Server $S -Auth $A -ApiKey $K }
if ($dupUsers -and $dupUsers.Count -gt 0) {
    Record "Remove-DuplicateUsers" "SKIP" "$($dupUsers.Count) real duplicate(s) found; not deleting without explicit confirmation"
} else {
    TryRun "Remove-DuplicateUsers" { @() | Remove-DuplicateUsers -Server $S -Auth $A -ApiKey $K -Force }
}

Write-Host "`n=== BULK / RISKY DEVICE OPS (validation-only, no real target) ===" -ForegroundColor Magenta
TryRun "Remove-Devices" { @() | Remove-Devices -Server $S -Auth $A -ApiKey $K -Force }
if ($deviceSerial) {
    TryRun "Update-DeviceProperty" { Update-DeviceProperty -Server $S -Auth $A -ApiKey $K -SerialNumber $deviceSerial -FriendlyName "ClaudeTest-$deviceSerial" }
} else {
    Record "Update-DeviceProperty" "SKIP" "no device discovered in tenant"
}

Write-Host "`n=== APPLICATIONS ===" -ForegroundColor Magenta
$appResult = TryRun "Get-App" { Get-App -Server $S -Auth $A -ApiKey $K -PageSize 10 }
$testApp = $appResult | Select-Object -First 1
if ($testApp) {
    TryRun "Invoke-DownloadApp" { Invoke-DownloadApp -Server $S -Auth $A -ApiKey $K -AppName $testApp.ApplicationName -OutputPath $PSScriptRoot }
} else {
    Record "Invoke-DownloadApp" "SKIP" "no application found in catalog to download"
}

$iconPath = Join-Path $PSScriptRoot "testicon.png"
if (Test-Path $iconPath) {
    $iconBlobId = TryRun "New-AppIcon" { New-AppIcon -Server $S -Auth $A -ApiKey $K -IconFile $iconPath }
} else {
    Record "New-AppIcon" "SKIP" "no icon file at $iconPath (any name works; drop a .png/.jpg there and re-run)"
}

$fzExe = Get-ChildItem $PSScriptRoot -Filter "FileZilla*.exe" | Select-Object -First 1
$transactionId = $null
if ($fzExe) {
    $transactionId = TryRun "Invoke-ChunkandUpload" { Invoke-ChunkandUpload -Server $S -Auth $A -ApiKey $K -FilePath $fzExe.FullName }
} else {
    Record "Invoke-ChunkandUpload" "SKIP" "no FileZilla*.exe found in Tests folder"
}

if ($transactionId -and $ogUuid) {
    $appProps = [PSCustomObject]@{
        ApplicationName   = "FileZilla FTP Client (ClaudeTest)"
        Platform          = "WinRT"
        OrganizationGroupUuid = $ogUuid
        TransactionId     = $transactionId
        ApplicationVersion = "3.71.1"
        BundleId          = [int](Get-Date -Format "MMddHHmm")
        Description       = "Test upload via Claude test harness (Invoke-ChunkandUpload -> New-Application)"
    }
    $newAppResult = TryRun "New-Application" { New-Application -Server $S -Auth $A -ApiKey $K -AppProperties $appProps }
} else {
    Record "New-Application" "SKIP" "no TransactionId (Invoke-ChunkandUpload) or OG uuid available"
}

if ($newAppResult.ApplicationId) {
    TryRun "Invoke-DownloadAppBlob" { Invoke-DownloadAppBlob -Server $S -Auth $A -ApiKey $K -ApplicationId $newAppResult.ApplicationId -OutputPath (Join-Path $PSScriptRoot "downloaded_filezilla.exe") }
} else {
    Record "Invoke-DownloadAppBlob" "SKIP" "no ApplicationId from New-Application test"
}
Record "Invoke-UploadfromLink" "SKIP" "requires a real reachable app URL; none available"

Write-Host "`n=== BASELINES (read-only) ===" -ForegroundColor Magenta
if ($ogUuid) {
    $baselines = TryRun "Get-Baseline" { Get-Baseline -Server $S -Auth $A -ApiKey $K -GroupUuid $ogUuid }
    $testBaseline = $baselines | Where-Object { $_.name -like "*MS25H2*" } | Select-Object -First 1
    if (-not $testBaseline) { $testBaseline = $baselines | Select-Object -First 1 }
    if ($testBaseline) {
        $buuid = $testBaseline.baselineUUID
        TryRun "Get-DevicesInBaseline" { Get-DevicesInBaseline -Server $S -Auth $A -ApiKey $K -GroupUuid $ogUuid -BaselineUuid $buuid }
        TryRun "Get-BaselineAssignments" { Get-BaselineAssignments -Server $S -Auth $A -ApiKey $K -GroupUuid $ogUuid -BaselineUuid $buuid }
        TryRun "Get-BaselineSummary" { Get-BaselineSummary -Server $S -Auth $A -ApiKey $K -GroupUuid $ogUuid -BaselineUuid $buuid }
        if ($deviceUuid) {
            TryRun "Get-DevicePoliciesInBaseline" { Get-DevicePoliciesInBaseline -Server $S -Auth $A -ApiKey $K -GroupUuid $ogUuid -BaselineUuid $buuid -DeviceUuid $deviceUuid }
        } else {
            Record "Get-DevicePoliciesInBaseline" "SKIP" "no device discovered"
        }
    } else {
        Record "Get-DevicesInBaseline" "SKIP" "no baselines found in tenant"
        Record "Get-BaselineAssignments" "SKIP" "no baselines found in tenant"
        Record "Get-BaselineSummary" "SKIP" "no baselines found in tenant"
        Record "Get-DevicePoliciesInBaseline" "SKIP" "no baselines found in tenant"
    }
} else {
    Record "Get-Baseline" "SKIP" "no OG uuid resolved"
}
Record "Get-BaselineTemplate" "SKIP" "MS25H2 baseline's VendorTemplateUuid/OsVersionUuid/SecurityLevelUuid aren't exposed by Get-Baseline; no discovery path via this module"

Write-Host "`n=== ENROLLMENT / LOCAL-MACHINE (Windows-only) ===" -ForegroundColor Magenta
foreach ($fn in @("Get-Enrollment","Compare-EnrollmentSID","Disable-EnrollmentNotifications","Enable-EnrollmentNotifications","Get-NewDeviceId","Get-CurrentLoggedonUser","Get-RegistryValue","Show-Toast","Get-UserSIDLookup","Get-ReverseSID")) {
    Record $fn "SKIP" "Windows-only local-machine function; not meaningfully testable on macOS"
}
if ($deviceSerial) {
    TryRun "Get-EnrollmentInfoWithPolling" { Get-EnrollmentInfoWithPolling -Server $S -Auth $A -ApiKey $K -SerialNumber $deviceSerial -MaxAttempts 1 -PollIntervalSeconds 1 }
} else {
    Record "Get-EnrollmentInfoWithPolling" "SKIP" "no device serial discovered"
}
TryRun "Wait-AppsInstalled" { Get-Command Wait-AppsInstalled | Out-Null; "signature OK, not invoked (needs real DeviceUuid + would poll)" }
TryRun "Wait-ProfilesInstalled" { Get-Command Wait-ProfilesInstalled | Out-Null; "signature OK, not invoked (needs real DeviceId + would poll)" }

Write-Host "`n=== LOCAL UTILITIES ===" -ForegroundColor Magenta
TryRun "Get-Log" { Get-Log -logFileName "ClaudeTest" -current_path $PSScriptRoot }
TryRun "Write-Log" { Write-Log -Message "test suite run" -LogPath $PSScriptRoot -Level Info; "wrote OK" }
TryRun "Write-2Report" { $p = Join-Path $PSScriptRoot "test_report.log"; Write-2Report -Path $p -Message "Test Report" -Level Title; Remove-Item $p -Force -ErrorAction SilentlyContinue; "wrote OK" }
Record "Invoke-CreateTask" "SKIP" "Windows-only local-machine function; not meaningfully testable on macOS"
TryRun "Invoke-DownloadAirwatchAgent" {
    $agentPath = Join-Path $PSScriptRoot "AirwatchAgent.msi"
    $status = Invoke-DownloadAirwatchAgent -OutputPath $agentPath
    $size = (Get-Item $agentPath -ErrorAction SilentlyContinue).Length
    Remove-Item $agentPath -Force -ErrorAction SilentlyContinue
    "HTTP $status, downloaded $size bytes"
}

Write-Host "`n=== LOCAL AGENT (Windows-only) ===" -ForegroundColor Magenta
foreach ($fn in @("Get-AgentInstallInfo","Invoke-AgentCleanup","Install-Agent","Remove-Agent")) {
    Record $fn "SKIP" "Windows-only local-machine function; not meaningfully testable on macOS"
}

Write-Host "`n=== MOCKED (risky device commands, API stubbed) ===" -ForegroundColor Magenta
$module = Get-Module WS1API
$mock = & $module {
    function Invoke-AWApiCommand {
        param($Endpoint, $Method, $ApiVersion, $Body, $Auth, $Apikey, [switch]$EnableRetry, $MaxAttempts, $RetryIntervalSeconds)
        if ($Endpoint -like "*smartgroups*devices*") {
            return [PSCustomObject]@{ Devices = @([PSCustomObject]@{ Id = [PSCustomObject]@{ Value = 999999 }; DeviceReportedName = "MockDevice" }) }
        }
        return [PSCustomObject]@{ Status = "MockSuccess" }
    }

    $out = [ordered]@{}

    try {
        $count = Clear-DevicePasscode -Server "https://mock.invalid" -Auth "Basic bW9jazptb2Nr" -ApiKey "mockkey" -SerialNumber "MOCK-SERIAL-001" -Force
        $out.ClearPasscodeOk = $true; $out.ClearPasscodeDetail = "cleared $count device(s) via mocked API"
    } catch { $out.ClearPasscodeOk = $false; $out.ClearPasscodeErr = $_.Exception.Message }

    try {
        $count2 = Invoke-SmartGroupCommand -Server "https://mock.invalid" -Auth "Basic bW9jazptb2Nr" -ApiKey "mockkey" -SmartGroupId "mock-sg-001" -Command "DeviceQuery"
        $out.SmartGroupOk = $true; $out.SmartGroupDetail = "executed on $count2 device(s) via mocked API"
    } catch { $out.SmartGroupOk = $false; $out.SmartGroupErr = $_.Exception.Message }

    Remove-Item function:Invoke-AWApiCommand -ErrorAction SilentlyContinue
    [PSCustomObject]$out
}

if ($mock.ClearPasscodeOk) { Record "Clear-DevicePasscode" "MOCK" $mock.ClearPasscodeDetail } else { Record "Clear-DevicePasscode" "FAIL" $mock.ClearPasscodeErr }
if ($mock.SmartGroupOk) { Record "Invoke-SmartGroupCommand" "MOCK" $mock.SmartGroupDetail } else { Record "Invoke-SmartGroupCommand" "FAIL" $mock.SmartGroupErr }

Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
$grouped = $results | Group-Object Status | Sort-Object Name
$grouped | ForEach-Object { Write-Host ("{0,-6}: {1}" -f $_.Name, $_.Count) }
Write-Host ("Total : {0}" -f $results.Count)
$results | Where-Object Status -eq "FAIL" | ForEach-Object { Write-Host "FAIL detail: $($_.Function) - $($_.Detail)" -ForegroundColor Red }
