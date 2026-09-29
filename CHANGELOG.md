# Changelog

All notable changes to this project will be documented in this file.

## 1.2.0 - September 2026

This release renames functions for naming consistency and fixes several logging/auth bugs:

- Renamed 20 functions to drop the redundant "Uem" segment (e.g. Get-UemStaleDevices -> Get-StaleDevices, Invoke-DownloadUemAppBlob -> Invoke-DownloadAppBlob, Clear-UemDevicePasscode -> Clear-DevicePasscode); Get-DevicesExtensive renamed to Get-Devices. Breaking change - update any scripts calling the old names.
- Get-ServerAuth automatically prepends "https://" to -Server when the scheme is omitted
- Write-Log: -Path was declared incorrectly and never actually bound as a parameter; fixed so -Path/-LogPath/-LogLocation all work correctly
- Write-Log: messages at Info/Success level were silently dropped from the log file and console; all levels are now written
- Write-Log and Get-Log: OS delimiter detection was inverted on PowerShell 7+ (always used "\" regardless of platform); corrected for cross-platform use
- Write-Log and Get-Log: no longer throw when called outside a running script; fall back gracefully to a generic name/location
- Get-Log gained the same script-name/date/current-folder auto-detection as Write-Log; -logFileName and -current_path are now optional
- Invoke-AWApiCommand: fixed invalid parameter calls in the retry/error-handling path that could throw, and corrected the "server offline" detection which previously never matched
- Added Tests/run_full_suite.ps1, a combined live/mocked smoke test exercising every exported function against a real tenant

Total functions exported: 58

## 1.1.0 - August 2026

This release adds application lifecycle operations and refines existing functions:

- Application lifecycle operations (icon upload, chunked upload, app creation, URL-based uploads, blob UUID download)
- Get-App consolidates app search and catalog listing into a single function (previously split across Get-App and Get-UemApplications), adding optional AppName/GroupId/Platform filters and automatic multi-page result retrieval so large catalogs are no longer truncated at the first page
- Invoke-DownloadUemApp: finds an application by name (prompting to disambiguate when multiple match, matching the Invoke-OGSearch UX) and downloads its blob in one call
- Show-Toast gains an optional -Timeout (Short/Long) parameter for auto-dismissing toasts; toasts remain persistent (reminder-scenario) by default
- Internal Basic-auth credential helper renamed New-BasicAuthCredential -> Get-BasicAuthCredential (not exported; no impact on public API)

Total functions exported: 58

## 1.0.0 - May 2026

This release delivers comprehensive WS1 UEM automation coverage across major workflows:

- Authentication and configuration (OAuth 2.0, basic auth, retry-enabled API invocation)
- Organization discovery and search (OG lookup, enrollment context retrieval)
- Device discovery, tagging, and lifecycle management (stale/duplicate/problematic detection, bulk deletion, passcode clear, device property updates)
- Application lifecycle operations (icon upload, chunked upload, app creation, catalog queries, URL-based uploads)
- Baseline reporting and assignment insights (templates, devices, policies, summary views)
- Agent deployment and maintenance (download, install, uninstall, cleanup, app/profile wait operations)
- User identity and enrollment correlation (SID lookups, duplicate user detection and cleanup)
- Local system and utility operations (registry access, task creation, notifications, tagging)
- Logging and reporting utilities for operational visibility

Total functions exported: 57

Notes:
- Capability descriptions can be sourced from each function's PowerShell help .DESCRIPTION block
- Example: Get-Help <FunctionName> -Full
