# WS1API

A comprehensive PowerShell module for interacting with Omnissa Workspace ONE UEM RestAPI. Features OAuth 2.0 authentication with multi-datacenter support, complete device management operations, application distribution, user management, and advanced logging capabilities.

**Module Version:** 1.0.0  
**Functions Exported:** 57  
**PowerShell Version Required:** 5.0+

## Installation

Install from the PowerShell Gallery:

```powershell
Install-Module -Name WS1API
```

Or manually download and extract to your PowerShell modules directory:
- Windows: `$PROFILE\..\Modules\WS1API\`
- macOS/Linux: `~/.local/share/powershell/Modules/WS1API/`

## Quick Start

```powershell
# Import the module
Import-Module WS1API

# Get OAuth token (supports 10 global data centers)
$OAuthURL = Get-WSONEOAuthURL -DataCenterLocation "UnitedStates"
$OAuthToken = Get-WSONEOAuthToken -ClientId "your-id" -ClientSecret "your-secret"

# Or use Basic authentication
$auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"

# List all available commands
Get-Command -Module WS1API
```

## Features by Category

### Authentication & Configuration (5 functions)

| Function | Description |
|----------|-------------|
| **Get-ServerAuth** | Prompt for or accept server authentication credentials |
| **Get-WSONEOAuthToken** | Retrieve OAuth access token with Bearer format |
| **Invoke-AWApiCommand** | Execute RestAPI commands against WS1 UEM |
| **Invoke-RestMethodWithRetry** | Invoke REST methods with exponential backoff retry logic |
| **Get-OG** | Retrieve Organization Groups from WS1 UEM |

### Organization & Search (2 functions)

| Function | Description |
|----------|-------------|
| **Invoke-OGSearch** | Search for OG and prompt user to select from results |
| **Get-Enrollment** | Retrieve detailed WS1 enrollment info from device registry |

### Device Discovery & Tagging (6 functions)

| Function | Description |
|----------|-------------|
| **Get-NewDeviceId** | Retrieve device ID from WS1 UEM based on serial number |
| **Get-DevicesByCustomAttribute** | Search devices by custom attribute name and values |
| **Get-DeviceTags** | Retrieve tags from organization group |
| **Get-DeviceEnrollmentStatus** | Check device enrollment status |
| **Disable-EnrollmentNotifications** | Disable enrollment activity notifications for device |
| **Enable-EnrollmentNotifications** | Enable enrollment activity notifications for device |

### Device Management (11 functions)

| Function | Description |
|----------|-------------|
| **Add-DeviceTag** | Apply tags to devices |
| **Remove-DeviceTag** | Remove tags from devices |
| **Get-UemDevicesExtensive** | Recursive pagination for all devices with full details |
| **Get-UemStaleDevices** | Identify devices not seen in N days (default 90) |
| **Get-UemDuplicateDevices** | Find duplicate devices by serial number with KeepNewest filter |
| **Get-UemProblematicDevices** | Detect devices with invalid/placeholder serial numbers |
| **Remove-UemDevices** | Bulk delete devices via /api/mdm/devices/bulk with confirmation |
| **Get-UemDeviceNotes** | Retrieve console notes for devices |
| **Update-UemDeviceProperty** | Update device properties (FriendlyName, AssetNumber) |
| **Clear-UemDevicePasscode** | Bulk clear device passcodes with confirmation |
| **Invoke-UemSmartGroupCommand** | Execute commands on smart group devices |

### Applications (6 functions)

| Function | Description |
|----------|-------------|
| **Get-App** | Query installed applications from registry |
| **New-UemAppIcon** | Upload app icons with BlobId return |
| **New-UemApplication** | Create internal apps with platform validation (BundleId mandatory) |
| **Get-UemApplications** | Query apps by platform (iOS, Android, macOS, WinRT, ChromeOS) |
| **Invoke-ChunkandUpload** | Handle large file uploads with chunking |
| **Invoke-UploadfromLink** | Upload application from external URL |

### Baselines (6 functions)

| Function | Description |
|----------|-------------|
| **Get-Baseline** | Retrieve baseline templates |
| **Get-BaselineTemplate** | Get baseline template details |
| **Get-DevicesInBaseline** | Query devices assigned to baseline |
| **Get-DevicePoliciesInBaseline** | Get policy details assigned to baseline |
| **Get-BaselineAssignments** | Retrieve baseline assignment information |
| **Get-BaselineSummary** | Get summary statistics for baseline deployments |

### Agent Management (7 functions)

| Function | Description |
|----------|-------------|
| **Get-UemAgentInstallInfo** | Check Workspace ONE agent installation status |
| **Install-UemAgent** | Install and enroll the WS1 Hub agent |
| **Remove-UemAgent** | Uninstall the WS1 Hub agent |
| **Invoke-DownloadAirwatchAgent** | Download agent installer from UEM server |
| **Invoke-AgentCleanup** | Remove Workspace ONE Agent and artifacts |
| **Wait-UemAppsInstalled** | Wait for assigned apps to install on device |
| **Wait-UemProfilesInstalled** | Wait for assigned profiles to install on device |

### User Management & Enrollment (5 functions)

| Function | Description |
|----------|-------------|
| **Get-CurrentLoggedonUser** | Get currently logged-on user on local system |
| **Get-UserSIDLookup** | Translate username to Security Identifier (SID) |
| **Get-ReverseSID** | Translate SID to username or group name |
| **Compare-EnrollmentSID** | Compare current user SID with enrollment SID |
| **Get-EnrollmentInfoWithPolling** | Poll UEM API for device enrollment info with retries |
| **Get-UemDuplicateUsers** | Find duplicate user accounts |
| **Remove-UemDuplicateUsers** | Delete duplicate user accounts with confirmation |

### Local System & Utilities (5 functions)

| Function | Description |
|----------|-------------|
| **Get-RegistryValue** | Query Windows registry values |
| **Get-Log** | Retrieve and parse log files |
| **Invoke-CreateTask** | Create scheduled task for automation |
| **Show-Toast** | Display Windows toast notification to user |
| **New-Tag** | Create new tag in organization group |

### Logging & Reporting (2 functions)

| Function | Description |
|----------|-------------|
| **Write-Log** | Write timestamped, color-coded log messages to file and console |
| **Write-2Report** | Generate formatted report output with decorative borders |

## Authentication

### Using OAuth 2.0 (Recommended)

```powershell
# OAuth2 auth (Recommended method)
$auth = Get-ServerAuth -Server "uem.example.com" -ClientId "id" -ClientSecret "secret" -TokenUrl "https://token.url" -ApiKey "key" -OGName "Corp"
```

```powershell
# Get OAuth token for specific data center
$OAuthURL = Get-WSONEOAuthURL -DataCenterLocation "UnitedStates"
$Token = Get-WSONEOAuthToken -ClientId "your-client-id" -ClientSecret "your-client-secret"

# Use in API calls
$auth = Get-ServerAuth -Server "uem.example.com" -BearerToken $Token -OGName "Corp"
```

### Using Basic Authentication

```powershell
# Interactive credential collection
$auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" `
    -ApiKey "your-api-key" -OGName "Corp"

# Returns auth object with:
# - Server: UEM server hostname
# - cred: Base64-encoded credentials for Authorization header
# - ApiKey: aw-tenant-code for API calls
# - OrgGroupUUID: Organization group UUID
```

## Workflow Examples

### Device Maintenance Workflow

```powershell
# Get authentication
$auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" `
    -ApiKey "key" -OGName "Corp"

# Find stale devices (not seen in 180 days)
$staleDevices = Get-UemStaleDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -DaysSinceLastSeen 180 -PageSize 500

# Find duplicate devices
$duplicates = Get-UemDuplicateDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -KeepNewest -ExcludeProblematicSerials

# Remove devices (with confirmation)
Remove-UemDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -DeviceIds ($duplicates | Select-Object -ExpandProperty Id)
```

### Application Distribution Workflow

```powershell
# Get authentication
$auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" `
    -ApiKey "key" -OGName "Corp"

# Upload app icon
$blobId = Send-UemAppIcon -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -IconFile "C:\path\to\icon.png"

# Or upload chunked application file
$transId = Invoke-ChunkandUpload -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -FilePath "C:\app.ipa" -ChunkSizesMB 10

# Create application (BundleId is mandatory for versioning)
$app = New-UemApplication -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -ApplicationName "MyApp" -Platform iOS -BundleId 1001 `
    -OrganizationGroupUuid $auth.OrgGroupUUID -BlobId $blobId -ApplicationVersion "1.0"
```

### Bulk Device Operations Workflow

```powershell
# Get all devices and filter
$devices = Get-UemDevicesExtensive -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
$problemDevices = $devices | Where-Object { $_.EnrollmentStatus -eq "Enrolled" }

# Update device properties
$problemDevices | ForEach-Object {
    Update-UemDeviceProperty -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -SerialNumber $_.SerialNumber -FriendlyName "Updated-$($_.SerialNumber)"
}

# Clear passcodes for iOS devices
$iosDevices = $devices | Where-Object { $_.Platform -eq "iOS" }
$iosDevices | Select-Object -ExpandProperty SerialNumber | Clear-UemDevicePasscode `
    -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -Force
```

### Smart Group Command Execution

```powershell
# Execute sync command on all devices in smart group
$syncResult = Invoke-UemSmartGroupCommand -Server $auth.Server -Auth $auth.cred `
    -ApiKey $auth.ApiKey -SmartGroupId "sg-12345" -Command "SyncDevice"

# Lock all devices and get affected list
$lockedDevices = Invoke-UemSmartGroupCommand -Server $auth.Server -Auth $auth.cred `
    -ApiKey $auth.ApiKey -SmartGroupId "sg-67890" -Command "Lock" -PassThru

Write-Log -Message "Locked $($lockedDevices.Count) devices" -Level "Success"
```

### User Management Workflow

```powershell
# Find duplicate user accounts
$duplicates = Get-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred `
    -ApiKey $auth.ApiKey -UserType "BasicOnly"

# Delete duplicates (with confirmation: type 'DELETE' to confirm)
Remove-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
    -UserIds ($duplicates | Select-Object -ExpandProperty Uuid)
```

## Data Center Locations

Supported values for `Get-WSONEOAuthURL -DataCenterLocation`:

| Location | Code |
|----------|------|
| User Acceptance Testing | UAT |
| United States | UnitedStates |
| Canada | Canada |
| United Kingdom | UnitedKingdom |
| Germany | Germany |
| India | India |
| Japan | Japan |
| Singapore | Singapore |
| Australia | Australia |
| Hong Kong | HongKong |

## Common Parameters

Most functions support these common parameters:

- **Server**: UEM server hostname/FQDN (e.g., `uem.example.com`)
- **Auth**: Authorization header (from Get-ServerAuth)
- **ApiKey**: aw-tenant-code for API authentication
- **EnableRetry**: Enable exponential backoff retry (default: $false)
- **MaxAttempts**: Max retry attempts when -EnableRetry specified (default: 3)
- **RetryIntervalSeconds**: Base retry interval in seconds (default: 30-60)

## Error Handling & Logging

All functions include comprehensive error handling with logging:

```powershell
# Enable logging to file
Write-Log -Message "Starting device cleanup" -Path "C:\logs\cleanup.log" -Level "Info"

# Functions automatically log at Info/Success/Error levels
# View logs with:
Get-Log -Path "C:\logs\cleanup.log"
```

## Help Documentation

For detailed function documentation, use PowerShell's built-in help system:

```powershell
# Full help for a function
Get-Help Get-UemDevicesExtensive -Full

# Get all available functions
Get-Command -Module WS1API | Select-Object Name, Version

# Search for functions by keyword
Get-Command -Module WS1API -Name "*Device*"
```

## Requirements

- PowerShell 5.0 or higher
- .NET Framework 4.5+
- For user lookup features: Active Directory/LDAP access (domain-joined systems)
- For local system features: Administrative privileges (for registry/service operations)

## API Versions Supported

- v1 - Legacy endpoints and bulk operations
- v2 - Modern endpoints and device management
- v3 - Latest endpoints (where available)

## Retry & Resilience

All API calls support exponential backoff retry logic:

```powershell
# Formula: sleepTime = RetryIntervalSeconds × 2^attemptNumber
# Default: MaxAttempts=3, RetryIntervalSeconds=30-60

# Enable retry on specific call
$result = Invoke-AWApiCommand -Endpoint $url -Method GET -Auth $auth -ApiKey $key `
    -EnableRetry -MaxAttempts 5 -RetryIntervalSeconds 60
```

## Bulk Operations

Functions optimized for bulk operations include:

- **Remove-UemDevices**: Delete 100+ devices in single API call
- **Invoke-UemSmartGroupCommand**: Execute commands on 1000+ devices
- **Remove-UemDuplicateUsers**: Delete multiple user accounts
- **Clear-UemDevicePasscode**: Bulk passcode clear with confirmation

Pipeline input supported for accumulating items before batch processing.

## Performance Tips

1. **Pagination**: All list functions support PageSize parameter (max 500)
2. **Filtering**: Use API filtering (searchBy, platform, etc.) before retrieving
3. **Caching**: Store auth object to avoid repeated authentication
4. **Bulk Operations**: Use bulk endpoints for 10x performance improvement
5. **Concurrency**: Use PowerShell jobs for parallel API calls across devices

## License

This project is licensed under the terms specified in the LICENSE file.

## Contributing

Contributions are welcome! Please submit issues and pull requests to the [GitHub repository](https://github.com/helmlingp/WS1API).

## Author

Phil Helmling  

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and version details.
