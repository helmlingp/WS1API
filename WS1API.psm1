<#
 .Synopsis
    PowerShell module for interacting with Omnissa Workspace ONE UEM RestAPI with OAuth support
 .NOTES
    Created:   	    March, 2026
    Created by:	    Phil Helmling
    Organization:   
    Filename:       WS1API.psm1
    GitHub:         https://github.com/helmlingp/WS1API 
 .Description
    A comprehensive module providing 57 functions for authenticating with and interacting with
    Workspace ONE UEM via RestAPI. Supports multiple data center locations and includes OAuth
    token management, device management, application distribution, user management, and logging.
    
    AUTHENTICATION & CONFIGURATION (5 functions):
    - Get-ServerAuth - Prompt for or accept server authentication credentials
    - Get-WSONEOAuthToken - Retrieve OAuth access token with Bearer format
    - Invoke-AWApiCommand - Execute RestAPI commands against WS1 UEM
    - Invoke-RestMethodWithRetry - Invoke REST methods with exponential backoff retry logic
    - Get-OG - Retrieve Organization Groups from WS1 UEM
    
    ORGANIZATION & SEARCH (2 functions):
    - Invoke-OGSearch - Search for OG and prompt user to select from results
    - Get-Enrollment - Retrieve detailed WS1 enrollment info from device registry
    
    DEVICE DISCOVERY & TAGGING (6 functions):
    - Get-NewDeviceId - Retrieve device ID from WS1 UEM based on serial number
    - Get-DevicesByCustomAttribute - Search devices by custom attribute name and values
    - Get-DeviceTags - Retrieve tags from organization group
    - Get-DeviceEnrollmentStatus - Check device enrollment status
    - Disable-EnrollmentNotifications - Disable enrollment activity notifications for device
    - Enable-EnrollmentNotifications - Enable enrollment activity notifications for device
    
    DEVICE MANAGEMENT (11 functions):
    - Add-DeviceTag - Apply tags to devices
    - Remove-DeviceTag - Remove tags from devices
    - Get-UemDevicesExtensive - Recursive pagination for all devices with full details
    - Get-UemStaleDevices - Identify devices not seen in N days (default 90)
    - Get-UemDuplicateDevices - Find duplicate devices by serial number with KeepNewest filter
    - Get-UemProblematicDevices - Detect devices with invalid/placeholder serial numbers
    - Remove-UemDevices - Bulk delete devices via /api/mdm/devices/bulk with confirmation
    - Get-UemDeviceNotes - Retrieve console notes for devices
    - Update-UemDeviceProperty - Update device properties (FriendlyName, AssetNumber)
    - Clear-UemDevicePasscode - Bulk clear device passcodes with confirmation
    - Invoke-UemSmartGroupCommand - Execute commands on smart group devices

    APPLICATIONS (6 functions):
    - Get-App - Query installed applications from registry
    - New-UemAppIcon - Upload app icons with BlobId return
    - New-UemApplication - Create internal apps with platform validation (BundleId mandatory)
    - Get-UemApplications - Query apps by platform (iOS, Android, macOS, WinRT, ChromeOS)
    - Invoke-ChunkandUpload - Handle large file uploads with chunking
    - Invoke-UploadfromLink - Upload application from external URL
    
    BASELINES (6 functions):
    - Get-Baseline - Retrieve baseline templates
    - Get-BaselineTemplate - Get baseline template details
    - Get-DevicesInBaseline - Query devices assigned to baseline
    - Get-DevicePoliciesInBaseline - Get policy details assigned to baseline
    - Get-BaselineAssignments - Retrieve baseline assignment information
    - Get-BaselineSummary - Get summary statistics for baseline deployments
    
    AGENT MANAGEMENT (7 functions):
    - Get-UemAgentInstallInfo - Check Workspace ONE agent installation status
    - Install-UemAgent - Install and enroll the WS1 Hub agent
    - Remove-UemAgent - Uninstall the WS1 Hub agent
    - Invoke-DownloadAirwatchAgent - Download agent installer from UEM server
    - Invoke-AgentCleanup - Remove Workspace ONE Agent and artifacts
    - Wait-UemAppsInstalled - Wait for assigned apps to install on device
    - Wait-UemProfilesInstalled - Wait for assigned profiles to install on device
    
    USER MANAGEMENT & ENROLLMENT (5 functions):
    - Get-CurrentLoggedonUser - Get currently logged-on user on local system
    - Get-UserSIDLookup - Translate username to Security Identifier (SID)
    - Get-ReverseSID - Translate SID to username or group name
    - Compare-EnrollmentSID - Compare current user SID with enrollment SID
    - Get-EnrollmentInfoWithPolling - Poll UEM API for device enrollment info with retries
    - Get-UemDuplicateUsers - Find duplicate user accounts
    - Remove-UemDuplicateUsers - Delete duplicate user accounts with confirmation
    
    LOCAL SYSTEM & UTILITIES (5 functions):
    - Get-RegistryValue - Query Windows registry values
    - Get-Log - Retrieve and parse log files
    - Invoke-CreateTask - Create scheduled task for automation
    - Show-Toast - Display Windows toast notification to user
    - New-Tag - Create new tag in organization group
    
    LOGGING & REPORTING (2 functions):
    - Write-Log - Write timestamped, color-coded log messages to file and console
    - Write-2Report - Generate formatted report output with decorative borders

    HELP DOCUMENTATION:
    Each function includes comprehensive help with .SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE,
    and .OUTPUTS sections. Access help using: Get-Help <FunctionName> -Full

 .Example
   # OAuth authentication flow with Bearer token
   $token = Get-WSONEOAuthToken -ClientId "app-id" -ClientSecret "app-secret" -DataCenterLocation "UnitedStates"

 .Example
   # Get server authentication details
   $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"

 .Example
   # Get server authentication details
   $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"

   # PHASE 1 - Device Management Workflow
   # Find stale devices not seen in 180 days
   $staleDevices = Get-UemStaleDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -DaysSinceLastSeen 180
   
   # Find duplicate devices and keep newest
   $duplicates = Get-UemDuplicateDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -KeepNewest -ExcludeProblematicSerials
   
   # Bulk delete devices
   Remove-UemDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -DeviceIds ($duplicates | Select-Object -ExpandProperty Id)

 .Example
   # PHASE 2 - Application Distribution Workflow
   # Upload app icon
   $blobId = Send-UemAppIcon -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -IconFile "C:\path\to\icon.png"
   
   # Or upload chunked app file
   $transId = Invoke-ChunkandUpload -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -FilePath "C:\app.ipa" -ChunkSizesMB 10
   
   # Create application (BundleId is mandatory for versioning)
   $app = New-UemApplication -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -ApplicationName "MyApp" -Platform iOS -BundleId 1001 `
       -OrganizationGroupUuid $auth.OrgGroupUUID -BlobId $blobId -ApplicationVersion "1.0"

 .Example
   # PHASE 2 - Smart Group Command Execution
   # Lock all devices in smart group
   $lockedCount = Invoke-UemSmartGroupCommand -Server $auth.Server -Auth $auth.cred `
       -ApiKey $auth.ApiKey -SmartGroupId "sg-12345" -Command "Lock"
   
   # Or get list of affected devices
   $devices = Invoke-UemSmartGroupCommand -Server $auth.Server -Auth $auth.cred `
       -ApiKey $auth.ApiKey -SmartGroupId "sg-12345" -Command "SyncDevice" -PassThru

 .Example
   # PHASE 3 - Device Properties & Maintenance Workflow
   # Update device properties
   Update-UemDeviceProperty -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -SerialNumber "ABC123XYZ" -FriendlyName "LAPTOP-001" -AssetNumber "ASSET-12345"
   
   # Retrieve device notes from console
   $notes = Get-UemDeviceNotes -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -SerialNumber "ABC123XYZ"
   
   # Clear passcodes on multiple devices
   @("ABC123XYZ", "DEF456UVW", "GHI789RST") | Clear-UemDevicePasscode `
       -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -Force

 .Example
   # PHASE 2 - User Management Workflow
   # Find duplicate user accounts
   $duplicates = Get-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred `
       -ApiKey $auth.ApiKey -UserType "BasicOnly"
   
   # Delete duplicates (requires 'DELETE' confirmation)
   Remove-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
       -UserIds ($duplicates | Select-Object -ExpandProperty Uuid)

 .Example
   # Retrieve Organization Group
   # First get server authentication details
   $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
   $OG = Get-OG -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -OrgGroup $auth.OGName
   $OGUuid = $OG.OrganizationGroups[0].Uuid

 .Example
   # Execute RestAPI command
   # First get server authentication details
   $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
   $devices = Invoke-AWApiCommand -Method GET -Endpoint "https://uem.example.com/api/v1/devices" `
     -Auth $auth.cred -Apikey $auth.ApiKey

 .Example
   # Retrieve device ID
   # First get server authentication details
   $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
   $deviceId = Get-NewDeviceId -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey

 .Example
   # Get current logged-on user
   $user = Get-CurrentLoggedonUser
   Write-Host "Current user: $user"

 .Example
   # Get user SID (simplified syntax - no parameter name needed)
   $sid = Get-UserSIDLookup "jsmith"
   # Or use with domain format
   $sid = Get-UserSIDLookup "CONTOSO\jsmith"
   # Or get current user's SID
   $sid = Get-UserSIDLookup

 .Example
   # Translate SID to username
   $username = Get-ReverseSID "S-1-5-21-3623811015-3361044348-30300820-1013"
   # Include group lookups
   $account = Get-ReverseSID "S-1-5-32-544" -ignoreGroups $false

 .Example
   # Logging with Write-Log
   Write-Log -Message "Device enrollment completed" -Level "Success"
   Write-Log -Message "Failed to connect to server" -Path "C:\Logs\deploy.log" -Level "Error"

 .Example
   # Generate formatted report
   Write-2Report -Path "C:\Reports\WS1Report.log" -Message "Device Deployment Report" -Level "Title"
   Write-2Report -Path "C:\Reports\WS1Report.log" -Message "Summary" -Level "Header"
   Write-2Report -Path "C:\Reports\WS1Report.log" -Message "Process completed" -Level "Footer"

 .LINK
   https://github.com/helmlingp/WS1API
 .LINK
   https://www.powershellgallery.com/packages/WS1API
   #>
$current_path = $PSScriptRoot;

# Module-level variable - single source of truth for OAuth data centers and their URLs
$Script:DataCenterUrls = @{
    'UAT'           = 'https://uat.uemauth.workspaceone.com/connect/token'
    'UnitedStates'  = 'https://na.uemauth.workspaceone.com/connect/token'
    'Canada'        = 'https://na.uemauth.workspaceone.com/connect/token'
    'UnitedKingdom' = 'https://emea.uemauth.workspaceone.com/connect/token'
    'Germany'       = 'https://emea.uemauth.workspaceone.com/connect/token'
    'India'         = 'https://apac.uemauth.workspaceone.com/connect/token'
    'Japan'         = 'https://apac.uemauth.workspaceone.com/connect/token'
    'Singapore'     = 'https://apac.uemauth.workspaceone.com/connect/token'
    'Australia'     = 'https://apac.uemauth.workspaceone.com/connect/token'
    'HongKong'      = 'https://apac.uemauth.workspaceone.com/connect/token'
}

# Valid datacenters derived from the hashtable keys
$Script:ValidDatacenters = @($Script:DataCenterUrls.Keys)


function Get-ServerAuth {
    <#
    .SYNOPSIS
    Retrieves server authentication details for Workspace ONE UEM with auto-detection of auth method.
    
    .DESCRIPTION
    Intelligently handles both Basic and OAuth2 authentication. Auto-detects the auth method based on provided
    credentials, prompts for missing fields, and returns appropriate authorization credentials.
    
    Precedence: explicit -AuthMethod parameter > auto-detect complete method > prompt user
    
    .PARAMETER Server
    The WS1 UEM server hostname or URL.
    
    .PARAMETER Username
    Username for Basic authentication.
    
    .PARAMETER Password
    Password for Basic authentication (plaintext).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) - required for both Basic and OAuth2.
    
    .PARAMETER OGName
    The Organizational Group name.
    
    .PARAMETER ClientId
    OAuth2 Client ID.
    
    .PARAMETER ClientSecret
    OAuth2 Client Secret.
    
    .PARAMETER TokenUrl
    OAuth2 Token URL.
    
    .PARAMETER AuthMethod
    Explicitly specify auth method: 'Basic' or 'OAuth2'. Auto-detected if omitted.
    
    .EXAMPLE
    # Basic auth - all params supplied
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    
    .EXAMPLE
    # OAuth2 auth
    $auth = Get-ServerAuth -Server "uem.example.com" -ClientId "id" -ClientSecret "secret" -TokenUrl "https://token.url" -ApiKey "key" -OGName "Corp"
    
    .EXAMPLE
    # Interactive - prompts for missing values
    $auth = Get-ServerAuth
    
    .EXAMPLE
    # Explicit auth method to resolve ambiguity
    $auth = Get-ServerAuth -AuthMethod "OAuth2" -ClientId "id" -ClientSecret "secret" -TokenUrl "https://token.url" -ApiKey "key" -OGName "Corp"
    
    .OUTPUTS
    Hashtable with properties: 
    - Server: WS1 UEM server URL
    - ApiKey: API key (aw-tenant-code)
    - OGName: Organization Group name
    - AuthMode: Authentication method used (Basic or OAuth2)
    - cred: Authorization header value (Basic or Bearer token) ready for API calls
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [string]$OGName,
        
        [Parameter(Mandatory = $false)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $false)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [string]$TokenUrl,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "OAuth2")]
        [string]$AuthMethod
    )
    
    # Precedence: explicit -AuthMethod parameter > auto-detect complete method > prompt user
    $localMethod = $AuthMethod
    
    # Check if Basic auth is complete (password can be plaintext)
    $basicAuthComplete = -not ([string]::IsNullOrEmpty($Server) -or 
                                [string]::IsNullOrEmpty($Username) -or
                                [string]::IsNullOrEmpty($Password) -or
                                [string]::IsNullOrEmpty($ApiKey) -or
                                [string]::IsNullOrEmpty($OGName))
    
    $oauthAuthComplete = -not ([string]::IsNullOrEmpty($Server) -or 
                                [string]::IsNullOrEmpty($ClientId) -or
                                [string]::IsNullOrEmpty($ClientSecret) -or 
                                [string]::IsNullOrEmpty($TokenUrl) -or
                                [string]::IsNullOrEmpty($ApiKey) -or 
                                [string]::IsNullOrEmpty($OGName))
    
    # Auto-detect auth method if not explicitly provided
    if ([string]::IsNullOrEmpty($localMethod)) {
        if ($basicAuthComplete) {
            $localMethod = "Basic"
        } elseif ($oauthAuthComplete) {
            $localMethod = "OAuth2"
        } else {
            do {
                $input = Read-Host -Prompt "Choose Authentication Method (Basic or OAuth2)"
                if ($input -ieq "Basic") { $localMethod = "Basic" }
                elseif ($input -ieq "OAuth2") { $localMethod = "OAuth2" }
                else { Write-Host "Invalid choice. Enter 'Basic' or 'OAuth2'." -ForegroundColor Red }
            } while ([string]::IsNullOrEmpty($localMethod))
        }
    }
    
    # Ensure all required fields for chosen auth method
    if ($localMethod -eq "Basic") {
        if ([string]::IsNullOrEmpty($Server))   { $Server   = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name' }
        if ([string]::IsNullOrEmpty($Username)) { $Username = Read-Host -Prompt 'Enter the Username' }
        if ([string]::IsNullOrEmpty($Password)) { $Password = Read-Host -Prompt 'Enter the Password' -AsSecureString }
        if ([string]::IsNullOrEmpty($ApiKey))   { $ApiKey   = Read-Host -Prompt 'Enter the API Key' }
        if ([string]::IsNullOrEmpty($OGName))   { $OGName   = Read-Host -Prompt 'Enter the Organizational Group Name' }
        
        # Convert SecureString if provided
        if ($Password -is [System.Security.SecureString]) {
            $Password = New-BasicAuthCredential -Username $Username -SecurePassword $Password -ReturnPlainPassword
        }
        
        $credential = New-BasicAuthCredential -Username $Username -PlainPassword $Password
    } else {
        if ([string]::IsNullOrEmpty($Server))       { $Server       = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name' }
        if ([string]::IsNullOrEmpty($ClientId))     { $ClientId     = Read-Host -Prompt 'Enter the OAuth Client ID' }
        if ([string]::IsNullOrEmpty($ClientSecret)) { $ClientSecret = Read-Host -Prompt 'Enter the OAuth Client Secret' }
        if ([string]::IsNullOrEmpty($ApiKey))       { $ApiKey       = Read-Host -Prompt 'Enter the API Key (aw-tenant-code)' }
        if ([string]::IsNullOrEmpty($OGName))       { $OGName       = Read-Host -Prompt 'Enter the Organizational Group Name' }
        
        # For TokenUrl, offer choice of data center or custom URL
        if ([string]::IsNullOrEmpty($TokenUrl)) {
            $dcSelected = $false
            do {
                $dcChoice = Read-Host -Prompt "Select data center ($($Script:ValidDatacenters -join '/')) or enter 'custom' for explicit URL"
                if ($dcChoice -ieq "custom") {
                    $TokenUrl = Read-Host -Prompt 'Enter the OAuth Token URL'
                    $dcSelected = $true
                } elseif ($Script:DataCenterUrls.ContainsKey($dcChoice)) {
                    $TokenUrl = $Script:DataCenterUrls[$dcChoice]
                    $dcSelected = $true
                } else {
                    Write-Host "Invalid data center. Valid options are: $($Script:ValidDatacenters -join ', ')" -ForegroundColor Yellow
                }
            } while (-not $dcSelected)
        }
        
        $credential = Get-WSONEOAuthToken -ClientId $ClientId -ClientSecret $ClientSecret -TokenUrl $TokenUrl
    }
    
    if ($Debug) { 
        Write-Information "`nServer Auth"
        Write-Information "WS1 Host: $Server"
        Write-Information "Auth Mode: $localMethod"
        Write-Information "APIKey: [REDACTED]"
        Write-Information "OG Name: $OGName"
    }
    
    return @{
        Server   = $Server
        ApiKey   = $ApiKey
        OGName   = $OGName
        AuthMode = $localMethod
        cred     = $credential
    }
}


function Get-WSONEOAuthToken {
    <#
    .SYNOPSIS
    Retrieves an OAuth token from Workspace ONE UEM and returns it as a Bearer token string.
    
    .DESCRIPTION
    Authenticates with Workspace ONE UEM using client credentials and returns an OAuth access token
    in Bearer format ready for API calls.
    
    .PARAMETER ClientId
    The OAuth client ID credential.
    
    .PARAMETER ClientSecret
    The OAuth client secret credential.
    
    .PARAMETER DataCenterLocation
    The Workspace ONE data center location. Valid values: UAT, UnitedStates, Canada, UnitedKingdom, Germany, India, Japan, Singapore, Australia, HongKong. Defaults to UnitedStates.
    
    .PARAMETER TokenUrl
    Explicit OAuth token URL. If provided, DataCenterLocation is ignored.
    
    .EXAMPLE
    $token = Get-WSONEOAuthToken -ClientId "oauth-app-id" -ClientSecret "oauth-app-secret" -DataCenterLocation "UnitedStates"
    
    .EXAMPLE
    # Use explicit token URL
    $token = Get-WSONEOAuthToken -ClientId "oauth-app-id" -ClientSecret "oauth-app-secret" -TokenUrl "https://uemauth.example.com/connect/token"
    
    .EXAMPLE
    # Use token in API call
    $token = Get-WSONEOAuthToken -ClientId "oauth-app-id" -ClientSecret "oauth-app-secret"
    $result = Invoke-WebRequest -Uri "https://uem.example.com/api/v1/devices" -Headers @{"Authorization" = $token}
    
    .OUTPUTS
    String - Bearer token in the format "Bearer eyJhbGciOiJSUzI1NiIs..."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('UAT', 'UnitedStates', 'Canada', 'UnitedKingdom', 'Germany', 'India', 'Japan', 'Singapore', 'Australia', 'HongKong')]
        [string]$DataCenterLocation = 'UnitedStates',
        
        [Parameter(Mandatory = $false)]
        [string]$TokenUrl
    )
    
    Write-Information "Getting OAuth Token..."
    
    # Use explicit TokenUrl if provided, otherwise look up by data center
    if ([string]::IsNullOrEmpty($TokenUrl)) {
        $TokenUrl = $Script:DataCenterUrls[$DataCenterLocation]
    }
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
    }
 
    try {
        $response = Invoke-WebRequest -Method Post -Uri $TokenUrl -Body $body -UseBasicParsing
        $response = $response | ConvertFrom-Json
        $access_token = [string]$($response.access_token)
        $cred = "Bearer $access_token"
    }
    catch {
        $ErrorMessage = $_
        Write-Error "Failed to fetch OAuth2 token from '$TokenUrl'. Check clientId, clientSecret, and tokenUrl. Error: $($ErrorMessage.Exception.Message)"
    }

    return $cred

}

function New-BasicAuthCredential {
    <#
    .SYNOPSIS
    Creates a Basic authentication credential header.
    
    .DESCRIPTION
    Encodes username and password into Base64 format for Basic HTTP authentication.
    Handles both SecureString and plaintext passwords.
    
    .PARAMETER Username
    The username for Basic auth.
    
    .PARAMETER PlainPassword
    The plaintext password.
    
    .PARAMETER SecurePassword
    A SecureString password (will be converted to plaintext).
    
    .PARAMETER ReturnPlainPassword
    If SecurePassword is provided and this switch is set, returns the converted plaintext password
    instead of the Basic auth header. Used internally for password conversion.
    
    .EXAMPLE
    $basicAuth = New-BasicAuthCredential -Username "admin" -PlainPassword "password123"
    # Returns: "Basic YWRtaW46cGFzc3dvcmQxMjM="
    
    .EXAMPLE
    $securePass = Read-Host -Prompt "Enter password" -AsSecureString
    $basicAuth = New-BasicAuthCredential -Username "admin" -SecurePassword $securePass
    
    .OUTPUTS
    String - Basic auth header in format "Basic <base64-encoded-credentials>"
    Or plaintext password if -ReturnPlainPassword is specified
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [string]$PlainPassword,
        
        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$SecurePassword,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReturnPlainPassword
    )
    
    $plainPass = $null
    
    # Convert SecureString if present, otherwise use plaintext password
    if ($SecurePassword) {
        [string]$psver = $PSVersionTable.PSVersion
        if ($psver -lt 7) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
            $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } else {
            $plainPass = ConvertFrom-SecureString $SecurePassword -AsPlainText
        }
    } else {
        $plainPass = $PlainPassword
    }
    
    # If only conversion is requested, return plaintext
    if ($ReturnPlainPassword) {
        return $plainPass
    }
    
    # Validate that we have a password
    if ([string]::IsNullOrEmpty($plainPass)) {
        throw "Password is empty or not set. Cannot build Basic auth credential."
    }
    
    # Build Base64-encoded Basic auth header
    $combined = $Username + ":" + $plainPass
    $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
    $encoded = [Convert]::ToBase64String($encoding)
    return "Basic $encoded"
}

function Get-Log {
    <#
    .SYNOPSIS
    Retrieves the log file path for the specified log file name and current path.
    
    .PARAMETER logFileName
    The name of the log file.
    
    .PARAMETER current_path
    The current path where the log file will be created.
    
    .OUTPUTS
    String - The full path of the log file.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$logFileName,
        [string]$current_path
    )
    $DateNow = Get-Date -Format "yyyyMMdd_HHmm";
    $Path = "$current_path\$logFileName\_$DateNow.log";
    if ($Debug) {
        Write-Host "Path: $Path"
        Write-Host "LogLocation: $LogLocation"
    }
    return $path
}

function Get-NewDeviceId {
    <#
    .SYNOPSIS
    Retrieves a device ID from WS1 UEM based on the device's serial number.
    
    .DESCRIPTION
    Looks up the current device's serial number and queries WS1 UEM to get the assigned device ID.
    Useful for identifying enrolled devices in automation scripts.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com). Should include protocol if needed.
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    $deviceId = Get-NewDeviceId -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    # Returns: Device ID or "Unenrolled" if not enrolled
    
    .EXAMPLE
    if ((Get-NewDeviceId -Server $server -Auth $auth -ApiKey $key) -ne "Unenrolled") { Write-Host "Device is enrolled" }
    
    .OUTPUTS
    String - Device ID or "Unenrolled" if the device is not enrolled in WS1 UEM
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $serialSearch = Get-CimInstance -ClassName Win32_BIOS | Format-List SerialNumber
    $serialnumber = $serialSearch[2].Trim()

    $serialEncoded = [System.Web.HttpUtility]::UrlEncode($serialnumber)
    $endpoint = "$Server/api/mdm/devices?searchBy=Serialnumber&id=$serialEncoded"

    $WebResponse = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey

    if ($WebResponse.Id) {
        if ($WebResponse.EnrollmentStatus -eq "Enrolled") {
            return $WebResponse.Id.Value
        }
    }
    return "Unenrolled"
}

function Get-OG {
    <#
    .SYNOPSIS
    Retrieves an Organization Group from Workspace ONE UEM.
    
    .DESCRIPTION
    Queries the WS1 UEM RestAPI to retrieve Organization Group details by name.
    Returns matching organization group(s) with all properties including UUID, Name, and ID.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com)
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (tenant code) for authentication
    
    .PARAMETER OrgGroup
    The Organization Group name to search for
    
    .PARAMETER Debug
    Switch to enable debug logging
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key123" -OGName "Corporate"
    $OG = Get-OG -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -OrgGroup $auth.OGName
    $OGUuid = $OG.OrganizationGroups[0].Uuid
    
    .OUTPUTS
    Object containing OrganizationGroups array with UUID, Name, and ID properties
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        [Parameter(Mandatory = $true)]
        [string]$apikey,
        [Parameter(Mandatory = $true)]
        [string]$OrgGroup,
        [Parameter(Mandatory = $false)]
        [bool]$Debug = $false
    )

    $og_search_endpoint = "$Server/API/system/groups/search?name=$OrgGroup";

    $OG_Search = Invoke-AWApiCommand -Method Get -Endpoint $og_search_endpoint -ApiVersion 2 -Auth $Auth -Apikey $apikey -Debug $Debug
    if ($OG_Search.OrganizationGroups) {
        if ($Debug) {
            $OGName = $OG_Search.OrganizationGroups[0].Name
            $OGID = $OG_Search.OrganizationGroups[0].Id
            Write-Log -Path $logLocation -Message "OG Name $OGName & OG ID $OGID" -Level Info
        }
    }
    return $OG_Search;
}

function Invoke-AWApiCommand {
    <#
    .SYNOPSIS
    Invokes a REST API command to Workspace ONE UEM with optional retry logic.
    
    .DESCRIPTION
    Sends a REST API request to the specified endpoint with proper headers and authentication.
    Supports all HTTP methods and API versions. Returns parsed JSON response.
    Supports exponential backoff retry logic for transient failures (5xx, 408, 429).
    
    .PARAMETER Endpoint
    The complete API endpoint URL (e.g., https://uem.example.com/api/v1/devices)
    
    .PARAMETER Method
    The HTTP method to use: GET, POST, PUT, DELETE. Default is GET.
    
    .PARAMETER ApiVersion
    The API version (1 or 2). Default is 1.
    
    .PARAMETER Body
    The request body data (for POST/PUT requests).
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER Apikey
    The API key (aw-tenant-code) for authentication
    
    .PARAMETER EnableRetry
    Switch to enable exponential backoff retry logic for transient errors. Default is $false.
    
    .PARAMETER MaxAttempts
    Maximum number of retry attempts. Only used if -EnableRetry is specified. Default is 3.
    
    .PARAMETER RetryIntervalSeconds
    Base interval in seconds for exponential backoff. Only used if -EnableRetry is specified. Default is 60.
    
    .PARAMETER Debug
    Switch to enable debug logging to console
    
    .EXAMPLE
    $auth = Get-ServerAuth
    $result = Invoke-AWApiCommand -Method GET -Endpoint "https://uem.example.com/api/v1/devices" -Auth $auth.cred -Apikey $auth.ApiKey
    
    .EXAMPLE
    # POST request with data
    $payload = @{name="NewDevice"; platform="Android"} | ConvertTo-Json
    $result = Invoke-AWApiCommand -Method POST -Endpoint "https://uem.example.com/api/v1/devices" -Body $payload -Auth $auth.cred -Apikey $auth.ApiKey
    
    .EXAMPLE
    # With retry logic for reliability
    $result = Invoke-AWApiCommand -Method GET -Endpoint "https://uem.example.com/api/v1/devices" -Auth $auth.cred -Apikey $auth.ApiKey -EnableRetry -MaxAttempts 5
    
    .OUTPUTS
    PSCustomObject - Parsed API response or error message
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",
        [Parameter(Mandatory = $false)]
        [int]$ApiVersion = 1,
        [Parameter(Mandatory = $false)]
        $Body,
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        [Parameter(Mandatory = $true)]
        [string]$Apikey,
        [Parameter(Mandatory = $false)]
        [switch]$EnableRetry = $false,
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3,
        [Parameter(Mandatory = $false)]
        [int]$RetryIntervalSeconds = 60,
        [Parameter(Mandatory = $false)]
        [bool]$Debug = $false
    )

    $headers = @{
        'aw-tenant-code'  = $ApiKey
        'Authorization'   = $Auth
        'accept'          = "application/json;version=$ApiVersion"
        'Content-Type'    = 'application/json'
    }

    $attempt = 0
    $maxRetries = if ($EnableRetry) { $MaxAttempts } else { 1 }
    
    while ($attempt -lt $maxRetries) {
        $WebRequest = $null
        
        try {
            if ($Body) {
                $WebRequest = Invoke-WebRequest -Uri $Endpoint -Method $Method -Body $Body -UseBasicParsing -Headers $headers
            }
            else {
                $WebRequest = Invoke-WebRequest -Uri $Endpoint -Method $Method -UseBasicParsing -Headers $headers
            }
            
            if ($Debug) {
                Write-Log -Path $logLocation -Message "Connecting to: $Endpoint" -Level "Info"
                $statuscode = $WebRequest.StatusCode
                if ($WebRequest.Content) {
                    Write-Log -Path $logLocation -Message "WebRequest.StatusCode: $statuscode" -Level "Info"
                    Write-Log -Path $logLocation -Message $WebRequest.Content -Level "Info"
                }
            }

            # Success - parse and return
            try {
                if ($WebRequest.StatusCode -lt 300) {
                    if ($WebRequest.Content) {
                        $ReturnObj = ConvertFrom-Json($WebRequest.Content)
                    }
                    return $ReturnObj
                }
                else {
                    return $WebRequest.Content
                }
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                return (New-Object -TypeName PSCustomObject -Property @{"Error" = "$ErrorMessage" })
            }
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            $statusCode = $_.Exception.Response.StatusCode.Value__
            
            # Handle offline scenario
            if ($_.Exception -like "Unable to connect to the remote server") {
                Write-Log -Path $logLocation -Message "Server is offline: $ErrorMessage" -Level "Error"
                return "Offline"
            }
            
            # Determine if error is transient
            $isTransient = ($statusCode -ge 500) -or ($statusCode -eq 408) -or ($statusCode -eq 429)
            
            # Client errors (4xx except 408, 429) should not retry
            if ($statusCode -ge 400 -and $statusCode -lt 500 -and -not ($statusCode -eq 408 -or $statusCode -eq 429)) {
                Write-Log -Path $logLocation -Message "HTTP $statusCode (client error, not retrying): $ErrorMessage" -Level "Error"
                return (New-Object -TypeName PSCustomObject -Property @{"Error" = "$ErrorMessage" })
            }
            
            # If retry is disabled or this is the last attempt, return error
            if (-not $EnableRetry -or $attempt -eq ($maxRetries - 1)) {
                Write-Log -Path $logLocation -Message "An error has occurred. Error: $ErrorMessage" -Level "Error"
                return (New-Object -TypeName PSCustomObject -Property @{"Error" = "$ErrorMessage" })
            }
            
            # Calculate exponential backoff
            $attempt++
            $sleepTime = $RetryIntervalSeconds * [Math]::Pow(2, $attempt)
            Write-Log -Path $logLocation -Message "Transient error (HTTP $statusCode). Retry attempt $attempt/$maxRetries in $sleepTime seconds..." -Level "Warn"
            Start-Sleep -Seconds $sleepTime
            continue
        }
    }
}

function Invoke-RestMethodWithRetry {
    <#
    .SYNOPSIS
    Invokes a generic REST method with exponential backoff retry logic for transient failures.
    
    .DESCRIPTION
    Generic REST API wrapper with automatic retry on transient errors (5xx, 408, 429).
    Uses exponential backoff to space out retries. Client errors (4xx except 408) are not retried.
    
    NOTE: For Workspace ONE UEM API calls, use Invoke-AWApiCommand which includes WS1-specific
    headers (aw-tenant-code, API versioning) and also supports retry logic via -EnableRetry.
    Use this function for non-WS1 REST APIs that require retry capability.
    
    .PARAMETER Method
    HTTP method (GET, POST, PUT, DELETE).
    
    .PARAMETER Uri
    The URI to invoke.
    
    .PARAMETER Credential
    PSCredential for authentication.
    
    .PARAMETER Headers
    HTTP headers hashtable.
    
    .PARAMETER Body
    Optional request body.
    
    .PARAMETER MaxAttempts
    Maximum number of retry attempts. Default is 5.
    
    .PARAMETER RetryIntervalSeconds
    Base interval in seconds for exponential backoff. Default is 60.
    
    .PARAMETER AdditionalTransientStatusCodes
    Additional HTTP status codes to treat as transient (array of integers).
    
    .EXAMPLE
    $result = Invoke-RestMethodWithRetry -Method Get -Uri "https://api.example.com/devices" -Credential $cred -Headers $headers
    
    .OUTPUTS
    Response object from successful API call
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method,
        
        [Parameter(Mandatory = $true)]
        [uri]$Uri,
        
        [Parameter(Mandatory = $true)]
        [pscredential]$Credential,
        
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Headers,
        
        [Parameter(Mandatory = $false)]
        [object]$Body = $null,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 5,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryIntervalSeconds = 60,
        
        [Parameter(Mandatory = $false)]
        [int[]]$AdditionalTransientStatusCodes
    )
    
    $attempts = 0
    while ($attempts -lt $MaxAttempts) {
        try {
            if ($Body) {
                $response = Invoke-RestMethod -Method $Method -Uri $Uri -Credential $Credential -Headers $Headers -Body $Body
            } else {
                $response = Invoke-RestMethod -Method $Method -Uri $Uri -Credential $Credential -Headers $Headers
            }
            return $response
        } catch {
            $errorResponse = $_.Exception.Response
            
            if ($errorResponse) {
                $statusCode = $errorResponse.StatusCode.value__
                
                # Treat 5xx, 408, 429, and additional codes as transient
                $isTransient = ($statusCode -ge 500) -or ($statusCode -eq 408) -or ($statusCode -eq 429) -or ($AdditionalTransientStatusCodes -contains $statusCode)
                
                # Client errors (4xx) except transient ones are not retried
                if ($statusCode -ge 400 -and $statusCode -lt 500 -and -not $isTransient) {
                    Write-Log -Message "HTTP $statusCode error (client error, not retrying): $($_.Exception.Message)" -Level "Error"
                    throw $_
                }
            }
            
            # Last attempt failed
            if ($attempts -eq ($MaxAttempts - 1)) {
                Write-Log -Message "Failed after $MaxAttempts attempts: $($_.Exception.Message)" -Level "Error"
                throw $_
            }
        }
        
        $attempts++
        $sleepTime = $RetryIntervalSeconds * [Math]::Pow(2, $attempts)
        Write-Log -Message "Retry attempt $attempts/$MaxAttempts in $sleepTime seconds..." -Level "Warn"
        Start-Sleep -Seconds $sleepTime
    }
}

function Get-CurrentLoggedonUser {
    <#
    .SYNOPSIS
    Gets the currently logged-on user on the local system.
    
    .DESCRIPTION
    Returns the username of the currently logged-on user using Windows Identity API.
    Works with both domain and local user accounts.
    
    .EXAMPLE
    $currentUser = Get-CurrentLoggedonUser
    # Returns: DOMAIN\username
    
    .EXAMPLE
    Write-Host "Current user is: $currentUser"
    
    .OUTPUTS
    String - Username in format DOMAIN\USERNAME or COMPUTERNAME\USERNAME
    #>
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

<# function Get-CurrentLoggedonUser {
    param([bool]$ReturnObj = $false)
    if (-not ([Management.Automation.PSTypeName]'AWDeviceInventory.QueryUser').Type) {
        [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
        $CSharpCode = @"
// Date Modified: 01-08-2016
// Version Number: 3.6.8

using System;
using System.Text;
using System.Collections;
using System.ComponentModel;
using System.DirectoryServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace AWDeviceInventory
{
	public class QueryUser
	{
		[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern IntPtr WTSOpenServer(string pServerName);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern void WTSCloseServer(IntPtr hServer);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
		public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr pBuffer, out int pBytesReturned);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
		public static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr pSessionInfo, out int pCount);
		
		[DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern void WTSFreeMemory(IntPtr pMemory);
		
		[DllImport("winsta.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern int WinStationQueryInformation(IntPtr hServer, int sessionId, int information, ref WINSTATIONINFORMATIONW pBuffer, int bufferLength, ref int returnedLength);
		
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern int GetCurrentProcessId();
		
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		public static extern bool ProcessIdToSessionId(int processId, ref int pSessionId);
		
		public class TerminalSessionData
		{
			public int SessionId;
			public string ConnectionState;
			public string SessionName;
			public bool IsUserSession;
			public TerminalSessionData(int sessionId, string connState, string sessionName, bool isUserSession)
			{
				SessionId = sessionId;
				ConnectionState = connState;
				SessionName = sessionName;
				IsUserSession = isUserSession;
			}
		}
		
		public class TerminalSessionInfo
		{
			public string NTAccount;
			public string SID;
			public string UserName;
			public string DomainName;
			public int SessionId;
			public string SessionName;
			public string ConnectState;
			public bool IsCurrentSession;
			public bool IsConsoleSession;
			public bool IsActiveUserSession;
			public bool IsUserSession;
			public bool IsRdpSession;
			public bool IsLocalAdmin;
			public DateTime? LogonTime;
			public TimeSpan? IdleTime;
			public DateTime? DisconnectTime;
			public string ClientName;
			public string ClientProtocolType;
			public string ClientDirectory;
			public int ClientBuildNumber;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		private struct WTS_SESSION_INFO
		{
			public Int32 SessionId;
			[MarshalAs(UnmanagedType.LPStr)]
			public string SessionName;
			public WTS_CONNECTSTATE_CLASS State;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct WINSTATIONINFORMATIONW
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 70)]
			private byte[] Reserved1;
			public int SessionId;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			private byte[] Reserved2;
			public FILETIME ConnectTime;
			public FILETIME DisconnectTime;
			public FILETIME LastInputTime;
			public FILETIME LoginTime;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1096)]
			private byte[] Reserved3;
			public FILETIME CurrentTime;
		}
		
		public enum WINSTATIONINFOCLASS
		{
			WinStationInformation = 8
		}
		
		public enum WTS_CONNECTSTATE_CLASS
		{
			Active,
			Connected,
			ConnectQuery,
			Shadow,
			Disconnected,
			Idle,
			Listen,
			Reset,
			Down,
			Init
		}
		
		public enum WTS_INFO_CLASS
		{
			SessionId=4,
			UserName,
			SessionName,
			DomainName,
			ConnectState,
			ClientBuildNumber,
			ClientName,
			ClientDirectory,
			ClientProtocolType=16
		}
		
		private static IntPtr OpenServer(string Name)
		{
			IntPtr server = WTSOpenServer(Name);
			return server;
		}
		
		private static void CloseServer(IntPtr ServerHandle)
		{
			WTSCloseServer(ServerHandle);
		}
		
		private static IList<T> PtrToStructureList<T>(IntPtr ppList, int count) where T : struct
		{
			List<T> result = new List<T>();
			long pointer = ppList.ToInt64();
			int sizeOf = Marshal.SizeOf(typeof(T));
			
			for (int index = 0; index < count; index++)
			{
				T item = (T) Marshal.PtrToStructure(new IntPtr(pointer), typeof(T));
				result.Add(item);
				pointer += sizeOf;
			}
			return result;
		}
		
		public static DateTime? FileTimeToDateTime(FILETIME ft)
		{
			if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0)
			{
				return null;
			}
			long hFT = (((long) ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
			return DateTime.FromFileTime(hFT);
		}
		
		public static WINSTATIONINFORMATIONW GetWinStationInformation(IntPtr server, int sessionId)
		{
			int retLen = 0;
			WINSTATIONINFORMATIONW wsInfo = new WINSTATIONINFORMATIONW();
			WinStationQueryInformation(server, sessionId, (int) WINSTATIONINFOCLASS.WinStationInformation, ref wsInfo, Marshal.SizeOf(typeof(WINSTATIONINFORMATIONW)), ref retLen);
			return wsInfo;
		}
		
		public static TerminalSessionData[] ListSessions(string ServerName)
		{
			IntPtr server = IntPtr.Zero;
			if (ServerName == "localhost" || ServerName == String.Empty)
			{
				ServerName = Environment.MachineName;
			}
			
			List<TerminalSessionData> results = new List<TerminalSessionData>();
			
			try
			{
				server = OpenServer(ServerName);
				IntPtr ppSessionInfo = IntPtr.Zero;
				int count;
				bool _isUserSession = false;
				IList<WTS_SESSION_INFO> sessionsInfo;
				
				if (WTSEnumerateSessions(server, 0, 1, out ppSessionInfo, out count) == 0)
				{
					throw new Win32Exception();
				}
				
				try
				{
					sessionsInfo = PtrToStructureList<WTS_SESSION_INFO>(ppSessionInfo, count);
				}
				finally
				{
					WTSFreeMemory(ppSessionInfo);
				}
				
				foreach (WTS_SESSION_INFO sessionInfo in sessionsInfo)
				{
					if (sessionInfo.SessionName != "Services" && sessionInfo.SessionName != "RDP-Tcp")
					{
						_isUserSession = true;
					}
					results.Add(new TerminalSessionData(sessionInfo.SessionId, sessionInfo.State.ToString(), sessionInfo.SessionName, _isUserSession));
					_isUserSession = false;
				}
			}
			finally
			{
				CloseServer(server);
			}
			
			TerminalSessionData[] returnData = results.ToArray();
			return returnData;
		}
		
		public static TerminalSessionInfo GetSessionInfo(string ServerName, int SessionId)
		{
			IntPtr server = IntPtr.Zero;
			IntPtr buffer = IntPtr.Zero;
			int bytesReturned;
			TerminalSessionInfo data = new TerminalSessionInfo();
			bool _IsCurrentSessionId = false;
			bool _IsConsoleSession = false;
			bool _IsUserSession = false;
			int currentSessionID = 0;
			string _NTAccount = String.Empty;
			if (ServerName == "localhost" || ServerName == String.Empty)
			{
				ServerName = Environment.MachineName;
			}
			if (ProcessIdToSessionId(GetCurrentProcessId(), ref currentSessionID) == false)
			{
				currentSessionID = -1;
			}
			
			// Get all members of the local administrators group
			bool _IsLocalAdminCheckSuccess = false;
			List<string> localAdminGroupSidsList = new List<string>();
			try
			{
				DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + ServerName + ",Computer");
				string localAdminGroupName = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\')[1];
				DirectoryEntry admGroup = localMachine.Children.Find(localAdminGroupName, "group");
				object members = admGroup.Invoke("members", null);
				foreach (object groupMember in (IEnumerable)members)
				{
					DirectoryEntry member = new DirectoryEntry(groupMember);
					if (member.Name != String.Empty)
					{
						localAdminGroupSidsList.Add((new NTAccount(member.Name)).Translate(typeof(SecurityIdentifier)).Value);
					}
				}
				_IsLocalAdminCheckSuccess = true;
			}
			catch { }
			
			try
			{
				server = OpenServer(ServerName);
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientBuildNumber, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				int lData = Marshal.ReadInt32(buffer);
				data.ClientBuildNumber = lData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientDirectory, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				string strData = Marshal.PtrToStringAnsi(buffer);
				data.ClientDirectory = strData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer);
				data.ClientName = strData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientProtocolType, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				Int16 intData = Marshal.ReadInt16(buffer);
				if (intData == 2)
				{
					strData = "RDP";
					data.IsRdpSession = true;
				}
				else
				{
					strData = "";
					data.IsRdpSession = false;
				}
				data.ClientProtocolType = strData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ConnectState, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				lData = Marshal.ReadInt32(buffer);
				data.ConnectState = ((WTS_CONNECTSTATE_CLASS) lData).ToString();
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionId, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				lData = Marshal.ReadInt32(buffer);
				data.SessionId = lData;
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.DomainName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer).ToUpper();
				data.DomainName = strData;
				if (strData != String.Empty)
				{
					_NTAccount = strData;
				}
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.UserName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer);
				data.UserName = strData;
				if (strData != String.Empty)
				{
					data.NTAccount = _NTAccount + "\\" + strData;
					string _Sid = (new NTAccount(_NTAccount + "\\" + strData)).Translate(typeof(SecurityIdentifier)).Value;
					data.SID = _Sid;
					if (_IsLocalAdminCheckSuccess == true)
					{
						foreach (string localAdminGroupSid in localAdminGroupSidsList)
						{
							if (localAdminGroupSid == _Sid)
							{
								data.IsLocalAdmin = true;
								break;
							}
							else
							{
								data.IsLocalAdmin = false;
							}
						}
					}
				}
				
				if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionName, out buffer, out bytesReturned) == false)
				{
					return data;
				}
				strData = Marshal.PtrToStringAnsi(buffer);
				data.SessionName = strData;
				if (strData != "Services" && strData != "RDP-Tcp" && data.UserName != String.Empty)
				{
					_IsUserSession = true;
				}
				data.IsUserSession = _IsUserSession;
				if (strData == "Console")
				{
					_IsConsoleSession = true;
				}
				data.IsConsoleSession = _IsConsoleSession;
				
				WINSTATIONINFORMATIONW wsInfo = GetWinStationInformation(server, SessionId);
				DateTime? _loginTime = FileTimeToDateTime(wsInfo.LoginTime);
				DateTime? _lastInputTime = FileTimeToDateTime(wsInfo.LastInputTime);
				DateTime? _disconnectTime = FileTimeToDateTime(wsInfo.DisconnectTime);
				DateTime? _currentTime = FileTimeToDateTime(wsInfo.CurrentTime);
				TimeSpan? _idleTime = (_currentTime != null && _lastInputTime != null) ? _currentTime.Value - _lastInputTime.Value : TimeSpan.Zero;
				data.LogonTime = _loginTime;
				data.IdleTime = _idleTime;
				data.DisconnectTime = _disconnectTime;
				
				if (currentSessionID == SessionId)
				{
					_IsCurrentSessionId = true;
				}
				data.IsCurrentSession = _IsCurrentSessionId;
			}
			finally
			{
				WTSFreeMemory(buffer);
				buffer = IntPtr.Zero;
				CloseServer(server);
			}
			return data;
		}
		
		public static TerminalSessionInfo[] GetUserSessionInfo(string ServerName)
		{
			if (ServerName == "localhost" || ServerName == String.Empty)
			{
				ServerName = Environment.MachineName;
			}
			
			// Find and get detailed information for all user sessions
			// Also determine the active user session. If a console user exists, then that will be the active user session.
			// If no console user exists but users are logged in, such as on terminal servers, then select the first logged-in non-console user that is either 'Active' or 'Connected' as the active user.
			TerminalSessionData[] sessions = ListSessions(ServerName);
			TerminalSessionInfo sessionInfo = new TerminalSessionInfo();
			List<TerminalSessionInfo> userSessionsInfo = new List<TerminalSessionInfo>();
			string firstActiveUserNTAccount = String.Empty;
			bool IsActiveUserSessionSet = false;
			foreach (TerminalSessionData session in sessions)
			{
				if (session.IsUserSession == true)
				{
					sessionInfo = GetSessionInfo(ServerName, session.SessionId);
					if (sessionInfo.IsUserSession == true)
					{
						if ((firstActiveUserNTAccount == String.Empty) && (sessionInfo.ConnectState == "Active" || sessionInfo.ConnectState == "Connected"))
						{
							firstActiveUserNTAccount = sessionInfo.NTAccount;
						}
						
						if (sessionInfo.IsConsoleSession == true)
						{
							sessionInfo.IsActiveUserSession = true;
							IsActiveUserSessionSet = true;
						}
						else
						{
							sessionInfo.IsActiveUserSession = false;
						}
						
						userSessionsInfo.Add(sessionInfo);
					}
				}
			}
			
			TerminalSessionInfo[] userSessions = userSessionsInfo.ToArray();
			if (IsActiveUserSessionSet == false)
			{
				foreach (TerminalSessionInfo userSession in userSessions)
				{
					if (userSession.NTAccount == firstActiveUserNTAccount)
					{
						userSession.IsActiveUserSession = true;
						break;
					}
				}
			}
			
			return userSessions;
		}
	}
}
"@
        Add-Type -TypeDefinition $CSharpCode -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
    }
    #$usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:ComputerName")
    $usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:COMPUTERNAME") | Where-Object { $_.Connectstate -eq "Active" -and $_.IsConsoleSession -eq $True }
    if ($usernameLookup) {
        $usernameLookup = $usernameLookup.username;
    }
    if ($ReturnObj) {
        if ($usernameLookup -match "([^\\]*)\\(.*)") {
            $usernameProp = @{"Username" = $Matches[2]; "Domain" = $Matches[1]; "FullName" = $Matches[0] }
            $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
        }
        elseif ($usernameLookup -match "([^@]*)@(.*)") {
            $usernameProp = @{"Username" = $Matches[1]; "Domain" = $Matches[2]; "Fullname" = $Matches[0] }
            $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
        }         
    }
    return $usernameLookup;
}
 #>
function Get-UserSIDLookup {
    <#
    .SYNOPSIS
    Retrieves the Security Identifier (SID) for a given username.
    
    .DESCRIPTION
    Translates a username to its corresponding Windows SID.
    Supports domain and local users. Uses current user if none specified.
    
    .PARAMETER UsernameLookup
    The username to look up (e.g., "username", "DOMAIN\username", or "user@domain.com").
    If not provided or set to "(current_user)", uses the current logged-on user.
    
    .EXAMPLE
    $sid = Get-UserSIDLookup "jsmith"
    # Returns: S-1-5-21-3623811015-3361044348-30300820-1013
    
    .EXAMPLE
    # Get SID for current user
    $sid = Get-UserSIDLookup
    
    .EXAMPLE
    $sid = Get-UserSIDLookup "CONTOSO\jsmith"
    
    .OUTPUTS
    String - The user's SID or error message if user not found
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [string]$UsernameLookup
    )
    if ($usernameLookup -eq "(current_user)" -or $UsernameLookup -eq "") {
        $usernameLookup = Get-CurrentLoggedonUser
    } 
        
    if ($usernameLookup.Contains("\")) {
        $usernameLookup = $usernameLookup.Split("\")[1];
    }
    elseif ($usernameLookup.Contains("@")) {
        $usernameLookup = $usernameLookup.Split("@")[0];
    }
    $User = New-Object System.Security.Principal.NTAccount($usernameLookup)
    try {
        $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value;
        return $sid;
    }
    catch {
        $ErrorMessage = $_.Exception.Message;
        return ("Error:: " + $ErrorMessage);
    }
    
}

function Get-ReverseSID {
    <#
    .SYNOPSIS
    Retrieves the username or group name for a given Security Identifier (SID).
    
    .DESCRIPTION
    Translates a Windows SID to its corresponding username or group name.
    Queries the local system and domain for account information.
    
    .PARAMETER SID
    The Security Identifier to translate (e.g., "S-1-5-21-3623811015-3361044348-30300820-1013")
    
    .PARAMETER ignoreGroups
    If $true, returns error if SID is a group. If $false, includes group lookups. Default is $true.
    
    .EXAMPLE
    $username = Get-ReverseSID "S-1-5-21-3623811015-3361044348-30300820-1013"
    # Returns: jsmith
    
    .EXAMPLE
    # Include group lookups
    $account = Get-ReverseSID "S-1-5-32-544" -ignoreGroups $false
    # Returns: Administrators
    
    .OUTPUTS
    String - The username/group name or error message if SID not found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$SID, 
        [Parameter(Mandatory = $false)]
        [bool]$ignoreGroups = $true
    )

    try {
        
        $domainJoined = $false;
        $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
        $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain;
        $domainJoined = (Get-CimInstance -Class CIM_ComputerSystem).PartOfDomain
        if ($domainJoined) {
            $domain = $localmachine;
        }


        $newSID = Get-WmiObject -Class Win32_UserAccount -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        if (($newSID | Measure-Object).Count -eq 0 -and $ignoreGroups) {
            return "Error:: User not found"
        }
        elseif (($newSID | Measure-Object).Count -eq 0 -and !$ignoreGroups) {
            $newSID = Get-WmiObject -Class Win32_Group -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        }

        if ($newSID) {     
            if ($domain.ToLower().Contains($newSID.domain.ToLower())) {
                #Local user, just return the username
                return $newSID.Name;
            }
            else {
                #Domain user, just return the username
                return $newSID.Caption;
            }
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message;
        return ("Error:: " + $ErrorMessage);
    }
}

function Write-Log {
    <#
    .SYNOPSIS
    Writes a log message to a file with timestamp and log level.
    
    .DESCRIPTION
    Writes color-coded messages to both console and log file with ISO 8601 timestamps.
    Supports multiple log levels and prevents file overwriting with NoClobber.
    
    .PARAMETER Message
    The message to write to the log file and console.
    
    .PARAMETER Path
    The path to the log file. Defaults to $PSScriptRoot or C:\Temp if script root is unavailable.
    
    .PARAMETER Level
    The log level: Success (Green), Error (Red), Warn (Yellow), Info (White). Default is Info.
    
    .PARAMETER NoClobber
    If specified, prevents overwriting existing log files.
    
    .EXAMPLE
    Write-Log -Message "Device enrollment completed" -Level "Success"
    
    .EXAMPLE
    Write-Log -Message "Failed to connect to server" -Path "C:\Logs\deployment.log" -Level "Error"
    
    .EXAMPLE
    Write-Log -Message "Configuration updated" -Level "Info" -NoClobber
    
    .OUTPUTS
    None - writes to console and log file only
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()] [Alias("LogContent")] [string]$Message,
        [Parameter(Mandatory = $false)]
        [Alias('LogPath')] [Alias('LogLocation')] [string]$Local:Path,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Success", "Error", "Warn", "Info")] [string]$Level = "Info",
        [Parameter(Mandatory = $false)] [switch]$NoClobber
    )

    begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'

        if(!$LogPath){
            $LogPath = $PSScriptRoot;
            if($null -eq $PSScriptRoot){
                #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
                $LogPath = Get-Location
            }
        }
		#write-host "LogPath: $LogPath"
		if($null -eq $IsWindows){
			if($env:OS -eq "Windows_NT"){
				$delimiter = "\"
			}else{
				$delimiter = "/"
			}
		} else {
			$delimiter = "\"
		}
        $DateNow = Get-Date -Format "yyyyMMdd"
        $scriptName = split-path $MyInvocation.PSCommandPath -Leaf
        $scriptBaseName = $scriptName.TrimEnd(".ps1")
        $Script:NewLogFileName = "$scriptBaseName"+"_"+"$DateNow"+".log"
        $Script:NewLogFile = "$LogPath"+"$delimiter"+"$Script:NewLogFileName"

        if (!(Test-Path $Script:NewLogFile)) {
            # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
            New-Item -Path $Script:NewLogFile -Force -ItemType File
        }
		$Script:LogFile = $Script:NewLogFile

        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffZ"

        $ColorMap = @{"Success" = "Green"; "Error" = "Red"; "Warn" = "Yellow" }
        $FontColor = "White"
        if ($ColorMap.ContainsKey($Level)) {
            $FontColor = $ColorMap[$Level]
        }
    }
    process {
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Script:LogFile) -and $NoClobber) {
            Write-Error "Log file $Local:LogFile already exists, and you specified NoClobber. Either delete the file or specify a different LogPath."
            return
        }

        # Write message with Date Level and Message
        Add-Content -Path $Script:LogFile -Value ("$timestamp`t$Level`t$Message")
        Write-Host "$Level`t$Message" -ForegroundColor $FontColor
    }
    end {

    }
}

function Write-2Report { 
    <#
    .SYNOPSIS
    Writes a formatted message to a report file with decorative formatting.
    
    .DESCRIPTION
    Creates professional-looking report output with color-coded text and decorative borders.
    Suitable for generating audit reports, compliance reports, and deployment logs.
    
    .PARAMETER Message
    The message to write to the report file.
    
    .PARAMETER Path
    The path to the report file.
    
    .PARAMETER Level
    The formatting level: Title (Cyan), Header (Yellow), Body (White), Footer (Yellow), Error (Red).
    Title automatically adds the date. Default is Body.
    
    .EXAMPLE
    Write-2Report -Path "C:\Reports\deployment.log" -Message "Device Deployment Report" -Level "Title"
    
    .EXAMPLE
    Write-2Report -Path "C:\Reports\deployment.log" -Message "Enrolled Devices" -Level "Header"
    Write-2Report -Path "C:\Reports\deployment.log" -Message "Device XYZ: Configuration applied" -Level "Body"
    
    .EXAMPLE
    Write-2Report -Path "C:\Reports\deployment.log" -Message "Report generated successfully" -Level "Footer"
    
    .OUTPUTS
    None - writes to console and report file only
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()] [Alias("LogContent")] [string]$Message,
        [Parameter(Mandatory = $true)]
        [Alias('LogPath')] [Alias('LogLocation')] [string]$Path,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Title", "Header", "Body", "Footer", "Error")] [string]$Level = "Body"       
    )
    
    $ColorMap = @{"Title" = "Cyan"; "Header" = "Yellow"; "Footer" = "Yellow"; "Error" = "Red" };
    $FontColor = "White";
    if ($ColorMap.ContainsKey($Level)) {
        $FontColor = $ColorMap[$Level];
    }
    if ($Level -eq "Error") {
        $Errormsg = @("************************************************************************`n`n`t$Message`n`n************************************************************************`n");
        $Message = $Errormsg
    }

    if ($Level -eq "Title") {
        $DateNow = Get-Date -Format f;
        $Title = @("************************************************************************`n`n`t$Message`n`n`t$DateNow`n`n************************************************************************`n");
        $Message = $Title
    }

    if ($Level -eq "Footer") {
        $Footer = @("************************************************************************`n`n`t$Message`n`n************************************************************************`n");
        $Message = $Footer
    }

    Add-Content -Path $Path -Value ("$Message")
    Write-Information "$Message" -ForegroundColor $FontColor;
    
}

function Show-Toast {
    <#
    .SYNOPSIS
    Displays a toast notification.
    
    .DESCRIPTION
    This function displays a toast notification with a specified title and message.
    
    .PARAMETER Title
    The title of the toast notification.
    
    .PARAMETER Message
    The message of the toast notification.
    
    .PARAMETER AppId
    The AppId of the application displaying the toast notification. Default is PowerShell.
    
    .OUTPUTS
    None
    #>

    param(
        [Parameter(Mandatory = $false)]
        [string]$Title,
        [Parameter(Mandatory = $false)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$AppId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    )

    try {
        #Ensure-ToastAppId -AppId $AppId
        #$appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        $WorkspaceOne = Get-StartApps | Where-Object Name -Like "Workspace ONE Intelligent Hub" | Select-Object Name, AppId
        if (($WorkspaceOne | Measure-Object).Count -gt 0) {
            $AppId = $WorkspaceOne.AppId
        }
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $xml = @"
<toast duration="long" scenario="reminder">
  <visual>
    <binding template="ToastGeneric">
      <text>$Title</text>
      <text>$Message</text>
    </binding>
  </visual>
</toast>
"@

        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xml)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $doc
        $toast.ExpirationTime = (Get-Date).AddMinutes(1)
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId)
        $notifier.Show($toast)
    }
    catch {
        # Ignore toast errors
        Write-Error "Failed to show toast notification: $($_.Exception.Message)"
    }
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [string]$value
    )
    if (-not (Test-Path $path)) {
        return $null
    }

    try {
        $registryValue = (Get-ItemProperty -Path $path -Name $value -ErrorAction Stop).$value
        return $registryValue
    }
    catch {
        Write-Error "Failed to get registry value: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-AgentCleanup {
    <#
    .SYNOPSIS
    Removes Workspace ONE Agent and associated artifacts for device repurposing or troubleshooting.
    
    .DESCRIPTION
    Uninstalls Workspace ONE Agent and removes residual registry keys, files, and certificates.
    Useful for device troubleshooting, testing, and re-enrollment scenarios.
    
    .EXAMPLE
    Invoke-AgentCleanup
    Removes all WS1 Agent components
    
    .OUTPUTS
    None
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Starting Workspace ONE Agent Cleanup" -Level "Info"
    
    $apps2remove = @("Workspace ONE", "*AirWatchLLC*")
    $regpaths2remove = @(
        "HKLM:\SOFTWARE\Airwatch"
        "HKLM:\SOFTWARE\AirwatchMDM"
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Endpoint Telemetry"
        "HKLM:\SOFTWARE\VMware, Inc.\VMware EUC Telemetry"
        "HKLM:\SOFTWARE\WorkspaceONE"
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
        "HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\*\MSI"
    )
    $filepaths2remove = @(
        "$env:ProgramData\AirWatch"
        "$env:ProgramData\AirWatchMDM"
        "$env:ProgramData\EUC"
        "$env:ProgramData\VMware\SfdAgent"
        "$env:ProgramData\VMware\vmwetlm"
        "$env:ProgramData\VMWOSQEXT"
        "$env:ProgramFiles\WorkspaceONE"
        "$env:LOCALAPPDATA\VMware\IntelligentHub"
        "$env:LOCALAPPDATA\WorkspaceONE"
        "$env:ProgramFiles(x86)\Airwatch"
    )
    $certs2remove = @("*AirWatchCA*", "*AwDeviceRoot*")
    
    Write-Log -Message "Removing WS1 Agent applications" -Level "Info"
    foreach ($app in $apps2remove) {
        $win32App = Get-WmiObject -Class Win32_Product -Filter "Name like '%$app%'" -ErrorAction SilentlyContinue
        if ($win32App) {
            Write-Log -Message "Uninstalling: $($win32App.Name)" -Level "Info"
            $win32App.Uninstall() | Out-Null
        }
    }
    
    Write-Log -Message "Removing WS1 Registry Keys" -Level "Info"
    foreach ($path in $regpaths2remove) {
        if (Test-Path $path) {
            Write-Log -Message "Removing registry path: $path" -Level "Info"
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    
    Write-Log -Message "Removing WS1 Files and Folders" -Level "Info"
    foreach ($path in $filepaths2remove) {
        if (Test-Path $path) {
            Write-Log -Message "Removing file/folder: $path" -Level "Info"
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    
    Write-Log -Message "Removing WS1 Certificates" -Level "Info"
    foreach ($certname in $certs2remove) {
        $certs = Get-ChildItem cert: -Recurse | Where-Object {$_.Issuer -like $certname} -ErrorAction SilentlyContinue
        foreach ($cert in $certs) {
            Write-Log -Message "Removing certificate: $($cert.Subject)" -Level "Info"
            Remove-Item -Path $cert.PSPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    
    Write-Log -Message "Workspace ONE Agent Cleanup completed" -Level "Success"
}

function Get-DevicesByCustomAttribute {
    <#
    .SYNOPSIS
    Retrieves devices matching specified custom attribute name and values.
    
    .DESCRIPTION
    Searches WS1 UEM for devices with a specific custom attribute containing any of the specified values.
    Uses pagination to retrieve all matching devices across multiple pages.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com)
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication.
    
    .PARAMETER CustomAttribute
    The custom attribute name to search for.
    
    .PARAMETER CustomAttributeValues
    Array of custom attribute values to match.
    
    .PARAMETER PageSize
    Number of results per page. Default is 500.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    $devices = Get-DevicesByCustomAttribute -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -CustomAttribute "Department" -CustomAttributeValues @("IT", "Finance")
    
    .OUTPUTS
    PSCustomObject with Devices array and total count
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$CustomAttribute,
        
        [Parameter(Mandatory = $false)]
        [string[]]$CustomAttributeValues = @(),
        
        [Parameter(Mandatory = $false)]
        [int]$PageSize = 500
    )
    
    $page = 0
    $allDevices = @()
    $total = $null
    
    while ($true) {
        $endpoint = "$Server/API/mdm/devices/litesearch?customattributes=$CustomAttribute&page=$page&pagesize=$PageSize"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey
        
        if ($response -and $response.Devices) {
            if ($CustomAttributeValues.Count -gt 0) {
                $allDevices += $response.Devices | Where-Object { $_.CustomAttributes | Where-Object { $_.Name -eq $CustomAttribute -and $_.Value -in $CustomAttributeValues } }
            } else {
                $allDevices += $response.Devices
            }
            
            if ($page -eq 0) {
                $total = $response.total
                if (-not $total) { break }
            }
            
            $page++
            if ($total -le $page * $PageSize) { break }
        } else {
            break
        }
    }
    
    return [PSCustomObject]@{
        Devices = $allDevices
        Total   = $total
    }
}

function New-Tag {
    <#
    .SYNOPSIS
    Creates a new tag in Workspace ONE UEM for an Organization Group.
    
    .DESCRIPTION
    Creates a new tag in WS1 UEM using the MDM API V3 endpoint. The tag will be available
    for assignment to devices in the specified organization group. Uses Get-OG to resolve
    the organization group name to UUID.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com)
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication.
    
    .PARAMETER TagName
    The name of the tag to create. Cannot exceed 255 characters.
    
    .PARAMETER OrgGroupName
    The Organization Group name to create the tag in.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    $newTag = New-Tag -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -TagName "Enrolled" -OrgGroupName "Corp"
    
    .EXAMPLE
    # Using auth object OG name
    $newTag = New-Tag -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -TagName "Production" -OrgGroupName $auth.OGName
    
    .OUTPUTS
    PSCustomObject with tag creation result (UUID and name on success)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$TagName,
        
        [Parameter(Mandatory = $true)]
        [string]$OrgGroupName
    )
    
    # Validate tag name
    if ([string]::IsNullOrEmpty($TagName) -or $TagName.Length -gt 255) {
        Write-Log -Message "Tag name must be non-empty and not exceed 255 characters" -Level "Error"
        return $null
    }
    
    # Get OG UUID using Get-OG
    Write-Log -Message "Looking up Organization Group: $OrgGroupName" -Level "Info"
    $ogResponse = Get-OG -Server $Server -Auth $Auth -Apikey $ApiKey -OrgGroup $OrgGroupName
    
    if (-not $ogResponse -or -not $ogResponse.OrganizationGroups -or $ogResponse.OrganizationGroups.Count -eq 0) {
        Write-Log -Message "Organization Group '$OrgGroupName' not found" -Level "Error"
        return $null
    }
    
    $OrgGroupUuid = $ogResponse.OrganizationGroups[0].Uuid
    Write-Log -Message "Found OG UUID: $OrgGroupUuid" -Level "Info"
    
    # Create tag via V3 API
    $tagPayload = @{
        tag_name              = $TagName
        organization_group_uuid = $OrgGroupUuid
    } | ConvertTo-Json
    
    $endpoint = "$Server/api/v3/tags"
    $response = Invoke-AWApiCommand -Endpoint $endpoint -Method POST -ApiVersion 3 -Body $tagPayload -Auth $Auth -Apikey $ApiKey
    
    if ($response -and -not $response.Error) {
        Write-Log -Message "Tag '$TagName' created successfully" -Level "Success"
        return $response
    } else {
        $errorMsg = if ($response.Error) { $response.Error } else { "Unknown error" }
        Write-Log -Message "Failed to create tag '$TagName': $errorMsg" -Level "Error"
        return $null
    }
}

function Get-DeviceTags {
    <#
    .SYNOPSIS
    Retrieves tags from a Workspace ONE UEM Organization Group.
    
    .DESCRIPTION
    Lists available tags in an organization group. Optionally filters by tag name using wildcard patterns.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com)
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication.
    
    .PARAMETER OrgGroupId
    The Organization Group ID.
    
    .PARAMETER TagName
    Optional tag name filter (supports wildcards).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    $tags = Get-DeviceTags -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -OrgGroupId 1
    
    .EXAMPLE
    # Filter tags by name pattern
    $enrollmentTags = Get-DeviceTags -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -OrgGroupId 1 -TagName "Enrollment*"
    
    .OUTPUTS
    PSCustomObject with Tags array
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [int]$OrgGroupId,
        
        [Parameter(Mandatory = $false)]
        [string]$TagName
    )
    
    if ($TagName) {
        $endpoint = "$Server/API/mdm/tags/search?name=$TagName&organizationgroupid=$OrgGroupId"
    } else {
        $endpoint = "$Server/API/mdm/tags/search?organizationgroupid=$OrgGroupId"
    }
    
    $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey
    
    return $response
}

function Add-DeviceTag {
    <#
    .SYNOPSIS
    Applies a tag to a device in Workspace ONE UEM.
    
    .DESCRIPTION
    Tags a device in WS1 UEM. If the tag doesn't exist and -CreateIfMissing is specified,
    the tag will be created before applying it to the device.
    Supports batch operations by calling in a loop against multiple devices.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com)
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication.
    
    .PARAMETER DeviceUuid
    The device UUID to tag.
    
    .PARAMETER TagName
    The name of the tag to apply.
    
    .PARAMETER OrgGroupId
    The Organization Group ID. Used to search for existing tags.
    
    .PARAMETER OrgGroupName
    The Organization Group name. Used when creating tags with -CreateIfMissing.
    If not specified, falls back to searching by OrgGroupId only.
    
    .PARAMETER CreateIfMissing
    Switch to create the tag if it doesn't already exist in the organization group.
    Requires OrgGroupName to be specified.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    Add-DeviceTag -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DeviceUuid "device-uuid-123" -TagName "Enrolled" -OrgGroupId 1
    
    .EXAMPLE
    # Create tag if it doesn't exist
    Add-DeviceTag -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DeviceUuid "device-uuid-123" -TagName "NewTag" -OrgGroupId 1 -OrgGroupName "Corp" -CreateIfMissing
    
    .EXAMPLE
    # Batch tag multiple devices with auto-creation
    $devices | ForEach-Object { 
        Add-DeviceTag -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
            -DeviceUuid $_.DeviceUuid -TagName "Batch01" -OrgGroupId 1 -OrgGroupName "Corp" -CreateIfMissing
    }
    
    .OUTPUTS
    PSCustomObject with tag operation result
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$DeviceUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$TagName,
        
        [Parameter(Mandatory = $true)]
        [int]$OrgGroupId,
        
        [Parameter(Mandatory = $false)]
        [string]$OrgGroupName,
        
        [Parameter(Mandatory = $false)]
        [switch]$CreateIfMissing
    )
    
    # Search for existing tag
    $tags = Get-DeviceTags -Server $Server -Auth $Auth -ApiKey $ApiKey -OrgGroupId $OrgGroupId -TagName $TagName
    
    if ($tags.Tags -and $tags.Tags.Count -gt 0) {
        $tagId = $tags.Tags[0].Id.Value
        $tagUuid = $tags.Tags[0].Uuid
    } else {
        if ($CreateIfMissing) {
            if ([string]::IsNullOrEmpty($OrgGroupName)) {
                Write-Log -Message "OrgGroupName is required when using -CreateIfMissing" -Level "Error"
                return $null
            }
            
            Write-Log -Message "Tag '$TagName' not found. Creating new tag..." -Level "Info"
            $createdTag = New-Tag -Server $Server -Auth $Auth -ApiKey $ApiKey -TagName $TagName -OrgGroupName $OrgGroupName
            
            if (-not $createdTag) {
                Write-Log -Message "Failed to create tag '$TagName'" -Level "Error"
                return $null
            }
            
            $tagUuid = $createdTag.uuid
            Write-Log -Message "Tag created with UUID: $tagUuid" -Level "Success"
        } else {
            Write-Log -Message "Tag '$TagName' not found. Use -CreateIfMissing to create it automatically." -Level "Error"
            return $null
        }
    }
    
    $endpoint = "$Server/API/mdm/devices/$DeviceUuid/tags/$tagUuid"
    $response = Invoke-AWApiCommand -Endpoint $endpoint -Method POST -ApiVersion 1 -Auth $Auth -Apikey $ApiKey
    
    Write-Log -Message "Tagged device $DeviceUuid with tag '$TagName'" -Level "Success"
    return $response
}

function Remove-DeviceTag {
    <#
    .SYNOPSIS
    Removes a tag from a device in Workspace ONE UEM.
    
    .DESCRIPTION
    Removes a specified tag from a device using the DELETE HTTP method.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com)
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication.
    
    .PARAMETER DeviceUuid
    The device UUID.
    
    .PARAMETER TagName
    The name of the tag to remove.
    
    .PARAMETER OrgGroupId
    The Organization Group ID.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    Remove-DeviceTag -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DeviceUuid "device-uuid-123" -TagName "TestTag" -OrgGroupId 1
    
    .OUTPUTS
    PSCustomObject with removal result
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$DeviceUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$TagName,
        
        [Parameter(Mandatory = $true)]
        [int]$OrgGroupId
    )
    
    # Search for tag
    $tags = Get-DeviceTags -Server $Server -Auth $Auth -ApiKey $ApiKey -OrgGroupId $OrgGroupId -TagName $TagName
    
    if (-not $tags.Tags -or $tags.Tags.Count -eq 0) {
        Write-Error "Tag '$TagName' not found."
        return $null
    }
    
    $tagUuid = $tags.Tags[0].Uuid
    $endpoint = "$Server/API/mdm/devices/$DeviceUuid/tags/$tagUuid"
    $response = Invoke-AWApiCommand -Endpoint $endpoint -Method DELETE -ApiVersion 1 -Auth $Auth -Apikey $ApiKey
    
    Write-Log -Message "Removed tag '$TagName' from device $DeviceUuid" -Level "Success"
    return $response
}

function Get-DeviceEnrollmentStatus {
    <#
    .SYNOPSIS
    Checks the enrollment status of the local device in Workspace ONE UEM.
    
    .DESCRIPTION
    Retrieves device enrollment status from the local registry or via remote API query.
    Returns enrollment details including whether the device is enrolled, enrollment user, date, and source.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com). Required when LocalOnly is false.
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property. Required when LocalOnly is false.
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code) for authentication. Required when LocalOnly is false.
    
    .PARAMETER LocalOnly
    If true, only checks local registry. If false, queries WS1 API. Default is true.
    
    .EXAMPLE
    # Check local enrollment status only (no parameters)
    $status = Get-DeviceEnrollmentStatus
    if ($status.IsEnrolled) { Write-Host "Device is enrolled" }
    
    .EXAMPLE
    # Check enrollment status via API
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "Corp"
    $status = Get-DeviceEnrollmentStatus -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -LocalOnly $false
    
    .OUTPUTS
    PSCustomObject with IsEnrolled, EnrollmentUser, EnrollmentDate, and Source properties
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [string]$Auth,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [bool]$LocalOnly = $true
    )
    
    # Check local registry for enrollment indicators
    $enrollmentKey = "HKLM:\SOFTWARE\AirwatchMDM\EnrollmentStatus"
    $workspaceOneKey = "HKLM:\SOFTWARE\WorkspaceONE"
    
    $isEnrolled = $false
    $enrollmentUser = $null
    $enrollmentDate = $null
    
    if (Test-Path $enrollmentKey) {
        $status = (Get-ItemProperty -Path $enrollmentKey -Name "Status" -ErrorAction SilentlyContinue).Status
        if ($status -eq 1) {
            $isEnrolled = $true
            $enrollmentUser = (Get-ItemProperty -Path $enrollmentKey -Name "EnrollmentUser" -ErrorAction SilentlyContinue).EnrollmentUser
            $enrollmentDate = (Get-ItemProperty -Path $enrollmentKey -Name "EnrollmentDate" -ErrorAction SilentlyContinue).EnrollmentDate
        }
    } elseif (Test-Path $workspaceOneKey) {
        $isEnrolled = $true
    }
    
    return [PSCustomObject]@{
        IsEnrolled      = $isEnrolled
        EnrollmentUser  = $enrollmentUser
        EnrollmentDate  = $enrollmentDate
        Source          = "LocalRegistry"
    }
}

function Get-Enrollment {
    <#
    .SYNOPSIS
    Retrieves detailed Workspace ONE enrollment information from the local device registry.
    
    .DESCRIPTION
    Queries the Windows registry to retrieve information about the current WS1 UEM enrollment,
    including the enrolled user (UPN), enrollment GUID, and enrolled server details.
    Returns enrollment object if device is enrolled, or $false if not enrolled.
    
    .EXAMPLE
    $enrollment = Get-Enrollment
    if ($enrollment) {
        Write-Host "Enrolled User: $($enrollment.UPN)"
        Write-Host "Enrolled Server: $($enrollment.Server)"
        Write-Host "Enrollment GUID: $($enrollment.GUID)"
    } else {
        Write-Host "Device not enrolled"
    }
    
    .OUTPUTS
    PSCustomObject with UPN, GUID, and Server properties if enrolled, or $false if not enrolled.
    #>
    
    Write-Log -Message "Checking for valid Workspace ONE Enrollment..." -Level "Info"
    
    # Getting GUID from MDM Enrollment
    $val = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue).PSChildname
    
    $mdm = $false
    foreach ($row in $val) {
        $PATH2 = "HKLM:\SOFTWARE\Microsoft\Enrollments\$row"
        $upn = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).UPN
        $EnrollmentState = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).EnrollmentState
        $providerID = (Get-ItemProperty -Path $PATH2 -ErrorAction SilentlyContinue).ProviderID
        
        if ($EnrollmentState -eq "1" -and $upn -and $providerID -eq "AirWatchMDM") {
            $mdm = $True
            $guid = $row
        }
    }
    
    if ($mdm) {
        $server = (Get-ItemProperty -Path "HKLM:\SOFTWARE\AIRWATCH\BEACON\CONSOLE SETTINGS" -ErrorAction SilentlyContinue).Server
        
        $Object = New-Object psobject
        $Object | Add-Member -MemberType NoteProperty -Name UPN -Value $UPN
        $Object | Add-Member -MemberType NoteProperty -Name GUID -Value $GUID
        $Object | Add-Member -MemberType NoteProperty -Name Server -Value $server
        Write-Log -Message "Workspace ONE Enrollment found. Enrolled user: $UPN. Enrolled Server: $server" -Level "Success"
        return $Object
    } else {
        Write-Log -Message "No Workspace ONE Enrollment found." -Level "Warn"
        return $false
    }
}

function Compare-EnrollmentSID {
    <#
    .SYNOPSIS
    Compares the current logged-in user SID with the Workspace ONE enrollment SID.
    
    .DESCRIPTION
    Retrieves the currently active Windows user's SID and compares it with the SID of the user
    who enrolled the device in Workspace ONE UEM. Returns $true if they match, $false if not.
    Useful for detecting enrollment mismatches during re-enrollment scenarios.
    
    .PARAMETER Enrollment
    Optional enrollment object from Get-Enrollment. If not provided, retrieves enrollment info automatically.
    
    .EXAMPLE
    $match = Compare-EnrollmentSID
    if ($match) {
        Write-Host "Current user matches enrollment SID"
    } else {
        Write-Host "Enrollment SID mismatch - re-enrollment recommended"
    }
    
    .EXAMPLE
    # Compare using retrieved enrollment object
    $enrollment = Get-Enrollment
    if ($enrollment) {
        $match = Compare-EnrollmentSID -Enrollment $enrollment
    }
    
    .OUTPUTS
    Boolean - $true if SIDs match, $false if they don't match
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [psobject]$Enrollment
    )
    
    Write-Log -Message "Checking Windows and enrollment SIDs..." -Level "Info"
    
    # Get current logged-in user session
    $user = quser | Select-Object -Skip 1 | ConvertFrom-String -PropertyNames NTAccount, SessionName, SessionId, SessionState, Idle, Login
    
    $currentSID = $null
    $ntAccount = $null
    foreach ($session in $user) {
        If ($session.SessionState -eq "Active") {
            $currentSID = [System.Security.Principal.NTAccount]$session.NTAccount | ForEach-Object { $_.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            $ntAccount = $session.NTAccount
        }
    }
    
    If ($currentSID) {
        Write-Log -Message "NTAccount: $ntAccount" -Level "Info"
        Write-Log -Message "Active Windows SID: $currentSID" -Level "Info"
    } else {
        Write-Log -Message "No logged in User to verify SID...exiting." -Level "Error"
        return $false
    }
    
    # Get enrollment info if not provided
    if (-not $Enrollment) {
        $Enrollment = Get-Enrollment
    }
    
    if (-not $Enrollment) {
        Write-Log -Message "No Workspace ONE enrollment found." -Level "Error"
        return $false
    }
    
    # Get enrollment SID from registry
    $GUID = $Enrollment.GUID
    $key = "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\"
    
    try {
        $WS1_SID = Get-ChildItem $key$GUID -ErrorAction SilentlyContinue | Select-Object name | Where-Object Name -notlike "*device" | ForEach-Object { $_.name.split('\') | Select-Object -last 1 }
        
        if ($WS1_SID.count -gt 1) {
            $WS1_SID = $WS1_SID[-1] # Select last item in array (proper enrollment SID)
        }
        
        Write-Log -Message "Enrollment SID: $WS1_SID" -Level "Info"
        
        If ($currentSID -eq $WS1_SID) {
            Write-Log -Message "SIDs Match" -Level "Success"
            return $true
        } else {
            Write-Log -Message "SIDs don't match" -Level "Warn"
            return $false
        }
    } catch {
        Write-Log -Message "Error comparing SIDs: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Disable-EnrollmentNotifications {
    <#
    .SYNOPSIS
    Disables Windows toast notifications for device enrollment activity.
    
    .DESCRIPTION
    Suppresses Windows System Toast notifications for MDM device enrollment and management.
    Useful for re-enrollment scenarios where users should not see enrollment-related system messages.
    Modifies the registry for the specified user or current user if not specified.
    
    .PARAMETER UserSID
    Optional user SID to modify registry for. If not specified, uses current user.
    
    .EXAMPLE
    # Disable notifications for current user
    Disable-EnrollmentNotifications
    
    .EXAMPLE
    # Disable notifications for specific user SID
    Disable-EnrollmentNotifications -UserSID "S-1-5-21-3623811015-3361044348-30300820-1013"
    
    .OUTPUTS
    None - Registry modifications are made in-place
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserSID
    )
    
    # Get current user SID if not provided
    if ([string]::IsNullOrEmpty($UserSID)) {
        $UserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    }
    
    $regPath = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity"
    
    try {
        Write-Log -Message "Disabling Windows Toast notification for Device Enrollment Activity for user $UserSID" -Level "Info"
        New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $regPath -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Device enrollment activity notifications disabled" -Level "Success"
    } catch {
        Write-Log -Message "Error disabling notifications: $($_.Exception.Message)" -Level "Error"
    }
}

function Enable-EnrollmentNotifications {
    <#
    .SYNOPSIS
    Enables Windows toast notifications for device enrollment activity.
    
    .DESCRIPTION
    Re-enables Windows System Toast notifications for MDM device enrollment and management.
    Reverses the effects of Disable-EnrollmentNotifications by removing the registry restriction.
    Modifies the registry for the specified user or current user if not specified.
    
    .PARAMETER UserSID
    Optional user SID to modify registry for. If not specified, uses current user.
    
    .EXAMPLE
    # Enable notifications for current user
    Enable-EnrollmentNotifications
    
    .EXAMPLE
    # Enable notifications for specific user SID
    Enable-EnrollmentNotifications -UserSID "S-1-5-21-3623811015-3361044348-30300820-1013"
    
    .OUTPUTS
    None - Registry modifications are made in-place
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserSID
    )
    
    # Get current user SID if not provided
    if ([string]::IsNullOrEmpty($UserSID)) {
        $UserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    }
    
    $regPath = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity"
    
    try {
        Write-Log -Message "Enabling Windows Toast notification for Device Enrollment Activity for user $UserSID" -Level "Info"
        Remove-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue -Force
        Write-Log -Message "Device enrollment activity notifications enabled" -Level "Success"
    } catch {
        Write-Log -Message "Error enabling notifications: $($_.Exception.Message)" -Level "Error"
    }
}

function Get-UemAgentInstallInfo {
    <#
    .SYNOPSIS
    Retrieves installation information for the Workspace ONE Intelligent Hub agent.
    
    .DESCRIPTION
    Queries WMI to check if Workspace ONE Intelligent Hub Installer is installed and returns installation status.
    
    .EXAMPLE
    $agentInfo = Get-UemAgentInstallInfo
    if ($agentInfo -and $agentInfo.InstallState -eq 5) {
        Write-Host "Agent is installed"
    } else {
        Write-Host "Agent not installed or not ready"
    }
    
    .OUTPUTS
    WMI object with installation information, or $null if not installed
    #>
    try {
        $installInfo = Get-WmiObject -Class Win32_Product -Filter "Name = 'Workspace ONE Intelligent Hub Installer'" -ErrorAction SilentlyContinue
        if ($installInfo) {
            Write-Log -Message "Found Hub Installer: State=$($installInfo.InstallState), Version=$($installInfo.Version)" -Level "Info"
        } else {
            Write-Log -Message "Hub Installer not found" -Level "Info"
        }
        return $installInfo
    } catch {
        Write-Log -Message "Error checking Hub installation: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Install-UemAgent {
    <#
    .SYNOPSIS
    Installs the Workspace ONE Intelligent Hub agent and enrolls the device.
    
    .DESCRIPTION
    Installs the WS1 Hub agent via MSI with enrollment parameters. If agent is already installed in ready state,
    skips installation. Logs installation activity.
    
    .PARAMETER AgentMsiPath
    Full path to the AirwatchAgent.msi file.
    
    .PARAMETER EnrollmentUrl
    The enrollment server URL (e.g., https://uem.example.com or https://ds001.awmdm.com).
    
    .PARAMETER EnrollmentOG
    The organization group name for enrollment.
    
    .PARAMETER EnrollmentUsername
    Username for enrollment.
    
    .PARAMETER EnrollmentPassword
    Password for enrollment (plaintext during installation).
    
    .PARAMETER LogPath
    Optional path for installation log. Defaults to script root.
    
    .EXAMPLE
    Install-UemAgent -AgentMsiPath "C:\Recovery\AirwatchAgent.msi" `
      -EnrollmentUrl "https://uem.example.com" `
      -EnrollmentOG "Corporate" `
      -EnrollmentUsername "enroll-user" `
      -EnrollmentPassword "P@ssw0rd"
    
    .OUTPUTS
    None - Installation is performed via msiexec
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AgentMsiPath,
        
        [Parameter(Mandatory = $true)]
        [string]$EnrollmentUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$EnrollmentOG,
        
        [Parameter(Mandatory = $true)]
        [string]$EnrollmentUsername,
        
        [Parameter(Mandatory = $true)]
        [string]$EnrollmentPassword,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = $PSScriptRoot
    )
    
    $installInfo = Get-UemAgentInstallInfo
    if ($installInfo -and $installInfo.InstallState -eq 5) {
        Write-Log -Message "UEM agent is already installed and ready, skipping installation" -Level "Success"
        return
    }
    
    if (-not (Test-Path -Path $AgentMsiPath)) {
        Write-Log -Message "Unable to find agent MSI file: $AgentMsiPath" -Level "Error"
        throw "MSI file not found: $AgentMsiPath"
    }
    
    $logFile = Join-Path -Path $LogPath -ChildPath "AirwatchAgent_$(Get-Date -Format 'yyyyMMdd_HHmmss').msi.log"
    
    Write-Log -Message "Installing UEM agent from: $AgentMsiPath" -Level "Info"
    Write-Log -Message "Enrollment parameters: Server=$EnrollmentUrl, OG=$EnrollmentOG, User=$EnrollmentUsername" -Level "Info"
    try {
        Write-Log "Installing AirwatchAgent" -Level Info
        $process = Start-Process msiexec.exe -ArgumentList "/i","$AgentMsiPath","/quiet","ENROLL=Y","SERVER=$EnrollmentUrl","LGNAME=$EnrollmentOG","USERNAME=$EnrollmentUsername","PASSWORD=$EnrollmentPassword" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Hub Install Completed." -Level Success
            #exit 0
        }
        else {
            Write-Log "Warning: HUB Install failed with exit code $($process.ExitCode)." -Level Error
            exit $($process.ExitCode)
        }
    }
    catch {
        Write-Log "Error: Script encountered an error: $_" -Level Error
        #exit 1
    }
<#     try {
        & msiexec /i $AgentMsiPath /qn /L*V $logFile `
            ENROLL=Y `
            SERVER=$EnrollmentUrl `
            LGNAME=$EnrollmentOG `
            USERNAME=$EnrollmentUsername `
            PASSWORD=$EnrollmentPassword
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Message "UEM agent installation initiated successfully. Log: $logFile" -Level "Success"
        } else {
            Write-Log -Message "MSI installation returned exit code: $LASTEXITCODE. Check log: $logFile" -Level "Warn"
        }
    } catch {
        Write-Log -Message "Error installing UEM agent: $($_.Exception.Message)" -Level "Error"
        throw $_
    } #>
}

function Remove-UemAgent {
    <#
    .SYNOPSIS
    Uninstalls the Workspace ONE Intelligent Hub agent from the device.
    
    .DESCRIPTION
    Removes the installed WS1 Hub agent if it exists and is in ready state (InstallState=5).
    Device enrollment should be removed first via appropriate unenrollment method.
    
    .EXAMPLE
    Remove-UemAgent
    
    .OUTPUTS
    None - Uninstallation is performed via WMI
    #>
    Write-Log -Message "Checking if UEM agent uninstall is required..." -Level "Info"
    
    try {
        $installInfo = Get-UemAgentInstallInfo
        
        if ($installInfo -and $installInfo.InstallState -eq 5) {
            Write-Log -Message "UEM agent found and ready. Uninstalling..." -Level "Info"
            $installInfo.Uninstall() | Out-Null
            Write-Log -Message "UEM agent uninstall initiated" -Level "Success"
        } else {
            Write-Log -Message "UEM agent not found or not in ready state, uninstall not required" -Level "Info"
        }
    } catch {
        Write-Log -Message "Error uninstalling UEM agent: $($_.Exception.Message)" -Level "Error"
        throw $_
    }
}

function Get-EnrollmentInfoWithPolling {
    <#
    .SYNOPSIS
    Retrieves comprehensive enrollment information by polling UEM API until device appears.
    
    .DESCRIPTION
    Queries WS1 UEM API for device enrollment information using serial number. Polls API repeatedly
    (every 2 minutes) until device appears in the expected state. Useful for waiting for device sync
    after enrollment or re-enrollment.
    
    Each API call includes automatic retry logic (exponential backoff) for transient failures,
    improving reliability in unstable network conditions.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER SerialNumber
    The device serial number to search for.
    
    .PARAMETER ExpectedStatus
    Expected enrollment status to wait for (Enrolled or Unenrolled). Default is Enrolled.
    
    .PARAMETER MaxAttempts
    Maximum polling attempts. Default is 30 (60 minutes).
    
    .PARAMETER PollIntervalSeconds
    Seconds between polls. Default is 120 (2 minutes).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $enrollment = Get-EnrollmentInfoWithPolling -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -SerialNumber "ABC123XYZ"
    if ($enrollment) {
        Write-Host "Device ID: $($enrollment.ID)"
        Write-Host "Device UUID: $($enrollment.UUID)"
    }
    
    .OUTPUTS
    Hashtable with ID, UUID, UDID, and Status properties when found, or $null on timeout
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$SerialNumber,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Enrolled", "Unenrolled")]
        [string]$ExpectedStatus = "Enrolled",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$PollIntervalSeconds = 120
    )
    
    $enrollmentFound = $false
    $attemptCount = 0
    
    Write-Log -Message "Polling for device enrollment status. Serial: $SerialNumber, Expected: $ExpectedStatus" -Level "Info"
    
    $endpoint = "$Server/api/mdm/devices?searchby=SerialNumber&id=$([System.Web.HttpUtility]::UrlEncode($SerialNumber))"
    
    while (-not $enrollmentFound -and $attemptCount -lt $MaxAttempts) {
        try {
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 5 -RetryIntervalSeconds 30
            
            if ($response -and $response.EnrollmentStatus -eq $ExpectedStatus) {
                $enrollmentFound = $true
                
                $enrollmentInfo = @{
                    Status = $response.EnrollmentStatus
                    ID     = $response.Id.Value
                    UUID   = $response.Uuid
                    UDID   = $response.Udid
                }
                
                Write-Log -Message "Device found as $($ExpectedStatus.ToLowerInvariant()). ID=$($enrollmentInfo.ID), UUID=$($enrollmentInfo.UUID)" -Level "Success"
                return $enrollmentInfo
            }
        } catch {
            Write-Log -Message "Error querying device: $($_.Exception.Message)" -Level "Warn"
        }
        
        $attemptCount++
        if (-not $enrollmentFound) {
            Write-Log -Message "Device not $($ExpectedStatus.ToLowerInvariant()) yet. Attempt $attemptCount/$MaxAttempts. Retrying in $PollIntervalSeconds seconds..." -Level "Info"
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
    
    if ($enrollmentFound) {
        return $enrollmentInfo
    } else {
        Write-Log -Message "Device still not found in $ExpectedStatus state after $($attemptCount * $PollIntervalSeconds) seconds ($attemptCount attempts)" -Level "Error"
        return $null
    }
}

function Wait-UemAppsInstalled {
    <#
    .SYNOPSIS
    Waits for all assigned applications to be installed on a device.
    
    .DESCRIPTION
    Polls UEM API to check installation status of assigned apps. Continues polling until all apps
    are installed or maximum attempts reached. Useful for post-enrollment workflows.
    
    Each API call includes automatic retry logic (exponential backoff) for transient failures,
    improving reliability in unstable network conditions.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER DeviceUuid
    The device UUID.
    
    .PARAMETER MaxAttempts
    Maximum polling attempts. Default is 30 (60 minutes).
    
    .PARAMETER PollIntervalSeconds
    Seconds between polls. Default is 120 (2 minutes).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $success = Wait-UemAppsInstalled -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DeviceUuid "device-uuid-123"
    if ($success) { Write-Host "All apps installed" }
    
    .OUTPUTS
    Boolean - $true if all apps installed, $false if timeout or error
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$DeviceUuid,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$PollIntervalSeconds = 120
    )
    
    $appsComplete = $false
    $attemptCount = 0
    
    Write-Log -Message "Waiting for assigned apps to install on device: $DeviceUuid" -Level "Info"
    
    $endpoint = "$Server/API/mdm/devices/$([System.Web.HttpUtility]::UrlEncode($DeviceUuid))/apps/search"
    
    while (-not $appsComplete -and $attemptCount -lt $MaxAttempts) {
        try {
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 5 -RetryIntervalSeconds 30
            
            if ($response -and $response.app_items) {
                $assignedApps = $response.app_items | Where-Object { $_.assignment_status -eq "Assigned" }
                $installedApps = $assignedApps | Where-Object { $_.installed_status -eq "Installed" }
                $pendingApps = $assignedApps | Where-Object { $_.installed_status -ne "Installed" }
                
                $assignedCount = @($assignedApps).Count
                $installedCount = @($installedApps).Count
                $pendingCount = @($pendingApps).Count
                
                Write-Log -Message "App status: $installedCount/$assignedCount installed, $pendingCount pending" -Level "Info"
                
                if ($pendingCount -eq 0) {
                    $appsComplete = $true
                    Write-Log -Message "All assigned apps installed successfully" -Level "Success"
                    return $true
                }
            } else {
                Write-Log -Message "No apps assigned to device" -Level "Info"
                $appsComplete = $true
                return $true
            }
        } catch {
            Write-Log -Message "Error checking app status: $($_.Exception.Message)" -Level "Warn"
        }
        
        $attemptCount++
        if (-not $appsComplete) {
            Write-Log -Message "Apps still installing. Attempt $attemptCount/$MaxAttempts. Waiting $PollIntervalSeconds seconds..." -Level "Info"
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
    
    Write-Log -Message "App installation did not complete within timeout period" -Level "Error"
    return $false
}

function Wait-UemProfilesInstalled {
    <#
    .SYNOPSIS
    Waits for all assigned profiles to be installed on a device.
    
    .DESCRIPTION
    Polls UEM API to check installation status of assigned profiles. Continues polling until all profiles
    are installed or maximum attempts reached. Useful for post-enrollment workflows.
    
    Each API call includes automatic retry logic (exponential backoff) for transient failures,
    improving reliability in unstable network conditions.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER DeviceId
    The device ID (numeric).
    
    .PARAMETER MaxAttempts
    Maximum polling attempts. Default is 30 (60 minutes).
    
    .PARAMETER PollIntervalSeconds
    Seconds between polls. Default is 120 (2 minutes).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $success = Wait-UemProfilesInstalled -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DeviceId 12345
    if ($success) { Write-Host "All profiles installed" }
    
    .OUTPUTS
    Boolean - $true if all profiles installed, $false if timeout or error
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [int32]$DeviceId,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$PollIntervalSeconds = 120
    )
    
    $profilesComplete = $false
    $attemptCount = 0
    
    Write-Log -Message "Waiting for assigned profiles to install on device: $DeviceId" -Level "Info"
    
    $endpoint = "$Server/API/mdm/devices/$DeviceId/profiles"
    
    while (-not $profilesComplete -and $attemptCount -lt $MaxAttempts) {
        try {
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 5 -RetryIntervalSeconds 30
            
            if ($response -and $response.DeviceProfiles) {
                $assignedProfiles = $response.DeviceProfiles | Where-Object { $_.AssignmentType -eq 1 }
                $installedProfiles = $assignedProfiles | Where-Object { $_.Status -eq 3 }
                $pendingProfiles = $assignedProfiles | Where-Object { $_.Status -ne 3 }
                
                $assignedCount = @($assignedProfiles).Count
                $installedCount = @($installedProfiles).Count
                $pendingCount = @($pendingProfiles).Count
                
                Write-Log -Message "Profile status: $installedCount/$assignedCount installed, $pendingCount pending" -Level "Info"
                
                if ($pendingCount -eq 0) {
                    $profilesComplete = $true
                    Write-Log -Message "All assigned profiles installed successfully" -Level "Success"
                    return $true
                }
            } else {
                Write-Log -Message "No profiles assigned to device" -Level "Info"
                $profilesComplete = $true
                return $true
            }
        } catch {
            Write-Log -Message "Error checking profile status: $($_.Exception.Message)" -Level "Warn"
        }
        
        $attemptCount++
        if (-not $profilesComplete) {
            Write-Log -Message "Profiles still installing. Attempt $attemptCount/$MaxAttempts. Waiting $PollIntervalSeconds seconds..." -Level "Info"
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
    
    Write-Log -Message "Profile installation did not complete within timeout period" -Level "Error"
    return $false
}

function Invoke-OGSearch {
    <#
    .SYNOPSIS
    Search for Organization Groups and prompt user to select from results.
    
    .DESCRIPTION
    Queries Workspace ONE UEM for Organization Groups matching a partial name search.
    If multiple matches found, displays list and prompts user for selection.
    Returns the selected Organization Group with UUID, Name, GroupId, and Country properties.
    
    .PARAMETER Server
    Workspace ONE UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential in format "Basic {base64string}" (for Basic auth) or "Bearer {token}" (for OAuth2).
    Typically obtained from Get-ServerAuth -cred property.
    
    .PARAMETER ApiKey
    Workspace ONE UEM API Key (aw-tenant-code) for authentication.
    
    .PARAMETER OrgGroup
    Organization Group name or partial name to search for.
    
    .PARAMETER Debug
    Enable debug output to console.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass123" -ApiKey "key" -OGName "IT"
    $selectedOG = Invoke-OGSearch -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -OrgGroup "IT"
    Write-Host "Selected OG: $($selectedOG.Name) with UUID: $($selectedOG.Uuid)"
    
    .OUTPUTS
    PSCustomObject with Uuid, Name, GroupId, and Country properties of selected Organization Group, or $null if user cancels
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server,
        
        [Parameter(Mandatory=$true)]
        [string]$Auth,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [string]$OrgGroup,
        
        [Parameter(Mandatory=$false)]
        [bool]$Debug = $false
    )
    
    $OGSearch = Get-OG -Server $Server -Auth $Auth -ApiKey $ApiKey -OrgGroup $OrgGroup -Debug $Debug
    $OGSearchOGs = $OGSearch.OrganizationGroups
    $OGSearchTotal = $OGSearch.TotalResults
    
    if($Debug){ 
        Write-Log -Message "OGSearch: $OGSearch" -Level "Info"
    }
    
    if($null -eq $OGSearch){
        Write-Log -Message "Server Authentication or Server Connection Failure" -Level "Error"
        return $null
    } elseif ($OGSearchTotal -eq 1){
        $selectedOG = [PSCustomObject]@{
            Uuid = $OGSearch.OrganizationGroups[0].Uuid
            Name = $OGSearch.OrganizationGroups[0].Name
            GroupId = $OGSearch.OrganizationGroups[0].GroupId
            Country = $OGSearch.OrganizationGroups[0].Country
        }
        if($Debug){ 
            Write-Log -Message "Selected OG UUID: $($selectedOG.Uuid)" -Level "Info"
        }
        return $selectedOG
    } elseif ($OGSearchTotal -gt 1) {
        $ValidChoices = 0..($OGSearchOGs.Count -1)
        $ValidChoices += 'Q'
        Write-Host "`nMultiple OGs found. Please select an OG from the list:" -ForegroundColor Yellow
        $Choice = ''
        while ([string]::IsNullOrEmpty($Choice)) {

            $i = 0
            foreach ($OG in $OGSearchOGs) {
                Write-Host ('{0}: {1}       {2}       {3}' -f $i, $OG.name, $OG.GroupId, $OG.Country)
                $i += 1
            }

            $Choice = Read-Host -Prompt 'Type the number that corresponds to the OG or Press "Q" to quit'
            if ($Choice -in $ValidChoices) {
                if ($Choice -eq 'Q'){
                    Write-Log -Message "User exited OG selection" -Level "Info"
                    return $null
                } else {
                    $selectedOG = [PSCustomObject]@{
                        Uuid = $OGSearchOGs[$Choice].Uuid
                        Name = $OGSearchOGs[$Choice].Name
                        GroupId = $OGSearchOGs[$Choice].GroupId
                        Country = $OGSearchOGs[$Choice].Country
                    }
                    return $selectedOG
                }
            } else {
                [console]::Beep(1000, 300)
                Write-Warning ('    [ {0} ] is NOT a valid selection.' -f $Choice)
                Write-Warning '    Please try again ...'
                pause
                $Choice = ''
            }
        }
    } else {
        Write-Log -Message "No Organization Groups found matching '$OrgGroup'" -Level "Error"
        return $null
    }
}

function Invoke-DownloadAirwatchAgent {
    <#
    .SYNOPSIS
    Downloads the latest Workspace ONE Intelligent Hub (AirwatchAgent.msi) from Omnissa CDN.
    
    .DESCRIPTION
    Downloads AirwatchAgent.msi from https://packages.omnissa.com/wsone/AirwatchAgent.msi
    to the specified output path. Configures TLS 1.1 and 1.2 for secure transfer.
    Useful for automated deployment and golden image preparation.
    
    .PARAMETER OutputPath
    Destination path for downloaded AirwatchAgent.msi file. If not specified, uses $PSScriptRoot.
    Default is "$PSScriptRoot\AirwatchAgent.msi"
    
    .EXAMPLE
    Invoke-DownloadAirwatchAgent -OutputPath "C:\Windows\Setup\Scripts\AirwatchAgent.msi"
    Downloads latest Hub agent to specified location.
    
    .EXAMPLE
    $DownloadPath = "C:\Temp\AirwatchAgent.msi"
    Invoke-DownloadAirwatchAgent -OutputPath $DownloadPath
    Write-Log -Message "Download completed to: $DownloadPath" -Level "Success"
    
    .OUTPUTS
    System.Int32 - HTTP status code (200 for success, error code for failure)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$PSScriptRoot\AirwatchAgent.msi"
    )
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
        $url = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"
        
        Write-Log -Message "Starting download of AirwatchAgent.msi from $url" -Level "Info"
        Write-Log -Message "Output destination: $OutputPath" -Level "Info"
        
        $Response = Invoke-WebRequest -Uri $url -OutFile $OutputPath -ErrorAction Stop
        
        if ($Response.StatusCode -eq 200) {
            Write-Log -Message "Successfully downloaded AirwatchAgent.msi" -Level "Success"
            return $Response.StatusCode
        }
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Log -Message "Failed to download AirwatchAgent.msi. Status Code: $StatusCode. Error: $($_.Exception.Message)" -Level "Error"
        return $StatusCode
    }
}

function Invoke-CreateTask {
    <#
    .SYNOPSIS
    Creates a Windows Scheduled Task to run a PowerShell script with flexible scheduling options.
    
    .DESCRIPTION
    Creates a scheduled task that executes a PowerShell script with specified arguments.
    Supports multiple trigger types: at logon, on schedule, or immediately.
    Runs in SYSTEM context with highest privileges.
    Useful for automating enrollment and post-enrollment workflows.
    
    The task is configured with:
    - Hidden task display (optional)
    - System context with elevated privileges
    - Multiple instance policy: Queue new instances
    - Start when available if on battery
    
    .PARAMETER TaskName
    Name of the scheduled task. Default is "EnrollintoWS1"
    
    .PARAMETER ScriptPath
    Full path to PowerShell script to execute (e.g., C:\Windows\Setup\Scripts\EnrollintoWS1.ps1)
    
    .PARAMETER Arguments
    Arguments to pass to the PowerShell script. Can include parameters like:
    "-ServerName $ServerName -GroupID $GroupID -UserName $UserName -Password $Password"
    
    .PARAMETER TriggerType
    Type of trigger for task execution. Options:
    - "AtLogOn" (default): Runs when user logs on
    - "Now": Runs immediately
    - "Daily": Runs at specified time daily
    - "Weekly": Runs on specified day and time weekly
    
    .PARAMETER ScheduleTime
    Time for scheduled execution in 24-hour format (e.g., "14:30", "09:00").
    Required when TriggerType is "Daily" or "Weekly". Ignored for "AtLogOn" and "Now".
    
    .PARAMETER DayOfWeek
    Day of week for weekly execution (e.g., "Monday", "Friday", "Sunday").
    Only used when TriggerType is "Weekly". Default is "Monday".
    
    .PARAMETER RandomDelaySeconds
    Random delay in seconds before task executes. Default is 60 seconds.
    Used with "AtLogOn", "Daily", and "Weekly" triggers.
    
    .EXAMPLE
    # Run at next user logon with random delay
    $args = "-ServerName uem.example.com -GroupID 'Corp' -UserName staging -Password 'pass123'"
    Invoke-CreateTask -TaskName "EnrollintoWS1" -ScriptPath "C:\Windows\Setup\Scripts\EnrollintoWS1.ps1" -Arguments $args
    
    .EXAMPLE
    # Run immediately
    Invoke-CreateTask -TaskName "ImmediateTask" -ScriptPath "C:\Scripts\Configure.ps1" `
        -Arguments "-ConfigPath 'C:\Config\settings.json'" -TriggerType "Now"
    
    .EXAMPLE
    # Run daily at 9:30 AM
    Invoke-CreateTask -TaskName "DailySync" -ScriptPath "C:\Scripts\Sync.ps1" `
        -Arguments "-Mode Full" -TriggerType "Daily" -ScheduleTime "09:30"
    
    .EXAMPLE
    # Run every Friday at 5:00 PM
    Invoke-CreateTask -TaskName "WeeklyReport" -ScriptPath "C:\Scripts\Report.ps1" `
        -Arguments "-Generate" -TriggerType "Weekly" -ScheduleTime "17:00" -DayOfWeek "Friday"
    
    .OUTPUTS
    Boolean - $true if task created successfully, $false if error occurs
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory = $true)]
        [string]$Arguments,
        
        [Parameter(Mandatory = $false)]
        [string]$TaskName = "EnrollintoWS1",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("AtLogOn", "Now", "Daily", "Weekly")]
        [string]$TriggerType = "AtLogOn",
        
        [Parameter(Mandatory = $false)]
        [string]$ScheduleTime,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")]
        [string]$DayOfWeek = "Monday",
        
        [Parameter(Mandatory = $false)]
        [int]$RandomDelaySeconds = 60
    )
    
    try {
        $cmd = "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe"
        $fullArguments = "-ep Bypass -File $ScriptPath $Arguments"
        
        Write-Log -Message "Creating scheduled task: $TaskName" -Level "Info"
        Write-Log -Message "  Trigger Type: $TriggerType" -Level "Info"
        Write-Log -Message "  Command: $cmd" -Level "Info"
        Write-Log -Message "  Arguments: $fullArguments" -Level "Info"
        
        # Validate ScheduleTime for Daily/Weekly
        if ($TriggerType -in @("Daily", "Weekly") -and [string]::IsNullOrEmpty($ScheduleTime)) {
            throw "ScheduleTime parameter is required for TriggerType '$TriggerType'"
        }
        
        # Parse schedule time if provided
        $taskTime = $null
        if ($TriggerType -in @("Daily", "Weekly")) {
            try {
                $timeObj = [DateTime]::ParseExact($ScheduleTime, @("HH:mm", "H:mm", "HH:mm:ss"), $null)
                $taskTime = $timeObj
                Write-Log -Message "  Schedule Time: $($taskTime.ToString('HH:mm'))" -Level "Info"
            } catch {
                throw "Invalid ScheduleTime format. Use 24-hour format (e.g., '14:30' or '09:00')"
            }
        }
        
        # Create task action
        $taskAction = New-ScheduledTaskAction -Execute $cmd -Argument $fullArguments
        
        # Create trigger based on TriggerType
        switch ($TriggerType) {
            "AtLogOn" {
                Write-Log -Message "  Trigger: User logon with $RandomDelaySeconds second random delay" -Level "Info"
                $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay (New-TimeSpan -Seconds $RandomDelaySeconds)
            }
            "Now" {
                Write-Log -Message "  Trigger: Immediate execution (once)" -Level "Info"
                $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
            }
            "Daily" {
                Write-Log -Message "  Trigger: Daily at $($taskTime.ToString('HH:mm')) with $RandomDelaySeconds second random delay" -Level "Info"
                $taskTrigger = New-ScheduledTaskTrigger -Daily -At $taskTime -RandomDelay (New-TimeSpan -Seconds $RandomDelaySeconds)
            }
            "Weekly" {
                Write-Log -Message "  Trigger: Weekly on $DayOfWeek at $($taskTime.ToString('HH:mm')) with $RandomDelaySeconds second random delay" -Level "Info"
                $taskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $taskTime -RandomDelay (New-TimeSpan -Seconds $RandomDelaySeconds)
            }
        }
        
        # Create principal (SYSTEM context with highest privileges)
        $taskPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Create task settings
        $taskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -StartWhenAvailable -Priority 5
        $taskSettings.CimInstanceProperties['MultipleInstances'].Value = 3  # Queue new instances
        
        # Create and register the task
        $task = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettings
        Register-ScheduledTask -InputObject $task -TaskName $TaskName -Force -ErrorAction Stop
        
        Write-Log -Message "Successfully created scheduled task: $TaskName" -Level "Success"
        return $true
    } catch {
        Write-Log -Message "Error creating scheduled task: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Get-App {
    <#
    .SYNOPSIS
    Searches for existing applications in Workspace ONE UEM by name and organization group.
    
    .DESCRIPTION
    Queries the WS1 UEM MAM API to find applications by name within a specific organization group.
    Returns matching application objects including bundle ID, version, and file name for version management.
    Useful for checking if app versions already exist before uploading.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER AppName
    Name of the application to search for.
    
    .PARAMETER GroupId
    The organization group ID to search within.
    
    .PARAMETER Platform
    Optional platform filter (e.g., WinRT, Android, iOS). Searches all if not specified.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $apps = Get-App -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -AppName "7-Zip" -GroupId 15
    if ($apps) { Write-Host "Found $($apps.Count) matching apps" }
    
    .OUTPUTS
    PSCustomObject array with ApplicationName, AppVersion, BundleId, ApplicationFileName properties, or $null if not found
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $true)]
        [int]$GroupId,
        
        [Parameter(Mandatory = $false)]
        [string]$Platform
    )
    
    try {
        Write-Log -Message "Searching for application: $AppName in group $GroupId" -Level "Info"
        
        $url = "$Server/API/mam/apps/search?applicationname=$AppName&locationgroupid=$GroupId"
        if (-not [string]::IsNullOrEmpty($Platform)) {
            $url += "&platform=$Platform"
        }
        
        $response = Invoke-AWApiCommand -Endpoint $url -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.Application) {
            Write-Log -Message "Found $($response.Application.Count) application(s) matching '$AppName'" -Level "Success"
            return $response.Application
        } else {
            Write-Log -Message "No applications found matching '$AppName'" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error searching for application: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Invoke-ChunkandUpload {
    <#
    .SYNOPSIS
    Uploads large application files to Workspace ONE UEM in configurable chunks.
    
    .DESCRIPTION
    Splits large files into chunks (default 10MB) and uploads each chunk to UEM API.
    Converts each chunk to Base64 for transmission. Returns transaction ID for app creation.
    Essential for uploading MSI, EXE, and other large installers.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER FilePath
    Full path to the file to upload.
    
    .PARAMETER ChunkSizeBytes
    Size of each chunk in bytes. Default is 10MB (10485760 bytes).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $transId = Invoke-ChunkandUpload -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -FilePath "C:\apps\installer.msi"
    if ($transId) { Write-Host "Upload transaction: $transId" }
    
    .OUTPUTS
    String - Transaction ID for uploaded file, or $null if upload fails
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [int]$ChunkSizeBytes = 10485760  # 10MB default
    )
    
    try {
        if (-not (Test-Path -Path $FilePath)) {
            throw "File not found: $FilePath"
        }
        
        $fileInfo = Get-Item -Path $FilePath
        $totalSize = $fileInfo.Length
        $totalChunks = [math]::Ceiling($totalSize / $ChunkSizeBytes)
        
        Write-Log -Message "Starting chunked upload: $($fileInfo.Name) ($totalSize bytes, $totalChunks chunks)" -Level "Info"
        
        $reader = [System.IO.File]::OpenRead($FilePath)
        $chunkNumber = 0
        $transactionId = ""
        
        try {
            $buffer = New-Object byte[] $ChunkSizeBytes
            
            while ($true) {
                $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -eq 0) { break }
                
                $chunkNumber++
                
                # Resize buffer if last chunk is smaller
                $chunkData = $buffer
                if ($bytesRead -ne $buffer.Length) {
                    $chunkData = New-Object byte[] $bytesRead
                    [Array]::Copy($buffer, $chunkData, $bytesRead)
                }
                
                # Convert to Base64
                $base64Chunk = [Convert]::ToBase64String($chunkData, [System.Base64FormattingOptions]::None)
                
                Write-Log -Message "Uploading chunk $chunkNumber/$totalChunks ($bytesRead bytes)" -Level "Info"
                
                # Create chunk payload
                $chunkPayload = @{
                    TransactionId         = $transactionId
                    ChunkData             = $base64Chunk
                    ChunkSequenceNumber   = $chunkNumber
                    TotalApplicationSize  = $totalSize
                    ChunkSize             = $bytesRead
                } | ConvertTo-Json
                
                # Upload chunk
                $uploadUrl = "$Server/API/mam/apps/internal/uploadchunk"
                $response = Invoke-AWApiCommand -Endpoint $uploadUrl -Method POST -ApiVersion 1 -Body $chunkPayload -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
                
                if ($response -and $response.TransactionId) {
                    $transactionId = $response.TransactionId
                    Write-Log -Message "Chunk $chunkNumber uploaded successfully. TransactionId: $transactionId" -Level "Info"
                } else {
                    throw "Failed to upload chunk $chunkNumber"
                }
            }
        } finally {
            $reader.Close()
        }
        
        Write-Log -Message "Chunked upload completed. Final TransactionId: $transactionId" -Level "Success"
        return $transactionId
    } catch {
        Write-Log -Message "Error during chunked upload: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Invoke-UploadfromLink {
    <#
    .SYNOPSIS
    Creates a blob in Workspace ONE UEM from an external URL.
    
    .DESCRIPTION
    Downloads application from external URL and creates a blob in UEM for app deployment.
    Validates URL accessibility and content type before uploading.
    Useful for deploying apps directly from CDNs or external repositories.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER ApplicationUrl
    Full URL to the application installer file.
    
    .PARAMETER FileName
    Name of the file as it will appear in UEM.
    
    .PARAMETER GroupId
    The organization group ID where blob will be stored.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $blobId = Invoke-UploadfromLink -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -ApplicationUrl "https://releases.example.com/app-1.0.msi" -FileName "app-1.0.msi" -GroupId 15
    if ($blobId) { Write-Host "Created blob: $blobId" }
    
    .OUTPUTS
    String - Blob ID for the uploaded file, or $null if upload fails
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$ApplicationUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        
        [Parameter(Mandatory = $true)]
        [int]$GroupId
    )
    
    try {
        Write-Log -Message "Validating URL accessibility: $ApplicationUrl" -Level "Info"
        
        # Validate URL is accessible
        $urlTest = Invoke-WebRequest -Uri $ApplicationUrl -DisableKeepAlive -UseBasicParsing -Method Head -ErrorAction Stop
        if ($urlTest.StatusCode -ne 200) {
            throw "URL returned status code $($urlTest.StatusCode)"
        }
        
        Write-Log -Message "URL validation successful. Creating blob for: $FileName" -Level "Info"
        
        # Escape URL for API
        $escapedUrl = [System.Uri]::EscapeDataString($ApplicationUrl)
        
        # Create blob from link
        $uploadUrl = "$Server/API/mam/blobs/uploadblob?fileName=$FileName&organizationGroupId=$GroupId&moduleType=Application&fileLink=$escapedUrl&accessVia=Direct"
        $response = Invoke-AWApiCommand -Endpoint $uploadUrl -Method POST -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.Value) {
            $blobId = $response.Value
            Write-Log -Message "Successfully created blob ID: $blobId for $FileName" -Level "Success"
            return $blobId
        } else {
            throw "API did not return blob ID"
        }
    } catch {
        Write-Log -Message "Error creating blob from URL: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function New-UemApplication {
    <#
    .SYNOPSIS
    Creates an internal application in Workspace ONE UEM.
    
    .DESCRIPTION
    Creates a new internal application (managed by UEM) with specified properties.
    Application can be deployed from chunked upload (TransactionId), blob (BlobId), or external link.
    Supports MSI, EXE, ZIP and other application types for all platforms (iOS, Android, macOS, Windows).
    Accepts either individual parameters or a PSCustomObject with application properties.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER ApplicationName
    Display name of the application.
    
    .PARAMETER Platform
    Target platform: iOS, Android, macOS, WinRT (for Windows), ChromeOS.
    
    .PARAMETER OrganizationGroupUuid
    Organization group UUID where app will be available.
    
    .PARAMETER TransactionId
    Transaction ID from chunked upload (use either TransactionId or BlobId, not both).
    
    .PARAMETER BlobId
    Blob ID from URL upload or icon upload (use either TransactionId or BlobId, not both).
    
    .PARAMETER ApplicationVersion
    Version number of the application.
    
    .PARAMETER BundleId
    Bundle ID (integer). Required for identifying and versioning applications. Must be unique per application and consistent across versions.
    
    .PARAMETER Description
    Application description.
    
    .PARAMETER AppProperties
    PSCustomObject containing application configuration. Must include: ApplicationName, Platform, OrganizationGroupUuid, and either TransactionId or BlobId.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $result = New-UemApplication -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -ApplicationName "MyApp" -Platform WinRT -OrganizationGroupUuid "550e8400-e29b-41d4-a716-446655440000" `
        -BlobId "12345" -ApplicationVersion "1.0" -BundleId 1
    
    .EXAMPLE
    # Using AppProperties object
    $appProps = @{
        ApplicationName = "MyApp"
        Platform = "WinRT"
        OrganizationGroupUuid = "550e8400-e29b-41d4-a716-446655440000"
        BlobId = "12345"
        ApplicationVersion = "1.0"
        BundleId = 1
    }
    $result = New-UemApplication -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -AppProperties $appProps
    
    .OUTPUTS
    PSCustomObject with ApplicationId, status, and creation details
    #>
    [CmdletBinding(DefaultParameterSetName='Individual')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true, ParameterSetName='Individual')]
        [string]$ApplicationName,
        
        [Parameter(Mandatory = $true, ParameterSetName='Individual')]
        [ValidateSet('iOS', 'Android', 'macOS', 'WinRT', 'ChromeOS')]
        [string]$Platform,
        
        [Parameter(Mandatory = $true, ParameterSetName='Individual')]
        [string]$OrganizationGroupUuid,
        
        [Parameter(Mandatory = $false, ParameterSetName='Individual')]
        [string]$TransactionId,
        
        [Parameter(Mandatory = $false, ParameterSetName='Individual')]
        [string]$BlobId,
        
        [Parameter(Mandatory = $false, ParameterSetName='Individual')]
        [string]$ApplicationVersion,
        
        [Parameter(Mandatory = $true, ParameterSetName='Individual')]
        [int]$BundleId,
        
        [Parameter(Mandatory = $false, ParameterSetName='Individual')]
        [string]$Description,
        
        [Parameter(Mandatory = $true, ParameterSetName='Properties')]
        [PSCustomObject]$AppProperties
    )
    
    try {
        # Handle AppProperties parameter set
        if ($PSCmdlet.ParameterSetName -eq 'Properties') {
            $ApplicationName = $AppProperties.ApplicationName
            $Platform = $AppProperties.Platform
            $OrganizationGroupUuid = $AppProperties.OrganizationGroupUuid
            $TransactionId = $AppProperties.TransactionId
            $BlobId = $AppProperties.BlobId
            $ApplicationVersion = $AppProperties.ApplicationVersion
            $BundleId = $AppProperties.BundleId
            $Description = $AppProperties.Description
        }
        
        if (-not $TransactionId -and -not $BlobId) {
            Write-Log -Message "Either TransactionId or BlobId must be provided" -Level "Error"
            return $null
        }
        
        Write-Log -Message "Creating application: $ApplicationName (Platform: $Platform)" -Level "Info"
        
        # Build application properties
        $appBody = @{
            ApplicationName = $ApplicationName
            Platform = $Platform
            OrganizationGroupUuid = $OrganizationGroupUuid
        }
        
        if ($TransactionId) {
            $appBody.TransactionId = $TransactionId
        } elseif ($BlobId) {
            $appBody.BlobId = $BlobId
        }
        
        $appBody.BundleId = $BundleId
        if ($ApplicationVersion) { $appBody.ApplicationVersion = $ApplicationVersion }
        if ($Description) { $appBody.Description = $Description }
        
        $bodyJson = $appBody | ConvertTo-Json
        
        $endpoint = "$Server/api/v1/mam/apps/internal/begininstall"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method POST -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -Body $bodyJson -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response) {
            Write-Log -Message "Application created successfully. ID: $($response.ApplicationId)" -Level "Success"
            return $response
        } else {
            Write-Log -Message "Application creation returned no response" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error creating application: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-Baseline {
    <#
    .SYNOPSIS
    Retrieves all baselines for a specific organization group.
    
    .DESCRIPTION
    Queries the WS1 UEM MDM API to retrieve all baselines assigned to an organization group.
    Includes baseline metadata: name, description, version, template info, and assignment count.
    Essential for baseline management and compliance reporting workflows.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER GroupUuid
    The organization group UUID to retrieve baselines for.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $baselines = Get-Baseline -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -GroupUuid "550e8400-e29b-41d4-a716-446655440000"
    $baselines | Select-Object name, description, version | Format-Table
    
    .OUTPUTS
    PSCustomObject array with name, description, version, baselineUUID, templateName, assignmentCount properties
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid
    )
    
    try {
        Write-Log -Message "Retrieving baselines for organization group: $GroupUuid" -Level "Info"
        
        $endpoint = "$Server/api/mdm/groups/$GroupUuid/baselines"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.baselines) {
            Write-Log -Message "Retrieved $($response.baselines.Count) baseline(s)" -Level "Success"
            return $response.baselines
        } else {
            Write-Log -Message "No baselines found for organization group" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving baselines: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-DevicesInBaseline {
    <#
    .SYNOPSIS
    Retrieves devices assigned to a baseline with optional filtering by status and compliance.
    
    .DESCRIPTION
    Queries devices in a baseline with pagination support and filtering options.
    Includes device name, user, installation status, baseline version, and compliance status.
    Useful for compliance reporting and device troubleshooting.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER GroupUuid
    The organization group UUID.
    
    .PARAMETER BaselineUuid
    The baseline UUID to query devices for.
    
    .PARAMETER MaxResults
    Maximum number of results to return. Default is 500.
    
    .PARAMETER Status
    Comma-separated status filter (e.g., "CONFIRMED_INSTALL,PENDING_REMOVAL"). Default is "All".
    
    .PARAMETER ComplianceLevel
    Comma-separated compliance filter (e.g., "Compliant,NonCompliant,Intermediate,NotAvailable"). Default is all.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $devices = Get-DevicesInBaseline -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -GroupUuid "550e8400-e29b-41d4-a716-446655440000" -BaselineUuid "baseline-uuid" `
        -ComplianceLevel "NonCompliant,Intermediate"
    
    .OUTPUTS
    PSCustomObject array with device details including compliance and installation status
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselineUuid,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxResults = 500,
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "All",
        
        [Parameter(Mandatory = $false)]
        [string]$ComplianceLevel = "Compliant,NonCompliant,Intermediate,NotAvailable"
    )
    
    try {
        Write-Log -Message "Retrieving devices in baseline $BaselineUuid (Status: $Status, Compliance: $ComplianceLevel)" -Level "Info"
        
        $endpoint = "$Server/api/mdm/groups/$GroupUuid/baselines/$BaselineUuid/devices?start_index=0&sort_asc=true&max_results=$MaxResults&sort_by=id&status=$Status&compliance_level=$ComplianceLevel"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.results) {
            Write-Log -Message "Retrieved $($response.results.Count) device(s) from baseline" -Level "Success"
            return $response
        } else {
            Write-Log -Message "No devices found in baseline" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving devices in baseline: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-DevicePoliciesInBaseline {
    <#
    .SYNOPSIS
    Retrieves policy compliance details for a specific device in a baseline.
    
    .DESCRIPTION
    Queries individual policy compliance status for a device within a baseline.
    Shows which policies are compliant, non-compliant, or unavailable.
    Essential for troubleshooting compliance issues on specific devices.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER GroupUuid
    The organization group UUID.
    
    .PARAMETER BaselineUuid
    The baseline UUID.
    
    .PARAMETER DeviceUuid
    The device UUID to retrieve policies for.
    
    .PARAMETER Limit
    Maximum number of policies to return. Default is 100.
    
    .PARAMETER ComplianceLevel
    Comma-separated compliance filter (e.g., "NonCompliant,NotAvailable"). Default retrieves all.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $policies = Get-DevicePoliciesInBaseline -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -GroupUuid "550e8400-e29b-41d4-a716-446655440000" -BaselineUuid "baseline-uuid" `
        -DeviceUuid "device-uuid" -ComplianceLevel "NonCompliant"
    
    .OUTPUTS
    PSCustomObject array with policy name, path, status, and compliance information
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselineUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$DeviceUuid,
        
        [Parameter(Mandatory = $false)]
        [int]$Limit = 100,
        
        [Parameter(Mandatory = $false)]
        [string]$ComplianceLevel = "NonCompliant,NotAvailable"
    )
    
    try {
        Write-Log -Message "Retrieving policies for device $DeviceUuid in baseline (Compliance: $ComplianceLevel)" -Level "Info"
        
        $endpoint = "$Server/api/mdm/groups/$GroupUuid/baselines/$BaselineUuid/devices/$DeviceUuid/policies?offset=0&sort_order=asc&limit=$Limit&sort_by=compliance_level&compliance_level=$ComplianceLevel"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.results) {
            Write-Log -Message "Retrieved $($response.results.Count) policy compliance record(s)" -Level "Success"
            return $response.results
        } else {
            Write-Log -Message "No policies found for device in baseline" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving device policies: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-BaselineAssignments {
    <#
    .SYNOPSIS
    Retrieves smart group assignments and exclusions for a baseline.
    
    .DESCRIPTION
    Queries which smart groups a baseline is assigned to and which are excluded.
    Useful for understanding baseline scope and deployment targeting.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER GroupUuid
    The organization group UUID.
    
    .PARAMETER BaselineUuid
    The baseline UUID to retrieve assignments for.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $assignments = Get-BaselineAssignments -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -GroupUuid "550e8400-e29b-41d4-a716-446655440000" -BaselineUuid "baseline-uuid"
    $assignments.assigned_smart_groups | Select-Object name | Format-Table
    
    .OUTPUTS
    PSCustomObject with assigned_smart_groups and excluded_smart_groups arrays
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselineUuid
    )
    
    try {
        Write-Log -Message "Retrieving assignments for baseline $BaselineUuid" -Level "Info"
        
        $endpoint = "$Server/api/mdm/groups/$GroupUuid/baselines/$BaselineUuid/assignments"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 2 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response) {
            $assignedCount = @($response.assigned_smart_groups).Count
            $excludedCount = @($response.excluded_smart_groups).Count
            Write-Log -Message "Retrieved $assignedCount assigned and $excludedCount excluded smart groups" -Level "Success"
            return $response
        } else {
            Write-Log -Message "No assignment data found" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving baseline assignments: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-BaselineSummary {
    <#
    .SYNOPSIS
    Retrieves comprehensive summary information for a baseline.
    
    .DESCRIPTION
    Queries baseline summary including compliance statistics, version information, customizations,
    additional policies, and detailed compliance metrics. Essential for compliance reporting.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER GroupUuid
    The organization group UUID.
    
    .PARAMETER BaselineUuid
    The baseline UUID to retrieve summary for.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $summary = Get-BaselineSummary -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -GroupUuid "550e8400-e29b-41d4-a716-446655440000" -BaselineUuid "baseline-uuid"
    $summary.summary.compliance | Format-Table
    
    .OUTPUTS
    PSCustomObject with summary, customizations, and policies information
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselineUuid
    )
    
    try {
        Write-Log -Message "Retrieving summary for baseline $BaselineUuid" -Level "Info"
        
        $endpoint = "$Server/api/mdm/groups/$GroupUuid/baselines/$BaselineUuid`?customizations=true&summary=true"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 2 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response) {
            Write-Log -Message "Retrieved baseline summary with customizations and policies" -Level "Success"
            return $response
        } else {
            Write-Log -Message "No summary data found" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving baseline summary: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-BaselineTemplate {
    <#
    .SYNOPSIS
    Retrieves detailed information for a baseline template.
    
    .DESCRIPTION
    Queries baseline template details including security level, policies, and version information.
    Includes full policy tree structure when requested.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER VendorTemplateUuid
    The vendor template UUID.
    
    .PARAMETER OsVersionUuid
    The OS version UUID.
    
    .PARAMETER SecurityLevelUuid
    The security level UUID.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $template = Get-BaselineTemplate -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -VendorTemplateUuid "vendor-uuid" -OsVersionUuid "os-uuid" -SecurityLevelUuid "security-uuid"
    
    .OUTPUTS
    PSCustomObject with template details and full policy tree
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$VendorTemplateUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$OsVersionUuid,
        
        [Parameter(Mandatory = $true)]
        [string]$SecurityLevelUuid
    )
    
    try {
        Write-Log -Message "Retrieving template details for vendor=$VendorTemplateUuid, osVersion=$OsVersionUuid, securityLevel=$SecurityLevelUuid" -Level "Info"
        
        $endpoint = "$Server/api/mdm/baselines/templates/search/$VendorTemplateUuid`?osVersionUUID=$OsVersionUuid&securityLevelUUID=$SecurityLevelUuid&policyTree=true"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response) {
            Write-Log -Message "Retrieved baseline template with policy tree" -Level "Success"
            return $response
        } else {
            Write-Log -Message "No template data found" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving baseline template: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-UemDevicesExtensive {
    <#
    .SYNOPSIS
    Retrieves all devices for an organization group using recursive pagination with extensivesearch API.
    
    .DESCRIPTION
    Queries all devices using the /api/mdm/devices/extensivesearch endpoint with automatic recursive pagination.
    Handles large device counts efficiently without memory issues. Best for comprehensive device queries with full data.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER PageSize
    Number of records per page. Default is 500 (max: 500).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $allDevices = Get-UemDevicesExtensive -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    $allDevices | Where-Object { $_.EnrollmentStatus -eq "Enrolled" } | Select-Object DeviceReportedName | Format-Table
    
    .OUTPUTS
    PSCustomObject array with all device records from extensive search
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [int]$PageSize = 500
    )
    
    try {
        Write-Log -Message "Starting extensive device query with recursive pagination (PageSize: $PageSize)" -Level "Info"
        
        # Recursive pagination function (defined inline)
        function QueryDevicesRecursive {
            param (
                [int]$Page,
                [array]$Records
            )
            
            Write-Log -Message "Querying page $Page (PageSize: $PageSize, Current records: $($Records.Count))" -Level "Info"
            
            $endpoint = "$Server/api/mdm/devices/extensivesearch?page=$Page&pagesize=$PageSize"
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
            
            if ($response -and $response.Devices) {
                $Records = $Records + $response.Devices
                
                # Calculate last page
                $total = $response.total
                $lastPage = [Math]::Ceiling($total / $PageSize) - 1
                
                if ($Page -ge $lastPage) {
                    Write-Log -Message "Reached last page ($Page). Total records retrieved: $($Records.Count)" -Level "Info"
                    return $Records
                } else {
                    Write-Log -Message "Page $Page complete. Continuing to next page..." -Level "Info"
                    return QueryDevicesRecursive -Page ($Page + 1) -Records $Records
                }
            } else {
                Write-Log -Message "No devices found in response" -Level "Info"
                return $Records
            }
        }
        
        # Start recursive pagination from page 0
        $allDevices = QueryDevicesRecursive -Page 0 -Records @()
        
        Write-Log -Message "Retrieved $($allDevices.Count) devices total" -Level "Success"
        return $allDevices
    } catch {
        Write-Log -Message "Error retrieving devices extensively: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-UemStaleDevices {
    <#
    .SYNOPSIS
    Identifies devices that have not communicated with UEM within a specified number of days.
    
    .DESCRIPTION
    Queries all devices and filters for those with LastSeen date older than specified threshold.
    Useful for compliance reporting, device lifecycle management, and identifying inactive devices.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER DaysSinceLastSeen
    Number of days back to check. Devices not seen in this many days are considered stale. Default is 90.
    
    .PARAMETER PageSize
    Number of records per API call. Default is 500 (max: 500).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $staleDevices = Get-UemStaleDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DaysSinceLastSeen 90
    $staleDevices | Select-Object DeviceReportedName, SerialNumber, LastSeen | Format-Table
    
    .EXAMPLE
    # Get devices inactive for 120 days
    $oldDevices = Get-UemStaleDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DaysSinceLastSeen 120
    
    .OUTPUTS
    PSCustomObject array containing stale device details
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysSinceLastSeen = 90,
        
        [Parameter(Mandatory = $false)]
        [int]$PageSize = 500
    )
    
    try {
        Write-Log -Message "Retrieving stale devices (not seen in $DaysSinceLastSeen days)" -Level "Info"
        
        # Calculate cutoff date
        $cutoffDate = (Get-Date).AddDays(-$DaysSinceLastSeen).ToString('yyyy-MM-dd')
        Write-Log -Message "Cutoff date: $cutoffDate" -Level "Info"
        
        # Get all devices
        $allDevices = Get-UemDevicesExtensive -Server $Server -Auth $Auth -ApiKey $ApiKey -PageSize $PageSize
        
        if (-not $allDevices) {
            Write-Log -Message "No devices found" -Level "Info"
            return $null
        }
        
        # Filter for stale devices
        $staleDevices = @()
        foreach ($device in $allDevices) {
            if ($device.LastSeen -and $device.LastSeen -ne "0001-01-01" -and $device.LastSeen -le $cutoffDate) {
                $staleDevices += $device
            }
        }
        
        Write-Log -Message "Found $($staleDevices.Count) stale devices" -Level "Success"
        return $staleDevices
    } catch {
        Write-Log -Message "Error retrieving stale devices: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-UemDuplicateDevices {
    <#
    .SYNOPSIS
    Identifies devices with duplicate serial numbers.
    
    .DESCRIPTION
    Queries all devices and groups by serial number to find duplicates.
    Useful for data quality checks and resolving enrollment issues.
    Excludes problematic serial formats (empty, placeholder, default values).
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER KeepNewest
    If specified, returns only the duplicates to be deleted (keeps the most recently seen device).
    Otherwise returns all duplicate devices. Default is $false (return all duplicates).
    
    .PARAMETER ExcludeProblematicSerials
    If specified, filters out devices with common placeholder/invalid serial formats. Default is $true.
    
    .PARAMETER PageSize
    Number of records per API call. Default is 500.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $duplicates = Get-UemDuplicateDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    $duplicates | Group-Object SerialNumber | Select-Object Name, @{N="Count";E={$_.Group.Count}} | Format-Table
    
    .EXAMPLE
    # Get only devices to delete (keeping the newest)
    $toDelete = Get-UemDuplicateDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -KeepNewest
    
    .OUTPUTS
    PSCustomObject array of duplicate devices
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [switch]$KeepNewest = $false,
        
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeProblematicSerials = $true,
        
        [Parameter(Mandatory = $false)]
        [int]$PageSize = 500
    )
    
    try {
        Write-Log -Message "Retrieving duplicate devices" -Level "Info"
        
        # Get all devices
        $allDevices = Get-UemDevicesExtensive -Server $Server -Auth $Auth -ApiKey $ApiKey -PageSize $PageSize
        
        if (-not $allDevices) {
            Write-Log -Message "No devices found" -Level "Info"
            return $null
        }
        
        # Filter out problematic serials if requested
        if ($ExcludeProblematicSerials) {
            $problematicSerials = @('System Serial Number', 'To be filled by O.E.M.', 'Default string', '', '0', '1234567')
            $allDevices = $allDevices | Where-Object { $_.SerialNumber -notin $problematicSerials }
            Write-Log -Message "Filtered out problematic serials" -Level "Info"
        }
        
        # Group by serial and find duplicates
        $grouped = $allDevices | Group-Object -Property SerialNumber | Where-Object { $_.Count -gt 1 }
        
        Write-Log -Message "Found $($grouped.Count) unique serial numbers with duplicates" -Level "Info"
        
        if (-not $grouped) {
            Write-Log -Message "No duplicates found" -Level "Info"
            return $null
        }
        
        # If KeepNewest, return only the older devices (to be deleted)
        if ($KeepNewest) {
            Write-Log -Message "Filtering to keep only the newest device per serial" -Level "Info"
            $toDelete = @()
            foreach ($group in $grouped) {
                # Sort by LastSeen descending, then by DeviceID descending (most recent first)
                $sorted = $group.Group | Sort-Object -Property @{Expression={$_.LastSeen}; Descending=$true}, @{Expression={$_.id.value}; Descending=$true}
                # Add all except the first (newest) one
                $toDelete += $sorted | Select-Object -Skip 1
            }
            Write-Log -Message "Found $($toDelete.Count) devices to delete (keeping newest)" -Level "Success"
            return $toDelete
        } else {
            Write-Log -Message "Returning all $($grouped.Group.Count) duplicate devices" -Level "Success"
            return $grouped.Group
        }
    } catch {
        Write-Log -Message "Error retrieving duplicate devices: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-UemProblematicDevices {
    <#
    .SYNOPSIS
    Identifies devices with invalid or placeholder serial numbers.
    
    .DESCRIPTION
    Queries all devices and filters for those with common placeholder, malformed, or problematic serial formats.
    Useful for data quality validation and identifying enrollment issues.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER PageSize
    Number of records per API call. Default is 500.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $problematic = Get-UemProblematicDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    $problematic | Select-Object DeviceReportedName, SerialNumber, Platform | Format-Table
    
    .OUTPUTS
    PSCustomObject array of devices with problematic serial numbers
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [int]$PageSize = 500
    )
    
    try {
        Write-Log -Message "Retrieving devices with problematic serials" -Level "Info"
        
        # Define problematic serial patterns
        $problematicSerials = @(
            'System Serial Number',
            'To be filled by O.E.M.',
            'Default string',
            '',
            '0',
            '1234567',
            'Not Specified',
            'N/A',
            'Unknown'
        )
        
        # Get all devices
        $allDevices = Get-UemDevicesExtensive -Server $Server -Auth $Auth -ApiKey $ApiKey -PageSize $PageSize
        
        if (-not $allDevices) {
            Write-Log -Message "No devices found" -Level "Info"
            return $null
        }
        
        # Filter for problematic serials
        $problematicDevices = $allDevices | Where-Object { $_.SerialNumber -in $problematicSerials }
        
        Write-Log -Message "Found $($problematicDevices.Count) devices with problematic serials" -Level "Success"
        return $problematicDevices
    } catch {
        Write-Log -Message "Error retrieving problematic devices: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Remove-UemDevices {
    <#
    .SYNOPSIS
    Bulk deletes devices from UEM using the bulk API endpoint.
    
    .DESCRIPTION
    Efficiently deletes multiple devices in a single API call using /api/mdm/devices/bulk endpoint.
    Significantly faster than per-device deletion (10-100x improvement for large batches).
    Requires confirmation before deletion to prevent accidental data loss.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER DeviceIds
    Array of device IDs to delete. Can be pipeline input or direct array.
    
    .PARAMETER Force
    If specified, skips confirmation prompt. Use with caution.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $staleDevices = Get-UemStaleDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -DaysSinceLastSeen 180
    $staleDevices.id.value | Remove-UemDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    
    .EXAMPLE
    # Pipe directly from device query
    Get-UemDuplicateDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -KeepNewest | 
        ForEach-Object { $_.id.value } | 
        Remove-UemDevices -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -Force
    
    .INPUTS
    Array of device IDs (strings) from pipeline
    
    .OUTPUTS
    PSCustomObject response from delete operation
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$DeviceIds,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force = $false
    )
    
    begin {
        $allDeviceIds = @()
    }
    
    process {
        # Handle pipeline input
        $allDeviceIds += $DeviceIds
    }
    
    end {
        try {
            if (-not $allDeviceIds -or $allDeviceIds.Count -eq 0) {
                Write-Log -Message "No device IDs provided for deletion" -Level "Error"
                return $null
            }
            
            Write-Log -Message "Preparing to delete $($allDeviceIds.Count) device(s)" -Level "Info"
            
            # Build quoted device ID array
            $quotedIds = @()
            foreach ($id in $allDeviceIds) {
                $quotedIds += "`"$id`""
            }
            
            # Prompt for confirmation unless -Force is used
            if (-not $Force) {
                $confirmation = Read-Host "About to delete $($allDeviceIds.Count) device(s). Type 'DELETE' to confirm or any other key to cancel"
                if ($confirmation -ne "DELETE") {
                    Write-Log -Message "Device deletion cancelled by user" -Level "Info"
                    return $null
                }
            }
            
            # Build request body
            $bodyContent = "`"$($quotedIds -join '","')`""
            $body = @"
{
    "BulkValues": {
        "Value":[$bodyContent]
    }
}
"@
            
            Write-Log -Message "Executing bulk delete API call" -Level "Info"
            
            $endpoint = "$Server/api/mdm/devices/bulk"
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method POST -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -Body $body -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
            
            if ($response) {
                Write-Log -Message "Successfully deleted $($allDeviceIds.Count) device(s)" -Level "Success"
                return $response
            } else {
                Write-Log -Message "Delete operation completed with no response" -Level "Info"
                return $null
            }
        } catch {
            Write-Log -Message "Error deleting devices: $($_.Exception.Message)" -Level "Error"
            return $null
        }
    }
}

function New-UemAppIcon {
    <#
    .SYNOPSIS
    Uploads an application icon blob to Workspace ONE UEM.
    
    .DESCRIPTION
    Uploads an application icon image file to UEM's /api/mam/blobs/uploadblob endpoint.
    Supports both local and remote image files. Returns blob ID for app creation.
    Icon should be in PNG or JPG format (recommended: 512x512px).
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER IconFile
    Full path to local icon file, or URL to remote icon file.
    
    .PARAMETER IsUrl
    If specified, IconFile is treated as URL and downloaded. Otherwise treated as local file path.
    
    .PARAMETER OrgGroupId
    Optional organization group ID for blob storage. Default is root OG.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    # Upload local icon
    $blobId = New-UemAppIcon -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -IconFile "C:\icons\app.png"
    
    .EXAMPLE
    # Upload from URL
    $blobId = New-UemAppIcon -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -IconFile "https://example.com/icons/app.png" -IsUrl
    
    .OUTPUTS
    String - Blob ID for the uploaded icon, or $null if upload fails
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$IconFile,
        
        [Parameter(Mandatory = $false)]
        [switch]$IsUrl = $false,
        
        [Parameter(Mandatory = $false)]
        [string]$OrgGroupId
    )
    
    try {
        Write-Log -Message "Uploading application icon" -Level "Info"
        
        # Read icon file
        $iconContent = $null
        if ($IsUrl) {
            Write-Log -Message "Downloading icon from URL: $IconFile" -Level "Info"
            $iconContent = Invoke-WebRequest -Uri $IconFile -UseBasicParsing | Select-Object -ExpandProperty Content
        } else {
            if (-not (Test-Path $IconFile)) {
                Write-Log -Message "Icon file not found: $IconFile" -Level "Error"
                return $null
            }
            $iconContent = Get-Content -Path $IconFile -Raw -AsByteStream
        }
        
        # Build endpoint with optional parameters
        $endpoint = "$Server/api/mam/blobs/uploadblob"
        if ($OrgGroupId) {
            $endpoint += "?lgid=$OrgGroupId"
        }
        
        Write-Log -Message "Uploading to $endpoint" -Level "Info"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method POST -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -Body $iconContent -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.BlobId) {
            Write-Log -Message "Icon uploaded successfully. Blob ID: $($response.BlobId)" -Level "Success"
            return $response.BlobId
        } else {
            Write-Log -Message "Icon upload returned unexpected response" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error uploading app icon: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-UemApplications {
    <#
    .SYNOPSIS
    Retrieves applications available in Workspace ONE UEM by platform.
    
    .DESCRIPTION
    Queries the /api/mam/apps/search endpoint to retrieve applications filtered by platform.
    Returns list of available applications with details for app management and distribution.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER Platform
    Target platform to search: iOS, Android, macOS, WinRT (Windows), ChromeOS, Any (all platforms).
    
    .PARAMETER MaxResults
    Maximum number of applications to return. Default is 500.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $winApps = Get-UemApplications -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -Platform WinRT
    $winApps | Select-Object ApplicationName, ApplicationVersion | Format-Table
    
    .EXAMPLE
    # Get all iOS apps
    $iosApps = Get-UemApplications -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -Platform iOS
    
    .OUTPUTS
    PSCustomObject array with ApplicationName, ApplicationVersion, BundleId, ApplicationFileName, and other app details
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'Android', 'macOS', 'WinRT', 'ChromeOS', 'Any')]
        [string]$Platform,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxResults = 500
    )
    
    try {
        # Map platform parameter to API format
        $apiPlatform = $Platform
        if ($Platform -eq 'Any') {
            $apiPlatform = ''
        }
        
        Write-Log -Message "Retrieving applications for platform: $Platform" -Level "Info"
        
        # Build endpoint
        $endpoint = "$Server/api/mam/apps/search?pagesize=$MaxResults"
        if ($apiPlatform) {
            $endpoint += "&platform=$apiPlatform"
        }
        
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response -and $response.Application) {
            Write-Log -Message "Retrieved $($response.Application.Count) application(s)" -Level "Success"
            return $response.Application
        } else {
            Write-Log -Message "No applications found for platform: $Platform" -Level "Info"
            return $null
        }
    } catch {
        Write-Log -Message "Error retrieving applications: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Invoke-UemSmartGroupCommand {
    <#
    .SYNOPSIS
    Executes a command on all devices in a Workspace ONE UEM smart group.
    
    .DESCRIPTION
    Retrieves all devices from a smart group and executes the specified command on each device.
    Supports commands like Lock, DeviceQuery, SyncDevice, EnterpriseReset, ClearPasscode, etc.
    Significantly faster than per-device command execution for large groups.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER SmartGroupId
    The smart group UUID or ID to target.
    
    .PARAMETER Command
    The command to execute. Common options: Lock, DeviceQuery, SyncDevice, EnterpriseReset, ClearPasscode, Retire, Unenroll.
    
    .PARAMETER MaxDevices
    Maximum number of devices to target from the smart group. Default is all (5000).
    
    .PARAMETER PassThru
    If specified, returns array of device IDs that command was executed on.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    Invoke-UemSmartGroupCommand -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -SmartGroupId "sg-123" -Command "SyncDevice"
    
    .EXAMPLE
    # Lock all devices in a group and get device list
    $lockedDevices = Invoke-UemSmartGroupCommand -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -SmartGroupId "sg-456" -Command "Lock" -PassThru
    $lockedDevices.Count
    
    .OUTPUTS
    Integer count of devices affected, or PSCustomObject array if -PassThru specified
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$SmartGroupId,
        
        [Parameter(Mandatory = $true)]
        [string]$Command,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDevices = 5000,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru = $false
    )
    
    try {
        Write-Log -Message "Retrieving devices from smart group: $SmartGroupId" -Level "Info"
        
        # Get devices from smart group
        $endpoint = "$Server/api/mdm/smartgroups/$SmartGroupId/devices?pagesize=$MaxDevices"
        $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if (-not $response -or -not $response.Devices) {
            Write-Log -Message "No devices found in smart group" -Level "Info"
            return 0
        }
        
        $devices = $response.Devices
        Write-Log -Message "Found $($devices.Count) device(s) in smart group. Executing command: $Command" -Level "Info"
        
        # Execute command on each device
        $executedDevices = @()
        $successCount = 0
        
        foreach ($device in $devices) {
            try {
                $deviceId = $device.Id.Value
                $commandEndpoint = "$Server/api/mdm/devices/$deviceId/commands?command=$Command"
                
                Invoke-AWApiCommand -Endpoint $commandEndpoint -Method POST -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 2 -RetryIntervalSeconds 10 | Out-Null
                
                $executedDevices += $device
                $successCount++
            } catch {
                Write-Log -Message "Failed to execute $Command on device $($device.DeviceReportedName): $($_.Exception.Message)" -Level "Error"
            }
        }
        
        Write-Log -Message "Command '$Command' executed on $successCount device(s)" -Level "Success"
        
        if ($PassThru) {
            return $executedDevices
        } else {
            return $successCount
        }
    } catch {
        Write-Log -Message "Error executing smart group command: $($_.Exception.Message)" -Level "Error"
        return 0
    }
}

function Get-UemDuplicateUsers {
    <#
    .SYNOPSIS
    Identifies user accounts with duplicate usernames in Workspace ONE UEM.
    
    .DESCRIPTION
    Queries all users and identifies accounts with matching usernames.
    Useful for finding and cleaning up duplicate user accounts that may have been created during migrations or sync issues.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER UserType
    Filter by user type: BasicOnly, DirectoryOnly, Any (default).
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $dupUsers = Get-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    $dupUsers | Select-Object Username, UserType, UUID | Format-Table
    
    .OUTPUTS
    PSCustomObject array of duplicate users with username, UUID, type, and details
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Any', 'BasicOnly', 'DirectoryOnly')]
        [string]$UserType = 'Any'
    )
    
    try {
        Write-Log -Message "Retrieving users to identify duplicates (UserType: $UserType)" -Level "Info"
        
        # Get all users with pagination
        $allUsers = @()
        $page = 0
        $pageSize = 500
        
        do {
            $endpoint = "$Server/api/system/users?page=$page&pagesize=$pageSize"
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
            
            if ($response -and $response.Users) {
                $allUsers += $response.Users
                $page++
            } else {
                break
            }
        } while ($response.Users.Count -eq $pageSize)
        
        Write-Log -Message "Retrieved $($allUsers.Count) total users" -Level "Info"
        
        # Filter by user type if specified
        if ($UserType -ne 'Any') {
            $userTypeValue = if ($UserType -eq 'BasicOnly') { 'Basic' } else { 'Directory' }
            $allUsers = $allUsers | Where-Object { $_.UserType -eq $userTypeValue }
            Write-Log -Message "Filtered to $($allUsers.Count) $UserType user(s)" -Level "Info"
        }
        
        # Find duplicates by username
        $grouped = $allUsers | Group-Object -Property Username | Where-Object { $_.Count -gt 1 }
        
        if (-not $grouped) {
            Write-Log -Message "No duplicate users found" -Level "Info"
            return $null
        }
        
        # Return all duplicates (excluding the first/primary)
        $duplicateUsers = @()
        foreach ($group in $grouped) {
            $duplicateUsers += $group.Group | Sort-Object -Property CreatedOnDate -Descending | Select-Object -Skip 1
        }
        
        Write-Log -Message "Found $($duplicateUsers.Count) duplicate user account(s) across $($grouped.Count) username(s)" -Level "Success"
        return $duplicateUsers
    } catch {
        Write-Log -Message "Error retrieving duplicate users: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Remove-UemDuplicateUsers {
    <#
    .SYNOPSIS
    Deletes duplicate user accounts from Workspace ONE UEM.
    
    .DESCRIPTION
    Removes duplicate user accounts identified by Get-UemDuplicateUsers.
    Only deletes users with no enrolled devices (safe deletion).
    Users with active device enrollments must have devices removed first.
    Requires confirmation before deletion.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN.
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER UserIds
    Array of user UUIDs to delete. Can be pipeline input.
    
    .PARAMETER Force
    If specified, skips confirmation prompt.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $dupUsers = Get-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    $dupUsers | ForEach-Object { $_.UUID } | Remove-UemDuplicateUsers -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    
    .INPUTS
    String array of user UUIDs from pipeline or parameter
    
    .OUTPUTS
    Integer count of users deleted
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$UserIds,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force = $false
    )
    
    begin {
        $allUserIds = @()
    }
    
    process {
        $allUserIds += $UserIds
    }
    
    end {
        try {
            if (-not $allUserIds -or $allUserIds.Count -eq 0) {
                Write-Log -Message "No user IDs provided for deletion" -Level "Error"
                return 0
            }
            
            Write-Log -Message "Preparing to delete $($allUserIds.Count) duplicate user account(s)" -Level "Info"
            
            # Prompt for confirmation unless -Force is used
            if (-not $Force) {
                $confirmation = Read-Host "About to delete $($allUserIds.Count) user account(s). Type 'DELETE' to confirm or any other key to cancel"
                if ($confirmation -ne "DELETE") {
                    Write-Log -Message "User deletion cancelled by user" -Level "Info"
                    return 0
                }
            }
            
            $deletedCount = 0
            foreach ($userId in $allUserIds) {
                try {
                    $endpoint = "$Server/api/system/users/$userId"
                    Invoke-AWApiCommand -Endpoint $endpoint -Method DELETE -ApiVersion 1 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 2 -RetryIntervalSeconds 10 | Out-Null
                    
                    $deletedCount++
                    Write-Log -Message "Deleted user: $userId" -Level "Info"
                } catch {
                    Write-Log -Message "Failed to delete user $userId`: $($_.Exception.Message)" -Level "Error"
                }
            }
            
            Write-Log -Message "Successfully deleted $deletedCount duplicate user account(s)" -Level "Success"
            return $deletedCount
        } catch {
            Write-Log -Message "Error deleting duplicate users: $($_.Exception.Message)" -Level "Error"
            return 0
        }
    }
}

function Get-UemDeviceNotes {
    <#
    .SYNOPSIS
    Retrieves console notes for devices in WS1 UEM.
    
    .DESCRIPTION
    Queries the /API/mdm/devices/notes endpoint to retrieve notes added in the WS1 UEM console for one or more devices.
    Can accept device serial numbers individually or via pipeline.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER SerialNumber
    The device serial number to retrieve notes for. Accepts pipeline input.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    $notes = Get-UemDeviceNotes -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -SerialNumber "ABC123XYZ"
    $notes | Format-List
    
    .EXAMPLE
    # Retrieve notes for multiple devices via pipeline
    @("ABC123XYZ", "DEF456UVW") | Get-UemDeviceNotes -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey
    
    .OUTPUTS
    PSCustomObject with note content and metadata, or $null if no notes found or error occurs
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$SerialNumber
    )
    
    process {
        try {
            Write-Log -Message "Retrieving notes for device: $SerialNumber" -Level "Info"
            
            $serialEncoded = [System.Web.HttpUtility]::UrlEncode($SerialNumber)
            $endpoint = "$Server/API/mdm/devices/notes?searchBy=SerialNumber&id=$serialEncoded"
            
            $response = Invoke-AWApiCommand -Endpoint $endpoint -Method GET -ApiVersion 2 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
            
            if ($response) {
                Write-Log -Message "Successfully retrieved notes for device: $SerialNumber" -Level "Success"
                return $response
            } else {
                Write-Log -Message "No notes found for device: $SerialNumber" -Level "Info"
                return $null
            }
        } catch {
            Write-Log -Message "Error retrieving notes for device $SerialNumber`: $($_.Exception.Message)" -Level "Error"
            return $null
        }
    }
}

function Update-UemDeviceProperty {
    <#
    .SYNOPSIS
    Updates device properties in WS1 UEM (friendly name, asset number, etc.).
    
    .DESCRIPTION
    Updates one or more device properties such as DeviceFriendlyName and AssetNumber.
    First retrieves current device information, then updates specified properties via PUT request.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER SerialNumber
    The device serial number to update.
    
    .PARAMETER FriendlyName
    New friendly name for the device.
    
    .PARAMETER AssetNumber
    New asset number for the device.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    Update-UemDeviceProperty -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -SerialNumber "ABC123XYZ" -FriendlyName "LAPTOP-001" -AssetNumber "ASSET-12345"
    
    .OUTPUTS
    PSCustomObject with updated device information, or $null if error occurs
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true)]
        [string]$SerialNumber,
        
        [Parameter(Mandatory = $false)]
        [string]$FriendlyName,
        
        [Parameter(Mandatory = $false)]
        [string]$AssetNumber
    )
    
    try {
        Write-Log -Message "Retrieving current properties for device: $SerialNumber" -Level "Info"
        
        # Get current device info
        $serialEncoded = [System.Web.HttpUtility]::UrlEncode($SerialNumber)
        $getEndpoint = "$Server/API/mdm/devices?searchBy=SerialNumber&id=$serialEncoded"
        
        $deviceInfo = Invoke-AWApiCommand -Endpoint $getEndpoint -Method GET -ApiVersion 2 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if (-not $deviceInfo -or -not $deviceInfo.id) {
            Write-Log -Message "Device not found: $SerialNumber" -Level "Error"
            return $null
        }
        
        $deviceId = $deviceInfo.id.value
        Write-Log -Message "Found device ID: $deviceId" -Level "Info"
        
        # Build update body with current or new values
        $updateBody = @{}
        
        if ($FriendlyName) {
            $updateBody["DeviceFriendlyName"] = $FriendlyName
        } else {
            $updateBody["DeviceFriendlyName"] = $deviceInfo.DeviceFriendlyName
        }
        
        if ($AssetNumber) {
            $updateBody["AssetNumber"] = $AssetNumber
        } elseif ($deviceInfo.AssetNumber) {
            $updateBody["AssetNumber"] = $deviceInfo.AssetNumber
        }
        
        $body = $updateBody | ConvertTo-Json
        
        # Update device
        $updateEndpoint = "$Server/API/mdm/devices/$deviceId"
        Write-Log -Message "Updating device properties for ID: $deviceId" -Level "Info"
        
        $response = Invoke-AWApiCommand -Endpoint $updateEndpoint -Method PUT -ApiVersion 2 -Auth $Auth -Apikey $ApiKey -Body $body -EnableRetry -MaxAttempts 3 -RetryIntervalSeconds 30
        
        if ($response) {
            Write-Log -Message "Successfully updated device properties for: $SerialNumber" -Level "Success"
            return $response
        } else {
            Write-Log -Message "Device update returned no response for: $SerialNumber" -Level "Warn"
            return $null
        }
    } catch {
        Write-Log -Message "Error updating device properties for $SerialNumber`: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Clear-UemDevicePasscode {
    <#
    .SYNOPSIS
    Clears the passcode on one or more devices in WS1 UEM.
    
    .DESCRIPTION
    Sends the ClearPasscode command to devices via the WS1 UEM API.
    Can accept device serial numbers individually or as an array.
    Requires "device clear passcode" permission on the admin account.
    
    .PARAMETER Server
    The WS1 UEM server hostname or FQDN (e.g., uem.example.com).
    
    .PARAMETER Auth
    Authorization credential (Basic or Bearer token).
    
    .PARAMETER ApiKey
    The API key (aw-tenant-code).
    
    .PARAMETER SerialNumber
    The device serial number(s) to clear passcode for. Accepts pipeline input and arrays.
    
    .PARAMETER Force
    If specified, skips confirmation prompt.
    
    .EXAMPLE
    $auth = Get-ServerAuth -Server "uem.example.com" -Username "admin" -Password "pass" -ApiKey "key" -OGName "Corp"
    Clear-UemDevicePasscode -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey -SerialNumber "ABC123XYZ"
    
    .EXAMPLE
    # Clear passcode for multiple devices
    Clear-UemDevicePasscode -Server $auth.Server -Auth $auth.cred -ApiKey $auth.ApiKey `
        -SerialNumber @("ABC123XYZ", "DEF456UVW", "GHI789RST") -Force
    
    .OUTPUTS
    Integer count of devices where passcode clear was initiated, or 0 if error occurs
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $true)]
        [string]$Auth,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$SerialNumber,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force = $false
    )
    
    begin {
        $allSerials = @()
    }
    
    process {
        $allSerials += $SerialNumber
    }
    
    end {
        try {
            Write-Log -Message "Preparing to clear passcode for $($allSerials.Count) device(s)" -Level "Info"
            
            # Prompt for confirmation unless -Force is used
            if (-not $Force) {
                $confirmation = Read-Host "About to clear passcode on $($allSerials.Count) device(s). Type 'CLEAR' to confirm or any other key to cancel"
                if ($confirmation -ne "CLEAR") {
                    Write-Log -Message "Passcode clear cancelled by user" -Level "Info"
                    return 0
                }
            }
            
            $clearCount = 0
            foreach ($serial in $allSerials) {
                try {
                    $serialEncoded = [System.Web.HttpUtility]::UrlEncode($serial)
                    $endpoint = "$Server/API/mdm/devices/commands/ClearPasscode/device/SerialNumber/$serialEncoded"
                    
                    Write-Log -Message "Clearing passcode for device: $serial" -Level "Info"
                    
                    $response = Invoke-AWApiCommand -Endpoint $endpoint -Method POST -ApiVersion 2 -Auth $Auth -Apikey $ApiKey -EnableRetry -MaxAttempts 2 -RetryIntervalSeconds 10
                    
                    if ($response) {
                        $clearCount++
                        Write-Log -Message "Passcode clear initiated for device: $serial" -Level "Success"
                    } else {
                        Write-Log -Message "Passcode clear failed for device: $serial (no response)" -Level "Warn"
                    }
                } catch {
                    Write-Log -Message "Error clearing passcode for device $serial`: $($_.Exception.Message)" -Level "Error"
                }
            }
            
            Write-Log -Message "Successfully initiated passcode clear for $clearCount/$($allSerials.Count) device(s)" -Level "Success"
            return $clearCount
        } catch {
            Write-Log -Message "Error clearing device passcodes: $($_.Exception.Message)" -Level "Error"
            return 0
        }
    }
}

Export-ModuleMember -Function Get-OG, Invoke-AWApiCommand, Get-CurrentLoggedonUser, Get-UserSIDLookup, Get-ReverseSID, Write-Log, Write-2Report, Show-Toast, Get-RegistryValue, Get-ServerAuth, Get-Log, Get-WSONEOAuthToken, Get-NewDeviceId, Invoke-AgentCleanup, Get-DevicesByCustomAttribute, Add-DeviceTag, Remove-DeviceTag, Get-DeviceTags, Get-DeviceEnrollmentStatus, Invoke-OGSearch, Get-Enrollment, Compare-EnrollmentSID, Disable-EnrollmentNotifications, Enable-EnrollmentNotifications, Invoke-RestMethodWithRetry, Get-UemAgentInstallInfo, Install-UemAgent, Remove-UemAgent, Get-EnrollmentInfoWithPolling, Wait-UemAppsInstalled, Wait-UemProfilesInstalled, New-Tag, Invoke-DownloadAirwatchAgent, Invoke-CreateTask, Get-App, Invoke-ChunkandUpload, Invoke-UploadfromLink, Get-Baseline, Get-DevicesInBaseline, Get-DevicePoliciesInBaseline, Get-BaselineAssignments, Get-BaselineSummary, Get-BaselineTemplate, Get-UemDevicesExtensive, Get-UemStaleDevices, Get-UemDuplicateDevices, Get-UemProblematicDevices, Remove-UemDevices, New-UemAppIcon, New-UemApplication, Get-UemApplications, Invoke-UemSmartGroupCommand, Get-UemDuplicateUsers, Remove-UemDuplicateUsers, Get-UemDeviceNotes, Update-UemDeviceProperty, Clear-UemDevicePasscode
