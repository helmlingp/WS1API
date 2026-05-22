@{
    RootModule        = 'WS1API.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd7f61bba-8135-45f5-920d-6ca40f0963d6'
    Author            = 'Phil Helmling'
    CompanyName       = ''
    Copyright         = '(c) 2020-2026 Phil Helmling. All rights reserved.'
    Description       = 'PowerShell module for interacting with Omnissa Workspace ONE UEM RestAPI with OAuth support and multi-data center support'
    PowerShellVersion = '5.0'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Add-DeviceTag',
        'Clear-UemDevicePasscode',
        'Compare-EnrollmentSID',
        'Disable-EnrollmentNotifications',
        'Enable-EnrollmentNotifications',
        'Get-App',
        'Get-Baseline',
        'Get-BaselineAssignments',
        'Get-BaselineSummary',
        'Get-BaselineTemplate',
        'Get-CurrentLoggedonUser',
        'Get-DeviceEnrollmentStatus',
        'Get-DevicePoliciesInBaseline',
        'Get-DevicesByCustomAttribute',
        'Get-DevicesInBaseline',
        'Get-DeviceTags',
        'Get-Enrollment',
        'Get-EnrollmentInfoWithPolling',
        'Get-Log',
        'Get-NewDeviceId',
        'Get-OG',
        'Get-RegistryValue',
        'Get-ReverseSID',
        'Get-ServerAuth',
        'Get-UemAgentInstallInfo',
        'Get-UemApplications',
        'Get-UemDeviceNotes',
        'Get-UemDevicesExtensive',
        'Get-UemDuplicateDevices',
        'Get-UemDuplicateUsers',
        'Get-UemProblematicDevices',
        'Get-UemStaleDevices',
        'Get-UserSIDLookup',
        'Get-WSONEOAuthToken',
        'Install-UemAgent',
        'Invoke-AgentCleanup',
        'Invoke-AWApiCommand',
        'Invoke-ChunkandUpload',
        'Invoke-CreateTask',
        'Invoke-DownloadAirwatchAgent',
        'Invoke-OGSearch',
        'Invoke-RestMethodWithRetry',
        'Invoke-UemSmartGroupCommand',
        'Invoke-UploadfromLink',
        'New-Tag',
        'New-UemAppIcon',
        'New-UemApplication',
        'Remove-DeviceTag',
        'Remove-UemAgent',
        'Remove-UemDevices',
        'Remove-UemDuplicateUsers',
        'Show-Toast',
        'Update-UemDeviceProperty',
        'Wait-UemAppsInstalled',
        'Wait-UemProfilesInstalled',
        'Write-2Report',
        'Write-Log'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags       = @('Workspace-ONE', 'WS1', 'RestAPI', 'API', 'OAuth', 'Authentication', 'UEM', 'Enterprise-Mobility', 'Management', 'Device-Management', 'Application-Management', 'Baseline-Management', 'Agent-Management', 'User-Management', 'Enrollment', 'Utilities', 'MDM', 'Mobile Device-Management')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/helmlingp/WS1API/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/helmlingp/WS1API'

            # A URL to an icon representing this module.
            # IconUri    = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
1.0.0 Release Notes:

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
'@

            # Prerelease string of this module
            # Prerelease  = 'beta1'

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI       = 'https://github.com/helmlingp/WS1API'

    # Minimum version of the Common Language Runtime (CLR) required by this module. This prerequisite is ignored on PowerShell Core.
    # CLRVersion        = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is only enforced on Windows PowerShell.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # PowerShellVersion = ''

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules   = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess  = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess    = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess  = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules     = @()
}
