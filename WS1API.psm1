<#
 .Synopsis
    A collection of useful functions for interacting with VMware Workspace ONE UEM RestAPI
 .NOTES
    Created:   	    December, 2020
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       WS1API.psm1
    GitHub:         https://github.com/helmlingp/WS1API 
 .Description
    The following functions are currently provided:
    - Get-OG, (requires Write-Log2, Invoke-AWApiCommand)
    - Invoke-AWApiCommand, (requires Write-Log2)
    - Get-CurrentLoggedonUser, (requires GetWin32User.cs in the smae folder)
    - Get-UserSIDLookup, (requires Get-CurrentLoggedonUser)
    - Get-ReverseSID, 
    - Write-Log, 
    - Write-Log2, (requires Write-Log)
    - Write-2Report.

 .Example
   # Get OG from provided name
   $OGSearch = Get-OG -Server $script:Server -Cred $script:cred -ApiKey $script:ApiKey -OrgGroup $script:OrgGroup -Debug $Debug
   $script:groupuuid = $OGSearch.OrganizationGroups[0].Uuid;

 .Example
   # Main function machine RestAPI call
   $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

 .Example
   # Get Currently Logged on User in active console session. Returns username
   $getuser = Get-CurrentLoggedonUser

 .Example
   # Return user SID for specified user
   $getuserSID = Get-UserSIDLookup -UsernameLookup user1
   
   # Return user SID for current user
   $getuserSID = Get-UserSIDLookup
   or
   $getuserSID = Get-UserSIDLookup -UsernameLookup (Current_user)

 .Example
   # Return user/group name from SID
   $getuserfromSID = Get-ReverseSID -SID S-1-12-.....

   # Return username from SID (default)
   $getuserfromSID = Get-ReverseSID -SID S-1-12-..... -ignoreGroups $true
   
 .Example
   # Writes messages in easily readable log file format to screen and log file. 
   
   For example:
   $Write-Log -Message "WebRequest.StatusCode: 200" -Path "path_to_log_file"
   writes the following into the "path_to_log_file"
        2020-12-23 11:23:33 INFO: WebRequest.StatusCode: 200
   and displays the following to the screen in Yellow
        VERBOSE: WebRequest.StatusCode: 200

   $Write-Log -Message "WebRequest.StatusCode: 200" -Path "path_to_log_file" -Level "Info" -NoClobber
   
   -Message "text to write"
   -Path "path_to_log_file". Will create file if it doesn't exist
   -NoClobber will not overwrite existing file and error to screen if it exists
   -Level options include "Error","Warn","Info"
        Error -writes MESSAGE to error stream, Write-Error: MESSAGE to screen, and DATETIME: WARNING: MESSAGE to log file
        Warn -writes WARNING: message to screen and DATETIME: WARNING: MESSAGE to log file
        Info -writes VERBOSE: message to screen and DATETIME: INFO: MESSAGE to log file

 .Example
   # Wrapper function on top of Write-Log. Adding -UseLocal changes output to screen and log file.
   For example:
   $Write-Log2 -Message "WebRequest.StatusCode: 200" -Path "path_to_log_file" -Level "Warn" -UseLocal
   writes the following into the "path_to_log_file"
        2020-12-23 11:23:33     (WARN)     WebRequest.StatusCode: 200
   and displays the following to the screen in Yellow
        MethodName::WARN    WebRequest.StatusCode: 200

        Note: this function is not complete

   -Level options include "Success", "Error", "Warn", "Info". Each Level writes to screen in different colour:
        "Success" = Green
        "Error" = Red
        "Warn" = Yellow
        "Info" = White
   -UseLocal should not be used at this stage. If not used, function calls Write-Log function.

 .Example
   # Function to write in more of a Report format. Writes to log / report file as well as screen
   For example:
   Write-2Report -Path "path_to_log_file" -Message "WS1 Baseline Report" -Level "Title"
   writes the following to "path_to_log_file" 
   ************************************************************************

	 WS1 Baseline Report

	 Wednesday, December 23, 2020 12:48 PM

   ************************************************************************

   Write-2Report -Path $Script:Path -Message "Completed report on Non-Compliant Devices and Settings for $BaselineName Baseline in $BaselineParentOG" -Level "Footer"
   writes the following to "path_to_log_file" 
   ************************************************************************

	 Completed report on All Devices and Settings for LOB1 Baseline in EUC Office of the CTO

   ************************************************************************
   #>
$current_path = $PSScriptRoot;

<# function Get-AWAPIConfiguration{
    if(Test-Path "$current_path\api-debug.config"){
        $useDebugConfig = $true;
        $api_config_file = [IO.File]::ReadAllText("$shared_path\api-debug.config");
        $Private:api_settings = $api_config_file;
    } elseif(Test-Path "$current_path\api.config"){
        $api_config_file = [IO.File]::ReadAllText("$current_path\api.config");
    }
    
    if($api_config_file){
        if($api_config_file.Contains('"ApiConfig"')){
            $api_settings = $api_config_file;
            $encrypted = ConvertTo-EncryptedFile -FileContents $api_config_file;
            if($encrypted){
                Set-Content -Path ("$current_path\api.config") -Value $encrypted;
            }
        } else {
            $Private:api_settings = ConvertFrom-EncryptedFile -FileContents $api_config_file;
        }

        $Private:api_settings_obj = ConvertFrom-Json -InputObject $Private:api_settings
        $Global:Server =  $Private:api_settings_obj.ApiConfig.Server;
        $Private:API_Key = $Private:api_settings_obj.ApiConfig.ApiKey
        $Private:Auth = $Private:api_settings_obj.ApiConfig.ApiAuth;
        $Global:OrganizationGroupId = $Private:api_settings_obj.ApiConfig.OrganizationGroupId;    

        #DeviceId Getter
        If(![bool]($api_settings_obj.ApiConfig.PSobject.Properties.name -match "DeviceId")) {
            $Private:api_settings_obj.ApiConfig | Add-Member -MemberType NoteProperty -Name "DeviceId" -Value -1;
        } Else {
            If($api_settings_obj.ApiConfig.DeviceId -ne ""){
            $deviceid = $Private:api_settings_obj.ApiConfig.DeviceId;
            }
            if($debug){
                Write-Log2 -Path $logLocation -Message "Device ID $deviceid" -Level Info
            }
        } 
    }

    $content_type = "application/json;version=1";
    $content_type_v2 = "application/json;version=2";

    return $api_settings_obj;
} #>

<# function Get-EnrollmentStatus{
    param([string]$DeviceId)

    Set-Variable -Name "api_settings_obj" -Value (Get-AWAPIConfiguration) -Scope "Private"

    $Server = $Private:api_settings_obj.ApiConfig.Server;
    if($debug){
        Write-Log2 -Path $logLocation -Message "API Server $Server" -Level Info
    }
    Set-Content "C:\Temp\temp.log" -Value ($Private:api_settings_obj | Format-Table | Out-String)

    #$serialSearch = wmic bios get serialnumber;
    $serialSearch = get-ciminstance win32_bios | format-list serialnumber
    $serialnumber = $serialSearch[2];
    $serialnumber = $serialnumber.Trim();

    $Enrolled = $true;
        
    $deviceEndpoint = "$Server/api/mdm/devices/$DeviceId";

    $currentDevice = Invoke-WebRequest -URI $deviceEndpoint -Headers $Private:api_settings_obj.HeadersV1 -UseBasicParsing;
    If($serialnumber -eq $currentDevice.SerialNumber){
        If($currentDevice.EnrollmentStatus -ne "Enrolled"){
            $deviceid = "";
            $Enrolled = $false;
        }
    } Else{
        $deviceid = "";
    }   
    return $Enrolled;
} #>

<# function Invoke-SecureWebRequest{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, [string]$Auth, [string]$Apikey, [bool]$Debug=$false)
    #$Private:api_settings_obj = Get-AWAPIConfiguration;

    #$SSLThumbprint = $Private:api_settings_obj.ApiConfig.SSLThumbprint;
    if($Global:DeviceId or $Global:OrganizationGroupId){
        $Endpoint = $Endpoint.Replace("{DeviceId}",$Global:DeviceId).Replace("{OrganizationGroupId}",$Global:OrganizationGroupId);
    } 
    if($debug){
        Write-Log2 -Path $logLocation -Message "API Endpoint $Endpoint" -Level Info
    }
    Try
    {
        # Create web request
        $WebRequest = [System.Net.WebRequest]::Create("$Global:Server/$Endpoint")
        $WebRequest.Method = $Method;

        #Setting Private Headers
        #$WebRequest.Headers.Add("aw-tenant-code",$Private:api_settings_obj.ApiConfig.ApiKey);
        #$WebRequest.Headers.Add("Authorization",$Private:api_settings_obj.ApiConfig.ApiAuth);
        $WebRequest.Headers.Add("aw-tenant-code",$ApiKey);
        $WebRequest.Headers.Add("Authorization",$Auth);

        #Setting Content
        $WebRequest.Accept = "application/json;version=$ApiVersion";
        $WebRequest.ContentType = "application/json;version=$ApiVersion";  
    
        #Data stream 
        If($Data){
            $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($Data);
            $WebRequest.ContentLength = $ByteArray.Length;  
            $Stream = $WebRequest.GetRequestStream();
            Try{              
                $Stream.Write($ByteArray, 0, $ByteArray.Length);   
            } Catch {
                $Error = $_.Exception.Message; 
            } Finally{
                $Stream.Close();
            }
        } Else {
            $WebRequest.ContentLength = 0;
        }

        # Set the callback to check for null certificate and thumbprint matching.
        $WebRequest.ServerCertificateValidationCallback = {
            $ThumbPrint = $SSLThumbprint;
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$args[1]
            
            If ($certificate -eq $null)
            {
                return $false
            }
 
            If (($certificate.Thumbprint -eq $ThumbPrint) -and ($certificate.SubjectName.Name -ne $certificate.IssuerName.Name))
            {
                return $true
            }
            return $false
        }      
        # Get response stream
        $Response = $webrequest.GetResponse();
        $ResponseStream = $webrequest.GetResponse().GetResponseStream()

        $SSLThumbPrint = $null;
        $Private:api_settings_obj = $null;

        # Create a stream reader and read the stream returning the string value.
        $StreamReader = New-Object System.IO.StreamReader -ArgumentList $ResponseStream
        
        Try{
            $Content = $StreamReader.ReadToEnd();
        } Catch {
            $Error = $_.Exception.Message;
        } Finally{
            $StreamReader.Close();
        }

        $CustomWebResponse = $Response | Select-Object Headers, ContentLength, ContentType, CharacterSet, LastModified, ResponseUri,
            @{N='StatusCode';E={$_.StatusCode.value__}},@{N='Content';E={$Content}}

        return $CustomWebResponse;
    }
    Catch
    {
        Write-Log2 -Path $logLocation -Message "Failed: $($_.exception.innerexception.message)" -Level Error
        $StatusCode = $_.Exception.InnerException.Response.StatusCode.value__;
        If(!($StatusCode)){
            $StatusCode = 999;
            $Content = $_.Exception.InnerException.Message;
        } ElseIf($_.Exception.InnerException.StatusCode.value__){
            $StatusCode = 999;
            $Content = $_.Exception.InnerException.Message;
        }
        return New-Object -TypeName PSCustomObject -Property @{"StatusCode"=$StatusCode;"Content"=$Content}
    } 

} #>

<# function Invoke-PrivateWebRequest{
    param([string]$Endpoint, $Method="Get", $ApiVersion=1, $Data, [string]$Auth, [string]$Apikey, [bool]$Debug=$false)
    
    #$Private:api_settings_obj = Get-AWAPIConfiguration;
    #Setting Private Headers
    $WebRequest.Headers.Add("aw-tenant-code",$ApiKey);
    $WebRequest.Headers.Add("Authorization",$Auth);

    #Setting Content
    $WebRequest.Accept = "application/json;version=$ApiVersion";
    $WebRequest.ContentType = "application/json;version=$ApiVersion";  
    #$Endpoint = $Endpoint.Replace("{DeviceId}",$Global:DeviceId).Replace("{OrganizationGroupId}",$Global:OrganizationGroupId);
    $WebRequest = $null;
    Try {
        $WebRequest = Invoke-WebRequest -Uri ("$Global:Server/$Endpoint") -Method $Method -Headers $ApiVersion -Body $Data -UseBasicParsing;
    } Catch{
        $ErrorMessage = $_.Exception.Message;
        If($Debug){ Write-Log2 -Message "An error has occurrred.  Error: $ErrorMessage" }
        if($_.Exception -like "Unable to connect to the remote server"){
            return "Offline";
        } 
    } Finally{
        $Private:api_settings_obj = $null;
    }

    return $WebRequest;
} #>

function Get-NewDeviceId{

    #$serialSearch = wmic bios get serialnumber;
    $serialSearch = get-ciminstance win32_bios | format-list serialnumber
    $serialnumber = $serialSearch[2];
    $serialnumber = $serialnumber.Trim();

    $serialEncoded = [System.Web.HttpUtility]::UrlEncode($serialnumber);
    $deviceSearchEndpoint = "api/mdm/devices?searchBy=Serialnumber&id=$serialEncoded";

    $WebResponse = Invoke-AWApiCommand -Endpoint $deviceSearchEndpoint -Method $Method -ApiVersion 1 -Data $Data -Debug $Debug

    If($device_json.Id){
        $deviceid = $device_json.Id.Value;
        If ($device_json.EnrollmentStatus -ne "Enrolled"){
            return "Unenrolled";
        }
        return $deviceid;
    } 
    return "Unenrolled";
}

function Get-OG{
    param([string]$Server, [string]$cred, [string]$apikey, [string]$OrgGroup, [bool]$Debug=$false)
    $og_search_endpoint = "$Server/API/system/groups/search?name=$OrgGroup";
    $OG_Search = Invoke-AWApiCommand -Method Get -Endpoint $og_search_endpoint -ApiVersion 2 -Auth $cred -Apikey $apikey -Debug $Debug
    If($OG_Search.OrganizationGroups){
        if($Debug){
            $OGName = $OG_Search.OrganizationGroups[0].Name
            $OGID = $OG_Search.OrganizationGroups[0].Id
            Write-Log2 -Path $logLocation -Message "OG Name $OGName & OG ID $OGID" -Level Info
        }
    }
    return $OG_Search;
}

function Invoke-AWApiCommand{
    param([string]$Endpoint, [string]$Method="GET", [int]$ApiVersion=1, $Data, [string]$Auth, [string]$Apikey, [bool]$Debug=$false)

    $WebRequest = $null;

    $WebRequest = [System.Net.WebRequest]::Create("$Endpoint")
    
    Try {
        
        if($Data){
            #$WebRequest = Invoke-RestMethod -Uri "$Endpoint" -Method $Method -Body $Data -Headers @{'aw-tenant-code' = $ApiKey;'Authorization' = $Auth;'accept' = 'application/json';'Content-Type' = 'application/json'};
            $WebRequest = Invoke-WebRequest -Uri ("$Endpoint") -Method $Method -Body $Data -UseBasicParsing -Headers @{'aw-tenant-code' = $ApiKey;'Authorization' = $Auth;'accept' = "application/json;version=$ApiVersion";'Content-Type' = 'application/json'};
        } else {
            #$WebRequest = Invoke-RestMethod -Uri "$Endpoint" -Method $Method -Headers @{'aw-tenant-code' = $ApiKey;'Authorization' = $Auth;'accept' = 'application/json';'Content-Type' = 'application/json'};
            $WebRequest = Invoke-WebRequest -Uri ("$Endpoint") -Method $Method -UseBasicParsing -Headers @{'aw-tenant-code' = $ApiKey;'Authorization' = $Auth;'accept' = "application/json;version=$ApiVersion";'Content-Type' = 'application/json'};
        }
        
    } Catch{
        $ErrorMessage = $_.Exception.Message;
        #If($Debug){ Write-Log2 -Path $logLocation -Message "An error has occurrred.  Error: $ErrorMessage"}
        Write-Log2 -Path $logLocation -Message "An error has occurrred.  Error: $ErrorMessage" -Level "Error"
        if($_.Exception -like "Unable to connect to the remote server"){
            return "Offline";
        } 
    }

    If($Debug){
        Write-Log2 -Path $logLocation -Message "Connecting to: $Endpoint" -Level "Info";
        $statuscode = $WebRequest.StatusCode
        If($WebRequest.Content){
            Write-Log2 -Path $logLocation -Message "WebRequest.StatusCode: $statuscode" -Level "Info";
            Write-Log2 -Path $logLocation -Message $WebRequest.Content -Level "Info";
        }
    }

    Try{ 
        if($WebRequest.StatusCode -lt 300){
           If($WebRequest.Content){
               $ReturnObj = ConvertFrom-Json($WebRequest.Content); 
           } 
           return $ReturnObj;
        }
        else {
           return $WebRequest.Content;
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return (New-Object -TypeName PSCustomObject -Property @{"Error"="$ErrorMessage"});
    }
}

function Get-CurrentLoggedonUser{
    param([bool]$ReturnObj=$false)
    If(Test-Path "$current_path\GetWin32User.cs"){
        Unblock-File "$current_path\GetWin32User.cs"
        if (-not ([Management.Automation.PSTypeName]'AWDeviceInventory.QueryUser').Type) {
                    [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
                    Add-Type -Path "$current_path\GetWin32User.cs" -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
        }
    } Else{
        $usernameLookup = Get-WMIObject -class Win32_ComputerSystem | Select-Object username;
    }
    #$usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:ComputerName")
    $usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:COMPUTERNAME") | Where-Object {$_.Connectstate -eq "Active" -and $_.IsConsoleSession -eq $True}
    if($usernameLookup){
        $usernameLookup = $usernameLookup.username;
    }
    if($ReturnObj){
        if($usernameLookup -match "([^\\]*)\\(.*)"){
            $usernameProp = @{"Username"=$Matches[2];"Domain"=$Matches[1];"FullName"=$Matches[0]}
            $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
        } elseif($usernameLookup -match "([^@]*)@(.*)"){
            $usernameProp = @{"Username"=$Matches[1];"Domain"=$Matches[2];"Fullname"=$Matches[0]}
            $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
        }         
    }
    return $usernameLookup;
}

<#
Function: Get-UserSIDLookup
Author  : cbradley@vmware.com
Description : Gets an SID lookup of a user based on username 
Input Params:  
        .PARAMETER  'UsernameLookup'
		 Username to evaluate.  Can support NT and UPN formats.  
         Using the values '(current_user)' or leaving this parameter
         empty returns the SID of the current logged in user.
            
Output: String
Example: Get-CurrentLoggedonUser
        returns Chase Bradley
#>
function Get-UserSIDLookup{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$UsernameLookup
    )
        If($usernameLookup -eq "(current_user)" -or $UsernameLookup -eq ""){
            $usernameLookup = Get-CurrentLoggedonUser
        } 
        
        If($usernameLookup.Contains("\")){
            $usernameLookup = $usernameLookup.Split("\")[1];
        } Elseif ($usernameLookup.Contains("@")){
            $usernameLookup = $usernameLookup.Split("@")[0];
        }
        $User = New-Object System.Security.Principal.NTAccount($usernameLookup)
        Try{
            $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value;
            return $sid;
        } Catch{
            $ErrorMessage = $_.Exception.Message;
            return ("Error:: " + $ErrorMessage);
        }
    
}

function Get-ReverseSID{
    Param([string]$SID,[bool]$ignoreGroups=$true)

    Try{
        
        $domainJoined = $false;
        $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
        $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain;
        $domainJoined = (Get-CimInstance -Class CIM_ComputerSystem).PartOfDomain
        if($domainJoined){
            $domain = $localmachine;
        }


        $newSID = Get-WmiObject -Class Win32_UserAccount -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        if(($newSID | Measure-Object).Count -eq 0 -and $ignoreGroups){
            return "Error:: User not found"
        } elseif (($newSID | Measure-Object).Count -eq 0 -and !$ignoreGroups){
            $newSID = Get-WmiObject -Class Win32_Group -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        }

        if($newSID){     
            if($domain.ToLower().Contains($newSID.domain.ToLower())){
                #Local user, just return the username
                return $newSID.Name;
            } else {
                #Domain user, just return the username
                return $newSID.Caption;
            }
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return ("Error:: " + $ErrorMessage);
    }
}

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'

        if(!$Path){
            $current_path = $PSScriptRoot;
            if($PSScriptRoot -eq ""){
                #default path
                $current_path = "C:\Temp";
            }
    
            #setup Report/Log file
            $DateNow = Get-Date -Format "yyyyMMdd_hhmm";
            $pathfile = "$current_path\WS1API_$DateNow";
            $Local:logLocation = "$pathfile.log";
            $Local:Path = $logLocation;
        }
        
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            #Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

function Write-Log2{
    [CmdletBinding()]
    Param
    (
        [string]$Message,
        
        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info",
        
        [switch]$UseLocal
    )
    if((!$UseLocal) -and $Level -ne "Success"){
        Write-Log -Path "$Path" -Message $Message -Level $Level;
    } else {
        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
        $FontColor = "White";
        If($ColorMap.ContainsKey($Level)){
            $FontColor = $ColorMap[$Level];
        }
        $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        #$DateNow = (Date).ToString("yyyy-mm-dd hh:mm:ss");
        Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
        Write-Host "$MethodName::$Level`t$Message" -ForegroundColor $FontColor;
    }
}

function Write-2Report{ 
    [CmdletBinding()]
    Param
    (
        [string]$Message,

        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Title","Header","Body","Footer")]
        [string]$Level="Body"
        
    )
    
    $ColorMap = @{"Title"="Cyan";"Header"="Yellow";"Footer"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){
        $FontColor = $ColorMap[$Level];
    }

    if($Level -eq "Title"){
        $DateNow = Get-Date -Format f;
        $Title = @("************************************************************************`n`n`t $Message`n`n`t $DateNow`n`n************************************************************************`n");
        $Message = $Title
    }

    if($Level -eq "Footer"){
        $Footer = @("************************************************************************`n`n`t $Message`n`n************************************************************************`n");
        $Message = $Footer
    }

    Add-Content -Path $Path -Value ("$Message")
    Write-Host "$Message" -ForegroundColor $FontColor;
    
}

Export-ModuleMember -Function Get-OG, Invoke-AWApiCommand, Get-CurrentLoggedonUser, Get-UserSIDLookup, Get-ReverseSID, Write-Log, Write-Log2, Write-2Report
