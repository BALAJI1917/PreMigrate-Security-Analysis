& {
param($PoshToolsRoot)
<#
New Version 3.2.5 - 09/SEP/2026 - Customer Release
.SYNOPSIS
   Opsole Migrate - Automated device transition from Hybrid/AD Join to Entra Join.
.DESCRIPTION
    This script is part of Opsole Migrate, an enterprise-grade solution that automates 
    the silent, agentless migration of Windows devices from on-premises Active Directory 
    or Hybrid Azure AD Join to Microsoft Entra ID Join with zero user disruption.
    
    Opsole Migrate is purpose-built to accelerate organizations through Microsoft's 
    "Road to the Cloud" transformation, enabling secure, scalable, cloud-first 
    device identity management.
    
    KEY CAPABILITIES:
    - Zero-disruption migration with no downtime or user impact
    - Silent, automated, and fully agentless operation
    - End-to-end security with enterprise-grade credential protection
    - Automated at scale: from 100 to 100,000+ devices
    - Comprehensive reporting with full audit trails and compliance tracking
    - Self-service option for end-user initiated migrations
    - Optimized for mergers, acquisitions, and large-scale IT transformations
    - Cloud-native design aligned with Microsoft Entra best practices
    
    SUPPORTED SCENARIOS:
    - Local AD Join to Entra ID Join
    - Hybrid Azure AD Join to Entra ID Join
    - Domain-joined devices to Cloud-native managed devices
.PARAMETER ConfigPath
    Optional. Path to migration configuration file. Uses embedded defaults if not specified.
.PARAMETER Mode
    Optional. Migration mode: 'Silent' (default), 'Interactive', or 'SelfService'
.EXAMPLE
    .\OpsoleMigrate.exe
    Executes silent migration with default embedded configuration.
.EXAMPLE
    .\OpsoleMigrate.exe -ConfigPath "C:\Config\migrate.json" -Mode Interactive
    Runs migration with custom configuration and user prompts.
.INPUTS
    None. Script does not accept pipeline input.
.OUTPUTS
    Exit codes:
    0  - Success
    1  - Pre-flight validation failed
    2  - Migration failed (rollback completed)
    3  - User intervention required
.NOTES
    Name:           OpsoleMigrate
    Version:        3.2.5
    Author:         Opsole Team
    Contact:        support@opsole.com
    Created:        2025-01-15
    Updated:        2026-09-09
        
    Execution Context:  SYSTEM (required)
    Minimum OS:         Windows 10 20H2 / Windows 11
    Prerequisites:      Internet connectivity, Entra ID tenant configured
    
    Copyright:      © 2026 Opsole. All rights reserved.
    License:        Proprietary - Licensed for enterprise use only 
.LINK
    https://docs.opsole.com/
.LINK
    https://support.opsole.com
.COMPONENT
    Opsole Migrate
.FUNCTIONALITY
    Entra ID Join Migration, Cloud-First Identity Transformation, Device Provisioning
#>

#API Configuration and Initialization
###############################################
Add-Type -AssemblyName System.Security
$apiConfigRegPath = 'HKLM:\SOFTWARE\OpsoleMigrate\ApiConfig'
$keyBase64 = 'nG+k7v0CMip2nsiZpDpwIZjIvqOKRsXJfwC0zpKPnCc='
$key = [Convert]::FromBase64String($keyBase64.Trim())
if ($key.Length -ne 32) { throw 'AES key must be 32 bytes (256-bit).' }

function Unprotect-OpsoleRegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$CipherTextBase64,
        [Parameter(Mandatory)]
        [byte[]]$Key
    )

    $fullBytes = [Convert]::FromBase64String($CipherTextBase64.Trim())
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $Key

        $ivLen = $aes.BlockSize / 8
        if ($fullBytes.Length -le $ivLen) { throw 'Ciphertext too short.' }

        $iv = $fullBytes[0..($ivLen - 1)]
        $cipherBytes = $fullBytes[$ivLen..($fullBytes.Length - 1)]

        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $plain = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
        return [System.Text.Encoding]::UTF8.GetString($plain)
    }
    finally {
        $aes.Dispose()
    }
}

$cfg = Get-ItemProperty -LiteralPath $apiConfigRegPath -ErrorAction Stop
$bearerToken = Unprotect-OpsoleRegistryValue -CipherTextBase64 $cfg.BearerToken -Key $key
$apiKey = Unprotect-OpsoleRegistryValue -CipherTextBase64 $cfg.ApiKey -Key $key
$apidomain = Unprotect-OpsoleRegistryValue -CipherTextBase64 $cfg.ApiDomain -Key $key

# API URLs
############################
$apihealth = "https://$apidomain/client/healthy"
$LicenseUrl = "https://$apidomain/client/license"
$logapiUrl = "https://$apidomain/client/logs"
$bitlockerurl = "https://$apidomain/client/bitlockerkeys"
$StatusLogApiUrl = "https://$apidomain/client/migration"
$configUrl = "https://$apidomain/client/config"
$addcfgUrl = "https://$apidomain/client/additional-config"
$groupchange = "https://$apidomain/client/group-ids"
$ppkgurl = "https://$apidomain/client/download?file=package"

$ErrorActionPreference = "Continue"

# Enforce secure TLS
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls13

# Create API Headers (best practice)
$apiheaders = @{
    "Authorization" = "Bearer $bearerToken"
    "x-api-key"     = $apiKey
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
    "User-Agent"    = "OpsoleMigrate/1.0 (Windows; PowerShell)"
}

$cli = [Environment]::GetCommandLineArgs()
$forceMode = $cli -contains "--forced"

# Windows Form Initiation
##########################
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$exePath = Get-Location
$iconPath = Join-Path $exePath 'assets\icon.ico'
$logoPath = Join-Path $exePath 'assets\logo.jpg'

# FUNCTION: Log
################
$global:apiLogErrorLogged = $false
$global:apiLogSucessLogged = $false
$global:CachedSerialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
$global:CachedHostName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name
$script:ApiEndpointUnavailable = $false

# Function  Api response
#########################
function Get-ApiErrorResponse {
    param(
        [Parameter(Mandatory = $true)]
        $ErrorRecord
    )

    if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        try {
            return ($ErrorRecord.ErrorDetails.Message | ConvertFrom-Json)
        }
        catch {
            return [PSCustomObject]@{
                status  = $false
                message = $ErrorRecord.ErrorDetails.Message
            }
        }
    }

    return $null
}

# Function RestApi Retry Logic
################################
function Invoke-ApiWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Post', 'Put', 'Patch', 'Delete')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [hashtable]$Headers,
        [object]$Body = $null,
        [string]$ContentType,
        [int]$TimeoutSec = 30,
        [int]$MaxRetries = 4
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $params = @{
                Method      = $Method
                Uri         = $Uri
                TimeoutSec  = $TimeoutSec
                ErrorAction = 'Stop'
            }

            if ($Headers) {
                $params.Headers = $Headers
            }

            if (($Method -in @('Post', 'Put', 'Patch')) -and $null -ne $Body) {
                if ($Body -is [string] -or $Body -is [byte[]]) {
                    $params.Body = $Body
                }
                else {
                    $params.Body = $Body | ConvertTo-Json -Depth 10
                }

                if (-not [string]::IsNullOrWhiteSpace($ContentType)) {
                    $params.ContentType = $ContentType
                }
                elseif (-not ($Body -is [string] -or $Body -is [byte[]])) {
                    $params.ContentType = 'application/json'
                }
            }

            return Invoke-RestMethod @params
        }
        catch {
            $message = $_.Exception.Message
            $statusCode = $null

            if ($_.Exception.Response) {
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
            }

            $apiError = Get-ApiErrorResponse -ErrorRecord $_
            if ($apiError) {
                return $apiError
            }

            $retryable = ($null -eq $statusCode) -and (
                $message -match 'remote name could not be resolved' -or
                $message -match 'unable to connect to the remote server' -or
                $message -match 'the operation has timed out' -or
                $message -match 'a connection attempt failed' -or
                $message -match 'the underlying connection was closed'
            )

            $logMessage = "API call failed attempt $i/$MaxRetries [$Method]. StatusCode: $statusCode. Error: $message"

            try {
                Write-EventLog -LogName "OpsoleMigrate" -Source "OpsoleMigrate" -EntryType Warning -EventId 5002 -Message $logMessage
            }
            catch {
                try {
                    Write-EventLog -LogName "Application" -Source "Application" -EntryType Warning -EventId 5002 -Message $logMessage
                }
                catch { }
            }

            if (-not $retryable -or $i -eq $MaxRetries) {
                return $null
            }

            switch ($i) {
                1 { Start-Sleep -Seconds 2 }
                2 { Start-Sleep -Seconds 5 }
                3 { Start-Sleep -Seconds 10 }
            }
        }
    }

    return $null
}

# Function  Web Download Retry Logic
####################################
function Invoke-DownloadWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$OutFile,

        [hashtable]$Headers,
        [int]$TimeoutSec = 120,
        [int]$MaxRetries = 4
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $params = @{
                Uri             = $Uri
                OutFile         = $OutFile
                TimeoutSec      = $TimeoutSec
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }

            if ($Headers) {
                $params.Headers = $Headers
            }

            Invoke-WebRequest @params | Out-Null
            return $true
        }
        catch {
            $message = $_.Exception.Message

            $retryable = (
                $message -match 'remote name could not be resolved' -or
                $message -match 'unable to connect to the remote server' -or
                $message -match 'the operation has timed out' -or
                $message -match 'a connection attempt failed' -or
                $message -match 'the underlying connection was closed'
            )

            Write-Log -Message "File download attempt $i of $MaxRetries failed." -isWarning $true

            if (-not $retryable -or $i -eq $MaxRetries) {
                return $false
            }

            switch ($i) {
                1 { Start-Sleep -Seconds 2 }
                2 { Start-Sleep -Seconds 5 }
                3 { Start-Sleep -Seconds 10 }
            }
        }
    }

    return $false
}

# Function Write-Log
######################
function Write-Log {
    param (
        [string]$message,
        [string]$logName = "OpsoleMigrate",
        [bool]$isError = $false,
        [bool]$isWarning = $false,
        [string]$fallbackLogFile = "C:\ProgramData\OpsoleLog\opsolemigrate.log"
    )
    # Get system details
    $serialNumber = $global:CachedSerialNumber
    $hostName = $global:CachedHostName

    # Create the log if it doesn't exist
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($logName)) {
            # Create the custom log under the specified log name
            New-EventLog -LogName $logName -Source $logName
        }
    }
    catch {
        Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 50001 -Message "Failed to initialize custom log. Error: $_" 
    }
    # Determine the log entry type
    $entryType = if ($isError) { [System.Diagnostics.EventLogEntryType]::Error } elseif ($isWarning) { [System.Diagnostics.EventLogEntryType]::Warning } else { [System.Diagnostics.EventLogEntryType]::Information }
    # Write the log message to the custom Event Viewer log
    try {
        Write-EventLog -LogName $logName -Source $logName -EntryType $entryType -EventId 50000 -Message $message
    }
    catch {
        $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Log: $message"
        $logDir = Split-Path -Path $fallbackLogFile        
        if (-not (Test-Path -Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $fallbackLogFile -Value $logMessage
    }
    # Prepare log data for API
    $logData = @{
        timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        log          = $message
        serialNumber = $serialNumber
        hostName     = $hostName
        isError      = $isError
        isWarning    = $isWarning
    }
    # Convert log data to JSON
    $jsonBody = $logData | ConvertTo-Json -Depth 5
    # Send POST request to API
    if (-not $script:ApiEndpointUnavailable) {
        try {
            $response = Invoke-ApiWithRetry  -Uri $logapiUrl -Method Post -Headers $apiheaders -Body $jsonBody
            if (-not $global:apiLogSucessLogged) {
                $global:apiLogSucessLogged = $true 
                Write-EventLog -LogName "Application" -Source "Application" -EntryType Information -EventId 5000 -Message "Log sent successfully to API. Response: $response"
            }
        }
        catch {
        
            if (-not $global:apiLogErrorLogged) {
                $global:apiLogErrorLogged = $true 
                $err = $_.Exception.Message
                Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 5001 -Message "Failed to send log to API. Error: $err"
            }
        }
    }
}

# FUNCTION: Write-variables to API
##################################
$global:apivarErrorLogged = $false
$global:apivarSucessLogged = $false
function Write-variables {

    # Get system details
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    # Prepare log data for API
    $logData = @{
        SerialNumber       = $serialNumber
        MigrationStarted   = $MigrationStarted
        MigrationStartTime = $MigrationStartTime
        PrecheckStatus     = $PrecheckStatus
        Oldhostname        = $oldhostname
        OldlocalDomain     = $oldlocalDomain
        OldazureAdJoined   = $OldazureAdJoined
        Olddomainjoined    = $Olddomainjoined
        OldintuneId        = $OldintuneId
        OldentraDeviceId   = $OldentraDeviceId
        OldlapsPassword    = $OldlapsPassword
        OldAdminPassword   = $adminPassword
        OldautopilotId     = $OldautopilotId
        OlduserName        = $OlduserName
        Oldupn             = $oldupn
        OldentraUserId     = $OldentraUserId
        OldSAMName         = $OldSAMName
        OldSID             = $OldSID
        PartOfDomain       = $PartOfDomain
        Newupn             = $Newupn
        NewentraUserId     = $NewentraUserId
        NewSAMName         = $NewSAMName
        NewSID             = $NewSID
        MigrationStatus    = $MigrationStatus
        MigrationPercent   = $MigrationPercent
        MigrationEndTime   = $MigrationEndTime
        NewHostName        = $new_hostname
    }
    # Convert log data to JSON
    $jsonBody = $logData | ConvertTo-Json -Depth 5
    # Send POST request to API
    try {
        $response = Invoke-ApiWithRetry  -Uri $StatusLogApiUrl -Method Post -Headers $apiheaders -Body $jsonBody
        if (-not $global:apivarSucessLogged) {
            $global:apivarSucessLogged = $true 
            Write-EventLog -LogName "Application" -Source "Application" -EntryType Information -EventId 5000 -Message "Log sent successfully to variables API. Response: $response"
        }
    }
    catch {
        if (-not $global:apivarErrorLogged) {
            $global:apivarErrorLogged = $true 
            $err = $_.Exception.Message
            Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 5001 -Message "Failed to send log to variables API. Error: $err"
        }
    }
}

# FUNCTION: Write-migstatus to API
#################################
$global:apiMigErrorLogged = $false
$global:apiMigSuccessLogged = $false
function Write-migstatus {

    # Get system details
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    # Prepare log data for API
    $logData = @{
        SerialNumber     = $serialNumber
        MigrationStatus  = $MigrationStatus
        MigrationPercent = $MigrationPercent
        MigrationEndTime = $MigrationEndTime
    }
    # Convert log data to JSON
    $jsonBody = $logData | ConvertTo-Json -Depth 5
    # Send POST request to API
    try {
        $response = Invoke-ApiWithRetry  -Uri $StatusLogApiUrl -Method Put -Headers $apiheaders -Body $jsonBody
        if (-not $global:apiMigSuccessLogged) {
            $global:apiMigSuccessLogged = $true 
            Write-EventLog -LogName "Application" -Source "Application" -EntryType Information -EventId 5000 -Message "Log sent successfully to variables API. Response: $response"
        }
    }
    catch {
        if (-not $global:apiMigErrorLogged) {
            $global:apiMigErrorLogged = $true 
            $err = $_.Exception.Message
            Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 5001 -Message "Failed to send log to variables API. Error: $err"
        }
    }
}

# FUNCTION: Device Group Add Function
#################################
$global:apiGrpErrorLogged = $false
$global:apiGrpSuccessLogged = $false
function Write-group {

    # Get system details
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    # Prepare log data for API
    $logData = @{
        serialNumber = $serialNumber
        deviceId     = $entraDeviceId
    }
    # Convert log data to JSON
    $jsonBody = $logData | ConvertTo-Json -Depth 5
    # Send POST request to API
    try {
        $response = Invoke-ApiWithRetry  -Uri $groupchange -Method Post -Headers $apiheaders -Body $jsonBody
        if (-not $global:apiGrpSuccessLogged) {
            $global:apiGrpSuccessLogged = $true
            Write-EventLog -LogName "Application" -Source "Application" -EntryType Information -EventId 5000 -Message "Log sent successfully to variables API. Response: $response"
        }
    }
    catch {
        if (-not $global:apiGrpErrorLogged) {
            $global:apiGrpErrorLogged = $true
            $err = $_.Exception.Message
            Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 5001 -Message "Failed to send log to variables API. Error: $err"
        }
    }
}

# FUNCTION: Write Bitlocker-key
###############################
function Write-bitlockerkey {
    param (
        [string]$message,
        [bool]$isError = $false
    )
    # Get system details
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

    # Prepare log data for API
    $logData = @{
        timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
        Bitlockerkey = $message
        serialNumber = $serialNumber
        isError      = $isError  
    }
    # Convert log data to JSON
    $jsonBody = $logData | ConvertTo-Json -Depth 5
    # Send POST request to API
    try {
        $response = Invoke-ApiWithRetry  -Uri $bitlockerurl -Method Post -Headers $apiheaders -Body $jsonBody
        Write-EventLog -LogName "Application" -Source "Application" -EntryType Information -EventId 5001 -Message "Write-bitlockerkey successfully to API. Response: $response"
    }
    catch {
        Write-EventLog -LogName "Application" -Source "Application" -EntryType Information -EventId 5001 -Message "Failed to send Write-bitlockerkey to API. Error: $($_.Exception.Message)"
    }
}

# FUNCTION: exitScript
##########################
$MigrationStatus = $null
function exitScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$functionName,
        [array]$tasks = @("InterMigrateTask", "PostMigrateTask")
    )
    $kbMap = @{
        "Getconfigapi"           = "KB-022201"
        "StoredeviceDetails"     = "KB-022207"
        "UserProfileCollection"  = "KB-022208"
        "EntraFetchUserDetails"  = "KB-022209"
        "dsregcmd"               = "KB-022210"
        "Remove-Computer"        = "KB-022211"
        "Remove-ComputerForce"   = "KB-022211"
        "EntrapackageInfo"       = "KB-022212"
        "Entrapkgdownload"       = "KB-022212"
        "Entrajoin"              = "KB-022212"
        "CreateInterMigrateTask" = "KB-022213"
        "Get-Intermediate"       = "KB-022213"
    }
    function ShowInstallationFailed {
        $kbId = if ($kbMap.ContainsKey($functionName)) {
            $kbMap[$functionName]
        }
        else {
            "Not available"
        }

        if ($kbId -eq "Not available") {
            $ExitErrorLabel.Text = "Migration failed in module $functionName`r`n`r`nKB article: Not available`r`n`r`nPlease contact your IT department or Opsole Support."
        }
        else {
            $ExitErrorLabel.Text = "Migration failed in module $functionName`r`n`r`nKB article: $kbId`r`n`r`nPlease follow the KB article from the Opsole Knowledge Base."
        }
        $progressBar.Visible = $false
        $progressLabel.Visible = $false
        $ExitErrorLabel.Visible = $true
        $closeButton.Visible = $true
    }
    $global:MigrationStatus = "False"
    $global:serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $global:MigrationEndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $MigrationStatus = $global:MigrationStatus
    $serialNumber = $global:serialNumber
    $MigrationEndTime = $global:MigrationEndTime
    Write-Log -Message "Migration failed in module $functionName." -isError $true
    Write-migstatus 

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 0  | Out-Null
    }
    catch {
        Write-Log -Message "Failed to apply user access configuration. Error: $_"
    }

    try {
        $tasks = Get-ScheduledTask -TaskPath '\Migration\' -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath '\Migration\' -Confirm:$false -ErrorAction Stop
                Write-Log -Message "Migration process removed successfully: $($task.TaskName)."
            }
            catch {
                Write-Log -Message "Failed to remove migration process: $($task.TaskName)." -isError $true
            }
        }
    }
    catch {
        Write-Log -Message "Failed to enumerate migration processes: $($_.Exception.Message)" -isError $true
    }

    $registryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $entryNames = @("legalnoticecaption", "legalnoticetext")
    foreach ($entryName in $entryNames) {
        try {
            $entryExists = Get-ItemProperty -Path $registryKeyPath -Name $entryName -ErrorAction SilentlyContinue
            if ($null -ne $entryExists) {
                Remove-ItemProperty -Path $registryKeyPath -Name $entryName -Force | Out-Null
            }
            else {
                Write-Log -Message "Configuration entry not found: $entryName"
            }
        }
        catch {
            Write-Log -Message "Failed to verify or remove configuration entry: $entryName." -isError $true
        }
    }

    try {
        if ($functionName -eq "EntraJoin") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "Entra Join Failed...Please check logs" -Type String -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "Please log in with Local Admin Account and proceed with Recovery Steps " -Type String -Force | Out-Null
        }
        else {
        }
    }
    catch {
        Write-Log -Message "Failed to set failure lock screen caption. Error: $($_.Exception.Message)" -isError $true
    }

    Start-Sleep -Seconds 1
    Write-Log -Message "Migration did not complete successfully."
    ShowInstallationFailed
}

# FUNCTION: generatePassword
###############################
function generatePassword() {
    param(
        [int]$length = 12
    )
    $charSet = "ABCDEFGHJMPQRSTUVWXYZabcdefghnrt2346789@#&"
    $securePassword = New-Object -TypeName System.Security.SecureString
    # Ensure at least one of each required character type
    $requiredChars = @(
        "ABCDEFGHJMPQRSTUVWXYZ"[(Get-Random -Minimum 0 -Maximum "ABCDEFGHJMPQRSTUVWXYZ".Length)]
        "abcdefghnrt"[(Get-Random -Minimum 0 -Maximum "abcdefghnrt".Length)]
        "2346789"[(Get-Random -Minimum 0 -Maximum "2346789".Length)]
        "@#&"[(Get-Random -Minimum 0 -Maximum "@#&".Length)]
    )
    $requiredChars | Sort-Object { Get-Random } | ForEach-Object {
        $securePassword.AppendChar($_)
    }

    ($requiredChars.Count + 1)..$length | ForEach-Object {
        $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
        $securePassword.AppendChar($random)
    }
    return $securePassword
}
    
# Get battery status
###############################
function Charger {
    # Attempt to get battery status
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($battery -and $battery.BatteryStatus -eq 2) {
        return $true  
    }
    elseif ($null -eq $battery) {
        return $true  
    }
    else {
        return $false   
    }
}

# Check for pending reboot
###############################
function RebootOrUpdatePending {
    $rebootPendingKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )

    foreach ($key in $rebootPendingKeys) {
        if (Test-Path $key) {
            return $true
        }
    }

    return $false
}

# Create the form and controls
###############################
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NativeMethods {
    [DllImport("user32.dll")]
    public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

    [DllImport("user32.dll")]
    public static extern bool EnableMenuItem(IntPtr hMenu, uint uIDEnableItem, uint uEnable);

    public const uint SC_CLOSE = 0xF060;
    public const uint MF_GRAYED = 0x1;
    public const uint MF_BYCOMMAND = 0x0;
}
"@
# Function to disable the Close button
####################################
function Disable-CloseButton {
    param ($form)
    $handle = $form.Handle
    $hMenu = [NativeMethods]::GetSystemMenu($handle, $false)
    [NativeMethods]::EnableMenuItem($hMenu, [NativeMethods]::SC_CLOSE, [NativeMethods]::MF_GRAYED -bor [NativeMethods]::MF_BYCOMMAND)
}
# Windows Form Design
####################

$form = New-Object System.Windows.Forms.Form -Property @{
    Text            = "Opsole Migrate v3.2"
    Size            = New-Object System.Drawing.Size(700, 475)
    StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterScreen
    BackColor       = [System.Drawing.Color]::White
    FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    MaximizeBox     = $false
    MinimizeBox     = $false
}

$topBorder = New-Object System.Windows.Forms.Panel -Property @{
    Size      = New-Object System.Drawing.Size(700, 1)  #
    BackColor = [System.Drawing.Color]::LightGray
    Dock      = "Top"  
}

$form.Icon = New-Object System.Drawing.Icon($iconPath)

$leftPanel = New-Object System.Windows.Forms.Panel
$leftPanel.Size = New-Object System.Drawing.Size(175, 475)
$leftPanel.BackColor = [System.Drawing.Color]::Transparent
$leftPanel.Dock = "Left"
$form.Controls.Add($leftPanel)

$logoPictureBox = New-Object System.Windows.Forms.PictureBox -Property @{
    SizeMode  = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    Width     = 175   
    Height    = 445 
    BackColor = [System.Drawing.Color]::Transparent
    Visible   = $true
}
$newHeight = 442 
$logoPictureBox.Height = $newHeight
$logoPictureBox.Top = 445 - $newHeight 

$logoPictureBox.Image = [System.Drawing.Image]::FromFile($logoPath)

$headingLabel = New-Object System.Windows.Forms.Label -Property @{
    Text      = "Welcome to Opsole Migrate Setup Wizard"
    Font      = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    ForeColor = [System.Drawing.Color]::FromArgb(9, 58, 48)
    AutoSize  = $false
    TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    Width     = 500
    Height    = 30
}

$instructionLabel = New-Object System.Windows.Forms.Label -Property @{
    Text      = "`nPlease close all open applications.`n`nPreparing your system for migration...."
    Font      = New-Object System.Drawing.Font("Segoe UI", 10)
    ForeColor = [System.Drawing.Color]::FromArgb(9, 58, 48)
    AutoSize  = $false
    TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    Width     = 500
    Height    = 75
}

$startButton = New-Object System.Windows.Forms.Button -Property @{
    Text      = "Start Migration"
    Font      = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    Size      = New-Object System.Drawing.Size(150, 40)
    BackColor = [System.Drawing.Color]::FromArgb(1, 188, 183)
    ForeColor = [System.Drawing.Color]::FromArgb(9, 58, 48) 
}

$closeButton = New-Object System.Windows.Forms.Button -Property @{
    Text      = "Close"
    Font      = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    Size      = New-Object System.Drawing.Size(150, 40)
    BackColor = [System.Drawing.Color]::Gray
    ForeColor = [System.Drawing.Color]::White
    Visible   = $false  
}

$RebootButton = New-Object System.Windows.Forms.Button -Property @{
    Text      = "Reboot"
    Font      = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    Size      = New-Object System.Drawing.Size(150, 40)
    BackColor = [System.Drawing.Color]::Tomato
    ForeColor = [System.Drawing.Color]::Black
    Visible   = $false  
}

$progressBar = New-Object System.Windows.Forms.ProgressBar -Property @{
    Size    = New-Object System.Drawing.Size(400, 30)
    Style   = [System.Windows.Forms.ProgressBarStyle]::Continuous
    Minimum = 0
    Maximum = 100
    Value   = 0
    Visible = $false
}

$progressBarcheck = New-Object System.Windows.Forms.ProgressBar -Property @{
    Size    = New-Object System.Drawing.Size(400, 30)
    Style   = [System.Windows.Forms.ProgressBarStyle]::Continuous
    Minimum = 0
    Maximum = 100
    Value   = 0
    Visible = $false
}

$progressLabel = New-Object System.Windows.Forms.Label -Property @{
    Text     = "Progress: 0%"
    Font     = New-Object System.Drawing.Font("Segoe UI", 10)
    AutoSize = $true
    Visible  = $false
}

$completionLabel = New-Object System.Windows.Forms.Label -Property @{
    Text      = ""
    Font      = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    AutoSize  = $true
    ForeColor = [System.Drawing.Color]::FromArgb(9, 58, 48)
    Visible   = $false
}

$ExitErrorLabel = New-Object System.Windows.Forms.Label -Property @{
    Text      = ""
    Font      = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    ForeColor = [System.Drawing.Color]::DarkRed
    AutoSize  = $false
    Width     = 520
    Height    = 130
    TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    Visible   = $false
}

$ErrorLabel = New-Object System.Windows.Forms.Label -Property @{
    Text      = ""
    Font      = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    ForeColor = [System.Drawing.Color]::DarkRed
    AutoSize  = $true
    Visible   = $false  
}

# Add controls to the form
############################
$form.Controls.AddRange(@($topBorder, $logoPictureBox, $headingLabel, $instructionLabel, $progressBarcheck, $startButton, $progressBar, $progressLabel, $completionLabel, $closeButton, $RebootButton, $ErrorLabel, $ExitErrorLabel))

# Center the controls
######################
$form.Add_Shown({
        Disable-CloseButton $form

        $form.Controls.SetChildIndex($logoPictureBox, 0)    

        $headingLabel.Left = ($form.ClientSize.Width - $headingLabel.Width) / 1
        $headingLabel.Top = 10

        $instructionLabel.Left = ($form.ClientSize.Width - $instructionLabel.Width) / 1
        $instructionLabel.Top = $headingLabel.Bottom 

        $startButton.Left = ($form.ClientSize.Width - $startButton.Width) / 1.5
        $startButton.Top = $instructionLabel.Bottom + 20

        $progressBar.Left = ($form.ClientSize.Width - $progressBar.Width) / 1.2
        $progressBar.Top = $startButton.Bottom + 30

        $progressLabel.Left = ($form.ClientSize.Width - $progressLabel.Width) / 1.8
        $progressLabel.Top = $progressBar.Bottom + 10

        $completionLabel.Left = ($form.ClientSize.Width - $completionLabel.Width) / 2
        $completionLabel.Top = $progressLabel.Bottom + 20

        $closeButton.Left = ($form.ClientSize.Width - $closeButton.Width) / 1.5
        $closeButton.Top = $completionLabel.Bottom + 50

        $RebootButton.Left = ($form.ClientSize.Width - $RebootButton.Width) / 1.5
        $RebootButton.Top = $completionLabel.Bottom + 20

        $ExitErrorLabel.Left = ($form.ClientSize.Width - $ExitErrorLabel.Width) / 1
        $ExitErrorLabel.Top = $startButton.Bottom + 30

        $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 2
        $ErrorLabel.Top = $instructionLabel.Bottom + 20
       

        # OPTIONAL: auto-start when run with --forced
        if ($forceMode) {
            $form.BeginInvoke([Action] { $startButton.PerformClick() }) | Out-Null
        }
    })

$form.Add_Resize({
        Disable-CloseButton $form
    })

# Starting the Migration Process
#################################
$startButton.Add_Click({
        # Disable the start button to prevent multiple clicks
        $startButton.Enabled = $false
        $progressBar.Visible = $true
        $progressLabel.Visible = $true
        $ErrorLabel.Visible = $false

        # Capture current script location
        Write-Log -Message "Starting prerequisite validation. Version:3.2.5"
        $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Log -Message "Execution context verified: $context"

        $regPath = "HKLM:\SOFTWARE\OpsoleMigrate"
        try {
            if (-not (Test-Path -LiteralPath $regPath)) {
                New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Log -Message "Failed to initialize local configuration store." -isError $true
            return
        }
        
        ############### Progress bar update ##################  
        $progressBar.Value = 1
        $progressLabel.Text = "Progress: 1%"
        [System.Windows.Forms.Application]::DoEvents()

        # ########################################################################
        # Check Migration completion status to prevent rerun on already migrated devices
        # ########################################################################
        $migrationCompleted = (Get-ItemProperty -LiteralPath $regPath -Name "MigrationCompleted" -ErrorAction SilentlyContinue).MigrationCompleted

        if ($migrationCompleted -eq 1) {
            $ErrorLabel.Text = "* This device has already completed migration.`n* Please contact IT Support if a re-run is required."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.3
            $ErrorLabel.Top = $progressLabel.Bottom + 20
            $ErrorLabel.Visible = $true
            $startButton.Enabled = $false
            $closeButton.Visible = $true
            $progressBar.Visible = $false
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            Write-Log -Message "Migration blocked. Device is already marked as migrated."
            return
        }

        # Check if the API is reachable
        #############################################
        Start-Sleep -Seconds 1
        $authSuccess = $false
        $healthResponse = Invoke-ApiWithRetry -Uri $apihealth -Method Get -Headers $apiheaders -TimeoutSec 5 -MaxRetries 3

        if ($healthResponse -and $healthResponse.message -eq "Healthy") {
            $authSuccess = $true
            $script:ApiEndpointUnavailable = $false
        }

        if (-not $authSuccess) {
            $ErrorLabel.Text = "* Failed to connect to the API Endpoint. Contact IT department."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.3
            $ErrorLabel.Top = $progressLabel.Bottom + 20
            $ErrorLabel.Visible = $true
            $startButton.Enabled = $false  
            $closeButton.Visible = $true 
            $progressBar.Visible = $false    
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            Write-Log -Message "Management service endpoint is unreachable. Endpoint: $apidomain" -isError $true
            return     
        }
        else {
            ############### Progress bar update ##################
            $progressBar.Value = 5
            $progressLabel.Text = "Progress: 5%"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            # Check License is available
            ####################################################
            $response = Invoke-ApiWithRetry -Uri $LicenseUrl -Method Get -Headers $apiheaders -TimeoutSec 10 -MaxRetries 3

            if ($response -and $null -ne $response.available_licenses) {
                $licenseValue = $response.available_licenses

                if ($licenseValue -eq 0) {
                    $ErrorLabel.Text = "* No valid license available. Please contact your IT Support."
                    $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.3
                    $ErrorLabel.Top = $progressLabel.Bottom + 20
                    $ErrorLabel.Visible = $true
                    $startButton.Enabled = $false
                    $closeButton.Visible = $true
                    $progressBar.Visible = $false
                    $progressBarcheck.Visible = $false
                    $progressLabel.Visible = $false
                    Write-Log -Message "No active licenses are available." -isError $true
                    return
                }
                else {
                    Write-Log -Message "License validation completed successfully."
                }
            }
            else {
                Write-Log -Message "Failed to retrieve license information. No response received." -isError $true
                $ErrorLabel.Text = "* Failed to connect to the API Server. Please contact your IT Support."
                $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.4
                $ErrorLabel.Top = $progressLabel.Bottom + 20
                $ErrorLabel.Visible = $true
                $startButton.Enabled = $true
                $closeButton.Visible = $true
                $progressBar.Visible = $false
                $progressBarcheck.Visible = $false
                $progressLabel.Visible = $false
                return
            }      
        }

        #Check PreMigration Task
        #########################################
        try {
            $PMTask = Get-ScheduledTask -TaskPath "\Migration\" -TaskName "PreMigrateTaskauto" -ErrorAction SilentlyContinue
            if ($null -ne $PMTask) {
                Unregister-ScheduledTask -TaskPath "\Migration\" -TaskName "PreMigrateTaskauto"  -Confirm:$false 
                Write-Log -Message "Pre-migration preparation completed successfully."
            }
            else {
                # No existing task found
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Log -Message "Failed to process pre-execution task. Error: $errorMessage" -isError $true
        }

        # Retrieve configuration from API and the additonal Config before starting the migration
        #####################################################################################################
            
        $bitlockerBackup = $true
        $lapsPasswordBackup = $true
        $multiProfileRequired = $false
        $deviceCrossForestMigration = $false
        $crossTenant = $false
        $websignin = $false

        Write-Log -Message "Retrieving configurations from management service..."
        $config = Invoke-ApiWithRetry -Uri $configUrl -Method Get -Headers $apiheaders
        $addcfg = Invoke-ApiWithRetry -Uri $addcfgUrl -Method Get -Headers $apiheaders

        if (-not $config) {
            Write-Log -Message "Failed to retrieve configuration from management service." -isError $true
            return
        }

        if (-not $addcfg) {
            Write-Log -Message "Failed to retrieve additional configurations from management service." -isError $true
            return
        }

        if ($null -ne $config.deviceCrossForestMigration) {
            $deviceCrossForestMigration = $config.deviceCrossForestMigration
        }
        if ($null -ne $config.crossTenant) {
            $crossTenant = $config.crossTenant
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$addcfg.bitlockerBackup)) {
            $bitlockerBackup = $addcfg.bitlockerBackup
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$addcfg.lapsPasswordBackup)) {
            $lapsPasswordBackup = $addcfg.lapsPasswordBackup
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$addcfg.multiProfileRequired)) {
            $multiProfileRequired = $addcfg.multiProfileRequired
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$addcfg.multiProfileRequired)) {
            $multiProfileRequired = $addcfg.multiProfileRequired
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$addcfg.Websignin)) {
            $websignin = $addcfg.websignin
        }

        Write-Log -Message "Configurations retrieved successfully from management service"

        ##Checking for all the required parameters in the configuration
        #################################################################
        $missingParams = @()
        if (-not $config -or -not $addcfg) {
            $ErrorLabel.Text = "* Failed to retrieve configuration from management service. Please contact IT Support."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.1
            $ErrorLabel.Top = $progressLabel.Bottom + 20
            $ErrorLabel.Visible = $true
            $startButton.Enabled = $false
            $closeButton.Visible = $true
            $progressBar.Visible = $false
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            Write-Log -Message "Failed to retrieve configuration from management service." -isError $true
            return
        }
        if (-not $config.sourceTenant) {
            $missingParams += "sourceTenant"
        }
        elseif ([string]::IsNullOrWhiteSpace([string]$config.sourceTenant.tenantName)) {
            $missingParams += "sourceTenant.tenantName"
        }

        if ($config.crossTenant -eq $true) {
            if (-not $config.targetTenant) {
                $missingParams += "targetTenant"
            }
            elseif ([string]::IsNullOrWhiteSpace([string]$config.targetTenant.tenantName)) {
                $missingParams += "targetTenant.tenantName"
            }
        }

        if ([string]::IsNullOrWhiteSpace([string]$addcfg.domainLeaveUser)) {
            $missingParams += "domainLeaveUser"
        }

        if ([string]::IsNullOrWhiteSpace([string]$addcfg.domainLeavePassword)) {
            $missingParams += "domainLeavePassword"
        }

        if ([string]::IsNullOrWhiteSpace([string]$addcfg.bitlocker)) {
            $missingParams += "bitlocker"
        }

        # If anything is missing, show generic error
        if ($missingParams.Count -gt 0) {
            $ErrorLabel.Text = "* Migration configuration is missing parameters, Please update and try again."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.1
            $ErrorLabel.Top = $progressBar.Bottom + 20
            $ErrorLabel.Visible = $true
            $closeButton.Visible = $true
            $progressBar.Visible = $false    
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            Write-Log -Message "Configuration missing required parameters: $($missingParams -join ', ')" -isError $true
            return
        }
        
        Write-Log -Message "Configuration validated successfully for tenant: $($config.sourceTenant.tenantName)."

        # Check for presence of .ppkg uploaded in the management service
        ############### Progress bar update ##################
        $progressBar.Value = 10
        $progressLabel.Text = "Progress: 10%"
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Seconds 1
        $ppkgExists = Invoke-ApiWithRetry -Uri $ppkgurl -Method Get -Headers $apiheaders

        if (-not $ppkgExists) {
            Write-Log -Message "Failed to check provisioning package availability from management service." -isError $true
            return
        }
        elseif ($ppkgExists.isPackageAdded -eq $false) {
            Write-Log -Message "Microsoft Entra provisioning package was not found in management service." -isError $true
            $ErrorLabel.Text = "* Provisioning package (.ppkg) file not found.`n * Please contact IT Support."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.4
            $ErrorLabel.Top = $progressLabel.Bottom + 20
            $ErrorLabel.Visible = $true
            $startButton.Enabled = $true
            $closeButton.Visible = $true
            $progressBar.Visible = $false
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            return
        }

        #Check if the system is connected to the charger
        ####################################################
        if (-not (Charger)) {
            $ErrorLabel.Text = "* Charger not connected. Please connect the charger and check again."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.2
            $ErrorLabel.Top = $progressLabel.Bottom + 20
            $ErrorLabel.Visible = $true
            $startButton.Enabled = $true   
            $closeButton.Visible = $false      
            $progressBar.Visible = $false    
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            Write-Log -Message "Power source not connected." -isError $true
            return   
        }
        #check if the system is having any pending reboot or update
        ####################################################
        if (RebootOrUpdatePending) {
            $ErrorLabel.Text = "* System reboot is pending. Please restart the system and try again."
            $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.2
            $ErrorLabel.Top = $progressLabel.Bottom + 20
            $ErrorLabel.Visible = $true
            $RebootButton.Visible = $true  
            $progressBar.Visible = $false    
            $progressBarcheck.Visible = $false
            $progressLabel.Visible = $false
            Write-Log -Message "System restart is pending."
            return  
        }

        ############### Progress bar update ##################
        $progressBar.Value = 15
        $progressLabel.Text = "Progress: 15%"
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Seconds 1

        Write-Log -Message "Prerequisite validation completed successfully."

        ############### Start Migration Process script  ##################
        try {
            # Clicked Start Migrate
            $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
            $Oldhostname = $env:COMPUTERNAME
            $userName = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserName)
            if ([string]::IsNullOrWhiteSpace($userName) -or $userName -notlike "*\*") {
                $OldSAMName = "No User"
            }
            else {
                $SAMName = $userName.Split("\")[1]
                $OldSAMName = $SAMName.ToUpper()
            }
            
            $PrecheckStatus = "True"
            $MigrationStarted = "True"
            $MigrationStartTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
            Write-variables
            $MigrationPercent = "10"
            Write-migstatus

            #Starting of Script
            Write-Log -Message "Migration initiated for device $Oldhostname and user $OldSAMName."
            
            ### Get current logon user SID and write to registry for later use in migration script
            $CurrentLogonUserSid = $null
            if (-not [string]::IsNullOrWhiteSpace($userName) -and $userName -like "*\*") {
                try {
                    $CurrentLogonUserSid = (New-Object System.Security.Principal.NTAccount($userName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Log -Message "Failed to resolve current logon user '$userName'. Error: $($_.Exception.Message)" -isWarning $true
                }

                if (-not [string]::IsNullOrWhiteSpace($CurrentLogonUserSid)) {
                    try {
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\OpsoleMigrate" -Name "CurrentLogonUserSid" -Value $CurrentLogonUserSid -Type String -Force | Out-Null
                    }
                    catch {
                        Write-Log -Message "Failed to store current user context for migration. Error: $($_.Exception.Message)" -isWarning $true
                    }
                }
            }
     
            # Get Tenant Name from API
            ######################################
            $config = Invoke-ApiWithRetry -Uri $configUrl -Method Get -Headers $apiheaders
            $addcfg = Invoke-ApiWithRetry -Uri $addcfgUrl -Method Get -Headers $apiheaders
            if (-not $config -or -not $addcfg) {
                Write-Log -Message "Failed to retrieve configuration from management service." -isError $true
                exitScript -functionName "Getconfigapi"
                return
            }
            
            # Write to Registry
            ######################################
            try {
                $sourceTenantName = $config.sourceTenant.tenantName
                $targetTenantName = $config.targetTenant.tenantName
                $deviceCrossForestMigration = $config.deviceCrossForestMigration
                $crossTenant = $config.crossTenant
                $regPath = "HKLM:\SOFTWARE\OpsoleMigrate"

                Write-Log -Message "Updating Tenant information."

                if (![string]::IsNullOrEmpty($sourceTenantName)) {
                    Set-ItemProperty -Path $regPath -Name "SourceTenantName" -Value $sourceTenantName -Type String -Force
                }

                if (![string]::IsNullOrEmpty($targetTenantName)) {
                    Set-ItemProperty -Path $regPath -Name "TargetTenantName" -Value $targetTenantName -Type String -Force
                }

                if (![string]::IsNullOrEmpty($deviceCrossForestMigration)) {
                    Set-ItemProperty -Path $regPath -Name "DeviceCrossForestMigration" -Value $deviceCrossForestMigration -Type String -Force
                }

                if (![string]::IsNullOrEmpty($crossTenant)) {
                    Set-ItemProperty -Path $regPath -Name "CrossTenant" -Value $crossTenant -Type String -Force
                }

                Write-Log -Message "Tenant information updated successfully."
            }
            catch {
                Write-Log -Message "Failed to update tenant information. Error: $($_.Exception.Message)" -isWarning $true
            }

            Start-Sleep -Seconds 1

            ##################################################################################################################
            ########################## Check Microsoft account connection registry policy ####################################
            ##################################################################################################################
            $accountConnectionPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts"
            $accountConnectionName = "AllowMicrosoftAccountConnection"

            try {
                if (-not (Test-Path -LiteralPath $accountConnectionPath)) {
                    New-Item -Path $accountConnectionPath -Force | Out-Null
                }

                $accountConnectionValue = (Get-ItemProperty -Path $accountConnectionPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $accountConnectionName -ErrorAction SilentlyContinue)

                if ($null -eq $accountConnectionValue) {
                    New-ItemProperty -Path $accountConnectionPath -Name $accountConnectionName -Value 1 -PropertyType DWord -Force | Out-Null
                }
                elseif ($accountConnectionValue -ne 1) {
                    Set-ItemProperty -Path $accountConnectionPath -Name $accountConnectionName -Value 1 | Out-Null
                }
            }
            catch {
                Write-Log -Message "Failed to apply Microsoft account connection policy. Error: $($_.Exception.Message)" -isWarning $true
            }
            
            ############### Progress bar update ##################
            $progressBar.Value = 20
            $progressLabel.Text = "Progress: 20%"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            #################################################################################################
            ########################## FUNCTION: deviceObject Collection ####################################
            #################################################################################################

            [string]$hostname = $env:COMPUTERNAME
            [string]$serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
            $azureAdJoinedLine = dsregcmd.exe /status | Select-String "AzureAdJoined" | Select-Object -First 1
            $domainJoinedLine = dsregcmd.exe /status | Select-String "DomainJoined" | Select-Object -First 1
            [string]$azureAdJoined = if ($azureAdJoinedLine) { $azureAdJoinedLine.ToString().Split(":")[1].Trim() } else { "" }
            [string]$domainjoined = if ($domainJoinedLine) { $domainJoinedLine.ToString().Split(":")[1].Trim() } else { "" }
            
            if ($crossTenant -ne $true -and $azureAdJoined -eq "YES" -and $domainjoined -ne "YES") {
                Write-Log -Message "Device is joined to Entra ID and migration method is AD Joined. Migration cannot continue." -isError $true
                $ErrorLabel.Text = "* Device is joined to Entra ID and migration method is AD Joined.`n * Migration cannot continue."
                $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.4
                $ErrorLabel.Top = $progressLabel.Bottom + 20
                $ErrorLabel.Visible = $true
                $startButton.Enabled = $true
                $closeButton.Visible = $true
                $progressBar.Visible = $false
                $progressBarcheck.Visible = $false
                $progressLabel.Visible = $false
                return
            }

            if ($azureAdJoined -ne "YES" -and $domainjoined -ne "YES") {
                Write-Log -Message "Device is not joined to Entra ID or Active Directory domain. Migration cannot continue." -isError $true
                $ErrorLabel.Text = "* This device is not joined to Entra ID or Active Directory.`n * Migration cannot continue."
                $ErrorLabel.Left = ($form.ClientSize.Width - $ErrorLabel.Width) / 1.4
                $ErrorLabel.Top = $progressLabel.Bottom + 20
                $ErrorLabel.Visible = $true
                $startButton.Enabled = $true
                $closeButton.Visible = $true
                $progressBar.Visible = $false
                $progressBarcheck.Visible = $false
                $progressLabel.Visible = $false
                return
            }
            
            [string]$certPath = "Cert:\LocalMachine\My"
            [string]$intuneIssuer = "Microsoft Intune MDM Device CA"
            [string]$azureIssuer = "MS-Organization-Access"
            [string]$groupTag = $addcfg.groupTag
            [string]$regPath = "HKLM:\SOFTWARE\OpsoleMigrate"
            [string]$autopilotRegPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot"
            [string]$autopilotRegName = "CloudAssignedMdmId"
            $autopilotRegValue = Get-ItemProperty -Path $autopilotRegPath -Name $autopilotRegName -ErrorAction SilentlyContinue
            [bool]$mdm = $false

            Write-Log -Message  "Collecting device information..."

            # Get Intune device certificate
            $intuneCert = Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $intuneIssuer }

            # Get Entra device certificate
            $entraDevicecert = Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $azureIssuer }

            # Get Entra Device ID and Intune device ID
            ############################################

            if ($entraDevicecert) {
                $entraDeviceId = [string](($entraDevicecert | Select-Object -First 1).Subject) -replace '^CN=', ''
            }
            else {
                Write-Log -Message "Device certificate state not available."
            }

            if ($intuneCert) {
                $mdm = $true
                $intuneId = [string](($intuneCert | Select-Object -First 1).Subject) -replace '^CN=', ''
            }
            else {
                Write-Log -Message "Managed device state: Not managed by Microsoft Intune."
                $intuneId = $null
            }

            if ([string]::IsNullOrWhiteSpace($intuneId)) {
                $intuneId = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments\*\DMClient\MS DM Server" -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.EntDMID } |
                Select-Object -ExpandProperty EntDMID -First 1

                if ($intuneId) {
                    $mdm = $true
                }
            }

            # Get Autopilot ID Locally
            ############################################
            $autopilotId = $null
            if ($autopilotRegValue) {
                try {
                    $autopilotId = Get-ItemPropertyValue -Path "$autopilotRegPath\EstablishedCorrelations" -Name "ZtdRegistrationId" -ErrorAction Stop
                }
                catch {
                    Write-Log -Message "Device provisioning identifier not available."
                }
            }
            else {
                #"Autopilot registration not found locally"
            }

            # Get Autopilot ID from Windows Autopilot devices
            ############################################
            try {
                $encodedSerial = [System.Uri]::EscapeDataString($serialNumber)
                $autopilotResponse = Invoke-ApiWithRetry -Method Get -Uri "https://$apidomain/client/autopilot?serialNumber=$encodedSerial" -Headers $apiheaders

                if ($autopilotResponse -and $autopilotResponse.status -eq $true) {
                    if ($autopilotResponse.data -and -not [string]::IsNullOrWhiteSpace($autopilotResponse.data.id)) {
                        $autopilotId = $autopilotResponse.data.id
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($autopilotResponse.message)) {
                        Write-Log -message $autopilotResponse.message 
                    }
                }
                elseif ($autopilotResponse -and -not [string]::IsNullOrWhiteSpace($autopilotResponse.message)) {
                    Write-Log -message $autopilotResponse.message 
                }
                else {
                    Write-Log -Message "Autopilot lookup failed. No response received."
                }
            }
            catch {
                Write-Log -Message "Failed to query Autopilot device record. Error: $($_.Exception.Message)" -isWarning $true
            }

            Write-Log -Message "Device information collected successfully."

            #################################################################################################
            ########################## Get Local Administrator Password ####################################
            #################################################################################################
            if ($lapsPasswordBackup -and -not [string]::IsNullOrWhiteSpace($entraDeviceId) -and -not [string]::IsNullOrWhiteSpace($intuneId)) {
                Write-Log -Message "Credential backup enabled. Retrieving required details..."
                try {
                    $body = @{
                        entraDeviceId = $entraDeviceId
                        serialNumber  = $serialNumber
                    } | ConvertTo-Json -Depth 5


                    $lapsResponse = Invoke-ApiWithRetry -Method Post -Uri "https://$apidomain/client/laps" -Headers $apiheaders -Body $body

                    if ($lapsResponse -and $lapsResponse.status -eq $false) {
                        $lapsError = if (-not [string]::IsNullOrWhiteSpace($lapsResponse.message)) { $lapsResponse.message } else { "Failed to process local administrator password information." }
                        Write-Log -Message "Credential backup status: $lapsError"
                    }
                    elseif (-not $lapsResponse) {
                        Write-Log -Message "Failed to process local administrator password information. No response received." 
                    }
                    elseif ($lapsResponse -and $lapsResponse.status -eq $true) {
                        Write-Log -Message "Credential backup details retrieved successfully."
                    }
                }
                catch {
                    Write-Log -Message "Failed to process local administrator password information. Error: $($_.Exception.Message)"
                }
            }
            else {
                Write-Log -Message "Credential backup skipped : Not enabled or device not managed by Intune."
            }

            #################################################################################################
            ########################## Get Intune Primary User ##############################################
            #################################################################################################
            $primaryUserId = $null

            if ($crossTenant -eq $true) {
                Write-Log -Message "Cross-tenant migration detected. Skipping Intune primary user lookup."
            }
            elseif (-not [string]::IsNullOrWhiteSpace($intuneId)) {
                Write-Log -Message "Retrieving Intune user details..."
                try {
                    $encodedIntuneId = [System.Uri]::EscapeDataString($intuneId)
                    $primaryUserResponse = Invoke-ApiWithRetry -Method Get -Uri "https://$apidomain/client/user-id?intuneDeviceId=$encodedIntuneId" -Headers $apiheaders

                    if ($primaryUserResponse -and $primaryUserResponse.status -eq $true) {
                        if ($primaryUserResponse.data -and -not [string]::IsNullOrWhiteSpace($primaryUserResponse.data.id)) {
                            $primaryUserId = $primaryUserResponse.data.id
                            Write-Log -Message "Intune user details retrieved successfully."
                        }
                        elseif (-not [string]::IsNullOrWhiteSpace($primaryUserResponse.message)) {
                            Write-Log -message $primaryUserResponse.message -isWarning $true
                        }
                    }
                    elseif ($primaryUserResponse -and -not [string]::IsNullOrWhiteSpace($primaryUserResponse.message)) {
                        Write-Log -message $primaryUserResponse.message -isError $true
                    }
                    else {
                        Write-Log -Message "Failed to retrieve primary user details." -isError $true
                    }
                }
                catch {
                    Write-Log -Message "Failed to retrieve primary user details. Error: $($_.Exception.Message)" -isError $true
                }
            }
            else {
                Write-Log -Message "Primary user lookup skipped : Device not managed by Intune."
            }

            # Check if device is domain joined
            #########################################
            $localDomain = $null
            if ($domainjoined -eq "YES") {
                try {
                    $localDomain = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Domain" -ErrorAction Stop
                }
                catch {
                    Write-Log -Message "Failed to read local domain information.Error: $($_.Exception.Message)"
                }
            }

            $pc = @{
                hostname      = $hostname
                serialNumber  = $serialNumber
                azureAdJoined = $azureAdJoined
                domainJoined  = $domainjoined
                intuneId      = $intuneId
                entraDeviceId = $entraDeviceId
                autopilotId   = $autopilotId
                groupTag      = $groupTag
                mdm           = $mdm
                localDomain   = $localDomain
                primaryUser   = $primaryUserId

            }
            # Write device object to registry
            Write-Log -Message "Updating device information..."
            $regWriteErrors = @()
            foreach ($x in $pc.Keys) {
                $pcName = "OLD_$($x)"
                $pcValue = $pc[$x]
                if (![string]::IsNullOrEmpty($pcValue)) {
                    try {
                        Set-ItemProperty -Path $regPath -Name $pcName -Value $pcValue -Type String -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        $regWriteErrors += "$pcName : $($_.Exception.Message)"
                    }
                }
            }
            if ($regWriteErrors.Count -eq 0) {
                Write-Log -Message "Device information updated successfully."
            }
            else {
                Write-Log -Message "Failed to update the following Device information entries:" -isError $true
                foreach ($entryError  in $regWriteErrors) {
                    Write-Log -Message "Device information update failed: $entryError" -isError $true
                }
                exitScript -functionName "StoredeviceDetails"
                return
            }
            
            # Function : Send the Variables to API Server
            $oldlocalDomain = $localDomain
            $OldazureAdJoined = $azureAdJoined
            $Olddomainjoined = $domainjoined
            $OldintuneId = $intuneId
            $OldentraDeviceId = $entraDeviceId
            $OldautopilotId = $autopilotId
            Write-variables

            if (
                -not [string]::IsNullOrWhiteSpace($entraDeviceId) -and
                $deviceCrossForestMigration -ne $true -and
                $crossTenant -ne $true
            ) {
                Write-Group
            }

            Write-Log -Message "Device join state synchronized: Domain : $oldlocalDomain, Azure AD Joined : $OldazureAdJoined, Domain Joined : $Olddomainjoined "
            Write-Log -Message "Device identifiers synchronized: Intune ID : $OldintuneId, Entra Device ID : $OldentraDeviceId, Autopilot ID : $OldautopilotId"

            ############### Progress bar update ##################
            $progressBar.Value = 25
            $progressLabel.Text = "Progress: 25% - Initialization"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            ############################################################################################################
            ##################### Stop Windows Serch Service and Disable #########################################
            ############################################################################################################

            try {
                Stop-Service -Name "WSearch" -Force -ErrorAction Stop
            }
            catch {
                # Write-Log -Message "Background indexing service stop could not be completed. Error: $($_.Exception.Message)" -isWarning $true
            }

            try {
                Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction Stop
            }
            catch {
                Write-Log -Message "Background indexing service preparation could not be completed. Error: $($_.Exception.Message)" -isWarning $true
            }

            #############################################################
            # Create local administrator account for migration operations 
            ################################################################

            $migrateAdmin = "Opsolemigrateadmin"
            $adminPW = generatePassword
            $securePassword = $adminPW
            $adminGroup = Get-CimInstance -Query "Select * From Win32_Group Where LocalAccount = True And SID = 'S-1-5-32-544'"
            $adminGroupName = $adminGroup.Name

            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPW)
            try {
                $adminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }

            if (-not [string]::IsNullOrEmpty($adminPassword)) {
                Write-variables
            }
            $adminPassword = $null

            # Ensure migrateAdmin account exists and is a member of local administrators group for domain leave operations

            if (-not (Get-LocalUser -Name $migrateAdmin -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $migrateAdmin -Password $adminPW -PasswordNeverExpires *> $null
            }
            if (-not (Get-LocalGroupMember -Group $adminGroupName -Member $migrateAdmin -ErrorAction SilentlyContinue)) {
                Add-LocalGroupMember -Group $adminGroupName -Member $migrateAdmin *> $null
            }

            ############################################################################################################
            ##################### Collect ALL local user profiles to registry  #########################################
            ############################################################################################################

            Write-Log -Message "Collecting user profile information..."

            try {
                $rootKey = "HKLM:\SOFTWARE\OpsoleMigrate"
                $profilesRoot = Join-Path $rootKey "Profiles"
                $profileList = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

                $eligibleCount = 0
                $collectedCount = 0
                $skippedCount = 0
                $errorCount = 0

                if (-not (Test-Path -LiteralPath $profilesRoot)) {
                    New-Item -Path $profilesRoot -Force -ErrorAction Stop | Out-Null
                }

                $excludeSids = @("S-1-5-18", "S-1-5-19", "S-1-5-20")
                $excludeLeaf = @("Default", "Default User", "Public", "All Users")

                $keys = Get-ChildItem -LiteralPath $profileList -ErrorAction Stop

                foreach ($k in $keys) {

                    $sidRaw = $k.PSChildName

                    # Fast skips
                    if ($excludeSids -contains $sidRaw) { $skippedCount++; continue }
                    if ($sidRaw -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -and $sidRaw -notmatch '^S-1-12-1-\d+(-\d+){3,}$') { $skippedCount++; continue }

                    $profileRegKey = Join-Path $profileList $sidRaw
                    $bakRegKey = "$profileRegKey.bak"

                    # Read both SID and SID.bak (if present)
                    $primaryData = $null
                    $bakData = $null
                    if (Test-Path -LiteralPath $profileRegKey) {
                        try { $primaryData = Get-ItemProperty -LiteralPath $profileRegKey -ErrorAction Stop } catch { $primaryData = $null }
                    }
                    if (Test-Path -LiteralPath $bakRegKey) {
                        try { $bakData = Get-ItemProperty -LiteralPath $bakRegKey -ErrorAction Stop } catch { $bakData = $null }
                    }

                    if (-not $primaryData -and -not $bakData) { $skippedCount++; continue }

                    # Pick effective key/data:
                    # Prefer non-TEMP profile path that exists on disk.
                    $effectiveData = $null

                    if ($primaryData -and $bakData) {
                        $pPath = [string]$primaryData.ProfileImagePath
                        $bPath = [string]$bakData.ProfileImagePath

                        $pIsTemp = (-not [string]::IsNullOrWhiteSpace($pPath)) -and ($pPath -match '\\Users\\TEMP($|\.|\\)')
                        $bIsTemp = (-not [string]::IsNullOrWhiteSpace($bPath)) -and ($bPath -match '\\Users\\TEMP($|\.|\\)')

                        $pGood = (-not $pIsTemp) -and (Test-Path -LiteralPath $pPath -PathType Container)
                        $bGood = (-not $bIsTemp) -and (Test-Path -LiteralPath $bPath -PathType Container)

                        if ($bGood -and -not $pGood) {
                            $effectiveData = $bakData
                        }
                        elseif ($pGood) {
                            $effectiveData = $primaryData
                        }
                        else {
                            # Safer fallback when both are weak
                            $effectiveData = $bakData
                        }
                    }
                    elseif ($primaryData) {
                        $effectiveData = $primaryData
                    }
                    else {
                        $effectiveData = $bakData
                    }

                    # Read profile properties from effective data
                    $profilePath = [string]$effectiveData.ProfileImagePath
                    $state = 0
                    if ($effectiveData.PSObject.Properties.Name -contains "State") { $state = [int]$effectiveData.State }

                    # Validate profile path
                    if ([string]::IsNullOrWhiteSpace($profilePath)) { $skippedCount++; continue }
                    if (-not (Test-Path -LiteralPath $profilePath -PathType Container)) { $skippedCount++; continue }

                    $leaf = Split-Path -Path $profilePath -Leaf
                    if ($excludeLeaf -contains $leaf) { $skippedCount++; continue }

                    # Skip TEMP profiles (State bit 256) and explicit TEMP path
                    if (($state -band 256) -ne 0) { $skippedCount++; continue }
                    if ($profilePath -match '\\Users\\TEMP($|\.|\\)') { $skippedCount++; continue }

                    # Skip mandatory profiles
                    if (Test-Path -LiteralPath (Join-Path $profilePath "NTUSER.MAN")) { $skippedCount++; continue }

                    # Translate SID -> NTAccount (best-effort, do not skip on failure)
                    $ntAccount = ""
                    $samName = ""
                    try {
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidRaw)
                        $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        $samName = ($ntAccount -split '\\')[-1]
                    }
                    catch {
                        # keep empty values; Entra lookup uses OLD_SID later
                    }

                    $eligibleCount++

                    try {
                        $profileStorageKey = Join-Path $profilesRoot $sidRaw
                        if (-not (Test-Path -LiteralPath $profileStorageKey)) {
                            New-Item -Path $profileStorageKey -Force -ErrorAction Stop | Out-Null
                        }

                        # Write OLD_* (idempotent)
                        Set-ItemProperty -LiteralPath $profileStorageKey -Name "OLD_userName"    -Value $ntAccount   -Type String -Force -ErrorAction Stop | Out-Null
                        Set-ItemProperty -LiteralPath $profileStorageKey -Name "OLD_SAMName"     -Value $samName     -Type String -Force -ErrorAction Stop | Out-Null
                        Set-ItemProperty -LiteralPath $profileStorageKey -Name "OLD_profilePath" -Value $profilePath -Type String -Force -ErrorAction Stop | Out-Null
                        Set-ItemProperty -LiteralPath $profileStorageKey -Name "OLD_SID"         -Value $sidRaw      -Type String -Force -ErrorAction Stop | Out-Null

                        # Keep OLD_upn placeholder for consistency
                        try {
                            $null = Get-ItemPropertyValue -LiteralPath $profileStorageKey -Name "OLD_upn" -ErrorAction Stop
                        }
                        catch {
                            Set-ItemProperty -LiteralPath $profileStorageKey -Name "OLD_upn" -Value "" -Type String -Force -ErrorAction Stop | Out-Null
                        }

                        # Init control fields once
                        $status = $null
                        try { $status = Get-ItemPropertyValue -LiteralPath $profileStorageKey -Name "Status" -ErrorAction Stop } catch { $status = $null }
                        if ([string]::IsNullOrWhiteSpace($status)) {
                            Set-ItemProperty -LiteralPath $profileStorageKey -Name "Status"       -Value "PendingEntraLookup" -Type String -Force -ErrorAction Stop | Out-Null
                            Set-ItemProperty -LiteralPath $profileStorageKey -Name "AttemptCount" -Value 0 -Type DWord -Force -ErrorAction Stop | Out-Null
                            Set-ItemProperty -LiteralPath $profileStorageKey -Name "LastError"    -Value "" -Type String -Force -ErrorAction Stop | Out-Null
                        }

                        Set-ItemProperty -LiteralPath $profileStorageKey -Name "UpdatedAt" -Value (Get-Date).ToString("s") -Type String -Force -ErrorAction Stop | Out-Null

                        $collectedCount++
                    }
                    catch {
                        $errorCount++
                        if ($errorCount -le 3) {
                            Write-Log -Message "User profile collection failed for SID '$sidRaw'. Error: $($_.Exception.Message)" -isWarning $true
                        }
                        continue
                    }
                }

                Write-Log -Message "User profile information collected and updated successfully. Eligible=$eligibleCount"

                if ($eligibleCount -gt 0 -and $collectedCount -eq 0) {
                    Write-Log -Message "Eligible profiles were detected, but no profiles were collected successfully. Eligible profiles: $eligibleCount."
                    exitScript -functionName "UserProfileCollection"
                    return
                }
            }
            catch {
                Write-Log -Message "Failure occurred during user profile collection. Error: $($_.Exception.Message)" -isError $true
                exitScript -functionName "UserProfileCollection"
                return
            }

            ############### Progress bar update ##################
            $progressBar.Value = 35
            $progressLabel.Text = "Progress: 35% - Initialization"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            ############################################################################################################
            ##################### Entra mapping for collected User Profiles ###########################################
            ############################################################################################################

            Write-Log -Message "Retrieving user identity details..."

            try {
                $rootKey = "HKLM:\SOFTWARE\OpsoleMigrate"
                $profilesRoot = Join-Path $rootKey "Profiles"

                # Feature flag gate + root check (silent)
                if (-not (Test-Path -LiteralPath $profilesRoot)) {
                    throw "Path not found: $profilesRoot. User profile Entra mapping cannot proceed."
                }

                $MaxAttempts = 8
                # Counters
                $processedCount = 0
                $readyCount = 0
                $notFoundCount = 0
                $missingSidCount = 0
                $failedCount = 0
                $skippedMaxCount = 0

                # Low-noise sampled logs
                $maxGraphLogs = 3
                $maxRegistryLogs = 3
                $maxUnhandledLogs = 2
                $loggedGraph = 0
                $loggedRegistry = 0
                $loggedUnhandled = 0

                function Set-ProfileStatus {
                    param(
                        [Parameter(Mandatory)][string]$KeyPath,
                        [Parameter(Mandatory)][string]$Status,
                        [Parameter()][string]$LastError = ""
                    )
                    # Best-effort: keep deterministic state
                    Set-ItemProperty -LiteralPath $KeyPath -Name "Status"    -Value $Status    -Type String -Force -ErrorAction Stop | Out-Null
                    Set-ItemProperty -LiteralPath $KeyPath -Name "LastError" -Value $LastError -Type String -Force -ErrorAction Stop | Out-Null
                    Set-ItemProperty -LiteralPath $KeyPath -Name "UpdatedAt" -Value (Get-Date).ToString("s") -Type String -Force -ErrorAction Stop | Out-Null
                }

                function Clear-NewFields {
                    param([Parameter(Mandatory)][string]$KeyPath)
                    foreach ($name in @("NEW_upn", "NEW_entraUserId", "NEW_SAMName", "NEW_SID")) {
                        Set-ItemProperty -LiteralPath $KeyPath -Name $name -Value "" -Type String -Force -ErrorAction Stop | Out-Null
                    }
                }

                function Write-NewFields {
                    param(
                        [Parameter(Mandatory)][string]$KeyPath,
                        [Parameter()][string]$Upn,
                        [Parameter()][string]$EntraUserId,
                        [Parameter()][string]$Sam,
                        [Parameter()][string]$EntraSid
                    )
                    if ([string]::IsNullOrEmpty($Upn)) { $Upn = "" }
                    if ([string]::IsNullOrEmpty($EntraUserId)) { $EntraUserId = "" }
                    if ([string]::IsNullOrEmpty($Sam)) { $Sam = "" }
                    if ([string]::IsNullOrEmpty($EntraSid)) { $EntraSid = "" }

                    Set-ItemProperty -LiteralPath $KeyPath -Name "NEW_upn"         -Value $Upn        -Type String -Force -ErrorAction Stop | Out-Null
                    Set-ItemProperty -LiteralPath $KeyPath -Name "NEW_entraUserId" -Value $EntraUserId -Type String -Force -ErrorAction Stop | Out-Null
                    Set-ItemProperty -LiteralPath $KeyPath -Name "NEW_SAMName"     -Value $Sam        -Type String -Force -ErrorAction Stop | Out-Null
                    Set-ItemProperty -LiteralPath $KeyPath -Name "NEW_SID"         -Value $EntraSid   -Type String -Force -ErrorAction Stop | Out-Null
                }

                $profileKeys = Get-ChildItem -LiteralPath $profilesRoot -ErrorAction Stop

                foreach ($k in $profileKeys) {

                    $oldSid = $k.PSChildName

                    # Only process AD-style and Entra-style user SIDs

                    if ([string]::IsNullOrWhiteSpace($oldSid)) { continue }
                    if ($oldSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -and $oldSid -notmatch '^S-1-12-1-\d+(-\d+){3,}$') { continue }

                    # Build a deterministic HKLM:\ path (instead of using PSPath)
                    $profileKeyPath = Join-Path $profilesRoot $oldSid

                    # Optional (safe): keep or remove. It's redundant because $k came from Get-ChildItem.
                    if (-not (Test-Path -LiteralPath $profileKeyPath)) { continue }


                    try {
                        # Read Status + AttemptCount
                        $status = $null
                        $attempt = 0
                        try { $status = Get-ItemPropertyValue -LiteralPath $profileKeyPath -Name "Status"        -ErrorAction Stop } catch { $status = $null }
                        try { $attempt = Get-ItemPropertyValue -LiteralPath $profileKeyPath -Name "AttemptCount"  -ErrorAction Stop } catch { $attempt = 0 }

                        if (($status -eq "EntraLookupFailed") -and ($attempt -ge $MaxAttempts)) {
                            $skippedMaxCount++
                            continue
                        }

                        # Increment attempt count (must persist)
                        $attempt++
                        try {
                            Set-ItemProperty -LiteralPath $profileKeyPath -Name "AttemptCount" -Value $attempt -Type DWord -Force -ErrorAction Stop | Out-Null
                        }
                        catch {
                            $failedCount++
                            $processedCount++

                            if ($loggedRegistry -lt $maxRegistryLogs) {
                                $loggedRegistry++
                                Write-Log -Message "User identity mapping attempt update failed for SID '$oldSid'. Error: $($_.Exception.Message)" -isWarning $true
                            }

                            # Best-effort status mark (do not loop forever)
                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError ("AttemptCount write failed: " + $_.Exception.Message) } catch { }
                            continue
                        }
                    
                        # Proxy lookup by OLD SID
                        $userResponse = $null
                        try {
                            $encodedSid = [System.Uri]::EscapeDataString($oldSid)
                            $userResponse = Invoke-ApiWithRetry -Method Get -Uri "https://$apidomain/client/user-details?sid=$encodedSid&deviceCrossForestMigration=$deviceCrossForestMigration&crossTenant=$crossTenant" -Headers $apiheaders
                        }
                        catch {
                            $failedCount++
                            $processedCount++

                            if ($loggedGraph -lt $maxGraphLogs) {
                                $loggedGraph++
                                Write-Log -Message "User identity mapping request failed for SID '$oldSid'. Error: $($_.Exception.Message)" -isWarning $true
                            }

                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError ("API call failed: " + $_.Exception.Message) } catch { }
                            continue
                        }

                        # Normalize proxy response to existing shape
                        $values = @()

                        if ($userResponse -and $userResponse.status -eq $true) {
                            if ($userResponse.data) {
                                $values = @(
                                    [PSCustomObject]@{
                                        userPrincipalName  = $userResponse.data.userPrincipalName
                                        id                 = $userResponse.data.id
                                        securityIdentifier = $userResponse.data.securityIdentifier
                                    }
                                )
                            }
                        }
                        elseif ($userResponse -and -not [string]::IsNullOrWhiteSpace($userResponse.message)) {
                            $failedCount++
                            $processedCount++

                            if ($loggedGraph -lt $maxGraphLogs) {
                                $loggedGraph++
                                Write-Log -Message "User identity mapping request failed for SID '$oldSid'. Message: $($userResponse.message)" -isWarning $true
                            }

                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError $userResponse.message } catch { }
                            continue
                        }

                        #explicit no-response handling to avoid silent failures
                        if (-not $userResponse) {
                            $failedCount++
                            $processedCount++

                            if ($loggedGraph -lt $maxGraphLogs) {
                                $loggedGraph++
                                Write-Log -Message "User identity mapping returned no response for SID '$oldSid'." -isWarning $true
                            }

                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError "API returned no response." } catch { }
                            continue
                        }


                        # No match => deterministic clear + NotEligible
                        if ($values.Count -lt 1) {
                            try {
                                Clear-NewFields -KeyPath $profileKeyPath
                                Set-ProfileStatus -KeyPath $profileKeyPath -Status "NotEligibleHybridSync" -LastError "No Entra user matched onPremisesSecurityIdentifier"
                            }
                            catch {
                                $failedCount++
                                $processedCount++

                                if ($loggedRegistry -lt $maxRegistryLogs) {
                                    $loggedRegistry++
                                    Write-Log -Message "User identity mapping status update failed for SID '$oldSid'. Error: $($_.Exception.Message)" -isWarning $true
                                }

                                try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError ("Failed to clear/set status: " + $_.Exception.Message) } catch { }
                                continue
                            }

                            $notFoundCount++
                            $processedCount++
                            continue
                        }

                        $u = $values[0]
                        if (-not $u) {
                            $failedCount++
                            $processedCount++
                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError "API response contained null user object" } catch { }
                            continue
                        }

                        $newUpn = $null
                        $newEntraUserId = $null
                        $newEntraSid = $null
                        try { $newUpn = $u.userPrincipalName } catch { $newUpn = $null }
                        try { $newEntraUserId = $u.id } catch { $newEntraUserId = $null }
                        try { $newEntraSid = $u.securityIdentifier } catch { $newEntraSid = $null }  # keep as-is

                        if ([string]::IsNullOrWhiteSpace($newEntraUserId)) {
                            $failedCount++
                            $processedCount++
                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError "API returned user without id" } catch { }
                            continue
                        }

                        $newSam = ""
                        if (-not [string]::IsNullOrWhiteSpace($newUpn)) {
                            $newSam = ($newUpn.Split("@")[0])
                        }

                        try {
                            Write-NewFields -KeyPath $profileKeyPath -Upn $newUpn -EntraUserId $newEntraUserId -Sam $newSam -EntraSid $newEntraSid
                        }
                        catch {
                            $failedCount++
                            $processedCount++

                            if ($loggedRegistry -lt $maxRegistryLogs) {
                                $loggedRegistry++
                                Write-Log -Message "Failed to store user identity mapping for SID '$oldSid'. Error: $($_.Exception.Message)" -isWarning $true
                            }

                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError ("Registry write failed: " + $_.Exception.Message) } catch { }
                            continue
                        }

                        # Status decision
                        if ([string]::IsNullOrEmpty($newEntraSid)) {
                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraSidMissing" -LastError "Entra user found but securityIdentifier is empty" } catch { }
                            $missingSidCount++
                        }
                        else {
                            try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "ReadyForMigration" -LastError "" } catch { }
                            $readyCount++
                        }

                        $processedCount++
                    }
                    catch {
                        $failedCount++
                        $processedCount++

                        if ($loggedUnhandled -lt $maxUnhandledLogs) {
                            $loggedUnhandled++
                            Write-Log -Message "Unhandled failure occurred during user identity mapping for SID '$oldSid'. Error: $($_.Exception.Message)" -isWarning $true
                        }

                        try { Set-ProfileStatus -KeyPath $profileKeyPath -Status "EntraLookupFailed" -LastError ("Unhandled error: " + $_.Exception.Message) } catch { }
                        continue
                    }
                }

                if ($readyCount -lt 1) {
                    Write-Log -Message "No eligible user profiles found." -isError $true
                    exitScript -functionName "EntraFetchUserDetails"
                    return
                }

                Write-Log -Message "User identity details prepared successfully. Ready profiles: $readyCount."

            }
            catch {
                Write-Log -Message "Failed to prepare user identity details. Error: $($_.Exception.Message)" -isError $true
                exitScript -functionName "EntraFetchUserDetails"
                return
            }  

            ############### Progress bar update ##################
            $progressBar.Value = 40
            $progressLabel.Text = "Progress: 40% - Verification"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            ############################################################################################################
            ##################### Restrict to current logon profile when multi-profile is disabled ####################
            ############################################################################################################

            if (-not $multiProfileRequired) {
                Write-Log -Message "Single-profile migration mode detected. Proceeding with migration."

                $rootKey = "HKLM:\SOFTWARE\OpsoleMigrate"
                $profilesRoot = Join-Path $rootKey "Profiles"
                $currentLogonUserSid = $null
                $profileKeys = @()
                $matchedReadyProfile = $false
                $skippedNonCurrentCount = 0

                try {
                    $currentLogonUserSid = Get-ItemPropertyValue -LiteralPath $rootKey -Name "CurrentLogonUserSid" -ErrorAction Stop
                }
                catch {
                    Write-Log -Message "Primary user context not available. Proceeding with multi-profile migration." -isWarning $true
                }

                if (-not [string]::IsNullOrWhiteSpace($currentLogonUserSid) -and (Test-Path -LiteralPath $profilesRoot)) {
                    $profileKeys = Get-ChildItem -LiteralPath $profilesRoot -ErrorAction SilentlyContinue

                    foreach ($k in $profileKeys) {
                        $profileKeyPath = $k.PSPath
                        $oldSid = $null
                        $status = $null

                        try { $oldSid = Get-ItemPropertyValue -LiteralPath $profileKeyPath -Name "OLD_SID" -ErrorAction Stop } catch { continue }
                        try { $status = Get-ItemPropertyValue -LiteralPath $profileKeyPath -Name "Status" -ErrorAction Stop } catch { $status = $null }

                        if ($oldSid -eq $currentLogonUserSid -and $status -eq "ReadyForMigration") {
                            $matchedReadyProfile = $true
                            break
                        }
                    }

                    if ($matchedReadyProfile) {
                        foreach ($k in $profileKeys) {
                            $profileKeyPath = $k.PSPath
                            $oldSid = $null
                            $status = $null

                            try { $oldSid = Get-ItemPropertyValue -LiteralPath $profileKeyPath -Name "OLD_SID" -ErrorAction Stop } catch { continue }
                            try { $status = Get-ItemPropertyValue -LiteralPath $profileKeyPath -Name "Status" -ErrorAction Stop } catch { $status = $null }

                            if ($status -eq "ReadyForMigration" -and $oldSid -ne $currentLogonUserSid) {
                                try {
                                    Set-ItemProperty -LiteralPath $profileKeyPath -Name "Status" -Value "SkippedNonCurrentProfile" -Type String -Force -ErrorAction Stop | Out-Null
                                    Set-ItemProperty -LiteralPath $profileKeyPath -Name "LastError" -Value "Skipped because multi-profile migration is disabled." -Type String -Force -ErrorAction Stop | Out-Null
                                    Set-ItemProperty -LiteralPath $profileKeyPath -Name "UpdatedAt" -Value (Get-Date).ToString("s") -Type String -Force -ErrorAction Stop | Out-Null
                                    $skippedNonCurrentCount++
                                }
                                catch {
                                    Write-Log -Message "Failed to mark non-current profile as skipped for SID '$oldSid'. Error: $($_.Exception.Message)" -isWarning $true
                                }
                            }
                        }

                        Write-Log -Message "Profile migration applied successfully for user '$userName'."
                    }
                    else {
                        Write-Log -Message "Not eligible for single-profile migration. Proceeding with multi-profile migration." -isWarning $true
                    }
                }
                else {
                    Write-Log -Message "Single-profile mode requested, but primary user context could not be resolved. Proceeding with multi-profile migration." -isWarning $true
                }
            }

            ######################################################################################################################
            ########################## Get BitLocker recovery keys if enabled ####################################################
            ######################################################################################################################

            if ($bitlockerBackup -eq $true) {
                Write-Log -Message "Encryption backup enabled. Retrieving required details..."
                try {
                    $volumes = Get-BitLockerVolume
                    $bitlockerEnabledVolumes = $volumes | Where-Object { $_.ProtectionStatus -eq 'On' }            
                    if ($bitlockerEnabledVolumes) {
                        foreach ($volume in $bitlockerEnabledVolumes) {
                            $keyProtectors = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }                    
                            if ($keyProtectors) {
                                foreach ($keyProtector in $keyProtectors) {
                                    # Log the recovery password
                                    $recoveryPassword = $keyProtector.RecoveryPassword
                                    Write-Log -Message "Encryption details retrieved successfully for $($volume.MountPoint):"
                                    Write-bitlockerkey -Message "Recovery password for $($volume.MountPoint): $recoveryPassword"
                                }
                            }                        
                        }
                    }
                    else {
                        Write-Log -Message "No encrypted volumes detected on this device."
                    }
                }
                catch {
                    $message = $_.Exception.Message
                    Write-Log -Message "Failed to access encryption information. Error: $message" -isWarning $true
                }
            }
            else {
                Write-Log -Message "Encryption backup not enabled."
            }

            ############################################################################################################
            # Validate target Entra profile does not already exist before continuing migration
            ############################################################################################################

            $profileListRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            foreach ($profileKey in Get-ChildItem -LiteralPath $profilesRoot -ErrorAction SilentlyContinue) {
                $status = Get-ItemPropertyValue -LiteralPath $profileKey.PSPath -Name "Status" -ErrorAction SilentlyContinue

                if ($status -ne "ReadyForMigration") {
                    continue
                }
                $newSid = Get-ItemPropertyValue -LiteralPath $profileKey.PSPath -Name "NEW_SID" -ErrorAction SilentlyContinue
                $newRegPath = Join-Path $profileListRoot $newSid

                if (Test-Path -LiteralPath $newRegPath) {
                    $backupName = "newsidbak.$(Get-Date -Format 'yyyyMMddHHmmss')"
                    Write-Log -Message "[PreValidation] Target ProfileList key already exists for SID $newSid. Renaming existing target key." -isWarning $true
                    Rename-Item -LiteralPath $newRegPath -NewName $backupName -Force
                }
            }

            ##########################################################################################        
            ################################ Get KMS activation status ###############################
            ########################################################################################### 
            $regPath = "HKLM:\SOFTWARE\OpsoleMigrate"

            try {
                $licenseStatus = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" |
                Select-Object -First 1

                if ($licenseStatus.ProductKeyChannel -eq "Volume:GVLK") {
                    New-ItemProperty -Path $regPath -Name "IsKmsClient" -Value 1 -PropertyType DWord -Force | Out-Null
                    Write-Log -Message "Windows activation method is KMS." -isWarning $true
                }
                else {
                    New-ItemProperty -Path $regPath -Name "IsKmsClient" -Value 0 -PropertyType DWord -Force | Out-Null
                    Write-Log -Message "Windows activation method: $($licenseStatus.ProductKeyChannel)."
                }
            }
            catch {
                Write-Log -Message "Failed to determine Windows activation method. Error: $($_.Exception.Message)" -isWarning $true
            }
  
            ##########################################################################################
            ############### Validating and clearing device management enrollments ##################
            #########################################################################################
            
            Start-Sleep -Seconds 1
            Write-Log -Message "Validating and cleaning device management enrollments..."

            # Remove MDM certificate if present
            if ($pc.mdm -eq $true) {
                try {
                    Get-ChildItem -Path "Cert:\LocalMachine\My" |
                    Where-Object { $_.Issuer -match "Microsoft Intune MDM Device CA" } |
                    Remove-Item -Force
                    #"MDM certificate removed successfully."
                }
                catch {
                    Write-Log -Message "Failed to remove MDM certificate: $($_.Exception.Message)" -isWarning $true
                }
            }
            else {
                # "MDM certificate not present. Skipping MDM Certificate removal"
            }

            ######################################################################################################################
            ################################## Remove MDM enrollment if present ##################################################
            ######################################################################################################################
            if ($pc.mdm -eq $true) {
                $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
                $enrollments = Get-ChildItem -Path $enrollmentPath -ErrorAction SilentlyContinue
                $removedEnrollments = @()
                foreach ($enrollment in $enrollments) {
                    try {
                        $object = Get-ItemProperty -Path Registry::$enrollment -ErrorAction Stop
                        $enrollId = $object.PSChildName
                        $enrollPath = Join-Path $enrollmentPath $enrollId

                        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL" -ErrorAction SilentlyContinue
                        if ($key) {
                            # Remove main enrollment key
                            if (Test-Path $enrollPath) {
                                Remove-Item -Path $enrollPath -Recurse -Force -ErrorAction SilentlyContinue
                            }
                            # Remove additional registry paths
                            $additionalPaths = @(
                                "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$enrollId",
                                "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$enrollId",
                                "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$enrollId",
                                "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$enrollId",
                                "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$enrollId",
                                "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$enrollId",
                                "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$enrollId"
                            )
                            foreach ($path in $additionalPaths) {
                                if (Test-Path $path) {
                                    try {
                                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                                    }
                                    catch {
                                        Write-Log -Message "Failed to remove device management enrollment entry: $path. Error: $($_.Exception.Message)" -isWarning $true
                                    }
                                }
                            }

                            $removedEnrollments += $enrollId
                        }
                    }
                    catch {
                        Write-Log -Message "Device management enrollment cleanup failed. Error: $($_.Exception.Message)" -isWarning $true
                    }
                }

                if ($removedEnrollments.Count -gt 0) {
                    Write-Log -Message "Device management enrollment validation and cleanup completed successfully."
                }
                else {
                    # "No valid MDM enrollments found to remove."
                }
            }
            else {
                Write-Log -Message "No device management enrollment detected. Skipping cleanup."
            }

            ######################################################################################################################
            ############################## Delete Intune and Autopilot object if exist ##########################################
            ######################################################################################################################

            Write-Log -Message "Validating and cleaning device records in management services..."

            if (-not [string]::IsNullOrEmpty($pc.autopilotId)) {
                # "Deleting Autopilot object..." 
                try {
                    Start-Sleep -Seconds 2
                    $encodedAutopilotId = [System.Uri]::EscapeDataString($pc.autopilotId)
                    $deleteResponse = Invoke-ApiWithRetry -Method Delete -Uri "https://$apidomain/client/autopilot?autopilotId=$encodedAutopilotId" -Headers $apiheaders

                    if (-not $deleteResponse) {
                        Write-Log -Message "Failed to submit Autopilot cleanup request." -isWarning $true
                    }
                    elseif ($deleteResponse.PSObject.Properties['status'] -and $deleteResponse.status -eq $false) {
                        $deleteMessage = if (-not [string]::IsNullOrWhiteSpace($deleteResponse.message)) { $deleteResponse.message } else { "Failed to submit Autopilot cleanup request." }
                        Write-Log -message $deleteMessage -isWarning $true
                    }
                }
                catch {
                    Write-Log -Message "Failed to submit Autopilot cleanup request. Error: $($_.Exception.Message)" -isWarning $true
                }
            }

            # Intune object removal
            if ([string]::IsNullOrEmpty($pc.intuneId)) {
            }
            else {
                #"Deleting Intune object..." 
                try {
                    Start-Sleep -Seconds 2
                    $encodedIntuneId = [System.Uri]::EscapeDataString($pc.intuneId)
                    $deleteResponse = Invoke-ApiWithRetry -Method Delete -Uri "https://$apidomain/client/intune-device?intuneDeviceId=$encodedIntuneId" -Headers $apiheaders

                    if (-not $deleteResponse) {
                        Write-Log -Message "Failed to submit Intune cleanup request." -isWarning $true
                    }
                    elseif ($deleteResponse.PSObject.Properties['status'] -and $deleteResponse.status -eq $false) {
                        $deleteMessage = if (-not [string]::IsNullOrWhiteSpace($deleteResponse.message)) { $deleteResponse.message } else { "Failed to submit Intune cleanup request." }
                        Write-Log -message $deleteMessage -isWarning $true
                    }
                }
                catch {
                    Write-Log -Message "Failed to submit Intune cleanup request. Error: $($_.Exception.Message)" -isWarning $true
                }
            }
            Write-Log -Message "Device management validation and cleanup completed successfully."

            # Reset MMPC enrollment flag 
            ###################################
            $mmpcFlag = "HKLM:\SOFTWARE\Microsoft\Enrollments"
            $flagName = "MmpcEnrollmentFlag"

            try {
                if (Get-ItemProperty -Path $mmpcFlag -Name $flagName -ErrorAction SilentlyContinue) {
                    Set-ItemProperty -Path $mmpcFlag -Name $flagName -Value 0 -Type DWord -Force -ErrorAction Stop
                }
            }
            catch {
                Write-Log -Message "Failed to reset Intune Enrollment Flag. Error: $($_.Exception.Message)" -isWarning $true
            }

            ######################################################################################################################
            # FUNCTION: removeSCCM
            # DESCRIPTION: Removes the SCCM client from the device.
            ######################################################################################################################
            function removeSCCM() {
                [CmdletBinding()]
                param(
                    [string]$CCMpath = "C:\Windows\ccmsetup\ccmsetup.exe",
                    [array]$services = @("CcmExec", "smstsmgr", "CmRcService", "ccmsetup"),
                    [string]$CCMProcess = "ccmsetup",
                    [string]$servicesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\",
                    [string]$ccmRegPath = "HKLM:\SOFTWARE\Microsoft\CCM",
                    [array]$sccmKeys = @("CCM", "SMS", "CCMSetup"),
                    [string]$CSPPath = "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP",
                    [array]$sccmFolders = @("C:\Windows\ccm", "C:\Windows\ccmsetup", "C:\Windows\ccmcache", "C:\Windows\ccmcache2", "C:\Windows\SMSCFG.ini", "C:\Windows\SMS*.mif"),
                    [array]$sccmNamespaces = @("ccm", "sms")
                )
    
                # Remove SCCM client
                if (Test-Path $CCMpath) {
                    try {
                        Start-Process -FilePath $CCMpath -ArgumentList "/uninstall" -Wait -ErrorAction Stop
                    }
                    catch {
                        Write-Log -Message "SCCM uninstall command failed. Error: $($_.Exception.Message)" -isWarning $true
                    }
        
                    # Check if process is still running and kill if necessary
                    Start-Sleep -Seconds 2
                    $runningProcess = Get-Process -Name $CCMProcess -ErrorAction SilentlyContinue
                    if ($runningProcess) {
                        try {
                            Stop-Process -Name $CCMProcess -Force -ErrorAction Stop
                            Start-Sleep -Seconds 2
                        }
                        catch {
                            Write-Log -Message "Failed to do forceful removal of SCCM process. Error: $($_.Exception.Message)" -isWarning $true
                        }
                    }
        
                    # Stop SCCM services
                    foreach ($service in $services) {
                        try {
                            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
                            if ($serviceStatus) {
                                Stop-Service -Name $service -Force -NoWait -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Log -Message "Failed to stop service: $service. Error: $($_.Exception.Message)" -isWarning $true
                        }
                    }
        
                    # Wait for services to stop
                    Start-Sleep -Seconds 3
        
                    # Remove WMI Namespaces with timeout protection
                    foreach ($namespace in $sccmNamespaces) {
                        try {
                            $job = Start-Job -ScriptBlock {
                                param($ns)
                                Get-CimInstance -Query "SELECT * FROM __Namespace WHERE Name = '$ns'" -Namespace "root" -ErrorAction Stop | Remove-CimInstance -ErrorAction Stop
                            } -ArgumentList $namespace
        
                            Wait-Job -Job $job -Timeout 30 | Out-Null
        
                            if ($job.State -eq 'Running') {
                                Stop-Job -Job $job -ErrorAction SilentlyContinue
                                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                                Write-Log -Message "WMI operation timed out for namespace: $namespace" -isWarning $true
                            }
                            elseif ($job.State -eq 'Failed') {
                                Write-Log -Message "WMI job failed for namespace: $namespace" -isWarning $true
                                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                            }
                            else {
                                Remove-Job -Job $job -ErrorAction SilentlyContinue
                            }
                        }
                        catch {
                            Write-Log -Message "Failed to remove WMI namespace '$namespace'. Error: $($_.Exception.Message)" -isWarning $true
                        }
                    }
                    # Remove SCCM registry keys for services
                    foreach ($service in $services) {
                        $serviceKey = $servicesRegPath + $service
                        try {
                            if (Test-Path $serviceKey) {
                                Remove-Item -Path $serviceKey -Recurse -Force -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Log -Message "Failed to remove service registration: $serviceKey. Error: $($_.Exception.Message)" -isWarning $true
                        }
                    }
        
                    # Remove SCCM registry keys
                    foreach ($key in $sccmKeys) {
                        $keyPath = $ccmRegPath + "\" + $key
                        try {
                            if (Test-Path $keyPath) {
                                Remove-Item -Path $keyPath -Recurse -Force -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Log -Message "Failed to remove configuration entry: $keyPath. Error: $($_.Exception.Message)" -isWarning $true
                        }
                    }
        
                    # Remove CSP
                    try {
                        if (Test-Path $CSPPath) {
                            Remove-Item -Path $CSPPath -Recurse -Force -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Log -Message "Failed to remove CSP configuration entry. Error: $($_.Exception.Message)" -isWarning $true
                    }
        
                    # Remove SCCM folders
                    foreach ($folder in $sccmFolders) {
                        try {
                            if (Test-Path $folder) {
                                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Log -Message "Failed to remove Configuration Manager folder: $folder. Error: $($_.Exception.Message)" -isWarning $true
                        }
                    }
                }
            }

            ######################################################################################################################
            # Remove SCCM client if required
            ######################################################################################################################
            $services = @("CcmExec", "smstsmgr", "CmRcService", "ccmsetup")
            $sccmInstalled = $false

            foreach ($service in $services) {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    $sccmInstalled = $true
                    break
                }
            }

            if ($sccmInstalled) {
                Write-Log -Message "SCCM client detected. Starting removal..."
                try {
                    removeSCCM
                    Write-Log -Message "SCCM client removal completed."
                }
                catch {
                    $message = $_.Exception.Message
                    Write-Log -Message "Failed to remove SCCM client. Error: $message" -isWarning $true
                }
            }
            else {
                Write-Log -Message "SCCM client is not installed"
            }

            ############### Progress bar update ##################
            $progressBar.Value = 45
            $progressLabel.Text = "Progress: 45% - Verification"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            #################################################################################################
            ############################# Leave Entra AD / Entra Join ########################################
            ##################################################################################################
            if ($pc.azureAdJoined -eq "YES") {
                Write-Log -Message "Entra join detected. Starting disconnect operation..."
                try {
                    $dsregProc = Start-Process -FilePath "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave" -Wait -PassThru -ErrorAction Stop
                    Start-Sleep -Seconds 10
                    $azureAdJoinedLine = dsregcmd.exe /status | Select-String "AzureAdJoined" | Select-Object -First 1
                    $azureAdJoined = if ($azureAdJoinedLine) { $azureAdJoinedLine.ToString().Split(":")[1].Trim() } else { "" }
                    if ($azureAdJoined -ne "NO") {
                        Write-Log -Message "Entra disconnect operation failed. Exit code: $($dsregProc.ExitCode). Migration process will stop." -isError $true
                        exitScript -functionName "dsregcmd"
                        return
                    }

                    Write-Log -Message "Disconnected from Entra ID successfully."
                }
                catch {
                    $message = $_.Exception.Message
                    Write-Log -Message "Failed to disconnect from Entra ID. Error: $message. Migration process will stop." -isError $true
                    exitScript -functionName "dsregcmd"
                    return
                }
            }
            else {
                try {
                    $encodedHostname = [System.Uri]::EscapeDataString($env:COMPUTERNAME)
                    $entraCleanupResponse = Invoke-ApiWithRetry -Method Delete -Uri "https://$apidomain/client/entra-device?hostname=$encodedHostname" -Headers $apiheaders

                    if (-not $entraCleanupResponse) {
                        Write-Log -Message "Failed to process Entra device cleanup." -isWarning $true
                    }
                }
                catch {
                    Write-Log -Message "Failed to process Entra device cleanup. Error: $($_.Exception.Message)" -isWarning $true
                }
            }

            ############### Progress bar update ##################
            $progressBar.Value = 50
            $progressLabel.Text = "Progress: 50% - Preparation"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            # Leave Domain/Hybrid Join
            #######################################################################
            # Check domain join status and attempt to leave domain gracefully if possible, otherwise prepare for offline domain disjoin

            if ($pc.domainJoined -eq "YES") {
                Write-Log -Message "Directory join status verified successfully.."
                
                $dcSrvRecord = "_ldap._tcp.dc._msdcs.$localDomain"
                try {
                    $DomainLeaveUser = $addcfg.DomainLeaveUser
                    $DomainLeavePassword = $addcfg.DomainLeavePassword
                    $Dmpw = $DomainLeavePassword | ConvertTo-SecureString -AsPlainText -Force
                    $Dmusr = $DomainLeaveUser
                    $Dmcreds = New-Object System.Management.Automation.PSCredential($Dmusr, $Dmpw)
                    # DNS resolution of domain controller
                    $dnsResult = Resolve-DnsName -Type SRV $dcSrvRecord -ErrorAction Stop
                    $dcList = (($dnsResult | Where-Object { $_.PSObject.Properties['NameTarget'] } | Select-Object -ExpandProperty NameTarget) -join ', ')
                    Write-Log -Message "DNS query completed successfully: $dcList"

                    Write-Log -Message "Initiating domain leave operation for device $($hostname)..."
                    try {
                        Remove-Computer -UnjoinDomainCredential $Dmcreds -WorkgroupName "WORKGROUP" -Force -ErrorAction Stop | Out-Null
                        Write-Log -Message "Device $hostname successfully disjoined from domain."
                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                        Write-Log -Message "Domain leave operation failed for device $hostname. Error: $errorMessage" -isError $true
                        exitScript -functionName "Remove-Computer"
                        return
                    }
                }
                catch {
                    Write-Log -Message "No direct connectivity to directory services detected for device $($hostname)."
                    #Check and enable migrateAdmin account
                    $localMigrateUser = Get-LocalUser -Name $migrateAdmin -ErrorAction SilentlyContinue
                    $acctStatus = if ($localMigrateUser) { $localMigrateUser.Enabled } else { $false }
                    if ($acctStatus -eq $false) {
                        Get-LocalUser -Name $migrateAdmin | Enable-LocalUser
                    }
                    else {
                    }

                    Write-Log -Message "Initiating forced domain leave operation..."
                    try {
                        $cred = New-Object System.Management.Automation.PSCredential("$hostname\$migrateAdmin", $securePassword)
                        $disjoinresult = Remove-Computer -UnjoinDomainCredential $cred -PassThru -Force -ErrorAction Stop
                        Write-Log -Message "Forced domain leave operation completed. Status: $disjoinresult."
                    }
                    catch {
                        $message = $_.Exception.Message
                        Write-Log -Message "Forced domain leave operation failed for device $hostname. Error: $message." -isError $true
                        exitScript -functionName "Remove-ComputerForce"
                        return
                    }
                }
            }
            else {
                Write-Log -Message "$($hostname) is not joined to a domain."
            }

            ############### Progress bar update ##################
            $progressBar.Value = 60
            $progressLabel.Text = "Progress: 60% - Preparation"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            #Write AD Disjoin Status to API
            $PartOfDomain = (Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
            Write-variables
            Write-Log -Message "Domain join status: $PartOfDomain"

            #Send Migration Status to API
            $MigrationPercent = "30"
            Write-migstatus

            #################################################################################################
            ############### Download provisioning package from api ##########################################
            #################################################################################################
            $ppkgResponse = Invoke-ApiWithRetry -Uri $ppkgurl -Method Get -Headers $apiheaders

            if (-not $ppkgResponse) {
                Write-Log -Message "Failed to retrieve Microsoft Entra provisioning package information." -isError $true
                exitScript -functionName "EntrapackageInfo"
                return
            }
            elseif ($ppkgResponse.isPackageAdded -eq $true) {
                # Store the URL for download later
                $script:ppkgfileUrl = $ppkgResponse.url
            }
            else {
                Write-Log -Message "Microsoft Entra provisioning package not available." -isError $true
                exitScript -functionName "EntrapackageInfo"
                return
            }

            Write-Log -Message "Downloading Microsoft Entra provisioning package..."
            $ppkgPath = "C:\ProgramData\OpsoleMigrate"
            try {
                $cleanUrl = $script:ppkgfileUrl.Split("?")[0]
                $ppkgFileName = [System.IO.Path]::GetFileName($cleanUrl)
                $downloadPath = Join-Path $ppkgPath $ppkgFileName

                # Download the file
                $downloadSucceeded = Invoke-DownloadWithRetry -Uri $script:ppkgfileUrl -OutFile $downloadPath -TimeoutSec 120

                if (-not $downloadSucceeded) {
                    Write-Log -Message "Failed to download Microsoft Entra provisioning package." -isError $true
                    exitScript -functionName "Entrapkgdownload"
                    return
                }

                Write-Log -Message "Microsoft Entra provisioning package downloaded successfully."
            }
            catch {
                Write-Log -Message "Failed to download Microsoft Entra provisioning package: $($_.Exception.Message)" -isError $true 
                exitScript -functionName "Entrapkgdownload"
                return
            }

            # Check provisioning package
            #############################
            Write-Log -Message "Checking installed Microsoft Entra provisioning packages on the device..."
            try {
                $OpsolePackagePath = "C:\ProgramData\OpsoleMigrate\package.ppkg"
                $OpsolePackage = Get-ProvisioningPackage -PackagePath $OpsolePackagePath -ErrorAction Stop
                $InstalledPackages = Get-ProvisioningPackage -AllInstalledPackages -ErrorAction SilentlyContinue

                foreach ($InstalledPackage in $InstalledPackages) {
                    if ($InstalledPackage.PackageID -eq $OpsolePackage.PackageID) {
                        Write-Log -Message "Matching provisioning package found. Removing the package..."
                        Uninstall-ProvisioningPackage -PackageId $InstalledPackage.PackageID -ErrorAction Stop
                        Write-Log -Message "Provisioning package removed successfully."
                    }
                }
            }
            catch {
                Write-Log -Message "Failed to check installed provisioning packages. Error: $($_.Exception.Message)"
            }

            #################################################################################################
            ############################# Entra Join Process ################################################
            #################################################################################################

            Start-Sleep -Seconds 10
            try {
                # Install provisioning package
                
                $ppkg = (Get-ChildItem -Path "C:\ProgramData\OpsoleMigrate" -Filter "*.ppkg" -Recurse).FullName
                if ($ppkg) {
                    Write-Log -Message "Starting installation of Microsoft Entra provisioning package..."
                    try {
                        $result = Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -ForceInstall

                        if ($null -eq $result) {
                            Write-Log -Message "Microsoft Entra join result could not be confirmed. Validation will continue in the next phase." 
                        }
                        else {
                            $aadJoinStep = $result.Result.ProvxmlResults |
                            Where-Object { $_.Category -match "DeviceAADJoin" } |
                            Select-Object -First 1
                            if ($null -eq $aadJoinStep -or $aadJoinStep.LastResult -ne "Success") {
                                Write-Log -Message "Microsoft Entra join result could not be confirmed. Validation will continue in the next phase. Result: $($aadJoinStep.LastResult) Message: $($aadJoinStep.Message)." -isWarning $true
                            }

                            Write-Log -Message "Microsoft Entra provisioning package installed successfully. $($result | Select-Object PackageID,PackageName,PackagePath,LastInstallTime,Result | Out-String)"
                        }

                        shutdown -a
                    }
                    catch {
                        $message = $_.Exception.Message
                        Write-Log -Message  "Failed to install Microsoft Entra provisioning package. Error: $message" -isWarning $true
                    }
                }
                else {
                    Write-Log -Message  "Microsoft Entra provisioning package not found......"   -isError $true
                    exitScript -functionName "Entrajoin"
                    return
                }      
            }
            catch {
                # Log any errors
                Write-Log -Message "Microsoft Entra provisioning operation failed. Error: $($_.Exception.Message)" -isError $true
                return
            }
  
            ############### Progress bar update ##################
            $progressBar.Value = 70
            $progressLabel.Text = "Progress: 70% - Finalization"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            #################################################################################################
            #Create Intermediate Migration Taskschedule -EXE
            #################################################################################################
            $localPath = "C:\ProgramData\OpsoleMigrate\runtime"
            $TaskPath = "\Migration\"
            $InterTaskname = "InterMigrateTask"
            $InterExepath = "$localPath\InterMigrate.exe"
     
            try {
                # Check if the task already exists
                $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $InterTaskname -ErrorAction SilentlyContinue
     
                if ($null -eq $task) {
                    if (-not (Test-Path -LiteralPath $InterExepath)) {
                        Write-Log -Message "Intermediate migration executable not found at $InterExepath. Migration process will stop." -isError $true
                        exitScript -functionName "CreateInterMigrateTask"
                        return
                    }
                    Write-Log -Message "Preparing intermediate migration process..."
                    $action = New-ScheduledTaskAction -Execute $InterExepath -WorkingDirectory $localPath
                    $trigger = New-ScheduledTaskTrigger -AtStartup
                    $trigger.Delay = 'PT1M'
     
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable -MultipleInstances IgnoreNew
     
                    Register-ScheduledTask -Principal $principal -Action $action -Trigger $Trigger -TaskName $InterTaskname -Settings $settings -Description "OpsoleMigrate InterMigrate Activity" -TaskPath $TaskPath -ErrorAction Stop
                    Write-Log -Message "Intermediate migration process preparation completed." 
     
                }
                else {
                    #Write-Log -Message "Intermediate migration process found. No changes made."  
                }
            }
            catch {
                Write-Log -Message "Failed to create intermediate migration process preparation: $($_.Exception.Message)" -isError $true
                exitScript -functionName "CreateInterMigrateTask"
                return
            }
                 
            Start-Sleep -Seconds 10

            #################################################################################################
            # Check Intermediate Migration Task created or not
            #################################################################################################
            try {
                $createdTask = Get-ScheduledTask -TaskPath $TaskPath -TaskName $InterTaskname -ErrorAction Stop

                if ($null -eq $createdTask) {
                    Write-Log -Message "$($InterTaskname) process not created under $($TaskPath), Migration process will stop." -isError $true
                    exitScript -functionName "Get-Intermediate"
                    return
                }
                else {
                    $taskState = $createdTask.State
                    $taskEnabled = $createdTask.Settings.Enabled
                    Write-Log -Message "Intermediate migration process exists. State: $taskState, Enabled: $taskEnabled"

                    if (-not $taskEnabled) {
                        #Write-Log -Message "$($InterTaskname) task is currently disabled. Attempting to enable..." 
                        try {
                            Enable-ScheduledTask -TaskPath $TaskPath -TaskName $InterTaskname -ErrorAction Stop
                            # Write-Log -Message "$($InterTaskname) task has been successfully enabled."
                        }
                        catch {
                            Write-Log -Message "Failed to enable $($InterTaskname) task: $($_.Exception.Message)" -isError $true
                            exitScript -functionName "Get-Intermediate"
                            return
                        }
                    }
                }
            }
            catch {
                $message = $_.Exception.Message
                Write-Log -Message "Failed to verify intermediate migration task $($InterTaskname) under $($TaskPath). Error: $message. Migration process will stop." -isError $true
                exitScript -functionName "Get-Intermediate"
                return
            }

            #################################################################################################
            # Create InterMonitor task schedule - EXE
            #################################################################################################
            $localPath = "C:\ProgramData\OpsoleMigrate\runtime"
            $TaskPath = "\Migration\"
            $MonitorTaskName = "InterMonitorTask"
            $MonitorExePath = "$localPath\InterMonitor.exe"

            try {
                $monitorTask = Get-ScheduledTask -TaskPath $TaskPath -TaskName $MonitorTaskName -ErrorAction SilentlyContinue

                if ($null -eq $monitorTask) {
                    if (-not (Test-Path -LiteralPath $MonitorExePath)) {
                        Write-Log -Message "Migration monitoring process not found at $MonitorExePath." -isWarning $true
                    }

                    Write-Log -Message "Preparing intermediate migration monitoring process..."
                    $monitorAction = New-ScheduledTaskAction -Execute $MonitorExePath -WorkingDirectory $localPath
                    $monitorTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(10))
                    $monitorPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $monitorSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 12) -StartWhenAvailable -MultipleInstances IgnoreNew

                    Register-ScheduledTask -Principal $monitorPrincipal -Action $monitorAction -Trigger $monitorTrigger -TaskName $MonitorTaskName -Settings $monitorSettings -Description "OpsoleMigrate InterMonitor Activity" -TaskPath $TaskPath *> $null
                    Write-Log -Message "Intermediate migration monitoring process preparation completed."
                }
            }
            catch {
                Write-Log -Message "Failed to create intermediate migration monitoring process: $($_.Exception.Message)" -isError $true
            }

            Start-Sleep -Seconds 5

            #################################################################################################
            # Check InterMonitor task created or not
            #################################################################################################
            try {
                $createdMonitorTask = Get-ScheduledTask -TaskPath $TaskPath -TaskName $MonitorTaskName -ErrorAction Stop

                if ($null -eq $createdMonitorTask) {
                    Write-Log -Message "$($MonitorTaskName) process not created under $($TaskPath), Migration process will stop." -isWarning $true
                }
                else {
                    $monitorTaskState = $createdMonitorTask.State
                    $monitorTaskEnabled = $createdMonitorTask.Settings.Enabled
                    Write-Log -Message "Intermediate migration monitoring process exists. State: $monitorTaskState, Enabled: $monitorTaskEnabled"

                    if (-not $monitorTaskEnabled) {
                        try {
                            Enable-ScheduledTask -TaskPath $TaskPath -TaskName $MonitorTaskName -ErrorAction Stop
                        }
                        catch {
                            Write-Log -Message "Failed to enable $($MonitorTaskName) process: $($_.Exception.Message)" -isWarning $true
                        }
                    }
                }
            }
            catch {
                $message = $_.Exception.Message
                Write-Log -Message "Failed to verify intermediate migration monitoring process $($MonitorTaskName) in path $($TaskPath). Error: $message" -isWarning $true
            }

            ############### Progress bar update ##################
            $progressBar.Value = 80
            $progressLabel.Text = "Progress: 80% - Finalization"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            Write-Log -Message "Applying system configuration ..."

            ##############################################################################################
            # Enable Web sign-in for Entra ID authentication at Windows sign-in
            ##############################################################################################
            
            if ($websignin -eq $true) {
                try {
                    $webSignInPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Authentication"

                    if (-not (Test-Path -Path $webSignInPath)) {
                        New-Item -Path $webSignInPath -Force | Out-Null
                    }

                    New-ItemProperty -Path $webSignInPath `
                        -Name "EnableWebSignIn" `
                        -Value 1 `
                        -PropertyType DWord `
                        -Force | Out-Null

                    Write-Log -Message "Web sign-in enabled successfully."
                }
                catch {
                    Write-Log -Message "Failed to enable Web sign-in. Error: $($_.Exception.Message)" -isWarning $true
                }
            }
	            
            ##############################################################################################
            ################## Disable last user display, set lock screen message ########################
            ##############################################################################################  

            # Force "Other user" only and clear cached login artifacts
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "0" -Type String -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Log -Message "Failed to disable cached sign-ins. Error: $($_.Exception.Message)"
            }

            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord -ErrorAction Stop | Out-Null
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnumerateLocalUsers" -Value 0 -Type DWord -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Log -Message "Failed to hide last signed-in user or disable user enumeration. Error: $($_.Exception.Message)"
            }

            $authPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication"
            $logonUiPath = Join-Path $authPath "LogonUI"

            try {
                if (-not (Test-Path $authPath)) {
                    New-Item -Path $authPath | Out-Null
                }
                if (-not (Test-Path $logonUiPath)) {
                    New-Item -Path $logonUiPath | Out-Null
                }

                $show = Get-ItemProperty -Path $logonUiPath -Name "ShowLastUser" -ErrorAction SilentlyContinue
                if ($null -eq $show) {
                    New-ItemProperty -Path $logonUiPath -Name "ShowLastUser" -Value 0 -PropertyType DWord | Out-Null
                }
                else {
                    Set-ItemProperty -Path $logonUiPath -Name "ShowLastUser" -Value 0 -Type DWord | Out-Null
                }
            }
            catch {
                Write-Log -Message "Failed to apply sign-in UI setting. Error: $($_.Exception.Message)"
            }

            try {
                Remove-ItemProperty -Path $logonUiPath -Name "LastLoggedOnUser" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path $logonUiPath -Name "LastLoggedOnSAMUser" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path $logonUiPath -Name "LastLoggedOnDisplayName" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path $logonUiPath -Name "LastLoggedOnUserSID" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path $logonUiPath -Name "SelectedUserSID" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path $logonUiPath -Name "LastLoggedOnProvider" -ErrorAction Stop
            }
            catch { }

            try {
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "LastUsedUsername" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ErrorAction Stop
            }
            catch { }
            try {
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -ErrorAction Stop
            }
            catch { }

            $sessionPath = Join-Path $logonUiPath "SessionData"
            try {
                if (Test-Path $sessionPath) {
                    Get-ChildItem -Path $sessionPath | Remove-Item -Recurse -Force -ErrorAction Stop
                }
            }
            catch {
                Write-Log -Message "Failed to clear sign-in session cache. Error: $($_.Exception.Message)"
            }

            # Backup existing lock screen / personalization registry values
            ###################################
            $regChecks = @(
                @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name = "LockScreenImage" },
                @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"; Name = "LockScreenImagePath" },
                @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"; Name = "LockScreenImageStatus" },
                @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "DisableAcrylicBackgroundOnLogon" }
            )
            $backupPath = "HKLM:\SOFTWARE\OpsoleMigrate\LockScreenBackup"
            if (-not (Test-Path $backupPath)) {
                New-Item -Path $backupPath -Force | Out-Null
            }

            $backupAlreadyTaken = (Get-ItemProperty -LiteralPath $backupPath -Name "LockScreenBackup" -ErrorAction SilentlyContinue).LockScreenBackup

            if ($backupAlreadyTaken -eq 1) {
                # Write-Log -Message "Original lock screen / personalization values were already backed up on a previous attempt. Skipping re-backup to preserve the original snapshot."
            }
            else {
                foreach ($check in $regChecks) {
                    if (Test-Path $check.Path) {
                        $key = Get-Item -Path $check.Path -ErrorAction SilentlyContinue
                        if ($key -and ($key.Property -contains $check.Name)) {
                            $value = $key.GetValue($check.Name)
                            $kind = $key.GetValueKind($check.Name)

                            New-ItemProperty -Path $backupPath -Name $check.Name -Value $value -PropertyType $kind -Force | Out-Null
                            New-ItemProperty -Path $backupPath -Name "$($check.Name)_Present" -Value 1 -PropertyType DWord -Force | Out-Null
                        }
                        else {
                            New-ItemProperty -Path $backupPath -Name "$($check.Name)_Present" -Value 0 -PropertyType DWord -Force | Out-Null
                        }
                    }
                    else {
                        New-ItemProperty -Path $backupPath -Name "$($check.Name)_Present" -Value 0 -PropertyType DWord -Force | Out-Null
                    }
                }

                New-ItemProperty -Path $backupPath -Name "LockScreenBackup" -Value 1 -PropertyType DWord -Force | Out-Null
            }

            ############### Progress bar update ##################
            $progressBar.Value = 90
            $progressLabel.Text = "Progress: 90% - Completion"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            # Set migration lock screen image
            ###################################
            try {
                $lockScreenImage = "C:\ProgramData\OpsoleMigrate\assets\lockscreen.jpg"
                $gpPersonalizationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
                $cspPersonalizationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
                $gpSystemPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

                if (Test-Path $lockScreenImage) {
                    try {
                        Remove-ItemProperty -Path $gpPersonalizationPath -Name 'LockScreenImage' -Force -ErrorAction SilentlyContinue
                        New-Item -Path $gpPersonalizationPath -Force -ErrorAction Stop | Out-Null
                        New-ItemProperty -Path $gpPersonalizationPath -Name 'LockScreenImage' -Value $lockScreenImage -PropertyType String -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Log -Message "Failed to set GPO lock screen policy. Error: $($_.Exception.Message)" -isWarning $true
                    }

                    try {
                        foreach ($propertyName in @("LockScreenImagePath", "LockScreenImageStatus")) {
                            Remove-ItemProperty -Path $cspPersonalizationPath -Name $propertyName -Force -ErrorAction SilentlyContinue
                        }
                        New-Item -Path $cspPersonalizationPath -Force -ErrorAction Stop | Out-Null
                        New-ItemProperty -Path $cspPersonalizationPath -Name 'LockScreenImagePath'   -Value $lockScreenImage -PropertyType String -Force -ErrorAction Stop | Out-Null
                        New-ItemProperty -Path $cspPersonalizationPath -Name 'LockScreenImageStatus' -Value 1               -PropertyType DWord  -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Log -Message "Failed to set CSP lock screen policy. Error: $($_.Exception.Message)" -isWarning $true
                    }

                    # Ensure the lock screen background carries onto the Ctrl+Alt+Del / sign-in screen
                    try {
                        Remove-ItemProperty -Path $gpSystemPath -Name 'DisableAcrylicBackgroundOnLogon' -Force -ErrorAction SilentlyContinue
                        New-Item -Path $gpSystemPath -Force -ErrorAction Stop | Out-Null
                        New-ItemProperty -Path $gpSystemPath -Name 'DisableAcrylicBackgroundOnLogon' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Log -Message "Failed to set sign-in screen acrylic policy. Error: $($_.Exception.Message)" -isWarning $true
                    }

                    # Write-Log -Message "Migration lock screen image configured successfully."
                }
                else {
                    Write-Log -Message "Lock screen image not found: $lockScreenImage."
                }
            }
            catch {
                Write-Log -Message "Failed to configure migration lock screen image. Error: $($_.Exception.Message)"
            }

            # set lock screen caption
            if ($targetTenantName) {
                $tenant = $targetTenantName
            }
            else {
                $tenant = $sourceTenantName
            }

            $tenantDisplay = $tenant
            $rootKey = "HKLM:\SOFTWARE\OpsoleMigrate"
            $profilesRoot = Join-Path $rootKey "Profiles"

            try {
                $currentLogonUserSid = Get-ItemPropertyValue -LiteralPath $rootKey -Name "CurrentLogonUserSid" -ErrorAction Stop
                $currentUserProfileKey = Join-Path $profilesRoot $currentLogonUserSid
                $newUpn = Get-ItemPropertyValue -LiteralPath $currentUserProfileKey -Name "NEW_upn" -ErrorAction Stop

                if (-not [string]::IsNullOrWhiteSpace($newUpn) -and $newUpn -like "*@*") {
                    $tenantDisplay = $newUpn.Split("@")[1]
                }
            }
            catch {
                Write-Log -Message "Could not determine tenant display name from current user context. Using configured tenant '$tenant'."
            }


            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "CRITICAL WARNING : Migration in Progress...Do not try Login" -Type String -Force | Out-Null
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "Your PC is being migrated to the $tenantDisplay tenant and will automatically reboot. Please wait and do not power off the device." -Type String -Force | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set lock screen message. Continuing migration. Error: $($_.Exception.Message)"
            }
            ######################################################################
            # Allow log on locally to local administrators only to prevent login during migration
            ######################################################################
            $lockInf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544
"@

            $lockInf | Out-File -FilePath "$env:TEMP\mig-lock.inf" -Encoding Unicode -Force
            Remove-Item "$env:TEMP\mig-lock.sdb" -Force -ErrorAction SilentlyContinue
            secedit.exe /configure /db "$env:TEMP\mig-lock.sdb" /cfg "$env:TEMP\mig-lock.inf" /areas USER_RIGHTS
            $seceditExitCode = $LASTEXITCODE

            if ($seceditExitCode -eq 0) {
                Write-Log -Message "System configuration applied successfully."
            }
            else {
                Write-Log -Message "Failed to apply migration logon restriction. Exit code: $seceditExitCode." -isWarning $true
            }
                
            ##################################################################################################
            # Backup Opsole profile registry 
            ##################################################################################################
            try {
                $backupDir = "C:\ProgramData\OpsoleMigrate\Backup"
                if (-not (Test-Path -LiteralPath $backupDir)) {
                    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
                }

                $ts = Get-Date -Format "yyyyMMdd-HHmmss"

                $profileListBackup = Join-Path $backupDir "ProfileList-$ts.reg"
                & "$env:windir\system32\reg.exe" export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "$profileListBackup" /y | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "ProfileList backup failed (rc=$LASTEXITCODE)"
                }

                $opsoleBackup = Join-Path $backupDir "OpsoleMigrate-$ts.reg"
                & "$env:windir\system32\reg.exe" export "HKLM\SOFTWARE\OpsoleMigrate" "$opsoleBackup" /y | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "OpsoleMigrate backup failed (rc=$LASTEXITCODE)"
                }
            }
            catch {
                Write-Log -Message "Failed to create migration configuration backup. Error: $($_.Exception.Message)" -isWarning $true
            }

            ############### Progress bar update ##################
            $progressBar.Value = 100
            $progressLabel.Text = "Progress: 100% - Completed"
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1

            #Write MIgration Percentage to API
            $MigrationPercent = "40"
            Write-migstatus  

            # Show completion message on the form
            $completionLabel.Text = "Your system will restart shortly."
            $completionLabel.Visible = $true
            $completionLabel.Left = ($form.ClientSize.Width - $completionLabel.Width) / 1.5
            $closeButton.Visible = $false            
            # Stop and restart
            Write-Log -Message "Pre-migration phase completed. Device $($pc.hostname) is scheduled to restart."
            shutdown -r -t 10                        
        }
        catch {
            Write-Log -Message "Pre-migration phase failed. Error: $_" -isError $true
            exitScript -functionName "PreMigrateMainUnhandled"
            return
        }
    })  

$closeButton.Add_Click({
        $form.Close()
    })
$RebootButton.Add_Click({
        $completionLabel.Text = "Plese Wait...Your system will restart shortly."
        $completionLabel.Visible = $true
        $completionLabel.Left = ($form.ClientSize.Width - $completionLabel.Width) / 1.5
        $ErrorLabel.Visible = $false
 
        #Create Migration Taskschedule when reboot required - EXE
        $localPath = "C:\ProgramData\OpsoleMigrate"
        $TaskPath = "\Migration\"
        $PreTaskname = "PreMigrateTaskauto"
        $ServiceUIPath = "$localPath\runtime\OpsoleMigrateUI.exe"
        $arguments = "-process:explorer.exe $localPath\PreMigrate.exe"
        $argumentsForce = "-process:explorer.exe $localPath\PreMigrate.exe --forced"

        $selectedArguments = $arguments
        if ($forceMode) {
            $selectedArguments = $argumentsForce
        }

        try {
            # Check if the task already exists
            $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $PreTaskname -ErrorAction SilentlyContinue

            if ($null -eq $task) {
                Write-Log -Message "Pre-migration process not found; initiating setup." 
                $action = New-ScheduledTaskAction -Execute $ServiceUIPath -Argument $selectedArguments -WorkingDirectory $localPath
                $trigger = New-ScheduledTaskTrigger -AtLogOn
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable -MultipleInstances IgnoreNew
                Register-ScheduledTask -Principal $principal -Action $action -Trigger $trigger -TaskName $PreTaskname -Settings $settings -Description "OpsoleMigrate PreMigrate Activity" -TaskPath $TaskPath *> $null
                Write-Log -Message "Pre-migration process has been established." 
            }
            else {
                Write-Log -Message "Pre-migration process already exists. No changes made."  
            }
            Write-Log -Message "Restarting device because a system restart is pending."
            shutdown -r -t 5
        } 
        catch {
            Write-Log -Message "Pre-migration phase failed. Error: $_" -isError $true
        }

    })
# Show the form
[void]$form.ShowDialog()

# SIG # Begin signature block
# MIIv9gYJKoZIhvcNAQcCoIIv5zCCL+MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpNvfECIrn/NaB
# cNojNEHzP3zAsKr+0zsRIrNtxnO/XaCCEkgwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYcMIIEBKADAgECAhAz1wio
# kUBTGeKlu9M5ua1uMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAs
# BgNVBAMTJVNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBFViBSMzYwggGi
# MA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC70f4et0JbePWQp64sg/GNIdMw
# hoV739PN2RZLrIXFuwHP4owoEXIEdiyBxasSekBKxRDogRQ5G19PB/YwMDB/NSXl
# wHM9QAmU6Kj46zkLVdW2DIseJ/jePiLBv+9l7nPuZd0o3bsffZsyf7eZVReqskmo
# PBBqOsMhspmoQ9c7gqgZYbU+alpduLyeE9AKnvVbj2k4aOqlH1vKI+4L7bzQHkND
# brBTjMJzKkQxbr6PuMYC9ruCBBV5DFIg6JgncWHvL+T4AvszWbX0w1Xn3/YIIq62
# 0QlZ7AGfc4m3Q0/V8tm9VlkJ3bcX9sR0gLqHRqwG29sEDdVOuu6MCTQZlRvmcBME
# Jd+PuNeEM4xspgzraLqVT3xE6NRpjSV5wyHxNXf4T7YSVZXQVugYAtXueciGoWnx
# G06UE2oHYvDQa5mll1CeHDOhHu5hiwVoHI717iaQg9b+cYWnmvINFD42tRKtd3V6
# zOdGNmqQU8vGlHHeBzoh+dYyZ+CcblSGoGSgg8sCAwEAAaOCAWMwggFfMB8GA1Ud
# IwQYMBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBSBMpJBKyjNRsjE
# osYqORLsSKk/FDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAT
# BgNVHSUEDDAKBggrBgEFBQcDAzAaBgNVHSAEEzARMAYGBFUdIAAwBwYFZ4EMAQMw
# SwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv
# UHVibGljQ29kZVNpZ25pbmdSb290UjQ2LmNybDB7BggrBgEFBQcBAQRvMG0wRgYI
# KwYBBQUHMAKGOmh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0Nv
# ZGVTaWduaW5nUm9vdFI0Ni5wN2MwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNl
# Y3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBfNqz7+fZyWhS38Asd3tj9lwHS
# /QHumS2G6Pa38Dn/1oFKWqdCSgotFZ3mlP3FaUqy10vxFhJM9r6QZmWLLXTUqwj3
# ahEDCHd8vmnhsNufJIkD1t5cpOCy1rTP4zjVuW3MJ9bOZBHoEHJ20/ng6SyJ6UnT
# s5eWBgrh9grIQZqRXYHYNneYyoBBl6j4kT9jn6rNVFRLgOr1F2bTlHH9nv1HMePp
# GoYd074g0j+xUl+yk72MlQmYco+VAfSYQ6VK+xQmqp02v3Kw/Ny9hA3s7TSoXpUr
# OBZjBXXZ9jEuFWvilLIq0nQ1tZiao/74Ky+2F0snbFrmuXZe2obdq2TWauqDGIgb
# MYL1iLOUJcAhLwhpAuNMu0wqETDrgXkG4UGVKtQg9guT5Hx2DJ0dJmtfhAH2KpnN
# r97H8OQYok6bLyoMZqaSdSa+2UA1E2+upjcaeuitHFFjBypWBmztfhj24+xkc6Zt
# CDaLrw+ZrnVrFyvCTWrDUUZBVumPwo3/E3Gb2u2e05+r5UWmEsUUWlJBl6MGAAjF
# 5hzqJ4I8O9vmRsTvLQA1E802fZ3lqicIBczOwDYOSxlP0GOabb/FKVMxItt1UHeG
# 0PL4au5rBhs+hSMrl8h+eplBDN1Yfw6owxI9OjWb4J0sjBeBVESoeh2YnZZ/WVim
# VGX/UUIL+Efrz/jlvzCCBrEwggUZoAMCAQICEFtTUEoJzVIrG5b318aQF4QwDQYJ
# KoZIhvcNAQELBQAwVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIEVW
# IFIzNjAeFw0yNjAyMTAwMDAwMDBaFw0yOTAyMDkyMzU5NTlaMIGlMQ8wDQYDVQQF
# EwYxMDA3NDAxEzARBgsrBgEEAYI3PAIBAxMCSU4xHTAbBgNVBA8TFFByaXZhdGUg
# T3JnYW5pemF0aW9uMQswCQYDVQQGEwJJTjEPMA0GA1UECAwGS2VyYWxhMR8wHQYD
# VQQKDBZPUFNPTEUgUFJJVkFURSBMSU1JVEVEMR8wHQYDVQQDDBZPUFNPTEUgUFJJ
# VkFURSBMSU1JVEVEMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj7x3
# aeZhvJuSYVnN8ji+xBH37jpusLTToyc+Z+sEIb20Z/OpUgwB+EwHSDJCdXfS17XW
# pFeGJWU7HJSN0H5bVxt/58QTqjSXw+Ra3YjUWSeXU5PhPS90ORUAusEqJkmJPmCq
# TFU0S7Vz2JL0mqVQ/pXmIsB/CQaqHfp0O/2EYX55RZYMa5nPfZh2GOouREATu0Zw
# lngB6xXjsuw7fPx3VtbfzDOlof9+ec0XkZSjWKt5hlP4OErMwr2xwKw9KmwK73Pb
# GXxA2ARFkRfKoe/V0otqRhDF0PPY6LQYdck1qGDzDO+W+ekTDDA46o5j7t249MJy
# tomJMGj4VW2z1SwBskzI83Uj/jWpFG3BBBVDA72jHvZ1tWCvSgRg74hlTz8xSzXM
# G8oPY0N54TU0ovW07+R1njtCJOop6gpAKt/ew4S2d+M21OE8i6aADQhO39nlrLCU
# poTXwzr8w1OiSIDv4Y2TqyNzq3LeogReA6DI9188GforR4eUqMTspD+mL+wqRhzi
# mLCG8F9Y8VwzYhAlR3Ti7OOzbhCV9qNJ5aKTpW4aFdQOr/vroNKVrahbFBNds9ii
# pMXSwzTc1r/mI1PnoXaOmfUR+7CGwkzmz50d1oaYymBRElWMp9PXuteLtppIuDGW
# z8lk3pg5D1TtJQSuJ+m1X7UngHFZ5SkrT3Hi7o0CAwEAAaOCAagwggGkMB8GA1Ud
# IwQYMBaAFIEykkErKM1GyMSixio5EuxIqT8UMB0GA1UdDgQWBBRwYBrDLBDSRA0J
# XVuwlBL4IH/fbTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUE
# DDAKBggrBgEFBQcDAzBJBgNVHSAEQjBAMDUGDCsGAQQBsjEBAgEGATAlMCMGCCsG
# AQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAHBgVngQwBAzBLBgNVHR8E
# RDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWND
# b2RlU2lnbmluZ0NBRVZSMzYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcw
# AoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25p
# bmdDQUVWUjM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5j
# b20wGgYDVR0RBBMwEYEPaW5mb0BvcHNvbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IB
# gQAI4j/I9SMpk/xlCFCczOTzyyy+Tt18/KOhMADcGlYRWfJWcBCKeP/v1HzWA5hG
# iL8adwqcH2iw2bnkUk0QHwgJRe4RcKHbQNqTfPcAy12KUuyLcsc0cgGSIAP6Cy2V
# xWXYMDgLeo/8DULdFKuva2sKcTLwjSFHQUa1dtf7UzPOIvnrBBPLMrrM9Wo2lbiA
# Yoo02bcfvXS9lqIH7PHZUVxidW23e2LbCZMTcWG2yeVo1LY/K7suM/waZLq0xMQB
# Y6SnTpirqSDroo5JvosIBnfADrDfi/QnSk6fCrNcw1f8BRolZrFoMtoH2l89VtjV
# RgMjo1246EzArZOdPBpaHnir+mXzhSM806Vnc27jxfzSNDCXf7VppoRWhWmXGOnZ
# wfnx+nu4JT3Ctt2kTTz0Sd5Ec5IvzZfRNpsXgxjp3ZcIxw1VjFs6omtercPZndW5
# QcNI9nnF2JG6RiyQMYCsBpSX2s9kn8mKr7LMraoD7YKSkQ8Rg1hel7d7rB/MqEHf
# XWoxgh0EMIIdAAIBATBrMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBFViBSMzYCEFtTUEoJzVIrG5b318aQF4QwDQYJYIZIAWUDBAIBBQCgfDAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgHlL9Kij9BUjm
# ttlr8ks8Wjh0pVGbNied1/nptLagS8AwDQYJKoZIhvcNAQEBBQAEggIAG2rAMNxa
# ZRAKt/IfX97e7OeS1sCRKlPSOrAh2H98IHE/KS4WioZ9MuXLLv6oNW2kjNKZFMSK
# 1H1L48z892kL/tVQJkXEsgfjYPMPnviwHACwE3Opbss71pyg+8rRAcqBK/W1FWkD
# P59sCiieqv0SopFKPA4J4s5H2EZarolzlW+OLubhO/h/DIWIfuJp7f7OblyZgcff
# d8kZ3ieMsV9wTCkqtdSdAHpNyqMiWXCxuTxjcLmjz+v2F6xCXb5Mq31/8mKn+tFv
# +g/nrImjTlygAj+whuAmD173iEM07tjp+DXLBAoseb8vYUwdniFZL3qPZ+4G9oo6
# 0nkTZtPWp7SPk5NMzN7LC6S+//pjAkProTszJns7G8rEqpVktBjlu6EEY9ZshEsL
# 7QtvpL9BEWlOKCMSvqplYgmDibqo8zjTz6rV4/XxvCuc3OT/KXPDhVCIhVwwjhhn
# wF/eiHy3FiC0c8bVlBgPdwxMfEaB/xjHUK9dD1o4LZt31aqRdBq8RG5oZV4e8t3o
# D9W/ciwcCTYtStiqm27PEwW1M8uGL7HdNa46LGTWlG7zYTKKp4W0Z5LEONRUG5lh
# 2VDlJ4CcehMHWjxm410BcA8zzi1pUujKuYtAEN2zXVHvH8Maio2iCiZwLg19EkV4
# 2qFVGzJhd3JVqktdYFTJgkpbxYErVaC0lX+hghnsMIIZ6AYKKwYBBAGCNwMDATGC
# GdgwghnUBgkqhkiG9w0BBwKgghnFMIIZwQIBAzEPMA0GCWCGSAFlAwQCAgUAMIH4
# BgsqhkiG9w0BCRABBKCB6ASB5TCB4gIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFl
# AwQCAQUABCAIczi0N5wUxFRZmIXUmzpbOJQJ3krghux8MLnuMDGuxgIVALOAJKZn
# 4DGTsH7atFzdkrutO0foGA8yMDI2MDkwOTA5MDUwMVqgdqR0MHIxCzAJBgNVBAYT
# AkdCMRcwFQYDVQQIEw5HcmVhdGVyIExvbmRvbjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNp
# Z25lciBSMzegghQXMIIG4jCCBMqgAwIBAgIRAOdO8lWwUE/626bf9/yLoxUwDQYJ
# KoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBS
# NDEwHhcNMjYwMzI1MDAwMDAwWhcNMzcwNjI0MjM1OTU5WjByMQswCQYDVQQGEwJH
# QjEXMBUGA1UECBMOR3JlYXRlciBMb25kb24xGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWdu
# ZXIgUjM3MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsv/DbUvcUNlF
# LQURd9m4+1St5+JudFKo5P803Iks4mFeNB9SymodP6BJJWBuNhOFQj9w77AVAeg5
# qQpA2dIwp2QTyBHr2h9eWSTkMBVj9mV6+WI5SaW+vDZW7PhJTbysd9v9WB3Xt6ql
# Ei8m47pcTy8+k/OfhziKiuzNQXqfC7KcoRD/6up8OZBsU0qxr7n5nh/iRfAp1QXF
# TBQONBZSGIdHAyVRYYX033VoC8v71rizEKCpH97Pxbwcn9eq9K7W8h5v4npsMUoq
# CS/c8mQwylDQGx15dHYV6NlcVFdjXD11l7qCrIy/unH5OlZtgx58QJRXRbGgQyBd
# STpEpwuj3i5Qc52Z9m7hd7yCGCXKujf83hUQpOPx1w8+84EbEUTHVAfq4cpORaGW
# gY8NJy6txmd3wpS1MeXrOaVAMczTgzAZ+yZBWIqdgQBgTxEeXldEToZOrRkxvn1I
# jIlfr4I4NWJz+Rb52FshLVnkA/wdoad789Eb7XZDNKd4oMmnc636TgauaaVZP2LL
# oU0JD/fYr53hwBn4uXu5ZsSfpnqAT60S7szJm/Na882xEoyRzLJ+UVbXOlHLO63D
# KkAtdz1CDuwWxgRE1drnwplepT06dz+1yTr5p1AkUz21bzE6cT/8/kjh4OPzggYY
# qrOBQPfuKEL5ZJPcN9jRgEpYvRlq5ucCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaA
# FDp0pQxnxkJQwv21/Me7KTSC9Hq5MB0GA1UdDgQWBBRhEOl6Eq9RxIXU8s+kdA9Q
# zSCv+DAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDBKBgNVHSAEQzBBMAgGBmeBDAEEAjA1BgwrBgEEAbIxAQIBAwgw
# JTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwSgYDVR0fBEMw
# QTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGlt
# ZVN0YW1waW5nQ0FSNDEuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5
# aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5n
# Q0FSNDEuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEAA+o9jdGszfoZepOmygef1OlbkjrPd2QW9z3M8vVb
# QSCruPeO2eRsC9GhZ4CMZfhkrixayYD67gQkbyiRCbJu5L/i0NQjlQhBvbWfiEba
# +KHFKGud5YHRWhDZUtDeMIJGZG0BD7/sftZUo2Ifk+CXi/ZlM50+xK3OkqeXVi5G
# ubDD/5txmYuqCT3T3LAilmoB+5th9sQxiMhyQuT3R/aYb4vypoZJLYklUzTalXle
# W1nV9s4UROlE389CHDKAi/fepRSMnV8TghODDQxwzNGrOJZ04k/yhzHHDupfHPU5
# 1FYJqXIvWq9SAAWdlNV1JGIxhkp/TAtxBwz/Vd/VbgVb2d9/wRFfxFkka39O0+4x
# aZSl/oEK/1DqjxjJRO2Se9lGlJDScu21Zd23Cys3aYyB8y5H/+DFWtVe8PMKgr+V
# uIDp0Rk5bneVDAEW0TPAT8Ufwl2F6DJiDg/KZk5NmsYES+CxvF7bnISEnQh0ZrWn
# AJixquV0mElUx01wA5TuPIgyodxzNq/fC0hen9LBtdnfFfSZ+wt8A1Injsbio+DH
# Vq1voYiVNpBfO7+nh9NB4AhRXNldPgr3zgjJ+47s0uNYy2iDXAZSlkP3ym/7gy31
# jlu989SNpRWO14/LUNV2LSuXkRI1iLTPI6ZdXG0DnPPG7UftF0tk5m6BP9eNfr2t
# j1swgganMIIEj6ADAgECAhEAkKwIciD9xafEa1zHDfc9BjANBgkqhkiG9w0BAQwF
# ADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYD
# VQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTI2
# MDMyNTAwMDAwMFoXDTQxMDMyNDIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGlt
# ZSBTdGFtcGluZyBDQSBSNDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCu5EqiAa2CHGL5Zi1bmgPM8NUXwYZJ+BtQqHps43GLTC+sjVLypsBh+8uv+TLk
# gtVGD//vSmA0qrzELf9YRCh2MTAA/aGaQZKGg0BRCmziR3pbCnvgWjtGXBDUyn3j
# 3K2lZAO8KxgFtlxwOYEAkL+CCqK4v9zzTl8ZwzDpPMiDIFa5THk8an1ieF5I09cX
# NrPQw+1ER1liThaG0z6FrOpqwxZWmPRZQBw2E32878UB1bL0Zp91vuWZgsMpNNiP
# CoBj0/1F+LE8+NRokfqacFI0F2tftrRB2W7HQClLR9zjxFbWb5be2rceIfNyHUUf
# KGIvMI2NzoxSlxXnFqUG887D8W1Cj8DFok688JKxWvHR/9aQykSbd+9Vutj36ij2
# sgq/125wTpUZ/AgC0ph50bRs7gFrUyaXE9wSsOqMvCCC+sEm7vd/BemSG0TSHNXS
# myCba+FCzekeWX03TRIcF3Laqd0Rw24OH7jpei4zaGhcI7nfdhBA4c8RScxNY6je
# HLHHmSMMTk9Wqn7H4dLhUBP5YEwbgbN4uv1i9ltTnHli8t1xHV0StX9BFgrnmunT
# X19kUXY1H5ORJbRZyZDdvm1oZyteDj0SnMozr+YSmdIleDUTXdfoY7b2taz8s2+Q
# bOxLxcahEIYGWzqu6h955tKwcANHcZ4gTmAhT3btuOiQsQIDAQABo4IBbjCCAWow
# HwYDVR0jBBgwFoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFDp0pQxn
# xkJQwv21/Me7KTSC9Hq5MA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/
# AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMCMGA1UdIAQcMBowCAYGZ4EMAQQCMA4G
# DCsGAQQBsjEBAgEDCDBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3Rp
# Z28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LmNybDB8Bggr
# BgEFBQcBAQRwMG4wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzAB
# hhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMt5S
# R2bxngNm+N8oc6Gq76Gx1c235fkX7jw8Ho9MAkJGADerHE7dhsBXttqmzgr/7ZZa
# hZSykGRPhPY1crj028kB8KzO0dKC2qQBAwtfgqMLKkkX/6bYq2uT33eD6ByAp2/X
# KD0LcmZh0kKecvSBr6ln9ajX6u1dnx2fA7xEKy1M3qBhfQSUWLtjs2nFt0ELVLpt
# zTlX9ID0cL+iOPfdboZ3CelT+JXKVKR2Sge0d4YiFAtPZkfSo8z1Z1x7y/Z9mwMI
# lBAnyuWXs4YsNuxdrYIt/QxE31PDOJ9DesS4Bc7H9OTORlEV/AvfiF/VepKZpira
# 1MzLYuCw+uoLZn/pkpvd+CvNTS+mEHjBJNa6WK1j8qXFu+jIq+sG9QILHiyB6p/x
# pHrkJu8zkw393+VqF9eKlTY2VjRxdycZLrVemZ4Yp3wi33b+W58CllH3HqjmowlZ
# 7SOrgmx8YwYOkgrHsXOQHyBp6O4FRb8In0+FzjT7ElGie9V7CfhL3IlVFZ4zjuKs
# ZtH1iU3fGu4z/JnOGT6sCb0BbTqe/uhvpFCQBdH5xPGIA/LrbQUXjU2tWJgHhTIq
# nN/HvHyOHi5tM4zP3nhgh2rJ6Kqq2xsHBeNYs/R18xQ8DeIg+c90Eoaeh0YlN1KU
# 8AyYol3K9M+qY5ez8syd/7ZlrRnoVewgH3P1pcswggaCMIIEaqADAgECAhA2wrC9
# fBs656Oz3TbLyXVoMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoT
# FVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBD
# ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0yMTAzMjIwMDAwMDBaFw0zODAxMTgy
# MzU5NTlaMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# LjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCIndi5RWedHd3ouSaBmlRU
# wHxJBZvMWhUP2ZQQRLRBQIF3FJmp1OR2LMgIU14g0JIlL6VXWKmdbmKGRDILRxEt
# ZdQnOh2qmcxGzjqemIk8et8sE6J+N+Gl1cnZocew8eCAawKLu4TRrCoqCAT8uRjD
# eypoGJrruH/drCio28aqIVEn45NZiZQI7YYBex48eL78lQ0BrHeSmqy1uXe9xN04
# aG0pKG9ki+PC6VEfzutu6Q3IcZZfm00r9YAEp/4aeiLhyaKxLuhKKaAdQjRaf/h6
# U13jQEV1JnUTCm511n5avv4N+jSVwd+Wb8UMOs4netapq5Q/yGyiQOgjsP/JRUj0
# MAT9YrcmXcLgsrAimfWY3MzKm1HCxcquinTqbs1Q0d2VMMQyi9cAgMYC9jKc+3mW
# 62/yVl4jnDcw6ULJsBkOkrcPLUwqj7poS0T2+2JMzPP+jZ1h90/QpZnBkhdtixMi
# WDVgh60KmLmzXiqJc6lGwqoUqpq/1HVHm+Pc2B6+wCy/GwCcjw5rmzajLbmqGygE
# gaj/OLoanEWP6Y52Hflef3XLvYnhEY4kSirMQhtberRvaI+5YsD3XVxHGBjlIli5
# u+NrLedIxsE88WzKXqZjj9Zi5ybJL2WjeXuOTbswB7XjkZbErg7ebeAQUQiS/uRG
# Z58NHs57ZPUfECcgJC+v2wIDAQABo4IBFjCCARIwHwYDVR0jBBgwFoAUU3m/Wqor
# Ss9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFPZ3at0//QET/xahbIICL9AKPRQlMA4G
# A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8v
# Y3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhv
# cml0eS5jcmwwNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2Nz
# cC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAOvmVB7WhEuOWhxdQR
# h+S3OyWM637ayBeR7djxQ8SihTnLf2sABFoB0DFR6JfWS0snf6WDG2gtCGflwVvc
# YXZJJlFfym1Doi+4PfDP8s0cqlDmdfyGOwMtGGzJ4iImyaz3IBae91g50QyrVbrU
# oT0mUGQHbRcF57olpfHhQEStz5i6hJvVLFV/ueQ21SM99zG4W2tB1ExGL98idX8C
# hsTwbD/zIExAopoe3l6JrzJtPxj8V9rocAnLP2C8Q5wXVVZcbw4x4ztXLsGzqZIi
# Rh5i111TW7HV1AtsQa6vXy633vCAbAOIaKcLAo/IU7sClyZUk62XD0VUnHD+YvVN
# vIGezjM6CRpcWed/ODiptK+evDKPU2K6synimYBaNH49v9Ih24+eYXNtI38byt5k
# Ivh+8aW88WThRpv8lUJKaPn37+YHYafob9Rg7LyTrSYpyZoBmwRWSE4W6iPjB7wJ
# jJpH29308ZkpKKdpkiS9WNsf/eeUtvRrtIEiSJHN899L1P4l6zKVsdrUu1FX1T/u
# bSrsxrYJD+3f3aKg6yxdbugot06YwGXXiy5UUGZvOu3lXlxA+fC13dQ5OlL2gIb5
# lmF6Ii8+CQOYDwXM+yd9dbmocQsHjcRPsccUd5E9FiswEqORvz8g3s+jR3SFCgXh
# N4wz7NgAnOgpCdUo4uDyllU9PzGCBJMwggSPAgEBMGowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSNDECEQDnTvJVsFBP+tum3/f8i6MVMA0GCWCG
# SAFlAwQCAgUAoIIB+jAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTI2MDkwOTA5MDUwMVowPwYJKoZIhvcNAQkEMTIEMLm/6fQwf8sa
# JgPvdPbULgrbb+aIc23dqzQc+8SKd53Lm7NT7ouCoVGLJn1c/3dJbzCCAXsGCyqG
# SIb3DQEJEAIMMYIBajCCAWYwggFiMBYEFOl4GKko2hUKn+G/nMx6q7mgDu6sMIGI
# BBRlwyhpb31OUCz9A8fCBpcYyvv3TzBwMFukWTBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2AhEAkKwIciD9xafEa1zHDfc9BjCBvAQUhT1j
# LZOCgmF80JA1xJHeksFC2scwgaMwgY6kgYswgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMV
# VGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENl
# cnRpZmljYXRpb24gQXV0aG9yaXR5AhA2wrC9fBs656Oz3TbLyXVoMA0GCSqGSIb3
# DQEBAQUABIICAA66qh2Ss8qjpgzcy48cbqzDpwInh5T0km3pPoQ/kvo+SFD6c0WO
# EeYh82syOvj3h0HZZV7kxkNwL37pb5dIKTOz+o8qVw2kb/MMXHrAUNLI8LiDc6/1
# Z8X36nbup9WrQ3iXJrZ7w80iQYmU2ZTmJWR3SmP5+OXl2Zp78pi9l+yfO0aUazwx
# sEM22y1xrY7t/h47cBW0I2EWFsHJcVh61z0e5e1qChR3rHY5Cod7rsCLupXkAQRA
# oOaMMyBuanBqCqGVWMjlbk0lAKzbZMIVmxqgSwUzZ8v+s7iGOk4ROgZSiPPuiaZq
# hkl8Y2uY6/qGiFou7FPAGt9eCtuEA1f3wFhVl4nHqPvCvDtS2IMT0+JKiXD2SILI
# 4WENyFHwDupQAbHtJNIXY+UKbEjkwvq7+9eue5G6C6hENFtr7m2mvPVxiiPd1Mbj
# OB28ZZwuI2bDQC61flKekfnU0hNWupUWJBGV0OMXXwiUq+LEaW3BvxaxTEIqpp/l
# HGf2/u3cPq+37ph9N7p1EDln9GE7zyuuMjRmVvfg11ta6HLKgUIZzKXtnai5DJXw
# niNdDwuqVHHo+RN2BN23q4lVkt3ti90l7uYGmRj5k3o2GF5HTXbWLlyk6mA6DmFu
# zzzzb11kdKzKlAnLuh1pZCPpOlXbRsDb1DOKOvIz8o174SzlVmMJz0P4
# SIG # End signature block

}