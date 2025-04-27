#ps1
# Configuration parameters
$ServiceName = "tat_install"
$TmpDir = "$env:TEMP\$ServiceName"
$InstallDir = "$env:ProgramFiles\qcloud\tat_agent\$ServiceName"
$LogFile = "$InstallDir\logs\$ServiceName.log"
$ScriptName = Split-Path -Leaf $PSCommandPath
$InstalledScriptPath = Join-Path -Path $InstallDir -ChildPath $ScriptName

# Define domains
$PrimaryDomain = "invoke.tat-tc.tencent.cn"
$BackupDomain = "invoke.tat-tc.tencentyun.com"

# Get download URL for a specific domain
function Get-DownloadUrl {
    param (
        [string]$Domain
    )
    
    return "https://$Domain/download?latest=true&arch=x86_64&system=windows"
}

# Ensure log directory exists
function Ensure-LogDirectory {
    $LogDir = Split-Path -Parent $LogFile
    if (-not (Test-Path -Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
}

# Write log
function Write-Log {
    param (
        [string]$Message
    )
    
    Ensure-LogDirectory
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# Check administrator privileges
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Restart as administrator if needed
function Restart-AsAdmin {
    if (-not (Test-Administrator)) {
        Write-Host "Administrator privileges are required. Restarting as administrator..."
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $args" -Verb RunAs
        exit
    }
}

# Download file with retry and domain fallback
function Download-File {
    param (
        [string]$OutputPath
    )
    
    # Disable certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    
    $downloadSuccess = $false
    $primaryUrl = Get-DownloadUrl -Domain $PrimaryDomain
    $backupUrl = Get-DownloadUrl -Domain $BackupDomain
    $maxRetries = 5
    $retryCount = 0
    
    while (-not $downloadSuccess -and $retryCount -lt $maxRetries) {
        $retryCount++
        
        # Try primary domain first
        Write-Log "Trying primary domain (attempt $retryCount): $PrimaryDomain"
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($primaryUrl, $OutputPath)
            $downloadSuccess = $true
            Write-Log "File downloaded successfully from primary domain: $primaryUrl"
            break
        }
        catch {
            Write-Log "Download from primary domain failed: $($_.Exception.Message)"
            if ($webClient) {
                $webClient.Dispose()
            }
        }
        
        # Primary domain failed, immediately try backup domain
        Write-Log "Primary domain failed, immediately trying backup domain (attempt $retryCount): $BackupDomain"
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($backupUrl, $OutputPath)
            $downloadSuccess = $true
            Write-Log "File downloaded successfully from backup domain: $backupUrl"
            break
        }
        catch {
            Write-Log "Download from backup domain failed: $($_.Exception.Message)"
            if ($webClient) {
                $webClient.Dispose()
            }
        }
        
        # Both domains failed, wait before retry
        if (-not $downloadSuccess -and $retryCount -lt $maxRetries) {
            Write-Log "Both domains failed on attempt $retryCount, waiting before retry..."
            Start-Sleep -Seconds 2
        }
    }
    
    # If all attempts failed, throw exception
    if (-not $downloadSuccess) {
        Write-Log "Download failed after all attempts"
        throw "Download failed after all attempts"
    }
    
    # Reset certificate validation to default
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    
    return $downloadSuccess
}

# Service main logic
function Run-Service {
    Write-Log "Installation started $(Get-Date)"
    
    # Create temp and install directories
    if (-not (Test-Path -Path $TmpDir)) {
        New-Item -Path $TmpDir -ItemType Directory -Force | Out-Null
    }
    
    if (-not (Test-Path -Path $InstallDir)) {
        New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
    }
    
    # Download package
    $zipPath = Join-Path -Path $TmpDir -ChildPath "installer.zip"
    Download-File -OutputPath $zipPath
    
    # Extract package
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -Path "$InstallDir\pkg") {
             Remove-Item -Path "$InstallDir\pkg" -Recurse -Force
        }
        New-Item -Path "$InstallDir\pkg" -ItemType Directory -Force | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, "$InstallDir\pkg")
        Write-Log "Package extracted"
    }
    catch {
        Write-Log "Extraction failed: $($_.Exception.Message)"
        throw "Extraction failed: $($_.Exception.Message)"
    }
    
    # Execute install script
    $installScript = Join-Path -Path "$InstallDir\pkg" -ChildPath "install.bat"
    if (Test-Path -Path $installScript) {
        try {
            Write-Log "Executing install script: $installScript"
            & $installScript | Out-File -FilePath $LogFile -Append -Encoding utf8
            Write-Log "Install script executed"
        }
        catch {
            Write-Log "Install script failed: $($_.Exception.Message)"
            throw "Install script failed: $($_.Exception.Message)"
        }
    }
    else {
        $errorMsg = "Install script not found: $installScript"
        Write-Log $errorMsg
        throw $errorMsg
    }
    
    # Cleanup temp files
    try {
        Remove-Item -Path $TmpDir -Recurse -Force
        Write-Log "Temp files cleaned"
    }
    catch {
        Write-Log "Temp file cleanup failed: $($_.Exception.Message)"
    }
    
    Write-Log "Installation completed $(Get-Date)"
}

# Copy script to install directory
function Copy-ScriptToInstallDir {
    try {
        if (-not (Test-Path -Path $InstallDir)) {
            New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
        }
        
        Copy-Item -Path $PSCommandPath -Destination $InstalledScriptPath -Force
        Write-Log "Script copied to: $InstalledScriptPath"
        return $true
    }
    catch {
        Write-Log "Script copy failed: $($_.Exception.Message)"
        return $false
    }
}

# Register service
function Register-TatService {
    if (-not (Test-Path -Path $InstalledScriptPath)) {
        if (-not (Copy-ScriptToInstallDir)) {
            Write-Log "Using original script path"
            $scriptToUse = $PSCommandPath
        } else {
            $scriptToUse = $InstalledScriptPath
        }
    } else {
        $scriptToUse = $InstalledScriptPath
    }
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptToUse`" -service"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    
    try {
        Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
        Write-Log "Service registered using: $scriptToUse"
        return $true
    }
    catch {
        Write-Log "Service registration failed: $($_.Exception.Message)"
        return $false
    }
}

# Uninstall service
function Uninstall-TatService {
    try {
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
        Write-Log "Service uninstalled"
        return $true
    }
    catch {
        Write-Log "Service uninstall failed: $($_.Exception.Message)"
        return $false
    }
}

# Main logic
function Main {
    param (
        [switch]$Service
    )
    
    Restart-AsAdmin
    
    if ($Service) {
        try {
            Run-Service
            Write-Host "Uninstalling service..."
            Uninstall-TatService
        }
        catch {
            Write-Log "Service execution failed: $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Copy-ScriptToInstallDir
        
        Write-Host "Registering service..."
        if (Register-TatService) {
            Write-Host "Starting service..."
            try {
                Start-ScheduledTask -TaskName $ServiceName
                Write-Host "Service started"
            }
            catch {
                Write-Log "Service start failed: $($_.Exception.Message)"
                Write-Host "Running installation directly..."
                Run-Service
            }
        }
        else {
            Write-Host "Service registration failed, running installation..."
            Run-Service
        }
    }
}

# Parse command line arguments
$serviceParam = $false
foreach ($arg in $args) {
    if ($arg -eq "-service") {
        $serviceParam = $true
        break
    }
}

# Execute
if ($serviceParam) {
    Main -Service
}
else {
    Main
}
