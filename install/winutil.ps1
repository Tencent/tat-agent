$userName = "TAT-AGENT"
$agentDir = "C:\Program Files\qcloud\tat_agent"
$agentPath = "C:\Program Files\qcloud\tat_agent\tat_agent.exe"
$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path

function Read-IniFile ([string] $FilePath) {
    $ini = @{}
    switch -regex -file $FilePath {
        "^\[(.+)\]" {
            # Section
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" {
            # Comment
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = $CommentCount + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" {
            # Key
            $name, $value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

function Write-IniFile( $InputObject, $FilePath ) {
    foreach ($i in $InputObject.keys) {
        $content += "[$i]`r`n"
        Foreach ($j in ($InputObject[$i].keys | Sort-Object)) {
            if ($j -match "^Comment[\d]+") {
                $content += "$($InputObject[$i][$j])`r`n"
            }
            else {
                $content += "$j=$($InputObject[$i][$j])`r`n"
            }
        }
    }
    $content | Out-File $FilePath
}

function Add-Security([string]$UserName, [String[]]$SecurityArrays, $SaveFile = "$ScriptDir\gpo.ini") {
    secedit /export /areas USER_RIGHTS /cfg $SaveFile
    $iniObj = Read-IniFile $SaveFile;
    $changed = $False
    for ($i = 0; $i -lt $SecurityArrays.Count; $i++) {
        $SecurityName = $SecurityArrays[$i]
        $userList = $iniObj["Privilege Rights"][$SecurityName]
        if ( $null -ne $userList ) {
            if ( !$userList.contains($UserName) ) {
                $iniObj["Privilege Rights"][$SecurityName] = "$userList,$UserName"
                $changed = $True
            }
        }
        else {
            $iniObj["Privilege Rights"][$SecurityName] = " $UserName"
            $changed = $True
        }
    }
    if ( $changed ) {
        Write-Host "Privilege changed,need import."
        Write-IniFile -InputObject $iniObj -FilePath $SaveFile
        secedit /configure /db profile.sdb /cfg $SaveFile /areas USER_RIGHTS
        Remove-Item profile.*
    }
    Remove-Item $SaveFile
    return;
}


function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs = ""
    return [String]$characters[$random]
}

function Get-RandomPassword {
    $password = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 2 -characters '!@#$%^&*()'
    $password += Get-RandomCharacters -length 2 -characters '1234567890'
    $password += Get-RandomCharacters -length 5 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    return $password;
}


function Install-User($UserName, $UserPass) {
    Write-Host "=>Install-User"
    net user $UserName > $null
    if ( $LASTEXITCODE -ne 0 ) {
        net user $UserName $UserPass /add
        net localgroup Administrators $UserName /add
    }
    else {
        net user $UserName $UserPass
    }
    WMIC USERACCOUNT WHERE "Name='$UserName'" SET PasswordExpires=FALSE
    #hide ueser from control pannel
    REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v $UserName /t REG_DWORD /d 0 /f
}


function Install-Files {
    Write-Host "=>Install-Files"
    if ( !(Test-Path $agentDir) ) {
        New-Item  -Type Directory -Path $agentDir -Force
        New-Item  -Type Directory -Path "$agentDir\\workdir" -Force
    }

    if ( Test-Path $agentPath ) {
        $randstr = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz';
        $newName = "$agentDir\temp_$randstr.exe";
        Rename-Item -Path $agentPath -NewName $newName
    }

    if ( Test-Path "$agentDir\winpty.dll" ) {
        $randstr = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz';
        $newName = "$agentDir\temp_$randstr.dll";
        Rename-Item -Path "$agentDir\winpty.dll" -NewName $newName
    }

    if ( Test-Path "$agentDir\winpty.exe" ) {
        $randstr = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz';
        $newName = "$agentDir\temp_$randstr.exe";
        Rename-Item -Path "$agentDir\winpty.exe" -NewName $newName
    }

    Copy-Item "$ScriptDir\tat_agent.exe"  -Destination "$agentDir\tat_agent.exe" 
    Copy-Item "$ScriptDir\winpty-agent.exe"  -Destination "$agentDir\winpty-agent.exe"  
    Copy-Item "$ScriptDir\winpty.dll"  -Destination "$agentDir\winpty.dll" 
}


function Install-Service() {
    Write-Host "=>Install-Service"
    $userPass = Get-RandomPassword
    Install-User -UserName $userName -UserPass $userPass
    sc.exe query tatsvc > $null
    if ( $LASTEXITCODE -ne 0 ) {
        Write-Host "install new service"
        sc.exe create tatsvc binPath= $agentPath start= auto
        sc.exe failure tatsvc actions= restart/1000 reset= -1
    }
    sc.exe config tatsvc obj= ".\$userName" password= "$userPass"
}

function Install-Privilege {
    Write-Host "=>Install-Privilege"
    $Arrays = ("SeServiceLogonRight", "SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege", "SeDenyNetworkLogonRight")
    Add-Security -UserName $userName -SecurityArrays  $Arrays
}

Install-Files;
Install-Service;
Install-Privilege;
