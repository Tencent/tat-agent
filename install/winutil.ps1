$agentDir = "C:\Program Files\qcloud\tat_agent"
$agentPath = "C:\Program Files\qcloud\tat_agent\tat_agent.exe"
$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path


function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs = ""
    return [String]$characters[$random]
}


function Install-Files {
    Write-Host "=>Install-Files"
    if ( !(Test-Path $agentDir) ) {
        New-Item  -Type Directory -Path $agentDir -Force
    }

    if ( !(Test-Path "$agentDir\\workdir") ) {
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
    sc.exe query tatsvc > $null
    if ( $LASTEXITCODE -ne 0 ) {
        Write-Host "install new service"
        sc.exe create tatsvc binPath= $agentPath start= auto
        sc.exe failure tatsvc actions= restart/1000 reset= -1
    }
    else {
        sc.exe config tatsvc obj= LocalSystem
        net user TAT-AGENT /delete
    }
}

Install-Files;
Install-Service;
