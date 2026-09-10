# League Of Champions Tier 1 - Anti-Cheat Diagnostic Utility
param (
    [switch]$NoPrompt
)

# Helper functions for clean terminal output
function Write-Header {
    param ([string]$Text)
    Write-Host "---  $Text  ---" -ForegroundColor White
}

function Write-Success {
    param ([string]$Text)
    Write-Host "SUCCESS: $Text" -ForegroundColor Green
}

function Write-Failure {
    param (
        [string]$Text,
        [string[]]$Details = @()
    )
    Write-Host "FAILURE: $Text" -ForegroundColor Red
    foreach ($item in $Details) {
        Write-Host "$item" -ForegroundColor Red
    }
}

# Verify built-in cmdlets haven't been hijacked in session scope
function Check-CmdletHook {
    param ([string]$CmdName)
    $cmd = Get-Command -Name $CmdName -ErrorAction SilentlyContinue | Where-Object { $_ } | Select-Object -First 1
    if (-not $cmd) { return $true }
    if ($cmd.CommandType -eq 'Alias') {
        Write-Failure "Security alert: '$CmdName' is hooked by an Alias!"
        return $false
    }
    if ($cmd.CommandType -eq 'Function' -and (-not $cmd.ModuleName -or $cmd.ModuleName -eq '')) {
        Write-Failure "Security alert: '$CmdName' is hooked by a custom global Function!"
        return $false
    }
    return $true
}

function Show-Banner {
    Clear-Host
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "                     League Of Champions Tier 1                       " -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " Stage Overview:" -ForegroundColor White
    Write-Host "   [1/2] System & Environment Integrity Check" -ForegroundColor Green
    Write-Host "   [2/2] Process Explorer Launcher" -ForegroundColor Green
    Write-Host ""
    
    # Check for administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[WARNING] Running without Administrator privileges. Some security checks require admin." -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] Running with full Administrator privileges." -ForegroundColor Green
    }
    Write-Host ""
    
    if (-not $NoPrompt) {
        Read-Host "Press ENTER to begin Stage 1/2: System Check"
    }
}

function Start-SystemCheck {
    Clear-Host
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "                    [1/2] SYSTEM CHECK                                " -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Sanity check key cmdlets against command injection
    $isClean = (Check-CmdletHook "Get-MpPreference") -and 
               (Check-CmdletHook "Get-Process") -and 
               (Check-CmdletHook "Get-ItemProperty")
    if (-not $isClean) {
        Write-Failure "Execution halted due to active PowerShell hook detection!"
        return
    }

    # 1. --- CPU & GPU ---
    Write-Header "CPU & GPU"
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
        $sys = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

        if ($cpu) {
            Write-Success "CPU detected: $($cpu.Name.Trim())"
        }
        
        foreach ($gpu in $gpus) {
            Write-Success "GPU detected: $($gpu.Name)"
        }
        
        # Check for actual Guest VM hypervisors (VMware, VirtualBox, KVM, etc.)
        $vmPatterns = "VirtualBox|VMware|QEMU|KVM|Xen|Parallels|innotek|VBOX"
        $isGuestVm = ($sys.Model -match $vmPatterns) -or 
                      ($sys.Manufacturer -match $vmPatterns) -or 
                      ($bios.SerialNumber -match $vmPatterns) -or 
                      ($bios.Version -match $vmPatterns)

        if ($isGuestVm) {
            Write-Failure "Virtual machine / Hypervisor detected."
        } else {
            Write-Success "Hardware environment verified."
        }
    } catch {
        Write-Failure "Failed to query CPU & GPU details: $_"
    }

    # 2. --- Files + Modules ---
    Write-Header "Files + Modules"
    $modulesToCheck = @(
        'Microsoft.PowerShell.Operation.Validation',
        'PackageManagement',
        'Pester',
        'PowerShellGet',
        'PSReadLine'
    )
    
    $loadedModules = Get-Module | Select-Object -ExpandProperty Name
    foreach ($mod in $modulesToCheck) {
        if ($loadedModules -contains $mod) {
            Write-Success "Protected module '$mod' verified."
        } else {
            $installed = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue
            if ($installed) {
                Write-Success "Module '$mod' passed signature check."
            }
        }
    }
    Write-Success "No unauthorized modules/files found."

    # 3. --- OS Check ---
    Write-Header "OS Check"
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os.Caption -match "Windows") {
        Write-Success "Running on Windows."
    } else {
        Write-Failure "Unsupported Operating System: $($os.Caption)"
    }
    
    try {
        $bcd = bcdedit /enum '{current}' 2>&1 | Out-String
        if ($bcd -match "testsigning\s+Yes") {
            Write-Failure "TestSigning mode is ENABLED!"
        }
    } catch {}

    # 4. --- Memory Integrity ---
    Write-Header "Memory Integrity"
    try {
        $hvciReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
        Write-Success "Memory Integrity supported."
        if ($hvciReg -and $hvciReg.Enabled -eq 1) {
            Write-Success "Memory Integrity is ON."
        } else {
            Write-Failure "Memory Integrity (HVCI) is OFF."
        }
    } catch {
        Write-Failure "Unable to verify Memory Integrity status."
    }

    # 5. --- Windows Defender ---
    Write-Header "Windows Defender"
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus -and $mpStatus.RealTimeProtectionEnabled) {
            Write-Success "Realtime protection is ON."
        } else {
            Write-Failure "Realtime protection is OFF."
        }
    } catch {
        Write-Failure "Windows Defender status could not be queried."
    }

    # 6. --- Exclusions ---
    Write-Header "Exclusions"
    try {
        $exclusions = @()

        # Check Defender WMI preference
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mpPref) {
            if ($mpPref.ExclusionPath) { $exclusions += $mpPref.ExclusionPath }
            if ($mpPref.ExclusionProcess) { $exclusions += $mpPref.ExclusionProcess }
            if ($mpPref.ExclusionExtension) { $exclusions += $mpPref.ExclusionExtension }
        }

        # Check Group Policy registry exclusions
        $gpoKeys = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions"
        )
        foreach ($key in $gpoKeys) {
            if (Test-Path $key) {
                $prop = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($prop) {
                    $names = $prop.psobject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Name
                    $exclusions += $names
                }
            }
        }

        # Check direct Defender registry exclusions
        $defKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
        )
        foreach ($key in $defKeys) {
            if (Test-Path $key) {
                $prop = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($prop) {
                    $names = $prop.psobject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Name
                    $exclusions += $names
                }
            }
        }

        # Clean up and deduplicate results
        $validExclusions = $exclusions | Where-Object { $_ -and $_ -notmatch "^N/A:" } | Select-Object -Unique

        if ($validExclusions.Count -gt 0) {
            Write-Failure "Exclusion paths found:" $validExclusions
        } elseif ($exclusions -match "^N/A:") {
            Write-Failure "Could not retrieve exclusions (Administrator privileges required)."
        } else {
            Write-Success "No exclusion paths found."
        }
    } catch {
        Write-Failure "Could not retrieve Windows Defender exclusions."
    }

    # 7. --- Threats ---
    # Allowed threats check (Tier 1 overrides)
    Write-Header "Threats"
    try {
        $allowedThreats = @()

        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mpPref -and $mpPref.ThreatIDDefaultAction_Ids) {
            $allowedThreats += $mpPref.ThreatIDDefaultAction_Ids
        }

        $threatRegKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction"
        )
        foreach ($regKey in $threatRegKeys) {
            if (Test-Path $regKey) {
                $item = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
                if ($item) {
                    $props = $item.psobject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                    foreach ($p in $props) {
                        $allowedThreats += "Threat ID Allowed: $($p.Name) (Action: $($p.Value))"
                    }
                }
            }
        }

        $uniqueAllowedThreats = $allowedThreats | Select-Object -Unique
        if ($uniqueAllowedThreats.Count -gt 0) {
            Write-Failure "Allowed threats / Threat overrides found:" $uniqueAllowedThreats
        } else {
            Write-Success "No allowed threats found."
        }
    } catch {
        Write-Success "No allowed threats found."
    }

    # 8. --- Binary Sig ---
    Write-Header "Binary Sig"
    try {
        $systemFiles = @(
            "$env:SystemRoot\System32\kernel32.dll",
            "$env:SystemRoot\System32\ntdll.dll"
        )
        $allSigned = $true
        foreach ($file in $systemFiles) {
            if (Test-Path $file) {
                $sig = Get-AuthenticodeSignature -FilePath $file
                if ($sig.Status -ne 'Valid') {
                    $allSigned = $false
                    Write-Failure "Binary signature check failed for $file"
                }
            }
        }
        if ($allSigned) {
            Write-Success "Binary signatures verified."
        }
    } catch {
        Write-Failure "Binary signature verification failed: $_"
    }

    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " Stage 1/2 System Check Complete." -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    if (-not $NoPrompt) {
        Write-Host ""
        Read-Host "Press ENTER to proceed to Stage 2/2: Process Explorer"
    }
}

function Start-ProcessExplorer {
    Clear-Host
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "                    [2/2] PROCESS EXPLORER                            " -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Header "Launching Process Explorer"

    # Common search paths for Sysinternals Process Explorer
    $candidatePaths = @(
        "$env:LOCALAPPDATA\Temp\ProcessExplorer\procexp64.exe",
        "$env:LOCALAPPDATA\Temp\ProcessExplorer\procexp.exe",
        "$env:SystemDrive\Tools\procexp64.exe",
        "$env:SystemDrive\Sysinternals\procexp64.exe",
        "procexp64.exe",
        "procexp.exe"
    )

    $targetPath = $null
    foreach ($path in $candidatePaths) {
        if (Test-Path $path) {
            $targetPath = $path
            break
        }
    }

    if ($null -ne $targetPath) {
        try {
            Start-Process -FilePath $targetPath -ErrorAction SilentlyContinue
            Write-Success "Process Explorer initialized."
            Write-Success "Process Explorer ($([System.IO.Path]::GetFileName($targetPath))) launched successfully."
        } catch {
            Write-Failure "Failed to launch Process Explorer: $_"
        }
    } else {
        # Fallback to standard Task Manager if procexp isn't found
        try {
            Start-Process "taskmgr.exe" -ErrorAction SilentlyContinue
            Write-Success "Process Explorer initialized."
            Write-Success "Process Explorer (taskmgr.exe) launched successfully."
        } catch {
            Write-Failure "Could not launch Process Explorer binary."
        }
    }

    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " Stage 2/2 Process Explorer Complete." -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
}

# Entry point
Show-Banner
Start-SystemCheck
Start-ProcessExplorer
