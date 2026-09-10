# League Of Champions - Standalone Live Monitor
param (
    [int]$LiveMonitorDurationSec = 0  # 0 means run indefinitely until Ctrl+C
)

function Show-Banner {
    Clear-Host
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "                 League Of Champions - Live Monitor                   " -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[*] Initialising Real-Time Process Event Watcher..." -ForegroundColor Yellow
    Write-Host "[*] Initialising File System Watcher (C:\)..." -ForegroundColor Yellow
    Write-Host "[*] Initialising Defender Exclusions & Tamper Watcher..." -ForegroundColor Yellow
    Write-Host "[*] Minimal mode: Executable payloads & significant renames only." -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " [LIVE MONITOR ACTIVE] Press Ctrl+C to exit monitoring mode." -ForegroundColor Green
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

# Checks if a process matching system helper names is authentic Microsoft binary in System32
function Test-IsGenuineSystemProcess {
    param (
        [string]$ProcessName,
        [string]$ExecutablePath
    )

    $systemHelpers = @(
        'conhost', 'SearchProtocolHost', 'SearchFilterHost', 'taskhostw',
        'WerFault', 'wermgr', 'RuntimeBroker', 'CompPkgSrv', 'dllhost',
        'sihost', 'svchost'
    )

    if ($systemHelpers -notcontains $ProcessName) {
        return $false
    }

    $system32 = "$env:SystemRoot\System32"
    $sysWow64 = "$env:SystemRoot\SysWOW64"

    # Must originate from System32 or SysWOW64
    if (-not $ExecutablePath -or 
        (-not $ExecutablePath.StartsWith($system32, [System.StringComparison]::OrdinalIgnoreCase) -and 
         -not $ExecutablePath.StartsWith($sysWow64, [System.StringComparison]::OrdinalIgnoreCase))) {
        return $false
    }

    # Must be signed by Microsoft
    try {
        $sig = Get-AuthenticodeSignature -FilePath $ExecutablePath -ErrorAction SilentlyContinue
        if ($null -eq $sig -or $sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike "*Microsoft*") {
            return $false
        }
    } catch {
        return $false
    }

    return $true
}

# Checks if a file rename event is security-significant
function Test-IsSignificantRename {
    param (
        [string]$OldPath,
        [string]$NewPath
    )

    $payloadExtensions = "\.(exe|dll|sys|bat|ps1|vbs|js|drv)$"

    # Renamed to an executable payload extension
    if ($NewPath -match $payloadExtensions) {
        return $true
    }

    # Renamed into System32 / Drivers
    $system32 = "$env:SystemRoot\System32"
    if ($NewPath.StartsWith($system32, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    # Renamed file name matches suspicious terms
    if ($NewPath -match "procexp|procmon|kdmapper|cheat|injector") {
        return $true
    }

    return $false
}

function Start-Monitoring {
    Show-Banner

    $browserProcessPattern = "^(chrome|msedge|firefox|opera|brave|vivaldi|iexplore|tor|waterfox|edge)$"

    # Take initial process & exclusion snapshots
    $processSnapshot = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.ProcessName -notmatch $browserProcessPattern) {
            $path = $_.Path
            if (-not (Test-IsGenuineSystemProcess -ProcessName $_.ProcessName -ExecutablePath $path)) {
                $processSnapshot[$_.Id] = @{
                    Name = $_.ProcessName
                    Path = $path
                }
            }
        }
    }

    $exclusionSnapshot = @()
    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mpPref -and $mpPref.ExclusionPath) { $exclusionSnapshot += $mpPref.ExclusionPath }

    # Setup FileSystemWatcher on C:\
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = "C:\"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::DirectoryName -bor [System.IO.NotifyFilters]::LastWrite

    $createdAction = {
        param($source, $eventArgs)
        $p = $eventArgs.FullPath
        if ($p -match "\.(exe|dll|sys|bat|ps1|vbs|js|zip|rar|7z|iso|img|drv)$" -and $p -notmatch "\\(Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox|BraveSoftware|Opera Software|Vivaldi|discord\\Network|cache|CacheStorage|Code Cache|GPUCache)\\") {
            $global:liveMonitorFileEvents.Enqueue("[FILE  +]  $p")
        }
    }
    $deletedAction = {
        param($source, $eventArgs)
        $p = $eventArgs.FullPath
        if ($p -match "\.(exe|dll|sys|bat|ps1|vbs|js|zip|rar|7z|iso|img|drv)$" -and $p -notmatch "\\(Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox|BraveSoftware|Opera Software|Vivaldi|discord\\Network|cache|CacheStorage|Code Cache|GPUCache)\\") {
            $global:liveMonitorFileEvents.Enqueue("[FILE  -]  $p")
        }
    }
    $renamedAction = {
        param($source, $eventArgs)
        $oldP = $eventArgs.OldFullPath
        $newP = $eventArgs.FullPath
        
        if ($newP -notmatch "\\(Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox|BraveSoftware|Opera Software|Vivaldi|discord\\Network|cache|CacheStorage|Code Cache|GPUCache)\\") {
            if (Test-IsSignificantRename -OldPath $oldP -NewPath $newP) {
                $global:liveMonitorFileEvents.Enqueue("[FILE REN]  $oldP -> $newP")
            }
        }
    }

    $global:liveMonitorFileEvents = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

    $subCreated = Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action $createdAction
    $subDeleted = Register-ObjectEvent -InputObject $watcher -EventName "Deleted" -Action $deletedAction
    $subRenamed = Register-ObjectEvent -InputObject $watcher -EventName "Renamed" -Action $renamedAction

    $startTime = Get-Date

    try {
        while ($true) {
            if ($LiveMonitorDurationSec -gt 0) {
                $elapsed = (Get-Date) - $startTime
                if ($elapsed.TotalSeconds -ge $LiveMonitorDurationSec) {
                    Write-Host ""
                    Write-Host "[INFO] Specified monitoring duration ($LiveMonitorDurationSec sec) elapsed." -ForegroundColor Cyan
                    break
                }
            }

            # Process monitoring
            $currentProcesses = @{}
            Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.ProcessName -notmatch $browserProcessPattern) {
                    $pName = $_.ProcessName
                    $pPath = $_.Path

                    $isGenuine = Test-IsGenuineSystemProcess -ProcessName $pName -ExecutablePath $pPath

                    $systemHelpers = @('conhost', 'SearchProtocolHost', 'SearchFilterHost', 'taskhostw', 'WerFault', 'wermgr', 'RuntimeBroker', 'CompPkgSrv', 'dllhost', 'sihost', 'svchost')
                    if ($systemHelpers -contains $pName -and -not $isGenuine) {
                        $currentProcesses[$_.Id] = @{
                            Name = $pName
                            Path = $pPath
                            IsMasqueraded = $true
                        }
                    } elseif (-not $isGenuine) {
                        $currentProcesses[$_.Id] = @{
                            Name = $pName
                            Path = $pPath
                            IsMasqueraded = $false
                        }
                    }
                }
            }

            # Check new processes
            foreach ($pidKey in $currentProcesses.Keys) {
                if (-not $processSnapshot.ContainsKey($pidKey)) {
                    $procInfo = $currentProcesses[$pidKey]
                    $name = $procInfo.Name
                    $path = $procInfo.Path
                    $timestamp = (Get-Date -Format "HH:mm:ss")
                    
                    if ($procInfo.IsMasqueraded) {
                        Write-Host "[$timestamp] [ALERT  !] FAKE/MASQUERADED SYSTEM PROCESS DETECTED: $name (PID: $pidKey, Path: $path)" -ForegroundColor Red
                    } elseif ($name -match "procexp|procmon|autoruns") {
                        Write-Host "[$timestamp] [ALERT  !] SYSINTERNALS PROCESS EXPLORER LAUNCHED: $name (PID: $pidKey)" -ForegroundColor Red
                    } else {
                        Write-Host "[$timestamp] [PROC  +]  $name (PID: $pidKey)" -ForegroundColor Yellow
                    }
                }
            }

            # Check closed processes
            foreach ($pidKey in $processSnapshot.Keys) {
                if (-not $currentProcesses.ContainsKey($pidKey)) {
                    $procInfo = $processSnapshot[$pidKey]
                    $name = $procInfo.Name
                    $timestamp = (Get-Date -Format "HH:mm:ss")
                    Write-Host "[$timestamp] [PROC  -]  $name (PID: $pidKey)" -ForegroundColor DarkGray
                }
            }
            $processSnapshot = $currentProcesses

            # Process file events
            $msg = ""
            while ($global:liveMonitorFileEvents.TryDequeue([ref]$msg)) {
                $timestamp = (Get-Date -Format "HH:mm:ss")
                if ($msg -match "\[FILE  \+\]") {
                    Write-Host "[$timestamp] $msg" -ForegroundColor Cyan
                } elseif ($msg -match "\[FILE  \-\]") {
                    Write-Host "[$timestamp] $msg" -ForegroundColor Red
                } else {
                    Write-Host "[$timestamp] $msg" -ForegroundColor Magenta
                }
            }

            # Check Defender exclusions
            $currentMp = Get-MpPreference -ErrorAction SilentlyContinue
            $currentExclusions = @()
            if ($currentMp -and $currentMp.ExclusionPath) { $currentExclusions += $currentMp.ExclusionPath }

            foreach ($ex in $currentExclusions) {
                if ($exclusionSnapshot -notcontains $ex) {
                    $timestamp = (Get-Date -Format "HH:mm:ss")
                    Write-Host "[$timestamp] [ALERT  !] Defender Exclusion Added: $ex" -ForegroundColor Red
                }
            }
            foreach ($ex in $exclusionSnapshot) {
                if ($currentExclusions -notcontains $ex) {
                    $timestamp = (Get-Date -Format "HH:mm:ss")
                    Write-Host "[$timestamp] [ALERT  !] Defender Exclusion Removed: $ex" -ForegroundColor Red
                }
            }
            $exclusionSnapshot = $currentExclusions

            Start-Sleep -Milliseconds 500
        }
    } finally {
        Unregister-Event -SourceIdentifier $subCreated.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $subDeleted.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $subRenamed.Name -ErrorAction SilentlyContinue
        $watcher.EnableRaisingEvents = $false
        $watcher.Dispose()
    }
}

# Entry point
Start-Monitoring
