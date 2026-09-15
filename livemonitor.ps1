# League Of Champions - Standalone Live Monitor

$csharpCode = @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class HandleWatcher {
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int ReturnLength);
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")]
    public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, ushort hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);
    [DllImport("kernel32.dll")]
    public static extern int GetProcessId(IntPtr Process);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    private static byte _processObjectType = 0;

    public static byte GetProcessObjectType() {
        if (_processObjectType != 0) return _processObjectType;
        int length = 0x10000;
        IntPtr ptr = Marshal.AllocHGlobal(length);
        int retLength = 0;
        while (NtQuerySystemInformation(16, ptr, length, ref retLength) == unchecked((int)0xC0000004)) {
            Marshal.FreeHGlobal(ptr);
            length = retLength + 0x10000;
            ptr = Marshal.AllocHGlobal(length);
        }
        long handleCount = Marshal.ReadIntPtr(ptr).ToInt64();
        IntPtr currentPtr = new IntPtr(ptr.ToInt64() + IntPtr.Size);
        IntPtr currentProcess = GetCurrentProcess();
        for (long i = 0; i < handleCount; i++) {
            int processId = Marshal.ReadInt32(currentPtr);
            byte objectType = Marshal.ReadByte(new IntPtr(currentPtr.ToInt64() + 4));
            ushort handleValue = (ushort)Marshal.ReadInt16(new IntPtr(currentPtr.ToInt64() + 6));
            currentPtr = new IntPtr(currentPtr.ToInt64() + (IntPtr.Size == 8 ? 24 : 16));
            
            if (processId <= 4) continue;
            IntPtr hSourceProcess = OpenProcess(0x0040, false, processId);
            if (hSourceProcess != IntPtr.Zero) {
                IntPtr hDup;
                if (DuplicateHandle(hSourceProcess, handleValue, currentProcess, out hDup, 0, false, 2)) {
                    int targetPid = GetProcessId(hDup);
                    CloseHandle(hDup);
                    CloseHandle(hSourceProcess);
                    if (targetPid > 0) {
                        Marshal.FreeHGlobal(ptr);
                        _processObjectType = objectType;
                        return objectType;
                    }
                }
                CloseHandle(hSourceProcess);
            }
        }
        Marshal.FreeHGlobal(ptr);
        return 0;
    }

    public static int[] GetProcessesWithHandleTo(int targetPid) {
        byte processObjectType = GetProcessObjectType();
        List<int> pids = new List<int>();
        if (processObjectType == 0) return pids.ToArray();

        int length = 0x10000;
        IntPtr ptr = Marshal.AllocHGlobal(length);
        int retLength = 0;
        while (NtQuerySystemInformation(16, ptr, length, ref retLength) == unchecked((int)0xC0000004)) {
            Marshal.FreeHGlobal(ptr);
            length = retLength + 0x10000;
            ptr = Marshal.AllocHGlobal(length);
        }
        long handleCount = Marshal.ReadIntPtr(ptr).ToInt64();
        IntPtr currentPtr = new IntPtr(ptr.ToInt64() + IntPtr.Size);
        IntPtr currentProcess = GetCurrentProcess();

        for (long i = 0; i < handleCount; i++) {
            int processId = Marshal.ReadInt32(currentPtr);
            byte objectType = Marshal.ReadByte(new IntPtr(currentPtr.ToInt64() + 4));
            ushort handleValue = (ushort)Marshal.ReadInt16(new IntPtr(currentPtr.ToInt64() + 6));
            currentPtr = new IntPtr(currentPtr.ToInt64() + (IntPtr.Size == 8 ? 24 : 16));
            
            if (objectType != processObjectType) continue;
            if (processId <= 4) continue;
            if (pids.Contains(processId)) continue;
            
            IntPtr hSourceProcess = OpenProcess(0x0040, false, processId);
            if (hSourceProcess != IntPtr.Zero) {
                IntPtr hDup;
                if (DuplicateHandle(hSourceProcess, handleValue, currentProcess, out hDup, 0, false, 2)) {
                    int pId = GetProcessId(hDup);
                    CloseHandle(hDup);
                    if (pId == targetPid) {
                        pids.Add(processId);
                    }
                }
                CloseHandle(hSourceProcess);
            }
        }
        Marshal.FreeHGlobal(ptr);
        return pids.ToArray();
    }
}
"@
Add-Type -TypeDefinition $csharpCode -ErrorAction SilentlyContinue

function Show-Banner {
    Clear-Host
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "                 League Of Champions - Live Monitor                   " -ForegroundColor White
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-AVSnapshot {
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $mp) { return $null }
    return @{
        ExclusionPath = ($mp.ExclusionPath -join ',')
        ExclusionProcess = ($mp.ExclusionProcess -join ',')
        ExclusionExtension = ($mp.ExclusionExtension -join ',')
        ThreatIDDefaultAction_Ids = ($mp.ThreatIDDefaultAction_Ids -join ',')
        DisableRealtimeMonitoring = $mp.DisableRealtimeMonitoring
    }
}

function Start-Monitoring {
    Show-Banner
    
    $browserProcessPattern = "^(chrome|msedge|firefox|opera|brave|vivaldi|iexplore|tor|waterfox|edge)$"
    $browserFilePattern = "\\(Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox|BraveSoftware|Opera Software|Vivaldi|discord\\Network|cache|CacheStorage|Code Cache|GPUCache)\\"
    $system32 = "$env:SystemRoot\System32"

    $avSnapshot = Get-AVSnapshot
    $reportedHandles = @{}

    # Take initial process snapshot
    $processSnapshot = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        if ($p.ProcessName -notmatch $browserProcessPattern) {
            $processSnapshot[$p.Id] = $p.ProcessName
        }
    }

    # Setup FileSystemWatcher on C:\
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = "C:\"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::DirectoryName
    
    $global:liveMonitorFileEvents = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

    $createdAction = {
        param($source, $eventArgs)
        if ($eventArgs.FullPath -notmatch $browserFilePattern) {
            $global:liveMonitorFileEvents.Enqueue("[FILE  +]  $($eventArgs.FullPath)")
        }
    }
    $deletedAction = {
        param($source, $eventArgs)
        if ($eventArgs.FullPath -notmatch $browserFilePattern) {
            $global:liveMonitorFileEvents.Enqueue("[FILE  -]  $($eventArgs.FullPath)")
        }
    }
    $renamedAction = {
        param($source, $eventArgs)
        if ($eventArgs.FullPath -notmatch $browserFilePattern) {
            $global:liveMonitorFileEvents.Enqueue("[FILE REN]  $($eventArgs.OldFullPath) -> $($eventArgs.FullPath)")
        }
    }

    $subCreated = Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action $createdAction
    $subDeleted = Register-ObjectEvent -InputObject $watcher -EventName "Deleted" -Action $deletedAction
    $subRenamed = Register-ObjectEvent -InputObject $watcher -EventName "Renamed" -Action $renamedAction

    try {
        $loopCount = 0
        while ($true) {
            # Process monitoring
            $currentProcesses = @{}
            $robloxPids = @()
            
            foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
                if ($p.ProcessName -notmatch $browserProcessPattern) {
                    $currentProcesses[$p.Id] = $p.ProcessName
                }
                if ($p.ProcessName -match "RobloxPlayerBeta") {
                    $robloxPids += $p.Id
                }
            }

            # Check handles to Roblox
            foreach ($rPid in $robloxPids) {
                $pidsWithHandle = [HandleWatcher]::GetProcessesWithHandleTo($rPid)
                foreach ($hPid in $pidsWithHandle) {
                    $key = "$hPid-$rPid"
                    if (-not $reportedHandles.ContainsKey($key)) {
                        $reportedHandles[$key] = $true
                        $hProc = Get-Process -Id $hPid -ErrorAction SilentlyContinue
                        if ($hProc) {
                            $isAllowed = $false
                            $isMasquerade = $false
                            
                            $allowedHandles = @(
                                "audiodg", 
                                "RadeonSoftware", 
                                "RobloxCrashHandler", 
                                "PresentMon-x64",
                                "csrss",
                                "lsass",
                                "dwm",
                                "taskmgr",
                                "explorer",
                                "conhost",
                                "WmiPrvSE"
                            )

                            if ($hProc.ProcessName -eq "svchost") {
                                $hPath = $hProc.Path
                                if ($hPath -and $hPath.StartsWith($system32, [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $isAllowed = $true
                                } else {
                                    $isMasquerade = $true
                                }
                            } elseif ($allowedHandles -contains $hProc.ProcessName) {
                                $hPath = $hProc.Path
                                if ($hPath) {
                                    $sig = Get-AuthenticodeSignature -FilePath $hPath -ErrorAction SilentlyContinue
                                    if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match "Microsoft|Advanced Micro Devices|Intel|Roblox") {
                                        $isAllowed = $true
                                    } else {
                                        $isMasquerade = $true
                                    }
                                } else {
                                    # Cannot read path (sometimes true for system processes even as admin), tentatively allow
                                    $isAllowed = $true
                                }
                            }

                            if ($isMasquerade) {
                                $timestamp = (Get-Date -Format "HH:mm:ss")
                                Write-Host "[$timestamp] [ALERT !] MASQUERADED MEMORY READ: $($hProc.ProcessName) (PID: $hPid) is hooked to Roblox! Path: $($hProc.Path)" -ForegroundColor Red
                            } elseif (-not $isAllowed) {
                                $timestamp = (Get-Date -Format "HH:mm:ss")
                                Write-Host "[$timestamp] [ALERT !] MEMORY READ: $($hProc.ProcessName) (PID: $hPid) has a handle to Roblox (PID: $rPid)" -ForegroundColor Red
                            }
                        }
                    }
                }
            }

            # Check new processes
            foreach ($pidKey in $currentProcesses.Keys) {
                if (-not $processSnapshot.ContainsKey($pidKey)) {
                    $name = $currentProcesses[$pidKey]
                    $timestamp = (Get-Date -Format "HH:mm:ss")
                    
                    $isMasq = $false
                    $systemHelpers = @('conhost', 'SearchProtocolHost', 'SearchFilterHost', 'taskhostw', 'WerFault', 'wermgr', 'RuntimeBroker', 'CompPkgSrv', 'dllhost', 'sihost', 'svchost', 'explorer', 'taskmgr', 'dwm', 'lsass', 'csrss')
                    if ($systemHelpers -contains $name) {
                        $newProc = Get-Process -Id $pidKey -ErrorAction SilentlyContinue
                        if ($newProc -and $newProc.Path) {
                            $sig = Get-AuthenticodeSignature -FilePath $newProc.Path -ErrorAction SilentlyContinue
                            if ($null -eq $sig -or $sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
                                $isMasq = $true
                            }
                        }
                    }

                    if ($isMasq) {
                        Write-Host "[$timestamp] [ALERT !] FAKE/MASQUERADED SYSTEM PROCESS DETECTED: $name (PID: $pidKey)" -ForegroundColor Red
                    } else {
                        Write-Host "[$timestamp] [PROC  +]  $name (PID: $pidKey)" -ForegroundColor Yellow
                    }
                }
            }

            # Check closed processes
            foreach ($pidKey in $processSnapshot.Keys) {
                if (-not $currentProcesses.ContainsKey($pidKey)) {
                    $name = $processSnapshot[$pidKey]
                    $timestamp = (Get-Date -Format "HH:mm:ss")
                    Write-Host "[$timestamp] [PROC  -]  $name (PID: $pidKey)" -ForegroundColor DarkGray
                    
                    # Cleanup handle alerts cache
                    $keysToRemove = @()
                    foreach ($k in $reportedHandles.Keys) {
                        if ($k.StartsWith("$pidKey-") -or $k.EndsWith("-$pidKey")) {
                            $keysToRemove += $k
                        }
                    }
                    foreach ($k in $keysToRemove) {
                        $reportedHandles.Remove($k)
                    }
                }
            }
            $processSnapshot = $currentProcesses

            # AV Tamper checks (every ~2 seconds to save CPU)
            if ($loopCount % 4 -eq 0 -and $avSnapshot) {
                $newAv = Get-AVSnapshot
                if ($newAv) {
                    if ($newAv.DisableRealtimeMonitoring -ne $avSnapshot.DisableRealtimeMonitoring) {
                        $timestamp = (Get-Date -Format "HH:mm:ss")
                        Write-Host "[$timestamp] [ALERT !] AV TAMPER: Real-Time Protection changed to $($newAv.DisableRealtimeMonitoring)" -ForegroundColor Red
                    }
                    if ($newAv.ExclusionPath -ne $avSnapshot.ExclusionPath) {
                        $timestamp = (Get-Date -Format "HH:mm:ss")
                        Write-Host "[$timestamp] [ALERT !] AV TAMPER: Defender Exclusion Path Modified!" -ForegroundColor Red
                    }
                    if ($newAv.ExclusionProcess -ne $avSnapshot.ExclusionProcess) {
                        $timestamp = (Get-Date -Format "HH:mm:ss")
                        Write-Host "[$timestamp] [ALERT !] AV TAMPER: Defender Exclusion Process Modified!" -ForegroundColor Red
                    }
                    if ($newAv.ExclusionExtension -ne $avSnapshot.ExclusionExtension) {
                        $timestamp = (Get-Date -Format "HH:mm:ss")
                        Write-Host "[$timestamp] [ALERT !] AV TAMPER: Defender Exclusion Extension Modified!" -ForegroundColor Red
                    }
                    if ($newAv.ThreatIDDefaultAction_Ids -ne $avSnapshot.ThreatIDDefaultAction_Ids) {
                        $timestamp = (Get-Date -Format "HH:mm:ss")
                        Write-Host "[$timestamp] [ALERT !] AV TAMPER: Allowed Threats Modified!" -ForegroundColor Red
                    }
                    $avSnapshot = $newAv
                }
            }

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

            $loopCount++
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
