<#
.SYNOPSIS
    Resets the WSUS / Windows Update / SCCM client stack on one or more remote computers.

.DESCRIPTION
    Troubleshooting helper for machines whose Configuration Manager (SCCM / MECM) client or
    Windows Update agent is stuck (no scan, stale compliance state, broken policy, ...).
    The sequence runs through PowerShell remoting and every remote log line is echoed in the
    local console (as soon as it is received) and appended to a local log file.

    On each target, the sequence:
      1. Stops the SCCM client (ccmexec), Windows Update (wuauserv), WMI (winmgmt), BITS and any
         optional extra services (see $Config.ExtraServices), dependents first. A service that
         refuses to stop is killed ONLY if it runs in its own dedicated process.
      2. Deletes the network cache directory (BITS download queue) and restarts BITS.
      3. Optionally deletes the local Windows Update policy key (HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate).
      4. Optionally resets / enforces the WinHTTP proxy (disabled unless configured).
      5. Checks Registry.pol and renames it to registry.old if its header is invalid.
      6. Runs gpupdate, then optionally re-applies local Windows Update policy values
         (disabled unless configured).
      7. Un-pauses SCCM Software Distribution, restarts the services, requests a Windows Update scan.
      8. Triggers the SCCM client schedules, removes SCCM PrePostActions records and refreshes the
         software update compliance state.
      9. In every case (success or failure) the stopped services are started again.

    All environment-specific settings (proxy, Windows Update policy values, extra services, ...)
    live in the CONFIGURATION region below and are EMPTY BY DEFAULT: with the defaults, the
    proxy and policy steps are skipped.

    WARNING: this is a disruptive maintenance action. It restarts core services (including WMI),
    deletes the BITS queue, can change the Windows Update policy and the WinHTTP proxy, and
    triggers update scans. Review the target list and use a maintenance window.
    It is provided as-is, without warranty: test it on a non-production machine first.

.PARAMETER ComputerName
    One or more target computers (names are trimmed and de-duplicated).

.PARAMETER ThrottleLimit
    Maximum number of targets processed in parallel. Default: 16.

.PARAMETER Credential
    Optional credential used for the remote connections. Default: the current user.

.PARAMETER LogPath
    Local log file. Default: %LOCALAPPDATA%\ShakeWSUS\Logs\ShakeWSUS_<user>.log

.PARAMETER Force
    Skips the interactive confirmation. Use with care.

.EXAMPLE
    .\ShakeWSUS.ps1 -ComputerName SERVER01, SERVER02
    Shows the targets and asks for confirmation (type YES) before touching anything.

.EXAMPLE
    .\ShakeWSUS.ps1 -ComputerName (Get-Content .\servers.txt) -ThrottleLimit 4 -Force
    Processes a list of servers, four at a time, without prompting.

.NOTES
    PowerShell    : Windows PowerShell 5.1 or later (the remote targets run the script block
                    with whatever PowerShell version their remoting endpoint provides).
    Remoting      : WinRM / PowerShell remoting must be enabled and reachable on each target.
    Authorization : The account used (current user or -Credential) must be a local
                    administrator on every target.
    Exit code     : 0 when every target completed, 1 otherwise.
    Safety        : No remote change is made unless YES is typed (or -Force is used).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]]$ComputerName,

    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 16,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$LogPath = (Join-Path $env:LOCALAPPDATA ("ShakeWSUS\Logs\ShakeWSUS_{0}.log" -f $env:USERNAME)),

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# CONFIGURATION - everything environment-specific lives here.
# The defaults below are generic; the optional features are disabled until configured.
# This hashtable is sent as-is to every target, keep it made of plain hashtables/arrays/strings/numbers.
# -----------------------------------------------------------------------------
$Config = @{
    # Service handling ---------------------------------------------------------
    ServiceRetryCount  = 3      # stop attempts per service
    ServiceWaitTimeout = 60     # seconds to wait for a start/stop transition

    # Optional extra services stopped before and restarted after the maintenance
    # (for example an endpoint-protection agent that locks files). Service short names.
    # They are stopped after the core services and started after them. Example:
    #   ExtraServices = @('MyEndpointAgent', 'MyEndpointMonitor')
    ExtraServices      = @()

    # Directory deleted during the maintenance (BITS download queue / network cache).
    NetworkCachePath   = 'C:\ProgramData\Microsoft\Network'

    # Timeouts -----------------------------------------------------------------
    GpUpdateTimeout    = 180    # seconds before gpupdate is killed
    UpdateScanTimeout  = 300    # max seconds spent waiting for the Windows Update service to go idle

    # Windows Update local policy ----------------------------------------------
    # $true : delete HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate before gpupdate,
    #         so that the domain policy is applied from a clean state.
    ResetWindowsUpdatePolicy = $true

    # Values (re)written AFTER gpupdate, under ...\Policies\Microsoft\Windows\WindowsUpdate
    # and ...\WindowsUpdate\AU. Strings become REG_SZ, integers become REG_DWORD.
    # Leave empty to skip. Example (documented Windows Update policy names, placeholder URLs):
    #   WindowsUpdatePolicy   = @{
    #       WUServer        = 'https://wsus.example.com:8531'
    #       WUStatusServer  = 'https://wsus.example.com:8531'
    #       DisableDualScan = 1
    #   }
    #   WindowsUpdateAuPolicy = @{ UseWUServer = 1 }
    WindowsUpdatePolicy   = @{}
    WindowsUpdateAuPolicy = @{}

    # WinHTTP proxy ------------------------------------------------------------
    # The step is skipped when neither LegacyPatterns nor (Server + DetectPattern) is set.
    # The comparison is a case-insensitive substring search in the output of
    # "netsh winhttp show proxy", so it does not depend on the OS display language.
    Proxy = @{
        # Texts (host name, IP address, ...) that identify an OBSOLETE proxy. If one of them
        # is found, the WinHTTP proxy is reset to direct access.   Example: @('10.0.0.1')
        LegacyPatterns = @()

        # Text identifying a proxy configuration that must be kept in line with the settings
        # below (example: the proxy host name). When found, Server and BypassList must both
        # be present, otherwise they are re-applied.
        DetectPattern  = ''

        # Proxy to enforce, as accepted by "netsh winhttp set proxy". Example: 'proxy.example.com:8080'
        Server         = ''

        # Bypass list ("a;b;<local>"). Empty = no bypass list.
        BypassList     = '<local>'
    }
}

# -----------------------------------------------------------------------------
# Local helpers
# -----------------------------------------------------------------------------

# Appends a timestamped line to the local log file.
function Write-LocalLog {
    param([string]$Message)
    $entry = '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $LogPath -Value $entry -Encoding UTF8
}

# Result bookkeeping (filled while the remote output is streamed).
$completed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$failed    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Handles one item coming back from Invoke-Command: an error, the completion marker,
# or a log line emitted by the remote script block.
function Write-RemoteResult {
    param($Result)

    # Invoke-Command tags every output object with the name of the computer it comes from.
    $computer = [string]$Result.PSComputerName

    if ($Result -is [System.Management.Automation.ErrorRecord]) {
        # For connection errors PSComputerName may be empty: fall back to OriginInfo, then to
        # the error target (which is the computer name in that case).
        if (-not $computer) { $computer = [string]$Result.OriginInfo.PSComputerName }
        if (-not $computer -and $Result.TargetObject -is [string]) { $computer = $Result.TargetObject }
        if (-not $computer) { $computer = 'Unknown target' }

        [void]$failed.Add($computer)
        $message = $Result.Exception.Message
        Write-Host "[$computer] ERROR: $message" -ForegroundColor Red
        Write-LocalLog "[$computer] ERROR: $message"
        return
    }

    if (-not $computer) { $computer = 'Unknown target' }

    # The remote block ends with a marker object: it means the sequence ran to the end.
    if ($Result -is [pscustomobject] -and $Result.MaintenanceComplete) {
        [void]$completed.Add($computer)
        [void]$completed.Add([string]$Result.ComputerName)
        return
    }

    # Anything else is a log line produced by Write-Log on the target.
    $line = [string]$Result
    if ($line) {
        $color = if ($line -match '\[Error\]') { 'Red' }
                 elseif ($line -match '\[Warning\]') { 'Yellow' }
                 elseif ($line -match '\[Success\]') { 'Green' }
                 else { 'Gray' }
        Write-Host "[$computer] $line" -ForegroundColor $color
        Write-LocalLog "[$computer] $line"
    }
}

# -----------------------------------------------------------------------------
# Remote script block - runs on each target (receives $Config as its only argument).
# -----------------------------------------------------------------------------
$MaintenanceScriptBlock = {
    param($Cfg)

    # Keep going on non-terminating errors: every step handles and logs its own failures.
    $ErrorActionPreference = 'Continue'

    $ServiceRetryCount  = [int]$Cfg.ServiceRetryCount
    $ServiceWaitTimeout = [int]$Cfg.ServiceWaitTimeout
    $GpUpdateTimeout    = [int]$Cfg.GpUpdateTimeout
    $UpdateScanTimeout  = [int]$Cfg.UpdateScanTimeout

    # --- Generic helpers ---------------------------------------------------------

    # Log lines are written to the output stream so that the caller receives them.
    function Write-Log {
        param(
            [Parameter(Mandatory, Position = 0)][string]$Message,
            [ValidateSet('Info', 'Warning', 'Error', 'Success')][string]$Level = 'Info'
        )
        Write-Output "$(Get-Date -Format 'HH:mm:ss') [$Level] $Message"
    }

    # Case-insensitive "contains" without wildcard/regex interpretation.
    function Test-TextContains {
        param([string]$Text, [string]$Value)
        if (-not $Value) { return $false }
        return ($Text.IndexOf($Value, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    }

    # Returns the Win32_Service instance of a service ($null if it does not exist).
    # Backslashes and quotes are escaped so that any service name is safe in a WQL filter.
    function Get-ServiceInfo {
        param([Parameter(Mandatory)][string]$Name)
        $safeName = $Name.Replace('\', '\\').Replace("'", "\'")
        Get-CimInstance -ClassName Win32_Service -Filter "Name='$safeName'" -ErrorAction SilentlyContinue
    }

    # --- Service handling --------------------------------------------------------

    # Stops a service (dependents first). Escalation: Stop-Service, wait for pending states,
    # then kill the process ONLY when it hosts that single service.
    # On failure it sets $script:StopFailed (the log lines use the output stream, so the
    # function cannot also return a value).
    function Stop-ServiceWithRetry {
        param(
            [Parameter(Mandatory)][string]$ServiceName,
            [int]$RetryCount = $ServiceRetryCount,
            [int]$WaitTimeoutSeconds = $ServiceWaitTimeout
        )

        Write-Log "STOP SERVICE: $ServiceName (retries=$RetryCount timeout=${WaitTimeoutSeconds}s)"

        # A service cannot stop while services depending on it are running: stop those first.
        $dependents = @(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty DependentServices)
        foreach ($dependent in $dependents) {
            Write-Log "  Stopping dependent: $($dependent.Name)"
            Stop-ServiceWithRetry -ServiceName $dependent.Name -RetryCount $RetryCount -WaitTimeoutSeconds $WaitTimeoutSeconds
            if ($script:StopFailed) { return }
        }

        $svcInfo = Get-ServiceInfo -Name $ServiceName
        if (-not $svcInfo) {
            Write-Log "Service not found, skipping: $ServiceName" -Level Warning
            return
        }

        # Normal stop, with retries.
        for ($i = 1; $i -le $RetryCount; $i++) {
            $svcInfo = Get-ServiceInfo -Name $ServiceName
            if (-not $svcInfo -or $svcInfo.State -eq 'Stopped') {
                Write-Log "$ServiceName stopped" -Level Success
                return
            }

            if ($svcInfo.State -notmatch 'Pending') {
                Write-Log "Attempt #$i to stop '$ServiceName' (state=$($svcInfo.State))" -Level Warning
                try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
                catch { Write-Log "Stop request failed for $ServiceName : $($_.Exception.Message)" -Level Warning }
            } else {
                Write-Log "$ServiceName is already $($svcInfo.State); waiting for the current transition" -Level Warning
            }

            # Wait for the transition to finish (or for the service to leave the Pending state).
            $stopwatch = [Diagnostics.Stopwatch]::StartNew()
            while ($stopwatch.Elapsed.TotalSeconds -lt $WaitTimeoutSeconds) {
                Start-Sleep -Seconds 2
                $svcInfo = Get-ServiceInfo -Name $ServiceName
                if (-not $svcInfo -or $svcInfo.State -eq 'Stopped') {
                    Write-Log "$ServiceName stopped" -Level Success
                    return
                }
                if ($svcInfo.State -notmatch 'Pending') { break }
            }
            $stopwatch.Stop()

            # Still stuck in a Pending state after the full timeout: retrying will not help.
            if ($svcInfo -and $svcInfo.State -match 'Pending') {
                Write-Log "$ServiceName remains $($svcInfo.State) after ${WaitTimeoutSeconds}s" -Level Warning
                break
            }
        }

        # Last resort: kill the process, but only if it hosts this service alone
        # (never kill a shared svchost.exe that carries unrelated services).
        $svcInfo = Get-ServiceInfo -Name $ServiceName
        if ($svcInfo -and $svcInfo.ProcessId -gt 0 -and $svcInfo.State -ne 'Stopped') {
            $hostedServices = @(Get-CimInstance -ClassName Win32_Service -Filter "ProcessId=$($svcInfo.ProcessId)" -ErrorAction SilentlyContinue)
            if ($hostedServices.Count -eq 1 -and $hostedServices[0].Name -eq $ServiceName) {
                Write-Log "$ServiceName did not stop; killing its dedicated PID $($svcInfo.ProcessId)" -Level Warning
                try { Stop-Process -Id $svcInfo.ProcessId -Force -ErrorAction Stop }
                catch {
                    taskkill.exe /PID $svcInfo.ProcessId /F 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Log "Failed to kill dedicated PID $($svcInfo.ProcessId) for $ServiceName" -Level Error
                    }
                }

                # Give the service control manager a moment to notice the process is gone.
                $stopwatch = [Diagnostics.Stopwatch]::StartNew()
                while ($stopwatch.Elapsed.TotalSeconds -lt 15) {
                    Start-Sleep -Seconds 1
                    $svcInfo = Get-ServiceInfo -Name $ServiceName
                    if (-not $svcInfo -or $svcInfo.State -eq 'Stopped') {
                        Write-Log "$ServiceName stopped after dedicated-process termination" -Level Success
                        return
                    }
                }
                $stopwatch.Stop()
            } else {
                $sharedNames = ($hostedServices | ForEach-Object { $_.Name }) -join ', '
                Write-Log "$ServiceName PID $($svcInfo.ProcessId) is shared by [$sharedNames]; refusing to kill unrelated services" -Level Error
            }
        }

        Write-Log "FAILED to stop $ServiceName; the maintenance will not continue with cache/policy changes" -Level Error
        $script:StopFailed = $true
    }

    # Starts a service, then starts its dependents that are set to Automatic start.
    function Start-ServiceWithChildServices {
        param(
            [Parameter(Mandatory)][string]$ParentService,
            [int]$WaitTimeoutSeconds = $ServiceWaitTimeout
        )

        $parent = Get-ServiceInfo -Name $ParentService
        if (-not $parent) {
            Write-Log "Parent service not found: $ParentService" -Level Warning
            return
        }

        if ($parent.State -ne 'Running') {
            Write-Log "Starting $ParentService" -Level Warning
            try {
                Start-Service -Name $ParentService -ErrorAction Stop
                (Get-Service -Name $ParentService).WaitForStatus('Running', (New-TimeSpan -Seconds $WaitTimeoutSeconds))
                Write-Log "$ParentService is Running" -Level Success
            } catch {
                Write-Log "$ParentService failed to start: $($_.Exception.Message)" -Level Warning
            }
        } else {
            Write-Log "$ParentService already Running"
        }

        Get-Service -Name $ParentService -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty DependentServices |
            ForEach-Object {
                $svcName = $_.Name
                $info = Get-ServiceInfo -Name $svcName
                if ($info -and $info.StartMode -eq 'Auto') {
                    if ($info.State -ne 'Running') {
                        # The whole start is inside the try block: a failure must be logged as a
                        # warning, not leak as an error record (which would flag the target as failed).
                        try {
                            Start-Service -Name $svcName -ErrorAction Stop
                            (Get-Service -Name $svcName).WaitForStatus('Running', (New-TimeSpan -Seconds $WaitTimeoutSeconds))
                            Write-Log "$svcName Running" -Level Success
                        } catch {
                            Write-Log "$svcName did not start within ${WaitTimeoutSeconds}s: $($_.Exception.Message)" -Level Warning
                        }
                    }
                } elseif ($info) {
                    Write-Log "Skipped $svcName (StartMode='$($info.StartMode)')"
                }
            }
    }

    # --- Group Policy / Windows Update / SCCM -----------------------------------

    # Checks the header of the local Group Policy file (Registry.pol). A valid file starts
    # with the 4 ASCII bytes "PReg"; a corrupt one breaks policy processing, so it is renamed
    # (Windows recreates it at the next policy refresh).
    function Test-RegistryPolFile {
        $polPath = Join-Path $env:windir 'System32\GroupPolicy\Machine\Registry.pol'
        if (-not (Test-Path -LiteralPath $polPath -PathType Leaf)) {
            Write-Log 'Registry.pol does not exist - nothing to remediate'
            return
        }

        try {
            # Open with shared read/write access: the Group Policy client may hold the file.
            $stream = [System.IO.File]::Open($polPath, 'Open', 'Read', 'ReadWrite')
            try {
                $header = New-Object byte[] 4
                $bytesRead = $stream.Read($header, 0, 4)
            } finally {
                $stream.Dispose()
            }

            # 0x50 0x52 0x65 0x67 = "PReg"
            if ($bytesRead -eq 4 -and $header[0] -eq 0x50 -and $header[1] -eq 0x52 -and
                $header[2] -eq 0x65 -and $header[3] -eq 0x67) {
                Write-Log 'Registry.pol is valid' -Level Success
                return
            }

            Write-Log 'Registry.pol is corrupt - renaming to registry.old' -Level Warning
            $backupPath = Join-Path (Split-Path $polPath) 'registry.old'
            if (Test-Path -LiteralPath $backupPath) { Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue }
            Rename-Item -LiteralPath $polPath -NewName 'registry.old' -Force -ErrorAction Stop
            Write-Log 'Registry.pol renamed' -Level Success
        } catch {
            Write-Log "Registry.pol check failed: $($_.Exception.Message)" -Level Error
        }
    }

    # Requests a Windows Update scan through UsoClient, then waits for the update service
    # to go idle before refreshing the update settings.
    function Invoke-WindowsUpdateScan {
        param([int]$TimeoutSeconds = $UpdateScanTimeout)

        $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
        if (-not (Test-Path -LiteralPath $uso)) {
            Write-Log 'UsoClient.exe not found - skipping scan' -Level Error
            return
        }

        try {
            Write-Log 'Starting update scan via UsoClient'
            Start-Process -FilePath $uso -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        } catch {
            Write-Log "StartScan failed: $($_.Exception.Message)" -Level Warning
        }

        # UsoClient returns immediately and gives no completion signal. The loop waits until
        # the Windows Update service stops (it stops itself once idle). NOTE: wuauserv often
        # stays running, in which case this loop lasts the whole timeout ($UpdateScanTimeout).
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            $wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
            if (-not $wu -or $wu.Status -ne 'Running') { break }
            Start-Sleep -Seconds 5
        }
        $stopwatch.Stop()

        try {
            Start-Process -FilePath $uso -ArgumentList 'RefreshSettings' -NoNewWindow -Wait -ErrorAction Stop
        } catch {
            Write-Log "RefreshSettings failed: $($_.Exception.Message)" -Level Warning
        }

        Write-Log 'Windows Update scan completed' -Level Success
    }

    # Writes a set of policy values under a registry key (created if missing).
    # Strings become REG_SZ, everything else REG_DWORD.
    function Set-PolicyValues {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)]$Values
        )
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        foreach ($entry in $Values.GetEnumerator()) {
            $propertyType = if ($entry.Value -is [string]) { 'String' } else { 'DWord' }
            New-ItemProperty -Path $Path -Name $entry.Key -PropertyType $propertyType `
                -Value $entry.Value -Force -ErrorAction Stop | Out-Null
        }
    }

    # Applies the optional WinHTTP proxy policy of the configuration (see $Config.Proxy).
    function Update-WinHttpProxy {
        param($Proxy)

        $legacyPatterns = @($Proxy.LegacyPatterns | Where-Object { $_ })
        $managed = [bool]($Proxy.Server -and $Proxy.DetectPattern)
        if (-not $legacyPatterns -and -not $managed) {
            Write-Log 'WinHTTP proxy management not configured - skipping'
            return
        }

        $proxyInfo = (netsh winhttp show proxy) -join "`n"

        # 1) Obsolete proxy still configured: go back to direct access.
        foreach ($pattern in $legacyPatterns) {
            if (Test-TextContains $proxyInfo $pattern) {
                netsh winhttp reset proxy | Out-Null
                Write-Log "Proxy reset (legacy pattern '$pattern' found) - WinHTTP is now direct" -Level Warning
                return
            }
        }

        # 2) Managed proxy: make sure the expected server and bypass entries are present.
        #    Substring checks on the whole netsh output keep this independent of the OS language.
        if ($managed -and (Test-TextContains $proxyInfo $Proxy.DetectPattern)) {
            $serverOk = Test-TextContains $proxyInfo $Proxy.Server
            $missingBypass = @($Proxy.BypassList -split ';' | Where-Object { $_ } |
                Where-Object { -not (Test-TextContains $proxyInfo $_) })

            if ($serverOk -and $missingBypass.Count -eq 0) {
                Write-Log 'Proxy OK' -Level Success
            } else {
                if ($Proxy.BypassList) {
                    netsh winhttp set proxy proxy-server="$($Proxy.Server)" bypass-list="$($Proxy.BypassList)" | Out-Null
                } else {
                    netsh winhttp set proxy proxy-server="$($Proxy.Server)" | Out-Null
                }
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Proxy configured: $($Proxy.Server)" -Level Success
                } else {
                    Write-Log "netsh failed to set the proxy (exit $LASTEXITCODE)" -Level Error
                }
            }
        } else {
            Write-Log 'No managed proxy pattern found - skipping proxy config'
        }
    }

    # Standard client schedules (TriggerSchedule IDs). Order matters only for the log.
    $sccmActions = [ordered]@{
        'App Deployment Evaluation'     = '{00000000-0000-0000-0000-000000000121}'
        'Hardware Inventory Cycle'      = '{00000000-0000-0000-0000-000000000001}'
        'Policy Retrieval Cycle'        = '{00000000-0000-0000-0000-000000000021}'
        'Policy Evaluation Cycle'       = '{00000000-0000-0000-0000-000000000022}'
        'Software Inventory Cycle'      = '{00000000-0000-0000-0000-000000000002}'
        'Update Deployment Eval Cycle'  = '{00000000-0000-0000-0000-000000000114}'
        'Update Scan Cycle'             = '{00000000-0000-0000-0000-000000000113}'
        'Update Evaluation'             = '{00000000-0000-0000-0000-000000000108}'
        'State Message Refresh'         = '{00000000-0000-0000-0000-000000000111}'
        'Source List Update Cycle'      = '{00000000-0000-0000-0000-000000000032}'
        'Location Service Refresh'      = '{00000000-0000-0000-0000-000000000024}'
        'Clearing Proxy Settings Cache' = '{00000000-0000-0000-0000-000000000037}'
    }
    $updateEvaluationSchedule = '{00000000-0000-0000-0000-000000000108}'

    # Services handled by the maintenance. The stop order and the start order differ on purpose
    # (core services first/last), so they are kept as ordered arrays defined here.
    $extraServices = @($Cfg.ExtraServices | Where-Object { $_ })
    $stopOrder  = @('ccmexec', 'wuauserv', 'winmgmt', 'bits') + $extraServices
    $script:RestartServices = @('winmgmt', 'bits', 'wuauserv', 'ccmexec') + $extraServices

    # --- Main sequence -------------------------------------------------------------
    try {
        Write-Log "Maintenance starting on $env:COMPUTERNAME (as $env:USERNAME)"
        $script:StopFailed = $false

        # 1. Stop the services. Abort BEFORE any destructive step if one of them refuses to stop.
        foreach ($svcName in $stopOrder) {
            Stop-ServiceWithRetry -ServiceName $svcName
            if ($script:StopFailed) {
                throw "Could not stop required service '$svcName'. See service-state diagnostics above."
            }
        }

        # 2. Delete the network cache (BITS queue), then bring BITS back right away.
        $networkCachePath = [string]$Cfg.NetworkCachePath
        if ($networkCachePath -and (Test-Path -LiteralPath $networkCachePath)) {
            Remove-Item -LiteralPath $networkCachePath -Recurse -Force -ErrorAction SilentlyContinue
            # Remove-Item is silent on failure here: check the result before claiming success.
            if (Test-Path -LiteralPath $networkCachePath) {
                Write-Log "Network cache could not be fully removed (files in use?): $networkCachePath" -Level Warning
            } else {
                Write-Log "Network cache removed: $networkCachePath" -Level Success
            }
        } else {
            Write-Log "Network cache path not found: $networkCachePath"
        }

        try {
            Start-Service -Name bits -ErrorAction Stop
            Write-Log 'BITS is Running' -Level Success
        } catch {
            Write-Log "Failed to start BITS: $($_.Exception.Message)" -Level Warning
        }

        # 3. Remove the local Windows Update policy key (optional).
        $wuPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        if ($Cfg.ResetWindowsUpdatePolicy -and (Test-Path -LiteralPath $wuPolicyPath)) {
            Remove-Item -LiteralPath $wuPolicyPath -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $wuPolicyPath) {
                Write-Log 'Windows Update policy key could not be fully removed' -Level Warning
            } else {
                Write-Log 'Windows Update policies removed' -Level Success
            }
        }

        # 4. WinHTTP proxy (optional).
        Update-WinHttpProxy -Proxy $Cfg.Proxy

        # 5. Group Policy file sanity check.
        Test-RegistryPolFile

        # 6. Refresh computer policy. Bounded by a timeout so a hung gpupdate cannot block the run.
        Write-Log 'Running gpupdate /force'
        try {
            $gp = Start-Process -FilePath 'gpupdate.exe' `
                -ArgumentList '/force', '/target:computer', "/wait:$GpUpdateTimeout" `
                -NoNewWindow -PassThru -ErrorAction Stop
            if ($gp.WaitForExit($GpUpdateTimeout * 1000)) {
                Write-Log "gpupdate finished (exit $($gp.ExitCode))" -Level Success
            } else {
                try { $gp.Kill() } catch { Write-Log "Could not kill gpupdate: $($_.Exception.Message)" -Level Warning }
                Write-Log "gpupdate timed out after ${GpUpdateTimeout}s - killed" -Level Warning
            }
        } catch {
            Write-Log "gpupdate failed: $($_.Exception.Message)" -Level Error
        }

        # 6b. Re-apply the configured local Windows Update policy values (optional).
        $wuValues   = $Cfg.WindowsUpdatePolicy
        $wuAuValues = $Cfg.WindowsUpdateAuPolicy
        if (($wuValues -and $wuValues.Count -gt 0) -or ($wuAuValues -and $wuAuValues.Count -gt 0)) {
            try {
                if ($wuValues -and $wuValues.Count -gt 0) {
                    Set-PolicyValues -Path $wuPolicyPath -Values $wuValues
                }
                if ($wuAuValues -and $wuAuValues.Count -gt 0) {
                    Set-PolicyValues -Path (Join-Path $wuPolicyPath 'AU') -Values $wuAuValues
                }
                Write-Log 'Windows Update local policy values reapplied' -Level Success
            } catch {
                Write-Log "Failed to reapply Windows Update local policy values: $($_.Exception.Message)" -Level Warning
            }
        } else {
            Write-Log 'No Windows Update policy values configured - nothing to reapply'
        }

        # 7. Make sure SCCM Software Distribution is not paused (the key only exists with the client).
        try {
            $sdState = 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\State'
            New-ItemProperty -Path $sdState -Name 'Paused' -PropertyType DWord -Force -Value 0 -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $sdState -Name 'PausedCookie' -PropertyType DWord -Force -Value 0 -ErrorAction Stop | Out-Null
            Write-Log 'SCCM Software Distribution unpaused' -Level Success
        } catch {
            Write-Log "Failed to unpause SCCM: $($_.Exception.Message)" -Level Warning
        }

        # 8. Start everything again, then request a Windows Update scan.
        foreach ($svcName in $script:RestartServices) {
            Start-ServiceWithChildServices -ParentService $svcName
        }
        Start-Sleep -Seconds 10
        Invoke-WindowsUpdateScan

        # 9. SCCM client actions (only when the client is installed).
        if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
            foreach ($action in $sccmActions.GetEnumerator()) {
                try {
                    Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule `
                        -Arguments @{ sScheduleID = $action.Value } -ErrorAction Stop | Out-Null
                    Write-Log "Triggered: $($action.Key)" -Level Success
                } catch {
                    Write-Log "Failed to trigger $($action.Key): $($_.Exception.Message)" -Level Error
                }
            }

            # Remove stale PrePostActions records (they can keep the software update group
            # locked), then trigger the update evaluation again.
            try {
                foreach ($ns in 'ROOT\ccm\Policy\Machine\RequestedConfig', 'ROOT\ccm\Policy\Machine\ActualConfig') {
                    Get-CimInstance -Namespace $ns -ClassName CCM_PrePostActions -ErrorAction SilentlyContinue |
                        Remove-CimInstance -ErrorAction SilentlyContinue
                }
                Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule `
                    -Arguments @{ sScheduleID = $updateEvaluationSchedule } -ErrorAction Stop | Out-Null
                Write-Log 'PrePostActions records removed' -Level Success
            } catch {
                Write-Log "PrePostActions removal failed: $($_.Exception.Message)" -Level Warning
            }

            # Refresh the software update compliance state through the client COM object.
            try {
                $store = New-Object -ComObject Microsoft.CCM.UpdatesStore
                $store.RefreshServerComplianceState() | Out-Null
                Write-Log 'Compliance state refreshed' -Level Success
            } catch {
                Write-Log "Compliance refresh failed: $($_.Exception.Message)" -Level Warning
            }
        } else {
            Write-Log 'SCCM client not installed - skipping SCCM actions'
        }

        Write-Log "Maintenance completed on $env:COMPUTERNAME" -Level Success
    } catch {
        Write-Log "CRITICAL ERROR: $($_.Exception.Message)" -Level Error
        throw
    } finally {
        # Always leave the machine with its services running, even after an error above:
        # restart what is still stopped, and the automatic dependents that went down with it.
        foreach ($svcName in ($script:RestartServices | Select-Object -Unique)) {
            $svcInfo = Get-ServiceInfo -Name $svcName
            if (-not $svcInfo) { continue }

            # A service caught mid-transition must settle before it can be started.
            if ($svcInfo.State -match 'Pending') {
                Write-Log "$svcName remains $($svcInfo.State); waiting before restart" -Level Warning
                $stopwatch = [Diagnostics.Stopwatch]::StartNew()
                while ($stopwatch.Elapsed.TotalSeconds -lt $ServiceWaitTimeout) {
                    Start-Sleep -Seconds 2
                    $svcInfo = Get-ServiceInfo -Name $svcName
                    if (-not $svcInfo -or $svcInfo.State -notmatch 'Pending') { break }
                }
                $stopwatch.Stop()
            }

            if ($svcInfo -and $svcInfo.State -eq 'Stopped') {
                Write-Log "$svcName is $($svcInfo.State) - forcing restart" -Level Warning
                try {
                    Start-Service -Name $svcName -ErrorAction Stop
                    (Get-Service -Name $svcName).WaitForStatus('Running', (New-TimeSpan -Seconds $ServiceWaitTimeout))
                    Write-Log "$svcName is Running" -Level Success
                } catch {
                    Write-Log "Failed to force-start $svcName : $($_.Exception.Message)" -Level Error
                }
            } elseif ($svcInfo -and $svcInfo.State -ne 'Running') {
                Write-Log "Could not restart $svcName because it remains $($svcInfo.State)" -Level Error
            }

            $dependentServices = @(Get-Service -Name $svcName -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty DependentServices)
            foreach ($dependent in $dependentServices) {
                $dependentName = $dependent.Name
                $dependentInfo = Get-ServiceInfo -Name $dependentName
                if (-not $dependentInfo -or $dependentInfo.State -ne 'Stopped') { continue }
                Write-Log "Restarting child dependency: $dependentName" -Level Warning
                try {
                    Start-Service -Name $dependentName -ErrorAction Stop
                    (Get-Service -Name $dependentName).WaitForStatus('Running', (New-TimeSpan -Seconds $ServiceWaitTimeout))
                    Write-Log "$dependentName is Running" -Level Success
                } catch {
                    Write-Log "Failed to force-start child service $dependentName : $($_.Exception.Message)" -Level Error
                }
            }
        }
    }

    # Completion marker: lets the caller tell "ran to the end" from "connection dropped".
    [pscustomobject]@{
        MaintenanceComplete = $true
        ComputerName        = $env:COMPUTERNAME
    }
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

# Normalise the target list.
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$ComputerName = @($ComputerName | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $seen.Add($_) })
if ($ComputerName.Count -eq 0) {
    throw 'No target computers were given. Pass one or more names with -ComputerName.'
}

Write-Host ''
Write-Host 'SHAKE WSUS - REMOTE WSUS/SCCM CLIENT MAINTENANCE' -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "Targets      : $($ComputerName -join ', ')" -ForegroundColor White
Write-Host "Throttle     : $ThrottleLimit" -ForegroundColor White
Write-Host 'Impact       : service restarts, policy changes, cache deletion, update scan' -ForegroundColor Yellow
Write-Host "Log file     : $LogPath" -ForegroundColor Gray
Write-Host ''
Write-Host 'The action may interrupt SCCM / Windows Update activity on the selected computers.' -ForegroundColor Yellow

if (-not $Force) {
    $confirmation = Read-Host 'Type YES to proceed'
    if ($confirmation -cne 'YES') {
        Write-Host 'Cancelled. No remote action was started.' -ForegroundColor Yellow
        return
    }
}

$logDirectory = Split-Path -Path $LogPath -Parent
if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
}

Write-Verbose 'Invoking the maintenance sequence over PowerShell remoting.'
Write-LocalLog "Started by $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) for: $($ComputerName -join ', ')"

$invokeParams = @{
    ComputerName  = $ComputerName
    ThrottleLimit = $ThrottleLimit
    ScriptBlock   = $MaintenanceScriptBlock
    ArgumentList  = @(, $Config)
    ErrorAction   = 'Continue'
}
if ($Credential) { $invokeParams.Credential = $Credential }

# Results are processed as they arrive, so the console follows each target live.
# 2>&1 turns remote and connection errors into objects that Write-RemoteResult can attribute.
try {
    Invoke-Command @invokeParams 2>&1 | ForEach-Object { Write-RemoteResult -Result $_ }
} catch {
    Write-RemoteResult -Result $_
}

# Summary: a target is OK only if it sent the completion marker and no error.
Write-Host ''
Write-Host 'RESULTS' -ForegroundColor Cyan
$failureCount = 0
foreach ($computer in $ComputerName) {
    if ($completed.Contains($computer) -and -not $failed.Contains($computer)) {
        Write-Host "  OK      $computer" -ForegroundColor Green
        Write-LocalLog "[$computer] RESULT=OK"
    } else {
        $failureCount++
        Write-Host "  FAILED  $computer (see preceding errors and log)" -ForegroundColor Red
        Write-LocalLog "[$computer] RESULT=FAILED or no completion marker"
    }
}
Write-Host "Detailed log: $LogPath" -ForegroundColor Gray
Write-LocalLog 'Run completed.'

if ($failureCount -gt 0) { exit 1 }
