# ShakeWSUS

PowerShell script that resets the WSUS / Windows Update / SCCM (MECM) client stack on one or more
remote computers, for machines whose client is stuck (no scan, stale compliance state, broken policy).

> **Warning** - this is a disruptive maintenance action. It restarts core services (including WMI),
> deletes the BITS download queue, can change the Windows Update policy and the WinHTTP proxy, and
> triggers update scans. Use a maintenance window and test on a non-production machine first.
> Provided as-is, without warranty (see [LICENSE](LICENSE)).

## What it does

On each target, through PowerShell remoting:

1. Stops `ccmexec`, `wuauserv`, `winmgmt`, `bits` and any optional extra service (dependents first).
2. Deletes the network cache directory (BITS queue) and restarts BITS.
3. Optionally deletes the local Windows Update policy key.
4. Optionally resets / enforces the WinHTTP proxy.
5. Checks `Registry.pol` and renames it to `registry.old` if its header is invalid.
6. Runs `gpupdate`, then optionally re-applies local Windows Update policy values.
7. Un-pauses SCCM Software Distribution, restarts the services, requests a Windows Update scan.
8. Triggers the SCCM client schedules, removes stale PrePostActions records, refreshes compliance state.

Services are always started again at the end, even after an error.

## Requirements

- Windows PowerShell 5.1 or later on the machine running the script.
- WinRM / PowerShell remoting enabled on each target.
- An account that is local administrator on each target.

## Usage

```powershell
# Asks for confirmation (type YES) before touching anything
.\ShakeWSUS.ps1 -ComputerName SERVER01, SERVER02

# From a list, 4 at a time, no prompt
.\ShakeWSUS.ps1 -ComputerName (Get-Content .\servers.txt) -ThrottleLimit 4 -Force
```

Parameters: `-ComputerName`, `-ThrottleLimit` (default 16), `-Credential`, `-LogPath`, `-Force`.
Exit code is `0` when every target completed, `1` otherwise.
The log is written to `%LOCALAPPDATA%\ShakeWSUS\Logs\` by default.

## Configuration

Environment-specific settings are in the `$Config` hashtable at the top of the script, and are
**empty by default** (the related steps are skipped):

| Setting | Purpose |
| --- | --- |
| `ExtraServices` | Extra services (e.g. an endpoint agent) stopped before and restarted after the maintenance |
| `WindowsUpdatePolicy` / `WindowsUpdateAuPolicy` | Policy values re-applied after `gpupdate` |
| `Proxy` | Legacy proxy patterns to reset, or a managed proxy to enforce (language-independent matching) |
| `ResetWindowsUpdatePolicy` | Delete the local Windows Update policy key before `gpupdate` |
| `NetworkCachePath`, timeouts | Cache directory and timeouts |

Examples are given in the comments of the script.

## Known limitation

After requesting a scan, the script waits for the Windows Update service to stop, which often only
happens at the timeout (`UpdateScanTimeout`, 300 s by default).

## License

[MIT](LICENSE)
