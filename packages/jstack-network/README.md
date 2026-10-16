# Wi-Fi connection and captive portal recovery

## Recovery flow

- `wifi-pick` shows cached scan results without waiting for a full scan. Selecting
  an already-active network checks its portal instead of tearing the link down.
- After a successful activation, one detached `captive-portal-helper` owns recovery.
  There are no competing shell verification loops or SSIDs interpolated into shell.
- `captive-portal-monitor.service` subscribes to `nmcli monitor` so automatic
  reconnects and resume are covered. `captive-portal-helper.timer` is the retry
  safety net. Enable these two units, not the legacy browser-opening watcher:

  ```sh
  systemctl --user daemon-reload
  systemctl --user enable --now captive-portal-monitor.service captive-portal-helper.timer
  ```

- The helper uses cached NetworkManager state and cached scan results, a
  nonblocking per-user lock, network identity guards, and a 60-second failed-attempt
  cooldown. A failed attempt is retryable, not permanently suppressed. A disconnect
  clears that cooldown. Browser-required portals open one fallback page.
- The acceptor never forces an NM connectivity check. Direct HTTP 204 probes have
  separate two-second connect/read timeouts. Negative results are briefly reused
  only within a session, and every portal request invalidates them. Positive
  post-submit verification returns immediately, before marketing-page redirects.
- Credential, payment, voucher, CAPTCHA, and required personal-information forms
  remain refused. These need the user's browser rather than automatic submission.

## Validation

```sh
packages/jstack-network/tests/test-package.sh
```

The suite includes real localhost HTTP portal acceptance, safety refusals,
redirect cycles, stale NM state, cache invalidation after submissions, helper
concurrency, retry expiry, network changes, event monitoring, picker cancellation,
password redaction, and preserving the active connection. The injected-delay
benchmark is synthetic, not a measurement of a train's internet connection.

A local 2026-10-16 investigation found several historical 41-43 second intervals
between DHCP activation and confirmed internet, plus one 96-second interval.
Typical successful association plus IP setup was about 2-3 seconds. The old
acceptor's Caltrain log confirmed internet, then followed four unnecessary website
redirects. Old per-request logs were not timestamped, so they do not prove how
much of each historical interval was software delay versus portal/network delay.

## Diagnostics and operational limits

```sh
journalctl -u NetworkManager -u iwd --since '10 minutes ago'
journalctl --user -u captive-portal-monitor -u captive-portal-helper --since '10 minutes ago'
cat ~/.cache/captive-portal-helper/autoaccept.last.log
```

HTTP and connectivity diagnostics include timestamps and elapsed durations. New
HTTP diagnostic labels exclude form values and URL query tokens. Existing portal
selection output can still contain redirect URLs, so treat the local logs as
private and redact before sharing them.

No NetworkManager/iwd restart, Wi-Fi disconnect, DNS ownership migration, or VPN
setting change is required to deploy these helper changes. Back up installed
scripts before a scoped installation. Deploying only these scripts/units leaves
package-manager version metadata unchanged until a normal package upgrade.

No helper can guarantee fast AP association or a working upstream connection.
Independent review found two ~34-second activation outliers where association
finished in under half a second but DHCP took about 33 seconds (2026-10-11 and
2026-10-15). There were also missed beacons, AP loss, and AP-originated
deauthentications, with no firmware-crash signature found. These cannot be
attributed to the portal helper. Station logs alone cannot distinguish an RF/AP
problem from every possible driver problem. No speculative power-save, protocol,
IWD ownership, or DNS/VPN setting changes were applied.

A future real captive-network connection is needed to measure actual end-user
improvement without deliberately disconnecting a working session. New timestamped
portal diagnostics now let the next slow attempt distinguish helper request time
from DHCP, association, and upstream availability.
