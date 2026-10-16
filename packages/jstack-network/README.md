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

## Live deployment observations (2026-10-16)

After installing the committed tools, these public interfaces were exercised
against the real NetworkManager and existing train connection, without stubs:

- Installed `WIFI_PICK_DUMP=1 /usr/bin/wifi-pick` returned the real active/saved
  network with its full-connectivity indicator in **0.124 seconds**. This verifies
  launcher data/startup, not interactive tofi selection.
- `systemctl --user start captive-portal-helper.service` completed successfully
  in **0.081 seconds**, with `ExecMainStatus=0` and cached connectivity `full`.
- Restarting only `captive-portal-monitor.service` exercised its real NM
  subscription/startup. The initial workers were serialized: one checked the
  actual network, another skipped the held lock. The monitor remained active
  with zero automatic restarts.
- Three real old-style `nmcli networking connectivity check` calls took
  **400.15, 404.65, and 377.06 ms**. Three new-style cached reads took
  **10.44, 11.68, and 10.64 ms**. The measured medians were **400.15 vs 10.64 ms**.
  This proves lower gate overhead on a working network, not a 38x improvement
  in joining Wi-Fi.
- The installed acceptor confirmed an actual external HTTP 204 and exited
  `already online` in **0.244 seconds**. No portal form was submitted.
- The IP address and active connection remained unchanged, with no NM activation
  or disconnect entries during these live checks. The retry timer was active.

The complete unauthenticated captive-login acceptance path remains blocked by
existing AP authorization: recreating it would require a fresh captive network
or altering the current authorization/connectivity. No logout, MAC change, or
disconnect was performed just to obtain a timing result. Local HTTP acceptance
and injected-delay regressions complement, but do not replace, that next real
connection measurement.

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
problem from every possible driver problem. At the initial deployment, no speculative power-save, protocol,
IWD ownership, or DNS/VPN setting changes had been applied. The targeted
follow-up below changes only the TLP Wi-Fi power policy.

A future real captive-network connection is needed to measure actual end-user
improvement without deliberately disconnecting a working session. New timestamped
portal diagnostics now let the next slow attempt distinguish helper request time
from DHCP, association, and upstream availability.

## October 16 afternoon follow-up

A subsequent real Stanford Visitor captive login succeeded at 14:13 PDT, taking
about 27.7 seconds. Timestamped diagnostics exposed a single connectivity probe
lasting **20.147 seconds**, despite requests connect/read timeouts of two seconds.
This proves a missing absolute deadline, not specifically a DNS fault. The probe
now uses curl with a three-second total timeout, two-second connect timeout, and
an independent four-second subprocess timeout that kills and reaps the child.
It ignores curlrc, does not follow redirects, never shares portal cookies, and
rejects even HTTP 204 with a Location header. Portal form handling stays in its
existing requests session. curl >=7.84 is now a declared dependency.

The installed public acceptor subsequently verified the real external HTTP 204
in **0.235 seconds** (whole process 0.371 seconds). The installed systemd helper
returned success/status 0. The final regression suite passed **53 tests** in
13.127 seconds, including public CLI tests using the installed script, real curl
and local HTTP. A deliberately stalled HTTP response hit the real curl deadline
in **3.007 seconds**, with the installed public process finishing in **3.160
seconds** and rejecting the probe. This directly exercises the deadline through
the installed interface, but is not a recreation of the original AP stall. Existing
authorization prevents measuring another fresh real captive login without
changing the current session. The previous real login demonstrates that the
portal workflow works, but is not a before/after join-speed comparison.

TLP was observed naturally changing wlan0 power saving from off to on when AC
was unplugged, on the same BSSID. Its battery default, not the SSID, owned this
policy. A live 30-packet gateway sample with power saving on averaged **36.295 ms**,
maximum **101.781 ms**; switching it off gave **2.653 ms**, maximum **9.105 ms**.
However, repeating on/off gave **3.085/5.783 ms** averages, so the initial latency
improvement was not consistently reproduced and is not proof of past drop causes.
All four samples had zero loss. The reversible mitigation sets only
`WIFI_PWR_ON_AC=off` and `WIFI_PWR_ON_BAT=off` in the existing owning TLP policy.
This trades some battery life for responsiveness. Live power saving is off and
TLP reports both effective values off. No CPU or other TLP setting was changed.

For unresolved Avalon DHCP stalls and radio losses, temporary NetworkManager
logging was enabled at 14:43:56 PDT: DHCP4:TRACE, WIFI:DEBUG, SUPPLICANT:DEBUG,
with other domains unchanged. A transient system timer restores the exact
previous logging configuration on **October 17, 2026 at 14:43:56 PDT**. Runtime
logging also resets on reboot. The internal DHCP library reads its log threshold
at client creation, so protocol detail starts with the next natural activation.
No activation was forced. To restore logging early:

```sh
sudo systemctl start jstack-wifi-diagnostics-reset-20261016.service
```

No causal DHCP/driver repair is proven yet. The current DHCP acquisition took
about 1.2 seconds, and the historical 33-second Avalon faults are not reproducible
on Stanford. DHCP4 trace on the next affected activation can distinguish discovery
retries from offered-lease handling, rather than guessing client IDs or shortening
timeouts. No protocol downgrade, DHCP backend migration, network restart, or
firmware upgrade was performed. IP and BSSID remained unchanged during checks.
Scoped installed-file backups are in
`/var/lib/jstack-network/backups/20261016-1447/`. Restore the saved TLP file and
run `sudo iw dev wlan0 set power_save on` to undo the battery-policy mitigation
while currently on battery. Restore the saved acceptor to undo the deadline fix.

### Requirement-to-observation acceptance map

| Requirement or changed behavior | Concrete check and observed result | Limit |
| --- | --- | --- |
| Identify why real joins stall | Actual 14:13 login diagnostics isolated a 20.147-second probe within a successful 27.7-second login; older NM timelines isolated two 33-second DHCP waits | Does not establish the HTTP stall phase or DHCP packet cause |
| Bound the newly identified probe wait | Installed CLI with real curl and stalled local HTTP response: probe 3.007 seconds, process 3.160 seconds, rejected response | Controlled server, not a replay of the AP fault |
| Preserve real online detection | Installed CLI contacted actual external endpoint, received 204 in 0.235 seconds, printed `already online`, exited successfully | Already authorized, not a fresh portal login |
| Preserve successful form acceptance | `test_real_http_accept_skips_success_redirect_cycle` executes installed CLI, real requests and curl against local HTTP; one accept POST, exit 0, no unnecessary redirect | Local controlled portal, not train AP |
| Reject redirects and misleading success | `test_public_script_real_curl_rejects_redirect_and_204_location` executes installed CLI for 302, 204+Location and 200; each exits 1, never follows target or exposes query token in diagnostic stderr | Controlled responses |
| Enforce subprocess cleanup and conservative errors | `test_stalled_resolver_child_is_killed_and_reaped` observes actual child termination; `test_probe_fails_closed_for_errors_redirects_and_missing_curl` covers return codes and absent executable | Resolver stand-in and unit injection, not evidence DNS caused original wait |
| Preserve credential/payment/personal-data refusal | `test_credential_payment_and_personal_fields_stay_refused` rejects those form fixtures | Fixture coverage, no real sensitive form submitted |
| Keep user launcher functional | At 14:50 PDT installed `WIFI_PICK_DUMP=1 /usr/bin/wifi-pick` showed Stanford Visitor active/full, Stanford saved, eduroam secured and Scan again | Real NM interface, not interactive menu selection or fresh join |
| Keep automatic recovery functional | Installed helper Result=success, ExecMainStatus=0; monitor and retry timer active at 14:50 | No fresh unauthenticated network transition induced |
| Prevent TLP from silently reversing mitigation | Natural AC-to-battery transition established owner; deployed config matches source, TLP effective AC/BAT values off, live iw off at 14:50, CPU policy unchanged | Future physical power transition not forced; drop cure unproven |
| Improve radio latency or eliminate losses | Four actual 30-packet gateway samples, all zero loss; initial 36.295-to-2.653 ms reduction did not repeat (3.085-to-5.783 ms) | No consistent latency improvement or long-term loss cure demonstrated |
| Resolve historical DHCP delays | Current real acquisition about 1.2 seconds; next-activation DHCP4 trace and automatic rollback timer verified active | Historical Avalon fault absent on Stanford, causal fix remains blocked |
| Avoid disruption and preserve rollback | Same Stanford Visitor BSSID/IP throughout, no activation/disconnect entries during checks; pre-change files backed up, commits 1c09091 and 6b1812a | Does not guarantee future AP availability |

Overall acceptance is **partial**, not an all-Wi-Fi-fixed result. The probe-deadline
requirement is verified at the installed interface. End-to-end join-speed, DHCP
and dropout requirements need the next naturally affected network activation.
Disconnecting, changing the MAC or revoking the working authorization solely to
manufacture that event was intentionally avoided.
