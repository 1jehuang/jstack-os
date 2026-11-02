# Launcher entry audience decisions

Reference snapshot: 2026-11-01 (local date). **132 visible entries: 7 shared, 125 personal.**

The source of truth is [launcher-entries.json](launcher-entries.json). Every visible
entry has exactly one decision and a rationale. Unknown future entries stay
personal until explicitly reviewed. The shared list is deliberately capped at
seven entries. "Personal" means "do not promote this reference shortcut by
default", not "nobody else could use this application".

This is a shortcut migration policy, not an application uninstall list or a Jofi
filter. It does not change Jeremy's menu, copy personal desktop files into the
image, or hide the standard application entries installed by distribution
packages. The existing distro dependency set is not pruned by this audit.
In particular, a personal classification for a reference Vesktop shortcut does
not uninstall the existing distro Vesktop package. No personal Exec commands,
URLs, credentials, profile paths, or device identifiers are included in the
inventory. These are labels and desktop file basenames only.

## The minimal shared list

| Entry | Desktop ID | Promotion notes |
| --- | --- | --- |
| Files | `org.gnome.Nautilus.desktop` | Basic file management. Share the Files role, not a requirement to use Nautilus instead of the distro's Thunar. |
| Firefox | `firefox.desktop` | One general-purpose browser entry. Do not add a duplicate New Window shortcut. |
| Jcode | `jcode.desktop` | Core Jstack agent entry. Package a portable launcher, never the reference machine's absolute desktop-client path. |
| Network Login | `network-login.desktop` | Generic captive-portal recovery already maintained by jstack-network. |
| Screenshot (Area) | `screenshot-area.desktop` | Basic area capture using the compositor. |
| Screenshot (Fullscreen) | `screenshot-fullscreen.desktop` | Basic fullscreen capture using the compositor. |
| Screenshot (Window) | `screenshot-window.desktop` | Basic window capture using the compositor. |

Shared means the generic capability is appropriate for Jstack, not that a local
implementation can be copied verbatim. Files uses Nautilus on the reference
machine but the distro already has Thunar. The local Jcode entry points at a
personal desktop-client binary, so a distro entry must use its packaged client
instead. Firefox and Network Login already come from their owning packages.
Screenshots should call Niri with portable arguments, without reference-machine
scripts. This audit does not claim to have packaged new desktop entries for all
seven roles.

## Personal entries

These remain on the reference machine. Optional websites, account launchers,
maintainer dashboards, hardware actions, games, media workflows and duplicate
app choices are not added to the default shared list.

| Entry | Desktop ID | Audience |
| --- | --- | --- |
| Apartment Price Tracker | `apt-tracker.desktop` | personal |
| Avalon Dogpatch Site Plan | `avalon-dogpatch-siteplan.desktop` | personal |
| Bitwarden | `bitwarden.desktop` | personal |
| Bookface | `bookface.desktop` | personal |
| Bookface Deals | `bookface-deals.desktop` | personal |
| btop++ | `btop.desktop` | personal |
| ChatGPT (Codex) | `chatgpt.desktop` | personal |
| Chinese 111 Lesson 6 | `chin111-lesson6.desktop` | personal |
| Claude Console | `claude-console.desktop` | personal |
| Connect AirPods Pro 3 | `airpods-connect.desktop` | personal |
| Connect iPhone Hotspot | `connect-iphone-hotspot.desktop` | personal |
| Copy Jcode Repo Link | `copy-jcode-repo-link.desktop` | personal |
| Copy Pitch Deck Link | `copy-pitch-deck.desktop` | personal |
| Disable Chinese Input | `disable-chinese-input.desktop` | personal |
| Disable Lid Switch - 10 Hours | `disable-lid-switch-10h.desktop` | personal |
| Disable Lid Switch - Dim Only | `disable-lid-switch.desktop` | personal |
| Disable Lid Switch - Until Unplugged | `disable-lid-switch-unplugged.desktop` | personal |
| Disconnect AirPods | `disconnect-airpods.desktop` | personal |
| Disconnect iPhone Hotspot | `disconnect-iphone-hotspot.desktop` | personal |
| Discord Web | `discord-web.desktop` | personal |
| Discordo | `discordo.desktop` | personal |
| Dislike Song | `dislike-song.desktop` | personal |
| EdStem | `edstem.desktop` | personal |
| Enable Chinese Trackpad Draw Bridge | `enable-chinese-trackpad-draw-bridge.desktop` | personal |
| Excalidraw | `excalidraw.desktop` | personal |
| Fix Camera | `camera-fix.desktop` | personal |
| Fundraising CRM | `bookface-seed-crm.desktop` | personal |
| Gemini | `gemini.desktop` | personal |
| GitHub | `github.desktop` | personal |
| GitHub Profile | `github-profile.desktop` | personal |
| GitHub Repos | `github-repos.desktop` | personal |
| Gmail | `gmail.desktop` | personal |
| Gmail (CSE) | `gmail-cse.desktop` | personal |
| Gmail (UW) | `gmail-uw.desktop` | personal |
| Gmail Code Watcher | `gmail-code-watcher.desktop` | personal |
| Google Calendar | `google-calendar.desktop` | personal |
| Google Chrome | `google-chrome.desktop` | personal |
| Google Maps | `google-maps.desktop` | personal |
| Google Meet Test | `google-meet-test.desktop` | personal |
| Google Passwords | `google-passwords-webapp.desktop` | personal |
| Gradescope | `gradescope.desktop` | personal |
| Hacker News | `hackernews.desktop` | personal |
| Hardware Locality lstopo | `lstopo.desktop` | personal |
| hn launch | `hn-launch.desktop` | personal |
| Hogpatch Door | `hogpatch-door.desktop` | personal |
| Htop | `htop.desktop` | personal |
| Investor DB | `investor-db.desktop` | personal |
| jcode Analytics | `jcode-analytics.desktop` | personal |
| Jcode Bench Results | `jcode-bench-results.desktop` | personal |
| Jcode Bench Spec | `jcode-bench-spec.desktop` | personal |
| Jcode Config | `jcode-config.desktop` | personal |
| Jcode Content: New Idea | `jcode-content-idea.desktop` | personal |
| Jcode Content: Review | `jcode-content-review.desktop` | personal |
| Jcode Desktop | `jcode-desktop.desktop` | personal |
| Jcode Desktop GitHub Issues | `jcode-desktop-github-issues.desktop` | personal |
| Jcode Desktop GitHub Pull Requests | `jcode-desktop-github-pull-requests.desktop` | personal |
| Jcode Desktop GitHub Repo | `jcode-desktop-github-repo.desktop` | personal |
| jcode discovery | `jcode-discovery.desktop` | personal |
| Jcode GitHub Context | `jcode-github-context.desktop` | personal |
| Jcode GitHub Issues | `jcode-github-issues.desktop` | personal |
| Jcode GitHub Pull Requests | `jcode-github-pull-requests.desktop` | personal |
| jcode github repo | `jcode-github-repo.desktop` | personal |
| Jcode Here | `jcode-here.desktop` | personal |
| jcode Hosted Dashboard | `jcode-hosted.desktop` | personal |
| Jcode Models | `jcode-models.desktop` | personal |
| Jcode Permissions Review | `jcode-permissions.desktop` | personal |
| Jcode Queries Dashboard | `jcode-queries-dashboard.desktop` | personal |
| Jcode Restore | `jcode-restore.desktop` | personal |
| Jcode Save For Reboot | `jcode-save-for-reboot.desktop` | personal |
| Jcode Sponsor Dashboard | `jcode-sponsor-dashboard.desktop` | personal |
| Jcode Stars | `jcode-stars.desktop` | personal |
| jcode stars notify | `jcode-stars-notify.desktop` | personal |
| jcode telemetry | `jcode-telemetry.desktop` | personal |
| jcode telemetry new | `jcode-telemetry-new.desktop` | personal |
| jcode website | `jcode-website.desktop` | personal |
| Jcode Website Screenshot | `jcode-website-screenshot.desktop` | personal |
| jcode.sh | `jcode.sh.desktop` | personal |
| Join Next Meeting | `meet-next.desktop` | personal |
| justrust | `justrust.desktop` | personal |
| justrust github repo | `justrust-github-repo.desktop` | personal |
| justrust Hosted Dashboard | `justrust-hosted.desktop` | personal |
| justrust Remote Compile Machine | `justrust-remote.desktop` | personal |
| Kill Discord | `kill-discord.desktop` | personal |
| Lichess 3+2 | `lichess-3-plus-2.desktop` | personal |
| Lichess Desktop | `lichess-desktop.desktop` | personal |
| LinkedIn - Jeremy Huang | `linkedin-jeremy-huang.desktop` | personal |
| Media Picker | `ffp-media.desktop` | personal |
| Monkeytype | `monkeytype.desktop` | personal |
| My Latest X Post | `x-latest-post.desktop` | personal |
| Neovim | `nvim.desktop` | personal |
| Notepad | `notepad-nvim-bare.desktop` | personal |
| OpenAI Platform | `openai-platform.desktop` | personal |
| OpenRouter | `openrouter.desktop` | personal |
| Organize Workspaces | `niri-organize-workspaces.desktop` | personal |
| Personal Email Copy | `copy-personal-email.desktop` | personal |
| Pitch Deck | `pitch-deck.desktop` | personal |
| Play Song | `play-song.desktop` | personal |
| Pokemon Showdown | `pokemon-showdown.desktop` | personal |
| Prism Launcher | `org.prismlauncher.PrismLauncher.desktop` | personal |
| Qt V4L2 video capture utility | `qvidcap.desktop` | personal |
| Reddit | `reddit.desktop` | personal |
| Rename Last Recording | `rename-last-recording.desktop` | personal |
| Rho | `rho.desktop` | personal |
| Rust Ops Log | `rust-ops-log.desktop` | personal |
| Send a SAFE | `bookface-send-safe.desktop` | personal |
| Skip Song | `skip-song.desktop` | personal |
| Slack | `slack.desktop` | personal |
| Soft Reboot (Keep Jcode) | `jcode-soft-reboot.desktop` | personal |
| Stop Song | `stop-song.desktop` | personal |
| Stripe (jcode) | `stripe-jcode.desktop` | personal |
| Thunar Preferences | `thunar-settings.desktop` | personal |
| Time and Date | `show-time.desktop` | personal |
| Todoist | `todoist.desktop` | personal |
| Toggle Touchpad | `toggle-touchpad.desktop` | personal |
| Toggle Touchscreen | `toggle-touchscreen.desktop` | personal |
| Toggle Waybar | `toggle-waybar.desktop` | personal |
| Vesktop | `vesktop.desktop` | personal |
| Vim | `vim.desktop` | personal |
| Work on Pitch Deck | `work-on-pitch-deck.desktop` | personal |
| Workflow 1 Min | `workflow-1min.desktop` | personal |
| X Compose | `x-compose.desktop` | personal |
| x.com | `x.desktop` | personal |
| YC Slack | `yc-slack.desktop` | personal |
| YouTube | `youtube.desktop` | personal |
| Zathura | `org.pwmt.zathura.desktop` | personal |

## Inspect and validate

From the repository root:

```sh
python3 tools/launcher-entry-policy.py --audience shared
python3 tools/launcher-entry-policy.py --audience personal
python3 tools/launcher-entry-policy.py --check-current
python3 -m unittest discover -s tools/tests -v
```

The current-inventory check is read-only and executes only `jofi list`, never
an app entry. It reports missing, renamed, new, or non-desktop entries instead
of silently classifying them as shared. For an offline saved TSV, use
`--inventory /path/to/jofi-list.tsv`. These checks do not require the reference
machine for fixture-based tests.

## App launcher migration

Jofi replaces Tofi's drun role for Alt+Space. Tofi remains only as a compatibility
backend for stdin/password/utility menus that Jofi does not currently implement
(Wi-Fi selection, window picker, power menu). Removing those prompts without a
replacement would break existing desktop features. Personal app launchers and
user configuration are not imported into the distro Jofi package.
