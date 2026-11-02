# Jofi default launcher

`jofi-jstack` installs Jofi and its workspace/origin-context wrapper in `/usr/bin`.
The Niri default binds Alt+Space to `/usr/bin/jofi-workspace`. This changes distro
assets, not the current user's running desktop or existing configuration.

Source is pinned to published commit
`9f85fa0d6c2b4d96dd4c138dbcbd75e023c5cf38` from `1jehuang/jofi`, with the
upstream Cargo lockfile enforced. The inspected local checkout was two commits
ahead at `e88385f9a51949f72dcfdc0d3d5395b77040d63d`, but that commit could not
be fetched from origin. Its unpublished matcher improvements are not shipped.
After the source owner publishes them, bump this pin and rerun validation.

Jofi discovers desktop entries directly and launches them using `gio` (glib2).
It has no stdin/dmenu selection mode. `tofi-jstack` remains installed explicitly
for Wi-Fi, password, window-picker, power-menu and calculator prompts. These
utilities must not be blindly changed to invoke Jofi. The wrapper does not kill
Tofi prompts. No automatic history import or personal Rust launcher copying runs.

Focused checks:

```sh
python -m unittest discover -s packages/jofi-jstack/tests -v
python -m unittest discover -s iso/tests -v
python -m unittest discover -s install/tests -v
python -m unittest discover -s packages/jstack-network/tests -v
niri validate --config packages/jstack-niri/files/config.kdl
```

The package staging unit test uses fixture executables. Real source compilation,
real binary staging, and booted graphical acceptance are separate checks. Do not
claim ISO or installed-system acceptance solely from these unit tests.
