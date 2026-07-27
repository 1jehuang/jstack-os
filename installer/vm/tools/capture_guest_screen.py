#!/usr/bin/env python3
"""Capture a running guest's screen through QEMU's monitor.

Every defect in the base-image build path so far has been a modal dialog waiting
for an answer that never comes: a Cancel confirmation, an OOBE region page, a
missing ProductKey. All of them present identically from outside, as a disk that
stopped growing, and all of them cost the build's full ninety-minute timeout
while reporting nothing. Three were identified by looking at the screen, and each
took minutes instead.

So the screen is treated as first-class diagnostic evidence rather than something
to reach for by hand. Read-only by construction: it issues `screendump` and
nothing else, and it never sends input, so it cannot perturb the run it is
diagnosing.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path


class CaptureError(RuntimeError):
    """Raised when the guest's screen cannot be captured."""


def capture(monitor: Path, output: Path, timeout: float = 20.0) -> Path:
    """Write the guest's current framebuffer to `output`.

    QEMU writes PPM. It is converted to PNG when Pillow is available, since a PPM
    is inconvenient to look at, but a successful capture is never failed just
    because the conversion is unavailable.
    """

    if not monitor.exists():
        raise CaptureError(f"no QEMU monitor socket at {monitor}")

    intermediate = output.with_suffix(".ppm")
    connection = socket.socket(socket.AF_UNIX)
    connection.settimeout(timeout)
    try:
        connection.connect(str(monitor))
        connection.recv(65536)  # greeting

        def execute(command: str, **arguments: object) -> str:
            payload: dict[str, object] = {"execute": command}
            if arguments:
                payload["arguments"] = arguments
            connection.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            return connection.recv(65536).decode("utf-8", errors="replace")

        execute("qmp_capabilities")
        reply = execute("screendump", filename=str(intermediate))
        if '"error"' in reply:
            raise CaptureError(f"screendump refused: {reply.strip()[:200]}")
    except OSError as error:
        raise CaptureError(f"the monitor connection failed: {error}") from error
    finally:
        connection.close()

    # QEMU writes asynchronously, so the file may lag the reply slightly.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if intermediate.is_file() and intermediate.stat().st_size > 0:
            break
        time.sleep(0.1)
    else:
        raise CaptureError("the screendump file never appeared")

    try:
        from PIL import Image
    except ImportError:
        return intermediate

    with Image.open(intermediate) as image:
        image.save(output)
    intermediate.unlink(missing_ok=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--monitor", required=True, help="QMP unix socket path")
    parser.add_argument("--output", required=True, help="PNG destination")
    arguments = parser.parse_args()

    try:
        written = capture(Path(arguments.monitor), Path(arguments.output))
    except CaptureError as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({"captured": str(written)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
