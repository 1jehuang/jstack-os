#!/usr/bin/env python3
"""Balance Niri workspaces and pin media apps to the last named workspace."""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List, Tuple


def run_json(cmd: List[str]) -> List[Dict]:
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or "")
        raise SystemExit(exc.returncode) from exc
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse JSON from {' '.join(cmd)}: {exc}")


def normalize_app_tokens(raw: str) -> List[str]:
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    return tokens or ["spotify", "vesktop", "todoist"]


def is_special(app_id: str, tokens: List[str]) -> bool:
    app_lower = (app_id or "").lower()
    return any(token in app_lower for token in tokens)


def plan_moves(
    workspaces: List[Dict], windows: List[Dict], special_tokens: List[str]
) -> List[Tuple[int, int, str, str]]:
    ws_by_id: Dict[int, Dict] = {ws["id"]: ws for ws in workspaces}

    workspaces_by_output: Dict[str, List[Dict]] = {}
    for ws in workspaces:
        workspaces_by_output.setdefault(ws["output"], []).append(ws)
    for ws_list in workspaces_by_output.values():
        ws_list.sort(key=lambda item: item["idx"])

    windows_by_output: Dict[str, List[Dict]] = {}
    for win in windows:
        ws_info = ws_by_id.get(win.get("workspace_id"))
        if not ws_info:
            continue
        record = {
            "id": win["id"],
            "app_id": win.get("app_id") or "",
            "title": win.get("title") or "",
            "workspace_idx": ws_info["idx"],
            "workspace_id": ws_info["id"],
            "output": ws_info["output"],
        }
        windows_by_output.setdefault(ws_info["output"], []).append(record)

    planned: List[Tuple[int, int, str, str]] = []
    scheduled: set[int] = set()

    for output, ws_list in workspaces_by_output.items():
        wins = windows_by_output.get(output, [])
        if not wins:
            continue

        target_last = max(ws_list, key=lambda item: item["idx"])
        base_pool = [ws for ws in ws_list if ws["id"] != target_last["id"]]
        base_pool.sort(key=lambda item: item["idx"])

        if not base_pool:
            continue

        pool_indices = [ws["idx"] for ws in base_pool]

        specials: List[Dict] = []
        others: List[Dict] = []
        for win in wins:
            if is_special(win["app_id"], special_tokens):
                specials.append(win)
            else:
                others.append(win)

        target_idx = target_last["idx"]
        for win in specials:
            if win["workspace_idx"] == target_idx:
                continue
            planned.append((win["id"], target_idx, win["app_id"], "pin"))
            scheduled.add(win["id"])

        pool_len = len(pool_indices)
        if pool_len == 0:
            continue

        others_sorted = sorted(
            others,
            key=lambda item: (item["workspace_idx"], item["app_id"].lower(), item["id"]),
        )
        for pos, win in enumerate(others_sorted):
            desired_idx = pool_indices[pos % pool_len]
            if win["workspace_idx"] == desired_idx:
                continue
            planned.append((win["id"], desired_idx, win["app_id"], "balance"))
            scheduled.add(win["id"])

        # Ensure no forbidden windows remain on the last workspace.
        for win in others:
            if win["workspace_idx"] != target_idx:
                continue
            if win["id"] in scheduled:
                continue
            desired_idx = pool_indices[0]
            if desired_idx == target_idx:
                continue
            planned.append((win["id"], desired_idx, win["app_id"], "evict"))
            scheduled.add(win["id"])

    return planned


def apply_moves(moves: List[Tuple[int, int, str, str]], dry_run: bool) -> None:
    if not moves:
        print("organize-workspaces: nothing to do")
        return

    for window_id, target_idx, app_id, reason in moves:
        print(
            f"organize-workspaces: {reason}: window {window_id} ({app_id}) -> workspace {target_idx}"
        )
        if dry_run:
            continue
        subprocess.run(
            [
                "niri",
                "msg",
                "action",
                "move-window-to-workspace",
                str(target_idx),
                "--window-id",
                str(window_id),
                "--focus",
                "false",
            ],
            check=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Organize Niri workspaces")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the planned moves without executing them",
    )
    args = parser.parse_args()

    special_env = os.environ.get("NIRI_ORGANIZE_LAST_APPS", "")
    special_tokens = (
        normalize_app_tokens(special_env)
        if special_env
        else ["spotify", "vesktop", "todoist"]
    )

    workspaces = run_json(["niri", "msg", "-j", "workspaces"])
    windows = run_json(["niri", "msg", "-j", "windows"])

    moves = plan_moves(workspaces, windows, special_tokens)
    apply_moves(moves, args.dry_run)


if __name__ == "__main__":
    main()
