#!/usr/bin/env python3
"""Create an iPhone simulator on a hosted macOS runner and print its UDID.

The iOS gate in examples/host-ios pins one simulator UDID that only the
author's Mac has; CI creates a fresh one with the newest Pro iPhone and the
newest iOS runtime, and the workflow points the runner's copy of the gate at it.
"""

import json
import subprocess


def simctl_json(*args):
    out = subprocess.check_output(["xcrun", "simctl", *args, "-j"])
    return json.loads(out)


def main():
    types = simctl_json("list", "devicetypes")["devicetypes"]
    runtimes = simctl_json("list", "runtimes", "available")["runtimes"]

    iphones = [
        t for t in types
        if t["name"].startswith("iPhone") and "Pro" in t["name"] and "Max" not in t["name"]
    ]
    ios = [
        r for r in runtimes
        if r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")
    ]
    if not iphones or not ios:
        raise SystemExit("no iPhone device type or iOS runtime on this runner")

    device_type = iphones[-1]["identifier"]
    runtime = sorted(ios, key=lambda r: [int(x) for x in r["version"].split(".")])[-1]["identifier"]
    udid = subprocess.check_output(
        ["xcrun", "simctl", "create", "nsh-auth", device_type, runtime], text=True
    ).strip()
    print(udid)


if __name__ == "__main__":
    main()
