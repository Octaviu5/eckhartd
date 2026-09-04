# eckhartd

> *"Stay present."*

A kernel-level, self-imposed usage enforcer for Linux. `eckhartd` intercepts every process launch on the system via eBPF and enforces per-app time budgets, allowed time-of-day windows, and single-focus ("intention") rules — killing anything that violates them, with no userspace escape hatch short of root.

## Why this exists

I built this to manage my own ADHD. The core problem isn't willpower in the abstract — it's that when I have a browser, a video player, and a DAW all available at once, my attention fragments across all of them simultaneously, and none of them get finished. Soft blockers (browser extensions, userspace timers) don't help, because the moment I actually want to bypass one, I have the technical ability to just... close it, kill it, or edit its config. The friction has to live somewhere I can't casually reach.

`eckhartd` enforces two constraints I couldn't reliably hold on my own:

1. **Time-boxing.** Each app or app group ("intention") only runs inside specific windows and daily budgets — e.g. video only after 6pm, capped at an hour, YouTube specifically blocked most days.
2. **Single-intention enforcement.** Only one intention can be active at a time. If I try to open something under a different intention while one is already running, the new process gets killed on the spot. This is the part that actually matters for ADHD — it's not just "less time on X," it's "one thing at a time, on purpose," enforced structurally instead of relying on me to notice I've drifted.

Because enforcement happens at the kernel level as root, and I run as an unprivileged user, I can't talk myself out of it in the moment. The friction is real, not performative.

## Architecture

`eckhartd` is two components:

### `eckhart-root.py` — the enforcement daemon (runs as root)

- Hooks `sys_enter_execve` via eBPF (using `bcc`), so it sees **every** process launch on the system, system-wide, at the syscall level — before the process meaningfully starts doing anything.
- Loads a `rules.json` policy per UID: named "intentions" (e.g. `WORK`, `MUSIC`, `VIDEO`), each mapping to a list of binaries, a daily time budget, and one or more allowed time-of-day windows — all of which can vary by day of week.
- On every launch, checks (in order): is the binary in an authorized filesystem zone; is it disabled today (`days_off`); which intention does it belong to; is there budget/window room left; is a *different* intention already active (conflict → kill); is this an intention marked single-binary-at-a-time.
- Violations get `SIGKILL`'d immediately — no warning grace period once a hard rule is broken, though the UI companion (below) does surface countdown warnings *before* a budget runs out.
- Tracks live per-second usage against budgets, persists state to disk so it survives restarts within the same day, and resets automatically at midnight.
- Streams live state and events over a per-user Unix domain socket (`/tmp/eckhart/<uid>.sock`) for the UI process to consume. This channel is read-only in effect — enforcement state lives entirely in the root process's memory, so nothing written to the socket from userspace can influence what gets killed.

### `eckhart-user.py` — the notifier (runs as your own user, no privileges)

- Connects to the daemon's per-user socket and turns its event stream into desktop notifications (via D-Bus).
- Shows a live heads-up display of the active intention, remaining time, and which window it's operating under.
- Fires escalating countdown warnings as a budget runs low (60/45/30/15/10/5 minutes, down to a final second-by-second countdown), so getting cut off is never a surprise.
- Surfaces daemon health (down / unresponsive / crashed) so you know when enforcement isn't running.
- Handles a scheduled sleep/shutdown sequence with its own warnings.

## Policy model (`rules.json`)

Rules are defined per UID. Each **intention** is a named bundle:

```json
"WORK": {
  "binaries": ["inkscape", "obs", "sublime_text"],
  "days": {
    "def": { "daily-time-budget": null, "time-windows": [{ "range": "05:00-24:00", "budget": null }] }
  }
}
```

- `binaries` — the executable basenames this intention governs.
- `days` — per-day-of-week overrides (`mon`, `tue`, ... `sun`), falling back to `def` if a specific day isn't listed.
- `daily-time-budget` — total seconds allowed per day; `null` means unlimited.
- `time-windows` — one or more `{range, budget}` pairs; a window can additionally cap usage *within* that window, independent of the daily total.
- `"single": "true"` — only one binary under this intention may run at a time; opening a second kills it.

Two additional top-level policy pieces:

- `days_off` — binaries fully disabled on specific days regardless of any other rule.
- `authorized_zones` / `dev_zones` — filesystem prefixes. Binaries outside `authorized_zones` are killed outright. `dev_zones` are treated as unrestricted *for non-GUI processes*, so tooling and headless dev work isn't budget-gated, while anything detected as a GUI process there still gets killed.

## Requirements

- Linux with a kernel new enough for `bcc`/eBPF (matching kernel headers installed)
- Root, to run the daemon (eBPF program loading requires elevated privileges)
- `bcc` Python bindings — installation is distro-specific and can be the fiddliest part of getting this running; check your distro's `bcc-tools`/`python3-bpfcc` (or equivalent) package
- `dbus-python`, for the notifier
- A D-Bus session and notification daemon (standard on most desktop environments) for `eckhart-user.py`'s notifications to appear

This was built and tested on a single-seat Xubuntu desktop (X11). It has not been tested on Wayland-only setups, multi-seat systems, or non-Debian-based distros — expect to need to adapt paths and package names.

## Known limitations

This is personal infrastructure, not a hardened product. Documenting the soft spots honestly rather than pretending it's bulletproof:

- **GUI detection in `dev_zones` is a heuristic, not a guarantee.** `is_gui_process()` currently checks whether specific library names (`libgtk`, `libQt`, `libX11`, `libwayland`) are mapped into the process's memory. Anything that doesn't link those directly — statically linked binaries, SDL2-based apps, raw XCB clients, apps connected to a nested or alternate display server — can run undetected inside a `dev_zone` indefinitely. A more robust check would inspect whether the process holds an open file descriptor to the actual active display socket, though even that can be routed around with a nested X server (`Xephyr`/`Xvfb`) pointed at a different display number. There is no fully spoof-proof way to detect "a human is looking at this" from a process's own memory/fd state — this is a fundamental limit of the approach, not just a missing check.
- **Interpreters and shells are not intention-gated.** Enforcement matches on the *exec'd binary's* basename against each intention's `binaries` list. Something like `python3`, `bash`, or `node` isn't listed anywhere, so a script run through one of those executes ungoverned as long as it's in an `authorized_zone` — regardless of what the script itself does or displays. Closing this fully would mean either gating interpreters directly (with allow-by-path logic to avoid blocking legitimate tooling) or inspecting captured argv data (currently collected by the eBPF probe but not yet used in enforcement).
- **No network-level awareness.** Enforcement operates purely on process launches. An already-permitted, unrestricted browser (e.g. under a `WORK` intention) can still be used for anything inside that browser — this tool has no visibility into what happens after a process is allowed to run.
- **Scope is this machine only.** Nothing here has any effect on other devices — phones, other computers, etc. Enforcement is only as complete as the coverage across every device you might drift to.
- **A brief reinit gap exists.** If the daemon's eBPF probe needs to reinitialize (e.g. after a heartbeat gap), there's a small window where new process launches aren't observed until the subsequent `/proc` sweep catches up.
- **Root/physical access defeats it by design.** Anyone with root, or physical access to boot into recovery mode or another OS, can disable this outright. That's expected — this defends against casual, in-the-moment impulse, not against a determined effort with elevated access. If that's a real concern for your use case, it needs to be paired with separate protections (disk encryption, bootloader lockdown, etc.), which is out of scope for this tool.

## Disclaimer

This is given away as-is, with no guarantees of any kind. It kills processes via `SIGKILL` based on a self-written eBPF hook running as root — that carries real risk of unintended behavior, data loss from abruptly terminated programs, or system issues if misconfigured. Read the code before running it. Use at your own risk, on your own machine, at your own discretion. I take no responsibility for whatever you do with it, or whatever it does on your system.

## License

GPLv3. See `LICENSE`.