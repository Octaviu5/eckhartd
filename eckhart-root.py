from bcc import BPF
import os
import time
import signal
import subprocess
import socket
import json
import argparse
import sys
import re
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(SCRIPT_DIR, "eckhart-rules.json")
STATE_PATH = os.path.join(SCRIPT_DIR, "state.json")

WALL_TICK_RATE = 1.0
SAVE_INTERVAL  = 60.0
SUSSY_CHECK_RATE = 2.0

# --- EBPF ---
ebpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
    char args[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    const char **argv = (const char **)args->argv;
    const char *argp;
    bpf_probe_read_user(&argp, sizeof(argp), &argv[1]);
    if (argp) {
        bpf_probe_read_user_str(&data.args, sizeof(data.args), argp);
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# --- SCHEDULE PARSING & VALIDATION ---
DURATION_REGEX = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?$")
WINDOW_REGEX   = re.compile(r"^(\d{2}:\d{2})-(\d{2}:\d{2})(?:\((.+?)\))?$")
DAY_ALIASES = {
    "mon": "mon", "monday": "mon",
    "tue": "tue", "tuesday": "tue",
    "wed": "wed", "wednesday": "wed",
    "thu": "thu", "thursday": "thu",
    "fri": "fri", "friday": "fri",
    "sat": "sat", "saturday": "sat",
    "sun": "sun", "sunday": "sun",
    "default": "def", "default-day": "def", "def": "def",
}
VALID_DAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

def parse_duration_str(dur_str):
    """Converts '2h', '30m', '1h30m' into seconds."""
    if not dur_str:
        return None
    m = DURATION_REGEX.match(dur_str.strip())
    if not m or not any(m.groups()):
        raise ValueError(f"Invalid duration format: '{dur_str}'")
    hours = int(m.group(1)) if m.group(1) else 0
    minutes = int(m.group(2)) if m.group(2) else 0
    return hours * 3600 + minutes * 60

def parse_clock_time(t_str):
    try:
        h, m = map(int, t_str.split(":"))
    except Exception:
        raise ValueError(f"Invalid time format: '{t_str}'")
    if not (0 <= h <= 23 and 0 <= m <= 59):
        if not (h == 24 and m == 0):
            raise ValueError(f"Time out of range: '{t_str}'")
    return h * 3600 + m * 60

def parse_window_entry(w_str):
    """Parses '05:00-23:59' or '05:00-23:59(2h30m)'."""
    m = WINDOW_REGEX.match(w_str.strip())
    if not m:
        raise ValueError(f"Invalid window format: '{w_str}'")
    start_str, end_str, cap_str = m.group(1), m.group(2), m.group(3)
    start_sec = parse_clock_time(start_str)
    end_sec   = parse_clock_time(end_str)
    if end_sec <= start_sec:
        raise ValueError(f"Window start must be before end: '{w_str}'")

    cap_sec = parse_duration_str(cap_str) if cap_str else None
    if cap_sec is not None and cap_sec > (end_sec - start_sec):
        raise ValueError(f"Window budget ({cap_str}) exceeds window duration: '{w_str}'")

    return {
        "range": f"{start_str}-{end_str}",
        "budget": cap_sec,
        "_start": start_sec,
        "_end": end_sec,
    }

def normalize_day_spec(spec):
    """Translates 'off', 'free', or custom dict into internal format."""
    if spec == "off":
        return {"daily-time-budget": 0, "time-windows": []}
    if spec == "free":
        return {
            "daily-time-budget": None,
            "time-windows": [{"range": "00:00-23:59", "budget": None}]
        }
    if isinstance(spec, dict):
        budget_raw = spec.get("day-budget", spec.get("daily-budget", spec.get("budget", None)))
        if isinstance(budget_raw, str):
            daily_budget = parse_duration_str(budget_raw)
        elif budget_raw is None:
            daily_budget = None
        else:
            daily_budget = int(budget_raw)

        raw_windows = spec.get("windows", [])
        parsed_windows = []
        for w in raw_windows:
            if isinstance(w, str):
                parsed_windows.append(parse_window_entry(w))
            elif isinstance(w, dict) and "range" in w:
                p = parse_window_entry(w["range"])
                if w.get("budget") is not None:
                    p["budget"] = parse_duration_str(w["budget"]) if isinstance(w["budget"], str) else w["budget"]
                parsed_windows.append(p)
            else:
                raise ValueError(f"Invalid window definition: {w}")

        parsed_windows.sort(key=lambda x: x["_start"])
        for i in range(len(parsed_windows) - 1):
            if parsed_windows[i]["_end"] > parsed_windows[i+1]["_start"]:
                raise ValueError(f"Overlapping windows: {parsed_windows[i]['range']} and {parsed_windows[i+1]['range']}")

        clean_windows = [{"range": w["range"], "budget": w["budget"]} for w in parsed_windows]
        return {"daily-time-budget": daily_budget, "time-windows": clean_windows}

    raise ValueError(f"Unknown day schedule format: {spec}")

def validate_and_normalize_profile(u_id, profile):
    # Normalize days_off aliases
    if "days_off" in profile:
        normalized_days_off = {}
        for day_key, bin_list in profile["days_off"].items():
            k = day_key.lower().strip()
            tokens = [t.strip() for t in k.split(",") if t.strip()]

            if len(tokens) == 1 and tokens[0] in ("default", "default-day", "def"):
                normalized_days_off["def"] = bin_list
                continue

            for token in tokens:
                if token not in DAY_ALIASES or DAY_ALIASES[token] == "def":
                    raise ValueError(f"Invalid day '{token}' in 'days_off'")
                normalized_k = DAY_ALIASES[token]
                normalized_days_off[normalized_k] = bin_list
        profile["days_off"] = normalized_days_off

    seen_binaries = {}
    for zone in profile.get("authorized_zones", []):
        if not os.path.isabs(zone):
            raise ValueError(f"authorized_zone must be an absolute path: '{zone}'")
    for zone in profile.get("dev_zones", []):
        if not os.path.isabs(zone):
            raise ValueError(f"dev_zone must be an absolute path: '{zone}'")

    intentions = profile.get("intentions", {})
    if not intentions:
        raise ValueError(f"User {u_id} has no intentions defined.")

    for intent_name, config in intentions.items():
        for b in config.get("binaries", []):
            if b in seen_binaries:
                raise ValueError(f"Binary '{b}' is assigned to both '{seen_binaries[b]}' and '{intent_name}'")
            seen_binaries[b] = intent_name

        schedule = config.get("schedule")
        if schedule is not None:
            normalized_days = {}
            for day_key, day_spec in schedule.items():
                k = day_key.lower().strip()
                tokens = [t.strip() for t in k.split(",") if t.strip()]

                if len(tokens) == 1 and tokens[0] in ("default", "default-day", "def"):
                    normalized_days["def"] = normalize_day_spec(day_spec)
                    continue

                for token in tokens:
                    if token not in DAY_ALIASES or DAY_ALIASES[token] == "def":
                        raise ValueError(f"Invalid day '{token}' in key '{day_key}' of intention '{intent_name}'")
                    normalized_k = DAY_ALIASES[token]
                    normalized_days[normalized_k] = normalize_day_spec(day_spec)

            if "def" not in normalized_days and set(normalized_days.keys()) != VALID_DAYS:
                raise ValueError(f"Intention '{intent_name}' must have a 'default' rule or cover all 7 days.")
            config["days"] = normalized_days
        elif "days" not in config:
            raise ValueError(f"Intention '{intent_name}' must define either 'schedule' or 'days'.")

# --- TIME HELPERS ---
def get_seconds_since_midnight():
    now = datetime.now()
    return now.hour * 3600 + now.minute * 60 + now.second

def time_to_seconds(t_str):
    h, m = map(int, t_str.split(":"))
    return h * 3600 + m * 60

def get_day_key():
    return datetime.now().strftime("%a").lower()

def get_active_window(windows, now_sec):
    """Return the active window dict or None."""
    for w in windows:
        start, end = map(time_to_seconds, w["range"].split("-"))
        if start <= now_sec <= end:
            return w
    return None

def budget_remaining(budget):
    """None means infinite — return a large sentinel."""
    return float("inf") if budget is None else budget

def atomic_write_json(path, data):
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except:
            pass

# --- SCHEDULE DISPLAY HELPERS ---
def format_seconds(sec):
    if sec is None:
        return "FREE"
    h = sec // 3600
    m = (sec % 3600) // 60
    if h > 0 and m > 0:
        return f"{h}h{m}m"
    elif h > 0:
        return f"{h}h"
    elif m > 0:
        return f"{m}m"
    return "0m"

def print_weekly_schedule(profiles):
    today_k = get_day_key()
    ordered_days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

    print("\033[96m[+] WEEKLY INTENTION SCHEDULE (Today: " + today_k.upper() + ")\033[0m\n")

    for u_id, profile in profiles.items():
        intentions = profile.get("intentions", {})
        for name, config in intentions.items():
            print(f"  \033[1;37m[{name}]\033[0m")
            days_cfg = config.get("days", {})

            for d in ordered_days:
                rule = days_cfg.get(d, days_cfg.get("def"))
                is_today = (d == today_k)
                marker = "*" if is_today else " "
                day_lbl = f"{d.capitalize()}{marker}"

                if not rule or rule.get("daily-time-budget") == 0 or not rule.get("time-windows"):
                    desc = "\033[91mOFF\033[0m"
                else:
                    daily = rule.get("daily-time-budget")
                    cap_tag = f" \033[93m(day-limit: {format_seconds(daily)})\033[0m" if daily is not None else ""
                    win_strs = []
                    for w in rule.get("time-windows", []):
                        r = w["range"]
                        b = w.get("budget")
                        if b is not None:
                            b_str = f"\033[93m({format_seconds(b)})\033[0m"
                            win_strs.append(f"{r}{b_str}")
                        else:
                            win_strs.append(r)
                    desc = f"[{', '.join(win_strs)}]{cap_tag}"

                prefix = "\033[92m>\033[0m" if is_today else " "
                print(f"   {prefix} {day_lbl:<5} : {desc}")
            print()

        days_off = profile.get("days_off", {})
        if days_off:
            print("  \033[1;37m[DAYS OFF (BINARIES)]\033[0m")
            for d in ordered_days:
                bins = days_off.get(d, days_off.get("def", []))
                if bins:
                    is_today = (d == today_k)
                    marker = "*" if is_today else " "
                    day_lbl = f"{d.capitalize()}{marker}"
                    prefix = "\033[92m>\033[0m" if is_today else " "
                    print(f"   {prefix} {day_lbl:<5} : {', '.join(bins)}")
            print()

    print("\033[95m" + "═" * 60 + "\033[0m")

# --- PERSISTENCE ---
def load_profiles():
    if not os.path.exists(RULES_PATH):
        print(f"[!] Rules file not found at: {RULES_PATH}", file=sys.stderr, flush=True)
        sys.exit(1)
    try:
        with open(RULES_PATH, "r") as f:
            profiles = json.load(f)
    except Exception as e:
        print(f"[!] JSON syntax error in {RULES_PATH}: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    try:
        for u_id, profile in profiles.items():
            validate_and_normalize_profile(u_id, profile)
    except ValueError as e:
        print(f"[!] Configuration validation error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    return profiles

def load_persistence():
    today = datetime.now().strftime("%Y-%m-%d")
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH, "r") as f:
                data = json.load(f)
                if data.get("date") == today:
                    return data.get("used-budget", {})
        except:
            pass
    return {}

# --- INIT ---
saved_data    = load_persistence()
USER_PROFILES = {}
USER_STATES   = {}

SOCKET_BASE_DIR = "/tmp/eckhart"
ACTIVE_SOCKETS  = {}

last_saved_snapshot = {}
last_save_tick      = time.time()


def main():
    parser = argparse.ArgumentParser(description="Eckhart Daemon")
    parser.add_argument("-v", "--verbose", action="store_true")
    args_parsed = parser.parse_args()
    VERBOSE = args_parsed.verbose

    global last_saved_snapshot, last_save_tick, USER_STATES, USER_PROFILES

    if os.geteuid() != 0:
        print("Root only. Use sudo.")
        return

    USER_PROFILES = load_profiles()

    print("\033[95m" + "═" * 60 + "\033[0m")
    print("\033[95m[+] ECKHART v2.0 | STAY PRESENT.\033[0m")
    print(f"\033[93m[+] VERBOSE: {'ENABLED' if VERBOSE else 'DISABLED'}\033[0m")
    print("\033[95m" + "═" * 60 + "\033[0m")

    print_weekly_schedule(USER_PROFILES)

    if os.path.exists(SOCKET_BASE_DIR):
        import shutil
        shutil.rmtree(SOCKET_BASE_DIR)
    os.makedirs(SOCKET_BASE_DIR, mode=0o755)

    # --- BUILD USER STATE ---
    for u_id, profile in USER_PROFILES.items():
        user_history = saved_data.get(str(u_id), {})

        intentions_state = {}
        for name, config in profile["intentions"].items():
            saved_intent = user_history.get(name, {})
            # Per-window usage: keyed by window range string
            window_used = {}
            for day_cfg in config["days"].values():
                for w in day_cfg.get("time-windows", []):
                    r = w["range"]
                    if r not in window_used:
                        window_used[r] = saved_intent.get("windows", {}).get(r, 0)

            intentions_state[name] = {
                "daily": saved_intent.get("daily", 0),
                "windows": window_used,
            }

        USER_STATES[u_id] = {
            "active_intention": {"name": None, "pids": {}},
            "intentions": intentions_state,
            "sussy_binaries": {},
            "conn": None,
        }

        s_path = os.path.join(SOCKET_BASE_DIR, f"{u_id}.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.setblocking(False)
        s.bind(s_path)
        s.listen(1)
        os.chmod(s_path, 0o666)
        ACTIVE_SOCKETS[u_id] = s

    # --- STATE BUILDING ---
    def build_state_blocks(target_uid_str):
        state   = USER_STATES[target_uid_str]
        profile = USER_PROFILES[target_uid_str]
        now_sec = get_seconds_since_midnight()

        time_blocks = {}
        for name, config in profile["intentions"].items():
            day_rule = config["days"].get(get_day_key(), config["days"].get("def"))
            if not day_rule:
                continue

            daily_budget  = day_rule.get("daily-time-budget")
            daily_used    = state["intentions"][name]["daily"]
            windows_info  = []

            for w in day_rule.get("time-windows", []):
                r           = w["range"]
                win_budget  = w.get("budget")
                win_used    = state["intentions"][name]["windows"].get(r, 0)
                start, end  = map(time_to_seconds, r.split("-"))
                is_active_w = start <= now_sec <= end

                windows_info.append({
                    "range":      r,
                    "budget":     win_budget,
                    "used":       win_used,
                    "is_active":  is_active_w,
                })

            time_blocks[name] = {
                "daily_budget": daily_budget,
                "daily_used":   daily_used,
                "windows":      windows_info,
            }

        return {
            "st_intention_name":     state["active_intention"]["name"],
            "st_intention_binaries": list(set(state["active_intention"]["pids"].values())),
            "st_time_blocks":        time_blocks,
        }

    def dump_state_file(target_uid_str):
        path = os.path.join(SOCKET_BASE_DIR, f"{target_uid_str}.state")
        atomic_write_json(path, build_state_blocks(target_uid_str))

    # --- SOCKET SEND ---
    def send_to_socket(target_uid_str, event_uid, event, status, aaa, bbb, now):
        state   = USER_STATES[target_uid_str]
        profile = USER_PROFILES[target_uid_str]

        if state["conn"] is None:
            try:
                conn, _ = ACTIVE_SOCKETS[target_uid_str].accept()
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return

            conn.setblocking(False)
            try:
                welcome = {
                    "ts": int(now), "uid": 0, "event": "SYSTEM", "status": "ONLINE",
                    "aaa": "DAEMON_ACTIVE", "bbb": "Eckhart monitoring started.", "state": None
                }
                conn.sendall((json.dumps(welcome) + "\n").encode())
            except (BlockingIOError, InterruptedError):
                state["conn"] = conn
                return
            except Exception:
                try:
                    conn.close()
                except:
                    pass
                return

            state["conn"] = conn

        try:
            msg = {
                "ts":     int(now),
                "uid":    event_uid,
                "event":  event,
                "status": status,
                "aaa":    aaa,
                "bbb":    bbb,
                "state":  build_state_blocks(target_uid_str),
            }
            state["conn"].sendall((json.dumps(msg) + "\n").encode())
        except Exception:
            try:
                state["conn"].close()
            except:
                pass
            state["conn"] = None

    # --- LOGGING ---
    def log(uid, event, status, aaa, bbb):
        now = time.time()
        str_uid = str(uid)
        if VERBOSE and status != "STATUS":
            readable = datetime.fromtimestamp(now).strftime("%H:%M:%S")
            print(f"[{readable}] {str_uid:<6} | {event:<12} | {status:<12} | {aaa:<10} | {bbb}")

        if uid == 0:
            for t_uid in USER_STATES:
                send_to_socket(t_uid, uid, event, status, aaa, bbb, now)
        elif str_uid in USER_STATES:
            send_to_socket(str_uid, uid, event, status, aaa, bbb, now)

    # --- PERSISTENCE SAVE ---
    def save_persistence(force=False):
        global last_saved_snapshot, last_save_tick
        today = datetime.now().strftime("%Y-%m-%d")

        file_date = None
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH, "r") as f:
                    file_date = json.load(f).get("date")
            except:
                pass

        if file_date and file_date != today:
            print(f"\n[!] DATE CHANGE: {file_date} -> {today}. Resetting budgets.\n")
            log(0, "SYSTEM", "RESET", "", f"New day: {today}")
            for u_id in USER_STATES:
                for intent_name in USER_STATES[u_id]["intentions"]:
                    USER_STATES[u_id]["intentions"][intent_name]["daily"] = 0
                    for r in USER_STATES[u_id]["intentions"][intent_name]["windows"]:
                        USER_STATES[u_id]["intentions"][intent_name]["windows"][r] = 0
            last_saved_snapshot = {}

        current = {
            str(u): {
                name: {
                    "daily":   istate["daily"],
                    "windows": dict(istate["windows"]),
                }
                for name, istate in state["intentions"].items()
            }
            for u, state in USER_STATES.items()
        }

        if not force and current == last_saved_snapshot:
            return

        try:
            with open(STATE_PATH, "w") as f:
                json.dump({"date": today, "used-budget": current}, f)
            last_saved_snapshot = current
            last_save_tick = time.time()
            log(0, "SYSTEM", "DISK", "", "OK")
        except Exception as e:
            log(0, "SYSTEM", "DISK_ERR", "", str(e))

    save_persistence()

    # --- HELPERS ---
    def get_real_path(pid, raw_path):
        if raw_path.startswith("/"):
            return os.path.realpath(raw_path)
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
            return os.path.realpath(os.path.join(cwd, raw_path))
        except:
            return os.path.realpath(raw_path)

    def is_gui_process(pid):
        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    if any(x in line for x in ["libgtk", "libQt", "libX11", "libwayland"]):
                        return True
        except:
            pass
        return False

    def can_use_intention(uid_str, intent_name, now_sec):
        """
        Returns (allowed: bool, reason: str)
        Checks: day rule exists, inside a window, window budget, daily budget.
        """
        profile     = USER_PROFILES[uid_str]
        state       = USER_STATES[uid_str]
        config      = profile["intentions"][intent_name]
        day_rule    = config["days"].get(get_day_key(), config["days"].get("def"))

        if not day_rule:
            return False, "DAY"

        windows = day_rule.get("time-windows", [])
        active_window = get_active_window(windows, now_sec)
        if not active_window:
            return False, "WINDOW"

        # Window budget check
        win_budget = active_window.get("budget")
        if win_budget is not None:
            win_used = state["intentions"][intent_name]["windows"].get(active_window["range"], 0)
            if win_used >= win_budget:
                return False, "WIN_BUDGET"

        # Daily budget check
        daily_budget = day_rule.get("daily-time-budget")
        if daily_budget is not None:
            daily_used = state["intentions"][intent_name]["daily"]
            if daily_used >= daily_budget:
                return False, "BUDGET"

        return True, "OK"

    # --- ENFORCEMENT ---
    def enforce_rules(pid, uid, full_path, extra_args):
        if not os.path.exists(full_path) and " (deleted)" not in full_path:
            return
        str_uid = str(uid)
        if str_uid not in USER_PROFILES or uid == 0 or pid <= 1:
            return

        profile         = USER_PROFILES[str_uid]
        state           = USER_STATES[str_uid]
        normalized_path = full_path.replace(" (deleted)", "")
        binary_name     = os.path.basename(normalized_path)

        is_authorized = any(normalized_path.startswith(z) for z in profile["authorized_zones"])
        is_dev_zone   = any(normalized_path.startswith(z) for z in profile["dev_zones"])

        if is_authorized:
            # Days off check
            days_off      = profile.get("days_off", {})
            today_off     = days_off.get(get_day_key(), days_off.get("def", []))
            if binary_name in today_off:
                try: os.kill(pid, signal.SIGKILL)
                except: pass
                log(uid, "DENIED", "BIN_DAY", pid, normalized_path)
                return

            # Find intention for this binary
            intent_name, intent_config = None, None
            for name, config in profile["intentions"].items():
                if binary_name in config["binaries"]:
                    intent_name, intent_config = name, config
                    break

            if not intent_name:
                return

            now_sec = get_seconds_since_midnight()

            # Check rules
            allowed, reason = can_use_intention(str_uid, intent_name, now_sec)
            if not allowed:
                try: os.kill(pid, signal.SIGKILL)
                except: pass
                log(uid, "DENIED", reason, pid, normalized_path)
                return

            # Conflict check — different intention already active
            active_name = state["active_intention"]["name"]
            if active_name and intent_name != active_name:
                try: os.kill(pid, signal.SIGKILL)
                except: pass
                log(uid, "DENIED", "CONFLICT", pid, normalized_path)
                return

            # Single binary check
            if intent_config.get("single") == "true":
                running_pids = state["active_intention"]["pids"]
                if running_pids:
                    current_bins = set(os.path.basename(p) for p in running_pids.values())
                    if any(b != binary_name for b in current_bins):
                        try: os.kill(pid, signal.SIGKILL)
                        except: pass
                        log(uid, "DENIED", "SINGLE", pid, normalized_path)
                        return

            # --- ALLOW: track ---
            if active_name is None:
                state["active_intention"]["name"] = intent_name
                log(uid, "INTENTION", "LOCKED", "", intent_name.upper())

            if pid not in state["active_intention"]["pids"]:
                state["active_intention"]["pids"][pid] = normalized_path
                log(uid, "TRACKING", "", pid, normalized_path)
                if binary_name in profile.get("hooks", {}):
                    try:
                        subprocess.Popen(["python3", profile["hooks"][binary_name], str(pid), str(uid)])
                    except:
                        pass

        elif is_dev_zone:
            if is_gui_process(pid):
                try: os.kill(pid, signal.SIGKILL)
                except: pass
                log(uid, "DENIED", "DEV-GUI", pid, normalized_path)
            else:
                if pid not in state["sussy_binaries"]:
                    log(uid, "TRACKING", "SUSSY", pid, full_path)
                    state["sussy_binaries"][pid] = {"uid": uid, "path": normalized_path}
        else:
            try: os.kill(pid, signal.SIGKILL)
            except: pass
            log(uid, "DENIED", "PATH", pid, normalized_path)

    # --- eBPF HANDLER ---
    def handle_launch(cpu, data, size):
        event = b["events"].event(data)
        try:
            raw_path   = event.filename.decode()
            extra_args = event.args.decode(errors="ignore")
            full_path  = get_real_path(event.pid, raw_path)
            enforce_rules(event.pid, event.uid, full_path, extra_args)
        except:
            pass

    def run_startup_sweep():
        log(0, "SYSTEM", "AUDIT", "", "START")
        with os.scandir("/proc") as it:
            for entry in it:
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                if pid == os.getpid() or pid == 1:
                    continue
                try:
                    uid       = entry.stat().st_uid
                    full_path = os.readlink(f"/proc/{pid}/exe")
                    enforce_rules(pid, uid, full_path, "")
                except:
                    continue
        log(0, "SYSTEM", "AUDIT", "", "FINISH")

    # --- MAIN LOOP ---
    b = BPF(text=ebpf_code)
    b["events"].open_perf_buffer(handle_launch)
    run_startup_sweep()

    last_wall_tick  = time.time()
    last_sussy_tick = 0
    last_heartbeat  = time.time()

    try:
        while True:
            b.perf_buffer_poll(timeout=10)
            now = time.time()

            # BPF reinit watchdog
            if now - last_heartbeat > 5.0:
                log(0, "SYSTEM", "WAKE", "", "REINIT")
                b.cleanup()
                b = BPF(text=ebpf_code)
                b["events"].open_perf_buffer(handle_launch)
                run_startup_sweep()
            last_heartbeat = now

            for u_id, state in USER_STATES.items():
                profile      = USER_PROFILES[u_id]
                active_intent = state["active_intention"]["name"]
                now_sec       = get_seconds_since_midnight()

                # PID cleanup
                for pid in list(state["active_intention"]["pids"].keys()):
                    if not os.path.exists(f"/proc/{pid}"):
                        died = state["active_intention"]["pids"].pop(pid, None)
                        log(u_id, "EXIT", "", pid, died)

                # Release intention when no pids left
                if active_intent and not state["active_intention"]["pids"]:
                    state["active_intention"]["name"] = None
                    log(u_id, "INTENTION", "RELEASED", "", active_intent.upper())
                    save_persistence(force=True)

                # Budget tick
                if now - last_wall_tick >= WALL_TICK_RATE:
                    if active_intent and state["active_intention"]["pids"]:
                        config   = profile["intentions"][active_intent]
                        day_rule = config["days"].get(get_day_key(), config["days"].get("def"))

                        if day_rule:
                            # Increment daily
                            state["intentions"][active_intent]["daily"] += 1

                            # Increment active window
                            active_window = get_active_window(day_rule.get("time-windows", []), now_sec)
                            if active_window:
                                r = active_window["range"]
                                state["intentions"][active_intent]["windows"][r] = \
                                    state["intentions"][active_intent]["windows"].get(r, 0) + 1

                            # Check if still allowed
                            allowed, reason = can_use_intention(u_id, active_intent, now_sec)
                            if not allowed:
                                for pid in list(state["active_intention"]["pids"]):
                                    try: os.kill(pid, signal.SIGKILL)
                                    except: pass
                                    log(u_id, "KILLED", reason, pid, active_intent.upper())
                                state["active_intention"]["pids"].clear()

                # Sussy check
                if now - last_sussy_tick >= SUSSY_CHECK_RATE:
                    for pid in list(state["sussy_binaries"].keys()):
                        if not os.path.exists(f"/proc/{pid}"):
                            sussy = state["sussy_binaries"].pop(pid, None)
                            if sussy:
                                log(u_id, "EXIT", "SUSSY", pid, sussy["path"])
                        elif is_gui_process(pid):
                            try: os.kill(pid, signal.SIGKILL)
                            except: pass
                            sussy = state["sussy_binaries"].pop(pid, None)
                            if sussy:
                                log(u_id, "KILLED", "GUI", pid, sussy["path"])

            if now - last_wall_tick >= WALL_TICK_RATE:
                for u_id in USER_STATES:
                    dump_state_file(u_id)
                log(0, "SYSTEM", "STATUS", "", "")
                last_wall_tick = now

            if now - last_save_tick >= SAVE_INTERVAL:
                save_persistence()
                last_save_tick = now

            if now - last_sussy_tick >= SUSSY_CHECK_RATE:
                last_sussy_tick = now

    except KeyboardInterrupt:
        print("\nStopping.")
        save_persistence(force=True)


if __name__ == "__main__":
    main()