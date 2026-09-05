import socket
import json
import os
import dbus
import time
import argparse
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(SCRIPT_DIR, "rules.json")
STATE_PATH = f"/tmp/eckhart/{os.getuid()}.state"    

# --- CONFIG ---
UID = os.getuid()
SOCKET_PATH = f"/tmp/eckhart/{UID}.sock"
NOTIF_TIMEOUT = 6000 
APP_NAME = "EckhartUI"

# Notification triggers
TRIGGER_EVENTS = ["INTENTION", "TRACKING", "KILLED", "DENIED", "EXIT", "SLEEP"]
# Time Milestones in seconds
MILESTONES = {3600: "60 MINUTES REMAINING", 2700: "45 MINUTES REMAINING", 1800: "30 MINUTES REMAINING", 900: "15 MINUTES REMAINING", 600: "10 MINUTES REMAINING", 300: "5 MINUTES REMAINING", 60: "1 MINUTE REMAINING", 30: "30 SECONDS REMAINING", 10: "10 SECONDS REMAINING", 5: "5 SECONDS REMAINING", 4: "4 SECONDS REMAINING", 3: "3 SECONDS REMAINING", 2: "2 SECONDS REMAINING", 1: "1 SECOND REMAINING"}

# --- CLI ARGS ---
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="Show logic in terminal")
parser.add_argument("-s", "--status", action="store_true", help="Print current status snapshot and exit")
args = parser.parse_args()

# --- DBUS SETUP ---
bus = dbus.SessionBus()
notif_obj = bus.get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
notify_interface = dbus.Interface(notif_obj, "org.freedesktop.Notifications")

last_notif_id = 999
current_state = {}
milestone_memory = {}  # {block_name: last_known_remaining_time}

def log_msg(status, event, aaa, bbb, state=None):
    if args.verbose:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] EVENT: {str(event):<12} | STATUS: {str(status):<12} | AAA: {str(aaa):<15} | BBB: {str(bbb)} \n{state}\n")

def show_hud(summary):
    global last_notif_id
    if args.verbose:
        print(f"-> UI PUSH:\n{summary}\n\n")
    last_notif_id = notify_interface.Notify(
        APP_NAME, last_notif_id, "", summary, "", [], {"urgency": 1}, NOTIF_TIMEOUT
    )

def notify(summary, id):
    if args.verbose:
        print(f"-> UI PUSH:\n{summary}\n\n")
    notify_interface.Notify(
        APP_NAME, id, "", summary, "", [], {"urgency": 1}, NOTIF_TIMEOUT
    )

def format_time(seconds):
    if seconds >= 900000: return "∞"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}h {m}m" if h > 0 else f"{m}m {s}s"

def time_to_seconds(t_str):
    h, m = map(int, t_str.split(":"))
    return h * 3600 + m * 60

def get_seconds_since_midnight():
    now = time.localtime()
    return now.tm_hour * 3600 + now.tm_min * 60 + now.tm_sec

def format_binaries(binary_list):
    if not binary_list:
        return ""
    return "\n".join(f" - {os.path.basename(b)}" for b in sorted(set(binary_list)))

def get_day_key():
    return datetime.now().strftime("%a").lower()

def load_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def print_cli_status():
    rules_data = load_json_file(RULES_PATH)
    state_data = load_json_file(STATE_PATH)

    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    ACC   = "\033[36m"          # Minimal accent: Cyan
    MUTED = "\033[38;5;238m"     # Dark slate/gray for lines

    if not state_data:
        print(f"{DIM}[!] ERROR: COULD NOT READ STATE FROM {STATE_PATH}{RST}")
        sys.exit(1)

    profile = rules_data.get(str(UID), {})
    intentions_cfg = profile.get("intentions", {})
    days_off_cfg = profile.get("days_off", {})

    now_sec = get_seconds_since_midnight()
    day_key = get_day_key()
    today_blocked_bins = [b.upper() for b in days_off_cfg.get(day_key, days_off_cfg.get("def", []))]

    time_blocks = state_data.get("st_time_blocks", {})
    active_intent = state_data.get("st_intention_name")

    # Fully wipe screen, clear scrollback buffer, and reset cursor to top
    print("\033[H\033[2J\033[3J", end="", flush=True)

    header_status = f"{BOLD}{ACC}{active_intent.upper()}{RST}" if active_intent else f"{DIM}IDLE{RST}"

    print(f"{MUTED}{'─' * 54}{RST}")
    print(f"  {BOLD}ECKHARTD{RST}                  ACTIVE INTENTION: {header_status}")
    print(f"{MUTED}{'─' * 54}{RST}")

    available_now = []
    upcoming = []
    depleted = []
    closed_today = []

    for name, cfg in intentions_cfg.items():
        day_rule = cfg.get("days", {}).get(day_key, cfg.get("days", {}).get("def"))
        u_name = name.upper()

        if not day_rule:
            closed_today.append(f"{DIM}{u_name:<12} (NO SCHEDULE){RST}")
            continue

        b_data = time_blocks.get(name, {})
        daily_budget = b_data.get("daily_budget")
        daily_used = b_data.get("daily_used", 0)
        daily_rem = float("inf") if daily_budget is None else max(0, daily_budget - daily_used)

        if daily_budget is not None and daily_rem <= 0:
            depleted.append(f"{DIM}{u_name:<12} DAILY LIMIT ({format_time(daily_used).upper()} / {format_time(daily_budget).upper()}){RST}")
            continue

        for w in b_data.get("windows", []):
            r = w["range"]
            start, end = map(time_to_seconds, r.split("-"))
            w_budget = w.get("budget")
            w_used = w.get("used", 0)
            w_rem = float("inf") if w_budget is None else max(0, w_budget - w_used)

            if start <= now_sec <= end:
                if w_budget is not None and w_rem <= 0:
                    depleted.append(f"{DIM}{u_name:<12} WINDOW LIMIT [{r}] ({format_time(w_used).upper()} / {format_time(w_budget).upper()}){RST}")
                else:
                    time_until_end = end - now_sec
                    eff_rem = min(daily_rem, w_rem, time_until_end)
                    rem_str = "∞" if eff_rem == float("inf") else format_time(eff_rem).upper()
                    used_str = format_time(daily_used).upper()

                    # Determine bottleneck reason
                    if eff_rem == float("inf"):
                        reason = "UL"
                    elif eff_rem == daily_rem and daily_budget is not None:
                        reason = "DB"
                    elif eff_rem == w_rem and w_budget is not None:
                        reason = "WB"
                    else:
                        reason = "TF"

                    available_now.append(
                        f"   {BOLD}{u_name:<12}{RST} {DIM}{r:<11}{RST}   SPENT: {used_str:<9} REM: {BOLD}{ACC}{rem_str:<8}{RST} {DIM}({reason}){RST}"
                    )
            elif now_sec < start:
                upcoming.append(
                    f"   {u_name:<12} {DIM}{r}{RST}   STARTS IN {DIM}{format_time(start - now_sec).upper()}{RST}"
                )

    print(f"\n {BOLD}AVAILABLE{RST}")
    if available_now:
        for item in available_now:
            print(item)
    else:
        print(f"   {DIM}NONE{RST}")

    if upcoming:
        print(f"\n {BOLD}UPCOMING{RST}")
        for item in upcoming:
            print(item)

    if depleted:
        print(f"\n {BOLD}DEPLETED{RST}")
        for item in depleted:
            print(f"   {item}")

    has_closed = today_blocked_bins or closed_today
    if has_closed:
        print(f"\n {BOLD}CLOSED TODAY{RST}")
        if today_blocked_bins:
            print(f"   {DIM}DAY-OFF:{RST} {', '.join(today_blocked_bins)}")
        for item in closed_today:
            print(f"   {item}")

    print(f"\n{MUTED}{'─' * 54}{RST}\n")
    sys.exit(0)


def parse_state():
    global current_state, milestone_memory
    my_state = current_state    .get(str(UID))
    if not my_state: return "NO INTENTION FOUND", False

    intent_name  = my_state.get("st_intention_name")
    intent_bins  = my_state.get("st_intention_binaries", [])
    time_blocks  = my_state.get("st_time_blocks", {})
    now_sec      = get_seconds_since_midnight()
    any_milestone_hit = False
    lines = []

    for name, info in time_blocks.items():
        is_active    = (name == intent_name)
        daily_budget = info.get("daily_budget")   # None = infinite
        daily_used   = info.get("daily_used", 0)
        windows      = info.get("windows", [])

        daily_remaining = float("inf") if daily_budget is None else max(0, daily_budget - daily_used)

        # find the currently active window
        active_win     = None
        window_end_str = "END"
        win_remaining  = float("inf")
        win_budget_rem = float("inf")

        for w in windows:
            if w.get("is_active"):
                active_win = w
                _, end_str = w["range"].split("-")
                window_end_str = end_str
                time_until_end = time_to_seconds(end_str) - now_sec
                win_budget     = w.get("budget")  # None = infinite
                win_used       = w.get("used", 0)
                win_budget_rem = float("inf") if win_budget is None else max(0, win_budget - win_used)
                win_remaining  = min(time_until_end, win_budget_rem)
                break

        if not active_win:
            continue

        rem_time       = min(daily_remaining, win_remaining)
        time_until_end = time_to_seconds(window_end_str) - now_sec

        # reason code
        if daily_remaining <= win_remaining and daily_remaining <= time_until_end:
            reason = "DB"
        elif active_win.get("budget") is not None and win_budget_rem <= time_until_end:
            reason = "WB"
        else:
            reason = "W"

        if is_active:
            last_val = milestone_memory.get(name, 999999)
            for m_sec in sorted(MILESTONES.keys(), reverse=True):
                if last_val > m_sec >= rem_time:
                    any_milestone_hit = True
                    break
            milestone_memory[name] = rem_time

            if daily_budget is None and active_win.get("budget") is None:
                display_time = f"> {window_end_str}"
            else:
                display_time = f"({format_time(rem_time)})({reason}) > {window_end_str}"

            if not any_milestone_hit:
                lines.append(f"🎯 {name.upper()} {display_time}\n{format_binaries(intent_bins)}")
            else:
                milestone_label = next((label for secs, label in sorted(MILESTONES.items()) if rem_time <= secs), format_time(rem_time))
                lines = [f"⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️\n\n{milestone_label} — {name.upper()}\n\n⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️ ⚠️"]

    if intent_name:
        return "".join(lines), any_milestone_hit
    else:
        return "🎯 NO INTENTION SET", False


def main():

    if args.status:
        print_cli_status()

    global current_state
    if args.verbose: print(f"Eckhart UI — UID {UID}")

    last_heartbeat    = time.time()
    last_warning_time = 0
    daemon_was_alive  = False

    while True:
        if not os.path.exists(SOCKET_PATH):
            now = time.time()
            if now - last_warning_time > 5:
                notify("💀 ROOT DAEMON DOWN.", 0)
                last_warning_time = now
            daemon_was_alive = False
            time.sleep(2)
            continue

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2.0)
                client.connect(SOCKET_PATH)

                notify("⚡ ECKHART ONLINE: Root is now enforcing.", 0)
                if args.verbose: print("Connected to Root Daemon.")

                last_heartbeat   = time.time()
                daemon_was_alive = True
                buffer           = ""

                while True:
                    try:
                        data = client.recv(4096).decode()
                        if not data:
                            if args.verbose: print("Connection closed by daemon.")
                            break

                        buffer += data
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            try:
                                msg = json.loads(line)
                                last_heartbeat = time.time()

                                status = msg.get("status")
                                event  = msg.get("event")

                                if "state" in msg and msg["state"]:
                                    current_state[str(UID)] = msg["state"]

                                # STATUS pulse — only fire HUD on milestone
                                if status == "STATUS":
                                    summary, hit = parse_state()
                                    if hit:
                                        show_hud(summary)

                                if event == "WINE":
                                    notify(f"🍷-{status}: {msg.get('aaa')}", 0)

                                if event == "SLEEP":
                                    if status == "WARNING":
                                        bbb = msg.get('bbb', '')
                                        if "Boot" in bbb:
                                            notify(f"😴 SLEEP HOURS: Shutting down in 30s. Go to bed.", 0)
                                        else:
                                            notify("😴 SLEEP IN 60s — Computer will shut down.", 0)
                                    elif status == "SHUTDOWN":
                                        notify("💤 SLEEP TIME: Shutting down now. Good night.", 0)

                                if event == "DENIED":
                                    notify(f"🚫 DENIED-{status}: {os.path.basename(msg.get('bbb', 'unknown'))}", 0)

                                if event == "INTENTION":
                                    if status == "RELEASED":
                                        notify(f"✅ INTENTION RELEASED: {msg.get('bbb')}", 0)
                                    elif status == "LOCKED":
                                        notify(f"🔒 LOCKED: {msg.get('bbb')}", 0)

                                if event == "KILLED":
                                    notify(f"💀 KILLED-{status}: {msg.get('bbb')}", 0)

                                if event in TRIGGER_EVENTS:
                                    log_msg(status, event, msg.get("aaa"), msg.get("bbb"), msg.get("state"))
                                    summary, _ = parse_state()
                                    if summary:
                                        show_hud(summary)

                            except json.JSONDecodeError:
                                continue

                    except socket.timeout:
                        now = time.time()
                        if now - last_heartbeat > 10:
                            if now - last_warning_time > 5:
                                notify("⚠️ DAEMON UNRESPONSIVE: Heartbeat lost!", 0)
                                last_warning_time = now
                        continue

        except (ConnectionRefusedError, socket.error):
            now = time.time()
            if now - last_warning_time > 5:
                msg_txt = ("🛑 ROOT DAEMON DOWN: Connection Refused" if not daemon_was_alive
                           else "💀 DAEMON CRASHED: Connection Lost")
                #notify(msg_txt, 0)
                last_warning_time = now
            current_state[str(UID)] = {}
            daemon_was_alive = False
            time.sleep(2)

        except Exception as e:
            if args.verbose: print(f"Unexpected Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()