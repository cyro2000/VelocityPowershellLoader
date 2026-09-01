import os, sys, hashlib, subprocess, time, datetime, json
import zipfile, struct, ctypes, shutil, webbrowser
from pathlib import Path
from collections import defaultdict

try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    import tkinter as tk
    from tkinter import filedialog
    HAS_TK = True
except Exception:
    HAS_TK = False

if getattr(sys, "frozen", False):
    RUN_DIR = Path(os.path.dirname(os.path.abspath(sys.executable)))
else:
    RUN_DIR = Path(os.path.dirname(os.path.abspath(sys.argv[0])))

DATA_DIR     = RUN_DIR / "data"
DEFAULTS_DIR = DATA_DIR / "defaults"
PRESETS_DIR  = RUN_DIR / "presets"
UI_DIR       = RUN_DIR / "ui"

W    = "\033[0m"
WH   = "\033[97m"
GR   = "\033[90m"
RD   = "\033[91m"
GN   = "\033[92m"
YL   = "\033[93m"
CY   = "\033[96m"
MG   = "\033[95m"
PU   = "\033[38;5;135m"  # bright purple
BOLD = "\033[1m"
DIM  = "\033[2m"

def c(*codes):
    def wrap(t): return "".join(codes) + str(t) + W
    return wrap

_out_buf   = []
_out_last  = 0.0
_OUT_BATCH = 40
_OUT_MS    = 0.05

def _out_flush(force=False):
    global _out_last
    if not _out_buf:
        return
    now = time.time()
    if not force and len(_out_buf) < _OUT_BATCH and (now - _out_last) < _OUT_MS:
        return
    sys.stdout.write("\n".join(_out_buf) + "\n")
    sys.stdout.flush()
    _out_buf.clear()
    _out_last = now

def p(t=""):
    _out_buf.append(str(t))
    _out_flush()

_openable_refs = []

def reset_refs():
    _openable_refs.clear()

def file_uri(path):
    ap = os.path.abspath(path).replace("\\", "/")
    if not ap.startswith("/"):
        ap = "/" + ap
    return "file://" + ap

def osc8(url, text):
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"

def add_ref(path, kind):
    is_exec = kind == "jar" or path.lower().endswith((".jar", ".exe", ".dll", ".bat", ".cmd", ".ps1"))
    target = os.path.dirname(path) if is_exec else path
    _openable_refs.append({"path": path, "target": target, "kind": kind, "is_folder": is_exec})
    return len(_openable_refs)

def link_ref(path, kind, label=None):
    n = add_ref(path, kind)
    ref = _openable_refs[n - 1]
    text = label if label else "▶"
    try:
        hyperlinked = osc8(file_uri(ref["target"]), c(CY, BOLD)(text))
    except Exception:
        hyperlinked = c(CY, BOLD)(text)
    return f"{hyperlinked} {c(DIM,GR)(f'[{n}]')}"

def open_ref(n):
    if not (1 <= n <= len(_openable_refs)):
        return None, f"No such reference: {n}"
    ref = _openable_refs[n - 1]
    target = ref["target"]
    try:
        if os.name == "nt":
            if ref["is_folder"] and os.path.isfile(ref["path"]):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(ref["path"])])
            else:
                xopen(target)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
        return target, None
    except Exception as e:
        return None, str(e)

COMMANDS = [
    "/admin","/clear","/dashboard","/elevate","/exit","/find",
    "/flash","/ghost","/help","/history","/inspect","/live","/livescan","/open","/path","/preset",
    "/pro","/max","/report","/seeterminal","/source","/stats","/strings","/whitelist","/window",
]

DATA_FILES = {
    "cheat_strings":   "cheat_strings.json",
    "client_profiles": "client_profiles.json",
    "scanner":         "scanner.json",
}

ghost_state = {"active": False, "paths": [], "focus_paths": [], "strings": []}
active_preset = {"name": "default", "data": None}

SCAN_RUNNING  = False
terminal_log  = []
scan_counters = {}
all_findings  = {}

_SCANNER_STATUS = "idle"

def set_scanner_status(s):
    global _SCANNER_STATUS
    _SCANNER_STATUS = s

def get_scanner_status():
    return _SCANNER_STATUS

def scanner_widget():
    s = get_scanner_status()
    if   s == "running": return c(MG)("●") + " " + c(MG)("Scanner")
    elif s == "warn":    return c(YL)("●") + " " + c(YL)("Scanner")
    elif s == "crashed": return c(RD)("●") + " " + c(RD)("Scanner")
    return c(GR)("●") + " " + c(GR)("Scanner")

def reset_state():
    global terminal_log, all_findings, scan_counters
    terminal_log  = []
    scan_counters = {"green": 0, "yellow": 0, "red": 0, "total": 0, "jars": 0}
    all_findings  = {
        "scanner": [], "config_hits": [], "log_hits": [], "jar_flags": [],
        "process_flags": [], "dns_flags": [], "registry_flags": [],
        "prefetch_flags": [],
        "summary": {"private_hits": 0, "spoof_hits": 0, "dns_hits": 0, "log_tampering": 0},
    }
    set_scanner_status("idle")

def tlog(msg, kind="info"):
    ts    = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    icons = {
        "info": c(GR)("[") + c(GR)("i") + c(GR)("]"),
        "scan": c(GR)("[") + c(CY)(">") + c(GR)("]"),
        "ok":   c(GR)("[") + c(GN)("+") + c(GR)("]"),
        "warn": c(GR)("[") + c(YL)("!") + c(GR)("]"),
        "bad":  c(GR)("[") + c(RD, BOLD)("x") + c(GR)("]"),
    }
    line  = f"  {c(GR)(f'{ts}')} {icons.get(kind, icons['info'])} {c(WH)(msg)}"
    terminal_log.append(line)
    if SCAN_RUNNING:
        p(line)

def status_bar():
    g = scan_counters.get("green", 0)
    y = scan_counters.get("yellow", 0)
    r = scan_counters.get("red", 0)
    t = scan_counters.get("total", 0)
    j = scan_counters.get("jars", 0)
    return (
        f"  {c(GN)('●')} {c(WH)(str(g))}  "
        f"{c(YL)('●')} {c(WH)(str(y))}  "
        f"{c(RD,BOLD)('●')} {c(WH)(str(r))}  "
        f"{c(GR)('files:')} {c(WH)(str(t))}  "
        f"{c(GR)('jars:')} {c(WH)(str(j))}  "
        f"│  {scanner_widget()}"
    )

def draw_status():
    _out_flush(force=True)
    sys.stdout.write("\r\033[K" + status_bar())
    sys.stdout.flush()

_last_progress_time = 0.0

def draw_progress(label, done, total, eta=""):
    global _last_progress_time
    now = time.time()
    if done < total and (now - _last_progress_time) < 0.06:
        return
    _last_progress_time = now
    _out_flush(force=True)
    bw     = 26
    pct    = min(done / max(total, 1), 1.0)
    filled = int(bw * pct)
    bar    = c(CY)("█" * filled) + c(GR)("░" * (bw - filled))
    eta_s  = c(GR)(f"  ETA {eta}") if eta else ""
    sys.stdout.write(
        f"\r\033[K  {c(GR)(label):<18} {bar}  "
        f"{c(WH)(f'{done}/{total}')}{eta_s}  "
        f"│ {scanner_widget()}   "
    )
    sys.stdout.flush()

def eta_str(elapsed, done, total):
    if done == 0: return "calc..."
    rate   = done / max(elapsed, 0.001)
    remain = max(0, total - done) / rate
    return f"~{int(remain)}s" if remain < 60 else f"~{int(remain//60)}m{int(remain%60)}s"


def sha1(path):
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536): h.update(chunk)
        return h.hexdigest()
    except Exception: return None

def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536): h.update(chunk)
        return h.hexdigest()
    except Exception: return None

def is_admin():
    if os.name == "nt":
        try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception: return False
    else:
        try: return os.getuid() == 0
        except Exception: return False

def open_folder_dialog(title="Select Folder"):
    if HAS_TK:
        try:
            root = tk.Tk(); root.withdraw()
            root.wm_attributes("-topmost", 1)
            path = filedialog.askdirectory(title=title)
            root.destroy()
            return path if path else None
        except Exception: pass
    try:
        result = subprocess.run(
            ["powershell","-NoProfile","-Command",
             "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')|Out-Null;"
             "$f=New-Object System.Windows.Forms.FolderBrowserDialog;"
             "$f.ShowDialog()|Out-Null;$f.SelectedPath"],
            capture_output=True, text=True, timeout=60)
        path = result.stdout.strip()
        return path if path and os.path.isdir(path) else None
    except Exception: return None

def open_file_dialog(title="Select File"):
    if HAS_TK:
        try:
            root = tk.Tk(); root.withdraw()
            root.wm_attributes("-topmost", 1)
            path = filedialog.askopenfilename(
                title=title,
                filetypes=(("JSON/Text","*.json *.txt"),("All files","*.*")),
            )
            root.destroy()
            return path if path else None
        except Exception: pass
    try:
        result = subprocess.run(
            ["powershell","-NoProfile","-Command",
             "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')|Out-Null;"
             "$f=New-Object System.Windows.Forms.OpenFileDialog;"
             "$f.Filter='JSON/Text|*.json;*.txt|All files|*.*';"
             "$f.ShowDialog()|Out-Null;$f.FileName"],
            capture_output=True, text=True, timeout=60)
        path = result.stdout.strip()
        return path if path and os.path.isfile(path) else None
    except Exception: return None

def get_hint(text):
    if not text or not text.startswith("/"): return ""
    for cmd in COMMANDS:
        if cmd.startswith(text) and cmd != text: return cmd
    return ""

_command_history = []

def get_clipboard_text():
    try:
        CF_UNICODETEXT = 13
        k32 = ctypes.windll.kernel32
        u32 = ctypes.windll.user32
        u32.GetClipboardData.restype = ctypes.c_void_p
        u32.GetClipboardData.argtypes = [ctypes.c_uint]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalLock.argtypes = [ctypes.c_void_p]
        k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        u32.OpenClipboard.argtypes = [ctypes.c_void_p]
        if not u32.OpenClipboard(None):
            return ""
        try:
            handle = u32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return ""
            ptr = k32.GlobalLock(handle)
            if not ptr:
                return ""
            try:
                text = ctypes.wstring_at(ptr)
            finally:
                k32.GlobalUnlock(handle)
            return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        finally:
            u32.CloseClipboard()
    except Exception:
        return ""

def read_line(prompt):
    _out_flush(force=True)
    sys.stdout.write(prompt); sys.stdout.flush()
    if not HAS_MSVCRT:
        try: return input()
        except (EOFError, KeyboardInterrupt): return "__CTRLC__"

    buf = []
    pos = 0
    hist_idx = len(_command_history)
    saved_current = ""

    def redraw():
        cur = "".join(buf)
        hint = get_hint(cur)
        hr = hint[len(cur):] if (hint and pos == len(buf)) else ""
        line = "\r\033[K" + prompt + cur
        if hr:
            line += "\033[2m" + hr + "\033[0m"
        back = len(hr) + (len(buf) - pos)
        if back:
            line += "\033[" + str(back) + "D"
        sys.stdout.write(line)
        sys.stdout.flush()

    while True:
        try: ch = msvcrt.getwch()
        except Exception: break

        if ch in ("\r", "\n"):
            sys.stdout.write("\r\033[K" + prompt + "".join(buf) + "\n")
            sys.stdout.flush()
            result = "".join(buf)
            if result.strip():
                _command_history.append(result)
            return result

        elif ch == "\x03":
            sys.stdout.write("^C\n")
            sys.stdout.flush()
            return "__CTRLC__"

        elif ch == "\x16":
            pasted = get_clipboard_text()
            if pasted:
                buf[pos:pos] = list(pasted)
                pos += len(pasted)
                redraw()

        elif ch == "\x08":
            if pos > 0:
                buf.pop(pos - 1)
                pos -= 1
                redraw()

        elif ch == "\t":
            hint = get_hint("".join(buf))
            if hint:
                buf = list(hint)
                pos = len(buf)
                redraw()

        elif ch in ("\xe0", "\x00"):
            nch = msvcrt.getwch()
            if nch == "M":
                hint = get_hint("".join(buf))
                if hint:
                    buf = list(hint); pos = len(buf)
                elif pos < len(buf):
                    pos += 1
                redraw()
            elif nch == "K":
                if pos > 0: pos -= 1
                redraw()
            elif nch == "H":
                if _command_history:
                    if hist_idx == len(_command_history):
                        saved_current = "".join(buf)
                    hist_idx = max(0, hist_idx - 1)
                    buf = list(_command_history[hist_idx]); pos = len(buf)
                    redraw()
            elif nch == "P":
                if hist_idx < len(_command_history):
                    hist_idx += 1
                    if hist_idx == len(_command_history):
                        buf = list(saved_current)
                    else:
                        buf = list(_command_history[hist_idx])
                    pos = len(buf)
                    redraw()
            elif nch == "S":
                if pos < len(buf):
                    buf.pop(pos)
                    redraw()
            elif nch == "G":
                pos = 0; redraw()
            elif nch == "O":
                pos = len(buf); redraw()

        elif ord(ch) >= 32:
            buf[pos:pos] = [ch]
            pos += 1
            redraw()

    return "".join(buf)

def xopen(path):
    """Open a file or folder cross-platform."""
    try:
        if os.name == "nt":
            xopen(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception: pass

def clear(): os.system("cls" if os.name == "nt" else "clear")

def divider(w=74): p(c(GR)("  " + "─" * w))

def section(title):
    tag = c(GR)("[") + c(MG)(">") + c(GR)("] ") + c(WH,BOLD)(title)
    visible_len = len(title) + 4
    pad = max(2, 76 - visible_len - 12)
    p()
    p(tag + " " * pad + scanner_widget())

def row(label, val, st=None, w=36):
    lb = c(WH)(f"  {label:<{w}}")
    if   st=="clean": vb = c(GN)(f"  {val}")
    elif st=="warn":  vb = c(YL)(f"  {val}")
    elif st=="bad":   vb = c(RD,BOLD)(f"  {val}")
    elif st=="info":  vb = c(CY)(f"  {val}")
    else:             vb = c(GR)(f"  {val}")
    p(lb + vb)

ASCII_LOGO = [
    "  ██╗   ██╗███████╗██╗      ██████╗  ██████╗██╗████████╗██╗   ██╗",
    "  ██║   ██║██╔════╝██║     ██╔═══██╗██╔════╝██║╚══██╔══╝╚██╗ ██╔╝",
    "  ██║   ██║█████╗  ██║     ██║   ██║██║     ██║   ██║    ╚████╔╝ ",
    "  ╚██╗ ██╔╝██╔══╝  ██║     ██║   ██║██║     ██║   ██║     ╚██╔╝  ",
    "   ╚████╔╝ ███████╗███████╗╚██████╔╝╚██████╗██║   ██║      ██║   ",
    "    ╚═══╝  ╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝   ╚═╝      ╚═╝   ",
]

# Purple gradient: 55→93→129→165→135→99
LOGO_GRADIENT = [55, 93, 129, 165, 135, 99]

def g256(n):
    def wrap(t): return f"\033[38;5;{n}m" + t + W
    return wrap

def print_logo():
    try:
        term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        term_width = 80
    width = max(len(l) for l in ASCII_LOGO)
    pad = max(0, (term_width - width) // 2)
    indent = " " * pad
    for line, shade in zip(ASCII_LOGO, LOGO_GRADIENT):
        p(indent + "\033[3m" + g256(shade)(line) + "\033[0m")
    p(indent + c(GR)("‾" * width))

def banner():
    clear()
    p()
    print_logo()
    p()
    p(c(GR)("[") + c(CY)(">") + c(GR)("] ") + c(WH)("Velocity ready.") + c(GR)("  /help  ·  Tab = autocomplete  ·  Ctrl+C = cancel scan"))
    if not is_admin():
        p(c(GR)("[") + c(YL)("!") + c(GR)("] ") + c(YL)(("Not Administrator" if os.name=="nt" else "Not root") + " — registry + prefetch scans limited"))
    if not PSUTIL_OK:
        p(c(GR)("[") + c(YL)("!") + c(GR)("] ") + c(YL)("pip install psutil  — process scanning limited"))
    p(c(GR)("[") + c(CY)("i") + c(GR)("] ") + c(WH)("Preset: ") + c(CY)(active_preset["name"]) +
      c(GR)("   Data: ") + c(GR)(str(DATA_DIR)) + c(GR)("   ") + scanner_widget())
    p()

KNOWN_LAUNCHERS = {
    "FastClient": [os.path.join(os.environ.get("APPDATA",""), ".fastclient", "profiles")],
    "Vanilla":       [os.path.expandvars(r"%APPDATA%\.minecraft")],
    "PrismLauncher": [os.path.expandvars(r"%APPDATA%\PrismLauncher")],
    "MultiMC":       [os.path.expandvars(r"%APPDATA%\MultiMC")],
    "CurseForge":    [os.path.join(os.path.expanduser("~"),"curseforge","minecraft")],
    "Technic":       [os.path.expandvars(r"%APPDATA%\.technic")],
    "FTB":           [os.path.expandvars(r"%APPDATA%\ftblauncher")],
    "PolyMC":        [os.path.expandvars(r"%APPDATA%\PolyMC")],
    "GDLauncher":    [os.path.expandvars(r"%APPDATA%\gdlauncher_next")],
    "Feather":       [os.path.expandvars(r"%APPDATA%\FeatherClient"),
                      os.path.expandvars(r"%APPDATA%\.feather")],
    "Badlion":       [os.path.expandvars(r"%APPDATA%\.badlion")],
    "Lunar":         [os.path.expandvars(r"%APPDATA%\.lunarclient")],
    "ATLauncher":    [os.path.expandvars(r"%APPDATA%\ATLauncher")],
    "Modrinth":      [os.path.expandvars(r"%APPDATA%\com.modrinth.theseus")],
    "TLauncher":     [os.path.expandvars(r"%APPDATA%\.tlauncher")],
    "Labymod":       [os.path.expandvars(r"%APPDATA%\.labymod4")],
    "Salwyrr":       [os.path.expandvars(r"%APPDATA%\Salwyrr")],
}

INSTANCE_SUBDIRS = {
    "Mods":"mods","Config":"config","Logs":"logs",
    "Crash Reports":"crash-reports","ResourcePacks":"resourcepacks",
    "Screenshots":"screenshots","Saves":"saves",
    "Shaderpacks":"shaderpacks","Versions":"versions",
}

DRIVE_WALK_SKIP = {
    "windows","$recycle.bin","system volume information","programdata",
    "$windows.~bt","$windows.~ws","recovery","perflogs",
    "node_modules",".git",".gradle",".m2",".gradle-cache",
    "target","build",".idea",".vscode","__pycache__",
    "venv",".venv","site-packages","dist","obj",
}

CLICKER_NAMES = [
    "198m","198macros","198_macros","zenith","zenithlauncher","zenith_macros",
    "akira_ghost","akiraghost","zoomin_client","zoominclient",
    "sodaclicker","soda_clicker","koidclicker","koid_clicker",
    "wraithclicker","wraith_clicker","rawaccel",
]

BYPASS_NAMES = [
    "modeleter","model_deleter","antiforensic","anti_forensic",
    "logcleaner","log_cleaner","journalwiper","prefetchcleaner",
]

CHEAT_DOMAINS = [
    "vape.gg","liquidbounce.net","meteorclient.com","wurst-client.tk",
    "sigma.rip","rusherhack.org","nulled.to","leak.sx","cracked.to",
    "mpgh.net","cyemer.xyz","cyemer.net","cyemer.gg",
    "velaris.xyz","velaris.net","scrimclient.xyz","lucidclient.xyz",
    "argonclient.xyz","spearcore.xyz","xenon.gg",
]

DEFAULT_DATA = {
    "cheat_strings": {"default_strings": sorted(list({
        "com.slither.cyemer","CyemerClient","com.slither","VelarisClient","ArgonClient",
        "LucidClient","ScrimClient","SpearCoreClient","ThunderHack","SigmaClient",
        "WurstClient","MeteorClient","VapeClient","RusherHack","LiquidBounce","net.ccbluex",
        "AutoMace","AutoCrystal","AutoTotemGuard","AutoTotem","KillAura","killaura",
        "TriggerBot","AimAssist","Fakelag","FakeLag","Blink","SpearSwap","MaceSwap",
        "ElytraSwap","Shielddrain","ShieldDrain","AntiKnockback","SelfDestruct","LogCleaner",
        "DirectByteOverwriter","JarUpdater","StringDecoder","Cyemer-Client-Updater",
        "Cyemer-Client-Byte-Overwriter","AutoAnchor","AutoObsidian","AutoShieldBreak",
        "AutoWindCharge","AutoJumpReset","PearlCatch","HoverTotem","KeyPearl","NoFall",
        "BHop","Scaffold","FlyHack","ESP","ShaderESP","HandCham","WTap",
        "ReachExtension","FastPlace","NoBreakDelay","WebBreaker","WindChargeKey",
        "TargetEffect","ObsidianGlow","cyemer/configs","velaris/config","argon/config",
        "module-name","module.isEnabled","ModuleManager","Category.COMBAT",
        "Category.CLIENT","Category.RENDER","BooleanSetting","SliderSetting",
        "ModeSetting","cdn.modrinth.com/data/LQ3K71Q1",
    }))},
    "client_profiles": {
        "Cyemer": {
            "real_packages": ["com/slither/cyemer/"],
            "spoof_mod_ids": ["dynamic_fps","dynamic-fps"],
            "spoof_jar_names": ["dynamic-fps","dynamicfps"],
            "config_dirs": ["cyemer","cyemer/configs"],
            "config_files": ["cyemer.json"],
            "config_path_sig": "cyemer/configs",
            "log_clean_terms": ["cyemer","nanovg"],
            "ua_strings": ["Cyemer-Client-Updater/1.0","Cyemer-Client-Byte-Overwriter/1.0"],
            "key_classes": ["CyemerClient","Cyemer","ModuleManager","ConfigManager",
                            "SelfDestruct","LogCleaner","JarUpdater","DirectByteOverwriter",
                            "StringDecoder","RemoteConfig"],
            "key_mixins": ["ClientConnectionMixin","ClientPlayNetworkHandlerMixin",
                           "LivingEntityMixin","PlayerEntityMixin","MouseMixin"],
            "module_names": ["AimAssist","AutoCrystal","AutoMace","AutoAnchor","AutoObsidian",
                             "AutoPot","AutoShieldBreak","AutoWindCharge","TriggerBot","WTap",
                             "Blink","ElytraSwap","Fakelag","Fly","MaceSwap","SelfDestruct",
                             "HoverTotem","KeyPearl","PearlCatch","AutoDrain","AutoTotem"],
            "selfdestruct_url": "cdn.modrinth.com/data/LQ3K71Q1",
        },
        "Cyemer Recode": {
            "real_packages": ["com/slither/cyemer/recode/","com/slither/recode/"],
            "spoof_mod_ids": ["dynamic_fps","dynamic-fps","lithium"],
            "spoof_jar_names": ["dynamic-fps","lithium","recode"],
            "config_dirs": ["cyemer-recode","recode"],
            "config_files": ["recode.json"],
            "config_path_sig": "cyemer-recode",
            "log_clean_terms": ["cyemer","recode","nanovg"],
            "ua_strings": ["Cyemer-Recode-Updater/1.0"],
            "key_classes": ["RecodeClient","CyemerRecode"],
            "key_mixins": [],
            "module_names": ["AimAssist","AutoCrystal","AutoMace","TriggerBot","Fakelag",
                             "ElytraSwap","SelfDestruct","Blink"],
            "selfdestruct_url": "",
        },
        "Velaris": {
            "real_packages": ["me/velaris/","velaris/client/","com/velaris/"],
            "spoof_mod_ids": ["sodium","immediatelyfast","dynamic_fps"],
            "spoof_jar_names": ["sodium","immediatelyfast","velaris"],
            "config_dirs": ["velaris",".velaris"],
            "config_files": ["velaris.json"],
            "config_path_sig": "velaris",
            "log_clean_terms": ["velaris"],
            "ua_strings": ["Velaris-Updater/1.0"],
            "key_classes": ["VelarisClient","VelarisModule"],
            "key_mixins": [],
            "module_names": ["AimAssist","AutoCrystal","AutoMace","KillAura","Fakelag",
                             "ElytraSwap","TriggerBot"],
            "selfdestruct_url": "",
        },
        "Argon": {
            "real_packages": ["me/argon/client/","argon/client/","com/argonhq/"],
            "spoof_mod_ids": ["sodium","fabric-api","krypton"],
            "spoof_jar_names": ["argon-client","argonclient","argon"],
            "config_dirs": ["argon",".argon","ArgonClient"],
            "config_files": ["argon.json","argon_settings.json"],
            "config_path_sig": "argon",
            "log_clean_terms": ["argon"],
            "ua_strings": [],
            "key_classes": ["ArgonClient","ArgonModule"],
            "key_mixins": [],
            "module_names": ["KillAura","AimAssist","AutoCrystal","Velocity","Scaffold"],
            "selfdestruct_url": "",
        },
        "Argon B2": {
            "real_packages": ["me/argon/b2/","argon/b2/"],
            "spoof_mod_ids": ["sodium","krypton"],
            "spoof_jar_names": ["argon-b2","argonb2"],
            "config_dirs": ["argon-b2",".argonb2"],
            "config_files": ["argon_b2.json"],
            "config_path_sig": "argon-b2",
            "log_clean_terms": ["argon"],
            "ua_strings": [],
            "key_classes": ["ArgonB2","ArgonB2Client"],
            "key_mixins": [],
            "module_names": ["KillAura","AimAssist","AutoCrystal"],
            "selfdestruct_url": "",
        },
        "Lucid": {
            "real_packages": ["me/lucid/client/","lucid/client/","com/lucidclient/"],
            "spoof_mod_ids": ["lithium","sodium-extra"],
            "spoof_jar_names": ["lucid-client","lucidclient"],
            "config_dirs": ["lucid",".lucid"],
            "config_files": ["lucid.json","lucid_settings.json"],
            "config_path_sig": "lucid",
            "log_clean_terms": ["lucid"],
            "ua_strings": [],
            "key_classes": ["LucidClient","LucidModule"],
            "key_mixins": [],
            "module_names": ["KillAura","AimAssist","AutoCrystal","Fakelag"],
            "selfdestruct_url": "",
        },
        "Lucid Argon": {
            "real_packages": ["me/lucidargon/","lucidargon/client/"],
            "spoof_mod_ids": ["lithium","sodium"],
            "spoof_jar_names": ["lucid-argon","lucidargon"],
            "config_dirs": ["lucid-argon",".lucid-argon"],
            "config_files": ["lucid-argon.json"],
            "config_path_sig": "lucid-argon",
            "log_clean_terms": ["lucidargon"],
            "ua_strings": [],
            "key_classes": ["LucidArgon"],
            "key_mixins": [],
            "module_names": [],
            "selfdestruct_url": "",
        },
        "Scrim": {
            "real_packages": ["me/scrim/","scrim/client/"],
            "spoof_mod_ids": ["fabric-api","modmenu"],
            "spoof_jar_names": ["scrim","scrim-client"],
            "config_dirs": ["scrim",".scrim"],
            "config_files": ["scrim.json"],
            "config_path_sig": "scrim",
            "log_clean_terms": ["scrim"],
            "ua_strings": [],
            "key_classes": ["ScrimClient"],
            "key_mixins": [],
            "module_names": [],
            "selfdestruct_url": "",
        },
        "SpearCore": {
            "real_packages": ["me/spearcore/","spearcore/client/","com/spearcore/"],
            "spoof_mod_ids": ["sodium","immediatelyfast"],
            "spoof_jar_names": ["spearcore","spear-core"],
            "config_dirs": ["spearcore",".spearcore"],
            "config_files": ["spearcore.json"],
            "config_path_sig": "spearcore",
            "log_clean_terms": ["spearcore"],
            "ua_strings": [],
            "key_classes": ["SpearCoreClient"],
            "key_mixins": [],
            "module_names": ["AutoMace","SpearSwap","MaceSwap"],
            "selfdestruct_url": "",
        },
        "Xenon": {
            "real_packages": ["me/xenon/","xenon/client/"],
            "spoof_mod_ids": ["sodium","krypton"],
            "spoof_jar_names": ["xenon","xenon-client"],
            "config_dirs": ["xenon",".xenon"],
            "config_files": ["xenon.json"],
            "config_path_sig": "xenon",
            "log_clean_terms": ["xenon"],
            "ua_strings": [],
            "key_classes": ["XenonClient"],
            "key_mixins": [],
            "module_names": [],
            "selfdestruct_url": "",
        },
        "Vape": {
            "real_packages": ["com/vape/","me/vape/"],
            "spoof_mod_ids": [],
            "spoof_jar_names": ["vape","vape-client"],
            "config_dirs": ["vape",".vape"],
            "config_files": ["vape.json"],
            "config_path_sig": "vape",
            "log_clean_terms": ["vape"],
            "ua_strings": [],
            "key_classes": ["VapeClient"],
            "key_mixins": [],
            "module_names": ["KillAura","AimAssist","AutoClicker"],
            "selfdestruct_url": "",
        },
        "Wurst": {
            "real_packages": ["com/wurst/","net/wurst/"],
            "spoof_mod_ids": [],
            "spoof_jar_names": ["wurst"],
            "config_dirs": ["wurst",".wurst"],
            "config_files": ["wurst.json"],
            "config_path_sig": "wurst",
            "log_clean_terms": ["wurst"],
            "ua_strings": [],
            "key_classes": ["WurstClient"],
            "key_mixins": [],
            "module_names": ["KillAura","Fly","Scaffold","Nuker"],
            "selfdestruct_url": "",
        },
        "Meteor": {
            "real_packages": ["meteordevelopment/meteorclient/","meteordevelopment/orbit/"],
            "spoof_mod_ids": [],
            "spoof_jar_names": ["meteor-client"],
            "config_dirs": ["meteor-client",".meteor"],
            "config_files": ["meteor-client.json"],
            "config_path_sig": "meteor-client",
            "log_clean_terms": ["meteor"],
            "ua_strings": [],
            "key_classes": ["MeteorClient"],
            "key_mixins": [],
            "module_names": ["KillAura","AutoCrystal","ElytraFly"],
            "selfdestruct_url": "",
        },
        "RusherHack": {
            "real_packages": ["net/rusherhack/","me/rusherhack/"],
            "spoof_mod_ids": [],
            "spoof_jar_names": ["rusherhack"],
            "config_dirs": ["rusherhack",".rusherhack"],
            "config_files": ["rusherhack.json"],
            "config_path_sig": "rusherhack",
            "log_clean_terms": ["rusherhack"],
            "ua_strings": [],
            "key_classes": ["RusherHack"],
            "key_mixins": [],
            "module_names": [],
            "selfdestruct_url": "",
        },
        "LiquidBounce": {
            "real_packages": ["net/ccbluex/liquidbounce/"],
            "spoof_mod_ids": [],
            "spoof_jar_names": ["liquidbounce"],
            "config_dirs": ["liquidbounce",".liquidbounce"],
            "config_files": ["liquidbounce.json"],
            "config_path_sig": "liquidbounce",
            "log_clean_terms": ["ccbluex","liquidbounce"],
            "ua_strings": [],
            "key_classes": ["LiquidBounce"],
            "key_mixins": [],
            "module_names": ["KillAura","AutoCrystal","Scaffold","BHop"],
            "selfdestruct_url": "",
        },
        "ThunderHack": {
            "real_packages": ["me/thunderhack/","thunderhack/client/"],
            "spoof_mod_ids": ["sodium","fabric-api"],
            "spoof_jar_names": ["thunderhack"],
            "config_dirs": ["thunderhack",".thunderhack"],
            "config_files": ["thunderhack.json"],
            "config_path_sig": "thunderhack",
            "log_clean_terms": ["thunderhack"],
            "ua_strings": [],
            "key_classes": ["ThunderHack","ThunderHackClient"],
            "key_mixins": [],
            "module_names": ["AutoCrystal","AutoMace","KillAura"],
            "selfdestruct_url": "",
        },
        "Sigma": {
            "real_packages": ["me/sigma/","net/sigma/","sigma/client/"],
            "spoof_mod_ids": [],
            "spoof_jar_names": ["sigma","sigma-v5"],
            "config_dirs": ["sigma",".sigma"],
            "config_files": ["sigma.json"],
            "config_path_sig": "sigma",
            "log_clean_terms": ["sigma"],
            "ua_strings": [],
            "key_classes": ["SigmaClient","SigmaV5"],
            "key_mixins": [],
            "module_names": [],
            "selfdestruct_url": "",
        },
        "Doomsday": {
            "real_packages": ["net/java/"],
            "spoof_mod_ids": ["dd","fullbright","fullbright-mod"],
            "spoof_jar_names": ["vmp2","doomsday","dd-client"],
            "config_dirs": [],
            "config_files": [],
            "config_path_sig": "",
            "log_clean_terms": ["doomsday"],
            "ua_strings": [],
            "key_classes": ["mod_d","BaseMod","net.java.h","net.java.m"],
            "key_mixins": [],
            "module_names": ["FullBright"],
            "selfdestruct_url": "dl.lennartloesche.de",
            "doomsday_markers": ["64FV7P4H2NO7Q","addon3.json","addon4.json","mod_d.class","net/java/h","invokePointer","defineClass","findLoadedClass","premain","loadConfig","fillSettings","getKey","configurationClass"],
        },
    },
    "scanner": {
        "scan_class_limit_standard": 150,
        "scan_class_limit_paranoid": 999999,
        "confidence_cheat_threshold": 8,
        "confidence_suspicious_threshold": 3,
        "min_cheat_strings_for_flag": 4,
        "known_legit_mod_ids": [
            "sodium","lithium","iris","fabric-api","modmenu","cloth-config",
            "krypton","c2me","feather","carpet","chunky","ias","placeholder-api",
            "sodium-extra","reeses-sodium-options","resourcify","packetfixer",
            "starlight","g1axfixer","fnp-patcher","language-reload","fabricloader",
            "mixin","immediatelyfast","entity-culling","ferritecore","memoryleakfix",
            "notenoughcrashes","carpet-extra","lazydfu","smoothboot","smoothswapping",
            "journeymap","jei","rei","jade","waystones","create","botania",
            "itemscroller","nametag","optifine",
        ],
    },
}

SKELETON_DATA = {
    "cheat_strings": {"default_strings": [
        "KillAura", "AutoCrystal", "Fakelag", "SelfDestruct",
        "YourClientNameHere",
    ]},
    "client_profiles": {
        "ExampleClient": {
            "real_packages": ["me/exampleclient/"],
            "spoof_mod_ids": ["sodium"],
            "spoof_jar_names": ["sodium-example"],
            "config_dirs": ["exampleclient"],
            "config_files": ["exampleclient.json"],
            "config_path_sig": "exampleclient",
            "log_clean_terms": ["exampleclient"],
            "ua_strings": [],
            "key_classes": ["ExampleClientMain"],
            "key_mixins": [],
            "module_names": ["KillAura", "Fly"],
            "selfdestruct_url": "",
        }
    },
    "scanner": {
        "scan_class_limit_standard": 150,
        "scan_class_limit_paranoid": 999999,
        "confidence_cheat_threshold": 8,
        "confidence_suspicious_threshold": 3,
        "min_cheat_strings_for_flag": 4,
        "known_legit_mod_ids": ["sodium", "lithium", "fabric-api"],
    },
}

PRESET_SKELETON_README = """VELOCITY — Preset Folder

This folder is a self-contained detection definition. Anyone can build
their own AC configuration by editing the files below and pointing
Velocity at this folder with:

    /preset load

or, if it's already inside the presets/ folder next to ac.py:

    /preset select <name>

Files in this preset:

  cheat_strings.json    - flat list of strings that indicate cheat code
  client_profiles.json  - one entry per known cheat client
  scanner.json           - scan tuning (thresholds, limits)
  settings.json          - which phases run and how deep

--------------------------------------------------------------------
cheat_strings.json format:
--------------------------------------------------------------------
{
  "default_strings": [
    "KillAura",
    "AutoCrystal",
    "YourCustomCheatStringHere"
  ]
}

--------------------------------------------------------------------
client_profiles.json format (one entry per cheat client):
--------------------------------------------------------------------
{
  "ExampleClient": {
    "real_packages":   ["me/exampleclient/"],
    "spoof_mod_ids":   ["sodium"],
    "spoof_jar_names": ["sodium-example"],
    "config_dirs":     ["exampleclient"],
    "config_files":    ["exampleclient.json"],
    "config_path_sig": "exampleclient",
    "log_clean_terms": ["exampleclient"],
    "ua_strings":      [],
    "key_classes":     ["ExampleClientMain"],
    "key_mixins":      [],
    "module_names":    ["KillAura", "Fly"],
    "selfdestruct_url": ""
  }
}

real_packages     - the ACTUAL class package the client's code lives
                     under, e.g. if a jar has classes under
                     me/exampleclient/Main.class this is "me/exampleclient/"
spoof_mod_ids     - fabric.mod.json "id" values this client fakes being
config_dirs       - folder names it drops under .minecraft/config/
config_files      - filenames of its saved settings
log_clean_terms   - words it strips from logs/latest.log to hide itself
key_classes       - exact class names worth string-matching in bytecode
module_names      - cheat module/feature names (KillAura, Fly, etc.)
selfdestruct_url  - CDN/host it downloads a replacement jar from, if any

--------------------------------------------------------------------
scanner.json format (scan tuning):
--------------------------------------------------------------------
{
  "scan_class_limit_standard": 150,
  "scan_class_limit_paranoid": 999999,
  "confidence_cheat_threshold": 8,
  "confidence_suspicious_threshold": 3,
  "min_cheat_strings_for_flag": 4,
  "known_legit_mod_ids": ["sodium", "lithium", "fabric-api"]
}

--------------------------------------------------------------------
settings.json format:
--------------------------------------------------------------------
{
  "description": "your preset description here",
  "run_log_scan":      true,
  "run_config_scan":   true,
  "run_scanner_scan":  true,
  "run_dns_scan":      true,
  "run_process_scan":  true,
  "run_registry_scan": false,
  "run_prefetch_scan": false,
  "paranoid_mode":     false,
  "max_config_depth":  4
}
"""

PRESET_DEFAULTS = {
    "default": {
        "description": "Balanced default settings",
        "run_log_scan": True, "run_config_scan": True, "run_scanner_scan": True,
        "run_dns_scan": True, "run_process_scan": True,
        "run_registry_scan": False, "run_prefetch_scan": False,
        "paranoid_mode": False, "max_config_depth": 4,
    },
    "defaultflash": {
        "description": "Speed-optimized — fewer classes scanned, shallow depth",
        "run_log_scan": True, "run_config_scan": True, "run_scanner_scan": True,
        "run_dns_scan": False, "run_process_scan": False,
        "run_registry_scan": False, "run_prefetch_scan": False,
        "paranoid_mode": False, "max_config_depth": 2,
    },
    "defaultpro": {
        "description": "Thoroughness-optimized — paranoid mode, all classes, all drives",
        "run_log_scan": True, "run_config_scan": True, "run_scanner_scan": True,
        "run_dns_scan": True, "run_process_scan": True,
        "run_registry_scan": True, "run_prefetch_scan": True,
        "paranoid_mode": True, "max_config_depth": 6,
    },
    "defaultmax": {
        "description": "Everything maxed — deepest scan, all phases, lowest thresholds",
        "run_log_scan": True, "run_config_scan": True, "run_scanner_scan": True,
        "run_dns_scan": True, "run_process_scan": True,
        "run_registry_scan": True, "run_prefetch_scan": True,
        "paranoid_mode": True, "max_config_depth": 10,
    },
}

DATA_SCHEMA_VERSION = 3

def ensure_data_files():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULTS_DIR.mkdir(parents=True, exist_ok=True)

    version_path = DATA_DIR / "_version.json"
    on_disk_version = 0
    if version_path.exists():
        try: on_disk_version = json.loads(version_path.read_text()).get("version", 0)
        except Exception: on_disk_version = 0
    needs_migration = on_disk_version < DATA_SCHEMA_VERSION

    for key, fname in DATA_FILES.items():
        dpath = DATA_DIR / fname
        default_path = DEFAULTS_DIR / fname
        if needs_migration or not default_path.exists():
            default_path.write_text(json.dumps(DEFAULT_DATA[key], indent=2))
        if needs_migration or not dpath.exists():
            dpath.write_text(json.dumps(DEFAULT_DATA[key], indent=2))

    if needs_migration:
        version_path.write_text(json.dumps({"version": DATA_SCHEMA_VERSION}))

    for pname, settings in PRESET_DEFAULTS.items():
        pdir = PRESETS_DIR / pname
        pdir.mkdir(parents=True, exist_ok=True)
        settings_path = pdir / "settings.json"
        if not settings_path.exists():
            settings_path.write_text(json.dumps(settings, indent=2))
        readme_path = pdir / "README.txt"
        if not readme_path.exists():
            readme_path.write_text(PRESET_SKELETON_README)
        for key, fname in DATA_FILES.items():
            fpath = pdir / fname
            if needs_migration or not fpath.exists():
                fpath.write_text(json.dumps(DEFAULT_DATA[key], indent=2))

    fp_path = DATA_DIR / "structure_fingerprints.json"
    if not fp_path.exists():
        seed = {}
        for client, profile in DEFAULT_DATA["client_profiles"].items():
            names = set(profile.get("key_classes", [])) | set(profile.get("module_names", []))
            if names: seed[client] = sorted(names)
        fp_path.write_text(json.dumps(seed, indent=2))

_loaded_data = {}

def load_data():
    global _loaded_data
    ensure_data_files()
    out = {}
    for key, fname in DATA_FILES.items():
        dpath = DATA_DIR / fname
        try:
            out[key] = json.loads(dpath.read_text())
        except Exception as e:
            tlog(f"Failed to load {fname}: {e} — using built-in defaults", "warn")
            out[key] = DEFAULT_DATA[key]
    _loaded_data = out
    return out

def DEFAULT_CHEAT_STRINGS():
    return set(_loaded_data.get("cheat_strings", {}).get("default_strings", []))

def CLIENT_PROFILES():
    return _loaded_data.get("client_profiles", {})

def SCANNER_CONFIG():
    return _loaded_data.get("scanner", DEFAULT_DATA["scanner"])

def KNOWN_LEGIT_MOD_IDS():
    return set(SCANNER_CONFIG().get("known_legit_mod_ids", []))

def get_all_module_names():
    names = set()
    for profile in CLIENT_PROFILES().values():
        names |= set(profile.get("module_names", []))
    return names

def get_log_clean_terms_map():
    out = {}
    for client_name, profile in CLIENT_PROFILES().items():
        terms = profile.get("log_clean_terms", [])
        if terms:
            out[client_name] = terms
    return out

def get_config_dirs_map():
    out = {}
    for client_name, profile in CLIENT_PROFILES().items():
        dirs = profile.get("config_dirs", [])
        if dirs:
            out[client_name] = dirs
    return out

def get_config_files_map():
    out = {}
    for client_name, profile in CLIENT_PROFILES().items():
        files = profile.get("config_files", [])
        if files:
            out[client_name] = files
    return out

def load_active_preset(name):
    pdir = PRESETS_DIR / name
    if not pdir.is_dir():
        return None
    try:
        settings = json.loads((pdir / "settings.json").read_text())
    except Exception:
        settings = PRESET_DEFAULTS.get(name, PRESET_DEFAULTS["default"])
    return settings

def extract_utf8_constants(class_bytes):
    strings = set()
    try:
        if len(class_bytes) < 10 or class_bytes[:4] != b'\xca\xfe\xba\xbe':
            return strings
        idx = 8
        pool_count = struct.unpack(">H", class_bytes[idx:idx+2])[0]
        idx += 2
        i = 1
        while i < pool_count:
            if idx >= len(class_bytes): break
            tag = class_bytes[idx]; idx += 1
            if tag == 1:
                if idx + 2 > len(class_bytes): break
                length = struct.unpack(">H", class_bytes[idx:idx+2])[0]
                idx += 2
                raw = class_bytes[idx:idx+length]; idx += length
                try:
                    s = raw.decode("utf-8", errors="ignore")
                    if len(s) >= 4: strings.add(s)
                except Exception: pass
                i += 1
            elif tag in (7,8,16,19,20): idx += 2; i += 1
            elif tag in (9,10,11,12,17,18): idx += 4; i += 1
            elif tag in (3,4): idx += 4; i += 1
            elif tag in (5,6): idx += 8; i += 2
            elif tag == 15: idx += 3; i += 1
            else: break
    except Exception: pass
    return strings

def extract_printable_fallback(raw, min_len=6):
    strings = set()
    i = 0; n = len(raw)
    while i < n - min_len:
        j = i
        while j < n and 32 <= raw[j] < 127: j += 1
        if j - i >= min_len:
            try: strings.add(raw[i:j].decode("ascii"))
            except Exception: pass
        i = max(j + 1, i + 1)
    return strings

def get_class_strings(raw_bytes):
    s = extract_utf8_constants(raw_bytes)
    if len(s) < 3: s |= extract_printable_fallback(raw_bytes)
    return s

def is_cheat_config_json(data, module_list=None):
    if not isinstance(data, dict): return False, 0
    module_list = module_list if module_list is not None else get_all_module_names()
    cheat_structure_count = 0
    cheat_modules_found = 0
    for key, val in data.items():
        if isinstance(val, dict):
            keys_lower = {k.lower() for k in val.keys()}
            if "enabled" in keys_lower and ("keycode" in keys_lower or "keybind" in keys_lower):
                cheat_structure_count += 1
            if key in module_list:
                cheat_modules_found += 1
    return (cheat_structure_count >= 2 or cheat_modules_found >= 3), max(cheat_structure_count, cheat_modules_found)

def _hash_store_path(name):
    return DATA_DIR / name

def load_hash_store(name):
    fp = _hash_store_path(name)
    if not fp.exists(): return {}
    try: return json.loads(fp.read_text())
    except Exception: return {}

def save_hash_store(name, data):
    try: _hash_store_path(name).write_text(json.dumps(data, indent=2))
    except Exception: pass

def record_bad_hash(sha, client, jar_path):
    store = load_hash_store("known_bad_hashes.json")
    if sha not in store:
        store[sha] = {"client": client, "first_seen": os.path.basename(jar_path)}
        save_hash_store("known_bad_hashes.json", store)

def is_whitelisted_hash(sha):
    return sha in load_hash_store("whitelist.json")

def add_to_whitelist(sha, path):
    store = load_hash_store("whitelist.json")
    store[sha] = {"path": path}
    save_hash_store("whitelist.json", store)

def class_basenames_of(class_paths):
    return {cp.rsplit("/",1)[-1][:-6] for cp in class_paths if cp.endswith(".class")}

def structure_similarity(a, b):
    if not a or not b: return 0.0
    inter = len(a & b)
    return inter / len(a | b) if (a | b) else 0.0

def match_structure(basenames, threshold=0.35):
    if len(basenames) < 3: return None, 0.0
    store = load_hash_store("structure_fingerprints.json")
    best_client, best_score = None, 0.0
    for client, known in store.items():
        score = structure_similarity(basenames, set(known))
        if score > best_score:
            best_client, best_score = client, score
    return (best_client, best_score) if best_score >= threshold else (None, 0.0)

def learn_structure(client, basenames):
    if not basenames: return
    store = load_hash_store("structure_fingerprints.json")
    known = set(store.get(client, [])) | basenames
    if len(known) > 300: known = set(list(known)[-300:])
    store[client] = sorted(known)
    save_hash_store("structure_fingerprints.json", store)

class ScanResult:
    def __init__(self, jar_path):
        self.jar_path = jar_path
        self.filename = os.path.basename(jar_path)
        self.sha256_val = sha256(jar_path)
        self.sha1_val   = sha1(jar_path)
        self.modrinth_id   = None   # what Modrinth says this jar IS
        self.modrinth_name = None
        self.modrinth_slug = None
        self.modrinth_spoof = False  # claims different mod ID inside fabric.mod.json
        self.mod_id = None
        self.mod_name = None
        self.mod_version = None
        self.mod_authors = None
        self.is_fabric = False
        self.file_count = 0
        self.class_count = 0
        self.pkg_tree = {}
        self.mixin_pkgs = []
        self.verdict = "CLEAN"
        self.detected_client = None
        self.cheat_strings = []
        self.client_packages = []
        self.infected_classes = []
        self.confidence = 0
        self.skip_reason = None
        self.spoof_evidence = []
        self.selfdestruct_ev = []
        self.notes = []
        self.class_basenames = set()
        self.structure_match = None

    def probability(self):
        if self.verdict == "CLEAN": return 0
        base = 45 + min(self.confidence * 7, 50)
        if len(self.cheat_strings) >= 5: base = min(base + 10, 99)
        if self.client_packages: base = min(base + 15, 99)
        if self.spoof_evidence: base = min(base + 10, 99)
        return base


_MODRINTH_CACHE = {}

def query_modrinth(sha1_hash):
    """Returns (project_id, slug, name) or (None,None,None). Cached per session."""
    if not sha1_hash: return None, None, None
    if sha1_hash in _MODRINTH_CACHE: return _MODRINTH_CACHE[sha1_hash]
    try:
        import urllib.request
        url = f"https://api.modrinth.com/v2/version_file/{sha1_hash}?algorithm=sha1"
        req = urllib.request.Request(url, headers={"User-Agent": "Velocity-Scanner/3.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        project_id = data.get("project_id", "")
        if not project_id:
            _MODRINTH_CACHE[sha1_hash] = (None, None, None)
            return None, None, None
        # fetch project details for slug + name
        req2 = urllib.request.Request(
            f"https://api.modrinth.com/v2/project/{project_id}",
            headers={"User-Agent": "Velocity-Scanner/3.0"})
        with urllib.request.urlopen(req2, timeout=6) as resp2:
            proj = json.loads(resp2.read())
        slug = proj.get("slug","")
        name = proj.get("title","")
        _MODRINTH_CACHE[sha1_hash] = (project_id, slug, name)
        return project_id, slug, name
    except Exception:
        _MODRINTH_CACHE[sha1_hash] = (None, None, None)
        return None, None, None

# Slugs that are legitimate mods — even if hash not on Modrinth we trust the bytecode scan
_MODRINTH_LEGIT_SKIP_SLUGS = set()  # populated from known_legit_mod_ids mapping

def analyze_jar(path, custom_strings=None, paranoid=False):
    r = ScanResult(path)

    if r.sha256_val and is_whitelisted_hash(r.sha256_val):
        r.verdict = "CLEAN"
        r.skip_reason = "Whitelisted by hash"
        return r

    if r.sha256_val:
        bad_store = load_hash_store("known_bad_hashes.json")
        if r.sha256_val in bad_store:
            entry = bad_store[r.sha256_val]
            r.verdict = "CHEAT"
            r.detected_client = entry.get("client", "Unknown")
            r.confidence = 10
            r.notes.append(f"hash matches previously confirmed {r.detected_client} (was named {entry.get('first_seen','?')})")
            return r


    # ── Modrinth hash verification ────────────────────────────────────────────
    # Hash the jar with SHA1, ask Modrinth what it actually is, then compare
    # against what the jar *claims* to be in fabric.mod.json.
    # Three outcomes:
    #   A) Modrinth knows this hash AND internal mod_id matches → legit, skip deep scan
    #   B) Modrinth knows this hash BUT internal mod_id differs → spoofing a legit mod → FLAG
    #   C) Modrinth doesn't know this hash → unknown, continue to bytecode scan
    _mr_pid, _mr_slug, _mr_name = query_modrinth(r.sha1_val)
    r.modrinth_id   = _mr_pid
    r.modrinth_slug = _mr_slug
    r.modrinth_name = _mr_name

    active_strings = DEFAULT_CHEAT_STRINGS()
    if custom_strings:
        active_strings = active_strings | set(custom_strings)
    profiles = CLIENT_PROFILES()
    legit_ids = KNOWN_LEGIT_MOD_IDS()
    hcfg = SCANNER_CONFIG()
    module_names = get_all_module_names()

    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()
            r.file_count = len(names)
            class_paths = [n for n in names if n.endswith(".class")]
            r.class_count = len(class_paths)
            r.class_basenames = class_basenames_of(class_paths)

            struct_client, struct_score = match_structure(r.class_basenames)
            if struct_client:
                r.structure_match = (struct_client, struct_score)
                r.notes.append(f"structure match: {int(struct_score*100)}% overlap with known {struct_client}")
                r.confidence = max(r.confidence, 9 if struct_score >= 0.6 else 6)

            pkg_tree = defaultdict(int)
            for cp in class_paths:
                parts = cp.split("/")
                if len(parts) >= 4: pkg_tree["/".join(parts[:3]) + "/"] += 1
                elif len(parts) >= 3: pkg_tree["/".join(parts[:2]) + "/"] += 1
                elif len(parts) >= 2: pkg_tree[parts[0] + "/"] += 1
            r.pkg_tree = dict(pkg_tree)

            if "fabric.mod.json" in names:
                r.is_fabric = True
                try:
                    meta = json.loads(z.read("fabric.mod.json").decode("utf-8", errors="ignore"))
                    r.mod_id = str(meta.get("id", "")).lower()
                    r.mod_name = meta.get("name", "")
                    r.mod_version = meta.get("version", "")
                    authors = meta.get("authors", [])
                    r.mod_authors = ", ".join(
                        a if isinstance(a, str) else a.get("name", "") for a in authors
                    ) if isinstance(authors, list) else str(authors)
                except Exception: pass

            # ── Modrinth cross-reference ──────────────────────────────────────
            if r.modrinth_id:
                # Modrinth knows this exact binary
                if r.mod_id and r.mod_id != r.modrinth_slug:
                    # Jar claims to be e.g. "sodium" but Modrinth says it's "cyemer"
                    r.modrinth_spoof = True
                    r.spoof_evidence.append(
                        f"Modrinth hash → '{r.modrinth_slug}' ({r.modrinth_name}) "
                        f"but fabric.mod.json claims '{r.mod_id}'"
                    )
                    r.confidence = max(r.confidence, 10)
                    tlog(f"MODRINTH SPOOF  [{r.filename}]  "
                         f"hash={r.modrinth_slug!r}  claimed={r.mod_id!r}", "bad")
                elif not paranoid:
                    # Hash matches and mod_id matches → genuinely legit
                    r.skip_reason = f"Modrinth verified: {r.modrinth_name or r.modrinth_slug}"
                    return r
            # ─────────────────────────────────────────────────────────────────


            client_scores = defaultdict(float)

            for client_name, profile in profiles.items():
                if r.mod_id and r.mod_id in profile.get("spoof_mod_ids", []):
                    for pkg in profile.get("real_packages", []):
                        if any(cp.startswith(pkg) for cp in class_paths):
                            r.spoof_evidence.append(f"claims '{r.mod_id}' but contains {pkg}")
                            client_scores[client_name] += 100
                            r.confidence = max(r.confidence, 10)
                            break

            if r.mod_id and r.mod_id in legit_ids and not r.spoof_evidence and not r.structure_match and not paranoid:
                r.skip_reason = f"Known legit: {r.mod_id}"
                return r

            for client_name, profile in profiles.items():
                for pkg in profile.get("real_packages", []):
                    matching = [cp for cp in class_paths if cp.startswith(pkg)]
                    if matching:
                        r.client_packages.append(f"{pkg} → {client_name} ({len(matching)} classes)")
                        client_scores[client_name] += 8 + min(len(matching), 20)
                        r.confidence = max(r.confidence, 9)

            GENERIC_PKG_SEGMENTS = {"me","com","net","org","io","client","impl","mod","internal","core","dev"}
            for mixin_file in [n for n in names if "mixin" in n.lower() and n.endswith(".json")]:
                try:
                    mx = json.loads(z.read(mixin_file).decode("utf-8", errors="ignore"))
                    pkg = mx.get("package", "")
                    if pkg: r.mixin_pkgs.append(pkg)
                    for client_name, profile in profiles.items():
                        for real_pkg in profile.get("real_packages", []):
                            segments = [s for s in real_pkg.strip("/").split("/") if s and s.lower() not in GENERIC_PKG_SEGMENTS]
                            if segments and any(seg.lower() in pkg.lower() for seg in segments):
                                r.client_packages.append(f"mixin:{pkg} → {client_name}")
                                client_scores[client_name] += 40
                                r.confidence = max(r.confidence, 8)
                except Exception: pass

            for cfg_file in [n for n in names if n.endswith((".json",".cfg",".txt")) and "config" in n.lower()]:
                try:
                    raw_cfg = z.read(cfg_file).decode("utf-8", errors="ignore")
                    try:
                        data = json.loads(raw_cfg)
                        for client_name, profile in profiles.items():
                            sig = profile.get("config_path_sig","")
                            if sig and sig in cfg_file:
                                r.notes.append(f"config path signature: {cfg_file} → {client_name}")
                                client_scores[client_name] += 10
                                r.confidence = max(r.confidence, 6)
                        is_cheat, score = is_cheat_config_json(data, module_names)
                        if is_cheat:
                            r.notes.append(f"cheat config structure (score {score}) in {cfg_file}")
                            r.confidence = max(r.confidence, 5 + score)
                    except Exception: pass
                    for sig in active_strings:
                        if sig in raw_cfg and sig not in r.cheat_strings:
                            r.cheat_strings.append(sig)
                except Exception: pass

            scan_limit = (len(class_paths) if paranoid
                         else min(len(class_paths), hcfg.get("scan_class_limit_standard", 150)))
            for cp in class_paths[:scan_limit]:
                try:
                    raw = z.read(cp)
                    strings = get_class_strings(raw)
                    hits = []
                    for s in strings:
                        for sig in active_strings:
                            if sig in s and len(s) < 150 and sig not in hits and sig not in r.cheat_strings:
                                hits.append(sig); r.cheat_strings.append(sig); break
                        for client_name, profile in profiles.items():
                            for kc in profile.get("key_classes", []):
                                if kc == s.strip():
                                    tag = f"class:{kc}"
                                    if tag not in r.cheat_strings: r.cheat_strings.append(tag)
                                    client_scores[client_name] += 15
                                    r.confidence = max(r.confidence, 8)
                            sd_url = profile.get("selfdestruct_url","")
                            if sd_url and sd_url in s:
                                r.selfdestruct_ev.append(s.strip()[:80])
                                client_scores[client_name] += 30
                                r.confidence = max(r.confidence, 10)
                            for ua in profile.get("ua_strings", []):
                                ua_prefix = ua.split("/")[0]
                                if ua_prefix in s:
                                    r.selfdestruct_ev.append(f"UA:{s.strip()[:60]}")
                                    client_scores[client_name] += 25
                                    r.confidence = max(r.confidence, 9)
                    if hits: r.infected_classes.append((cp, hits[:4]))
                except Exception: continue

            if r.structure_match:
                sm_client, sm_score = r.structure_match
                client_scores[sm_client] += 20 if sm_score >= 0.6 else 12

            if client_scores:
                r.detected_client = max(client_scores, key=client_scores.get)

            r.cheat_strings = list(dict.fromkeys(r.cheat_strings))[:50]

            dd_profile = profiles.get("Doomsday", {})
            dd_markers = dd_profile.get("doomsday_markers", [])
            if dd_markers:
                dd_hits = sum(1 for m in dd_markers if any(m in n for n in names))
                if dd_hits >= 3:
                    client_scores["Doomsday"] = client_scores.get("Doomsday", 0) + dd_hits * 15
                    r.detected_client = "Doomsday"
                    r.notes.append(f"Doomsday structural markers: {dd_hits} matched")
                    r.confidence = max(r.confidence, 9)

            if client_scores:
                r.detected_client = max(client_scores, key=client_scores.get)

    except zipfile.BadZipFile:
        r.verdict = "ERROR"; r.skip_reason = "Not a valid ZIP/JAR"; return r
    except Exception as e:
        r.verdict = "ERROR"; r.skip_reason = str(e)[:80]; return r

    cheat_thresh = hcfg.get("confidence_cheat_threshold", 8)
    min_strings  = hcfg.get("min_cheat_strings_for_flag", 4)

    if r.spoof_evidence and r.client_packages:
        r.verdict = "CHEAT"; r.confidence = max(r.confidence, 10)
    elif r.client_packages:
        r.verdict = "CHEAT"
    elif r.selfdestruct_ev:
        r.verdict = "CHEAT"; r.confidence = max(r.confidence, 9)
    elif len(r.cheat_strings) >= 5 and r.confidence >= 6:
        r.verdict = "CHEAT"
    elif r.cheat_strings and r.confidence >= cheat_thresh:
        r.verdict = "CHEAT"
    elif len(r.cheat_strings) >= min_strings or r.notes:
        r.verdict = "SUSPICIOUS"
    else:
        r.verdict = "CLEAN"

    return r

def format_scan_result(r):
    lines = []
    if r.skip_reason and r.verdict == "CLEAN":
        mr = f"  [{r.modrinth_name or r.modrinth_slug}]" if r.modrinth_slug else ""
        lines.append(c(GR)(f"  ├─ {r.filename:<48}") + c(GN)(f"  ✓ legit{mr}"))
        return lines
    if r.verdict == "CLEAN":
        lines.append(c(GR)(f"  ├─ {r.filename:<48}") + c(GN)("  ✓ clean"))
        return lines
    if r.verdict == "ERROR":
        lines.append(c(GR)(f"  ├─ {r.filename:<48}") + c(GR)(f"  — {r.skip_reason}"))
        return lines

    color = c(RD,BOLD) if r.verdict == "CHEAT" else c(YL)
    prob  = r.probability()
    lines.append("")
    lines.append(c(GR)("  ┌─ ") + color(r.filename))
    lines.append(c(GR)("  │  ") + c(WH)("Jar      ") + c(CY)(r.filename))
    if r.mod_id:   lines.append(c(GR)("  │  ") + c(WH)("Mod ID   ") + c(GR)(r.mod_id))
    if r.mod_name: lines.append(c(GR)("  │  ") + c(WH)("Name     ") + c(GR)(r.mod_name))
    # Modrinth hash result
    if r.modrinth_slug and not r.modrinth_spoof:
        lines.append(c(GR)("  │  ") + c(WH)("Modrinth ") + c(GN)(f"✓ {r.modrinth_name or r.modrinth_slug}"))
    elif r.modrinth_spoof:
        lines.append(c(GR)("  │  ") + c(WH)("Modrinth ") + c(RD,BOLD)(f"✗ HASH={r.modrinth_slug!r} but claims {r.mod_id!r}"))
    elif not r.modrinth_slug:
        lines.append(c(GR)("  │  ") + c(WH)("Modrinth ") + c(YL)("not found — unverified"))
    if r.detected_client: lines.append(c(GR)("  │  ") + c(WH)("Client   ") + color(r.detected_client))
    for ev in r.spoof_evidence:
        lines.append(c(GR)("  │  ") + c(WH)("Spoof    ") + c(RD,BOLD)(ev))
    for pkg in r.client_packages[:3]:
        lines.append(c(GR)("  │  ") + c(WH)("Package  ") + color(pkg))
    if r.mixin_pkgs:
        lines.append(c(GR)("  │  ") + c(WH)("Mixins   ") + c(CY)(", ".join(r.mixin_pkgs[:3])))
    if r.selfdestruct_ev:
        lines.append(c(GR)("  │  ") + c(WH)("SelfDest ") + c(RD,BOLD)(r.selfdestruct_ev[0][:55]))
    if r.cheat_strings:
        cs = ", ".join(r.cheat_strings[:8])
        if len(r.cheat_strings) > 8: cs += f" (+{len(r.cheat_strings)-8})"
        lines.append(c(GR)("  │  ") + c(WH)("Cheats   ") + color(cs))
    if r.infected_classes:
        lines.append(c(GR)("  │  ") + c(WH)("Classes  ") + c(GR)(f"{len(r.infected_classes)} infected"))
        for cls_path, hits in r.infected_classes[:3]:
            short = cls_path.split("/")[-1].replace(".class","")
            lines.append(c(GR)("  │    · ") + c(GR)(f"{short:<32}") + c(YL)(", ".join(hits[:3])))
    for note in r.notes[:2]:
        lines.append(c(GR)("  │  ") + c(WH)("Note     ") + c(YL)(note[:60]))
    lines.append(c(GR)("  └─ ") + c(WH)("Verdict  ") + color(r.verdict) + c(GR)("  ·  ") + c(WH)(f"{prob}% confidence"))
    lines.append("")
    return lines

CHEAT_CONFIG_SCAN_EXTS = {".json",".cfg",".txt",".properties",".toml",".yaml",".yml"}

MULTI_PROFILE_LAUNCHERS = {"FastClient", "PrismLauncher", "MultiMC", "PolyMC", "ATLauncher"}

def get_scan_roots():
    if ghost_state["active"] and ghost_state["paths"]:
        roots = list(ghost_state["paths"])
    else:
        roots = []
        for name, paths in KNOWN_LAUNCHERS.items():
            for p2 in paths:
                if not os.path.isdir(p2): continue
                if name in MULTI_PROFILE_LAUNCHERS:
                    try:
                        for sub in os.listdir(p2):
                            subpath = os.path.join(p2, sub)
                            if os.path.isdir(subpath):
                                roots.append(subpath)
                    except Exception: pass
                else:
                    roots.append(p2)
                break
    if ghost_state["focus_paths"]:
        roots = list(ghost_state["focus_paths"]) + roots
    return list(dict.fromkeys(roots))

def phase0_log_scan(game_root, max_depth=4):
    section("PHASE 0 — Log & Modloader Scan")
    divider()
    clean = True
    log_terms_map = get_log_clean_terms_map()
    logs_dir = os.path.join(game_root, "logs")
    if os.path.isdir(logs_dir):
        tlog(f"Scanning logs: {logs_dir}", "scan")
        for log_file in ["latest.log", "debug.log"]:
            log_path = os.path.join(logs_dir, log_file)
            if not os.path.isfile(log_path): continue
            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                content_lower = content.lower()
                for client_name, terms in log_terms_map.items():
                    for term in terms:
                        if term.lower() in content_lower:
                            tlog(f"LOG HIT  [{client_name}]  '{term}' in {log_file}", "bad")
                            all_findings["log_hits"].append({"file":log_file,"path":log_path,"term":term,"client":client_name})
                            all_findings["summary"]["log_tampering"] += 1
                            scan_counters["red"] += 1
                            clean = False
                mtime = os.path.getmtime(log_path)
                if time.time() - mtime < 600:
                    tlog(f"Log recently modified — may have been cleaned", "warn")
            except Exception as e:
                tlog(f"Log read error: {e}", "warn")
        crash_dir = os.path.join(game_root, "crash-reports")
        if os.path.isdir(crash_dir):
            for fname in os.listdir(crash_dir)[-10:]:
                fpath = os.path.join(crash_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        crash_content = f.read().lower()
                    for client_name, terms in log_terms_map.items():
                        for term in terms:
                            if term.lower() in crash_content:
                                tlog(f"CRASH REPORT HIT  [{client_name}]  {fname}", "bad")
                                all_findings["log_hits"].append({"file":fname,"path":fpath,"term":term,"client":client_name,"type":"crash"})
                                all_findings["summary"]["log_tampering"] += 1
                                scan_counters["red"] += 1
                                clean = False
                except Exception: pass
    else:
        tlog("No logs directory found", "info")
    if clean:
        tlog("Logs: clean ✓", "ok")
        scan_counters["green"] += 1

def phase1_config_scan(game_root, max_depth=4):
    section("PHASE 1 — Config Directory Scan")
    divider()
    clean = True
    config_root = os.path.join(game_root, "config")
    if not os.path.isdir(config_root):
        tlog("No config directory found", "info")
        return

    tlog(f"Scanning: {config_root}", "scan")
    config_dirs_map  = get_config_dirs_map()
    config_files_map = get_config_files_map()
    module_names     = get_all_module_names()

    for client_name, dirs in config_dirs_map.items():
        for d in dirs:
            full_dir = os.path.join(config_root, d)
            if os.path.isdir(full_dir):
                contents = os.listdir(full_dir)
                tlog(f"CONFIG DIR  [{client_name.upper()}]  {full_dir}  ({len(contents)} files)", "bad")
                all_findings["config_hits"].append({"client":client_name,"type":"directory","path":full_dir,"contents":contents[:10]})
                all_findings["summary"]["private_hits"] += 1
                scan_counters["red"] += 1
                clean = False

    for root, dirs, files in os.walk(config_root):
        depth = len(os.path.relpath(root, config_root).split(os.sep))
        if depth > max_depth: dirs[:] = []; continue

        rel_root = os.path.relpath(root, config_root).replace(os.sep, "/")
        path_clients = set()
        for client_name, cdirs in config_dirs_map.items():
            for d in cdirs:
                d_norm = d.replace("\\", "/").rstrip("/")
                if rel_root == d_norm or rel_root.startswith(d_norm + "/"):
                    path_clients.add(client_name)

        for fname in files:
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            scan_counters["total"] += 1

            if len(path_clients) == 1:
                client_name = next(iter(path_clients))
                tlog(f"CONFIG FILE  [{client_name.upper()}]  {fpath}", "bad")
                all_findings["config_hits"].append({"client":client_name,"type":"file","path":fpath})
                all_findings["summary"]["private_hits"] += 1
                scan_counters["red"] += 1
                clean = False
            elif not path_clients:
                for client_name, cfg_files in config_files_map.items():
                    if fname.lower() in [x.lower() for x in cfg_files]:
                        tlog(f"CONFIG FILE  [{client_name.upper()}]  {fpath}", "bad")
                        all_findings["config_hits"].append({"client":client_name,"type":"file","path":fpath})
                        all_findings["summary"]["private_hits"] += 1
                        scan_counters["red"] += 1
                        clean = False

            if ext not in CHEAT_CONFIG_SCAN_EXTS: continue
            try:
                raw = open(fpath,"r",encoding="utf-8",errors="ignore").read()
            except Exception: continue
            module_hits = [m for m in module_names if m in raw]
            if ext == ".json" and len(module_hits) >= 2:
                try:
                    data = json.loads(raw)
                    is_cheat, score = is_cheat_config_json(data, module_names)
                    if is_cheat:
                        tlog(f"CHEAT CONFIG STRUCTURE  {fpath}  (score {score})", "bad")
                        all_findings["config_hits"].append({"type":"cheat_config","path":fpath,"modules":module_hits[:8],"count":score})
                        all_findings["summary"]["private_hits"] += 1
                        scan_counters["red"] += 1
                        clean = False
                    elif module_hits:
                        tlog(f"CONFIG SUSPICIOUS  {fname}  {module_hits[:3]}", "warn")
                        scan_counters["yellow"] += 1
                        clean = False
                except Exception:
                    if len(module_hits) >= 3:
                        tlog(f"CONFIG HIT  {fname}  {module_hits[:3]}", "warn")
                        scan_counters["yellow"] += 1
                        clean = False

    if clean:
        tlog("Config: clean ✓", "ok")
        scan_counters["green"] += 1

def phase2_scanner(mods_dir, paranoid=False):
    section("PHASE 2 — Velocity Mod Scanner")
    divider()
    if not os.path.isdir(mods_dir):
        tlog(f"Mods directory not found: {mods_dir}", "info")
        return
    jars = [f for f in os.listdir(mods_dir) if f.lower().endswith(".jar")]
    if not jars:
        tlog("No JARs in mods directory", "info")
        return
    tlog(f"Scanning {len(jars)} JARs {'(paranoid)' if paranoid else ''}", "scan")
    set_scanner_status("running")
    custom = ghost_state["strings"] if ghost_state["active"] else None
    start = time.time()
    for i, fname in enumerate(jars):
        draw_progress(f"Scanning [{i}/{len(jars)}]", i, len(jars), eta_str(time.time()-start, i+1, len(jars)))
        jar_path = os.path.join(mods_dir, fname)
        scan_counters["jars"] += 1
        scan_counters["total"] += 1
        try:
            r = analyze_jar(jar_path, custom_strings=custom, paranoid=paranoid)
            if r.verdict == "CHEAT":
                scan_counters["red"] += 1
                prob = r.probability()
                name = r.detected_client or "Unknown"
                if r.sha256_val: record_bad_hash(r.sha256_val, name, jar_path)
                learn_structure(name, r.class_basenames)
                tlog(f"VELOCITY  CHEAT FOUND  {c(RD,BOLD)(name)}  ·  {r.filename}  ·  {c(YL)(str(prob)+'%')}", "bad")
                all_findings["scanner"].append({
                    "path":jar_path,"verdict":"CHEAT","client":name,"confidence":prob,
                    "strings":r.cheat_strings[:10],"packages":r.client_packages[:3],
                    "spoof":r.spoof_evidence,"selfdestruct":r.selfdestruct_ev,
                })
                all_findings["summary"]["private_hits"] += 1
                for line in format_scan_result(r): p(line)
            elif r.verdict == "SUSPICIOUS":
                scan_counters["yellow"] += 1
                tlog(f"SCANNING  SUSPICIOUS  {r.filename}", "warn")
                all_findings["scanner"].append({"path":jar_path,"verdict":"SUSPICIOUS","strings":r.cheat_strings[:5]})
            else:
                scan_counters["green"] += 1
        except Exception as e:
            tlog(f"Scan error on {fname}: {e}", "warn")
            set_scanner_status("warn")
    sys.stdout.write("\r\033[K")
    elapsed = time.time() - start
    cheats = scan_counters["red"]
    if cheats > 0:
        set_scanner_status("warn")
        tlog(f"Scan done · {len(jars)} JARs · {c(RD,BOLD)(str(cheats)+' CHEAT(S)')} · {elapsed:.1f}s", "bad")
    else:
        set_scanner_status("idle")
        tlog(f"Scan done · {len(jars)} JARs · clean · {elapsed:.1f}s", "ok")

def do_dns_scan():
    tlog("DNS cache scan...", "scan")
    try:
        result = subprocess.run(["ipconfig","/displaydns"], capture_output=True, text=True, timeout=15)
        raw = result.stdout
    except Exception as e:
        tlog(f"DNS failed: {e}", "warn"); return
    entries = []
    for line in raw.splitlines():
        if "Record Name" in line:
            parts = line.split(":",1)
            if len(parts)==2: entries.append(parts[1].strip().lower().rstrip("."))
    for entry in entries:
        for bad in CHEAT_DOMAINS:
            if bad in entry:
                tlog(f"CHEAT DOMAIN  {entry}", "bad")
                all_findings["dns_flags"].append({"entry":entry,"matched":bad})
                all_findings["summary"]["dns_hits"] += 1
                scan_counters["red"] += 1

def do_process_scan():
    if not PSUTIL_OK:
        tlog("psutil missing — skipping process scan", "warn"); return
    tlog("Process scan...", "scan")
    for proc in psutil.process_iter(["pid","name","exe"]):
        try:
            pn = (proc.info["name"] or "").lower().replace(".exe","")
            for cl in CLICKER_NAMES:
                if cl in pn:
                    tlog(f"CLICKER  {proc.info['name']} [PID {proc.info['pid']}]", "bad")
                    all_findings["process_flags"].append({"pid":proc.info["pid"],"name":proc.info["name"],"type":"clicker"})
                    scan_counters["red"] += 1; break
            for bp in BYPASS_NAMES:
                if bp in pn:
                    tlog(f"BYPASS TOOL  {proc.info['name']} [PID {proc.info['pid']}]", "bad")
                    all_findings["process_flags"].append({"pid":proc.info["pid"],"name":proc.info["name"],"type":"bypass"})
                    scan_counters["red"] += 1; break
        except Exception: continue
    MC_PROCS = {"javaw.exe","java.exe","minecraft.exe","prismlauncher.exe"}
    for proc in psutil.process_iter(["pid","name","cmdline"]):
        try:
            pn = (proc.info["name"] or "").lower()
            if pn not in {p2.lower() for p2 in MC_PROCS}: continue
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
            if "-javaagent" in cmd and "mixin" not in cmd:
                tlog(f"  -javaagent (non-mixin) [PID {proc.info['pid']}]","warn")
                all_findings["process_flags"].append({"pid":proc.info["pid"],"type":"javaagent"})
        except Exception: continue

def get_process_connections(proc):
    try:
        return proc.net_connections(kind="inet")
    except AttributeError:
        pass
    try:
        return proc.connections(kind="inet")
    except Exception:
        return []

def find_live_mc_processes():
    if not PSUTIL_OK:
        return []
    MC_PROCS = {"javaw.exe","java.exe","minecraft.exe"}
    found = []
    for proc in psutil.process_iter(["pid","name","exe","cmdline","create_time","cwd"]):
        try:
            pn = (proc.info["name"] or "").lower()
            if pn not in MC_PROCS: continue
            cmd = " ".join(proc.info.get("cmdline") or [])
            if pn in ("javaw.exe","java.exe") and "minecraft" not in cmd.lower() and "fabric" not in cmd.lower() and "forge" not in cmd.lower():
                continue
            found.append(proc)
        except Exception: continue
    return found

def resolve_instance_from_process(proc):
    try:
        cwd = proc.cwd()
    except Exception:
        cwd = None
    if cwd and os.path.isdir(os.path.join(cwd, "mods")):
        return cwd
    if cwd and os.path.isdir(os.path.join(cwd, "config")):
        return cwd
    try:
        cmdline = proc.cmdline()
    except Exception:
        cmdline = []
    for arg in cmdline:
        if os.path.isdir(arg) and os.path.isdir(os.path.join(arg, "mods")):
            return arg
    for root in get_scan_roots():
        if cwd and os.path.normcase(os.path.abspath(cwd)) == os.path.normcase(os.path.abspath(root)):
            return root
    return cwd

def live_module_audit(proc):
    tlog("Feature 1/3 — Live loaded-module audit", "scan")
    TEMP_PATHS = [t.lower() for t in [
        os.environ.get("TEMP",""), os.environ.get("TMP",""),
        os.path.join(os.environ.get("LOCALAPPDATA",""),"Temp"),
    ] if t]
    flagged = []
    try:
        for m in proc.memory_maps():
            mp = (m.path or "")
            if not mp.lower().endswith(".dll"): continue
            mpl = mp.lower()
            for tp in TEMP_PATHS:
                if tp and mpl.startswith(tp):
                    flagged.append(mp)
                    tlog(f"  SUSPICIOUS DLL (loaded from Temp)  {mp}", "bad")
                    scan_counters["red"] += 1
                    break
    except psutil.AccessDenied:
        tlog("  Access denied reading loaded modules — run as Administrator", "warn")
    except Exception as e:
        tlog(f"  Module read error: {e}", "warn")
    if not flagged:
        tlog("  No suspicious loaded modules", "ok")
        scan_counters["green"] += 1
    return flagged

def live_connection_reputation(proc):
    tlog("Feature 2/3 — Live connection reputation check", "scan")
    conns = get_process_connections(proc)
    flagged = []
    remotes = []
    for conn in conns:
        if conn.raddr:
            remotes.append(f"{conn.raddr.ip}:{conn.raddr.port}")
    if remotes:
        tlog(f"  {len(remotes)} active remote connection(s)", "info")
        for r in remotes[:15]:
            tlog(f"    → {r}", "info")
    for conn in conns:
        if not conn.raddr: continue
        ip = conn.raddr.ip
        try:
            import socket as _socket
            hostname = _socket.getfqdn(ip)
        except Exception:
            hostname = ""
        for bad in CHEAT_DOMAINS:
            if bad in hostname.lower():
                flagged.append((ip, hostname, bad))
                tlog(f"  CHEAT DOMAIN CONNECTION  {ip} ({hostname}) matches {bad}", "bad")
                all_findings["dns_flags"].append({"entry": hostname, "matched": bad, "live": True})
                scan_counters["red"] += 1
    if not flagged:
        tlog("  No connections to known cheat hosts", "ok")
        scan_counters["green"] += 1
    return flagged

def live_instance_correlation(proc):
    tlog("Feature 3/3 — Live instance-to-disk correlation", "scan")
    instance_path = resolve_instance_from_process(proc)
    if not instance_path or not os.path.isdir(instance_path):
        tlog("  Could not resolve running instance to a folder on disk", "warn")
        return None
    tlog(f"  Resolved live instance: {instance_path}", "ok")
    settings = active_preset["data"] or PRESET_DEFAULTS["default"]
    phase0_log_scan(instance_path, settings.get("max_config_depth", 4))
    phase1_config_scan(instance_path, settings.get("max_config_depth", 4))
    mods_dir = os.path.join(instance_path, "mods")
    if os.path.isdir(mods_dir):
        phase2_scanner(mods_dir, settings.get("paranoid_mode", False))
    return instance_path

def do_live():
    global SCAN_RUNNING
    SCAN_RUNNING = True
    reset_refs()
    section("LIVE SCAN — running instance, read-only process introspection")
    divider()

    if not PSUTIL_OK:
        tlog("psutil missing — /live requires psutil", "warn")
        SCAN_RUNNING = False
        return

    procs = find_live_mc_processes()
    if not procs:
        tlog("No running Minecraft process found", "info")
        p()
        p(c(YL)("  No live Minecraft instance detected. Launch the game first."))
        p()
        SCAN_RUNNING = False
        return

    for proc in procs:
        try:
            pid = proc.pid
            exe = proc.exe() if proc.is_running() else "unknown"
        except Exception:
            pid, exe = proc.pid, "unknown"
        tlog(f"Live process found: PID {pid}  {exe}", "ok")
        row("Executable", exe, "info")
        try:
            row("Started", datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S"), "info")
        except Exception: pass

        live_module_audit(proc)
        live_connection_reputation(proc)
        live_instance_correlation(proc)
        p()

    p(); draw_status(); p()
    print_verdict()
    SCAN_RUNNING = False

def do_prefetch_scan():
    pfdir = r"C:\Windows\Prefetch"
    if not os.path.isdir(pfdir):
        tlog("Prefetch: need Administrator","warn"); return
    tlog("Prefetch scan...","scan")
    now = time.time()
    FLAGS = list(get_config_dirs_map().keys()) + CLICKER_NAMES + BYPASS_NAMES + ["cheatengine","x64dbg","x32dbg","extremeinjector","xenos"]
    FLAGS = [f.lower() for f in FLAGS]
    try:
        for fname in os.listdir(pfdir):
            if not fname.endswith(".pf"): continue
            exe = fname.rsplit("-",1)[0].lower()
            flag = next((f for f in FLAGS if f in exe), None)
            if flag:
                mtime = os.path.getmtime(os.path.join(pfdir,fname))
                age = now - mtime
                run_t = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                tlog(f"PREFETCH  {exe.upper()}  last run {run_t}","bad")
                all_findings["prefetch_flags"].append({"file":fname,"last_run":run_t,"age":f"{int(age//3600)}h{int((age%3600)//60)}m"})
                scan_counters["red"] += 1
    except PermissionError:
        tlog("Prefetch: permission denied","warn")

def do_registry_scan():
    if not HAS_WINREG: return
    tlog("Registry scan...","scan")
    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]
    KEYWORDS = [k.lower() for k in (list(get_config_dirs_map().keys()) + CLICKER_NAMES + BYPASS_NAMES)]
    for hive,kpath in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive,kpath,0,winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name,data,_ = winreg.EnumValue(key,i)
                    dl,nl = str(data).lower(),name.lower()
                    for kw in KEYWORDS:
                        if kw in dl or kw in nl:
                            tlog(f"REGISTRY  [{name}]  {str(data)[:55]}","bad")
                            all_findings["registry_flags"].append({"key":kpath,"name":name,"value":str(data)})
                            scan_counters["red"] += 1; break
                    i += 1
                except OSError: break
            winreg.CloseKey(key)
        except Exception: continue

def build_case_files():
    cases = {}

    def get_case(client):
        if client not in cases:
            cases[client] = {"jars": [], "configs": [], "logs": [], "confidence": 0}
        return cases[client]

    for entry in all_findings.get("scanner", []):
        client = entry.get("client") or "Unknown"
        case = get_case(client)
        path = entry.get("path")
        if path and path not in case["jars"]:
            case["jars"].append(path)
        case["confidence"] = max(case["confidence"], entry.get("confidence", 0) or 0)

    for entry in all_findings.get("config_hits", []):
        client = entry.get("client")
        if not client: continue
        case = get_case(client)
        path = entry.get("path")
        if path and path not in case["configs"]:
            case["configs"].append(path)

    for entry in all_findings.get("log_hits", []):
        client = entry.get("client")
        if not client: continue
        case = get_case(client)
        path = entry.get("path")
        if path and path not in case["logs"]:
            case["logs"].append(path)

    return cases

def render_case_files():
    cases = build_case_files()
    if not cases:
        return
    p()
    p(c(GR)("[") + c(CY)(">") + c(GR)("] ") + c(WH,BOLD)("Detected clients — click ▶ to open, or /open <n>"))
    divider()
    for client, case in sorted(cases.items(), key=lambda x: -x[1]["confidence"]):
        conf_str = f"  {case['confidence']}% confidence" if case["confidence"] else ""
        p(c(RD,BOLD)(f"  {client}") + c(GR)(conf_str))
        for jpath in case["jars"]:
            p(f"    {link_ref(jpath,'jar')}  {c(GR)('[jar]')}     {c(WH)(os.path.basename(jpath))}")
            p(f"         {c(DIM,GR)(jpath)}")
        for cpath in case["configs"]:
            p(f"    {link_ref(cpath,'config')}  {c(GR)('[config]')}  {c(WH)(os.path.basename(cpath))}")
            p(f"         {c(DIM,GR)(cpath)}")
        for lpath in case["logs"]:
            p(f"    {link_ref(lpath,'log')}  {c(GR)('[log]')}     {c(WH)(os.path.basename(lpath))}")
            p(f"         {c(DIM,GR)(lpath)}")
        p()

def print_verdict():
    render_case_files()
    p()
    divider()
    g = scan_counters.get("green",0); y = scan_counters.get("yellow",0)
    r = scan_counters.get("red",0); t = scan_counters.get("total",0)
    j = scan_counters.get("jars",0)
    row("Files scanned", str(t), "info")
    row("JARs analyzed", str(j), "info")
    row("Clean", str(g), "clean")
    row("Suspicious", str(y), "warn")
    row("Flagged", str(r), "bad" if r else "clean")
    row("Log tampering", str(all_findings["summary"]["log_tampering"]),
        "bad" if all_findings["summary"]["log_tampering"] else "clean")
    row("DNS hits", str(all_findings["summary"]["dns_hits"]),
        "bad" if all_findings["summary"]["dns_hits"] else "clean")
    row("Scanner status", get_scanner_status(),
        "warn" if get_scanner_status()=="warn" else "clean" if get_scanner_status()=="idle" else "info")
    divider()
    if r == 0 and y == 0:
        p(c(GN,BOLD)("  ✓  CLEAN — no cheat indicators found"))
    elif r == 0:
        p(c(YL,BOLD)(f"  ▲  {y} SUSPICIOUS item(s) — /seeterminal to review"))
    else:
        names = list({
            e.get("client") or e.get("client_name") or ""
            for e in (all_findings.get("scanner",[]) + all_findings.get("config_hits",[]))
            if isinstance(e,dict)
        } - {""})
        ns = ", ".join(names[:4]) + ("..." if len(names)>4 else "") if names else "Unknown"
        p(c(RD,BOLD)(f"  ✗  FLAGGED — {r} indicator(s) · {ns}"))
    divider()
    report_path = None
    try:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(os.path.expanduser("~"),"Desktop", f"velocity_report_{ts}.json")
        json.dump(all_findings, open(report_path,"w"), indent=2, default=str)
        p(c(DIM,CY)(f"  Report → {report_path}"))
    except Exception: pass
    p()
    return report_path

def resolve_run_path(one_shot_arg):
    if one_shot_arg:
        cand = one_shot_arg.strip().strip('"')
        if not os.path.isdir(cand):
            p(c(RD)(f"  Invalid path (not found): {cand}"))
            return "__INVALID__"
        return cand
    if ghost_state["focus_paths"]:
        return None
    for attempt in range(3):
        raw = read_line(c(GR)("  Path to focus, or Enter for defaults: "))
        if raw == "__CTRLC__":
            return "__INVALID__"
        raw = raw.strip().strip('"')
        if not raw:
            return None
        if os.path.isdir(raw):
            return raw
        p(c(RD)(f"  Invalid path (not found): {raw}  — try again"))
    p(c(YL)("  Too many invalid attempts — running with defaults"))
    return None

def do_flash(one_shot_arg=""):
    global SCAN_RUNNING
    target = resolve_run_path(one_shot_arg)
    if target == "__INVALID__": return
    SCAN_RUNNING = True
    reset_refs()
    settings = active_preset["data"] or PRESET_DEFAULTS["default"]
    section("FLASH SCAN — logs → config → scanner → dns → process")
    divider()
    mc = target or os.path.expandvars(r"%APPDATA%\.minecraft")
    if not os.path.isdir(mc):
        row("Error",".minecraft not found","warn"); SCAN_RUNNING=False; return
    if target: tlog(f"Focused on: {target}  (this run only)", "info")
    if settings.get("run_log_scan", True): phase0_log_scan(mc, settings.get("max_config_depth",4))
    if settings.get("run_config_scan", True): phase1_config_scan(mc, settings.get("max_config_depth",4))
    if settings.get("run_scanner_scan", True): phase2_scanner(os.path.join(mc,"mods"), settings.get("paranoid_mode", False))
    if settings.get("run_dns_scan", True): do_dns_scan()
    if settings.get("run_process_scan", True): do_process_scan()
    p(); draw_status(); p()
    print_verdict()
    SCAN_RUNNING = False

def full_depth_note():
    tlog("MAX 1/20 — Full-depth mode: no scan caps, no sampling limits", "info")

def hash_prepass(all_jars):
    tlog("MAX 2/20 — Instant hash-cache pre-pass", "scan")
    bad = load_hash_store("known_bad_hashes.json")
    hits = 0
    for jp in all_jars:
        h = sha256(jp)
        if h and h in bad:
            entry = bad[h]
            tlog(f"  INSTANT HIT  {entry.get('client')}  ·  {os.path.basename(jp)}", "bad")
            scan_counters["red"] += 1
            hits += 1
    if not hits: tlog("  No instant hash hits", "ok")

def scan_recycle_bin():
    tlog("MAX 3/20 — Recycle Bin sweep", "scan")
    found = 0
    for letter in "CDEFGH":
        rb = f"{letter}:\\$Recycle.Bin"
        if not os.path.isdir(rb): continue
        try:
            for root, dirs, files in os.walk(rb):
                for fname in files:
                    if fname.lower().endswith((".jar",".json")):
                        fpath = os.path.join(root, fname)
                        tlog(f"  Deleted file found: {fpath}", "warn")
                        all_findings["config_hits"].append({"type":"recycle_bin","path":fpath})
                        scan_counters["yellow"] += 1
                        found += 1
        except Exception: pass
    if not found: tlog("  Nothing suspicious in Recycle Bin", "ok"); scan_counters["green"] += 1

def scan_other_user_profiles():
    tlog("MAX 4/20 — Other Windows user profiles", "scan")
    if not is_admin():
        tlog("  Skipped — requires Administrator", "warn"); return
    users_dir = r"C:\Users"
    own_mc = os.path.expandvars(r"%APPDATA%\.minecraft").lower()
    found = 0
    try:
        for uname in os.listdir(users_dir):
            mc = os.path.join(users_dir, uname, "AppData","Roaming",".minecraft")
            if os.path.isdir(mc) and mc.lower() != own_mc:
                tlog(f"  Found instance under user '{uname}': {mc}", "info")
                found += 1
    except Exception as e:
        tlog(f"  Error: {e}", "warn")
    if not found: tlog("  No other user profiles with Minecraft", "ok")

def scan_archives():
    tlog("MAX 5/20 — Downloads/Desktop scan (archives + loose executables, pre-install)", "scan")
    roots = [os.path.join(os.path.expanduser("~"),"Downloads"), os.path.join(os.path.expanduser("~"),"Desktop")]
    profile_names = [c.lower().replace(" ","") for c in CLIENT_PROFILES()]
    loose_keywords = [k.lower() for k in CLICKER_NAMES + BYPASS_NAMES + list(CLIENT_PROFILES().keys())]
    found = 0
    for root in roots:
        if not os.path.isdir(root): continue
        try: entries = os.listdir(root)
        except Exception: continue
        for fname in entries:
            fl = fname.lower()
            fpath = os.path.join(root, fname)

            if fl.endswith(".zip"):
                try:
                    with zipfile.ZipFile(fpath) as z:
                        names_lower = " ".join(z.namelist()).lower().replace(" ","")
                        for cn in profile_names:
                            if cn in names_lower:
                                tlog(f"  ARCHIVE  {cn} found inside {fname}", "warn")
                                scan_counters["yellow"] += 1
                                found += 1
                                break
                except Exception: pass

            elif fl.endswith((".exe",".jar",".bat",".cmd",".ps1")):
                stem = os.path.splitext(fl)[0].replace(" ","").replace("_","").replace("-","")
                for kw in loose_keywords:
                    kw_clean = kw.replace(" ","").replace("_","").replace("-","")
                    if kw_clean and kw_clean in stem:
                        tlog(f"  DOWNLOADED  '{fname}' matches known tool '{kw}'", "warn")
                        all_findings["config_hits"].append({"type":"downloaded_tool","path":fpath,"match":kw})
                        scan_counters["yellow"] += 1
                        found += 1
                        break
    if not found: tlog("  Nothing suspicious in Downloads/Desktop", "ok"); scan_counters["green"] += 1

def scan_resourcepacks(mc_root):
    found = 0
    for sub in ("resourcepacks","shaderpacks"):
        d = os.path.join(mc_root, sub)
        if not os.path.isdir(d): continue
        try: entries = os.listdir(d)
        except Exception: continue
        for fname in entries:
            if not fname.lower().endswith(".zip"): continue
            fpath = os.path.join(d, fname)
            try:
                with zipfile.ZipFile(fpath) as z:
                    for n in z.namelist():
                        if n.lower().endswith((".json",".txt")) and "config" in n.lower():
                            raw = z.read(n).decode("utf-8","ignore")
                            for cn, prof in CLIENT_PROFILES().items():
                                sig = prof.get("config_path_sig","")
                                if sig and sig in raw:
                                    tlog(f"  HIDDEN CONFIG  {cn} inside {sub}/{fname}", "bad")
                                    scan_counters["red"] += 1
                                    found += 1
            except Exception: pass
    return found

def scan_scheduled_tasks():
    tlog("MAX 7/20 — Scheduled Task persistence check", "scan")
    try:
        result = subprocess.run(["schtasks","/query","/fo","CSV"], capture_output=True, text=True, timeout=15)
        keywords = [k.lower() for k in list(CLIENT_PROFILES().keys()) + CLICKER_NAMES + BYPASS_NAMES]
        found = 0
        for line in result.stdout.splitlines():
            ll = line.lower()
            for kw in keywords:
                if kw in ll:
                    tlog(f"  SCHEDULED TASK matches '{kw}': {line[:90]}", "bad")
                    scan_counters["red"] += 1
                    found += 1
                    break
        if not found: tlog("  No suspicious scheduled tasks", "ok"); scan_counters["green"] += 1
    except Exception as e:
        tlog(f"  Error: {e}", "warn")

def diff_against_last_report():
    tlog("MAX 8/20 — Diff against your last saved report", "scan")
    desktop = os.path.join(os.path.expanduser("~"),"Desktop")
    try:
        reports = sorted([f for f in os.listdir(desktop) if f.startswith("velocity_report_") and f.endswith(".json")])
    except Exception:
        reports = []
    if not reports:
        tlog("  No prior report to diff against", "info"); return
    try:
        prev = json.loads(open(os.path.join(desktop, reports[-1])).read())
        prev_paths = {h.get("path") for h in prev.get("scanner",[]) if h.get("verdict")=="CHEAT"}
        current_paths = {h.get("path") for h in all_findings.get("scanner",[]) if h.get("verdict")=="CHEAT"}
        new_ones = current_paths - prev_paths
        if new_ones:
            for np in new_ones: tlog(f"  NEW SINCE LAST SCAN: {np}", "bad")
        else:
            tlog("  No new cheat detections since last scan", "ok")
    except Exception as e:
        tlog(f"  Diff error: {e}", "warn")

def cross_correlate_instances():
    tlog("MAX 9/20 — Cross-instance signature correlation", "scan")
    confirmed = [h for h in all_findings.get("scanner",[]) if h.get("verdict")=="CHEAT"]
    if not confirmed:
        tlog("  No confirmed cheats to correlate", "ok"); scan_counters["green"] += 1; return
    bad_store = load_hash_store("known_bad_hashes.json")
    struct_store = load_hash_store("structure_fingerprints.json")
    tlog(f"  {len(bad_store)} hash signatures + {len(struct_store)} structural signatures now in memory", "info")
    tlog("  Every future scan on this machine will catch these instantly, even if renamed", "ok")

def auto_dashboard():
    tlog("MAX 10/20 — Auto-generating dashboard", "scan")
    try:
        out_path = generate_dashboard()
        webbrowser.open(f"file://{out_path.resolve()}")
        tlog(f"  Dashboard opened: {out_path}", "ok")
    except Exception as e:
        tlog(f"  Dashboard error: {e}", "warn")

def scan_user_documents_for_cheats():
    tlog("MAX 11/20 — Documents/Videos/Desktop exe scan", "scan")
    roots = [
        os.path.join(os.path.expanduser("~"), d)
        for d in ("Documents","Videos","Desktop","Downloads","Music","Pictures","OneDrive")
    ]
    keywords = [k.lower().replace("-","").replace("_","") for k in CLICKER_NAMES + BYPASS_NAMES + list(CLIENT_PROFILES().keys())]
    found = 0
    for root in roots:
        if not os.path.isdir(root): continue
        for fname in os.listdir(root):
            stem = os.path.splitext(fname)[0].lower().replace("-","").replace("_","").replace(" ","")
            if any(k in stem for k in keywords):
                fpath = os.path.join(root, fname)
                tlog(f"  FOUND  '{fname}' in {os.path.basename(root)}", "bad")
                all_findings["config_hits"].append({"type":"user_dir_tool","path":fpath,"dir":root})
                scan_counters["red"] += 1; found += 1
    if not found: tlog("  Nothing in personal folders", "ok"); scan_counters["green"] += 1

def scan_temp_exe():
    tlog("MAX 12/20 — Temp directory executable sweep", "scan")
    temp_dirs = [os.environ.get("TEMP",""), os.environ.get("TMP",""),
                 os.path.join(os.environ.get("LOCALAPPDATA",""),"Temp")]
    found = 0
    for td in temp_dirs:
        if not td or not os.path.isdir(td): continue
        for fname in os.listdir(td):
            if not fname.lower().endswith((".exe",".jar",".dll",".bat",".ps1")): continue
            fpath = os.path.join(td, fname)
            age = time.time() - os.path.getmtime(fpath)
            if age < 86400 * 7:
                tlog(f"  TEMP EXEC  {fname}  ({int(age//3600)}h old)", "warn")
                all_findings["config_hits"].append({"type":"temp_exec","path":fpath,"age_h":int(age//3600)})
                scan_counters["yellow"] += 1; found += 1
    if not found: tlog("  Temp directories clean", "ok"); scan_counters["green"] += 1

def entropy_scan_mods(mc_root):
    tlog("MAX 13/20 — High-entropy JAR detection (packed/obfuscated)", "scan")
    mods_dir = os.path.join(mc_root, "mods")
    if not os.path.isdir(mods_dir): return
    from collections import Counter
    import math
    found = 0
    for fname in os.listdir(mods_dir):
        if not fname.lower().endswith(".jar"): continue
        fpath = os.path.join(mods_dir, fname)
        try:
            with open(fpath,"rb") as f: data = f.read(65536)
            freq = Counter(data)
            entropy = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values() if c)
            if entropy > 7.5:
                tlog(f"  HIGH ENTROPY  {fname}  ({entropy:.2f}/8.0)", "warn")
                all_findings["config_hits"].append({"type":"high_entropy","path":fpath,"entropy":round(entropy,3)})
                scan_counters["yellow"] += 1; found += 1
        except Exception: pass
    if not found: tlog("  No suspicious entropy detected", "ok"); scan_counters["green"] += 1

def scan_bam_registry():
    tlog("MAX 14/20 — BAM execution history (Background Activity Moderator)", "scan")
    if not HAS_WINREG or not is_admin():
        tlog("  Requires Administrator", "warn"); return
    BAM_KEY = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    keywords = [k.lower() for k in CLICKER_NAMES + BYPASS_NAMES]
    found = 0
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BAM_KEY)
        i = 0
        while True:
            try:
                subname = winreg.EnumKey(key, i); i += 1
                try:
                    sub = winreg.OpenKey(key, subname)
                    j = 0
                    while True:
                        try:
                            vname, _, _ = winreg.EnumValue(sub, j); j += 1
                            vl = vname.lower()
                            for kw in keywords:
                                if kw in vl:
                                    tlog(f"  BAM HIT  {vname[-60:]}", "bad")
                                    all_findings["registry_flags"].append({"type":"bam","value":vname,"match":kw})
                                    scan_counters["red"] += 1; found += 1; break
                        except OSError: break
                    winreg.CloseKey(sub)
                except Exception: pass
            except OSError: break
        winreg.CloseKey(key)
    except Exception as e:
        tlog(f"  BAM read error: {e}", "warn")
    if not found: tlog("  No BAM execution hits", "ok"); scan_counters["green"] += 1

def scan_userassist():
    tlog("MAX 15/20 — UserAssist execution history", "scan")
    if not HAS_WINREG:
        tlog("  winreg unavailable", "warn"); return
    UA_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    keywords = [k.lower() for k in CLICKER_NAMES + BYPASS_NAMES]
    found = 0
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, UA_KEY)
        i = 0
        while True:
            try:
                subname = winreg.EnumKey(key, i); i += 1
                try:
                    count_key = winreg.OpenKey(key, subname + r"\Count")
                    j = 0
                    while True:
                        try:
                            vname, _, _ = winreg.EnumValue(count_key, j); j += 1
                            decoded = bytes([b ^ 0x13 for b in vname.encode("utf-8","ignore")]).decode("utf-8","ignore").lower()
                            for kw in keywords:
                                if kw in decoded:
                                    tlog(f"  USERASSIST  {kw} in execution history", "bad")
                                    all_findings["registry_flags"].append({"type":"userassist","match":kw})
                                    scan_counters["red"] += 1; found += 1; break
                        except OSError: break
                    winreg.CloseKey(count_key)
                except Exception: pass
            except OSError: break
        winreg.CloseKey(key)
    except Exception as e:
        tlog(f"  UserAssist error: {e}", "warn")
    if not found: tlog("  No UserAssist execution hits", "ok"); scan_counters["green"] += 1

def scan_hosts_file():
    tlog("MAX 16/20 — Hosts file tampering check", "scan")
    hosts = r"C:\Windows\System32\drivers\etc\hosts"
    if not os.path.isfile(hosts):
        tlog("  Hosts file not found", "warn"); return
    found = 0
    try:
        with open(hosts,"r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"): continue
                for domain in CHEAT_DOMAINS:
                    if domain in stripped.lower():
                        tlog(f"  HOSTS  cheat domain blocked/redirected: {stripped[:70]}", "warn")
                        all_findings["dns_flags"].append({"type":"hosts","line":stripped,"domain":domain})
                        scan_counters["yellow"] += 1; found += 1; break
    except Exception as e:
        tlog(f"  Hosts read error: {e}", "warn")
    if not found: tlog("  Hosts file normal", "ok"); scan_counters["green"] += 1

def scan_startup_folders():
    tlog("MAX 17/20 — Startup folder persistence check", "scan")
    startup_dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]
    keywords = [k.lower() for k in CLICKER_NAMES + BYPASS_NAMES + list(CLIENT_PROFILES().keys())]
    found = 0
    for sd in startup_dirs:
        if not os.path.isdir(sd): continue
        try:
            for fname in os.listdir(sd):
                fl = fname.lower().replace("-","").replace("_","")
                for kw in keywords:
                    kw_clean = kw.replace("-","").replace("_","")
                    if kw_clean and kw_clean in fl:
                        fpath = os.path.join(sd, fname)
                        tlog(f"  STARTUP  {fname}", "bad")
                        all_findings["registry_flags"].append({"type":"startup_folder","path":fpath,"match":kw})
                        scan_counters["red"] += 1; found += 1; break
        except Exception: pass
    if not found: tlog("  Startup folders clean", "ok"); scan_counters["green"] += 1

def scan_env_variables():
    tlog("MAX 18/20 — Environment variable inspection", "scan")
    suspicious_keys = ["JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","JAVA_OPTS"]
    agent_flags = ["-javaagent","-agentlib","-agentpath","-Xbootclasspath"]
    found = 0
    for key in suspicious_keys:
        val = os.environ.get(key,"")
        if not val: continue
        for flag in agent_flags:
            if flag.lower() in val.lower():
                tlog(f"  ENV  {key}={val[:80]} — contains {flag}", "bad")
                all_findings["registry_flags"].append({"type":"env_var","key":key,"value":val[:200],"flag":flag})
                scan_counters["red"] += 1; found += 1; break
    if not found: tlog("  No suspicious env vars", "ok"); scan_counters["green"] += 1

def scan_file_age_anomaly(mc_root):
    tlog("MAX 19/20 — Mod file age anomaly detection", "scan")
    mods_dir = os.path.join(mc_root, "mods")
    if not os.path.isdir(mods_dir): return
    now = time.time()
    jars = [f for f in os.listdir(mods_dir) if f.lower().endswith(".jar")]
    if len(jars) < 2: return
    mtimes = []
    for fname in jars:
        try: mtimes.append((fname, os.path.getmtime(os.path.join(mods_dir, fname))))
        except Exception: pass
    if not mtimes: return
    avg_mtime = sum(m for _,m in mtimes) / len(mtimes)
    for fname, mtime in mtimes:
        delta = abs(mtime - avg_mtime)
        if delta > 86400 * 30:
            age_days = int((now - mtime) / 86400)
            tlog(f"  AGE OUTLIER  {fname}  (modified {age_days}d ago vs avg group)", "warn")
            all_findings["config_hits"].append({"type":"age_anomaly","path":os.path.join(mods_dir,fname),"age_days":age_days})
            scan_counters["yellow"] += 1

def deep_string_scan_all_jars(all_jars):
    tlog("MAX 20/20 — Deep string scan every jar, no class limit", "scan")
    custom = ghost_state["strings"] if ghost_state["active"] else None
    hits = 0
    start = time.time()
    for i, jar_path in enumerate(all_jars):
        if i % 10 == 0:
            draw_progress("Deep scan", i, len(all_jars), eta_str(time.time()-start, i+1, len(all_jars)))
        try:
            r = analyze_jar(jar_path, custom_strings=custom, paranoid=True)
            if r.verdict == "CHEAT":
                scan_counters["red"] += 1
                name = r.detected_client or "Unknown"
                if r.sha256_val: record_bad_hash(r.sha256_val, name, jar_path)
                learn_structure(name, r.class_basenames)
                tlog(f"  DEEP SCAN HIT  {name}  ·  {os.path.basename(jar_path)}", "bad")
                all_findings["scanner"].append({"path":jar_path,"verdict":"CHEAT","client":name,"confidence":r.probability(),"strings":r.cheat_strings[:8]})
                all_findings["summary"]["private_hits"] += 1
                hits += 1
            elif r.verdict == "SUSPICIOUS":
                scan_counters["yellow"] += 1
            else:
                scan_counters["green"] += 1
        except Exception: pass
    sys.stdout.write("\r\033[K")
    tlog(f"  Deep scan complete: {len(all_jars)} jars, {hits} hits", "ok" if not hits else "bad")

def do_max(one_shot_arg=""):
    global SCAN_RUNNING
    target = resolve_run_path(one_shot_arg)
    if target == "__INVALID__": return
    SCAN_RUNNING = True
    reset_refs()
    active_preset["name"] = "defaultmax"
    active_preset["data"] = load_active_preset("defaultmax") or PRESET_DEFAULTS["defaultmax"]
    load_data()
    settings = active_preset["data"]
    section("MAX SCAN — everything /pro does, plus 10 exclusive deep passes")
    divider()
    if not is_admin():
        tlog("Not Administrator — some MAX features limited","warn")

    full_depth_note()
    if target: tlog(f"Focused on: {target}  (this run only)", "info")
    roots = [target] if target else get_scan_roots()

    rp_found = 0
    for root in roots:
        phase0_log_scan(root, settings.get("max_config_depth",10))
        phase1_config_scan(root, settings.get("max_config_depth",10))
        mods = os.path.join(root,"mods")
        if os.path.isdir(mods):
            phase2_scanner(mods, paranoid=True)
        rp_found += scan_resourcepacks(root)
    tlog(f"MAX 6/20 — Resourcepack/shaderpack scan: {rp_found} hidden config(s)", "ok" if not rp_found else "bad")
    if not rp_found: scan_counters["green"] += 1

    if not target:
        import string
        drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
        all_jars = []
        tlog("Building system-wide JAR list...","scan")
        folders_seen = 0
        hb = time.time()
        for drive in drives:
            for root,dirs,files in os.walk(drive,topdown=True):
                dirs[:] = [d for d in dirs if d.lower() not in DRIVE_WALK_SKIP and not d.startswith("$") and d.lower()!="windows"]
                folders_seen += 1
                if time.time() - hb > 1.5:
                    draw_progress(f"Scanning {drive}", folders_seen, folders_seen + 1000, "")
                    hb = time.time()
                for fname in files:
                    if fname.lower().endswith(".jar"):
                        all_jars.append(os.path.join(root,fname))
        sys.stdout.write("\r\033[K")
        tlog(f"Folder walk complete — {folders_seen} folders checked", "ok")

        hash_prepass(all_jars)

        if all_jars:
            tlog(f"System-wide scan: {len(all_jars)} JARs","scan")
            set_scanner_status("running")
            start = time.time()
            for i,jar_path in enumerate(all_jars):
                draw_progress("System JARs",i,len(all_jars), eta_str(time.time()-start,i+1,len(all_jars)))
                scan_counters["jars"] += 1
                scan_counters["total"] += 1
                try:
                    r = analyze_jar(jar_path,paranoid=True)
                    if r.verdict=="CHEAT":
                        scan_counters["red"] += 1
                        name = r.detected_client or "Unknown"
                        if r.sha256_val: record_bad_hash(r.sha256_val, name, jar_path)
                        learn_structure(name, r.class_basenames)
                        tlog(f"FLAGGED  CHEAT  {name}  ·  {jar_path[-60:]}","bad")
                        all_findings["scanner"].append({"path":jar_path,"verdict":"CHEAT","client":name,"confidence":r.probability(),"strings":r.cheat_strings[:8]})
                        all_findings["summary"]["private_hits"] += 1
                        for line in format_scan_result(r): p(line)
                    elif r.verdict=="SUSPICIOUS":
                        scan_counters["yellow"] += 1
                    else:
                        scan_counters["green"] += 1
                except Exception: pass
            sys.stdout.write("\r\033[K")
            set_scanner_status("warn" if scan_counters["red"]>0 else "idle")

    do_registry_scan()
    do_prefetch_scan()
    do_dns_scan()
    do_process_scan()
    scan_recycle_bin()
    scan_other_user_profiles()
    scan_archives()
    scan_scheduled_tasks()
    diff_against_last_report()
    cross_correlate_instances()

    scan_user_documents_for_cheats()
    scan_temp_exe()
    scan_bam_registry()
    scan_userassist()
    scan_hosts_file()
    scan_startup_folders()
    scan_env_variables()

    for root in roots:
        entropy_scan_mods(root)
        scan_file_age_anomaly(root)

    _all_jars_for_deep = all_jars if not target else [
        os.path.join(rd, fn)
        for rd, _, files in os.walk(target)
        for fn in files if fn.lower().endswith(".jar")
    ]
    if _all_jars_for_deep:
        deep_string_scan_all_jars(_all_jars_for_deep)

    p(); draw_status(); p()
    print_verdict()
    auto_dashboard()
    SCAN_RUNNING = False

def do_pro(one_shot_arg=""):
    global SCAN_RUNNING
    target = resolve_run_path(one_shot_arg)
    if target == "__INVALID__": return
    SCAN_RUNNING = True
    reset_refs()
    settings = active_preset["data"] or PRESET_DEFAULTS["defaultpro"]
    section("PRO SCAN — paranoid · every drive · registry · prefetch")
    divider()
    if not is_admin():
        tlog("Not Administrator — registry/prefetch limited","warn")

    if target:
        tlog(f"Focused on: {target}  (this run only, skipping drive-wide hunt)", "info")
        roots = [target]
    else:
        roots = get_scan_roots()

    for root in roots:
        phase0_log_scan(root, settings.get("max_config_depth",6))
        phase1_config_scan(root, settings.get("max_config_depth",6))
        mods = os.path.join(root,"mods")
        if os.path.isdir(mods):
            phase2_scanner(mods, paranoid=True)

    if target:
        do_registry_scan()
        do_prefetch_scan()
        do_dns_scan()
        do_process_scan()
        p(); draw_status(); p()
        print_verdict()
        SCAN_RUNNING = False
        return

    import string
    drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    all_jars = []
    tlog("Building system-wide JAR list...","scan")
    folders_seen = 0
    hb = time.time()
    for drive in drives:
        for root,dirs,files in os.walk(drive,topdown=True):
            dirs[:] = [d for d in dirs if d.lower() not in DRIVE_WALK_SKIP and not d.startswith("$") and d.lower()!="windows"]
            folders_seen += 1
            if time.time() - hb > 1.5:
                draw_progress(f"Scanning {drive}", folders_seen, folders_seen + 1000, "")
                hb = time.time()
            for fname in files:
                if fname.lower().endswith(".jar"):
                    all_jars.append(os.path.join(root,fname))
    sys.stdout.write("\r\033[K")
    tlog(f"Folder walk complete — {folders_seen} folders checked", "ok")

    if all_jars:
        tlog(f"System-wide scan: {len(all_jars)} JARs","scan")
        set_scanner_status("running")
        start = time.time()
        custom = ghost_state["strings"] if ghost_state["active"] else None
        for i,jar_path in enumerate(all_jars):
            draw_progress("System JARs",i,len(all_jars), eta_str(time.time()-start,i+1,len(all_jars)))
            scan_counters["jars"] += 1
            scan_counters["total"] += 1
            try:
                r = analyze_jar(jar_path,custom_strings=custom,paranoid=True)
                if r.verdict=="CHEAT":
                    scan_counters["red"] += 1
                    name = r.detected_client or "Unknown"
                    if r.sha256_val: record_bad_hash(r.sha256_val, name, jar_path)
                    learn_structure(name, r.class_basenames)
                    tlog(f"FLAGGED  CHEAT  {name}  ·  {jar_path[-60:]}","bad")
                    all_findings["scanner"].append({"path":jar_path,"verdict":"CHEAT","client":name,"confidence":r.probability(),"strings":r.cheat_strings[:8]})
                    all_findings["summary"]["private_hits"] += 1
                    for line in format_scan_result(r): p(line)
                elif r.verdict=="SUSPICIOUS":
                    scan_counters["yellow"] += 1
                else:
                    scan_counters["green"] += 1
            except Exception: pass
        sys.stdout.write("\r\033[K")
        set_scanner_status("warn" if scan_counters["red"]>0 else "idle")

    do_registry_scan()
    do_prefetch_scan()
    do_dns_scan()
    do_process_scan()
    p(); draw_status(); p()
    print_verdict()
    SCAN_RUNNING = False

def cmd_inspect(arg):
    p()
    if not arg:
        p(c(YL)("  Usage: /inspect <jar_path>")); return
    path = arg.strip().strip('"').strip("'")
    if not os.path.isfile(path):
        mc_check = os.path.join(os.path.expandvars(r"%APPDATA%\.minecraft"),"mods",path)
        if os.path.isfile(mc_check): path = mc_check
    if not os.path.isfile(path):
        p(c(RD)(f"  File not found: {path}")); return
    p(c(MG)(f"  Velocity deep scan: {os.path.basename(path)}"))
    p()
    r = analyze_jar(path, paranoid=True)
    for line in format_scan_result(r): p(line)
    if r.verdict in ("CHEAT","SUSPICIOUS"):
        p(c(GR)("  Package tree:"))
        for pkg,cnt in sorted(r.pkg_tree.items(),key=lambda x:-x[1])[:8]:
            p(c(GR)(f"    {pkg:<48} {cnt} classes"))
        if r.infected_classes:
            p(); p(c(GR)("  Infected classes:"))
            for cls_path,hits in r.infected_classes[:8]:
                p(c(YL)(f"    {cls_path}"))
                for h in hits[:3]: p(c(GR)(f"      · {h}"))
    p()

def cmd_open(arg):
    p()
    if not arg or not arg.strip().isdigit():
        if not _openable_refs:
            p(c(YL)("  No open references yet — run a scan first, then /open <n>"))
        else:
            p(c(YL)(f"  Usage: /open <n>   (1-{len(_openable_refs)} from the last scan)"))
        p(); return
    n = int(arg.strip())
    target, err = open_ref(n)
    if err:
        p(c(RD)(f"  ✗  {err}"))
    else:
        note = " (revealed in folder, not executed)" if _openable_refs[n-1]["is_folder"] else ""
        p(c(GN)(f"  ✓ Opened: {target}{note}"))
    p()

def cmd_whitelist(args):
    tokens = args.split() if args else []
    p()
    if not tokens:
        store = load_hash_store("whitelist.json")
        if not store:
            p(c(GR)("  Whitelist empty."))
        else:
            for sha, entry in store.items():
                p(c(WH)(f"  {sha[:16]}...") + c(GR)(f"  {entry.get('path','')}"))
        p(c(GR)("  /whitelist add <n>  |  /whitelist remove <hash-prefix>")); p(); return
    sub = tokens[0].lower()
    if sub == "add" and len(tokens) >= 2 and tokens[1].isdigit():
        n = int(tokens[1])
        if not (1 <= n <= len(_openable_refs)):
            p(c(RD)(f"  ✗  No such reference: {n}")); p(); return
        path = _openable_refs[n-1]["path"]
        sha = sha256(path)
        if not sha:
            p(c(RD)("  ✗  Could not hash that file")); p(); return
        add_to_whitelist(sha, path)
        p(c(GN)(f"  ✓ Whitelisted: {path}"))
        p(c(GR)("  Will never be flagged again, even if renamed"))
        p(); return
    if sub == "remove" and len(tokens) >= 2:
        store = load_hash_store("whitelist.json")
        matches = [h for h in store if h.startswith(tokens[1])]
        if not matches:
            p(c(YL)("  No matching hash")); p(); return
        for h in matches: del store[h]
        save_hash_store("whitelist.json", store)
        p(c(GN)(f"  ✓ Removed {len(matches)} entr(y/ies)")); p(); return
    p(c(YL)("  /whitelist  |  /whitelist add <n>  |  /whitelist remove <hash-prefix>")); p()

def cmd_history():
    p(); section("COMMAND HISTORY"); divider()
    if not _command_history:
        p(c(GR)("  No commands run yet."))
    else:
        for i, cmd in enumerate(_command_history[-30:], 1):
            p(c(GR)(f"  {i:>3}.  ") + c(WH)(cmd))
    p()

def cmd_elevate():
    p()
    if is_admin():
        p(c(GN)("  ✓ Already running as Administrator/root")); p(); return
    try:
        exe  = sys.executable
        script = os.path.abspath(sys.argv[0])
        if os.name == "nt":
            params = f'"{script}"'
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if rc > 32: p(c(GN)("  ✓ Relaunching elevated — this window can be closed"))
            else:       p(c(YL)("  UAC prompt was cancelled or failed"))
        else:
            subprocess.Popen(["sudo", exe, script])
            p(c(GN)("  ✓ Relaunching with sudo — enter your password in the terminal"))
    except Exception as e:
        p(c(RD)(f"  ✗  {e}"))
    p()

def cmd_stats():
    p(); section("SCAN STATS"); divider()
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    try:
        reports = sorted(
            [f for f in os.listdir(desktop) if f.startswith("velocity_report_") and f.endswith(".json")],
            reverse=True)[:10]
    except Exception:
        reports = []
    if not reports:
        p(c(GR)("  No saved reports yet — run a scan first."))
        p(); return
    for fname in reports:
        try:
            data = json.loads(open(os.path.join(desktop, fname)).read())
            red = data.get("summary", {}).get("private_hits", 0)
            ts = fname.replace("velocity_report_", "").replace(".json", "")
            status = c(RD, BOLD)(f"{red} flagged") if red else c(GN)("clean")
            p(c(WH)(f"  {ts}  ") + status)
        except Exception: continue
    p()

def cmd_find(query=None):
    p()
    section("FIND LAUNCHER" + (f"  ·  '{query}'" if query else "  ·  all"))
    divider()
    matches = []
    for name,paths in KNOWN_LAUNCHERS.items():
        if query and query.lower() not in name.lower(): continue
        for path in paths:
            if os.path.isdir(path): matches.append((name,path)); break
    if not matches:
        p(c(YL)(f"  No launchers found")); p(); return
    for i,(name,path) in enumerate(matches,1):
        p(c(WH)(f"  {i}.") + c(CY,BOLD)(f"  {name:<22}") + c(GR)(f"  {path}"))
    p()
    raw = read_line(c(GR)("  Select number: "))
    if raw=="__CTRLC__" or not raw.strip().isdigit(): return
    idx = int(raw.strip())-1
    if not (0<=idx<len(matches)): p(c(YL)("  Invalid.")); return
    sel_name,sel_path = matches[idx]
    instances=[]
    for sub in ["instances","versions",""]:
        idir = os.path.join(sel_path,sub) if sub else sel_path
        if os.path.isdir(idir):
            ds = [d for d in os.listdir(idir) if os.path.isdir(os.path.join(idir,d))]
            if ds: instances=ds; break
    if not instances: instances=["(root)"]
    p()
    p(c(GR)(f"  Instances in {c(CY,BOLD)(sel_name)}:"))
    for i,inst in enumerate(instances,1): p(c(WH)(f"  {i}.  {inst}"))
    p()
    raw = read_line(c(GR)("  Select instance: "))
    if raw=="__CTRLC__" or not raw.strip().isdigit(): return
    idx = int(raw.strip())-1
    if not (0<=idx<len(instances)): p(c(YL)("  Invalid.")); return
    inst_name = instances[idx]
    inst_path = (sel_path if inst_name=="(root)" else
                 os.path.join(sel_path,"instances",inst_name)
                 if os.path.isdir(os.path.join(sel_path,"instances",inst_name))
                 else os.path.join(sel_path,"versions",inst_name))
    p()
    p(c(GR)(f"  Directories in {c(CY)(inst_name)}:"))
    subdir_list = []
    for label,dname in INSTANCE_SUBDIRS.items():
        fp = os.path.join(inst_path,dname)
        exists = os.path.isdir(fp)
        st = c(GN)("✓") if exists else c(GR)("—")
        p(c(WH)(f"  {len(subdir_list)+1}.  {st}  {label:<18}") + c(GR)(f"  {fp}"))
        subdir_list.append((label,fp,exists))
    p()
    raw = read_line(c(GR)("  Open (number) or Enter: "))
    if raw=="__CTRLC__" or not raw.strip(): return
    if raw.strip().isdigit():
        idx = int(raw.strip())-1
        if 0<=idx<len(subdir_list):
            label,open_path,exists = subdir_list[idx]
            if exists: xopen(open_path); p(c(GN)(f"  Opened: {open_path}"))
            else: p(c(YL)(f"  Not found: {open_path}"))
    p()

def cmd_path(args):
    tokens = args.split() if args else []; p()
    if not tokens:
        p(c(CY)("  Opening folder browser..."))
        path = open_folder_dialog()
        if path:
            ghost_state["focus_paths"].append(path)
            p(c(GN)(f"  ✓ Done — focus path set: {path}"))
        else: p(c(YL)("  Cancelled."))
        p(); return
    sub = tokens[0].lower()
    KNOWN_SUBS = {"add","focus","explorer","list","clear","remove"}
    if sub not in KNOWN_SUBS:
        path = args.strip().strip('"')
        if not os.path.isdir(path):
            p(c(RD)(f"  ✗ Invalid path (not found): {path}")); p(); return
        if path not in ghost_state["focus_paths"]:
            ghost_state["focus_paths"].append(path)
        p(c(GN)(f"  ✓ Done — /flash and /pro will focus on: {path}"))
        p(c(GR)("  (/path remove to undo, /path list to view)"))
        p(); return
    if sub=="remove":
        if len(tokens) < 2:
            n = len(ghost_state["focus_paths"])
            ghost_state["focus_paths"].clear()
            p(c(GN)(f"  ✓ Removed {n} focus path(s)")); p(); return
        path = " ".join(tokens[1:]).strip('"')
        if path in ghost_state["focus_paths"]:
            ghost_state["focus_paths"].remove(path)
            p(c(GN)(f"  ✓ Removed: {path}"))
        else:
            p(c(YL)(f"  Not in focus list: {path}"))
        p(); return
    if sub=="add" and len(tokens)>=2:
        path = " ".join(tokens[1:]).strip('"')
        if not os.path.isdir(path): p(c(RD)(f"  ✗ Not found: {path}")); p(); return
        if path not in ghost_state["focus_paths"]:
            ghost_state["focus_paths"].append(path)
        p(c(GN)(f"  ✓ Done — /flash and /pro will focus on: {path}")); p(); return
    if sub=="focus" and len(tokens)>=2:
        fp = " ".join(tokens[1:]).strip('"')
        if fp.lower()=="browse":
            path=open_folder_dialog()
            if path: ghost_state["focus_paths"].append(path); p(c(GN)(f"  ✓ Focus: {path}"))
        elif fp.lower()=="clear":
            ghost_state["focus_paths"].clear(); p(c(GN)("  ✓ Cleared"))
        else:
            if not os.path.exists(fp): p(c(RD)(f"  ✗ Not found: {fp}")); p(); return
            ghost_state["focus_paths"].append(fp); p(c(GN)(f"  ✓ Focus: {fp}"))
        p(); return
    if sub=="explorer":
        path=open_folder_dialog()
        if path: xopen(path)
        p(); return
    if sub=="list":
        for label,key in [("Paths","paths"),("Focus","focus_paths"),("Strings","strings")]:
            p(c(CY,BOLD)(f"  {label}:"))
            for item in ghost_state[key] or ["(none)"]: p(c(WH)(f"    · {item}"))
        p(); return
    if sub=="clear":
        ghost_state["paths"].clear(); ghost_state["focus_paths"].clear()
        ghost_state["strings"].clear(); p(c(GN)("  ✓ Cleared")); p(); return
    p(c(YL)("  /path  |  /path add <p>  |  /path focus <p|browse|clear>  |  /path list  |  /path clear  |  /path explorer"))
    p()

def cmd_strings(args):
    tokens = args.split(None) if args else []
    p()
    if not tokens:
        p(c(YL)("  /strings add <str>  |  /strings add <preset> <path|browse>"))
        p(c(YL)("  /strings list  |  /strings clear")); p(); return

    sub = tokens[0].lower()

    if sub == "add" and len(tokens) >= 2:
        preset_names = [d.name for d in PRESETS_DIR.iterdir() if d.is_dir()] if PRESETS_DIR.is_dir() else []
        if tokens[1] in preset_names:
            preset_name = tokens[1]
            src_arg = tokens[2] if len(tokens) > 2 else "browse"
            if src_arg.lower() == "browse":
                fpath = open_file_dialog(f"Select strings file for preset '{preset_name}'")
            else:
                fpath = " ".join(tokens[2:]).strip('"')
            if not fpath or not os.path.isfile(fpath):
                p(c(RD)("  ✗  No valid file selected")); p(); return
            try:
                if fpath.endswith(".json"):
                    loaded = json.loads(open(fpath).read())
                    new_strings = loaded.get("default_strings", loaded if isinstance(loaded, list) else [])
                else:
                    new_strings = [l.strip() for l in open(fpath).readlines() if l.strip()]
                pdir = PRESETS_DIR / preset_name
                target = pdir / "cheat_strings.json"
                existing = json.loads(target.read_text()) if target.exists() else {"default_strings": []}
                merged = sorted(set(existing.get("default_strings", [])) | set(new_strings))
                target.write_text(json.dumps({"default_strings": merged}, indent=2))
                p(c(GN)(f"  ✓ Done — {len(new_strings)} string(s) merged into preset '{preset_name}'"))
                p(c(GR)(f"  Total strings in preset: {len(merged)}"))
                if preset_name == active_preset["name"]:
                    load_data()
                    p(c(GR)("  (active preset — reloaded into current session)"))
            except Exception as e:
                p(c(RD)(f"  ✗  Failed: {e}"))
            p(); return
        else:
            sig = " ".join(tokens[1:])
            ghost_state["strings"].append(sig)
            p(c(GN)(f"  ✓ Added to session: {sig}")); p(); return

    if sub == "list":
        p(c(CY,BOLD)("  Session strings:"))
        for s in ghost_state["strings"] or ["(none)"]: p(c(WH)(f"    · {s}"))
        p(c(GR)(f"  Active preset default strings: {len(DEFAULT_CHEAT_STRINGS())}"))
        p(); return

    if sub in ("clear","reset"):
        ghost_state["strings"].clear()
        p(c(GN)("  ✓ Session strings cleared")); p(); return

    p(c(YL)("  /strings add <str>  |  /strings add <preset> <path|browse>  |  list  |  clear")); p()

def cmd_ghost(_):
    p()
    if ghost_state["active"]:
        ghost_state["active"]=False; p(c(YL)("  Ghost mode OFF"))
    else:
        if not ghost_state["paths"] and not ghost_state["strings"]:
            p(c(YL)("  Set paths first with /path"))
        else:
            ghost_state["active"]=True; p(c(GN)("  Ghost mode ON"))
            for pp in ghost_state["paths"]: p(c(GR)(f"    path: {pp}"))
            for s in ghost_state["strings"]: p(c(GR)(f"    string: {s}"))
    p()

def cmd_seeterminal():
    p(); section("LIVE TERMINAL"); divider()
    if not terminal_log: p(c(GR)("  No scan output yet."))
    else:
        for line in terminal_log: p(line)
    p()

def cmd_window():
    p()
    try:
        if os.name == "nt":
            subprocess.Popen([sys.executable, os.path.abspath(__file__)],
                             creationflags=subprocess.CREATE_NEW_CONSOLE)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-a", "Terminal", os.path.abspath(__file__)])
        else:
            # Try common Linux terminal emulators
            script = os.path.abspath(__file__)
            for term in ["gnome-terminal", "xterm", "konsole", "xfce4-terminal", "alacritty"]:
                try:
                    subprocess.Popen([term, "--", sys.executable, script])
                    break
                except FileNotFoundError:
                    continue
        p(c(GN)("  ✓ New Velocity window opened"))
    except Exception as e:
        p(c(RD)(f"  Failed: {e}"))
    p()

def cmd_report():
    p(); section("SAVED REPORTS"); divider()
    desktop = os.path.join(os.path.expanduser("~"),"Desktop")
    try:
        reports = sorted(
            [os.path.join(desktop,f) for f in os.listdir(desktop) if f.startswith("velocity_report_") and f.endswith(".json")],
            reverse=True)
    except Exception: reports=[]
    if not reports: p(c(GR)("  No reports on Desktop.")); p(); return
    for i,rp in enumerate(reports,1):
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(rp)).strftime("%Y-%m-%d %H:%M")
        p(c(WH)(f"  {i}.  ") + c(CY)(os.path.basename(rp)) + c(GR)(f"  {mtime}"))
    p()
    raw = read_line(c(GR)("  Open (number) or Enter: "))
    if raw!="__CTRLC__" and raw.strip().isdigit():
        idx=int(raw.strip())-1
        if 0<=idx<len(reports): xopen(reports[idx])
    p()

def cmd_source(args):
    tokens = args.split(None, 1) if args else []
    p()
    if not tokens:
        section("SOURCE — data files")
        divider()
        for key, fname in DATA_FILES.items():
            fpath = DATA_DIR / fname
            size = fpath.stat().st_size if fpath.exists() else 0
            row(key, f"{fpath}  ({size} bytes)", "info")
        p()
        p(c(GR)("  /source view <name>    show file contents"))
        p(c(GR)("  /source verify         check JSON syntax of all data files"))
        p(c(GR)("  /source reset          restore all data files to factory defaults"))
        p(c(GR)("  /source open           open the data folder in Explorer"))
        p(); return

    sub = tokens[0].lower()
    sub_arg = tokens[1] if len(tokens) > 1 else ""

    if sub == "view" and sub_arg in DATA_FILES:
        fpath = DATA_DIR / DATA_FILES[sub_arg]
        try:
            content = fpath.read_text()
            p(c(CY,BOLD)(f"  {fpath}"))
            divider()
            for line in content.splitlines()[:60]:
                p(c(GR)(f"  {line}"))
            if len(content.splitlines()) > 60:
                p(c(DIM,GR)(f"  ... ({len(content.splitlines())-60} more lines, open the file directly to see all)"))
        except Exception as e:
            p(c(RD)(f"  ✗  {e}"))
        p(); return

    if sub == "verify":
        all_ok = True
        for key, fname in DATA_FILES.items():
            fpath = DATA_DIR / fname
            try:
                json.loads(fpath.read_text())
                p(c(GN)(f"  ✓  {fname}  — valid JSON"))
            except Exception as e:
                p(c(RD)(f"  ✗  {fname}  — {e}"))
                all_ok = False
        p()
        if all_ok:
            p(c(GN,BOLD)("  All data files valid — reloading..."))
            load_data()
        else:
            p(c(YL)("  Fix the errors above, then run /source verify again."))
        p(); return

    if sub == "reset":
        for key, fname in DATA_FILES.items():
            default_path = DEFAULTS_DIR / fname
            target_path = DATA_DIR / fname
            if default_path.exists():
                shutil.copy(str(default_path), str(target_path))
        active_preset["name"] = "default"
        active_preset["data"] = load_active_preset("default") or PRESET_DEFAULTS["default"]
        load_data()
        p(c(GN)("  ✓ Done — all data files reset to factory defaults"))
        p(c(GR)("  Active preset reset to 'default'"))
        p(); return

    if sub == "open":
        xopen(str(DATA_DIR))
        p(c(GN)(f"  Opened: {DATA_DIR}"))
        p(); return

    p(c(YL)("  /source  |  /source view <name>  |  /source verify  |  /source reset  |  /source open"))
    p()

def cmd_preset(args):
    tokens = args.split(None) if args else []
    p()
    if not tokens:
        section("PRESET — active: " + active_preset["name"])
        divider()
        if PRESETS_DIR.is_dir():
            for pdir in sorted(PRESETS_DIR.iterdir()):
                if not pdir.is_dir(): continue
                is_active = pdir.name == active_preset["name"]
                marker = c(GN,BOLD)(" ● active") if is_active else ""
                settings_path = pdir / "settings.json"
                desc = ""
                if settings_path.exists():
                    try: desc = json.loads(settings_path.read_text()).get("description","")
                    except Exception: pass
                p(c(CY,BOLD)(f"  {pdir.name:<16}") + c(GR)(f"  {desc}") + marker)
        p()
        p(c(GR)("  /preset create <name> [path]   create a new preset skeleton"))
        p(c(GR)("  /preset remove <name>          delete a preset"))
        p(c(GR)("  /preset load                   browse for a preset folder to load"))
        p(c(GR)("  /preset select <name>          activate a built-in or created preset"))
        p(); return

    sub = tokens[0].lower()

    if sub == "create" and len(tokens) >= 2:
        name = tokens[1]
        if len(tokens) >= 3:
            base_path = " ".join(tokens[2:]).strip('"')
        else:
            p(c(CY)("  Opening folder browser to choose preset location..."))
            base_path = open_folder_dialog(f"Choose location for preset '{name}'")
        if not base_path or not os.path.isdir(base_path):
            p(c(RD)("  ✗  No valid location chosen")); p(); return
        pdir = Path(base_path) / name
        if pdir.exists():
            p(c(YL)(f"  ▲  {pdir} already exists")); p(); return
        pdir.mkdir(parents=True)
        for key, fname in DATA_FILES.items():
            (pdir / fname).write_text(json.dumps(SKELETON_DATA[key], indent=2))
        (pdir / "settings.json").write_text(json.dumps({
            "description": f"Custom preset: {name}",
            "run_log_scan": True, "run_config_scan": True, "run_scanner_scan": True,
            "run_dns_scan": True, "run_process_scan": True,
            "run_registry_scan": False, "run_prefetch_scan": False,
            "paranoid_mode": False, "max_config_depth": 4,
        }, indent=2))
        (pdir / "README.txt").write_text(PRESET_SKELETON_README)
        p(c(GN)(f"  ✓ Done — preset created at {pdir}"))
        p(c(GR)("  Skeleton contains a minimal example client — edit the JSON files,"))
        p(c(GR)("  then /preset load (browse to it) or copy it into presets/ and /preset select"))
        p(); return

    if sub == "remove" and len(tokens) >= 2:
        name = tokens[1]
        pdir = PRESETS_DIR / name
        if name in ("default","defaultflash","defaultpro","defaultmax"):
            p(c(RD)("  ✗  Cannot remove a built-in preset")); p(); return
        if not pdir.is_dir():
            p(c(RD)(f"  ✗  Preset not found: {name}")); p(); return
        shutil.rmtree(pdir)
        p(c(GN)(f"  ✓ Done — preset '{name}' removed"))
        if active_preset["name"] == name:
            active_preset["name"] = "default"
            active_preset["data"] = load_active_preset("default") or PRESET_DEFAULTS["default"]
            p(c(YL)("  Active preset reset to 'default'"))
        p(); return

    if sub == "load":
        p(c(CY)("  Opening folder browser..."))
        chosen = open_folder_dialog("Select a preset folder")
        if not chosen or not os.path.isdir(chosen):
            p(c(YL)("  Cancelled.")); p(); return
        chosen_path = Path(chosen)
        required = set(DATA_FILES.values())
        present = {f.name for f in chosen_path.iterdir() if f.is_file()}
        missing = required - present
        if missing:
            p(c(RD)(f"  ✗  Missing required files: {', '.join(missing)}")); p(); return
        try:
            for key, fname in DATA_FILES.items():
                json.loads((chosen_path / fname).read_text())
        except Exception as e:
            p(c(RD)(f"  ✗  Invalid JSON in preset: {e}")); p(); return
        for key, fname in DATA_FILES.items():
            shutil.copy(str(chosen_path / fname), str(DATA_DIR / fname))
        settings_path = chosen_path / "settings.json"
        active_preset["name"] = chosen_path.name
        active_preset["data"] = json.loads(settings_path.read_text()) if settings_path.exists() else PRESET_DEFAULTS["default"]
        load_data()
        p(c(GN)(f"  ✓ Done — loaded preset '{chosen_path.name}' from {chosen_path}"))
        p(); return

    if sub == "select" and len(tokens) >= 2:
        name = tokens[1]
        pdir = PRESETS_DIR / name
        if not pdir.is_dir():
            p(c(RD)(f"  ✗  Preset not found: {name}"))
            avail = [d.name for d in PRESETS_DIR.iterdir() if d.is_dir()] if PRESETS_DIR.is_dir() else []
            p(c(GR)("  Available: ") + ", ".join(avail))
            p(); return
        try:
            for key, fname in DATA_FILES.items():
                fpath = pdir / fname
                if fpath.exists():
                    json.loads(fpath.read_text())
        except Exception as e:
            p(c(RD)(f"  ✗  Invalid JSON in preset '{name}': {e}")); p(); return
        for key, fname in DATA_FILES.items():
            src = pdir / fname
            if src.exists():
                shutil.copy(str(src), str(DATA_DIR / fname))
        settings_path = pdir / "settings.json"
        active_preset["name"] = name
        active_preset["data"] = json.loads(settings_path.read_text()) if settings_path.exists() else PRESET_DEFAULTS.get(name, PRESET_DEFAULTS["default"])
        load_data()
        p(c(GN)(f"  ✓ Done — active preset: {name}"))
        p(); return

    p(c(YL)("  /preset  |  /preset create <name> [path]  |  /preset remove <name>"))
    p(c(YL)("  /preset load  |  /preset select <name>"))
    p()

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Velocity — Scan Report</title>
<style>
:root {
  --bg: #05070a;
  --panel: #0c1016;
  --panel-border: #1a212b;
  --blue: #2196f3;
  --green: #00e676;
  --yellow: #ffd600;
  --red: #ff3b3b;
  --text: #e8eef5;
  --dim: #7c8b9c;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: radial-gradient(circle at 20% 0%, #0d1420 0%, #05070a 60%);
  color: var(--text);
  font-family: 'Consolas', 'SF Mono', monospace;
  padding: 40px 24px;
  min-height: 100vh;
}
.container { max-width: 1100px; margin: 0 auto; }
.header {
  display: flex; align-items: center; gap: 16px;
  margin-bottom: 32px; padding-bottom: 24px;
  border-bottom: 1px solid var(--panel-border);
}
.title { font-size: 24px; font-weight: 700; letter-spacing: 3px; color: var(--blue); text-shadow: 0 0 20px rgba(33,150,243,0.35); }
.subtitle { color: var(--dim); font-size: 13px; margin-top: 4px; }
.verdict-banner {
  padding: 20px 28px; border-radius: 8px; margin-bottom: 32px;
  font-size: 18px; font-weight: 700; letter-spacing: 1px;
  border: 1px solid;
}
.verdict-clean { background: rgba(0,230,118,0.08); border-color: var(--green); color: var(--green); box-shadow: 0 0 30px rgba(0,230,118,0.15); }
.verdict-warn  { background: rgba(255,214,0,0.08); border-color: var(--yellow); color: var(--yellow); box-shadow: 0 0 30px rgba(255,214,0,0.15); }
.verdict-bad   { background: rgba(255,59,59,0.08); border-color: var(--red); color: var(--red); box-shadow: 0 0 30px rgba(255,59,59,0.18); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
.stat-card {
  background: var(--panel); border: 1px solid var(--panel-border);
  border-radius: 8px; padding: 18px 20px;
}
.stat-value { font-size: 32px; font-weight: 700; }
.stat-label { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
.stat-green { color: var(--green); text-shadow: 0 0 12px rgba(0,230,118,0.4); }
.stat-yellow { color: var(--yellow); text-shadow: 0 0 12px rgba(255,214,0,0.4); }
.stat-red { color: var(--red); text-shadow: 0 0 12px rgba(255,59,59,0.4); }
.stat-blue { color: var(--blue); text-shadow: 0 0 12px rgba(33,150,243,0.4); }
.section { margin-bottom: 28px; }
.section-title {
  font-size: 14px; text-transform: uppercase; letter-spacing: 2px;
  color: var(--blue); margin-bottom: 12px; padding-bottom: 8px;
  border-bottom: 1px solid var(--panel-border);
}
.finding {
  background: var(--panel); border: 1px solid var(--panel-border);
  border-left: 3px solid var(--red); border-radius: 6px;
  padding: 14px 18px; margin-bottom: 10px;
}
.finding-suspicious { border-left-color: var(--yellow); }
.finding-title { font-weight: 700; color: var(--red); margin-bottom: 6px; }
.finding-suspicious .finding-title { color: var(--yellow); }
.finding-meta { color: var(--dim); font-size: 12px; }
.finding-detail { margin-top: 8px; font-size: 13px; color: var(--text); }
.pill {
  display: inline-block; padding: 2px 10px; border-radius: 12px;
  font-size: 11px; font-weight: 700; margin-right: 6px;
}
.pill-red { background: rgba(255,59,59,0.15); color: var(--red); border: 1px solid var(--red); }
.pill-yellow { background: rgba(255,214,0,0.15); color: var(--yellow); border: 1px solid var(--yellow); }
.empty { color: var(--dim); font-style: italic; padding: 12px; }
.footer { text-align: center; color: var(--dim); font-size: 11px; margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--panel-border); }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="title">VELOCITY</div>
      <div class="subtitle">Scan report generated {timestamp}</div>
    </div>
  </div>

  <div class="verdict-banner {verdict_class}">{verdict_text}</div>

  <div class="grid">
    <div class="stat-card"><div class="stat-value stat-blue">{files_scanned}</div><div class="stat-label">Files Scanned</div></div>
    <div class="stat-card"><div class="stat-value stat-blue">{jars_scanned}</div><div class="stat-label">JARs Analyzed</div></div>
    <div class="stat-card"><div class="stat-value stat-green">{clean_count}</div><div class="stat-label">Clean</div></div>
    <div class="stat-card"><div class="stat-value stat-yellow">{suspicious_count}</div><div class="stat-label">Suspicious</div></div>
    <div class="stat-card"><div class="stat-value stat-red">{flagged_count}</div><div class="stat-label">Flagged</div></div>
  </div>

  <div class="section">
    <div class="section-title">Velocity Scanner Detections</div>
    {scanner_html}
  </div>

  <div class="section">
    <div class="section-title">Config Artifacts</div>
    {config_html}
  </div>

  <div class="section">
    <div class="section-title">Log Tampering</div>
    {log_html}
  </div>

  <div class="section">
    <div class="section-title">Network / DNS</div>
    {dns_html}
  </div>

  <div class="footer">Velocity &middot; Generated locally, not uploaded anywhere</div>
</div>
</body>
</html>"""

def generate_dashboard():
    g = scan_counters.get("green",0); y = scan_counters.get("yellow",0)
    r = scan_counters.get("red",0); t = scan_counters.get("total",0); j = scan_counters.get("jars",0)

    if r == 0 and y == 0:
        verdict_class, verdict_text = "verdict-clean", "✓  CLEAN — No cheat indicators found"
    elif r == 0:
        verdict_class, verdict_text = "verdict-warn", f"▲  SUSPICIOUS — {y} item(s) require review"
    else:
        verdict_class, verdict_text = "verdict-bad", f"✗  FLAGGED — {r} cheat indicator(s) detected"

    def esc(s): return str(s).replace("<","&lt;").replace(">","&gt;")

    scanner_html = ""
    for entry in all_findings.get("scanner", []):
        cls = "finding" if entry.get("verdict") == "CHEAT" else "finding finding-suspicious"
        pill = '<span class="pill pill-red">CHEAT</span>' if entry.get("verdict")=="CHEAT" else '<span class="pill pill-yellow">SUSPICIOUS</span>'
        client = esc(entry.get("client","Unknown"))
        conf = entry.get("confidence","")
        path = esc(entry.get("path",""))
        strings = ", ".join(entry.get("strings",[])[:6])
        scanner_html += f"""<div class="{cls}">
          <div class="finding-title">{pill} {client} {f'&middot; {conf}% confidence' if conf else ''}</div>
          <div class="finding-meta">{path}</div>
          <div class="finding-detail">{esc(strings)}</div>
        </div>"""
    if not scanner_html:
        scanner_html = '<div class="empty">No mod-level cheat detections.</div>'

    config_html = ""
    for entry in all_findings.get("config_hits", []):
        client = esc(entry.get("client","Unknown"))
        path = esc(entry.get("path",""))
        config_html += f"""<div class="finding">
          <div class="finding-title"><span class="pill pill-red">CONFIG</span> {client}</div>
          <div class="finding-meta">{path}</div>
        </div>"""
    if not config_html:
        config_html = '<div class="empty">No cheat config artifacts found.</div>'

    log_html = ""
    for entry in all_findings.get("log_hits", []):
        client = esc(entry.get("client","Unknown"))
        term = esc(entry.get("term",""))
        f = esc(entry.get("file",""))
        log_html += f"""<div class="finding">
          <div class="finding-title"><span class="pill pill-red">LOG</span> {client}</div>
          <div class="finding-meta">{f} &middot; matched '{term}'</div>
        </div>"""
    if not log_html:
        log_html = '<div class="empty">No log tampering detected.</div>'

    dns_html = ""
    for entry in all_findings.get("dns_flags", []):
        entry_val = esc(entry.get("entry",""))
        matched = esc(entry.get("matched",""))
        dns_html += f"""<div class="finding">
          <div class="finding-title"><span class="pill pill-red">DNS</span> {entry_val}</div>
          <div class="finding-meta">matched cheat domain: {matched}</div>
        </div>"""
    if not dns_html:
        dns_html = '<div class="empty">No cheat domains in DNS cache.</div>'

    html = DASHBOARD_TEMPLATE.format(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        verdict_class=verdict_class, verdict_text=verdict_text,
        files_scanned=t, jars_scanned=j, clean_count=g,
        suspicious_count=y, flagged_count=r,
        scanner_html=scanner_html, config_html=config_html,
        log_html=log_html, dns_html=dns_html,
    )

    UI_DIR.mkdir(parents=True, exist_ok=True)
    out_path = UI_DIR / f"dashboard_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path

def cmd_dashboard():
    p()
    if not terminal_log:
        p(c(YL)("  No scan data yet — run /flash, /efficient, or /pro first"))
        p(); return
    out_path = generate_dashboard()
    p(c(GN)(f"  ✓ Dashboard generated: {out_path}"))
    try:
        webbrowser.open(f"file://{out_path.resolve()}")
        p(c(GR)("  Opened in default browser"))
    except Exception as e:
        p(c(YL)(f"  Could not auto-open: {e}"))
    p()

def cmd_help():
    p(); section("HELP — commands"); divider()
    cmds = [
        ("/flash",                   "Config→Logs→Scanner→DNS→Process  (.minecraft only)"),
        ("/flash <path>",            "Same, but focused on <path> for this run only"),
        ("/pro",                     "Paranoid · every drive · registry · prefetch"),
        ("/pro <path>",              "Paranoid, but focused on <path> only — skips drive hunt"),
        ("/inspect <jar>",           "Deep Velocity scan on a single JAR"),
        ("/find [name]",             "Launcher browser → instance → open folder"),
        ("/live, /livescan",         "Scan the currently-running Minecraft instance (read-only)"),
        ("/open <n>",                "Open a numbered [n] reference from the last scan's findings"),
        ("/whitelist add <n>",       "Never flag this file again, by hash (survives renames)"),
        ("/whitelist",               "List whitelisted files"),
        ("/history",                 "Show recently run commands"),
        ("/elevate",                 "Relaunch as Administrator via UAC"),
        ("/stats",                   "Quick trend across your last 10 scan reports"),
        ("/dashboard",               "Generate + open HTML report of last scan"),
        ("/source",                  "List data files (cheat_strings, client_profiles, scanner)"),
        ("/source view <name>",      "Print a data file's contents"),
        ("/source verify",           "Check JSON syntax of all data files"),
        ("/source reset",            "Restore all data files to factory defaults"),
        ("/source open",             "Open the data folder in Explorer"),
        ("/preset",                  "List all presets, show active one"),
        ("/preset create <n> [p]",   "Create a new preset skeleton (folder dialog if no path)"),
        ("/preset remove <n>",       "Delete a custom preset"),
        ("/preset load",             "Browse for and load an external preset folder"),
        ("/preset select <n>",       "Activate default/defaultflash/defaultpro/defaultmax/custom"),
        ("/path <path>",             "Permanently focus /flash and /pro on <path>"),
        ("/path add <path>",         "Same as /path <path>"),
        ("/path remove [path]",      "Remove one focus path, or all if none given"),
        ("/path",                    "Open folder dialog to add a permanent focus path"),
        ("/path list / clear",       "Manage paths"),
        ("/path explorer",           "Browse and open a folder"),
        ("/strings add <str>",       "Add custom detection string to session"),
        ("/strings add <preset> <p>","Merge strings from a file into a preset"),
        ("/strings list / clear",    "Manage session strings"),
        ("/ghost",                   "Toggle ghost mode (custom paths/strings)"),
        ("/seeterminal",             "Replay scan log"),
        ("/report",                  "Browse saved JSON reports"),
        ("/window",                  "Open second Velocity window"),
        ("/clear",                   "Clear screen"),
        ("/exit",                    "Exit"),
    ]
    mw = max(len(x[0]) for x in cmds)+2
    for cmd2,desc in cmds:
        p(c(CY,BOLD)(f"  {cmd2:<{mw}}") + c(GR)("  ·  ") + c(WH)(desc))
    p()
    p(c(DIM,GR)("  Pipeline: Phase0·Logs  Phase1·Config  Phase2·Scanner(native)  Phase3·DNS/Process/Registry/Prefetch"))
    p(c(DIM,GR)("  ") + c(GN)("●") + c(DIM,GR)(" clean  ") + c(YL)("●") + c(DIM,GR)(" suspicious  ") +
      c(RD)("●") + c(DIM,GR)(" flagged  ·  ") + scanner_widget())
    p()

def handle_scan_cancel():
    global SCAN_RUNNING
    SCAN_RUNNING = False
    _out_flush(force=True)
    sys.stdout.write("\r\033[K")
    p()
    p(c(YL,BOLD)("  ▲  Scan cancelled (Ctrl+C) — back at the prompt"))
    p()

def repl():
    load_data()
    active_preset["data"] = load_active_preset("default") or PRESET_DEFAULTS["default"]
    banner()
    p(c(GR)("  /help for commands  ·  Tab = autocomplete  ·  Ctrl+C = cancel current scan"))
    p()
    while True:
        gt = c(MG)("[ghost] ") if ghost_state["active"] else ""
        prompt = (c(GR)("  ") + gt + c(MG,BOLD)(">") + c(GR)(" "))
        raw = read_line(prompt)
        if raw=="__CTRLC__":
            p(c(GR)("  Ctrl+C — /exit to quit")); p(); continue
        raw=raw.strip()
        if not raw: continue
        parts=raw.split(None,1)
        command=parts[0].lower()
        arg=parts[1].strip() if len(parts)>1 else ""
        reset_state()
        try:
            if   command=="/help":        cmd_help()
            elif command=="/clear":       banner()
            elif command in ("/exit","/quit"):
                p(c(GR)("  Goodbye.")); p(); sys.exit(0)
            elif command=="/flash":       do_flash(arg)
            elif command=="/pro":         do_pro(arg)
            elif command=="/max":         do_max(arg)
            elif command=="/inspect":     cmd_inspect(arg)
            elif command=="/find":        cmd_find(arg or None)
            elif command in ("/live","/livescan"): do_live()
            elif command=="/open":        cmd_open(arg)
            elif command=="/whitelist":   cmd_whitelist(arg)
            elif command=="/history":     cmd_history()
            elif command=="/elevate":     cmd_elevate()
            elif command=="/stats":       cmd_stats()
            elif command=="/dashboard":   cmd_dashboard()
            elif command=="/source":      cmd_source(arg)
            elif command=="/preset":      cmd_preset(arg)
            elif command=="/path":        cmd_path(arg)
            elif command=="/strings":     cmd_strings(arg)
            elif command=="/ghost":       cmd_ghost(arg)
            elif command=="/seeterminal": cmd_seeterminal()
            elif command=="/report":      cmd_report()
            elif command=="/window":      cmd_window()
            elif command=="/admin":
                p(); p(c(GR)("  /admin  ·  restricted")); p()
            else:
                p(c(YL)(f"  Unknown: {command}  — /help")); p()
        except KeyboardInterrupt:
            handle_scan_cancel()
        except SystemExit:
            raise
        except Exception as e:
            SCAN_RUNNING_FIX = False
            p(); p(c(RD)(f"  ✗  Unexpected error: {e}")); p(c(GR)("  Back at the prompt.")); p()

if __name__=="__main__":
    IS_WIN = os.name == "nt"
    if IS_WIN:
        # Enable ANSI + VT processing + quick-edit off on Windows console
        try:
            kernel32 = ctypes.windll.kernel32
            out_handle = kernel32.GetStdHandle(-11)
            kernel32.SetConsoleMode(out_handle, 7)
            in_handle = kernel32.GetStdHandle(-10)
            current_mode = ctypes.c_uint32()
            kernel32.GetConsoleMode(in_handle, ctypes.byref(current_mode))
            kernel32.SetConsoleMode(in_handle, current_mode.value | 0x0040 | 0x0080)
        except Exception: pass
    else:
        # Linux / macOS — ensure UTF-8 stdout and ANSI is live
        import locale
        try:
            if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
                sys.stdout.reconfigure(encoding="utf-8")
        except Exception: pass
    repl()
