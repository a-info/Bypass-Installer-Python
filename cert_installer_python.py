#!/usr/bin/env python3
"""
Bypass Installer v1 - Python Edition
Dark themed certificate management system for Android emulators
Landscape Edition - CustomTkinter
"""

import os
import sys
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog
import re
import base64
import shutil
import multiprocessing
from pathlib import Path
from enum import Enum
from typing import Optional, List, Dict, Tuple, Any, cast, TYPE_CHECKING
import logging
import winreg
import ctypes
import urllib.request
import socket

if TYPE_CHECKING:
    import customtkinter as ctk # type: ignore

try:
    import customtkinter as ctk # type: ignore
except ImportError:
    print("Missing required package: customtkinter")
    print("Please install: pip install customtkinter cryptography")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ── THEME  (obsidian violet) ───────────────────────────────────────────────────
BG_DEEP    = "#09090b"
BG_PANEL   = "#0f0f12"
BG_CARD    = "#16161a"
BG_CARD2   = "#1f1f24"
BG_ELEV    = "#27272e"
CHIP_BG    = "#1c1c22"
BORDER     = "#2e2e36"
BORDER_HI  = "#3f3f48"
ACCENT     = "#c084fc"
ACCENT2    = "#a855f7"
ACCENT_DIM = "#2e1f42"
ACCENT_GLO = "#c084fc"
SUCCESS    = "#86efac"
SUCCESS_DIM = "#142819"
DANGER     = "#fda4af"
DANGER_BTN = "#e11d48"
DANGER_BTN_H = "#f43f5e"
DANGER_DIM = "#2a1018"
WARN       = "#fde047"
WARN_DIM   = "#2a2410"
TEXT_PRI   = "#fafafa"
TEXT_SEC   = "#a1a1aa"
TEXT_DIM   = "#71717a"
LOG_BG     = "#0c0c0f"
LOG_TEXT   = "#d8b4fe"
# ── FONTS ──────────────────────────────────────────────────────────────────────
_F = "Segoe UI"
FONT_TITLE  = (_F, 18, "bold")
FONT_SUB    = (_F, 9)
FONT_HEAD   = (_F, 10, "bold")
FONT_BODY   = (_F, 10)
FONT_SMALL  = (_F, 9)
FONT_MICRO  = (_F, 8)
FONT_BTN    = (_F, 10, "bold")
FONT_BTN_SM = (_F, 9, "bold")
BTN_H   = 32
BTN_HSM = 30
BTN_HLG = 34
RADIUS  = 6
PAD     = 8
GAP     = 6

def crash_log_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "bypass_installer.log")

def log_fatal(msg: str) -> None:
    try:
        with open(crash_log_path(), "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except Exception:
        pass

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
    except Exception:
        return False

def ensure_admin():
    """Re-launch the process with UAC elevation if not already admin."""
    if sys.platform != "win32":
        return
    if is_admin():
        return
    try:
        if getattr(sys, "frozen", False):
            executable = os.path.abspath(sys.executable)
            work_dir = os.path.dirname(executable)
            params = subprocess.list2cmdline(sys.argv[1:]) if len(sys.argv) > 1 else ""
        else:
            executable = sys.executable
            work_dir = os.path.dirname(os.path.abspath(__file__))
            script = os.path.abspath(sys.argv[0])
            params = subprocess.list2cmdline([script] + sys.argv[1:])

        ret = int(ctypes.windll.shell32.ShellExecuteW(  # type: ignore
            None, "runas", executable, params or None, work_dir, 1
        ))
        if ret <= 32:
            ctypes.windll.user32.MessageBoxW(  # type: ignore
                0,
                "Administrator privileges are required to run Bypass Installer.\n"
                "Please right-click the EXE and choose 'Run as administrator'.",
                "Bypass Installer",
                0x10,
            )
    except Exception as exc:
        log_fatal(f"ensure_admin failed: {exc}")
        try:
            ctypes.windll.user32.MessageBoxW(  # type: ignore
                0,
                f"Could not request Administrator access:\n{exc}",
                "Bypass Installer",
                0x10,
            )
        except Exception:
            pass
    sys.exit(0)

def bring_window_to_front(window: tk.Misc) -> None:
    """Raise a tk window above others and give it keyboard focus (Windows-friendly)."""
    try:
        window.update_idletasks()
        window.deiconify()
        window.lift()
        window.attributes("-topmost", True)
        window.update()
        window.attributes("-topmost", False)
        window.focus_force()
        if sys.platform == "win32":
            hwnd = _win_hwnd(window)
            user32 = ctypes.windll.user32
            user32.BringWindowToTop(hwnd)
            user32.SetForegroundWindow(hwnd)
    except Exception:
        pass

def get_local_ipv4() -> str:
    """Return primary local IPv4 address; fallback to localhost."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "(Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object { $_.IPAddress -notlike '127.*' } | "
                "Select-Object -First 1).IPAddress",
            ],
            capture_output=True, text=True, timeout=5, creationflags=flags,
        )
        ip = (result.stdout or "").strip()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"

class EmulatorType(Enum):
    NONE = "None"
    BLUESTACKS5 = "BlueStacks App Player"
    BLUESTACKS_CN = "BlueStacks China"
    MSI5 = "MSI App Player"

def normalize_cert_hash(value: str) -> Optional[str]:
    value = value.strip().lower()
    if value.endswith(".0"):
        value = value[:-2]
    if re.fullmatch(r"[0-9a-f]{8}", value):
        return value
    return None

def exe_dir() -> str:
    """Directory containing the running app (persistent when frozen)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

def resource_dir() -> str:
    """Directory for bundled read-only assets (PyInstaller _MEIPASS when frozen)."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", exe_dir())
    return os.path.dirname(os.path.abspath(__file__))

def get_cert_cache_dir() -> str:
    cache_dir = os.path.join(exe_dir(), ".cert_cache")
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir

def app_dir() -> str:
    return resource_dir()

def find_logo_path() -> Optional[str]:
    for name in ("logo.ico", "logo.png"):
        path = os.path.join(app_dir(), name)
        if os.path.exists(path):
            return path
    return None

def load_logo_image(size: Tuple[int, int] = (44, 44)):
    path = os.path.join(app_dir(), "logo.png")
    if not os.path.exists(path):
        return None
    try:
        from PIL import Image
        img = Image.open(path).convert("RGBA")
        target = max(1, int(min(size) * 0.94))
        img.thumbnail((target, target), Image.Resampling.LANCZOS)
        canvas = Image.new("RGBA", size, (0, 0, 0, 0))
        ox = (size[0] - img.width) // 2
        oy = (size[1] - img.height) // 2
        canvas.paste(img, (ox, oy), img)
        return ctk.CTkImage(light_image=canvas, dark_image=canvas, size=size)
    except Exception:
        return None

def set_window_icon(window: tk.Misc) -> None:
    path = find_logo_path()
    if not path:
        return
    try:
        if path.lower().endswith(".ico"):
            window.iconbitmap(default=path)
        elif path.lower().endswith(".png"):
            icon = tk.PhotoImage(file=path)
            window.iconphoto(True, icon)
            window._logo_icon_ref = icon  # type: ignore[attr-defined]
    except Exception:
        pass

def set_app_user_model_id() -> None:
    """Help Windows show the correct taskbar icon for this process."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("BypassInstaller.App.1")  # type: ignore
    except Exception:
        pass

def _win_hwnd(window: tk.Misc) -> int:
    window.update_idletasks()
    hwnd = int(window.winfo_id())
    try:
        GA_ROOT = 2
        root = ctypes.windll.user32.GetAncestor(hwnd, GA_ROOT)  # type: ignore
        if root:
            return int(root)
    except Exception:
        pass
    parent = ctypes.windll.user32.GetParent(hwnd)  # type: ignore
    return int(parent) if parent else hwnd

def apply_native_frameless(window: tk.Misc) -> None:
    """Borderless look while keeping a normal Windows taskbar button and clickable UI."""
    if sys.platform != "win32":
        return
    try:
        hwnd = _win_hwnd(window)
        user32 = ctypes.windll.user32
        gwl_style = -16
        gwl_exstyle = -20
        ws_caption = 0x00C00000
        ws_sysmenu = 0x00080000
        ws_maximizebox = 0x00010000
        ws_minimizebox = 0x00020000
        ws_ex_appwindow = 0x00040000
        ws_ex_toolwindow = 0x00000080

        style = user32.GetWindowLongW(hwnd, gwl_style)
        style &= ~(ws_caption | ws_sysmenu | ws_maximizebox)
        style |= ws_minimizebox
        user32.SetWindowLongW(hwnd, gwl_style, style)

        ex_style = user32.GetWindowLongW(hwnd, gwl_exstyle)
        ex_style &= ~ws_ex_toolwindow
        ex_style |= ws_ex_appwindow
        user32.SetWindowLongW(hwnd, gwl_exstyle, ex_style)

        swp_nomove = 0x0002
        swp_nosize = 0x0001
        swp_nozorder = 0x0004
        swp_framechanged = 0x0020
        user32.SetWindowPos(
            hwnd, 0, 0, 0, 0, 0,
            swp_nomove | swp_nosize | swp_nozorder | swp_framechanged,
        )
    except Exception as exc:
        log_fatal(f"apply_native_frameless failed: {exc}")

def ensure_taskbar_icon(window: tk.Misc) -> None:
    """Legacy hook — native frameless keeps the taskbar button visible."""
    if sys.platform != "win32":
        return
    try:
        window.update_idletasks()
        window.wm_attributes("-toolwindow", False)
    except Exception:
        pass

class CertificateManager:
    """Manages certificate installation and emulator operations"""
    
    def __init__(self):
        self.selected_emulator = EmulatorType.NONE
        self.adb_port = "5555"
        self.certificate_path = ""
        self.cert_hash = ""
        self.custom_cert_hash = "c8750f0d.0"
        self.proxy_address = f"{get_local_ipv4()}:8080"
        self.proxy_applied = False
        self.active_proxy = ""
        self.is_connected = False
        self.last_error = ""
        self.emulator_name = "None"
        self.emulator_version = "None"
        self.adb_path = "adb"
        
    def _normalize_adb_path(self, path: str) -> str:
        return path.strip().strip('"').strip("'")

    def _adb_target(self) -> str:
        return f"127.0.0.1:{self.adb_port.strip()}"

    def _list_online_devices(self) -> List[str]:
        try:
            res = self._run_adb("devices", timeout=10)
            devices: List[str] = []
            for line in (res.stdout or "").splitlines():
                line = line.strip()
                if line and not line.lower().startswith("list of devices"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "device":
                        devices.append(parts[0])
            return devices
        except Exception:
            return []

    def _is_target_online(self) -> bool:
        target = self._adb_target()
        return any(d == target or d.endswith(f":{self.adb_port.strip()}") for d in self._list_online_devices())

    def _run_adb(self, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
        if not os.path.isfile(self.adb_path):
            self.resolve_adb_path()
        cmd = [self.adb_path, *args]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=flags,
        )

    def _adb_shell(self, command: str, timeout: int = 15) -> subprocess.CompletedProcess:
        return self._run_adb("-s", self._adb_target(), "shell", command, timeout=timeout)

    def _adb_err(self, result: subprocess.CompletedProcess) -> str:
        return ((result.stderr or "") + (result.stdout or "")).strip()

    def resolve_adb_path(self, log_cb=None) -> bool:
        def log(msg: str, color: Optional[str] = None):
            if log_cb:
                log_cb(msg, color)

        self.adb_path = self._normalize_adb_path(self.adb_path)

        if self.selected_emulator != EmulatorType.NONE:
            info = self.get_emulator_info(self.selected_emulator)
            emu_adb = self._normalize_adb_path(str(info.get("adb_path", "")))
            if emu_adb and os.path.isfile(emu_adb):
                self.adb_path = emu_adb
                log(f"ADB: {self.adb_path}")
                return True

        if self.adb_path == "adb" or not os.path.isfile(self.adb_path):
            found = shutil.which("adb")
            if found:
                self.adb_path = found
                log(f"ADB (PATH): {self.adb_path}")
                return True

            search_paths = [
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", "adb.exe"),
                r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe",
                r"C:\Program Files\BlueStacks_nxt_cn\HD-Adb.exe",
                r"C:\Program Files\BlueStacks_msi5\HD-Adb.exe",
                r"C:\Program Files\Bluestacks_msi5\HD-Adb.exe",
                os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_nxt", "Engine", "HD-Adb.exe"),
                "C:\\adb\\adb.exe",
            ]
            for p in search_paths:
                if os.path.isfile(p):
                    self.adb_path = p
                    log(f"ADB (found): {self.adb_path}")
                    return True

        if os.path.isfile(self.adb_path):
            log(f"ADB: {self.adb_path}")
            return True

        self.last_error = "ADB not found — run emulator first or install platform-tools"
        log(f"✕ {self.last_error}", "err")
        return False

    def check_adb_exists(self) -> bool:
        try:
            if not os.path.isfile(self.adb_path):
                if self.adb_path == "adb":
                    found = shutil.which("adb")
                    if not found:
                        return False
                    self.adb_path = found
                else:
                    return False
            result = self._run_adb("version", timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def get_emulator_paths(self) -> Dict[EmulatorType, str]:
        paths: Dict[EmulatorType, str] = {}
        try:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BlueStacks_nxt") as key:
                    val, _ = winreg.QueryValueEx(key, "InstallDir")
                    install_dir = str(val)
                    hd_player_path = os.path.join(install_dir, "HD-Player.exe")
                    if os.path.exists(hd_player_path):
                        paths[EmulatorType.BLUESTACKS5] = hd_player_path
            except (FileNotFoundError, OSError):
                default_bs5 = r"C:\Program Files\BlueStacks_nxt\HD-Player.exe"
                if os.path.exists(default_bs5):
                    paths[EmulatorType.BLUESTACKS5] = default_bs5
            
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BlueStacks_nxt_cn") as key:
                    val, _ = winreg.QueryValueEx(key, "InstallDir")
                    install_dir = str(val)
                    hd_player_path = os.path.join(install_dir, "HD-Player.exe")
                    if os.path.exists(hd_player_path):
                        paths[EmulatorType.BLUESTACKS_CN] = hd_player_path
            except (FileNotFoundError, OSError):
                default_bs5_cn = r"C:\Program Files\BlueStacks_nxt_cn\HD-Player.exe"
                if os.path.exists(default_bs5_cn):
                    paths[EmulatorType.BLUESTACKS_CN] = default_bs5_cn
            
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BlueStacks_msi5") as key:
                    val, _ = winreg.QueryValueEx(key, "InstallDir")
                    install_dir = str(val)
                    hd_player_path = os.path.join(install_dir, "HD-Player.exe")
                    if os.path.exists(hd_player_path):
                        paths[EmulatorType.MSI5] = hd_player_path
            except (FileNotFoundError, OSError):
                for default_msi5 in (
                    r"C:\Program Files\Bluestacks_msi5\HD-Player.exe",
                    r"C:\Program Files\BlueStacks_msi5\HD-Player.exe",
                ):
                    if os.path.exists(default_msi5):
                        paths[EmulatorType.MSI5] = default_msi5
                        break
        except Exception as e:
            logger.error(f"Error accessing registry: {e}")
        return paths
    
    def get_emulator_info(self, emulator_type: EmulatorType) -> Dict[str, str]:
        info: Dict[str, str] = {"name": str(emulator_type.value), "version": "Not Found", "path": "", "adb_path": "adb"}
        try:
            if emulator_type == EmulatorType.BLUESTACKS5:
                reg_path = r"SOFTWARE\BlueStacks_nxt"
            elif emulator_type == EmulatorType.BLUESTACKS_CN:
                reg_path = r"SOFTWARE\BlueStacks_nxt_cn"
            elif emulator_type == EmulatorType.MSI5:
                reg_path = r"SOFTWARE\BlueStacks_msi5"
            else:
                return info
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                val, _ = winreg.QueryValueEx(key, "InstallDir")
                install_dir = str(val)
                info["path"] = os.path.join(install_dir, "HD-Player.exe")
                info["adb_path"] = os.path.join(install_dir, "HD-Adb.exe")
                try:
                    ver_val, _ = winreg.QueryValueEx(key, "Version")
                    info["version"] = str(ver_val)
                except:
                    info["version"] = "Detected"
        except:
            paths = self.get_emulator_paths()
            if emulator_type in paths:
                info["path"] = paths[emulator_type]
                info["adb_path"] = os.path.join(os.path.dirname(paths[emulator_type]), "HD-Adb.exe")
                info["version"] = "Detected (Default Path)"
        
        adb_p = str(info.get("adb_path", "adb"))
        if not os.path.exists(adb_p):
            info["adb_path"] = "adb"
        return info
    
    def select_emulator(self, emulator_type: EmulatorType) -> bool:
        self.selected_emulator = emulator_type
        info = self.get_emulator_info(emulator_type)
        self.emulator_name = info["name"]
        self.emulator_version = info["version"]
        self.adb_path = info["adb_path"]
        detected_port = self.detect_adb_port(emulator_type)
        if detected_port:
            self.adb_port = detected_port
            return True
        return False

    def detect_adb_port(self, emulator_type: EmulatorType) -> Optional[str]:
        try:
            config_paths: List[str] = []
            if emulator_type == EmulatorType.BLUESTACKS5:
                program_data = os.environ.get("ProgramData", "C:\\ProgramData")
                config_paths = [os.path.join(program_data, "BlueStacks_nxt", "bluestacks.conf")]
            elif emulator_type == EmulatorType.BLUESTACKS_CN:
                program_data = os.environ.get("ProgramData", "C:\\ProgramData")
                config_paths = [os.path.join(program_data, "BlueStacks_nxt_cn", "bluestacks.conf")]
            elif emulator_type == EmulatorType.MSI5:
                program_data = os.environ.get("ProgramData", "C:\\ProgramData")
                config_paths = [
                    os.path.join(program_data, "BlueStacks_msi5", "bluestacks.conf"),
                    os.path.join(program_data, "Bluestacks_msi5", "bluestacks.conf"),
                ]
            
            for config_path in config_paths:
                if not os.path.exists(config_path):
                    continue
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                matches = re.findall(r'(?:^|\.)adb_port="(\d+)"', content, re.MULTILINE)
                if not matches:
                    matches = re.findall(r'adb_port="(\d+)"', content)
                if matches:
                    return matches[-1]
        except Exception as e:
            logger.error(f"Port detection failed: {e}")
        return None
    
    def force_kill_emulators(self) -> bool:
        try:
            processes = ["HD-Player.exe", "BlueStacks.exe", "BstkSVC.exe", 
                        "HD-MultiInstanceManager.exe", "MSIAppPlayer.exe",
                        "BlueStacksService.exe", "BstkAgent.exe"]
            for proc in processes:
                subprocess.run(f"taskkill /F /IM {proc} /T", capture_output=True, shell=True)
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def get_access(self) -> bool:
        if self.selected_emulator == EmulatorType.NONE:
            self.last_error = "No emulator selected"
            return False
        info = self.get_emulator_info(self.selected_emulator)
        exe_path = info["path"]
        if not exe_path or not os.path.exists(exe_path):
            self.last_error = f"Executable not found at {exe_path}"
            return False
        try:
            subprocess.Popen(f'"{exe_path}"', shell=True)
            return True
        except Exception as e:
            self.last_error = str(e)
            return False
    
    def connect_adb(self, log_cb=None) -> bool:
        def log(msg: str, color: Optional[str] = None):
            if log_cb:
                log_cb(msg, color)

        if not self.resolve_adb_path(log_cb):
            return False

        target = f"127.0.0.1:{self.adb_port}"
        try:
            log(f"Starting ADB server...")
            srv = self._run_adb("start-server", timeout=15)
            if srv.stderr.strip():
                log(f"Server note: {srv.stderr.strip()}", "warn")
            if srv.returncode != 0 and srv.stdout.strip():
                log(f"Server: {srv.stdout.strip()}", "warn")

            log(f"Connecting → {target}")
            self._run_adb("disconnect", target, timeout=5)
            result = self._run_adb("connect", target, timeout=20)

            out = (result.stdout or "").strip()
            err = (result.stderr or "").strip()
            combined = f"{out}\n{err}".lower()
            if out:
                log(f"Reply: {out}")
            if err:
                log(f"ADB stderr: {err}", "err" if result.returncode != 0 else "warn")

            connected = (
                "connected" in combined
                or "already connected" in combined
                or self._is_target_online()
            )
            if connected:
                log("Waiting for device...")
                try:
                    self._run_adb("-s", target, "wait-for-device", timeout=20)
                except subprocess.TimeoutExpired:
                    log("wait-for-device timed out — checking device state...", "warn")
                if self.is_adb_ready():
                    self.is_connected = True
                    log(f"✓ Connected on port {self.adb_port}", "ok")
                    return True
                self.last_error = "Device visible but not responding to shell"
                log(f"✕ {self.last_error}", "err")
                log("Tip: restart emulator → Get Access → Connect ADB", "warn")
                self.is_connected = False
                return False

            self.last_error = out or err or "Connection refused — is emulator running?"
            log(f"✕ Connect failed: {self.last_error}", "err")
            log("Tip: open emulator with Get Access, then Connect ADB", "warn")
            self.is_connected = False
            return False
        except subprocess.TimeoutExpired:
            self.last_error = "ADB connection timed out (20s)"
            log(f"✕ {self.last_error}", "err")
            self.is_connected = False
            return False
        except FileNotFoundError:
            self.last_error = f"ADB executable missing: {self.adb_path}"
            log(f"✕ {self.last_error}", "err")
            self.is_connected = False
            return False
        except Exception as e:
            self.last_error = str(e)
            log(f"✕ Connect error: {e}", "err")
            self.is_connected = False
            return False

    def disconnect_adb(self) -> bool:
        try:
            target = f"127.0.0.1:{self.adb_port}"
            self._run_adb("disconnect", target, timeout=5)
            self.is_connected = False
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def is_adb_ready(self) -> bool:
        """Check whether current ADB target is reachable and responsive."""
        if not self._is_target_online():
            return False
        target = self._adb_target()
        try:
            state_res = self._run_adb("-s", target, "get-state", timeout=8)
            state_out = (state_res.stdout or state_res.stderr or "").lower()
            if "device" in state_out:
                return True
            ping_res = self._run_adb("-s", target, "shell", "echo ok", timeout=8)
            return "ok" in (ping_res.stdout or "").lower()
        except Exception:
            return self._is_target_online()

    def ensure_adb_connection(self, log_cb=None) -> bool:
        """Guarantee a usable ADB session, auto-reconnecting when stale."""
        if self.is_connected and self.is_adb_ready():
            return True
        self.is_connected = False
        return self.connect_adb(log_cb=log_cb)

    def calculate_cert_hash(self) -> Optional[str]:
        if not self.certificate_path or not os.path.exists(self.certificate_path):
            return None
        for inform in ("PEM", "DER"):
            try:
                cmd = (
                    f'openssl x509 -inform {inform} -subject_hash_old '
                    f'-in "{self.certificate_path}" -noout'
                )
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
                if result.returncode == 0:
                    self.cert_hash = result.stdout.strip()
                    return self.cert_hash
            except:
                pass
        self.cert_hash = "c8750f0d"
        return self.cert_hash

    def get_cert_hash(self) -> str:
        custom = normalize_cert_hash(self.custom_cert_hash)
        if custom:
            self.cert_hash = custom
            return custom
        computed = self.calculate_cert_hash()
        if computed:
            return computed
        return "c8750f0d"

    def load_pasted_certificate(self, text: str) -> Tuple[bool, str]:
        raw = text.strip().strip('"').strip("'")
        if not raw:
            return False, "Clipboard is empty."

        file_candidate = raw.splitlines()[0].strip().strip('"').strip("'")
        if os.path.isfile(file_candidate):
            self.certificate_path = os.path.abspath(file_candidate)
            return True, self.certificate_path

        cache_dir = get_cert_cache_dir()
        if "BEGIN CERTIFICATE" in raw:
            out_path = os.path.join(cache_dir, "pasted-cert.pem")
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(raw if raw.endswith("\n") else raw + "\n")
            self.certificate_path = out_path
            return True, out_path

        cleaned = re.sub(r"\s+", "", raw)
        if re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned):
            try:
                der_data = base64.b64decode(cleaned, validate=True)
                out_path = os.path.join(cache_dir, "pasted-cert.cer")
                with open(out_path, "wb") as f:
                    f.write(der_data)
                self.certificate_path = out_path
                return True, out_path
            except Exception:
                pass

        if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
            try:
                der_data = bytes.fromhex(cleaned)
                out_path = os.path.join(cache_dir, "pasted-cert.cer")
                with open(out_path, "wb") as f:
                    f.write(der_data)
                self.certificate_path = out_path
                return True, out_path
            except Exception:
                pass

        return False, "Unsupported clipboard content. Paste PEM text or a cert file path."

    def apply_cert_selection(self, path: str, log_cb=None) -> None:
        def log(msg: str):
            if log_cb:
                log_cb(msg)

        self.certificate_path = path
        base = os.path.basename(path).lower()
        if re.fullmatch(r"[0-9a-f]{8}\.0", base):
            self.custom_cert_hash = base
            log(f"Custom hash from file: {base}")
            return

        computed = self.calculate_cert_hash()
        if computed:
            self.custom_cert_hash = f"{computed}.0"
            log(f"Auto hash: {computed}.0")

    def bypass_access(self) -> bool:
        try:
            program_data = os.environ.get("ProgramData", "C:\\ProgramData")
            engine_root = ""
            
            if self.selected_emulator == EmulatorType.MSI5:
                options = ["BlueStacks_msi5", "Bluestacks_msi5"]
            elif self.selected_emulator == EmulatorType.BLUESTACKS_CN:
                options = ["BlueStacks_nxt_cn", "BlueStacks_nxt", "BlueStacks"]
            else:
                options = ["BlueStacks_nxt", "BlueStacks_nxt_cn", "BlueStacks"]
                
            for opt in options:
                path = os.path.join(program_data, opt, "Engine")
                if os.path.exists(path):
                    engine_root = path
                    break
            
            if not engine_root:
                self.last_error = "Engine root path not found"
                return False
                
            for instance_dir in os.listdir(engine_root):
                dir_path = os.path.join(engine_root, instance_dir)
                if not os.path.isdir(dir_path): continue
                
                configs = [
                    os.path.join(dir_path, "Android.bstk.in"),
                    os.path.join(dir_path, f"{instance_dir}.bstk"),
                    os.path.join(dir_path, f"{instance_dir}.bstk-prev")
                ]
                
                for conf in configs:
                    if os.path.exists(conf):
                        with open(conf, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        content = re.sub(r'(<HardDisk\b[^>]*location\s*=\s*"Root\.vhd"[^>]*type\s*=\s*")Readonly(")', r'\1Normal\2', content, flags=re.IGNORECASE)
                        content = re.sub(r'(<HardDisk\b[^>]*location\s*=\s*"Data\.vhdx"[^>]*type\s*=\s*")Readonly(")', r'\1Normal\2', content, flags=re.IGNORECASE)
                        with open(conf, "w", encoding="utf-8") as f:
                            f.write(content)
            
            manager_dir = os.path.join(engine_root, "Manager")
            if os.path.exists(manager_dir):
                for f in os.listdir(manager_dir):
                    if f.startswith("BstkServer.log"):
                        try: os.remove(os.path.join(manager_dir, f))
                        except: pass
            
            for instance_dir in os.listdir(engine_root):
                logs_dir = os.path.join(engine_root, instance_dir, "Logs")
                if os.path.exists(logs_dir):
                    for f in os.listdir(logs_dir):
                        if f.startswith("BstkCore.log"):
                            try: os.remove(os.path.join(logs_dir, f))
                            except: pass
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def install_certificate(self, log_cb=None) -> bool:
        def log(m):
            if log_cb: log_cb(m)
            logger.info(m)
            
        try:
            final_path = self.certificate_path
            if not final_path or not os.path.exists(final_path):
                fallbacks = ["mitmproxy-ca-cert.cer", "ca.cer", "cert.0"]
                found = False
                for fb in fallbacks:
                    if os.path.exists(fb):
                        final_path = os.path.abspath(fb)
                        self.certificate_path = final_path
                        found = True
                        log(f"Auto-detect: {fb}")
                        break
                if not found:
                    self.last_error = "No certificate file found."
                    return False
            else:
                final_path = os.path.abspath(final_path)

            log("Computing certificate hash...")
            hash_val = self.get_cert_hash()
            cert_name = f"{hash_val}.0"
            log(f"Target: {cert_name}")

            if not self.ensure_adb_connection(log_cb):
                log(f"✕ ADB not connected: {self.last_error}", "err")
                return False

            log(f"Pushing → /sdcard/{cert_name}")
            remote_sd = f"/sdcard/{cert_name}"
            try:
                push_res = self._run_adb("-s", self._adb_target(), "push", final_path, remote_sd, timeout=60)
                if push_res.returncode != 0:
                    self.last_error = f"Push failed: {self._adb_err(push_res)}"
                    log(f"✕ {self.last_error}", "err")
                    return False
            except subprocess.TimeoutExpired:
                self.last_error = "ADB push timed out."
                log(f"✕ {self.last_error}", "err")
                return False

            su_path = "/boot/android/android/system/xbin/bstk/su"
            cert_sys = f"/system/etc/security/cacerts/{cert_name}"

            log("Injecting into system store...")
            install_cmd = (
                f"{su_path} -c 'mount -o rw,remount /dev/sda1 /system && "
                f"cp {remote_sd} {cert_sys} && "
                f"chmod 644 {cert_sys} && "
                f"chcon u:object_r:system_file:s0 {cert_sys} && "
                f"mount -o ro,remount /dev/sda1 /system && "
                f"rm {remote_sd} && sync'"
            )

            try:
                exec_res = self._adb_shell(install_cmd, timeout=30)
                if exec_res.returncode != 0:
                    log("Primary su failed, trying fallback...")
                    fallback_cmd = (
                        "su -c 'mount -o rw,remount /dev/sda1 /system && "
                        f"cp {remote_sd} {cert_sys} && chmod 644 {cert_sys} && "
                        f"chcon u:object_r:system_file:s0 {cert_sys} && "
                        f"mount -o ro,remount /dev/sda1 /system && rm {remote_sd} && sync'"
                    )
                    exec_res = self._adb_shell(fallback_cmd, timeout=30)
                    if exec_res.returncode != 0:
                        self.last_error = f"Injection denied: {self._adb_err(exec_res)}"
                        log(f"✕ {self.last_error}", "err")
                        return False
            except subprocess.TimeoutExpired:
                self.last_error = "Injection timed out."
                log(f"✕ {self.last_error}", "err")
                return False

            time.sleep(1)
            log("Verifying installation...")
            check_res = self._adb_shell(f"[ -f {cert_sys} ] && echo yes", timeout=10)

            if "yes" not in (check_res.stdout or ""):
                self.last_error = "Verification failed: file missing from system."
                log(f"✕ {self.last_error}", "err")
                return False

            log("Refreshing Android services...")
            try:
                self._adb_shell("stop && sleep 2 && start", timeout=15)
            except Exception:
                pass

            return True
        except Exception as e:
            self.last_error = f"Installer error: {str(e)}"
            log(f"✕ {self.last_error}", "err")
            return False

    def uninstall_certificate(self, log_cb=None) -> bool:
        def log(m):
            if log_cb: log_cb(m)
            logger.info(m)
            
        if not self.ensure_adb_connection(log_cb):
            log(f"✕ ADB not connected: {self.last_error}", "err")
            return False

        try:
            hash_val = self.get_cert_hash()
            cert_name = f"{hash_val}.0"
            log(f"Removing {cert_name}...")

            su_path = "/boot/android/android/system/xbin/bstk/su"
            cert_sys = f"/system/etc/security/cacerts/{cert_name}"

            uninstall_cmd = (
                f"{su_path} -c 'mount -o rw,remount /dev/sda1 /system && "
                f"rm -f {cert_sys} && "
                f"mount -o ro,remount /dev/sda1 /system && sync'"
            )

            res = self._adb_shell(uninstall_cmd, timeout=25)
            if res.returncode != 0:
                fallback = (
                    "su -c 'mount -o rw,remount /dev/sda1 /system && "
                    f"rm -f {cert_sys} && mount -o ro,remount /dev/sda1 /system && sync'"
                )
                res = self._adb_shell(fallback, timeout=25)
                if res.returncode != 0:
                    self.last_error = f"Remove failed: {self._adb_err(res)}"
                    log(f"✕ {self.last_error}", "err")
                    return False

            log("Refreshing UI...")
            try:
                self._adb_shell("stop && sleep 2 && start", timeout=15)
            except Exception:
                pass

            return True
        except Exception as e:
            self.last_error = str(e)
            log(f"✕ {self.last_error}", "err")
            return False

    def find_proxy_address(self, port: str = "8080") -> str:
        """Build proxy address from local IPv4 and port."""
        port = (port or "8080").strip() or "8080"
        return f"{get_local_ipv4()}:{port}"

    def get_device_proxy(self) -> Optional[str]:
        """Read active HTTP proxy from the connected emulator."""
        if not self.is_connected:
            return None
        try:
            res = self._adb_shell("settings get global http_proxy", timeout=10)
            addr = (res.stdout or res.stderr or "").strip()
            if addr and addr.lower() not in ("null", ":0", "0", "none"):
                return addr
        except Exception:
            pass
        return None

    def _put_device_proxy(self, addr: str) -> bool:
        """Apply proxy on device — tries direct shell then BlueStacks su."""
        cmds = [
            f"settings put global http_proxy {addr}",
            f"/boot/android/android/system/xbin/bstk/su -c 'settings put global http_proxy {addr}'",
            f"su -c 'settings put global http_proxy {addr}'",
        ]
        last_err = ""
        for cmd in cmds:
            res = self._adb_shell(cmd, timeout=15)
            if res.returncode == 0:
                time.sleep(0.3)
                current = self.get_device_proxy()
                if current and current not in (":0", "null") and (
                    current == addr or addr in current or current in addr
                ):
                    return True
                if res.returncode == 0:
                    return True
            last_err = self._adb_err(res) or last_err
        self.last_error = last_err or "Proxy command failed on device"
        return False

    def apply_proxy(self, log_cb=None) -> bool:
        def log(msg: str, color: Optional[str] = None):
            if log_cb:
                log_cb(msg, color)

        if not self.ensure_adb_connection(log_cb):
            self.last_error = self.last_error or "ADB not connected"
            log(f"✕ Proxy failed: {self.last_error}", "err")
            return False
        try:
            addr = self.proxy_address.strip()
            if not addr:
                addr = self.find_proxy_address()
            log(f"Applying proxy → {addr}")
            if not self._put_device_proxy(addr):
                log(f"✕ {self.last_error}", "err")
                return False
            self.proxy_applied = True
            self.active_proxy = addr
            self.proxy_address = addr
            return True
        except Exception as e:
            self.last_error = str(e)
            log(f"✕ Proxy error: {e}", "err")
            return False

    def clear_proxy(self, log_cb=None) -> bool:
        def log(msg: str, color: Optional[str] = None):
            if log_cb:
                log_cb(msg, color)

        if not self.ensure_adb_connection(log_cb):
            self.last_error = self.last_error or "ADB not connected"
            log(f"✕ Clear proxy failed: {self.last_error}", "err")
            return False
        try:
            su = "/boot/android/android/system/xbin/bstk/su"
            cmds = [
                "settings put global http_proxy :0",
                f"{su} -c 'settings put global http_proxy :0'",
                f"{su} -c 'settings delete global global_http_proxy_host'",
                f"{su} -c 'settings delete global global_http_proxy_port'",
                "su -c 'settings put global http_proxy :0'",
            ]
            for c in cmds:
                self._adb_shell(c, timeout=10)
            self.proxy_applied = False
            self.active_proxy = ""
            return True
        except Exception as e:
            self.last_error = str(e)
            log(f"✕ Clear proxy error: {e}", "err")
            return False


# ── CUSTOM WIDGETS ─────────────────────────────────────────────────────────────

_BTN_VARIANTS = {
    "primary":   {"fg_color": ACCENT,      "hover_color": ACCENT2,     "text_color": BG_DEEP,  "glow": ACCENT_GLO},
    "secondary": {"fg_color": BG_ELEV,     "hover_color": BORDER_HI,   "text_color": TEXT_PRI, "glow": ACCENT_GLO},
    "outline":   {"fg_color": BG_CARD2,    "hover_color": ACCENT_DIM,  "text_color": TEXT_PRI, "glow": ACCENT_GLO},
    "danger":    {"fg_color": DANGER_BTN,  "hover_color": DANGER_BTN_H,"text_color": TEXT_PRI, "glow": DANGER},
}


class TitleButton(ctk.CTkButton):
    def __init__(self, master, hover_color: str, **kwargs):
        kwargs.setdefault("width", 34)
        kwargs.setdefault("height", 28)
        kwargs.setdefault("corner_radius", 4)
        kwargs.setdefault("fg_color", BG_PANEL)
        kwargs.setdefault("hover_color", hover_color)
        kwargs.setdefault("text_color", TEXT_SEC)
        kwargs.setdefault("font", (_F, 13))
        kwargs.setdefault("border_width", 0)
        super().__init__(master, **kwargs)
        self._title_btn = True


class GlowButton(ctk.CTkButton):
    def __init__(self, master, variant="primary", glow_color=None, **kwargs):
        style = _BTN_VARIANTS.get(variant, _BTN_VARIANTS["primary"])
        glow = glow_color or style["glow"]
        kwargs.setdefault("corner_radius", RADIUS)
        kwargs.setdefault("border_width", 0)
        kwargs.setdefault("fg_color", kwargs.pop("fg_color", style["fg_color"]))
        kwargs.setdefault("hover_color", kwargs.pop("hover_color", style["hover_color"]))
        kwargs.setdefault("text_color", kwargs.pop("text_color", style["text_color"]))
        kwargs.setdefault("font", FONT_BTN_SM)
        kwargs.setdefault("height", kwargs.pop("height", BTN_H))
        kwargs.setdefault("anchor", "center")
        self._base_fg = kwargs["fg_color"]
        self._hover_fg = kwargs["hover_color"]
        self._glow = glow
        self._variant = variant
        if variant == "outline":
            kwargs["border_width"] = 1
            kwargs["border_color"] = BORDER
        super().__init__(master, **kwargs)


class SectionCard(ctk.CTkFrame):
    """Compact card — hugs its content, no dead space."""
    def __init__(self, master, title: str, **kwargs):
        kwargs.setdefault("fg_color", BG_CARD)
        kwargs.setdefault("corner_radius", RADIUS)
        kwargs.setdefault("border_width", 0)
        super().__init__(master, **kwargs)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=PAD, pady=(6, 0))
        ctk.CTkLabel(hdr, text=title, font=FONT_HEAD, text_color=ACCENT).pack(side="left")

        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="x", padx=PAD, pady=(4, PAD))


class FieldRow(ctk.CTkFrame):
    def __init__(self, master, label: str, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        ctk.CTkLabel(self, text=label, font=FONT_MICRO, text_color=TEXT_DIM,
                     width=40, anchor="w").pack(side="left", padx=(0, 4))
        self.slot = ctk.CTkFrame(self, fg_color="transparent")
        self.slot.pack(side="left", fill="x", expand=True)


class InfoChip(ctk.CTkFrame):
    def __init__(self, master, text: str = "—", accent=TEXT_DIM, **kwargs):
        kwargs.setdefault("fg_color", CHIP_BG)
        kwargs.setdefault("corner_radius", RADIUS)
        kwargs.setdefault("border_width", 0)
        kwargs.setdefault("border_color", BORDER)
        kwargs.setdefault("height", 28)
        super().__init__(master, **kwargs)
        self.pack_propagate(False)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=4)
        self.dot = ctk.CTkLabel(row, text="●", font=(_F, 8), text_color=accent, width=10)
        self.dot.pack(side="left")
        self.label = ctk.CTkLabel(row, text=text, font=FONT_MICRO, text_color=TEXT_SEC, anchor="w")
        self.label.pack(side="left", fill="x", expand=True)

    def set(self, text: str, accent=TEXT_SEC):
        if accent == SUCCESS:
            self.configure(fg_color=SUCCESS_DIM, border_width=0)
            text_col = SUCCESS
        elif accent == DANGER:
            self.configure(fg_color=DANGER_DIM, border_width=0)
            text_col = TEXT_PRI
        elif accent == WARN:
            self.configure(fg_color=WARN_DIM, border_width=0)
            text_col = WARN
        else:
            self.configure(fg_color=CHIP_BG, border_width=0)
            text_col = TEXT_SEC
        self.label.configure(text=text, text_color=text_col)
        self.dot.configure(text_color=accent)


class StyledEntry(ctk.CTkEntry):
    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", BG_ELEV)
        kwargs.setdefault("border_color", BORDER)
        kwargs.setdefault("border_width", 0)
        kwargs.setdefault("text_color", TEXT_PRI)
        kwargs.setdefault("placeholder_text_color", TEXT_DIM)
        kwargs.setdefault("font", FONT_BODY)
        kwargs.setdefault("corner_radius", RADIUS)
        kwargs.setdefault("height", 30)
        super().__init__(master, **kwargs)


class StyledDropdown(ctk.CTkFrame):
    """Full-width dropdown — popup matches bar width."""
    def __init__(self, master, values=None, command=None, **kwargs):
        super().__init__(master, fg_color="transparent")
        self._values = list(values or [])
        self._command = command
        self._current = self._values[0] if self._values else ""
        self._popup = None

        self._bar = ctk.CTkFrame(self, fg_color=BG_ELEV, corner_radius=RADIUS, height=40)
        self._bar.pack(fill="x")
        self._bar.pack_propagate(False)

        self._label = ctk.CTkLabel(
            self._bar, text=self._current, font=FONT_BODY, text_color=TEXT_PRI, anchor="w",
        )
        self._label.pack(side="left", fill="x", expand=True, padx=(12, 4))

        self._arrow = ctk.CTkButton(
            self._bar, text="▾", width=36, height=36, corner_radius=RADIUS,
            fg_color=ACCENT, hover_color=ACCENT2, text_color=BG_DEEP,
            font=(_F, 14, "bold"), command=self._toggle_popup,
        )
        self._arrow.pack(side="right", padx=3, pady=3)

        self._bar.bind("<Button-1>", self._on_bar_click, add="+")
        self._label.bind("<Button-1>", self._on_bar_click, add="+")

    def _on_bar_click(self, event):
        """Open popup from bar/label click (arrow uses its own command)."""
        if self._popup and self._popup.winfo_exists():
            return
        self._open_popup()

    def get(self) -> str:
        return self._current

    def set(self, value: str):
        if value in self._values:
            self._current = value
            self._label.configure(text=value)

    def configure(self, **kwargs):
        if "values" in kwargs:
            self._values = list(kwargs.pop("values"))
        if kwargs:
            super().configure(**kwargs)

    def _toggle_popup(self):
        if self._popup and self._popup.winfo_exists():
            self._close_popup()
        else:
            self._open_popup()

    def _open_popup(self):
        self.update_idletasks()
        w = max(self.winfo_width(), 200)
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height() + 2
        row_h = 34
        h = min(len(self._values) * row_h + 8, row_h * 6)

        self._popup = ctk.CTkToplevel(self)
        self._popup.overrideredirect(True)
        self._popup.configure(fg_color=BG_CARD2)
        self._popup.geometry(f"{w}x{h}+{x}+{y}")
        self._popup.attributes("-topmost", True)

        box = ctk.CTkFrame(self._popup, fg_color=BG_CARD2, corner_radius=RADIUS)
        box.pack(fill="both", expand=True)

        for val in self._values:
            btn = ctk.CTkButton(
                box, text=val, anchor="w", height=row_h,
                fg_color=BG_CARD2, hover_color=ACCENT_DIM, text_color=TEXT_PRI,
                font=FONT_BODY, corner_radius=4,
                command=lambda v=val: self._pick(v),
            )
            btn.pack(fill="x", padx=4, pady=1)

        self.after(100, self._bind_outside_click)

    def _bind_outside_click(self):
        if not self._popup or not self._popup.winfo_exists():
            return
        self._click_bind = self.winfo_toplevel().bind(
            "<Button-1>", self._on_outside_click, add="+"
        )

    def _on_outside_click(self, event):
        if not self._popup or not self._popup.winfo_exists():
            return
        x, y = event.x_root, event.y_root
        for win in (self._popup, self):
            wx, wy = win.winfo_rootx(), win.winfo_rooty()
            if wx <= x <= wx + win.winfo_width() and wy <= y <= wy + win.winfo_height():
                return
        self._close_popup()

    def _pick(self, value: str):
        self._current = value
        self._label.configure(text=value)
        self._close_popup()
        if self._command:
            self._command(value)

    def _close_popup(self):
        if self._popup and self._popup.winfo_exists():
            self._popup.destroy()
        self._popup = None
        if getattr(self, "_click_bind", None):
            try:
                self.winfo_toplevel().unbind("<Button-1>", self._click_bind)
            except Exception:
                pass
            self._click_bind = None


# ── MAIN APP ───────────────────────────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cert_manager = CertificateManager()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Bypass Installer")
        self.geometry("860x580")
        self.minsize(860, 580)
        self.resizable(False, False)
        self.configure(fg_color=BG_DEEP)
        self._center_on_screen()
        self.withdraw()

        set_window_icon(self)
        self._header_logo = load_logo_image((44, 44))

        self._build_ui()
        self.update_idletasks()
        self.deiconify()
        apply_native_frameless(self)
        ensure_taskbar_icon(self)
        set_window_icon(self)

        self.after(50, lambda: apply_native_frameless(self))
        self.after(100, lambda: bring_window_to_front(self))
        self.after(200, self._init_emulator_selection)
        self.after(1500, self.start_auto_connect)
        self.after(3000, self.update_status_loop)

    def _init_emulator_selection(self):
        self.emu_option.set("BlueStacks App Player")
        self.on_emu_change("BlueStacks App Player")

    def _center_on_screen(self):
        self.update_idletasks()
        w, h = 860, 580
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _is_title_control(self, widget) -> bool:
        w = widget
        while w is not None:
            if getattr(w, "_title_btn", False):
                return True
            w = getattr(w, "master", None)
        return False

    def _bind_window_drag(self, widget):
        widget.bind("<ButtonPress-1>", self._start_move, add="+")
        widget.bind("<B1-Motion>", self._on_move, add="+")
        widget.bind("<ButtonRelease-1>", self._end_move, add="+")

    def _start_move(self, event):
        if self._is_title_control(event.widget):
            return
        w = event.widget
        while w is not None:
            if isinstance(w, (ctk.CTkButton, ctk.CTkEntry, ctk.CTkTextbox, ctk.CTkOptionMenu)):
                return
            w = getattr(w, "master", None)
        self._drag_x = event.x_root - self.winfo_x()
        self._drag_y = event.y_root - self.winfo_y()
        self._dragging = True

    def _on_move(self, event):
        if not getattr(self, "_dragging", False) or self._is_title_control(event.widget):
            return
        self.geometry(f"+{event.x_root - self._drag_x}+{event.y_root - self._drag_y}")

    def _end_move(self, event):
        self._dragging = False

    def minimize_window(self):
        self.iconify()
        self.bind("<Map>", self._restore_frameless, add="+")

    def _restore_frameless(self, _=None):
        if self.state() == "normal":
            apply_native_frameless(self)
            set_window_icon(self)
            bring_window_to_front(self)
            self.unbind("<Map>")

    # ── UI CONSTRUCTION ────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── HEADER (title bar + window controls) ─────────────────────────────
        self.title_bar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=52)
        self.title_bar.pack(fill="x")
        self.title_bar.pack_propagate(False)

        bar = ctk.CTkFrame(self.title_bar, fg_color="transparent")
        bar.pack(fill="both", expand=True, padx=PAD, pady=5)

        if getattr(self, "_header_logo", None):
            self._logo_label = ctk.CTkLabel(bar, text="", image=self._header_logo, fg_color="transparent")
            self._logo_label.pack(side="left", padx=(0, 10))
        else:
            self._logo_label = ctk.CTkLabel(bar, text="⬡", font=(_F, 20), text_color=ACCENT, fg_color="transparent")
            self._logo_label.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(bar, text="Bypass Installer", font=FONT_TITLE,
                     text_color=TEXT_PRI).pack(side="left")
        ctk.CTkLabel(bar, text="  ·  cert & proxy", font=FONT_SUB,
                     text_color=TEXT_DIM).pack(side="left", pady=(3, 0))

        win_btns = ctk.CTkFrame(bar, fg_color="transparent")
        win_btns.pack(side="right", padx=(4, 0))

        close_btn = TitleButton(win_btns, text="✕", hover_color=DANGER_BTN, command=self.destroy)
        close_btn.pack(side="right")

        min_btn = TitleButton(win_btns, text="—", hover_color=BG_ELEV, command=self.minimize_window)
        min_btn.pack(side="right", padx=(0, 2))

        badges = ctk.CTkFrame(bar, fg_color="transparent")
        badges.pack(side="right", padx=(0, 8))
        admin_col = SUCCESS if is_admin() else WARN
        ctk.CTkLabel(badges, text=f"● {'Admin' if is_admin() else 'User'}",
                     font=FONT_MICRO, text_color=admin_col).pack(side="right", padx=(8, 0))
        ctk.CTkLabel(badges, text="v4.1.4", font=FONT_MICRO,
                     text_color=ACCENT).pack(side="right", padx=(8, 0))

        self._bind_window_drag(self.title_bar)
        self._bind_window_drag(bar)
        for w in bar.winfo_children():
            if w is not win_btns:
                self._bind_window_drag(w)

        # ── 2×2 GRID (no vertical stretch = no dead gaps) ─────────────────────
        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=PAD, pady=PAD)
        grid.columnconfigure(0, weight=1, uniform="c")
        grid.columnconfigure(1, weight=1, uniform="c")
        for r in range(3):
            grid.rowconfigure(r, weight=0)

        gp = dict(padx=GAP // 2, pady=GAP // 2)

        # ── Emulator ──
        emu_card = SectionCard(grid, "Emulator")
        emu_card.grid(row=0, column=0, sticky="nsew", **gp)
        ei = emu_card.body

        self.emu_option = StyledDropdown(
            ei,
            values=["Select Emulator", "BlueStacks App Player", "BlueStacks China", "MSI App Player"],
            command=self.on_emu_change,
        )
        self.emu_option.pack(fill="x", pady=(0, GAP))

        self.info_chip = InfoChip(ei, "No emulator selected", accent=TEXT_DIM)
        self.info_chip.pack(fill="x", pady=(0, GAP))

        er = ctk.CTkFrame(ei, fg_color="transparent")
        er.pack(fill="x")
        er.columnconfigure(0, weight=3)
        er.columnconfigure(1, weight=2)
        self.access_btn = GlowButton(er, text="Get Access", variant="primary", command=self.get_access_action)
        self.access_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self.refresh_emu_btn = GlowButton(er, text="Refresh", variant="secondary", command=self.refresh_emulator_action)
        self.refresh_emu_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

        # ── Certificate ──
        cert_card = SectionCard(grid, "Certificate")
        cert_card.grid(row=0, column=1, sticky="nsew", **gp)
        ci = cert_card.body

        self.file_chip = InfoChip(ci, "No certificate loaded", accent=TEXT_DIM)
        self.file_chip.pack(fill="x", pady=(0, GAP))

        cfr = ctk.CTkFrame(ci, fg_color="transparent")
        cfr.pack(fill="x", pady=(0, GAP))
        cfr.columnconfigure(0, weight=1)
        cfr.columnconfigure(1, weight=1)
        self.browse_btn = GlowButton(cfr, text="Browse", variant="secondary", command=self.browse_cert_action)
        self.browse_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self.paste_btn = GlowButton(cfr, text="Paste", variant="outline", command=self.paste_cert_action)
        self.paste_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

        hr = FieldRow(ci, "HASH")
        hr.pack(fill="x", pady=(0, 2))
        self.hash_entry = StyledEntry(hr.slot, placeholder_text="c8750f0d.0")
        self.hash_entry.insert(0, "c8750f0d.0")
        self.hash_entry.pack(fill="x")

        cbr = ctk.CTkFrame(ci, fg_color="transparent")
        cbr.pack(fill="x", pady=(GAP, 0))
        cbr.columnconfigure(0, weight=1)
        cbr.columnconfigure(1, weight=1)
        self.install_btn = GlowButton(cbr, text="Install", variant="primary", command=self.install_cert_action)
        self.install_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self.remove_btn = GlowButton(cbr, text="Remove", variant="danger", command=self.remove_cert_action)
        self.remove_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

        # ── ADB ──
        adb_card = SectionCard(grid, "ADB Connection")
        adb_card.grid(row=1, column=0, sticky="nsew", **gp)
        ai = adb_card.body

        pr = FieldRow(ai, "PORT")
        pr.pack(fill="x", pady=(0, GAP))
        self.port_entry = StyledEntry(pr.slot, placeholder_text="5555")
        self.port_entry.insert(0, "5555")
        self.port_entry.pack(fill="x")

        self.status_chip = InfoChip(ai, "Offline — not connected", accent=DANGER)
        self.status_chip.pack(fill="x", pady=(0, GAP))

        self.conn_btn = GlowButton(ai, text="Connect ADB", variant="primary", command=self.toggle_conn_action)
        self.conn_btn.pack(fill="x")

        # ── Proxy ──
        proxy_card = SectionCard(grid, "Proxy")
        proxy_card.grid(row=1, column=1, sticky="nsew", **gp)
        pi = proxy_card.body

        pxr = FieldRow(pi, "ADDR")
        pxr.pack(fill="x", pady=(0, GAP))
        self.proxy_entry = StyledEntry(pxr.slot)
        self.proxy_entry.insert(0, self.cert_manager.proxy_address)
        self.proxy_entry.pack(fill="x")

        self.proxy_status_chip = InfoChip(pi, "No proxy active", accent=TEXT_DIM)
        self.proxy_status_chip.pack(fill="x", pady=(0, GAP))

        pfr = ctk.CTkFrame(pi, fg_color="transparent")
        pfr.pack(fill="x", pady=(0, GAP))
        pfr.columnconfigure(0, weight=1)
        pfr.columnconfigure(1, weight=1)
        self.find_proxy_btn = GlowButton(pfr, text="Find Proxy", variant="secondary", height=BTN_HSM, command=self.find_proxy_action)
        self.find_proxy_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self.copy_proxy_btn = GlowButton(pfr, text="Copy IP:Port", variant="outline", height=BTN_HSM, command=self.copy_proxy_action)
        self.copy_proxy_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

        pbr = ctk.CTkFrame(pi, fg_color="transparent")
        pbr.pack(fill="x")
        pbr.columnconfigure(0, weight=1)
        pbr.columnconfigure(1, weight=1)
        self.apply_proxy_btn = GlowButton(pbr, text="Apply", variant="primary", height=BTN_HSM, command=self.apply_proxy_action)
        self.apply_proxy_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self.clear_proxy_btn = GlowButton(pbr, text="Clear", variant="danger", height=BTN_HSM, command=self.clear_proxy_action)
        self.clear_proxy_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

        # ── LOG ───────────────────────────────────────────────────────────────
        log_card = ctk.CTkFrame(grid, fg_color=BG_CARD, corner_radius=RADIUS, border_width=0)
        log_card.grid(row=2, column=0, columnspan=2, sticky="ew", padx=GAP // 2, pady=(GAP, 0))

        log_hdr = ctk.CTkFrame(log_card, fg_color="transparent")
        log_hdr.pack(fill="x", padx=PAD, pady=(6, 2))
        ctk.CTkLabel(log_hdr, text="Log", font=FONT_HEAD, text_color=ACCENT).pack(side="left")

        self.log_text = ctk.CTkTextbox(
            log_card, height=88,
            font=("Consolas", 9),
            fg_color=LOG_BG,
            text_color=LOG_TEXT,
            border_width=0,
            corner_radius=RADIUS,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=ACCENT_DIM,
            wrap="none",
            activate_scrollbars=True,
        )
        self.log_text.pack(fill="x", padx=PAD, pady=(0, 8))
        try:
            inner = self.log_text._textbox
            inner.configure(
                spacing1=0,
                spacing2=0,
                spacing3=1,
                padx=6,
                pady=4,
                font=("Consolas", 9),
            )
            inner.tag_configure("ok", foreground=SUCCESS)
            inner.tag_configure("err", foreground=DANGER)
            inner.tag_configure("warn", foreground=WARN)
        except Exception:
            pass

    # ── HELPERS ────────────────────────────────────────────────────────────────

    def run_on_ui_thread(self, fn, *args, **kwargs):
        if threading.current_thread() is threading.main_thread():
            fn(*args, **kwargs)
        else:
            self.after(0, lambda: fn(*args, **kwargs))

    def add_log(self, msg, color=None):
        if threading.current_thread() is not threading.main_thread():
            self.run_on_ui_thread(self.add_log, msg, color)
            return
        if color in ("error", "err", "fail"):
            color = "err"
        elif color in ("success", "ok"):
            color = "ok"
        elif color in ("warning", "warn"):
            color = "warn"
        ts = time.strftime("%H:%M:%S")
        base_color = color
        for part in str(msg).splitlines():
            line = f"[{ts}] {part}\n"
            self.log_text.insert("end", line)
            line_color = base_color
            if line_color is None:
                low = part.lower()
                if any(x in low for x in ("success", "linked", "connected", "active", "loaded", "applied", "pasted", "✓")):
                    line_color = "ok"
                elif any(x in low for x in ("fail", "error", "denied", "refused", "not found", "not recognized", "timed out", "✕")):
                    line_color = "err"
                elif any(x in low for x in ("warning", "warn", "tip:", "note:")):
                    line_color = "warn"
            if line_color:
                try:
                    start = self.log_text.index("end-2c linestart")
                    end = self.log_text.index("end-1c")
                    self.log_text._textbox.tag_add(line_color, start, end)
                except Exception:
                    pass
        self.log_text.see("end")

    def _sync_from_ui(self):
        """Keep manager state aligned with UI fields before ADB/proxy ops."""
        self.cert_manager.adb_port = self.port_entry.get().strip() or "5555"
        self.cert_manager.proxy_address = self.proxy_entry.get().strip()

    def _refresh_conn_ui(self, check_device_proxy: bool = False):
        if self.cert_manager.is_connected:
            self.status_chip.set(f"Connected · port {self.cert_manager.adb_port}", SUCCESS)
            self.conn_btn.configure(text="Disconnect ADB")
            if check_device_proxy:
                device_proxy = self.cert_manager.get_device_proxy()
                if device_proxy and not self.cert_manager.proxy_applied:
                    self.cert_manager.active_proxy = device_proxy
        else:
            self.status_chip.set("Offline — not connected", DANGER)
            self.conn_btn.configure(text="Connect ADB")
        self._refresh_proxy_ui(check_device=check_device_proxy)

    def _refresh_proxy_ui(self, check_device: bool = False):
        if self.cert_manager.proxy_applied and self.cert_manager.active_proxy:
            self.proxy_status_chip.set(
                f"Connected · {self.cert_manager.active_proxy}", SUCCESS
            )
            return
        if check_device and self.cert_manager.is_connected:
            device_proxy = self.cert_manager.get_device_proxy()
            if device_proxy:
                self.proxy_status_chip.set(f"Device · {device_proxy}", WARN)
                return
        if self.cert_manager.is_connected:
            self.proxy_status_chip.set("ADB linked — no proxy set", TEXT_DIM)
        else:
            self.proxy_status_chip.set("Connect ADB, then apply proxy", TEXT_DIM)

    def _proxy_text_to_copy(self) -> str:
        if self.cert_manager.proxy_applied and self.cert_manager.active_proxy:
            return self.cert_manager.active_proxy
        entry_text = self.proxy_entry.get().strip()
        if entry_text:
            return entry_text
        if self.cert_manager.is_connected:
            device_proxy = self.cert_manager.get_device_proxy()
            if device_proxy:
                return device_proxy
        return ""

    def find_proxy_action(self):
        self._sync_from_ui()
        current = self.proxy_entry.get().strip()
        port = "8080"
        if ":" in current:
            port = current.rsplit(":", 1)[-1].strip() or "8080"
        new_addr = self.cert_manager.find_proxy_address(port)
        self.proxy_entry.delete(0, "end")
        self.proxy_entry.insert(0, new_addr)
        self.cert_manager.proxy_address = new_addr
        self._refresh_proxy_ui()
        self.add_log(f"Proxy found: {new_addr}", "ok")

    def copy_proxy_action(self):
        self._sync_from_ui()
        text = self._proxy_text_to_copy()
        if not text:
            self.add_log("Nothing to copy — click Find Proxy or enter IP:port.", "warn")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update_idletasks()
            self.add_log(f"Copied to clipboard: {text}", "ok")
        except tk.TclError as e:
            self.add_log(f"✕ Copy failed: {e}", "err")

    def start_auto_connect(self):
        threading.Thread(target=self.auto_connect, daemon=True).start()

    def auto_connect(self):
        try:
            self._sync_from_ui()
            self.add_log("Auto-connect starting...")
            self.cert_manager.connect_adb(log_cb=self.add_log)
            self.run_on_ui_thread(lambda: self._refresh_conn_ui(check_device_proxy=True))
        except Exception as e:
            logger.exception("Auto connect crashed")
            self.add_log(f"✕ Auto-connect crash: {e}", "err")

    def on_emu_change(self, val):
        if val == "Select Emulator":
            self.cert_manager.select_emulator(EmulatorType.NONE)
            self.info_chip.set("No emulator selected", TEXT_DIM)
            self.add_log("Select an emulator to continue.")
            return
        emu_map = {"BlueStacks App Player": EmulatorType.BLUESTACKS5,
                   "BlueStacks China": EmulatorType.BLUESTACKS_CN,
                   "MSI App Player": EmulatorType.MSI5}
        emu_type = emu_map.get(val, EmulatorType.NONE)
        self.cert_manager.select_emulator(emu_type)
        info = self.cert_manager.get_emulator_info(emu_type)
        chip_text = f"{info['name']}  ·  v{info['version']}"
        chip_color = WARN if info["version"] == "Not Found" else SUCCESS
        self.info_chip.set(chip_text, chip_color)
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, self.cert_manager.adb_port)
        adb = self.cert_manager.adb_path
        self.add_log(f"Target → {val}  (port {self.cert_manager.adb_port}, ADB: {adb})")

    def refresh_emulator_action(self):
        selected = self.emu_option.get()
        if selected == "Select Emulator":
            self.add_log("Select an emulator first.")
            return
        self.on_emu_change(selected)
        self.add_log("Emulator info refreshed.")

    def get_access_action(self):
        self.add_log("Initiating system grant sequence...")
        self.cert_manager.force_kill_emulators()
        if self.cert_manager.bypass_access():
            self.add_log("Config bypass applied — R/W mode enabled.")
        else:
            self.add_log(f"Bypass warning: {self.cert_manager.last_error}")

        if self.cert_manager.get_access():
            self.add_log(f"Launching {self.cert_manager.selected_emulator.value}...")
            def poll_adb():
                self.add_log("Waiting for emulator ADB (up to 90s)...")
                start = time.time()
                attempt = 0
                while time.time() - start < 90:
                    if self.cert_manager.is_connected:
                        break
                    attempt += 1
                    if self.cert_manager.connect_adb(log_cb=self.add_log):
                        self.run_on_ui_thread(lambda: self._refresh_conn_ui(check_device_proxy=True))
                        break
                    self.add_log(f"Retry {attempt} — waiting 5s...", "warn")
                    time.sleep(5)
                if not self.cert_manager.is_connected:
                    self.add_log("✕ ADB auto-link timed out (90s)", "err")
                    self.add_log("Tip: click Connect ADB after emulator fully loads", "warn")
            self._sync_from_ui()
            threading.Thread(target=poll_adb, daemon=True).start()
        else:
            self.add_log(f"Launch failed: {self.cert_manager.last_error}")

    def toggle_conn_action(self):
        def task():
            self._sync_from_ui()
            if self.cert_manager.is_connected:
                self.cert_manager.disconnect_adb()
                self.add_log("ADB disconnected.", "warn")
                self.run_on_ui_thread(self._refresh_conn_ui)
                return
            self.cert_manager.connect_adb(log_cb=self.add_log)
            self.run_on_ui_thread(lambda: self._refresh_conn_ui(check_device_proxy=True))
        threading.Thread(target=task, daemon=True).start()

    def sync_cert_hash_from_ui(self):
        self.cert_manager.custom_cert_hash = self.hash_entry.get().strip()

    def update_hash_field(self, value: str):
        self.hash_entry.delete(0, "end")
        self.hash_entry.insert(0, value)
        self.cert_manager.custom_cert_hash = value

    def apply_cert_to_ui(self, path: str, source_label: str):
        self.cert_manager.apply_cert_selection(path, log_cb=self.add_log)
        display = "Pasted from clipboard" if source_label == "clipboard" else os.path.basename(path)
        self.file_chip.set(display, SUCCESS)
        self.update_hash_field(self.cert_manager.custom_cert_hash)

    def browse_cert_action(self):
        path = filedialog.askopenfilename(
            title="Select Certificate",
            filetypes=[("Certificates", "*.pem *.cer *.crt *.0"), ("All Files", "*.*")]
        )
        if path:
            self.apply_cert_to_ui(path, os.path.basename(path))
            self.add_log(f"Cert loaded: {os.path.basename(path)}")

    def paste_cert_action(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            self.add_log("✕ Paste failed: clipboard is empty.")
            return

        ok, result = self.cert_manager.load_pasted_certificate(text)
        if not ok:
            self.add_log(f"✕ Paste failed: {result}")
            return

        self.apply_cert_to_ui(result, "clipboard")
        self.add_log(f"Cert pasted: {os.path.basename(result)}")

    def install_cert_action(self):
        self.sync_cert_hash_from_ui()
        def task():
            if self.cert_manager.install_certificate(log_cb=self.add_log):
                self.add_log("▶ INJECTION SUCCESS.")
            else:
                self.add_log(f"✕ INJECTION FAILED: {self.cert_manager.last_error}")
        threading.Thread(target=task, daemon=True).start()

    def remove_cert_action(self):
        self.sync_cert_hash_from_ui()
        def task():
            if self.cert_manager.uninstall_certificate(log_cb=self.add_log):
                self.add_log("▶ CLEANUP SUCCESS.")
            else:
                self.add_log(f"✕ CLEANUP FAILED: {self.cert_manager.last_error}")
        threading.Thread(target=task, daemon=True).start()

    def apply_proxy_action(self):
        def task():
            self._sync_from_ui()
            if self.cert_manager.apply_proxy(log_cb=self.add_log):
                def on_ok():
                    self.proxy_entry.delete(0, "end")
                    self.proxy_entry.insert(0, self.cert_manager.active_proxy)
                    self._refresh_proxy_ui()
                    self.add_log(f"Proxy active: {self.cert_manager.active_proxy}", "ok")
                self.run_on_ui_thread(on_ok)
            else:
                self.add_log(f"Proxy failed: {self.cert_manager.last_error}", "err")
        threading.Thread(target=task, daemon=True).start()

    def clear_proxy_action(self):
        def task():
            self._sync_from_ui()
            if self.cert_manager.clear_proxy(log_cb=self.add_log):
                self.run_on_ui_thread(self._refresh_proxy_ui)
                self.add_log("Proxy cleared.", "ok")
            else:
                self.add_log(f"Proxy clear failed: {self.cert_manager.last_error}", "err")
        threading.Thread(target=task, daemon=True).start()

    def find_proxy_action(self):
        def task():
            if not self.cert_manager.is_connected:
                self.add_log("✕ Cannot find proxy: ADB not connected.", "err")
                return
            self.add_log("Reading proxy from device...")
            proxy = self.cert_manager.get_device_proxy()
            def on_done():
                self.proxy_entry.delete(0, "end")
                if proxy:
                    self.proxy_entry.insert(0, proxy)
                    self.add_log(f"Found active proxy: {proxy}", "ok")
                else:
                    self.proxy_entry.insert(0, "0")
                    self.add_log("No proxy found on device (0).", "warn")
            self.run_on_ui_thread(on_done)
        threading.Thread(target=task, daemon=True).start()

    def copy_proxy_action(self):
        proxy = self.proxy_entry.get().strip()
        if not proxy or proxy == "0":
            self.add_log("No proxy address to copy.", "warn")
            return
        self.clipboard_clear()
        self.clipboard_append(proxy)
        self.add_log("Proxy copied to clipboard.", "ok")
    def update_status_loop(self):
        lost = False
        if self.cert_manager.is_connected and not self.cert_manager.is_adb_ready():
            self.cert_manager.is_connected = False
            self.cert_manager.proxy_applied = False
            lost = True
        self._refresh_conn_ui()
        if lost:
            self.add_log("✕ ADB session lost — reconnect needed", "err")
        self.after(3000, self.update_status_loop)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    try:
        set_app_user_model_id()
        ensure_admin()
        app = App()
        bring_window_to_front(app)
        app.mainloop()
    except Exception as exc:
        logger.exception("Fatal startup/runtime error")
        log_fatal(f"Fatal error: {exc}")
        try:
            import tkinter.messagebox as messagebox
            messagebox.showerror("Bypass Installer Error", f"Application crashed:\n{exc}")
        except Exception:
            print(f"Application crashed: {exc}")


# ══════════════════════════════════════════════════════════════════
# BUILD INSTRUCTIONS — Bypass Installer v1
# ══════════════════════════════════════════════════════════════════
#
# STEP 1: Create the UAC manifest file (admin auto-elevation)
#   Save as: bypass_installer.manifest
#   ----------------------------------------------------------------
#   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
#   <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
#     <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
#       <security>
#         <requestedPrivileges>
#           <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
#         </requestedPrivileges>
#       </security>
#     </trustInfo>
#   </assembly>
#   ----------------------------------------------------------------
#
# STEP 2: Build command
#   python -m PyInstaller ^
#     --onefile ^
#     --noconsole ^
#     --name "Bypass Installer" ^
#     --icon logo.ico ^
#     --manifest bypass_installer.manifest ^
#     --collect-all customtkinter ^
#     --add-data "logo.ico;." ^
#     cert_installer_python.py
#
# OUTPUT: dist\Bypass Installer.exe  (auto-requests admin on launch)
# ══════════════════════════════════════════════════════════════════