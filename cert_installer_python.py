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

# ── THEME PALETTE  (deep dark vibes) ──────────────────────────────────────────
BG_DEEP    = "#0b0f1a"   # deepest backdrop
BG_PANEL   = "#111726"   # main shell/top panel
BG_CARD    = "#171f33"   # card surface
BG_CARD2   = "#1e2740"   # elevated card/button surface
BORDER     = "#2a3552"   # subtle border lines
ACCENT     = "#7c4dff"   # primary violet
ACCENT2    = "#6a3de6"   # accent hover
ACCENT_DIM = "#2a2450"   # muted accent fill
SUCCESS    = "#22c55e"   # green
DANGER     = "#ef4444"   # red
WARN       = "#f59e0b"   # amber
TEXT_PRI   = "#edf2ff"   # primary text
TEXT_SEC   = "#9aa7c7"   # secondary text
TEXT_DIM   = "#506088"   # dim text
# ── FONTS  (Segoe UI for a premium Windows feel) ───────────────────────────────
_F = "Segoe UI"
FONT_TITLE  = (_F, 26, "bold")
FONT_HEAD   = (_F, 10, "bold")
FONT_BODY   = (_F, 11)
FONT_SMALL  = (_F, 9)
FONT_BTN    = (_F, 12, "bold")
FONT_BTN_SM = (_F, 10, "bold")
BTN_HEIGHT_MAIN = 40
BTN_HEIGHT_SM = 36
BTN_HEIGHT_LG = 46

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() # type: ignore
    except:
        return False

def ensure_admin():
    """Re-launch the process with UAC elevation if not already admin."""
    if not is_admin():
        try:
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{a}"' for a in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(  # type: ignore
                None, "runas", sys.executable, f'"{script}" {params}', None, 1
            )
        except Exception:
            pass
        sys.exit(0)

def get_local_ipv4() -> str:
    """Return primary local IPv4 address; fallback to localhost."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # No traffic is sent; this is only used to resolve local interface IP.
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
    return "127.0.0.1"

class EmulatorType(Enum):
    NONE = "None"
    BLUESTACKS5 = "BlueStacks App Player"
    BLUESTACKS_CN = "BlueStacks China"
    MSI5 = "MSI App Player"

class CertificateManager:
    """Manages certificate installation and emulator operations"""
    
    def __init__(self):
        self.selected_emulator = EmulatorType.NONE
        self.adb_port = "5555"
        self.certificate_path = ""
        self.cert_hash = ""
        self.proxy_address = f"{get_local_ipv4()}:8080"
        self.is_connected = False
        self.last_error = ""
        self.emulator_name = "None"
        self.emulator_version = "None"
        self.adb_path = "adb"
        
    def check_adb_exists(self) -> bool:
        try:
            subprocess.run([self.adb_path, "version"], capture_output=True, shell=True, timeout=2)
            return True
        except:
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
                default_msi5 = r"C:\Program Files\Bluestacks_msi5\HD-Player.exe"
                if os.path.exists(default_msi5):
                    paths[EmulatorType.MSI5] = default_msi5
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
                config_paths = [os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_msi5", "bluestacks.conf")]
            
            for config_path in config_paths:
                if not os.path.exists(config_path):
                    continue
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
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
    
    def connect_adb(self) -> bool:
        if not self.check_adb_exists():
            common_paths = [
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", "adb.exe"),
                "C:\\adb\\adb.exe",
                os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_nxt", "adb.exe"),
                os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_nxt_cn", "adb.exe"),
                r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe",
                r"C:\Program Files\BlueStacks_nxt_cn\HD-Adb.exe"
            ]
            for p in common_paths:
                if os.path.exists(p):
                    self.adb_path = p
                    break
            
            if not self.check_adb_exists():
                self.last_error = "ADB not found. Please ensure ADB is installed."
                return False
            
        try:
            target = f"127.0.0.1:{self.adb_port}"
            subprocess.run(f'"{self.adb_path}" start-server', shell=True, timeout=15)
            # Drop any stale transport first to avoid "connected but unusable" state.
            subprocess.run(f'"{self.adb_path}" disconnect {target}', shell=True, capture_output=True, timeout=5)
            cmd = f'"{self.adb_path}" connect {target}'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=20)
            
            if "connected" in result.stdout.lower() or "already connected" in result.stdout.lower():
                subprocess.run(f'"{self.adb_path}" -s {target} wait-for-device', shell=True, timeout=8)
                if self.is_adb_ready():
                    self.is_connected = True
                    return True
            
            self.last_error = result.stdout.strip() or result.stderr.strip()
            self.is_connected = False
            return False
        except subprocess.TimeoutExpired:
            self.last_error = "ADB connection timed out"
            self.is_connected = False
            return False
        except Exception as e:
            self.last_error = str(e)
            self.is_connected = False
            return False
    
    def disconnect_adb(self) -> bool:
        try:
            subprocess.run(f'"{self.adb_path}" disconnect 127.0.0.1:{self.adb_port}', capture_output=True, shell=True, timeout=5)
            self.is_connected = False
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def is_adb_ready(self) -> bool:
        """Check whether current ADB target is reachable and responsive."""
        target = f"127.0.0.1:{self.adb_port}"
        try:
            state_res = subprocess.run(
                f'"{self.adb_path}" -s {target} get-state',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            if "device" not in state_res.stdout.lower():
                return False
            ping_res = subprocess.run(
                f'"{self.adb_path}" -s {target} shell "echo ok"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            return "ok" in ping_res.stdout.lower()
        except Exception:
            return False

    def ensure_adb_connection(self) -> bool:
        """Guarantee a usable ADB session, auto-reconnecting when stale."""
        if self.is_connected and self.is_adb_ready():
            return True
        self.is_connected = False
        return self.connect_adb()

    def calculate_cert_hash(self) -> Optional[str]:
        if not self.certificate_path or not os.path.exists(self.certificate_path):
            return None
        try:
            cmd = f'openssl x509 -inform PEM -subject_hash_old -in "{self.certificate_path}" -noout'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
            if result.returncode == 0:
                self.cert_hash = result.stdout.strip()
                return self.cert_hash
        except:
            pass
        self.cert_hash = "c8750f0d"
        return self.cert_hash

    def bypass_access(self) -> bool:
        try:
            program_data = os.environ.get("ProgramData", "C:\\ProgramData")
            engine_root = ""
            
            if self.selected_emulator == EmulatorType.MSI5:
                options = ["BlueStacks_msi5", "BlueStacks_msi", "BlueStacks_msi2"]
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
            target_ip = f"127.0.0.1:{self.adb_port}"
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
            hash_val = self.calculate_cert_hash() or "c8750f0d"
            cert_name = f"{hash_val}.0"
            log(f"Target: {cert_name}")

            if not self.ensure_adb_connection():
                log("Establishing ADB link...")
                return False
            
            log(f"Pushing → /sdcard/{cert_name}")
            remote_sd = f"/sdcard/{cert_name}"
            try:
                push_res = subprocess.run(f'"{self.adb_path}" -s {target_ip} push "{final_path}" {remote_sd}', capture_output=True, shell=True, timeout=60)
                if push_res.returncode != 0:
                    err = push_res.stderr.decode().strip() or push_res.stdout.decode().strip()
                    self.last_error = f"Push failed: {err}"
                    return False
            except subprocess.TimeoutExpired:
                self.last_error = "ADB push timed out."
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
                exec_res = subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "{install_cmd}"', shell=True, capture_output=True, timeout=30)
                if exec_res.returncode != 0:
                    log("Primary su failed, trying fallback...")
                    fallback_cmd = f"su -c 'mount -o rw,remount /dev/sda1 /system && cp {remote_sd} {cert_sys} && chmod 644 {cert_sys} && chcon u:object_r:system_file:s0 {cert_sys} && mount -o ro,remount /dev/sda1 /system && rm {remote_sd} && sync'"
                    exec_res = subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "{fallback_cmd}"', shell=True, capture_output=True, timeout=30)
                    if exec_res.returncode != 0:
                        self.last_error = f"Injection denied: {exec_res.stderr.decode().strip()}"
                        return False
            except subprocess.TimeoutExpired:
                self.last_error = "Injection timed out."
                return False

            time.sleep(1)
            log("Verifying installation...")
            check_cmd = f'"{self.adb_path}" -s {target_ip} shell "[ -f {cert_sys} ] && echo yes"'
            check_res = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if "yes" not in check_res.stdout:
                self.last_error = "Verification failed: file missing from system."
                return False

            log("Refreshing Android services...")
            try:
                subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "stop && sleep 2 && start"', shell=True, capture_output=True, timeout=15)
            except: pass
            
            return True
        except Exception as e:
            self.last_error = f"Installer error: {str(e)}"
            return False

    def uninstall_certificate(self, log_cb=None) -> bool:
        def log(m):
            if log_cb: log_cb(m)
            logger.info(m)
            
        if not self.ensure_adb_connection():
            return False
            
        try:
            target_ip = f"127.0.0.1:{self.adb_port}"
            hash_val = self.calculate_cert_hash() or "c8750f0d"
            cert_name = f"{hash_val}.0"
            log(f"Removing {cert_name}...")
            
            su_path = "/boot/android/android/system/xbin/bstk/su"
            cert_sys = f"/system/etc/security/cacerts/{cert_name}"
            
            uninstall_cmd = (
                f"{su_path} -c 'mount -o rw,remount /dev/sda1 /system && "
                f"rm -f {cert_sys} && "
                f"mount -o ro,remount /dev/sda1 /system && sync'"
            )
            
            subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "{uninstall_cmd} || (su -c \'{uninstall_cmd.split("-c ")[-1]}\')"', shell=True, capture_output=True, timeout=25)
            
            log("Refreshing UI...")
            try:
                subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "stop && sleep 2 && start"', shell=True, capture_output=True, timeout=15)
            except: pass
                
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def apply_proxy(self) -> bool:
        if not self.ensure_adb_connection():
            self.last_error = "ADB not connected"
            return False
        try:
            addr = self.proxy_address.strip()
            if not addr:
                addr = f"{get_local_ipv4()}:8080"
            cmd = f'"{self.adb_path}" -s 127.0.0.1:{self.adb_port} shell "settings put global http_proxy {addr}"'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def clear_proxy(self) -> bool:
        if not self.ensure_adb_connection():
            self.last_error = "ADB not connected"
            return False
        try:
            target_ip = f"127.0.0.1:{self.adb_port}"
            su = "/boot/android/android/system/xbin/bstk/su"
            cmds = [
                f"{su} -c 'settings put global http_proxy :0'",
                f"{su} -c 'settings delete global global_http_proxy_host'",
                f"{su} -c 'settings delete global global_http_proxy_port'"
            ]
            for c in cmds:
                subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "{c}"', shell=True, capture_output=True, timeout=10)
            return True
        except Exception as e:
            self.last_error = str(e)
            return False


# ── CUSTOM WIDGETS ─────────────────────────────────────────────────────────────

class GlowButton(ctk.CTkButton):
    """Pill-shaped button with left accent stripe + brightness-shift hover."""
    def __init__(self, master, glow_color=ACCENT, **kwargs):
        kwargs.setdefault("corner_radius", 8)
        kwargs.setdefault("border_width", 0)
        kwargs.setdefault("fg_color", kwargs.pop("fg_color", ACCENT_DIM))
        kwargs.setdefault("hover_color", ACCENT2)
        kwargs.setdefault("text_color", TEXT_PRI)
        kwargs.setdefault("font", FONT_BTN)
        kwargs.setdefault("height", 44)
        kwargs.setdefault("anchor", "center")
        self._base_fg   = kwargs["fg_color"]
        self._hover_fg  = kwargs["hover_color"]
        self._glow      = glow_color
        super().__init__(master, **kwargs)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, _=None):
        self.configure(fg_color=self._hover_fg,
                       border_width=1, border_color=self._glow)

    def _on_leave(self, _=None):
        self.configure(fg_color=self._base_fg,
                       border_width=0)


class SectionCard(ctk.CTkFrame):
    """Card with a thin top accent rule and bold section label."""
    def __init__(self, master, title: str, accent=ACCENT, **kwargs):
        kwargs.setdefault("fg_color", BG_CARD)
        kwargs.setdefault("corner_radius", 10)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", BORDER)
        super().__init__(master, **kwargs)

        # Top accent stripe
        stripe = tk.Frame(self, bg=accent, height=2)
        stripe.pack(fill="x", padx=2, pady=(0, 0))

        # Title row
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=14, pady=(7, 2))
        # Small square icon
        icon_lbl = tk.Label(header, text="▪", bg=BG_CARD, fg=accent,
                            font=(_F, 10, "bold"))
        icon_lbl.pack(side="left", padx=(0, 5))
        ctk.CTkLabel(header, text=title.upper(),
                     font=FONT_HEAD, text_color=TEXT_SEC).pack(side="left")


class StyledEntry(ctk.CTkEntry):
    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", BG_PANEL)
        kwargs.setdefault("border_color", ACCENT_DIM)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("text_color", TEXT_PRI)
        kwargs.setdefault("placeholder_text_color", TEXT_SEC)
        kwargs.setdefault("font", FONT_BODY)
        kwargs.setdefault("corner_radius", 8)
        kwargs.setdefault("height", 38)
        super().__init__(master, **kwargs)


class StyledDropdown(ctk.CTkOptionMenu):
    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", BG_PANEL)
        kwargs.setdefault("button_color", ACCENT)
        kwargs.setdefault("button_hover_color", ACCENT2)
        kwargs.setdefault("dropdown_fg_color", BG_CARD2)
        kwargs.setdefault("dropdown_hover_color", ACCENT_DIM)
        kwargs.setdefault("dropdown_text_color", TEXT_PRI)
        kwargs.setdefault("text_color", TEXT_PRI)
        kwargs.setdefault("font", FONT_BODY)
        kwargs.setdefault("dropdown_font", FONT_BODY)
        kwargs.setdefault("corner_radius", 8)
        kwargs.setdefault("height", BTN_HEIGHT_LG)
        kwargs.setdefault("dynamic_resizing", False)
        super().__init__(master, **kwargs)


# ── MAIN APP ───────────────────────────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cert_manager = CertificateManager()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("")
        self.geometry("900x560")
        self.resizable(False, False)
        self.configure(fg_color=BG_PANEL)

        if os.path.exists("logo.ico"):
            try: self.iconbitmap("logo.ico")
            except: pass

        self._build_ui()

        self.emu_option.set("BlueStacks App Player")
        self.on_emu_change("BlueStacks App Player")

        self.after(1000, self.start_auto_connect)
        self.after(3000, self.update_status_loop)

    # ── UI CONSTRUCTION ────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── TOP BAR ───────────────────────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color=BG_CARD, height=58, corner_radius=0)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        # Right: admin badge (packed first so center stays true)
        admin_text = "● ADMIN" if is_admin() else "● USER"
        admin_col  = SUCCESS if is_admin() else WARN
        ctk.CTkLabel(top, text=admin_text, font=FONT_SMALL,
                     text_color=admin_col).pack(side="right", padx=20)

        # Center: main title  ── BYPASS INSTALLER  v1
        title_frame = ctk.CTkFrame(top, fg_color="transparent")
        title_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(title_frame, text="BYPASS ",
                     font=("Segoe UI", 22, "bold"),
                     text_color=TEXT_PRI).pack(side="left")
        ctk.CTkLabel(title_frame, text="INSTALLER",
                     font=("Segoe UI", 22, "bold"),
                     text_color=ACCENT).pack(side="left")
        # v1 badge - pill shaped
        badge = ctk.CTkFrame(title_frame, fg_color=ACCENT,
                              corner_radius=10, width=36, height=22)
        badge.pack(side="left", padx=(10, 0), pady=(5, 0))
        badge.pack_propagate(False)
        ctk.CTkLabel(badge, text="v1", font=("Segoe UI", 10, "bold"),
                     text_color="#ffffff").pack(expand=True)

        # Thin accent line below header
        line = tk.Frame(self, bg=ACCENT, height=2)
        line.pack(fill="x")

        # ── BODY ──────────────────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=10)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # LEFT COLUMN
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        # ── Emulator Card ──
        emu_card = SectionCard(left, "Emulator", accent=ACCENT)
        emu_card.pack(fill="x", pady=(0, 8))

        emu_inner = ctk.CTkFrame(emu_card, fg_color="transparent")
        emu_inner.pack(fill="x", padx=14, pady=(2, 4))

        self.emu_option = StyledDropdown(
            emu_inner,
            values=["Select Emulator", "BlueStacks App Player", "BlueStacks China", "MSI App Player"],
            command=self.on_emu_change
        )
        self.emu_option.pack(fill="x", pady=(0, 8))

        self.info_label = ctk.CTkLabel(emu_inner, text="Version: Unknown",
                                       font=FONT_SMALL, text_color=TEXT_SEC)
        self.info_label.pack(anchor="w", pady=(0, 8))

        emu_btn_row = ctk.CTkFrame(emu_inner, fg_color="transparent")
        emu_btn_row.pack(fill="x", pady=(0, 8))
        emu_btn_row.columnconfigure(0, weight=1)
        emu_btn_row.columnconfigure(1, weight=1)

        self.access_btn = GlowButton(emu_btn_row, text="GET ACCESS",
                                     glow_color=ACCENT, fg_color=ACCENT,
                                     hover_color=ACCENT2, height=BTN_HEIGHT_MAIN,
                                     text_color="#ffffff",
                                     command=self.get_access_action)
        self.access_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.refresh_emu_btn = GlowButton(emu_btn_row, text="REFRESH",
                                          glow_color=ACCENT, fg_color=BG_CARD2,
                                          hover_color=ACCENT_DIM, height=BTN_HEIGHT_MAIN,
                                          font=FONT_BTN_SM, text_color=TEXT_PRI,
                                          command=self.refresh_emulator_action)
        self.refresh_emu_btn.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # ── ADB Card ──
        adb_card = SectionCard(left, "ADB Connection", accent=ACCENT)
        adb_card.pack(fill="x", pady=(0, 8))

        adb_inner = ctk.CTkFrame(adb_card, fg_color="transparent")
        adb_inner.pack(fill="x", padx=14, pady=(2, 4))

        port_row = ctk.CTkFrame(adb_inner, fg_color="transparent")
        port_row.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(port_row, text="PORT", font=("Segoe UI", 9, "bold"),
                     text_color=TEXT_SEC, width=44).pack(side="left")
        self.port_entry = StyledEntry(port_row, placeholder_text="5555")
        self.port_entry.insert(0, "5555")
        self.port_entry.pack(side="left", fill="x", expand=True)

        # Status pill
        self.status_frame = ctk.CTkFrame(adb_inner, fg_color=BG_PANEL,
                                          corner_radius=6, height=28)
        self.status_frame.pack(fill="x", pady=(0, 8))
        self.status_label = ctk.CTkLabel(self.status_frame,
                                          text="● OFFLINE", font=("Segoe UI", 10, "bold"),
                                          text_color=DANGER)
        self.status_label.pack(pady=5)

        self.conn_btn = GlowButton(adb_inner, text="CONNECT ADB",
                                    glow_color=ACCENT, fg_color=ACCENT,
                                    hover_color=ACCENT2, height=BTN_HEIGHT_MAIN,
                                    text_color="#ffffff",
                                    command=self.toggle_conn_action)
        self.conn_btn.pack(fill="x", pady=(0, 8))

        # RIGHT COLUMN
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        # ── Certificate Card ──
        cert_card = SectionCard(right, "Certificate Security", accent=SUCCESS)
        cert_card.pack(fill="x", pady=(0, 8))

        cert_inner = ctk.CTkFrame(cert_card, fg_color="transparent")
        cert_inner.pack(fill="x", padx=14, pady=(2, 4))

        # File info chip
        self.file_chip = ctk.CTkFrame(cert_inner, fg_color=BG_PANEL,
                                       corner_radius=6, height=32)
        self.file_chip.pack(fill="x", pady=(0, 8))
        self.file_label = ctk.CTkLabel(self.file_chip, text="No file selected",
                                        font=FONT_SMALL, text_color=TEXT_SEC)
        self.file_label.pack(pady=6, padx=10)

        self.browse_btn = GlowButton(cert_inner, text="BROWSE CERT FILE",
                                      glow_color=ACCENT, fg_color=ACCENT,
                                      hover_color=ACCENT2, height=BTN_HEIGHT_MAIN,
                                      text_color="#ffffff",
                                      command=self.browse_cert_action)
        self.browse_btn.pack(fill="x", pady=(0, 6))

        cert_btn_row = ctk.CTkFrame(cert_inner, fg_color="transparent")
        cert_btn_row.pack(fill="x", pady=(0, 8))
        cert_btn_row.columnconfigure(0, weight=1)
        cert_btn_row.columnconfigure(1, weight=1)

        self.install_btn = GlowButton(cert_btn_row,
                                       text="INSTALL CERT",
                                       glow_color=ACCENT, fg_color=ACCENT,
                                       hover_color=ACCENT2, height=BTN_HEIGHT_MAIN,
                                       font=FONT_BTN_SM,
                                       text_color="#ffffff",
                                       command=self.install_cert_action)
        self.install_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.remove_btn = GlowButton(cert_btn_row, text="REMOVE CERT",
                                      glow_color=DANGER, fg_color=BG_CARD2,
                                      hover_color="#3d1520", height=BTN_HEIGHT_MAIN,
                                      font=FONT_BTN_SM,
                                      text_color=TEXT_PRI,
                                      command=self.remove_cert_action)
        self.remove_btn.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # ── Proxy Card ──
        proxy_card = SectionCard(right, "Proxy Configuration", accent=WARN)
        proxy_card.pack(fill="x", pady=(0, 8))

        proxy_inner = ctk.CTkFrame(proxy_card, fg_color="transparent")
        proxy_inner.pack(fill="x", padx=14, pady=(2, 4))

        proxy_row = ctk.CTkFrame(proxy_inner, fg_color="transparent")
        proxy_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(proxy_row, text="ADDR", font=("Segoe UI", 9, "bold"),
                     text_color=TEXT_SEC, width=44).pack(side="left")
        self.proxy_entry = StyledEntry(proxy_row)
        self.proxy_entry.insert(0, self.cert_manager.proxy_address)
        self.proxy_entry.pack(side="left", fill="x", expand=True)

        btn_row = ctk.CTkFrame(proxy_inner, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 10))
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=1)

        self.apply_proxy_btn = GlowButton(btn_row, text="APPLY",
                                           glow_color=ACCENT, fg_color=ACCENT,
                                           hover_color=ACCENT2, height=BTN_HEIGHT_SM,
                                           font=FONT_BTN_SM,
                                           text_color="#ffffff",
                                           command=self.apply_proxy_action)
        self.apply_proxy_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.clear_proxy_btn = GlowButton(btn_row, text="CLEAR",
                                           glow_color=DANGER, fg_color=BG_CARD2,
                                           hover_color="#3d1520", height=BTN_HEIGHT_SM,
                                           font=FONT_BTN_SM,
                                           text_color=TEXT_PRI,
                                           command=self.clear_proxy_action)
        self.clear_proxy_btn.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # ── LOG BAR ───────────────────────────────────────────────────────────
        log_border = tk.Frame(self, bg=BORDER, height=1)
        log_border.pack(fill="x")

        log_header = ctk.CTkFrame(self, fg_color=BG_CARD, height=24, corner_radius=0)
        log_header.pack(fill="x")
        log_header.pack_propagate(False)
        ctk.CTkLabel(log_header, text="▸ SYSTEM LOG",
                     font=("Segoe UI", 9, "bold"), text_color=TEXT_SEC).pack(side="left", padx=18, pady=4)

        self.log_text = ctk.CTkTextbox(
            self, height=116,
            font=("Consolas", 10),
            fg_color="#1a1f2b",
            text_color="#3ddc84",
            border_width=0,
            corner_radius=0,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=ACCENT_DIM
        )
        self.log_text.pack(fill="x", padx=0, pady=0)

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
        ts = time.strftime('%H:%M:%S')
        self.log_text.insert("end", f"[{ts}]  {msg}\n")
        self.log_text.see("end")

    def start_auto_connect(self):
        threading.Thread(target=self.auto_connect, daemon=True).start()

    def auto_connect(self):
        try:
            self.add_log("Scanning for devices...")
            self.cert_manager.adb_port = self.port_entry.get()
            if self.cert_manager.connect_adb():
                self.add_log("ADB linked successfully.")
            else:
                self.add_log(f"Link fail — {self.cert_manager.last_error}")
        except Exception as e:
            logger.exception("Auto connect crashed")
            self.add_log(f"Auto-connect error: {e}")

    def on_emu_change(self, val):
        emu_map = {"BlueStacks App Player": EmulatorType.BLUESTACKS5,
                   "BlueStacks China": EmulatorType.BLUESTACKS_CN,
                   "MSI App Player": EmulatorType.MSI5}
        emu_type = emu_map.get(val, EmulatorType.NONE)
        self.cert_manager.select_emulator(emu_type)
        info = self.cert_manager.get_emulator_info(emu_type)
        self.info_label.configure(text=f"{info['name']} | Version: {info['version']}")
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, self.cert_manager.adb_port)
        self.add_log(f"Target → {val}  (port {self.cert_manager.adb_port})")

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
                self.add_log("Waiting for ADB handshake...")
                start = time.time()
                while time.time() - start < 90:
                    if self.cert_manager.is_connected: break
                    if self.cert_manager.connect_adb():
                        self.add_log("ADB auto-linked.")
                        break
                    time.sleep(5)
                if not self.cert_manager.is_connected:
                    self.add_log("ADB auto-link timed out.")
            threading.Thread(target=poll_adb, daemon=True).start()
        else:
            self.add_log(f"Launch failed: {self.cert_manager.last_error}")

    def toggle_conn_action(self):
        self.cert_manager.adb_port = self.port_entry.get()
        if self.cert_manager.is_connected:
            self.cert_manager.disconnect_adb()
            self.add_log("ADB link severed.")
        else:
            self.add_log(f"Connecting to port {self.cert_manager.adb_port}...")
            if self.cert_manager.connect_adb():
                self.add_log("ADB linked.")
            else:
                self.add_log(f"Link failed: {self.cert_manager.last_error}")

    def browse_cert_action(self):
        path = filedialog.askopenfilename(
            title="Select Certificate",
            filetypes=[("Certificates", "*.pem *.cer *.crt"), ("All Files", "*.*")]
        )
        if path:
            self.cert_manager.certificate_path = path
            self.file_label.configure(text=os.path.basename(path), text_color=SUCCESS)
            self.add_log(f"Cert loaded: {os.path.basename(path)}")

    def install_cert_action(self):
        def task():
            if self.cert_manager.install_certificate(log_cb=self.add_log):
                self.add_log("▶ INJECTION SUCCESS.")
            else:
                self.add_log(f"✕ INJECTION FAILED: {self.cert_manager.last_error}")
        threading.Thread(target=task, daemon=True).start()

    def remove_cert_action(self):
        def task():
            if self.cert_manager.uninstall_certificate(log_cb=self.add_log):
                self.add_log("▶ CLEANUP SUCCESS.")
            else:
                self.add_log(f"✕ CLEANUP FAILED: {self.cert_manager.last_error}")
        threading.Thread(target=task, daemon=True).start()

    def apply_proxy_action(self):
        self.cert_manager.proxy_address = self.proxy_entry.get()
        if self.cert_manager.apply_proxy():
            self.add_log(f"Proxy active: {self.cert_manager.proxy_address}")
        else:
            self.add_log(f"Proxy failed: {self.cert_manager.last_error}")

    def clear_proxy_action(self):
        if self.cert_manager.clear_proxy():
            self.add_log("Proxy cleared.")
        else:
            self.add_log("Proxy clear failed.")

    def update_status_loop(self):
        if self.cert_manager.is_connected and not self.cert_manager.is_adb_ready():
            self.cert_manager.is_connected = False
        if self.cert_manager.is_connected:
            self.status_label.configure(text="● LINKED", text_color=SUCCESS)
            self.conn_btn.configure(text="DISCONNECT ADB")
        else:
            self.status_label.configure(text="● OFFLINE", text_color=DANGER)
            self.conn_btn.configure(text="CONNECT ADB")
        self.after(3000, self.update_status_loop)


if __name__ == "__main__":
    try:
        ensure_admin()   # Re-launch with UAC elevation if not admin
        app = App()
        app.mainloop()
    except Exception as exc:
        logger.exception("Fatal startup/runtime error")
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