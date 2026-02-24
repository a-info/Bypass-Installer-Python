#!/usr/bin/env python3
"""
CertInstaller v1.0 - Python Edition
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

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() # type: ignore
    except:
        return False

class EmulatorType(Enum):
    NONE = "None"
    BLUESTACKS5 = "BlueStacks App Player"
    MSI5 = "MSI App Player"

class CertificateManager:
    """Manages certificate installation and emulator operations"""
    
    def __init__(self):
        self.selected_emulator = EmulatorType.NONE
        self.adb_port = "5555"
        self.certificate_path = ""
        self.cert_hash = ""
        self.proxy_address = "127.0.0.1:8080"
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
            # BlueStacks 5
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BlueStacks_nxt") as key: # type: ignore
                    val, _ = winreg.QueryValueEx(key, "InstallDir") # type: ignore
                    install_dir = str(val)
                    hd_player_path = os.path.join(install_dir, "HD-Player.exe")
                    if os.path.exists(hd_player_path):
                        paths[EmulatorType.BLUESTACKS5] = hd_player_path
            except (FileNotFoundError, OSError):
                default_bs5 = r"C:\Program Files\BlueStacks_nxt\HD-Player.exe"
                if os.path.exists(default_bs5):
                    paths[EmulatorType.BLUESTACKS5] = default_bs5
            
            # MSI AppPlayer 5
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BlueStacks_msi5") as key: # type: ignore
                    val, _ = winreg.QueryValueEx(key, "InstallDir") # type: ignore
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
            elif emulator_type == EmulatorType.MSI5:
                reg_path = r"SOFTWARE\BlueStacks_msi5"
            else:
                return info
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key: # type: ignore
                val, _ = winreg.QueryValueEx(key, "InstallDir") # type: ignore
                install_dir = str(val)
                info["path"] = os.path.join(install_dir, "HD-Player.exe")
                info["adb_path"] = os.path.join(install_dir, "HD-Adb.exe")
                try:
                    ver_val, _ = winreg.QueryValueEx(key, "Version") # type: ignore
                    info["version"] = str(ver_val)
                except:
                    info["version"] = "Detected"
        except:
            # Fallback check
            paths = self.get_emulator_paths()
            if emulator_type in paths:
                info["path"] = paths[emulator_type]
                info["adb_path"] = os.path.join(os.path.dirname(paths[emulator_type]), "HD-Adb.exe")
                info["version"] = "Detected (Default Path)"
        
        # Verify HD-Adb exists, else fallback to standard adb
        adb_p = str(info.get("adb_path", "adb"))
        if not os.path.exists(adb_p):
            info["adb_path"] = "adb"
            
        return info
    
    def select_emulator(self, emulator_type: EmulatorType) -> bool:
        """Sets the active emulator and updates info"""
        self.selected_emulator = emulator_type
        info = self.get_emulator_info(emulator_type)
        self.emulator_name = info["name"]
        self.emulator_version = info["version"]
        self.adb_path = info["adb_path"]
        
        # Auto-detect port when emulator changes
        detected_port = self.detect_adb_port(emulator_type)
        if detected_port:
            self.adb_port = detected_port
            return True
        return False

    def detect_adb_port(self, emulator_type: EmulatorType) -> Optional[str]:
        """Try to find the ADB port from emulator config files"""
        try:
            config_path = ""
            if emulator_type == EmulatorType.BLUESTACKS5:
                config_path = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_nxt", "bluestacks.conf")
            elif emulator_type == EmulatorType.MSI5:
                config_path = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_msi5", "bluestacks.conf")
            
            if config_path and os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Look for adb_port in the config
                    import re
                    # Finding the port for the default instance (usually 'instance.nougat32' or 'instance.Pie64')
                    matches = re.findall(r'adb_port="(\d+)"', content)
                    if matches:
                        # Return the highest port found (usually the active one)
                        return matches[-1]
        except Exception as e:
            logger.error(f"Port detection failed: {e}")
        return None
    
    def force_kill_emulators(self) -> bool:
        """Force kill all BlueStacks and MSI processes"""
        try:
            # Added more common process names
            processes = [
                "HD-Player.exe", "BlueStacks.exe", "BstkSVC.exe", 
                "HD-MultiInstanceManager.exe", "MSIAppPlayer.exe",
                "BlueStacksService.exe", "BstkAgent.exe"
            ]
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
            # Shell=True allows starting without blocking
            subprocess.Popen(f'"{exe_path}"', shell=True)
            return True
        except Exception as e:
            self.last_error = str(e)
            return False
    
    def connect_adb(self) -> bool:
        if not self.check_adb_exists():
            # Try to find adb in common locations
            common_paths = [
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", "adb.exe"),
                "C:\\adb\\adb.exe",
                os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "BlueStacks_nxt", "adb.exe")
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
            # Ensure server is running (increase timeout for start-server)
            subprocess.run(f'"{self.adb_path}" start-server', shell=True, timeout=15)
            
            # Try connecting
            cmd = f'"{self.adb_path}" connect {target}'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=20)
            
            if "connected" in result.stdout.lower() or "already connected" in result.stdout.lower():
                self.is_connected = True
                # Brief wait for stability
                subprocess.run(f'"{self.adb_path}" -s {target} wait-for-device', shell=True, timeout=5)
                return True
            
            self.last_error = result.stdout.strip() or result.stderr.strip()
            return False
        except subprocess.TimeoutExpired:
            self.last_error = "ADB connection timed out (Server unresponsive)"
            return False
        except Exception as e:
            self.last_error = str(e)
            return False
    
    def disconnect_adb(self) -> bool:
        try:
            subprocess.run(f'"{self.adb_path}" disconnect 127.0.0.1:{self.adb_port}', capture_output=True, shell=True, timeout=5)
            self.is_connected = False
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def calculate_cert_hash(self) -> Optional[str]:
        if not self.certificate_path or not os.path.exists(self.certificate_path):
            return None
        try:
            # Try openssl INFORM PEM
            cmd = f'openssl x509 -inform PEM -subject_hash_old -in "{self.certificate_path}" -noout'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
            if result.returncode == 0:
                self.cert_hash = result.stdout.strip()
                return self.cert_hash
        except:
            pass
        self.cert_hash = "c8750f0d" # Default
        return self.cert_hash

    def bypass_access(self) -> bool:
        """Modify .bstk configs and clean log artifacts to grant full access"""
        try:
            program_data = os.environ.get("ProgramData", "C:\\ProgramData")
            engine_root = ""
            
            if self.selected_emulator == EmulatorType.MSI5:
                options = ["BlueStacks_msi5", "BlueStacks_msi", "BlueStacks_msi2"]
            else:
                options = ["BlueStacks_nxt", "BlueStacks"]
                
            for opt in options:
                path = os.path.join(program_data, opt, "Engine")
                if os.path.exists(path):
                    engine_root = path
                    break
            
            if not engine_root:
                self.last_error = "Engine root path not found"
                return False
                
            # 1. Patch configs
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
                        
                        # Root.vhd R/W
                        content = re.sub(r'(<HardDisk\b[^>]*location\s*=\s*"Root\.vhd"[^>]*type\s*=\s*")Readonly(")', r'\1Normal\2', content, flags=re.IGNORECASE)
                        # Data.vhdx R/W
                        content = re.sub(r'(<HardDisk\b[^>]*location\s*=\s*"Data\.vhdx"[^>]*type\s*=\s*")Readonly(")', r'\1Normal\2', content, flags=re.IGNORECASE)
                        
                        with open(conf, "w", encoding="utf-8") as f:
                            f.write(content)
            
            # 2. Clean Logs (New from C# snippet)
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
            
            # Step 1: Ensure local certificate exists (Local Method as requested)
            final_path = self.certificate_path
            if not final_path or not os.path.exists(final_path):
                fallbacks = ["mitmproxy-ca-cert.cer", "ca.cer", "cert.0"]
                found = False
                for fb in fallbacks:
                    if os.path.exists(fb):
                        final_path = os.path.abspath(fb)
                        self.certificate_path = final_path
                        found = True
                        log(f"Auto-detecting local cert: {fb}")
                        break
                
                if not found:
                    self.last_error = "No local certificate file found. Please select one manually."
                    return False
            else:
                final_path = os.path.abspath(final_path)

            # Step 2: Calculate Hash for filename (Mirror C# CertHash logic)
            log("Identifying certificate hash...")
            hash_val = self.calculate_cert_hash() or "c8750f0d"
            cert_name = f"{hash_val}.0"
            log(f"Target Filename: {cert_name}")

            # Step 3: ADB Link (Exact C# logic - no adb root/remount)
            if not self.is_connected:
                log("Establishing ADB Link...")
                if not self.connect_adb(): return False
            
            # Step 4: Transfer to /sdcard/
            log(f"Pushing certificate to /sdcard/{cert_name}...")
            remote_sd = f"/sdcard/{cert_name}"
            try:
                # Use longer timeout for push
                push_res = subprocess.run(f'"{self.adb_path}" -s {target_ip} push "{final_path}" {remote_sd}', capture_output=True, shell=True, timeout=60)
                if push_res.returncode != 0:
                    err = push_res.stderr.decode().strip() or push_res.stdout.decode().strip()
                    self.last_error = f"Push Failed: {err}"
                    return False
            except subprocess.TimeoutExpired:
                self.last_error = "ADB Push timed out. Connection lost."
                return False

            # Step 5: System Injection via su -c (BlueStacks Way)
            su_path = "/boot/android/android/system/xbin/bstk/su"
            cert_sys = f"/system/etc/security/cacerts/{cert_name}"
            
            log("Injecting to System Store...")
            # Command sequence matching C# exactly
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
                    log("Primary su failed, trying global fallback...")
                    # Fallback to general su -c if bstk/su is missing
                    fallback_cmd = f"su -c 'mount -o rw,remount /dev/sda1 /system && cp {remote_sd} {cert_sys} && chmod 644 {cert_sys} && chcon u:object_r:system_file:s0 {cert_sys} && mount -o ro,remount /dev/sda1 /system && rm {remote_sd} && sync'"
                    exec_res = subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "{fallback_cmd}"', shell=True, capture_output=True, timeout=30)
                    if exec_res.returncode != 0:
                        self.last_error = f"Injection Denied: {exec_res.stderr.decode().strip()}"
                        return False
            except subprocess.TimeoutExpired:
                self.last_error = "Injection command timed out."
                return False

            # Step 6: Verify and Refresh (Zygote)
            time.sleep(1) # As in C# Thread.Sleep(1000)
            log("Verifying installation...")
            check_cmd = f'"{self.adb_path}" -s {target_ip} shell "[ -f {cert_sys} ] && echo yes"'
            check_res = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if "yes" not in check_res.stdout:
                self.last_error = "Verification failed: Certificate file missing from system folder."
                return False

            log("Refreshing Android Services...")
            try:
                subprocess.run(f'"{self.adb_path}" -s {target_ip} shell "stop && sleep 2 && start"', shell=True, capture_output=True, timeout=15)
            except: pass
            
            return True
        except Exception as e:
            self.last_error = f"Installer Error: {str(e)}"
            return False

    def uninstall_certificate(self, log_cb=None) -> bool:
        def log(m):
            if log_cb: log_cb(m)
            logger.info(m)
            
        if not self.is_connected:
            if not self.connect_adb(): return False
            
        try:
            target_ip = f"127.0.0.1:{self.adb_port}"
            hash_val = self.calculate_cert_hash() or "c8750f0d"
            cert_name = f"{hash_val}.0"
            
            log(f"Removing certificate {cert_name}...")
            
            su_path = "/boot/android/android/system/xbin/bstk/su"
            cert_sys = f"/system/etc/security/cacerts/{cert_name}"
            
            # Match C# uninstall command
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
        if not self.is_connected: return False
        try:
            addr = self.proxy_address.strip()
            if not addr: addr = "127.0.0.1:8080"
            cmd = f'"{self.adb_path}" -s 127.0.0.1:{self.adb_port} shell "settings put global http_proxy {addr}"'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def clear_proxy(self) -> bool:
        if not self.is_connected: return False
        try:
            target_ip = f"127.0.0.1:{self.adb_port}"
            su = "/boot/android/android/system/xbin/bstk/su"
            
            # Mirror the C# Cleanup logic
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

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cert_manager = CertificateManager()
        
        self.title("")
        self.geometry("920x600")
        self.resizable(False, False)
        
        # Set Window Icon
        if os.path.exists("logo.ico"):
            try:
                self.iconbitmap("logo.ico")
            except:
                pass
                
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0) # Title row
        self.grid_rowconfigure(1, weight=1) # Main content row
        self.grid_rowconfigure(2, weight=0) # Log row

        self.create_widgets()
        
        # FIX: Manually select BlueStacks as default and trigger logic
        self.emu_option.set("BlueStacks App Player")
        self.on_emu_change("BlueStacks App Player")
        
        self.after(1000, self.auto_connect)
        self.after(3000, self.update_status_loop)

    def create_widgets(self):
        # MAIN TITLE (Centered)
        self.top_title = ctk.CTkLabel(self, text="Bypass Installer", font=ctk.CTkFont(size=28, weight="bold"))
        self.top_title.grid(row=0, column=0, columnspan=2, pady=(20, 0))

        # LEFT COLUMN
        self.left_col = ctk.CTkFrame(self, fg_color="transparent")
        self.left_col.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        

        # Emulator Box
        self.emu_frame = ctk.CTkFrame(self.left_col)
        self.emu_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(self.emu_frame, text="Emulator Management", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.emu_option = ctk.CTkOptionMenu(self.emu_frame, values=["Select Emulator", "BlueStacks App Player", "MSI App Player"], command=self.on_emu_change)
        self.emu_option.pack(pady=5, padx=15, fill="x")
        self.info_label = ctk.CTkLabel(self.emu_frame, text="Version: Unknown", text_color="gray")
        self.info_label.pack(pady=2)
        
        self.access_btn = ctk.CTkButton(self.emu_frame, text="Get Access", font=ctk.CTkFont(weight="bold"), command=self.get_access_action)
        self.access_btn.pack(pady=5, padx=15, fill="x")
        
        self.kill_btn = ctk.CTkButton(self.emu_frame, text="FORCE KILL ALL EMULATORS", fg_color="#a10000", hover_color="#7a0000", font=ctk.CTkFont(weight="bold"), command=self.kill_emulators_action)
        self.kill_btn.pack(pady=5, padx=15, fill="x")

        # ADB Box
        self.adb_frame = ctk.CTkFrame(self.left_col)
        self.adb_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(self.adb_frame, text="ADB Connection", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.port_entry = ctk.CTkEntry(self.adb_frame, placeholder_text="ADB Port")
        self.port_entry.insert(0, "5555")
        self.port_entry.pack(pady=5, padx=15, fill="x")
        self.status_label = ctk.CTkLabel(self.adb_frame, text="Status: Disconnected", text_color="#ff5555")
        self.status_label.pack(pady=2)
        self.conn_btn = ctk.CTkButton(self.adb_frame, text="Connect ADB", command=self.toggle_conn_action)
        self.conn_btn.pack(pady=10, padx=15, fill="x")

        # RIGHT COLUMN
        self.right_col = ctk.CTkFrame(self, fg_color="transparent")
        self.right_col.grid(row=1, column=1, sticky="nsew", padx=20, pady=20)
        
        # Certificate Box
        self.cert_frame = ctk.CTkFrame(self.right_col)
        self.cert_frame.pack(fill="x", pady=(5, 5))
        ctk.CTkLabel(self.cert_frame, text="Certificate Security", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.file_label = ctk.CTkLabel(self.cert_frame, text="No certificate file selected", text_color="gray", wraplength=350)
        self.file_label.pack(pady=2)
        self.browse_btn = ctk.CTkButton(self.cert_frame, text="Browse Cert File", command=self.browse_cert_action)
        self.browse_btn.pack(pady=5, padx=15, fill="x")
        self.install_btn = ctk.CTkButton(self.cert_frame, text="Install Certificate (.0) & Reboot", fg_color="#1f538d", command=self.install_cert_action)
        self.install_btn.pack(pady=5, padx=15, fill="x")
        self.remove_btn = ctk.CTkButton(self.cert_frame, text="Remove Certificate & Reboot", fg_color="#444", command=self.remove_cert_action)
        self.remove_btn.pack(pady=5, padx=15, fill="x")

        # Proxy Box
        self.proxy_frame = ctk.CTkFrame(self.right_col)
        self.proxy_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(self.proxy_frame, text="Proxy Configuration (IP:Port)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.proxy_entry = ctk.CTkEntry(self.proxy_frame)
        self.proxy_entry.insert(0, "127.0.0.1:8080")
        self.proxy_entry.pack(pady=5, padx=15, fill="x")
        self.apply_proxy_btn = ctk.CTkButton(self.proxy_frame, text="Apply Proxy", command=self.apply_proxy_action)
        self.apply_proxy_btn.pack(pady=5, padx=15, fill="x")
        self.clear_proxy_btn = ctk.CTkButton(self.proxy_frame, text="Clear System Proxy", fg_color="#444", command=self.clear_proxy_action)
        self.clear_proxy_btn.pack(pady=5, padx=15, fill="x")

        # Bottom Log
        self.log_text = ctk.CTkTextbox(self, height=120, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_text.grid(row=2, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="ew")
        
        status = "ADMIN ACTIVE" if is_admin() else "USER MODE (Limited)"
        color = "cyan" if is_admin() else "yellow"
        self.add_log(f"System State: {status}", color)

    def add_log(self, msg, color=None):
        self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        # Could colorize if needed but complex in ctk textbox, just plain text
        self.log_text.see("end")

    def auto_connect(self):
        self.add_log("Searching for devices...")
        self.cert_manager.adb_port = self.port_entry.get()
        if self.cert_manager.connect_adb():
            self.add_log("ADB Linked successfully.")
        else:
            self.add_log(f"Link Fail: {self.cert_manager.last_error}")

    def on_emu_change(self, val):
        emu_map = {"BlueStacks App Player": EmulatorType.BLUESTACKS5, "MSI App Player": EmulatorType.MSI5}
        emu_type = emu_map.get(val, EmulatorType.NONE)
        self.cert_manager.select_emulator(emu_type)
        info = self.cert_manager.get_emulator_info(emu_type)
        self.info_label.configure(text=f"Version: {info['version']}")
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, self.cert_manager.adb_port)
        self.add_log(f"Target set to: {val} (Auto-Port: {self.cert_manager.adb_port})")

    def kill_emulators_action(self):
        self.add_log("Killing all emulator processes...")
        if self.cert_manager.force_kill_emulators():
            self.add_log("Cleanup complete.")
        else:
            self.add_log(f"Cleanup error: {self.cert_manager.last_error}")

    def get_access_action(self):
        self.add_log("Commencing System Grant...")
        
        # 1. Kill existing processes to release file locks
        self.cert_manager.force_kill_emulators()
        
        # 2. Apply Configuration Bypass (Normal Disk Mode)
        if self.cert_manager.bypass_access():
            self.add_log("Configuration Bypass Applied (R/W Enabled)")
        else:
            self.add_log(f"Bypass Warning: {self.cert_manager.last_error}")
            
        # 3. Launch
        if self.cert_manager.get_access():
            self.add_log(f"Launching {self.cert_manager.selected_emulator.value}...")
            
            # Start background polling for ADB auto-connect
            def poll_adb():
                self.add_log("Waiting for ADB handshake...")
                start_time = time.time()
                timeout = 90
                while time.time() - start_time < timeout:
                    if self.cert_manager.is_connected: break
                    if self.cert_manager.connect_adb():
                        self.add_log("ADB Linked automatically!")
                        break
                    time.sleep(5)
                if not self.cert_manager.is_connected:
                    self.add_log("ADB Auto-link timeout.")
            
            threading.Thread(target=poll_adb, daemon=True).start()
        else:
            self.add_log(f"Launch Fail: {self.cert_manager.last_error}")
            self.add_log(f"Launch Fail: {self.cert_manager.last_error}")

    def toggle_conn_action(self):
        self.cert_manager.adb_port = self.port_entry.get()
        if self.cert_manager.is_connected:
            self.cert_manager.disconnect_adb()
            self.add_log("ADB Link Severed.")
        else:
            self.add_log(f"Attempting manual link to port {self.cert_manager.adb_port}...")
            if self.cert_manager.connect_adb():
                self.add_log("ADB Linked.")
            else:
                self.add_log(f"Link Fail: {self.cert_manager.last_error}")

    def browse_cert_action(self):
        path = filedialog.askopenfilename(title="Select Certificate", filetypes=[("Certificates", "*.pem *.cer *.crt"), ("All Files", "*.*")])
        if path:
            self.cert_manager.certificate_path = path
            self.file_label.configure(text=os.path.basename(path))
            self.add_log(f"Cert Selected: {os.path.basename(path)}")

    def install_cert_action(self):
        def task():
            if self.cert_manager.install_certificate(log_cb=self.add_log):
                self.add_log("INJECTION SUCCESS.")
            else:
                self.add_log(f"INJECTION FAILED: {self.cert_manager.last_error}")
        threading.Thread(target=task, daemon=True).start()

    def remove_cert_action(self):
        def task():
            if self.cert_manager.uninstall_certificate(log_cb=self.add_log):
                self.add_log("CLEANUP SUCCESS.")
            else:
                self.add_log(f"CLEANUP FAILED: {self.cert_manager.last_error}")
        threading.Thread(target=task, daemon=True).start()

    def apply_proxy_action(self):
        self.cert_manager.proxy_address = self.proxy_entry.get()
        if self.cert_manager.apply_proxy():
            self.add_log(f"Proxy Active: {self.cert_manager.proxy_address}")
        else:
            self.add_log(f"Proxy Failed: {self.cert_manager.last_error}")

    def clear_proxy_action(self):
        if self.cert_manager.clear_proxy():
            self.add_log("Proxy Cleared.")
        else:
             self.add_log("Proxy Clear Failed.")

    def update_status_loop(self):
        if self.cert_manager.is_connected:
            self.status_label.configure(text="Status: Linked", text_color="cyan")
            self.conn_btn.configure(text="Disconnect ADB")
        else:
            self.status_label.configure(text="Status: Offline", text_color="#ff5555")
            self.conn_btn.configure(text="Connect ADB")
        self.after(3000, self.update_status_loop)

if __name__ == "__main__":
    # Ensure dist folder is not causing permission errors if user runs from there
    app = App()
    app.mainloop()

# TO BUILD:
# python -m PyInstaller --onefile --noconsole --name CertInstaller --collect-all customtkinter cert_installer_python.py
