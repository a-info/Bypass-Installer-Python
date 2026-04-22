# Bypass Installer v1.0

A professional certificate management and system bypass tool for Android Emulators (BlueStacks and MSI App Player). This tool allows you to inject CA certificates into the system store and configure system-wide proxies with ease.

## ✨ Features
*   **System Injection**: Automatically injects CA certificates into `/system/etc/security/cacerts/` using privileged access.
*   **Emulator Bypass**: Modifies emulator configurations to enable Read/Write access to system partitions.
*   **Proxy Management**: Easily apply or clear system-wide HTTP proxies.
*   **Auto-Detection**: Automatically finds BlueStacks and MSI installations and their ADB ports.
*   **Clean UI**: Modern dark-themed interface built with CustomTkinter.

## 🚀 How to Use
1.  **Run as Administrator**: Right-click `Bypass Installer.exe` and select "Run as Administrator".
2.  **Select Emulator**: Choose your emulator (BlueStacks or MSI) from the dropdown.
3.  **Get Access**: Click the "Get Access" button. This will launch the emulator and prepare the system for modifications.
4.  **Install Certificate**:
    *   Place your certificate (e.g., `mitmproxy-ca-cert.cer`) in the same folder or browse for it.
    *   Click "Install Certificate (.0) & Reboot".
    *   The app will automatically calculate the correct Android hash name and inject it.
5.  **Configure Proxy**: Enter your proxy IP and Port (e.g., `127.0.0.1:8080`) and click "Apply Proxy".

## 🛠️ Requirements
*   **Windows OS** (Runs best on Windows 10/11)
*   **BlueStacks 5** or **MSI App Player 5**
*   **Administrator Privileges**

## ⚠️ Disclaimer
This tool is provided for educational and testing purposes only. Modifying system files can potentially cause instability in your emulator. Always keep a backup of your important data.

---
*Created by A!*
# Bypass-Installer-Python
