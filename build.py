import subprocess
import sys
import os

def main():
    print("=" * 60)
    print("🚀 Starting Build Process: Bypass Installer")
    print("=" * 60)

    # Step 1: Run PyInstaller
    print("\n[1/2] Building executable with PyInstaller...")
    try:
        subprocess.run([sys.executable, "-m", "PyInstaller", "Bypass Installer.spec"], check=True)
        print("✅ PyInstaller build completed successfully.")
    except subprocess.CalledProcessError:
        print("❌ PyInstaller build failed!")
        sys.exit(1)

    # Step 2: Sign the executable
    print("\n[2/2] Signing executable to bypass Windows Defender...")
    script_path = os.path.join("scripts", "sign_exe.ps1")
    
    if os.path.exists(script_path):
        try:
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path], check=True)
            print("✅ Executable signed successfully.")
        except subprocess.CalledProcessError:
            print("❌ Signing failed! You may need to run this script as Administrator, or the certificate generation failed.")
            sys.exit(1)
    else:
        print(f"⚠️ Warning: Signing script not found at {script_path}")

    print("\n🎉 Build and Sign process complete! Check the 'dist' folder.")

if __name__ == "__main__":
    main()
