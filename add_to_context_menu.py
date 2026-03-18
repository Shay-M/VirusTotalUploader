# import winreg
# import sys
# import os

# def update_context_menu_to_windowed():
#     # Get the directory of current python.exe and swap to pythonw.exe
#     python_exe = sys.executable.lower().replace("python.exe", "pythonw.exe")
#     script_path = os.path.abspath("vt_uploader.py")
    
#     # The command: "pythonw.exe" "script.py" "%1"
#     command = f'"{python_exe}" "{script_path}" "%1"'
    
#     key_path = r"*\shell\Scan with VirusTotal\command"
    
#     try:
#         with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path, 0, winreg.KEY_SET_VALUE) as key:
#             winreg.SetValue(key, "", winreg.REG_SZ, command)
#         print("Updated Registry to use pythonw.exe (No console window).")
#     except FileNotFoundError:
#         print("Registry key not found. Make sure you've run the setup script first.")
#     except PermissionError:
#         print("Please run this script as Administrator.")

# if __name__ == "__main__":
#     update_context_menu_to_windowed()