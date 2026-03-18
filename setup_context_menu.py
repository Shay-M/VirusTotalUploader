# import winreg
# import sys
# import os

# def setup_context_menu():
#     # השגת הנתיב ל-pythonw.exe (שמריץ GUI בלי חלון שחור)
#     pythonw_exe = sys.executable.lower().replace("python.exe", "pythonw.exe")
#     # וודא שהנתיב לסקריפט שלך נכון
#     script_path = os.path.abspath("vt_uploader.py")
    
#     # הפקודה שתירשם ב-Registry
#     command = f'"{pythonw_exe}" "{script_path}" "%1"'
    
#     # הנתיבים ב-Registry
#     key_path = r"*\shell\Scan with VirusTotal"
#     command_path = rf"{key_path}\command"
    
#     try:
#         # 1. יצירת המפתח הראשי (מה שמופיע בתפריט)
#         with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
#             winreg.SetValue(key, "", winreg.REG_SZ, "Scan with VirusTotal")
#             # אופציונלי: הוספת אייקון לתפריט (אם יש לך קובץ .ico)
#             # winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'"{pythonw_exe}"')

#         # 2. יצירת מפתח הפקודה
#         with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, command_path) as key:
#             winreg.SetValue(key, "", winreg.REG_SZ, command)
            
#         print("--- Success! ---")
#         print(f"Menu item 'Scan with VirusTotal' created.")
#         print(f"Command set to: {command}")
#         print("You can now right-click any file to scan it.")
        
#     except PermissionError:
#         print("ERROR: Please run this terminal/script as Administrator!")
#     except Exception as e:
#         print(f"An error occurred: {e}")

# if __name__ == "__main__":
#     setup_context_menu()

import argparse
import sys
import winreg
from pathlib import Path


MENU_TEXT = "Scan with VirusTotal"
SCRIPT_NAME = "vt_uploader.py"
ICON_NAME = "app.ico"

USER_SHELL_KEY = rf"Software\Classes\*\shell\{MENU_TEXT}"
USER_COMMAND_KEY = rf"{USER_SHELL_KEY}\command"

MACHINE_SHELL_KEY = rf"Software\Classes\*\shell\{MENU_TEXT}"
LEGACY_HKCR_SHELL_KEY = rf"*\shell\{MENU_TEXT}"


def get_script_dir() -> Path:
    return Path(__file__).resolve().parent


def get_pythonw_executable() -> Path:
    python_exe = Path(sys.executable).resolve()
    pythonw_exe = python_exe.with_name("pythonw.exe")

    if not pythonw_exe.exists():
        raise FileNotFoundError(f"pythonw.exe not found next to: {python_exe}")

    return pythonw_exe


def get_scanner_script() -> Path:
    script_path = get_script_dir() / SCRIPT_NAME

    if not script_path.exists():
        raise FileNotFoundError(f"Scanner script not found: {script_path}")

    return script_path


def get_icon_target() -> str:
    icon_path = get_script_dir() / ICON_NAME
    if icon_path.exists():
        return str(icon_path)

    return str(get_pythonw_executable())


def build_command() -> str:
    pythonw_exe = get_pythonw_executable()
    script = get_scanner_script()
    return f'"{pythonw_exe}" "{script}" "%1"'


def registry_key_exists(root, subkey):
    try:
        with winreg.OpenKey(root, subkey):
            return True
    except FileNotFoundError:
        return False


def delete_registry_tree(root, subkey):
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                    delete_registry_tree(root, f"{subkey}\\{child}")
                except OSError:
                    break
        winreg.DeleteKey(root, subkey)
        return True
    except FileNotFoundError:
        return False


def write_menu_entry():
    command = build_command()
    icon = get_icon_target()

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, USER_SHELL_KEY) as key:
        winreg.SetValue(key, "", winreg.REG_SZ, MENU_TEXT)
        winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, USER_COMMAND_KEY) as key:
        winreg.SetValue(key, "", winreg.REG_SZ, command)


def install(cleanup=False):
    write_menu_entry()

    print("\n✔ Installed context menu")

    if cleanup:
        if delete_registry_tree(winreg.HKEY_CLASSES_ROOT, LEGACY_HKCR_SHELL_KEY):
            print("✔ Removed old HKCR entry")

        if delete_registry_tree(winreg.HKEY_LOCAL_MACHINE, MACHINE_SHELL_KEY):
            print("✔ Removed machine-wide entry")


def uninstall(remove_all=False):
    removed_user = delete_registry_tree(winreg.HKEY_CURRENT_USER, USER_SHELL_KEY)
    removed_old = delete_registry_tree(winreg.HKEY_CLASSES_ROOT, LEGACY_HKCR_SHELL_KEY)

    print("\n--- Uninstall ---")
    print(f"User entry removed: {removed_user}")
    print(f"Old HKCR removed: {removed_old}")

    if remove_all:
        removed_machine = delete_registry_tree(winreg.HKEY_LOCAL_MACHINE, MACHINE_SHELL_KEY)
        print(f"Machine-wide removed: {removed_machine}")


def status():
    print("\n--- Status ---")
    print("User:", registry_key_exists(winreg.HKEY_CURRENT_USER, USER_SHELL_KEY))
    print("HKCR:", registry_key_exists(winreg.HKEY_CLASSES_ROOT, LEGACY_HKCR_SHELL_KEY))
    print("HKLM:", registry_key_exists(winreg.HKEY_LOCAL_MACHINE, MACHINE_SHELL_KEY))

    print("Pythonw:", get_pythonw_executable())
    print("Script:", get_scanner_script())
    print("Icon:", get_icon_target())


def menu():
    while True:
        print("\n=== VirusTotal Menu Setup ===")
        print("1. Status")
        print("2. Install")
        print("3. Install + cleanup")
        print("4. Uninstall")
        print("5. Uninstall (full)")
        print("0. Exit")

        choice = input("Choose: ").strip()

        if choice == "1":
            status()
        elif choice == "2":
            install()
        elif choice == "3":
            install(cleanup=True)
        elif choice == "4":
            uninstall()
        elif choice == "5":
            uninstall(remove_all=True)
        elif choice == "0":
            break
        else:
            print("Invalid option")


def main():
    if len(sys.argv) == 1:
        menu()
        return

    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["install", "uninstall", "status"])
    parser.add_argument("--cleanup-legacy", action="store_true")
    parser.add_argument("--all", action="store_true")

    args = parser.parse_args()

    if args.cmd == "install":
        install(cleanup=args.cleanup_legacy)
    elif args.cmd == "uninstall":
        uninstall(remove_all=args.all)
    elif args.cmd == "status":
        status()


if __name__ == "__main__":
    main()