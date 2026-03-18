import winreg
import sys
import os

def setup_context_menu():
    # השגת הנתיב ל-pythonw.exe (שמריץ GUI בלי חלון שחור)
    pythonw_exe = sys.executable.lower().replace("python.exe", "pythonw.exe")
    # וודא שהנתיב לסקריפט שלך נכון
    script_path = os.path.abspath("vt_uploader.py")
    
    # הפקודה שתירשם ב-Registry
    command = f'"{pythonw_exe}" "{script_path}" "%1"'
    
    # הנתיבים ב-Registry
    key_path = r"*\shell\Scan with VirusTotal"
    command_path = rf"{key_path}\command"
    
    try:
        # 1. יצירת המפתח הראשי (מה שמופיע בתפריט)
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "Scan with VirusTotal")
            # אופציונלי: הוספת אייקון לתפריט (אם יש לך קובץ .ico)
            # winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'"{pythonw_exe}"')

        # 2. יצירת מפתח הפקודה
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, command_path) as key:
            winreg.SetValue(key, "", winreg.REG_SZ, command)
            
        print("--- Success! ---")
        print(f"Menu item 'Scan with VirusTotal' created.")
        print(f"Command set to: {command}")
        print("You can now right-click any file to scan it.")
        
    except PermissionError:
        print("ERROR: Please run this terminal/script as Administrator!")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    setup_context_menu()