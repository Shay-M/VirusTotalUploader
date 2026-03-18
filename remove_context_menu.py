import winreg

MENU_TEXT = "Scan with VirusTotal"
REGISTRY_KEY_PATH = rf"*\shell\{MENU_TEXT}"


def delete_registry_tree(root, subkey: str) -> None:
    """Delete a registry key tree recursively."""
    with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        while True:
            try:
                child_name = winreg.EnumKey(key, 0)
                delete_registry_tree(root, rf"{subkey}\{child_name}")
            except OSError:
                break

    winreg.DeleteKey(root, subkey)


def remove_context_menu() -> None:
    """Remove the VirusTotal context menu entry."""
    delete_registry_tree(winreg.HKEY_CLASSES_ROOT, REGISTRY_KEY_PATH)
    print(f"Menu item '{MENU_TEXT}' removed successfully.")


if __name__ == "__main__":
    try:
        remove_context_menu()
    except FileNotFoundError:
        print("Menu entry was not found.")
    except PermissionError:
        print("ERROR: Please run this script as Administrator.")
    except Exception as error:
        print(f"An unexpected error occurred: {error}")