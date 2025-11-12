import os
import sys
import shutil
import json
import traceback
import webbrowser
from pathlib import Path
import winreg as reg

def log(msg):   print(msg, flush=True)
def ok(msg):    print(f"[OK] {msg}", flush=True)
def fail(msg):  print(f"[ERROR] {msg}", flush=True)

def ensure_windows():
    if os.name != "nt":
        raise RuntimeError("This tool only supports Windows.")

def get_paths_main():
    """Main stencil path set."""
    user_profile = os.environ.get('USERPROFILE')
    if not user_profile:
        raise RuntimeError("USERPROFILE is not set.")
    base = Path(user_profile) / "AppData" / "Roaming" / "Trane"
    source_path = base / "CSET" / "Stencils" / "CSET"
    destination_path = base / "Stencils copy"
    stencil_file_path = source_path / "stenciltoload.cset"
    return stencil_file_path, source_path, destination_path

def get_user_data_stencil_path():
    """%APPDATA%\\Trane\\CSET\\UserData\\stenciltoload.cset"""
    appdata = os.environ.get('APPDATA')  # C:\Users\<user>\AppData\Roaming
    if not appdata:
        raise RuntimeError("APPDATA is not set.")
    return Path(appdata) / "Trane" / "CSET" / "UserData" / "stenciltoload.cset"

def open_stencils_folder(path: Path):
    try:
        if path.parent.exists():
            os.startfile(str(path.parent))
        else:
            fail(f"Folder does not exist: {path.parent}")
    except Exception as ex:
        fail(f"Could not open folder: {ex}")


def print_manual_security_instructions(path: Path):
    print(
        "\n>>> Manual step (company policy):\n"
        f"   File: {path}\n"
        "   1) Right-click → Properties → Security.\n"
        "   2) Edit… → Select your user.\n"
        "   3) Deny: Full Control.\n"
        "   4) Apply/OK.\n",
        flush=True
    )

def write_empty_list(path: Path):
    """
    Create or overwrite the file with '[]'.
    No ACL/attribute changes. If we can't write, we log it and move on.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps([]), encoding='utf-8')
        ok(f"Wrote empty list to: {path}")
    except Exception as ex:
        fail(f"Could not write file '{path}': {ex}")

def replace_stencil_file_main():
    """Create/overwrite main stenciltoload.cset with [], then open folder for manual security."""
    ensure_windows()
    stencil_file_path, _, _ = get_paths_main()
    write_empty_list(stencil_file_path)
    open_stencils_folder(stencil_file_path)

def replace_stencil_file_userdata():
    """Create/overwrite UserData stenciltoload.cset with []."""
    ensure_windows()
    stencil_file_path = get_user_data_stencil_path()
    write_empty_list(stencil_file_path)


def copy_folders():
    """Copy everything from source to destination (directories only).
    Skip any folders that already exist in the destination.
    """
    ensure_windows()
    _, source_path, destination_path = get_paths_main()

    if not source_path.exists():
        raise FileNotFoundError(f"Source path not found: {source_path}")

    destination_path.mkdir(parents=True, exist_ok=True)

    copied = 0
    for item in source_path.iterdir():
        src = item
        dst = destination_path / item.name
        if src.is_dir():
            # Only copy if destination folder doesn't already exist
            if not dst.exists():
                shutil.copytree(src, dst)
                copied += 1

    ok(f"Copied {copied} new folders to '{destination_path}'.")


def add_to_trusted_sites():
    """Add umw-stencil-loader.s3.amazonaws.com to Trusted Sites (HKCU)."""
    ensure_windows()
    domain = "umw-stencil-loader.s3.amazonaws.com"
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains",
                         0, reg.KEY_WRITE) as domains_key:
            subkey = reg.CreateKeyEx(domains_key, domain, 0, reg.KEY_SET_VALUE)
            # Trusted Sites = 2; set for https
            reg.SetValueEx(subkey, "https", 0, reg.REG_DWORD, 2)
        ok(f"Added https://{domain} to Trusted Sites (per-user).")
    except PermissionError:
        fail("Registry write denied by policy (HKCU). Ask IT or skip this step.")
    except Exception as ex:
        fail(f"Could not add Trusted Site: {ex}")

def open_installation_url():
    url = "https://umw-stencil-loader.s3.amazonaws.com/UMWStencilLoader.vsto"
    try:
        webbrowser.open(url)
        ok(f"Opened installer URL: {url}")
        ok("If the installer does not start, copy and paste the URL into your browser.")
    except Exception as ex:
        fail(f"Error opening URL: {ex}")

def main():
    print("=== UMW Stencil Tool (Console) ===", flush=True)
    steps = [
        ("Create/overwrite stenciltoload.cset (Stencils) and open folder", replace_stencil_file_main),
        ("Create/overwrite stenciltoload.cset (UserData)", replace_stencil_file_userdata),
        ("Copy Stencils folders", copy_folders),
        ("Add installer to Trusted Sites", add_to_trusted_sites),
        ("Open installer URL", open_installation_url),
    ]

    results = []
    for name, fn in steps:
        log(f"> {name} ...")
        try:
            fn()
            results.append((name, True, "OK"))
        except Exception as ex:
            results.append((name, False, f"{ex.__class__.__name__}: {ex}"))
            fail(f"{name} failed: {ex}")
            tb = traceback.format_exc(limit=1).strip()
            if tb:
                log(f"  Traceback: {tb}")

    print("\n--- Summary ---", flush=True)
    for name, okflag, detail in results:
        prefix = "OK " if okflag else "XX "
        print(f"{prefix} {name} - {detail}", flush=True)

    success = all(okflag for _, okflag, _ in results)
    print("\nAll steps completed." if success else "\nOne or more steps failed. See messages above.", flush=True)

    stencil_file_path, _, _ = get_paths_main()
    print_manual_security_instructions(stencil_file_path)


    input("\nPress Enter to close this window...")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
