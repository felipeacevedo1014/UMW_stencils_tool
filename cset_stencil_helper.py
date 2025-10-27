import os
import sys
import shutil
import json
import ctypes
import traceback
import webbrowser
from pathlib import Path
import winreg as reg

FILE_ATTRIBUTE_READONLY = 0x01

def log(msg):  # simple consistent logging
    print(msg, flush=True)

def ok(msg):
    print(f"[OK] {msg}", flush=True)

def fail(msg):
    print(f"[ERROR] {msg}", flush=True)

def ensure_windows():
    if os.name != "nt":
        raise RuntimeError("This tool only supports Windows.")

def get_paths():
    user_profile = os.environ.get('USERPROFILE')
    if not user_profile:
        raise RuntimeError("USERPROFILE is not set.")
    base = Path(user_profile) / "AppData" / "Roaming" / "Trane"
    source_path = base / "CSET" / "Stencils" / "CSET"
    destination_path = base / "Stencils copy"
    stencil_file_path = source_path / "stenciltoload.cset"
    return stencil_file_path, source_path, destination_path

def set_readonly(path: Path):
    # Use Windows API to set file attribute read-only (no admin needed)
    res = ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_READONLY)
    if res == 0:
        raise OSError(f"SetFileAttributesW failed for {path}")

def replace_stencil_file():
    """Create/replace stenciltoload.cset with [] and mark read-only (no ACLs)."""
    ensure_windows()
    stencil_file_path, _, _ = get_paths()

    stencil_file_path.parent.mkdir(parents=True, exist_ok=True)
    stencil_file_path.write_text(json.dumps([]), encoding="utf-8")
    ok(f"Wrote empty list to: {stencil_file_path}")

    try:
        # Best-effort read-only flag so CSET won’t casually overwrite it
        set_readonly(stencil_file_path)
        ok(f"Marked file as read-only: {stencil_file_path}")
    except Exception as ex:
        fail(f"Could not set read-only attribute: {ex}")

def copy_folders():
    """Copy everything from source to destination, excluding stenciltoload.cset."""
    ensure_windows()
    _, source_path, destination_path = get_paths()

    if not source_path.exists():
        raise FileNotFoundError(f"Source path not found: {source_path}")

    destination_path.mkdir(parents=True, exist_ok=True)

    copied = 0
    for item in source_path.iterdir():
        src = item
        dst = destination_path / item.name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
            copied += 1
        elif src.is_file() and src.name != "stenciltoload.cset":
            shutil.copy2(src, dst)
            copied += 1

    ok(f"Copied {copied} items to '{destination_path}' (skipped stenciltoload.cset).")

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
    except Exception as ex:
        fail(f"Error opening URL: {ex}")

def main():
    print("=== UMW Stencil Tool (Console) ===", flush=True)
    steps = [
        ("Replace stencil file", replace_stencil_file),
        ("Copy folders", copy_folders),
        ("Add Trusted Site", add_to_trusted_sites),
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
    if success:
        print("\nAll steps completed.", flush=True)
    else:
        print("\nOne or more steps failed. See messages above.", flush=True)

    # >>> Always pause here so the window stays open <<<
    input("\nPress Enter to close this window...")

    # Optional: return a proper exit code after the pause
    import sys
    sys.exit(0 if success else 1)



if __name__ == "__main__":
    main()
