import os
import sys
import shutil
import json
import ctypes
import traceback
import webbrowser
from pathlib import Path
import winreg as reg

# --- pywin32 for ACLs ---
try:
    import win32security
    import ntsecuritycon as ntsc
except Exception as e:
    raise SystemExit("pywin32 is required. Install with: pip install pywin32")

# ----------------- Constants / Helpers -----------------
FILE_ATTRIBUTE_READONLY = 0x01

def set_readonly(path: str | Path, make_readonly: bool):
    """Set or clear the Windows READONLY attribute (no admin needed)."""
    p = str(path)
    attrs = ctypes.windll.kernel32.GetFileAttributesW(p)
    if attrs == -1:
        # file might not exist yet; nothing to do
        return
    ctypes.windll.kernel32.SetFileAttributesW(
        p,
        (attrs | FILE_ATTRIBUTE_READONLY) if make_readonly else (attrs & ~FILE_ATTRIBUTE_READONLY)
    )

def force_delete_file(path: Path, retries: int = 2):
    """Best-effort delete: clear read-only, try remove; final fallback rename to .bak."""
    try:
        set_readonly(path, False)
    except Exception:
        pass
    for attempt in range(retries + 1):
        try:
            if path.exists():
                os.remove(path)
            return
        except PermissionError:
            if attempt == retries:
                bak = path.with_suffix(path.suffix + ".bak")
                try:
                    if bak.exists():
                        try:
                            os.remove(bak)
                        except Exception:
                            pass
                    os.replace(path, bak)
                    return
                except Exception:
                    raise

def log(msg):   print(msg, flush=True)
def ok(msg):    print(f"[OK] {msg}", flush=True)
def fail(msg):  print(f"[ERROR] {msg}", flush=True)

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

# ----------------- ACL logic -----------------
def deny_read_write_exec_modify_for_current_user(file_path: Path):
    """
    Prepend a DENY ACE for the current user covering:
      FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
    """
    username = os.getlogin()
    user_sid, _, _ = win32security.LookupAccountName(None, username)

    sd = win32security.GetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION)
    old_dacl = sd.GetSecurityDescriptorDacl()

    new_dacl = win32security.ACL()

    # What we want to deny (covers Read, Write, Read&Execute, Delete = "Modify"-like)
    deny_mask = (ntsc.FILE_GENERIC_READ |
                 ntsc.FILE_GENERIC_WRITE |
                 ntsc.FILE_GENERIC_EXECUTE |
                 ntsc.DELETE)

    # Put DENY first so it wins
    try:
        new_dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION_DS, 0, deny_mask, user_sid)
    except AttributeError:
        new_dacl.AddAccessDeniedAce(win32security.ACL_REVISION, deny_mask, user_sid)

    # Copy existing ACEs after our deny, handling both tuple formats
    def _unpack_ace(ace):
        # Returns (ace_type, ace_flags, access_mask, sid)
        if len(ace) == 4:
            return ace[0], ace[1], ace[2], ace[3]
        elif len(ace) == 3 and isinstance(ace[2], tuple) and len(ace[2]) == 2:
            return ace[0], ace[1], ace[2][0], ace[2][1]
        else:
            # Unknown/extended ACE form: skip it
            return None

    if old_dacl:
        for i in range(old_dacl.GetAceCount()):
            ace = old_dacl.GetAce(i)
            unpacked = _unpack_ace(ace)
            if not unpacked:
                # Ignore uncommon/object/audit ACEs we can't mirror cleanly
                continue
            ace_type, ace_flags, ace_mask, ace_sid = unpacked

            if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                try:
                    new_dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, ace_flags, ace_mask, ace_sid)
                except AttributeError:
                    new_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ace_mask, ace_sid)
            elif ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
                try:
                    new_dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION_DS, ace_flags, ace_mask, ace_sid)
                except AttributeError:
                    new_dacl.AddAccessDeniedAce(win32security.ACL_REVISION, ace_mask, ace_sid)
            else:
                # Skip other ACE types (system/audit/object)
                continue

    sd.SetSecurityDescriptorDacl(1, new_dacl, 1)
    win32security.SetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION, sd)


# ----------------- Steps -----------------
def replace_stencil_file():
    ensure_windows()
    stencil_file_path, _, _ = get_paths()
    stencil_file_path.parent.mkdir(parents=True, exist_ok=True)

    if stencil_file_path.exists():
        force_delete_file(stencil_file_path)
        ok(f"Deleted existing file: {stencil_file_path}")

    stencil_file_path.write_text(json.dumps([]), encoding='utf-8')
    ok(f"Wrote empty list to: {stencil_file_path}")

    # clear RO before DACL work (just in case)
    try:
        set_readonly(stencil_file_path, False)
    except Exception:
        pass

    deny_read_write_exec_modify_for_current_user(stencil_file_path)
    ok("Applied DENY (Read/Write/Execute/Delete) for current user")


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

# ----------------- Main -----------------
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
    print("\nAll steps completed." if success else "\nOne or more steps failed. See messages above.", flush=True)

    # Pause so the window stays open when double-clicked
    input("\nPress Enter to close this window...")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
