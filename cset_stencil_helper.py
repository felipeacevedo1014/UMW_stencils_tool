import os
import sys
import shutil
import json
import traceback
import webbrowser
from pathlib import Path
import winreg as reg
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import os

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


def create_umwstencilloader_config():
    """Create %APPDATA%\\UMWStencilLoader and write settings.json."""
    ensure_windows()
    appdata = os.environ.get('APPDATA')  # e.g., C:\Users\<user>\AppData\Roaming
    if not appdata:
        raise RuntimeError("APPDATA is not set.")

    cfg_dir = Path(appdata) / "UMWStencilLoader"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "settings.json"

    payload = {
        "StencilFoldersPath": [
            r"%appdata%\Trane\Stencils copy"
        ],
        "StencilExcludePaths": [],
        "DictShapes": "Error: \n\nVisio cannot open the file because it's not a Visio file or it has become corrupted."
    }

    try:
        cfg_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        ok(f"Wrote settings.json at: {cfg_path}")
    except Exception as ex:
        fail(f"Could not write settings.json '{cfg_path}': {ex}")



def show_manual_security_gui(target_file: Path):
    """
    Simple Tkinter wizard that shows step-by-step instructions with screenshots.
    PNGs are loaded from ./assets/manual_security/*.png if present.
    """
    ensure_windows()

    # Define your steps (title, description, image filename)
    assets_dir = Path(__file__).parent / "assets" / "manual_security"
    steps = [
        (
            "Right-click the file",
            f"Navigate to the folder and right-click the file:\n{target_file.name}\nChoose 'Properties'.",
            "step1_right_click_properties.png",
        ),
        (
            "Open the Security tab",
            "In the Properties window, click the 'Security' tab.",
            "step2_security_tab.png",
        ),
        (
            "Edit permissions",
            "Click 'Edit…', then select your Windows user in the list.",
            "step3_edit_select_user.png",
        ),
        (
            "Deny Full Control - Click Apply/OK",
            "Under 'Permissions for <your user>', check 'Deny' for 'Full control'.\nClick Apply and then OK.",
            "step4_deny_full_control.png",
        ),
    ]

    root = tk.Tk()
    root.title("Manual Security Instructions")
    root.geometry("720x920")   # wider so bold text wraps nicer
    root.minsize(720, 980)

    # --- TOP: Bold title
    title_var = tk.StringVar(value="")
    lbl_title = ttk.Label(root, textvariable=title_var, font=("Segoe UI", 14, "bold"))
    lbl_title.pack(padx=12, pady=(12, 6), anchor="w")

    # --- TOP (still): Bold description (moved above image and set to bold)
    desc_var = tk.StringVar(value="")
    lbl_desc = ttk.Label(root, textvariable=desc_var, font=("Segoe UI", 11, "bold"), wraplength=760, justify="left")
    lbl_desc.pack(padx=12, pady=(0, 8), anchor="w")

    # --- MIDDLE: image area
    canvas = tk.Canvas(root, highlightthickness=0)
    canvas.pack(fill="both", expand=True, padx=12, pady=6)

    # --- BOTTOM controls
    bottom = ttk.Frame(root)
    bottom.pack(fill="x", padx=12, pady=12)

    btn_back = ttk.Button(bottom, text="◀ Back")
    btn_next = ttk.Button(bottom, text="Next ▶")
    btn_open = ttk.Button(bottom, text="Open Folder")
    btn_close = ttk.Button(bottom, text="Close")

    btn_back.grid(row=0, column=0, padx=(0, 6))
    btn_next.grid(row=0, column=1, padx=(0, 6))
    bottom.grid_columnconfigure(2, weight=1)
    btn_open.grid(row=0, column=3, padx=6)
    btn_close.grid(row=0, column=5, padx=(6, 0))

    state = {"index": 0, "photo": None, "img_native": None}

    def open_folder():
        try:
            if target_file.parent.exists():
                os.startfile(str(target_file.parent))
            else:
                messagebox.showerror("Error", f"Folder does not exist:\n{target_file.parent}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder:\n{e}")

    def load_image_fit_canvas(image_path: Path):
        try:
            img = tk.PhotoImage(file=str(image_path))
        except Exception:
            return None

        c_w = max(canvas.winfo_width(), 1)
        c_h = max(canvas.winfo_height(), 1)
        img_w = img.width()
        img_h = img.height()

        scale_w = max(img_w // c_w, 1)
        scale_h = max(img_h // c_h, 1)
        subsample = max(scale_w, scale_h, 1)
        if subsample > 1:
            img = img.subsample(subsample, subsample)
        return img

    def render():
        i = state["index"]
        title, desc, img_file = steps[i]
        title_var.set(f"Step {i+1} of {len(steps)} — {title}")
        desc_var.set(desc)

        canvas.delete("all")
        img_path = assets_dir / img_file
        photo = load_image_fit_canvas(img_path)
        state["photo"] = photo

        if photo is None:
            canvas.create_text(
                canvas.winfo_width() // 2,
                canvas.winfo_height() // 2,
                text=f"(Missing image)\n{img_path}",
                font=("Segoe UI", 10),
                justify="center"
            )
        else:
            x = canvas.winfo_width() // 2
            y = canvas.winfo_height() // 2
            canvas.create_image(x, y, image=photo)

        btn_back.config(state=("disabled" if i == 0 else "normal"))
        btn_next.config(text=("Finish" if i == len(steps) - 1 else "Next ▶"))

    def on_back():
        if state["index"] > 0:
            state["index"] -= 1
            render()

    def on_next():
        if state["index"] < len(steps) - 1:
            state["index"] += 1
            render()
        else:
            root.destroy()

    def on_resize(_event):
        render()

    btn_back.config(command=on_back)
    btn_next.config(command=on_next)
    btn_open.config(command=open_folder)
    btn_close.config(command=root.destroy)

    root.bind("<Configure>", on_resize)
    root.bind("<Left>", lambda e: on_back())
    root.bind("<Right>", lambda e: on_next())
    root.bind("<Escape>", lambda e: root.destroy())

    root.after(50, render)
    root.mainloop()


def main():
    print("=== UMW Stencil Tool (Console) ===", flush=True)

    # define this ONCE up front so you can use it later
    stencil_file_path, _, _ = get_paths_main()

    steps = [
        ("Create/overwrite stenciltoload.cset (Stencils) and open folder", replace_stencil_file_main),
        ("Create/overwrite stenciltoload.cset (UserData)", replace_stencil_file_userdata),
        ("Copy Stencils folders", copy_folders),
        ("Create UMWStencilLoader config JSON", create_umwstencilloader_config),  
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

    # text instructions
    print_manual_security_instructions(stencil_file_path)

    # GUI instructions (BEFORE input/sys.exit)
    try:
        show_manual_security_gui(stencil_file_path)
    except Exception as ex:
        fail(f"Could not display GUI instructions: {ex}")

    # keep the console open after GUI closes
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()


