import os
import shutil
import json
import ctypes
import threading
import traceback
import webbrowser
from pathlib import Path
import winreg as reg

# Optional/Windows-specific imports guarded for clearer errors
try:
    import win32security
    import win32con
except Exception:
    win32security = None
    win32con = None

# ----- GUI (customtkinter) -----
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

try:
    import customtkinter as ctk
except ImportError:
    raise SystemExit("Please install customtkinter: pip install customtkinter")

APP_TITLE = "CSET Stencil Loader Helper"
LOG_LINES_MAX = 500

# ----------------- Core Step Functions -----------------

def ensure_windows():
    if os.name != "nt":
        raise RuntimeError("This tool only supports Windows.")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def friendly_exc(ex: Exception) -> str:
    tb = traceback.format_exc(limit=1)
    return f"{ex.__class__.__name__}: {ex} | {tb.strip()}"

def get_paths():
    user_profile = os.environ.get('USERPROFILE')
    if not user_profile:
        raise RuntimeError("USERPROFILE is not set.")
    base = Path(user_profile) / "AppData" / "Roaming" / "Trane"
    source_path = base / "CSET" / "Stencils" / "CSET"
    destination_path = base / "Stencils copy"
    stencil_file_path = source_path / "stenciltoload.cset"
    return stencil_file_path, source_path, destination_path

def deny_full_control_to_current_user(file_path: Path):
    if not win32security or not win32con:
        raise RuntimeError("pywin32 not available. Install with: pip install pywin32")
    username = os.getlogin()
    user_sid, _, _ = win32security.LookupAccountName(None, username)

    sd = win32security.GetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        dacl = win32security.ACL()

    # Deny ACE for full control on the file
    dacl.AddAccessDeniedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, user_sid)
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION, sd)

def replace_stencil_file():
    ensure_windows()
    stencil_file_path, _, _ = get_paths()

    stencil_file_path.parent.mkdir(parents=True, exist_ok=True)
    # Create/replace with an empty JSON list (your original said “empty dictionary” but used []; keeping [])
    new_content = json.dumps([])
    stencil_file_path.write_text(new_content, encoding="utf-8")

    # Set deny permissions only if running as admin (or we can try; if fails, we report)
    deny_full_control_to_current_user(stencil_file_path)

    return f"Replaced {stencil_file_path} and set deny ACL."

def copy_folders():
    ensure_windows()
    _, source_path, destination_path = get_paths()

    if not source_path.exists():
        raise FileNotFoundError(f"Source path not found: {source_path}")

    destination_path.mkdir(parents=True, exist_ok=True)

    # Copy everything except 'stenciltoload.cset'
    # For directories -> copytree (dirs_exist_ok=True)
    # For files -> copy2, skipping the .cset file specifically
    copied = []
    for item in source_path.iterdir():
        src = item
        dst = destination_path / item.name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
            copied.append(f"[DIR] {src.name}")
        elif src.is_file() and src.name != "stenciltoload.cset":
            shutil.copy2(src, dst)
            copied.append(f"[FILE] {src.name}")

    return f"Copied {len(copied)} items to '{destination_path}'."

def add_to_trusted_sites():
    ensure_windows()
    domain = "umw-stencil-loader.s3.amazonaws.com"
    # Internet Options -> ZoneMap\Domains\<domain>\https DWORD = 2 (Trusted Sites)
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains",
                         0, reg.KEY_WRITE) as domains_key:
            try:
                # You can nest subkeys for subdomains; using exact domain as provided
                subkey = reg.CreateKey(domains_key, domain)
                reg.SetValueEx(subkey, "https", 0, reg.REG_DWORD, 2)
            finally:
                pass
    except PermissionError:
        raise PermissionError("Registry write denied. Run as Administrator.")
    return f"Added https://{domain} to Trusted Sites (zone 2)."

def open_installation_url():
    url = "https://umw-stencil-loader.s3.amazonaws.com/UMWStencilLoader.vsto"
    webbrowser.open(url)
    return f"Opened installer URL: {url}"

# ----------------- GUI App -----------------

class Step:
    def __init__(self, name, func, default=True):
        self.name = name
        self.func = func
        self.enabled = tk.BooleanVar(value=default)
        self.result = ""
        self.details = ""

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("850x520")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.steps = [
            Step("Replace stencil file and set security", replace_stencil_file, True),
            Step("Copy folders (exclude .cset)", copy_folders, True),
            Step("Add URL to Trusted Sites", add_to_trusted_sites, True),
            Step("Open installation URL", open_installation_url, True),
        ]

        self._build_ui()
        self.worker = None
        self.log_lines = []

    def _build_ui(self):
        # Top section: step checkboxes + Run button
        top = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=(12, 6))

        left = ctk.CTkFrame(top, corner_radius=10)
        left.pack(side="left", fill="x", expand=True, padx=(0, 6), pady=6)

        ctk.CTkLabel(left, text="Steps to run:", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=10, pady=(10, 0))
        for s in self.steps:
            cb = ctk.CTkCheckBox(left, text=s.name, variable=s.enabled)
            cb.pack(anchor="w", padx=10, pady=4)

        right = ctk.CTkFrame(top, corner_radius=10)
        right.pack(side="right", fill="y", padx=(6, 0), pady=6)

        self.run_btn = ctk.CTkButton(right, text="Run", command=self.on_run_clicked, width=160, height=40)
        self.run_btn.pack(padx=12, pady=(18, 6))

        self.admin_label = ctk.CTkLabel(right, text=("Running as Admin" if is_admin() else "Not Admin"),
                                        text_color=("green" if is_admin() else "orange"))
        self.admin_label.pack(padx=12, pady=(6, 12))

        # Progress bar
        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=12, pady=(6, 6))

        # Status table
        table_frame = ctk.CTkFrame(self, corner_radius=10)
        table_frame.pack(fill="both", expand=True, padx=12, pady=6)

        columns = ("Step", "Result", "Details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
        for col, w in zip(columns, (220, 90, 460)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        # Log area (compact)
        bottom = ctk.CTkFrame(self, corner_radius=10)
        bottom.pack(fill="both", expand=False, padx=12, pady=(0, 12))

        ctk.CTkLabel(bottom, text="Log (last ~500 lines):").pack(anchor="w", padx=8, pady=(8, 0))
        self.log_text = tk.Text(bottom, height=6, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        # Style Treeview to match dark mode
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Treeview", background="#1f1f1f", foreground="#e5e5e5", fieldbackground="#1f1f1f", rowheight=24)
        style.configure("Treeview.Heading", background="#2b2b2b", foreground="#ffffff")

        self.reset_table()

    def reset_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for s in self.steps:
            self.tree.insert("", "end", iid=s.name, values=(s.name, "", ""))

    def on_run_clicked(self):
        if self.worker and self.worker.is_alive():
            return
        self.reset_table()
        self.progress.set(0)
        self.log_text.delete("1.0", tk.END)
        self.log_lines.clear()
        self.run_btn.configure(state="disabled", text="Running...")

        self.worker = threading.Thread(target=self.run_steps_worker, daemon=True)
        self.worker.start()
        self.after(150, self.poll_worker)

    def poll_worker(self):
        if self.worker and self.worker.is_alive():
            self.after(150, self.poll_worker)
        else:
            self.run_btn.configure(state="normal", text="Run")
            messagebox.showinfo(APP_TITLE, "Completed.")

    def append_log(self, line: str):
        self.log_lines.append(line)
        if len(self.log_lines) > LOG_LINES_MAX:
            self.log_lines = self.log_lines[-LOG_LINES_MAX:]
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, "\n".join(self.log_lines))
        self.log_text.see(tk.END)
        self.update_idletasks()

    def update_row(self, step_name: str, result: str, details: str):
        self.tree.item(step_name, values=(step_name, result, details))
        self.update_idletasks()

    def run_steps_worker(self):
        enabled_steps = [s for s in self.steps if s.enabled.get()]
        total = len(enabled_steps) if enabled_steps else 1
        done = 0

        if not enabled_steps:
            self.append_log("No steps selected. Nothing to do.")
            self.progress.set(1.0)
            return

        for s in enabled_steps:
            try:
                self.append_log(f"Running: {s.name}")
                msg = s.func()  # execute step
                s.result = "Success"
                s.details = msg
                self.append_log(f"✓ {s.name}: {msg}")
                self.update_row(s.name, "Success", msg)
            except Exception as ex:
                err = friendly_exc(ex)
                s.result = "Error"
                s.details = err
                self.append_log(f"✗ {s.name}: {err}")
                self.update_row(s.name, "Error", err)
            finally:
                done += 1
                self.progress.set(done / total)


def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
