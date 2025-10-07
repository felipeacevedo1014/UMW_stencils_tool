import os
import shutil
import win32security
import winreg as reg
import json
from pathlib import Path
import ctypes

# Function 1: Replace stenciltoload.cset with an empty dictionary and set security
def replace_stencil_file():
    user_profile = os.environ.get('USERPROFILE')
    stencil_file_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Trane', 'CSET', 'Stencils', 'CSET', 'stenciltoload.cset')

    # Create a new file with an empty dictionary
    new_content = json.dumps([])
    with open(stencil_file_path, 'w') as f:
        f.write(new_content)

    # Set the file permissions to Deny full control to the current user
    protect_file_read_only(stencil_file_path)

# Function to deny full control to the current user on the given file
def protect_file_read_only():
    # Get file path
    user_profile = os.environ['USERPROFILE']
    file_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Trane', 'CSET', 'Stencils', 'CSET', 'stenciltoload.cset')

    # Create the file with empty dictionary content
    with open(file_path, 'w') as f:
        json.dump([], f)

    # Get current user SID
    username = os.getlogin()
    user_sid, domain, type = win32security.LookupAccountName(None, username)

    # Get current DACL
    sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()

    # Define denied permissions (WRITE, MODIFY, DELETE)
    denied_perms = (
        win32security.FILE_WRITE_DATA | 
        win32security.FILE_APPEND_DATA |
        win32security.FILE_WRITE_EA |
        win32security.DELETE
    )

    # Add denied ACE for current user
    dacl.AddAccessDeniedAce(win32security.ACL_REVISION, denied_perms, user_sid)

    # Set updated DACL
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)

    print(f"File '{file_path}' created and write access denied to current user.")

# Function 2: Copy folders to a new location excluding .cset files
def copy_folders():
    user_profile = os.environ.get('USERPROFILE')
    source_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Trane', 'CSET', 'Stencils', 'CSET')
    destination_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Trane', 'Stencils copy')

    # Create the destination directory if it doesn't exist
    os.makedirs(destination_path, exist_ok=True)

    # Walk through the source directory
    for item in os.listdir(source_path):
        source_item = os.path.join(source_path, item)
        destination_item = os.path.join(destination_path, item)

        # Check if it is a directory and not a .cset file
        if os.path.isdir(source_item):
            shutil.copytree(source_item, destination_item)
        elif os.path.isfile(source_item) and item != "stenciltoload.cset":
            shutil.copy2(source_item, destination_item)

# Function 3: Add a URL to Trusted Sites in Internet Options
def add_to_trusted_sites():
    url = "https://umw-stencil-loader.s3.amazonaws.com/UMWStencilLoader.vsto"

    # Open the registry key for trusted sites
    try:
        registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains", 0, reg.KEY_WRITE)
        reg_key = reg.CreateKey(registry_key, "umw-stencil-loader.s3.amazonaws.com")
        reg.SetValueEx(reg_key, "https", 0, reg.REG_DWORD, 2)  # Trusted Sites zone is 2
        reg.CloseKey(reg_key)
        reg.CloseKey(registry_key)
        print("URL added to Trusted Sites.")
    except Exception as e:
        print(f"Error adding URL to Trusted Sites: {e}")

# Main function to run all steps
def main():
    replace_stencil_file()
    copy_folders()
    add_to_trusted_sites()

if __name__ == "__main__":
    main()
