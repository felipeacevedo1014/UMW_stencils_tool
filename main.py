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
    deny_full_control_to_current_user(stencil_file_path)

# Function to deny full control to the current user on the given file
def deny_full_control_to_current_user(file_path):
    user_profile = os.environ.get('USERPROFILE')
    username = os.getlogin()  # Get the current logged in username
    user_sid, _, _ = win32security.LookupAccountName(None, username)
    
    # Get the security descriptor
    sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()

    # Add a Deny ACE (Access Control Entry) for full control to the current user
    dacl.AddAccessDeniedAce(win32security.ACL_REVISION, win32security.FILE_ALL_ACCESS, user_sid)

    # Set the new security descriptor
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)

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
