import os
import time
import hashlib
import requests
import config
from pathlib import Path
import json

# Try to import win32com for shortcut handling
try:
    import win32com.client
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("[!] pywin32 not installed. Shortcuts (.lnk) will not be resolved.")
    print("    Run: pip install pywin32")

# ================= CONFIGURATION =================
API_KEY = config.API_KEY
FOLDER_TO_SCAN = config.FOLDER_TO_SCAN
GAME_PATH_EXAMPLE = config.GAME_PATH_EXAMPLE
LOG_FILE_PATH = config.LOG_FILE_PATH
FOLDER_HASHES_PATH = config.FOLDER_HASHES_PATH
RED_FLAG_THRESHOLD = config.RED_FLAG_THRESHOLD
# =================================================

# Priority mapping (lower number = higher scan priority)
PRIORITY_MAP = {
    'exe': 1, 'dll': 1, 'bat': 1, 'cmd': 1, 'js': 1, 'vbs': 1, 'py': 1, 'sh': 1, 'so': 1, 'wasm': 1,
    'zip': 2, 'rar': 2, '7z': 2,
    'htm': 3, 'bin': 3,
    'dat': 4, 'pak': 4, 'vdf': 4, 'db': 4,
    'txt': 5, 'json': 5, 'xml': 5, 'css': 5, '': 5,
}

# VirusTotal V3 API Endpoints
BASE_URL = 'https://www.virustotal.com/api/v3'
FILES_URL = f'{BASE_URL}/files'
ANALYSES_URL = f'{BASE_URL}/analyses'


def get_priority(filename):
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    return PRIORITY_MAP.get(ext, 10)   # unknown = lowest priority


def calculate_hash_flexible(path, folder_hash_to_red_nb):
    sha256_hash = hashlib.sha256()
    
    # Case 1: It's a single file
    if os.path.isfile(path):
        return _update_hash_with_file(sha256_hash, path)
    
    # Case 2: It's a directory
    elif os.path.isdir(path):
        # Walk through the directory
        for root, dirs, files in os.walk(path):
            if root in folder_hash_to_red_nb:
                _update_hash_with_file(sha256_hash, file_path)
                dirs[:] = []
                continue

            # Sort to ensure deterministic behavior (same files = same hash)
            files.sort()
            for file in files:
                file_path = os.path.join(root, file)
                
                # Optional: Hash the filename so renaming files changes the folder hash
                # sha256_hash.update(file.encode('utf-8')) 
                
                _update_hash_with_file(sha256_hash, file_path)
                    
        return sha256_hash.hexdigest()
    
    else:
        raise Exception("Path does not exist or is not a valid file/folder")

def _update_hash_with_file(hash_obj, filepath):
    """Helper function to read chunks"""
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_obj.update(byte_block)
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"   [!] Error reading file {filepath}: {e}")
        raise Exception("FILE_READ_ERROR")


def resolve_shortcut(lnk_path):
    """
    Extracts the target path from a Windows .lnk file using WScript.Shell.
    """
    if not WIN32_AVAILABLE:
        raise Exception("WIN32COM_NOT_AVAILABLE")
    
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(lnk_path)
        target = shortcut.TargetPath
        # Expand environment variables if present (e.g., %SystemRoot%)
        target = os.path.expandvars(target)
        return target
    except Exception as e:
        print(f"   [!] Failed to parse shortcut {os.path.basename(lnk_path)}: {e}")
        raise Exception("SHORTCUT_PARSE_ERROR")


def check_rate_limit(response):
    """
    Handles Rate Limits (wait and retry) and Quota Exits (stop script).
    """
    if response.status_code == 429:
        try:
            # Try to parse the error to see if it's a Quota issue
            error_data = response.json()
            error_code = error_data.get('error', {}).get('code', '')
            
            if error_code == 'QuotaExceededError':
                print("\n" + "="*50)
                print(" [X] CRITICAL: DAILY/MONTHLY QUOTA EXCEEDED")
                print(" [X] VirusTotal will not accept more requests today.")
                print("="*50)
                raise Exception("QUOTA_EXCEEDED")
            
        except Exception as e:
            # If the exception IS "QUOTA_EXCEEDED", re-raise it so main() hears it
            if str(e) == "QUOTA_EXCEEDED":
                raise e
            pass

        print("   [!] Rate limit (requests/min) hit. Waiting 60 seconds...")
        time.sleep(61)
        return True
        
    return False


def get_report_by_hash(file_hash):
    headers = {'x-apikey': API_KEY}
    url = f"{FILES_URL}/{file_hash}"
    response = requests.get(url, headers=headers)

    if check_rate_limit(response):
        return get_report_by_hash(file_hash)

    if response.status_code == 200:
        data = response.json()
        return data['data']['attributes']['last_analysis_stats']
    elif response.status_code == 404:
        raise Exception("NO_REPORT")
    else:
        print(f"   [Error] Check failed: {response.status_code} - {response.text}")
        raise Exception("CHECK_FAILED")


def upload_file(filepath):
    headers = {'x-apikey': API_KEY}
    try:
        filesize = os.path.getsize(filepath)
    except OSError:
        print("   [Skip] Cannot access file size.")
        raise Exception("FILE_ACCESS_ERROR")

    if filesize > 32 * 1024 * 1024:
        print("   [Skip] File too large for standard API (limit 32MB)")
        raise Exception("FILE_TOO_LARGE")

    try:
        with open(filepath, 'rb') as file_data:
            files = {'file': (os.path.basename(filepath), file_data)}
            response = requests.post(FILES_URL, headers=headers, files=files)
    except IOError as e:
        print(f"   [Error] Could not open file for upload: {e}")
        raise Exception("FILE_OPEN_ERROR")

    if check_rate_limit(response):
        return upload_file(filepath)

    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f"   [Error] Upload failed: {response.status_code} - {response.text}")
        raise Exception("UPLOAD_FAILED")

def get_analysis_result(analysis_id):
    headers = {'x-apikey': API_KEY}
    url = f"{ANALYSES_URL}/{analysis_id}"

    print("   [>] Waiting for analysis to complete...", end='', flush=True)
    
    while True:
        response = requests.get(url, headers=headers)

        if check_rate_limit(response):
            continue

        if response.status_code == 200:
            data = response.json()
            status = data['data']['attributes']['status']

            if status == 'completed':
                print(" Done!")
                return data['data']['attributes']['stats']
            else:
                print(".", end='', flush=True)
                time.sleep(20)
        else:
            print(f"\n   [Error] Analysis check failed: {response.status_code}")
            raise Exception("ANALYSIS_CHECK_FAILED")

def update_folder_hashes(splited_path, red, game_root_depth, folder_hash_to_red_nb):
    for j in range(len(splited_path) - 1, game_root_depth, -1):
        path = os.sep.join(splited_path[:j])
        folder_hash_to_red_nb[calculate_hash_flexible(path, folder_hash_to_red_nb)] = red
    with open(FOLDER_HASHES_PATH, 'w') as f:
        json.dump(folder_hash_to_red_nb, f)
        print("Data saved!")

def main():
    if API_KEY == 'YOUR_API_KEY_HERE':
        print("Please add your VirusTotal API Key.")
        raise Exception("NO_API_KEY")

    if not os.path.exists(FOLDER_TO_SCAN):
        print(f"Folder not found: {FOLDER_TO_SCAN}")
        raise Exception("FOLDER_NOT_FOUND")
    
    if not GAME_PATH_EXAMPLE.startswith(FOLDER_TO_SCAN):
        print(f"Game path example does not start with folder to scan.")
        raise Exception("GAME_PATH_MISMATCH")
    game_root_depth = len(GAME_PATH_EXAMPLE.strip(os.sep).split(os.sep))

    print(f"Scanning directory recursively: {FOLDER_TO_SCAN}")
    print("Files will be processed based on threat priority.\n")

    # ==============================
    # 🔥 RECURSIVE FILE COLLECTION
    # ==============================
    unique_files_set = set() # Used to avoid duplicate scans
    files_to_scan_list = []

    print("   [i] Building file list and resolving shortcuts...")

    try:
        with open(FOLDER_HASHES_PATH, 'r') as f:
            folder_hash_to_red_nb = json.load(f)
    except FileNotFoundError:
        folder_hash_to_red_nb = {}

    for root, dirs, files in os.walk(FOLDER_TO_SCAN):
        if root in folder_hash_to_red_nb:
            if folder_hash_to_red_nb[root] > 0:
                splited_path = root.strip(os.sep).split(os.sep)
                update_folder_hashes(splited_path[:len(splited_path) - 1], folder_hash_to_red_nb[root], game_root_depth, folder_hash_to_red_nb)
            dirs[:] = []
            continue

        for f in files:
            full_path = os.path.abspath(os.path.join(root, f))
            
            # Add normal file
            if full_path not in unique_files_set:
                unique_files_set.add(full_path)
                files_to_scan_list.append(full_path)

            # Check for Shortcut
            if f.lower().endswith('.lnk'):
                target_path = resolve_shortcut(full_path)
                
                if target_path and os.path.exists(target_path):
                    target_path = os.path.abspath(target_path)
                    
                    if target_path not in unique_files_set:
                        print(f"       -> Shortcut found: {f} points to {os.path.basename(target_path)}")
                        unique_files_set.add(target_path)
                        files_to_scan_list.append(target_path)

    # Sort based on risk priority (highest priority first)
    files_to_scan_list.sort(key=lambda x: get_priority(os.path.basename(x)))

    last_file_per_game = {}

    root = Path(FOLDER_TO_SCAN)
    
    # Create a glob pattern like "*/*" for depth 2
    # The pattern becomes "*" repeated 'depth' times, joined by slash
    pattern = "/".join(["*"] * (game_root_depth - 1))
    
    for path in root.glob(pattern):
        if path.is_dir():
            print(f"game found: {path}")
            game_root = str(path)
            i = len(files_to_scan_list)
            while i > 0:
                i -= 1
                if files_to_scan_list[i].startswith(game_root):
                    last_file_per_game[game_root] = files_to_scan_list[i]
                    break
    folder_to_last_file = {}
    last_file_to_folder = {}
    folder_hashes = {}
    for filepath in reversed(files_to_scan_list):
        folder = os.path.dirname(filepath)
        if folder not in folder_to_last_file:
            folder_hashes[folder] = calculate_hash_flexible(filepath)
            folder_to_last_file[folder] = filepath
            last_file_to_folder[filepath] = folder

    print(f"   [i] Total unique files to scan: {len(files_to_scan_list)}\n")

    # ==============================
    # 🔥 SCANNING LOOP
    # ==============================
    i = -1
    while i < len(files_to_scan_list) - 1:
        i += 1
        filepath = files_to_scan_list[i]
        filename = os.path.basename(filepath)
        priority = get_priority(filename)

        print(f"[START] -> {filename}  (Priority {priority})")
        print(f"        Path: {filepath}")

        sha = calculate_hash_flexible(filepath)
        if not sha:
            continue
            
        print(f"   [i] SHA256: {sha}")

        stats = get_report_by_hash(sha)
        time.sleep(16)

        if stats is None:
            print("   [-] No existing report -> Uploading file...")
            analysis_id = upload_file(filepath)

            time.sleep(16)
            stats = get_analysis_result(analysis_id)
        else:
            print("   [+] Report already exists.")

        if stats:
            red = stats['malicious']
            total = sum(stats.values())
            print(f"   [RESULT] {red}/{total} engines flagged")

            if red > 0:
                print("   [!!!] MALICIOUS FILE FOUND — SCAN STOPPED")
                splited_path = filepath.strip(os.sep).split(os.sep)
                game_root = os.sep.join(splited_path[:game_root_depth])
                files_to_scan_list = [path for path in files_to_scan_list if not path.startswith(game_root)]
                with open(LOG_FILE_PATH, 'a') as log_file:
                    log_file.write(f"Malicious file detected: {filepath} | {red}/{total} engines flagged\n")
                update_folder_hashes(splited_path, red, game_root_depth, folder_hash_to_red_nb)
            else:
                if filepath in last_file_to_folder:
                    game_root = last_file_to_folder[filepath]
                    print("   [i] Last file in game scanned, no threats found.")
                    with open(LOG_FILE_PATH, 'a') as log_file:
                        log_file.write(f"Game scanned clean: {game_root}\n")
                    folder_hash_to_red_nb[calculate_hash_flexible(filepath)] = 0
                    with open(FOLDER_HASHES_PATH, 'w') as f:
                        json.dump(folder_hash_to_red_nb, f)
                        print("Data saved!")

        print("-" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user (Ctrl+C). Stopping...")
    except Exception as e:
        print(f"Error: {e}")
    input("Scanning complete. Press Enter to exit...")