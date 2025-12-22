import os
import logging
import re
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
LOG_FILE_PATH = config.LOG_FILE_PATH
LAST_STOP_FILE_PATH = config.LAST_STOP_FILE_PATH
FOLDER_TO_SCAN = config.FOLDER_TO_SCAN
GAME_PATH_EXAMPLE = config.GAME_PATH_EXAMPLE
# =================================================

# Priority mapping (lower number = higher scan priority)
PRIORITY_MAP = {
    'exe': 1, 'dll': 1, 'bat': 1, 'cmd': 1, 'js': 1, 'vbs': 1, 'py': 1, 'sh': 1, 'so': 1, 'wasm': 1,
    'lnk': 1,                        # You handle this in code, but good to list
    'iso': 2, 'img': 2,              # Disk images (often contain malware)
    'zip': 2, 'rar': 2, '7z': 2, 'docm': 2, 'xlsm': 2, 'pptm': 2, # Office files with Macros
    'pdf': 3,                        # Common exploit vector
    'htm': 3, 'bin': 3,
    'dat': 4, 'pak': 4, 'vdf': 4, 'db': 4,
    'txt': 5, 'json': 5, 'xml': 5, 'css': 5, '': 5,
}

# VirusTotal V3 API Endpoints
BASE_URL = 'https://www.virustotal.com/api/v3'
FILES_URL = f'{BASE_URL}/files'
ANALYSES_URL = f'{BASE_URL}/analyses'

class Scan:
    def get_priority(self, filename, filepath=None):
        # 1. Try to detect if it is a hidden executable by reading the first 2 bytes
        if filepath and os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(2)
                    # 'MZ' is the signature for Windows Executables (exe, dll)
                    if header == b'MZ': 
                        return 1 # Force high priority regardless of extension
            except:
                pass

        # 2. Fallback to extension check
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        return PRIORITY_MAP.get(ext, 10)

    def _hash_file_content(self, filepath):
        """Hashes the content of a single file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256.update(byte_block)
            return sha256.hexdigest()
        except Exception as e:
            print(f" [!] Error reading {filepath}: {e}")
            return "READ_ERROR"

    def resolve_shortcut(self, lnk_path):
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


    def check_rate_limit(self, response):
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


    def get_report_by_hash(self, file_hash, filepath):
        headers = {'x-apikey': API_KEY}
        url = f"{FILES_URL}/{file_hash}"
        response = requests.get(url, headers=headers)

        if self.check_rate_limit(response):
            return self.get_report_by_hash(file_hash, filepath)

        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['last_analysis_stats']
        elif response.status_code == 404:
            print("   [-] No report found for this file.")
            raise Exception("NO_REPORT")
        else:
            print(f"   [Error] Check failed: {response.status_code} - {response.text}")
            raise Exception("CHECK_FAILED")


    def upload_file(self, filepath):
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

        # 1. Check Rate Limits (429)
        if self.check_rate_limit(response):
            return self.upload_file(filepath)

        # 2. Check Server Errors (502, 500, 503, 504)
        # If VirusTotal is having a hiccup, wait 60s and try again.
        if 500 <= response.status_code < 600:
            print(f"   [!] VirusTotal Server Error ({response.status_code}). Retrying in 60 seconds...")
            time.sleep(60)
            return self.upload_file(filepath)
        
        if response.status_code == 200:
            return response.json()['data']['id']
        else:
            print(f"   [Error] Upload failed: {response.status_code} - {response.text}")
            raise Exception("UPLOAD_FAILED")

    def get_analysis_result(self, analysis_id):
        headers = {'x-apikey': API_KEY}
        url = f"{ANALYSES_URL}/{analysis_id}"

        print("   [>] Waiting for analysis to complete...", end='', flush=True)
        
        while True:
            response = requests.get(url, headers=headers)

            if self.check_rate_limit(response):
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
            
    def parse_scan_logs(self):
        extracted_paths = []

        # Regex components based on your f-strings:
        # Timestamp: YYYY-MM-DD HH:MM:SS
        timestamp_pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
        
        # Pattern 1: Malicious file detected: {filepath} | {red}/{total} engines flagged
        # We use (.+) to capture the filepath. We escape the pipe character \|.
        malicious_regex = re.compile(rf"^{timestamp_pattern} Malicious file detected: (.+) \| \d+/\d+ engines flagged$")

        # Pattern 2: Game scanned clean: {directory}
        clean_regex = re.compile(rf"^{timestamp_pattern} Game scanned clean: (.+)$")

        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        with open(LOG_FILE_PATH, 'w'):
            pass

        with open(LOG_FILE_PATH, 'r') as file:
            for line_number, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue

                candidate_path = None

                # Attempt to match "Clean" format
                clean_match = clean_regex.match(line)
                if clean_match:
                    candidate_path = clean_match.group(1).strip()

                # Attempt to match "Malicious" format
                if not candidate_path:
                    malicious_match = malicious_regex.match(line)
                    if malicious_match:
                        # Capture is likely a filename, extract the directory part
                        full_path = malicious_match.group(1).strip()
                        candidate_path = os.path.dirname(full_path)

                # --- Validation Logic ---
                if candidate_path:
                    # Check if it actually exists and is a directory
                    if os.path.isdir(candidate_path):
                        # add only the game directory level
                        splited_path = candidate_path.strip(os.sep).split(os.sep)
                        game_root = os.sep.join(splited_path[:self.game_root_depth])
                        extracted_paths.append(game_root)
                    else:
                        logging.error(f"Line {line_number}: Path found but is not a valid directory or no longer exists: {candidate_path}")
                else:
                    # Only log error if neither regex matched
                    logging.error(f"Line {line_number} does not match expected format: {line}")

        return extracted_paths

    def main(self):
        if API_KEY == 'YOUR_API_KEY_HERE':
            print("Please add your VirusTotal API Key.")
            raise Exception("NO_API_KEY")

        if not os.path.exists(FOLDER_TO_SCAN):
            print(f"Folder not found: {FOLDER_TO_SCAN}")
            raise Exception("FOLDER_NOT_FOUND")
        
        if not GAME_PATH_EXAMPLE.startswith(FOLDER_TO_SCAN):
            print(f"Game path example does not start with folder to scan.")
            raise Exception("GAME_PATH_MISMATCH")
        self.game_root_depth = len(GAME_PATH_EXAMPLE.strip(os.sep).split(os.sep))

        print(f"Scanning directory recursively: {FOLDER_TO_SCAN}")
        print("Files will be processed based on threat priority.\n")

        # ==============================
        # 🔥 RECURSIVE FILE COLLECTION
        # ==============================
        unique_files_set = set() # Used to avoid duplicate scans
        files_to_scan_list = []
        
        parsed_games = self.parse_scan_logs()

        print("   [i] Building file list and resolving shortcuts...")

        # Creating files_to_scan_list
        for root, dirs, files in os.walk(FOLDER_TO_SCAN):
            for d in dirs[:]:
                dir_abs_path = os.path.abspath(os.path.join(root, d))
                
                if dir_abs_path in parsed_games:
                    dirs.remove(d)
                    
            for f in files:
                full_path = os.path.abspath(os.path.join(root, f))
                
                # Add normal file
                if full_path not in unique_files_set:
                    unique_files_set.add(full_path)
                    files_to_scan_list.append(full_path)

                # Check for Shortcut
                if f.lower().endswith('.lnk'):
                    target_path = self.resolve_shortcut(full_path)
                    
                    if target_path and os.path.exists(target_path):
                        target_path = os.path.abspath(target_path)
                        
                        if target_path not in unique_files_set:
                            print(f"       -> Shortcut found: {f} points to {os.path.basename(target_path)}")
                            unique_files_set.add(target_path)
                            files_to_scan_list.append(target_path)

        # Sort based on risk priority (highest priority first)
        files_to_scan_list.sort(key=lambda x: self.get_priority(os.path.basename(x)))

        last_file_per_game = {}

        root = Path(FOLDER_TO_SCAN)
        
        # Create a glob pattern like "*/*" for depth 2
        # The pattern becomes "*" repeated 'depth' times, joined by slash
        pattern = "/".join(["*"] * (self.game_root_depth - 1))
        
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
        
        os.makedirs(os.path.dirname(LAST_STOP_FILE_PATH), exist_ok=True)
        with open(LAST_STOP_FILE_PATH, 'w'):
            pass
        with open(LAST_STOP_FILE_PATH, 'r', encoding='utf-8') as last_stop_file:
            last_stopped_file = last_stop_file.read().strip()
            if last_stopped_file in files_to_scan_list:
                last_index = files_to_scan_list.index(last_stopped_file)
                files_to_scan_list = files_to_scan_list[last_index + 1:]
                print(f"   [i] Resuming from last scanned file: {last_stopped_file}")
            else:
                logging.warning("   [i] Last scanned file not found in current scan list. Starting from beginning.")

        print(f"   [i] Total unique files to scan: {len(files_to_scan_list)}\n")

        # ==============================
        # 🔥 SCANNING LOOP
        # ==============================
        i = -1
        while i < len(files_to_scan_list) - 1:
            i += 1
            filepath = files_to_scan_list[i]
            filename = os.path.basename(filepath)
            priority = self.get_priority(filename)



            ext = filename.lower().split('.')[-1]
            red = 0
       
            if 1 or priority == 1:
                print(f"[START] -> {filename}  (Priority {priority})")
                print(f"        Path: {filepath}")
                sha = self._hash_file_content(filepath)
                if not sha:
                    continue
                    
                print(f"   [i] SHA256: {sha}")

                try:
                    stats = self.get_report_by_hash(sha, filepath)
                except Exception as e:
                    if str(e) == "NO_REPORT":
                        stats = None
                    else:
                        raise e
                time.sleep(16)

                if stats is None:
                    print("   [-] No existing report -> Uploading file...")
                    analysis_id = self.upload_file(filepath)

                    time.sleep(16)
                    stats = self.get_analysis_result(analysis_id)
                else:
                    print("   [+] Report already exists.")

                if stats:
                    red = stats['malicious']
                    total = sum(stats.values())
                    print(f"   [RESULT] {red}/{total} engines flagged")
                    if total == 0:
                        raise Exception("NO_ENGINES")
            else:
                print(f"[SKIP] -> {filename} (Low Risk Media File)")


            os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
            with open(LOG_FILE_PATH, 'w'):
                pass
            if red > 0:
                print("   [!!!] MALICIOUS FILE FOUND")
                splited_path = filepath.strip(os.sep).split(os.sep)
                game_root = os.sep.join(splited_path[:self.game_root_depth])
                files_to_scan_list = [path for path in files_to_scan_list if not path.startswith(game_root)]
                with open(LOG_FILE_PATH, 'a') as log_file:
                    log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Malicious file detected: {filepath} | {red}/{total} engines flagged\n")
            elif filepath in last_file_per_game:
                directory = last_file_per_game[filepath]
                print("   [i] Last file in game scanned, no threats found.")
                with open(LOG_FILE_PATH, 'a') as log_file:
                    log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} Game scanned clean: {directory}\n")
            with open(LAST_STOP_FILE_PATH, 'w', encoding='utf-8') as last_stop_file:
                last_stop_file.write(filepath)
        print("-" * 60)



if __name__ == "__main__":
    try:
        scan = Scan()
        scan.main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user (Ctrl+C). Stopping...")
    except Exception as e:
        print(f"Error: {e}")
    input("Scanning complete. Press Enter to exit...")