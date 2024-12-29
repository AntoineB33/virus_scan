import os
import time
import requests
import shutil

# Folder path you want to scan
USE_VIRUSTOTAL = 1
ONE_GAME = 0
API_KEY_PATH = "API_KEY.txt"
DESTINATION_FOLDER = "copied_files"
FOLDER_PATH = "..\\to_scan"
PRIORITY_MAP = {
    # Very high risk: directly executable or scripting
    'exe': 1,
    'dll': 1,
    'bat': 1,
    'cmd': 1,
    'js': 1,
    'vbs': 1,
    'py': 1,
    'sh': 1,
    'so': 1,
    'wasm': 1,

    # High risk: archives (could contain malicious files inside)
    'zip': 2,
    'rar': 2,
    '7z': 2,

    # Medium risk: could contain code or be part of an exploit
    'htm': 3,
    'bin': 3,

    # Data/pack files (can still embed code or configurations)
    'dat': 4,
    'pak': 4,
    'vdf': 4,
    'db': 4,

    # Plain text or structured data: can contain macro-like content or scripts
    'txt': 5,
    'json': 5,
    'xml': 5,
    'css': 5
}


SKIP_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'bmp',     # Image files
    'wav', 'mp3', 'ogg',                    # Audio files
    'ttf', 'woff', 'otf',                   # Font files
    'efkefc', 'efkmat', 'efkmodel', 'bdic'  # Proprietary/engine data files
}

# File to store paths of analyzed files
ANALYZED_FILES_RECORD = "analyzed_files.txt"
ANALYZED_FOLDER_RECORD = "analyzed_folders.txt"

# VirusTotal endpoints
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

def load_analyzed_files(record_file):
    """Load the set of analyzed file paths from the record file."""
    if not os.path.exists(record_file):
        return set()
    with open(record_file, "r") as f:
        analyzed_files = {line.strip() for line in f}
    return analyzed_files

def load_analyzed_folders(record_file):
    """Load the set of analyzed folder paths from the record file."""
    if not os.path.exists(record_file):
        return set()
    with open(record_file, "r") as f:
        analyzed_folders = {line.strip() for line in f}
    return analyzed_folders

def append_to_record(record_file, file_path):
    """Append a new file path to the record file."""
    with open(record_file, "a") as f:
        f.write(file_path + "\n")

# Helper function to upload and scan a file
def upload_file_to_virustotal(file_path):
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        headers = {"x-apikey": API_KEY}
        
        try:
            # POST the file to VirusTotal
            response = requests.post(UPLOAD_URL, headers=headers, files=files)
            
            # Check for rate limit exceeded
            if response.status_code == 429:
                print("[ERROR] API rate limit exceeded.")
                return -1
            
            # Attempt to parse the JSON response
            response_json = response.json()
            
            # Check for other errors
            if response.status_code != 200:
                print(f"[ERROR] Could not upload file: {file_path}")
                print(response_json)
                return -1
            
            # Extract the analysis ID
            analysis_id = response_json["data"]["id"]
            return analysis_id
        
        except requests.exceptions.JSONDecodeError:
            print(f"[ERROR] Failed to parse JSON response for file: {file_path}")
            print(f"Response content: {response.text}")
            return -1

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")
            return -1

# Helper function to retrieve analysis results
def get_analysis_report(analysis_id):
    headers = {"x-apikey": API_KEY}
    url = ANALYSIS_URL.format(analysis_id)
    response = requests.get(url, headers=headers)
    
    # Check for rate limit exceeded
    if response.status_code == 429:
        print("[ERROR] API rate limit exceeded.")
        return -1
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"[ERROR] Failed to retrieve report for analysis ID {analysis_id}")
        return None

def should_skip_file(file_path, new_extensions, priority_lvl):
    """Determine if a file should be skipped based on its extension or prefix."""
    file_extension = os.path.splitext(file_path)[1].lower()[1:]
    
    # Check for prefix match (e.g., '.ogg_')
    for ext in SKIP_EXTENSIONS | new_extensions:
        if file_extension.startswith(ext):
            return True
    
    for ext, priority in PRIORITY_MAP.items():
        if file_extension.startswith(ext):
            return priority != priority_lvl

    new_extensions.add(file_extension)
    
    return True

def analyze_directory(directory, analyzed_files, analyzed_folders, new_extensions, files_to_copy, new_files, completed_folders, files_per_game, priority_lvl, time_to_wait, time_increment, min_time, max_time, lvl0=0):
    """Recursively analyze files in the directory before its subdirectories."""
    # Process all files in the current directory
    for entry in os.scandir(directory):
        if entry.is_file():
            file_path = entry.path
            if should_skip_file(file_path, new_extensions, priority_lvl):
                continue
            if file_path in analyzed_files:
                continue
            if USE_VIRUSTOTAL:
                print(f"\n[*] Uploading file: {file_path}")
            elif ONE_GAME:
                print(file_path)
            else:
                files_per_game[-1].append(file_path)
            if not USE_VIRUSTOTAL:
                files_to_copy.append(file_path)
                continue
            analysis_id = upload_file_to_virustotal(file_path)
            if analysis_id == -1:
                new_files.append(file_path)
                if USE_VIRUSTOTAL:
                    append_to_record(ANALYZED_FILES_RECORD, file_path)
                return -1
            # analysis_id = "NDA4NDE3ZmE0ZjIyYjM2Y2U4YjliMjJlM2M4ZDE4YzQ6MTczNTMwMDQ0NQ===="
            if not analysis_id:
                continue
            report = None
            nb_analysis_req = 0
            while not report or (stats:=report["data"]["attributes"]["stats"])['undetected'] == 0 and stats['suspicious'] == 0 and stats['malicious'] == 0 and stats['harmless'] == 0:
                print(f"[*] Analysis ID received: {analysis_id}")
                if nb_analysis_req and time_to_wait + time_increment <= max_time:
                    time_to_wait += time_increment
                time.sleep(time_to_wait)
                report = get_analysis_report(analysis_id)
                if report == -1:
                    return -1
                nb_analysis_req += 1
            if nb_analysis_req == 1 and time_to_wait - time_increment >= min_time:
                time_to_wait -= time_increment
            stats = report["data"]["attributes"]["stats"]
            print(f"  - Harmless: {stats['harmless']}")
            print(f"  - Malicious: {stats['malicious']}")
            print(f"  - Suspicious: {stats['suspicious']}")
            print(f"  - Undetected: {stats['undetected']}")
            if stats['malicious'] > 0 or stats['suspicious'] > 0:
                print("[ALERT] Suspicious or malicious file detected. Stopping the scan.")
                return -1
            new_files.append(file_path)
            if USE_VIRUSTOTAL:
                append_to_record(ANALYZED_FILES_RECORD, file_path)
    
    # Recursively process each subdirectory
    for entry in os.scandir(directory):
        if entry.is_dir():
            if entry.path not in analyzed_folders:
                if lvl0:
                    files_per_game.append([])
                time_to_wait = analyze_directory(entry.path, analyzed_files, analyzed_folders, new_extensions, files_to_copy, new_files, completed_folders, files_per_game, priority_lvl, time_to_wait, time_increment, min_time, max_time)
                if time_to_wait== -1:
                    return -1
    if priority_lvl == max(PRIORITY_MAP.values()):
        completed_folders.append(directory)
        if USE_VIRUSTOTAL:
            append_to_record(ANALYZED_FOLDER_RECORD, directory)
    return time_to_wait


def copy_files(file_paths, destination_folder):
    # Ensure the destination folder exists
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    for file_path in file_paths:
        # Check if the file exists
        if os.path.isfile(file_path):
            # Get the filename from the path
            filename = os.path.basename(file_path)
            # Define the destination path
            destination_path = os.path.join(destination_folder, filename)
            
            # Copy the file to the destination folder
            try:
                shutil.copy(file_path, destination_path)
                print(f"Copied: {file_path} to {destination_path}")
            except Exception as e:
                print(f"Error copying {file_path}: {e}")
        else:
            print(f"File not found: {file_path}")

def main():
    time_to_wait = 5
    time_increment = 5
    min_time = 5
    max_time = 60
    files_to_copy = []
    new_extensions = set()
    new_files = []
    completed_folders = []
    analyzed_files = load_analyzed_files(ANALYZED_FILES_RECORD)
    analyzed_folders = load_analyzed_folders(ANALYZED_FOLDER_RECORD)
    files_per_game = []
    for priority_lvl in sorted(PRIORITY_MAP.values()):
        time_to_wait = analyze_directory(FOLDER_PATH, analyzed_files, analyzed_folders, new_extensions, files_to_copy, new_files, completed_folders, files_per_game, priority_lvl, time_to_wait, time_increment, min_time, max_time, 1)
        if time_to_wait == -1:
            return -1
    print("new_extensions : ", new_extensions)
    if not USE_VIRUSTOTAL:
        if not ONE_GAME:
            files_per_game = [files for files in files_per_game if files]
            files_per_game.sort(key=lambda x: len(x))
            for i, files in enumerate(files_per_game):
                print(f"Game {i+1} has {len(files)} files")
                for file in files:
                    print(file)
        to_copy = input("Do you want to copy the files? (Y/n) ")
        if to_copy.lower() != "n":
            copy_files(files_to_copy, DESTINATION_FOLDER)
            to_update_record_input = input("Do you want to update the record file? (Y/n) ")
            if to_update_record_input.lower() != "n":
                append_to_record(ANALYZED_FILES_RECORD, "\n".join(new_files))
                append_to_record(ANALYZED_FOLDER_RECORD, "\n".join(completed_folders))

if __name__ == "__main__":
    # Get your VirusTotal API key from API_KEY.txt
    with open(API_KEY_PATH, "r") as f:
        API_KEY = f.read().strip()

    main()
    
    # report = get_analysis_report("MmU1MWVlMjA0MzRkZTc4ODQyOGUyMGNjODgyZDk2YTI6MTczNTEzMTk3Mw==")
    # if report:
    #     stats = report["data"]["attributes"]["stats"]
    #     print(f"  - Harmless: {stats['harmless']}")
    #     print(f"  - Malicious: {stats['malicious']}")
    #     print(f"  - Suspicious: {stats['suspicious']}")
    #     print(f"  - Undetected: {stats['undetected']}")
