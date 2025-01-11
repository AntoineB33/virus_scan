import os
import time
import requests
import shutil
import json

# Folder path you want to scan
FILES_MAX_PER_GAME = 20
API_KEY_PATH = "API_KEY.txt"
GAMES_FOLDER_DIRECT_PATH = "..\\to_scan"
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
    'css': 5,
    '' : 5,
}


SKIP_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'bmp',     # Image files
    'wav', 'mp3', 'ogg',                    # Audio files
    'ttf', 'woff', 'otf',                   # Font files
    'efkefc', 'efkmat', 'efkmodel', 'bdic',  # Proprietary/engine data files
    'ini',
}

# File to store paths of analyzed files
ANALYZED_FILES_RECORD = "analyzed_files2.txt"
TO_MANUALLY_SCAN_RECORD = "to_manually_scan.txt"
VIRUS_DETECT_RECORD = "virus_detect.txt"
CLEAN_RECORD = "clean_detect.txt"

# VirusTotal endpoints
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"


def add_to_record(record_file, new_files):
    with open(record_file, "a", encoding='utf-8', errors='ignore') as f:
        f.write(new_files + "\n")

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
                return -2
            
            # Attempt to parse the JSON response
            response_json = response.json()
            
            # Check for other errors
            if response.status_code != 200:
                print(f"[ERROR] Could not upload file: {file_path}")
                print(response_json)
                return -2
            
            # Extract the analysis ID
            analysis_id = response_json["data"]["id"]
            return analysis_id
        
        except requests.exceptions.JSONDecodeError:
            print(f"[ERROR] Failed to parse JSON response for file: {file_path}")
            print(f"Response content: {response.text}")
            return -1

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")
            return -2

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

def save_paths_dict(paths_dict, file_path):
    """
    Save the paths_dict to a JSON file.
    """
    with open(file_path, 'w') as f:
        json.dump(paths_dict, f, indent=4)

def remove_all_invalid_paths(paths_dict, path = ""):
    """Recursively remove all paths that are don't exist."""
    for path_name, sub_paths in list(paths_dict.items()):
        new_path = ((path + '/') if path else '') + path_name
        if not os.path.exists(new_path):
            del paths_dict[path_name]
        elif isinstance(sub_paths, dict):
            remove_all_invalid_paths(sub_paths, new_path)

def load_paths_dict(file_path, folder_path):
    loaded_data = {"paths_dict": {}, "time_to_wait": 5, "nb_analyzed": {}, "gamesHistory": []}
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            loaded_data = json.load(f)
        remove_all_invalid_paths(loaded_data["paths_dict"])
        remove_all_invalid_paths(loaded_data["nb_analyzed"])
    
    # Normalize folder_path
    folder_path = os.path.abspath(folder_path)
    folder_parts = folder_path.strip(os.sep).split(os.sep)

    # Traverse to the target folder in the nested dict
    current_level = loaded_data["paths_dict"]
    current_level_nb = loaded_data["nb_analyzed"]
    for part in folder_parts:
        if part not in current_level:
            current_level[part] = {}
            current_level_nb[part] = {}
        current_level = current_level[part]
        current_level_nb = current_level_nb[part]
    
    return loaded_data, current_level, current_level_nb, loaded_data["gamesHistory"]

def fold_to_done(game_paths_dict, game, loaded_dict, directory):
    game_paths_dict[game] = "done"
    save_paths_dict(loaded_dict, ANALYZED_FILES_RECORD)
    add_to_record(CLEAN_RECORD, directory + '/' + game)

def analyze_directory(directory, paths_dict, game_paths_dict, nb_analyzed, gamesHistory, loaded_dict, new_extensions, game, priority_lvl, time_increment, min_time, max_time, max_file_packets, lvl0=0):
    """Recursively analyze files in the directory before its subdirectories."""
    # Process all files in the current directory
    for entry in os.scandir(directory):
        if entry.is_file():
            if game and nb_analyzed[game] >= max_file_packets * FILES_MAX_PER_GAME:
                return 0, 1
            if should_skip_file(entry.name, new_extensions, priority_lvl):
                continue
            if entry.name in paths_dict:
                continue
            print(f"\n[*] Uploading file: {entry.path}")
            analysis_id = upload_file_to_virustotal(entry.path)
            if analysis_id == -2 or analysis_id == -1 or not analysis_id:
                if game:
                    nb_analyzed[game] += 1
                paths_dict[entry.name] = None
                save_paths_dict(loaded_dict, ANALYZED_FILES_RECORD)
                add_to_record(TO_MANUALLY_SCAN_RECORD, entry.path)
                if analysis_id == -2:
                    return 1, 0
                continue
            # analysis_id = "NDA4NDE3ZmE0ZjIyYjM2Y2U4YjliMjJlM2M4ZDE4YzQ6MTczNTMwMDQ0NQ===="
            report = None
            nb_analysis_req = 0
            print(game, nb_analyzed[game], max_file_packets, FILES_MAX_PER_GAME)
            while not report or (stats:=report["data"]["attributes"]["stats"])['undetected'] == 0 and stats['suspicious'] == 0 and stats['malicious'] == 0 and stats['harmless'] == 0:
                print(f"[*] Analysis ID received: {analysis_id}")
                if nb_analysis_req and loaded_dict["time_to_wait"] + time_increment <= max_time:
                    loaded_dict["time_to_wait"] += time_increment
                time.sleep(loaded_dict["time_to_wait"])
                if analysis_id == -1 or (report := get_analysis_report(analysis_id)) == -1:
                    if game:
                        nb_analyzed[game] += 1
                    paths_dict[entry.name] = None
                    save_paths_dict(loaded_dict, ANALYZED_FILES_RECORD)
                    add_to_record(TO_MANUALLY_SCAN_RECORD, entry.path)
                    break
                nb_analysis_req += 1
            if nb_analysis_req == 1 and loaded_dict["time_to_wait"] - time_increment >= min_time:
                loaded_dict["time_to_wait"] -= time_increment
            stats = report["data"]["attributes"]["stats"]
            print(f"  - Harmless: {stats['harmless']}")
            print(f"  - Malicious: {stats['malicious']}")
            print(f"  - Suspicious: {stats['suspicious']}")
            print(f"  - Undetected: {stats['undetected']}")
            if stats['malicious'] > 0 or stats['suspicious'] > 0:
                print("[ALERT] Suspicious or malicious file detected. Stopping the scan.")
                game_paths_dict[game] = "done"
                save_paths_dict(loaded_dict, ANALYZED_FILES_RECORD)
                add_to_record(VIRUS_DETECT_RECORD, directory + '/' + game)
                return 2, 0
            paths_dict[entry.name] = None
            if game:
                nb_analyzed[game] += 1
            save_paths_dict(loaded_dict, ANALYZED_FILES_RECORD)
            
    
    # Recursively process each subdirectory
    increase_max_nb = 0
    for entry in os.scandir(directory):
        if entry.is_dir():
            if entry.name in paths_dict:
                if paths_dict[entry.name] == "done":
                    continue
            else:
                paths_dict[entry.name] = {}
                if lvl0:
                    nb_analyzed[game] = 0
            if lvl0 and entry.name in gamesHistory:
                print("game already analyzed : ", entry.name)
                fold_to_done(game_paths_dict, game, loaded_dict, directory)
            if lvl0:
                game = entry.name
            err, increase_max_nb_temp = analyze_directory(entry.path, paths_dict[entry.name], game_paths_dict, nb_analyzed, gamesHistory, loaded_dict, new_extensions, game, priority_lvl, time_increment, min_time, max_time, max_file_packets)
            if err == 1:
                return 1, 0
            if err == 2 and not lvl0:
                return 2, 0
            if increase_max_nb_temp:
                increase_max_nb = 1
            elif lvl0 and priority_lvl == max(PRIORITY_MAP.values()):
                print("[ALERT] Suspicious or malicious file detected. Stopping the scan.")
                fold_to_done(game_paths_dict, game, loaded_dict, directory)
    if priority_lvl == max(PRIORITY_MAP.values()) and not increase_max_nb:
        game_paths_dict.add(game)
        save_paths_dict(loaded_dict, ANALYZED_FILES_RECORD)
    return 0, increase_max_nb

def main():
    while 1:
        try:
            if not os.path.exists(GAMES_FOLDER_DIRECT_PATH):
                raise Exception(f"Folder {GAMES_FOLDER_DIRECT_PATH} does not exist.")
            if not os.path.isdir(GAMES_FOLDER_DIRECT_PATH):
                raise Exception(f"{GAMES_FOLDER_DIRECT_PATH} is not a folder.")
            # remove all invalid paths from VIRUS_DETECT_RECORD
            with open(VIRUS_DETECT_RECORD, 'r') as f:
                invalid_paths = f.readlines()
            with open(VIRUS_DETECT_RECORD, 'w') as f:
                for path in invalid_paths:
                    if os.path.exists(path.strip()):
                        f.write(path)
            loaded_dict, game_paths_dict, nb_analyzed, gamesHistory = load_paths_dict(ANALYZED_FILES_RECORD, GAMES_FOLDER_DIRECT_PATH)
            while 1:
                err = 0
                time_increment = 5
                min_time = 5
                max_time = 60
                new_extensions = set()
                priority_lvl = 1
                max_file_packets = 1
                while priority_lvl <= max(PRIORITY_MAP.values()):
                    err, increase_max_nb = analyze_directory(GAMES_FOLDER_DIRECT_PATH, game_paths_dict, game_paths_dict, nb_analyzed, gamesHistory, loaded_dict, new_extensions, "", priority_lvl, time_increment, min_time, max_time, max_file_packets, 1)
                    if err == 1:
                        break
                    if increase_max_nb:
                        max_file_packets += 1
                    else:
                        priority_lvl += 1
                print("new_extensions : ", new_extensions)
                if input("Do you want to scan again? (Y/n) ").lower() == "n":
                    return
        except Exception as e:
            print(f"Error: {e}")
            # raise e
            if input("Do you want to scan again? (Y/n) ").lower() == "n":
                return

if __name__ == "__main__":
    # Get your VirusTotal API key from API_KEY.txt
    with open(API_KEY_PATH, "r", encoding='utf-8', errors='ignore') as f:
        API_KEY = f.read().strip()

    main()
    
    # report = get_analysis_report("MmU1MWVlMjA0MzRkZTc4ODQyOGUyMGNjODgyZDk2YTI6MTczNTEzMTk3Mw==")
    # if report:
    #     stats = report["data"]["attributes"]["stats"]
    #     print(f"  - Harmless: {stats['harmless']}")
    #     print(f"  - Malicious: {stats['malicious']}")
    #     print(f"  - Suspicious: {stats['suspicious']}")
    #     print(f"  - Undetected: {stats['undetected']}")
