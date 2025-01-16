import os
import time
import requests
import shutil
import json

# Folder path you want to scan
GAMES_FOLDER_DIRECT_PATH = "C:/Users/abarb/Documents/health/news_underground/games/downloaded/to_scan"
FILES_MAX_PER_GAME = 20
MAX_HISTORY = 20
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
    'gitignore'
}

max_size = 32 * 1024 * 1024

# File to store paths of analyzed files
WHAT_TO_DO_PATH = "C:/Users/abarb/Documents/health/news_underground/games/downloaded/virus_scan/what_to_do.txt"
RECORDS_PATH = "C:/Users/abarb/Documents/health/news_underground/games/downloaded/virus_scan/programs/records.txt"
API_KEY_PATH = "C:/Users/abarb/Documents/health/news_underground/games/downloaded/virus_scan/programs/API_KEY.txt"

# VirusTotal endpoints
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

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

def save_paths_dict(paths_dict, file_path):
    """
    Save the paths_dict to a JSON file.
    """
    with open(file_path, 'w') as f:
        json.dump(paths_dict, f, indent=4)

def load_paths_dict(file_path, folder_path):
    loaded_data = {"paths_dict": {}, "time_to_wait": 5, "nb_analyzed": {}, "clean_games": [], "suspicious_games": []}
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            loaded_data = json.load(f)
    
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
    
    return loaded_data, current_level, current_level_nb

def add_to_history(loaded_dict, user_indications, path, cat, game = ''):
    user_indications[cat].append(path)
    if game:
        loaded_dict[cat].append(game)
        if len(user_indications[cat]) > MAX_HISTORY:
            loaded_dict[cat].pop(0)
        save_paths_dict(loaded_dict, RECORDS_PATH)
    save_paths_dict(user_indications, WHAT_TO_DO_PATH)

def analyze_directory(directory, paths_dict, game_paths_dict, nb_analyzed, loaded_dict, user_indications, new_extensions, game, priority_lvl, time_increment, min_time, max_time, max_file_packets, lvl0=0):
    """Recursively analyze files in the directory before its subdirectories."""
    # Process all files in the current directory
    if game:
        for element in list(paths_dict.keys()):
            if element not in os.listdir(directory):
                del paths_dict[element]
        for entry in os.scandir(directory):
            if entry.is_file():
                if game and nb_analyzed[game] >= max_file_packets * FILES_MAX_PER_GAME:
                    return 0, 1
                if should_skip_file(entry.name, new_extensions, priority_lvl):
                    continue
                path = directory + '/' + entry.name
                if entry.name in paths_dict:
                    if paths_dict[entry.name] == "to_manually_scan":
                        add_to_history(loaded_dict, user_indications, path, "waiting_manual_scan")
                    continue
                if entry.stat().st_size > max_size:
                    if game:
                        nb_analyzed[game] += 1
                    add_to_history(loaded_dict, user_indications, path, "waiting_manual_scan")
                    continue
                print(f"\n[*] Uploading file: {entry.path}")
                print("new_extensions : ", new_extensions)
                analysis_id = upload_file_to_virustotal(entry.path)
                if analysis_id == -1:
                    return 1, 0
                # analysis_id = "NDA4NDE3ZmE0ZjIyYjM2Y2U4YjliMjJlM2M4ZDE4YzQ6MTczNTMwMDQ0NQ===="
                report = None
                nb_analysis_req = 0
                print(game, nb_analyzed[game], max_file_packets, FILES_MAX_PER_GAME)
                while not report or (stats:=report["data"]["attributes"]["stats"])['undetected'] == 0 and stats['suspicious'] == 0 and stats['malicious'] == 0 and stats['harmless'] == 0:
                    print("[*] Waiting for analysis results...")
                    if nb_analysis_req and loaded_dict["time_to_wait"] + time_increment <= max_time:
                        loaded_dict["time_to_wait"] += time_increment
                    time.sleep(loaded_dict["time_to_wait"])
                    if (report := get_analysis_report(analysis_id)) == -1:
                        return 1, 0
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
                    return 2, 0
                paths_dict[entry.name] = None
                if game:
                    nb_analyzed[game] += 1
                save_paths_dict(loaded_dict, RECORDS_PATH)
    else:
        for entry in list(paths_dict.keys()):
            if entry not in os.listdir(directory):
                del paths_dict[entry]
                del nb_analyzed[entry]
            
    
    # Recursively process each subdirectory
    increase_max_nb = 0
    for entry in os.scandir(directory):
        if entry.is_dir():
            if lvl0:
                game = entry.name
            found = 0
            if entry.name in paths_dict:
                if lvl0:
                    if paths_dict[entry.name] == "clean_games":
                        add_to_history(loaded_dict, user_indications, entry.path, "clean_games", game)
                        continue
                    if paths_dict[entry.name] == "suspicious_games":
                        add_to_history(loaded_dict, user_indications, entry.path, "suspicious_games", game)
                        continue
            if not found:
                paths_dict[entry.name] = {}
                if lvl0:
                    nb_analyzed[game] = 0
            if lvl0:
                if entry.name in loaded_dict["clean_games"]:
                    add_to_history(loaded_dict, user_indications, entry.path, "clean_games", game)
                    continue
                if entry.name in loaded_dict["suspicious_games"]:
                    add_to_history(loaded_dict, user_indications, entry.path, "suspicious_games", game)
                    continue
            err, increase_max_nb_temp = analyze_directory(entry.path, paths_dict[entry.name], game_paths_dict, nb_analyzed, loaded_dict, user_indications, new_extensions, game, priority_lvl, time_increment, min_time, max_time, max_file_packets)
            if err == 1:
                return 1, 0
            if err == 2:
                if lvl0:
                    add_to_history(loaded_dict, user_indications, entry.path, "suspicious_games", game)
                else:
                    return 2, 0
            if increase_max_nb_temp:
                increase_max_nb = 1
            elif err != 2 and lvl0 and priority_lvl == max(PRIORITY_MAP.values()):
                add_to_history(loaded_dict, user_indications, entry.path, "clean_games", game)
    return 0, increase_max_nb

def main():
    while 1:
        try:
            if not os.path.exists(GAMES_FOLDER_DIRECT_PATH):
                raise Exception(f"Folder {GAMES_FOLDER_DIRECT_PATH} does not exist.")
            if not os.path.isdir(GAMES_FOLDER_DIRECT_PATH):
                raise Exception(f"{GAMES_FOLDER_DIRECT_PATH} is not a folder.")
            loaded_dict, game_paths_dict, nb_analyzed = load_paths_dict(RECORDS_PATH, GAMES_FOLDER_DIRECT_PATH)
            while 1:
                err = 0
                time_increment = 5
                min_time = 5
                max_time = 60
                new_extensions = set()
                priority_lvl = 1
                max_file_packets = 1
                while priority_lvl <= max(PRIORITY_MAP.values()):
                    err, increase_max_nb = analyze_directory(GAMES_FOLDER_DIRECT_PATH, game_paths_dict, game_paths_dict, nb_analyzed, loaded_dict, {"clean_games": [], "suspicious_games": [], "waiting_manual_scan": []}, new_extensions, "", priority_lvl, time_increment, min_time, max_time, max_file_packets, 1)
                    if err == 1:
                        break
                    if increase_max_nb:
                        max_file_packets += 1
                    else:
                        priority_lvl += 1
                print("new_extensions : ", new_extensions)
                if input("Do you want to scan again? (Y/n) ").lower() == "n":
                    return
        except ZeroDivisionError  as e:
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
