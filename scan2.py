import os
import time
import hashlib
import requests
import sys
import config

# ================= CONFIGURATION =================
API_KEY = config.API_KEY
FOLDER_TO_SCAN = config.FOLDER_TO_SCAN
# =================================================

# Priority mapping (lower number = higher scan priority)
PRIORITY_MAP = {
    'exe': 1, 'dll': 1, 'bat': 1, 'cmd': 1, 'js': 1, 'vbs': 1, 'py': 1, 'sh': 1, 'so': 1, 'wasm': 1,
    'zip': 2, 'rar': 2, '7z': 2,
    'htm': 3, 'bin': 3,
    'dat': 4, 'pak': 4, 'vdf': 4, 'db': 4,
    'txt': 5, 'json': 5, 'xml': 5, 'css': 5, '' : 5,
}

# VirusTotal V3 API Endpoints
BASE_URL = 'https://www.virustotal.com/api/v3'
FILES_URL = f'{BASE_URL}/files'
ANALYSES_URL = f'{BASE_URL}/analyses'


def get_priority(filename):
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    return PRIORITY_MAP.get(ext, 10)   # unknown = lowest priority


def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_rate_limit(response):
    if response.status_code == 429:
        print("   [!] Rate limit exceeded. Waiting 60 seconds...")
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
        return None
    else:
        print(f"   [Error] Check failed: {response.status_code} - {response.text}")
        return None


def upload_file(filepath):
    headers = {'x-apikey': API_KEY}
    filesize = os.path.getsize(filepath)

    if filesize > 32 * 1024 * 1024:
        print("   [Skip] File too large for standard API (limit 32MB)")
        return None

    with open(filepath, 'rb') as file_data:
        files = {'file': (os.path.basename(filepath), file_data)}
        response = requests.post(FILES_URL, headers=headers, files=files)

    if check_rate_limit(response):
        return upload_file(filepath)

    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f"   [Error] Upload failed: {response.status_code} - {response.text}")
        return None


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
            return None


def main():
    if API_KEY == 'YOUR_API_KEY_HERE':
        print("Please add your VirusTotal API Key.")
        sys.exit()

    if not os.path.exists(FOLDER_TO_SCAN):
        print(f"Folder not found: {FOLDER_TO_SCAN}")
        sys.exit()

    print(f"Scanning directory recursively: {FOLDER_TO_SCAN}")
    print("Files will be processed based on threat priority.\n")

    # ==============================
    # 🔥 RECURSIVE FILE COLLECTION
    # ==============================
    all_files = []
    for root, dirs, files in os.walk(FOLDER_TO_SCAN):
        for f in files:
            full_path = os.path.join(root, f)
            all_files.append(full_path)

    # Sort based on risk priority (highest priority first)
    all_files.sort(key=lambda x: get_priority(os.path.basename(x)))

    # ==============================
    # 🔥 SCANNING LOOP
    # ==============================
    for filepath in all_files:
        filename = os.path.basename(filepath)
        priority = get_priority(filename)

        print(f"[START] -> {filepath}  (Priority {priority})")

        sha = calculate_sha256(filepath)
        print(f"   [i] SHA256: {sha}")

        stats = get_report_by_hash(sha)
        time.sleep(16)

        if stats is None:
            print("   [-] No existing report → Uploading file...")
            analysis_id = upload_file(filepath)

            time.sleep(16)
            if analysis_id:
                stats = get_analysis_result(analysis_id)
            else:
                continue
        else:
            print("   [+] Report already exists.")

        if stats:
            red = stats['malicious']
            total = sum(stats.values())
            print(f"   [RESULT] {red}/{total} engines flagged")

            if red > 0:
                print("   [!!!] MALICIOUS FILE FOUND — SCAN STOPPED")
                return

        print("-" * 60)

if __name__ == "__main__":
    main()
    input("Scanning complete. Press Enter to exit...")
