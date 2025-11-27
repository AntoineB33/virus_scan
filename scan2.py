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

    print(f"Scanning folder: {FOLDER_TO_SCAN}")
    print("Files will be scanned in priority order.\n")

    files = [f for f in os.listdir(FOLDER_TO_SCAN) if os.path.isfile(os.path.join(FOLDER_TO_SCAN, f))]

    # 🔥 SORT BASED ON THREAT PRIORITY
    files.sort(key=get_priority)

    for filename in files:
        filepath = os.path.join(FOLDER_TO_SCAN, filename)
        print(f"[START] -> {filename} (Priority {get_priority(filename)})")

        file_hash = calculate_sha256(filepath)
        print(f"   [i] SHA256: {file_hash}")

        stats = get_report_by_hash(file_hash)
        time.sleep(16)

        if not stats:
            print("   [-] Not found → Uploading...")
            analysis_id = upload_file(filepath)
            time.sleep(16)
            if analysis_id:
                stats = get_analysis_result(analysis_id)
            else:
                continue
        else:
            print("   [+] Existing report found.")

        if stats:
            red_flags = stats['malicious']
            total = sum(stats.values())
            print(f"   [RESULT] {red_flags}/{total} engines flagged")

            if red_flags > 0:
                print("   [!!!] WARNING — MALICIOUS FILE DETECTED!")
                return

        print("-" * 50)


if __name__ == "__main__":
    main()
