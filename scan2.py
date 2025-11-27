import os
import time
import hashlib
import requests
import sys
import config

# ================= CONFIGURATION =================
# PASTE YOUR VIRUSTOTAL API KEY HERE
API_KEY = config.API_KEY
# FOLDER TO SCAN
FOLDER_TO_SCAN = config.FOLDER_TO_SCAN
# =================================================

# VirusTotal V3 API Endpoints
BASE_URL = 'https://www.virustotal.com/api/v3'
FILES_URL = f'{BASE_URL}/files'
ANALYSES_URL = f'{BASE_URL}/analyses'

def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_rate_limit(response):
    """Checks if we hit the rate limit and waits if necessary."""
    if response.status_code == 429:
        print("   [!] Rate limit exceeded. Waiting 60 seconds...")
        time.sleep(61)
        return True
    return False

def get_report_by_hash(file_hash):
    """Checks if the file has already been scanned by hash."""
    headers = {'x-apikey': API_KEY}
    url = f"{FILES_URL}/{file_hash}"
    
    response = requests.get(url, headers=headers)
    
    if check_rate_limit(response):
        return get_report_by_hash(file_hash) # Retry after wait

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return stats
    elif response.status_code == 404:
        return None # File not found in VT database
    else:
        print(f"   [Error] Check failed: {response.status_code} - {response.text}")
        return None

def upload_file(filepath):
    """Uploads a file to VirusTotal for scanning."""
    headers = {'x-apikey': API_KEY}
    
    # Files larger than 32MB require a special upload URL
    filesize = os.path.getsize(filepath)
    if filesize > 32 * 1024 * 1024:
        print("   [Skip] File too large for standard API (limit 32MB)")
        return None

    with open(filepath, 'rb') as file_data:
        files = {'file': (os.path.basename(filepath), file_data)}
        response = requests.post(FILES_URL, headers=headers, files=files)

    if check_rate_limit(response):
        return upload_file(filepath) # Retry

    if response.status_code == 200:
        # Upload successful, return the analysis ID to track progress
        return response.json()['data']['id']
    else:
        print(f"   [Error] Upload failed: {response.status_code} - {response.text}")
        return None

def get_analysis_result(analysis_id):
    """Polls the analysis endpoint until the scan is complete."""
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
                time.sleep(20) # Wait 20s before polling again to save quota
        else:
            print(f"\n   [Error] Analysis check failed: {response.status_code}")
            return None

def main():
    if API_KEY == 'YOUR_API_KEY_HERE':
        print("Please edit the script and add your VirusTotal API Key.")
        sys.exit()

    if not os.path.exists(FOLDER_TO_SCAN):
        print(f"Folder not found: {FOLDER_TO_SCAN}")
        sys.exit()

    print(f"Scanning folder: {FOLDER_TO_SCAN}")
    print("Note: Free API is limited to 4 requests/minute. Delays are intentional.\n")

    files = [f for f in os.listdir(FOLDER_TO_SCAN) if os.path.isfile(os.path.join(FOLDER_TO_SCAN, f))]

    for filename in files:
        filepath = os.path.join(FOLDER_TO_SCAN, filename)
        print(f"Processing: {filename}")

        # 1. Calculate Hash
        file_hash = calculate_sha256(filepath)
        print(f"   [i] SHA256: {file_hash}")

        # 2. Check if exists
        stats = get_report_by_hash(file_hash)
        
        # Enforce Rate Limit Sleep (Safety buffer)
        time.sleep(16) 

        if stats:
            print(f"   [+] Found existing report.")
        else:
            print(f"   [-] Not found. Uploading file...")
            analysis_id = upload_file(filepath)
            
            time.sleep(16) # Safety buffer
            
            if analysis_id:
                stats = get_analysis_result(analysis_id)
            else:
                continue

        # 3. Print Results
        if stats:
            red_flags = stats['malicious']
            total_engines = sum(stats.values())
            print(f"   [RESULT] Red Flags: {red_flags}/{total_engines}")
            if red_flags > 0:
                print("   [!!!] WARNING: MALICIOUS DETECTIONS FOUND")
                return
        
        print("-" * 50)

if __name__ == "__main__":
    main()