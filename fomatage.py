import os
import json

# Input text file containing file paths (one per line)
INPUT_FILE = "analyzed_files.txt"
# Output JSON file in the expected format
ANALYZED_FILES_RECORD = "analyzed_files2.txt"
# Base folder to count subfolders
BASE_FOLDER = "../to_scan"

def build_nested_dict_from_paths(file_paths):
    """
    Build a nested dictionary from a list of file paths, starting with drive letters.
    """
    nested_dict = {}

    for path in file_paths:
        path = path.strip()
        if not path or not os.path.exists(path):
            continue  # Skip empty or non-existent paths

        path = os.path.abspath(path)  # Ensure absolute path
        drive, tail = os.path.splitdrive(path)  # Split drive (e.g., 'C:') and the rest of the path
        
        if not drive:
            continue  # Skip if the path doesn't have a drive letter (shouldn't happen on Windows)

        path_parts = os.path.normpath(tail).strip(os.sep).split(os.sep)

        current_level = nested_dict.setdefault(drive, {})
        for part in path_parts[:-1]:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]

        # Mark the final part (file) as None (leaf node)
        final_part = path_parts[-1]
        current_level[final_part] = None

    return nested_dict


def count_subfolders(base_folder):
    """
    Count all folders and subfolders under each top-level folder in base_folder.
    """
    folder_counts = {}

    if not os.path.exists(base_folder):
        print(f"[ERROR] Base folder {base_folder} does not exist.")
        return folder_counts

    for entry in os.scandir(base_folder):
        if entry.is_dir():
            folder_name = entry.name
            folder_counts[folder_name] = sum(1 for _, dirs, _ in os.walk(entry.path) for _ in dirs)

    return folder_counts


def main():
    # Read file paths from the input file
    with open(INPUT_FILE, "r", encoding='utf-8', errors='ignore') as f:
        file_paths = f.readlines()

    # Build nested dictionary
    nested_dict = build_nested_dict_from_paths(file_paths)

    # Count subfolders
    nb_analyzed = count_subfolders(BASE_FOLDER)

    # Wrap it in the expected structure
    analyzed_files_record = {
        "paths_dict": nested_dict,
        "time_to_wait": 5,
        "nb_analyzed": nb_analyzed
    }

    # Save to JSON file
    with open(ANALYZED_FILES_RECORD, "w", encoding='utf-8') as f:
        json.dump(analyzed_files_record, f, indent=4)

    print(f"[SUCCESS] Transformed file paths saved to {ANALYZED_FILES_RECORD}")


if __name__ == "__main__":
    main()
