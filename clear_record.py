import json

# File to store paths of analyzed files
ANALYZED_FILES_RECORD = "analyzed_files2.txt"

def save_paths_dict(file_path):
    """
    Save the paths_dict to a JSON file.
    """
    with open(file_path, 'w') as f:
        json.dump({"paths_dict": {}, "time_to_wait": 5, "nb_analyzed": {}}, f, indent=4)

save_paths_dict(ANALYZED_FILES_RECORD)