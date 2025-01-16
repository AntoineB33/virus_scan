import subprocess

def is_file_open(file_path):
    try:
        result = subprocess.run(['handle.exe', file_path], capture_output=True, text=True)
        if file_path in result.stdout:
            return True
    except FileNotFoundError:
        print("Make sure `handle.exe` is installed and accessible in your PATH.")
    return False

file_path = "example.txt"
if is_file_open(file_path):
    print(f"The file {file_path} is open.")
else:
    print(f"The file {file_path} is not open.")
