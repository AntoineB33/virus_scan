# In txt2.txt, write a list of all the files in the given folder, without searching in the subfolders

import os


FOLDER_PATH = "C:/Users/abarb/Documents/health/news_underground/games/downloaded/mega/Enishia_and_the_Binding_Brand_v1.06-Steam/Enishia and the Binding Brand"


def list_files(folder_path):
    """List all files in the given folder."""
    files = []
    for file in os.listdir(folder_path):
        if os.path.isfile(os.path.join(folder_path, file)):
            # append the file path to the list
            files.append(folder_path + "/"+  file)
    return files

# Load the list of files from txt2.txt into a list
files = list_files(FOLDER_PATH)
with open("txt2.txt", "w") as f:
    for file in files:
        f.write(file + "\n")