# Write in txt3.txt the union of the sets in analyzed_files.txt and txt2.txt.

with open("analyzed_files.txt", "r") as f:
    txt1 = list(map(lambda line: line.replace("\\", "/"), f.read().splitlines()))
with open("txt2.txt", "r") as f:
    txt2 = f.read().splitlines()
with open("txt3.txt", "w") as f:
    for line in txt1:
        f.write(line + "\n")
    for line in txt2:
        if line not in txt1:
            f.write(line + "\n")