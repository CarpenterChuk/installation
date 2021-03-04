with open(r'D:\6 семестр\стк\lab#2\lab#1.exe', 'rb') as infile:
    source = infile.read()
    with open(r'D:\lab#1_exe.txt', 'wb') as outfile:
        outfile.write(source)
