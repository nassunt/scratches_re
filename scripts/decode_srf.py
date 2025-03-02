# This script is used to read in a SCream resource file

res_file_path = "C:/Program Files (x86)/Got Game/Scratches Director's Cut/scream.res"
header = b''
byte_index = 0


# Open the resource file and loop through each byte
with open(res_file_path, 'rb') as file:

    # Read file header
    for header_index in range(0x14):
        header += file.read(1)

    if (header != b'SCream resource file'):
        print("Invalid SCream resource file!")

    # Read through the rest of the file
    while(byte := file.read(1)):
        print(byte)
        byte_index += 1


# Output stats about the file