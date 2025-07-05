# This script is used to read in a SCream resource file and dump the data to files

import sys

# Function to write the extracted data to a file
def output_file(file_name, file_data):
    file_name = "../file_dumps/scratches/" + file_name
    with open(file_name, "wb") as output_file:
        output_file.write(file_data)

#res_file_path = "C:/Program Files (x86)/Got Game/Scratches Director's Cut/scream.res"
res_file_path = "C:/Program Files (x86)/Got Game/Scratches Director's Cut/scratches.res"
header = b''
byte_index = 0
num_files = 0
data_file_info = b''
data_file_name = b''
data_file_name_counter = 0
data_file_offset = 0
data_file_length = 0
data_file_contents = b''

# Open the resource file and loop through each byte
with open(res_file_path, 'rb') as file:

    # Read file header
    for header_index in range(0x104):
        header += file.read(1)

    # Check the first 0x14 of the header to see if it is a SCream resource file
    if not (header.startswith(b'SCream resource file')):
        print("Error - Invalid SCream resource file!")
        sys.exit()

    # Grab the number of files from the header (last 4 bytes)
    num_files = int.from_bytes(header[-4:], byteorder='little')

    # Read through the rest of the file and dump individual files
    for data_file_index in range(num_files):
        data_file_info = file.read(0x5c)

        for data_file_info_byte in data_file_info:
            if(data_file_name_counter == 4):
                break
            elif(data_file_name_counter > 0):
                data_file_name_counter += 1
            elif(data_file_info_byte.to_bytes() == b'.'):
                data_file_name_counter += 1
            data_file_name += data_file_info_byte.to_bytes()

        print("Processing " + data_file_name.decode() + "...")

        # Get file offset
        data_file_offset = int.from_bytes(data_file_info[-8:4-8], byteorder='little')
        print("\tFile offset " + str(data_file_offset))

        # Get file length
        data_file_length = int.from_bytes(data_file_info[-4:], byteorder='little')
        print("\tFile size " + str(data_file_length))

        # Get current file pointer
        curr_file_pointer = file.tell()

        # Grab file contents
        file.seek(data_file_offset)
        data_file_contents = file.read(data_file_length)

        # Reset file pointer
        file.seek(curr_file_pointer)

        output_file(data_file_name.decode(), data_file_contents)

        data_file_name = b''
        data_file_name_counter = 0


    #while(byte := file.read(1)):
        #print(byte)
        #byte_index += 1


print("Script complete!")

# Output stats about the file
print("Number of files: " + str(num_files))