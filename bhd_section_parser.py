#!/usr/bin/env python3

import sys
import os
import zlib

def read_file(filename) -> str:
    f = open(filename, "rb+")
    data = f.read()
    f.close()
    return data

def parseTableData(firmware, table_offset) -> list:
    table_blob = firmware[table_offset:table_offset+19*4] #начинается на aa55aa55, заканчивается на 0055ffff
    return [table_blob[i:i+4] for i in range(0,len(table_blob),4)]

def binToAdress(data: bytes) -> str:
    return '0x'+''.join([hex(i)[2:] for i in data[::-1]])

def binToInt(data:bytes) -> int:
    return int.from_bytes(data, "little")

def sanitizeAddress(address: int, base_address):
    return address & (base_address | 0x00FFFFFF)

####
# Step 1. Parse global firmware table (Firmware Embedded Structure)
###

magic_string = b"\xff\xff\xff\xff\xaa\x55\xaa\x55"
firmware = read_file(sys.argv[1])

#TODO: Get normal FET base offset alghoritm (+- done)
if firmware[0x20000:0x20004] == b"\xaa\x55\xaa\x55":
    table_offset = 0x20000
    base_address = 0x00
else:
    table_offset = firmware.find(magic_string)+4
    if table_offset <4 :
        print("[-] Not found signature")
        sys.exit(-1)
    #TODO: Research: can offset be lesser than 0x20000
    base_address = table_offset - 0x20000

#TODO: rewrite to iterate on 4 byte while 0x55ffffff will not returned
# [5][6][7] is our BHD offset address
table_struct = parseTableData(firmware, table_offset)
print("[+] Possible tables addresses:")
possible_addresses = []
for i in [table_struct[i] for i in range(1,len(table_struct)-1)]:
    if binToInt(i) != 0:
        sanitized_addr = sanitizeAddress(binToInt(i)+base_address, base_address)
        possible_addresses.append(sanitized_addr)
        print("    " + hex(sanitized_addr) + " -> " + str(firmware[sanitized_addr:sanitized_addr+4]))

####
# Step 2.1 Checking $BHD Cookie
###
bhd_addresses= []
for address in possible_addresses:
    if firmware[address:address+4] == b"$BHD":
        #print(hex(address), "is $BHD directory")
        bhd_addresses.append(address)

####
# Step 2.2 Checking $PSP Cookie
###
psp_addresses= []
for address in possible_addresses:
    if firmware[address:address+4] == b"2PSP":
        #print(hex(address), "is 2PSP directory")
        psp_addresses.append(address)

####
# Step 3. Parse $BHD Headers.
###
directory_name = f"./{sys.argv[1]}.BHD_dump"
if bhd_addresses != []:
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

for bhd_address in bhd_addresses:
    # 1) get BHD header (4*4 byte)
    bhd_header = firmware[bhd_address:bhd_address+4*4]
    bhd_crc               = binToInt(bhd_header[4:8])
    bhd_number_of_entries = binToInt(bhd_header[8:12])
    bhd_undifinedBlob     = bhd_header[12:16]
    
    subfolder = f"/BHD_{hex(bhd_address)}"
    if not os.path.exists(directory_name + subfolder):
        os.makedirs(directory_name + subfolder)
    print(f"[+] bhd_address={hex(bhd_address)}\n\tbhd_header={bhd_header[0:4]}\n\tbhd_crc={bhd_crc}\n\tbhd_number_of_entries={bhd_number_of_entries}\n\tbhd_undifined_blob={bhd_undifinedBlob}\n\tLocation={directory_name+subfolder}")

    # 2) Parse BHD drivers (name?)
    bhd_sections_offset = bhd_address+4*4 
    for i in range(bhd_number_of_entries):
        bhd_entry = firmware[bhd_sections_offset + i*6*4:bhd_sections_offset+(i+1)*6*4]
        bhd_entry_type = binToInt(bhd_entry[0:4])
        bhd_entry_len  = binToInt(bhd_entry[4:8])
        bhd_entry_address = binToInt(bhd_entry[8:12]) + base_address
        bhd_entry_undifined_blob = bhd_entry[12:24]

        print(f"\t\t[>] BHD_Type={hex(bhd_entry_type)}\n\t\tBHD_entry_len={bhd_entry_len} ({hex(bhd_entry_len)})\n\t\tBHD_entry_address={hex(bhd_entry_address)}\n\t\tBHD_Enrty_Undf_blob={bhd_entry_undifined_blob}")

        # 3) dump it to FS
        bhd_entry_data = firmware[bhd_entry_address:bhd_entry_address+bhd_entry_len]

        out_filename = directory_name+subfolder+f"/BHD_Entry_{hex(bhd_entry_address)[2:]}_{hex(bhd_entry_len)[2:]}.bin"
        decompressed_out_filename = directory_name+subfolder+f"/BHD_Entry_{hex(bhd_entry_address)[2:]}_{hex(bhd_entry_len)[2:]}.decompress.bin"

        
        ZLIB_header = b"\x78\xda"
        zlib_found = bhd_entry_data.find(ZLIB_header)
        if zlib_found >= 0 and zlib_found <= 512: #TODO: Zlib signature bytes not too uniq
            try:
                print("\t\t[!] ZLib header found, trying do decompress")
                decompressed_data = zlib.decompress(bhd_entry_data[zlib_found:])
                f_out_dec = open(decompressed_out_filename, "wb+")
                f_out_dec.write(decompressed_data)
                f_out_dec.close()
                print(f"\t\t[+] Decompressed {len(decompressed_data)} bytes to {decompressed_out_filename}\n")
                continue
            except:
                print("[-] Failed to decompress zlib.")
        
        f_out = open(out_filename, "wb+")
        f_out.write(bhd_entry_data)
        print(f"\t\t[+] Dumped {len(bhd_entry_data)} bytes to {out_filename}\n")
        f_out.close()
