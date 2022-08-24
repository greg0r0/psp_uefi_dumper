
import re

import types_local as types
import utils_local as utils

class FET:
    def __init__(self, offset, binblob):
        #TODO: var naming :D
        self.raw_table = binblob

        self.fet_location = offset           # base image offset
        self.fet_offset   = offset - types.base_offset # seems like 0x020000 offset is some type of standard

        self.magic_start  = binblob[0:4]

        # next fields if often zero
        self.imc      = binblob[4:8]   # IMC offset
        self.ethernet = binblob[8:12]  # Ethernet offset
        self.xhci     = binblob[12:16] # xHCI FW offset

        # main part - get all PSP, BHD and Other addresses 
        # here just parsing 4 byte addresses and sanitizing it with FET offset in firmware
        self.modules_offsets = []
        
        pad_start = 0x10
        iter_addr = 0

        while binblob[pad_start+iter_addr*4:pad_start+4*(iter_addr+1)] != b"\x00\x55\xff\xff":
            
            address_new = utils.sanitizeAddress( int.from_bytes(binblob[pad_start+iter_addr*4:pad_start+4*(iter_addr+1)],'little'), self.fet_offset)
            self.modules_offsets.append(address_new)
            iter_addr+=1

        self.magic_end = binblob[pad_start+iter_addr*4:pad_start+4*(iter_addr+1)]

        if not (self.magic_start == b'\xaa\x55\xaa\x55' and self.magic_end == b"\x00\x55\xff\xff"):
            print(f"[!] FET at offset {self.fet_location} possible not FET.")

    def hexdump(self):
        return utils.hexdump(self.raw_table)



if __name__ == "__main__":
    import sys
    data = utils.read_file(sys.argv[1])

    for fet in re.finditer(types.re_fet, data):
        fet_blob = FET(fet.start(), fet.group())
        print(f"[+] FET foind at {hex(fet_blob.fet_location)}")
        print(fet_blob.hexdump())

        for addr in fet_blob.modules_offsets:
            print(utils.hex32_be(addr))
            print(data[addr:addr+4])
