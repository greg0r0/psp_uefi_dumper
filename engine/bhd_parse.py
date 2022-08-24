#!/usr/bin/env python3

import types_local as types
import utils_local as utils
import fet_parse

class BHD_Entry:
    def __init__(self, binary_blob, base_addr):
        assert len(binary_blob) == 24
        self.type = binary_blob[0:4][::-1]
        self.size = int.from_bytes(binary_blob[4:8], "little")
        self.firmware_offset = utils.sanitizeAddress(int.from_bytes(binary_blob[8:12], "little"),base_addr)
        self.undf_blob = binary_blob[12:24]

    def __str__(self) -> str:
        return f"BHD_Entry(type={self.type.hex()}, size={self.size} ({hex(self.size)}), firmware_file_offset={hex(self.firmware_offset)}, undf_data={self.undf_blob.hex()} )"

class BHD_Table:
    def __init__(self, firmware:bytes, bhd_address:int, base_addr:int):
        assert firmware[bhd_address:bhd_address+4] == b"$BHD"
        self.sign           = firmware[bhd_address:bhd_address+4]
        self.address        = bhd_address
        self.checksum       = firmware[bhd_address+4:bhd_address+8]
        self.entry_count    = int.from_bytes(firmware[bhd_address+8:bhd_address+12], "little")
        self.undf_blob      = firmware[bhd_address+12:bhd_address+16]
        self.bhd_entries = []
        for entry_iter in range(0, self.entry_count):
            entry_offset_address = (bhd_address+16) + entry_iter*24
            self.bhd_entries.append(BHD_Entry(firmware[entry_offset_address:entry_offset_address+24], base_addr))

    def __str__(self) -> str:
        start_str = f"BHD_Table(addr={hex(self.address)}, checksum={int.from_bytes(self.checksum, 'big')}, entry_count={self.entry_count}, undf_data={self.undf_blob.hex()})"
        for entry in self.bhd_entries:
            start_str+="\n\t"+entry.__str__()
        return start_str

def get_next_BHD_Table(fet_t: fet_parse.FET, firmware: bytes()) -> BHD_Table:
    for bhd_address in fet_t.iterate_over(b"$BHD", firmware):
        yield BHD_Table(firmware, bhd_address, fet_t.fet_offset)
        

def get_next_BHD_Entry(bhd_t: BHD_Table, firmware: bytes()) -> BHD_Entry:
    for bhd_entry in bhd_t.bhd_entries:
        yield bhd_entry


class BL2_Table:
    pass
class BHD2_Table:
    pass
class BHD2_Entry:
    pass


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"[-] Please use: {sys.argv[0]} <firmware file>")
        sys.exit(-1)
    data = utils.read_file(sys.argv[1])
    for fet in fet_parse.get_next_FET(firmware=data):
        print(f"[+] FET foind at {hex(fet.fet_location)}")
        for bhd in get_next_BHD_Table(fet, data):
            print(bhd)