
def hex32_le(value:int) -> str:
    return value.to_bytes(4, byteorder="little").hex()

def hex32_be(value:int) -> str:
    return value.to_bytes(4, byteorder="big").hex()

def read_file(filepath:str) -> bytes():
    with open(filepath, "rb+") as f:
        return f.read()

def hexdump(data:bytes()) -> str:
    ''' lol just local hexdump for debug '''
    res = ''
    i=0
    for entry in [data[i:i+16] for i in range(0,len(data),16)]:
        res += i.to_bytes(4, 'big').hex() + ": "
        res += ' '.join(entry[j:j+4].hex() for j in range(0,16,4))
        res += '\n'
        i+=0x10

    return res

def sanitizeAddress(address: int, offset:int):
    return (address & 0x00FFFFFF) + offset