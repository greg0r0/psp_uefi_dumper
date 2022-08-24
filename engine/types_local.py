
import re

base_offset = 0x00020000

re_fet = re.compile(b"\xaa\x55\xaa\x55.*\x00\x55\xff\xff")