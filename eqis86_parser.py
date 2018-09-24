
import sys
import zlib
import struct

import q86_2_esil as q2e

class Data_Elem:

    def __init__(self, data_bytes):

        self.size = struct.unpack("<i", data_bytes[0:4])[0]
        self.dtype = struct.unpack("<H", data_bytes[4:6])[0]
        self.bytes = data_bytes[6:6+self.size]

        # Decompress string
        if self.dtype == 1:
            self.string = zlib.decompress(self.bytes)

    def __str__(self):

        str_ret = ""

        if self.dtype == 0:
            hex_repr = ""
            for i in range(self.size):
                hex_repr += "{:02X}".format(self.bytes[i])
            str_ret = "raw data of {} bytes {{{}}}".format(self.size, hex_repr)

        elif self.dtype == 1:
            str_ret = self.string.decode("utf-8")

        else:
            str_ret = "[!] Not a printable data object"

        return str_ret


class Equis86:

    def __init__(self, exe_path):
        
        self.path = exe_path

        if not self.is_equis86():
            print("'[!] {}' is not an Equis86 executable".format(self.path))
            return

        if not self.parse_sections():
            return

    def is_equis86(self):

        hdr_ok = False

        with open(self.path, "rb") as fd:
            hdr_bytes = fd.read(4)

        if hdr_bytes == b"fq86": # 0x36387166
            hdr_ok = True

        return hdr_ok

    def parse_sections(self):

        sections_info = ""

        # Read sections info
        with open(self.path, "rb") as fd:
            fd.seek(4, 0)
            sections_info = fd.read(24)

        if len(sections_info) != 24:
            print("[!] Error reading sections information")
            return False

        sections_info = struct.iter_unpack("<i", sections_info[0:24])

        self.code_raw_addr = sections_info.__next__()[0]
        self.code_size = sections_info.__next__()[0]
        self.code_rva_addr = sections_info.__next__()[0]
        self.data_raw_addr = sections_info.__next__()[0]
        self.data_size = sections_info.__next__()[0]
        self.data_rva_addr = sections_info.__next__()[0]

        # Read sections
        with open(self.path, "rb") as fd:
            fd.seek(self.code_raw_addr, 0)
            self.code_bytes = fd.read(self.code_size)

            fd.seek(self.data_raw_addr, 0)
            self.data_bytes = fd.read(self.data_size)

        return True

    def print_esil(self):

        q2e.parse_code(self.code_bytes, self.code_rva_addr)

    def parse_data(self):

        num_data_elems = struct.unpack("<i", self.data_bytes[0:4])[0]

        print("Data section has {} elements".format(num_data_elems))

        self.data_elems = {}
        data_offset = 4 # Num elements

        for i in range(num_data_elems):
            new_data_elem = Data_Elem(self.data_bytes[data_offset:])
            self.data_elems[i] = new_data_elem

            new_data_raw_offset = self.data_raw_addr + data_offset
            
            if new_data_elem.dtype == 0:
                data_type = "raw"
            elif new_data_elem.dtype == 1:
                data_type = "str"
            else:
                data_type = "err"

            print("{:#x} ({}): {}".format(new_data_raw_offset, data_type, new_data_elem))


            data_offset += 4 + 2 + new_data_elem.size # size + type + bytes


def main():

    q86 = Equis86(sys.argv[1])

    print("Sections info:\n")

    print("code_raw_addr: {:#x}".format(q86.code_raw_addr))
    print("code_size: {:#x}".format(q86.code_size))
    print("code_rva_addr: {:#x}".format(q86.code_rva_addr))

    print("data_raw_addr: {:#x}".format(q86.data_raw_addr))
    print("data_size: {:#x}".format(q86.data_size))
    print("data_rva_addr: {:#x}".format(q86.data_rva_addr))


    print("\n\nESIL code:\n")
    q86.print_esil()

    print("\n\nData elements:\n")
    q86.parse_data()


if __name__ == '__main__':
    main()
