import sys
import struct
import inspect

code_address = 0
curr_offset = 0

def get_reg_str(reg_num):

    regs_equiv = {
        0: "eax",
        1: "ebx",
        2: "ecx",
        3: "edx",
        4: "esi",
        5: "edi",
        6: "ebp",
        7: "esp",
    }

    reg_str = regs_equiv.get(reg_num, "e??")

    return reg_str

def parse_code(asm_bytes, base_code_addr):

    global curr_offset
    global code_address
    inst_parsers = {}

    code_address = base_code_addr

    # init inst_parsers
    # Look for q86_i_*
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if name.startswith("q86_i_"):
            inst_parsers[obj.byte_id] = obj

    while curr_offset < len(asm_bytes):

        inst_parser = inst_parsers.get(asm_bytes[curr_offset], None)

        if inst_parser is None:
            print("\n[!] Error parsing executable code")
            print("[-] Unknown inst byte {:#x} at {:#x}".format(asm_bytes[curr_offset], curr_offset))
            return

        inst = inst_parser(asm_bytes[curr_offset:])
        print("{:#x}: {}".format(code_address + curr_offset, inst))

        curr_offset += inst_parser.size


class q86_inst:

    size = None

    def __init__(self, asm_bytes):
        self.bytes = asm_bytes[:self.size]

### Instructions ###

# ESIL: <reg>, <dword>, ==, $z, zf, =
class q86_i_1(q86_inst):

    byte_id = 0x12
    size = 6

    def __str__(self):
        reg_str = get_reg_str(self.bytes[1])
        dword_str = struct.unpack("<i", self.bytes[2:6])[0]
        esil_str = "{}, {:#x}, ==, $z, zf, =".format(reg_str, dword_str)
        
        return esil_str


# ESIL: <reg>, ++=
class q86_i_2(q86_inst):

    byte_id = 0xAD
    size = 2

    def __str__(self):
        reg_str = get_reg_str(self.bytes[1])
        esil_str = "{}, ++=".format(reg_str)
        
        return esil_str


# ESIL: zf, !, ?{ <offset>, eip, =,}
class q86_i_3(q86_inst):

    byte_id = 0xF0
    size = 5

    def __str__(self):
        global code_address
        global curr_offset
        jmp_offset = struct.unpack("<i", self.bytes[1:5])[0]
        jmp_addr = code_address + curr_offset + self.size + jmp_offset
        esil_str = "zf, !, ?{{ {:#x}, eip, =,}}".format(jmp_addr)

        return esil_str


# ESIL: zf, ?{ <offset>, eip, =,}
class q86_i_4(q86_inst):

    byte_id = 0xD1
    size = 5

    def __str__(self):
        global code_address
        global curr_offset
        jmp_offset = struct.unpack("<i", self.bytes[1:5])[0]
        jmp_addr = code_address + curr_offset + self.size + jmp_offset
        esil_str = "zf, ?{{ {:#x}, eip, =,}}".format(jmp_addr)

        return esil_str


# ESIL: <dword>, <reg>, =
class q86_i_5(q86_inst):

    byte_id = 0x33
    size = 6

    def __str__(self):
        reg_str = get_reg_str(self.bytes[1])
        dword_str = struct.unpack("<i", self.bytes[2:6])[0]
        esil_str = "{:#x}, {}, =".format(dword_str, reg_str)
        
        return esil_str


# ESIL: <reg2>, <offset>, +, [], <reg1>, =
class q86_i_6(q86_inst):

    byte_id = 0x4C
    size = 7

    def __str__(self):
        reg_1_str = get_reg_str(self.bytes[1])
        reg_2_str = get_reg_str(self.bytes[2])
        offset_str = struct.unpack("<i", self.bytes[3:7])[0]
        esil_str = "{}, {:#x}, +, [], {}, =".format(
            reg_2_str, offset_str, reg_1_str)
        
        return esil_str


# ESIL: <reg2>, <reg1>, =
class q86_i_7(q86_inst):

    byte_id = 0x7E
    size = 3

    def __str__(self):
        reg_1_str = get_reg_str(self.bytes[1])
        reg_2_str = get_reg_str(self.bytes[2])
        esil_str = "{}, {}, =".format(reg_2_str, reg_1_str)
        
        return esil_str


# ESIL: <reg>, --=
class q86_i_8(q86_inst):

    byte_id = 0x47
    size = 2

    def __str__(self):
        reg_str = get_reg_str(self.bytes[1])
        esil_str = "{}, --=".format(reg_str)
        
        return esil_str


# ESIL: 4, esp, -=, <reg>, esp, =[4]
class q86_i_9(q86_inst):

    byte_id = 0xAA
    size = 2

    def __str__(self):
        reg_str = get_reg_str(self.bytes[1])
        esil_str = "4, esp, -=, {}, esp, =[4]".format(reg_str)
        
        return esil_str


# ESIL: esp, [4], eip, =, 4, esp, +=
class q86_i_10(q86_inst):

    byte_id = 0xF8
    size = 1

    def __str__(self):
        esil_str = "esp, [4], eip, =, 4, esp, +="
        
        return esil_str


# ESIL: <reg2>, <reg1>, ^=
class q86_i_11(q86_inst):

    byte_id = 0x01
    size = 3

    def __str__(self):
        reg_1_str = get_reg_str(self.bytes[1])
        reg_2_str = get_reg_str(self.bytes[2])
        esil_str = "{}, {}, ^=".format(reg_1_str, reg_2_str)
        
        return esil_str
