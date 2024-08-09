import argparse
from capstone import *
from keystone import *

# Disassemble ARM64 binary
def disassemble_arm64(binary_path):
    with open(binary_path, 'rb') as f:
        code = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    instructions = list(md.disasm(code, 0x1000))
    return instructions

# Translate ARM64 instructions to x86_64
def translate_instructions(arm64_instructions):
    translated_instructions = []
    for ins in arm64_instructions:
        x86_instruction = translate_arm64_to_x86(ins)
        translated_instructions.extend(x86_instruction)
    print(translated_instructions)
    return translated_instructions

# Assemble x86_64 instructions into binary
def assemble_x86_64(instructions, output_path):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(' '.join(instructions))
    with open(output_path, 'wb') as f:
        f.write(bytearray(encoding))

# Extended translation logic for ARM64 to x86_64
def translate_arm64_to_x86(arm64_ins):
    reg_mapping = {
        'x0': 'rax', 'x1': 'rbx', 'x2': 'rcx', 'x3': 'rdx',
        'x4': 'rsi', 'x5': 'rdi', 'x6': 'rbp', 'x7': 'rsp',
        'x8': 'r8', 'x9': 'r9', 'x10': 'r10', 'x11': 'r11',
        'x12': 'r12', 'x13': 'r13', 'x14': 'r14', 'x15': 'r15',
        'x16': 'r16', 'x17': 'r17', 'x18': 'r18', 'x19': 'r19',
        'x20': 'r20', 'x21': 'r21', 'x22': 'r22', 'x23': 'r23',
        'x24': 'r24', 'x25': 'r25', 'x26': 'r26', 'x27': 'r27',
        'x28': 'r28', 'x29': 'r29', 'x30': 'r30'
    }

    x86_instructions = []

    # TODO: CLEAN THIS UP
def generate_x86_instruction(opcode, operands):
   x86_instructions = []
   if arm64_ins.mnemonic == 'mov':
    operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'add':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('add', [reg_mapping[operands[0]], reg_mapping[operands[2]]]))

    elif arm64_ins.mnemonic == 'sub':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('sub', [reg_mapping[operands[0]], reg_mapping[operands[2]]]))

    elif arm64_ins.mnemonic == 'ldx':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'ldy':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'ldz':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif 'fma' in arm64_ins.mnemonic and '(63=0)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vmulps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('vaddps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif 'fms' in arm64_ins.mnemonic and '(63=0)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vmulps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('vsubps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif 'mac' in arm64_ins.mnemonic and '(63=0)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vmulps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('vaddps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
    
    elif arm64_ins.mnemonic == 'smulh':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('imul', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'b':
        x86_instructions.append(generate_x86_instruction('jmp', [operands[0]]))

    elif arm64_ins.mnemonic == 'cbz':
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('jz', [operands[1]]))

    elif arm64_ins.mnemonic == 'cbnz':
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('jnz', [operands[1]]))

    elif arm64_ins.mnemonic == 'ldr':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{reg_mapping[operands[1]]}]"]))

    elif arm64_ins.mnemonic == 'str':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{reg_mapping[operands[0]]}]", reg_mapping[operands[1]]]))


    elif arm64_ins.mnemonic == 'nop':
        x86_instructions.append(generate_x86_instruction('nop', []))

    elif arm64_ins.mnemonic == 'cmp':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('cmp', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'tst':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('test', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'fsub':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('subss', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'fmul':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulss', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'movk':
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], operands[1]]))

    elif arm64_ins.mnemonic == 'ldx':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{reg_mapping[operands[1]]}]"]))

    elif arm64_ins.mnemonic == 'ldy':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{reg_mapping[operands[1]]}]"]))

    elif arm64_ins.mnemonic == 'ldz':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{reg_mapping[operands[1]]}]"]))

    elif arm64_ins.mnemonic == 'matfp':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('addss', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'vecint':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('add', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
    
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
    elif arm64_ins.mnemonic == 'lsl':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{reg_mapping[operands[1]]} << {reg_mapping[operands[2]]}]"]))

    elif arm64_ins.mnemonic == 'asr':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{reg_mapping[operands[1]]} >> {reg_mapping[operands[2]]}]"]))

    elif arm64_ins.mnemonic == 'smull':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping and operands[3] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[2]], f"[{reg_mapping[operands[0]]} * {reg_mapping[operands[1]]}]"]))
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[3]], f"[{reg_mapping[operands[0]]} * {reg_mapping[operands[1]]}]"]))

    elif arm64_ins.mnemonic == 'movk':
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], operands[1]]))

    elif arm64_ins.mnemonic == 'orr':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('or', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'ldx':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'ldy':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'ldz':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'stx':
        operands = arm64_ins.op_str.split(', ')
        if operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[0]}]", reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'sty':
        operands = arm64_ins.op_str.split(', ')
        if operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[0]}]", reg_mapping[operands[1]]]))

    elif 'fma' in arm64_ins.mnemonic and '(63=0)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vmulps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('vaddps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif 'fms' in arm64_ins.mnemonic and '(63=0)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vmulps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('vsubps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif 'mac' in arm64_ins.mnemonic and '(63=0)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vmulps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('vaddps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif 'vec' in arm64_ins.mnemonic and '(47≠4)' in arm64_ins.op_str:
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('vaddps', [reg_mapping[operands[0]], reg_mapping[operands[0]], reg_mapping[operands[1]]]))
    
    elif arm64_ins.mnemonic == 'umull':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping and operands[3] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[2]], f"[{reg_mapping[operands[0]]} * {reg_mapping[operands[1]]}]"]))
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[3]], f"[{reg_mapping[operands[0]]} * {reg_mapping[operands[1]]}]"]))

    elif arm64_ins.mnemonic == 'fma':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulps', [reg_mapping[operands[1]], reg_mapping[operands[2]]]))
            x86_instructions.append(generate_x86_instruction('addps', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'fms':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulps', [reg_mapping[operands[1]], reg_mapping[operands[2]]]))
            x86_instructions.append(generate_x86_instruction('subps', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'bl':
        x86_instructions.append(generate_x86_instruction('call', [arm64_ins.op_str]))

    elif arm64_ins.mnemonic == 'blr':
        x86_instructions.append(generate_x86_instruction('call', [arm64_ins.op_str]))

    elif arm64_ins.mnemonic == 'svc':
        x86_instructions.append(generate_x86_instruction('syscall', []))

    elif arm64_ins.mnemonic == 'msr':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[0]}]", reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'mrs':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))


    # Support for new instructions
    elif arm64_ins.mnemonic == 'set':
        x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))  # Simplified example for setting state

    elif arm64_ins.mnemonic == 'clr':
        x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], 0]))  # Simplified example for clearing state

    elif arm64_ins.mnemonic == 'ldx':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'ldy':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'ldz':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'stx':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[0]}]", reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'stz':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[0]}]", reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'mac16':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulsd', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('addsd', [reg_mapping[operands[2]], reg_mapping[operands[0]]]))

    elif arm64_ins.mnemonic == 'matint':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulsd', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('addsd', [reg_mapping[operands[2]], reg_mapping[operands[0]]]))

    elif arm64_ins.mnemonic == 'vecfp':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulsd', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('addsd', [reg_mapping[operands[2]], reg_mapping[operands[0]]]))

    elif arm64_ins.mnemonic == 'extrx':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'extry':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'extrh':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'extrv':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))

    elif arm64_ins.mnemonic == 'fms':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulps', [reg_mapping[operands[1]], reg_mapping[operands[2]]]))
            x86_instructions.append(generate_x86_instruction('subps', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'bl':
        x86_instructions.append(generate_x86_instruction('call', [arm64_ins.op_str]))

    elif arm64_ins.mnemonic == 'blr':
        x86_instructions.append(generate_x86_instruction('call', [arm64_ins.op_str]))

    elif arm64_ins.mnemonic == 'msr':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[0]}]", reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'dmb':
        x86_instructions.append(generate_x86_instruction('lfence', []))  # Memory barrier

    elif arm64_ins.mnemonic == 'isb':
        x86_instructions.append(generate_x86_instruction('sfence', []))  # Instruction synchronization

    elif arm64_ins.mnemonic == 'eor':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
            x86_instructions.append(generate_x86_instruction('xor', [reg_mapping[operands[0]], reg_mapping[operands[2]]]))

    elif arm64_ins.mnemonic == 'lsr':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('shr', [reg_mapping[operands[0]], reg_mapping[operands[2]]]))

    elif arm64_ins.mnemonic == 'fdiv':
        operands = arm64_ins.op_str.split(', ')
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('divss', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'extrh':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))
        
    elif arm64_ins.mnemonic == 'extrv':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))
    elif arm64_ins.mnemonic == 'ldx':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]+8}]", reg_mapping[operands[0]]]))  # Load pair
        
    elif arm64_ins.mnemonic == 'ldy':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]+8}]", reg_mapping[operands[0]]]))  # Load pair
        
    elif arm64_ins.mnemonic == 'ldz':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [reg_mapping[operands[0]], f"[{operands[1]}]"]))
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]+8}]", reg_mapping[operands[0]]]))  # Load pair
        
    elif arm64_ins.mnemonic == 'stx':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]}]", reg_mapping[operands[0]]]))
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]+8}]", reg_mapping[operands[0]]]))  # Store pair
        
    elif arm64_ins.mnemonic == 'stz':
        if operands[0] in reg_mapping and operands[1] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]}]", reg_mapping[operands[0]]]))
            x86_instructions.append(generate_x86_instruction('mov', [f"[{operands[1]+8}]", reg_mapping[operands[0]]]))  # Store pair
        
    elif arm64_ins.mnemonic == 'fma64':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulsd', [reg_mapping[operands[1]], reg_mapping[operands[2]]]))
            x86_instructions.append(generate_x86_instruction('addsd', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))

    elif arm64_ins.mnemonic == 'fms64':
        if operands[0] in reg_mapping and operands[1] in reg_mapping and operands[2] in reg_mapping:
            x86_instructions.append(generate_x86_instruction('mulsd', [reg_mapping[operands[1]], reg_mapping[operands[2]]]))
            x86_instructions.append(generate_x86_instruction('subsd', [reg_mapping[operands[0]], reg_mapping[operands[1]]]))
    print(x86_instructions)
    return x86_instructions

def main():
    parser = argparse.ArgumentParser(description="Translates (Apple) ARM64 binary to x86_64 binary")
    parser.add_argument('-i', '--input', required=True, help="Path to the input ARM64 binary")
    parser.add_argument('-o', '--output', required=True, help="Path to the output x86_64 binary")
    args = parser.parse_args()

    arm64_binary_path = args.input
    x86_64_binary_path = args.output

    # Disassemble ARM64 binary
    arm64_instructions = disassemble_arm64(arm64_binary_path)

    # Translate ARM64 instructions to x86_64
    x86_64_instructions = translate_instructions(arm64_instructions)

    # Assemble x86_64 instructions into new binary
    assemble_x86_64(x86_64_instructions, x86_64_binary_path)
    print("Translation complete. x86_64 binary created at", x86_64_binary_path)

if __name__ == "__main__":
    main()
