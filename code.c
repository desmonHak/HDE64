#include <stdio.h>
#include <stdint.h>
#include "hde64.h" // Include the HDE header file

#define MAX_INSTRUCTION_STRING 256

void print_hde64s(const hde64s* inst);

const char* register_names[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"
};

const char* get_register_name(uint8_t reg, int is_extended, int size) {
    if (size == 8) {
        if (reg < 4) {
            return register_names[32 + reg];  // al, cl, dl, bl
        } else {
            return register_names[36 + (reg - 4)];  // ah, ch, dh, bh
        }
    } else if (size == 16) {
        return register_names[24 + reg];  // ax, cx, dx, bx, etc.
    } else if (size == 32) {
        return register_names[16 + reg];  // eax, ecx, edx, ebx, etc.
    } else {  // 64 bits
        if (is_extended) {
            return register_names[reg + 8];
        } else {
            return register_names[reg];
        }
    }
}

void hde64_to_string(const hde64s* hs, const void* code, char* output, size_t output_size) {
    char temp[64];
    const char* opcode_name = "Unknown";
    //print_hde64s(hs);
    int operand_size = 64;  // Por defecto, asumimos operandos de 64 bits
    if (hs->p_66) operand_size = 16;
    else if (!hs->rex_w && !hs->p_67) operand_size = 32;
    if (hs->p_67) 
        if (operand_size == 64) operand_size = 32;
        else if (operand_size == 32) operand_size = 16;


    // Para instrucciones que operan explícitamente con bytes
    if (hs->opcode >= 0xB0 && hs->opcode <= 0xB7) operand_size = 8;


    // This is a very basic opcode to string conversion. You'll need to expand this significantly.
    switch (hs->opcode) {
        case 0x00 ... 0x05: opcode_name = "add"; goto exit_switch;
        case 0x08 ... 0x0d: opcode_name = "or"; goto exit_switch;
        case 0x0f:
            switch (hs->opcode2)
            {
                case 0x05:          snprintf(output, output_size, "syscall"); return;
                case 0xb0 ... 0xb1: opcode_name = "cmpxchg"; goto exit_switch;
                case 0xc0 ... 0xc1: opcode_name = "xadd"; goto exit_switch;
                case 0xc8 ... 0xcf: opcode_name = "bswap"; goto exit_switch;
                default:            
                    snprintf(output, output_size, "Unknown 0x%x 0x%x", hs->opcode, hs->opcode2); return;
            }
        case 0x10 ... 0x15: opcode_name = "adc"; goto exit_switch;
        case 0x18 ... 0x1d: opcode_name = "sbb"; goto exit_switch;
        case 0x20 ... 0x25: opcode_name = "and"; goto exit_switch;
        case 0x27:          opcode_name = "daa"; goto exit_switch;
        case 0x28 ... 0x2d: opcode_name = "sub"; goto exit_switch;
        case 0x68:
            snprintf(output, output_size, "push 0x%x", hs->imm.imm32);
            return;
        case 0x6a:
        case 0x50 ... 0x57: 
            snprintf(output, output_size, "push %s", get_register_name(hs->opcode - 0x50, hs->rex_b, operand_size));
            return;
        case 0x58 ... 0x5F: opcode_name = "pop"; goto exit_switch;
        case 0x75:          snprintf(output, output_size, "jne 0x%x", hs->imm.imm32); return;
        case 0x83:          opcode_name = "sub"; goto exit_switch;
        case 0x88 ... 0x8b: opcode_name = "mov"; goto exit_switch;
        case 0x8c:          opcode_name = "mov sreg"; goto exit_switch;
        case 0x8d:          opcode_name = "lea"; goto exit_switch;
        case 0xb0 ... 0xbf: opcode_name = "mov"; goto exit_switch;
        case 0xE8:          opcode_name = "call"; goto exit_switch;
        case 0xE9:          opcode_name = "jmp"; goto exit_switch;       // Añadido para JMP
        case 0xEA:          opcode_name = "jmp far"; goto exit_switch;   // JMP largo
        case 0xEB:          opcode_name = "jmp short"; goto exit_switch; // JMP corto
        case 0xC3:
            snprintf(output, output_size, "ret"); return;
        case 0xc7:
            snprintf(
                output, output_size, "mov %s, 0x%x", 
                get_register_name(hs->modrm_reg, hs->rex_r, operand_size),
                hs->imm.imm64
            ); return;
        case 0xC9:          
            snprintf(output, output_size, "leave"); return;
        case 0xCD: 
            snprintf(output, output_size, "int 0x%x", hs->imm.imm32); return;

        case 0xf6:
            opcode_name = "test"; break;
        default:
            snprintf(output, output_size, "Unknown 0x%x 0x%x", hs->opcode, hs->opcode2); return;
    }
    exit_switch:
    snprintf(output, output_size, "%s ", opcode_name);
    //if (hs->flags == 0) return;


    if (hs->flags & F_MODRM) {
        const char* reg = get_register_name(hs->modrm_reg, hs->rex_r, operand_size);
        const char* rm = get_register_name(hs->modrm_rm, hs->rex_b, operand_size);

        if (hs->modrm_mod == 3) {
            snprintf(temp, sizeof(temp), "%s, %s", rm, reg);
        } else {
            if (hs->flags & F_SIB) {
                int scale = 1 << hs->sib_scale;
                if (
                    hs->sib_base == 0b00000101   &&
                    hs->sib_index == 0b00000100  &&
                    hs->sib_scale == 0
                ) {
                    if (hs->flags & F_IMM8) {
                        snprintf(temp, sizeof(temp), "[0x%llx]", hs->disp.disp32);
                        goto final_analize;
                    } else {
                        snprintf(temp, sizeof(temp), "%s, [0x%llx]", reg, hs->disp.disp32);
                        goto final_analize;
                    }
                }
                const char* base = get_register_name(hs->sib_base, hs->rex_b, operand_size);
                const char* index = get_register_name(hs->sib_index, hs->rex_x, operand_size);
                

                if (hs->sib_index == 4 && !hs->rex_x) {
                    snprintf(temp, sizeof(temp), "%s, [%s", reg, base);
                } else {
                    snprintf(temp, sizeof(temp), "%s, [%s + %s*%d", reg, base, index, scale);
                }

                if (hs->flags & F_DISP32) {
                    snprintf(temp + strlen(temp), sizeof(temp) - strlen(temp), " + 0x%x]", hs->disp.disp32);
                } else if (hs->flags & F_DISP8) {
                    snprintf(temp + strlen(temp), sizeof(temp) - strlen(temp), " + 0x%x]", hs->disp.disp8);
                } else {
                    strcat(temp, "]");
                }
            } else {
                snprintf(temp, sizeof(temp), "%s, [%s", reg, rm);
                if (hs->flags & F_DISP32) {
                    snprintf(temp + strlen(temp), sizeof(temp) - strlen(temp), "+0x%x]", hs->disp.disp32);
                } else if (hs->flags & F_DISP16) {
                    snprintf(temp + strlen(temp), sizeof(temp) - strlen(temp), "+0x%x]", hs->disp.disp16);
                } else if (hs->flags & F_DISP8) {
                    snprintf(temp + strlen(temp), sizeof(temp) - strlen(temp), "+0x%x]", hs->disp.disp8);
                } else {
                    strcat(temp, "]");
                }
            }
        }
        final_analize:
        strncat(output, temp, output_size - strlen(output) - 1);
    } else if (hs->flags & F_RELATIVE) {
        int64_t target = (int64_t)(intptr_t)code + hs->len + (int32_t)hs->imm.imm32;
        snprintf(temp, sizeof(temp), "0x%llx", (unsigned long long)target);
        strncat(output, temp, output_size - strlen(output) - 1);
    } else {
        //if (inst->flags & 0x40)
        const char* reg = get_register_name(hs->modrm_reg, hs->rex_r, operand_size);
        snprintf(temp, sizeof(temp), "%s", reg);
        strncat(output, temp, output_size - strlen(output) - 1);
    }

    // Manejo de inmediatos
    if (!(hs->flags & F_RELATIVE)) {
        if (hs->flags & F_IMM8) {
            snprintf(temp, sizeof(temp), ", 0x%x", hs->imm.imm8);
            strncat(output, temp, output_size - strlen(output) - 1);
        } else if (hs->flags & F_IMM16) {
            snprintf(temp, sizeof(temp), ", 0x%x", hs->imm.imm16);
            strncat(output, temp, output_size - strlen(output) - 1);
        } else if (hs->flags & F_IMM32) {
            snprintf(temp, sizeof(temp), ", 0x%x", hs->imm.imm32);
            strncat(output, temp, output_size - strlen(output) - 1);
        }
    }

    // Manejo especial para SUB con inmediato
    if (hs->opcode == 0x83 && hs->modrm_reg == 5) {
        const char* rm = get_register_name(hs->modrm_rm, hs->rex_b, operand_size);
        snprintf(output, output_size, "sub %s, 0x%x", rm, hs->imm.imm8);
    }
}


    #define TABPRINT "\t"
void print_flags(uint32_t flags) {
    printf(TABPRINT"Flags:\n");

    if (flags & F_MODRM)        printf(TABPRINT "  F_MODRM\n");
    if (flags & F_SIB)          printf(TABPRINT "  F_SIB\n");
    if (flags & F_IMM8)         printf(TABPRINT "  F_IMM8\n");
    if (flags & F_IMM16)        printf(TABPRINT "  F_IMM16\n");
    if (flags & F_IMM32)        printf(TABPRINT "  F_IMM32\n");
    if (flags & F_IMM64)        printf(TABPRINT "  F_IMM64\n");
    if (flags & F_DISP8)        printf(TABPRINT "  F_DISP8\n");
    if (flags & F_DISP16)       printf(TABPRINT "  F_DISP16\n");
    if (flags & F_DISP32)       printf(TABPRINT "  F_DISP32\n");
    if (flags & F_RELATIVE)     printf(TABPRINT "  F_RELATIVE\n");
    if (flags & F_PREFIX_REPNZ) printf(TABPRINT "  F_PREFIX_REPNZ\n");
    if (flags & F_PREFIX_REPX)  printf(TABPRINT "  F_PREFIX_REPX\n");
    if (flags & F_PREFIX_REP)   printf(TABPRINT "  F_PREFIX_REP\n");
    if (flags & F_PREFIX_66)    printf(TABPRINT "  F_PREFIX_66\n");
    if (flags & F_PREFIX_67)    printf(TABPRINT "  F_PREFIX_67\n");
    if (flags & F_PREFIX_LOCK)  printf(TABPRINT "  F_PREFIX_LOCK\n");
    if (flags & F_PREFIX_SEG)   printf(TABPRINT "  F_PREFIX_SEG\n");
    if (flags & F_PREFIX_REX)   printf(TABPRINT "  F_PREFIX_REX\n");
    if (flags & F_PREFIX_ANY)   printf(TABPRINT "  F_PREFIX_ANY\n");
    
    // Flags de error
    if (flags & F_ERROR)         printf(TABPRINT"  F_ERROR\n");
    if (flags & F_ERROR_OPCODE)  printf(TABPRINT"  F_ERROR_OPCODE\n");
    if (flags & F_ERROR_LENGTH)  printf(TABPRINT"  F_ERROR_LENGTH\n");
    if (flags & F_ERROR_LOCK)    printf(TABPRINT"  F_ERROR_LOCK\n");
    if (flags & F_ERROR_OPERAND) printf(TABPRINT"  F_ERROR_OPERAND\n");
}
void print_hde64s(const hde64s* inst) {

    printf("  Length: %u\n", inst->len);
    printf("  Prefix REP: %u\n", inst->p_rep);
    printf("  Prefix LOCK: %u\n", inst->p_lock);
    printf("  Prefix Segment: %u\n", inst->p_seg);
    printf("  Prefix Operand-size override: %u\n", inst->p_66);
    printf("  Prefix Address-size override: %u\n", inst->p_67);
    printf("  REX: %u\n", inst->rex);
    printf("  REX.W: %u\n", inst->rex_w);
    printf("  REX.R: %u\n", inst->rex_r);
    printf("  REX.X: %u\n", inst->rex_x);
    printf("  REX.B: %u\n", inst->rex_b);
    printf("  Opcode: 0x%x\n", inst->opcode);
    printf("  Opcode2: 0x%x\n", inst->opcode2);
    printf("  ModRM: 0x%x\n", inst->modrm);
    printf("    ModRM.mod: %u\n", inst->modrm_mod);
    printf("    ModRM.reg: %u\n", inst->modrm_reg);
    printf("    ModRM.rm: %u\n", inst->modrm_rm);
    printf("  SIB: 0x%x\n", inst->sib);
    printf("    SIB.scale: %u\n", inst->sib_scale);
    printf("    SIB.index: %u\n", inst->sib_index);
    printf("    SIB.base: %u\n", inst->sib_base);
    printf(TABPRINT "imm: ");
    if (inst->flags & 0x04) { // F_IMM8
        printf( "%u (imm8)\n", inst->imm.imm8);
    } else if (inst->flags & 0x08) { // F_IMM16
        printf( "%u (imm16)\n", inst->imm.imm16);
    } else if (inst->flags & 0x10) { // F_IMM32
        printf( "%u (imm32)\n", inst->imm.imm32);
    } else if (inst->flags & 0x20) { // F_IMM64
        printf( "%llu (imm64)\n", inst->imm.imm64);
    } else {
        printf( "No immediate\n");
    }
    printf(TABPRINT "disp: ");
    if (inst->flags & 0x40) { // F_DISP8
        printf("%u (disp8)\n", inst->disp.disp8);
    } else if (inst->flags & 0x80) { // F_DISP16
        printf( "%u (disp16)\n", inst->disp.disp16);
    } else if (inst->flags & 0x100) { // F_DISP32
        printf("%u (disp32)\n", inst->disp.disp32);
    } else {
        printf("No displacement\n");
    }
    printf(TABPRINT"flags: 0x%x\n", inst->flags);
    print_flags(inst->flags);
}



void analyze_instruction(const unsigned char* code) {
    hde64s hs;
    unsigned int len = hde64_disasm(code, &hs);

    printf("Instruction Length: %u\n", hs.len);
    printf("Opcode: 0x%02X\n", hs.opcode);
    
    if (hs.flags & F_MODRM) {
        printf("ModR/M: 0x%02X (Mod: %d, Reg: %d, R/M: %d)\n", 
               hs.modrm, hs.modrm_mod, hs.modrm_reg, hs.modrm_rm);
    }
    
    if (hs.flags & F_SIB) {
        printf("SIB: 0x%02X (Scale: %d, Index: %d, Base: %d)\n", 
               hs.sib, hs.sib_scale, hs.sib_index, hs.sib_base);
    }
    
    if (hs.flags & F_IMM8) printf("Immediate8: 0x%02X\n", hs.imm.imm8);
    if (hs.flags & F_IMM16) printf("Immediate16: 0x%04X\n", hs.imm.imm16);
    if (hs.flags & F_IMM32) printf("Immediate32: 0x%08X\n", hs.imm.imm32);
    if (hs.flags & F_IMM64) printf("Immediate64: 0x%016llX\n", hs.imm.imm64);

    if (hs.flags & F_DISP8) printf("Displacement8: 0x%02X\n", hs.disp.disp8);
    if (hs.flags & F_DISP16) printf("Displacement16: 0x%04X\n", hs.disp.disp16);
    if (hs.flags & F_DISP32) printf("Displacement32: 0x%08X\n", hs.disp.disp32);

    printf("Flags: 0x%08X\n", hs.flags);
}
void disassemble_function(const unsigned char* code, size_t size) {
    const unsigned char* p = code;
    hde64s hs;
    unsigned int len;
    char instruction_string[MAX_INSTRUCTION_STRING];

    while (p < code + size) {
        len = hde64_disasm(p, &hs);
        printf("%p: ", (void*)p);
        hde64_to_string(&hs, p, instruction_string, sizeof(instruction_string));

        printf("%-30s\t", instruction_string);
        for (int i = 0; i < len; i++) {
            printf("%02X ", p[i]);
        }
        printf("\n", instruction_string);
    
        
        /*if (hs.opcode == 0xC3) // RET instruction
            break;*/
        
        p += len;
    }
}

void find_call_instructions(const unsigned char* code, size_t size) {
    const unsigned char* p = code;
    hde64s hs;
    unsigned int len;

    while (p < code + size) {
        len = hde64_disasm(p, &hs);
        
        if (hs.opcode == 0xE8) { // CALL instruction
            printf("CALL instruction found at offset: %td\n", p - code);
            printf("Target: 0x%08X\n", *(int32_t*)(p + 1) + (uint32_t)(p - code + 5));
        }
        
        p += len;
    }
}

int main() {
    // Example machine code (x86-64) to disassemble
    unsigned char code[] = {
        0x8d, 0x80, 0x88, 0x77, 0x22, 0x11,               // lea eax, [rax + 0x11227788]
        0x0f, 0x05,                                       // syscall
        0x48, 0x55,                                       // push   rbp
        0x48, 0x89, 0xe5,                                 // mov    rbp, rsp
        0x68, 0x44, 0x33, 0x22, 0x11,                     // push   0x11223344
        0x48, 0x13, 0x43, 0x0a,                           // adc    rax, [rbx + 10]
        0x48, 0x83, 0xec, 0x10,                           // sub    rsp, 0x10
        0x83, 0xec, 0x10,                                 // sub    esp, 0x10
        0xe8, 0x00, 0x00, 0x00, 0x00,                     // call   <function>
        0xc9,                                             // leave
        0xc3,                                             // ret
        0x4c, 0x8b, 0xd1,                                 // mov    r10, rcx
        0xe9, 0x60, 0x6b, 0x07, 0x00,                     // jmp    0x76b65
        0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,   // text byte ptr ds:[0x7ffe0308], 1
        0x75, 0x03,                                       // jmp
        0x0f, 0x05,                                       // syscall
        0xc3,                                             // ret
        0xcd, 0x2e,                                       // int 0x2e
        0xc3,                                             // ret

        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,         // mov     rax, 1
        0xBB, 0x02, 0x00, 0x00, 0x00,                     // mov     ebx, 2
        0x48, 0xc7, 0xc1, 0x03, 0x00, 0x00, 0x00,         // mov     rcx, 3
        0xBA, 0x04, 0x00, 0x00, 0x00,                     // mov     edx, 4
        0x0F, 0x05,                                       // syscall 
        0x8D, 0x04, 0x25, 0x88, 0x77, 0x66, 0x55,         // lea     eax, [0x55667788] 
    };

    hde64s hs; // Structure to hold disassembled instruction
    unsigned int len; // Length of the instruction

    analyze_instruction(code);
    disassemble_function(code, sizeof(code));
    find_call_instructions(code, sizeof(code));

    // Disassemble the code
    const unsigned char *p = code;
    while (p < code + sizeof(code)) {
        len = hde64_disasm(p, &hs); // Call the disassembler
        printf("Instruction: ");
        
        // Print the opcode and other details
        printf("Opcode: 0x%02X ", hs.opcode);
        if (hs.p_rep)  printf("Prefix: 0x%02X ", hs.p_rep);
        if (hs.p_lock) printf("Lock Prefix: 0x%02X ", hs.p_lock);
        if (hs.flags & F_ERROR) printf("Invalid instruction !\n");

        
        // Print length of instruction and move pointer forward
        printf("Length: %u\n", hs.len);
        
        p += len; // Move to the next instruction
    }

    return 0;
}