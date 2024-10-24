/*
 * Hacker Disassembler Engine 64
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 * hde64.h: C/C++ header file
 *
 */

#ifndef _HDE64_H_
#define _HDE64_H_

#include <Windows.h>

// Integer types for HDE. stdint.h
typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;
typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

// table64.h
#define C_NONE 0x00
#define C_MODRM 0x01
#define C_IMM8 0x02
#define C_IMM16 0x04
#define C_IMM_P66 0x10
#define C_REL8 0x20
#define C_REL32 0x40
#define C_GROUP 0x80
#define C_ERROR 0xff

#define PRE_ANY 0x00
#define PRE_NONE 0x01
#define PRE_F2 0x02
#define PRE_F3 0x04
#define PRE_66 0x08
#define PRE_67 0x10
#define PRE_LOCK 0x20
#define PRE_SEG 0x40
#define PRE_ALL 0xff

#define DELTA_OPCODES 0x4a
#define DELTA_FPU_REG 0xfd
#define DELTA_FPU_MODRM 0x104
#define DELTA_PREFIXES 0x13c
#define DELTA_OP_LOCK_OK 0x1ae
#define DELTA_OP2_LOCK_OK 0x1c6
#define DELTA_OP_ONLY_MEM 0x1d8
#define DELTA_OP2_ONLY_MEM 0x1e7

unsigned char hde64_table[] = {

    0xa5, 0xaa, 0xa5, 0xb8, 0xa5, 0xaa, 0xa5, 0xaa, 0xa5, 0xb8, 0xa5, 0xb8, 0xa5, 0xb8, 0xa5, // 15
    0xb8, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xac, 0xc0, 0xcc, 0xc0, 0xa1, 0xa1, // 30
    0xa1, 0xa1, 0xb1, 0xa5, 0xa5, 0xa6, 0xc0, 0xc0, 0xd7, 0xda, 0xe0, 0xc0, 0xe4, 0xc0, 0xea, // 45
    0xea, 0xe0, 0xe0, 0x98, 0xc8, 0xee, 0xf1, 0xa5, 0xd3, 0xa5, 0xa5, 0xa1, 0xea, 0x9e, 0xc0, // 60
    0xc0, 0xc2, 0xc0, 0xe6, 0x03, 0x7f, 0x11, 0x7f, 0x01, 0x7f, 0x01, 0x3f, 0x01, 0x01, 0xab, // 75
    0x8b, 0x90, 0x64, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x92, 0x5b, 0x5b, 0x76, 0x90, 0x92, 0x92, // 90
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x6a, 0x73, 0x90, // 105
    0x5b, 0x52, 0x52, 0x52, 0x52, 0x5b, 0x5b, 0x5b, 0x5b, 0x77, 0x7c, 0x77, 0x85, 0x5b, 0x5b, // 120
    0x70, 0x5b, 0x7a, 0xaf, 0x76, 0x76, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, // 135
    0x5b, 0x5b, 0x86,
    0x01, 0x03, 0x01, 0x04, 0x03, 0xd5, 0x03, 0xd5, 0x03, 0xcc, 0x01, 0xbc,                   // 150 // apartir de 138 empieza las flags?
    0x03, 0xf0, 0x03, 0x03, 0x04, 0x00, 0x50, 0x50, 0x50, 0x50, 0xff, 0x20, 0x20, 0x20, 0x20, // 165
    0x01, 0x01, 0x01, 0x01, 0xc4, 0x02, 0x10, 0xff, 0xff, 0xff, 0x01, 0x00, 0x03, 0x11, 0xff, // 180
    0x03, 0xc4, 0xc6, 0xc8, 0x02, 0x10, 0x00, 0xff, 0xcc, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, // 195
    0x00, 0x01, 0x01, 0x03, 0x01, 0xff, 0xff, 0xc0, 0xc2, 0x10, 0x11, 0x02, 0x03, 0x01, 0x01, // 210
    0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x10, // 225
    0x10, 0x10, 0x10, 0x02, 0x10, 0x00, 0x00, 0xc6, 0xc8, 0x02, 0x02, 0x02, 0x02, 0x06, 0x00, // 240
    0x04, 0x00, 0x02, 0xff, 0x00, 0xc0, 0xc2, 0x01, 0x01, 0x03, 0x03, 0x03, 0xca, 0x40, 0x00, // 255
    0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x33, 0x01, 0x00, 0x00, 0x00, 0x00, // 270
    0x00, 0x00, 0xff, 0xbf, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0xff, 0x00, // 285
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, // 300
    0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, // 315
    0xff, 0x40, 0x40, 0x40, 0x40, 0x41, 0x49, 0x40, 0x40, 0x40, 0x40, 0x4c, 0x42, 0x40, 0x40, // 330
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x4f, 0x44, 0x53, 0x40, 0x40, 0x40, 0x44, 0x57, 0x43, // 345
    0x5c, 0x40, 0x60, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, // 360
    0x40, 0x40, 0x64, 0x66, 0x6e, 0x6b, 0x40, 0x40, 0x6a, 0x46, 0x40, 0x40, 0x44, 0x46, 0x40, // 375
    0x40, 0x5b, 0x44, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x06, 0x06, 0x01, 0x06, // 390
    0x06, 0x02, 0x06, 0x06, 0x00, 0x06, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, // 405
    0x06, 0x02, 0x0d, 0x06, 0x06, 0x06, 0x0e, 0x05, 0x05, 0x02, 0x02, 0x00, 0x00, 0x04, 0x04, // 420
    0x04, 0x04, 0x05, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x08, 0x00, 0x10, // 435
    0x00, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x80, 0x01, 0x82, 0x01, 0x86, 0x00, // 450
    0xf6, 0xcf, 0xfe, 0x3f, 0xab, 0x00, 0xb0, 0x00, 0xb1, 0x00, 0xb3, 0x00, 0xba, 0xf8, 0xbb, // 465
    0x00, 0xc0, 0x00, 0xc1, 0x00, 0xc7, 0xbf,
    // apartir de aqui, empieza DELTA_OP_ONLY_MEM
    0x62, 0xff, 0x00, 0x8d, 0xff, 0x00, 0xc4, 0xff, // 480
    0x00, 0xc5, 0xff, 0x00, 0xff, 0xff, 0xeb, 0x01,
    // aqui acaba DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM
    0xff, 0x0e, 0x12, 0x08, 0x00, 0x13, 0x09,                                                 // 495
    0x00, 0x16, 0x08, 0x00, 0x17, 0x09, 0x00, 0x2b, 0x09, 0x00, 0xae, 0xff, 0x07, 0xb2, 0xff, // 510
    0x00, 0xb4, 0xff, 0x00, 0xb5, 0xff, 0x00, 0xc3, 0x01, 0x00, 0xc7, 0xff, 0xbf, 0xe7, 0x08, // 525
    0x00, 0xf0, 0x02, 0x00

    // posiblemente, los valores 0xff que hay aqui representados, se usen para detectas las instrucciones
    // invalidas
};
// end

/*
Special cases of immediate values are relative addresses. In previous versions
of the engine this values stores to hde32s.rel* fields. But now it stored to
hde32s.imm* as all others immediates. You can detect relative address by flag
F_RELATIVE, which setted with one of F_IMM* flags (see below).

Alignment of structure "hde64s" is 1 byte (no alignment). Be careful, check
settings of your compiler or use headers from this package.

Fields "hde64s.opcode" and "hde64s.len" will be always. Presence of other
fields you can get with following flags in field "hde64s.flags":

HDE64C guaranteed that it read from "const void *code" no more than 26 bytes,
if instruction is valid, than HDE64C read no more than "hde64s.len" bytes and
"hde64s.len" always no more than 15.
*/

#define F_MODRM 0x00000001        // ModR/M exists
#define F_SIB 0x00000002          // SIB exists
#define F_IMM8 0x00000004         // immediate value imm8 exists
#define F_IMM16 0x00000008        // immediate value imm16 exists
#define F_IMM32 0x00000010        // immediate value imm32 exists
#define F_IMM64 0x00000020        // immediate value imm64 exists
#define F_DISP8 0x00000040        // displacement disp8 exists
#define F_DISP16 0x00000080       // displacement disp16 exists
#define F_DISP32 0x00000100       // displacement disp32 exists
#define F_RELATIVE 0x00000200     // relative address rel8 exists
#define F_PREFIX_REPNZ 0x01000000 // repnz prefix exists
#define F_PREFIX_REPX 0x02000000  // rep(z) prefix exists
#define F_PREFIX_REP 0x03000000   // rep(z) or repnz prefix exists
#define F_PREFIX_66 0x04000000    // 0x66 prefix exists
#define F_PREFIX_67 0x08000000    // 0x67 prefix exists
#define F_PREFIX_LOCK 0x10000000  // lock prefix exists
#define F_PREFIX_SEG 0x20000000   // segment prefix exists
#define F_PREFIX_REX 0x40000000   // REX prefix exists
#define F_PREFIX_ANY 0x7f000000   // any prefix esists

/*
HDE64C analyses instruction for invalid, and do it thoroughly (more than half
of the size of engine is code and tables for detecting invalid instructions).
If HDE64C think, that instruction is invalid, it set flag "F_ERROR":
*/
#define F_ERROR 0x00001000 // invalid instruction

// Besides, HDE64C set flags to explain type of error:
#define F_ERROR_OPCODE 0x00002000  // invalid opcode
#define F_ERROR_LENGTH 0x00004000  // length of command more than 15
#define F_ERROR_LOCK 0x00008000    // prefix lock isn't allowed
#define F_ERROR_OPERAND 0x00010000 // operand isn't allowed
/*
On case of "F_ERROR_OPCODE" flag, under notion opcode is understood not only
"hde64s.opcode(2)" byte, but besides opcode's extension in ModR/M.reg, ModR/M
or prefix (when two-byte opcode). So, HDE64C detects commands like "c6 c8 00"
as invalid, because opcode "c6 /1" is invalid.

If HDE64C setted flag "F_ERROR_LENGTH", then field "hde64s.len" is 15, so
maximal value of "hde64s.len" is 15.

If engine detect instruction as invalid, it doesn't stop disassembling and
continue disassembling in general rules, but error flag (F_ERROR) and flag
of error's type (F_ERROR_*) will be setted.
*/

#define PREFIX_SEGMENT_CS 0x2e
#define PREFIX_SEGMENT_SS 0x36
#define PREFIX_SEGMENT_DS 0x3e
#define PREFIX_SEGMENT_ES 0x26
#define PREFIX_SEGMENT_FS 0x64
#define PREFIX_SEGMENT_GS 0x65
#define PREFIX_LOCK 0xf0
#define PREFIX_REPNZ 0xf2
#define PREFIX_REPX 0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#pragma pack(push, 1)

typedef struct
{
    uint8_t len;       // length of command
    uint8_t p_rep;     // rep/repz (0xf3) & repnz (0xf2) prefix
    uint8_t p_lock;    // lock prefix: 0xf0
    uint8_t p_seg;     // segment prefix: 0x26,0x2e,0x36,0x3e,0x64,0x65
    uint8_t p_66;      // operand-size override prefix: 0x66
    uint8_t p_67;      // address-size override prefix: 0x67
    uint8_t rex;       // REX prefix
    uint8_t rex_w;     //   REX.W
    uint8_t rex_r;     //   REX.R
    uint8_t rex_x;     //   REX.X
    uint8_t rex_b;     //   REX.B
    uint8_t opcode;    // opcode
    uint8_t opcode2;   // second opcode (if first opcode is 0x0f)
    uint8_t modrm;     // ModR/M byte
    uint8_t modrm_mod; //   ModR/M.mod
    uint8_t modrm_reg; //   ModR/M.reg
    uint8_t modrm_rm;  //   ModR/M.r/m
    uint8_t sib;       // SIB byte
    uint8_t sib_scale; //   SIB.scale
    uint8_t sib_index; //   SIB.index
    uint8_t sib_base;  //   SIB.base
    union
    {
        uint8_t imm8;   // immediate value imm8
        uint16_t imm16; // immediate value imm16
        uint32_t imm32; // immediate value imm32
        uint64_t imm64; // immediate value imm64
    } imm;
    union
    {
        uint8_t disp8;   // displacement disp8
        uint16_t disp16; // displacement disp16
        uint32_t disp32; // displacement disp32
    } disp;
    uint32_t flags; // flags
} hde64s;

#pragma pack(pop)

    #ifdef __cplusplus
    extern "C"
    {
    #endif

    /* __cdecl */
    unsigned int hde64_disasm(const void *code, hde64s *hs);

    #ifdef __cplusplus
    }
    #endif

#endif /* _HDE64_H_ */

// hde64.c
#pragma warning(push)
#pragma warning(disable : 4701)
#pragma warning(disable : 4706)
#pragma warning(disable : 26451)

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c = 0, *p = (uint8_t *)code, cflags, opcode, pref = 0;
    uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op64 = 0;

    // Avoid using memset to reduce the footprint.
    #ifndef _MSC_VER
        memset((LPBYTE)hs, 0, sizeof(hde64s));
    #else
        __stosb((LPBYTE)hs, 0, sizeof(hde64s));
    #endif

    // Aqui se analiza los prefijos
    // maximo 16 prefijos?
    for (x = 16; x; x--)
        switch (c = *p++)
        {
        case 0xf3:
            hs->p_rep = c;
            pref |= PRE_F3;
            break;
        case 0xf2:
            hs->p_rep = c;
            pref |= PRE_F2;
            break;
        case 0xf0:
            hs->p_lock = c;
            pref |= PRE_LOCK;
            break;
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
            hs->p_seg = c;
            pref |= PRE_SEG;
            break;
        case 0x66:
            hs->p_66 = c;
            pref |= PRE_66;
            break;
        case 0x67:
            hs->p_67 = c;
            pref |= PRE_67;
            break;
        default:
            goto pref_done; // si no se tiene prefijos, se sigue
        }
pref_done:

    /*
     * Si no hay prefijos, esto no hara nada
     */
    hs->flags = (uint32_t)pref << 23;

    // se indica que no tiene prefijos
    if (!pref)
        pref |= PRE_NONE;

    /*
     * se analiza el REX,
     * [C & 1111 0000(0xf0)] == 0100 0000(0x40)
     *
     * El prefijo REX tiene el formato 0100WRXB, donde:
     *  - W es el bit REX.W
     *  - R es el bit REX.R
     *  - X es el bit REX.X
     *  - B es el bit REX.B
     *
     * Estos campos permiten:
     *  - Acceder a registros de 64 bits.
     *  - Usar los 8 registros adicionales (R8-R15) introducidos en x86-64.
     *  - Realizar operaciones de 64 bits cuando es necesario.
     */
    if ((c & 0xf0) == 0x40)
    {
        hs->flags |= F_PREFIX_REX; // por ejemplo, si la instruccion
                                   // tiene un prefijo 0x48, esta instruccion usa REX
        if (
            (hs->rex_w = (c & 0xf) >> 3)
            /*
             * REX.W (bit 3 del byte REX):
             * Cuando está activado (1), indica una operación de 64 bits.
             * Cuando está desactivado (0), la operación es de 32 bits por defecto.
             */

            && (*p & 0xf8) == 0xb8)
            op64++;
        hs->rex_r = (c & 7) >> 2;
        /*
         * REX.R (bit 2 del byte REX):
         * Extiende el campo ModR/M reg.
         * Se usa para acceder a los registros R8-R15.
         */

        hs->rex_x = (c & 3) >> 1;
        /*
         * REX.X (bit 1 del byte REX):
         * Extiende el campo SIB index.
         * Permite usar los registros R8-R15 como índices en el direccionamiento SIB.
         */

        hs->rex_b = c & 1;
        /*
         * REX.B (bit 0 del byte REX):
         * Extiende el campo ModR/M r/m, el campo SIB base, o el campo opcode reg.
         * Permite usar los registros R8-R15 en estas posiciones.
         */

        if (((c = *p++) & 0xf0) == 0x40)
        {
            opcode = c;
            goto error_opcode;
        }
    }

    // se analiza el opcode o opcodes
    if ((hs->opcode = c) == 0x0f)
    {
        // si el opcode1 es 0x0f, se analiza el segundo opcode
        // https://stackoverflow.com/questions/6924912/finding-number-of-operands-in-an-instruction-from-opcodes?rq=1
        // https://sparksandflames.com/files/x86InstructionChart.html
        hs->opcode2 = c = *p++;
        ht += DELTA_OPCODES;
    }
    else if (c >= 0xa0 && c <= 0xa3)
    {
        // si el opcode es mayor o igual que 160 o es menor o igual que 163, se analiza el opcode
        // es decir, si el opcode es 0xa1 o 0xa2, se considerara que esta instruccion esta mal codificada
        // https://net.cs.uni-bonn.de/fileadmin/user_upload/plohmann/x86_opcode_structure_and_instruction_overview.pdf
        op64++;
        if (pref & PRE_67)   // si el prefijo 0x67 esta activado
            pref |= PRE_66;  // |= 0b0000 1000
        else                 // si el prefijo 0x67 no esta activado
            pref &= ~PRE_66; // &= 0b1111 0111 (complemento a 1 de PRE_66 y se almacena el prefijo despues del and?)
    }

    opcode = c;

    // un opcode 0x89, se divide entre 4 y se suma al resto del resultado de 0x89/4
    // es decir, ht[(0x89 / 0x04) == 0x22(34)] == 0xa5 + 1 == 0xa6(166)
    cflags = ht[ht[opcode / 4] +
                // se divide entre 4 y se accede, luego se suma al
                // resto del resultado el opcode/4
                (opcode % 4)];

    if (cflags == C_ERROR)
    {
    error_opcode:
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24)
            cflags++;
    }

    x = 0;
    if (cflags & C_GROUP)
    {
        uint16_t t;
        t = *(uint16_t *)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    // solo se analiza opcode2 si se tiene un prefijo REX:
    if (hs->opcode2)
    {
        ht = hde64_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    // si cflags tiene el bit 1 activo, la instruccion tiene Mod/RM
    if (cflags & C_MODRM)
    {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;                    // se obtiene el byte donde esta el mod rm
        hs->modrm_mod = m_mod = c >> 6;          // se desplaza 6 bits para obtener los 2bits de mod
        hs->modrm_rm = m_rm = c & 7;             // se deja solo los 3 primeros bits, para obtener el rm
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3; // elimina el mod con (C & 0b0011 1111), y deplaza 3 bits para obtener el reg

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf)
        {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3)
            {
                ht = hde64_table + DELTA_FPU_MODRM + t * 8;
                t = ht[m_reg] << m_rm;
            }
            else
            {
                ht = hde64_table + DELTA_FPU_REG;
                t = ht[t] << m_reg;
            }
            if (t & 0x80)
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
        }

        if (pref & PRE_LOCK)
        {
            if (m_mod == 3)
            {
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            }
            else
            {
                uint8_t *table_end, op = opcode;
                if (hs->opcode2)
                {
                    ht = hde64_table + DELTA_OP2_LOCK_OK;
                    table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
                }
                else
                {
                    ht = hde64_table + DELTA_OP_LOCK_OK;
                    table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
                    op &= -2;
                }
                for (; ht != table_end; ht++)
                    if (*ht++ == op)
                    {
                        if (!((*ht << m_reg) & 0x80))
                            goto no_lock_error;
                        else
                            break;
                    }
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            no_lock_error:;
            }
        }

        if (hs->opcode2)
        {
            switch (opcode)
            {
            case 0x20:
            case 0x22:
                m_mod = 3;
                if (m_reg > 4 || m_reg == 1)
                    goto error_operand;
                else
                    goto no_error_operand;
            case 0x21:
            case 0x23:
                m_mod = 3;
                if (m_reg == 4 || m_reg == 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            }
        }
        else
        {
            switch (opcode)
            {
            case 0x8c:
                if (m_reg > 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            case 0x8e:
                if (m_reg == 1 || m_reg > 5)
                    goto error_operand;
                else
                    goto no_error_operand;
            }
        }

        // si mod es 3 (0b11)
        if (m_mod == 3)
        {
            uint8_t *table_end;
            if (hs->opcode2)
            {
                ht = hde64_table + DELTA_OP2_ONLY_MEM;
                table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
            }
            else
            {
                ht = hde64_table + DELTA_OP_ONLY_MEM;
                table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
            }
            for (; ht != table_end; ht += 2)
                if (*ht++ == opcode)
                {
                    if (*ht++ & pref && !((*ht << m_reg) & 0x80))
                        goto error_operand;
                    else
                        break;
                }
            goto no_error_operand;
        }
        else if (hs->opcode2)
        {
            switch (opcode)
            {
            case 0x50:
            case 0xd7:
            case 0xf7:
                if (pref & (PRE_NONE | PRE_66))
                    goto error_operand;
                break;
            case 0xd6:
                if (pref & (PRE_F2 | PRE_F3))
                    goto error_operand;
                break;
            case 0xc5:
                goto error_operand;
            }
            goto no_error_operand;
        }
        else
            goto no_error_operand;

    error_operand:
        hs->flags |= F_ERROR | F_ERROR_OPERAND;
    no_error_operand:

        c = *p++;
        if (m_reg <= 1)
        {
            if (opcode == 0xf6)
                cflags |= C_IMM8;
            else if (opcode == 0xf7)
                cflags |= C_IMM_P66;
        }

        switch (m_mod)
        {
        case 0:
            if (pref & PRE_67)
            {
                if (m_rm == 6)
                    disp_size = 2;
            }
            else if (m_rm == 5)
                disp_size = 4;
            break;
        case 1:
            disp_size = 1;
            break;
        case 2:
            disp_size = 2;
            if (!(pref & PRE_67))
                disp_size <<= 1;
        }

        if (m_mod != 3 && m_rm == 4)
        {
            hs->flags |= F_SIB;
            p++;
            hs->sib = c;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                disp_size = 4;
        }

        p--;
        switch (disp_size)
        {
        case 1:
            hs->flags |= F_DISP8;
            hs->disp.disp8 = *p;
            break;
        case 2:
            hs->flags |= F_DISP16;
            hs->disp.disp16 = *(uint16_t *)p;
            break;
        case 4:
            hs->flags |= F_DISP32;
            hs->disp.disp32 = *(uint32_t *)p;
        }
        p += disp_size;
    }

    // si el bit 6 (0010 0000) esta activo, entonces es un error
    else if (pref & PRE_LOCK)
        hs->flags |= F_ERROR | F_ERROR_LOCK;

    if (cflags & C_IMM_P66)
    {
        if (cflags & C_REL32)
        {
            if (pref & PRE_66)
            {
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm.imm16 = *(uint16_t *)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (op64)
        {
            hs->flags |= F_IMM64;
            hs->imm.imm64 = *(uint64_t *)p;
            p += 8;
        }
        else if (!(pref & PRE_66))
        {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        }
        else
            goto imm16_ok;
    }

    if (cflags & C_IMM16)
    {
    imm16_ok:
        hs->flags |= F_IMM16;
        hs->imm.imm16 = *(uint16_t *)p;
        p += 2;
    }
    if (cflags & C_IMM8)
    {
        hs->flags |= F_IMM8;
        hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32)
    {
    rel32_ok:
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t *)p;
        p += 4;
    }
    else if (cflags & C_REL8)
    {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

disasm_done:

    // se obtiene el tamaño de la instruccion, una instruccion no sera mayor a 15 bytes segun esto:
    if ((hs->len = (uint8_t)(p - (uint8_t *)code)) > 15)
    {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }

    // si se usan prefijo 0x67, la cpu ignorara 16bits de la direccion de 32bits
    // que recibio, y lo reducira a 16bits
    if (hs->p_67) hs->len+=2;
    return (unsigned int)hs->len;
}
#pragma warning(pop)