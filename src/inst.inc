C(NOOPW)
C(HLT)
R0(-1, -1, -1, -1);

C(CMP32mi8)
C(CMP64mi8)
C(CMP8mi)
C(MOV32mi)
C(MOV8mi)
C(TEST32mi)
C(MOV64mi32)
R(6, 0, 5, -1, -1)

C(ADD64rm)
C(XCHG32rm)
C(XOR64rm)
C(SUB64rm)
R(7, 2, -1, 0, -1)

C(CMP64rm)
C(MOV32rm)
C(MOV64rm)
C(MOV8rm)
C(LEA64r)
C(LEA64_32r)
C(MOVSX64rm32)
R(6, 1, -1, 0, -1)

C(CMP64mr)
C(MOV32mr)
C(MOV64mr)
C(MOV8mr)
R(6, 0, -1, 5, -1)

C(MOV64ri32)
C(MOV32ri)
R(2, -1, 1, 0, -1)

C(XOR8ri)
C(AND32ri)
C(SUB64ri8)
R(3, -1, 2, 0, -1)

C(MOV32rr)
C(TEST32rr)
R(2, -1, -1, 0, 1)

C(XOR32rr)
C(SUB64rr)
R(3, -1, -1, 0, 2)

C(CMOV64rr)
R(4, -1, 3, 0, 2)

C(SYSCALL)
R(0, -1, -1, -1, -1)
