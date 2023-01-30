#ifndef C
#define C(...)
#endif

#ifndef IMM
#define IMM(...)
#endif

#ifndef R
#define R(...)
#endif

#ifndef R1
#define R1(...)
#endif

#ifndef N
#define N(...)
#endif

#ifndef M
#define M(...)
#endif

#ifndef E
#define E(...)
#endif

#ifndef USE
#define USE(...)
#endif

C(NOOPW)
C(HLT)
E()

C(CMP32mi8)
C(CMP64mi8)
C(CMP8mi)
C(MOV32mi)
C(MOV8mi)
C(TEST32mi)
C(MOV64mi32)
N(6) M(0) IMM(5) E()

C(ADD64rm)
C(XCHG32rm)
C(XOR64rm)
C(SUB64rm)
N(7) R(0) M(2) E()

C(CMP64rm)
C(MOV32rm)
C(MOV64rm)
C(MOV8rm)
C(LEA64r)
C(LEA64_32r)
C(MOVSX64rm32)
N(6) R(0) M(1) E()

C(CMP64mr)
C(MOV32mr)
C(MOV64mr)
C(MOV8mr)
N(6) M(0) R(5) E()

C(MOV64ri32)
C(MOV32ri)
N(2) R(0) IMM(1)  E()

C(XOR8ri)
C(AND32ri)
C(SUB64ri8)
N(3) R(0) IMM(2)  E()

C(MOV32rr)
C(MOV64rr)
C(TEST32rr)
N(2) R(0) R1(1) E()

C(XOR32rr)
C(SUB64rr)
N(3) R(0) R1(2) E()

C(CMOV64rr)
N(4) R(0) R1(2) IMM(3) E()

C(SYSCALL)
N(0) E()

C(CMP64i32)
C(CMP32i32)
N(1) IMM(0) USE(RAX) E()

#ifdef C
#undef C
#endif

#ifdef IMM
#undef IMM
#endif

#ifdef R
#undef R
#endif

#ifdef R1
#undef R1
#endif

#ifdef N
#undef N
#endif

#ifdef M
#undef M
#endif

#ifdef E
#undef E
#endif

#ifdef USE
#undef USE
#endif

