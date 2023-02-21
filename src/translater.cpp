#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compression.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/ConvertUTF.h"
#include "X86BaseInfo.h"

#include <algorithm>
#include <cstddef>
#include <ios>
#include <iostream>
#include <memory>
#include <vector>
#include <fstream>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <sstream>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "X86MCTargetDesc.h"
#include "elf.h"
#include "runtime.h"
#include "translater.h"
#include "utils.h"
#include "elf_file.h"

using namespace llvm;

namespace translater {

class raw_u8_ostream : public raw_ostream {
  std::vector<uint8_t> &OS;
  void write_impl(const char *Ptr, size_t Size) override {
    OS.insert(OS.end(), (uint8_t*)Ptr, (uint8_t*)Ptr+Size);
  }
  uint64_t current_pos() const override { return OS.size(); }
public:
  explicit raw_u8_ostream(std::vector<uint8_t> &O) : OS(O) {
    SetUnbuffered();
  }
};

static bool verbose;
static bool summary;
static bool debug;
static bool debugOnlyBefore;
static bool forAll;
static int forSingleInstr = -1;

struct AsmDism {
  MCTargetOptions MO;
  const Target *T;
  std::unique_ptr<MCSubtargetInfo> STI;
  std::unique_ptr<MCRegisterInfo> MRI;
  std::unique_ptr<MCAsmInfo> MAI;
  std::unique_ptr<MCInstrInfo> MII;
  SourceMgr SM;
  std::unique_ptr<MCContext> C;
  std::unique_ptr<MCInstrInfo> MCII;
  SmallString<128> Sb;
  raw_svector_ostream Ss;
  MCInstPrinter *IP;

  std::unique_ptr<MCStreamer> S;
  std::unique_ptr<MCCodeEmitter> E;
  std::unique_ptr<MCDisassembler> D;

  AsmDism(): Ss(Sb) {
    LLVMInitializeX86TargetInfo();
    LLVMInitializeX86TargetMC();
    LLVMInitializeX86AsmParser();
    LLVMInitializeX86Disassembler();

    std::string tname = sys::getDefaultTargetTriple();
    Triple triple(Triple::normalize(tname));
    std::string err;
    T = TargetRegistry::lookupTarget(tname, err);
    STI.reset(T->createMCSubtargetInfo(tname, "", ""));
    MRI.reset(T->createMCRegInfo(tname));
    MAI.reset(T->createMCAsmInfo(*MRI, tname, MO));
    MII.reset(T->createMCInstrInfo());
    C.reset(new MCContext(triple, MAI.get(), MRI.get(), STI.get(), &SM, &MO));
    MCII.reset(T->createMCInstrInfo());
    IP = T->createMCInstPrinter(triple, 0, *MAI, *MCII, *MRI);

    S.reset(T->createAsmStreamer(
        *C, 
        std::make_unique<formatted_raw_ostream>(Ss),
        /*asmverbose*/false, /*useDwarfDirectory*/false, 
        IP, 
        std::unique_ptr<MCCodeEmitter>(T->createMCCodeEmitter(*MCII, *C)),
        std::unique_ptr<MCAsmBackend>(T->createMCAsmBackend(*STI, *MRI, MO)),
        /*showinst*/true
    ));
    E.reset(T->createMCCodeEmitter(*MCII, *C));
    D.reset(T->createMCDisassembler(*STI, *C));
  }

  static constexpr uint16_t X86_BAD = X86::INSTRUCTION_LIST_END+1;

  std::vector<unsigned> gpRegs = {
    // keep order
    X86::RIP, X86::RSP, X86::RBP, X86::RAX,
    X86::RCX, X86::RDX, X86::RBX, X86::RSI, X86::RDI,
    X86::R8, X86::R9, X86::R10, X86::R11,
    X86::R12, X86::R13, X86::R14, X86::R15,
  };

  SmallVector<MCFixup, 4> fixups;

  void encode(const MCInst &inst, raw_u8_ostream &vcode) {
    E->encodeInstruction(inst, vcode, fixups, *STI);
  }

  void decode(MCInst &inst, uint64_t &size, Slice buf) {
    auto r = D->getInstruction(inst, size, {buf.data(), buf.size()}, 0, nulls());
    if (r != MCDisassembler::DecodeStatus::Success) {
      inst.setOpcode(X86_BAD);
      size = 1;
    }
  }

  int gpFreeStart = gpRegIdx(X86::RCX);
  int gpRspIdx = gpRegIdx(X86::RSP);

  int gpRegIdx(unsigned reg) {
    auto first = std::find(gpRegs.begin(), gpRegs.end(), reg);
    if (first == gpRegs.end()) {
      return -1;
    }
    return first - gpRegs.begin();
  }

  int gpFindFreeReg(unsigned mask) {
    for (int i = gpFreeStart; i < gpRegs.size(); i++) {
      if (!(mask & (1<<i))) {
        return i;
      }
    }
    return -1;
  }

  unsigned superReg(unsigned reg) {
    auto super = reg;
    for (MCSuperRegIterator i(reg, MRI.get()); i.isValid(); ++i) {
      super = *i;
    }
    return super;
  }

  std::string instHexStr(Slice buf) {
    std::vector<std::string> v;
    for (int i = 0; i < buf.size(); i++) {
      v.push_back(fmtSprintf("%.2X", buf[i]));
    }
    return "[" + stringsJoin(v, " ") + "]";
  }

  void dumpInstBuf(const std::string &prefix, Slice buf, uint64_t va = 0) {
    MCInst inst;
    uint64_t size;
    for (int addr = 0; addr < buf.size(); ) {
      decode(inst, size, buf.slice(addr));
      auto s = fmtSprintf("%lx", addr+va);
      auto s2 = instAllStr(inst, buf.slice(addr, size));
      fmtPrintf("%s %s %s\n", prefix.c_str(), s.c_str(), s2.c_str());
      addr += size;
    }
  };

  std::string instDisStr(const MCInst &inst) {
    S->emitInstruction(inst, *STI);
    auto r = Sb.slice(1, Sb.size()-1).str();
    for (int i = 0; i < r.size(); i++) {
      if (r[i] == '\t') {
        r[i] = ' ';
      }
    }
    Sb.clear();
    return r;
  }

  std::string instDumpStr(const MCInst &inst) {
    auto n = inst.getNumOperands();
    std::vector<std::string> v;
    for (int i = 0; i < n; i++) {
      auto op = inst.getOperand(i);
      if (op.isReg()) {
        v.push_back(fmtSprintf("r%d", op.getReg()));
      } else if (op.isImm()) {
        v.push_back(fmtSprintf("i%d", op.getImm()));
      }
    }
    return fmtSprintf("%s(%d),n=%d[%s]",
                      IP->getOpcodeName(inst.getOpcode()).str().c_str(),
                      inst.getOpcode(), n, stringsJoin(v, ",").c_str());
  }

  std::string instAllStr(const MCInst &inst, Slice buf = {}) {
    std::string s;
    if (inst.getOpcode() == X86_BAD) {
      s += "bad";
    } else {
      s += instDisStr(inst) + " " + instDumpStr(inst);
    }
    if (buf.size()) {
      s += " " + instHexStr(buf);
    }
    return s;
  }

  #define panicUnsupportedInstr(inst) {\
    auto s0 = instAllStr(inst); \
    fprintf(stderr, "%s:%d: unsupported instr %s\n", __FILE__, __LINE__, s0.c_str()); \
    exit(-1); \
    __builtin_unreachable(); \
  }

  struct InstInfo {
    bool ok;
    bool hasRspR;
    bool hasRspM;
    int mIdx; // [BaseReg, ScaleAmt, IndexReg, Disp, Segment]
    int immIdx;
    int regIdx;
    int regIdx1;
    int useReg;
  };

  InstInfo getInstInfo(const MCInst &inst, bool panic = true) {
    auto n = inst.getNumOperands();
    InstInfo r = {
      .mIdx = -1,
      .immIdx = -1,
      .regIdx = -1,
      .regIdx1 = -1,
      .useReg = -1,
    };

    #define C(op) case X86::op: 
    #define M(v) r.mIdx = v;
    #define IMM(v) r.immIdx = v;
    #define R(v) r.regIdx = v;
    #define R1(v) r.regIdx1 = v;
    #define N(v) if (inst.getNumOperands() != v) goto fail;
    #define E() goto ok;
    #define USE(v) r.useReg = X86::v;

    switch (inst.getOpcode()) {
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
      C(CMP32ri8)
      C(MOV8ri)
      N(2) R(0) IMM(1) E()

      C(XOR8ri)
      C(AND32ri)
      C(SUB64ri8)
      N(3) R(0) IMM(2) E()

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
    }

    fail:
    if (panic) { 
      panicUnsupportedInstr(inst);
    }
    return r;

    ok:
    auto isRsp = [&](int i) -> bool {
      auto r = inst.getOperand(i).getReg();
      return r == X86::ESP || r == X86::RSP;
    };

    if (r.regIdx != -1 && isRsp(r.regIdx) || r.regIdx1 != -1 && isRsp(r.regIdx1)) {
      r.hasRspR = true;
    }
    if (r.mIdx != -1 && (isRsp(r.mIdx) || isRsp(r.mIdx+2) || isRsp(r.mIdx+4))) {
      r.hasRspM = true;
    }

    r.ok = true;
    return r;

    #undef E
    #undef N
    #undef R1
    #undef R
    #undef IMM
    #undef M
    #undef C
  };

  unsigned instUsedRegMask(const MCInst &inst) {
    unsigned mask = 0;
    auto info = getInstInfo(inst);

    auto addR = [&](unsigned r) {
      unsigned sr = superReg(r);
      int i = gpRegIdx(sr);
      if (i == -1) {
        panicUnsupportedInstr(inst);
      }
      mask |= 1<<i;
    };

    auto add = [&](int oi) {
      auto o = inst.getOperand(oi);
      if (!o.isReg()) {
        panicUnsupportedInstr(inst);
      }
      unsigned r = o.getReg();
      if (r == 0) {
        return;
      }
      addR(r);
    };

    if (info.useReg != -1) {
      addR(info.useReg);
    }

    if (info.mIdx != -1) {
      add(info.mIdx + 0);
      add(info.mIdx + 2);
    }

    if (info.regIdx != -1) {
      add(info.regIdx);
    }

    if (info.regIdx1 != -1) {
      add(info.regIdx1);
    }

    return mask;
  }
};

class Translater {
public:
  AsmDism &ad;
  const ElfFile &file;
  Result &res;

  Elf64_Ehdr *eh;
  Elf64_Phdr *phX;
  Slice instBuf;

  struct Section {
    uint64_t start, end;
    const std::string &name;
    int startIdx, endIdx;
  };

  std::vector<Section> allSecs;
  std::string plt = ".plt";

  enum {
    NormalOp,
    TlsStackCanary,
    TlsOp,
    Syscall,
    OpTypeNr,
  };

  const char *OpTypeStr(int op) {
    static const char *a[] = {
      "normal_op",
      "tls_stack_canary",
      "tls_op",
      "syscall",
    };
    return a[op];
  }

  enum {
    NoJmp,
    IgnoreJmp,
    DirectCall,
    PushJmp,
    PushJmp2,
    CombineJmp,
    JmpFail,
    JmpTypeNr,
  };

  const char *JmpTypeStr(int op) {
    static const char *a[] = {
      "no_jmp",
      "ignore_jmp",
      "direct_call",
      "push_jmp",
      "push_jmp2",
      "combine_jmp",
      "jmp_fail",
    };
    return a[op];
  };

  struct OpcodeAndSize {
    uint16_t op;
    unsigned size:5;
    unsigned used:1;
    unsigned type:3;
    unsigned jmpto:1;
    unsigned bad:1;
  } __attribute__((packed, aligned(4)));
  static_assert(sizeof(OpcodeAndSize) == 4, "");

  std::vector<OpcodeAndSize> allOpcode;

  struct AddrAndIdx {
    uint64_t addr;
    int idx;
  };

  struct AddrRange {
    AddrAndIdx i;
    int n;
    uint64_t size;
  };

  struct JmpRes {
    int type;
    AddrRange r0;
    AddrRange r1;
  };

  struct JmpFailLog {
    uint64_t addr;
    const char *tag;
  };

  uint64_t vaddr(uint64_t a) { 
    return a + phX->p_vaddr; 
  };

  struct DecodeRes {
    MCInst inst;
    Slice buf;
    OpcodeAndSize op;
    uint64_t size;
  };

  DecodeRes decodeInst2(AddrAndIdx i) {
    DecodeRes r;
    r.op = allOpcode[i.idx];
    r.buf = {instBuf.data() + i.addr, (size_t)r.op.size};
    ad.decode(r.inst, r.size, r.buf);
    return r;
  }

  bool forInstAround(AddrAndIdx ai, int maxDist, std::function<int(AddrAndIdx i)> fn) {
    auto addr = ai.addr;
    for (int i = ai.idx; i > 0 && ai.addr-addr < maxDist; i--) {
      if (i != ai.idx) {
        int r = fn({.addr = addr, .idx = i});
        if (r == 0) 
          return true;
        if (r == 1)
          break;
      }
      addr -= allOpcode[i-1].size;
    }
    addr = ai.addr;
    for (int i = ai.idx; i < allOpcode.size() && addr-ai.addr < maxDist; i++) {
      if (i != ai.idx) {
        int r = fn({.addr = addr, .idx = i});
        if (r == 0) 
          return true;
        if (r == 1)
          break;
      }
      addr += allOpcode[i].size;
    }
    return false;
  }

  unsigned instType(const MCInst &inst) {
    auto opcode = inst.getOpcode();

    if (opcode == ad.X86_BAD) {
      return NormalOp;
    } 
    if (opcode == X86::SYSCALL) {
      return Syscall;
    }

    auto &idesc = ad.MII->get(opcode);
    for (int i = 0; i < idesc.NumOperands; i++) {
      auto od = inst.getOperand(i);
      auto opinfo = idesc.OpInfo[i];
      if (opinfo.RegClass == X86::SEGMENT_REGRegClassID) {
        if (od.getReg() == X86::FS) {
          unsigned type = TlsOp;
          if (i > 0) {
            auto preOp = inst.getOperand(i-1);
            if (preOp.isImm() && preOp.getImm() == 40) {
              type = TlsStackCanary;
            }
          }
          return type;
        }
      }
    }

    return NormalOp;
  }

  OpcodeAndSize decodeInst(uint64_t addr) {
    MCInst inst;
    uint64_t size;
    ad.decode(inst, size, instBuf.slice(addr));

    unsigned type = instType(inst);
    unsigned used = type != NormalOp;

    return {
      .op = (uint16_t)inst.getOpcode(),
      .size = (uint8_t)size,
      .used = used,
      .type = type,
    };
  };

  std::vector<AddrAndIdx> fsInsts;
  std::vector<AddrAndIdx> badRanges;
  const int BadMaxDiff = 100;

  std::hash<std::string_view> strHash;

  size_t instHash(AddrAndIdx i) {
    return strHash({(char *)instBuf.data()+i.addr, allOpcode[i.idx].size});
  };

  struct OccurPair {
    AddrAndIdx i;
    int n;
    uint64_t addr;
  };
  std::vector<OccurPair> instOccur;
  std::unordered_map<size_t, int> instOccurMap;

  void printInst(AddrAndIdx ai, JmpRes jmp) {
    auto r = decodeInst2(ai);
    std::string tag = JmpTypeStr(jmp.type);

    if (jmp.type == PushJmp) {
      tag += fmtSprintf(":%d", std::abs((int64_t)(jmp.r0.i.addr-ai.addr)));
    } else if (jmp.type == CombineJmp) {
      tag += fmtSprintf(":%d,%d", jmp.r0.size, jmp.r0.n);
    }

    if (r.op.jmpto) {
      tag += ":jmpto";
    }

    std::stringstream ss;
    std::string sep = " ";
    ss << fmtSprintf("%lx", vaddr(ai.addr)) <<
      sep << ad.instAllStr(r.inst, r.buf) <<
      sep << OpTypeStr(r.op.type) <<
      sep << tag << 
      "\n";
    fmtPrintf("%s", ss.str().c_str());
  };

  void debugInstOccur() {
    std::vector<int> sortIdx;
    for (int i = 0; i < instOccur.size(); i++) {
      sortIdx.push_back(i);
    }
    std::sort(sortIdx.begin(), sortIdx.end(), [&](auto &l, auto &r) {
      return instOccur[l].n > instOccur[r].n;
    });

    for (int i = 0; i < sortIdx.size(); i++) {
      auto p = instOccur[sortIdx[i]];
      auto r = decodeInst2(p.i);
      auto s = ad.instAllStr(r.inst, r.buf);
      fmtPrintf("instoccur %d %s %d\n", i, s.c_str(), p.n);
    }
  }

  class StubCE {
  public:
    AsmDism &ad;
    std::vector<uint8_t> code;
    raw_u8_ostream vcode;
    std::vector<Reloc> relocs;
    std::vector<uint8_t> patchCode;
    std::vector<Patch> patches;

    StubCE(AsmDism &ad): ad(ad), vcode(code) {
    }

    void emit(const MCInst &inst) {
      ad.encode(inst, vcode);
    }

    void patch8(uint8_t v) {
      patchCode.push_back(v);
    }

    void patchn(uint8_t v, int n) {
      while (n > 0) {
        patchCode.push_back(v);
        n--;
      }
    }

    void patchStart(uint64_t addr) {
      patches.push_back({(uint32_t)addr, (uint32_t)patchCode.size(), 0});
    }

    uint64_t patchAddr() {
      auto p = patches.end()-1;
      return p->addr + patchCode.size() - p->off;
    }

    void patchEnd() {
      auto p = patches.end()-1;
      p->size = patchCode.size() - p->off;
    }

    Slice codeSlice(size_t start) {
      return {(uint8_t *)code.data()+start, code.size()-start};
    }
  };

  StubCE E;

  int rspFix = 0;
  int totOpType[OpTypeNr] = {};
  int totJmpType[JmpTypeNr] = {};

  void adjustRIPImm4(const MCInst &inst, const AsmDism::InstInfo &info, uint64_t addr) {
    bool isJmp = inst.getOpcode() == X86::JCC_4 || inst.getOpcode() == X86::JMP_4;
    if (
      (inst.getOpcode() == X86::JCC_4 || inst.getOpcode() == X86::JMP_4) ||
      (info.mIdx != -1 && inst.getOperand(info.mIdx).getReg() == X86::RIP)
    ) {
      // v = v + text - stub (Sub)
      // v = v + addr-stubAddr - (stubStart-loadStart)
      *(int32_t *)&E.code[E.code.size()-4] += int(addr) - int(E.code.size());
      E.relocs.push_back({(uint32_t)E.code.size()-4, (unsigned)SlotType::Stub, (unsigned)RelType::Sub});
    }
  };

  void emitAndFix(const MCInst &inst, uint64_t addr) {
    auto info = ad.getInstInfo(inst);

    if (info.hasRspM && rspFix) {
      E.emit(MCInstBuilder(X86::LEA64r)
        .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(-rspFix).addReg(0));
    }

    E.emit(inst);
    adjustRIPImm4(inst, info, addr);

    if (info.hasRspM && rspFix) {
      E.emit(MCInstBuilder(X86::LEA64r)
        .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(rspFix).addReg(0));
    }
  };

  #define instAllStr ad.instAllStr

  // text jmp to stub (Add)
  // v = v + stub - text
  // v = v + (stubStart+stubAddr) - (loadStart+addr)
  // v = v + stubAddr-addr + (stubStart-loadStart)

  // stub jmp to text (Sub)
  // v = v + text - stub
  // v = v + (loadAddr+addr) - (stubStart+stubAddr)
  // v = v + addr-stubAddr - (stubStart-loadStart)

  void emitOldTlsInst(AddrAndIdx i) {
    auto r = decodeInst2(i);
    auto inst1 = r.inst;
    auto size1 = r.size;

    /*
      push %tmp // save tmp
      [optional] lea 8(%rsp), %rsp // save rsp
      lea inst1.mem, %tmp // get orig value
      [optional] lea -8(%rsp), %rsp // recovery rsp
      push %rax; call gettls; lea (%rax,%tmp), %tmp; pop %rax // add fs
      inst1.op inst1.reg, (%tmp) // modified instr
      pop %tmp // recovery tmp
    */
    auto info = ad.getInstInfo(inst1);
    if (info.mIdx == -1) {
      panicUnsupportedInstr(inst1);
    }
    auto used = ad.instUsedRegMask(inst1);
    int ti = ad.gpFindFreeReg(used);
    if (ti == -1) {
      panicUnsupportedInstr(inst1);
    }
    auto tmpReg = ad.gpRegs[ti];

    E.emit(MCInstBuilder(X86::PUSH64r).addReg(tmpReg));
    rspFix += 8;

    MCInst lea;
    lea.setOpcode(X86::LEA64r);
    lea.addOperand(MCOperand::createReg(tmpReg));
    for (int i = 0; i < 5; i++) {
      lea.addOperand(inst1.getOperand(info.mIdx+i));
    }
    lea.getOperand(5).setReg(0);
    emitAndFix(lea, i.addr+size1);

    rspFix -= 8;
    E.emit(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX));

    E.emit(MCInstBuilder(X86::CALL64m)
      .addReg(0).addImm(1).addReg(0).addImm(8).addReg(X86::GS)); // tcb.gettls

    E.emit(MCInstBuilder(X86::LEA64r)
      .addReg(tmpReg).addReg(X86::RAX).addImm(1).addReg(tmpReg).addImm(0).addReg(0));
    E.emit(MCInstBuilder(X86::POP64r).addReg(X86::RAX));

    MCInst inst2 = inst1;
    inst2.getOperand(info.mIdx).setReg(tmpReg);
    inst2.getOperand(info.mIdx+1).setImm(1);
    inst2.getOperand(info.mIdx+2).setReg(0);
    inst2.getOperand(info.mIdx+3).setImm(0);
    inst2.getOperand(info.mIdx+4).setReg(0);
    E.emit(inst2);

    E.emit(MCInstBuilder(X86::POP64r).addReg(tmpReg));
  };

  void emitOldInst(AddrAndIdx i) {
    auto op = allOpcode[i.idx];
    if (op.type == TlsOp) {
      emitOldTlsInst(i);
    } else if (op.type == Syscall) {
      E.emit(MCInstBuilder(X86::CALL64m)
        .addReg(0).addImm(1).addReg(0).addImm(0).addReg(X86::GS)); // tcb.syscall
    } else {
      auto r = decodeInst2(i);
      emitAndFix(r.inst, i.addr+r.size);
    }
  };

  #undef instAllStr

  void emitOldInsts(AddrRange r) {
    auto addr = r.i.addr;
    for (auto i = r.i.idx; i < r.i.idx+r.n; i++) {
      emitOldInst({.addr = addr, .idx = i});
      addr += allOpcode[i].size;
    }
  };

  void emitJmpBack(AddrRange r) {
    E.emit(MCInstBuilder(X86::JMP_4).addImm(128));
    // v = text - stub (Sub)
    // v = addr-stubAddr - (stubStart-loadStart)
    auto addr = r.i.addr+r.size;
    *(int32_t *)&E.code[E.code.size()-4] = int(addr) - int(E.code.size());
    E.relocs.push_back({(uint32_t)E.code.size()-4, (unsigned)SlotType::Stub, (unsigned)RelType::Sub});
  };

  void emitDirectJmpStub(AddrRange r0) {
    emitOldInsts(r0);
    emitJmpBack(r0);
  };

  void emitDirectCallStub(AddrRange r0) {
    rspFix += 8;
    E.emit(MCInstBuilder(X86::ENDBR64));
    emitOldInsts(r0);
    E.emit(MCInstBuilder(X86::RET64));
    rspFix -= 8;
  };

  void emitPushJmpStub(AddrRange r0, AddrRange r1, bool pushF) {
    // r0: push rsp; jmp 
    // r1: [pushq]; jmp
    /*
      push %rax; pushfq // save rax,eflags
      lea 24(%rsp),%rax; cmp 16(%rsp),%rax // check push_val == %rsp
      jne 1f
    */
    E.emit(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX));
    E.emit(MCInstBuilder(X86::PUSHF64));
    E.emit(MCInstBuilder(X86::LEA64r)
      .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(24).addReg(0));
    E.emit(MCInstBuilder(X86::CMP64rm)
      .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(16).addReg(0));
    E.emit(MCInstBuilder(X86::JCC_1).addImm(0).addImm(5)); // 4=je 5=jne
    auto jmp1Off = E.code.size();

    auto recovery = [&](bool addRsp) {
      /* 
        popfd; pop %rax;
        [optional] lea 8(%rsp),%rsp 
      */
      E.emit(MCInstBuilder(X86::POPF64));
      E.emit(MCInstBuilder(X86::POP64r).addReg(X86::RAX));
      if (addRsp) {
        E.emit(MCInstBuilder(X86::LEA64r)
          .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(8).addReg(0));
      }
    };

    /*
      recovery
      normal_op
      jmp back0
    */
    recovery(true);
    emitOldInsts(r0);
    emitJmpBack(r0);

    /*
    1:
      recovery
      tls_op
      jmp back1
    */
    E.code[jmp1Off-1] = E.code.size() - jmp1Off;
    recovery(pushF);
    emitOldInsts(r1);
    emitJmpBack(r1);
  };

  void patch32Reloc(uint64_t stubAddr) {
    auto p = E.patchCode.size();
    E.patchCode.resize(p+4);
    // v = stub - text (Add)
    // v = stubAddr-addr + (stubStart-loadStart)
    *(int32_t *)&E.patchCode[p] = int(stubAddr) - int(E.patchAddr());
    E.relocs.push_back({(uint32_t)E.patchAddr()-4, (unsigned)SlotType::Patch, (unsigned)RelType::Add});
  };

  void patchLongJmp(AddrRange r0, uint64_t stubAddr, unsigned op = 0) {
    E.patchStart(r0.i.addr);
    int n = r0.size;
    if (op) {
      E.patch8(op);
      n--;
    }
    E.patchn(0xf2, n-5); // repne call
    E.patch8(0xe9);
    patch32Reloc(stubAddr);
    E.patchEnd();
  };

  void patchShortJmp(AddrRange r0, AddrRange r1, int off1 = 0, unsigned op = 0) {
    E.patchStart(r0.i.addr);
    int n = r0.size;
    if (op) {
      E.patch8(op);
      n--;
    }
    E.patchn(0xf2, n-2); // repne jmp
    E.patch8(0xeb);
    E.patch8(int(r1.i.addr + off1) - int(E.patchAddr() + 1));
    E.patchEnd();
  };

  void patchPushRspJmp(AddrRange r0, uint64_t stubAddr) {
    patchLongJmp(r0, stubAddr, 0x54); // push %rsp
  };

  void patchPushFJmp(AddrRange r0, AddrRange r1) {
    patchShortJmp(r0, r1, 1, 0x9c); // pushf; skip push %rsp
  };

  void patchCall(AddrRange r0, int stubAddr) {
    E.patchStart(r0.i.addr);
    E.patchn(0xf2, r0.size-5); // repne call
    E.patch8(0xe8);
    patch32Reloc(stubAddr);
    E.patchEnd();
  };

  AddrRange singleAddrRange(AddrAndIdx i) {
    AddrRange r;
    r.i = i;
    r.n = 1;
    r.size = allOpcode[r.i.idx].size;
    return r;
  };

  bool canReplaceInst(const MCInst &inst) {
    auto op = inst.getOpcode();
    if (op == X86::JCC_1 || op == X86::JMP_1) {
      return false;
    }
    auto info = ad.getInstInfo(inst, false);
    return info.ok && !info.hasRspR;
  };

  bool canReplaceIdx(AddrAndIdx i) {
    return canReplaceInst(decodeInst2(i).inst);
  };

  void markInstRangeUsed(AddrRange r) {
    for (int i = r.i.idx; i < r.i.idx+r.n; i++) {
      allOpcode[i].used = 1;
    }
  };

  void logJmpFail(uint64_t addr, const char *tag) {
    if (debug) {
      fmtPrintf("jmpfailat addr %lx %s\n", vaddr(addr), tag);
    }
  };

  JmpRes checkPushJmp(AddrAndIdx i, int minSize, int type) {
    auto op = allOpcode[i.idx];

    if (op.size < minSize) {
      return {.type = JmpFail};
    }

    AddrAndIdx j;

    if (forInstAround(i, 127, [&](AddrAndIdx i) -> int {
      auto op = allOpcode[i.idx];
      if (canReplaceIdx(i) && !op.used && op.size >= 6) {
        j = i;
        return 0;
      }
      return -1;
    })) {
      return {
        .type = type,
        .r0 = singleAddrRange(j),
        .r1 = singleAddrRange(i),
      };
    }

    return {.type = JmpFail};
  };

  JmpRes checkCombineJmp(AddrAndIdx i0) {
    JmpRes res = {.type = JmpFail};

    uint64_t size = 0;
    auto addr = i0.addr;
    for (int i = i0.idx; i > 0; i--) {
      auto &op = allOpcode[i];
      if (!canReplaceIdx({addr, i})) {
        logJmpFail(addr, "replace");
        break;
      }
      if (op.used && i != i0.idx) {
        logJmpFail(addr, "used");
        break;
      }
      size += op.size;
      if (size >= 5) {
        return {
          .type = CombineJmp,
          .r0 = {
            .i = {
              .addr = addr,
              .idx = i,
            },
            .n = i0.idx - i + 1,
            .size = size,
          },
        };
      }
      if (op.jmpto) {
        logJmpFail(addr, "jmpto");
        break;
      }
      addr -= allOpcode[i-1].size;
    }

    size = 0;
    addr = i0.addr;
    for (int i = i0.idx; i < allOpcode.size(); i++) {
      auto &op = allOpcode[i];
      if (!canReplaceIdx({addr, i})) {
        logJmpFail(addr, "replace");
        break;
      }
      if (op.used && i != i0.idx) {
        logJmpFail(addr, "used");
        break;
      }
      if (op.jmpto && i != i0.idx) {
        logJmpFail(addr, "jmpto");
        break;
      }
      size += op.size;
      addr += op.size;
      if (size >= 5) {
        return {
          .type = CombineJmp,
          .r0 = {
            .i = i0,
            .n = i - i0.idx + 1,
            .size = size,
          },
        };
      }
    }

    return res;
  };

  JmpRes doReplace(AddrAndIdx i) {
    auto op = allOpcode[i.idx];

    if (op.type == NormalOp) {
      return {.type = NoJmp};
    }

    if (op.bad) {
      return {.type = IgnoreJmp};
    }

    if (!canReplaceIdx(i)) {
      return {.type = JmpFail};
    }

    if (op.size >= 5) {
      return {
        .type = DirectCall,
        .r0 = singleAddrRange(i),
      };
    }

    JmpRes res;

    res = checkCombineJmp(i);
    if (res.type != JmpFail) {
      return res;
    }

    res = checkPushJmp(i, 3, PushJmp);
    if (res.type != JmpFail) {
      return res;
    }

    res = checkPushJmp(i, 2, PushJmp2);
    if (res.type != JmpFail) {
      return res;
    }

    return {.type = JmpFail};
  };

  std::string fmtReloc(Reloc r, int i) {
    uint64_t vaddr;
    const char *vatype;
    if (r.slot == (int)SlotType::Patch) {
      vaddr = r.addr + file.phX->p_vaddr;
      vatype = "patch";
    } else {
      vaddr = r.addr;
      vatype = "stub";
    }
    return fmtSprintf("reloc_%d %s addr %lx rel %d", i, vatype, vaddr, r.rel);
  }

  void handleInst(AddrAndIdx i) {
    auto op = allOpcode[i.idx];

    JmpRes jmp = doReplace(i);
    markInstRangeUsed(jmp.r0);
    markInstRangeUsed(jmp.r1);

    totOpType[op.type]++;
    totJmpType[jmp.type]++;

    if (verbose) {
      printInst(i, jmp);
    }

    auto stubAddr = E.code.size();
    auto relocIdx = E.relocs.size();
    auto patchIdx = E.patches.size();

    switch (jmp.type) {
      case PushJmp: {
        patchPushRspJmp(jmp.r0, stubAddr);
        patchPushFJmp(jmp.r1, jmp.r0);
        emitPushJmpStub(jmp.r0, jmp.r1, true);
        break;
      }

      case PushJmp2: {
        patchPushRspJmp(jmp.r0, stubAddr);
        patchShortJmp(jmp.r1, jmp.r0, 1);
        emitPushJmpStub(jmp.r0, jmp.r1, false);
        break;
      }

      case DirectCall: {
        auto i = instOccurMap.find(instHash(jmp.r0.i));
        assert(i != instOccurMap.end());
        int oi = i->second;
        auto &o = instOccur[oi];
        if (!o.addr) {
          o.addr = stubAddr;
          emitDirectCallStub(jmp.r0);
        }
        patchCall(jmp.r0, o.addr);
        break;
      }

      case CombineJmp: {
        patchLongJmp(jmp.r0, stubAddr);
        emitDirectJmpStub(jmp.r0);
        break;
      }
    }

    if (debug) {
      for (int i = patchIdx; i < E.patches.size(); i++) {
        auto p = E.patches[i];
        fmtPrintf("add patch_%d addr %lx off %d size %d\n", i, vaddr(p.addr), p.off, p.size);
      }
      for (int i = relocIdx; i < E.relocs.size(); i++) {
        auto r = E.relocs[i];
        fmtPrintf("add %s\n", fmtReloc(r, i).c_str());
      }
      auto D = [&](const std::string &s, Slice buf, uint64_t va) {
        ad.dumpInstBuf(fmtSprintf("%s_%s", JmpTypeStr(jmp.type), s.c_str()), buf, va);
      };
      auto before = [&](const std::string &s, AddrRange r) {
        D(s + "_before", instBuf.slice(r.i.addr, r.size), vaddr(r.i.addr));
      };
      auto after = [&](const std::string &s, int i) {
        if (patchIdx + i < E.patches.size()) {
          auto p = E.patches[patchIdx + i];
          auto c = E.patchCode.begin() + p.off;
          D(s + "_after", {c, c + p.size}, vaddr(p.addr));
        }
      };
      if (debugOnlyBefore) {
        before("inst0", jmp.r0);
        before("inst1", jmp.r1);
      } else {
        before("inst0", jmp.r0);
        after("inst0", 0);
        before("inst1", jmp.r1);
        after("inst1", 1);
        D("stub", E.codeSlice(stubAddr), stubAddr);
      }
    }
  };

  void forAllInst0(std::function<void(AddrAndIdx,const Section&)> fn) {
    for (auto sec: allSecs) {
      uint64_t addr = sec.start;
      for (int i = sec.startIdx; i < sec.endIdx; i++) {
        fn({.addr = addr, .idx = i}, sec);
        addr += allOpcode[i].size;
      }
    }
  };

  void forAllInst(std::function<void(AddrAndIdx)> fn) {
    forAllInst0([&](AddrAndIdx i, const Section& sec) {
      fn(i);
    });
  };

  void markAllJmp() {
    for (auto sec: allSecs) {
      std::vector<uint64_t> tos;
      uint64_t addr = sec.start;
      for (int i = sec.startIdx; i < sec.endIdx; addr += allOpcode[i].size, i++) {
        auto &op = allOpcode[i];
        if (op.bad) {
          continue;
        }
        int32_t off;
        if (op.op == X86::JCC_1 || op.op == X86::JMP_1) {
          off = *(int8_t*)(instBuf.data()+addr+op.size-1);
        } else if (op.op == X86::JCC_4 || op.op == X86::JMP_4) {
          off = *(int32_t*)(instBuf.data()+addr+op.size-4);
        } else {
          continue;
        }
        auto to = addr+op.size+off;
        if (to >= sec.start && to < sec.end) {
          tos.push_back(to);
        }
      }

      std::sort(tos.begin(), tos.end());
      int n = 0;
      int i = sec.startIdx;
      addr = sec.start;
      for (int ti = 0; ti < tos.size(); ti++) {
        while (i < sec.endIdx && addr < tos[ti]) {
          addr += allOpcode[i].size, i++;
        }
        if (addr == tos[ti]) {
          allOpcode[i].jmpto = 1;
          n++;
        }
      }

      if (debug) {
        fmtPrintf("markjmp %d/%d\n", n, tos.size());
      }
    }
  };

  Translater(AsmDism &ad, const ElfFile & file, Result &res): 
    ad(ad),
    file(file), 
    res(res),
    eh(file.eh()),
    phX(file.phX),
    instBuf((uint8_t *)eh + phX->p_offset, phX->p_filesz),
    E(ad)
  {
  }

  void run() {
    for (auto &s: file.secs) {
      if (!(s.sh->sh_flags & SHF_EXECINSTR)) {
        continue;
      }
      if (s.name.substr(0, plt.size()) == plt) {
        continue;
      }
      uint64_t addr = s.sh->sh_offset - phX->p_offset;
      uint64_t start = addr;
      uint64_t end = addr + s.sh->sh_size;
      if (debug) {
        fmtPrintf("section %s %lx %lx\n", s.name.c_str(), vaddr(start), vaddr(end));
      }
      allSecs.push_back({.start = addr, .end = end, .name = s.name});
    }

    for (auto &sec: allSecs) {
      sec.startIdx = allOpcode.size();
      for (uint64_t addr = sec.start; addr < sec.end; ) {
        auto op = decodeInst(addr);

        auto idx = (int)allOpcode.size();

        if (op.op == ad.X86_BAD) {
          if (badRanges.size() == 0 ||
              addr - badRanges[badRanges.size()-1].addr > BadMaxDiff)
          {
            badRanges.push_back({addr, idx});
            badRanges.push_back({addr+op.size, idx+1});
          } else {
            badRanges[badRanges.size()-1] = {addr+op.size, idx+1};
          }
        }

        AddrAndIdx ai = {addr, idx};
        allOpcode.push_back(op);
        addr += op.size;

        if (op.type >= TlsStackCanary) {
          fsInsts.push_back(ai);
        }

        if (op.type != NormalOp) {
          if (op.size >= 5) {
            auto h = instHash(ai);
            auto mi = instOccurMap.emplace(h, (int)instOccur.size());
            int oi;
            if (mi.second) {
              oi = instOccur.size();
              instOccur.push_back({});
            } else {
              oi = mi.first->second;
            }
            auto &p = instOccur[oi];
            p.i = ai;
            p.n++;
          }
        }
      }
      sec.endIdx = allOpcode.size();
    }

    if (debug) {
      debugInstOccur();
    }

    for (auto bi: badRanges) {
      for (int i = 0; i < badRanges.size(); i += 2) {
        for (int j = badRanges[i].idx; j < badRanges[i+1].idx; j++) {
          allOpcode[j].bad = 1;
        }
      }
      forInstAround(bi, BadMaxDiff, [&](AddrAndIdx i) -> int {
        allOpcode[i.idx].bad = 1;
        allOpcode[i.idx].used = 1;
        return -1;
      });
    }

    if (debug) {
      for (int i = 0; i < badRanges.size(); i += 2) {
        auto start = badRanges[i];
        auto end = badRanges[i+1];
        fmtPrintf("bad range %d addr %lx %lx len %lu n %d\n", i / 2,
                  vaddr(start.addr), vaddr(end.addr), end.addr - start.addr,
                  end.idx - start.idx);
      }
    }

    markAllJmp();

    if (forAll) {
      forAllInst([&](AddrAndIdx i) {
        handleInst(i);
      });
    } else if (forSingleInstr != -1) {
      forAllInst([&](AddrAndIdx i) {
        if (vaddr(i.addr) == forSingleInstr) {
          handleInst(i);
        }
      });
    } else {
      for (auto i: fsInsts) {
        handleInst(i);
      }
    }

    if (summary) {
      std::stringstream ss;
      for (int i = 0; i < OpTypeNr; i++) {
        ss << OpTypeStr(i) << " " << totOpType[i] << " ";
      }
      for (int i = 1; i < JmpTypeNr; i++) {
        ss << JmpTypeStr(i) << " " << totJmpType[i] << " ";
      }
      fmtPrintf("%s\n", ss.str().c_str());
    }

    res.relocs = std::move(E.relocs);
    res.stubCode = std::move(E.code);
    res.patches = std::move(E.patches);
    res.patchCode = std::move(E.patchCode);
  }
};

static AsmDism AD;

void translate(const ElfFile &file, Result &res) {
  Translater t(AD, file, res);
  t.run();
}

error writeElfFile(const Result &res, const ElfFile &input, const std::string &output) {
  auto totSize = sysPageCeil(input.buf.size());
  auto l = input.loads[input.loads.size()-1];
  auto lend = sysPageCeil(l->p_vaddr + l->p_memsz);
  if (lend > totSize) {
    totSize = lend;
  }

  auto codeVaddr = input.phX->p_vaddr;
  auto newPhsVaddr = totSize;
  auto stubCodeVaddr = newPhsVaddr + sysPageSize;
  totSize = stubCodeVaddr + res.stubCode.size();
  auto newPhsOff = newPhsVaddr;
  auto stubCodeOff = stubCodeVaddr;

  auto oldPhs = (Elf64_Phdr *)(input.buf.data() + input.eh()->e_phoff);
  auto phs = std::vector<Elf64_Phdr>(oldPhs, oldPhs + input.eh()->e_phnum);
  auto newPhsSize = (phs.size() + 2) * sizeof(phs[0]);

  File f;
  auto err = f.create(output);
  if (err) {
    return err;
  }

  err = f.truncate(totSize);
  if (err) {
    return err;
  }

  Slice buf;
  err = f.mmapWrite(buf);
  if (err) {
    return err;
  }

  auto filem = buf.p();
  auto codeOff = input.phX->p_offset;
  auto code = filem + codeOff;
  auto stubCode = filem + stubCodeOff;

  memcpy(filem, input.buf.data(), input.buf.size());
  memcpy(filem + stubCodeOff, res.stubCode.data(), res.stubCode.size());

  for (auto p: res.patches) {
    auto c = code + p.addr;
    memcpy(c, &res.patchCode[p.off], p.size);
  }

  for (int i = 0; i < res.relocs.size(); i++) {
    auto r = res.relocs[i];
    uint8_t *base = nullptr;
    switch ((SlotType)r.slot) {
    case SlotType::Patch: base = code; break;
    case SlotType::Stub: base = stubCode; break;
    }

    auto p = base + r.addr;
    auto diff = int32_t(stubCodeVaddr - codeVaddr);

    switch ((RelType)r.rel) {
    case RelType::Add: *(int32_t *)p += diff; break;
    case RelType::Sub: *(int32_t *)p -= diff; break;
    }
  }

  for (auto &ph: phs) {
    if (ph.p_type == PT_PHDR) {
      ph.p_offset = newPhsOff;
      ph.p_vaddr = newPhsVaddr;
      ph.p_paddr = newPhsVaddr;
      ph.p_filesz = newPhsSize;
      ph.p_memsz = newPhsSize;
    }
  }

  auto at = std::find_if(phs.begin(), phs.end(), [](auto ph) {
    return ph.p_type == PT_LOAD && ph.p_flags & PF_W;
  });

  phs.insert(at, {{
    .p_type = PT_LOAD, .p_flags = PF_R,
    .p_offset = newPhsOff, .p_vaddr = newPhsVaddr, .p_paddr = newPhsVaddr,
    .p_filesz = newPhsSize, .p_memsz = newPhsSize,
    .p_align = 0x1,
  }, {
    .p_type = PT_LOAD, .p_flags = PF_R|PF_X,
    .p_offset = stubCodeOff, .p_vaddr = stubCodeVaddr, .p_paddr = stubCodeVaddr,
    .p_filesz = res.stubCode.size(), .p_memsz = res.stubCode.size(),
    .p_align = sysPageSize,
  }});
  memcpy(filem + newPhsOff, phs.data(), newPhsSize);

  auto newEh = (Elf64_Ehdr *)filem;
  newEh->e_phoff = newPhsOff;
  newEh->e_phnum = phs.size();

  if (msync(filem, totSize, MS_SYNC) == -1) {
    return fmtErrorf("msync failed");
  }

  return nullptr;
}

error genAddrFiles(const std::vector<std::string> &args) {
  auto addrStart = 0x00007ff000000000UL;
  auto addrInc   = 0x0000000010000000UL;
  auto addr = addrStart;
  std::fstream faddr("addrs", std::fstream::out);
  std::fstream faddrGdb("addrs.gdb", std::fstream::out);

  for (auto &filename: args) {
    ElfFile file;
    auto err = file.open(filename);
    if (err) {
      return err;
    }

    auto basename = std::filesystem::path(filename).filename().string();
    auto trname = "tr."+basename;
    fmtPrintf("translate %s %s\n", basename.c_str(), trname.c_str());

    Result res;
    translate(file, res);
    err = writeElfFile(res, file, trname);
    if (err) {
      return err;
    }

    faddr << basename <<  " " << trname << " 0x" << std::hex << addr << "\n";
    faddrGdb << "add-symbol-file" << " " << trname;
    for (auto i: file.secs) {
      if (i.sh->sh_addr) {
        faddrGdb << " -s " << i.name << " 0x" << std::hex << i.sh->sh_addr + addr;
      }
    }
    faddrGdb << "\n";
    addr += addrInc;
  }

  return nullptr;
}

error cmdMain(const std::vector<std::string> &args0) {
  std::vector<std::string> args;
  bool gen = false;

  for (int i = 0; i < args0.size(); i++) {
    auto &o = args0[i];
    if (o == "-i") {
      if (i+1 >= args0.size()) {
        return fmtErrorf("missing param");
      }
      sscanf(args0[i+1].c_str(), "%x", &forSingleInstr);
      i++;
      continue;
    }
    if (o == "-d") {
      debug = true;
      continue;
    }
    if (o == "-vd") {
      debug = true;
      verbose = true;
      continue;
    }
    if (o == "-vad") {
      debug = true;
      forAll = true;
      verbose = true;
      continue;
    }
    if (o == "-dob") {
      debugOnlyBefore = true;
      continue;
    }
    if (o == "-v") {
      verbose = true;
      continue;
    }
    if (o == "-a") {
      forAll = true;
      continue;
    }
    if (o == "-s") {
      summary = true;
      continue;
    }
    if (o == "-g") {
      gen = true;
      continue;
    }
    args.push_back(o);
  }

  if (args.size() < 1) {
    return fmtErrorf("missing filename");
  }

  if (gen) {
    return genAddrFiles(args);
  }

  auto input0 = args[0];

  std::string output0 = "a.out";
  if (args.size() > 1) {
    output0 = args[1];
  }

  ElfFile input;
  auto err = input.open(input0);
  if (err) {
    return err;
  }

  Result res;
  translate(input, res);

  err = writeElfFile(res, input, output0);
  if (err) {
    return err;
  }

  return nullptr;
}

}
