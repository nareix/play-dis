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
#include "X86BaseInfo.h"

#include <vector>
#include <string>
#include <string_view>

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "elf.h"

using namespace llvm;

template <typename... Types>
std::string fmt(const char *f, Types... args) {
  ssize_t n = snprintf(NULL, 0, f, args...);
  char buf[n+1];
  snprintf(buf, n+1, f, args...);
  return std::string(buf);
}

template <typename... Types>
void outsfmt(const char *f, Types... args) {
  outs() << fmt(f, args...);
}

int main(int argc, char **argv) {
  std::vector<std::string> args;
  std::vector<std::string> args0;
  bool verbose = false;
  bool forAll = false;
  int forSingleInstr = -1;
  bool summary = false;
  bool debug = false;
  bool debugOnlyBefore = false;

  for (int i = 1; i < argc; i++) {
    args0.push_back(std::string(argv[i]));
  }

  for (int i = 0; i < args0.size(); i++) {
    auto &o = args0[i];
    if (o == "-i") {
      if (i+1 >= args0.size()) {
        fprintf(stderr, "need param\n");
        return -1;
      }
      sscanf(args0[i+1].c_str(), "%x", &forSingleInstr);
      i++;
      continue;
    }
    if (o == "-d") {
      debug = true;
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
    args.push_back(o);
  }

  if (args.size() == 0) {
    errs() << "need filename\n";
    return -1;
  }

  auto filename = args[0];
  int fd = open(filename.c_str(), O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open %s failed\n", filename.c_str());
    return -1;
  }

  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    fprintf(stderr, "stat %s failed\n", filename.c_str());
    return -1;
  }
  auto fileSize = sb.st_size;

  uint8_t *faddr = (uint8_t *)mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (faddr == MAP_FAILED) {
    fprintf(stderr, "mmap %s failed\n", filename.c_str());
    return -1;
  }

  Elf64_Ehdr *eh = (Elf64_Ehdr *)faddr;
  uint8_t osabi = eh->e_ident[EI_OSABI];
  if (
    eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_ident[EI_MAG1] != ELFMAG1 ||
    eh->e_ident[EI_MAG2] != ELFMAG2 || eh->e_ident[EI_MAG3] != ELFMAG3 ||
    eh->e_ident[EI_CLASS] != ELFCLASS64 ||
    eh->e_ident[EI_DATA] != ELFDATA2LSB ||
    (osabi != ELFOSABI_LINUX && osabi != ELFOSABI_SYSV) ||
    eh->e_machine != EM_X86_64 ||
    (eh->e_type != ET_EXEC && eh->e_type != ET_DYN)
    )
  {
    fprintf(stderr, "%s elf not supported\n", filename.c_str());
    return -1;
  }

  if (debug) {
    outsfmt("filesize %lx e_ehsize %d e_phoff %lx size %d e_shoff %lx size %d\n",
      sb.st_size, eh->e_ehsize,
      eh->e_phoff, eh->e_phentsize*eh->e_phnum,
      eh->e_shoff, eh->e_shentsize*eh->e_shnum
    );
  }

  uint64_t vaddrLoadEnd = 0;
  uint64_t vaddrStubStart = 0;
  Elf64_Phdr *phX = NULL;
  uint8_t *phStart = (uint8_t *)eh + eh->e_phoff;
  for (int i = 0; i < eh->e_phnum; i++) {
    Elf64_Phdr *ph = (Elf64_Phdr *)(phStart + eh->e_phentsize*i);
    if (ph->p_type == PT_LOAD) {
      if (ph->p_flags & PF_X) {
        phX = ph;
      }
      vaddrLoadEnd = ph->p_vaddr + ph->p_memsz;
    }
  }

  auto alignAddr = [&](uint64_t base, uint64_t align) {
    return (base + (align - 1)) & ~(align - 1);
  };

  vaddrStubStart = alignAddr(vaddrLoadEnd, 0x1000);

  if (debug) {
    outsfmt("load off %lx size %lx\n", phX->p_offset, phX->p_filesz);
    outsfmt("load end %lx stub start %lx\n", vaddrLoadEnd, vaddrStubStart);
  }

  ArrayRef<uint8_t> instrBuf((uint8_t *)eh + phX->p_offset, phX->p_filesz);
  auto vaddr = [&](uint64_t addr) -> uint64_t {
    return addr + phX->p_vaddr;
  };

  auto newText = std::vector<uint8_t>(instrBuf.begin(), instrBuf.end());

  struct Section {
    uint64_t start, end;
    std::string name;
    int startIdx, endIdx;
  };
  std::vector<Section> allSecs;
  std::string plt = ".plt";

  uint8_t *shStart = (uint8_t *)eh + eh->e_shoff;
  Elf64_Shdr *shStrtab = (Elf64_Shdr *)(shStart + eh->e_shentsize*eh->e_shstrndx);
  const char *strtab = (const char *)((uint8_t *)eh + shStrtab->sh_offset);
  for (int i = 0; i < eh->e_shnum; i++) {
    Elf64_Shdr *sh = (Elf64_Shdr *)(shStart + eh->e_shentsize*i);
    auto name = std::string(strtab + sh->sh_name);
    if (!(sh->sh_flags & SHF_EXECINSTR)) {
      continue;
    }
    if (name.substr(0, plt.size()) == plt) {
      continue;
    }
    uint64_t addr = sh->sh_offset - phX->p_offset;
    uint64_t start = addr;
    uint64_t end = addr + sh->sh_size;
    if (debug) {
      outsfmt("section %s %lx %lx\n", name.c_str(), vaddr(start), vaddr(end));
    }
    allSecs.push_back({.start = addr, .end = end, .name = name, .startIdx = -1});
  }

  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86AsmParser();
  LLVMInitializeX86Disassembler();

  const MCTargetOptions MCOptions = mc::InitMCTargetOptionsFromFlags();

  std::string tripleName = sys::getDefaultTargetTriple();
  Triple TheTriple(Triple::normalize(tripleName));
  std::string err;
  const Target *T = TargetRegistry::lookupTarget(tripleName, err);

  std::unique_ptr<MCSubtargetInfo> STI(T->createMCSubtargetInfo(tripleName, "", ""));
  std::unique_ptr<MCRegisterInfo> MRI(T->createMCRegInfo(tripleName));
  std::unique_ptr<MCAsmInfo> MAI(T->createMCAsmInfo(*MRI, tripleName, MCOptions));
  std::unique_ptr<MCInstrInfo> MII(T->createMCInstrInfo());

  SourceMgr SrcMgr;
  MCContext Ctx(TheTriple, MAI.get(), MRI.get(), STI.get(), &SrcMgr, &MCOptions);

  std::unique_ptr<MCInstrInfo> MCII(T->createMCInstrInfo());
  std::unique_ptr<MCCodeEmitter> CE(T->createMCCodeEmitter(*MCII, Ctx));
  std::unique_ptr<MCAsmBackend> MAB(T->createMCAsmBackend(*STI, *MRI, MCOptions));

  SmallString<128> ss;
  raw_svector_ostream osv(ss);
  auto FOut = std::make_unique<formatted_raw_ostream>(osv);
  MCInstPrinter *IP = T->createMCInstPrinter(Triple(tripleName), 0, *MAI, *MCII, *MRI);
  std::unique_ptr<MCStreamer> Str(
      T->createAsmStreamer(Ctx, std::move(FOut), /*asmverbose*/false,
                           /*useDwarfDirectory*/false, IP,
                           std::move(CE), std::move(MAB), /*showinst*/true));

  std::unique_ptr<MCCodeEmitter> CE2(T->createMCCodeEmitter(*MCII, Ctx));
  std::unique_ptr<MCDisassembler> DisAsm(T->createMCDisassembler(*STI, Ctx));

  std::vector<unsigned> gpRegs = {
    // keep order
    X86::RIP, X86::RSP, X86::RBP, X86::RAX,
    X86::RCX, X86::RDX, X86::RBX, X86::RSI, X86::RDI,
    X86::R8, X86::R9, X86::R10, X86::R11,
    X86::R12, X86::R13, X86::R14, X86::R15,
  };

  auto gpRegIdx = [&](unsigned reg) -> int {
    auto first = std::find(gpRegs.begin(), gpRegs.end(), reg);
    if (first == gpRegs.end()) {
      return -1;
    }
    return first - gpRegs.begin();
  };

  auto gpFreeStart = gpRegIdx(X86::RCX);
  auto gpRspIdx = gpRegIdx(X86::RSP);

  auto gpFindFreeReg = [&](unsigned mask) -> int {
    for (int i = gpFreeStart; i < gpRegs.size(); i++) {
      if (!(mask & (1<<i))) {
        return i;
      }
    }
    return -1;
  };

  auto superReg = [&](unsigned reg) -> unsigned {
    auto super = reg;
    for (MCSuperRegIterator i(reg, MRI.get()); i.isValid(); ++i) {
      super = *i;
    }
    return super;
  };

  auto instrHexStr = [&](ArrayRef<uint8_t> buf) -> std::string {
    std::string hex = "[";
    for (int i = 0; i < buf.size(); i++) {
      hex += fmt("%.2X", buf[i]);
      if (i < buf.size()-1) {
        hex += " ";
      }
    }
    hex += "]";
    return hex;
  };

  auto instrDisStr = [&](const MCInst &Inst) -> std::string {
    Str->emitInstruction(Inst, *STI);
    auto r = ss.slice(1, ss.size()-1).str();
    for (int i = 0; i < r.size(); i++) {
      if (r[i] == '\t') {
        r[i] = ' ';
      }
    }
    ss.clear();
    return r;
  };

  auto instrDumpStr = [&](const MCInst &inst) -> std::string {
    auto n = inst.getNumOperands();
    std::string s = fmt("%d,n=%d[", inst.getOpcode(), n);
    for (int i = 0; i < n; i++) {
      auto op = inst.getOperand(i);
      if (op.isReg()) {
        s += fmt("r%d", op.getReg());
      } else if (op.isImm()) {
        s += fmt("i%d", op.getImm());
      }
      if (i < n-1) {
        s += ",";
      }
    }
    s += "]";
    return s;
  };

  struct InstrInfo {
    bool ok;
    int mIdx; // [BaseReg, ScaleAmt, IndexReg, Disp, Segment]
    int immIdx;
    int regIdx;
    int regIdx1;
    int useReg;
  };

  #define panicUnsupportedInstr(inst) {\
    auto s0 = instrDisStr(inst); \
    auto s1 = instrDumpStr(inst); \
    auto s2 = IP->getOpcodeName(inst.getOpcode()).str(); \
    fprintf(stderr, "%s:%d: unsupported instr %s %s %s\n", __FILE__, __LINE__, s2.c_str(), s0.c_str(), s1.c_str()); \
    exit(-1); \
    __builtin_unreachable(); \
  }

  auto getInstrInfo = [&](const MCInst &inst, bool panic = true) -> InstrInfo {
    auto n = inst.getNumOperands();
    InstrInfo r = {
      .mIdx = -1,
      .immIdx = -1,
      .regIdx = -1,
      .regIdx1 = -1,
      .useReg = -1,
    };

    #define RET if (panic) { panicUnsupportedInstr(inst); } else { return r; }
    #define C(op) case X86::op: 
    #define M(v) r.mIdx = v;
    #define IMM(v) r.immIdx = v;
    #define R(v) r.regIdx = v;
    #define R1(v) r.regIdx1 = v;
    #define N(v) if (inst.getNumOperands() != v) { RET }
    #define E() r.ok = true; return r;
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
    }

    RET

    #undef E
    #undef N
    #undef R1
    #undef R
    #undef IMM
    #undef M
    #undef C
    #undef RET
  };

  auto instrUsedRegMask = [&](const MCInst &inst) -> unsigned {
    unsigned mask = 0;
    auto info = getInstrInfo(inst);

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
  };

  enum {
    kNormalOp,
    kTlsStackCanary,
    kTlsOp,
    kSyscall,
    kOpTypeNr,
  };

  const char *kOpTypeStrs[] = {
    "normal_op",
    "tls_stack_canary",
    "tls_op_normal",
    "syscall",
  };

  enum {
    kNoJmp,
    kIgnoreJmp,
    kDirectJmp,
    kPushJmp,
    kPushJmp2,
    kCombineJmp,
    kJmpFail,
    kJmpTypeNr,
  };

  const char *kJmpTypeStrs[] = {
    "no_jmp",
    "ignore_jmp",
    "direct_jmp",
    "push_jmp",
    "push_jmp2",
    "combine_jmp",
    "jmp_fail",
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

  auto logJmpFail = [&](uint64_t addr, const char *tag) {
    if (debug) {
      outsfmt("jmpfailat addr %lx %s\n", vaddr(addr), tag);
    }
  };

  std::vector<OpcodeAndSize> allOpcode;

  using SmallCode = SmallString<256>;

  auto disamInstrBuf = [&](const std::string &prefix, ArrayRef<uint8_t> buf, uint64_t va = 0) {
    MCInst Inst;
    uint64_t Size;
    for (int addr = 0; addr < buf.size(); ) {
      auto r = DisAsm->getInstruction(Inst, Size, buf.slice(addr), 0, nulls());
      std::string dis, dump;
      if (r != MCDisassembler::DecodeStatus::Success) {
        Size = 1;
        dis = "bad";
        dump = "bad";
      } else {
        dis = instrDisStr(Inst);
        dump = instrDumpStr(Inst);
      }
    print:
      outs() << prefix << " " << fmt("%lx", addr+va) << 
        " " << dis << 
        " " << dump << 
        " " << instrHexStr(buf.slice(addr,  Size)) << 
        "\n";
      addr += Size;
    }
  };

  auto forInstrAround = [&](AddrAndIdx ai, int maxDist, std::function<int(AddrAndIdx i)> fn) -> bool {
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
  };

  auto constexpr X86_BAD = X86::INSTRUCTION_LIST_END+1;

  auto decodeInstr = [&](uint64_t addr) -> OpcodeAndSize {
    MCInst Inst;
    uint64_t Size;
    auto S = DisAsm->getInstruction(Inst, Size, instrBuf.slice(addr), 0, nulls());

    if (S != MCDisassembler::DecodeStatus::Success) {
      return {.op = X86_BAD, .size = 1, .type = kNormalOp};
    }

    auto &idesc = MII->get(Inst.getOpcode());
    unsigned type = kNormalOp;
    unsigned used = 0;

    if (Inst.getOpcode() == X86::SYSCALL) {
      type = kSyscall;
      used = 1;
    } else {
      for (int i = 0; i < idesc.NumOperands; i++) {
        auto od = Inst.getOperand(i);
        auto opinfo = idesc.OpInfo[i];
        if (opinfo.RegClass == X86::SEGMENT_REGRegClassID) {
          if (od.getReg() == X86::FS) {
            type = kTlsOp;
            used = 1;
            if (i > 0) {
              auto preOp = Inst.getOperand(i-1);
              if (preOp.isImm() && preOp.getImm() == 40) {
                type = kTlsStackCanary;
              }
            }
            break;
          }
        }
      }
    }

    return {
      .op = (uint16_t)Inst.getOpcode(),
      .size = (uint8_t)Size,
      .used = used,
      .type = type,
    };
  };

  std::vector<AddrAndIdx> fsInstrs;
  std::vector<AddrAndIdx> badRanges;
  const int BadMaxDiff = 100;

  auto instStrview = [&](AddrAndIdx i) -> std::string_view {
    return {(char *)instrBuf.data()+i.addr, allOpcode[i.idx].size};
  };

  std::hash<std::string_view> strhash;

  auto instHash = [&](AddrAndIdx i) -> size_t {
    return strhash(instStrview(i));
  };

  struct OccurPair {
    AddrAndIdx i;
    int n;
  };
  std::vector<OccurPair> instOccur;
  std::unordered_map<size_t, int> instOccurMap;

  for (auto &sec: allSecs) {
    sec.startIdx = allOpcode.size();
    for (uint64_t addr = sec.start; addr < sec.end; ) {
      auto op = decodeInstr(addr);

      auto idx = (int)allOpcode.size();

      if (op.op == X86_BAD) {
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

      if (op.type >= kTlsStackCanary) {
        fsInstrs.push_back(ai);
      }

      if (op.type != kNormalOp) {
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
    std::vector<int> sortIdx;
    for (int i = 0; i < instOccur.size(); i++) {
      sortIdx.push_back(i);
    }
    std::sort(sortIdx.begin(), sortIdx.end(), [&](auto &l, auto &r) {
      return instOccur[l].n > instOccur[r].n;
    });

      for (int i = 0; i < sortIdx.size(); i++) {
      MCInst Inst;
      uint64_t Size;
      auto p = instOccur[sortIdx[i]];
      auto op = allOpcode[p.i.idx];
      ArrayRef<uint8_t> b = {instrBuf.data() + p.i.addr, op.size};
      DisAsm->getInstruction(Inst, Size, b, 0, nulls());
      auto s = instrDisStr(Inst);
      auto bs = instrHexStr(b);
      outsfmt("instoccur %d %s %s %d\n", i, s.c_str(), bs.c_str(), p.n);
    }
   }

  for (auto bi: badRanges) {
    for (int i = 0; i < badRanges.size(); i += 2) {
      for (int j = badRanges[i].idx; j < badRanges[i+1].idx; j++) {
        allOpcode[j].bad = 1;
      }
    }
    forInstrAround(bi, BadMaxDiff, [&](AddrAndIdx i) -> int {
      allOpcode[i.idx].bad = 1;
      allOpcode[i.idx].used = 1;
      return -1;
    });
  }

  if (debug) {
    for (int i = 0; i < badRanges.size(); i += 2) {
      auto start = badRanges[i];
      auto end = badRanges[i+1];
      outsfmt("bad range %d addr %lx %lx len %lu n %d\n", i/2, vaddr(start.addr), vaddr(end.addr),
        end.addr-start.addr, end.idx-start.idx);
    }
  }

  auto printInstr = [&](AddrAndIdx ai, JmpRes jmp) {
    auto op = allOpcode[ai.idx];
    auto addr = ai.addr;

    std::string sep = " ";

    auto formatInstHeader = [&](uint64_t addr, uint64_t size) -> std::string {
      return fmt("%lx", vaddr(addr));
    };

    if (op.op == X86_BAD) {
      outs() << formatInstHeader(addr, op.size) << "BAD " << "\n";
      return;
    }

    MCInst Inst;
    uint64_t Size;

    DisAsm->getInstruction(Inst, Size, instrBuf.slice(addr), addr, nulls());

    std::string tag = kJmpTypeStrs[jmp.type];

    if (jmp.type == kPushJmp) {
      auto rop = allOpcode[jmp.r0.i.idx];
      std::string name = IP->getOpcodeName(rop.op).str();
      tag += fmt(":%lu,%s,%d", rop.size, name.c_str(), std::abs((int64_t)(jmp.r0.i.addr-addr)));
    } else if (jmp.type == kCombineJmp) {
      tag += fmt(":%d,%d", jmp.r0.size, jmp.r0.n);
    }

    if (op.jmpto) {
      tag += ":jmpto";
    }

    outs() << formatInstHeader(addr, Size) <<
      sep << instrDisStr(Inst) <<
      sep << IP->getOpcodeName(Inst.getOpcode()) <<
      sep << instrDumpStr(Inst) << 
      sep << instrHexStr(instrBuf.slice(addr, Size)) << 
      sep << kOpTypeStrs[op.type] <<
      sep << tag << 
      "\n";
  };

  int totOpType[kOpTypeNr] = {};
  int totJmpType[kJmpTypeNr] = {};

  enum {
    kStubReloc,
    kTextReloc,
    kRelocNr,
  };

  enum {
    kRelText,
    kRelStub,
    kRelCall,
    kRelRIP,
  };

  enum {
    kFnGetTls,
    kFnSyscall,
    kFnNr,
  };

  struct SimpleReloc {
    uint32_t addr;
    unsigned slot:2;
    unsigned type:3;
  };

  class SimpleCE {
  public:
    const std::unique_ptr<MCCodeEmitter> &CE2;
    const std::unique_ptr<MCSubtargetInfo> &STI;
    SmallCode code;
    raw_svector_ostream vcode;
    uint8_t *text;
    SmallVector<MCFixup, 4> fixups;
    std::vector<SimpleReloc> relocs;

    SimpleCE(typeof(CE2) &CE2, typeof(STI) &STI, uint8_t *text): 
      CE2(CE2), STI(STI), vcode(code), text(text) {
    }

    void emit(const MCInst &inst) {
      CE2->encodeInstruction(inst, vcode, fixups, *STI);
    }

    ArrayRef<uint8_t> codeSlice(size_t start) {
      return {(uint8_t *)code.data()+start, code.size()-start};
    }

    void reloc(int slot, int type, uint8_t *base, uint32_t addr, int32_t v, bool add = false) {
      auto p = (int32_t *)(base + addr);
      if (add) {
        *p += v;
      } else {
        *p = v;
      }
      relocs.push_back({(uint32_t)addr, (unsigned)slot, (unsigned)type});
    }

    void relocStub(int32_t v, int type = kRelText, bool add = false) {
      reloc(kStubReloc, type, (uint8_t *)code.data(), code.size()-4, v, add);
    }

    void relocText(uint64_t addr, int32_t v, int type = kRelStub) {
      reloc(kTextReloc, type, text, addr, v);
    }
  };

  SimpleCE E(CE2, STI, newText.data());

  auto adjustImm4 = [&](MCInst &inst, uint64_t backAddr) {
    if ([&]() -> bool {
      if (inst.getOpcode() == X86::JCC_4 || inst.getOpcode() == X86::JMP_4) {
        return true;
      }
      auto info = getInstrInfo(inst);
      if (info.mIdx != -1) {
        auto reg = superReg(inst.getOperand(info.mIdx).getReg());
        if (reg == X86::RIP) {
          return true;
        }
      }
      return false;
    }()) {
      E.relocStub(-int32_t(backAddr), kRelRIP, true);
    }
  };

  auto emitCallFn = [&](int fn) {
    E.code.push_back(0xe8);
    E.code.push_back(0);
    E.code.push_back(0);
    E.code.push_back(0);
    E.code.push_back(0);
    E.relocStub(fn, kRelCall);
  };

  auto emitOldTlsInst = [&](AddrAndIdx i) {
    MCInst inst1;
    uint64_t size1;
    auto addr1 = i.addr;
    DisAsm->getInstruction(inst1, size1, instrBuf.slice(addr1), 0, nulls());
    auto backAddr1 = addr1+size1;

    /*
      push %tmp; lea 8(%rsp), %rsp // save tmp,rsp(optional)
      lea inst1.mem, %tmp // get orig value
      lea -8(%rsp), %rsp // recovery rsp(optional)
      push %rax; call get_fs; lea (%rax,%tmp), %tmp; pop %rax // add fs
      inst1.op inst1.reg, (%tmp) // modified instr
      pop %tmp // recovery tmp
    */
    auto info = getInstrInfo(inst1);
    if (info.mIdx == -1) {
      panicUnsupportedInstr(inst1);
    }
    unsigned used = instrUsedRegMask(inst1);
    int ti = gpFindFreeReg(used);
    if (ti == -1) {
      panicUnsupportedInstr(inst1);
    }
    unsigned tmpReg = gpRegs[ti];
    bool useRsp = used & (1<<gpRspIdx);

    E.emit(MCInstBuilder(X86::PUSH64r).addReg(tmpReg));

    if (useRsp) {
      E.emit(MCInstBuilder(X86::LEA64r)
        .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(-8).addReg(0));
    }

    MCInst lea;
    lea.setOpcode(X86::LEA64r);
    lea.addOperand(MCOperand::createReg(tmpReg));
    for (int i = 0; i < 5; i++) {
      lea.addOperand(inst1.getOperand(info.mIdx+i));
    }
    lea.getOperand(5).setReg(0);
    E.emit(lea);
    adjustImm4(lea, backAddr1);

    if (useRsp) {
      E.emit(MCInstBuilder(X86::LEA64r)
        .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(8).addReg(0));
    }

    E.emit(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX));

    emitCallFn(kFnGetTls);

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

  auto emitOldNormalInst = [&](AddrAndIdx i) {
    MCInst inst;
    uint64_t size;
    auto addr = i.addr;
    DisAsm->getInstruction(inst, size, instrBuf.slice(addr), 0, nulls());
    auto backAddr = addr+size;

    if (inst.getOpcode() == X86::SYSCALL) {
      emitCallFn(kFnSyscall);
      return;
    }

    E.emit(inst);
    adjustImm4(inst, backAddr);
  };

  auto emitOldInst = [&](AddrAndIdx i) {
    auto op = allOpcode[i.idx];
    if (op.type == kTlsOp) {
      emitOldTlsInst(i);
    } else {
      emitOldNormalInst(i);
    }
  };

  auto emitOldInsts = [&](AddrRange r) {
    auto addr = r.i.addr;
    for (auto i = r.i.idx; i < r.i.idx+r.n; i++) {
      emitOldInst({.addr = addr, .idx = i});
      addr += allOpcode[i].size;
    }
  };

  auto emitJmpBack = [&](AddrRange r) {
    E.emit(MCInstBuilder(X86::JMP_4).addImm(128));
    E.relocStub(r.i.addr+r.size);
  };

  auto emitDirectJmpStub = [&](AddrRange r0) {
    emitOldInsts(r0);
    emitJmpBack(r0);
  };

  auto emitDirectCallStub = [&](AddrRange r0) {
    E.emit(MCInstBuilder(X86::ENDBR64));
    emitOldInsts(r0);
    E.emit(MCInstBuilder(X86::RET));
  };

  auto emitPushJmpStub = [&](AddrRange r0, AddrRange r1, bool pushF = true) {
    /*
      push %rax; pushfq // save rax,eflags
      lea -16(%rsp),%rax; cmp 16(%rsp),%rax // check jmpval == %rsp
      jne 1f
    */
    E.emit(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX));
    E.emit(MCInstBuilder(X86::PUSHF64));
    E.emit(MCInstBuilder(X86::MOV64rm)
      .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(16).addReg(0));
    E.emit(MCInstBuilder(X86::CMP64rm)
      .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(0).addReg(0));
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
    recovery(pushF);
    emitOldInsts(r0);
    emitJmpBack(r0);

    /*
    1:
      recovery
      tls_op
      jmp back1
    */
    E.code[jmp1Off-1] = int8_t(E.code.size() - jmp1Off);
    recovery(true);
    emitOldInsts(r1);
    emitJmpBack(r1);
  };

  auto modifyLongJmp = [&](AddrRange r0, uint64_t stubAddr) {
    while (r0.size > 5) {
      newText[r0.i.addr] = 0xf2; // repne
      r0.i.addr++;
      r0.size--;
    }
    newText[r0.i.addr] = 0xe9; // jmp
    E.relocText(r0.i.addr+1, stubAddr);
  };

  auto modifyShortJmp = [&](AddrRange r0, AddrRange r1, int off1 = 0) {
    while (r0.size > 2) {
      newText[r0.i.addr] = 0xf2; // repne
      r0.i.addr++;
      r0.size--;
    }
    auto addr1 = r1.i.addr + off1;
    newText[r0.i.addr] = 0xeb; // jmp
    newText[r0.i.addr+1] = uint8_t(int8_t(int64_t(r0.i.addr+2)-int64_t(addr1)));
  };

  auto modifyPushRspJmp = [&](AddrRange r0, uint64_t stubAddr) {
    newText[r0.i.addr] = 0x54; // push %rsp
    r0.i.addr++;
    r0.size--;
    modifyLongJmp(r0, stubAddr);
  };

  auto modifyPushFJmp = [&](AddrRange r0, AddrRange r1) {
    newText[r0.i.addr] = 0x9c; // pushf
    r0.i.addr++;
    r0.size--;
    modifyShortJmp(r0, r1, 1); // skip push %rsp
  };

  auto modifyCall = [&](AddrRange r0, int fn) {
    assert(r0.size >= 5);
    while (r0.size > 5) {
      newText[r0.i.addr++] = 0xf2;
      r0.size--;
    }
    newText[r0.i.addr++] = 0xe8;
    *(int32_t *)&newText[r0.i.addr] = fn;
  };

  auto singleAddrRange = [&](AddrAndIdx i) -> AddrRange {
    AddrRange r;
    r.i = i;
    r.n = 1;
    r.size = allOpcode[r.i.idx].size;
    return r;
  };

  auto regIsRsp = [](const MCInst &inst, int i) -> bool {
    auto r = inst.getOperand(i).getReg();
    return r == X86::ESP || r == X86::RSP;
  };

  auto canReplaceInst = [&](const MCInst &inst) -> bool {
    auto op = inst.getOpcode();
    if (op == X86::JCC_1 || op == X86::JMP_1) {
      return false;
    }
    auto info = getInstrInfo(inst, false);
    if (!info.ok) {
      return false;
    }
    if (info.regIdx != -1 && regIsRsp(inst, info.regIdx)) {
      return false;
    }
    if (info.regIdx1 != -1 && regIsRsp(inst, info.regIdx1)) {
      return false;
    }
    return true;
  };

  auto canReplaceIdx = [&](AddrAndIdx i) -> bool {
    MCInst inst;
    uint64_t size;
    DisAsm->getInstruction(inst, size, instrBuf.slice(i.addr), 0, nulls());
    return canReplaceInst(inst);
  };

  auto markInstRangeUsed = [&](AddrRange r) {
    for (int i = r.i.idx; i < r.i.idx+r.n; i++) {
      allOpcode[i].used = 1;
    }
  };

  auto markResInstUsed = [&](JmpRes r) -> JmpRes {
    markInstRangeUsed(r.r0);
    markInstRangeUsed(r.r1);
    return r;
  };

  auto checkPushJmp = [&](AddrAndIdx i, int minSize, int type) -> JmpRes {
    auto op = allOpcode[i.idx];

    if (op.size < minSize) {
      return {.type = kJmpFail};
    }

    AddrAndIdx j;

    if (forInstrAround(i, 127, [&](AddrAndIdx i) -> int {
      auto op = allOpcode[i.idx];
      if (canReplaceIdx(i) && !op.used && op.size >= 6) {
        j = i;
        return 0;
      }
      return -1;
    })) {
      return markResInstUsed({
        .type = type,
        .r0 = singleAddrRange(j),
        .r1 = singleAddrRange(i),
      });
    }

    return {.type = kJmpFail};
  };

  auto checkCombineJmp = [&](AddrAndIdx i0) -> JmpRes {
    JmpRes res = {.type = kJmpFail};

    uint64_t size = 0;
    auto addr = i0.addr;
    for (int i = i0.idx; i > 0; i--) {
      auto &op = allOpcode[i];
      if (!canReplaceIdx({addr,i})) {
        logJmpFail(addr, "cantrep");
        break;
      }
      if (op.used && i != i0.idx) {
        logJmpFail(addr, "used");
        break;
      }
      size += op.size;
      if (size >= 5) {
        return markResInstUsed({
          .type = kCombineJmp,
          .r0 = {
            .i = {
              .addr = addr,
              .idx = i,
            },
            .n = i0.idx - i + 1,
            .size = size,
          },
        });
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
      if (!canReplaceIdx({addr,i})) {
        logJmpFail(addr, "cantrep");
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
        return markResInstUsed({
          .type = kCombineJmp,
          .r0 = {
            .i = i0,
            .n = i - i0.idx + 1,
            .size = size,
          },
        });
      }
    }

    return res;
  };

  auto doReplace = [&](AddrAndIdx i) -> JmpRes {
    auto op = allOpcode[i.idx];

    if (op.type == kNormalOp) {
      return {.type = kNoJmp};
    }

    if (op.bad) {
      return {.type = kIgnoreJmp};
    }

    if (!canReplaceIdx(i)) {
      return {.type = kJmpFail};
    }

    if (op.size >= 5) {
      return {
        .type = kDirectJmp,
        .r0 = singleAddrRange(i),
      };
    }

    JmpRes res;

    res = checkPushJmp(i, 3, kPushJmp);
    if (res.type != kJmpFail) {
      return res;
    }

    res = checkPushJmp(i, 2, kPushJmp2);
    if (res.type != kJmpFail) {
      return res;
    }

    res = checkCombineJmp(i);
    if (res.type != kJmpFail) {
      return res;
    }

    return {.type = kJmpFail};
  };

  auto handleInstr = [&](AddrAndIdx i) {
    auto op = allOpcode[i.idx];

    JmpRes jmp = doReplace(i);

    totOpType[op.type]++;
    totJmpType[jmp.type]++;

    if (verbose) {
      printInstr(i, jmp);
    }

    auto stubAddr = E.code.size();
    auto relocIdx = E.relocs.size();
    auto stype = kJmpTypeStrs[jmp.type];

    if (jmp.type == kPushJmp) {
      modifyPushFJmp(jmp.r1, jmp.r0);
      modifyPushRspJmp(jmp.r0, stubAddr);
      emitPushJmpStub(jmp.r0, jmp.r1);
    } else if (jmp.type == kPushJmp2) {
      modifyShortJmp(jmp.r1, jmp.r0, 1);
      modifyPushRspJmp(jmp.r0, stubAddr);
      emitPushJmpStub(jmp.r0, jmp.r1, false);
    } else if (jmp.type == kDirectJmp) {
      auto i = instOccurMap.find(instHash(jmp.r0.i));
      assert(i != instOccurMap.end());
      int fn = i->second;
      modifyCall(jmp.r0, fn);
    } else if (jmp.type == kCombineJmp) {
      modifyLongJmp(jmp.r0, stubAddr);
      emitDirectJmpStub(jmp.r0);
    }

    if (debug) {
      auto D = [&](const char *s, ArrayRef<uint8_t> buf, uint64_t va) {
        disamInstrBuf(fmt("%s_%s", stype, s), buf, va);
      };
      auto D2 = [&](const char *s, const uint8_t *base, AddrRange r) {
        D(s, {base+r.i.addr,r.size}, vaddr(r.i.addr));
      };
      auto oldp = instrBuf.data();
      auto newp = newText.data();
      if (debugOnlyBefore) {
        D2("inst0_before", oldp, jmp.r0);
        D2("inst1_before", oldp, jmp.r1);
      } else {
        D2("inst0_before", oldp, jmp.r0);
        D2("inst0_after", newp, jmp.r0);
        D2("inst1_before", oldp, jmp.r1);
        D2("inst1_after", newp, jmp.r1);
        D("stub", E.codeSlice(stubAddr), stubAddr);
      }
    }
  };

  auto forAllInstr0 = [&](std::function<void(AddrAndIdx,const Section&)> fn) {
    for (auto sec: allSecs) {
      if (sec.startIdx == -1) {
        continue;
      }
      uint64_t addr = sec.start;
      for (int i = sec.startIdx; i < sec.endIdx; i++) {
        fn({.addr = addr, .idx = i}, sec);
        addr += allOpcode[i].size;
      }
    }
  };

  auto forAllInstr = [&](std::function<void(AddrAndIdx)> fn) {
    forAllInstr0([&](AddrAndIdx i, const Section& sec) {
      fn(i);
    });
  };

  auto markAllJmp = [&]() {
    for (auto sec: allSecs) {
      if (sec.startIdx == -1) {
        continue;
      }

      std::vector<uint64_t> tos;
      uint64_t addr = sec.start;
      for (int i = sec.startIdx; i < sec.endIdx; addr += allOpcode[i].size, i++) {
        auto &op = allOpcode[i];
        if (op.bad) {
          continue;
        }
        int32_t off;
        if (op.op == X86::JCC_1 || op.op == X86::JMP_1) {
          off = *(int8_t*)(instrBuf.data()+addr+op.size-1);
        } else if (op.op == X86::JCC_4 || op.op == X86::JMP_4) {
          off = *(int32_t*)(instrBuf.data()+addr+op.size-4);
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
        outsfmt("markjmp %d/%d\n", n, tos.size());
      }
    }
  };

  markAllJmp();

  if (forAll) {
    forAllInstr([&](AddrAndIdx i) {
      handleInstr(i);
    });
  } else if (forSingleInstr != -1) {
    forAllInstr([&](AddrAndIdx i) {
      if (vaddr(i.addr) == forSingleInstr) {
        handleInstr(i);
      }
    });
  } else {
    for (auto i: fsInstrs) {
      handleInstr(i);
    }
  }

  if (summary) {
    outs() << filename << " ";
    for (int i = 0; i < kOpTypeNr; i++) {
      outs() << kOpTypeStrs[i] << " " << totOpType[i] << " ";
    }
    for (int i = 1; i < kJmpTypeNr; i++) {
      outs() << kJmpTypeStrs[i] << " " << totJmpType[i] << " ";
    }
    outs() << "\n";
  }

  return 0;
}
