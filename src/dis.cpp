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

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "elf.h"

using namespace llvm;

template <typename... Types>
std::string formatStr(const char *fmt, Types... args) {
  ssize_t n = snprintf(NULL, 0, fmt, args...);
  char buf[n+1];
  snprintf(buf, n+1, fmt, args...);
  return std::string(buf);
}

int main(int argc, char **argv) {
  std::vector<std::string> args;
  std::vector<std::string> args0;
  bool verbose = false;
  bool forAll = false;
  int forSingleInstr = -1;
  bool summary = false;
  bool debug = false;
  bool printJmp = false;

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
    if (o == "-j") {
      printJmp = true;
      continue;
    }
    if (o == "-d") {
      debug = true;
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
    outs() << formatStr("filesize %lx e_ehsize %d e_phoff %lx size %d e_shoff %lx size %d\n",
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
    outs() << formatStr("load off %lx size %lx\n", phX->p_offset, phX->p_filesz);
    outs() << formatStr("load end %lx stub start %lx\n", vaddrLoadEnd, vaddrStubStart);
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
      outs() << formatStr("section %s %lx %lx\n", name.c_str(), vaddr(start), vaddr(end));
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
      hex += formatStr("%.2X", buf[i]);
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
    std::string s = formatStr("%d,n=%d[", inst.getOpcode(), n);
    for (int i = 0; i < n; i++) {
      auto op = inst.getOperand(i);
      if (op.isReg()) {
        s += formatStr("r%d", op.getReg());
      } else if (op.isImm()) {
        s += formatStr("i%d", op.getImm());
      }
      if (i < n-1) {
        s += ",";
      }
    }
    s += "]";
    return s;
  };

  /*
    M: [BaseReg, ScaleAmt, IndexReg, Disp, Segment]
    MRM0m/MRM7m -> M,Imm
    MRMDestMem -> M,Reg
    MRMSrcMem -> Reg,M
  */

  struct InstrInfo {
    int mIdx;
    int immIdx;
    int regIdx;
    int regIdx1;
  };

  #define panicUnsupportedInstr(inst) {\
    auto s0 = instrDisStr(inst); \
    auto s1 = instrDumpStr(inst); \
    auto s2 = IP->getOpcodeName(inst.getOpcode()).str(); \
    fprintf(stderr, "%s:%d: unsupported instr %s %s %s\n", __FILE__, __LINE__, s2.c_str(), s0.c_str(), s1.c_str()); \
    exit(-1); \
    __builtin_unreachable(); \
  }

  auto getInstrInfo = [&](const MCInst &inst) -> InstrInfo {
    auto n = inst.getNumOperands();
    #define C(op) case X86::op: 
    #define R(n_, m, imm, r0, r1) if (n != n_) panicUnsupportedInstr(inst); \
      return {.mIdx = m, .immIdx = imm, .regIdx = r0, .regIdx1 = r1};

    switch (inst.getOpcode()) {
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
      R(7, 2, -1, 0, 1)

      C(CMP64rm)
      C(MOV32rm)
      C(MOV64rm)
      C(MOV8rm)
      C(LEA64r)
      C(MOVSX64rm32)
      R(6, 1, -1, 0, -1)

      C(CMP64mr)
      C(MOV32mr)
      C(MOV64mr)
      C(MOV8mr)
      R(6, 0, -1, 5, -1)
    }

    panicUnsupportedInstr(inst);

    #undef C
    #undef X
  };

  auto instrUsedRegMask = [&](const MCInst &inst) -> unsigned {
    unsigned mask = 0;
    auto info = getInstrInfo(inst);

    auto add = [&](int oi) {
      auto o = inst.getOperand(oi);
      if (!o.isReg()) {
        panicUnsupportedInstr(inst);
      }
      unsigned r = o.getReg();
      if (r == 0) {
        return;
      }
      unsigned sr = superReg(r);
      int i = gpRegIdx(sr);
      if (i == -1) {
        panicUnsupportedInstr(inst);
      }
      mask |= 1<<i;
    };

    if (info.mIdx != -1) {
      add(info.mIdx + 0);
      add(info.mIdx + 2);
    }

    if (info.regIdx != -1) {
      add(info.regIdx);
    }

    return mask;
  };

  using SmallCode = SmallString<256>;

  auto disamInstrBuf = [&](const std::string &prefix, ArrayRef<uint8_t> buf) {
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
      outs() << prefix << " " << formatStr("%lx", addr) << 
        " " << dis << 
        " " << dump << 
        " " << instrHexStr(buf.slice(addr,  Size)) << 
        "\n";
      addr += Size;
    }
  };

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

  auto adjustImm = [&](MCInst &inst, uint64_t backAddr, bool noRsp) {
    if ([&]() -> bool {
      if (inst.getOpcode() == X86::JCC_4) {
        return true;
      }
      auto info = getInstrInfo(inst);
      if (info.mIdx != -1) {
        auto reg = superReg(inst.getOperand(info.mIdx).getReg());
        if (noRsp && reg == X86::RSP) { 
          panicUnsupportedInstr(inst);
        }
        if (reg == X86::RIP) {
          return true;
        }
      }
      return false;
    }()) {
      E.relocStub(-int32_t(backAddr), kRelRIP, true);
    }
  };

  auto emitTlsOpStub = [&](MCInst &inst1, uint64_t backAddr1) {
    /*
      push %tmp // save tmp
      lea inst1.mem, %tmp // get orig value
      push %rax; call get_fs; lea (%rax,%tmp), %tmp; pop %rax // add fs
      inst1.op inst1.reg, (%tmp) // modified instr
      pop %tmp // recovery tmp
    */
    auto info = getInstrInfo(inst1);
    if (info.mIdx == -1) {
      panicUnsupportedInstr(inst1);
    }
    unsigned used = instrUsedRegMask(inst1);
    int ti = gpFindFreeReg(instrUsedRegMask(inst1));
    if (ti == -1) {
      panicUnsupportedInstr(inst1);
    }
    unsigned tmpReg = gpRegs[ti];

    E.emit(MCInstBuilder(X86::PUSH64r).addReg(tmpReg));

    MCInst lea;
    lea.setOpcode(X86::LEA64r);
    lea.addOperand(MCOperand::createReg(tmpReg));
    for (int i = 0; i < 5; i++) {
      lea.addOperand(inst1.getOperand(info.mIdx+i));
    }
    lea.getOperand(5).setReg(0);
    E.emit(lea);
    adjustImm(lea, backAddr1, true);

    E.emit(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX));
    E.emit(MCInstBuilder(X86::CALL64pcrel32).addImm(0));
    E.relocStub(0, kRelCall);
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

  auto emitDirectJmpStub = [&](MCInst &inst0, uint64_t backAddr0) {
    E.emit(inst0);
    adjustImm(inst0, backAddr0, false);
    E.emit(MCInstBuilder(X86::JMP_4).addImm(128));
    E.relocStub(backAddr0);
  };

  auto emitPushJmpStub = [&](
    MCInst &inst0, uint64_t backAddr0, // normal
    MCInst &inst1, uint64_t backAddr1  // tls
  ) {
    /*
      push %rax; pushfq // save rax,eflags
      mov 16(%rsp),%rax; cmp (%rsp),%rax // check jmpval == eflags
      je 1f
    */
    E.emit(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX));
    E.emit(MCInstBuilder(X86::PUSHF64));
    E.emit(MCInstBuilder(X86::MOV64rm)
      .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(16).addReg(0));
    E.emit(MCInstBuilder(X86::CMP64rm)
      .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(0).addReg(0));
    E.emit(MCInstBuilder(X86::JCC_1).addImm(0).addImm(4));
    auto jmp1Off = E.code.size();
    auto jmp1Fix = (uint8_t *)&E.code[E.code.size()-1];

    auto recovery = [&]() {
      E.emit(MCInstBuilder(X86::POPF64));
      E.emit(MCInstBuilder(X86::POP64r).addReg(X86::RAX));
      E.emit(MCInstBuilder(X86::LEA64r)
        .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(8).addReg(0));
    };

    /*
      popfd; pop %rax; lea 8(%rsp),%rsp // recover rax,eflags,rsp
      normal_op
      jmp back0
    */
    recovery();
    emitDirectJmpStub(inst0, backAddr0);

    /*
    1:
      popfd; pop %rax; lea 8(%rsp),%rsp // recover rax,eflags,rsp
      tls_op
      jmp back1
    */
    auto label1Off = E.code.size();
    *jmp1Fix = int8_t(label1Off - jmp1Off);
    recovery();
    emitTlsOpStub(inst1, backAddr1);
    E.emit(MCInstBuilder(X86::JMP_4).addImm(128));
    E.relocStub(backAddr1);
  };

  auto emitShortJmpNop = [&](uint64_t addr0, uint64_t addr1, uint64_t size1) {
    while (size1 > 2) {
      newText[addr1] = 0xf2; // repne
      addr1++;
      size1--;
    }
    newText[addr1] = 0x74; // jmp
    newText[addr1+1] = uint8_t(int8_t(int64_t(addr1+2)-int64_t(addr0)));
  };

  auto emitLongJmpNop = [&](uint64_t addr, uint64_t size, uint64_t stubAddr) {
    while (size > 5) {
      newText[addr] = 0xf2; // repne
      addr++;
      size--;
    }
    newText[addr] = 0xe9; // jmp
    E.relocText(addr+1, stubAddr);
  };

  auto modifyPushJmpInst0 = [&](uint64_t addr, uint64_t size, uint64_t stubAddr) {
    newText[addr] = 0x54; // push %rsp
    emitLongJmpNop(addr+1, size-1, stubAddr);
  };

  auto modifyPushJmpInst1 = [&](uint64_t addr0, uint64_t addr1, uint64_t size1) {
    newText[addr1] = 0x9c; // pushf
    emitShortJmpNop(addr0, addr1+1, size1-1);
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
    kNoopJmp,
    kCombineJmp,
    kJmpFail,
    kJmpTypeNr,
  };

  const char *kJmpTypeStrs[] = {
    "no_jmp",
    "ignore_jmp",
    "direct_jmp",
    "push_jmp",
    "noop_jmp",
    "combine_jmp",
    "jmp_fail",
  };

  struct OpcodeAndSize {
    uint16_t op;
    uint8_t size;
    char used:1;
    char type:4;
  } __attribute__((packed, aligned(4)));

  struct AddrAndIdx {
    uint64_t addr;
    int idx;
  };

  struct JmpRes {
    int type;
    AddrAndIdx i;
  };

  std::vector<OpcodeAndSize> allOpcode;

  auto forInstrAround = [&](AddrAndIdx ai, int maxDist, std::function<bool(AddrAndIdx i)> fn) -> bool {
    auto addr = ai.addr;
    for (int i = ai.idx; i > 0 && ai.addr-addr < maxDist; i--) {
      if (i != ai.idx) {
        if (fn({.addr = addr, .idx = i})) {
          return true;
        }
      }
      addr -= allOpcode[i-1].size;
    }
    addr = ai.addr;
    for (int i = ai.idx; i < allOpcode.size() && addr-ai.addr < maxDist; i++) {
      if (i != ai.idx) {
        if (fn({.addr = addr, .idx = i})) {
          return true;
        }
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

    switch (Inst.getOpcode()) {
      case X86::NOOP:
      case X86::NOOPL:
      case X86::NOOPW:
        return {.op = X86::NOOP, .size = (uint8_t)Size};
    }

    auto &idesc = MII->get(Inst.getOpcode());
    char type = kNormalOp;
    char used = 0;

    if (Inst.getOpcode() == X86::SYSCALL) {
      type = kSyscall;
      used = 1;
    } else {
      for (int i = 0; i < idesc.NumOperands; i++) {
        auto opinfo = idesc.OpInfo[i];
        if (opinfo.RegClass == X86::SEGMENT_REGRegClassID) {
          if (Inst.getOperand(i).getReg() == X86::FS) {
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

  for (auto &sec: allSecs) {
    sec.startIdx = allOpcode.size();
    for (uint64_t addr = sec.start; addr < sec.end; ) {
      auto op = decodeInstr(addr);

      if (op.op == X86::NOOP) {
        auto newaddr = addr + op.size;
        while (newaddr < instrBuf.size()) {
          auto op = decodeInstr(newaddr);
          if (op.op != X86::NOOP) {
            break;
          }
          newaddr += op.size;
        }

        int n = newaddr - addr;
        while (n > 5) {
          allOpcode.push_back({.op = X86::NOOP, .size = 5});
          n -= 5;
        }
        allOpcode.push_back({.op = X86::NOOP, .size = (uint8_t)n});
        addr = newaddr;
        continue;
      }

      auto idx = (int)allOpcode.size();

      if (op.op == X86_BAD) {
        if (badRanges.size() == 0 ||
            addr - badRanges[badRanges.size()-1].addr > BadMaxDiff)
        {
          badRanges.push_back({.addr = addr, .idx = idx});
          badRanges.push_back({.addr = addr+op.size, .idx = idx+1});
        } else {
          badRanges[badRanges.size()-1] = {.addr = addr+op.size, .idx = idx+1};
        }
      }

      if (op.type >= kTlsStackCanary) {
        fsInstrs.push_back({.addr = addr, .idx = idx});
      }

      allOpcode.push_back(op);
      addr += op.size;
    }
    sec.endIdx = allOpcode.size();
  }

  for (auto bi: badRanges) {
    forInstrAround(bi, BadMaxDiff, [&](AddrAndIdx i) -> bool {
      allOpcode[i.idx].used = 1;
      return false;
    });
  }

  if (debug) {
    outs() << formatStr("bad ranges %lu:\n", badRanges.size());
    for (int i = 0; i < badRanges.size(); i += 2) {
      auto start = badRanges[i];
      auto end = badRanges[i+1];
      outs() << formatStr("addr %lx %lx len %lu n %d\n", vaddr(start.addr), vaddr(end.addr),
        end.addr-start.addr, end.idx-start.idx);
    }
  }

  auto inBadRange = [&](uint64_t addr) -> bool {
    auto upper = std::upper_bound(badRanges.begin(), badRanges.end(), addr, 
      [](uint64_t addr, const AddrAndIdx &i) -> bool {
        return i.addr > addr;
      });
    if (upper == badRanges.end()) {
      return false;
    }
    auto i = std::distance(badRanges.begin(), upper);
    if (i%2 != 0) {
      return true;
    }
    if (i > 0 && addr-badRanges[i-1].addr < BadMaxDiff) {
      return true;
    }
    if (badRanges[i].addr-addr < BadMaxDiff) {
      return true;
    }
    return false;
  };

  /*
  ADD64rm CMP32mi8 CMP64mi8 CMP64mr CMP64rm
  CMP8mi MOV32mi MOV32mr MOV32rm MOV64mi32 MOV64mr
  MOV64rm MOV8mi MOV8mr MOV8rm MOVSX64rm32 SUB64rm
  TEST32mi XCHG32rm XOR64rm
  */

  auto formatInstHeader = [&](uint64_t addr, uint64_t size) -> std::string {
    return formatStr("%lx n=%lu ", vaddr(addr), size);
  };

  auto printInstr = [&](AddrAndIdx ai, JmpRes jmp) {
    auto op = allOpcode[ai.idx];
    auto addr = ai.addr;

    if (op.op == X86_BAD) {
      outs() << formatInstHeader(addr, op.size) << "BAD " << "\n";
      return;
    }

    MCInst Inst;
    uint64_t Size;

    if (op.op == X86::NOOP) {
      Inst.setOpcode(X86::NOOP);
      Inst.setFlags(0);
      Size = op.size;
    } else {
      DisAsm->getInstruction(Inst, Size, instrBuf.slice(addr), addr, nulls());
    }

    std::string tag = kJmpTypeStrs[jmp.type];

    if (jmp.type == kPushJmp) {
      auto rop = allOpcode[jmp.i.idx];
      std::string name = IP->getOpcodeName(rop.op).str();
      tag += formatStr(":%lu,%s,%d", rop.size, name.c_str(), std::abs((int64_t)(jmp.i.addr-addr)));
    }

    auto &idesc = MII->get(Inst.getOpcode());
    uint64_t TSFlags = idesc.TSFlags;
    uint64_t Form = TSFlags & X86II::FormMask;

    auto formStr = [](uint64_t form) -> std::string {
      #define X(x) case X86II::x: return #x;
      switch (form) {
        X(MRMDestMem)
        X(MRMSrcMem)
        X(MRM0m)
        X(MRM7m)
        default:
          return formatStr("form=%lu", form);
      }
      #undef X
    };

    outs() << formatInstHeader(addr, Size) <<
      IP->getOpcodeName(Inst.getOpcode()) <<
      " " << formStr(Form) << 
      " " << kOpTypeStrs[op.type] <<
      " " << tag << 
      " " << instrDisStr(Inst) <<
      " " << instrDumpStr(Inst) << 
      " " << instrHexStr(instrBuf.slice(addr, Size)) << 
      "\n";
  };

  int totOpType[kOpTypeNr] = {};
  int totJmpType[kJmpTypeNr] = {};

  auto debugJmpStub = [&](int jmpType, uint64_t stubAddr, int relocIdx, 
    uint64_t addr0, uint64_t size0, uint64_t addr1 = 0, uint64_t size1 = 0
  ) {
    if (!debug) {
      return;
    }
    auto stype = kJmpTypeStrs[jmpType];
    disamInstrBuf(formatStr("%s_stub", stype), E.codeSlice(stubAddr));
    disamInstrBuf(formatStr("%s_inst0_after", stype), {&newText[addr0], size0});
    if (size1) {
      disamInstrBuf(formatStr("%s_inst1_after", stype), {&newText[addr1], size1});
    }
  };

  auto opIsValid = [&](unsigned op, bool noop) -> bool {
    if (noop) {
      return op == X86::NOOP;
    }
    switch (op) {
      case X86::MOV64rm:
      case X86::MOV64mr:
      case X86::LEA64r:
      case X86::JCC_4:
      case X86::MOV32rm:
        return true;
    }
    return false;
  };

  auto findReplaceInstr = [&](AddrAndIdx i, AddrAndIdx &res, int size, bool noop) -> bool {
    return forInstrAround(i, 127, [&](AddrAndIdx i) -> bool {
      auto op = &allOpcode[i.idx];
      if (opIsValid(op->op, noop) && !op->used && op->size >= size) {
        res = i;
        return true;
      }
      return false;
    });
  };

  auto doReplace = [&](AddrAndIdx i) {
    auto op = allOpcode[i.idx];
    JmpRes jmp = {};

    [&]() {
      if (op.type == kTlsOp || op.type == kSyscall) {
        if (inBadRange(i.addr)) {
          jmp.type = kIgnoreJmp;
          return;
        }
      }

      if (op.type == kTlsOp) {
        if (op.size < 5) {
          if (findReplaceInstr(i, jmp.i, 5, true)) {
            jmp.type = kNoopJmp;
            allOpcode[jmp.i.idx].used = 1;
          } else if (findReplaceInstr(i, jmp.i, 6, false)) {
            jmp.type = kPushJmp;
            allOpcode[jmp.i.idx].used = 1;
          } else {
            jmp.type = kJmpFail;
          }
        } else {
          jmp.type = kDirectJmp;
        }
      } else if (op.type == kSyscall) {
        AddrAndIdx j = i;
        int size = 0;
        while (size < 5 && j.idx >= 0) {
          auto &op = allOpcode[j.idx];
          op.used = 1;
          size += op.size;
          j.idx--;
          j.addr -= op.size;
        }
        if (size < 5) {
          jmp.type = kJmpFail;
        } else {
          jmp.type = kCombineJmp;
          jmp.i = j;
        }
      }
    }();

    totOpType[op.type]++;
    totJmpType[jmp.type]++;

    if (printJmp) {
      if (jmp.type == kPushJmp) {
        outs() << "push_jmp_instr0:\n";
        printInstr(jmp.i, {});
      }
    }

    if (verbose) {
      printInstr(i, jmp);
    }

    if (jmp.type == kPushJmp) {
      MCInst inst0, inst1;
      uint64_t addr0 = jmp.i.addr;
      uint64_t size0;
      uint64_t addr1 = i.addr;
      uint64_t size1;

      DisAsm->getInstruction(inst0, size0, instrBuf.slice(addr0), 0, nulls());
      DisAsm->getInstruction(inst1, size1, instrBuf.slice(addr1), 0, nulls());

      auto stubAddr = E.code.size();
      auto relocIdx = E.relocs.size();

      emitPushJmpStub(inst0, addr0+size0, inst1, addr1+size1);
      modifyPushJmpInst0(addr0, size0, stubAddr);
      modifyPushJmpInst1(addr0, addr1, size1);

      debugJmpStub(jmp.type, stubAddr, relocIdx, addr0, size0, addr1, size1);

    } else if (jmp.type == kNoopJmp) {
      MCInst inst0, inst1;
      uint64_t addr0 = jmp.i.addr;
      uint64_t size0 = 5;
      uint64_t addr1 = i.addr;
      uint64_t size1 = allOpcode[i.idx].size;

      DisAsm->getInstruction(inst1, size1, instrBuf.slice(addr1), 0, nulls());

      auto stubAddr = E.code.size();
      auto relocIdx = E.relocs.size();

      emitDirectJmpStub(inst1, addr1+size1);
      emitLongJmpNop(addr0, size0, stubAddr);
      emitShortJmpNop(addr0, addr1, size1);

      // debugJmpStub(jmp.type, stubAddr, relocIdx, addr0, size0);

    } else if (jmp.type == kDirectJmp) {
      MCInst inst0;
      uint64_t addr0 = i.addr;
      uint64_t size0;

      DisAsm->getInstruction(inst0, size0, instrBuf.slice(addr0), 0, nulls());

      auto stubAddr = E.code.size();
      auto relocIdx = E.relocs.size();

      emitDirectJmpStub(inst0, addr0+size0);
      emitLongJmpNop(addr0, size0, stubAddr);

      debugJmpStub(jmp.type, stubAddr, relocIdx, addr0, size0);
    }
  };

  auto forAllInstr = [&](std::function<void(AddrAndIdx)> fn) {
    for (auto sec: allSecs) {
      if (sec.startIdx == -1) {
        continue;
      }
      if (debug) {
        outs() << formatStr("disam section %s\n", sec.name.c_str());
      }
      uint64_t addr = sec.start;
      for (int i = sec.startIdx; i < sec.endIdx; i++) {
        fn({.addr = addr, .idx = i});
        addr += allOpcode[i].size;
      }
    }
  };

  if (forAll) {
    forAllInstr([&](AddrAndIdx i) {
      doReplace(i);
    });
  } else if (forSingleInstr != -1) {
    forAllInstr([&](AddrAndIdx i) {
      if (vaddr(i.addr) == forSingleInstr) {
        doReplace(i);
      }
    });
  } else {
    for (auto i: fsInstrs) {
      doReplace(i);
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
