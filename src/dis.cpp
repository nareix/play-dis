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

#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

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
  bool verbose = false;
  bool forAll = false;
  bool summary = false;
  bool debug = false;
  bool printJmp = false;

  for (int i = 1; i < argc; i++) {
    std::string o = argv[i];
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

  uint8_t *faddr = (uint8_t *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
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

  Elf64_Phdr *phX = NULL;
  uint8_t *phStart = (uint8_t *)eh + eh->e_phoff;
  for (int i = 0; i < eh->e_phnum; i++) {
    Elf64_Phdr *ph = (Elf64_Phdr *)(phStart + eh->e_phentsize*i);
    if (ph->p_type == PT_LOAD) {
      if (ph->p_flags & PF_X) {
        phX = ph;
        break;
      }
    }
  }
  if (debug) {
    outs() << formatStr("load off %lx size %lx\n", phX->p_offset, phX->p_filesz);
  }

  ArrayRef<uint8_t> instrBuf((uint8_t *)eh + phX->p_offset, phX->p_filesz);
  auto vaddr = [&](uint64_t addr) -> uint64_t {
    return addr + phX->p_vaddr;
  };

  struct Section {
    uint64_t start, end;
    std::string name;
    int startIdx, endIdx;
  };
  std::vector<Section> xsecs;
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
    xsecs.push_back({.start = addr, .end = end, .name = name, .startIdx = -1});
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
    X86::RAX, X86::RCX, X86::RDX, X86::RBX,
    X86::RSP, X86::RBP, X86::RSI, X86::RDI,
    X86::R8, X86::R9, X86::R10, X86::R11,
    X86::R12, X86::R13, X86::R14, X86::R15,
  };

  auto gpRegIdx = [&](unsigned reg) -> int {
  };

  auto superReg = [&](unsigned reg) -> unsigned {
    auto super = reg;
    for (MCSuperRegIterator i(reg, MRI.get()); i.isValid(); ++i) {
      super = *i;
    }
    return super;
  };

  auto instrDisStr = [&](const MCInst &Inst) -> std::string {
    Str->emitInstruction(Inst, *STI);
    auto r = ss.slice(0, ss.size()-1).str();
    ss.clear();
    return r;
  };

  auto instrDumpStr = [&](const MCInst &Inst) -> std::string {
    std::string is;
    raw_string_ostream ois(is);
    Inst.dump_pretty(ois);
    return is;
  };

  using SmallCode = SmallString<256>;

  auto disamInstrBuf = [&](const SmallCode &code) {
    ArrayRef<uint8_t> buf((uint8_t *)code.data(), code.size());
    MCInst Inst;
    uint64_t Size;
    for (int addr = 0; addr < buf.size(); ) {
      auto r = DisAsm->getInstruction(Inst, Size, buf.slice(addr), addr, nulls());
      if (r != MCDisassembler::DecodeStatus::Success) {
        addr++;
        continue;
      }
      std::string hex;
      for (int i = addr; i < addr+Size; i++) {
        hex += formatStr("%.2X ", buf[i]);
      }
      outs() << formatStr("%lx", addr) << instrDisStr(Inst)
        << " [ " << hex << "] " << instrDumpStr(Inst) << "\n";
      addr += Size;
    }
  };

  auto emitPushJmpStub = [&](SmallCode &code) {
    raw_svector_ostream vcode(code);
    SmallVector<MCFixup, 4> fixups;

    /*
      push %rax; pushfq // save rax,eflags
      mov -16(%rsp),%rax; cmp (%rsp),%rax // check jmpval == eflags
      je is_tls
    */
    CE2->encodeInstruction(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX), vcode, fixups, *STI);
    CE2->encodeInstruction(MCInstBuilder(X86::PUSHF64), vcode, fixups, *STI);
    CE2->encodeInstruction(
        MCInstBuilder(X86::MOV64rm)
        .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(-16).addReg(0),
        vcode, fixups, *STI);
    CE2->encodeInstruction(
        MCInstBuilder(X86::CMP64rm)
        .addReg(X86::RAX).addReg(X86::RSP).addImm(1).addReg(0).addImm(0).addReg(0),
        vcode, fixups, *STI);
    CE2->encodeInstruction(
        MCInstBuilder(X86::JCC_1).addImm(111).addImm(4),
        vcode, fixups, *STI);

    /*
    is_orig:
      popfd; pop %rax; lea 8(%rsp),%rsp // recover rax,eflags,rsp
      orig_instr; jmp after_orig
    */
    CE2->encodeInstruction(MCInstBuilder(X86::POPF64), vcode, fixups, *STI);
    CE2->encodeInstruction(MCInstBuilder(X86::POP64r).addReg(X86::RAX), vcode, fixups, *STI);
    CE2->encodeInstruction(
        MCInstBuilder(X86::LEA64r)
        .addReg(X86::RSP).addReg(X86::RSP).addImm(1).addReg(0).addImm(8).addReg(0),
        vcode, fixups, *STI);
    CE2->encodeInstruction(MCInstBuilder(X86::JMP_4).addImm(128), vcode, fixups, *STI);

    /*
    is_tls:
      push %tmp1 // save tmp1
      lea orig_m_without_fs,%tmp1; call get_fs_value; lea (%rax),%tmp1 // get orig value
      lea 8(%rsp),%rsp; popfd; pop %rax; lea 8(%rsp),%rsp;  // recover rax,eflags,rsp
      orig_op (%tmp1),orig_reg // modified orig instr
      mov 24(%rsp),%tmp1 // recovery tmp1
      jmp after_tls
    */
    CE2->encodeInstruction(MCInstBuilder(X86::PUSH64r).addReg(X86::RAX), vcode, fixups, *STI);
  };

  enum {
    kNormalOp,
    kBadOp,
    kTlsStackCanary,
    kTlsOp,
    kTlsOpBad,
    kSyscall,
    kOpTypeNr,
  };

  const char *kOpTypeStrs[] = {
    "normal_op",
    "bad_op",
    "tls_stack_canary",
    "tls_op_normal",
    "tls_op_bad",
    "syscall",
  };

  enum {
    kNoJmp,
    kDirectJmp,
    kPushJmp,
    kNoopJmp,
    kJmpFail,
    kJmpTypeNr,
  };

  const char *kJmpTypeStrs[] = {
    "no_jmp",
    "direct_jmp",
    "push_jmp",
    "noop_jmp",
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

  auto findReplaceInstr = [&](AddrAndIdx i, AddrAndIdx &res, int size, bool noop) -> bool {
    return forInstrAround(i, 127, [&](AddrAndIdx i) -> bool {
      auto op = &allOpcode[i.idx];
      if (noop == (op->op == X86::NOOP) && !op->used && op->size >= size) {
        res = i;
        return true;
      }
      return false;
    });
  };

  auto decodeInstr = [&](uint64_t addr) -> OpcodeAndSize {
    MCInst Inst;
    uint64_t Size;
    auto S = DisAsm->getInstruction(Inst, Size, instrBuf.slice(addr), addr, nulls());

    if (S != MCDisassembler::DecodeStatus::Success) {
      return {.size = 1, .type = kBadOp};
    }

    switch (Inst.getOpcode()) {
      case X86::NOOP:
      case X86::NOOPL:
      case X86::NOOPW:
        return {.op = X86::NOOP, .size = (uint8_t)Size};
    }

    auto &idesc = MII->get(Inst.getOpcode());
    char type = 0;
    char used = 0;

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

  for (auto &sec: xsecs) {
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

      if (op.type >= kTlsStackCanary) {
        fsInstrs.push_back({.addr = addr, .idx = idx});
      }

      if (op.type == kBadOp) {
        if (badRanges.size() == 0 ||
            addr - badRanges[badRanges.size()-1].addr > BadMaxDiff)
        {
          badRanges.push_back({.addr = addr, .idx = idx});
          badRanges.push_back({.addr = addr+op.size, .idx = idx+1});
        } else {
          badRanges[badRanges.size()-1] = {.addr = addr+op.size, .idx = idx+1};
        }
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

  for (auto i: fsInstrs) {
    auto op = &allOpcode[i.idx];
    if (op->type == kTlsOp) {
      if (inBadRange(i.addr)) {
        op->type = kTlsOpBad;
      }
    }
  }

  /*
  ADD64rm CMP32mi8 CMP64mi8 CMP64mr CMP64rm
  CMP8mi MOV32mi MOV32mr MOV32rm MOV64mi32 MOV64mr
  MOV64rm MOV8mi MOV8mr MOV8rm MOVSX64rm32 SUB64rm
  TEST32mi XCHG32rm XOR64rm
  */

  /*
    M: [BaseReg, ScaleAmt, IndexReg, Disp, Segment]
    MRM0m/MRM7m -> M,Imm
    MRMDestMem -> M,Reg
    MRMSrcMem -> Reg,M
  */

  auto formatInstHeader = [&](uint64_t addr, uint64_t size) -> std::string {
    return formatStr("%lx n=%lu ", vaddr(addr), size);
  };

  auto printInstr = [&](AddrAndIdx ai, JmpRes jmp) {
    auto op = allOpcode[ai.idx];
    auto addr = ai.addr;

    if (op.type == kBadOp) {
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

    // std::string is;
    // raw_string_ostream ois(is);
    // Inst.dump_pretty(ois);
    // Str->emitInstruction(Inst, *STI);
    // auto dis = ss.slice(0, ss.size()-1);

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

    if (op.type == kTlsOp) {
      if (Form == X86II::MRM0m) {
        unsigned i = X86II::getOperandBias(idesc);
        bool HasEVEX_K = TSFlags & X86II::EVEX_K;
        bool HasVEX_4V = TSFlags & X86II::VEX_4V;
        bool HasEVEX_RC = TSFlags & X86II::EVEX_RC;
        if (HasVEX_4V)
          i++;
        if (HasEVEX_K)
          i++;
        MCOperand &SegReg = Inst.getOperand(i + X86::AddrSegmentReg);
        MCOperand &Imm = Inst.getOperand(i + X86::AddrNumOperands);
        // SegReg.setReg(0);
      }
    }

    outs() << formatInstHeader(addr, Size) << 
      IP->getOpcodeName(Inst.getOpcode()) << 
      " " << formStr(Form) << 
      " " << kOpTypeStrs[op.type] <<
      " " << tag << 
      " " << instrDisStr(Inst) <<
      " " << instrDumpStr(Inst) << "\n";
  };

  int totOpType[kOpTypeNr] = {};
  int totJmpType[kJmpTypeNr] = {};

  auto doReplace = [&](AddrAndIdx i) {
    auto op = allOpcode[i.idx];
    JmpRes jmp = {};

    if (op.type == kTlsOp) {
      if (op.size < 5) {
        if (findReplaceInstr(i, jmp.i, 5, true)) {
          jmp.type = kNoopJmp;
          allOpcode[jmp.i.idx].used = 1;
        } else if (findReplaceInstr(i, jmp.i, 6, false)) {
          jmp.type = kPushJmp;
          allOpcode[jmp.i.idx].used = 1;
          if (printJmp) {
            printInstr(jmp.i, {});
          }
        } else {
          jmp.type = kJmpFail;
        }
      } else {
        jmp.type = kDirectJmp;
      }
    }

    totOpType[op.type]++;
    totJmpType[jmp.type]++;

    if (verbose) {
      printInstr(i, jmp);
    }
  };

  if (forAll) {
    for (auto sec: xsecs) {
      if (sec.startIdx == -1) {
        continue;
      }
      if (debug) {
        outs() << formatStr("disam section %s\n", sec.name.c_str());
      }
      uint64_t addr = sec.start;
      for (int i = sec.startIdx; i < sec.endIdx; i++) {
        doReplace({.addr = addr, .idx = i});
        addr += allOpcode[i].size;
      }
    }
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

  // printf("total %d\n", n);
  // FILE *fp2 = fopen("text2", "wb+");
  // fwrite(data, 1, length, fp2);
  // fclose(fp2);

  return 0;
}

