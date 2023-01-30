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

  auto isOpSupported = [&](unsigned op) -> bool {
    #define C(op) case X86::op: 
    #define R0(...) return true;
    #define R(...) return true;

    switch (op) {
      #include "inst.inc"
    }
    return false;

    #undef C
    #undef R
    #undef R0
  };

  auto getInstrInfo = [&](const MCInst &inst) -> InstrInfo {
    auto n = inst.getNumOperands();
    #define C(op) case X86::op: 
    #define R0(m, imm, r0, r1) return {.mIdx = m, .immIdx = imm, .regIdx = r0, .regIdx1 = r1};
    #define R(n_, m, imm, r0, r1) if (n != n_) panicUnsupportedInstr(inst); R0(m, imm, r0, r1)

    switch (inst.getOpcode()) {
      #include "inst.inc"
    }

    panicUnsupportedInstr(inst);

    #undef C
    #undef R
    #undef R0
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
    kCanaryImm,
    kDirectJmp,
    kPushJmp,
    kCombineJmp,
    kJmpFail,
    kJmpTypeNr,
  };

  const char *kJmpTypeStrs[] = {
    "no_jmp",
    "ignore_jmp",
    "canary_imm",
    "direct_jmp",
    "push_jmp",
    "combine_jmp",
    "jmp_fail",
  };

  struct OpcodeAndSize {
    uint16_t op;
    uint8_t size;
    char used:1;
    char type:3;
    char jmpto:1;
    char bad:1;
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
    int err;
  };

  std::vector<OpcodeAndSize> allOpcode;

  auto newTextRange = [&](AddrRange r) -> ArrayRef<uint8_t> {
    return {newText.data() + r.i.addr, r.size};
  };

  auto oldTextRange = [&](AddrRange r) -> ArrayRef<uint8_t> {
    return {instrBuf.data() + r.i.addr, r.size};
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
      outs() << formatStr("bad range %d addr %lx %lx len %lu n %d\n", i/2, vaddr(start.addr), vaddr(end.addr),
        end.addr-start.addr, end.idx-start.idx);
    }
  }

  auto printInstr = [&](AddrAndIdx ai, JmpRes jmp) {
    auto op = allOpcode[ai.idx];
    auto addr = ai.addr;

    std::string sep = " ";

    auto formatInstHeader = [&](uint64_t addr, uint64_t size) -> std::string {
      return formatStr("%lx%sn=%lu%s", vaddr(addr), sep.c_str(), size, sep.c_str());
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
      tag += formatStr(":%lu,%s,%d", rop.size, name.c_str(), std::abs((int64_t)(jmp.r0.i.addr-addr)));
    } else if (jmp.type == kCombineJmp) {
      tag += formatStr(":%d,%d", jmp.r0.size, jmp.r0.n);
    }

    outs() << formatInstHeader(addr, Size) <<
      IP->getOpcodeName(Inst.getOpcode()) <<
      sep << kOpTypeStrs[op.type] <<
      sep << tag << 
      sep << instrDisStr(Inst) <<
      sep << instrDumpStr(Inst) << 
      sep << instrHexStr(instrBuf.slice(addr, Size)) << 
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

  auto emitOldTlsInst = [&](AddrAndIdx i) {
    MCInst inst1;
    uint64_t size1;
    auto addr1 = i.addr;
    DisAsm->getInstruction(inst1, size1, instrBuf.slice(addr1), 0, nulls());
    auto backAddr1 = addr1+size1;

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

  auto emitOldNormalInst = [&](AddrAndIdx i) {
    MCInst inst1;
    uint64_t size1;
    auto addr1 = i.addr;
    DisAsm->getInstruction(inst1, size1, instrBuf.slice(addr1), 0, nulls());
    auto backAddr1 = addr1+size1;

    E.emit(inst1);
    adjustImm(inst1, backAddr1, false);
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

  auto emitPushJmpStub = [&](AddrRange r0, AddrRange r1) {
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
    emitOldInsts(r0);
    emitJmpBack(r0);

    /*
    1:
      popfd; pop %rax; lea 8(%rsp),%rsp // recover rax,eflags,rsp
      tls_op
      jmp back1
    */
    auto label1Off = E.code.size();
    *jmp1Fix = int8_t(label1Off - jmp1Off);
    recovery();
    emitOldInsts(r1);
    emitJmpBack(r1);
  };

  auto modifyLongJmpNop = [&](AddrRange r0, uint64_t stubAddr) {
    while (r0.size > 5) {
      newText[r0.i.addr] = 0xf2; // repne
      r0.i.addr++;
      r0.size--;
    }
    newText[r0.i.addr] = 0xe9; // jmp
    E.relocText(r0.i.addr+1, stubAddr);
  };

  auto modifyShortJmpNop = [&](AddrRange r0, AddrRange r1) {
    while (r0.size > 2) {
      newText[r0.size] = 0xf2; // repne
      r0.i.addr++;
      r0.size--;
    }
    newText[r0.i.addr] = 0x74; // jmp
    newText[r0.i.addr+1] = uint8_t(int8_t(int64_t(r0.i.addr+2)-int64_t(r1.i.addr)));
  };

  auto modifyPushRspJmpInst = [&](AddrRange r0, uint64_t stubAddr) {
    newText[r0.i.addr] = 0x54; // push %rsp
    r0.i.addr++;
    r0.size--;
    modifyLongJmpNop(r0, stubAddr);
  };

  auto modifyPushFJmpInst = [&](AddrRange r0, AddrRange r1) {
    newText[r0.i.addr] = 0x9c; // pushf
    r0.i.addr++;
    r0.size--;
    r1.i.addr++; // skip push %rsp
    modifyShortJmpNop(r0, r1);
  };

  auto singleAddrRange = [&](AddrAndIdx i) -> AddrRange {
    AddrRange r;
    r.i = i;
    r.n = 1;
    r.size = allOpcode[r.i.idx].size;
    return r;
  };

  auto replaceTls = [&](AddrAndIdx i) -> JmpRes {
    auto op = allOpcode[i.idx];

    if (op.size >= 5) {
      return {
        .type = kDirectJmp,
        .r0 = singleAddrRange(i),
      };
    }

    AddrAndIdx j;

    if (forInstrAround(i, 127, [&](AddrAndIdx i) -> int {
      auto op = allOpcode[i.idx];
      if (isOpSupported(op.op) && !op.used && op.size >= 6) {
        j = i;
        return 0;
      }
      return -1;
    })) {
      allOpcode[j.idx].used = 1;
      return {
        .type = kPushJmp,
        .r0 = singleAddrRange(j),
        .r1 = singleAddrRange(i),
      };
    }

    return {.type = kJmpFail};
  };

  auto replaceSyscall = [&](AddrAndIdx i0) -> JmpRes {
    JmpRes res;
    int err0, err1;

    uint64_t size = 0;
    for (int i = i0.idx; i > 0; i--) {
      auto &op = allOpcode[i];
      if (!isOpSupported(op.op)) {
        err0 = 1;
        break;
      }
      if (op.used && i != i0.idx) {
        err0 = 2;
        break;
      }
      size += op.size;
      if (size >= 5) {
        return {
          .type = kCombineJmp,
          .r0 = {
            .i = {
              .addr = i0.addr + allOpcode[i0.idx].size - size,
              .idx = i,
            },
            .n = i0.idx - i + 1,
            .size = size,
          },
        };
      }
      if (op.jmpto) {
        err0 = 3;
        break;
      }
    }

    for (int i = i0.idx; i < allOpcode.size(); i++) {
      auto &op = allOpcode[i];
      if (!isOpSupported(op.op)) {
        err1 = 1;
        break;
      }
      if (op.used && i != i0.idx) {
        err1 = 2;
        break;
      }
      if (op.jmpto && i != i0.idx) {
        err1 = 3;
        break;
      }
      size += op.size;
      if (size >= 5) {
        return {
          .type = kCombineJmp,
          .r0 = {
            .i = i0,
            .n = i - i0.idx + 1,
            .size = size,
          },
        };
      }
    }

    if (debug) {
      outs() << formatStr("syscall fail %d %d\n", err0, err1);
    }

    return {.type = kJmpFail};
  };

  auto doReplace = [&](AddrAndIdx i) -> JmpRes {
    auto op = allOpcode[i.idx];
    if (op.type == kTlsOp || op.type == kSyscall) {
      if (op.bad) {
        return {.type = kIgnoreJmp};
      }
    }

    if (op.type == kTlsOp) {
      return replaceTls(i);
    } else if (op.type == kSyscall) {
      return replaceSyscall(i);
    } else {
      return {.type = kNoJmp};
    }
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
      modifyPushFJmpInst(jmp.r1, jmp.r0);
      modifyPushRspJmpInst(jmp.r0, stubAddr);
      emitPushJmpStub(jmp.r0, jmp.r1);
    } else if (jmp.type == kDirectJmp) {
      modifyLongJmpNop(jmp.r0, stubAddr);
      emitDirectJmpStub(jmp.r0);
    } else if (jmp.type == kCombineJmp) {
      modifyLongJmpNop(jmp.r0, stubAddr);
      emitDirectJmpStub(jmp.r0);
    }

    if (debug) {
      if (jmp.r0.size) {
        disamInstrBuf(formatStr("%s_inst0_before", stype), oldTextRange(jmp.r0));
        disamInstrBuf(formatStr("%s_inst0_after", stype), newTextRange(jmp.r0));
      }
      if (jmp.r1.size) {
        disamInstrBuf(formatStr("%s_inst1_before", stype), oldTextRange(jmp.r1));
        disamInstrBuf(formatStr("%s_inst1_after", stype), newTextRange(jmp.r1));
      }
      if (E.code.size() != stubAddr) {
        disamInstrBuf(formatStr("%s_stub", stype), E.codeSlice(stubAddr));
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
          allOpcode[i-1].jmpto = 1;
          n++;
        }
      }

      if (debug) {
        outs() << formatStr("markjmp %d/%d\n", n, tos.size());
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
