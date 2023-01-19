
LLVM=/src/llvm-src/llvm

gen() {
  filename=$1
  shift
  llvm-tblgen -I$LLVM/include -I$LLVM/lib/Target/X86 $LLVM/lib/Target/X86/X86.td $* >$filename
}

cp /src/llvm-src/llvm/lib/Target/X86/MCTargetDesc/*.h .
gen X86GenInstrInfo.inc -gen-instr-info -instr-info-expand-mi-operand-info=0
gen X86GenMnemonicTables.inc -gen-x86-mnemonic-tables -asmwriternum=1
gen X86GenRegisterInfo.inc -gen-register-info
gen X86GenSubtargetInfo.inc -gen-subtarget
