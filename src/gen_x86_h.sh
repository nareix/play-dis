
LLVM=/src/llvm-src/llvm
TARGET=/src/llvm-x86

gen() {
  filename=$1
  shift
  llvm-tblgen -I$LLVM/include -I$LLVM/lib/Target/X86 $LLVM/lib/Target/X86/X86.td $* >$filename
}

mkdir -p $TARGET
cp $LLVM/lib/Target/X86/MCTargetDesc/*.h $TARGET
gen $TARGET/X86GenInstrInfo.inc -gen-instr-info -instr-info-expand-mi-operand-info=0
gen $TARGET/X86GenMnemonicTables.inc -gen-x86-mnemonic-tables -asmwriternum=1
gen $TARGET/X86GenRegisterInfo.inc -gen-register-info
gen $TARGET/X86GenSubtargetInfo.inc -gen-subtarget
