# bpf_loop vs Manual Loop - BPF Assembly Comparison

## Compile

```bash
cd marketing/content/bpf_loop/code

# With -O2
clang -D__TARGET_ARCH_x86 -I$(pwd)/../../../../src/Kernel \
  -O2 -g -target bpf -Wall -Wno-unused-function -fno-stack-protector \
  -c loop_comparison.bpf.c -o loop_comparison_O2.bpf.o

# With -O0
clang -D__TARGET_ARCH_x86 -I$(pwd)/../../../../src/Kernel \
  -O0 -g -target bpf -Wall -Wno-unused-function -fno-stack-protector \
  -c loop_comparison.bpf.c -o loop_comparison_O0.bpf.o
```

## Dump a specific probe to a file

```bash
# bpf_loop probe
llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=probe_bpf_loop,loop_body \
  loop_comparison_O2.bpf.o > bpf_loop_O2.asm

# manual loop probe
llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=probe_manual_loop,loop_body \
  loop_comparison_O2.bpf.o > manual_loop_O2.asm

# same for -O0
llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=probe_bpf_loop,loop_body \
  loop_comparison_O0.bpf.o > bpf_loop_O0.asm

llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=probe_manual_loop,loop_body \
  loop_comparison_O0.bpf.o > manual_loop_O0.asm
```

## Dump everything at once

```bash
llvm-objdump -d --no-show-raw-insn loop_comparison_O2.bpf.o > all_O2.asm
llvm-objdump -d --no-show-raw-insn loop_comparison_O0.bpf.o > all_O0.asm
```
