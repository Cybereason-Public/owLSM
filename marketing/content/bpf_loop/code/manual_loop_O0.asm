
loop_comparison_O0.bpf.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <loop_body>:
       0:	*(u64 *)(r10 - 0x10) = r1
       1:	*(u64 *)(r10 - 0x18) = r2
       2:	r1 = *(u64 *)(r10 - 0x18)
       3:	if r1 != 0x0 goto +0x4 <LBB2_2>
       4:	goto +0x0 <LBB2_1>

Disassembly of section lsm/path_chmod:

00000000000000c8 <probe_manual_loop>:
      25:	*(u64 *)(r10 - 0x30) = r1
      26:	r3 = *(u64 *)(r10 - 0x30)
      27:	r2 = *(u64 *)(r3 + 0x0)
      28:	r1 = *(u64 *)(r3 + 0x8)
      29:	*(u64 *)(r10 - 0x8) = r3
      30:	*(u64 *)(r10 - 0x10) = r2
      31:	*(u16 *)(r10 - 0x12) = r1
      32:	r1 = 0x0
      33:	*(u32 *)(r10 - 0x18) = r1
      34:	*(u32 *)(r10 - 0x1c) = r1
      35:	goto +0x0 <LBB1_1>
