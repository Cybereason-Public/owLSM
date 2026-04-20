
loop_comparison_O0.bpf.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <loop_body>:
       0:	*(u64 *)(r10 - 0x10) = r1
       1:	*(u64 *)(r10 - 0x18) = r2
       2:	r1 = *(u64 *)(r10 - 0x18)
       3:	if r1 != 0x0 goto +0x4 <LBB2_2>
       4:	goto +0x0 <LBB2_1>

Disassembly of section lsm/path_chmod:

0000000000000000 <probe_bpf_loop>:
       0:	*(u64 *)(r10 - 0x28) = r1
       1:	r3 = *(u64 *)(r10 - 0x28)
       2:	r2 = *(u64 *)(r3 + 0x0)
       3:	r1 = *(u64 *)(r3 + 0x8)
       4:	*(u64 *)(r10 - 0x8) = r3
       5:	*(u64 *)(r10 - 0x10) = r2
       6:	*(u16 *)(r10 - 0x12) = r1
       7:	r4 = 0x0
       8:	*(u64 *)(r10 - 0x30) = r4
       9:	*(u32 *)(r10 - 0x18) = r4
      10:	r2 = 0x0 ll
      12:	r1 = 0xa
      13:	r3 = r10
      14:	r3 += -0x18
      15:	call 0xb5
      16:	r3 = *(u32 *)(r10 - 0x18)
      17:	r1 = 0x0 ll
      19:	r2 = 0x9
      20:	call 0x6
      21:	r1 = r0
      22:	r0 = *(u64 *)(r10 - 0x30)
      23:	*(u64 *)(r10 - 0x20) = r1
      24:	exit
