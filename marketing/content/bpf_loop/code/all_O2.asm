
loop_comparison_O2.bpf.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <loop_body>:
       0:	r3 = r1
       1:	r0 = 0x1
       2:	if r2 == 0x0 goto +0x5 <LBB2_2>
       3:	r1 = 0x9 ll
       5:	r2 = 0xb
       6:	call 0x6
       7:	r0 = 0x0

0000000000000040 <LBB2_2>:
       8:	exit

Disassembly of section lsm/path_chmod:

0000000000000000 <probe_bpf_loop>:
       0:	r1 = 0x0
       1:	*(u32 *)(r10 - 0x4) = r1
       2:	r3 = r10
       3:	r3 += -0x4
       4:	r1 = 0x64
       5:	r2 = 0x0 ll
       7:	r4 = 0x0
       8:	call 0xb5
       9:	r3 = *(u32 *)(r10 - 0x4)
      10:	r1 = 0x0 ll
      12:	r2 = 0x9
      13:	call 0x6
      14:	r0 = 0x0
      15:	exit

0000000000000080 <probe_manual_loop>:
      16:	r6 = 0x0
      17:	*(u32 *)(r10 - 0x4) = r6

0000000000000090 <LBB1_1>:
      18:	r2 = r10
      19:	r2 += -0x4
      20:	r1 = r6
      21:	call -0x1
      22:	r6 += 0x1
      23:	if r6 != 0x64 goto -0x6 <LBB1_1>
      24:	r3 = *(u32 *)(r10 - 0x4)
      25:	r1 = 0x14 ll
      27:	r2 = 0x9
      28:	call 0x6
      29:	r0 = 0x0
      30:	exit
