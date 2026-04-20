# bpf_loop is not needed. Our trick for eBPF loops when bpf_loop() isn't available.

I haven't seen anyone talking or using this trick. Let me know if you ever encountered it.

anyone writing eBPF programs has hit the loop problem. Before kernel 5.17, loops with complex bodies were painful — the verifier needs to prove loop termination and track state across every iteration. The more code inside the loop, the faster the verifier state explodes.

The common workarounds were:
- **Bounded loops with `#pragma unroll`** — rarely sometimes, the verifier still inlines every iteration. A 10-iteration loop with a complex body can easily blow past the complexity limit.
- **Fake bounded loops** with a hard max and early `break` — same problem, the verifier still walks through every possible path.
- **tail calls** - you can use tail calls as a `for(i < TAIL_MAX)`. However TAIL_MAX is 32. On top of that tail calls might not be a possibility in your program logic.

## bpf_loop (Kernel 5.17+)

Kernel 5.17 introduced `bpf_loop`, a helper that takes a callback function and calls it N times. Here's the actual kernel implementation:

```c
BPF_CALL_4(bpf_loop, u32, nr_loops, void *, callback_fn, void *, callback_ctx,
           u64, flags)
{
    bpf_callback_t callback = (bpf_callback_t)callback_fn;
    u64 ret;
    u32 i;

    if (flags)
        return -EINVAL;
    if (nr_loops > BPF_MAX_LOOPS)
        return -E2BIG;

    for (i = 0; i < nr_loops; i++) {
        ret = callback((u64)i, (u64)(long)callback_ctx, 0, 0, 0);
        /* return value: 0 - continue, 1 - stop and return */
        if (ret)
            return i + 1;
    }

    return i;
}
```

It's dead simple — a C for-loop that calls your callback. The trick is that the kernel manages the iteration, so the verifier only needs to verify the callback once, independently. The loop complexity disappears.

## The Same Trick, Without the Helper (Kernel 5.10+)

But what if you're targeting kernels between 5.10 and 5.17? That's a significant range — RHEL 9, AlmaLinux 9, Ubuntu 22, and many LTS distros ship kernels in that versios range.

Starting from kernel 5.10, BPF supports mixing tail calls and functions.<br>
**functions (sub-programs)** — functions are non-inlined functions, that are treated by the verifier as a new bpf program. Functions have more to it, but for this post the important thing to know is that a function has its own instruction count, and doesn't effect the instruction count of the caller.

This is the key insight: if you extract the loop body into a separate BPF function, the verifier handles the function body independently. The calling program just sees a simple bounded loop with a function call — no complexity explosion.

This is exactly what `bpf_loop` does internally, except you're doing it yourself in BPF code instead of relying on the API.

## Example: Side by Side

Here's a minimal example with both approaches — same hook, same callback, different loop mechanism:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LOOP_COUNT 100

static __noinline long loop_body(u64 index, void *ctx)
{
    if (ctx)
    {
        bpf_printk("index: %d\n", index);
        return 0;
    }
    return 1;
}

// Approach 1: bpf_loop helper (kernel 5.17+)
SEC("lsm/path_chmod")
int BPF_PROG(probe_bpf_loop, const struct path *path, umode_t mode)
{
    int sum = 0;
    bpf_loop(LOOP_COUNT, loop_body, &sum, 0);
    bpf_printk("sum: %d\n", sum);
    return 0;
}

// Approach 2: manual bounded loop + __noinline function (kernel 5.12+)
SEC("lsm/path_chmod")
int BPF_PROG(probe_manual_loop, const struct path *path, umode_t mode)
{
    int sum = 0;
    for (int i = 0; i < LOOP_COUNT; i++)
    {
        loop_body((u64)i, &sum);
    }
    bpf_printk("sum: %d\n", sum);
    return 0;
}
```

Both probes call the exact same `loop_body` function. The only difference is who manages the iteration.

## Comparing the BPF Assembly (bytecode)

Compile with `-O2`:

```bash
clang -D__TARGET_ARCH_x86 -I<path_to_vmlinux_h> \
  -O2 -g -target bpf -Wall -fno-stack-protector \
  -c loop_comparison.bpf.c -o loop_comparison.bpf.o
```

Dump the BPF bytecode:

```bash
llvm-objdump -d --no-show-raw-insn loop_comparison.bpf.o
```

The full output — `loop_body` (shared), then both probes:

```
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
```

`probe_bpf_loop` does one `call 0xb5` — the kernel iterates 100 times internally.  
`probe_manual_loop` has a tight 6-instruction loop: setup args → call subprogram → increment → branch back.

### Verdict

16 vs 15 instructions. Both call the same `loop_body` as a BPF subprogram. Both avoid verifier complexity explosion. The efficiency at runtime is essentially identical — one does an API call, the other does a direct BPF-to-BPF subprogram call with a branch. For practical purposes, the performance difference is negligible.

Using this technique we were able to use loops with complex bodies and even nested loop on kernels under 5.17. It completely changed our approach to what is possible in the eBPF echosystem. 

The `bpf_loop` helper is cleaner and is the right choice when your minimum kernel is 5.17+. But if you need to support 5.12–5.16, the manual approach with `__noinline` functions gives you the same result — because it's fundamentally the same trick.

**Note:** The compiler's behavior depends on the iteration count, optimization level, etc. You may see different bytecode if you change things.  
For example, when I used `LOOP_COUNT = 5`, the compiler unrollred the manual loop instead.