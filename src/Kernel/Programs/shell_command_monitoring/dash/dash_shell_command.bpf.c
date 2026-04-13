/*
 * =============================================================================
 * DASH SHELL COMMAND MONITORING - eBPF UPROBE IMPLEMENTATION
 * =============================================================================
 * 
 * PURPOSE:
 *   Monitor commands typed by users in interactive dash shell sessions.
 *   Filter out noise from non-interactive shells (scripts, subshells, etc.)
 * 
 * HOW DASH WORKS (simplified):
 * 
 *   1. User types: "echo hello > file.txt; rm file.txt"
 *   
 *   2. Dash PARSER converts this into a PARSE TREE (Abstract Syntax Tree):
 *   
 *                    NSEMI (;)              <-- Root: semicolon operator
 *                   /        \
 *             NREDIR          NCMD          <-- Left: redirect wrapper, Right: simple command
 *               |               |
 *             NCMD           "rm"           <-- The actual command
 *               |              |
 *            "echo"       "file.txt"        <-- Arguments linked list
 *               |
 *           "hello"
 *               |
 *          redirect --> NTO "file.txt"     <-- The "> file.txt" part
 *   
 *   3. The list() function in parser.c RETURNS this tree
 *   
 *   4. We hook list() to intercept the tree and extract command info
 * 
 * INTERACTIVE DETECTION:
 *   - setprompt(1) is called ONLY when dash displays "$ " prompt
 *   - We hook setprompt() to mark PIDs as "interactive"
 *   - In list() hook, we skip PIDs not in our "interactive" map
 * 
 * =============================================================================
 */

 #include "allocators.bpf.h"
 #include "fill_event_structs.bpf.h"
 #include "pids_to_ignore.bpf.h"
 #include "active_shells.bpf.h"
 #include "dash_nodes.h"
 
 #define DASH_SHELL_COMMAND_EVENT
 #include "tail_calls_manager.bpf.h"
 
 struct CmdStr
 {
     char arr[CMD_MAX];
     unsigned short length;
 };

static unsigned int __attribute__((noinline)) boundedCmdIdx(int i)
{
    return (unsigned int)i & (CMD_MAX - 1);
}
 
static __always_inline void appendStr(struct CmdStr *out, const char *str)
{
    if (out->length >= CMD_MAX - 1)
        return;
    long n;
    if (out->length == 0)
        n = BPF_SNPRINTF(out->arr, sizeof(out->arr), "%s", str);
    else
        n = BPF_SNPRINTF(out->arr, sizeof(out->arr), "%s %s", out->arr, str);
    // BPF_SNPRINTF returns length INCLUDING the trailing NUL (unlike POSIX snprintf).
    // Subtract 1 so that out->length reflects the actual string length.
    if (n > 1)
        out->length = (n - 1 < CMD_MAX) ? (unsigned short)(n - 1) : CMD_MAX - 1;
}

static __always_inline void appendStrNoLeadingSpace(struct CmdStr *out, const char *str)
{
    if (out->length >= CMD_MAX - 1)
        return;
    long n;
    if (out->length == 0)
        n = BPF_SNPRINTF(out->arr, sizeof(out->arr), "%s", str);
    else
        n = BPF_SNPRINTF(out->arr, sizeof(out->arr), "%s%s", out->arr, str);
    // BPF_SNPRINTF returns length INCLUDING the trailing NUL (unlike POSIX snprintf).
    // Subtract 1 so that out->length reflects the actual string length.
    if (n > 1)
        out->length = (n - 1 < CMD_MAX) ? (unsigned short)(n - 1) : CMD_MAX - 1;
}
 
 // Global BPF function: must return scalar, and must null-check pointer args
 // (the verifier types them as mem_or_null)
__noinline int appendSeparator(struct CmdStr *out, int type)
 {
     if (!out)
         return 0;
 
     if (type == DASH_NSEMI)
     {
         // Don't add ';' after '&' — background already acts as a separator
         if (out->length > 0 && out->arr[((unsigned int)out->length - 1) & (CMD_MAX - 1)] == '&')
             return 0;
         appendStrNoLeadingSpace(out, ";");
     }
     else if (type == DASH_NAND)
         appendStr(out, "&&");
     else if (type == DASH_NOR)
         appendStr(out, "||");
 
     return 0;
 }
 
 /*
  * =============================================================================
  * BPF MAP: Tree walk state (stored in per-CPU map to avoid BPF stack overflow)
  * =============================================================================
  * 
  * Used as a DFS stack to walk dash's parse tree.
  * Each entry stores a node address and the separator to print before it.
  * Max stack depth = max leaf commands (16), proven by binary tree DFS property.
  */
 #define MAX_CHAIN_CMDS 16
 
struct WalkState
{
    unsigned long node_addrs[MAX_CHAIN_CMDS];
    int separators[MAX_CHAIN_CMDS]; // -1 = no separator, else DASH_NSEMI/NAND/NOR
    struct CmdStr cmd; // accumulated full command string (stored here to save BPF stack space)
};
 
 struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __uint(max_entries, 1);
     __type(key, unsigned int);
     __type(value, struct WalkState);
 } walk_state SEC(".maps");
 
 
 /*
  * =============================================================================
  * BPF MAP: Scratch space for print functions (avoids large stack allocations)
  * =============================================================================
  * 
  * Text buffers and struct temporaries used by printNcmdWithRedir and
  * printRedirects are stored here instead of on the BPF stack, since the
  * combined call chain would otherwise exceed the 512-byte stack limit.
  */
 struct PrintScratch
 {
     char text_buf[CMD_MAX];     // reused for cmd name, args, and redirect filenames
     char redir_sym[8];              // redirect symbol (e.g., ">", "2>", ">>")
     struct dash_nfile nf;           // current redirect node
     struct dash_narg fname_arg;     // redirect filename narg
 };
 
 struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __uint(max_entries, 1);
     __type(key, unsigned int);
     __type(value, struct PrintScratch);
 } print_scratch SEC(".maps");
 
 
/*
 * =============================================================================
 * HELPER: Sanitize dash internal control characters in narg.text buffers
 * =============================================================================
 *
 * Dash encodes quoting/expansion info as control bytes (0x81-0x88) inside
 * narg.text.  We translate them back so userspace sees the original command:
 *
 *   CTLQUOTEMARK (0x88) → single-quote character  (marks quote boundaries)
 *   CTLESC       (0x81) → drop, keep next byte    (literal escaped char)
 *   0x82-0x87           → drop                     (expansion markers)
 */
// Global BPF function: process a single character during sanitization.
// Verified once by the verifier (no loop), keeping instruction count low.
// Returns packed (r << 16 | w) on success, or -1 to signal end-of-string.
//
// Array indices use "& (CMD_MAX - 1)" masking so the verifier can
// directly prove they are in [0, 255].  Comparison-based bounds checks
// alone are not enough: the compiler may re-read the original unchecked
// register for the memory access, causing "makes mem pointer be out of bounds".
__noinline int sanitizeOneChar(struct CmdStr *cmd, int r, int w)
{
    if (!cmd)
        return -1;
    if ((unsigned int)r >= CMD_MAX || (unsigned int)w >= CMD_MAX)
        return -1;

    unsigned char c = (unsigned char)cmd->arr[boundedCmdIdx(r)];
    if (c == '\0')
        return -1;

    if (c == DASH_CTLQUOTEMARK)
    {
        cmd->arr[boundedCmdIdx(w)] = '\'';
        return ((r + 1) << 16) | (w + 1);
    }

    if (c == DASH_CTLESC)
    {
        int next_r = r + 1;
        if ((unsigned int)next_r >= CMD_MAX)
            return -1;
        if (cmd->arr[boundedCmdIdx(next_r)] != '\0')
        {
            cmd->arr[boundedCmdIdx(w)] = cmd->arr[boundedCmdIdx(next_r)];
            return ((next_r + 1) << 16) | (w + 1);
        }
        return (next_r << 16) | w;
    }

    if (c >= 0x82 && c <= 0x87)
        return ((r + 1) << 16) | w;

    cmd->arr[boundedCmdIdx(w)] = cmd->arr[boundedCmdIdx(r)];
    return ((r + 1) << 16) | (w + 1);
}

static void sanitizeNullTerminate(struct CmdStr *cmd, int w)
{
    if (w < 0 || (unsigned int)w >= CMD_MAX)
        return;
    cmd->arr[boundedCmdIdx(w)] = '\0';
}

// Inline wrapper: the loop is trivial (call + unpack per iteration),
// while the branching logic is in the global function above.
// Called once on the fully-assembled command string before sending to userspace.
static __always_inline void sanitizeDashText(struct CmdStr *cmd)
{
    int r = 0, w = 0;

    for (int i = 0; i < CMD_MAX; i++)
    {
        int result = sanitizeOneChar(cmd, r, w);
        if (result < 0)
            break;
        r = (result >> 16) & 0xFFFF;
        w = result & 0xFFFF;
    }

    sanitizeNullTerminate(cmd, w);
    cmd->length = (unsigned short)w;
}

 /*
  * =============================================================================
  * HELPER: Print file redirections (>, <, >>)
  * =============================================================================
  * 
  * Redirections in dash are stored as a linked list of nfile nodes:
  * 
  *   struct nfile {
  *       int type;        // NTO (>), NFROM (<), NAPPEND (>>), etc.
  *       node *next;      // Next redirection in chain
  *       int fd;          // File descriptor (0=stdin, 1=stdout, 2=stderr)
  *       node *fname;     // Filename node (contains the path)
  *   }
  * 
  * Example: "echo hi > out.txt 2> err.txt"
  *   Creates a chain: nfile(NTO, "out.txt") -> nfile(NTO, "err.txt") -> NULL
  */
static __always_inline void printRedirects(void *redir, struct CmdStr *out,
                                             struct PrintScratch *s)
 {
     void *cur = redir;
     
     for (int i = 0; i < 4 && cur; i++)
     {
         __builtin_memset(&s->nf, 0, sizeof(s->nf));
        if (bpf_probe_read_user(&s->nf, sizeof(s->nf), cur) < 0)
            return;
         
         if (s->nf.type >= DASH_NTO && s->nf.type <= DASH_NAPPEND && s->nf.fname)
         {
             __builtin_memset(&s->fname_arg, 0, sizeof(s->fname_arg));
             if (bpf_probe_read_user(&s->fname_arg, sizeof(s->fname_arg), s->nf.fname) == 0 &&
                 s->fname_arg.type == DASH_NARG && s->fname_arg.text)
             {
                __builtin_memset(s->text_buf, 0, sizeof(s->text_buf));
                bpf_probe_read_user_str(s->text_buf, sizeof(s->text_buf), s->fname_arg.text);
                
                // Include fd prefix when non-default (e.g., "2>" instead of ">")
                 __builtin_memset(s->redir_sym, 0, sizeof(s->redir_sym));
                 
                 if (s->nf.type == DASH_NTO || s->nf.type == DASH_NCLOBBER)
                 {
                     if (s->nf.fd != 1)
                         BPF_SNPRINTF(s->redir_sym, sizeof(s->redir_sym), "%d>", s->nf.fd);
                     else
                         s->redir_sym[0] = '>';
                 }
                 else if (s->nf.type == DASH_NFROM)
                 {
                     if (s->nf.fd != 0)
                         BPF_SNPRINTF(s->redir_sym, sizeof(s->redir_sym), "%d<", s->nf.fd);
                     else
                         s->redir_sym[0] = '<';
                 }
                 else if (s->nf.type == DASH_NAPPEND)
                 {
                     if (s->nf.fd != 1)
                         BPF_SNPRINTF(s->redir_sym, sizeof(s->redir_sym), "%d>>", s->nf.fd);
                     else
                     {
                         s->redir_sym[0] = '>';
                         s->redir_sym[1] = '>';
                     }
                 }
                 else if (s->nf.type == DASH_NFROMTO)
                 {
                     if (s->nf.fd != 0)
                         BPF_SNPRINTF(s->redir_sym, sizeof(s->redir_sym), "%d<>", s->nf.fd);
                     else
                     {
                         s->redir_sym[0] = '<';
                         s->redir_sym[1] = '>';
                     }
                 }
                 
                 appendStr(out, s->redir_sym);
                 appendStr(out, s->text_buf);
             }
         }
         
         cur = s->nf.next;
     }
 }
 
 
 /*
  * =============================================================================
  * HELPER: Print a simple command (NCMD) with its arguments and redirections
  * =============================================================================
  * 
  * A simple command in dash looks like this in memory:
  * 
  *   struct ncmd {
  *       int type;        // Always NCMD (0)
  *       int linno;       // Line number in script
  *       node *assign;    // Variable assignments before command (VAR=value cmd)
  *       node *args;      // Arguments linked list (first is command name)
  *       node *redirect;  // Redirections linked list
  *   }
  * 
  * The args field points to a linked list of narg nodes:
  * 
  *   For "echo hello world":
  *   
  *   ncmd.args --> narg("echo") --> narg("hello") --> narg("world") --> NULL
  *                   |                 |                  |
  *                  text              text               text
  * 
  * Parameters:
  *   node:        Pointer to ncmd structure in dash's memory
 *   extra_redir: Redirections from an outer NREDIR wrapper (if any)
 */
 __noinline int printNcmdWithRedir(unsigned long node_addr, unsigned long extra_redir_addr, struct CmdStr *out)
 {
     void *node = (void *)node_addr;
     if (!node || !out)
         return 0;
     
    // No REPORT_ERROR in this function: it sits at call depth 4 in the deepest
    // chain (exitList → processSingleNode → processPipeStage → printNcmdWithRedir),
    // and adding report_error() would create a 5th frame exceeding the 512-byte
    // combined stack limit.
    unsigned int zero = 0;
    struct PrintScratch *s = bpf_map_lookup_elem(&print_scratch, &zero);
    if (!s)
        return 0;
    
    struct dash_ncmd cmd = {};
    if (bpf_probe_read_user(&cmd, sizeof(cmd), node) < 0)
        return 0;
    
    if (!cmd.args)
        return 0;
    
    __builtin_memset(&s->fname_arg, 0, sizeof(s->fname_arg));
    if (bpf_probe_read_user(&s->fname_arg, sizeof(s->fname_arg), cmd.args) < 0)
        return 0;
    if (s->fname_arg.type != DASH_NARG || !s->fname_arg.text)
        return 0;
    
    __builtin_memset(s->text_buf, 0, sizeof(s->text_buf));
    if (bpf_probe_read_user_str(s->text_buf, sizeof(s->text_buf), s->fname_arg.text) <= 0)
        return 0;
     
     appendStr(out, s->text_buf);
     
     void *next_arg = s->fname_arg.next;
     
     for (int i = 1; i <= 16 && next_arg; i++)
     {
         __builtin_memset(&s->fname_arg, 0, sizeof(s->fname_arg));
         if (bpf_probe_read_user(&s->fname_arg, sizeof(s->fname_arg), next_arg) != 0 ||
             s->fname_arg.type != DASH_NARG || !s->fname_arg.text)
         {
             break;
         }
         
         __builtin_memset(s->text_buf, 0, sizeof(s->text_buf));
         bpf_probe_read_user_str(s->text_buf, sizeof(s->text_buf), s->fname_arg.text);
         appendStr(out, s->text_buf);
         next_arg = s->fname_arg.next;
     }
     
     if (cmd.redirect)
        printRedirects(cmd.redirect, out, s);
    
    if (extra_redir_addr)
        printRedirects((void *)extra_redir_addr, out, s);
     
     return 0;
 }
 
 
 /*
  * =============================================================================
  * HELPER: Unwrap an NREDIR node to get the inner command and redirections
  * =============================================================================
  * 
  * When a command has redirections, dash sometimes wraps it in an NREDIR node:
  * 
  *   "echo hi > file"  becomes:
  *   
  *   NREDIR
  *     |-- n (inner node) --> NCMD "echo hi"
  *     |-- redirect       --> NTO "file"
  * 
  * struct nredir {
  *     int type;        // NREDIR, NBACKGND (&), or NSUBSHELL (())
  *     int linno;       // Line number
  *     node *n;         // The wrapped command
  *     node *redirect;  // The redirections
  * }
  */
 static __always_inline void unwrapRedir(void *node, void **inner, void **redir)
 {
     struct dash_nredir r = {};
     if (bpf_probe_read_user(&r, sizeof(r), node) < 0)
     {
         *inner = NULL;
         *redir = NULL;
         return;
     }
     *inner = r.n;
     *redir = r.redirect;
 }
 
 
 /*
  * =============================================================================
  * HELPER: Get children of a binary operator node (;, &&, ||)
  * =============================================================================
  * 
  * Binary operators connect two commands:
  * 
  *   "cmd1 ; cmd2"   NSEMI:  run cmd1, then cmd2
  *   "cmd1 && cmd2"  NAND:   run cmd2 only if cmd1 succeeds
  *   "cmd1 || cmd2"  NOR:    run cmd2 only if cmd1 fails
  * 
  * struct nbinary {
  *     int type;     // NSEMI, NAND, or NOR
  *     node *ch1;    // First child (left side)
  *     node *ch2;    // Second child (right side)
  * }
  * 
  *   "a ; b ; c" parses as:
  *   
  *        NSEMI
  *       /     \
  *    NSEMI     c
  *   /     \
  *  a       b
  */
 static __always_inline void getBinaryChildren(void *node, void **ch1, void **ch2)
 {
     struct dash_nbinary bin = {};
     if (bpf_probe_read_user(&bin, sizeof(bin), node) < 0)
     {
         *ch1 = NULL;
         *ch2 = NULL;
         return;
     }
     *ch1 = bin.ch1;
     *ch2 = bin.ch2;
 }
 
 
 /*
  * =============================================================================
  * HELPER: Unwrap wrapper nodes and read the actual command type
  * =============================================================================
  * 
  * Peels off layers of NNOT and NREDIR/NBACKGND/NSUBSHELL to reach the
  * actual command node (NCMD, NPIPE, etc.).
  * 
  * Returns the final node type via *out_type, updates *node in place,
  * and stores any outer redirect pointer in *out_redir.
  */
static __always_inline int unwrapToCommand(void **node, int *out_type,
                                             void **out_redir, int *out_subshell_depth,
                                             int *out_background, struct CmdStr *out)
 {
     *out_redir = NULL;
     *out_subshell_depth = 0;
     *out_background = 0;
     
     int type = 0;
     if (bpf_probe_read_user(&type, sizeof(type), *node) < 0)
     {
         REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user(node type) failed");
         return -1;
     }
     
     // Peel off wrapper layers (NNOT, NREDIR, NBACKGND, NSUBSHELL) in any
     // order and nesting depth, up to 8 layers, to reach the real command.
     for (int i = 0; i < 4; i++)
     {
         if (type == DASH_NNOT)
         {
             struct dash_nnot nnot = {};
             if (bpf_probe_read_user(&nnot, sizeof(nnot), *node) < 0)
             {
                 REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user(nnot) failed");
                 return -1;
             }
             appendStr(out, "!");
             *node = nnot.com;
             if (!*node)
                 return -1;
             if (bpf_probe_read_user(&type, sizeof(type), *node) < 0)
             {
                 REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user(type after nnot) failed");
                 return -1;
             }
         }
         else if (type == DASH_NREDIR || type == DASH_NBACKGND || type == DASH_NSUBSHELL)
         {
             if (type == DASH_NBACKGND)
                 *out_background = 1;
             if (type == DASH_NSUBSHELL)
                 (*out_subshell_depth)++;
             void *inner = NULL;
             unwrapRedir(*node, &inner, out_redir);
             if (inner)
             {
                 if (bpf_probe_read_user(&type, sizeof(type), inner) < 0)
                 {
                     REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user(type after redir) failed");
                     return -1;
                 }
                 *node = inner;
             }
             else
             {
                 break;
             }
         }
         else
         {
             break; // reached a real command node (NCMD, NPIPE, etc.)
         }
     }
     
     *out_type = type;
     return 0;
 }
 
 
/*
 * =============================================================================
 * HELPER: Process one stage of a pipeline (unwrap wrappers, then print NCMD)
 * =============================================================================
 * Inlined into processSingleNode to avoid adding an extra call frame.
 * Without inlining, the chain exitList → processSingleNode → processPipeStage
 * → printNcmdWithRedir → report_error would be 5 frames and exceed the
 * 512-byte combined stack limit.
 */
 __noinline int processPipeStage(unsigned long node_addr, struct CmdStr *out)
{
    void *pipe_node = (void *)node_addr;
    if (!pipe_node || !out)
        return 0;
    
    int pipe_type = 0;
    void *pipe_redir = NULL;
    int pipe_subshell = 0;
    int pipe_bg = 0;
    
    if (unwrapToCommand(&pipe_node, &pipe_type, &pipe_redir, &pipe_subshell, &pipe_bg, out) == 0 &&
        pipe_type == DASH_NCMD)
    {
        for (int j = 0; j < pipe_subshell && j < 8; j++)
            appendStr(out, "(");
        printNcmdWithRedir((unsigned long)pipe_node, (unsigned long)pipe_redir, out);
        for (int j = 0; j < pipe_subshell && j < 8; j++)
            appendStr(out, ")");
    }
    
    return 0;
}


// Forward declaration: mini-DFS for binary operators inside subshells
__noinline int processSubshellBinary(unsigned long node_addr, struct CmdStr *out);

 /*
  * =============================================================================
  * HELPER: Process a single node (unwrap, then handle NCMD or NPIPE)
  * =============================================================================
  * A node might be:
  *   - NCMD directly: "echo hello"
  *   - NREDIR wrapping NCMD: "echo hello > file"
  *   - NBACKGND wrapping NCMD: "echo hello &"
  *   - NSUBSHELL wrapping commands: "(echo hello)"
  *   - NNOT wrapping any of the above: "! echo hello"
  *   - NPIPE: "cmd1 | cmd2 | cmd3"
  */
__noinline int processSingleNode(unsigned long node_addr, struct CmdStr *out)
{
    void *node = (void *)node_addr;
    if (!node || !out)
        return 0;
    
    int type = 0;
    void *extra_redir = NULL;
    int subshell_depth = 0;
    int background = 0;
    
    if (unwrapToCommand(&node, &type, &extra_redir, &subshell_depth, &background, out) < 0)
        return 0;
    
    for (int i = 0; i < subshell_depth && i < 8; i++)
        appendStr(out, "(");
    
    if (type == DASH_NCMD)
    {
        printNcmdWithRedir((unsigned long)node, (unsigned long)extra_redir, out);
    }
    else if (subshell_depth > 0 &&
             (type == DASH_NSEMI || type == DASH_NAND || type == DASH_NOR))
    {
        // Binary operator inside subshell: use mini-DFS with separate stack
        processSubshellBinary((unsigned long)node, out);
    }
    else if (type == DASH_NPIPE)
    {
        /*
         * Pipeline: cmd1 | cmd2 | ...
         * 
         * struct npipe { int type; int backgnd; nodelist *cmdlist; }
         * nodelist: { nodelist *next; node *n; }
         * 
         * Walk the cmdlist linked list, processing each command
         * with "|" separators between them.
         */
        struct dash_npipe pipe = {};
        if (bpf_probe_read_user(&pipe, sizeof(pipe), node) < 0)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user(npipe) failed");
            return 0;
        }
        
        void *cur_list = pipe.cmdlist;
        for (int i = 0; i < 8 && cur_list; i++)
        {
            struct dash_nodelist entry = {};
            if (bpf_probe_read_user(&entry, sizeof(entry), cur_list) < 0)
                break;
            
            if (i > 0)
                appendStr(out, "|");
            
            if (entry.n)
                processPipeStage((unsigned long)entry.n, out);
            
            cur_list = entry.next;
        }
        
        if (extra_redir)
        {
            unsigned int zero = 0;
            struct PrintScratch *s = bpf_map_lookup_elem(&print_scratch, &zero);
            if (s)
                printRedirects(extra_redir, out, s);
        }
    }
    
    for (int i = 0; i < subshell_depth && i < 8; i++)
        appendStr(out, ")");
    
    if (background)
        appendStr(out, "&");
    
    return 0;
}
 
 
/*
 * =============================================================================
 * BPF MAP: Separate DFS stack for subshell content (avoids clobbering main DFS)
 * =============================================================================
 */
#define MAX_SUBSHELL_CMDS 8

struct SubshellState
{
    unsigned long node_addrs[MAX_SUBSHELL_CMDS];
    int separators[MAX_SUBSHELL_CMDS];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct SubshellState);
} subshell_state SEC(".maps");


/*
 * =============================================================================
 * HELPER: Walk binary operator tree inside a subshell (global function)
 * =============================================================================
 * Mini-DFS that handles NSEMI/NAND/NOR trees found inside NSUBSHELL nodes.
 * Processes NCMD leaves directly via printNcmdWithRedir.
 * Uses a separate per-CPU map to avoid clobbering the main DFS state.
 */
__noinline int processSubshellBinary(unsigned long node_addr, struct CmdStr *out)
{
    if (!out)
        return 0;
    
    unsigned int zero = 0;
    struct SubshellState *ss = bpf_map_lookup_elem(&subshell_state, &zero);
    if (!ss)
        return 0;
    
    ss->node_addrs[0] = node_addr;
    ss->separators[0] = -1;
    int top = 1;
    
    for (int iter = 0; iter < MAX_SUBSHELL_CMDS * 2 && top > 0; iter++)
    {
        top--;
        int idx = top & (MAX_SUBSHELL_CMDS - 1);
        unsigned long na = ss->node_addrs[idx];
        int sep = ss->separators[idx];
        
        if (!na)
            continue;
        
        int t = 0;
        if (bpf_probe_read_user(&t, sizeof(t), (void *)na) < 0)
            continue;
        
        if (t == DASH_NSEMI || t == DASH_NAND || t == DASH_NOR)
        {
            void *ch1 = NULL, *ch2 = NULL;
            getBinaryChildren((void *)na, &ch1, &ch2);
            
            if (top < MAX_SUBSHELL_CMDS)
            {
                int pi = top & (MAX_SUBSHELL_CMDS - 1);
                ss->node_addrs[pi] = (unsigned long)ch2;
                ss->separators[pi] = t;
                top++;
            }
            if (top < MAX_SUBSHELL_CMDS)
            {
                int pi = top & (MAX_SUBSHELL_CMDS - 1);
                ss->node_addrs[pi] = (unsigned long)ch1;
                ss->separators[pi] = sep;
                top++;
            }
        }
        else
        {
            if (sep >= 0)
                appendSeparator(out, sep);
            
            if (t == DASH_NCMD)
            {
                printNcmdWithRedir(na, 0, out);
            }
            else if (t == DASH_NREDIR || t == DASH_NBACKGND)
            {
                // Unwrap one layer of NREDIR/NBACKGND to find NCMD
                struct dash_nredir r = {};
                if (bpf_probe_read_user(&r, sizeof(r), (void *)na) == 0 && r.n)
                {
                    int inner_t = 0;
                    if (bpf_probe_read_user(&inner_t, sizeof(inner_t), r.n) == 0 &&
                        inner_t == DASH_NCMD)
                        printNcmdWithRedir((unsigned long)r.n, (unsigned long)r.redirect, out);
                }
                if (t == DASH_NBACKGND)
                    appendStr(out, "&");
            }
        }
    }
    
    return 0;
}


/*
 * Extracted loop body for DFS walk to reduce program size for verifier.
 * Returns the new stack top after processing one node.
 */
static __noinline int processDfsIteration(struct WalkState *ws, int top)
{
    top--;
    int idx = top & (MAX_CHAIN_CMDS - 1);  // bounds mask for verifier
    unsigned long node_addr = ws->node_addrs[idx];
    int sep = ws->separators[idx];

    if (!node_addr)
        return top;

    int type = 0;
    if (bpf_probe_read_user(&type, sizeof(type), (void *)node_addr) < 0)
        return top;

    if (type == DASH_NSEMI || type == DASH_NAND || type == DASH_NOR)
    {
        void *ch1 = NULL, *ch2 = NULL;
        getBinaryChildren((void *)node_addr, &ch1, &ch2);

        // Push ch2 first (popped second), then ch1 (popped first = left-to-right order)
        if (top < MAX_CHAIN_CMDS)
        {
            int pi = top & (MAX_CHAIN_CMDS - 1);
            ws->node_addrs[pi] = (unsigned long)ch2;
            ws->separators[pi] = type;
            top++;
        }

        if (top < MAX_CHAIN_CMDS)
        {
            int pi = top & (MAX_CHAIN_CMDS - 1);
            ws->node_addrs[pi] = (unsigned long)ch1;
            ws->separators[pi] = sep;
            top++;
        }
    }
    else
    {
        if (sep >= 0)
            appendSeparator(&ws->cmd, sep);
        processSingleNode(node_addr, &ws->cmd);
    }
    return top;
}

/*
 * =============================================================================
 * URETPROBE: Hook list() return to capture the parsed command tree
 * =============================================================================
 * 
 * list() is called for every command line the user types.
 * The return value is the root of the parse tree.
 * 
 * TREE WALKING STRATEGY:
 * 
 * Dash's parse tree mixes different binary operators (;, &&, ||)
 * at different levels. For example "a ; b && c || d ; e" produces:
 * 
 *        NSEMI
 *       /     \
 *    NSEMI     e
 *   /     \
 *  a      NOR
 *        /    \
 *      NAND    d
 *     /    \
 *    b      c
 * 
 * We use a stack-based DFS to handle any tree shape:
 *   1. Push root onto stack
 *   2. Pop a node:
 *      - If binary operator (;, &&, ||): push ch2 then ch1 (so ch1 is popped first)
 *        ch2 inherits the operator type as separator, ch1 inherits incoming separator
 *      - If leaf command: output separator (if any) then process the command
 *   3. Repeat until stack is empty
 */
SEC("uretprobe")
int exitList(struct pt_regs *ctx)
{
    set_hook_name("exit_list", 9);
    
    if (is_current_pid_related())
    {
        return 0;
    }
    
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = pid_tgid >> 32;
    
    unsigned char *active = bpf_map_lookup_elem(&active_shell_pids, &pid);
    if (!active)
        return 0;
    
    void *root = (void *)PT_REGS_RC(ctx);
    if (!root)
        return 0;
    
    unsigned int zero = 0;
    struct WalkState *ws = bpf_map_lookup_elem(&walk_state, &zero);
    if (!ws)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem(walk_state) failed");
        return 0;
    }
    
    ws->cmd.length = 0;
    ws->cmd.arr[0] = '\0';
    
    ws->node_addrs[0] = (unsigned long)root;
    ws->separators[0] = -1;
    int top = 1;
    
    // DFS loop: each iteration pops one node (binary operator or leaf)
    // Max iterations = (N-1) binary pops + N leaf pops = 2N-1 = 31 for N=16
    for (int iter = 0; iter < MAX_CHAIN_CMDS * 2 && top > 0; iter++)
    {
        top = processDfsIteration(ws, top);
    }
    
    if (ws->cmd.length > 0)
    {
        reset_tail_counter();
        do_tail_call(ctx, &dash_shell_command_prog_array);
    }
    
    return 0;
}

SEC("uretprobe")
int exitList_2(struct pt_regs *ctx)
{
    unsigned int zero = 0;
    struct WalkState *ws = bpf_map_lookup_elem(&walk_state, &zero);
    if (!ws)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_lookup_elem(walk_state) failed");
        return 0;
    }

    sanitizeDashText(&ws->cmd);
        
    struct process_t *process = allocate_process_t();
    if (!process)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed");
        return 0;
    }
    if (fill_event_process_from_cache(process) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "fill_event_process_from_cache failed");
        return 0;
    }
    
    process->shell_command.length = (short)ws->cmd.length;
    if (bpf_probe_read_kernel(process->shell_command.value, sizeof(process->shell_command.value), ws->cmd.arr) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel(shell_command) failed");
        return 0;
    }
    
    update_shell_command_in_process(process->pid, &process->shell_command);
    return 0;
}
 
 
 /*
  * =============================================================================
  * UPROBE: Hook setprompt() to detect interactive sessions
  * =============================================================================
  * 
  * In dash source (parser.c):
  * 
  *   void setprompt(int which) {
  *       // which=1: Display PS1 (primary prompt, e.g., "$ ")
  *       // which=2: Display PS2 (continuation prompt, e.g., "> ")
  *   }
  * 
  * setprompt(1) is ONLY called when:
  *   - The shell is interactive (has -i flag or connected to terminal)
  *   - It's about to read a new command from the user
  * 
  * This is our "signal" that the next parsed command is from an interactive user.
  */
 SEC("uprobe")
 int enterSetprompt(struct pt_regs *ctx)
 {
     set_hook_name("enter_setprompt", 15);
     
     if (is_current_pid_related())
     {
         return 0;
     }
     
     int which = (int)PT_REGS_PARM1(ctx);
     
     if (which != 1)
         return 0;
     
     unsigned long long pid_tgid = bpf_get_current_pid_tgid();
     unsigned int pid = pid_tgid >> 32;
     
     unsigned char val = 1;
     bpf_map_update_elem(&active_shell_pids, &pid, &val, BPF_ANY);
     
     delete_shell_command_from_alive_process(pid);
     
     return 0;
 }