#pragma once
#include "common_maps.bpf.h"
#include "error_reports.bpf.h"
#include "allocators.bpf.h"
#include "string_utils.bpf.h"
#include "preprocessor_definitions/stat.bpf.h"
#include "syscall_tracepoint_layout.h"

#define TMPFS_MAGIC            0x01021994
#define MEMFD_WITH_NULL_LENGTH 6
#define MAX_PATH_COMPONENT_LEN FILENAME_MAX_LENGTH
#define MAX_PATH_COMPONENTS 20
#define MAX_ARGV_COMPONENTS 32
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_CMD_SIZE(x) ((x) & (CMD_MAX - 1))

struct sys_enter_execve_record {
    unsigned long long _common;   // 0
    unsigned long long _nr;       // 8
    const char *filename;         // 16
    const char *const *argv;      // 24
    const char *const *envp;      // 32
};

struct sys_enter_execveat_record {
    unsigned long long _common;   // 0
    unsigned long long _nr;       // 8
    unsigned long long fd;        // 16
    const char *filename;         // 24
    const char *const *argv;      // 32
    const char *const *envp;      // 40
};

_Static_assert(__builtin_offsetof(struct sys_enter_execve_record, argv) == SYS_ENTER_EXECVE_ARGV_OFFSET,
               "sys_enter_execve_record.argv must be at SYS_ENTER_EXECVE_ARGV_OFFSET");
_Static_assert(__builtin_offsetof(struct sys_enter_execveat_record, argv) == SYS_ENTER_EXECVEAT_ARGV_OFFSET,
               "sys_enter_execveat_record.argv must be at SYS_ENTER_EXECVEAT_ARGV_OFFSET");

statfunc const char *const *get_execve_argv_from_ctx(const void *ctx)
{
    return ((const struct sys_enter_execve_record *)ctx)->argv;
}

statfunc const char *const *get_execveat_argv_from_ctx(const void *ctx)
{
    return ((const struct sys_enter_execveat_record *)ctx)->argv;
}

statfunc long get_cmd_from_task(struct task_struct * task, struct command_line_t  *output_cmd)
{
    unsigned int pid = BPF_CORE_READ(task, pid);
    if(pid <= 2)
    {
        return SUCCESS;
    }
    
    unsigned long arg_start = 0, arg_end = 0;
    BPF_CORE_READ_INTO(&arg_start, task, mm, arg_start);
    BPF_CORE_READ_INTO(&arg_end, task, mm, arg_end);
    if (arg_end > arg_start) {
        unsigned long size = arg_end - arg_start;
        if (size >= CMD_MAX)
        {
            size = CMD_MAX - 1; // Keep room for null char
        }
        if(bpf_probe_read_user(output_cmd->value, size, (void *)arg_start) != SUCCESS)
        {
            REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_user failed. pid: %d", pid);
            return GENERIC_ERROR;
        }

        // Replace nulls with spaces for readability
        for (int i = 0; i < CMD_MAX; i++) 
        {
            if (output_cmd->value[i] == '\0')
            {
                output_cmd->value[i] = ' ';
            }
        }
        output_cmd->value[size] = '\0';
        output_cmd->length = size - 1;
    }
    else 
    {
        REPORT_ERROR(GENERIC_ERROR, "get_cmd_from_task arg_end <= arg_start. pid: %d", pid);
        return GENERIC_ERROR;
    }
    return SUCCESS;
}

statfunc long get_cmd_from_user_argv(struct command_line_t *cmd, const char *const *argv)
{
    struct string_buffer *out_buf = allocate_string_buffer();
    if(!out_buf)
    {
        return GENERIC_ERROR;
    }

    unsigned int offset = 0;
    for(int i = 0; i < MAX_ARGV_COMPONENTS; i++)
    {
        const char *argp = NULL;
        if(bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != SUCCESS)
        {
            break;
        }
        if(!argp)
        {
            break; // NULL terminator -> end of argv
        }
        if(offset >= CMD_MAX - 1)
        {
            break;
        }

        unsigned int idx = offset;
        barrier_var(idx);
        long read_len = bpf_probe_read_user_str(&out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(idx)], CMD_MAX - 1, argp);
        if(read_len <= 0)
        {
            break;
        }
        offset += read_len;
        out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(offset - 1)] = ' ';
    }
    if(offset == 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "get_cmd_from_user_argv: offset is 0");
        return GENERIC_ERROR;
    }

    unsigned int length = offset - 1;
    if(length > CMD_MAX - 1)
    {
        length = CMD_MAX - 1;
    }
    bpf_probe_read(cmd->value, length, &out_buf->data[0]);
    cmd->value[LIMIT_CMD_SIZE(length)] = '\0';
    cmd->length = length;

    return SUCCESS;
}

statfunc unsigned long long get_unique_inode_id_from_dentry(const struct dentry *dentry)
{
    unsigned long long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    unsigned int dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
    unsigned int gen = BPF_CORE_READ(dentry, d_inode, i_generation);

    // pack dev|gen into one lane, xor with ino, then finalize
    unsigned long long lane = ((unsigned long long)dev << 32) | gen;
    unsigned long long x = ino ^ lane;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

statfunc int get_filename_from_dentry(struct filename_t *output_filename, const struct dentry *dentry)
{
    struct qstr d_name    = BPF_CORE_READ(dentry, d_name);
    if(d_name.len > FILENAME_MAX_LENGTH || d_name.len < 1)
    {
        REPORT_ERROR(GENERIC_ERROR, "Filename to long. length: %d, name: '%s'", d_name.len, d_name.name);
        return GENERIC_ERROR;
    }
    bpf_probe_read_kernel_str(output_filename->value, FILENAME_MAX_LENGTH, d_name.name);
    output_filename->length = d_name.len;
    return SUCCESS;
}

static long get_path_from_path(struct path_t *output_path, const struct path *path)
{
    struct dentry *dentry      = BPF_CORE_READ(path, dentry);
    unsigned long inode = BPF_CORE_READ(dentry, d_inode, i_ino);
    unsigned int dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
    const unsigned char * name = BPF_CORE_READ(dentry, d_name).name;
    struct vfsmount *vfsmnt    = BPF_CORE_READ(path, mnt);
    struct mount *mnt          = container_of(vfsmnt, struct mount, mnt);
    struct mount *mnt_parent   = BPF_CORE_READ(mnt, mnt_parent);

    struct string_buffer *out_buf = allocate_string_buffer();
    if(!out_buf)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_string_buffer failed. inode: %lu, dev: %u, name: '%s'", inode, dev, name);
        return GENERIC_ERROR;
    }

    size_t buf_off = HALF_PERCPU_ARRAY_SIZE;   // We start from offset HALF_PERCPU_ARRAY_SIZE, and we write backwards. 
    unsigned short is_memfd = FALSE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) // MAX_PATH_COMPONENTS represents the max parent directories we are going to iterate. In each iteration we reveal another iteration.
    {
        struct dentry *mnt_root  = BPF_CORE_READ(vfsmnt, mnt_root);
        struct dentry *d_parent  = BPF_CORE_READ(dentry, d_parent);

        // Here we check if the current component we are parsing is the mount direcory. Or if the current component is the same as the parent directory.
        if (dentry == mnt_root || dentry == d_parent) 
        {        
            /* In regular files (dentry == d_parent) is suppose to be true only when, dentry == mnt_root. Which means that the current component is the root dir '/'
               If (dentry == d_parent) but (dentry != mnt_root) it means one of 2 things:
               1. We built the path wrong for some reason and now we have a corrupted path.
               2. Its a pathless file. Currently we only support these pathless files: memfd, 
            */
            if (dentry != mnt_root)           
            {
                // Handle memfd
                unsigned int magic = BPF_CORE_READ(dentry, d_sb, s_magic);
                if(magic == TMPFS_MAGIC)
                {
                    char name[MEMFD_WITH_NULL_LENGTH] = {0};
                    bpf_probe_read_kernel_str(name, MEMFD_WITH_NULL_LENGTH, BPF_CORE_READ(dentry, d_name).name);
                    if(string_exact_match_known_length(name, "memfd", MEMFD_WITH_NULL_LENGTH - 1) == TRUE)
                    {
                        is_memfd = TRUE;
                        goto build_path;
                    }
                }
                
                // If not memfd, its an error.
                REPORT_ERROR(GENERIC_ERROR, "dentry == d_parent. Corruption in path creation. inode: %lu, dev: %u, name: '%s'", inode, dev, name);
                return GENERIC_ERROR;
            }

            // Cross mount‑point? continue with parent mount.
            if (mnt != mnt_parent) 
            {
                dentry      = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt         = mnt_parent;
                mnt_parent  = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt      = &mnt->mnt;
                continue;
            }
                        
                // Succesfully constructed the full path.
                // dentry == mnt_root, so we stop building the path as the current component is the mount directory, which means we parsed the full path. 
                break;  
        }

build_path:
            // copy component name 
            struct qstr d_name   = BPF_CORE_READ(dentry, d_name);
            size_t name_len      = LIMIT_PATH_SIZE(d_name.len) + 1; // The +1 is due to the leading '/' we are going to add.
               
            //  Check if the current component name is longer from the offset that remaining. This means that the next iteration will write to a wrong offset. 
            if (name_len > buf_off)
            {
                REPORT_ERROR(GENERIC_ERROR, "name_len > buf_off. Component is longer then remaining space. inode: %lu, dev: %u, name: '%s'", inode, dev, name);
                return GENERIC_ERROR;
            }                           

            // Both in the file path and in the buffer we start from the end and iterate to the start (from right to left).
            // So now we calculate the offset that current path component should be stored in. With this technique we will have leading garbage bytes at the end result. But we "cut" them later.
            size_t new_off = buf_off - name_len;      
            long ret = bpf_probe_read_kernel_str(&out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_off)], MAX_PATH_COMPONENT_LEN , d_name.name);
               
            // Check if bpf_probe_read_kernel_str had an error
            if (ret <= 1)                             
            {
                REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel_str failed. inode: %lu, dev: %u, name: '%s'", inode, dev, name);
                return GENERIC_ERROR;
            }
                
            // We are adding '/' so we need to decrement the offset
            buf_off -= 1;                             
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // This is only for the verifier, as the "if (name_len > buf_off)" above makes sure, buf_off can't be negative here. 
            out_buf->data[buf_off] = '/';

            // decrementing the offset by the current component length + '/'
            buf_off -= (ret - 1);
            if(buf_off < 0)
            {
                REPORT_ERROR(GENERIC_ERROR, "offset became negative. inode: %lu, dev: %u, name: '%s'", inode, dev, name);
                return GENERIC_ERROR;
            }
            buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // This is only for the verifier
                
            if(is_memfd == TRUE)
            {
                break;
            }
            
            // Go to the next component 
            dentry = d_parent;
    }

    // TODO: Not sure yet if this means that we had an error, or someone tried to open '/'. Need to check. If it means error, return -1;
    if (buf_off == HALF_PERCPU_ARRAY_SIZE) 
    {          
        out_buf->data[--buf_off] = '/';
    } 
    else if (buf_off > 0 && out_buf->data[buf_off] != '/') // If the first character is the path isn't '/', add it. 
    {
        --buf_off;
        buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // This is only for the verifier
        out_buf->data[buf_off] = '/';
    }

    // Add null byte, to terminate the path. 
    out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = '\0';
    // Cut all the leading garbage bytes, and place the clean path in output_path.
    if(buf_off < 0 || buf_off > HALF_PERCPU_ARRAY_SIZE)
    {
        REPORT_ERROR(GENERIC_ERROR, "offset is outside of its limits. inode: %lu, dev: %u, name: '%s'", inode, dev, name);
        return GENERIC_ERROR;
    }
    int test_offset = LIMIT_PATH_SIZE(HALF_PERCPU_ARRAY_SIZE - buf_off);

    bpf_probe_read(output_path->value, test_offset,  &out_buf->data[buf_off]);
    // return the length of the string. 
    output_path->length = HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
    return output_path->length;
}

statfunc long get_file_strings_from_path_and_dentry(struct file_t *output_file, const struct path *dir, const struct dentry *dentry)
{
    if(get_path_from_path(&output_file->path, dir) <= 0)
    {
        REPORT_ERROR(GENERIC_ERROR, "get_path_from_path failed");
        return GENERIC_ERROR;
    }
    if(get_filename_from_dentry(&output_file->filename, dentry) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "get_filename_from_dentry failed");
        return GENERIC_ERROR;
    }

    int full_path_length = output_file->path.length + output_file->filename.length + 1; // +1 due to the '/' we will add.
    if(full_path_length > PATH_MAX || full_path_length < 1)
    {
        REPORT_ERROR(GENERIC_ERROR, "Full path to long. length: %d, dir: %s, dentry: %s", full_path_length, output_file->path.value, output_file->filename.value);
        return GENERIC_ERROR;
    }
    BPF_SNPRINTF(output_file->path.value, PATH_MAX, "%s/%s", output_file->path.value, output_file->filename.value);
    output_file->path.length = full_path_length;
    return SUCCESS;
}

statfunc void get_owner_uid_from_dentry(const struct dentry *dentry, unsigned int * owner_uid)
{
    *owner_uid = BPF_CORE_READ(dentry, d_inode, i_uid.val);
}

statfunc void get_owner_gid_from_dentry(const struct dentry *dentry, unsigned int * owner_gid)
{
    *owner_gid = BPF_CORE_READ(dentry, d_inode, i_gid.val);
}

statfunc void get_mode_from_dentry(const struct dentry *dentry, unsigned short * mode) 
{
    *mode = BPF_CORE_READ(dentry, d_inode, i_mode);
}

statfunc void get_inode_from_dentry(const struct dentry *dentry, unsigned long *ino)
{
    *ino = BPF_CORE_READ(dentry, d_inode, i_ino);
}

statfunc void get_dev_from_dentry(const struct dentry *dentry, unsigned int *dev)
{
    *dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
}

struct inode___pre_kernel_66 {
    struct timespec64 i_mtime;
} __attribute__((preserve_access_index));

struct inode___pre_kernel_611 {
    struct timespec64 __i_mtime;
} __attribute__((preserve_access_index));

struct inode___new {
    unsigned long long i_mtime_sec;
} __attribute__((preserve_access_index));

statfunc void get_last_modified_from_dentry(const struct dentry *dentry, unsigned long long *last_modified)
{
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (bpf_core_field_exists(((struct inode___new *)0)->i_mtime_sec))
    {
        struct inode___new *inode_new = (void *)inode;
        *last_modified = BPF_CORE_READ(inode_new, i_mtime_sec);
    }
    else if (bpf_core_field_exists(((struct inode___pre_kernel_611 *)0)->__i_mtime.tv_sec)) 
    {
        struct inode___pre_kernel_611 *ino_pre_kernel_611 = (void *)inode;
        *last_modified = BPF_CORE_READ(ino_pre_kernel_611, __i_mtime.tv_sec);
    } 
    else if (bpf_core_field_exists(((struct inode___pre_kernel_66 *)0)->i_mtime.tv_sec)) 
    {
        struct inode___pre_kernel_66 *ino_pre_kernel_66 = (void *)inode;
        *last_modified = BPF_CORE_READ(ino_pre_kernel_66, i_mtime.tv_sec);

    } 
    else 
    {
        REPORT_ERROR(GENERIC_ERROR, "get_last_modified_from_dentry: No last modified time found");
        *last_modified = 0;
    }
}

statfunc void get_nlink_from_dentry(const struct dentry *dentry, unsigned int *nlink)
{
    *nlink = BPF_CORE_READ(dentry, d_inode, i_nlink);
}

statfunc enum file_type get_file_type_from_mode(umode_t mode)
{
    if(S_ISSOCK(mode)) return SOCKET;
    if(S_ISLNK(mode)) return SYMLINK;
    if(S_ISREG(mode)) return REGULAR_FILE;
    if(S_ISDIR(mode)) return DIRECTORY;
    if(S_ISCHR(mode)) return CHAR_DEVICE;
    if(S_ISBLK(mode)) return BLOCK_DEVICE;
    if(S_ISFIFO(mode)) return FIFO;
    return UNKNOWN_FILE_TYPE;
}

#define READ_FD_TYPE(fd_num, fd_name)                                                                \
do {                                                                                                 \
    struct file *_file_##fd_name = NULL;                                                             \
    bpf_core_read(&_file_##fd_name, sizeof(_file_##fd_name), &fdtab[fd_num]);                        \
    if(!_file_##fd_name)                                                                             \
    {                                                                                                \
        stdio_file_descriptors_at_process_creation->fd_name = NO_FILE;                               \
        break;                                                                                       \
    }                                                                                                \
    struct inode *_ino_##fd_name = BPF_CORE_READ(_file_##fd_name, f_inode);                          \
    if(!_ino_##fd_name)                                                                              \
    {                                                                                                \
        REPORT_ERROR(GENERIC_ERROR, "Failed to get inode from " #fd_name);                           \
        break;                                                                                       \
    }                                                                                                \
    umode_t _mode_##fd_name = BPF_CORE_READ(_ino_##fd_name, i_mode);                                 \
    stdio_file_descriptors_at_process_creation->fd_name = get_file_type_from_mode(_mode_##fd_name);  \
} while(0)

statfunc void get_stdio_file_descriptors_at_process_creation_from_task(const struct task_struct *task, struct stdio_file_descriptors_at_process_creation_t *stdio_file_descriptors_at_process_creation)
{
    struct files_struct *files = BPF_CORE_READ(task, files);
    if(!files)
    {
        REPORT_ERROR(GENERIC_ERROR, "Failed to get files from task");
        return;
    }
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if(!fdt)
    {
        REPORT_ERROR(GENERIC_ERROR, "Failed to get fdt from files");
        return;
    }
    struct file **fdtab = BPF_CORE_READ(fdt, fd);
    if(!fdtab)
    {
        REPORT_ERROR(GENERIC_ERROR, "Failed to get fdtab from fdt");
        return;
    }

    READ_FD_TYPE(0, stdin);
    READ_FD_TYPE(1, stdout);
    READ_FD_TYPE(2, stderr);

    return;
}