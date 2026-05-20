#pragma once

#include "constants.h"

#define ERROR_DETAILS_MAX 512
#undef PATH_MAX
#define PATH_MAX 256
#define CMD_MAX PATH_MAX
#define HOOK_NAME_MAX_LENGTH 32
#define FILENAME_MAX_LENGTH 128

enum event_type {
    EXEC = 0,
    FORK,
    EXIT,
    FILE_CREATE,
    CHOWN,
    CHMOD,
    WRITE,
    READ,
    UNLINK,
    RENAME,
    NETWORK,
    MKDIR,
    RMDIR,
    SIGNAL,
    PTRACE
};


struct command_line_t 
{
    short length; // without null character
    char value[CMD_MAX];
};

struct path_t
{
    short length; // without null character
    char value[PATH_MAX];
};

struct filename_t
{
    short length; // without null character
    char value[FILENAME_MAX_LENGTH];
};

struct owner_t
{
    unsigned int uid;
    unsigned int gid;
};

struct file_t
{
    unsigned long inode;
    unsigned int dev;
    unsigned long long unique_inode_id; 
    struct path_t path;
    struct owner_t owner;
    unsigned short mode;
    enum file_type type; 
    unsigned char suid;
    unsigned char sgid;
    unsigned long long last_modified_seconds;
    unsigned int nlink;
    struct filename_t filename;
};

struct stdio_file_descriptors_at_process_creation_t
{
    enum file_type stdin;
    enum file_type stdout;
    enum file_type stderr;
};

struct process_t 
{
    unsigned int pid;
    unsigned int ppid;
    unsigned long long unique_process_id;
    unsigned long long unique_ppid_id;
  
    unsigned int ruid;
    unsigned int rgid;
    unsigned int euid;
    unsigned int egid;
    unsigned int suid;
  
    unsigned long long cgroup_id;
    unsigned long long start_time;
    unsigned int ptrace_flags;
  
    struct file_t file;
    struct command_line_t cmd;
    struct stdio_file_descriptors_at_process_creation_t stdio_file_descriptors_at_process_creation;

    struct command_line_t shell_command;
};

struct chown_event_t
{
    struct file_t file;
    unsigned int requested_owner_uid; // TODO: can't get this value 
    unsigned int requested_owner_gid; // TODO: can't get this value
};

struct chmod_event_t
{
    struct file_t file;
    unsigned short requested_mode;
};

struct fork_event_t
{
};

struct exec_event_t
{
    struct process_t new_process;
};

struct exit_event_t
{
    unsigned int exit_code;
    unsigned int signal;
};

struct file_create_event_t
{
    struct file_t file;
};

struct write_event_t
{
    unsigned long long event_hash;
    struct file_t file;
};

typedef struct write_event_t read_event_t;

typedef struct file_create_event_t unlink_event_t;

typedef struct file_create_event_t mkdir_event_t;

typedef struct file_create_event_t rmdir_event_t;

struct rename_event_t
{
    unsigned int flags;
    struct file_t source_file;
    struct file_t destination_file;
};

struct signal_event_t
{
    struct process_t process;
    unsigned int signal;
};

struct ptrace_event_t
{
    struct process_t process;
    unsigned int mode;
};

struct network_event_t
{
    enum connection_direction direction;
    unsigned char protocol;
    unsigned char ip_type;
    unsigned short source_port;
    unsigned short destination_port;
    union 
    {
    struct { unsigned int source_ip, destination_ip; } ipv4;
    struct { unsigned int source_ip[4], destination_ip[4]; } ipv6;
    } addresses;
    
};

struct event_t 
{
    unsigned long long id;
    enum event_type type;
    enum rule_action action;
    unsigned int matched_rule_id; 
    unsigned char had_error_while_handling; // TODO - fill
    unsigned long long time;
    struct process_t process;
    struct process_t parent_process;
    union
    {
        struct chown_event_t chown;
        struct chmod_event_t chmod;
        struct fork_event_t fork;
        struct exec_event_t exec;
        struct exit_event_t exit;
        struct file_create_event_t file_create;
        struct write_event_t write;
        read_event_t read;
        unlink_event_t unlink;
        struct rename_event_t rename;
        struct network_event_t network;
        mkdir_event_t mkdir;
        rmdir_event_t rmdir;
        struct signal_event_t signal;
        struct ptrace_event_t ptrace;
    } data;
};

struct error_report_t{
    int error_code;
    char location[ERROR_DETAILS_MAX / 4];
    char details[ERROR_DETAILS_MAX];
    char hook_name[HOOK_NAME_MAX_LENGTH];
};