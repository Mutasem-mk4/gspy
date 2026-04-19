#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef _Bool bool;

enum { false = 0, true = 1 };

/* BPF map types used by gspy */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

/* BPF map update flags */
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

/* BPF get_stack flags */
#define BPF_F_USER_STACK (1ULL << 8)

/* x86_64 pt_regs — register state at uprobe entry */
struct pt_regs {
	unsigned long r15, r14, r13, r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di;
	unsigned long orig_ax;
	unsigned long ip, cs;
	unsigned long flags;
	unsigned long sp, ss;
};

/* Networking structs referenced by bpf_helper_defs.h */
struct __sk_buff { int len; };
struct xdp_md { int data; };
struct bpf_sock { int family; };
struct bpf_sock_addr { int family; };
struct bpf_sock_ops { int op; };
struct sk_msg_md { int size; };
struct bpf_perf_event_data { int addr; };
struct bpf_cgroup_dev_ctx { int major; };
struct bpf_sysctl { int write; };
struct bpf_sockopt { int optname; };
struct sk_reuseport_md { int len; };
struct bpf_dynptr { };
struct bpf_sk_lookup { int family; };

/* tracepoint context for raw_syscalls/sys_enter */
struct trace_event_raw_sys_enter {
	unsigned long long unused;
	long id;
	unsigned long args[6];
};

/* tracepoint context for raw_syscalls/sys_exit */
struct trace_event_raw_sys_exit {
	unsigned long long unused;
	long id;
	long ret;
};

#endif /* __VMLINUX_H__ */
