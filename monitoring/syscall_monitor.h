#ifndef __SYSCALL_MONITOR_H__
#define __SYSCALL_MONITOR_H__

#define PATH_SIZE 256
#define XNAME_SIZE 128
#define XVALUE_SIZE 128

#define HASH_MAX_DIGESTSIZE 64
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define XATTR_SECURITY_PREFIX "security."

#define XATTR_EVM_SUFFIX "evm"
#define XATTR_NAME_EVM XATTR_SECURITY_PREFIX XATTR_EVM_SUFFIX

#define XATTR_IMA_SUFFIX "ima"
#define XATTR_NAME_IMA XATTR_SECURITY_PREFIX XATTR_IMA_SUFFIX

struct ima_data {
	__u64 size;
	__u8 value[2 + HASH_MAX_DIGESTSIZE];
};

enum events_type { SYSCALL_EVENT, FPUT_EVENT };

struct event {
	__u64 ts;
	__u64 event_start_time;

	__u32 type;
	char comm[TASK_COMM_LEN];
	__u32 pid;
	__u32 tgid;
	__u32 euid;
	__u32 egid;

	union {
		struct syscall_event {
			__u32 syscall_nr;
			__s64 ret;
			/* Copy of userspace registers. */
			unsigned long args[6];

			union {
				struct {
					char pathname[PATH_SIZE];
					int flags;
					__u32 mode;
					__u32 uid;
					__u32 gid;
					unsigned ino;
					unsigned perms;
				} open;
				struct {
					int dfd;
					char pathname[PATH_SIZE];
					int flags;
					__u32 mode;
					__u32 uid;
					__u32 gid;
					unsigned ino;
					unsigned perms;
				} openat;
				struct {
					char pathname[PATH_SIZE];
					__u32 mode;
					__u32 uid;
					__u32 gid;
					unsigned ino;
					unsigned perms;
				} creat;
				struct {
					char pathname[PATH_SIZE];
					__u32 mode;
					__u32 uid;
					__u32 gid;
					unsigned ino;
					unsigned perms;
				} mkdir;
				struct {
					int dfd;
					char pathname[PATH_SIZE];
					__u32 mode;
					__u32 uid;
					__u32 gid;
					unsigned ino;
					unsigned perms;
				} mkdirat;
				struct {
					char dir[PATH_SIZE];
				} chdir;
				struct {
					int fd;
				} fchdir;
				struct {
					char pathname[PATH_SIZE];
					__u32 mode;
					__u32 perms;
					struct ima_data evm_hash;
				} chmod;
				struct {
					int fd;
					__u32 mode;
					__u32 perms;
					struct ima_data evm_hash;
				} fchmod;
				struct {
					char pathname[PATH_SIZE];
					__u32 owner;
					__u32 group;
					__u32 perms;
					struct ima_data evm_hash;
				} chown;
				struct {
					int fd;
					__u32 owner;
					__u32 group;
					__u32 perms;
					struct ima_data evm_hash;
				} fchown;
				struct {
					unsigned int fd;
					unsigned ino;
					unsigned dev;
				} close;
				struct {
					int mask;
				} umask;
				struct {
					char pathname[PATH_SIZE];
				} unlink;
				struct {
					char pathname[PATH_SIZE];
				} rmdir;
				struct {
					unsigned int fd;
					//struct linux_dirent __user *dirent;
					//unsigned int count;
				} getdents;
				struct {
					char oldname[PATH_SIZE];
					char newname[PATH_SIZE];
				} link;
				struct {
					char oldname[PATH_SIZE];
					char newname[PATH_SIZE];
					struct ima_data ima_hash;
					struct ima_data evm_hash;
				} symlink;
				struct getxattr {
					char pathname[PATH_SIZE];
					char name[XNAME_SIZE];
					union {
						__u8 value[XVALUE_SIZE];
						void *addr;
					};
					__u64 size;
				} getxattr;
				struct setxattr {
					char pathname[PATH_SIZE];
					char name[XNAME_SIZE];
					__u8 value[XVALUE_SIZE];
					__u64 size;
					int flags;
				} setxattr;
				struct {
					char pathname[PATH_SIZE];
					//char __user *__user *argv;
					//char __user *__user *envp;
					int umask;
				} execve;
				struct {
					int error_code;
				} exit_group;
				struct {
					int error_code;
				} exit;
			};
		} syscall;
		struct fput_event {
			unsigned ino;
			unsigned dev;
			struct ima_data ima_hash;
			struct ima_data evm_hash;
		} fput;
	};
} __attribute__((packed));

struct monitor_config {
	__u32 enabled;
	__u32 filter_tst;
};

#endif
