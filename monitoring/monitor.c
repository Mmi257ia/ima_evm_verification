#include <linux/types.h>
#include "syscall_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_monitor.skel.h"
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/perf_event.h>

#define PIN_PATH "/sys/fs/bpf/anis"
#define MAPS_PATH PIN_PATH "/maps"
#define PROGS_PATH PIN_PATH "/progs"
#define LINKS_PATH PIN_PATH "/links"

const char *BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		     "abcdefghijklmnopqrstuvwxyz"
		     "0123456789+/";

#if 0
static size_t base64_encode(const uint8_t *src, size_t len, char *dst)
{
    char *e = dst;
    size_t n;

    *e++ = '0';
    *e++ = 's';
    for (n = 0; n + 2 < len; n += 3) {
        *e++ = BASE64[src[0] >> 2];
        *e++ = BASE64[((src[0] & 0x03) << 4) | ((src[1] & 0xF0) >> 4)];
        *e++ = BASE64[((src[1] & 0x0F) << 2) | (src[2] >> 6)];
        *e++ = BASE64[src[2] & 0x3F];
        src += 3;
    }
    if (len - n == 2) {
        *e++ = BASE64[src[0] >> 2];
        *e++ = BASE64[((src[0] & 0x03) << 4) | ((src[1] & 0xF0) >> 4)];
        *e++ = BASE64[(src[1] & 0x0F) << 2];
        *e++ = '=';
    } else if (len - n == 1) {
        *e++ = BASE64[src[0] >> 2];
        *e++ = BASE64[(src[0] & 0x03) << 4];
        *e++ = '=';
        *e++ = '=';
    }
    *e = '\0';

    return e - dst;
}
#endif

int findIndex(const char val)
{
	if ('A' <= val && val <= 'Z')
		return val - 'A';
	if ('a' <= val && val <= 'z')
		return val - 'a' + 26;
	if ('0' <= val && val <= '9')
		return val - '0' + 52;
	if (val == '+')
		return 62;
	if (val == '/')
		return 63;
	return -1;
}

int base64_decode(const __u8 *str, char *out)
{
	const size_t length = strlen((const char *)str);
	const __u8 *it = str;
	const __u8 *end = str + length;
	int acc;

	if ((length - 2) % 4 != 0)
		return 1;

	it += 2; // skip 0s

	while (it != end) {
		const __u8 b1 = *it++;
		const __u8 b2 = *it++;
		const __u8 b3 = *it++; // might be the first padding byte
		const __u8 b4 =
			*it++; // might be the first or second padding byte

		const int i1 = findIndex(b1);
		const int i2 = findIndex(b2);

		acc = i1 << 2; // six bits came from the first byte
		acc |= i2 >> 4; // two bits came from the first byte
		*out++ = acc; // output the first byte

		if (b3 != '=') {
			const int i3 = findIndex(b3);

			acc = (i2 & 0xF)
			      << 4; // four bits came from the second byte
			acc += i3 >> 2; // four bits came from the second byte
			*out++ = acc; // output the second byte

			if (b4 != '=') {
				const int i4 = findIndex(b4);

				acc = (i3 & 0x3)
				      << 6; // two bits came from the third byte
				acc |= i4; // six bits came from the third byte
				*out++ = acc; // output the third byte
			}
		}
	}

	*out = '\0'; // add the sigil for end of string
	return 0;
}

static inline bool is_string(const uint8_t *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len && buf[i] != '\0'; ++i) {
		if (!isprint(buf[i])) {
			return false;
		}
	}
	return i != len;
}

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev) & MINORMASK))
static __always_inline unsigned old_encode_dev(unsigned dev)
{
	return (MAJOR(dev) << 8) | MINOR(dev);
}

#define field_size(type, member) sizeof(((type *)0)->member)

char base64_xattr[(field_size(struct getxattr, value) + 2) / 3 * 4 + 1];
char hex_xattr[field_size(struct getxattr, value) * 2 + 1];

static void hex_encode(const uint8_t *src, size_t len, char *dst)
{
	for (size_t i = 0; i < len; i++)
		sprintf(dst + i * 2, "%02x", src[i]);
	dst[len * 2] = '\0';
}

#define sys_entry(e) [SYS_##e] = #e
static const char *syscall_names[500] = {
	sys_entry(open),     sys_entry(openat),	    sys_entry(creat),
	sys_entry(mkdir),    sys_entry(mkdirat),    sys_entry(chdir),
	sys_entry(fchdir),   sys_entry(chmod),	    sys_entry(fchmod),
	sys_entry(chown),    sys_entry(fchown),	    sys_entry(close),
	sys_entry(exit),     sys_entry(exit_group), sys_entry(umask),
	sys_entry(unlink),   sys_entry(rmdir),	    sys_entry(getdents),
	sys_entry(link),     sys_entry(symlink),    sys_entry(getxattr),
	sys_entry(setxattr), sys_entry(execve),	    sys_entry(execveat),
};
#undef sys_entry

static int handle_event(void *ctx, void *data, size_t len)
{
	struct event *e = data;
	char ima_hash_hex[129];
	ima_hash_hex[0] = '\0';
	char evm_hash_hex[129];
	evm_hash_hex[0] = '\0';

	if (e->type == FPUT_EVENT) {
		printf("{ \"call\": \"__fput\", \"proc\": \"%s\", \"pid\": %d, \"euid\": %d, \"egid\": %d, \"time\": %llu ,",
		       e->comm, e->pid, e->euid, e->egid, e->event_start_time);
		hex_encode(e->fput.ima_hash.value, e->fput.ima_hash.size,
			   ima_hash_hex);
		hex_encode(e->fput.evm_hash.value, e->fput.evm_hash.size,
			   evm_hash_hex);
		printf("\"ino\": %u, \"dev\": %u, \"contentHash\": \"%s\", \"contentHashLen\": \"%llu\", \"metaHash\": \"%s\", \"metaHashLen\": \"%llu\"}\n",
		       e->fput.ino, old_encode_dev(e->fput.dev), ima_hash_hex,
		       e->fput.ima_hash.size, evm_hash_hex,
		       e->fput.evm_hash.size);
		return 0;
	}

	printf("{ \"syscall\": \"%s\", \"proc\": \"%s\", \"pid\": %d, \"euid\": %d, \"egid\": %d, \"time\": %llu ,",
	       syscall_names[e->syscall.syscall_nr], e->comm, e->pid, e->euid,
	       e->egid, e->event_start_time);

	switch (e->syscall.syscall_nr) {
	case SYS_open:
		printf("\"pathname\": \"%s\", \"flags\": %d, \"mode\": %d, ",
		       e->syscall.open.pathname, e->syscall.open.flags,
		       e->syscall.open.mode);
		if (e->syscall.ret >= 0)
			printf("\"uid\": %u, \"gid\": %u, "
			       "\"ino\": %u, \"perms\": %u, ",
			       e->syscall.open.uid, e->syscall.open.gid,
			       e->syscall.open.ino, e->syscall.open.perms);
		break;
	case SYS_openat:
		printf("\"dfd\": %d, \"pathname\": \"%s\", \"flags\": %d, \"mode\": %d, ",
		       e->syscall.openat.dfd, e->syscall.openat.pathname,
		       e->syscall.openat.flags, e->syscall.openat.mode);
		if (e->syscall.ret >= 0)
			printf("\"uid\": %u, \"gid\": %u, "
			       "\"ino\": %u, \"perms\": %u, ",
			       e->syscall.openat.uid, e->syscall.openat.gid,
			       e->syscall.openat.ino, e->syscall.openat.perms);
		break;
	case SYS_creat:
		printf("\"pathname\": \"%s\", \"mode\": %d, ",
		       e->syscall.creat.pathname, e->syscall.creat.mode);
		if (e->syscall.ret >= 0)
			printf("\"uid\": %u, \"gid\": %u, "
			       "\"ino\": %u, \"perms\": %u, ",
			       e->syscall.creat.uid, e->syscall.creat.gid,
			       e->syscall.creat.ino, e->syscall.creat.perms);
		break;
	case SYS_mkdir:
		printf("\"pathname\": \"%s\", \"mode\": %d, ",
		       e->syscall.mkdir.pathname, e->syscall.mkdir.mode);
		if (e->syscall.ret == 0)
			printf("\"uid\": %u, \"gid\": %u, "
			       "\"ino\": %u, \"perms\": %u, ",
			       e->syscall.mkdir.uid, e->syscall.mkdir.gid,
			       e->syscall.mkdir.ino, e->syscall.mkdir.perms);
		break;
	case SYS_mkdirat:
		printf("\"dfd\": %d, \"pathname\": \"%s\", \"mode\": %d, ",
		       e->syscall.mkdirat.dfd, e->syscall.mkdirat.pathname,
		       e->syscall.mkdirat.mode);
		if (e->syscall.ret == 0)
			printf("\"uid\": %u, \"gid\": %u, "
			       "\"ino\": %u, \"perms\": %u, ",
			       e->syscall.mkdirat.uid, e->syscall.mkdirat.gid,
			       e->syscall.mkdirat.ino,
			       e->syscall.mkdirat.perms);
		break;
	case SYS_chdir:
		printf("\"dir\": \"%s\", ", e->syscall.chdir.dir);
		break;
	case SYS_fchdir:
		printf("\"fd\": %d, ", e->syscall.fchdir.fd);
		break;
	case SYS_chmod:
		hex_encode(e->syscall.chmod.evm_hash.value,
			   e->syscall.chmod.evm_hash.size, evm_hash_hex);
		printf("\"pathname\": \"%s\", \"mode\": %d, ",
		       e->syscall.chmod.pathname, e->syscall.chmod.mode);
		if (e->syscall.ret == 0)
			printf("\"perms\": %u, \"metaHash\": \"%s\", \"metaHashLen\": %llu,",
			       e->syscall.chmod.perms, evm_hash_hex,
			       e->syscall.chmod.evm_hash.size);
		break;
	case SYS_fchmod:
		hex_encode(e->syscall.fchmod.evm_hash.value,
			   e->syscall.fchmod.evm_hash.size, evm_hash_hex);
		printf("\"fd\": %d, \"mode\": %d, ", e->syscall.fchmod.fd,
		       e->syscall.fchmod.mode);
		if (e->syscall.ret == 0)
			printf("\"perms\": %u, \"metaHash\": \"%s\", \"metaHashLen\": %llu, ",
			       e->syscall.fchmod.perms, evm_hash_hex,
			       e->syscall.fchmod.evm_hash.size);
		break;
	case SYS_chown:
		hex_encode(e->syscall.chown.evm_hash.value,
			   e->syscall.chown.evm_hash.size, evm_hash_hex);
		printf("\"pathname\": \"%s\", \"owner\": %d, \"group\": %d, ",
		       e->syscall.chown.pathname, e->syscall.chown.owner,
		       e->syscall.chown.group);
		if (e->syscall.ret == 0)
			printf("\"perms\": %u, \"metaHash\": \"%s\", \"metaHashLen\": %llu,",
			       e->syscall.chown.perms, evm_hash_hex,
			       e->syscall.chown.evm_hash.size);
		break;
	case SYS_fchown:
		hex_encode(e->syscall.fchown.evm_hash.value,
			   e->syscall.fchown.evm_hash.size, evm_hash_hex);
		printf("\"fd\": \"%d\", \"owner\": %d, \"group\": %d, ",
		       e->syscall.fchown.fd, e->syscall.fchown.owner,
		       e->syscall.fchown.group);
		if (e->syscall.ret == 0)
			printf("\"perms\": %u, \"metaHash\": \"%s\", \"metaHashLen\": %llu,",
			       e->syscall.fchown.perms, evm_hash_hex,
			       e->syscall.fchown.evm_hash.size);
		break;
	case SYS_close:
		printf("\"fd\": %u, \"ino\": %u, \"dev\": %u,",
		       e->syscall.close.fd, e->syscall.close.ino,
		       old_encode_dev(e->syscall.close.dev));
		break;
	case SYS_umask:
		printf("\"mask\": %d,", e->syscall.umask.mask);
		break;
	case SYS_unlink:
		printf("\"pathname\": \"%s\",", e->syscall.unlink.pathname);
		break;
	case SYS_rmdir:
		printf("\"pathname\": \"%s\",", e->syscall.rmdir.pathname);
		break;
	case SYS_getdents:
		printf("\"fd\": %u,", e->syscall.getdents.fd);
		break;
	case SYS_link:
		printf("\"oldname\": \"%s\", \"newname\": \"%s\",",
		       e->syscall.link.oldname, e->syscall.link.newname);
		break;
	case SYS_symlink:
		hex_encode(e->syscall.symlink.ima_hash.value,
			   e->syscall.symlink.ima_hash.size, ima_hash_hex);
		hex_encode(e->syscall.symlink.evm_hash.value,
			   e->syscall.symlink.evm_hash.size, evm_hash_hex);
		printf("\"oldname\": \"%s\", \"newname\": \"%s\", \"contentHash\": \"%s\", \"contentHashLen\": %llu, \"metaHash\": \"%s\", \"metaHashLen\": %llu,",
		       e->syscall.symlink.oldname, e->syscall.symlink.newname,
		       ima_hash_hex, e->syscall.symlink.ima_hash.size,
		       evm_hash_hex, e->syscall.symlink.evm_hash.size);
		break;
	case SYS_getxattr: {
		char *decoded_value;
		__u8 *raw_value = e->syscall.getxattr.value;
		__u64 raw_size = e->syscall.getxattr.size;
		ssize_t size = e->syscall.ret;
		if (raw_size <= 0 || size <= 0) {
			decoded_value = ""; // getxattr fails
		} else if (is_string(raw_value, size + 1)) {
			if (size > 2 && raw_value[0] == 'O' &&
			    raw_value[1] == 's') {
				base64_decode(raw_value, base64_xattr);
				decoded_value = base64_xattr;
			} else {
				static char
					raw[sizeof e->syscall.getxattr.value];
				strncpy(raw, (char *)raw_value, size);
				raw[size] = '\0';
				decoded_value = raw;
			}
		} else {
			hex_encode(raw_value, size, hex_xattr);
			decoded_value = hex_xattr;
		}

		printf("\"pathname\": \"%s\", \"name\": \"%s\", "
		       "\"value\": \"%s\", \"size\": %llu,",
		       e->syscall.getxattr.pathname, e->syscall.getxattr.name,
		       decoded_value, raw_size);
		break;
	}
	case SYS_setxattr: {
		//char *value;
		//struct setxattr *sxattr = &e->setxattr;
		//if (is_string(sxattr->value, sxattr->size)) {
		//    value = sxattr->value;
		//    value[sxattr->size] = '\0';
		//} else {
		//    base64_encode(sxattr->value, sxattr->size, base64_xattr);
		//    value = base64_xattr;
		//}

		printf("\"pathname\": \"%s\", \"name\": \"%s\", "
		       "\"value\": \"%s\", \"size\": %llu, \"flags\": %d,",
		       e->syscall.setxattr.pathname, e->syscall.setxattr.name,
		       e->syscall.setxattr.value, e->syscall.setxattr.size,
		       e->syscall.setxattr.flags);
		break;
	}
	case SYS_execve:
		printf("\"pathname\": \"%s\", "
		       "\"umask\": %d, ",
		       e->syscall.execve.pathname, e->syscall.execve.umask);
		break;
	case SYS_exit:
		printf("\"error_code\": %d,", e->syscall.exit.error_code);
		break;
	case SYS_exit_group:
		printf("\"error_code\": %d,", e->syscall.exit_group.error_code);
		break;
	default:
		fprintf(stderr, "Unknown syscall %d\n", e->syscall.syscall_nr);
		abort();
	}
	printf(" \"ret\": %lld }\n", e->syscall.ret);

	return 0;
}

static volatile int exited = 0;

void set_exited(int sig)
{
	exited = 1;
}

int load(void)
{
	struct syscall_monitor_bpf *skel;
	int err;

	if (!(skel = syscall_monitor_bpf__open_and_load())) {
		fprintf(stderr, "Failed to create skeleton\n");
		return 1;
	}

	if ((err = mkdir(PIN_PATH, 0700)) != 0) {
		fprintf(stderr, "Failed to mkdir " PIN_PATH "; error %d\n",
			err);
		goto END;
	}

	if ((err = mkdir(MAPS_PATH, 0700)) != 0) {
		fprintf(stderr, "Failed to mkdir " MAPS_PATH "; error %d\n",
			err);
		goto END;
	}
	if ((err = bpf_object__pin_maps(skel->obj, MAPS_PATH)) != 0) {
		fprintf(stderr, "Failed to pin maps; error %d\n", err);
	}

	if ((err = mkdir(PROGS_PATH, 0700)) != 0) {
		fprintf(stderr, "Failed to mkdir " PROGS_PATH "; error %d\n",
			err);
		goto END;
	}
	if ((err = bpf_object__pin_programs(skel->obj, PROGS_PATH)) != 0) {
		fprintf(stderr, "Failed to pin programs; error %d\n", err);
		goto END;
	}

	int cfg_fd;
	if ((cfg_fd = bpf_obj_get(MAPS_PATH "/config_map")) < 0) {
		err = cfg_fd;
		fprintf(stderr,
			"Failed to open the pinned map 'config_map'; error %d\n",
			err);
		goto END;
	}
	struct monitor_config cfg = { 0 };
	__u32 key = 0;
	cfg.enabled = 0;
	cfg.filter_tst = 1;
	bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);

	if ((err = syscall_monitor_bpf__attach(skel)) !=
	    0) { // attach all links
		fprintf(stderr, "Failed to attach links; error %d\n", err);
		goto END;
	}

	if ((err = mkdir(LINKS_PATH, 0700)) != 0) {
		fprintf(stderr, "Failed to mkdir " LINKS_PATH "; error %d\n",
			err);
		goto END;
	}
	struct bpf_link **links = (struct bpf_link **)&skel->links;
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_link *link = *links++;
		const char *name = bpf_program__name(prog);

		char path[sizeof LINKS_PATH + 256];
		snprintf(path, sizeof(path), LINKS_PATH "/%s", name);

		if ((err = bpf_link__pin(link, path)) != 0) {
			fprintf(stderr, "Failed to pin link '%s'; error %d\n",
				name, err);
			goto END;
		}
	}

END:
	syscall_monitor_bpf__destroy(skel);
	if (err != 0) {
		system("rm -rf " PIN_PATH);
	}
	return (err == 0 ? 0 : 1);
}

int unload(void)
{
	int err = system("rm -rf " PIN_PATH);
	return (err == 0 ? 0 : 1);
}

int run(int argc, char *argv[])
{
	struct ring_buffer *rb = 0;
	int err = 0;

	int events_fd;
	int cfg_fd = -1;
	if ((events_fd = bpf_obj_get(MAPS_PATH "/events")) < 0) {
		fprintf(stderr,
			"Failed to open the pinned map 'events'; error %d\n",
			events_fd);
		err = events_fd;
		goto END;
	}

	if (!(rb = ring_buffer__new(events_fd, handle_event, 0, 0))) {
		fprintf(stderr, "Failed to allocate the new ring buffer\n");
		err = 1;
		goto END;
	}

	if ((cfg_fd = bpf_obj_get(MAPS_PATH "/config_map")) < 0) {
		fprintf(stderr,
			"Failed to open the pinned map 'config_map'; error %d\n",
			err);
		err = 1;
		goto END;
	}
	struct monitor_config cfg = { 0 };
	__u32 key = 0;
	cfg.enabled = 1;
	cfg.filter_tst = 1;
	bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);

	signal(SIGINT, set_exited);

	pid_t child = 0;
	if ((err = child = fork()) < 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		exited = 1;
	} else if (child == 0) {
		ring_buffer__free(rb);
		execvp(argv[2], &argv[2]);
		fprintf(stderr, "%s: %s\n", argv[2], strerror(errno));
		return 127;
	}

	int status;
	while (!exited) {
		if ((err = ring_buffer__poll(rb, 100)) < 0) {
			if (err != -EINTR) {
				fprintf(stderr,
					"Failed to poll the ring buffer; error %d\n",
					err);
			}
			kill(child, SIGKILL);
			exited = 1;
		} else if (err == 0 && waitpid(child, &status, WNOHANG) > 0) {
			if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
				err = 1; // execvp failed
			}
			exited = 1;
		}
	}

END:
	if (rb)
		ring_buffer__free(rb);

	if (cfg_fd != -1) {
		cfg.enabled = 0;
		bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);
	}

	return err == 0 ? 0 : 1;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s cmd args...\n", argv[0]);
		return 1;
	} else if (strcmp(argv[1], "load") == 0) {
		return load();
	} else if (strcmp(argv[1], "unload") == 0) {
		return unload();
	} else if (strcmp(argv[1], "run") == 0) {
		return run(argc, argv);
	} else {
		fprintf(stderr, "Usage: %s cmd args...\n", argv[0]);
		return 1;
	}
}
