// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * handler.bpf.c: eBPF kernel-space code for curl sandbox
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h> // Include for bpf_ntohs/bpf_ntohl
// #include <linux/socket.h>  // To check value of AF_INET
// #include <linux/fcntl.h>   // To chek value of O_RDWR, O_WRONLY, O_CREAT

#include "handler.h"

// Definitions taken from linux source code

#define O_APPEND   00002000
#define O_TRUNC	   00001000
#define O_CREAT	   00000100
#define O_RDONLY   00000000
#define O_WRONLY   00000001
#define O_RDWR	   00000002
#define EPERM	   1

#define MAY_EXEC   0x00000001
#define MAY_WRITE  0x00000002
#define MAY_READ   0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010

// --- eBPF Maps ---

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, pid_t);
	__type(value, __u32);
} sandboxed_pid SEC(".maps");

// Holds the command name to sandbox (e.g., "curl")
// This is a single-entry array, so key is always {0}
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_COMMAND_LEN]);
} command_to_sandbox SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct lpm_path_key {
	__u32 prefixlen;
	char path[MAX_PATH_LEN];
};

// NEW MAP for FS-001
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(key_size, sizeof(struct lpm_path_key)); // Key is the path string
	__uint(value_size, sizeof(__u32)); // Value can be anything (e.g., 1)
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_write_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16);
	__uint(key_size, sizeof(struct lpm_path_key));
	__uint(value_size, sizeof(__u32));
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_read_paths SEC(".maps");

// NEW MAP for SEC-001
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, char[MAX_FORBIDDEN_LEN]); // Key is the forbidden string
	__type(value, __u32); // Value can be anything (e.g., 1)
} blocked_env_keys SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, pid_t);
	__type(value, __u32); // 1 = block
} block_pid_on_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u32);
} policy_toggle_map SEC(".maps");

/*
 * Logs a network policy violation event
 */
static __always_inline void log_net_violation(struct pt_regs *ctx, enum policy_id policy,
					      __u32 dest_ip, __u16 dest_port)
{
	struct log_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->type = EVENT_NET;
	e->policy_id = policy;
	e->net.dest_ip = dest_ip;
	e->net.dest_port = dest_port;

	bpf_ringbuf_submit(e, 0);
}

/*
 * Logs a file system policy violation event.
 */
static __always_inline void log_fs_violation(struct pt_regs *ctx, enum policy_id policy,
					     const char *path)
{
	struct log_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->type = EVENT_FS;
	e->policy_id = policy;
	bpf_probe_read_user_str(&e->fs.path, sizeof(e->fs.path), path);

	bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename_ptr;
	char filename[MAX_PATH_LEN];
	long basename_idx = 0; // Store index, not pointer to satisfy verifier
	char *target_cmd;
	__u32 key = 0;
	pid_t pid;

	// Get the command to sandbox from the map
	target_cmd = bpf_map_lookup_elem(&command_to_sandbox, &key);
	if (!target_cmd || target_cmd[0] == '\0') {
		return 0; // No command configured
	}

	// Read the filename being executed
	filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
	bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);

// Find the basename *index* (the part after the last '/')
// We do this with a simple, verifier-friendly bounded loop
// basename_ptr = filename; // <-- OLD
#pragma unroll
	for (int i = 0; i < MAX_PATH_LEN; i++) {
		if (filename[i] == '\0') {
			break; // End of string
		}
		if (filename[i] == '/') {
			// basename_ptr = &filename[i+1]; // <-- OLD
			basename_idx = i + 1; // <-- NEW: Store index of char after '/'
		}
	}

	// Compare basename to our target command
	bool match = true;
#pragma unroll
	for (int i = 0; i < MAX_COMMAND_LEN; i++) {
		// --- This is the key verifier-friendly bounds check ---
		long current_idx = basename_idx + i;
		if (current_idx < 0 || current_idx >= MAX_PATH_LEN) {
			match = false; // We've gone past the end of our stack buffer
			break;
		}

		char b_char = filename[current_idx]; // Read char from basename index

		// Check for match termination
		if (target_cmd[i] == '\0') {
			// target_cmd ended. We match if basename also ended.
			// The original code checked for '\n', which is smart
			// for scripts (e.g., #!/usr/bin/curl\n)
			if (b_char == '\0' || b_char == '\n') {
				break; // Good match
			} else {
				match = false; // target_cmd is shorter
				break;
			}
		}

		// Check for mismatch
		if (target_cmd[i] != b_char) {
			match = false;
			break;
		}

		// Check for basename termination (if target_cmd is longer)
		if (b_char == '\0' || b_char == '\n') {
			// Basename ended, but target_cmd[i] was not '\0'
			match = false; // Basename is shorter
			break;
		}
	}

	// If it matches, add this PID to our sandbox map
	if (match) {
		pid = bpf_get_current_pid_tgid() >> 32;
		__u32 value = 1;
		bpf_map_update_elem(&sandboxed_pid, &pid, &value, BPF_ANY);
		bpf_printk("[sandbox] Added PID %d (%s) to sandbox.", pid, &filename[basename_idx]);

		// Check the env variables here itself easily, and flag it if env lsm should block it

		__u32 env_key = TOGGLE_KEY_ENV;
		__u32 *env_toggle = bpf_map_lookup_elem(&policy_toggle_map, &env_key);

		if (env_toggle) {
			// Key exists = wildcard is active
			bpf_printk("[sandbox] Access to all env variables blocked\n");
			__u32 block_val = 1;
			bpf_map_update_elem(&block_pid_on_exec, &pid, &block_val, BPF_ANY);
			bpf_printk("[sandbox] Marked PID %d for blocking - Wildcard env block",
				   pid);
			return 0;
		}

		const char **envp = (const char **)ctx->args[2];
		char env_var[MAX_ENV_LEN];
		bool found_forbidden = false;

		// Check up to MAX_ENV_VARS environment variables
		for (int env_idx = 0; env_idx < MAX_ENV_VARS && !found_forbidden; env_idx++) {
			const char *env_ptr = NULL;

			// Read pointer to env string
			if (bpf_probe_read_user(&env_ptr, sizeof(env_ptr), &envp[env_idx]) < 0)
				break;

			if (!env_ptr)
				break;

			// Read the env string
			long ret = bpf_probe_read_user_str(env_var, sizeof(env_var), env_ptr);
			if (ret <= 1)
				continue;

			int env_len = ret - 1;

			// Find the '=' character to split KEY=VALUE
			int equals_idx = -1;
			for (int j = 0; j < MAX_ENV_LEN && j < env_len; j++) {
				if (env_var[j] == '=') {
					equals_idx = j;
					break;
				}
			}

			if (equals_idx <= 0)
				continue; // No '=' found or key is empty

			// Build the key to check against blocked_env_keys map
			// Must be exact size of map key: char[MAX_FORBIDDEN_LEN]
			char forbidden_key[MAX_FORBIDDEN_LEN];

// Manually zero the array
#pragma unroll
			for (int z = 0; z < MAX_FORBIDDEN_LEN; z++) {
				forbidden_key[z] = 0;
			}

			// Copy the key part (before '=') manually
			int copy_len = equals_idx < MAX_FORBIDDEN_LEN ? equals_idx :
									MAX_FORBIDDEN_LEN - 1;
#pragma unroll
			for (int j = 0; j < MAX_FORBIDDEN_LEN; j++) {
				if (j >= copy_len)
					break;
				forbidden_key[j] = env_var[j];
			}
			bpf_printk("%s", forbidden_key);
			// Check if this key is in the blocked_env_keys map
			if (bpf_map_lookup_elem(&blocked_env_keys, forbidden_key) != NULL) {
				bpf_printk("[sandbox] FORBIDDEN env key found: %.20s",
					   forbidden_key);
				found_forbidden = true;
				break;
			}
		}

		// Mark PID for blocking if forbidden env found
		if (found_forbidden) {
			__u32 block_val = 1;
			bpf_map_update_elem(&block_pid_on_exec, &pid, &block_val, BPF_ANY);
			bpf_printk("[sandbox] Marked PID %d for blocking", pid);
		}
	}

	return 0;
}

/*
 * This hook fires every time a process exits.
 * We check if the exiting PID is in our sandbox map.
 * If so, we remove it to prevent the map from filling up.
 */
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	pid_t pid = BPF_CORE_READ(ctx, pid);

	// Check if the PID is one we are tracking
	if (bpf_map_lookup_elem(&sandboxed_pid, &pid)) {
		// Remove it from the map
		bpf_map_delete_elem(&sandboxed_pid, &pid);
		bpf_printk("[sandbox] Removed PID %d from sandbox.", pid);
	}

	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&sandboxed_pid, &pid)) {
		return 0;
	}

	__u32 fs_key = TOGGLE_KEY_FS;
	__u32 *fs_toggle = bpf_map_lookup_elem(&policy_toggle_map, &fs_key);

	if (fs_toggle) {
		// Key exists = wildcard is active
		bpf_printk(
			"[sandbox-lsm] File System wildcard active, allowing write to all dirs\n");
		return 0;
	}

	// Get directory entry
	struct dentry *dentry = file->f_path.dentry;
	int flags = file->f_flags;
	if (!dentry) {
		return 0;
	}

	char name_ptr[MAX_PATH_LEN];

	bpf_d_path(&file->f_path, name_ptr, MAX_PATH_LEN); // name_ptr exists in kernel space

	char name_ptr_user[sizeof(name_ptr)]; // Move name_ptr to user space
	bpf_probe_read_user(name_ptr_user, sizeof(name_ptr_user), name_ptr);
	bpf_printk("Path: %s", name_ptr);

	// Policy FS-001: Allow file writes ONLY to specific files
	// Check if this is a write operation

	if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) {
		char path_buf[MAX_PATH_LEN];
		__builtin_memset(path_buf, 0, sizeof(path_buf));

		long path_len = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
		bpf_printk("Path len %ld", path_len);
		if (path_len <= 0) {
			return -EPERM;
		}
		// Ensure path_len is within bounds (for verifier)
		if (path_len > sizeof(path_buf)) {
			path_len = sizeof(path_buf);
		}

		// Build the key
		struct lpm_path_key key;
		__builtin_memset(&key, 0, sizeof(key));

		long string_len_bytes = path_len - 1;

		if (string_len_bytes < 0) {
			return -EPERM;
		}
		// path_len from bpf_d_path includes the null terminator
		// key.prefixlen = path_len - 1;
		key.prefixlen = string_len_bytes * 8;

		bpf_printk("Path len = %ld", key.prefixlen);

		// Copy the path string into the key's path field
		bpf_probe_read_kernel(&key.path, sizeof(key.path), path_buf);

		// Look up the key (now 104 bytes) in the map
		if (bpf_map_lookup_elem(&allowed_write_paths, &key) == NULL) {
			bpf_printk("Here");
			log_fs_violation(ctx, POLICY_FS_001_WRITE_PATH, path_buf);
			return -EPERM;
		}
	}

	int access_mode = flags & 3;
	int is_read = (access_mode == O_RDONLY) || (access_mode == O_RDWR);

	if (is_read) {

		char path_buf[MAX_PATH_LEN];
		__builtin_memset(path_buf, 0, sizeof(path_buf));

		long path_len = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
		bpf_printk("Path len %ld", path_len);
		if (path_len <= 0) {
			return -EPERM;
		}
		// Ensure path_len is within bounds (for verifier)
		if (path_len > sizeof(path_buf)) {
			path_len = sizeof(path_buf);
		}

		// Build the key
		struct lpm_path_key key;
		__builtin_memset(&key, 0, sizeof(key));

		long string_len_bytes = path_len - 1;

		if (string_len_bytes < 0) {
			return -EPERM;
		}
		// path_len from bpf_d_path includes the null terminator
		// key.prefixlen = path_len - 1;
		key.prefixlen = string_len_bytes * 8;

		bpf_printk("Path len = %ld", key.prefixlen);

		// Copy the path string into the key's path field
		bpf_probe_read_kernel(&key.path, sizeof(key.path), path_buf);

		__u32 *is_blocked = bpf_map_lookup_elem(&blocked_read_paths, &key);

		if (is_blocked) {
			log_fs_violation(ctx, POLICY_FS_002_READ_PATH, path_buf);
			return -EPERM;
		}
	}

	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_forbidden_env, struct linux_binprm *bprm)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	// Check if this PID should be blocked due to forbidden env vars
	if (bpf_map_lookup_elem(&block_pid_on_exec, &pid)) {
		bpf_printk("[LSM] BLOCKING execution for PID %d (forbidden env)", pid);

		// Cleanup done at sched tracepoint

		return -EPERM;
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
