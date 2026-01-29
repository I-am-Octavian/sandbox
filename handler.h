/*
 * handler.h: Shared definitions for kernel and user-space
 */
#ifndef __HANDLER_H
#define __HANDLER_H

// Max limits set to pass verifier
#define MAX_CMD_LEN 16
#define MAX_PATH_LEN 100

#define MAX_ENV_VARS 35
#define MAX_ENV_LEN 50

#define MAX_DOMAINS 10

#define MAX_FORBIDDEN_STRINGS 3
#define MAX_FORBIDDEN_LEN 50

#define MAX_COMMAND_LEN 100
#define LOG_PATH_LEN 20



/*
 * Enum for identifying which policy was violated.
 */
enum policy_id {
	// Network Policies
	POLICY_NET_001_WHITELIST,   // Blocked by domain whitelist
	POLICY_NET_002_FAMILY,      // Blocked non-AF_INET
	POLICY_NET_005_PRIVATE_IP,  // Blocked private IP
	POLICY_NET_006_PORT,        // Blocked non-80/443 port
	
	// File System Policies
	POLICY_FS_001_WRITE_PATH,   // Blocked write to non-whitelisted path
	POLICY_FS_001_READ_PATH,
	POLICY_FS_006_SYS_PATH,     // Blocked access to system path
};

/*
 * Enum to distinguish event types in the union.
 */
enum event_type {
	EVENT_NET,
	EVENT_FS,
};

/*
 * Data structure for network violation events.
 */
struct net_event_t {
	__u32 dest_ip;
	__u16 dest_port;
};

/*
 * Data structure for file system violation events.
 */
struct fs_event_t {
	char path[MAX_PATH_LEN];
};

/*
 * Main log structure.
 * We use a union to save space in the ring buffer.
 */
struct log_event {
	pid_t pid;
	char comm[MAX_CMD_LEN];
	enum event_type type;
	enum policy_id policy_id;
	
	union {
		struct net_event_t net;
		struct fs_event_t fs;
	};
};

enum policy_toggle_key {
    TOGGLE_KEY_NONE= 0,
    TOGGLE_KEY_NET,
    TOGGLE_KEY_FS,
    TOGGLE_KEY_ENV,
};

// Values for the toggle map
#define POLICY_WILDCARD 1  // Special value for wildcard behavior

#endif /* __HANDLER_H */

