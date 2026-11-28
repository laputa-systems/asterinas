// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SELFCHECK_CASE_ID "core.selfcheck"
#define ADAPTER_CASE_ID "core.adapter"
#define EXT2_CREATE_CASE_ID "ext2.create-read-write"
#define EXT2_SPARSE_CASE_ID "ext2.sparse-truncate"
#define EXT2_LINKS_CASE_ID "ext2.links-rename"
#define EXT2_PERMISSIONS_CASE_ID "ext2.permissions"
#define EXT2_REMOUNT_CASE_ID "ext2.sync-remount"
#define EXT2_ENOSPC_CASE_ID "ext2.enospc-fill"
#define EXT4_READ_CASE_ID "ext4.read"
#define EXT4_MULTIGROUP_CASE_ID "ext4.multi-group"
#define EXT4_SPARSE_CASE_ID "ext4.sparse"
#define EXT4_WRITE_CASE_ID "ext4.write"
#define EXT4_WRITE_READBACK_CASE_ID "ext4.write-linux-readback"
#define EXT4_ALLOC_CASE_ID "ext4.alloc"
#define EXT4_DIR_CASE_ID "ext4.dir"
#define EXT4_ORPHAN_CASE_ID "ext4.orphan"
#define EXT4_XATTR_CASE_ID "ext4.xattr"
#define EXT4_DURABILITY_CASE_ID "ext4.durability"
#define EXT4_ERRORS_CASE_ID "ext4.errors"
#define EXT4_OVERSIZED_SPARSE_CASE_ID "ext4.oversized-sparse-write"
#define FD_EVENTFD_CASE_ID "fd.eventfd"
#define FD_EPOLL_CASE_ID "fd.epoll"
#define FD_PIPE_CASE_ID "fd.pipe"
#define FD_LIFETIME_CASE_ID "fd.lifetime"
#define ERRORS_FSYNC_CASE_ID "errors.fsync"
#define ERRORS_FDATASYNC_CASE_ID "errors.fdatasync"
#define ERRORS_SYNCFS_CASE_ID "errors.syncfs"
#define ERRORS_MSYNC_CASE_ID "errors.msync"
#define PERSISTENCE_SYNCED_CASE_ID "persistence.synced"
#define PERSISTENCE_OMITTED_CASE_ID "persistence.omitted-sync"
#define INPUT_PATH "/qual/input.txt"
#define MISSING_PATH "/qual/no-such-file"
#define SERIAL_PATH "/dev/ttyS1"
#define ADAPTER_SERIAL "qual-lc06-adapter"
#define ADAPTER_MOUNT_POINT "/mnt/qualification"
#define ADAPTER_MARKER_PATH "/mnt/qualification/marker.txt"
#define ADAPTER_ROUNDTRIP_PATH "/mnt/qualification/probe-roundtrip.bin"
#define ADAPTER_ROUNDTRIP_TEXT "qc06-write\n"
#define ADAPTER_NETWORK_INTERFACE "eth0"
#define ADAPTER_WRITE_CACHE "write back"
#define SETUP_SUBTESTS 5
#define SETUP_ASSERTIONS 5

static int serial_fd = -1;
static bool omit_final_sync = false;
static unsigned long sequence = 0;
static char active_case_id[128] = SELFCHECK_CASE_ID;

static void diagnostic(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    fputs("qual-probe: ", stdout);
    vfprintf(stdout, format, arguments);
    fputc('\n', stdout);
    fflush(stdout);
    va_end(arguments);
}

static bool write_all(int fd, const char *data, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, data, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        data += written;
        length -= (size_t)written;
    }
    return true;
}

static void emit_record(const char *record) {
    if (serial_fd < 0) {
        return;
    }
    if (!write_all(serial_fd, record, strlen(record))) {
        diagnostic("failed to write result record: %s", strerror(errno));
    }
}

static void common_fields(char *buffer, size_t size, const char *run_id, const char *nonce,
                          const char *manifest_hash, const char *payload_hash) {
    sequence += 1;
    snprintf(buffer, size,
             "\"case_id\":\"%s\",\"sequence\":%lu,\"manifest_hash\":\"%s\",\"payload_hash\":\"%s\",\"emitted_at\":%ld",
             active_case_id, sequence, manifest_hash, payload_hash, (long)time(NULL));
    (void)run_id;
    (void)nonce;
}

static void emit_start(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    char fields[1024];
    char line[1400];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line), "QUAL %s %s {%s,\"kind\":\"start\"}\n", run_id, nonce, fields);
    emit_record(line);
}

static void emit_string_named(const char *run_id, const char *nonce, const char *manifest_hash,
                              const char *payload_hash, const char *subtest, const char *assertion_id,
                              const char *value, bool passed) {
    char fields[1024];
    char line[1800];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"subtest\",\"subtest\":\"%s\",\"status\":\"%s\",\"assertions\":[{\"id\":\"%s\",\"value\":\"%s\"}]}\n",
             run_id, nonce, fields, subtest, passed ? "pass" : "fail", assertion_id, value);
    emit_record(line);
}

static void emit_bytes_named(const char *run_id, const char *nonce, const char *manifest_hash,
                             const char *payload_hash, const char *subtest, const char *assertion_id,
                             const char *value, bool passed) {
    emit_string_named(run_id, nonce, manifest_hash, payload_hash, subtest, assertion_id, value, passed);
}

static void emit_text_named(const char *run_id, const char *nonce, const char *manifest_hash,
                            const char *payload_hash, const char *subtest, const char *assertion_id,
                            const char *value, bool passed) {
    emit_string_named(run_id, nonce, manifest_hash, payload_hash, subtest, assertion_id, value, passed);
}

static void emit_permission_named(const char *run_id, const char *nonce, const char *manifest_hash,
                                  const char *payload_hash, const char *subtest, const char *assertion_id,
                                  const char *value, bool passed) {
    emit_string_named(run_id, nonce, manifest_hash, payload_hash, subtest, assertion_id, value, passed);
}

static void emit_integer_named(const char *run_id, const char *nonce, const char *manifest_hash,
                                const char *payload_hash, const char *subtest, const char *assertion_id,
                                long value, bool passed) {
    char fields[1024];
    char line[1800];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"subtest\",\"subtest\":\"%s\",\"status\":\"%s\",\"assertions\":[{\"id\":\"%s\",\"value\":%ld}]}\n",
             run_id, nonce, fields, subtest, passed ? "pass" : "fail", assertion_id, value);
    emit_record(line);
}

static void emit_errno_named(const char *run_id, const char *nonce, const char *manifest_hash,
                             const char *payload_hash, const char *subtest, const char *assertion_id,
                             long value, bool passed) {
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, subtest, assertion_id, value, passed);
}

static void emit_errno_subtest(const char *run_id, const char *nonce, const char *manifest_hash,
                               const char *payload_hash, int value, bool passed) {
    char fields[1024];
    char line[1600];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"subtest\",\"subtest\":\"errno-on-failure\",\"status\":\"%s\",\"assertions\":[{\"id\":\"errno\",\"value\":%d}]}\n",
             run_id, nonce, fields, passed ? "pass" : "fail", value);
    emit_record(line);
}

static void emit_bytes_subtest(const char *run_id, const char *nonce, const char *manifest_hash,
                               const char *payload_hash, const char *value, bool passed) {
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "read-fixed-input", "bytes", value, passed);
}

static void emit_permission_subtest(const char *run_id, const char *nonce, const char *manifest_hash,
                                    const char *payload_hash, const char *value, bool passed) {
    char fields[1024];
    char line[1600];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"subtest\",\"subtest\":\"dev-null-write\",\"status\":\"%s\",\"assertions\":[{\"id\":\"permission\",\"value\":\"%s\"}]}\n",
             run_id, nonce, fields, passed ? "pass" : "fail", value);
    emit_record(line);
}

static void emit_final(const char *run_id, const char *nonce, const char *manifest_hash,
                       const char *payload_hash, bool passed, int subtests_completed, int assertions_completed) {
    char fields[1024];
    char line[1800];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"final\",\"status\":\"%s\",\"subtests_completed\":%d,\"assertions_completed\":%d,\"artifacts\":[]}\n",
             run_id, nonce, fields, passed ? "pass" : "fail", subtests_completed, assertions_completed);
    emit_record(line);
    if (serial_fd >= 0) {
        tcdrain(serial_fd);
    }
}

static void copy_value(const char *start, size_t length, char *output, size_t output_size) {
    size_t copied = length < output_size - 1 ? length : output_size - 1;
    memcpy(output, start, copied);
    output[copied] = '\0';
}

static void parse_cmdline(char *cmdline, char *run_id, size_t run_id_size,
                          char *nonce, size_t nonce_size,
                          char *manifest_hash, size_t manifest_hash_size,
                          char *payload_hash, size_t payload_hash_size,
                          char *control, size_t control_size,
                          char *case_id, size_t case_id_size) {
    run_id[0] = '\0';
    nonce[0] = '\0';
    manifest_hash[0] = '\0';
    payload_hash[0] = '\0';
    strcpy(control, "none");
    strcpy(case_id, SELFCHECK_CASE_ID);
    char *save = NULL;
    for (char *token = strtok_r(cmdline, " \t\r\n", &save); token != NULL; token = strtok_r(NULL, " \t\r\n", &save)) {
        struct parameter {
            const char *name;
            char *output;
            size_t size;
        } parameters[] = {
            {"qual.run_id=", run_id, run_id_size},
            {"qual.nonce=", nonce, nonce_size},
            {"qual.manifest_hash=", manifest_hash, manifest_hash_size},
            {"qual.payload_hash=", payload_hash, payload_hash_size},
            {"qual.control=", control, control_size},
            {"qual.case_id=", case_id, case_id_size},
        };
        for (size_t index = 0; index < sizeof(parameters) / sizeof(parameters[0]); index += 1) {
            size_t prefix = strlen(parameters[index].name);
            if (strncmp(token, parameters[index].name, prefix) == 0) {
                copy_value(token + prefix, strlen(token + prefix), parameters[index].output, parameters[index].size);
            }
        }
    }
}

static bool read_cmdline(char *buffer, size_t size) {
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", 0, NULL) != 0 && errno != EBUSY) {
        diagnostic("proc mount failed: %s", strerror(errno));
    }
    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd < 0) {
        diagnostic("open /proc/cmdline failed: %s", strerror(errno));
        return false;
    }
    ssize_t amount = read(fd, buffer, size - 1);
    close(fd);
    if (amount < 0) {
        diagnostic("read /proc/cmdline failed: %s", strerror(errno));
        return false;
    }
    buffer[amount] = '\0';
    return true;
}

static int open_result_serial(void) {
    int fd = open(SERIAL_PATH, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) {
        mknod(SERIAL_PATH, S_IFCHR | 0600, makedev(4, 65));
        fd = open(SERIAL_PATH, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    }
    if (fd < 0) {
        diagnostic("open " SERIAL_PATH " failed: %s", strerror(errno));
        return -1;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    struct termios settings;
    if (tcgetattr(fd, &settings) == 0) {
        settings.c_oflag &= (tcflag_t)~OPOST;
        tcsetattr(fd, TCSANOW, &settings);
    }
    return fd;
}

static void base64_encode(const unsigned char *input, size_t length, char *output, size_t output_size) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out = 0;
    for (size_t index = 0; index < length && out + 4 < output_size; index += 3) {
        unsigned int first = input[index];
        unsigned int second = index + 1 < length ? input[index + 1] : 0;
        unsigned int third = index + 2 < length ? input[index + 2] : 0;
        output[out++] = alphabet[first >> 2];
        output[out++] = alphabet[((first & 3) << 4) | (second >> 4)];
        output[out++] = index + 1 < length ? alphabet[((second & 15) << 2) | (third >> 6)] : '=';
        output[out++] = index + 2 < length ? alphabet[third & 63] : '=';
    }
    output[out] = '\0';
}

static int probe_missing_errno(void) {
    errno = 0;
    int fd = open(MISSING_PATH, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return errno;
}

static size_t probe_input_bytes(char *encoded, size_t encoded_size) {
    unsigned char data[128];
    int fd = open(INPUT_PATH, O_RDONLY);
    if (fd < 0) {
        diagnostic("open input failed: %s", strerror(errno));
        base64_encode((const unsigned char *)"", 0, encoded, encoded_size);
        return 0;
    }
    ssize_t amount = read(fd, data, sizeof(data));
    close(fd);
    if (amount < 0) {
        diagnostic("read input failed: %s", strerror(errno));
        amount = 0;
    }
    base64_encode(data, (size_t)amount, encoded, encoded_size);
    return (size_t)amount;
}

static bool probe_dev_null_write(void) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        diagnostic("open /dev/null failed: %s", strerror(errno));
        return false;
    }
    ssize_t written = write(fd, "q", 1);
    int saved_errno = errno;
    close(fd);
    if (written != 1) {
        diagnostic("write /dev/null failed: %s", strerror(saved_errno));
        return false;
    }
    return true;
}

static size_t read_file_bytes(const char *path, unsigned char *data, size_t capacity) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    ssize_t amount = read(fd, data, capacity);
    close(fd);
    return amount < 0 ? 0 : (size_t)amount;
}

static bool read_first_line(const char *path, char *output, size_t output_size) {
    unsigned char data[256];
    size_t amount = read_file_bytes(path, data, sizeof(data) - 1);
    if (amount == 0) {
        output[0] = '\0';
        return false;
    }
    data[amount] = '\0';
    size_t length = strcspn((const char *)data, "\r\n");
    copy_value((const char *)data, length, output, output_size);
    return true;
}

static bool write_file_bytes(const char *path, const char *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return false;
    }
    bool written = write_all(fd, data, length);
    bool synced = fsync(fd) == 0;
    if (close(fd) != 0) {
        synced = false;
    }
    return written && synced;
}

static void mount_sysfs(void) {
    mkdir("/sys", 0555);
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) != 0 && errno != EBUSY) {
        diagnostic("sysfs mount failed: %s", strerror(errno));
    }
}


static const char *block_sysfs_root(void) {
    struct stat status;
    if (stat("/sys/block", &status) == 0) {
        return "/sys/block";
    }
    return "/sys/class/block";
}

static bool read_serial_candidate(const char *path, const char *expected, char *serial, size_t serial_size) {
    char value[128];
    if (!read_first_line(path, value, sizeof(value))) {
        return false;
    }
    if (serial[0] == '\0') {
        copy_value(value, strlen(value), serial, serial_size);
    }
    return strcmp(value, expected) == 0;
}

static bool find_adapter_disk(char *device_name, size_t device_name_size, char *serial, size_t serial_size) {
    DIR *directory = opendir(block_sysfs_root());
    if (directory == NULL) {
        diagnostic("open block sysfs failed: %s", strerror(errno));
        return false;
    }
    bool found = false;
    serial[0] = '\0';
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL && !found) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[256];
        snprintf(path, sizeof(path), "%s/%s/serial", block_sysfs_root(), entry->d_name);
        bool matches = read_serial_candidate(path, ADAPTER_SERIAL, serial, serial_size);
        if (!matches) {
            snprintf(path, sizeof(path), "%s/%s/device/serial", block_sysfs_root(), entry->d_name);
            matches = read_serial_candidate(path, ADAPTER_SERIAL, serial, serial_size);
        }
        if (matches) {
            copy_value(entry->d_name, strlen(entry->d_name), device_name, device_name_size);
            copy_value(ADAPTER_SERIAL, strlen(ADAPTER_SERIAL), serial, serial_size);
            found = true;
        }
    }
    closedir(directory);
    return found;
}

static bool ensure_device_node(const char *device_name, char *device_path, size_t device_path_size) {
    char sysdev[256];
    char major_minor[64];
    unsigned int major_number = 0;
    unsigned int minor_number = 0;
    snprintf(sysdev, sizeof(sysdev), "%s/%s/dev", block_sysfs_root(), device_name);
    if (!read_first_line(sysdev, major_minor, sizeof(major_minor)) || sscanf(major_minor, "%u:%u", &major_number, &minor_number) != 2) {
        diagnostic("could not resolve device number for %s", device_name);
        return false;
    }
    snprintf(device_path, device_path_size, "/dev/%s", device_name);
    struct stat status;
    if (stat(device_path, &status) != 0) {
        if (mknod(device_path, S_IFBLK | 0600, makedev(major_number, minor_number)) != 0) {
            diagnostic("mknod %s failed: %s", device_path, strerror(errno));
            return false;
        }
    }
    return true;
}

static void drop_sys_admin_capability(void) {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[2];
    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &header, data) != 0) {
        diagnostic("capget failed: %s", strerror(errno));
        return;
    }
    unsigned int index = CAP_SYS_ADMIN / 32;
    unsigned int mask = 1U << (CAP_SYS_ADMIN % 32);
    data[index].effective &= ~mask;
    data[index].permitted &= ~mask;
    data[index].inheritable &= ~mask;
    if (syscall(SYS_capset, &header, data) != 0) {
        diagnostic("capset failed: %s", strerror(errno));
    } else {
        diagnostic("dropped CAP_SYS_ADMIN");
    }
}



struct storage_setup {
    char device_name[64];
    char serial[128];
    char write_cache[128];
    char filesystem[64];
    char device_path[128];
    int mount_errno;
    int uid;
    bool disk_found;
    bool cache_ok;
    bool privilege_ok;
    bool mounted;
};

static bool have_sys_admin(void) {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[2];
    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &header, data) != 0) {
        diagnostic("capget failed: %s", strerror(errno));
        return false;
    }
    unsigned int index = CAP_SYS_ADMIN / 32;
    unsigned int mask = 1U << (CAP_SYS_ADMIN % 32);
    return (data[index].effective & mask) != 0;
}

static void read_mount_filesystem(char *output, size_t output_size) {
    output[0] = '\0';
    int fd = open("/proc/mounts", O_RDONLY);
    if (fd < 0) {
        diagnostic("open /proc/mounts failed: %s", strerror(errno));
        return;
    }
    char buffer[8192];
    ssize_t amount = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (amount < 0) {
        return;
    }
    buffer[amount] = '\0';
    for (char *line = strtok(buffer, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        char source[256];
        char mount_point[256];
        char filesystem[64];
        if (sscanf(line, "%255s %255s %63s", source, mount_point, filesystem) == 3 &&
            strcmp(mount_point, ADAPTER_MOUNT_POINT) == 0) {
            copy_value(filesystem, strlen(filesystem), output, output_size);
            return;
        }
    }
}

static bool is_ext4_case(void) {
    return strcmp(active_case_id, EXT4_READ_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_MULTIGROUP_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_SPARSE_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_WRITE_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_WRITE_READBACK_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_ALLOC_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_DIR_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_ORPHAN_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_XATTR_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_DURABILITY_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_ERRORS_CASE_ID) == 0 ||
           strcmp(active_case_id, EXT4_OVERSIZED_SPARSE_CASE_ID) == 0;
}

static const char *expected_mount_filesystem(void) {
    return is_ext4_case() ? "ext4" : "ext2";
}

static void setup_storage_volume(struct storage_setup *setup) {
    memset(setup, 0, sizeof(*setup));
    setup->mount_errno = ENODEV;
    setup->uid = (int)getuid();
    mount_sysfs();
    setup->disk_found = find_adapter_disk(setup->device_name, sizeof(setup->device_name),
                                          setup->serial, sizeof(setup->serial));
    if (!setup->disk_found) {
        diagnostic("scratch disk with the manifest serial was not found");
        return;
    }
    char cache_path[256];
    snprintf(cache_path, sizeof(cache_path), "%s/%s/queue/write_cache", block_sysfs_root(), setup->device_name);
    if (!read_first_line(cache_path, setup->write_cache, sizeof(setup->write_cache))) {
        snprintf(cache_path, sizeof(cache_path), "%s/%s/write_cache", block_sysfs_root(), setup->device_name);
        read_first_line(cache_path, setup->write_cache, sizeof(setup->write_cache));
    }
    setup->cache_ok = strcmp(setup->write_cache, ADAPTER_WRITE_CACHE) == 0;
    if (!setup->cache_ok) {
        diagnostic("scratch disk write cache is %s, expected %s", setup->write_cache, ADAPTER_WRITE_CACHE);
    }
    setup->privilege_ok = setup->uid == 0 && have_sys_admin();
    if (!setup->privilege_ok) {
        diagnostic("required guest privilege is unavailable: uid=%d", setup->uid);
    }
    if (!ensure_device_node(setup->device_name, setup->device_path, sizeof(setup->device_path))) {
        return;
    }
    mkdir("/mnt", 0555);
    mkdir(ADAPTER_MOUNT_POINT, 0555);
    int mount_flags =
        (is_ext4_case() && strcmp(active_case_id, EXT4_WRITE_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_ALLOC_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_DIR_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_ORPHAN_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_XATTR_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_DURABILITY_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_ERRORS_CASE_ID) != 0 &&
         strcmp(active_case_id, EXT4_OVERSIZED_SPARSE_CASE_ID) != 0) ? MS_RDONLY : 0;
    if (mount(setup->device_path, ADAPTER_MOUNT_POINT, expected_mount_filesystem(), mount_flags, NULL) != 0) {
        setup->mount_errno = errno;
        diagnostic("filesystem mount failed: %s", strerror(errno));
        return;
    }
    setup->mounted = true;
    read_mount_filesystem(setup->filesystem, sizeof(setup->filesystem));
}

static bool storage_setup_ok(const struct storage_setup *setup) {
    return setup->disk_found && strcmp(setup->serial, ADAPTER_SERIAL) == 0 && setup->cache_ok &&
           setup->privilege_ok && setup->mounted &&
           strcmp(setup->filesystem, expected_mount_filesystem()) == 0;
}

static void emit_setup_observations(const char *run_id, const char *nonce, const char *manifest_hash,
                                    const char *payload_hash, const struct storage_setup *setup) {
    bool serial_ok = strcmp(setup->serial, ADAPTER_SERIAL) == 0;
    bool cache_ok = strcmp(setup->write_cache, ADAPTER_WRITE_CACHE) == 0;
    bool filesystem_ok = strcmp(setup->filesystem, expected_mount_filesystem()) == 0;
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "setup-disk-identity", "serial", setup->serial, serial_ok);
    emit_text_named(run_id, nonce, manifest_hash, payload_hash, "setup-write-cache", "mode", setup->write_cache, cache_ok);
    emit_text_named(run_id, nonce, manifest_hash, payload_hash, "setup-filesystem", "filesystem", setup->filesystem, filesystem_ok);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "setup-mount", "result", setup->mounted ? 0 : -1, setup->mounted);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "setup-privilege", "uid", setup->uid, setup->privilege_ok);
}

static bool begin_storage_case(const char *run_id, const char *nonce, const char *manifest_hash,
                               const char *payload_hash, struct storage_setup *setup) {
    setup_storage_volume(setup);
    emit_setup_observations(run_id, nonce, manifest_hash, payload_hash, setup);
    bool ok = storage_setup_ok(setup);
    if (!ok) {
        diagnostic("storage setup failed; operation assertions are not exercised");
    }
    return ok;
}

static void unmount_adapter_volume(void) {
    if (!omit_final_sync) {
        sync();
    }
    if (umount(ADAPTER_MOUNT_POINT) != 0) {
        diagnostic("ext2 umount failed: %s", strerror(errno));
    }
}

static bool read_all(int fd, char *data, size_t length) {
    while (length > 0) {
        ssize_t amount = read(fd, data, length);
        if (amount < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (amount == 0) {
            return false;
        }
        data += amount;
        length -= (size_t)amount;
    }
    return true;
}

static size_t read_file_base64(const char *path, char *encoded, size_t encoded_size) {
    unsigned char data[256];
    size_t amount = read_file_bytes(path, data, sizeof(data));
    base64_encode(data, amount, encoded, encoded_size);
    return amount;
}

static size_t read_at_base64(int fd, off_t offset, size_t length, char *encoded, size_t encoded_size) {
    unsigned char data[64];
    if (length > sizeof(data)) {
        encoded[0] = '\0';
        return 0;
    }
    ssize_t amount = pread(fd, data, length, offset);
    if (amount < 0) {
        amount = 0;
    }
    base64_encode(data, (size_t)amount, encoded, encoded_size);
    return (size_t)amount;
}

static void make_case_directory(const char *path) {
    if (mkdir(path, 0755) != 0) {
        diagnostic("mkdir %s failed: %s", path, strerror(errno));
    }
}

static void run_ext4_file_case(const char *run_id, const char *nonce, const char *manifest_hash,
                               const char *payload_hash, const char *name, const char *expected_b64,
                               long expected_size, bool check_sparse_tail) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", ADAPTER_MOUNT_POINT, name);
    struct storage_setup setup;
    char marker_b64[256] = "";
    char tail_b64[64] = "";
    long size = -1;
    bool mounted = begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup);
    if (mounted) {
        read_file_base64(path, marker_b64, sizeof(marker_b64));
        struct stat status;
        if (stat(path, &status) == 0) {
            size = (long)status.st_size;
        }
        if (check_sparse_tail) {
            char sparse_path[256];
            snprintf(sparse_path, sizeof(sparse_path), "%s/sparse.bin", ADAPTER_MOUNT_POINT);
            int fd = open(sparse_path, O_RDONLY);
            if (fd >= 0) {
                read_at_base64(fd, 12 * 1024 * 1024, 5, tail_b64, sizeof(tail_b64));
                close(fd);
            }
        }
        unmount_adapter_volume();
    }
    bool bytes_passed = strcmp(marker_b64, expected_b64) == 0;
    bool size_passed = size == expected_size;
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "marker-read", "bytes", marker_b64, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-size", "bytes", size, size_passed);
    int extra = 2;
    bool tail_passed = true;
    if (check_sparse_tail) {
        tail_passed = strcmp(tail_b64, "dGFpbAo=") == 0;
        emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "sparse-tail", "bytes", tail_b64, tail_passed);
        extra += 1;
    }
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               mounted && bytes_passed && size_passed && tail_passed,
               SETUP_SUBTESTS + extra, SETUP_ASSERTIONS + extra);
}

static void run_ext4_errors_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *path = ADAPTER_MOUNT_POINT "/errors.txt";
    const char *content = "lc23-error\n";
    struct storage_setup setup;
    char roundtrip[256] = "";
    long rejected = 0;
    long written = -1;
    long fsync_result = -1;
    long size = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            int directory = open(ADAPTER_MOUNT_POINT, O_RDONLY | O_DIRECTORY);
            if (directory >= 0) {
                if (write(directory, content, strlen(content)) < 0) {
                    rejected = 1;
                }
                close(directory);
            }
            written = write(fd, content, strlen(content));
            fsync_result = fsync(fd);
            close(fd);
            read_file_base64(path, roundtrip, sizeof(roundtrip));
            struct stat status;
            if (stat(path, &status) == 0) {
                size = (long)status.st_size;
            }
        } else {
            diagnostic("ext4 errors create failed: %s", strerror(errno));
        }
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool rejected_passed = rejected == 1;
    bool write_passed = written == 11;
    bool fsync_passed = fsync_result == 0;
    bool bytes_passed = strcmp(roundtrip, "bGMyMy1lcnJvcgo=") == 0;
    bool size_passed = size == 11;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "directory-fd-write-rejected", "rejected", rejected, rejected_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "post-error-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "post-error-fsync", "result", fsync_result, fsync_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "post-error-read", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "post-error-size", "bytes", size, size_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               rejected_passed && write_passed && fsync_passed && bytes_passed && size_passed,
               SETUP_SUBTESTS + 5, SETUP_ASSERTIONS + 5);
}

static void run_ext4_oversized_sparse_case(const char *run_id, const char *nonce,
                                           const char *manifest_hash, const char *payload_hash) {
    struct storage_setup setup;
    if (!begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    const off_t offset = 128 * 1024 * 1024;
    int fd = open(ADAPTER_MOUNT_POINT "/oversized-sparse.txt", O_RDWR | O_CREAT | O_EXCL, 0640);
    long written = -1;
    long size = -1;
    char hole[8] = "";
    char tail[8] = "";
    if (fd >= 0) {
        written = pwrite(fd, "S", 1, offset);
        struct stat status;
        if (fstat(fd, &status) == 0) {
            size = (long)status.st_size;
        }
        read_at_base64(fd, 0, 1, hole, sizeof(hole));
        read_at_base64(fd, offset, 1, tail, sizeof(tail));
        close(fd);
    }
    unmount_adapter_volume();
    bool written_ok = written == 1;
    bool size_ok = size == offset + 1;
    bool hole_ok = strcmp(hole, "AA==") == 0;
    bool tail_ok = strcmp(tail, "Uw==") == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "sparse-write", "result", written, written_ok);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "sparse-size", "bytes", size, size_ok);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "sparse-hole", "bytes", hole, hole_ok);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "sparse-tail", "bytes", tail, tail_ok);
    emit_final(run_id, nonce, manifest_hash, payload_hash, written_ok && size_ok && hole_ok && tail_ok,
               SETUP_SUBTESTS + 4, SETUP_ASSERTIONS + 4);
}

static void run_ext4_durability_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/durable";
    const char *path = ADAPTER_MOUNT_POINT "/durable/data.txt";
    const char *content = "lc25-durable\n";
    struct storage_setup setup;
    char roundtrip[256] = "";
    long made_dir = 0;
    long written = -1;
    long file_fsync = -1;
    long directory_fsync = -1;
    long clean_umount = -1;
    long remount_result = -1;
    long size = -1;
    long final_umount = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        made_dir = mkdir(directory_path, 0750) == 0 ? 1 : 0;
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            written = write_all(fd, content, strlen(content));
            file_fsync = fsync(fd);
            close(fd);
        }
        int directory = open(directory_path, O_RDONLY | O_DIRECTORY);
        if (directory >= 0) {
            directory_fsync = fsync(directory);
            close(directory);
        }
        sync();
        clean_umount = umount(ADAPTER_MOUNT_POINT);
        if (clean_umount == 0) {
            if (mount(setup.device_path, ADAPTER_MOUNT_POINT, "ext4", 0, NULL) == 0) {
                remount_result = 0;
                read_file_base64(path, roundtrip, sizeof(roundtrip));
                struct stat status;
                if (stat(path, &status) == 0) {
                    size = (long)status.st_size;
                }
                sync();
                final_umount = umount(ADAPTER_MOUNT_POINT);
            } else {
                diagnostic("ext4 durability remount failed: %s", strerror(errno));
            }
        } else {
            diagnostic("ext4 durability umount failed: %s", strerror(errno));
            unmount_adapter_volume();
        }
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool dir_passed = made_dir == 1;
    bool write_passed = written == 1;
    bool file_passed = file_fsync == 0;
    bool dirsync_passed = directory_fsync == 0;
    bool umount_passed = clean_umount == 0;
    bool remount_passed = remount_result == 0;
    bool bytes_passed = strcmp(roundtrip, "bGMyNS1kdXJhYmxlCg==") == 0;
    bool size_passed = size == 13;
    bool final_passed = final_umount == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "mkdir", "result", made_dir, dir_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", file_fsync, file_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "directory-fsync", "result", directory_fsync, dirsync_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "clean-umount", "result", clean_umount, umount_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "remount", "result", remount_result, remount_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "persistent-data", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "persistent-size", "bytes", size, size_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-umount", "result", final_umount, final_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               dir_passed && write_passed && file_passed && dirsync_passed && umount_passed && remount_passed &&
               bytes_passed && size_passed && final_passed,
               SETUP_SUBTESTS + 9, SETUP_ASSERTIONS + 9);
}

static void run_ext4_xattr_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *path = ADAPTER_MOUNT_POINT "/xattr.txt";
    const char *expected = "lc23-xattr\n";
    struct storage_setup setup;
    char value[64] = "";
    char listing[256] = "";
    long written = -1;
    long set_result = -1;
    long get_size = -1;
    long list_size = -1;
    long remove_result = -1;
    long after_remove_errno = 0;
    long retained_result = -1;
    long unmount_result = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            written = write(fd, expected, strlen(expected));
            close(fd);
            set_result = setxattr(path, "user.test", "value", 5, 0);
            get_size = getxattr(path, "user.test", value, sizeof(value));
            list_size = listxattr(path, listing, sizeof(listing));
            remove_result = removexattr(path, "user.test");
            char probe[64];
            after_remove_errno = getxattr(path, "user.test", probe, sizeof(probe)) < 0 ? errno : 0;
            retained_result = setxattr(path, "user.test", "retained", 8, XATTR_CREATE);
        } else {
            diagnostic("ext4 xattr create failed: %s", strerror(errno));
        }
        unmount_result = umount(ADAPTER_MOUNT_POINT);
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool write_passed = written == 11;
    bool set_passed = set_result == 0;
    bool get_passed = get_size == 5 && strcmp(value, "value") == 0;
    bool list_passed = list_size == 10 && strcmp(listing, "user.test") == 0;
    bool remove_passed = remove_result == 0;
    bool gone_passed = after_remove_errno == ENODATA;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "setxattr", "result", set_result, set_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "getxattr-size", "bytes", get_size, get_size == 5);
    emit_text_named(run_id, nonce, manifest_hash, payload_hash, "getxattr-value", "value", value, strcmp(value, "value") == 0);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "listxattr-size", "bytes", list_size, list_size == 10);
    emit_text_named(run_id, nonce, manifest_hash, payload_hash, "listxattr-names", "names", listing, strcmp(listing, "user.test") == 0);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "removexattr", "result", remove_result, remove_passed);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "after-remove", "errno", after_remove_errno, gone_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "retain-xattr", "result", retained_result, retained_result == 0);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "unmount", "result", unmount_result, unmount_result == 0);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               write_passed && set_passed && get_passed && list_passed && remove_passed && gone_passed &&
               retained_result == 0 && unmount_result == 0,
               SETUP_SUBTESTS + 10, SETUP_ASSERTIONS + 10);
}

static void run_ext4_orphan_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *path = ADAPTER_MOUNT_POINT "/orphan.txt";
    const char *first = "lc22-orphan\n";
    const char *second = "lc22-after\n";
    struct storage_setup setup;
    long written = -1;
    long fsync_result = -1;
    long unlink_result = -1;
    long gone = 0;
    long after_unlink_write = -1;
    long close_result = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            written = write(fd, first, strlen(first));
            fsync_result = fsync(fd);
            unlink_result = unlink(path);
            struct stat status;
            gone = (stat(path, &status) == 0) ? 0 : 1;
            after_unlink_write = write(fd, second, strlen(second));
            close_result = close(fd);
        } else {
            diagnostic("ext4 orphan create failed: %s", strerror(errno));
        }
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool write_passed = written == 12;
    bool fsync_passed = fsync_result == 0;
    bool unlink_passed = unlink_result == 0;
    bool gone_passed = gone == 1;
    bool after_passed = after_unlink_write == 11;
    bool close_passed = close_result == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", fsync_result, fsync_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "open-unlink", "result", unlink_result, unlink_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "after-unlink", "gone", gone, gone_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "write-after-unlink", "bytes_written", after_unlink_write, after_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "close", "result", close_result, close_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               write_passed && fsync_passed && unlink_passed && gone_passed && after_passed && close_passed,
               SETUP_SUBTESTS + 6, SETUP_ASSERTIONS + 6);
}

static void run_ext4_dir_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *dir = ADAPTER_MOUNT_POINT "/subdir";
    const char *file = ADAPTER_MOUNT_POINT "/subdir/data.txt";
    const char *hardlink = ADAPTER_MOUNT_POINT "/hardlink.txt";
    const char *renamed = ADAPTER_MOUNT_POINT "/renamed.txt";
    const char *expected = "lc21-dir\n";
    struct storage_setup setup;
    char roundtrip[256] = "";
    long mkdir_result = -1;
    long is_dir = 0;
    long written = -1;
    long fsync_result = -1;
    long link_result = -1;
    long rename_result = -1;
    long link_count = -1;
    long rmdir_result = 0;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        mkdir_result = mkdir(dir, 0750);
        struct stat dirstat;
        if (stat(dir, &dirstat) == 0 && S_ISDIR(dirstat.st_mode)) {
            is_dir = 1;
        }
        int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            written = write(fd, expected, strlen(expected));
            fsync_result = fsync(fd);
            close(fd);
        } else {
            diagnostic("ext4 dir create failed: %s", strerror(errno));
        }
        link_result = link(file, hardlink);
        rename_result = rename(hardlink, renamed);
        read_file_base64(renamed, roundtrip, sizeof(roundtrip));
        struct stat linkstat;
        if (stat(renamed, &linkstat) == 0) {
            link_count = (long)linkstat.st_nlink;
        }
        rmdir_result = rmdir(dir) == 0 ? 1 : 0;
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool mkdir_passed = mkdir_result == 0;
    bool dir_passed = is_dir == 1;
    bool write_passed = written == 9;
    bool fsync_passed = fsync_result == 0;
    bool link_passed = link_result == 0;
    bool rename_passed = rename_result == 0;
    bool bytes_passed = strcmp(roundtrip, "bGMyMS1kaXIK") == 0;
    bool links_passed = link_count == 2;
    bool rmdir_passed = rmdir_result == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "mkdir", "result", mkdir_result, mkdir_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "dir-type", "is_dir", is_dir, dir_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", fsync_result, fsync_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "link", "result", link_result, link_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "rename", "result", rename_result, rename_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "read-renamed", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "link-count", "nlink", link_count, links_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "rmdir-nonempty", "rejected", rmdir_result, rmdir_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               mkdir_passed && dir_passed && write_passed && fsync_passed && link_passed &&
               rename_passed && bytes_passed && links_passed && rmdir_passed,
               SETUP_SUBTESTS + 9, SETUP_ASSERTIONS + 9);
}

static void run_ext4_alloc_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *path = ADAPTER_MOUNT_POINT "/alloc.txt";
    const char *expected = "lc20-alloc\n";
    struct storage_setup setup;
    char roundtrip[256] = "";
    long written = -1;
    long fsync_result = -1;
    long size = -1;
    long unlink_result = -1;
    long after_unlink = 0;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            written = write(fd, expected, strlen(expected));
            fsync_result = fsync(fd);
            close(fd);
        } else {
            diagnostic("ext4 alloc create failed: %s", strerror(errno));
        }
        read_file_base64(path, roundtrip, sizeof(roundtrip));
        struct stat status;
        if (stat(path, &status) == 0) {
            size = (long)status.st_size;
        }
        unlink_result = unlink(path);
        struct stat gone;
        after_unlink = (stat(path, &gone) == 0) ? 0 : 1;
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool write_passed = written == 11;
    bool fsync_passed = fsync_result == 0;
    bool bytes_passed = strcmp(roundtrip, "bGMyMC1hbGxvYwo=") == 0;
    bool size_passed = size == 11;
    bool unlink_passed = unlink_result == 0;
    bool gone_passed = after_unlink == 1;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", fsync_result, fsync_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "reopen-read", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-size", "bytes", size, size_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "unlink", "result", unlink_result, unlink_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "after-unlink", "gone", after_unlink, gone_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               write_passed && fsync_passed && bytes_passed && size_passed && unlink_passed && gone_passed,
               SETUP_SUBTESTS + 6, SETUP_ASSERTIONS + 6);
}

static void run_ext4_write_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *path = ADAPTER_MOUNT_POINT "/marker.txt";
    const char *expected = "lc19-journal\n";
    struct storage_setup setup;
    char roundtrip[256] = "";
    long written = -1;
    long fsync_result = -1;
    long size = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) {
            written = write(fd, expected, strlen(expected));
            fsync_result = fsync(fd);
            close(fd);
        } else {
            diagnostic("ext4 write open failed: %s", strerror(errno));
        }
        read_file_base64(path, roundtrip, sizeof(roundtrip));
        struct stat status;
        if (stat(path, &status) == 0) {
            size = (long)status.st_size;
        }
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool write_passed = written == 13;
    bool fsync_passed = fsync_result == 0;
    bool bytes_passed = strcmp(roundtrip, "bGMxOS1qb3VybmFsCg==") == 0;
    bool size_passed = size == 13;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", fsync_result, fsync_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "reopen-read", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-size", "bytes", size, size_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               write_passed && fsync_passed && bytes_passed && size_passed,
               SETUP_SUBTESTS + 4, SETUP_ASSERTIONS + 4);
}

static void run_ext4_read_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    run_ext4_file_case(run_id, nonce, manifest_hash, payload_hash,
                       "marker.txt", "bGMxNC1iYXNpYwo=", 11, false);
}

static void run_ext4_multigroup_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    run_ext4_file_case(run_id, nonce, manifest_hash, payload_hash,
                       "f64.txt", "Z3JvdXAtMDY0Cg==", 10, false);
}

static void run_ext4_sparse_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    run_ext4_file_case(run_id, nonce, manifest_hash, payload_hash,
                       "marker.txt", "bGMxNC1zcGFyc2UK", 12, true);
}

static void run_ext2_create_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/create-read-write";
    const char *path = ADAPTER_MOUNT_POINT "/create-read-write/data.bin";
    const char *expected_text = "ext2-create-write\n";
    const size_t expected_length = strlen(expected_text);
    struct storage_setup setup;
    char roundtrip[256] = "";
    long written = -1;
    long fsync_result = -1;
    long size = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        make_case_directory(directory_path);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
        if (fd >= 0) {
            written = write(fd, expected_text, expected_length);
            fsync_result = fsync(fd);
            close(fd);
        } else {
            diagnostic("create open failed: %s", strerror(errno));
        }
        read_file_base64(path, roundtrip, sizeof(roundtrip));
        struct stat status;
        if (stat(path, &status) == 0) {
            size = (long)status.st_size;
        }
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool write_passed = written == (long)expected_length;
    bool fsync_passed = fsync_result == 0;
    bool bytes_passed = strcmp(roundtrip, "ZXh0Mi1jcmVhdGUtd3JpdGUK") == 0;
    bool size_passed = size == (long)expected_length;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "create-write", "bytes_written", written, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", fsync_result, fsync_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "reopen-read", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-size", "bytes", size, size_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash, write_passed && fsync_passed && bytes_passed && size_passed,
               SETUP_SUBTESTS + 4, SETUP_ASSERTIONS + 4);
}

static void run_ext2_sparse_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/sparse-truncate";
    const char *path = ADAPTER_MOUNT_POINT "/sparse-truncate/sparse.bin";
    struct storage_setup setup;
    char hole[64] = "";
    char extended[64] = "";
    long write_result = -1;
    long initial_size = -1;
    long shrink_result = -1;
    long extend_result = -1;
    long final_size = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        make_case_directory(directory_path);
        int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) {
            write_result = pwrite(fd, "END!", 4, 8192);
            struct stat status;
            if (fstat(fd, &status) == 0) {
                initial_size = (long)status.st_size;
            }
            read_at_base64(fd, 4096, 16, hole, sizeof(hole));
            shrink_result = ftruncate(fd, 4096);
            extend_result = ftruncate(fd, 12288);
            read_at_base64(fd, 8192, 16, extended, sizeof(extended));
            if (fstat(fd, &status) == 0) {
                final_size = (long)status.st_size;
            }
            close(fd);
        } else {
            diagnostic("sparse open failed: %s", strerror(errno));
        }
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool write_passed = write_result == 4;
    bool initial_size_passed = initial_size == 8196;
    bool hole_passed = strcmp(hole, "AAAAAAAAAAAAAAAAAAAAAA==") == 0;
    bool shrink_passed = shrink_result == 0;
    bool extend_passed = extend_result == 0;
    bool extended_passed = strcmp(extended, "AAAAAAAAAAAAAAAAAAAAAA==") == 0;
    bool final_size_passed = final_size == 12288;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "sparse-write", "bytes_written", write_result, write_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "sparse-size", "bytes", initial_size, initial_size_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "hole-zeroing", "bytes", hole, hole_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "truncate-shrink", "result", shrink_result, shrink_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "truncate-extend", "result", extend_result, extend_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "extend-zeroing", "bytes", extended, extended_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-size", "bytes", final_size, final_size_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               write_passed && initial_size_passed && hole_passed && shrink_passed && extend_passed && extended_passed && final_size_passed,
               SETUP_SUBTESTS + 7, SETUP_ASSERTIONS + 7);
}

static void run_ext2_links_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/links-rename";
    const char *original = ADAPTER_MOUNT_POINT "/links-rename/original";
    const char *hardlink = ADAPTER_MOUNT_POINT "/links-rename/hardlink";
    const char *symlink_path = ADAPTER_MOUNT_POINT "/links-rename/alias";
    const char *renamed = ADAPTER_MOUNT_POINT "/links-rename/renamed";
    const char *content = "link-target\n";
    struct storage_setup setup;
    char hardlink_bytes[256] = "";
    char symlink_bytes[256] = "";
    char symlink_target[128] = "";
    long hardlink_result = -1;
    long link_count = -1;
    long symlink_result = -1;
    long rename_result = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        make_case_directory(directory_path);
        write_file_bytes(original, content, strlen(content));
        hardlink_result = link(original, hardlink);
        struct stat status;
        if (stat(hardlink, &status) == 0) {
            link_count = (long)status.st_nlink;
        }
        symlink_result = symlink("renamed", symlink_path);
        ssize_t target_length = readlink(symlink_path, symlink_target, sizeof(symlink_target) - 1);
        if (target_length >= 0) {
            symlink_target[target_length] = '\0';
        }
        rename_result = rename(original, renamed);
        read_file_base64(hardlink, hardlink_bytes, sizeof(hardlink_bytes));
        read_file_base64(symlink_path, symlink_bytes, sizeof(symlink_bytes));
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool hardlink_create_passed = hardlink_result == 0;
    bool count_passed = link_count == 2;
    bool symlink_create_passed = symlink_result == 0;
    bool target_passed = strcmp(symlink_target, "renamed") == 0;
    bool rename_passed = rename_result == 0;
    bool hardlink_read_passed = strcmp(hardlink_bytes, "bGluay10YXJnZXQK") == 0;
    bool symlink_read_passed = strcmp(symlink_bytes, "bGluay10YXJnZXQK") == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "hardlink-create", "result", hardlink_result, hardlink_create_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "hardlink-count", "links", link_count, count_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "symlink-create", "result", symlink_result, symlink_create_passed);
    emit_text_named(run_id, nonce, manifest_hash, payload_hash, "symlink-target", "target", symlink_target, target_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "rename", "result", rename_result, rename_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "hardlink-read", "bytes", hardlink_bytes, hardlink_read_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "symlink-read", "bytes", symlink_bytes, symlink_read_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               hardlink_create_passed && count_passed && symlink_create_passed && target_passed && rename_passed &&
                   hardlink_read_passed && symlink_read_passed,
               SETUP_SUBTESTS + 7, SETUP_ASSERTIONS + 7);
}

struct permission_observation {
    int setup_failed;
    int private_allowed;
    int private_errno;
    int readonly_allowed;
    int readonly_errno;
    int public_allowed;
};

static void observe_open_permission(const char *path, int flags, int *allowed, int *error_number) {
    errno = 0;
    int fd = open(path, flags);
    if (fd >= 0) {
        *allowed = 1;
        *error_number = 0;
        close(fd);
    } else {
        *allowed = 0;
        *error_number = errno;
    }
}

static bool collect_permission_observation(struct permission_observation *observation) {
    int pipes[2];
    if (pipe(pipes) != 0) {
        diagnostic("permission pipe failed: %s", strerror(errno));
        return false;
    }
    pid_t child = fork();
    if (child == 0) {
        close(pipes[0]);
        struct permission_observation child_observation = {0};
        if (setgid(65534) != 0 || setuid(65534) != 0) {
            child_observation.setup_failed = 1;
        } else {
            observe_open_permission(ADAPTER_MOUNT_POINT "/permissions/private.txt", O_RDONLY,
                                    &child_observation.private_allowed, &child_observation.private_errno);
            observe_open_permission(ADAPTER_MOUNT_POINT "/permissions/readonly.txt", O_WRONLY,
                                    &child_observation.readonly_allowed, &child_observation.readonly_errno);
            int public_errno = 0;
            observe_open_permission(ADAPTER_MOUNT_POINT "/permissions/public.txt", O_RDONLY,
                                    &child_observation.public_allowed, &public_errno);
        }
        write_all(pipes[1], (const char *)&child_observation, sizeof(child_observation));
        _exit(0);
    }
    close(pipes[1]);
    bool complete = false;
    bool exited = false;
    if (child > 0) {
        complete = read_all(pipes[0], (char *)observation, sizeof(*observation));
        int status = 0;
        exited = waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    close(pipes[0]);
    if (child < 0) {
        diagnostic("permission fork failed: %s", strerror(errno));
    }
    return complete && exited;
}

static void run_ext2_permissions_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/permissions";
    const char *private_path = ADAPTER_MOUNT_POINT "/permissions/private.txt";
    const char *readonly_path = ADAPTER_MOUNT_POINT "/permissions/readonly.txt";
    const char *public_path = ADAPTER_MOUNT_POINT "/permissions/public.txt";
    struct storage_setup setup;
    struct permission_observation observation = {
        .setup_failed = 1,
        .private_allowed = 1,
        .private_errno = 0,
        .readonly_allowed = 1,
        .readonly_errno = 0,
        .public_allowed = 0,
    };
    bool child_ok = false;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        make_case_directory(directory_path);
        write_file_bytes(private_path, "private\n", 8);
        chmod(private_path, 0600);
        write_file_bytes(readonly_path, "readonly\n", 9);
        chmod(readonly_path, 0444);
        write_file_bytes(public_path, "public\n", 7);
        child_ok = collect_permission_observation(&observation);
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool usable = child_ok && observation.setup_failed == 0;
    const char *private_decision = observation.private_allowed ? "allow" : "deny";
    const char *readonly_decision = observation.readonly_allowed ? "allow" : "deny";
    const char *public_decision = observation.public_allowed ? "allow" : "deny";
    bool private_decision_passed = usable && !observation.private_allowed;
    bool private_errno_passed = usable && observation.private_errno == EACCES;
    bool readonly_decision_passed = usable && !observation.readonly_allowed;
    bool readonly_errno_passed = usable && observation.readonly_errno == EACCES;
    bool public_decision_passed = usable && observation.public_allowed;
    emit_permission_named(run_id, nonce, manifest_hash, payload_hash, "private-read-decision", "decision", private_decision, private_decision_passed);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "private-read-errno", "errno", observation.private_errno, private_errno_passed);
    emit_permission_named(run_id, nonce, manifest_hash, payload_hash, "readonly-write-decision", "decision", readonly_decision, readonly_decision_passed);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "readonly-write-errno", "errno", observation.readonly_errno, readonly_errno_passed);
    emit_permission_named(run_id, nonce, manifest_hash, payload_hash, "public-read-decision", "decision", public_decision, public_decision_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               private_decision_passed && private_errno_passed && readonly_decision_passed && readonly_errno_passed && public_decision_passed,
               SETUP_SUBTESTS + 5, SETUP_ASSERTIONS + 5);
}

static void run_ext2_remount_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/sync-remount";
    const char *path = ADAPTER_MOUNT_POINT "/sync-remount/durable.txt";
    const char *content = "durability\n";
    struct storage_setup setup;
    char roundtrip[256] = "";
    long file_fsync = -1;
    long directory_fsync = -1;
    long first_umount = -1;
    long remount_result = -1;
    long final_umount = -1;
    long size = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        make_case_directory(directory_path);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) {
            write_all(fd, content, strlen(content));
            file_fsync = fsync(fd);
            close(fd);
        }
        int directory = open(directory_path, O_RDONLY | O_DIRECTORY);
        if (directory >= 0) {
            directory_fsync = fsync(directory);
            close(directory);
        }
        sync();
        first_umount = umount(ADAPTER_MOUNT_POINT);
        if (first_umount == 0) {
            if (mount(setup.device_path, ADAPTER_MOUNT_POINT, "ext2", 0, NULL) == 0) {
                remount_result = 0;
                read_file_base64(path, roundtrip, sizeof(roundtrip));
                struct stat status;
                if (stat(path, &status) == 0) {
                    size = (long)status.st_size;
                }
                sync();
                final_umount = umount(ADAPTER_MOUNT_POINT);
            } else {
                diagnostic("ext2 remount failed: %s", strerror(errno));
            }
        } else {
            diagnostic("ext2 first umount failed: %s", strerror(errno));
            unmount_adapter_volume();
        }
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool file_fsync_passed = file_fsync == 0;
    bool directory_fsync_passed = directory_fsync == 0;
    bool first_umount_passed = first_umount == 0;
    bool remount_passed = remount_result == 0;
    bool bytes_passed = strcmp(roundtrip, "ZHVyYWJpbGl0eQo=") == 0;
    bool size_passed = size == 11;
    bool final_umount_passed = final_umount == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "file-fsync", "result", file_fsync, file_fsync_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "directory-fsync", "result", directory_fsync, directory_fsync_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "clean-umount", "result", first_umount, first_umount_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "remount", "result", remount_result, remount_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "persistent-data", "bytes", roundtrip, bytes_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "persistent-size", "bytes", size, size_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-umount", "result", final_umount, final_umount_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               file_fsync_passed && directory_fsync_passed && first_umount_passed && remount_passed && bytes_passed &&
                   size_passed && final_umount_passed,
               SETUP_SUBTESTS + 7, SETUP_ASSERTIONS + 7);
}

static void run_ext2_enospc_case(const char *run_id, const char *nonce, const char *manifest_hash, const char *payload_hash) {
    const char *directory_path = ADAPTER_MOUNT_POINT "/enospc-fill";
    const char *path = ADAPTER_MOUNT_POINT "/enospc-fill/fill.bin";
    const char *full_directory = ADAPTER_MOUNT_POINT "/enospc-fill/full-directory";
    static unsigned char chunk[16384];
    struct storage_setup setup;
    long data_write_result = 0;
    long data_write_errno = 0;
    long metadata_create_result = 0;
    long metadata_create_errno = 0;
    long fsync_result = -1;
    if (begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        make_case_directory(directory_path);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) {
            memset(chunk, 'q', sizeof(chunk));
            for (unsigned int iterations = 0; iterations < 4096; iterations += 1) {
                ssize_t written = write(fd, chunk, sizeof(chunk));
                if (written <= 0) {
                    break;
                }
            }
            errno = 0;
            ssize_t final_write = write(fd, "x", 1);
            data_write_result = final_write;
            data_write_errno = final_write < 0 ? errno : 0;
            fsync_result = fsync(fd);
            close(fd);
        } else {
            diagnostic("enospc open failed: %s", strerror(errno));
        }
        errno = 0;
        metadata_create_result = mkdir(full_directory, 0755);
        metadata_create_errno = metadata_create_result < 0 ? errno : 0;
        unmount_adapter_volume();
    } else {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }
    bool data_result_passed = data_write_result == -1;
    bool data_errno_passed = data_write_errno == ENOSPC;
    bool fsync_passed = fsync_result == 0;
    bool metadata_result_passed = metadata_create_result == -1;
    bool metadata_errno_passed = metadata_create_errno == ENOSPC;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "data-write-result", "result", data_write_result, data_result_passed);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "data-write-errno", "errno", data_write_errno, data_errno_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "filled-file-fsync", "result", fsync_result, fsync_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "metadata-create-result", "result", metadata_create_result, metadata_result_passed);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "metadata-create-errno", "errno", metadata_create_errno, metadata_errno_passed);
    emit_final(run_id, nonce, manifest_hash, payload_hash,
               data_result_passed && data_errno_passed && fsync_passed && metadata_result_passed && metadata_errno_passed,
               SETUP_SUBTESTS + 5, SETUP_ASSERTIONS + 5);
}

static void run_adapter_probe(const char *run_id, const char *nonce, const char *manifest_hash,
                              const char *payload_hash) {
    struct storage_setup setup;
    char marker_b64[256] = "";
    char roundtrip_b64[256] = "";
    const char *network_state = "missing";
    setup_storage_volume(&setup);

    if (setup.mounted) {
        unsigned char marker[128];
        size_t marker_length = read_file_bytes(ADAPTER_MARKER_PATH, marker, sizeof(marker));
        base64_encode(marker, marker_length, marker_b64, sizeof(marker_b64));
        if (write_file_bytes(ADAPTER_ROUNDTRIP_PATH, ADAPTER_ROUNDTRIP_TEXT, strlen(ADAPTER_ROUNDTRIP_TEXT))) {
            unsigned char roundtrip[128];
            size_t roundtrip_length = read_file_bytes(ADAPTER_ROUNDTRIP_PATH, roundtrip, sizeof(roundtrip));
            base64_encode(roundtrip, roundtrip_length, roundtrip_b64, sizeof(roundtrip_b64));
        }
        sync();
        if (umount(ADAPTER_MOUNT_POINT) != 0) {
            diagnostic("umount failed: %s", strerror(errno));
        }
    } else if (setup.mount_errno != 0) {
        diagnostic("adapter mount errno=%d", setup.mount_errno);
    }

    struct stat network_status;
    if (stat("/sys/class/net/" ADAPTER_NETWORK_INTERFACE, &network_status) == 0) {
        network_state = "present";
    }
    long uid_value = (long)setup.uid;

    bool serial_passed = strcmp(setup.serial, ADAPTER_SERIAL) == 0;
    bool cache_passed = strcmp(setup.write_cache, ADAPTER_WRITE_CACHE) == 0;
    bool marker_passed = strcmp(marker_b64, "bGMwNi1hZGFwdGVyCg==") == 0;
    bool roundtrip_passed = strcmp(roundtrip_b64, "cWMwNi13cml0ZQo=") == 0;
    bool network_passed = strcmp(network_state, "present") == 0;
    bool uid_passed = uid_value == 0;

    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "serial-identity", "serial", setup.serial, serial_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "write-cache", "mode", setup.write_cache, cache_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "mount-identity", "marker", marker_b64, marker_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "mount-writeback", "roundtrip", roundtrip_b64, roundtrip_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "network-interface", "interface", network_state, network_passed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "privilege-identity", "uid", uid_value, uid_passed);

    bool passed = serial_passed && cache_passed && marker_passed && roundtrip_passed && network_passed && uid_passed;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed, 6, 6);
    diagnostic("adapter probe complete status=%s", passed ? "pass" : "fail");
}

static void run_selfcheck_probe(const char *run_id, const char *nonce, const char *manifest_hash,
                                const char *payload_hash) {
    int missing_errno = probe_missing_errno();
    emit_errno_subtest(run_id, nonce, manifest_hash, payload_hash, missing_errno, missing_errno == ENOENT);

    char encoded[256];
    size_t input_length = probe_input_bytes(encoded, sizeof(encoded));
    bool input_passed = input_length == 6 && memcmp(encoded, "aGVsbG8K", 8) == 0;
    emit_bytes_subtest(run_id, nonce, manifest_hash, payload_hash, encoded, input_passed);

    bool null_write = probe_dev_null_write();
    emit_permission_subtest(run_id, nonce, manifest_hash, payload_hash, null_write ? "allow" : "deny", null_write);

    bool passed = missing_errno == ENOENT && input_passed && null_write;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed, 3, 3);
    diagnostic("probe complete status=%s", passed ? "pass" : "fail");
}


static void run_fd_eventfd_case(const char *run_id, const char *nonce, const char *manifest_hash,
                                const char *payload_hash) {
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    bool create_ok = efd >= 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "eventfd-create", "ok", create_ok ? 1 : 0, create_ok);
    if (!create_ok) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, 1, 1);
        close(efd);
        return;
    }

    uint64_t value = 0;
    errno = 0;
    long empty_read = read(efd, &value, sizeof(value));
    long empty_errno = empty_read < 0 ? errno : 0;
    bool empty_ok = empty_read < 0 && empty_errno == EAGAIN;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "empty-read", "result", empty_read, empty_ok);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "empty-read-errno", "errno", empty_errno, empty_errno == EAGAIN);

    uint64_t seed = 7;
    long write_result = write(efd, &seed, sizeof(seed));
    bool write_ok = write_result == (long)sizeof(seed);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "semaphore-write", "result", write_result, write_ok);

    value = 0;
    long read_result = read(efd, &value, sizeof(value));
    bool read_ok = read_result == (long)sizeof(value) && value == seed;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "semaphore-read", "result", read_result, read_ok);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "semaphore-value", "value", (long)value, value == seed);

    uint64_t first = 3, second = 2;
    write(efd, &first, sizeof(first));
    write(efd, &second, sizeof(second));
    value = 0;
    long coalesced = read(efd, &value, sizeof(value));
    bool coalesced_ok = coalesced == (long)sizeof(value) && value == 5;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "coalesced-read", "value", (long)value, coalesced_ok);

    close(efd);
    bool passed = create_ok && empty_ok && write_ok && read_ok && coalesced_ok;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed, 7, 7);
}

static void run_fd_epoll_case(const char *run_id, const char *nonce, const char *manifest_hash,
                              const char *payload_hash) {
    int pipefd[2];
    long pipe_result = pipe2(pipefd, O_NONBLOCK | O_CLOEXEC);
    bool pipe_ok = pipe_result == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "pipe-create", "ok", pipe_ok ? 1 : 0, pipe_ok);
    if (!pipe_ok) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, 1, 1);
        return;
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    bool create_ok = epfd >= 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "epoll-create", "ok", create_ok ? 1 : 0, create_ok);
    if (!create_ok) {
        close(pipefd[0]);
        close(pipefd[1]);
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, 2, 2);
        return;
    }

    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.fd = pipefd[0];
    long ctl_result = epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &event);
    bool ctl_ok = ctl_result == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "ctl-add", "result", ctl_result, ctl_ok);

    struct epoll_event ready = {0};
    long wait_before = epoll_wait(epfd, &ready, 1, 0);
    bool before_ok = wait_before == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "wait-before", "result", wait_before, before_ok);

    long byte_written = write(pipefd[1], "x", 1);
    long wait_after = epoll_wait(epfd, &ready, 1, 1000);
    bool after_ok = byte_written == 1 && wait_after == 1;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "wait-after", "result", wait_after, after_ok);

    long event_mask = (long)(ready.events & EPOLLIN);
    bool mask_ok = wait_after == 1 && event_mask == EPOLLIN;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "event-mask", "mask", event_mask, mask_ok);

    char byte = 0;
    long drained = read(pipefd[0], &byte, 1);
    long wait_after_read = epoll_wait(epfd, &ready, 1, 0);
    bool after_read_ok = drained == 1 && wait_after_read == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "wait-after-read", "result", wait_after_read, after_read_ok);

    close(epfd);
    close(pipefd[0]);
    close(pipefd[1]);
    bool passed = pipe_ok && create_ok && ctl_ok && before_ok && after_ok && mask_ok && after_read_ok;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed, 7, 7);
}

static void run_fd_pipe_case(const char *run_id, const char *nonce, const char *manifest_hash,
                             const char *payload_hash) {
    int pipefd[2];
    long pipe_result = pipe2(pipefd, O_NONBLOCK | O_CLOEXEC);
    bool pipe_ok = pipe_result == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "pipe-create", "ok", pipe_ok ? 1 : 0, pipe_ok);
    if (!pipe_ok) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, 1, 1);
        return;
    }

    char buffer[16];
    errno = 0;
    long empty_read = read(pipefd[0], buffer, sizeof(buffer));
    long empty_errno = empty_read < 0 ? errno : 0;
    bool empty_ok = empty_read < 0 && empty_errno == EAGAIN;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "empty-read", "result", empty_read, empty_ok);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "empty-read-errno", "errno", empty_errno, empty_errno == EAGAIN);

    const char message[] = "ready";
    long write_result = write(pipefd[1], message, sizeof(message) - 1);
    bool write_ok = write_result == (long)(sizeof(message) - 1);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "write", "result", write_result, write_ok);

    memset(buffer, 0, sizeof(buffer));
    long read_result = read(pipefd[0], buffer, sizeof(buffer));
    bool read_ok = read_result == (long)(sizeof(message) - 1);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "read", "result", read_result, read_ok);

    char encoded[64];
    base64_encode((unsigned char *)buffer, read_ok ? (size_t)read_result : 0, encoded, sizeof(encoded));
    bool bytes_ok = strcmp(encoded, "cmVhZHk=") == 0;
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "read-bytes", "bytes", encoded, bytes_ok);

    close(pipefd[1]);
    errno = 0;
    long eof_read = read(pipefd[0], buffer, sizeof(buffer));
    bool eof_ok = eof_read == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "eof-read", "result", eof_read, eof_ok);

    close(pipefd[0]);
    bool passed = pipe_ok && empty_ok && write_ok && read_ok && bytes_ok && eof_ok;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed, 7, 7);
}

static void run_fd_lifetime_case(const char *run_id, const char *nonce, const char *manifest_hash,
                                 const char *payload_hash) {
    int fd = open("/dev/null", O_RDONLY);
    bool open_ok = fd >= 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "open", "ok", open_ok ? 1 : 0, open_ok);
    if (!open_ok) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, 1, 1);
        return;
    }

    int duplicate = dup(fd);
    bool dup_ok = duplicate >= 0 && duplicate != fd;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "dup-distinct", "ok", dup_ok ? 1 : 0, dup_ok);
    if (!dup_ok) {
        close(fd);
        if (duplicate >= 0) close(duplicate);
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, 2, 2);
        return;
    }

    long flags_before = fcntl(duplicate, F_GETFD);
    bool before_ok = flags_before >= 0 && (flags_before & FD_CLOEXEC) == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "cloexec-before", "flag",
                       (flags_before & FD_CLOEXEC) != 0 ? 1 : 0, before_ok);

    long set_result = fcntl(duplicate, F_SETFD, FD_CLOEXEC);
    long flags_after = fcntl(duplicate, F_GETFD);
    bool after_ok = set_result == 0 && flags_after >= 0 && (flags_after & FD_CLOEXEC) != 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "cloexec-after", "flag",
                       (flags_after & FD_CLOEXEC) != 0 ? 1 : 0, after_ok);

    close(fd);
    char byte = 0;
    errno = 0;
    long independent_read = read(duplicate, &byte, 1);
    bool independent_ok = independent_read == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "dup-independent", "result",
                       independent_read, independent_ok);

    close(duplicate);
    int reused = open("/dev/null", O_RDONLY);
    bool reuse_ok = reused >= 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "reuse", "ok", reuse_ok ? 1 : 0, reuse_ok);
    if (reused >= 0) close(reused);

    bool passed = open_ok && dup_ok && before_ok && after_ok && independent_ok && reuse_ok;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed, 6, 6);
}


static long errors_sync(int fd, int mode) {
    if (mode == 1) return fdatasync(fd);
    if (mode == 2) return syncfs(fd);
    return fsync(fd);
}

static void run_errors_sync_case(const char *run_id, const char *nonce, const char *manifest_hash,
                                 const char *payload_hash, int mode) {
    struct storage_setup setup;
    if (!begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }

    const char *path = ADAPTER_MOUNT_POINT "/marker.txt";
    int fd1 = open(path, O_RDWR);
    int fd2 = open(path, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        diagnostic("errors.fsync open failed: %s", strerror(errno));
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        unmount_adapter_volume();
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }

    long first_write = write(fd1, "A", 1);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "first-write", "result", first_write, first_write == 1);

    errno = 0;
    long first_fsync_fd1 = errors_sync(fd1, mode);
    long first_fsync_fd1_errno = first_fsync_fd1 < 0 ? errno : 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "first-fsync-fd1", "result", first_fsync_fd1,
                       first_fsync_fd1 < 0 && first_fsync_fd1_errno == EIO);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "first-fsync-fd1-errno", "errno", first_fsync_fd1_errno,
                     first_fsync_fd1_errno == EIO);

    errno = 0;
    long first_fsync_fd2 = errors_sync(fd2, mode);
    long first_fsync_fd2_errno = first_fsync_fd2 < 0 ? errno : 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "first-fsync-fd2", "result", first_fsync_fd2,
                       first_fsync_fd2 < 0 && first_fsync_fd2_errno == EIO);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "first-fsync-fd2-errno", "errno", first_fsync_fd2_errno,
                     first_fsync_fd2_errno == EIO);

    errno = 0;
    long repeat_fsync_fd1 = errors_sync(fd1, mode);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "repeat-fsync-fd1", "result", repeat_fsync_fd1,
                       repeat_fsync_fd1 == 0);
    errno = 0;
    long repeat_fsync_fd2 = errors_sync(fd2, mode);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "repeat-fsync-fd2", "result", repeat_fsync_fd2,
                       repeat_fsync_fd2 == 0);

    long second_write = write(fd1, "B", 1);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "second-write", "result", second_write, second_write == 1);

    errno = 0;
    long second_fsync_fd1 = errors_sync(fd1, mode);
    long second_fsync_fd1_errno = second_fsync_fd1 < 0 ? errno : 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "second-fsync-fd1", "result", second_fsync_fd1,
                       second_fsync_fd1 < 0 && second_fsync_fd1_errno == EIO);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "second-fsync-fd1-errno", "errno", second_fsync_fd1_errno,
                     second_fsync_fd1_errno == EIO);

    errno = 0;
    long second_fsync_fd2 = errors_sync(fd2, mode);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "second-fsync-fd2", "result", second_fsync_fd2,
                       second_fsync_fd2 < 0);

    errno = 0;
    long final_fsync_fd1 = errors_sync(fd1, mode);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-fsync-fd1", "result", final_fsync_fd1,
                       final_fsync_fd1 == 0);
    errno = 0;
    long final_fsync_fd2 = errors_sync(fd2, mode);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-fsync-fd2", "result", final_fsync_fd2,
                       final_fsync_fd2 == 0);

    close(fd1);
    close(fd2);
    unmount_adapter_volume();

    bool passed = first_write == 1 && first_fsync_fd1_errno == EIO && first_fsync_fd2_errno == EIO
                  && repeat_fsync_fd1 == 0 && repeat_fsync_fd2 == 0 && second_write == 1
                  && second_fsync_fd1_errno == EIO && second_fsync_fd2 < 0
                  && final_fsync_fd1 == 0 && final_fsync_fd2 == 0;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed,
               SETUP_SUBTESTS + 13, SETUP_ASSERTIONS + 13);
    diagnostic("errors.fsync probe complete status=%s", passed ? "pass" : "fail");
}


static void run_errors_msync_case(const char *run_id, const char *nonce, const char *manifest_hash,
                                  const char *payload_hash) {
    struct storage_setup setup;
    if (!begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }

    const char *path = ADAPTER_MOUNT_POINT "/marker.txt";
    int fd1 = open(path, O_RDWR);
    int fd2 = open(path, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        unmount_adapter_volume();
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }

    void *map1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    void *map2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    bool maps_ok = map1 != MAP_FAILED && map2 != MAP_FAILED;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "mmap", "ok", maps_ok ? 1 : 0, maps_ok);
    if (!maps_ok) {
        if (map1 != MAP_FAILED) munmap(map1, 4096);
        if (map2 != MAP_FAILED) munmap(map2, 4096);
        close(fd1);
        close(fd2);
        unmount_adapter_volume();
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS + 1, SETUP_ASSERTIONS + 1);
        return;
    }

    ((char *)map1)[0] = 'A';
    errno = 0;
    long first_msync_fd1 = msync(map1, 4096, MS_SYNC);
    long first_msync_fd1_errno = first_msync_fd1 < 0 ? errno : 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "first-msync-fd1", "result", first_msync_fd1,
                       first_msync_fd1 < 0 && first_msync_fd1_errno == EIO);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "first-msync-fd1-errno", "errno", first_msync_fd1_errno,
                     first_msync_fd1_errno == EIO);

    errno = 0;
    long first_msync_fd2 = msync(map2, 4096, MS_SYNC);
    long first_msync_fd2_errno = first_msync_fd2 < 0 ? errno : 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "first-msync-fd2", "result", first_msync_fd2,
                       first_msync_fd2 < 0 && first_msync_fd2_errno == EIO);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "first-msync-fd2-errno", "errno", first_msync_fd2_errno,
                     first_msync_fd2_errno == EIO);

    errno = 0;
    long repeat_msync_fd1 = msync(map1, 4096, MS_SYNC);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "repeat-msync-fd1", "result", repeat_msync_fd1,
                       repeat_msync_fd1 == 0);
    errno = 0;
    long repeat_msync_fd2 = msync(map2, 4096, MS_SYNC);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "repeat-msync-fd2", "result", repeat_msync_fd2,
                       repeat_msync_fd2 == 0);

    ((char *)map1)[0] = 'B';
    errno = 0;
    long second_msync_fd1 = msync(map1, 4096, MS_SYNC);
    long second_msync_fd1_errno = second_msync_fd1 < 0 ? errno : 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "second-msync-fd1", "result", second_msync_fd1,
                       second_msync_fd1 < 0 && second_msync_fd1_errno == EIO);
    emit_errno_named(run_id, nonce, manifest_hash, payload_hash, "second-msync-fd1-errno", "errno", second_msync_fd1_errno,
                     second_msync_fd1_errno == EIO);

    errno = 0;
    long second_msync_fd2 = msync(map2, 4096, MS_SYNC);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "second-msync-fd2", "result", second_msync_fd2,
                       second_msync_fd2 < 0);

    errno = 0;
    long final_msync_fd1 = msync(map1, 4096, MS_SYNC);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-msync-fd1", "result", final_msync_fd1,
                       final_msync_fd1 == 0);
    errno = 0;
    long final_msync_fd2 = msync(map2, 4096, MS_SYNC);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "final-msync-fd2", "result", final_msync_fd2,
                       final_msync_fd2 == 0);

    munmap(map1, 4096);
    munmap(map2, 4096);
    close(fd1);
    close(fd2);
    unmount_adapter_volume();

    bool passed = first_msync_fd1_errno == EIO && first_msync_fd2_errno == EIO
                  && repeat_msync_fd1 == 0 && repeat_msync_fd2 == 0
                  && second_msync_fd1_errno == EIO && second_msync_fd2 < 0
                  && final_msync_fd1 == 0 && final_msync_fd2 == 0;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed,
               SETUP_SUBTESTS + 12, SETUP_ASSERTIONS + 12);
    diagnostic("errors.msync probe complete status=%s", passed ? "pass" : "fail");
}

static void run_persistence_case(const char *run_id, const char *nonce, const char *manifest_hash,
                                 const char *payload_hash, bool sync_file) {
    struct storage_setup setup;
    if (!begin_storage_case(run_id, nonce, manifest_hash, payload_hash, &setup)) {
        emit_final(run_id, nonce, manifest_hash, payload_hash, false, SETUP_SUBTESTS, SETUP_ASSERTIONS);
        return;
    }

    const char *path = ADAPTER_MOUNT_POINT "/marker.txt";
    int fd = open(path, O_WRONLY);
    long write_result = -1;
    long sync_result = 0;
    if (fd >= 0) {
        write_result = write(fd, "P", 1);
        if (sync_file) {
            sync_result = fsync(fd);
        }
        if (!omit_final_sync) {
            close(fd);
        }
    } else {
        diagnostic("persistence open failed: %s", strerror(errno));
    }

    bool write_ok = write_result == 1;
    bool sync_ok = sync_result == 0;
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "data-write", "result", write_result, write_ok);
    emit_integer_named(run_id, nonce, manifest_hash, payload_hash, "sync-result", "result", sync_result, sync_ok);
    if (!omit_final_sync) {
        unmount_adapter_volume();
    }
    emit_final(run_id, nonce, manifest_hash, payload_hash, write_ok && sync_ok,
               SETUP_SUBTESTS + 2, SETUP_ASSERTIONS + 2);
    diagnostic("persistence probe complete status=%s sync=%s", write_ok && sync_ok ? "pass" : "fail", sync_file ? "yes" : "no");
    if (omit_final_sync) {
        for (;;) {
            pause();
        }
    }
}

static void terminate_vm(void) {
    if (!omit_final_sync) {
        sync();
    }
    if (serial_fd >= 0) {
        tcdrain(serial_fd);
    }
    diagnostic("requesting poweroff");
    reboot(RB_POWER_OFF);
    diagnostic("poweroff failed: %s; requesting restart", strerror(errno));
    reboot(RB_AUTOBOOT);
    diagnostic("restart failed: %s; exiting init", strerror(errno));
    _exit(0);
}

int main(void) {
    char cmdline[4096];
    char run_id[128];
    char nonce[128];
    char manifest_hash[128];
    char payload_hash[128];
    char control[64];
    char case_id[128];

    diagnostic("probe init started");
    serial_fd = open_result_serial();
    if (!read_cmdline(cmdline, sizeof(cmdline))) {
        terminate_vm();
    }
    parse_cmdline(cmdline, run_id, sizeof(run_id), nonce, sizeof(nonce), manifest_hash, sizeof(manifest_hash),
                  payload_hash, sizeof(payload_hash), control, sizeof(control), case_id, sizeof(case_id));
    copy_value(case_id, strlen(case_id), active_case_id, sizeof(active_case_id));
    diagnostic("run_id=%s control=%s case=%s", run_id, control, active_case_id);
    if (!run_id[0] || !nonce[0] || !manifest_hash[0] || !payload_hash[0]) {
        diagnostic("missing qualification cmdline parameters");
        terminate_vm();
    }

    emit_start(run_id, nonce, manifest_hash, payload_hash);
    omit_final_sync = strcmp(control, "persistence-cut") == 0;
    if (strcmp(control, "hang") == 0) {
        diagnostic("entering deliberate hang control");
        for (;;) {
            pause();
        }
    }
    if (strcmp(control, "panic") == 0) {
        diagnostic("entering deliberate panic control");
        int trigger = open("/proc/sysrq-trigger", O_WRONLY);
        if (trigger >= 0) {
            write(trigger, "c", 1);
            close(trigger);
        }
        _exit(1);
    }

    mount_sysfs();
    if (strcmp(control, "drop-sys-admin") == 0) {
        drop_sys_admin_capability();
    }
    if (strcmp(active_case_id, ADAPTER_CASE_ID) == 0) {
        run_adapter_probe(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_READ_CASE_ID) == 0) {
        run_ext4_read_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_MULTIGROUP_CASE_ID) == 0) {
        run_ext4_multigroup_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_SPARSE_CASE_ID) == 0) {
        run_ext4_sparse_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_WRITE_CASE_ID) == 0) {
        run_ext4_write_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_WRITE_READBACK_CASE_ID) == 0) {
        run_ext4_file_case(run_id, nonce, manifest_hash, payload_hash, "marker.txt", "bGMxOS1qb3VybmFsCg==", 13, false);
    } else if (strcmp(active_case_id, EXT4_ALLOC_CASE_ID) == 0) {
        run_ext4_alloc_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_DIR_CASE_ID) == 0) {
        run_ext4_dir_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_ORPHAN_CASE_ID) == 0) {
        run_ext4_orphan_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_XATTR_CASE_ID) == 0) {
        run_ext4_xattr_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_DURABILITY_CASE_ID) == 0) {
        run_ext4_durability_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_ERRORS_CASE_ID) == 0) {
        run_ext4_errors_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT4_OVERSIZED_SPARSE_CASE_ID) == 0) {
        run_ext4_oversized_sparse_case(run_id, nonce, manifest_hash, payload_hash);

    } else if (strcmp(active_case_id, EXT2_CREATE_CASE_ID) == 0) {
        run_ext2_create_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT2_SPARSE_CASE_ID) == 0) {
        run_ext2_sparse_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT2_LINKS_CASE_ID) == 0) {
        run_ext2_links_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT2_PERMISSIONS_CASE_ID) == 0) {
        run_ext2_permissions_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT2_REMOUNT_CASE_ID) == 0) {
        run_ext2_remount_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, EXT2_ENOSPC_CASE_ID) == 0) {
        run_ext2_enospc_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, FD_EVENTFD_CASE_ID) == 0) {
        run_fd_eventfd_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, FD_EPOLL_CASE_ID) == 0) {
        run_fd_epoll_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, FD_PIPE_CASE_ID) == 0) {
        run_fd_pipe_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, FD_LIFETIME_CASE_ID) == 0) {
        run_fd_lifetime_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, ERRORS_FSYNC_CASE_ID) == 0) {
        run_errors_sync_case(run_id, nonce, manifest_hash, payload_hash, 0);
    } else if (strcmp(active_case_id, ERRORS_FDATASYNC_CASE_ID) == 0) {
        run_errors_sync_case(run_id, nonce, manifest_hash, payload_hash, 1);
    } else if (strcmp(active_case_id, ERRORS_SYNCFS_CASE_ID) == 0) {
        run_errors_sync_case(run_id, nonce, manifest_hash, payload_hash, 2);
    } else if (strcmp(active_case_id, ERRORS_MSYNC_CASE_ID) == 0) {
        run_errors_msync_case(run_id, nonce, manifest_hash, payload_hash);
    } else if (strcmp(active_case_id, PERSISTENCE_SYNCED_CASE_ID) == 0) {
        run_persistence_case(run_id, nonce, manifest_hash, payload_hash, true);
    } else if (strcmp(active_case_id, PERSISTENCE_OMITTED_CASE_ID) == 0) {
        run_persistence_case(run_id, nonce, manifest_hash, payload_hash, false);
    } else {
        run_selfcheck_probe(run_id, nonce, manifest_hash, payload_hash);
    }
    terminate_vm();
    return 0;
}
