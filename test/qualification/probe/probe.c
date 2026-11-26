// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SELFCHECK_CASE_ID "core.selfcheck"
#define ADAPTER_CASE_ID "core.adapter"
#define INPUT_PATH "/qual/input.txt"
#define MISSING_PATH "/qual/no-such-file"
#define SERIAL_PATH "/dev/ttyS1"
#define ADAPTER_SERIAL "qual-lc06-adapter"
#define ADAPTER_MOUNT_POINT "/mnt/qualification"
#define ADAPTER_MARKER_PATH "/mnt/qualification/marker.txt"
#define ADAPTER_ROUNDTRIP_PATH "/mnt/qualification/probe-roundtrip.bin"
#define ADAPTER_ROUNDTRIP_TEXT "qc06-write\n"
#define ADAPTER_NETWORK_INTERFACE "eth0"

static int serial_fd = -1;
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

static void emit_bytes_named(const char *run_id, const char *nonce, const char *manifest_hash,
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
    DIR *directory = opendir("/sys/block");
    if (directory == NULL) {
        diagnostic("open /sys/block failed: %s", strerror(errno));
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
        snprintf(path, sizeof(path), "/sys/block/%s/serial", entry->d_name);
        bool matches = read_serial_candidate(path, ADAPTER_SERIAL, serial, serial_size);
        if (!matches) {
            snprintf(path, sizeof(path), "/sys/block/%s/device/serial", entry->d_name);
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
    snprintf(sysdev, sizeof(sysdev), "/sys/block/%s/dev", device_name);
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

static void run_adapter_probe(const char *run_id, const char *nonce, const char *manifest_hash,
                              const char *payload_hash) {
    char device_name[64] = "";
    char serial[128] = "";
    char write_cache[128] = "";
    char device_path[128] = "";
    char marker_b64[256] = "";
    char roundtrip_b64[256] = "";
    const char *network_state = "missing";
    bool found = find_adapter_disk(device_name, sizeof(device_name), serial, sizeof(serial));
    if (found) {
        char cache_path[256];
        snprintf(cache_path, sizeof(cache_path), "/sys/block/%s/queue/write_cache", device_name);
        read_first_line(cache_path, write_cache, sizeof(write_cache));
    }

    bool mounted = false;
    int mount_error = 0;
    if (found && ensure_device_node(device_name, device_path, sizeof(device_path))) {
        mkdir("/mnt", 0555);
        mkdir(ADAPTER_MOUNT_POINT, 0555);
        if (mount(device_path, ADAPTER_MOUNT_POINT, "ext2", 0, NULL) == 0) {
            mounted = true;
        } else {
            mount_error = errno;
            diagnostic("mount %s failed: %s", device_path, strerror(errno));
        }
    }

    if (mounted) {
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
    } else if (mount_error != 0) {
        diagnostic("adapter mount errno=%d", mount_error);
    }

    struct stat network_status;
    if (stat("/sys/class/net/" ADAPTER_NETWORK_INTERFACE, &network_status) == 0) {
        network_state = "present";
    }
    long uid_value = (long)getuid();

    bool serial_passed = strcmp(serial, ADAPTER_SERIAL) == 0;
    bool cache_passed = strcmp(write_cache, "write back") == 0;
    bool marker_passed = strcmp(marker_b64, "bGMwNi1hZGFwdGVyCg==") == 0;
    bool roundtrip_passed = strcmp(roundtrip_b64, "cWMwNi13cml0ZQo=") == 0;
    bool network_passed = strcmp(network_state, "present") == 0;
    bool uid_passed = uid_value == 0;

    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "serial-identity", "serial", serial, serial_passed);
    emit_bytes_named(run_id, nonce, manifest_hash, payload_hash, "write-cache", "mode", write_cache, cache_passed);
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

static void terminate_vm(void) {
    sync();
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
    } else {
        run_selfcheck_probe(run_id, nonce, manifest_hash, payload_hash);
    }
    terminate_vm();
    return 0;
}
