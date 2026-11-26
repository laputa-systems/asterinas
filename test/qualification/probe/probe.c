// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CASE_ID "core.selfcheck"
#define INPUT_PATH "/qual/input.txt"
#define MISSING_PATH "/qual/no-such-file"
#define SERIAL_PATH "/dev/ttyS1"

static int serial_fd = -1;
static unsigned long sequence = 0;

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
             CASE_ID, sequence, manifest_hash, payload_hash, (long)time(NULL));
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
    char fields[1024];
    char line[1600];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"subtest\",\"subtest\":\"read-fixed-input\",\"status\":\"%s\",\"assertions\":[{\"id\":\"bytes\",\"value\":\"%s\"}]}\n",
             run_id, nonce, fields, passed ? "pass" : "fail", value);
    emit_record(line);
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
                       const char *payload_hash, bool passed) {
    char fields[1024];
    char line[1800];
    common_fields(fields, sizeof(fields), run_id, nonce, manifest_hash, payload_hash);
    snprintf(line, sizeof(line),
             "QUAL %s %s {%s,\"kind\":\"final\",\"status\":\"%s\",\"subtests_completed\":3,\"assertions_completed\":3,\"artifacts\":[]}\n",
             run_id, nonce, fields, passed ? "pass" : "fail");
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
                          char *control, size_t control_size) {
    run_id[0] = '\0';
    nonce[0] = '\0';
    manifest_hash[0] = '\0';
    payload_hash[0] = '\0';
    strcpy(control, "none");
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

    diagnostic("probe init started");
    serial_fd = open_result_serial();
    if (!read_cmdline(cmdline, sizeof(cmdline))) {
        terminate_vm();
    }
    parse_cmdline(cmdline, run_id, sizeof(run_id), nonce, sizeof(nonce), manifest_hash, sizeof(manifest_hash),
                  payload_hash, sizeof(payload_hash), control, sizeof(control));
    diagnostic("run_id=%s control=%s", run_id, control);
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

    int missing_errno = probe_missing_errno();
    emit_errno_subtest(run_id, nonce, manifest_hash, payload_hash, missing_errno, missing_errno == ENOENT);

    char encoded[256];
    size_t input_length = probe_input_bytes(encoded, sizeof(encoded));
    bool input_passed = input_length == 6 && memcmp(encoded, "aGVsbG8K", 8) == 0;
    emit_bytes_subtest(run_id, nonce, manifest_hash, payload_hash, encoded, input_passed);

    bool null_write = probe_dev_null_write();
    emit_permission_subtest(run_id, nonce, manifest_hash, payload_hash, null_write ? "allow" : "deny", null_write);

    bool passed = missing_errno == ENOENT && input_passed && null_write;
    emit_final(run_id, nonce, manifest_hash, payload_hash, passed);
    diagnostic("probe complete status=%s", passed ? "pass" : "fail");
    terminate_vm();
    return 0;
}
