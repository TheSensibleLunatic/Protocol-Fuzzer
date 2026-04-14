/*
 * mock_listener.c — Raw socket listener for proto-fuzzer.
 *
 * Binds to a network interface in promiscuous mode, receives raw Ethernet
 * frames, dispatches to the modular parser, and logs every result.
 *
 * SAFE_MODE compile flag:
 *   -DSAFE_MODE=1  → handles all errors gracefully (default, safe)
 *   -DSAFE_MODE=0  → simulates a vulnerable device (may crash on bad input)
 *
 * Compile:
 *   make safe      (SAFE_MODE=1, -fsanitize=address)
 *   make unsafe    (SAFE_MODE=0, no sanitizer)
 *
 * Usage (root required):
 *   sudo ./listener_safe   -i eth0 [-l listener.log]
 *   sudo ./listener_unsafe -i eth0 [-l listener.log]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

/* POSIX / Linux raw-socket headers */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "packet_parser.h"

/* =========================================================================
 * Configuration defaults
 * ========================================================================= */
#define DEFAULT_IFACE     "lo"
#define DEFAULT_LOG_FILE  "listener.log"
#define CRASH_LOG_FILE    "listener_crashes.log"
#define RECV_BUFFER_SIZE  65536

#ifndef SAFE_MODE
#define SAFE_MODE 1
#endif

/* =========================================================================
 * Globals (needed by signal handler)
 * ========================================================================= */
static volatile sig_atomic_t g_running     = 1;
static volatile sig_atomic_t g_crash_count = 0;
static FILE   *g_log_fp                    = NULL;
static char    g_iface[IFNAMSIZ]           = DEFAULT_IFACE;
static long    g_pkt_count                 = 0;

/* =========================================================================
 * Signal handlers
 * ========================================================================= */

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static void handle_sigsegv(int sig) {
    (void)sig;
    /* Write crash report — async-signal-safe functions only */
    int fd = creat(CRASH_LOG_FILE, 0644);
    if (fd >= 0) {
        const char *msg = "SIGSEGV caught — listener crashed on malformed packet\n";
        write(fd, msg, strlen(msg));
        close(fd);
    }
    /* Re-raise to get a core dump */
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

static void handle_sigbus(int sig) {
    (void)sig;
    int fd = creat(CRASH_LOG_FILE, 0644);
    if (fd >= 0) {
        const char *msg = "SIGBUS caught — bus error on malformed packet\n";
        write(fd, msg, strlen(msg));
        close(fd);
    }
    signal(SIGBUS, SIG_DFL);
    raise(SIGBUS);
}

/* =========================================================================
 * Logging
 * ========================================================================= */

static void log_result(const ParseResult *result) {
    if (!g_log_fp) return;

    char line[512];
    result_to_log_line(result, line, sizeof(line));
    fprintf(g_log_fp, "%s\n", line);
    fflush(g_log_fp);
}

static void log_message(const char *level, const char *fmt, ...) {
    if (!g_log_fp) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(g_log_fp, "[%ld.%06ld] [%s] ",
            (long)ts.tv_sec, ts.tv_nsec / 1000, level);
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log_fp, fmt, args);
    va_end(args);
    fprintf(g_log_fp, "\n");
    fflush(g_log_fp);
}

/* Need va_list for log_message */
#include <stdarg.h>

/* =========================================================================
 * Promiscuous mode helpers
 * ========================================================================= */

static int set_promisc(int sock, const char *iface, int enable) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        return -1;
    }
    if (enable) {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= ~IFF_PROMISC;
    }
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        return -1;
    }
    return 0;
}

static int get_iface_index(int sock, const char *iface) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }
    return ifr.ifr_ifindex;
}

/* =========================================================================
 * Main receive loop
 * ========================================================================= */

static void run_listener(int sock) {
    static uint8_t buf[RECV_BUFFER_SIZE];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    printf("[listener] Listening on %s (SAFE_MODE=%d) ...\n",
           g_iface, SAFE_MODE);
    printf("[listener] Press Ctrl+C to stop.\n");
    log_message("INFO", "Listener started on %s SAFE_MODE=%d", g_iface, SAFE_MODE);

    while (g_running) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src_addr, &addr_len);
        if (n < 0) {
            if (errno == EINTR) continue;  /* interrupted by signal */
            perror("recvfrom");
            break;
        }

        g_pkt_count++;

        ParseResult result;
        ParseStatus status = parse_frame(buf, (size_t)n, &result);

        /* Console output */
        const char *status_str = "OK";
        switch (status) {
            case PARSE_MALFORMED:   status_str = "\033[33mMALFORMED\033[0m";   break;
            case PARSE_TRUNCATED:   status_str = "\033[33mTRUNCATED\033[0m";   break;
            case PARSE_UNKNOWN:     status_str = "\033[90mUNKNOWN\033[0m";     break;
            case PARSE_UNSUPPORTED: status_str = "\033[90mUNSUPPORTED\033[0m"; break;
            default:                status_str = "\033[32mOK\033[0m";          break;
        }

        printf("[%06ld] proto=%-7s len=%-5zd status=%s\n",
               g_pkt_count, result.proto, n, status_str);

        log_result(&result);

#if !SAFE_MODE
        /*
         * Additional unsafe path (vuln sim):
         * Trust packet count field from payload and use it as a loop bound.
         * A crafted packet can cause large/infinite iterations → DoS / crash.
         */
        if (status == PARSE_MALFORMED && n > 20) {
            uint32_t count_field;
            memcpy(&count_field, buf + 16, 4);
            count_field = ntohl(count_field);
            /* Dangerous: no upper-bound check */
            volatile uint32_t dummy = 0;
            for (uint32_t i = 0; i < count_field && i < 0x0FFFFFFF; i++) {
                dummy += buf[i % n];
            }
            (void)dummy;
        }
#endif
    }

    printf("\n[listener] Stopped. Packets received: %ld\n", g_pkt_count);
    log_message("INFO", "Listener stopped after %ld packets", g_pkt_count);
}

/* =========================================================================
 * Usage
 * ========================================================================= */

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-i interface] [-l logfile]\n"
            "  -i  Network interface (default: " DEFAULT_IFACE ")\n"
            "  -l  Log file path    (default: " DEFAULT_LOG_FILE ")\n"
            "  -h  Show this help\n",
            prog);
}

/* =========================================================================
 * Entry point
 * ========================================================================= */

int main(int argc, char *argv[]) {
    const char *log_path = DEFAULT_LOG_FILE;
    int opt;

    while ((opt = getopt(argc, argv, "i:l:h")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(g_iface, optarg, IFNAMSIZ - 1);
                break;
            case 'l':
                log_path = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    /* Root check */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: must be run as root (sudo).\n");
        return 1;
    }

    /* Open log file */
    g_log_fp = fopen(log_path, "a");
    if (!g_log_fp) {
        fprintf(stderr, "Warning: cannot open log file %s: %s\n",
                log_path, strerror(errno));
        /* Not fatal — continue without file logging */
    }

    /* Install signal handlers */
    signal(SIGINT,  handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGSEGV, handle_sigsegv);
    signal(SIGBUS,  handle_sigbus);

    /* Create raw socket (AF_PACKET = Layer 2) */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        if (g_log_fp) fclose(g_log_fp);
        return 1;
    }

    /* Get interface index */
    int iface_idx = get_iface_index(sock, g_iface);
    if (iface_idx < 0) {
        close(sock);
        if (g_log_fp) fclose(g_log_fp);
        return 1;
    }

    /* Bind to the interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = iface_idx;
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        if (g_log_fp) fclose(g_log_fp);
        return 1;
    }

    /* Enable promiscuous mode */
    if (set_promisc(sock, g_iface, 1) < 0) {
        fprintf(stderr, "Warning: could not set promiscuous mode.\n");
    }

    /* Main loop */
    run_listener(sock);

    /* Cleanup */
    set_promisc(sock, g_iface, 0);
    close(sock);
    if (g_log_fp) fclose(g_log_fp);

    return 0;
}
