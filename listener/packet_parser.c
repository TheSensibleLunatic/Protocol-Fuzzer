/*
 * packet_parser.c — Modular packet parsing for proto-fuzzer listener.
 *
 * SAFE_MODE compile flag:
 *   -DSAFE_MODE=1  (default, safe)   → all bounds checked, no UB
 *   -DSAFE_MODE=0  (unsafe/vuln sim) → deliberate unsafe accesses to
 *                                       simulate a vulnerable device
 *
 * Compile:
 *   gcc -DSAFE_MODE=1 -Wall -Wextra -c packet_parser.c
 */

#include "packet_parser.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

/* Default to safe mode if not explicitly set */
#ifndef SAFE_MODE
#define SAFE_MODE 1
#endif

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static void set_timestamp(ParseResult *result) {
    clock_gettime(CLOCK_REALTIME, &result->timestamp);
}

static void ip_bytes_to_str(const uint8_t *bytes, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%u.%u.%u.%u",
             bytes[0], bytes[1], bytes[2], bytes[3]);
}

/* =========================================================================
 * ARP parser
 * ========================================================================= */

ParseStatus parse_arp(const uint8_t *frame, size_t frame_len, ParseResult *result) {
    strncpy(result->proto, "ARP", sizeof(result->proto) - 1);

#if SAFE_MODE
    /* Minimum frame: 14 (Eth) + 28 (ARP) = 42 bytes */
    if (frame_len < 42) {
        result->status = PARSE_TRUNCATED;
        return PARSE_TRUNCATED;
    }
#endif

    const ArpHeader *arp = (const ArpHeader *)(frame + sizeof(EthHeader));

#if !SAFE_MODE
    /*
     * UNSAFE (vuln sim): trust the hlen/plen fields and compute offsets
     * without bounds checking — a crafted hlen=255 will cause OOB read.
     */
    uint8_t hlen = arp->hlen;
    uint8_t plen = arp->plen;
    /* OOB read possible here if hlen+plen > remaining buffer */
    const uint8_t *sha = (const uint8_t *)arp + 8;
    const uint8_t *spa = sha + hlen;
    const uint8_t *tha = spa + plen;
    const uint8_t *tpa = tha + hlen;
    (void)sha; (void)spa; (void)tha; (void)tpa;
#endif

    uint16_t oper  = ntohs(arp->oper);
    uint16_t htype = ntohs(arp->htype);
    uint16_t ptype = ntohs(arp->ptype);

    result->data.arp.oper = oper;
    result->data.arp.hlen = arp->hlen;
    result->data.arp.plen = arp->plen;

    ip_bytes_to_str(arp->spa, result->data.arp.spa, sizeof(result->data.arp.spa));
    ip_bytes_to_str(arp->tpa, result->data.arp.tpa, sizeof(result->data.arp.tpa));

    /* Validate fields */
    int malformed = 0;
    if (htype != 1)          malformed = 1;   /* not Ethernet */
    if (ptype != 0x0800)     malformed = 1;   /* not IPv4     */
    if (arp->hlen != 6)      malformed = 1;   /* wrong HW len */
    if (arp->plen != 4)      malformed = 1;   /* wrong  P len */
    if (oper != 1 && oper != 2) malformed = 1; /* invalid opcode */

    result->status = malformed ? PARSE_MALFORMED : PARSE_OK;
    return result->status;
}

/* =========================================================================
 * ICMP parser
 * ========================================================================= */

ParseStatus parse_icmp(const uint8_t *frame, size_t frame_len, ParseResult *result) {
    strncpy(result->proto, "ICMP", sizeof(result->proto) - 1);

#if SAFE_MODE
    /* Minimum: 14 (Eth) + 20 (IP) + 8 (ICMP) = 42 bytes */
    if (frame_len < 42) {
        result->status = PARSE_TRUNCATED;
        return PARSE_TRUNCATED;
    }
#endif

    const IPv4Header *ip = (const IPv4Header *)(frame + sizeof(EthHeader));
    uint8_t ihl = (ip->ihl_version & 0x0F) * 4;

#if SAFE_MODE
    if (ihl < 20 || (size_t)(sizeof(EthHeader) + ihl + sizeof(IcmpHeader)) > frame_len) {
        result->status = PARSE_MALFORMED;
        return PARSE_MALFORMED;
    }
#endif

    const IcmpHeader *icmp = (const IcmpHeader *)(frame + sizeof(EthHeader) + ihl);

#if !SAFE_MODE
    /*
     * UNSAFE (vuln sim): blindly trust ip->tot_len to index into payload —
     * a packet advertising tot_len=65535 will attempt OOB access.
     */
    uint16_t tot_len = ntohs(ip->tot_len);
    size_t icmp_data_len = (size_t)tot_len - ihl - sizeof(IcmpHeader);
    /* Dangerous: no bounds check on icmp_data_len */
    const uint8_t *icmp_payload = (const uint8_t *)icmp + sizeof(IcmpHeader);
    volatile uint8_t probe = icmp_payload[icmp_data_len - 1]; /* OOB read */
    (void)probe;
#endif

    result->data.icmp.type     = icmp->type;
    result->data.icmp.code     = icmp->code;
    result->data.icmp.checksum = ntohs(icmp->checksum);
    result->data.icmp.ttl      = ip->ttl;
    result->data.icmp.ip_len   = ntohs(ip->tot_len);

    int malformed = 0;
    /* type 0 (echo reply) and type 8 (echo request) are most common */
    if (icmp->type > 18 && icmp->type < 30) malformed = 1;  /* reserved range */
    if (ip->ttl == 0)                        malformed = 1;  /* TTL expired    */
    if (ip->protocol != IPPROTO_ICMP_LOCAL)  malformed = 1;  /* not ICMP       */

    result->status = malformed ? PARSE_MALFORMED : PARSE_OK;
    return result->status;
}

/* =========================================================================
 * MACsec parser
 * ========================================================================= */

ParseStatus parse_macsec(const uint8_t *frame, size_t frame_len, ParseResult *result) {
    strncpy(result->proto, "MACSEC", sizeof(result->proto) - 1);

    /* Minimum: 14 (Eth) + 6 (SecTAG base) + 16 (ICV) = 36 bytes */
#if SAFE_MODE
    if (frame_len < 36) {
        result->status = PARSE_TRUNCATED;
        return PARSE_TRUNCATED;
    }
#endif

    const uint8_t *sectag = frame + sizeof(EthHeader);
    uint8_t tci_an = sectag[0];
    uint8_t sl     = sectag[1] & 0x3F;    /* 6-bit field */
    uint32_t pn;
    memcpy(&pn, sectag + 2, 4);
    pn = ntohl(pn);

    uint8_t sc_bit = (tci_an >> 3) & 0x01; /* bit 3 of TCI byte */
    uint8_t v_bit  = (tci_an >> 7) & 0x01; /* version bit; must be 0 */

    result->data.macsec.tci_an  = tci_an;
    result->data.macsec.sl      = sl;
    result->data.macsec.pn      = pn;
    result->data.macsec.has_sci = sc_bit;

    int malformed = 0;
    if (v_bit != 0)   malformed = 1;   /* MACsec V bit MUST be 0      */
    if (pn == 0)      malformed = 1;   /* PN=0 is invalid per 802.1AE */

#if !SAFE_MODE
    /*
     * UNSAFE (vuln sim): use sl as a direct index into the frame buffer
     * without checking against frame_len — crafted sl values cause OOB.
     */
    size_t payload_offset = sizeof(EthHeader) + 6 + (sc_bit ? 8 : 0);
    const uint8_t *payload = frame + payload_offset;
    /* OOB read: sl can be up to 0xFF after fuzzing the high bits */
    volatile uint8_t probe = payload[sl];
    (void)probe;
#endif

    result->status = malformed ? PARSE_MALFORMED : PARSE_OK;
    return result->status;
}

/* =========================================================================
 * Top-level dispatcher
 * ========================================================================= */

ParseStatus parse_frame(const uint8_t *frame, size_t frame_len, ParseResult *result) {
    memset(result, 0, sizeof(*result));
    result->frame_len = frame_len;
    set_timestamp(result);
    strncpy(result->proto, "UNKNOWN", sizeof(result->proto) - 1);

#if SAFE_MODE
    if (frame == NULL || frame_len < sizeof(EthHeader)) {
        result->status = PARSE_TRUNCATED;
        return PARSE_TRUNCATED;
    }
#endif

    const EthHeader *eth = (const EthHeader *)frame;
    uint16_t ethertype = ntohs(eth->ethertype);

    switch (ethertype) {
        case ETHERTYPE_ARP:
            return parse_arp(frame, frame_len, result);

        case ETHERTYPE_IP:
            /* Check IP protocol field before dispatching to ICMP */
            if (frame_len >= sizeof(EthHeader) + sizeof(IPv4Header)) {
                const IPv4Header *ip = (const IPv4Header *)(frame + sizeof(EthHeader));
                if (ip->protocol == IPPROTO_ICMP_LOCAL) {
                    return parse_icmp(frame, frame_len, result);
                }
            }
            strncpy(result->proto, "IPv4", sizeof(result->proto) - 1);
            result->status = PARSE_UNSUPPORTED;
            return PARSE_UNSUPPORTED;

        case ETHERTYPE_MACSEC:
            return parse_macsec(frame, frame_len, result);

        default:
            result->status = PARSE_UNKNOWN;
            return PARSE_UNKNOWN;
    }
}

/* =========================================================================
 * Log line formatter
 * ========================================================================= */

void result_to_log_line(const ParseResult *result, char *buf, size_t buf_len) {
    const char *status_str = "OK";
    switch (result->status) {
        case PARSE_MALFORMED:   status_str = "MALFORMED";   break;
        case PARSE_TRUNCATED:   status_str = "TRUNCATED";   break;
        case PARSE_UNKNOWN:     status_str = "UNKNOWN";     break;
        case PARSE_UNSUPPORTED: status_str = "UNSUPPORTED"; break;
        default:                status_str = "OK";          break;
    }

    snprintf(buf, buf_len,
             "[%ld.%09ld] proto=%-7s len=%-5zu status=%s",
             (long)result->timestamp.tv_sec,
             result->timestamp.tv_nsec,
             result->proto,
             result->frame_len,
             status_str);
}
