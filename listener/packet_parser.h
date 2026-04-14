/*
 * packet_parser.h — Public API for the modular packet parser.
 *
 * Provides structs for ARP, ICMP, and MACsec headers, plus parse functions
 * that return a unified ParseResult.
 *
 * Compile-time flag:
 *   SAFE_MODE=1  — bounds-checked parsing, no unsafe behaviour
 *   SAFE_MODE=0  — simulates a vulnerable device (may crash on bad input)
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* =========================================================================
 * EtherType constants
 * ========================================================================= */
#define ETHERTYPE_ARP    0x0806
#define ETHERTYPE_IP     0x0800
#define ETHERTYPE_MACSEC 0x88E5

/* IP protocol numbers */
#define IPPROTO_ICMP_LOCAL 1

/* =========================================================================
 * Parse status codes
 * ========================================================================= */
typedef enum {
    PARSE_OK          = 0,
    PARSE_MALFORMED   = 1,
    PARSE_UNKNOWN     = 2,
    PARSE_TRUNCATED   = 3,
    PARSE_UNSUPPORTED = 4
} ParseStatus;

/* =========================================================================
 * Ethernet header (14 bytes)
 * ========================================================================= */
#define ETH_ALEN 6
#pragma pack(push, 1)
typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;   /* network byte order */
} EthHeader;

/* =========================================================================
 * ARP header (28 bytes for IPv4-over-Ethernet)
 * ========================================================================= */
typedef struct {
    uint16_t htype;    /* hardware type (1 = Ethernet)        */
    uint16_t ptype;    /* protocol type (0x0800 = IPv4)       */
    uint8_t  hlen;     /* hardware address length (6)         */
    uint8_t  plen;     /* protocol address length (4)         */
    uint16_t oper;     /* operation: 1=REQUEST, 2=REPLY       */
    uint8_t  sha[6];   /* sender hardware address             */
    uint8_t  spa[4];   /* sender protocol address             */
    uint8_t  tha[6];   /* target hardware address             */
    uint8_t  tpa[4];   /* target protocol address             */
} ArpHeader;

/* =========================================================================
 * IPv4 header (minimum 20 bytes)
 * ========================================================================= */
typedef struct {
    uint8_t  ihl_version;  /* version (4) + IHL                 */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint8_t  saddr[4];
    uint8_t  daddr[4];
} IPv4Header;

/* =========================================================================
 * ICMP header (8 bytes minimum)
 * ========================================================================= */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} IcmpHeader;

/* =========================================================================
 * MACsec SecTAG (6 bytes base + optional 8-byte SCI)
 * ========================================================================= */
typedef struct {
    uint8_t  tci_an;   /* TCI + AN byte                       */
    uint8_t  sl;       /* Short Length (6-bit field)          */
    uint32_t pn;       /* Packet Number (replay counter)      */
    uint8_t  sci[8];   /* Secure Channel Identifier (opt.)    */
    uint8_t  has_sci;  /* 1 if SCI was present                */
} MacsecSecTag;
#pragma pack(pop)

/* =========================================================================
 * Unified parse result
 * ========================================================================= */
#define PROTO_STR_LEN 16

typedef struct {
    ParseStatus  status;
    char         proto[PROTO_STR_LEN];  /* "ARP", "ICMP", "MACSEC", "UNKNOWN" */
    size_t       frame_len;
    struct timespec timestamp;

    /* Protocol-specific fields (union for memory efficiency) */
    union {
        struct {
            uint16_t oper;
            char     spa[16];  /* dotted-decimal sender IP       */
            char     tpa[16];  /* dotted-decimal target IP       */
            uint8_t  hlen;
            uint8_t  plen;
        } arp;

        struct {
            uint8_t  type;
            uint8_t  code;
            uint16_t checksum;
            uint8_t  ttl;
            uint16_t ip_len;
        } icmp;

        struct {
            uint8_t  tci_an;
            uint8_t  sl;
            uint32_t pn;
            uint8_t  has_sci;
        } macsec;
    } data;
} ParseResult;

/* =========================================================================
 * Public API
 * ========================================================================= */

/**
 * parse_frame() — Entry point.  Dispatches to the protocol-specific parser.
 *
 * @param frame      Pointer to the raw Ethernet frame buffer.
 * @param frame_len  Number of bytes in the buffer.
 * @param result     Output struct populated by the parser.
 * @return           PARSE_OK on success, error code otherwise.
 */
ParseStatus parse_frame(const uint8_t *frame, size_t frame_len, ParseResult *result);

/* Protocol-specific parsers */
ParseStatus parse_arp(const uint8_t *frame, size_t frame_len, ParseResult *result);
ParseStatus parse_icmp(const uint8_t *frame, size_t frame_len, ParseResult *result);
ParseStatus parse_macsec(const uint8_t *frame, size_t frame_len, ParseResult *result);

/* Utility */
void        result_to_log_line(const ParseResult *result, char *buf, size_t buf_len);

#endif /* PACKET_PARSER_H */
