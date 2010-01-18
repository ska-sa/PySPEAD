#ifndef SPEAD_PACKET_H
#define SPEAD_PACKET_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#ifndef htonll
#ifdef _BIG_ENDIAN
#define htonll(x)   ((uint64_t)x)
#define ntohll(x)   ((uint64_t)x)
#else
#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(((uint64_t)x) >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(((uint64_t)x) >> 32))
#endif
#endif

// Constants
#define SPEAD_MAGIC                 0x4b52
#define SPEAD_VERSION               3
#define SPEAD_RESERVED              0

#define SPEAD_FRAME_CNT_ID          0x01
#define SPEAD_PAYLOAD_CNTLEN_ID     0x02
#define SPEAD_HEAP_LENOFF_ID        0x03
#define SPEAD_STREAM_CTRL_ID        0x05

#define SPEAD_STREAM_CTRL_TERM_VAL  0x02

#define SPEAD_ITEM_BYTES            8
#define SPEAD_MAX_PACKET_SIZE       9200

// Objects

typedef struct {
    bool is_ext;
    uint16_t id;
    uint64_t val;
} SpeadRawItem;

typedef struct {
    uint16_t n_items;
    SpeadRawItem *items;
    uint64_t frame_cnt;
    char *payload;
    uint32_t payload_len;
    uint32_t payload_cnt;
} SpeadPacket;

// Methods
void spead_init_packet(SpeadPacket *pkt);
void spead_free_packet(SpeadPacket *pkt);
int spead_unpack_hdr(SpeadPacket *pkt, char *data);
int spead_unpack_items(SpeadPacket *pkt, char *data);
int spead_unpack_payload(SpeadPacket *pkt, char *data);
void spead_pack(SpeadPacket *pkt, char *data);

#endif
