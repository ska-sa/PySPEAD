#ifndef SPEAD_PACKET_H
#define SPEAD_PACKET_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
//#include <netinet/in.h>

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
#define SPEAD_MAGIC                 0x4b5254
#define SPEAD_VERSION               3

#define SPEAD_FRAME_CNT_ID          0x01
#define SPEAD_PAYLOAD_OFFSET_ID     0x02
#define SPEAD_PAYLOAD_LENGTH_ID     0x03
#define SPEAD_DESCRIPTOR_ID         0x04
#define SPEAD_STREAM_CTRL_ID        0x05

#define SPEAD_STREAM_CTRL_TERM_VAL  0x02

#define SPEAD_ITEM_BYTES            8
#define SPEAD_ITEM_VAL_BYTES        5
#define SPEAD_MAX_PACKET_SIZE       9200

#define SPEAD_ERR                   -1

// Macros
#define SPEAD_GET_MAGIC(hdr) (0xFFFFFF & (hdr >> 40))
#define SPEAD_GET_VERSION(hdr) (0xFF & (hdr >> 32))
#define SPEAD_GET_NITEMS(hdr) ((int) 0x7FFFFFFF & hdr)

#define SPEAD_ITEM(data,n) (ntohll(((uint64_t *)(data + n * SPEAD_ITEM_BYTES))[0]))
#define SPEAD_ITEM_EXT(item) ((bool) 0x1 & (item >> 63))
#define SPEAD_ITEM_ID(item) ((int) 0x7FFFFF & (item >> 40))
#define SPEAD_ITEM_VAL(item) ((uint64_t) 0xFFFFFFFFFFLL & item)

// Objects
typedef struct {
    bool is_ext;
    int id;
    uint64_t val;
} SpeadRawItem;

struct spead_item {
    bool is_valid;
    int id;
    char *val;
    int64_t length;
    struct spead_item *next;
};
typedef struct spead_item SpeadItem;

struct spead_payload {
    char *data;
    int64_t length;
    int64_t offset;
    struct spead_payload *next;
};
typedef struct spead_payload SpeadPayload;

struct spead_packet {
    int64_t frame_cnt;
    int n_items;
    SpeadRawItem *raw_items;
    SpeadPayload *payload;
    struct spead_packet *next;
};
typedef struct spead_packet SpeadPacket;

typedef struct {
    bool is_valid;
    int64_t frame_cnt;
    SpeadPacket *head_pkt;
    SpeadPacket *last_pkt;
    SpeadItem *head_item;
    SpeadItem *last_item;
} SpeadFrame;

// Methods
void spead_item_init(SpeadItem *item) ;
void spead_item_wipe(SpeadItem *item) ;
void spead_payload_init(SpeadPayload *pyld) ;
void spead_payload_wipe(SpeadPayload *pyld) ;
void spead_packet_init(SpeadPacket *pkt) ;
SpeadPacket *spead_packet_clone(SpeadPacket *pkt) ;
void spead_packet_wipe(SpeadPacket *pkt) ;
void spead_frame_init(SpeadFrame *frame) ;
void spead_frame_wipe(SpeadFrame *frame) ;

int64_t spead_packet_unpack_header(SpeadPacket *pkt, char *data) ;
int64_t spead_packet_unpack_items(SpeadPacket *pkt, char *data) ;
int64_t spead_packet_unpack_payload(SpeadPacket *pkt, char *data) ;

int spead_frame_add_packet(SpeadFrame *frame, SpeadPacket *pkt) ;
int spead_frame_finalize(SpeadFrame *frame) ;

#endif
