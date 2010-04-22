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
#define SPEAD_FMT_BYTES             4
#define SPEAD_ITEM_VAL_BYTES        5
#define SPEAD_MAX_PACKET_SIZE       9200
#define SPEAD_MAX_FMT_SIZE          1024

#define SPEAD_ERR                   -1

// Macros
#define SPEAD_GET_MAGIC(hdr) (0xFFFFFF & ((hdr) >> 40))
#define SPEAD_GET_VERSION(hdr) (0xFF & ((hdr) >> 32))
#define SPEAD_GET_NITEMS(hdr) ((int) 0x7FFFFFFF & (hdr))

#define SPEAD_ITEM(data,n) (ntohll(((uint64_t *)(data + (n) * SPEAD_ITEM_BYTES))[0]))
#define SPEAD_ITEM_EXT(item) ((bool) 0x1 & (item >> 63))
#define SPEAD_ITEM_ID(item) ((int) 0x7FFFFF & (item >> 40))
#define SPEAD_ITEM_VAL(item) ((uint64_t) 0xFFFFFFFFFFLL & item)

#define SPEAD_HEADER_BUILD(nitems) ((((uint64_t) SPEAD_MAGIC) << 40) | (((uint64_t) SPEAD_VERSION) << 32) | (0xFFFFFFFFLL & (nitems)))
#define SPEAD_ITEM_BUILD(ext,id,val) (((0x1LL & (ext)) << 63) | ((0x7FFFFFLL & (id)) << 40) | (0xFFFFFFFFFFLL & (val)))
#define SPEAD_SET_ITEM(data,n,pkitem) (((uint64_t *)(data + (n) * SPEAD_ITEM_BYTES))[0] = htonll(pkitem))

#define SPEAD_FMT(data,n) (ntohl(((uint32_t *)(data + (n) * SPEAD_FMT_BYTES))[0]))
#define SPEAD_FMT_GET_TYPE(fmt) ((char) 0xFF & (fmt >> 24))
#define SPEAD_FMT_GET_NBITS(fmt) ((int) 0xFFFFFF & fmt)

#define SPEAD_U8_ALIGN(data,off) \
    ((off == 0) ? \
    ((uint8_t *)data)[0] : \
    (((uint8_t *)data)[0] << off) | (((uint8_t *)data)[1] >> (8*sizeof(uint8_t) - off)))

uint32_t spead_u32_align(char *data, int off, int n_bits);
uint64_t spead_u64_align(char *data, int off, int n_bits);
int64_t spead_i64_align(char *data, int off, int n_bits);
void spead_copy_bits(char *data, char *val, int off, int n_bits);

/*___                       _ ____            _        _   
/ ___| _ __   ___  __ _  __| |  _ \ __ _  ___| | _____| |_ 
\___ \| '_ \ / _ \/ _` |/ _` | |_) / _` |/ __| |/ / _ \ __|
 ___) | |_) |  __/ (_| | (_| |  __/ (_| | (__|   <  __/ |_ 
|____/| .__/ \___|\__,_|\__,_|_|   \__,_|\___|_|\_\___|\__|
      |_|                                                  */

struct spead_packet {
    int64_t frame_cnt;
    int n_items;
    bool is_stream_ctrl_term;
    int64_t payload_len;
    int64_t payload_off;
    char data[SPEAD_MAX_PACKET_SIZE];
    char *payload;  // Will point to spot in data where payload starts
    struct spead_packet *next; // For chaining packets together a frame
};
typedef struct spead_packet SpeadPacket;

void spead_packet_init(SpeadPacket *pkt);
void spead_packet_copy(SpeadPacket *pkt1, SpeadPacket *pkt2);
int64_t spead_packet_unpack_header(SpeadPacket *pkt);
int64_t spead_packet_unpack_items(SpeadPacket *pkt);

/*___                       _ ___ _                 
/ ___| _ __   ___  __ _  __| |_ _| |_ ___ _ __ ___  
\___ \| '_ \ / _ \/ _` |/ _` || || __/ _ \ '_ ` _ \ 
 ___) | |_) |  __/ (_| | (_| || || ||  __/ | | | | |
|____/| .__/ \___|\__,_|\__,_|___|\__\___|_| |_| |_|
      |_|                                           */

struct spead_item {
    bool is_valid;
    int id;
    char *val;
    int64_t length;
    struct spead_item *next;
};
typedef struct spead_item SpeadItem;

void spead_item_init(SpeadItem *item) ;
void spead_item_wipe(SpeadItem *item) ;

/*___                       _ _____                         
/ ___| _ __   ___  __ _  __| |  ___| __ __ _ _ __ ___   ___ 
\___ \| '_ \ / _ \/ _` |/ _` | |_ | '__/ _` | '_ ` _ \ / _ \
 ___) | |_) |  __/ (_| | (_| |  _|| | | (_| | | | | | |  __/
|____/| .__/ \___|\__,_|\__,_|_|  |_|  \__,_|_| |_| |_|\___|
      |_|                                                   */

typedef struct {
    int is_valid;
    int64_t frame_cnt;
    SpeadPacket *head_pkt;
    SpeadPacket *last_pkt;
    SpeadItem *head_item;
    SpeadItem *last_item;
} SpeadFrame;

void spead_frame_init(SpeadFrame *frame) ;
void spead_frame_wipe(SpeadFrame *frame) ;
int spead_frame_add_packet(SpeadFrame *frame, SpeadPacket *pkt) ;
int spead_frame_finalize(SpeadFrame *frame) ;

#endif
