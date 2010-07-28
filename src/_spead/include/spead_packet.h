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

// Flavor constants
#define SPEAD_MAGIC                 0x53
#define SPEAD_VERSION               4
#define SPEAD_ITEMSIZE              64
#define SPEAD_ADDRSIZE              40
#define SPEAD_HEAP_ADDR_WIDTH     (SPEAD_ADDRSIZE/8)
#define SPEAD_ITEM_PTR_WIDTH	  ((SPEAD_ITEMSIZE-SPEAD_ADDRSIZE)/8)
#define SPEAD_ITEMLEN             (SPEAD_ITEMSIZE/8)
#define SPEAD_ADDRLEN             (SPEAD_ADDRSIZE/8)

#define SPEAD_ITEMMASK              0xFFFFFFFFFFFFFFFFLL
#define SPEAD_ADDRMASK              (SPEAD_ITEMMASK >> (SPEAD_ITEMSIZE-SPEAD_ADDRSIZE))
#define SPEAD_IDMASK                (SPEAD_ITEMMASK >> (SPEAD_ADDRSIZE+1))
#define SPEAD_ADDRMODEMASK          0x1LL
#define SPEAD_DIRECTADDR            0
#define SPEAD_IMMEDIATEADDR         1

#define SPEAD_MAX_PACKET_LEN       9200
#define SPEAD_MAX_FMT_LEN          1024

// Reserved Item IDs
#define SPEAD_HEAP_CNT_ID           0x01
#define SPEAD_HEAP_LEN_ID           0x02
#define SPEAD_PAYLOAD_OFF_ID     0x03
#define SPEAD_PAYLOAD_LEN_ID     0x04
#define SPEAD_DESCRIPTOR_ID         0x05
#define SPEAD_STREAM_CTRL_ID        0x06

#define SPEAD_STREAM_CTRL_TERM_VAL  0x02
#define SPEAD_ERR                   -1

// Header Macros
#define SPEAD_HEADERLEN             8
#define SPEAD_HEADER(data) (ntohll(((uint64_t *)(data))[0]))
#define SPEAD_HEADER_BUILD(nitems) ((((uint64_t) SPEAD_MAGIC) << 56) | (((uint64_t) SPEAD_VERSION) << 48) | (((uint64_t) SPEAD_ITEM_PTR_WIDTH) << 40) | (((uint64_t) SPEAD_HEAP_ADDR_WIDTH) << 32) | (0xFFFFLL & (nitems)))
#define SPEAD_GET_MAGIC(hdr) (0xFF & ((hdr) >> 56))
#define SPEAD_GET_VERSION(hdr) (0xFF & ((hdr) >> 48))
#define SPEAD_GET_ITEMSIZE(hdr) (0xFF & ((hdr) >> 40))
#define SPEAD_GET_ADDRSIZE(hdr) (0xFF & ((hdr) >> 32))
#define SPEAD_GET_NITEMS(hdr) ((int) 0xFFFF & (hdr))

// ItemPointer Macros
#define SPEAD_ITEM_BUILD(mode,id,val) (((SPEAD_ADDRMODEMASK & (mode)) << (SPEAD_ITEMSIZE-1)) | ((SPEAD_IDMASK & (id)) << (SPEAD_ADDRSIZE)) | (SPEAD_ADDRMASK & (val)))
#define SPEAD_ITEM(data,n) (ntohll(((uint64_t *)(data + (n) * SPEAD_ITEMLEN))[0]))
#define SPEAD_ITEM_MODE(item) ((int)(SPEAD_ADDRMODEMASK & (item >> (SPEAD_ITEMSIZE-1))))
#define SPEAD_ITEM_ID(item) ((int)(SPEAD_IDMASK & (item >> SPEAD_ADDRSIZE)))
#define SPEAD_ITEM_ADDR(item) ((uint64_t)(SPEAD_ADDRMASK & item))
#define SPEAD_SET_ITEM(data,n,pkitem) (((uint64_t *)(data + (n) * SPEAD_ITEMLEN))[0] = htonll(pkitem))

// Format Macros
#define SPEAD_FMT_LEN             4
#define SPEAD_FMT(data,n) (ntohl(((uint32_t *)(data + (n) * SPEAD_FMT_LEN))[0]))
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
    int64_t heap_cnt;
    int64_t heap_len;
    int n_items;
    int is_stream_ctrl_term;
    int64_t payload_len;
    int64_t payload_off;
    char data[SPEAD_MAX_PACKET_LEN];
    char *payload;  // Will point to spot in data where payload starts
    struct spead_packet *next; // For chaining packets together a heap
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
    int is_valid;
    int id;
    char *val;
    int64_t len;
    struct spead_item *next;
};
typedef struct spead_item SpeadItem;

void spead_item_init(SpeadItem *item) ;
void spead_item_wipe(SpeadItem *item) ;

/*___                       _ _   _                  
/ ___| _ __   ___  __ _  __| | | | | ___  __ _ _ __  
\___ \| '_ \ / _ \/ _` |/ _` | |_| |/ _ \/ _` | '_ \ 
 ___) | |_) |  __/ (_| | (_| |  _  |  __/ (_| | |_) |
|____/| .__/ \___|\__,_|\__,_|_| |_|\___|\__,_| .__/ 
      |_|                                     |_|    */

typedef struct {
    int is_valid;
    int64_t heap_cnt;
    int64_t heap_len;
    int has_all_packets;
    SpeadPacket *head_pkt;
    SpeadPacket *last_pkt;
    SpeadItem *head_item;
    SpeadItem *last_item;
} SpeadHeap;

void spead_heap_init(SpeadHeap *heap) ;
void spead_heap_wipe(SpeadHeap *heap) ;
int spead_heap_add_packet(SpeadHeap *heap, SpeadPacket *pkt) ;
int spead_heap_got_all_packets(SpeadHeap *heap) ;
int spead_heap_finalize(SpeadHeap *heap) ;

#endif
