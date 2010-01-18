#include "include/spead_packet.h"

/* Initialize a SpeadPacket with default values */
void spead_init_packet(SpeadPacket *pkt) {
    pkt->n_items = 0;
    pkt->items = NULL;
    pkt->frame_cnt = 0xFFFFFFFFFFFFFFFF;  // > 48b = flag for not initialized
    pkt->payload = NULL;
    pkt->payload_len = 0;
    pkt->payload_cnt = 0;
}

/* Release any memory buffers that were malloc'd in a SpeadPacket */
void spead_free_packet(SpeadPacket *pkt) {
    if (pkt->items != NULL) free(pkt->items);
    if (pkt->payload != NULL) free(pkt->payload);
    spead_init_packet(pkt);
}

#define HDR_MAGIC(hdr) (0xFFFF & (hdr >> 48))
#define HDR_VERSION(hdr) (0xFFFF & (hdr >> 32))
#define HDR_RESERVED(hdr) (0xFFFF & (hdr >> 16))
#define HDR_N_ITEMS(hdr) ((int) 0xFFFF & hdr)
#define ITEM(data,n) (ntohll(((uint64_t *)(data + n * SPEAD_ITEM_BYTES))[0]))

/* Check magic values in a spead header and initialize pkt->n_items from first 8 bytes of data
 * pkt gets cleared (with spead_free_packet)
 * data must be at least 8 bytes long */
int spead_unpack_hdr(SpeadPacket *pkt, char *data) {
    uint64_t hdr;
    spead_free_packet(pkt);  // Clear this packet (in case it isn't fresh)
    hdr = ITEM(data, 0);
    //printf("magic: 0x%x <> 0x%x\n", HDR_MAGIC(hdr), SPEAD_MAGIC);
    //printf("version: 0x%x <> 0x%x\n", HDR_VERSION(hdr), SPEAD_VERSION);
    //printf("reserved: 0x%x <> 0x%x\n", HDR_RESERVED(hdr), SPEAD_RESERVED);
    if ((HDR_MAGIC(hdr) != SPEAD_MAGIC) || 
            (HDR_VERSION(hdr) != SPEAD_VERSION) || 
            (HDR_RESERVED(hdr) != SPEAD_RESERVED)) return -1;
    pkt->n_items = HDR_N_ITEMS(hdr);
    return 8;  // Return # of bytes read
}
    
#define ITEM_EXT(item) ((bool) 0x1 & (item >> 63))
#define ITEM_ID(item) ((uint16_t) 0x7FFF & (item >> 48))
#define ITEM_VAL(item) ((uint64_t) 0xFFFFFFFFFFFF & item)

#define PAYLOAD_CNTLEN_CNT(val) ((uint32_t) 0xFFFFFF & (val >> 24))
#define PAYLOAD_CNTLEN_LEN(val) ((uint32_t) 0xFFFFFF & val)

/* Create array of pkt->items from 8-byte entries in packet header stored in data buffer,
 * and initialize pkt->payload_len, pkt->payload_cnt, and pkt->frame_cnt from items.
 * pkt must have n_items already initialized (from spead_unpack_hdr)
 * data must be at least 8*pkt->n_items bytes long */
int spead_unpack_items(SpeadPacket *pkt, char *data) {
    uint64_t item;
    int j;
    // Read each item
    pkt->items = (SpeadRawItem *) malloc(pkt->n_items * sizeof(SpeadRawItem));
    for (j=0; j < pkt->n_items; j++) {
        item = ITEM(data,j);
        //printf("spead_unpack_items,item=%d:", j);
        //printf("%02x %02x %02x %02x %02x %02x %02x %02x ->", 
        //    0xFF & (item >> 56), 0xFF & (item >> 48), 0xFF & (item >> 40),
        //    0xFF & (item >> 32), 0xFF & (item >> 24), 0xFF & (item >> 16),
        //    0xFF & (item >>  8), 0xFF & (item >>  0));
        pkt->items[j].is_ext = ITEM_EXT(item);
        pkt->items[j].id = ITEM_ID(item);
        pkt->items[j].val = ITEM_VAL(item);
        //printf("is_ext=%d, id=%d, val=%d\n",  pkt->items[j].is_ext,
        //    pkt->items[j].id, pkt->items[j].val);
        // Check for FRAME_CNT and PAYLOAD_CNTLEN, which are required
        // for packet decoding
        if (pkt->items[j].id == SPEAD_FRAME_CNT_ID) {
            pkt->frame_cnt = pkt->items[j].val;
        } else if (pkt->items[j].id == SPEAD_PAYLOAD_CNTLEN_ID) {
            pkt->payload_len = PAYLOAD_CNTLEN_LEN(pkt->items[j].val);
            pkt->payload_cnt = PAYLOAD_CNTLEN_CNT(pkt->items[j].val);
        }
    }
    return pkt->n_items * 8; // Return # of bytes read
}

/* Create buffer pkt->payload and copy pkt->payload_len bytes of data into it.
 * pkt must have payload_len already initialized (from spead_unpack_items)
 * data must be at least pkt->payload_len bytes long */
int spead_unpack_payload(SpeadPacket *pkt, char *data) {
    int i;
    // Read the payload (if any)
    if (pkt->payload_len > 0) {
        // Copy the payload into a new string
        pkt->payload = (char *) malloc(pkt->payload_len * sizeof(char));
        for (i=0; i < pkt->payload_len; i++) {
            pkt->payload[i] = data[i];
        }
    }
    return pkt->payload_len; // Return # of bytes read
}

void spead_pack(SpeadPacket *pkt, char *data) {
}
