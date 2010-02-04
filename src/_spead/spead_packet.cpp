#include "include/spead_packet.h"

/*___                       _ ____            _        _   
/ ___| _ __   ___  __ _  __| |  _ \ __ _  ___| | _____| |_ 
\___ \| '_ \ / _ \/ _` |/ _` | |_) / _` |/ __| |/ / _ \ __|
 ___) | |_) |  __/ (_| | (_| |  __/ (_| | (__|   <  __/ |_ 
|____/| .__/ \___|\__,_|\__,_|_|   \__,_|\___|_|\_\___|\__|
      |_|                                                  */

void spead_packet_init(SpeadPacket *pkt) {
    pkt->frame_cnt = SPEAD_ERR;
    pkt->n_items = 0;
    pkt->is_stream_ctrl_term = 0;
    pkt->payload_len = 0;
    pkt->payload_off = 0;
    pkt->payload = NULL;
    pkt->next = NULL;
}

void spead_packet_wipe(SpeadPacket *pkt) {
    spead_packet_init(pkt);
}

// Copy pkt1 into pkt2, but don't link (i.e. not pkt->next)
void spead_packet_copy(SpeadPacket *pkt1, SpeadPacket *pkt2) {
    int64_t j;
    pkt2->frame_cnt     = pkt1->frame_cnt;
    pkt2->n_items       = pkt1->n_items;
    pkt2->is_stream_ctrl_term = pkt1->is_stream_ctrl_term;
    pkt2->payload_len   = pkt1->payload_len;
    pkt2->payload_off   = pkt1->payload_off;
    pkt2->payload       = pkt1->payload;
    pkt2->next          = NULL;
    for (j=0; j < SPEAD_ITEM_BYTES * pkt1->n_items + pkt1->payload_len; j++) {
        pkt2->data[j] = pkt1->data[j];
    }
}
    
/* Check magic values in a spead header and initialize pkt->n_items from first 8 bytes of data
 * pkt gets wiped
 * data must be at least 8 bytes long */
int64_t spead_packet_unpack_header(SpeadPacket *pkt) {
    uint64_t hdr;
    hdr = SPEAD_ITEM(pkt->data, 0);
    if ((SPEAD_GET_MAGIC(hdr) != SPEAD_MAGIC) || (SPEAD_GET_VERSION(hdr) != SPEAD_VERSION)) return SPEAD_ERR;
    pkt->n_items = SPEAD_GET_NITEMS(hdr);
    pkt->payload = pkt->data + (pkt->n_items + 1) * SPEAD_ITEM_BYTES;
    return SPEAD_ITEM_BYTES;  // Return # of bytes read
}
    
/* Create array of pkt->items from 8-byte entries in packet header stored in data buffer,
 * and initialize pkt->payload_len and pkt->frame_cnt from items.
 * pkt must have n_items already initialized (from spead_unpack_header) */
int64_t spead_packet_unpack_items(SpeadPacket *pkt) {
    uint64_t item;
    int i;
    // Read each raw item, starting at 1 to skip header
    for (i=1; i <= pkt->n_items; i++) {
        item = SPEAD_ITEM(pkt->data, i);
        //printf("item%d: ext=%d, id=%d, val=%d\n", i, SPEAD_ITEM_EXT(item), SPEAD_ITEM_ID(item), SPEAD_ITEM_VAL(item));
        switch (SPEAD_ITEM_ID(item)) {
            case SPEAD_FRAME_CNT_ID:      pkt->frame_cnt   = (int64_t) SPEAD_ITEM_VAL(item); break;
            case SPEAD_PAYLOAD_OFFSET_ID: pkt->payload_off = (int64_t) SPEAD_ITEM_VAL(item); break;
            case SPEAD_PAYLOAD_LENGTH_ID: pkt->payload_len = (int64_t) SPEAD_ITEM_VAL(item); break;
            case SPEAD_STREAM_CTRL_ID: if (SPEAD_ITEM_VAL(item) == SPEAD_STREAM_CTRL_TERM_VAL) pkt->is_stream_ctrl_term = 1; break;
            default: break;
        }
    }
    return pkt->n_items * SPEAD_ITEM_BYTES; // Return # of bytes read
}

/*___                       _ ___ _                 
/ ___| _ __   ___  __ _  __| |_ _| |_ ___ _ __ ___  
\___ \| '_ \ / _ \/ _` |/ _` || || __/ _ \ '_ ` _ \ 
 ___) | |_) |  __/ (_| | (_| || || ||  __/ | | | | |
|____/| .__/ \___|\__,_|\__,_|___|\__\___|_| |_| |_|
      |_|                                           */

void spead_item_init(SpeadItem *item) {
    item->is_valid = 0;
    item->id = SPEAD_ERR;
    item->val = NULL;
    item->length = SPEAD_ERR;
    item->next = NULL;
}

void spead_item_wipe(SpeadItem *item) {
    if (item->val != NULL) free(item->val);
    spead_item_init(item);  // Wipe this item clean
}
    
/*___                       _ _____                         
/ ___| _ __   ___  __ _  __| |  ___| __ __ _ _ __ ___   ___ 
\___ \| '_ \ / _ \/ _` |/ _` | |_ | '__/ _` | '_ ` _ \ / _ \
 ___) | |_) |  __/ (_| | (_| |  _|| | | (_| | | | | | |  __/
|____/| .__/ \___|\__,_|\__,_|_|  |_|  \__,_|_| |_| |_|\___|
      |_|                                                   */

void spead_frame_init(SpeadFrame *frame) {
    frame->is_valid = 0;
    frame->frame_cnt = SPEAD_ERR;
    frame->head_pkt = NULL;
    frame->last_pkt = NULL;
    frame->head_item = NULL;
    frame->last_item = NULL;
}

void spead_frame_wipe(SpeadFrame *frame) {
    SpeadPacket *pkt, *next_pkt;
    SpeadItem *item, *next_item;
    item = frame->head_item;
    while (item != NULL) {
        next_item = item->next;
        spead_item_wipe(item);
        free(item);
        item = next_item;
    }
    // Do not touch frame->last_item b/c it was deleted by spead_item_wipe
    pkt = frame->head_pkt;
    while (pkt != NULL) {
        next_pkt = pkt->next;
        free(pkt);
        pkt = next_pkt;
    }
    // Do not touch frame->last_pkt b/c it was deleted by spead_packet_wipe
    spead_frame_init(frame); // Wipe this frame clean
}
    
int spead_frame_add_packet(SpeadFrame *frame, SpeadPacket *pkt) {
    SpeadPacket *_pkt;
    if (pkt->n_items == 0) return SPEAD_ERR;
    if (frame->frame_cnt < 0) {  // We have a fresh frame
        frame->frame_cnt = pkt->frame_cnt;
        frame->head_pkt = pkt;
        frame->last_pkt = pkt;
    } else { // We need to insert this packet in the correct order
        if (frame->frame_cnt != pkt->frame_cnt) return SPEAD_ERR;
        _pkt = frame->head_pkt;
        // Find the right slot to insert this pkt
        while (_pkt->next != NULL && _pkt->next->payload_off < pkt->payload_off) {
            _pkt = _pkt->next;
        }
        // Insert the pkt
        pkt->next = _pkt->next;
        _pkt->next = pkt;
        if (pkt->next == NULL) frame->last_pkt = pkt;
    }
    return 0;
}

int spead_frame_finalize(SpeadFrame *frame) {
    SpeadPacket *pkt1, *pkt2;
    SpeadItem *item;
    int i, j, flag, id;
    int64_t off, o, heaplen, rawitem1, rawitem2;
    // Sanity check on frame
    if (frame->head_pkt == NULL) return 0;
    if (frame->head_item != NULL) {
        spead_item_wipe(frame->head_item);
        free(frame->head_item);
        frame->head_item = NULL;
    }
    frame->last_item = NULL;
    heaplen = frame->last_pkt->payload_off + frame->last_pkt->payload_len;
    pkt1 = frame->head_pkt;
    // Loop over all items in all packets received
    while (pkt1 != NULL) {
        for (i=1; i <= pkt1->n_items; i++) {
            rawitem1 = SPEAD_ITEM(pkt1->data, i);
            id = SPEAD_ITEM_ID(rawitem1);
            switch (id) {
                case SPEAD_FRAME_CNT_ID: 
                case SPEAD_PAYLOAD_OFFSET_ID:
                case SPEAD_PAYLOAD_LENGTH_ID:
                case SPEAD_STREAM_CTRL_ID:
                    continue;
                default: break;
            }
            item = (SpeadItem *) malloc(sizeof(SpeadItem));
            if (item == NULL) return SPEAD_ERR;
            spead_item_init(item);
            item->is_valid = 1;
            item->id = id;
            // Extension items must be retrieved from the packet payloads
            if (SPEAD_ITEM_EXT(rawitem1)) {
                off = (int64_t) SPEAD_ITEM_VAL(rawitem1);
                // Figure out length of item by defaulting to remaining heap, then looping over 
                // remaining rawitems (in all remaining of packets) to find start of next
                // extension item.
                item->length = heaplen - off;
                flag = 0;  // Used to tell when we've found next extension item to break out
                pkt2 = pkt1; j = i+1;  // Start with the next rawitem in this packet
                do {
                    for (; j <= pkt2->n_items; j++) {
                        rawitem2 = SPEAD_ITEM(pkt2->data, j);
                        if (SPEAD_ITEM_EXT(rawitem2)) {
                            item->length = (int64_t) SPEAD_ITEM_VAL(rawitem2) - off;
                            flag = 1;
                            break;
                        }
                    }
                    if (flag) break;
                    pkt2 = pkt2->next; j = 0;  // Move on to first rawitem in next packet
                } while (pkt2 != NULL);
                //printf("Allocating item of length %d\n", item->length);
                if (item->length < 0) {  // This happens when the last packet in a frame goes missing
                    item->is_valid = 0;
                } else {
                    item->val = (char *) malloc(item->length * sizeof(char));
                    if (item->val == NULL) return SPEAD_ERR;
                    // Dig through the payloads to retrieve item value
                    pkt2 = frame->head_pkt;
                    for (o=0; o < item->length; o++) {
                        while (pkt2 != NULL && (pkt2->payload_off + pkt2->payload_len <= off + o)) {
                            //printf("Moving to next packet\n");
                            pkt2 = pkt2->next;
                        }
                        // If packet with relevant data is missing, fill with zeros and mark invalid
                        if (pkt2 == NULL || pkt2->payload_off > off + o) {
                            //printf("Copying value[%d] = 00 (missing)\n", o);
                            item->val[o] = '\x00';
                            item->is_valid = 0;
                        } else {
                            item->val[o] = pkt2->payload[off + o - pkt2->payload_off];
                            //printf("o=%d, off=%d, payload_off=%d, index=%d\n",
                            //    o, off, pkt2->payload->offset, off + o - pkt2->payload->offset);
                            //printf("Copying value[%d] = %02x\n", o, (uint8_t)item->val[o]);
                        }
                    }
                }
            // Non-extension items must be re-converted to big-endian strings
            } else {
                //printf("Item %d is not an extension\n", i);
                item->length = SPEAD_ITEM_VAL_BYTES;
                item->val = (char *) malloc(item->length * sizeof(char));
                //printf("Allocating item of length %d\n", item->length);
                if (item->val == NULL) return SPEAD_ERR;
                // Value copy here is hardcoded to big/network endian
                //((uint64_t *)item->val)[0] = htonll(rawitem->val);
                for (o=0; o < item->length; o++) {
                    // since val is in the lsbs of rawitem1, can just grab it
                    item->val[o] = 0xFF & (rawitem1 >> (8 * (SPEAD_ITEM_VAL_BYTES - o - 1))); // 8 bits per byte
                }
            }
            // Link this new item in
            if (frame->last_item == NULL) {
                frame->head_item = item;
                frame->last_item = item;
                frame->is_valid = item->is_valid;
            } else {
                frame->is_valid &= item->is_valid;
                frame->last_item->next = item;
                frame->last_item = item;
            }
        }
        pkt1 = pkt1->next;
    }
    return 0;
}
        
