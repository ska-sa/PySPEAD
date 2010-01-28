#include "include/spead_packet.h"

void spead_item_init(SpeadItem *item) {
    item->is_valid = 0;
    item->id = SPEAD_ERR;
    item->val = NULL;
    item->length = SPEAD_ERR;
    item->next = NULL;
}

void spead_item_wipe(SpeadItem *item) {
    if (item->next != NULL) {
        spead_item_wipe(item->next);
        free(item->next);
    }
    if (item->val != NULL) free(item->val);
    spead_item_init(item);  // Wipe this item clean
}
    
void spead_payload_init(SpeadPayload *pyld) {
    pyld->data = NULL;
    pyld->length = 0;
    pyld->offset = 0;
    pyld->next = NULL;
}

void spead_payload_wipe(SpeadPayload *pyld) {
    //printf("Wiping payload (%d)\n", pyld);
    if (pyld->next != NULL) {
        //printf("Wiping payload (%d) -> next (%d)\n", pyld, pyld->next);
        spead_payload_wipe(pyld->next);
        free(pyld->next);
    }
    //printf("Wiping payload (%d) freeing data (%d)\n", pyld, pyld->data);
    if (pyld->data != NULL) free(pyld->data);
    spead_payload_init(pyld);  // Wipe this payload clean
    //printf("Wiping payload (%d) done.\n", pyld);
}

void spead_packet_init(SpeadPacket *pkt) {
    pkt->frame_cnt = SPEAD_ERR;
    pkt->n_items = 0;
    pkt->raw_items = NULL;
    pkt->payload = NULL;
    pkt->next = NULL;
}

void spead_packet_wipe(SpeadPacket *pkt) {
    //printf("Wiping SpeadPacket (%d)\n", pkt);
    if (pkt->next != NULL) {
        //printf("Wiping SpeadPacket (%d) -> next (%d)\n", pkt, pkt->next);
        spead_packet_wipe(pkt->next);
        free(pkt->next);
    }
    //printf("Wiping SpeadPacket (%d) raw_items (%d)\n", pkt, pkt->raw_items);
    if (pkt->raw_items != NULL) free(pkt->raw_items);
    //printf("Wiping SpeadPacket (%d) payload (%d)\n", pkt, pkt->payload);
    if (pkt->payload != NULL) {
        spead_payload_wipe(pkt->payload);
        free(pkt->payload);
    }
    spead_packet_init(pkt); // Wipe this packet clean
}

SpeadPacket *spead_packet_clone(SpeadPacket *pkt) {
    SpeadPacket *newpkt;
    int i;
    int64_t j;
    newpkt = (SpeadPacket *)malloc(sizeof(SpeadPacket));
    if (newpkt == NULL) return NULL;
    spead_packet_init(newpkt);
    newpkt->frame_cnt = pkt->frame_cnt;
    newpkt->n_items = pkt->n_items;
    if (newpkt->n_items > 0) {
        newpkt->raw_items = (SpeadRawItem *)malloc(newpkt->n_items * sizeof(SpeadRawItem));
        if (newpkt->raw_items == NULL) return NULL;
        for (i=0; i < newpkt->n_items; i++) {
            newpkt->raw_items[i] = pkt->raw_items[i];
        }
    }
    if (pkt->payload != NULL) {
        newpkt->payload = (SpeadPayload *)malloc(sizeof(SpeadPayload));
        if (newpkt->payload == NULL) return NULL;
        spead_payload_init(newpkt->payload);
        newpkt->payload->length = pkt->payload->length;
        newpkt->payload->offset = pkt->payload->offset;
        newpkt->payload->next = NULL;
        if (newpkt->payload->length > 0) {
            newpkt->payload->data = (char *)malloc(newpkt->payload->length * sizeof(char));
            if (newpkt->payload->data == NULL) return NULL;
            for (j=0; j < newpkt->payload->length; j++) {
                newpkt->payload->data[j] = pkt->payload->data[j];
            }
        }
    }
    //printf("Cloning pkt (%d) to newpkt (%d)\n", pkt, newpkt);
    return newpkt;
}
    

void spead_frame_init(SpeadFrame *frame) {
    frame->is_valid = 0;
    frame->frame_cnt = SPEAD_ERR;
    frame->head_pkt = NULL;
    frame->last_pkt = NULL;
    frame->head_item = NULL;
    frame->last_item = NULL;
}

void spead_frame_wipe(SpeadFrame *frame) {
    if (frame->head_item != NULL) {
        spead_item_wipe(frame->head_item);
        free(frame->head_item);
    }
    // Do not touch frame->last_item b/c it was deleted by spead_item_wipe
    if (frame->head_pkt != NULL) {
        spead_packet_wipe(frame->head_pkt);
        free(frame->head_pkt);
    }
    // Do not touch frame->last_pkt b/c it was deleted by spead_packet_wipe
    spead_frame_init(frame); // Wipe this frame clean
}
    
/* Check magic values in a spead header and initialize pkt->n_items from first 8 bytes of data
 * pkt gets wiped
 * data must be at least 8 bytes long */
int64_t spead_packet_unpack_header(SpeadPacket *pkt, char *data) {
    uint64_t hdr;
    spead_packet_wipe(pkt);  // Wipe this packet in case it isn't fresh
    hdr = SPEAD_ITEM(data, 0);
    //printf("magic: 0x%x <> 0x%x\n", HDR_MAGIC(hdr), SPEAD_MAGIC);
    //printf("version: 0x%x <> 0x%x\n", HDR_VERSION(hdr), SPEAD_VERSION);
    //printf("reserved: 0x%x <> 0x%x\n", HDR_RESERVED(hdr), SPEAD_RESERVED);
    if ((SPEAD_GET_MAGIC(hdr) != SPEAD_MAGIC) || (SPEAD_GET_VERSION(hdr) != SPEAD_VERSION)) return SPEAD_ERR;
    pkt->n_items = SPEAD_GET_NITEMS(hdr);
    return SPEAD_ITEM_BYTES;  // Return # of bytes read
}
    
/* Create array of pkt->items from 8-byte entries in packet header stored in data buffer,
 * and initialize pkt->payload and pkt->frame_cnt from items.
 * pkt must have n_items already initialized (from spead_unpack_header)
 * data must be at least 8*pkt->n_items bytes long */
int64_t spead_packet_unpack_items(SpeadPacket *pkt, char *data) {
    uint64_t packed_item;
    int i;
    // Allocate memory for items and payload
    if (pkt->raw_items != NULL) free(pkt->raw_items);
    pkt->raw_items = (SpeadRawItem *) malloc(pkt->n_items * sizeof(SpeadRawItem));
    if (pkt->payload == NULL) {
        pkt->payload = (SpeadPayload *) malloc(sizeof(SpeadPayload));
        spead_payload_init(pkt->payload);
    } else {
        spead_payload_wipe(pkt->payload);
    }
    if (pkt->raw_items == NULL || pkt->payload == NULL) return SPEAD_ERR;
    // Read each raw item
    for (i=0; i < pkt->n_items; i++) {
        packed_item = SPEAD_ITEM(data,i);
        //printf("spead_unpack_items,item=%d:", i);
        //printf("%02x %02x %02x %02x %02x %02x %02x %02x ->", 
        //    0xFF & (packed_item >> 56), 0xFF & (packed_item >> 48), 0xFF & (packed_item >> 40),
        //    0xFF & (packed_item >> 32), 0xFF & (packed_item >> 24), 0xFF & (packed_item >> 16),
        //    0xFF & (packed_item >>  8), 0xFF & (packed_item >>  0));
        pkt->raw_items[i].is_ext = SPEAD_ITEM_EXT(packed_item);
        pkt->raw_items[i].id = SPEAD_ITEM_ID(packed_item);
        pkt->raw_items[i].val = SPEAD_ITEM_VAL(packed_item);
        //printf("is_ext=%d, id=%d, val=%d\n",  pkt->items[j].is_ext, pkt->items[j].id, pkt->items[j].val);
        // Check for FRAME_CNT and PAYLOAD_LENOFF (required for packet decoding)
        switch (pkt->raw_items[i].id) {
            case SPEAD_FRAME_CNT_ID:      pkt->frame_cnt       = (int64_t) pkt->raw_items[i].val; break;
            case SPEAD_PAYLOAD_OFFSET_ID: pkt->payload->offset = (int64_t) pkt->raw_items[i].val; break;
            case SPEAD_PAYLOAD_LENGTH_ID: pkt->payload->length = (int64_t) pkt->raw_items[i].val; break;
            default: break;
        }
    }
    return pkt->n_items * SPEAD_ITEM_BYTES; // Return # of bytes read
}

/* Create buffer pkt->payload and copy pkt->payload_len bytes of data into it.
 * pkt must have payload_len already initialized (from spead_unpack_items)
 * data must be at least pkt->payload_len bytes long */
int64_t spead_packet_unpack_payload(SpeadPacket *pkt, char *data) {
    int64_t i;
    if (pkt->payload == NULL) return SPEAD_ERR;
    // Read the payload (if any)
    if (pkt->payload->length > 0) {
        // Copy the payload into a new string
        if (pkt->payload->data != NULL) free(pkt->payload->data);
        pkt->payload->data = (char *) malloc(pkt->payload->length * sizeof(char));
        if (pkt->payload->data == NULL) return SPEAD_ERR;
        for (i=0; i < pkt->payload->length; i++) {
            pkt->payload->data[i] = data[i];
        }
    }
    return pkt->payload->length; // Return # of bytes read
}

int spead_frame_add_packet(SpeadFrame *frame, SpeadPacket *pkt) {
    SpeadPacket *_pkt;
    if (pkt->raw_items == NULL or pkt->payload == NULL) return SPEAD_ERR;
    if (frame->frame_cnt < 0) {  // We have a fresh frame
        frame->frame_cnt = pkt->frame_cnt;
        frame->head_pkt = pkt;
        frame->last_pkt = pkt;
    } else { // We need to insert this packet in the correct order
        if (frame->frame_cnt != pkt->frame_cnt) return SPEAD_ERR;
        _pkt = frame->head_pkt;
        // Find the right slot to insert this pkt
        while (_pkt->next != NULL && _pkt->next->payload->offset < pkt->payload->offset) {
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
    SpeadRawItem *raw_item;
    SpeadItem *item;
    int i, j, flag;
    int64_t off, o, heaplen;
    // Sanity check on frame
    if (frame->head_pkt == NULL) return 0;
    if (frame->head_item != NULL) {
        spead_item_wipe(frame->head_item);
        free(frame->head_item);
        frame->head_item = NULL;
    }
    frame->last_item = NULL;
    heaplen = frame->last_pkt->payload->offset + frame->last_pkt->payload->length;
    //printf("spead_frame_finalize: HEAPLEN=%d\n", heaplen);
    pkt1 = frame->head_pkt;
    // Loop over all items in all packets received
    while (pkt1 != NULL) {
        //printf("Processing packet\n");
        for (i=0; i < pkt1->n_items; i++) {
            raw_item = &pkt1->raw_items[i];
            switch (raw_item->id) {
                case SPEAD_FRAME_CNT_ID: 
                case SPEAD_PAYLOAD_OFFSET_ID:
                case SPEAD_PAYLOAD_LENGTH_ID:
                    continue;
                default: break;
            }
            //printf("Processing item %d: EXT=%d, ID=%d, VAL=%d\n", i, raw_item->is_ext, raw_item->id, raw_item->val);
            item = (SpeadItem *) malloc(sizeof(SpeadItem));
            if (item == NULL) return SPEAD_ERR;
            spead_item_init(item);
            item->is_valid = 1;
            item->id = raw_item->id;
            // Extension items must be retrieved from the packet payloads
            if (raw_item->is_ext) {
                off = (int64_t) raw_item->val;
                // Figure out length of item by defaulting to remaining heap, then looping over 
                // remaining raw_items (in all remaining of packets) to find start of next
                // extension item.
                item->length = heaplen - off;
                flag = 0;  // Used to tell when we've found next extension item to break out
                pkt2 = pkt1; j = i+1;  // Start with the next raw_item in this packet
                do {
                    for (; j < pkt2->n_items; j++) {
                        if (pkt2->raw_items[j].is_ext) {
                            item->length = (int64_t) pkt2->raw_items[j].val - off;
                            flag = 1;
                            break;
                        }
                    }
                    if (flag) break;
                    pkt2 = pkt2->next; j = 0;  // Move on to first raw_item in next packet
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
                        while (pkt2 != NULL && (pkt2->payload->offset + pkt2->payload->length <= off + o)) {
                            //printf("Moving to next packet\n");
                            pkt2 = pkt2->next;
                        }
                        // If packet with relevant data is missing, fill with zeros and mark invalid
                        if (pkt2 == NULL || pkt2->payload->offset > off + o) {
                            //printf("Copying value[%d] = 00 (missing)\n", o);
                            item->val[o] = '\x00';
                            item->is_valid = 0;
                        } else {
                            item->val[o] = pkt2->payload->data[off + o - pkt2->payload->offset];
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
                //((uint64_t *)item->val)[0] = htonll(raw_item->val);
                for (o=0; o < item->length; o++) {
                    item->val[o] = 0xFF & (raw_item->val >> 8*(SPEAD_ITEM_VAL_BYTES - o - 1));
                }
                //printf("id=%d val=%d, raw_val=%d\n", raw_item->id, ((uint64_t *)item->val)[0], raw_item->val);
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
        
