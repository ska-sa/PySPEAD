#include "include/ring_buffer.h"

/* Construct and initialize a RING_BUFFER.  */
RING_BUFFER *ring_buffer_create(size_t item_count) {
	// create list items
	RING_ITEM *head_item = (RING_ITEM *)malloc(item_count * sizeof(RING_ITEM));
	int i;
    if (head_item == NULL) return NULL;
	for(i=0; i < item_count; i++) {
		RING_ITEM *this_item = &head_item[i];
		RING_ITEM *next_item = &head_item[(i + 1) % item_count];
		this_item->next = next_item;
		sem_init(&this_item->write_mutex, 0, 1);
		sem_init(&this_item->read_mutex, 0, 0);
        spead_init_packet(&this_item->pkt);
	}
	// create ring buffer
	RING_BUFFER *rb = (RING_BUFFER *)malloc(sizeof(RING_BUFFER));
    if (rb == NULL) return NULL;
	rb->list_ptr = head_item;
	rb->list_length = item_count;
	rb->write_ptr = head_item;
	rb->read_ptr = head_item;
	return rb;
}

/* Destroy a RING_BUFFER and free its memory.  */
void ring_buffer_delete(RING_BUFFER *rb) {
	// delete list items
	RING_ITEM *head_item = rb->list_ptr;
	size_t item_count = rb->list_length;
	int i;
	for(i=0; i<item_count; i++) {
		RING_ITEM *this_item = &head_item[i];
		sem_destroy(&this_item->write_mutex);
		sem_destroy(&this_item->read_mutex);
        spead_free_packet(&this_item->pkt);
	}
	free(head_item);
	free(rb);
}

