#include "include/ring_buffer.h"

int ring_buffer_init(RingBuffer *rb, size_t item_count) {
	// create list items
	RingItem *head_item = (RingItem *)malloc(item_count * sizeof(RingItem));
	int i;
    if (head_item == NULL) return -1;
	for(i=0; i < item_count; i++) {
		RingItem *this_item = &head_item[i];
		RingItem *next_item = &head_item[(i + 1) % item_count];
		this_item->next = next_item;
		pthread_mutex_init(&this_item->write_mutex, NULL);
		pthread_mutex_init(&this_item->read_mutex, NULL);
		//pthread_mutex_lock(&this_item->read_mutex); // On startup, no read mutex's should be available
        spead_packet_init(&this_item->pkt);
	}
	rb->list_ptr = head_item;
	rb->list_length = item_count;
	rb->write_ptr = head_item;
	rb->read_ptr = head_item;
    ring_buffer_set_all_mutex(rb, 1, 0);  // On startup, no read_mutex should be available
	return 0;
}

void ring_buffer_set_all_mutex(RingBuffer *rb, int rd_lock, int wr_lock) {
    RingItem *head_item = rb->list_ptr;
    size_t item_count = rb->list_length;
    int i;
    for (i=0; i < item_count; i++) {
        if (rd_lock) {
            //printf("ring_buffer_set_all_mutex: locking read in slot %d\n", i);
            pthread_mutex_lock(&head_item[i].read_mutex);
        } else {
            //printf("ring_buffer_set_all_mutex: unlocking read in slot %d\n", i);
            pthread_mutex_unlock(&head_item[i].read_mutex);
        }
        if (wr_lock) {
            //printf("ring_buffer_set_all_mutex: locking write in slot %d\n", i);
            pthread_mutex_lock(&head_item[i].write_mutex);
        } else {
            //printf("ring_buffer_set_all_mutex: unlocking write in slot %d\n", i);
            pthread_mutex_unlock(&head_item[i].write_mutex);
        }
    }
}

void ring_buffer_wipe(RingBuffer *rb) {
	// delete list items
	RingItem *head_item = rb->list_ptr;
	size_t item_count = rb->list_length;
	int i;
    //printf("Wiping RingBuffer (%d)\n", rb);
	for(i=0; i<item_count; i++) {
        //printf("ring_buffer_wipe: Wiping RingBuffer (%d) item[%d]\n", rb, i);
		RingItem *this_item = &head_item[i];
        //printf("ring_buffer_wipe: destroying write_mutex\n");
		pthread_mutex_destroy(&this_item->write_mutex);
        //printf("ring_buffer_wipe: destroying read_mutex\n");
		pthread_mutex_destroy(&this_item->read_mutex);
        //printf("Wiping RingBuffer (%d) item[%d] -> pkt (%d)\n", rb, i, &this_item->pkt);
        spead_packet_wipe(&this_item->pkt);
        //printf("Wiping RingBuffer (%d) item[%d] -> freeing pkt (%d)\n", rb, i, &this_item->pkt);
        //free(&this_item->pkt);
	}
    //printf("Wiping RingBuffer (%d) freeing head_item (%d)\n", rb, head_item);
	free(head_item);
    rb->list_ptr = NULL;
}

