#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

//#include <netdb.h>
#include <pthread.h>
//#include <stdlib.h>
//#include <string.h>
#include "spead_packet.h"

//Objects

struct ring_item {
	pthread_mutex_t write_mutex;
	pthread_mutex_t read_mutex;
	SpeadPacket pkt;
	struct ring_item *next;
};
typedef struct ring_item RingItem;

typedef struct {
	RingItem *list_ptr;
	size_t list_length;

	RingItem *write_ptr;
	RingItem *read_ptr;
} RingBuffer;

int ring_buffer_init(RingBuffer *rb, size_t item_count);
void ring_buffer_wipe(RingBuffer *rb);
void ring_buffer_set_all_mutex(RingBuffer *rb, int rd_lock, int wr_lock);

#endif // _RING_BUFFER_H_
