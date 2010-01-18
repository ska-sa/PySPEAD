#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

#include <netdb.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include "spead_packet.h"

//Objects

typedef struct ring_item {
	struct ring_item *next;
	sem_t write_mutex;
	sem_t read_mutex;
	SpeadPacket pkt;
} RING_ITEM;

typedef struct ring_buffer {
	//SpeadPacket *pktbuf_ptr;
	//size_t pktbuf_size;

	struct ring_item *list_ptr;
	size_t list_length;

	struct ring_item *write_ptr;
	struct ring_item *read_ptr;
} RING_BUFFER;

RING_BUFFER *ring_buffer_create(size_t item_count);
void ring_buffer_delete(RING_BUFFER *rb);

#endif // _RING_BUFFER_H_
