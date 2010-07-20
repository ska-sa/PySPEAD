#ifndef BUFFER_SOCKET_H
#define BUFFER_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include "spead_packet.h"

/*___  _             ____         __  __           
|  _ \(_)_ __   __ _| __ ) _   _ / _|/ _| ___ _ __ 
| |_) | | '_ \ / _` |  _ \| | | | |_| |_ / _ \ '__|
|  _ <| | | | | (_| | |_) | |_| |  _|  _|  __/ |   
|_| \_\_|_| |_|\__, |____/ \__,_|_| |_|  \___|_|   
               |___/                               */

struct ring_item {
	pthread_mutex_t write_mutex;
	pthread_mutex_t read_mutex;
	SpeadPacket *pkt;
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

/*___         __  __           ____             _        _   
| __ ) _   _ / _|/ _| ___ _ __/ ___|  ___   ___| | _____| |_ 
|  _ \| | | | |_| |_ / _ \ '__\___ \ / _ \ / __| |/ / _ \ __|
| |_) | |_| |  _|  _|  __/ |   ___) | (_) | (__|   <  __/ |_ 
|____/ \__,_|_| |_|  \___|_|  |____/ \___/ \___|_|\_\___|\__|*/

typedef int socket_t;
typedef struct sockaddr_in SA_in;
typedef struct sockaddr SA;

typedef struct {
    RingBuffer *ringbuf;
    pthread_t net_thread, data_thread;
    int (*callback)(SpeadPacket *, void *);
    int run_threads;
    int port;
    int buffer_size;
    void *userdata;
} BufferSocket;

int default_callback(SpeadPacket *pkt, void *userdata);
void buffer_socket_init(BufferSocket *, size_t item_count);
void buffer_socket_wipe(BufferSocket *);
void buffer_socket_set_callback(BufferSocket *, int (*cb_func)(SpeadPacket *, void *));
int buffer_socket_start(BufferSocket *bs, int port, int buffer_size);
int buffer_socket_stop(BufferSocket *bs);
void *buffer_socket_net_thread(void *arg);
void *buffer_socket_data_thread(void *arg);
socket_t buffer_socket_setup_socket(short port, int buffer_size);

#endif
