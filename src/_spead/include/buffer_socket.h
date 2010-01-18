#ifndef BUFFER_SOCKET_H
#define BUFFER_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <signal.h>

#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "spead_packet.h"
#include "ring_buffer.h"

typedef int socket_t;
typedef struct sockaddr_in SA_in;
typedef struct sockaddr SA;

typedef struct {
    RING_BUFFER *buf;
    pthread_t net_thread, data_thread;
    int (*callback)(SpeadPacket *, void *);
    int run_threads;
    int port;
    void *userdata;
} BufferSocket;

int default_callback(SpeadPacket *pkt, void *userdata);
void init_buffer_socket(BufferSocket *, size_t item_count);
void free_buffer_socket(BufferSocket *);
void set_callback(BufferSocket *, int (*cb_func)(SpeadPacket *, void *));
int start(BufferSocket *bs, int port);
int stop(BufferSocket *bs);
void *net_thread_function(void *arg);
void *data_thread_function(void *arg);
socket_t setup_network_listener(short port);

#endif
