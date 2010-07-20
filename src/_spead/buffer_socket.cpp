#include "include/buffer_socket.h"

#define DEBUG   0
#define DBGPRINTF  if (DEBUG) printf

/*___  _             ____         __  __           
|  _ \(_)_ __   __ _| __ ) _   _ / _|/ _| ___ _ __ 
| |_) | | '_ \ / _` |  _ \| | | | |_| |_ / _ \ '__|
|  _ <| | | | | (_| | |_) | |_| |  _|  _|  __/ |   
|_| \_\_|_| |_|\__, |____/ \__,_|_| |_|  \___|_|   
               |___/                               */

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
		pthread_mutex_lock(&this_item->read_mutex); // On startup, no read mutex should be available
        this_item->pkt = NULL;
	}
	rb->list_ptr = head_item;
	rb->list_length = item_count;
	rb->write_ptr = head_item;
	rb->read_ptr = head_item;
	return 0;
}

void ring_buffer_wipe(RingBuffer *rb) {
	RingItem *head_item = rb->list_ptr;
	size_t item_count = rb->list_length;
	int i;
	for(i=0; i<item_count; i++) {
		RingItem *this_item = &head_item[i];
		pthread_mutex_destroy(&this_item->write_mutex);
		pthread_mutex_destroy(&this_item->read_mutex);
        if (this_item->pkt != NULL) free(this_item->pkt);
	}
	free(head_item);
    rb->list_ptr = NULL;
}

/*___         __  __           ____             _        _   
| __ ) _   _ / _|/ _| ___ _ __/ ___|  ___   ___| | _____| |_ 
|  _ \| | | | |_| |_ / _ \ '__\___ \ / _ \ / __| |/ / _ \ __|
| |_) | |_| |  _|  _|  __/ |   ___) | (_) | (__|   <  __/ |_ 
|____/ \__,_|_| |_|  \___|_|  |____/ \___/ \___|_|\_\___|\__|*/

int default_callback(SpeadPacket *pkt, void *userdata) {
    printf("    Readout packet: heap_cnt=%d, n_items=%d, payload_len=%d\n, payload_off=%d\n", 
            pkt->heap_cnt, pkt->n_items, pkt->payload_len, pkt->payload_off);
    free(pkt);
    return 0;
}

void buffer_socket_init(BufferSocket *bs, size_t item_count) {
    // Initialize a BufferSocket
    bs->ringbuf = (RingBuffer *) malloc(sizeof(RingBuffer));
    ring_buffer_init(bs->ringbuf, item_count);
    buffer_socket_set_callback(bs, &default_callback);
    DBGPRINTF("buffer_socket_init: Setting bs->run_threads to 0\n");
    bs->run_threads = 0;
    bs->userdata = NULL;
}

void buffer_socket_wipe(BufferSocket *bs) {
    // Free all memory allocated for a BufferSocket
    buffer_socket_stop(bs);
    if (bs->ringbuf != NULL) {
        ring_buffer_wipe(bs->ringbuf);
        free(bs->ringbuf);
    }
}

void buffer_socket_set_callback(BufferSocket *bs, int (*cb_func)(SpeadPacket *, void *)) {
    /* Set a callback function for handling data out of ring buffer */
    bs->callback = cb_func;
}

int buffer_socket_start(BufferSocket *bs, int port, int buffer_size) {
    /* Start socket => buffer and buffer => callback threads */
    if (bs->run_threads != 0) {
        fprintf(stderr, "buffer_socket_start: BufferSocket already running.\n");
        return -1;
    }
    bs->port = port;
    bs->buffer_size = buffer_size;
    DBGPRINTF("buffer_socket_start: Setting bs->run_threads to 1\n");
    bs->run_threads = 1;
    pthread_create(&bs->net_thread, NULL, buffer_socket_net_thread, bs);
    pthread_create(&bs->data_thread, NULL, buffer_socket_data_thread, bs);
    return 0;
}

int buffer_socket_stop(BufferSocket *bs) {
    /* Send halt signal for net/data threads, then join them */
    DBGPRINTF("buffer_socket_stop: Called with bs->run_threads=%d\n", bs->run_threads);
    if (!bs->run_threads) return -1;
    DBGPRINTF("buffer_socket_stop: Setting bs->run_threads to 0\n");
    bs->run_threads = 0;
    DBGPRINTF("buffer_socket_stop: Joining net_thread\n");
    pthread_join(bs->net_thread, NULL);
    DBGPRINTF("buffer_socket_stop: Joining data_thread\n");
    pthread_join(bs->data_thread, NULL);
    DBGPRINTF("buffer_socket_stop: Done.\n");
    return 0;
}
    

void *buffer_socket_data_thread(void *arg) {
    /* This thread reads data out of a ring buffer through a callback */
    BufferSocket *bs = (BufferSocket *)arg;
    RingItem *this_slot;
    int gotterm=0;

    while (bs->run_threads) {
        // Wait for next buffer slot to fill up
        if (pthread_mutex_trylock(&bs->ringbuf->read_ptr->read_mutex) != 0) {
            usleep(10000);
            continue;
        }
        this_slot = bs->ringbuf->read_ptr;
        DBGPRINTF("buffer_socket_data_thread: Got read_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        // Check if this packet has STREAM_CTRL set to STREAM_CTRL_VAL_TERM
        DBGPRINTF("buffer_socket_data_thread: Checking for TERM in slot %d\n", this_slot - bs->ringbuf->list_ptr);
        if (spead_packet_unpack_header(this_slot->pkt) != SPEAD_ERR && spead_packet_unpack_items(this_slot->pkt) != SPEAD_ERR) {
            gotterm = this_slot->pkt->is_stream_ctrl_term;
            // Feed data from buffer slot to callback function
            // The callback steals the reference to pkt, and should free its memory when done
            // Send packet to callback (even if it's a STREAM_CTRL TERM packet)
            // Check run_threads first b/c otherwise existence of callback is not guaranteed
            DBGPRINTF("buffer_socket_data_thread: Entering callback for slot %d (if %d = 1)\n", this_slot - bs->ringbuf->list_ptr, bs->run_threads);
            if (bs->run_threads && bs->callback(this_slot->pkt, bs->userdata) != 0) { 
                fprintf(stderr, "buffer_socket_data_thread: Callback returned nonzero.\n");
                bs->run_threads = 0;
            } 
            if (gotterm) bs->run_threads = 0;
        } else {
            DBGPRINTF("buffer_socket_data_thread: Got invalid packet in slot %d\n", this_slot - bs->ringbuf->list_ptr);
            free(this_slot->pkt);
        }
            
        // At this point this_slot->pkt is an invalid reference
        this_slot->pkt = NULL;
        DBGPRINTF("buffer_socket_data_thread: Releasing write_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        bs->ringbuf->read_ptr = this_slot->next;
        pthread_mutex_unlock(&this_slot->write_mutex);
        DBGPRINTF("buffer_socket_data_thread: Looping with bs->run_threads=%d\n", bs->run_threads);
    }
    DBGPRINTF("buffer_socket_data_thread: Leaving thread\n");
    return NULL;
}

void *buffer_socket_net_thread(void *arg) {
    /* This thread puts data into a ring buffer from a socket*/
    BufferSocket *bs = (BufferSocket *)arg;
    RingItem *this_slot;
    SpeadPacket *pkt;

    socket_t sock = buffer_socket_setup_socket((short) bs->port, (int) bs->buffer_size);
    ssize_t num_bytes=0;
    int is_ready;
    fd_set readset;
    struct timeval tv;

    // If sock open fails, end all threads
    if (sock == -1) {
        fprintf(stderr, "buffer_socket_net_thread: Unable to open socket\n");
        bs->run_threads = 0;
        return NULL;
    }

    while (bs->run_threads) {
        // Poll socket until we have some data to write
        FD_ZERO(&readset);
        FD_SET(sock, &readset);
        tv.tv_sec = 0; tv.tv_usec = 50000;      // 10 ms
        is_ready = select(sock + 1, &readset, NULL, NULL, &tv);
        if (is_ready <= 0) {
            if (is_ready != 0 && errno != EINTR) {
                fprintf(stderr, "Unable to receive packets.\n");
                bs->run_threads = 0;
            }
            continue;
        }
        // Wait for next buffer slot to open up for writing
        DBGPRINTF("buffer_socket_net_thread: Waiting for write_mutex on slot %d\n", bs->ringbuf->write_ptr - bs->ringbuf->list_ptr);
        pthread_mutex_lock(&bs->ringbuf->write_ptr->write_mutex);
        this_slot = bs->ringbuf->write_ptr;
        //if (pthread_mutex_trylock(&this_slot->write_mutex) != 0) continue;
        DBGPRINTF("buffer_socket_net_thread: Got write_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        
        // For UDP, recvfrom returns exactly one packet
        pkt = (SpeadPacket *) malloc(sizeof(SpeadPacket));
        if (pkt == NULL) {
            fprintf(stderr, "buffer_socket_net_thread: Unable to allocate memory for packet\n");
            bs->run_threads = 0;
            return NULL;
        }
        spead_packet_init(pkt);
        num_bytes = recvfrom(sock, pkt->data, SPEAD_MAX_PACKET_LEN, 0, NULL, NULL);
        DBGPRINTF("buffer_socket_net_thread: Received %d bytes\n", num_bytes);
        DBGPRINTF("buffer_socket_net_thread: Releasing read_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        this_slot->pkt = pkt;
        bs->ringbuf->write_ptr = this_slot->next;
        pthread_mutex_unlock(&this_slot->read_mutex);
        DBGPRINTF("buffer_socket_net_thread: Looping with bs->run_threads=%d\n", bs->run_threads);
    }
    close(sock);
    DBGPRINTF("buffer_socket_net_thread: Leaving thread\n");
    return NULL;
}

socket_t buffer_socket_setup_socket(short port, int buffer_size) {
    /* Open up a UDP socket on the specified port for receiving data */
    int result, sock = -1;
    struct sockaddr_in my_addr; // server's address information
    sock = socket(PF_INET, SOCK_DGRAM, 0); // create a new UDP socket descriptor
    if (sock == -1) return -1;
    // initialize local address struct
    my_addr.sin_family = AF_INET; // host byte order
    my_addr.sin_port = htons(port); // short, network byte order
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY); // listen on all interfaces
    memset(my_addr.sin_zero, 0, sizeof(my_addr.sin_zero));
    // bind socket to local address
    if (bind(sock, (SA *)&my_addr, sizeof(my_addr)) == -1) return -1;
    // prevent "address already in use" errors
    const int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1) return -1;
    if (buffer_size > 0) {
     result = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
     if(result < 0) {
      #ifdef SO_RCVBUFFORCE
      result = setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &buffer_size, sizeof(buffer_size));
      if(result < 0){
      #endif
      fprintf(stderr, "warning unable to set receive buffer size to %d: %s\n", buffer_size, strerror(errno));
      #ifdef SO_RCVBUFFORCE
      }
      #endif
     }
    } // end of if buffer size to be set
    return sock;
}
