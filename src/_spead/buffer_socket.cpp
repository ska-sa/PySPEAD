#include "include/buffer_socket.h"

#define DEBUG   0
#define DBGPRINTF  if (DEBUG) printf

int default_callback(SpeadPacket *pkt, void *userdata) {
    if (pkt->payload == NULL) return SPEAD_ERR;
    printf("    Readout packet with frame_cnt=%d, n_items=%d, payload_len=%d\n", 
            pkt->frame_cnt, pkt->n_items, pkt->payload->length);
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

int buffer_socket_start(BufferSocket *bs, int port) {
    /* Start socket => buffer and buffer => callback threads */
    if (bs->run_threads != 0) {
        fprintf(stderr, "BufferSocket already running.\n");
        return -1;
    }
    bs->port = port;
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
    //ring_buffer_set_all_mutex(bs->ringbuf, 0, 0);
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
    int i, gotterm=0;

    while (bs->run_threads) {
        // Wait for next buffer slot to fill up
        if (pthread_mutex_trylock(&bs->ringbuf->read_ptr->read_mutex) != 0) continue;
        this_slot = bs->ringbuf->read_ptr;
        DBGPRINTF("buffer_socket_data_thread: Got read_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        // Check if this packet has STREAM_CTRL set to STREAM_CTRL_VAL_TERM
        DBGPRINTF("buffer_socket_data_thread: Checking for TERM in slot %d\n", this_slot - bs->ringbuf->list_ptr);
        for (i=0; i < this_slot->pkt.n_items; i++) {
            DBGPRINTF("buffer_socket_data_thread: slot %d => item[%d], id=%d, val=%d\n", this_slot - bs->ringbuf->list_ptr, i, this_slot->pkt.raw_items[i].id, this_slot->pkt.raw_items[i].val);
            if (this_slot->pkt.raw_items[i].id == SPEAD_STREAM_CTRL_ID &&
                    this_slot->pkt.raw_items[i].val == SPEAD_STREAM_CTRL_TERM_VAL) {
                DBGPRINTF("buffer_socket_data_thread: Found TERM in slot %d\n", this_slot - bs->ringbuf->list_ptr);
                gotterm = 1;
                break;
            }
        }
        // Feed data from buffer slot to callback function
        // The callback steals the reference to pkt, and should free its memory when done
        // Send packet to callback (even if it's a STREAM_CTRL TERM packet)
        // Check run_threads first b/c otherwise existence of callback is not guaranteed
        DBGPRINTF("buffer_socket_data_thread: Entering callback for slot %d (if %d = 1)\n", this_slot - bs->ringbuf->list_ptr, bs->run_threads);
        if (bs->run_threads && bs->callback(&this_slot->pkt, bs->userdata) != 0) { 
            fprintf(stderr, "Data: Callback returned nonzero.\n");
            bs->run_threads = 0;
        } 
        spead_packet_wipe(&this_slot->pkt);
        DBGPRINTF("buffer_socket_data_thread: Releasing write_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        bs->ringbuf->read_ptr = this_slot->next;
        pthread_mutex_unlock(&this_slot->write_mutex);
        if (gotterm) bs->run_threads = 0;
        DBGPRINTF("buffer_socket_data_thread: Looping with bs->run_threads=%d\n", bs->run_threads);
    }
    DBGPRINTF("buffer_socket_data_thread: Leaving thread\n");
    return NULL;
}

void *buffer_socket_net_thread(void *arg) {
    /* This thread puts data into a ring buffer from a socket*/
    BufferSocket *bs = (BufferSocket *)arg;
    RingItem *this_slot;

    socket_t sock = setup_network_listener((short) bs->port);
    ssize_t num_bytes=0;
    int is_ready;
    fd_set readset;
    struct timeval tv;

    char buf[SPEAD_MAX_PACKET_SIZE];
    int i, j;

    // If sock open fails, end all threads
    if (sock == -1) {
        fprintf(stderr, "Unable to open socket.\n");
        bs->run_threads = 0;
        return NULL;
    }

    while (bs->run_threads) {
        // Poll socket until we have some data to write
        FD_ZERO(&readset);
        FD_SET(sock, &readset);
        tv.tv_sec = 0; tv.tv_usec = 10000;      // 10 ms
        is_ready = select(sock + 1, &readset, NULL, NULL, &tv);
        if (is_ready <= 0) {
            if (is_ready != 0 && errno != EINTR) {
                fprintf(stderr, "Unable to receive packets.\n");
                DBGPRINTF("Unable to receive packets.\n");
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
        num_bytes = recvfrom(sock, buf, SPEAD_MAX_PACKET_SIZE, 0, NULL, NULL);
        DBGPRINTF("buffer_socket_net_thread: Received %d bytes\n", num_bytes);
        //for (i=0;i<num_bytes;i++) {
        //    if (i % 8 == 0) DBGPRINTF("\n");
        //    DBGPRINTF("%02x ", (uint8_t)buf[i]);
        //}
        //DBGPRINTF("\n");
        if (num_bytes < SPEAD_ITEM_BYTES) continue;
        i = spead_packet_unpack_header(&this_slot->pkt, buf);
        if (i == SPEAD_ERR || num_bytes < i + this_slot->pkt.n_items * SPEAD_ITEM_BYTES) continue;
        j = spead_packet_unpack_items(&this_slot->pkt, buf + i);
        i += j;
        if (j == SPEAD_ERR || num_bytes < i + this_slot->pkt.payload->length) continue;
        spead_packet_unpack_payload(&this_slot->pkt, buf + i);
        DBGPRINTF("buffer_socket_net_thread: Releasing read_mutex for slot %d\n", this_slot - bs->ringbuf->list_ptr);
        bs->ringbuf->write_ptr = this_slot->next;
        pthread_mutex_unlock(&this_slot->read_mutex);
        DBGPRINTF("buffer_socket_net_thread: Looping with bs->run_threads=%d\n", bs->run_threads);
    }
    close(sock);
    DBGPRINTF("buffer_socket_net_thread: Leaving thread\n");
    return NULL;
}

socket_t setup_network_listener(short port) {
    /* Open up a UDP socket on the specified port for receiving data */
    int sock = -1;
    struct sockaddr_in my_addr; // server's address information

    // create a new UDP socket descriptor
    sock = socket(PF_INET, SOCK_DGRAM, 0);
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

    return sock;
}
