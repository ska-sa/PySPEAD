#include "include/buffer_socket.h"

int default_callback(SpeadPacket *pkt, void *userdata) {
    printf("    Readout packet with frame_cnt=%d, n_items=%d, payload_len=%d, payload_cnt=%d\n", 
            pkt->frame_cnt, pkt->n_items, pkt->payload_len, pkt->payload_cnt);
    return 0;
}

void init_buffer_socket(BufferSocket *bs, size_t item_count) {
    // Initialize a BufferSocket
    bs->buf = ring_buffer_create(item_count);
    set_callback(bs, &default_callback);
    bs->run_threads = 0;
    bs->userdata = NULL;
}

void free_buffer_socket(BufferSocket *bs) {
    // Free all memory allocated for a BufferSocket
    stop(bs);
    if (bs->buf) ring_buffer_delete(bs->buf);
}

void set_callback(BufferSocket *bs, int (*cb_func)(SpeadPacket *, void *)) {
    /* Set a callback function for handling data out of ring buffer */
    bs->callback = cb_func;
}

int start(BufferSocket *bs, int port) {
    /* Start socket => buffer and buffer => callback threads */
    if (bs->run_threads != 0) {
        fprintf(stderr, "BufferSocket already running.\n");
        return 1;
    }
    bs->port = port;
    bs->run_threads = 1;
    pthread_create(&bs->net_thread, NULL, net_thread_function, bs);
    pthread_create(&bs->data_thread, NULL, data_thread_function, bs);
    return 0;
}

int stop(BufferSocket *bs) {
    /* Send halt signal for net/data threads, then join them */
    if (!bs->run_threads) return 1;
    bs->run_threads = 0;
    pthread_join(bs->net_thread, NULL);
    pthread_join(bs->data_thread, NULL);
    return 0;
}
    

void *data_thread_function(void *arg) {
    /* This thread reads data out of a ring buffer through a callback */
    BufferSocket *bs = (BufferSocket *)arg;
    RING_ITEM *this_slot;
    struct timespec ts;
    int i;

    while (bs->run_threads) {
        this_slot = bs->buf->read_ptr;
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            fprintf(stderr, "Data: clock_gettime returned nonzero.\n");
            bs->run_threads = 0;
            continue;
        }
        ts.tv_nsec += 10000000;     // 10 ms
        // Wait for next buffer slot to fill up
        if (sem_timedwait(&this_slot->read_mutex, &ts) == -1) continue;
         //printf("Reading in a packet: size=%d slot=%d\n", this_slot->size, this_slot - bs->buf->list_ptr);
        // Feed data from buffer slot to callback function
        // The callback steals the reference to pkt, and should free its memory when done

        // Check if this packet has STREAM_CTRL set to STREAM_CTRL_VAL_TERM
        for (i=0; i < this_slot->pkt.n_items; i++) {
            if (this_slot->pkt.items[i].id == SPEAD_STREAM_CTRL_ID &&
                    this_slot->pkt.items[i].val == SPEAD_STREAM_CTRL_TERM_VAL)
                bs->run_threads = 0;
        }

        // Send packet to callback (even if it's a STREAM_CTRL TERM packet)
        if (bs->callback(&this_slot->pkt, bs->userdata) != 0) {
            fprintf(stderr, "Data: Callback returned nonzero.\n");
            bs->run_threads = 0;
        } else {
            // Release this slot for writing
            spead_free_packet(&this_slot->pkt);
            sem_post(&this_slot->write_mutex);
            bs->buf->read_ptr = this_slot->next;
        }
    }
    return NULL;
}

void *net_thread_function(void *arg) {
    /* This thread puts data into a ring buffer from a socket*/
    BufferSocket *bs = (BufferSocket *)arg;
    RING_ITEM *this_slot;

    socket_t sock = setup_network_listener((short) bs->port);
    //SA_in addr; // packet source's address
    //socklen_t addr_len = sizeof(addr);
    ssize_t num_bytes=0, bufoff=0;
    int is_ready;
    fd_set readset;
    struct timeval tv;
    struct timespec ts;

    char buf[SPEAD_MAX_PACKET_SIZE];
    int i;

    // If sock open fails, end all threads
    if (sock == -1) {
        fprintf(stderr, "Unable to open socket.\n");
        bs->run_threads = 0;
        return NULL;
    }

    while (bs->run_threads) {
        this_slot = bs->buf->write_ptr;
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            fprintf(stderr, "Net: clock_gettime returned nonzero.\n");
            bs->run_threads = 0;
            continue;
        }
        ts.tv_nsec += 10000000;     // 10 ms
        // Wait for next buffer slot to open up for writing
        if (sem_timedwait(&this_slot->write_mutex, &ts) == -1) continue;
        
        // Poll until socket has data
        while (bs->run_threads) {
            //printf("RX: Starting over\n");
            FD_ZERO(&readset);
            FD_SET(sock, &readset);
            tv.tv_sec = 0; tv.tv_usec = 10000;      // 10 ms
            is_ready = select(sock + 1, &readset, NULL, NULL, &tv);
            // Start creating packet from incoming data
            if (is_ready > 0) {
                //printf("RX: Reading data: bufoff=%d\n", bufoff);
                num_bytes = recv(sock, buf+bufoff, SPEAD_MAX_PACKET_SIZE, 0) + bufoff;
                //for (i=0;i<num_bytes;i++) {
                //    if (i % 8 == 0) printf("\n");
                //    printf("%02x ", (uint8_t)buf[i]);
                //}
                //printf("\n");
                if (num_bytes >= SPEAD_ITEM_BYTES) {
                    i = spead_unpack_hdr(&this_slot->pkt, buf);
                    if (num_bytes >= i + this_slot->pkt.n_items * SPEAD_ITEM_BYTES) {
                        i += spead_unpack_items(&this_slot->pkt, buf + i);
                        if (num_bytes >= i + this_slot->pkt.payload_len) {
                            i += spead_unpack_payload(&this_slot->pkt, buf + i);
                            // If there are leftovers (we read part of the next packet) copy them to the
                            // front of buf and set bufoff
                            //printf("RX: finished reading packet, %d/%d\n", i, num_bytes);
                            for (bufoff=0; bufoff < num_bytes - i; bufoff++) {
                                buf[bufoff] = buf[i+bufoff];
                            }
                            break;
                        }
                    }
                    bufoff = 0;  // bufoff is reset whenever there are enough data for a packet, but no match
                }
            } else if (is_ready < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "Unable to receive packets.\n");
                bs->run_threads = 0;
            }
        }
        // Mark this slot ready for readout if we broke out of loop (not if run_threads went down)
        if (bs->run_threads) {
            //printf("RX: Posting packet\n");
            sem_post(&this_slot->read_mutex);
            bs->buf->write_ptr = this_slot->next;
        }
    }
    close(sock);
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
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
            (void *)&on, sizeof(on)) == -1) return -1;

    return sock;
}
