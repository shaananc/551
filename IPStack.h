/* 
 * File:   TransportProtocol.h
 * Author: user
 *
 * Created on March 8, 2013, 7:05 PM
 */

#ifndef IPSTACK_H
#define	IPSTACK_H

#include "pktstruct.h"
#include <arpa/inet.h>

#define PROT_OTHER 0

void addrToString(u_char *ptr, char *buf);
u_short tcp_checksum(unsigned short len_tcp, unsigned short src_addr[], unsigned short dest_addr[], struct sniff_tcp* tcp, u_char *payload, int size);



// Higher Layers

typedef u_char* Payload;


// Layer 4

class TransportProtocol {
public:
    int header_size;
    int source_port;
    int dest_port;
    int payload_size;
    Payload payload;
};

class TCP : public TransportProtocol {
public:

    TCP() {
        ;
    }

    bool valid_checksum;
    int checksum;
    u_char flags;
    tcp_seq seq;
    tcp_seq ack;
	int ack_complete;

};

class UDP : public TransportProtocol {
};

class Packet {
public:

    Packet() {
        ;
    }

    //has layer 1
    sniff_ip *ip;
    sniff_ethernet *ethernet;

    u_short transport_type;
    TransportProtocol *transport;

    u_int ip_size;

    void PrintPacket();
};


#endif	/* TRANSPORTPROTOCOL_H */

