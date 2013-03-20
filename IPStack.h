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
#include <string> 
#include <stdio.h>

#define PROT_OTHER 0

void addrToString(u_char *ptr, char *buf);
u_short tcp_checksum(unsigned short len_tcp, unsigned short src_addr[], unsigned short dest_addr[], struct sniff_tcp* tcp, u_char *payload, int size);



// Higher Layers

typedef u_char* Payload;


//Application protocol

class NetApp {
public:

    // Need both because we are reading both data sent and received
    virtual void serverPayload(Payload payload){}
    virtual void clientPayload(Payload payload){}
};

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
    uint32_t seq;
    uint32_t ack;
    int ack_complete;
    std::string pload;
    struct in_addr ipaddr;
    bool operator<(const TCP &rhs) const { return seq < rhs.seq; }

};

class UDP : public TransportProtocol {
};

class Packet {
public:

    Packet() {
        ;
    }
    
    virtual ~Packet();

    //has layer 1
    sniff_ip *ip;
    sniff_ethernet *ethernet;

    u_short transport_type;
    TransportProtocol *transport;

    u_int ip_size;

    void PrintPacket();
};


#endif	/* TRANSPORTPROTOCOL_H */

