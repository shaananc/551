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

};

class UDP : public TransportProtocol {
};


class Packet {
public:
    //has layer 1
    sniff_ip *ip;
    sniff_ethernet *ethernet;

    u_short transport_type;
    TransportProtocol *transport;

    u_int ip_size;

    void PrintPacket();
};

#endif	/* TRANSPORTPROTOCOL_H */

