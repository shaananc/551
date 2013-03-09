/* 
 * File:   main.h
 * Author: user
 *
 * Created on March 7, 2013, 12:44 PM
 */

#ifndef MAIN_H
#define	MAIN_H

#include "pktstruct.h"
#include "IPStack.h"

class IpKey {
public:

    IpKey() {
        ;
    }


public:
    
    
    uint32_t addrA;
    uint32_t addrB;

    u_char portA;
    u_char portB;

public:

    IpKey(struct sniff_ip *ip, TCP *tcp) {
        if (ip->ip_src.s_addr > ip->ip_dst.s_addr) {
            addrA = ip->ip_src.s_addr;
            portA = tcp->source_port;

            addrB = ip->ip_dst.s_addr;
            portB = tcp->dest_port;

        } else {
            addrB = ip->ip_src.s_addr;
            portB = tcp->source_port;

            addrA = ip->ip_dst.s_addr;
            portA = tcp->dest_port;
            
        }
    }
    
    
    
    




};

bool operator<(const IpKey& lhs, const IpKey& rhs);

#endif	/* MAIN_H */

