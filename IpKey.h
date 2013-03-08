/* 
 * File:   main.h
 * Author: user
 *
 * Created on March 7, 2013, 12:44 PM
 */

#ifndef MAIN_H
#define	MAIN_H

#include "pktstruct.h"

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

    IpKey(struct sniff_ip *ip, struct sniff_tcp *tcp) {
        if (ip->ip_src.s_addr > ip->ip_dst.s_addr) {
            addrA = ip->ip_src.s_addr;
            portA = tcp->th_sport;

            addrB = ip->ip_dst.s_addr;
            portB = tcp->th_dport;

        } else {
            addrB = ip->ip_src.s_addr;
            portB = tcp->th_sport;

            addrA = ip->ip_dst.s_addr;
            portA = tcp->th_dport;
            
        }
    }
    
    
    
    




};

bool operator<(const IpKey& lhs, const IpKey& rhs);

#endif	/* MAIN_H */

