/* 
 * File:   pktstruct.h
 * Author: user
 *
 * Created on February 19, 2013, 1:39 AM
 * Source from provided material and #include <netinet/tcp.h>
 */



#ifndef PKTSTRUCT_H
#define	PKTSTRUCT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


    // Size of Ethernet Frame Header
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19

extern int file_num;

    /* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define PROT_TCP 6
#define PROT_UDP 17
#define PROT_IP 8    

    typedef u_int32_t tcp_seq;

    /* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl; /* version << 4 | header length >> 2 */
        u_char ip_tos; /* type of service */
        u_short ip_len; /* total length */
        u_short ip_id; /* identification */
        u_short ip_off; /* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl; /* time to live */
        u_char ip_p; /* protocol */
        u_short ip_sum; /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
    };
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

    /* TCP header */
    struct sniff_tcp {
        u_short th_sport; /* source port */
        u_short th_dport; /* destination port */
        //tcp_seq th_seq; /* sequence number */
        uint32_t th_seq;
        uint32_t th_ack;
        //tcp_seq th_ack; /* acknowledgement number */

        u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win; /* window */
        u_short th_sum; /* checksum */
        u_short th_urp; /* urgent pointer */
    };

    /* Pseduo TCP Header*/
    struct pseudo_tcphdr {
        u_long daddr;
        u_long saddr;
        char nullb;
        char prot;
        u_short tcpl;
    };

    struct sniff_udp {
        u_short udp_sport; /* source port */
        u_short udp_dport; /* destination port */
        u_short udp_hlen; /* Udp header length*/
        u_short udp_sum; /* Udp Checksum */
    };


#ifdef	__cplusplus
}
#endif

#endif	/* PKTSTRUCT_H */

