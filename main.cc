/* 
 * File:   main.c
 * Author: user
 *
 * Created on February 19, 2013, 12:39 AM
 * 
 * Credit to: http://yuba.stanford.edu/~casado/pcap/section2.html
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>



#include "pktstruct.h"

// Size of Ethernet Frame Header
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19

// Structs to take bits of the packet
const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const struct sniff_udp *udp; /* The UDP header */
const char *payload; /* Packet payload */

/*
 * 
 */


void addrToString(u_char *ptr, char *buf);
u_short checksum(struct sniff_ip *ip, struct sniff_tcp *tcp, u_char *payload, int size);
u_short calcsum(u_short *ptr, int size);

int main(int argc, char** argv) {

    // ???
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    u_char *packet;
    u_int i = 0;
    int res;

    // Size of ip header
    u_int size_ip;
    // Size of tcp header
    u_int size_tcp;
    // Size of udp header
    u_int size_udp;

    if (argc < 2) {
        printf("Usage: packetparse <file>.pcap");
        return -1;
    }


    if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL) {
        fprintf(stderr, "Error opening dump file");
        return -1;
    }

    while ((res = pcap_next_ex(fp, &header, (const u_char**)&packet)) >= 0) {
        //printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
        ethernet = (struct sniff_ethernet*) (packet);
        char type_s[7];
        bzero(type_s, 7);

        // Make string out of addresses
        char src_mac[MAC_STRING_SIZE];
        char dst_mac[MAC_STRING_SIZE];

        addrToString((u_char*)ethernet->ether_shost, src_mac);
        addrToString((u_char*)ethernet->ether_dhost, dst_mac);

        printf("Source MAC:  %.17s\nDestin MAC:  %.17s\t \n", src_mac, dst_mac);

        if (!(ethernet->ether_type == PROT_IP)) {
            strcpy(type_s, "other");

            bzero(type_s, 7);
        } else {



            ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
            size_ip = IP_HL(ip)*4;
            //char src_ip[INET_ADDRSTRLEN];
            //char dst_ipINET_ADDRSTRLEN];

            char src_s[INET_ADDRSTRLEN];
            char dst_s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->ip_src, src_s, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip->ip_dst, dst_s, INET_ADDRSTRLEN);

            // current->info->src_ip= src_s;
            //current->info->dst_ip = dst_s;
            printf("Source addr: %s\nDestin addr: %s\n", src_s, dst_s);


            if ((int) ip->ip_p == PROT_TCP) {
                strcpy(type_s, "TCP");
                printf("Packet Type: %.7s\n", type_s);
                tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
                printf("Source port: %-5u \nDestin Port: %-5u\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
                
                // printf("the now is %-5u\n",current);
                // printf("the next is%-5u\n ",current->next);
                size_tcp = TH_OFF(tcp)*4;

                int d_size = ntohs(ip->ip_len) - size_ip - size_tcp; // - ip->ip_len; // go till ip->ip_len
                printf("Payload Size: %d\n", d_size);

                payload = (const char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
                //TODO: Calculate Checksum Here
                printf("Checksum: %x\n", ntohs(tcp->th_sum));
                // TODO Integrate
                printf("Computed Checksum: %x\n", ntohs(checksum((struct sniff_ip *)ip, (struct sniff_tcp *) tcp, (u_char *)payload, d_size)));

            }


            else if ((int) ip->ip_p == PROT_UDP) {
                strcpy(type_s, "UDP");
                printf("Packet Type: %.7s\n", type_s);
                udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
                printf("Source port: %-5u \nDestin Port: %-5u\n", ntohs(udp->udp_sport), ntohs(udp->udp_dport));

            } else {
                strcpy(type_s, "other");
            }



            printf("\n\n");
            bzero(type_s, 7);
        }
       
    }
    


    return (EXIT_SUCCESS);
}


void addrToString(u_char *addr, char *buf) {
    int i = ETHER_ADDR_LEN;
    char *sptr = buf;
    u_char *ptr = addr;
    do {
        sprintf(sptr, "%.2x", *ptr++);
        sprintf(sptr + 2, ":");
        sptr += 3;
    } while (--i > 0);
    buf[MAC_STRING_SIZE - 2] = '\0';
}

u_short checksum(struct sniff_ip *ip, struct sniff_tcp *tcp, u_char *payload, int size) {
    char buf[65536];

    // Construct pseduo header
    struct pseudo_tcphdr psd_header;
    psd_header.saddr = ip->ip_src.s_addr;
    psd_header.daddr = ip->ip_dst.s_addr;
    psd_header.nullb = 0;
    psd_header.prot = IPPROTO_TCP;
    psd_header.tcpl = htons(sizeof (struct sniff_tcp) +size);

    u_short bak = tcp->th_sum;
    tcp->th_sum = 0;

    //Copy bytes into buffer
    memcpy(buf, &psd_header, sizeof (struct pseudo_tcphdr));
    memcpy(buf + sizeof (struct pseudo_tcphdr), tcp, sizeof (struct sniff_tcp));
    memcpy(buf + sizeof (struct pseudo_tcphdr) + sizeof (struct sniff_tcp), payload, size);

    tcp->th_sum = bak;

    int total_s = sizeof (struct pseudo_tcphdr) + sizeof (struct sniff_tcp) +size;
    //     Compute checksum /


    return calcsum((ushort *) buf, total_s);



}


// Modified checksum function from internet

u_short calcsum(u_short *ptr, int size) {

    u_long chk = 0;
    int i = size;
    while (i > 1) {
        i -= sizeof (u_short);
        chk += *ptr;
        ptr++;

    }
    if (i) {
        chk += *(u_char *) ptr;
    }

    // What do these lines do?
    chk = (chk >> 16) + (chk & 0xffff);
    chk += (chk >> 16);

    return (u_short) ~chk;

}

