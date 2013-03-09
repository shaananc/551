#include <iostream>
#include <stdarg.h>
#include <string>
#include <vector>

#include "IPStack.h"
#include "pktstruct.h"

void addrToString(u_char *ptr, char *buf);


/* print packet details*/

void Packet::PrintPacket() {

    // Make string out of addresses
    char source_mac[MAC_STRING_SIZE];
    char dest_mac[MAC_STRING_SIZE];

    addrToString((u_char*) ethernet->ether_shost, source_mac);
    addrToString((u_char*) ethernet->ether_dhost, dest_mac);



    char source_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, source_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->ip_dst, dest_addr, INET_ADDRSTRLEN);



    if (transport_type == PROT_TCP) {

        TCP *tcp = (TCP *)transport;
        char valid;
        if (tcp->valid_checksum) {
            valid = 'Y';
        } else {
            valid = 'N';
        }

        printf("%.7s %.17s %.17s %s %s %d %u %u 0x%x %c\n",
                "TCP", source_mac, dest_mac, source_addr, dest_addr,
                tcp->payload_size, tcp->source_port, tcp->dest_port,
                tcp->checksum, valid);

    } else if (transport_type == PROT_UDP) {
        UDP *udp = (UDP *)transport;

        printf("%.7s %.17s %.17s %s %s %d %u %u\n", "UDP", source_mac,
                dest_mac, source_addr, dest_addr, udp->payload_size,
                udp->source_port, udp->dest_port);
    } else {
        printf("%.7s %.17s %.17s %s %s\n", "OTHER", source_mac, dest_mac,
                source_addr, dest_addr);
    }

}


/* converts mac addresses to string format*/
void addrToString(u_char *addr, char *buf) {
    sprintf(buf,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", addr[0] , addr[1] , addr[2] , addr[3] , addr[4] , addr[5]);

}