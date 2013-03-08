/* 
 * File:   packetparse.c
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
#include "Connection.h"
#include <map>

#include "pktstruct.h"

#include "IpKey.h"

// Size of Ethernet Frame Header
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19

using namespace std;

// Structs to take bits of the packet
const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const struct sniff_udp *udp; /* The UDP header */
const char *payload; /* Packet payload */

char source_mac[MAC_STRING_SIZE];
char dest_mac[MAC_STRING_SIZE];
char source_addr[INET_ADDRSTRLEN];
char dest_addr[INET_ADDRSTRLEN];
int source_port;
int dest_port;
int payload_size;
int checksum_value;
char valid;
int num_total_packets;
int num_tpackets;
int num_upackets;
int num_opackets;

char *FLAG;
u_short PRINT_LEVEL;

// A map of IP:Port pairs to connections
// Needs Testing
map<IpKey, Connection> connections;



void addrToString(u_char *ptr, char *buf);
//u_short checksum(struct sniff_ip *ip, struct sniff_tcp *tcp, u_char* payload, int size);
//u_short calcsum(u_short *ptr, int size);
void print_packets(char *type_s);
void print_total_count(int num_total_packets, int num_tpackets, int num_upackets, int num_opackets);
void process_tcp(struct sniff_ip *ip, struct sniff_tcp *tcp, u_char *payload);
u_short tcp_checksum(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], struct sniff_tcp *tcp, u_char *payload, int size);

int main(int argc, char** argv) {

    if (argc > 1) {
        FLAG = argv[1];
        if (strcmp(FLAG, "-t") == 0) {
            PRINT_LEVEL = 0;
        }
    } else {
        PRINT_LEVEL = 1;
    }


    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    u_char *packet;
    u_int i = 0;
    int res;

    u_int size_ip; /*Size of ip header*/
    u_int size_tcp; /*Size of tcp header*/
    u_int size_udp; /*Size of udp header*/



    if ((fp = pcap_open_offline("-", errbuf)) == NULL) {
        fprintf(stderr, "Error opening dump file");
        return -1;
    }


    /* parses each individual packet*/
    while ((res = pcap_next_ex(fp, &header, (const u_char**) &packet)) >= 0) {

        num_total_packets++;
        ethernet = (struct sniff_ethernet*) (packet);
        char type_s[7];
        bzero(type_s, 7);

        // Make string out of addresses
        char src_mac[MAC_STRING_SIZE];
        char dst_mac[MAC_STRING_SIZE];

        addrToString((u_char*) ethernet->ether_shost, src_mac);
        addrToString((u_char*) ethernet->ether_dhost, dst_mac);


        strcpy(source_mac, src_mac); /* source mac address*/
        strcpy(dest_mac, dst_mac); /* destination mac address*/

        if (!(ethernet->ether_type == PROT_IP)) {
            strcpy(type_s, "other");

            bzero(type_s, 7);
        } else {



            ip = (struct sniff_ip*) (packet + SIZE_ETHERNET); /* address of ip header*/
            size_ip = IP_HL(ip)*4; /* size in bytes*/

            char src_s[INET_ADDRSTRLEN];
            char dst_s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->ip_src, src_s, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip->ip_dst, dst_s, INET_ADDRSTRLEN);


            strcpy(source_addr, src_s); /* source IP address*/
            strcpy(dest_addr, dst_s); /* destination IP address*/

            if ((int) ip->ip_p == PROT_TCP) { /*tcp packet*/
                num_tpackets++;
                strcpy(type_s, "TCP");
                tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip); /* address of tcp header located after ip header*/
                source_port = ntohs(tcp->th_sport);
                dest_port = ntohs(tcp->th_dport);
                size_tcp = TH_OFF(tcp)*4; /* tcp size in bytes*/
                int d_size = ntohs(ip->ip_len) - size_ip - size_tcp; /* size of payload */
                payload_size = d_size;
                payload = (const char *) (packet + SIZE_ETHERNET + size_ip + size_tcp); /* address of payload*/

                checksum_value = ntohs(tcp->th_sum); /* checksum value in the packet*/
                int comp_value = ((unsigned short) tcp_checksum((unsigned short) (size_tcp), (unsigned short *) &ip->ip_src, (unsigned short *) &ip->ip_dst, tcp, payload, d_size));

                if (ntohs(tcp->th_sum) == ntohs(comp_value)) { /* check validity of checksum*/

                    valid = 'Y';

                } else {

                    valid = 'N';
                }

                // if the packet is valid and the FLAG is TCP_STREAM
                // perform additional logic
                if (strcmp("-t", FLAG) == 0) {
                    process_tcp((struct sniff_ip*) ip, (struct sniff_tcp*) tcp, (u_char *) payload);
                }



            } else if ((int) ip->ip_p == PROT_UDP) { /* udp packet*/
                num_upackets++;
                strcpy(type_s, "UDP");
                udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip); /* address of udp*/
                int udp_payload = ntohs(udp->udp_hlen) - 8; /* udp payload size: udpheader - 8*/
                payload_size = udp_payload;
                source_port = ntohs(udp->udp_sport);
                dest_port = ntohs(udp->udp_dport);

            } else { /* other types of packets*/
                strcpy(type_s, "other");
                num_opackets++;
            }



            print_packets(type_s); /* calls function to print packet info after parsing each packet*/

            bzero(type_s, 7);
        }
    }

    print_total_count(num_total_packets, num_tpackets, num_upackets, num_opackets); /* prints the total number of packets parsed*/

    return (EXIT_SUCCESS);
}

/* converts mac addresses to string format*/
void addrToString(u_char *addr, char *buf) {
    int i = ETHER_ADDR_LEN;
    char *sptr = buf;
    char *ptr = (char *) addr;
    do {
        sprintf(sptr, "%.2x", *ptr++);
        sprintf(sptr + 2, ":");
        sptr += 3;
    } while (--i > 0);
    buf[MAC_STRING_SIZE - 2] = '\0';
}

/* computes the checksum*/
u_short tcp_checksum(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], struct sniff_tcp* tcp, u_char *payload, int size)
{
    char buf[65536];
    unsigned char prot_tcp=6;
    unsigned long sum;
    int s;
    
    sum = 0;
    s = (len_tcp + size); /*tcp header length + payload length */
	
    u_short bak = tcp->th_sum;
    tcp->th_sum = 0;
	
	/*TCP header and payload */
    memcpy(buf, tcp, len_tcp);
    memcpy(buf + len_tcp, payload, size);
    u_short *ptr = (ushort *) buf;
	
    
    while(s > 1)
    {
        sum += *ptr++;
        s -= 2;
    }
	
    
    if(s>0)
    {
		sum += *((unsigned char *)ptr);
    }
	
	/* pseudoheader*/
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(prot_tcp);
    sum += htons(len_tcp + size);
	
	while (sum >> 16){
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	
	tcp->th_sum = bak;
	
	return (u_short*) ~sum;
}

/*
u_short checksum(struct sniff_ip *ip, struct sniff_tcp *tcp, u_char *payload, int size) {
    char buf[65536];

    
    struct pseudo_tcphdr psd_header;
    psd_header.saddr = ip->ip_src.s_addr;
    psd_header.daddr = ip->ip_dst.s_addr;
    psd_header.nullb = 0;
    psd_header.prot = IPPROTO_TCP;
    psd_header.tcpl = htons(sizeof (struct sniff_tcp) +size);

    u_short bak = tcp->th_sum;
    tcp->th_sum = 0;

    
    memcpy(buf, &psd_header, sizeof (struct pseudo_tcphdr));
    memcpy(buf + sizeof (struct pseudo_tcphdr), tcp, sizeof (struct sniff_tcp));
    memcpy(buf + sizeof (struct pseudo_tcphdr) + sizeof (struct sniff_tcp), payload, size);

    tcp->th_sum = bak;

    int total_s = sizeof (struct pseudo_tcphdr) + sizeof (struct sniff_tcp) +size;
    


    return calcsum((ushort *) buf, total_s);



}


u_short calcsum(u_short *ptr, int size) {

    int s = size;
    u_long sum = 0;

    while (s > 1) {
        s -= sizeof (u_short);
        sum = sum + *ptr;
        ptr = ptr + 1;
    }

    if (s) {
        sum = sum + *(u_char *) ptr;
    }


    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);

    return (u_short) ~sum;

}
*/

/* print packet details*/
void print_packets(char *type_s) {
    if (PRINT_LEVEL > 0) {
        if (!strcmp(type_s, "TCP")) {
            printf("%.7s %.17s %.17s %s %s %d %u %u 0x%x %c\n", type_s, source_mac, dest_mac, source_addr, dest_addr, payload_size, source_port, dest_port, checksum_value, valid);
        } else if (!strcmp(type_s, "UDP")) {
            printf("%.7s %.17s %.17s %s %s %d %u %u\n", type_s, source_mac, dest_mac, source_addr, dest_addr, payload_size, source_port, dest_port);
        } else {
            printf("%.7s %.17s %.17s %s %s\n", type_s, source_mac, dest_mac, source_addr, dest_addr);
        }
        payload_size = 0;
        source_port = 0;
        dest_port = 0;
    }
}

/* print the number and type of packets parsed*/
void print_total_count(int num_total_packets, int num_tpackets, int num_upackets, int num_opackets) {
    if (PRINT_LEVEL > 0) {
        printf("%d %d %d %d\n", num_total_packets, num_tpackets, num_upackets, num_opackets);
    }
}

void process_tcp(struct sniff_ip *ip, struct sniff_tcp *tcp, u_char *payload) {

    IpKey key = *(new IpKey(ip, tcp));

    map<IpKey, Connection> ::iterator conn = connections.find(key);
    if (conn == connections.end()) {
        std::cout << "New connection!" << endl;
        Connection c;
        c.processPacket(tcp, ip, payload);
        connections.insert(make_pair(key, c));
    } else {
        conn->second.processPacket(tcp, ip, payload);
    }



}
