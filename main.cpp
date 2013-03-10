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
#include "Connection.h"
#include <map>

#include "pktstruct.h"

#include "IpKey.h"
#include "IPStack.h"


using namespace std;


int num_total_packets;
int num_tpackets;
int num_upackets;
int num_opackets;

int num_connections;

char *FLAG;
u_short PRINT_LEVEL;

// A map of IP:Port pairs to connections
// Needs Testing
map<IpKey, Connection> connections;

void print_total_count(int num_total_packets, int num_tpackets, int num_upackets, int num_opackets);
void process_tcp(Packet *packet);
void cleanup_connections();
void connection_died(Connection *c);

int main(int argc, char** argv) {

    num_connections = 0;

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
    u_char *raw_packet;
    int res;



    if ((fp = pcap_open_offline("-", errbuf)) == NULL) {
        fprintf(stderr, "Error opening dump file");
        return -1;
    }


    /* parses each individual packet*/
    while ((res = pcap_next_ex(fp, &header, (const u_char**) &raw_packet)) >= 0) {

        num_total_packets++;
        Packet *packet = new Packet();
        packet->ethernet = (struct sniff_ethernet*) (raw_packet);



        if (!(packet->ethernet->ether_type == PROT_IP)) {
            packet->transport_type = PROT_OTHER;
        } else {



            packet->ip = (struct sniff_ip*) (raw_packet + SIZE_ETHERNET); /* address of ip header*/
            packet->ip_size = IP_HL(packet->ip)*4; /* size in bytes*/


            if ((int) packet->ip->ip_p == PROT_TCP) { /*tcp packet*/
                num_tpackets++;
                packet->transport_type = PROT_TCP;
                packet->transport = new TCP();
                struct sniff_tcp *raw_tcp = (struct sniff_tcp*) (raw_packet + SIZE_ETHERNET + packet->ip_size); /* address of tcp header located after ip header*/


                TCP *tcp = (TCP *) packet->transport;
                tcp->header_size = TH_OFF(raw_tcp)*4; /* tcp size in bytes*/
                tcp->payload_size = ntohs(packet->ip->ip_len) - packet->ip_size - tcp->header_size; /* size of payload */
                tcp->payload = (Payload) (raw_packet + SIZE_ETHERNET + packet->ip_size + packet->transport->header_size); /* address of payload*/
                tcp->flags = raw_tcp->th_flags;
                tcp->seq = raw_tcp->th_seq; /* tcp sequence number*/
                tcp->ack = raw_tcp->th_ack; /* tcp ACK number */
                tcp->checksum = ntohs(raw_tcp->th_sum); /* checksum value in the packet*/
                int comp_value = ((unsigned short) tcp_checksum((unsigned short) (tcp->header_size), (unsigned short *) &packet->ip->ip_src, (unsigned short *) &packet->ip->ip_dst, raw_tcp, tcp->payload, tcp->payload_size));

                if (ntohs(raw_tcp->th_sum) == ntohs(comp_value)) { /* check validity of checksum*/
                    tcp->valid_checksum = true;

                } else {
                    tcp->valid_checksum = false;
                }
                
                
                // perform additional logic
                if (FLAG && strcmp("-t", FLAG) == 0) {
                    process_tcp(packet);
                }



            } else if (packet->transport_type == PROT_UDP) { /* udp packet*/
                num_upackets++;
                packet->transport_type = PROT_UDP;
                packet->transport = new UDP();

                sniff_udp *raw_udp = (struct sniff_udp*) (raw_packet + SIZE_ETHERNET + packet->ip_size); /* address of udp*/
                UDP *udp = (UDP *) packet->transport;

                udp->payload_size = ntohs(raw_udp->udp_hlen) - 8;
                udp->source_port = ntohs(raw_udp->udp_sport);
                udp->dest_port = ntohs(raw_udp->udp_dport);


            } else { /* other types of packets*/
                packet->transport_type = PROT_OTHER;
                num_opackets++;
            }


            // TODO Print PACKET
            packet->PrintPacket();
            //print_packet(packet); /* calls function to print packet info after parsing each packet*/


        }
    }

    if (FLAG && strcmp("-t", FLAG) == 0) {
        cleanup_connections();
    }


    print_total_count(num_total_packets, num_tpackets, num_upackets, num_opackets); /* prints the total number of packets parsed*/

    return (EXIT_SUCCESS);
}

/* print the number and type of packets parsed*/
void print_total_count(int num_total_packets, int num_tpackets, int num_upackets, int num_opackets) {
    if (PRINT_LEVEL > 0) {
        printf("%d %d %d %d\n", num_total_packets, num_tpackets, num_upackets, num_opackets);
    }
}

void process_tcp(Packet *packet) {

    IpKey key = *(new IpKey(packet->ip, (TCP *) packet->transport));

    map<IpKey, Connection> ::iterator conn = connections.find(key);
    if (conn == connections.end()) {
        std::cout << "New connection!" << endl;
        Connection c;
        c.deathCallback = &connection_died;
        c.setKey(key);
        c.setId(num_connections);
        c.processPacket(packet); 
        
        connections.insert(make_pair(key, c));
        num_connections++;
    } else {
        conn->second.processPacket(packet);
    }




}

void connection_died(Connection *c) {
    connections.erase(c->getKey());
}

void cleanup_connections() {
      map<IpKey, Connection> ::iterator conn;
      for(conn = connections.begin(); conn != connections.end(); conn++){
          //conn->second.write_meta();
      }


}