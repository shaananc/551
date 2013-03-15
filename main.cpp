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

#include <map>
#include <memory>


#include "pktstruct.h"

#include "IpKey.h"
#include "IPStack.h"

#include "SMTPProtocol.h"
#include "TCPConnection.h"

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
map<IpKey, TCPConnection> connections;

// A map from server port to registered application callbacks on TCP ports
map<int, NetApp* > applicationCallbacks;

void print_total_count(int num_total_packets, int num_tpackets, int num_upackets, int num_opackets);
void process_tcp(auto_ptr<Packet> packet, struct sniff_tcp* raw_tcp);
void process_udp(auto_ptr<Packet> packet, struct sniff_udp* raw_udp);
void cleanup_connections();
void register_applications();
void connection_died(TCPConnection *c);

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

    register_applications();

    if ((fp = pcap_open_offline("-", errbuf)) == NULL) {
        fprintf(stderr, "Error opening dump file");
        return -1;
    }


    /* parses each individual packet*/
    while ((res = pcap_next_ex(fp, &header, (const u_char**) &raw_packet)) >= 0) {

        num_total_packets++;

        auto_ptr<Packet> packet(new Packet());
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
                process_tcp(packet, raw_tcp);

            } else if (packet->transport_type == PROT_UDP) { /* udp packet*/
                num_upackets++;
                packet->transport_type = PROT_UDP;
                packet->transport = new UDP();

                sniff_udp *raw_udp = (struct sniff_udp*) (raw_packet + SIZE_ETHERNET + packet->ip_size); /* address of udp*/

                process_udp(packet, raw_udp);

            } else { /* other types of packets*/
                packet->transport_type = PROT_OTHER;
                num_opackets++;
            }


            packet->PrintPacket();


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

void process_tcp(auto_ptr<Packet> packet, struct sniff_tcp *raw_tcp) {


    TCP *tcp = (TCP *) packet->transport;
    tcp->header_size = TH_OFF(raw_tcp)*4; /* tcp size in bytes*/
    tcp->payload_size = ntohs(packet->ip->ip_len) - packet->ip_size - tcp->header_size; /* size of payload */
    tcp->payload = (Payload) (raw_tcp + packet->transport->header_size); /* address of payload*/
    tcp->flags = raw_tcp->th_flags;
    tcp->seq = ntohl(raw_tcp->th_seq); /* tcp sequence number*/
    tcp->ack = ntohl(raw_tcp->th_ack); /* tcp ACK number */
    tcp->checksum = ntohs(raw_tcp->th_sum); /* checksum value in the packet*/
    tcp->source_port = ntohs(raw_tcp->th_sport);
    tcp->dest_port = ntohs(raw_tcp->th_dport);
    int comp_value = ((unsigned short) tcp_checksum((unsigned short) (tcp->header_size), (unsigned short *) &packet->ip->ip_src, (unsigned short *) &packet->ip->ip_dst, raw_tcp, tcp->payload, tcp->payload_size));

    if (ntohs(raw_tcp->th_sum) == ntohs(comp_value)) { /* check validity of checksum*/
        tcp->valid_checksum = true;

    } else {
        tcp->valid_checksum = false;
    }


    // perform additional logic
    if (FLAG && (strcmp("-t", FLAG) == 0 || strcmp("-m", FLAG) == 0)) {

        IpKey key = *(new IpKey(packet->ip, (TCP *) packet->transport));

        map<IpKey, TCPConnection> ::iterator conn = connections.find(key);
        TCPConnection c;
        if (conn == connections.end()) {
            std::cout << "New connection! " << endl;

            c.deathCallback = &connection_died;
            c.setKey(key);
            c.setId(num_connections);
            c.processPacket(packet);

            connections.insert(make_pair(key, c));
            num_connections++;
        } else {
            if ((((TCP *) packet->transport)->flags & TH_SYN) && conn->second.state >= TCPConnection::EST) {
                conn->second.forceClose();
                c.deathCallback = &connection_died;
                c.setKey(key);
                c.setId(num_connections);
                c.processPacket(packet);
                conn->second = c;
            }

            conn->second.processPacket(packet);
        }


        if (strcmp("-m", FLAG) == 0) {

            map<int, NetApp*>::iterator app = applicationCallbacks.find(conn->second.recv_port);
            // There is an application waiting
            if (conn->second.state == TCPConnection::EST && app != applicationCallbacks.end()) {

                // Server sending
                if (c.initiator.s_addr == packet->ip->ip_src.s_addr) {
                    app->second->clientPayload(packet->transport->payload);
                } else if (c.receiver.s_addr == packet->ip->ip_src.s_addr) {
                    app->second->serverPayload(packet->transport->payload);
                }
            }

        }

    }




}

void process_udp(auto_ptr<Packet> packet, struct sniff_udp* raw_udp) {

    UDP *udp = (UDP *) packet->transport;

    udp->payload_size = ntohs(raw_udp->udp_hlen) - 8;
    udp->source_port = ntohs(raw_udp->udp_sport);
    udp->dest_port = ntohs(raw_udp->udp_dport);

}

void connection_died(TCPConnection *c) {
    connections.erase(c->getKey());
}

void cleanup_connections() {
    map<IpKey, TCPConnection> ::iterator conn;
    for (conn = connections.begin(); conn != connections.end(); conn++) {
        conn->second.tcpFlow();
        conn->second.forceClose();
    }


}

void register_applications() {
    NetApp *smtp25 = (NetApp *) new SMTPProtocol();
    applicationCallbacks.insert(make_pair(25, smtp25));
    NetApp *smtp587 = (NetApp *) new SMTPProtocol();
    applicationCallbacks.insert(make_pair(587, smtp587));
    NetApp *smtp465 = (NetApp *) new SMTPProtocol();
    applicationCallbacks.insert(make_pair(465, smtp465));
}
