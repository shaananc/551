#include <iostream>
#include "Connection.h"
#include "IpKey.h"

using namespace std;
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19

void Connection::initializeConnection(Packet *packet) {
    // First step - check if SYN or SYN-ACK
    // All these lines should check sequence numbers on the ACK
    TCP *tcp = (TCP *) packet->transport;
    struct sniff_ip *ip = packet->ip;

    if ((tcp->flags & TH_SYN) && !(tcp->flags & TH_ACK)) {
        cout << "SYN" << endl;
        state = SYN_SENT;
        initiator = ip->ip_src;
        receiver = ip->ip_dst;
        init_port = tcp->source_port;
        recv_port = tcp->dest_port;


    } else if ((tcp->flags & TH_SYN) && (tcp->flags & TH_ACK)) {
        cout << "SYN/ACK" << endl;
        state = SYN_REC;
        //cout << "The current state is " << state << endl;
        initiator = ip->ip_dst;
        receiver = ip->ip_src;
        init_port = tcp->dest_port;
        recv_port = tcp->source_port;

    } else if (((state == SYN_REC) || (state == SYN_SENT)) && (tcp->flags & TH_ACK)) {
        state = EST;
        cout << "Established." << endl;
      
    } else {
        cout << "ERROR" << endl;
    }
}

Connection::Connection() {
    state = INIT;
}

bool Connection::processPacket(Packet *packet) {
    /*
    The logic goes like this 
    1)I see a tcp i check whether its part of vector of sequence no.If no I add it to the vector of sequence nos as well as checksums.If it not present its not a duplicate and I add it to the vector,other wise print that its duplicate
    2)Then check for the SYN as well as ACK flag if syc is set this means we receive the sync and hence the state is SYNRCVD,if sync and ack both are set then we sent the sync and the state is SYNCSENT.
    3)After this any ack tcp rcvd with a seq no difference of 1 takes the state to ESTABLISHED after which we get the payload and assign to byte sent or byte recvd state depending on if we sent the sync or we received the sync.
    4)The temination of connection is still to be discussed with TA for EOF part


     */


    TCP *tcp = (TCP *) packet->transport;


    // First step - check if SYN or SYN-ACK
    // All these lines should check sequence numbers on the ACK
    if (state == INIT || state == SYN_REC || state == SYN_SENT) {
        initializeConnection(packet);
    } else if (state == EST) {
        //all the manipulations for payload and bytes recvd and sent
        //ip = (struct sniff_ip*) (tcp + SIZE_ETHERNET);
        //tcp = (struct sniff_tcp*) (tcp + SIZE_ETHERNET + size_ip); /* address of tcp header located after ip header*/
        //cout << "Established!" << endl;

        //int d_size = ntohs(ip->ip_len) - size_ip - size_tcp;
        //payload = (u_char *) (tcp + SIZE_ETHERNET + size_ip + size_tcp);
        cout << "HERE!" << endl;
        cout << tcp->payload << endl;



    } else {
        cout << "uhoh" << endl;
    }



    return false;
    //TODO implement


}

bool Connection::seenPacket() {
    return false;
    // TODO implement
}

string Connection::getState() {
    switch (state) {
        case SYN_REC: return "SYN RECEIVED";
        case SYN_SENT: return "SYN SENT";
        case EST: return "ESTABLISHED";

    }
    return NULL;
}
