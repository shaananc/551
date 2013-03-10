#include <iostream>
#include "Connection.h"
#include "IpKey.h"
#include <string.h> 
#include <stdio.h>
#include <fstream>
#include <sstream>

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

        init_duplicates = 0;
        recv_duplicates = 0;
        bytes_recv = 0;
        bytes_sent = 0;
        packets_recv = 0;
        packets_sent = 0;


    } else if ((tcp->flags & TH_SYN) && (tcp->flags & TH_ACK)) {
        cout << "SYN/ACK" << endl;
        state = SYN_REC;
        //cout << "The current state is " << state << endl;
        initiator = ip->ip_dst;
        receiver = ip->ip_src;
        init_port = tcp->dest_port;
        recv_port = tcp->source_port;

    } else if ((state == SYN_REC)&&(tcp->flags & TH_RST))//added case for RST
    {

        state = INIT;
        cout << "RST SENT" << endl;
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

void Connection::setId(int id_num) {
    this->id_num = id_num;
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
    struct sniff_ip *ip = packet->ip;

    // First step - check if SYN or SYN-ACK
    // All these lines should check sequence numbers on the ACK
    if (state == INIT || state == SYN_REC || state == SYN_SENT) {
        initializeConnection(packet);
    } else if (state == EST) {


        if (ip->ip_src.s_addr == initiator.s_addr) {
            bytes_sent += tcp->payload_size;
            packets_sent++;
            cout << "The packets and bytes sent are " << bytes_sent << " " << packets_sent << endl;
        } else if (ip->ip_src.s_addr == receiver.s_addr) {
            packets_recv++;
            bytes_recv += tcp->payload_size;
            cout << "The packets and bytes received are " << bytes_recv << " " << packets_recv << endl;


            std::ostringstream str;
            str << id_num << ".meta";
            std::ofstream myfile;

            myfile.open(str.str().c_str());
            // TODO: Insert Metadata here
            myfile << "Swaraj Writing this to a file.\n" << std::endl;
            myfile.close();

        }

        int duplicate_exists = 0;

        if (!(ip->ip_src.s_addr == initiator.s_addr)) { //the source of the packet is the initiator
            for (std::list<TCP>::iterator iter = init_buf.begin(); iter != init_buf.end(); iter++) {
                if (iter->seq == tcp->seq && (iter->payload_size == tcp->payload_size)) {
                    init_duplicates++; //NUMBER OF DUPLICATE PACKETS FROM INITIATOR. NEED TO PRINT
                    duplicate_exists = 1;
                    cout << "duplicate sender?" << endl;
                }
            }

            if (duplicate_exists == 0) {
                init_buf.push_back(*tcp);
            }

            duplicate_exists = 0;

            std::ostringstream filename;
            filename << id_num << ".initiator";
            std::ofstream init_file;
            init_file.open(filename.str().c_str(), ios::app);
            cout << "PAYLOAD"  << tcp->payload << endl;
            init_file << tcp->payload; //PAYLOAD OF INITIATOR
            init_file.close();
            return true;
            


        } else if (!(ip->ip_src.s_addr == receiver.s_addr)) {
            std::list<TCP>::iterator iter;
            for (iter = recv_buf.begin(); iter != recv_buf.end(); iter++) {
                if ((ntohl(iter->seq) == ntohl(tcp->seq)) && (iter->payload_size == tcp->payload_size)) {
                    recv_duplicates++; //NUMBER OF DUPLICATE PACKETS FROM RESPONDER. NEED TO PRINT
                    duplicate_exists = 1;
                    cout << "duplicate receiver?" << endl;
                }
            }

            if (duplicate_exists == 0) {
                recv_buf.push_back(*tcp);
            }

            duplicate_exists = 0;
            std::list<TCP>::iterator it;
            for (it = init_buf.begin(); it != init_buf.end(); it++) {
                if (ntohl(it->seq) < ntohl(tcp->ack)) {
                    if (it->ack_complete != 1) {
                        it->ack_complete = 1;

                        std::ostringstream filename;
                        filename.str("");
                        filename << id_num << ".receiver";
                        std::ofstream recv_file;
                        recv_file.open(filename.str().c_str(),ios::app);
                        recv_file << tcp->payload; //PAYLOAD OF RESPONDER
                        recv_file.close();


                    }
                }
            }
            return true;

        }


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

void Connection::checktermination(Packet* packet) {
    TCP* tcp = (TCP*) (packet->transport);
    if (((state == EST)&&(tcp->flags & TH_FIN)) || ((state == EST)&&(tcp->flags & TH_FIN)&&(tcp->flags & TH_ACK))) {
        //Here the ack corresponds to ack of ther last packet and hence has to be taken care like the lsst ack packet before termination
        state = FIN_INIT;
        cout << "FIN Initiated" << endl;
        force_close = false;
    } else if (state == FIN_INIT && (tcp->flags & TH_FIN)&&(tcp->flags & TH_ACK)) {
        state = FIN_INIT;
        cout << "This FIN ACK is from Receiver indicating it also wants to terminate" << endl;
    } else if ((state == FIN_INIT)&&(tcp->flags & TH_ACK)) {
        state = FIN_EST;
        force_close = true;
        cout << "Termination done" << endl;
    } else {

        cout << "ERROR" << endl;
    }

}

string Connection::getState() {
    switch (state) {
        case SYN_REC: return "SYN RECEIVED";
        case SYN_SENT: return "SYN SENT";
        case EST: return "ESTABLISHED";

    }
    return NULL;
}

void Connection::setKey(IpKey key) {
    this->key = key;
}

IpKey Connection::getKey() {
    return this->key;
}
