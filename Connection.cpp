#include <iostream>
#include "Connection.h"
#include "IpKey.h"
#include <string.h> 
#include <stdio.h>
#include <fstream>

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

    } 
      else if((state == SYN_REC)&&(tcp->flags & TH_RST))//added case for RST
        {
        
        state = INIT;
        cout<<"RST SENT"<<endl;
        }

      else if (((state == SYN_REC) || (state == SYN_SENT)) && (tcp->flags & TH_ACK)) {
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

    ofstream myfile;
    TCP *tcp = (TCP *) packet->transport;
    struct sniff_ip *ip = packet->ip;

    // First step - check if SYN or SYN-ACK
    // All these lines should check sequence numbers on the ACK
    if (state == INIT || state == SYN_REC || state == SYN_SENT) {
        initializeConnection(packet);
    } else if (state == EST) {
        //all the manipulations for payload and bytes recvd and sent
        //TODO: needs to check for duplicates
        char src[INET_ADDRSTRLEN];
        char in[INET_ADDRSTRLEN];
        char recv[INET_ADDRSTRLEN]; 
        inet_ntop(AF_INET, &ip->ip_src, src, INET_ADDRSTRLEN); //IP of the source of the packet
        inet_ntop(AF_INET, &initiator, in, INET_ADDRSTRLEN); //IP of the initiato
        inet_ntop(AF_INET, &receiver, recv, INET_ADDRSTRLEN); //IP of the initiato

        tcp->payload_size = ntohs(packet->ip->ip_len) - packet->ip_size - tcp->header_size; /* size of payload */
        //tcp->payload = (Payload) (raw_packet + SIZE_ETHERNET + packet->ip_size + packet->transport->header_size); /* address of payload*/
        if(strcmp(src,in)==0)
       {
        bytes_sent+=  tcp->payload_size;
        packets_sent++;
        cout<<"The packets and bytess sent are" <<bytes_sent<<packets_sent<<endl;
       }
       else if(strcmp(src,recv)==0)
       {
        packets_recv++;
        bytes_recv+= tcp->payload_size;   
        cout<<"The packets and bytes received are" <<bytes_recv<<packets_recv<<endl;
        
        myfile.open ("example1.txt");
        myfile << "Swaraj Writing this to a file.\n";
        myfile.close();
  

        cout << "HERE!" << endl;
       } /*
        char src[INET_ADDRSTRLEN];
    	char in[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_src, src, INET_ADDRSTRLEN); //IP of the source of the packet
	inet_ntop(AF_INET, &initiator, in, INET_ADDRSTRLEN); //IP of the initiator
		
	if(!strcmp(src,in)){ //the source of the packet is the initiator
		init.push_back(*tcp);
			
		for(std::list<TCP>::iterator it = recv.begin(); it != recv.end(); it++){
			if(ntohl(it->seq) < ntohl(tcp->ack)){ //the packet in the receiver buffer has been acknowledged
				if(it->ack_complete != 1){ //if packet hasn't already been acknowledged
					it->ack_complete = 1; //set the ACK field in tcp packet to complete (1).
					//if(it->payload_size > 0){
						cout << it->payload <<endl; //print payload
					//}
					
				}
			}
		}
			
			
	} else { //source of the packet is the receiver
		recv.push_back(*tcp);
			
		for(std::list<TCP>::iterator it = init.begin(); it != init.end(); it++){
			if(ntohl(it->seq) < ntohl(tcp->ack)){ //the packet in the initiator buffer has been acknowledged
				if(it->ack_complete != 1){ //if packet hasn't already been acknowledged
					it->ack_complete = 1; //set the ACK field in tcp packet to complete (1).
					//if(it->payload_size > 0){
						cout << it->payload <<endl; //print payload
					//}
					
				}
			}
		}
				   
	}
*/
        //cout << tcp->payload << endl;

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
