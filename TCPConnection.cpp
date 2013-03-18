#include <iostream>
#include "TCPConnection.h"
#include "SMTPProtocol.h"
#include "IpKey.h"
#include <string.h> 
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>

using namespace std;
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19

#include "IPStack.h"
#include <map>


extern map<int, NetApp* > applicationCallbacks;


void TCPConnection::initializeConnection(Packet *packet) {
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
        packets_sent++;


    } else if ((tcp->flags & TH_SYN) && (tcp->flags & TH_ACK)) {
        cout << "SYN/ACK" << endl;
        state = SYN_REC;
        //cout << "The current state is " << state << endl;
        initiator = ip->ip_dst;
        receiver = ip->ip_src;
        init_port = tcp->dest_port;
        recv_port = tcp->source_port;
        packets_recv++;

    } else if ((state == SYN_REC)&&(tcp->flags & TH_RST))//added case for RST
    {

        state = INIT;
        cout << "RST SENT" << endl;
    } else if (((state == SYN_REC) || (state == SYN_SENT)) && (tcp->flags & TH_ACK)) {
        state = EST;
        cout << "Established." << endl;
        packets_sent++;

    } else {

        cout << "ERROR" << endl;
    }

}

TCPConnection::TCPConnection() {
    state = INIT;
    init_duplicates = 0;
    recv_duplicates = 0;
    bytes_recv = 0;
    bytes_sent = 0;
    packets_recv = 0;
    packets_sent = 0;
    force_close = false;
}

void TCPConnection::setId(int id_num) {
    this->id_num = id_num;
}

void TCPConnection::tcpFlow(){
    
    /* Reconstruction of TCP flow from the client side*/
	std::sort(init_buf.begin(), init_buf.end());
        
        std::vector<TCP>::iterator it = init_buf.begin();
        while(it != init_buf.end()){
		if(it->ack_complete != 1){
		   it = init_buf.erase(it);
		} else {
                    it++;
                }
	}
	
	for (std::vector<TCP>::iterator it = init_buf.begin(); it != init_buf.end(); it++) {
		std::vector<TCP>::iterator nit = it;
		++nit;
		uint32_t next = nit->seq;
		uint32_t i = next - it->seq;
		
		std::string in = it->pload.substr(0, i);
		
		clientData.push_back(in);	
	}
	
    /* Reconstruction of TCP flow from the server side*/
	std::sort(recv_buf.begin(), recv_buf.end());
        
        it = recv_buf.begin();
        while(it != recv_buf.end()){
		if(it->ack_complete != 1){
		   it = recv_buf.erase(it);
		} else {
                    it++;
                }
	}
	
	
	for (std::vector<TCP>::iterator it = recv_buf.begin(); it != recv_buf.end(); it++) {
		std::vector<TCP>::iterator nit = it;
		++nit;
		uint32_t next = nit->seq;
		uint32_t i = next - it->seq;
		
		std::string in = it->pload.substr(0, i);
		
		serverData.push_back(in);	
	}
	
	SMTPProtocol smtp;
	smtp.clientPayload(clientData);
	//smtp.serverPayload(serverData);
}


void TCPConnection::writeMeta() {

    std::ostringstream filename;
    filename.str("");
    filename << id_num << ".meta";
    std::ofstream recv_file;
    recv_file.open(filename.str().c_str(), ios::app);

    char source_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &initiator, source_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &receiver, dest_addr, INET_ADDRSTRLEN);

    recv_file << source_addr << " " << dest_addr << endl;
    recv_file << init_port << " " << recv_port << endl;
    recv_file << packets_sent << " " << packets_recv << endl;
    recv_file << bytes_sent << " " << bytes_recv << endl;
    recv_file << init_duplicates << " " << recv_duplicates << endl;
    recv_file << force_close << " " << endl;



    recv_file.close();

}

bool TCPConnection::processPacket(Packet *packet) {
    TCP *tcp = (TCP *) packet->transport;
    struct sniff_ip *ip = packet->ip;
    int duplicate_exists;



    // First step - check if SYN or SYN-ACK
    // All these lines should check sequence numbers on the ACK
    if (state == INIT || state == SYN_REC || state == SYN_SENT) {
        initializeConnection(packet);
    } else if (state == EST) {


        if (ip->ip_src.s_addr == initiator.s_addr) {
            duplicate_exists = 0;

            for (std::vector<TCP>::iterator it = init_buf.begin(); it != init_buf.end(); it++) {
                if ((it->seq == tcp->seq) && (it->payload_size == tcp->payload_size)) {// && (it->payload_size <= tcp->payload_size)){
                    duplicate_exists = 1;
                    init_duplicates++;
                }
            }

            if (duplicate_exists == 0 tcp->payload_size > 0) {
                TCP t;
    		t.seq = tcp->seq;
		t.payload_size = tcp->payload_size;
		t.ack_complete = 0;
		std::stringstream s;
		int i = 0;
		u_char *c = tcp->payload;
		while (*c && i < tcp->payload_size) {
		  s << *c;
		  c++;
	          i++;
		}
		std::string cstring = s.str();
				
		t.pload = cstring;
				
                init_buf.push_back(t);
            }

            std::vector<TCP>::iterator iter;
            for (iter = recv_buf.begin(); iter != recv_buf.end(); iter++) {
                
                if (iter->seq < tcp->ack) {
                    if (iter->ack_complete != 1) {
                        iter->ack_complete = 1;

                        std::ostringstream filename;
                        filename.str("");
                        filename << id_num << ".receiver";
                        std::ofstream recv_file;
                        recv_file.open(filename.str().c_str(), ios::app);
                        u_char *p = tcp->payload;
                        int i = 0;
                        while (*p && i < tcp->payload_size) {
                            recv_file << *p;
                            p++;
                            i++;
                        }
                        
                        //serverData.push(tcp->payload);

                        recv_file.close();
                        //iter = recv_buf.erase(iter);

                        bytes_sent += tcp->payload_size;
                        packets_sent++;

                    }
                }
            }



        
        } else if (ip->ip_src.s_addr == receiver.s_addr) {
            std::vector<TCP>::iterator iter;
            for (iter = recv_buf.begin(); iter != recv_buf.end(); iter++) {
                if ((iter->seq == tcp->seq) && (iter->payload_size == tcp->payload_size)) { //&& (iter->payload_size <= tcp->payload_size)){
                    duplicate_exists = 1;
                    recv_duplicates++;
                }
            }


            if (duplicate_exists == 0 && tcp->payload_size > 0) {
                TCP t;
    		t.seq = tcp->seq;
		t.payload_size = tcp->payload_size;
		t.ack_complete = 0;
		std::stringstream s;
		int i = 0;
		u_char *c = tcp->payload;
		while (*c && i < tcp->payload_size) {
		  s << *c;
		  c++;
		  i++;
		}
		std::string cstring = s.str();
				
		t.pload = cstring;
				
                recv_buf.push_back(t);
            }
          

            for (std::vector<TCP>::iterator it = init_buf.begin(); it != init_buf.end(); it++) {
                if (it->seq < tcp->ack) {
                    if (it->ack_complete != 1) {
                        it->ack_complete = 1;

                        std::ostringstream filename;
                        filename << id_num << ".initiator";
                        std::ofstream init_file;
                        init_file.open(filename.str().c_str(), ios::app);
                        
                        u_char *p = tcp->payload;
                        int i = 0;
                        while (*p && i < tcp->payload_size) {
                            init_file << *p;
                            p++;
                            i++;
                        }
                        init_file.close();
                        //it = init_buf.erase(it);

                        //clientData.push(tcp->payload);
                        
                        packets_recv++;
                        bytes_recv += tcp->payload_size;
                       



                    }
                }
            }



        }



    } else {
        cout << "uhoh" << endl;
    }



    return false;
    //TODO implement


}

void TCPConnection::checktermination(Packet *packet) {
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
        tcpFlow();
        writeMeta();
        deathCallback(this);
    } else {

        cout << "ERROR" << endl;
    }

}

string TCPConnection::getState() {
    switch (state) {
        case SYN_REC: return "SYN RECEIVED";
        case SYN_SENT: return "SYN SENT";
        case EST: return "ESTABLISHED";

    }
    return NULL;
}

void TCPConnection::setKey(IpKey key) {
    this->key = key;
}

IpKey TCPConnection::getKey() {
    return this->key;
}

void TCPConnection::forceClose() {
    force_close = true;
    cout << "force close" << endl;
    this->tcpFlow();
    this->writeMeta();

}
