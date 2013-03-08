#include <iostream>
#include "Connection.h"
#include "IpKey.h"

using namespace std;
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19

Connection::Connection() {
    ;
}

bool Connection::processPacket(struct sniff_tcp *tcp, struct sniff_ip *ip, u_char *payload) {
    /*
    The logic goes like this 
    1)I see a tcp i check whether its part of vector of sequence no.If no I add it to the vector of sequence nos as well as checksums.If it not present its not a duplicate and I add it to the vector,other wise print that its duplicate
    2)Then check for the SYN as well as ACK flag if syc is set this means we receive the sync and hence the state is SYNRCVD,if sync and ack both are set then we sent the sync and the state is SYNCSENT.
    3)After this any ack tcp rcvd with a seq no difference of 1 takes the state to ESTABLISHED after which we get the payload and assign to byte sent or byte recvd state depending on if we sent the sync or we received the sync.
    4)The temination of connection is still to be discussed with TA for EOF part


     */

    u_int size_ip; /*Size of ip header*/
    u_int size_tcp; /*Size of tcp header*/


    
    
    // First step - check if SYN or SYN-ACK
    // All these lines should check sequence numbers on the ACK
    
    
    if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK)) {
        cout << "SYN" << endl;
        state = SYN_SENT;
        //cout << "The current state is " << state << endl;
        src = ip->ip_src;
        dest = ip->ip_dst;
        src_port = tcp->th_sport;
        dst_port = tcp->th_dport;

    } else if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
        cout << "SYN/ACK" << endl;
        state = SYN_REC;
        //cout << "The current state is " << state << endl;
        dest = ip->ip_src;
        src = ip->ip_dst;
        dst_port = tcp->th_sport;
        src_port = tcp->th_dport;

    } else if (((state == SYN_REC) || (state == SYN_SENT)) && (tcp->th_flags & TH_ACK)) {
        state = EST;
        cout << "Established." << endl;
        //cout << "The current state is " << state << endl;



    } else if (state == EST) {
        //all the manipulations for payload and bytes recvd and sent
        //ip = (struct sniff_ip*) (tcp + SIZE_ETHERNET);
        //tcp = (struct sniff_tcp*) (tcp + SIZE_ETHERNET + size_ip); /* address of tcp header located after ip header*/
        //cout << "Established!" << endl;
        size_ip = IP_HL(ip)*4;
        size_tcp = TH_OFF(tcp)*4;
        int d_size = ntohs(ip->ip_len) - size_ip - size_tcp;
        //payload = (u_char *) (tcp + SIZE_ETHERNET + size_ip + size_tcp);
        
        cout << payload << endl;
        
        

    } else{
        cout << "uhoh" << endl;
    }
    
    

return false;
//TODO implement


}




bool Connection::seenPacket() {
    return false;
    // TODO implement
}

