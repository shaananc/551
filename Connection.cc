#include <iostream>
#include "Connection.h"

using namespace std;
#define SIZE_ETHERNET 14
#define MAC_STRING_SIZE 19


Connection::Connection(){
    ;
}

bool Connection::processPacket(struct sniff_tcp *packet,struct sniff_ip *packet2, u_char *payload)
{
/*
The logic goes like this 
1)I see a packet i check whether its part of vector of sequence no.If no I add it to the vector of sequence nos as well as checksums.If it not present its not a duplicate and I add it to the vector,other wise print that its duplicate
2)Then check for the SYN as well as ACK flag if syc is set this means we receive the sync and hence the state is SYNRCVD,if sync and ack both are set then we sent the sync and the state is SYNCSENT.
3)After this any ack packet rcvd with a seq no difference of 1 takes the state to ESTABLISHED after which we get the payload and assign to byte sent or byte recvd state depending on if we sent the sync or we received the sync.
4)The temination of connection is still to be discussed with TA for EOF part


*/
int payload_size;
int checksum_value;
char valid;
int num_total_packets;
int num_tpackets;
int num_upackets;
int num_opackets;

u_int size_ip; /*Size of ip header*/
u_int size_tcp; /*Size of tcp header*/
u_int size_udp; /*Size of udp header*/


u_int32_t duplicate_cnt;
u_short tmpseq_no = packet->th_seq;
StateType type;

//Change checksum vector to seqNo Vector
for(std::vector<u_int32_t>::iterator it = sequenceNo.begin();it!= sequenceNo.end();++it)
{
if(packet->th_seq==*it)
{
cout<< "Duplicate packet received.\n";
duplicate_cnt++;
}
else
{
sequenceNo.push_back(packet->th_seq);
if((packet->th_flags & TH_SYN)== TH_SYN)
   {
    cout<<"I received a SYNC request\n";
    type = SYN_SENT;
    cout<<"The current state is "<<type;
    src = packet2->ip_src;
    dest = packet2->ip_dst;
    src_port = packet->th_sport;
    dst_port = packet->th_dport;

   }
else if (((packet->th_flags & TH_SYN) == TH_SYN) && (( packet->th_flags & TH_ACK ) == TH_ACK ))
    { 
    type = SYN_REC;
    cout<<"The current state is "<<type;
    dest = packet2->ip_src;
    src = packet2->ip_dst;
    dst_port = packet->th_sport;
    src_port = packet->th_dport;

    }   
else if(((type = SYN_REC) || (type = SYN_SENT)) && (packet->th_flags & TH_ACK) == TH_ACK)
    {
    type = EST;
    cout<<"The current state is "<<type;
    


    }
else if(type = EST )
{ 
//all the manipulations for payload and bytes recvd and sent
 //ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
 //tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip); /* address of tcp header located after ip header*/

 size_ip =IP_HL(packet2)*4;
 size_tcp = TH_OFF(packet)*4; 
int d_size = ntohs(packet2->ip_len) - size_ip - size_tcp;
payload_size = d_size;
 
 //payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

}


 
}
}
}
bool Connection::seenPacket()
{
;
}

