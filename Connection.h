/* 
 * File:   Connection.h
 * Author: Shaanan Cohney
 *
 * Created on March 1, 2013, 6:30 AM
 */

#ifndef CONNECTION_H
#define	CONNECTION_H


#include <iostream>
#include <sys/types.h>
#include <vector>
#include <string>

#include "pktstruct.h"
#include "IpKey.h"

class Connection {
public:
    Connection();

    Connection(struct in_addr src, struct in_addr dest, u_short src_port, u_short dst_port, int hashCode) {
        ;
    }

    virtual ~Connection() {
    };

    enum StateType {
        SYN_REC = 1,
        SYN_SENT = 2,
        EST = 3,
    };

private:

    bool seenPacket();

    std::vector<u_short> checksums;
    std::vector<u_int32_t> awaitingACK;
    void setState(u_short state);

protected:

    // the once who sent the syn
    struct in_addr initiator;
    struct in_addr receiver;
    u_short init_port;
    u_short recv_port;

    u_short state;

    int packets_sent;
    int packets_recv;


    int bytes_recv;
    int bytes_sent;

    bool force_close;


public:

    // returns whether or not contained usable payload
    // calls seenPacket();
    // updates variables (sent, recvd)
    // throw exception on invalid packet
    bool processPacket(struct sniff_tcp *tcp, struct sniff_ip *ip, u_char *payload);
    void initializeConnection(struct sniff_tcp *tcp, struct sniff_ip *ip);
    std::string getState();

//    friend std::ostream& operator<<(std::ostream &out, Connection & c) {
//        char src_s[INET_ADDRSTRLEN];
//        char dst_s[INET_ADDRSTRLEN];
//        inet_ntop(AF_INET, c.initiator, src_s, INET_ADDRSTRLEN);
//        inet_ntop(AF_INET, c.receiver, dst_s, INET_ADDRSTRLEN);
//
//        //std::cout << "Initiator: " << src_s << " on port" << c. << std::endl;
//        //std::cout << "Receiver: " << dst_s << " on port" << c. << std::endl;
//    }

};



#endif	/* CONNECTION_H */

