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
#include "pktstruct.h"
#include "IpKey.h"


class Connection {
public:
    Connection();

    Connection(struct in_addr src, struct in_addr dest, u_short src_port, u_short dst_port, int hashCode){;}

    virtual ~Connection(){};

    enum StateType {
        SYN_REC = 1,
        SYN_SENT = 2,
        EST = 3,
    };

private:

    bool seenPacket();

    std::vector<u_short> checksums;
    std::vector<u_int32_t> sequenceNo;
    void setState(u_short state);

protected:

    struct in_addr src;
    struct in_addr dest;
    u_short src_port;
    u_short dst_port;

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



};

bool operator<(const Connection& lhs, const Connection& rhs);


#endif	/* CONNECTION_H */

