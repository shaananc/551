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
#include <list>

#include "pktstruct.h"
#include "IpKey.h"

class Connection {
public:
    Connection();

    Connection(struct in_addr src, struct in_addr dest, u_short src_port, u_short dst_port, int hashCode, int id_num) {
        ;
    }

    virtual ~Connection() {
    };

    enum StateType {
        INIT = 0,
        SYN_REC = 1,
        SYN_SENT = 2,
        EST = 3,
        FIN_INIT = 4,
        FIN_WAIT1 = 5,
        FIN_WAIT2 = 6,
        CLOSING = 7,
        CLOSE_WAIT = 8,
        FIN_EST = 9,
        CLOSED = 10,
    };

private:

    bool seenPacket();

    std::vector<u_short> checksums;
    std::vector<u_int32_t> awaitingACK;
    void setState(u_short state);
    std::list<TCP> init_buf; //buffer for initiator
    std::list<TCP> recv_buf; //buffer for receiver

protected:

    IpKey key;
    
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

    int init_duplicates;
    int recv_duplicates;

    u_int id_num;


public:

    // returns whether or not contained usable payload
    // calls seenPacket();
    // updates variables (sent, recvd)
    // throw exception on invalid packet
    bool processPacket(Packet *packet);
    void initializeConnection(Packet *packet);
    std::string getState();
    void setId(int id_num);
    void setKey(IpKey key);
    IpKey getKey();
    void checktermination(Packet* packet);
    void (*deathCallback)(Connection*);

};



#endif	/* CONNECTION_H */

