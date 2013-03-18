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
#include <queue>
#include <memory>

#include "pktstruct.h"
#include "IpKey.h"

class TCPConnection {
public:
    TCPConnection();

    TCPConnection(struct in_addr src, struct in_addr dest, u_short src_port, u_short dst_port, int hashCode, int id_num) {
        ;
    }

    virtual ~TCPConnection() {
        delete &key;
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

    // the once who sent the syn
    struct in_addr initiator;
    struct in_addr receiver;
    int init_port;
    int recv_port;

private:

    void setState(u_short state);
    std::vector<TCP> init_buf; //buffer for initiator
    std::vector<TCP> recv_buf; //buffer for receiver
    std::vector<std::string> clientData;
    std::vector<std::string> serverData;

protected:

    IpKey key;





    int packets_sent;
    int packets_recv;


    int bytes_recv;
    int bytes_sent;

    bool force_close;

    int init_duplicates;
    int recv_duplicates;

    u_int id_num;

    // Contains an array of pointers to the raw packet data
    //std::queue <Payload> serverData;
    //std::queue <Payload> clientData;

public:


    bool processPacket(Packet *packet);
    void initializeConnection(Packet * packet);
    std::string getState();
    void setId(int id_num);
    void setKey(IpKey key);
    IpKey getKey();
    void checktermination(Packet *packet);
    void (*deathCallback)(TCPConnection*);
    void tcpFlow();
    void writeMeta();
    void forceClose();

    u_short state;

};



#endif	/* CONNECTION_H */

