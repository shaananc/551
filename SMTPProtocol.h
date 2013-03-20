/* 
 * File:   SMTPProtocol.h
 * Author: user
 *
 * Created on March 14, 2013, 2:25 PM
 */

#ifndef SMTPPROTOCOL_H
#define	SMTPPROTOCOL_H

#include <string>
#include "IPStack.h"
#include <iostream>
//#include <string>
#include <vector>

using namespace std;

class SMTPProtocol : public NetApp {
public:

    SMTPProtocol() {

    }

    virtual ~SMTPProtocol() {
    }

    // SMTP States

    enum StateType {
        INIT = 0,
        BEGIN = 2,
        ECREAT = 3,
        RECP_SET = 4,
        WRITE = 5,
        DELV = 6

    };

    string message;
    StateType state;

private:
    void outputMeta();


public:

  
    virtual void clientPayload(std::vector<TCP> &clientData, std::vector<TCP> &serverData);
    
    void output_emails(struct in_addr clientip, struct in_addr serverip, std::vector< std::string > init_strings,
            std::vector< std::string > emails,
            std::vector<int> emailResponses);

};

#endif	/* SMTPPROTOCOL_H */

