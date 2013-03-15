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

using namespace std;

class SMTPProtocol : public NetApp {
public:
    SMTPProtocol();
    SMTPProtocol(const SMTPProtocol& orig);
    virtual ~SMTPProtocol();
    
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
    int state;
    
private:
    void outputMeta();


public:

    
    void parseEmail(string email);
    virtual void clientPayload(Payload payload);
    virtual void serverPayload(Payload payload);
};

#endif	/* SMTPPROTOCOL_H */

