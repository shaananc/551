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
#include <boost/algorithm/string.hpp>
#include <iostream>
//#include <string>
#include <vector>

using namespace std;

class SMTPProtocol : public NetApp {
public:
    SMTPProtocol(){
        
    }
    
    virtual ~SMTPProtocol(){}
    
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

//    void print(std::vector<string>&v); 
    void parseEmail(string email);
    virtual void clientPayload(Payload payload);
    virtual void serverPayload(Payload payload);
};

#endif	/* SMTPPROTOCOL_H */

