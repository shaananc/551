/* 
 * File:   SMTPProtocol.h
 * Author: user
 *
 * Created on March 14, 2013, 2:25 PM
 */

#ifndef SMTPPROTOCOL_H
#define	SMTPPROTOCOL_H

class SMTPProtocol : public ApplicationProtocol {
public:
    SMTPProtocol();
    SMTPProtocol(const SMTPProtocol& orig);
    virtual ~SMTPProtocol();
    
    // SMTP States
      enum StateType {
    
    };
    
private:
    void outputMeta();


public:
    void processPayload(u_char *payload);
    

};

#endif	/* SMTPPROTOCOL_H */

