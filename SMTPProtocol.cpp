/* 
 * File:   SMTPProtocol.cpp
 * Author: user
 * 
 * Created on March 14, 2013, 2:25 PM
 */

#include "SMTPProtocol.h"




// Takes payload sent TO server
// Dumps the actual message to 'message' and then calls parseEmail

void SMTPProtocol::serverPayload(Payload payload) {
    string str((const char*) payload);
    if ((str.compare(0, 3, "HELO") == 0 || str.compare(0, 3, "EHLO")) && state == INIT) {
        state = INIT;
    } else if (str.compare(0, 8, "MAIL FROM") == 0 && state == BEGIN) {
        state = ECREAT;
    } else if (str.compare(0, 6, "RCPT TO") == 0 && state == ECREAT) {
        state = RECP_SET;
    } else if (str.compare(0, 3, "DATA") == 0 && state == RECP_SET) {
        state = WRITE;
    } else if (str.compare(0, 3, "RSET") == 0) {
        state = INIT;

    }
}

// Takes payload sent TO client

void SMTPProtocol::clientPayload(Payload payload) {
    string str((const char*)payload);
}

// Reads email header

void parseEmail(string email) {
    // Email headers will be the start of the DATA segment if it starts with "Reply-To" and ends after the first BLANK newline
}
