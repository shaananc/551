/* 
 * File:   SMTPProtocol.cpp
 * Author: user
 * 
 * Created on March 14, 2013, 2:25 PM
 */

#include "SMTPProtocol.h"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>


// Takes payload sent TO server
// Dumps the actual message to 'message' and then calls parseEmail
using namespace boost;

extern map<int, NetApp> applicationCallbacks;

void SMTPProtocol::serverPayload(Payload payload) {

    string str((const char*) payload);
    //unsigned foundInit;
    if (state == WRITE) {
        if (str.compare(".\n")) {
            // finish email
            // process email
            state = BEGIN;
            parseEmail(message);
        }
        message.append(str);
        cout << message << endl;
    } else if ((str.find("HELO") || str.find("EHLO")) != std::string::npos) {
        state = BEGIN;
    } else if (str.find("MAIL FROM") != std::string::npos && state == BEGIN) {
        state = ECREAT;
    } else if (str.find("RCPT TO") != std::string::npos && state == ECREAT) {
        state = RECP_SET;
    } else if (str.find("DATA") != std::string::npos && state == RECP_SET) {
        state = WRITE;
    } else if (str.find("RSET") != std::string::npos) {
        state = INIT;
    }



}



// Takes payload sent FROM client

void SMTPProtocol::clientPayload(std::vector<std::string> &clientData, std::vector<std::string> &serverData) {
    //string str((const char*)payload);
    bool inMail = false;
    bool mailSent = false;
    std::vector< std::string > init_strings;
    std::vector< std::string > emails;
    std::vector<int> emailResponses;
    
    string cur_email;
    string cur_init;
    
    std::vector<std::string>::iterator itr;
    for (itr = clientData.begin(); itr != clientData.end(); itr++) {
        
        if (((*itr).compare("DATA\r\n") == 0) && (inMail == false)) {
            init_strings.push_back(cur_init);
            inMail = true;
            cur_init.clear();
        } else if (inMail == true){
            std::stringstream ss(*itr);
    	    std::string temp;
	    /*Check each line within packet for "." to indicate end of email. 
	    There is some other junk in the packet from IMF protocol. */
	    while(std::getline(ss, temp)){  
		if(temp.compare(".\r") == 0){
		  inMail = false;
		  emails.push_back(cur_email);
		  cur_email.clear();
		}		
	    }
	    
	    if(inMail == true){ //Don't want to include the last packet with "." in our output
		cur_email.append(*itr);
	    }
	    
        } else {
            cur_init.append(*itr);
        }
    }
    
    // Temp to check
    /*
    for(itr = init_strings.begin(); itr != init_strings.end(); itr++){
        cout << *itr << endl;
    }
    */
    
    std::vector<std::string>::iterator iter;
    for (iter = serverData.begin(); iter != serverData.end(); iter++) {
	if(((*iter).find("354") == 0) && (mailSent == false)){
	   mailSent = true;
	} else if (mailSent == true){
	   if((*iter).find("250 OK") == 0){ //email Accepted
		mailSent = false;
		emailResponses.push_back(1); //push 1 to indicate email accepted
	   } else { //If it's not 250, then email is rejected. There are too many codes for why an email could be rejected.
		mailSent = false;
		emailResponses.push_back(0); //push 0 to indicate email rejected
	   }
        }
     }
     
     
 //TODO: check the emails in emails buffer with the corresponding acknowledgements in emailResponses buffer to print if an email is accepted or rejected.

}

//Takes payload sent FROM server
/*void SMTPProtocol::serverPayload(std::vector<std::string> &serverData) {
    
}*/


// Reads email header

void SMTPProtocol::parseEmail(string email) {
    //ing namespace boost;
    if (email.size() != 0) {
        std::vector<string>fields;
        std::vector<string>sendorVector;
        std::vector<string>fromVector;
        std::vector<string>receiveVector;
        std::vector<string>subjectVector;
        std::vector<string>dateVector;
        std::vector<string>mimeversionVector;
        std::vector<string>contenttypeVector;
        std::vector<string>xmailerVector;
        std::vector<string>threadIndexVector;
        std::vector<string>xmimeOleVector;
        std::vector<string>emailbodyVector;
        //string str = string(const char*)(payload);



        //Split code




        boost::split(fields, email, boost::is_any_of("\n"));

        // for (size_t n = 0; n < fields.size(); n++)
        //{
        //boost::split(
        std::string goAheadField("354 go ahead");
        if (fields[0].find(goAheadField) != std::string::npos) {
            // cout<<fields[0]<<endl;
            split(sendorVector, fields[1], is_any_of(":"));

            cout << "We are replying to " << sendorVector[1] << endl;

            split(fromVector, fields[2], is_any_of(":"));

            cout << "The mail is from " << fromVector[1] << endl;

            split(receiveVector, fields[3], is_any_of(":"));

            cout << "The mail is directed towards" << receiveVector[1] << endl;

            split(subjectVector, fields[4], is_any_of(":"));

            cout << "The subject is" << subjectVector[1] << endl;

            split(dateVector, fields[5], is_any_of(":"));

            cout << "The date of email is" << dateVector[1] << endl;

            split(mimeversionVector, fields[6], is_any_of(":"));

            cout << "The Mime Version of email is" << mimeversionVector[1] << endl;

            split(contenttypeVector, fields[7], is_any_of(":"));

            cout << "The Content Type of email is" << contenttypeVector[1] << endl;

            split(xmailerVector, fields[9], is_any_of(":"));

            cout << "The X-Mailer Type of email is" << xmailerVector[1] << endl;

            split(threadIndexVector, fields[10], is_any_of(":"));

            cout << "The Thread Index of email is" << threadIndexVector[1] << endl;

            split(xmimeOleVector, fields[11], is_any_of(":"));

            cout << "The xmimeOle Type of email is" << xmimeOleVector[1] << endl;

            //cout << fields[ n ] << endl;
            //cout << endl;
        } else {
            cout << "There's some problem" << endl;
        }
        split(emailbodyVector, email, is_any_of("This is a multi-part message in MIME format."));
        cout << "the body content is " << emailbodyVector[1] << endl;
        //}
    } else {
        cout << "There no payload attached to it";
    }
}


// Email headers will be the start of the DATA segment if it starts with "Reply-To" and ends after the first BLANK newline

