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



// Takes payload sent TO server
// Dumps the actual message to 'message' and then calls parseEmail
using namespace boost;

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

void SMTPProtocol::parseEmail(string email) {
//ing namespace boost;
if(email.size()!=0)
{
std::vector<string>fields;
std::vector<string>sendorVector;
std::vector<string>fromVector;
std::vector<string>receiveVector;
std::vector<string>subjectVector;
std::vector<string>dateVector;
std::vector<string>mimeversionVector;
std::vector<string>contenttypeVector;

//string str = string(const char*)(payload);



//Split code




boost::split( fields, email, boost::is_any_of( "\n" ) );

// for (size_t n = 0; n < fields.size(); n++)
//{
  //boost::split(
  std::string goAheadField("go ahead");
if(fields[0].find(goAheadField)!=std::string::npos)
{
 // cout<<fields[0]<<endl;
  split(sendorVector,fields[1],is_any_of( "Reply-To" ));

  cout<<"We are replying to "<<sendorVector[1]<<endl;
  
  split(fromVector,fields[2],is_any_of("From:"));
 
  cout<<"The mail is from "<<fromVector[1]<<endl;

  split(receiveVector,fields[3],is_any_of("To:"));

  cout<<"The mail is directed towards"<<receiveVector[1]<<endl;

  split(subjectVector,fields[4],is_any_of("Subject:"));
  
  cout<<"The subject is"<<subjectVector[1]<<endl; 

  split(dateVector,fields[5],is_any_of("Date:"));

  cout<<"The date of email is"<<dateVector[1]<<endl;
    
  split(mimeversionVector,fields[6],is_any_of("MIME-Version:"));

  cout<<"The Mime Version of email is"<<mimeversionVector[1]<<endl;

  split(contenttypeVector,fields[7],is_any_of("Content-Type:"));

  cout<<"The Content Type of email is"<<contenttypeVector[1]<<endl;


  //cout << fields[ n ] << endl;
  //cout << endl;
}
else{
cout<<"There's some problem"<<endl;
}

//}
}
else{
cout<< "There no payload attached to it";
}
}

 
    // Email headers will be the start of the DATA segment if it starts with "Reply-To" and ends after the first BLANK newline

