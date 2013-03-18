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


// Takes payload sent TO server
// Dumps the actual message to 'message' and then calls parseEmail
using namespace boost;

extern map<int, NetApp> applicationCallbacks;

void SMTPProtocol::serverPayload(Payload payload) {
    
string str((const char*) payload);
//unsigned foundInit;
if (state == WRITE){
    if(str.compare(".\n")){
        // finish email
        // process email
        state = BEGIN;
        parseEmail(message);
    }
    message.append(str);
    cout << message << endl;
}
else if((str.find("HELO")||str.find("EHLO"))!=std::string::npos)
{
state = BEGIN;
}
else if(str.find("MAIL FROM")!=std::string::npos && state ==BEGIN)
{
state = ECREAT;
}
else if(str.find("RCPT TO")!=std::string::npos && state == ECREAT)
{
state = RECP_SET;
}
else if(str.find("DATA")!=std::string::npos && state == RECP_SET)
{
state = WRITE;
}
else if(str.find("RSET")!=std::string::npos)
{
state = INIT;
}



}



// Takes payload sent FROM client

void SMTPProtocol::clientPayload(std::vector<std::string> &clientData) {
    //string str((const char*)payload);
}

//Takes payload sent FROM server
/*void SMTPProtocol::serverPayload(std::vector<std::string> &serverData) {
    
}*/


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
std::vector<string>xmailerVector;
std::vector<string>threadIndexVector;
std::vector<string>xmimeOleVector;
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
  split(sendorVector,fields[1],is_any_of( ":" ));

  cout<<"We are replying to "<<sendorVector[1]<<endl;
  
  split(fromVector,fields[2],is_any_of(":"));
 
  cout<<"The mail is from "<<fromVector[1]<<endl;

  split(receiveVector,fields[3],is_any_of(":"));

  cout<<"The mail is directed towards"<<receiveVector[1]<<endl;

  split(subjectVector,fields[4],is_any_of(":"));
  
  cout<<"The subject is"<<subjectVector[1]<<endl; 

  split(dateVector,fields[5],is_any_of(":"));

  cout<<"The date of email is"<<dateVector[1]<<endl;
    
  split(mimeversionVector,fields[6],is_any_of(":"));

  cout<<"The Mime Version of email is"<<mimeversionVector[1]<<endl;

  split(contenttypeVector,fields[7],is_any_of(":"));

  cout<<"The Content Type of email is"<<contenttypeVector[1]<<endl;

  split(xmailerVector,fields[9],is_any_of(":"));

  cout<<"The X-Mailer Type of email is"<<xmailerVector[1]<<endl;

  split(threadIndexVector,fields[10],is_any_of(":"));

  cout<<"The Thread Index of email is"<<threadIndexVector[1]<<endl;
  
  split(xmimeOleVector,fields[11],is_any_of(":"));

  cout<<"The xmimeOle Type of email is"<<xmimeOleVector[1]<<endl;

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

