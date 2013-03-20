/* 
 * File:   SMTPProtocol.cpp
 * Author: user
 * 
 * Created on March 14, 2013, 2:25 PM
 */

#include "SMTPProtocol.h"
#include "IpKey.h"
#include "pktstruct.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>


extern map<int, NetApp> applicationCallbacks;


// Takes payload sent FROM client

void SMTPProtocol::clientPayload(std::vector<TCP> &clientData, std::vector<TCP> &serverData) {
    //string str((const char*)payload);
    bool inMail = false;
    bool mailSent = false;
    std::vector< std::string > init_strings;
    std::vector< std::string > emails;
    std::vector<int> emailResponses;
    
    string cur_email;
    string cur_init;
    
    struct in_addr clientip;
    struct in_addr serverip;
    
    std::vector<TCP>::iterator c_ip = clientData.begin();
    if(c_ip != clientData.end()){
	clientip = c_ip->ipaddr;
    }
    std::vector<TCP>::iterator s_ip = serverData.begin();
    if(s_ip != serverData.end()){
	serverip = s_ip->ipaddr;
    }

    
   	//Parse email from client data
    std::vector<TCP>::iterator itr;
    for (itr = clientData.begin(); itr != clientData.end(); itr++) {
    	
	if (((itr->pload).compare("DATA\r\n") == 0) && (inMail == false)) {
	   for(std::vector<TCP>::iterator iter = serverData.begin(); iter != serverData.end(); iter++){
		   if(itr->ack == iter->seq){
			if((iter->pload).find("354") == 0){
			   init_strings.push_back(cur_init);
			   inMail = true;
			    cur_init.clear();
			}
		   }			
	    }
           
        } else if (inMail == true){
	   std::stringstream ss(itr->pload);
    	    std::string temp;
	    while(std::getline(ss, temp)){  //Check each line within packet for "." to indicate end of email. 
		if(temp.compare(".\r") == 0){
		   inMail = false;
		    emails.push_back(cur_email);
		    cur_email.clear();
		}		
	    }
	    
	   if(inMail == true){ //Don't want to include the last packet with "." in our output
	      cur_email.append(itr->pload);
	   }
	    
        } else {
            cur_init.append(itr->pload);
        }
    }
    
    
    if(inMail == true){ // Time-Out has occurred.
	emails.push_back(cur_email);
	cur_email.clear();
	inMail = false;
    }
	
    
    // Check sever response
    std::vector<TCP>::iterator iter;
    for (iter = serverData.begin(); iter != serverData.end(); iter++) {
	if(((iter->pload).find("354") == 0) && (mailSent == false)){
	   mailSent = true;
	} else if (mailSent == true){
	   if((iter->pload).find("250") == 0){ //email Accepted
	     mailSent = false;
	     emailResponses.push_back(1); //push 1 to indicate email accepted
	   } else { //If it's not 250, then email is rejected. There are too many codes for why an email could be rejected.
	      mailSent = false;
	      emailResponses.push_back(0); //push 0 to indicate email rejected
	   }
        }
    }
	
    
    output_emails(clientip, serverip, init_strings, emails, emailResponses);

}



void SMTPProtocol::output_emails(struct in_addr clientip, struct in_addr serverip, std::vector< std::string > init_strings,
            std::vector< std::string > emails,
            std::vector<int> emailResponses){
            	
            	
    char source_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientip, source_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &serverip, dest_addr, INET_ADDRSTRLEN);
    
    //Check if email was accepted or rejected, and Print to files!
    std::vector<int>::iterator response = emailResponses.begin();
    for(std::vector<std::string>::iterator itr = emails.begin(); itr != emails.end(); itr++){
    	file_num++;
		
	std::ostringstream filename;
	filename.str("");
	filename << file_num << ".mail";
	std::ofstream recv_file;
	recv_file.open(filename.str().c_str());
		
	recv_file << source_addr<<"\n";
	recv_file << dest_addr<<"\n";
    	recv_file << *itr <<"\n"; //Email message
    	
	if(response != emailResponses.end()){
	   if(*response == 1){
		recv_file << "ACCEPT\n";
	    } else {
		recv_file << "REJECT\n";
	    }
		response++;
	}
	
	recv_file.close();
    }
    
}


