all: packetparse

packetparse: connection.o
	g++ -g main.cc ./build/Connection.o -lpcap -o packetparse -fpermissive
	
	

connection.o:
	g++ -c Connection.cc -o ./build/Connection.o
