CC=g++
CFLAGS= -g -c -Wall -fpermissive -std=c++0x
LDFLAGS= -lpcap 
SOURCES=main.cpp IpKey.cpp IPStack.cpp TCPConnection.cpp SMTPProtocol.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=packetparse

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -std=c++0x -lpcap -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf *.o