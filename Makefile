CC=g++
CFLAGS=-c -Wall -fpermissive
LDFLAGS= -lpcap
SOURCES=main.cpp IpKey.cpp Connection.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=packetparse

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -lpcap -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@


