CC=g++
CFLAGS= -g -c -Wall -fpermissive
LDFLAGS= -lpcap
SOURCES=main.cpp IpKey.cpp IPStack.cpp Connection.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=packetparse

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -lpcap -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf *.o