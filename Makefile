CC=gcc
CFLAGS=-c -Wall -pedantic -std=c99 -g
LDFLAGS=
SOURCES=dnsclient.c dns.c udp.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=dns

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS)
