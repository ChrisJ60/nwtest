CC	=    gcc
CFLAGS	=    -O3
LDFLAGS	=    -O3
DEFS	=    -DLINUX
LIBS    =    -lpthread

#
#	Top-level targets
#

all:        nwtest

clean:
	rm -f *.o nwtest

nwtest:	nwtest.o nwtest_help.o nwtest_util.o nwtest_network.o nwtest_server.o nwtest_client.o
	$(CC) $(LDFLAGS) -o nwtest nwtest.o nwtest_help.o nwtest_util.o nwtest_network.o \
			   nwtest_server.o nwtest_client.o $(LIBS)

nwtest.o:	../nwtest.c ../nwtest.h
	$(CC) $(CFLAGS) $(DEFS) -I.. -c -o nwtest.o ../nwtest.c

nwtest_help.o:	../nwtest_help.c ../nwtest.h
	$(CC) $(CFLAGS) $(DEFS) -I.. -c -o nwtest_help.o ../nwtest_help.c

nwtest_util.o:	../nwtest_util.c ../nwtest.h
	$(CC) $(CFLAGS) $(DEFS) -I.. -c -o nwtest_util.o ../nwtest_util.c

nwtest_network.o:	../nwtest_network.c ../nwtest.h
	$(CC) $(CFLAGS) $(DEFS) -I.. -c -o nwtest_network.o ../nwtest_network.c

nwtest_server.o:	../nwtest_server.c ../nwtest.h
	$(CC) $(CFLAGS) $(DEFS) -I.. -c -o nwtest_server.o ../nwtest_server.c

nwtest_client.o:	../nwtest_client.c ../nwtest.h
	$(CC) $(CFLAGS) $(DEFS) -I.. -c -o nwtest_client.o ../nwtest_client.c

