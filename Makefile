#
# Makefile to compile Project Titor
#

CC=g++
CPPFLAGS=-I include
LDLIBS= -Wl,-Bstatic -lcryptopp -Wl,-Bdynamic

DEPS=titor.o src/arguments.o src/pem-com.o src/pem-rd.o src/pem-wr.o src/shinfi.o

all: titor

titor: $(DEPS)

clean:
	rm $(DEPS)
