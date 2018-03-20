CFLAGS=-g -Wall -Werror `ldns-config --cflags`
LDFLAGS=`ldns-config --libs` -Lcrypto

LDNS_ZONEDIFF_OBJECTS=\
main.o \
dns_zonediff.o

all: ldns-zonediff

ldns-zonediff: ${LDNS_ZONEDIFF_OBJECTS}
	${CC} -o ldns-zonediff ${LDNS_ZONEDIFF_OBJECTS} ${LDFLAGS} -pthread -lm

clean:
	rm -f ldns-zonediff *.o

