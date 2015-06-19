CFLAGS=	-g 
#Solaris
#CFLAGS= -g -Dsys5
LDFLAGS=
LIBS = -lresolv
#Solaris
#LIBS= -lnsl -lsocket -lresolv
TARGET= dns-stress

OBJS= dns-stress.o
SRCS= dns-stress.c
HEADERS= dns-stress.h

${TARGET} : ${OBJS}
	${CC} ${CFLAGS} -o ${TARGET} ${OBJS} ${LDFLAGS} ${LIBS}

tar : clean
	tar cvf ${TARGET}.tar *
	gzip ${TARGET}.tar

clean :
	rm -f *.o a.out ${TARGET} *.core

install: ${TARGET}
	mv ${TARGET} /usr/sbin
