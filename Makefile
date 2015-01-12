DESTDIR = ./
DEBUG =
g++FLAGS = -g -fpermissive -std=c++11 -Wfatal-errors

#SOURCES 	=	lpfw.c \
#			lpfw.h \
#			msgq.h \
#			test.c \
#			test.h \
#			sha512/sha.c \
#			argtable/arg_end.c \
#			argtable/arg_file.c \
#			argtable/arg_int.c \
#			argtable/arg_lit.c \
#			argtable/arg_rem.c \
#			argtable/arg_str.c \
#			argtable/argtable2.c \
#			common/includes.h \
#			common/defines.h \

ifeq ($(DESTDIR), ./)
    DESTDIR = $(shell pwd)
endif

all: lpfw testprocess

lpfw: sha256.o base64.o conntrack.o testmain.o \
      argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      lpfw.cpp lpfw.h common/defines.h common/includes.h
	g++ $(g++FLAGS) sha256.o base64.o conntrack.o testmain.o \
	    argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
	    lpfw.cpp -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

sha256.o : sha256/sha256.c sha256/sha256.h sha256/u64.h
	g++ $(g++FLAGS) -c sha256/sha256.c
base64.o : base64.cpp base64.h
	g++ $(g++FLAGS) -c base64.cpp
conntrack.o : conntrack.c conntrack.h
	g++ $(g++FLAGS) -c conntrack.c
argtable2.o : argtable/argtable2.c
	g++ $(g++FLAGS) -c argtable/argtable2.c
arg_end.o : argtable/arg_end.c
	g++ $(g++FLAGS) -c argtable/arg_end.c
arg_file.o : argtable/arg_file.c
	g++ $(g++FLAGS) -c argtable/arg_file.c
arg_int.o : argtable/arg_int.c
	g++ $(g++FLAGS) -c argtable/arg_int.c
arg_lit.o : argtable/arg_lit.c
	g++ $(g++FLAGS) -c argtable/arg_lit.c
arg_rem.o : argtable/arg_rem.c
	g++ $(g++FLAGS) -c argtable/arg_rem.c
arg_str.o : argtable/arg_str.c
	g++ $(g++FLAGS) -c argtable/arg_str.c
testmain.o : testmain.cpp
	g++ $(g++FLAGS) -c testmain.cpp


lpfwpygui:
	cd lpfw-pygui; make $(DEBUG); make DESTDIR=$(DESTDIR) install

debug: g++FLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: DESTDIR = $(shell pwd)
debug: DEBUG = debug
debug: lpfw install lpfwpygui


clean:
	rm sha.o \
	argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o
	
testprocess: testprocess.cpp
	g++ -g -std=c++11 testprocess.cpp -lpthread -o testprocess
	
