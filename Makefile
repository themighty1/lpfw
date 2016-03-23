g++FLAGS = -g -fpermissive -std=c++11 -Wfatal-errors
gtestInclude = -Igtest/include
gtestFLAGS = $(g++FLAGS) $(gtestInclude)
gtestLinkFLAGS = gtest/gtest-all.o gtest/libgtest.a $(gtestInclude)

.PHONY: all clean tests

all: lpfw testprocess tests

clean: rm -rf *.o testprocess lpfw alltests testexe

lpfw: sha256.o conntrack.o \
      argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      lpfw.cpp lpfw.h common/defines.h common/includes.h \
      rulesfile.o ruleslist.o removeterminatedprocess.o
	g++ $(g++FLAGS) sha256.o conntrack.o testmain.o \
	    argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      rulesfile.o ruleslist.o removeterminatedprocess.o\
	    lpfw.cpp -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

sha256.o : sha256/sha256.c sha256/sha256.h sha256/u64.h
	g++ $(g++FLAGS) -c sha256/sha256.c
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
rulesfile.o : rulesfile.cpp rulesfile.h
	g++ $(g++FLAGS) -c rulesfile.cpp
rulesfile_test.o : rulesfile.o rulesfile_test.cpp
	g++ $(gtestFLAGS) -c rulesfile_test.cpp
ruleslist.o : ruleslist.cpp ruleslist.h sha256.o
	g++ $(g++FLAGS) -c ruleslist.cpp
ruleslist_test.o : ruleslist.o ruleslist_test.cpp
	g++ $(gtestFLAGS) -c ruleslist_test.cpp
removeterminatedprocess.o : removeterminatedprocess.cpp removeterminatedprocess.h
	g++ $(g++FLAGS) -c removeterminatedprocess.cpp
testexe : unix_socket.o testexe.cpp
	g++ $(g++FLAGS) testexe.cpp unix_socket.o -o testexe
unix_socket.o : unix_socket.cpp unix_socket.h
	g++ $(g++FLAGS) -c unix_socket.cpp




testprocess: testprocess.cpp
	g++ -g -std=c++11 testprocess.cpp -lpthread -o testprocess
	
tests:	all_tests.cpp rulesfile_test.o ruleslist_test.o unix_socket.o testexe
	g++ $(g++FLAGS) $(gtestLinkFLAGS) \
	rulesfile.o rulesfile_test.o ruleslist.o sha256.o ruleslist_test.o unix_socket.o \
	all_tests.cpp -lpthread -o alltests

