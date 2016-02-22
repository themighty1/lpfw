g++FLAGS = -g -fpermissive -std=c++11 -Wfatal-errors

all: lpfw testprocess tests

clean:
	rm -rf *.o testprocess lpfw

lpfw: sha256.o conntrack.o testmain.o \
      argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      lpfw.cpp lpfw.h common/defines.h common/includes.h \
      rulesfile.o
	g++ $(g++FLAGS) sha256.o conntrack.o testmain.o \
	    argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      rulesfile.o \
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
testmain.o : testmain.cpp
	g++ $(g++FLAGS) -c testmain.cpp
rulesfile.o : rulesfile.cpp rulesfile.h
	g++ $(g++FLAGS) -c rulesfile.cpp



testprocess: testprocess.cpp
	g++ -g -std=c++11 testprocess.cpp -lpthread -o testprocess
	
tests:	rulesfile.cpp rulesfile.h rulesfile_test.cpp all_tests.cpp
	g++ -g -std=c++11 -I/home/default2/Desktop/githubrepos/lpfw/gtest/include \
	gtest/gtest-all.o gtest/libgtest.a rulesfile.cpp rulesfile_test.cpp all_tests.cpp -lpthread -o alltests

