g++FLAGS = -g -fpermissive -std=c++11 -Wfatal-errors

all: lpfw testprocess

clean:
	rm -rf *.o testprocess lpfw

lpfw: sha256.o conntrack.o testmain.o \
      argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      lpfw.cpp lpfw.h common/defines.h common/includes.h
	g++ $(g++FLAGS) sha256.o conntrack.o testmain.o \
	    argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
	    lpfw.cpp -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

sha256.o: sha256/sha256.c sha256/sha256.h sha256/u64.h
	g++ $(g++FLAGS) -c "$<"
conntrack.o: conntrack.c conntrack.h
	g++ $(g++FLAGS) -c "$<"
argtable2.o: argtable/argtable2.c
	g++ $(g++FLAGS) -c "$<"
arg_end.o: argtable/arg_end.c
	g++ $(g++FLAGS) -c "$<"
arg_file.o: argtable/arg_file.c
	g++ $(g++FLAGS) -c "$<"
arg_int.o: argtable/arg_int.c
	g++ $(g++FLAGS) -c "$<"
arg_lit.o: argtable/arg_lit.c
	g++ $(g++FLAGS) -c "$<"
arg_rem.o: argtable/arg_rem.c
	g++ $(g++FLAGS) -c "$<"
arg_str.o: argtable/arg_str.c
	g++ $(g++FLAGS) -c "$<"
testmain.o: testmain.cpp
	g++ $(g++FLAGS) -c "$<"

%.o: %.cpp
	g++ $(g++FLAGS) -c "$<"


testprocess: testprocess.cpp
	g++ -g -std=c++11 testprocess.cpp -lpthread -o testprocess
