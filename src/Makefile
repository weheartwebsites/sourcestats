OUTBIN = sourcestats
#OBJ = GameserverEntry.o GameserverInfo.o Masterquery.o Masterserver.o MasterserverManager.o SourceStats.o util.o main.o GameStats.o ThreadedRequest.o ThreadFactory.o GameInfoQuery.o DebugLog.o DBProcessor.o GameStatsResult.o Client2MasterProt.o ServerQueries.o
OBJ = main.o Client2MasterProt.o Masterquery.o MasterserverManager.o util.o DebugLog.o ServerQueries.o DBProcessor.o

default: all

%.o: %.cpp
	g++ -I/usr/include/mysql++ -I/usr/include/mysql -c -ggdb -DDEBUG -c $<

all: ${OBJ}
	g++ -ggdb -DDEBUG -o ${OUTBIN} -pthread -lmysqlpp -lboost_system -lboost_thread *.o -lbz2

clean:
	rm -f *.o ${OUTBIN}
