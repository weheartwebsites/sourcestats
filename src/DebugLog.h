#ifndef DEBUGLOG_H
#define DEBUGLOG_H


class DebugLog
{
public:
	DebugLog() { }
	~DebugLog() { }

	virtual void Log( const char* logMsg );
	virtual void Log( const char* logMsg , const char *id_tag);
	virtual void LogNoDeadLock( const char* logMsg );
};

#endif // DEBUGLOG_H
