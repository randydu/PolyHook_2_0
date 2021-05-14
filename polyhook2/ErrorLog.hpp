#ifndef POLYHOOK_2_0_ERRORLOG_HPP
#define POLYHOOK_2_0_ERRORLOG_HPP

#include <vector>
#include <string>
#include <iostream>
#include "polyhook2/Enums.hpp"

namespace PLH {

// abstract base class for logging, clients should subclass this to intercept log messages
class Logger
{
public:
	virtual void log(const std::string& msg, ErrorLevel level) = 0;
	virtual ~Logger() {};
};

// class for registering client loggers
class Log
{
private:
	static std::shared_ptr<Logger> m_logger;
public:
	static void registerLogger(std::shared_ptr<Logger> logger);
	static void log(const std::string& msg, ErrorLevel level);
	static void log(ErrorLevel level, const char* fmt, ...);
};


#define PLH_LOG(level, fmt, ...) do { PLH::Log::log(PLH::ErrorLevel::##level, fmt, ##__VA_ARGS__); } while(0)

#define PLH_INFO(fmt, ...) PLH_LOG(INFO, fmt, ##__VA_ARGS__)
#define PLH_WARN(fmt, ...) PLH_LOG(WARN, fmt, ##__VA_ARGS__)
#define PLH_ERROR(fmt, ...) PLH_LOG(SEV, fmt, ##__VA_ARGS__)

// simple logger implementation

struct Error {
	std::string msg;
	ErrorLevel lvl;
};

class ErrorLog : public Logger {
public:
	void setLogLevel(ErrorLevel level);
	virtual void log(const std::string& msg, ErrorLevel level) override;
	void push(const std::string& msg, ErrorLevel level);
	void push(Error err);
	Error pop();
	static ErrorLog& singleton();
private:
	std::vector<Error> m_log;
	ErrorLevel m_logLevel = ErrorLevel::INFO;
};

}

#endif
