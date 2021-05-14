#include "polyhook2/ErrorLog.hpp"

#include <cstdarg>

std::shared_ptr<PLH::Logger> PLH::Log::m_logger = nullptr;

void PLH::Log::registerLogger(std::shared_ptr<Logger> logger) {
	m_logger = logger;
}

void PLH::Log::log(const std::string& msg, ErrorLevel level) {
	if (m_logger) m_logger->log(msg, level);
}
	
void PLH::Log::log(PLH::ErrorLevel level, const char* fmt, ...){
	constexpr int MAX_LOG_MSG_SIZE = 2048;

	std::va_list args;
    va_start(args, fmt);

    char buf[MAX_LOG_MSG_SIZE];
    vsprintf_s(buf, fmt, args);
    va_end(args);

	log(buf, level);
}

void PLH::ErrorLog::setLogLevel(PLH::ErrorLevel level) {
	m_logLevel = level;
}

void PLH::ErrorLog::log(const std::string& msg, ErrorLevel level)
{
	push({ msg, level });
}

void PLH::ErrorLog::push(const std::string& msg, ErrorLevel level)
{
	push({ msg, level });
}

void PLH::ErrorLog::push(PLH::Error err) {
	if (err.lvl >= m_logLevel) {
		switch (err.lvl) {
		case ErrorLevel::INFO:
			std::cout << "[+] Info: " << err.msg << std::endl;
			break;
		case ErrorLevel::WARN:
			std::cout << "[!] Warn: " << err.msg << std::endl;
			break;
		case ErrorLevel::SEV:
			std::cout << "[!] Error: " << err.msg << std::endl;
			break;
		default:
			std::cout << "Unsupported error message logged " << err.msg << std::endl;
		}
	}

	m_log.push_back(std::move(err));
}

PLH::Error PLH::ErrorLog::pop() {
	Error err{};
	if (!m_log.empty()) {
		err = m_log.back();
		m_log.pop_back();
	}
	return err;
}

PLH::ErrorLog& PLH::ErrorLog::singleton() {
	static ErrorLog log;
	return log;
}
