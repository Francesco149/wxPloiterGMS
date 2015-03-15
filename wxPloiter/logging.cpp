/*
	Copyright 2014 Francesco "Franc[e]sco" Noferi (francesco149@gmail.com)

	This file is part of wxPloiter.

	wxPloiter is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	wxPloiter is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with wxPloiter. If not, see <http://www.gnu.org/licenses/>.
*/

#include "logging.hpp"

#include "checksumhack.hpp"
#include "utils.hpp"
#include <typeinfo>
#include <iostream>

// a complete logging class I copy-pasted from one of my other projects
namespace utils
{
    // static members
    const char * const logging::tag = "utils::logging";
	const char * logging::filename = "lastsession.log";
	boost::shared_ptr<logging> logging::inst;

    logging::logging()
        : verb(info)
    {
		CHECKSUM_HACK()
        // initialize empty logging file
        std::ofstream f;

        if (openfile(f, std::fstream::out | std::fstream::trunc))
            f.close();
    }

    logging::~logging()
    {
		CHECKSUM_HACK()
        // empty
    }

	void logging::setfilename(const char * const filename)
	{
		CHECKSUM_HACK()
		logging::filename = filename;
	}

	boost::shared_ptr<logging> logging::get()
    {
		CHECKSUM_HACK()
		if (!inst.get())
			inst.reset(new logging);

        return inst;
    }

    void logging::setverbosity(const logging::verbosity v)
    {
		CHECKSUM_HACK()
        log(logging::info, tag, strfmt() << "setverbosity: setting log verbosity to " << static_cast<int>(v));
        this->verb = v;
    }

    logging::verbosity logging::getverbosity() const
    {
		CHECKSUM_HACK()
        return verb;
    }

    bool logging::wtf(const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::assert))
            return log(logging::assert, tag, message);

        return true; // no errors, but it won't log anything because of verbosity
    }

    bool logging::e(const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::error))
            return log(logging::error, tag, message);

        return true;
    }

    bool logging::w(const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::warn))
            return log(logging::warn, tag, message);

        return true;
    }

    bool logging::i(const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::info))
            return log(logging::info, tag, message);

        return true;
    }

    bool logging::d(const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::debug))
            return log(logging::debug, tag, message);

        return true;
    }

    bool logging::v(const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::verbose))
            return log(logging::verbose, tag, message);

        return true;
    }

    bool logging::wtf(const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::assert))
            return log(logging::assert, tag, format);

        return true;
    }

    bool logging::e(const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::error))
            return log(logging::error, tag, format);

        return true;
    }

    bool logging::w(const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::warn))
            return log(logging::warn, tag, format);

        return true;
    }

    bool logging::i(const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::info))
            return log(logging::info, tag, format);

        return true;
    }

    bool logging::d(const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::debug))
            return log(logging::debug, tag, format);

        return true;
    }

    bool logging::v(const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        if (static_cast<int>(verb) >= static_cast<int>(logging::verbose))
            return log(logging::verbose, tag, format);

        return true;
    }

    bool logging::openfile(std::ofstream &f, const std::fstream::openmode mode) const
    {
		CHECKSUM_HACK()
        f.open(filename, mode);

        if (!f.is_open())
        {
            std::cout << "logging.openfile: failed to open log file." << std::endl;
            return false;
        }

        return true;
    }

    // appends text to the log file
    bool logging::puts(const char * const text) const
    {
		CHECKSUM_HACK()
        std::ofstream f;

        if (!openfile(f, std::fstream::out | std::fstream::app))
            return false;

        f << text;

        // define LOGCONSOLE to also send log messages to stdout
        #ifdef LOGCONSOLE
        std::cout << text;
        #endif

        if (f.bad())
        {
            std::cout << "logging.openfile: failed to write to log file." << std::endl;
            return false;
        }

        f.close();

        return true;
    }

    // logs something in the format <verbosity> [tag] message
    bool logging::log(const logging::verbosity v, const std::string tag, const std::string message) const
    {
		CHECKSUM_HACK()
        const char * verbositytag;
        std::ostringstream oss;

        // converts verbosity to text
        switch (v)
        {
        case assert:
            verbositytag = "assert";
            break;

        case error:
            verbositytag = "error";
            break;

        case warn:
            verbositytag = "warn";
            break;

        case info:
            verbositytag = "info";
            break;

        case debug:
            verbositytag = "debug";
            break;

        case verbose:
            verbositytag = "verbose";
            break;

        default:
            verbositytag = "invalid";
            wtf(this->tag, strfmt() << "log: invalid verbosity of " << static_cast<int>(v) << " provided");
            break;
        }

        oss << "<" << verbositytag << "> [" << tag << "] " << message << "\r\n";
        return puts(oss.str().c_str());
    }

    // this overload allows me to format messages on-the-fly like this: log(v, tag, strfmt() << "foo" << bar)
    bool logging::log(const verbosity v, const std::string tag, const std::basic_ostream<char> &format) const
    {
		CHECKSUM_HACK()
        // obtain the stream's streambuf and cast it back to stringbuf
        std::basic_streambuf<char> * const strbuf = format.rdbuf();

        if (strbuf && typeid(*strbuf) == typeid(std::stringbuf))
        {
            const std::string &str = dynamic_cast<std::stringbuf &>(*strbuf).str();
            return log(v, tag, str);
        }

        wtf(this->tag, "log: invalid stringstream provided");

        return false;
    }
}
