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

#pragma once

#include <string>
#include <sstream>
#include <fstream>
#include <boost/shared_ptr.hpp>

namespace utils
{
    // a complete logging class I copy-pasted from one of my other projects
    class logging
    {
    public:
        enum verbosity
        {
            assert = 0,
            error = 1,
            warn = 2,
            info = 3,
            debug = 4,
            verbose = 5
        };

        virtual ~logging();

		// changes the log file name. THIS IS NOT THREAD SAFE
		static void setfilename(const char * const filename);

        static boost::shared_ptr<logging> get(); // returns the singleton instance

		// sets the logging verbosity level. THIS IS NOT THREAD SAFE.
        void setverbosity(const verbosity v);

        verbosity getverbosity() const;

        bool wtf(const std::string tag, const std::string message) const;
        bool e(const std::string tag, const std::string message) const;
        bool w(const std::string tag, const std::string message) const;
        bool i(const std::string tag, const std::string message) const;
        bool d(const std::string tag, const std::string message) const;
        bool v(const std::string tag, const std::string message) const;

        bool wtf(const std::string tag, const std::basic_ostream<char> &format) const;
        bool e(const std::string tag, const std::basic_ostream<char> &format) const;
        bool w(const std::string tag, const std::basic_ostream<char> &format) const;
        bool i(const std::string tag, const std::basic_ostream<char> &format) const;
        bool d(const std::string tag, const std::basic_ostream<char> &format) const;
        bool v(const std::string tag, const std::basic_ostream<char> &format) const;

    protected:
        static const char * const tag;
        static const char * filename;
		static boost::shared_ptr<logging> inst;

        verbosity verb;

        logging(); // ensures there is no way to construct more than one singleton instance
        bool openfile(std::ofstream &f, const std::fstream::openmode mode = std::fstream::out) const;
        bool puts(const char * const text) const;
        bool log(const verbosity v, const std::string tag, const std::string message) const;
        bool log(const verbosity v, const std::string tag, const std::basic_ostream<char> &format) const;
    };
}
