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

#include "utils.hpp"

#include "detours.h"
#include <ctime>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time.hpp>
#include <locale>
#include <tchar.h>
#include <wx/clipbrd.h>
#include <wx/log.h>

#include "checksumhack.hpp"

namespace maple
{
	HWND getwnd()
	{
		CHECKSUM_HACK()
		TCHAR buf[200];
		DWORD procid;

		for (HWND hwnd = GetTopWindow(NULL); hwnd != NULL; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			GetWindowThreadProcessId(hwnd, &procid);

			if (procid != GetCurrentProcessId()) 
				continue;

			if (!GetClassName(hwnd, buf, 200)) 
				continue;

			if (_tcscmp(buf, _T("MapleStoryClass")) != 0) 
				continue;

			return hwnd;
		}

		return NULL;
	}
}

namespace utils
{
	bool copytoclipboard(wxTextDataObject *source)
	{
		CHECKSUM_HACK()
		if (!wxTheClipboard->Open())
		{
			wxLogError("Failed to open clipboard!");
			return false;
		}

		wxTheClipboard->SetData(source);
		wxTheClipboard->Close();
		return true;
	}

	namespace detours
	{
		bool hook(bool enabled, __inout PVOID *ppvTarget, __in PVOID pvDetour)
		{
			CHECKSUM_HACK()
			if (DetourTransactionBegin() != NO_ERROR)
				return false;

			do // cool trick to handle many errors with the same cleanup code
			{
				if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
					break;

				if ((enabled ? DetourAttach : DetourDetach)(ppvTarget, pvDetour) != NO_ERROR)
					break;

				if (DetourTransactionCommit() == NO_ERROR)
					return true;
			}
			while (false);

			DetourTransactionAbort();
			return false;
		}
	}

	namespace datetime
	{
		std::string utc_date()
		{
			CHECKSUM_HACK()
			namespace bg = boost::gregorian;

			static const char * const fmt = "%Y-%m-%d";
			std::ostringstream ss;
			// assumes std::cout's locale has been set appropriately for the entire app
			ss.imbue(std::locale(std::cout.getloc(), new bg::date_facet(fmt)));
			ss << bg::day_clock::universal_day();
			return ss.str();
		}

		std::string utc_time()
		{
			CHECKSUM_HACK()
			namespace pt = boost::posix_time;

			static const char * const fmt = "%H:%M:%S";
			std::ostringstream ss;
			// assumes std::cout's locale has been set appropriately for the entire app
			ss.imbue(std::locale(std::cout.getloc(), new pt::time_facet(fmt)));
			ss << pt::second_clock::universal_time();
			return ss.str();
		}
	}

	boost::shared_ptr<random> random::instance;

	void random::init()
	{
		CHECKSUM_HACK()
		// thread safe singleton initialization
		// must be called in the main thread
		instance.reset(new random);
	}

	boost::shared_ptr<random> random::get()
	{
		CHECKSUM_HACK()
		return instance; // return a pointer to the singleton instance
	}

	random::random()
	{
		CHECKSUM_HACK()
		// initialize random seed
		gen.seed(static_cast<uint32_t>(std::time(0)));
	}

	random::~random()
	{
		CHECKSUM_HACK()
		// empty
	}

	byte random::getbyte()
	{
		CHECKSUM_HACK()
		return getinteger<byte>(0, 0xFF);
	}

	void random::getbytes(byte *bytes, size_t cb)
	{
		CHECKSUM_HACK()
		for (size_t i = 0; i < cb; i++)
			bytes[i] = getbyte();
	}

	word random::getword()
	{
		CHECKSUM_HACK()
		return getinteger<word>(0, 0xFFFF);
	}

	dword random::getdword()
	{
		CHECKSUM_HACK()
		return getinteger<dword>(-0x7FFFFFFF, 0x7FFFFFFF);
	}

	namespace asmop
	{
		byte ror(byte val, int num)
		{
			CHECKSUM_HACK()
			for (int i = 0; i < num; i++)
			{
				int lowbit;

				if(val & 1)
					lowbit = 1;
				else
					lowbit = 0;

				val >>= 1; 
				val |= (lowbit << 7);
			}

			return val;
		}

		byte rol(byte val, int num)
		{
			CHECKSUM_HACK()
			int highbit;

			for (int i = 0; i < num; i++)
			{
				if(val & 0x80)
					highbit = 1;
				else
					highbit = 0;

				val <<= 1;
				val |= highbit;
			}

			return val;
		}
	}
}
