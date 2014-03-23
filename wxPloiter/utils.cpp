#include "utils.hpp"

#include "detours.h"
#include <ctime>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time.hpp>
#include <locale>
#include <tchar.h>
#include <wx/clipbrd.h>
#include <wx/log.h>

namespace maple
{
	HWND getwnd()
	{
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
		// thread safe singleton initialization
		// must be called in the main thread
		instance.reset(new random);
	}

	boost::shared_ptr<random> random::get()
	{
		return instance; // return a pointer to the singleton instance
	}

	random::random()
	{
		// initialize random seed
		gen.seed(static_cast<uint32_t>(std::time(0)));
	}

	random::~random()
	{
		// empty
	}

	byte random::getbyte()
	{
		return getinteger<byte>(0, 0xFF);
	}

	void random::getbytes(byte *bytes, size_t cb)
	{
		for (size_t i = 0; i < cb; i++)
			bytes[i] = getbyte();
	}

	word random::getword()
	{
		return getinteger<word>(0, 0xFFFF);
	}

	dword random::getdword()
	{
		return getinteger<dword>(-0x7FFFFFFF, 0x7FFFFFFF);
	}

	namespace asmop
	{
		byte ror(byte val, int num)
		{
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
