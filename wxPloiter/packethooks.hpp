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

#include "common.h"
#include "packetstruct.h"
#include "packet.hpp"
#include "logging.hpp"
#include "safeheaderlist.hpp"

#include <boost/shared_ptr.hpp>
#include <Windows.h>

namespace wxPloiter
{
	class packethooks
	{
	public:
		static boost::shared_ptr<packethooks> get();
		virtual ~packethooks();
		bool isinitialized(); // returns false if the class was unable to find the packet funcs
		void sendpacket(maple::packet &p); // injects a send packet
		void recvpacket(maple::packet &p); // injects a recv packet
		void hooksend(bool enabled);
		void hookrecv(bool enabled);

	protected:
		static const std::string tag;
		static boost::shared_ptr<packethooks> inst;

		static void injectpacket(maple::inpacket *ppacket);
		static void injectpacket(maple::outpacket *ppacket);

		boost::shared_ptr<utils::logging> log;
		bool initialized;

		static dword _stdcall handlepacket(dword isrecv, void *retaddy, int size, byte pdata[]);
		static LRESULT WINAPI DispatchMessageA_hook(_In_ const MSG *lpmsg);
		static void sendhook();
		static void recvhook();

		packethooks();
#ifdef APRILFOOLS
		static void aprilfools();
#endif
	};
}
