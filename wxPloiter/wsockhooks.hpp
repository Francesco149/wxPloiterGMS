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

#include "safeheaderlist.hpp"
#include "crypt.hpp"
#include "logging.hpp"

#include <string>
#include <Windows.h>
#include <Winsock2.h>
#include <boost/shared_ptr.hpp>
#include <vector>

#define STEALTH_HOOKS

namespace wxPloiter
{
	// hooks winsock connect/recv/send, grabs cypher keys
	// and decrypts packets
	class wsockhooks
	{
	public:
		static boost::shared_ptr<wsockhooks> get();
		virtual ~wsockhooks();

		// returns true if the hooks are correctly set
		bool ishooked();

	protected:
		static const std::string tag;
		static const size_t header_size; // size of encrypted headers

		static boost::shared_ptr<wsockhooks> inst;

		// these should prevent concurrent packets from messing up the keys
#ifdef WINSOCK_MUTEX
		typedef boost::mutex mutex;
		mutex sendmut;
		mutex recvmut;
#endif

		std::vector<byte> recvbuf;
		std::vector<byte> sendbuf;

		// trampoline typedefs
		typedef int (WINAPI *pfnconnect)
			(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen);

		typedef int (WINAPI *pfnsend)
			(_In_ SOCKET s, _In_ const char *buf, _In_ int len, _In_ int flags);

		typedef int (WINAPI *pfnrecv)
			(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);

		// microsoft pls stop using those ugly naming conventions

		// trampolines
		pfnconnect pconnect;
		pfnsend psend;
		pfnrecv precv;

#ifdef STEALTH_HOOKS
		static dword connecthookret;
		static dword sendjump1;
		static dword sendhookret;
		static dword sendmov1;
		static dword sendcmp1;
		static dword recvjump1;
		static dword recvhookret;

		static void _pconnect();
		static void _psend();
		static void _precv();
		static void connect_relay();
		static void send_relay();
		static void recv_relay();
#endif

		// hooks
		static int WINAPI connect_hook(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen);
		static int WINAPI send_hook(_In_ SOCKET s, _In_ const char *buf, _In_ int len, _In_ int flags);
		static int WINAPI recv_hook(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);

		boost::shared_ptr<utils::logging> log;
		bool transition; // true when moving from loginserver to channel server and stuff like that
		SOCKET targetsocket; // currently active socket
		bool hooked;
		boost::shared_ptr<maple::crypt> sendcrypt; // send decoder
		boost::shared_ptr<maple::crypt> recvcrypt; // recv decoder

		wsockhooks();

		int connect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen);
		int send(_In_ SOCKET s, _In_ const char *buf, _In_ int len, _In_ int flags);
		int recv(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);
	};
}
