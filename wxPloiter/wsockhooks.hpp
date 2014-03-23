#pragma once

#include "safeheaderlist.hpp"
#include "crypt.hpp"
#include "logging.hpp"

#include <string>
#include <Windows.h>
#include <boost/shared_ptr.hpp>

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
		typedef boost::mutex mutex;
		mutex sendmut;
		mutex recvmut;

		// trampoline typedefs
		typedef int (WINAPI *pfnconnect)
			(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen);

		typedef int (WINAPI *pfnsend)
			(_In_ SOCKET s, _In_ const char *buf, _In_ int len, _In_ int flags);

		typedef int (WINAPI *pfnrecv)
			(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);

		// trampolines
		pfnconnect pconnect;
		pfnsend psend;
		pfnrecv precv;

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
