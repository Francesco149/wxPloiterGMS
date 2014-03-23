#pragma once

#include "common.h"
#include "packetstruct.h"
#include "packet.hpp"
#include "logging.hpp"
#include "safeheaderlist.hpp"

#include <boost/shared_ptr.hpp>

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
		bool isusingwsock();
		void enablesendblock(bool enabled);

	protected:
		static const std::string tag;
		static boost::shared_ptr<packethooks> inst;

		// function signatures of internal maplestory send/recv funcs
		// since we can't use __thiscall directly, we have to use __fastcall and add a placeholder EDX param
		// __thiscall passes the instance as a hidden first parameter in ecx
		// __fastcall passes the first two parameters in ecx and edx, the other params are pushed normally
		// so calling a __thiscall as a __fastcall requires ignoring the parameters on edx 
		// and making sure the real params are pushed
		typedef void (__fastcall* pfnsendpacket)(void *instance, void *edx, maple::outpacket* ppacket);
		typedef void (__fastcall* pfnrecvpacket)(void *instance, void *edx, maple::inpacket* ppacket);

		static void injectpacket(maple::inpacket *ppacket);
		static void injectpacket(maple::outpacket *ppacket);

		boost::shared_ptr<utils::logging> log;
		bool initialized;
		bool wsocklogging;
		static dword maplethreadid; // thread that created the maplestory wnd
		static void **ppcclientsocket; // pointer to the CClientSocket instance
		static pfnsendpacket mssendpacket; // maplestory's internal send func
		static void *mssendhook; // some virtualized code related to mssendpacket
		static dword mssendhookret;
		static pfnrecvpacket msrecvpacket; // maplestory's internal recv func
		static dword *recviat; // pointer for recv iat hooking
		static dword originalrecviat;
		static dword recviatret; // return addy of the iat hook
		static void *someretaddy; // for ret addy spoofing

		static dword _stdcall handlepacket(dword isrecv, void *retaddy, int size, byte pdata[]);
		static void __fastcall sendblockhook(void *instance, void *edx, maple::outpacket* ppacket);
		static void sendhook();
		static void recviathook();
		static void recvhook();

		packethooks();
		static void getmaplethreadid(dword current_thread); // waits for the maplestory window and stores its thread id
	};
}
