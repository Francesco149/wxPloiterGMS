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

#include "packethooks.hpp"

#include "mem.h"
#include "mainform.hpp"
#include "aobscan.hpp"
#include "utils.hpp"

#include <boost/thread.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>

#define FORCE_NOSEND 0
#define FORCE_NORECV 0

namespace wxPloiter
{
	namespace detours = utils::detours;

	const std::string packethooks::tag = "wxPloiter::packethooks";
	boost::shared_ptr<packethooks> packethooks::inst;

	// TODO: make these non-static and push them as params to injectpacket
	void **packethooks::ppcclientsocket = NULL; // pointer to the CClientSocket instance
	void **packethooks::pDispatchMessageA = NULL;
	void *packethooks::DispatchMessageAret = NULL;
	packethooks::pfnsendpacket packethooks::mssendpacket = NULL; // maplestory's internal send func
	packethooks::pfnrecvpacket packethooks::msrecvpacket = NULL; // maplestory's internal recv func
	void *packethooks::mssendhook = NULL;
	dword packethooks::mssendhookret = 0;
	void *packethooks::msrecvhook = NULL;
	dword packethooks::msrecvhookret = 0;
	void *packethooks::someretaddy = NULL; // for ret addy spoofing
	dword packethooks::maplethreadid;

	boost::lockfree::queue<maple::inpacket *> packethooks::inqueue;
	boost::lockfree::queue<maple::outpacket *> packethooks::outqueue;

	boost::shared_ptr<packethooks> packethooks::get()
	{
		if (!inst.get())
			inst.reset(new packethooks);

		return inst;
	}

	void packethooks::findvirtualizedhook(void *pmaplebase, size_t maplesize, const char *name, 
		void *function, void **phook, dword *phookret) 
	{
		byte *iterator = reinterpret_cast<byte *>(function);
		bool found = false;

		for (int i = 0; i < 100; i++) 
		{
			if (*iterator == 0xE9) // jmp to virtualized code
			{
				found = true;
				break;
			}

			iterator++;
		}

		if (!found) {
			wxLogWarning(wxString::Format("Could not find jump to vm code for the virtualized %s hook. "
				"%s logging will not work.", name, name));
		}

		iterator = utils::mem::getjump(iterator);

		found = false;
		for (int i = 0; i < 1000; i++) {
			if (*iterator == 0xE9 || *iterator == 0xE8) // hookable jmp or call
			{
				// todo use an actual disassembler instead of this ghetto method
				void *dst = (*iterator == 0xE8 ? utils::mem::getcall : utils::mem::getjump)(iterator);
				if (dst >= pmaplebase && dst <= reinterpret_cast<byte *>(pmaplebase) + maplesize)
				{
					found = true;
					break;
				}
			}

			iterator++;
		}

		if (!found) {
			wxLogWarning(wxString::Format("Could not find hookable jump or call in the "
				"virtualized %s code. %s logging will not work.", name, name));
		}

		*phook = iterator;
		*phookret = reinterpret_cast<dword>(
			*iterator == 0xE9 ? 
			utils::mem::getjump(iterator) : 
			utils::mem::getcall(iterator)
		);
	}

	packethooks::packethooks()
		: log(utils::logging::get()),
		  initialized(false)
	{
		void *pmaplebase = NULL;
		size_t maplesize = 0;

		if (!utils::mem::getmodulesize(GetModuleHandle(NULL), &pmaplebase, &maplesize))
		{
			log->e(tag, "packethooks: failed to retrieve maple module size & base");
			return;
		}

		// credits to airride for this bypassless DispatchMessage hook point
		utils::mem::aobscan dispatchmessage("FF 15 ? ? ? ? 8D 55 ? 52 8B 8D ? ? ? ? E8", pmaplebase, maplesize);
		if (!dispatchmessage.result()) 
		{
			wxLogWarning("Could not find DispatchMessageA hook, packet injection will not work.");
		}
		else {
			pDispatchMessageA = *reinterpret_cast<void ***>(dispatchmessage.result() + 2);
			*pDispatchMessageA = DispatchMessageA_hook;
			DispatchMessageAret = dispatchmessage.result() + 6;
		}

		utils::mem::aobscan send("8B 0D ? ? ? ? E8 ? ? ? ? 8D 4C 24 ? E9", pmaplebase, maplesize);

		if (!send.result() || FORCE_NOSEND)
		{
			log->w(tag, "packethooks: failed to find send address. send injection will not work");
			mainform::get()->enablesend(false);
		}
		else
		{
			mssendpacket = reinterpret_cast<pfnsendpacket>(utils::mem::getcall(send.result() + 6));
			ppcclientsocket = reinterpret_cast<void **>(*reinterpret_cast<dword *>(send.result() + 2));
			mainform::get()->enablesend(true);
		}

		utils::mem::aobscan fakeret("90 C3", pmaplebase, maplesize, 1);

		if (!fakeret.result())
		{
			wxLogWarning("Could not find the fake return address. Will fall-back to another "
				"return address which might cause crashes.");

			someretaddy = reinterpret_cast<byte *>(mssendpacket) - 0xA;
		}
		else
			someretaddy = reinterpret_cast<void *>(fakeret.result());

		utils::mem::aobscan recv("E8 ? ? ? ? 8D 4C 24 ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 83 7E", pmaplebase, maplesize);

		if (!recv.result() || FORCE_NORECV)
		{
			log->w(tag, "packethooks: failed to find recv address. recv injection will not work");
			mainform::get()->enablerecv(false);
		}
		else
		{
			mainform::get()->enablerecv(true);
			msrecvpacket = reinterpret_cast<pfnrecvpacket>(utils::mem::getcall(recv.result()));
		}

		findvirtualizedhook(pmaplebase, maplesize, "Send", mssendpacket, &mssendhook, &mssendhookret);
		findvirtualizedhook(pmaplebase, maplesize, "Recv", msrecvpacket, &msrecvhook, &msrecvhookret);

		log->i(tag, 
			strfmt() << "packethooks: initialized - "
			"maplebase = 0x" << pmaplebase << 
			" maplesize = " << maplesize << 
			" mssendpacket = 0x" << mssendpacket << 
			" msrecvpacket = 0x" << msrecvpacket << 
			" someretaddy = 0x" << someretaddy << 
			" ppcclientsocket = 0x" << ppcclientsocket << 
			" mssendhook = 0x" << mssendhook << 
			" mssendhookret = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << mssendhookret << 
			" msrecvhook = 0x" << msrecvhook << 
			" msrecvhookret = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << msrecvhookret
		);

		maplethreadid = GetCurrentThreadId(); // will be changed to moopla thread id as soon as it's detected
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(
			&packethooks::getmaplethreadid, GetCurrentThreadId());

		initialized = true;
	}

	LRESULT WINAPI packethooks::DispatchMessageA_hook(_In_ const MSG *lpmsg) 
	{
		if (_ReturnAddress() == DispatchMessageAret)
		{
			maple::outpacket *out;
			while (outqueue.pop(out)) 
			{
				injectpacket(out);
				delete[] out->pbData;
				delete out;
			}

			maple::inpacket *in;
			while (inqueue.pop(in)) 
			{
				injectpacket(in);
				delete[] reinterpret_cast<byte *>(in->lpvData);
				delete in;
			}
		}

		return DispatchMessageA(lpmsg);
	}

	void packethooks::hooksend(bool enabled)
	{
		if (!mssendhook)
			return;

		log->i(tag, strfmt() << "packethooks: " << (enabled ? "hooking" : "unhooking") << " send");
		(*reinterpret_cast<byte *>(mssendhook) == 0xE9 ? utils::mem::writejmp : utils::mem::writecall)(
			reinterpret_cast<byte *>(mssendhook), 
			enabled ? sendhook : reinterpret_cast<void *>(mssendhookret), 
			0
		);
	}

	void packethooks::hookrecv(bool enabled)
	{
		if (!msrecvhook)
			return;

		log->i(tag, strfmt() << "packethooks: " << (enabled ? "hooking" : "unhooking") << " recv");
		(*reinterpret_cast<byte *>(msrecvhook) == 0xE9 ? utils::mem::writejmp : utils::mem::writecall)(
			reinterpret_cast<byte *>(msrecvhook), 
			enabled ? recvhook : reinterpret_cast<void *>(msrecvhookret), 
			0
		);
	}

	packethooks::~packethooks()
	{
		// empty
	}

	bool packethooks::isinitialized()
	{
		return initialized;
	}

	void __declspec(naked) packethooks::injectpacket(maple::inpacket *ppacket)
	{
		__asm
		{
			// set class ptr
			mov ecx,[ppcclientsocket]
			mov ecx,[ecx]

			// push packet and fake return address
			push [esp+0x4] // ppacket
			push [someretaddy]

			// send packet
			jmp [msrecvpacket]
		}
	}

	void __declspec(naked) packethooks::injectpacket(maple::outpacket *ppacket)
	{
		__asm
		{
			// set class ptr
			mov ecx,[ppcclientsocket]
			mov ecx,[ecx]

			// push packet and fake return address
			push [esp+0x4] // ppacket
			push [someretaddy]

			// send packet
			jmp [mssendpacket]
		}
	}

	void packethooks::getmaplethreadid(dword current_thread)
	{
		namespace tt = boost::this_thread;
		namespace pt = boost::posix_time;

		HWND hmoopla = NULL;

		while (!hmoopla)
		{
			hmoopla = maple::getwnd();
			tt::sleep(pt::milliseconds(500));
		}

		maplethreadid = GetWindowThreadProcessId(hmoopla, NULL);
		utils::logging::get()->i(tag, strfmt() 
			<< "getmaplethreadid: spoofing active - current thread: " << current_thread
			<< " spoofed to: " << maplethreadid);

		while (!*reinterpret_cast<byte **>(0x016CF0A0))
			tt::sleep(pt::milliseconds(500));

#ifdef APRILFOOLS
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(&packethooks::aprilfools);
#endif
	}

	void packethooks::aprilfools()
	{
		namespace tt = boost::this_thread;
		namespace pt = boost::posix_time;

		const char *messages[] = 
		{
			"Hey. Having a good day? I hope you're not botting.", 
			"Your account is restricted for visiting ccplz.net.", 
			"Hi, just making sure that you're not botting."
		};

		while (true)
		{
			maple::packet p;
			p.append<dword>(utils::random::get()->getdword());
			p.append<word>(0x011A);
			p.append<byte>(0x12);
			p.append_string("GMNeru");
			p.append<word>(utils::random::get()->getword() % 14);
			p.append_string(messages[utils::random::get()->getinteger<int>(0, 2)]);
			utils::logging::get()->i(tag, strfmt() << "sending april fools packet: " << p.tostring());
			get()->recvpacket(p);
			tt::sleep(pt::seconds(utils::random::get()->getinteger<int>(60, 180)));
		}
	}

	void packethooks::sendpacket(maple::packet &p)
	{
		maple::packet pt = p; // the raw data will be encrypted so we need to make a copy

		// construct packet object
		maple::outpacket *mspacket = new maple::outpacket;
		ZeroMemory(mspacket, sizeof(maple::outpacket));
		mspacket->cbData = pt.size();
		mspacket->pbData = new byte[pt.size()];
		memcpy_s(mspacket->pbData, pt.size(), pt.raw(), pt.size());

		// spoof thread id
		// credits to kma4 for hinting me the correct TIB thread id offset
		//__writefsdword(0x06B8, maplethreadid);

		// send packet
		//injectpacket(&mspacket);

		outqueue.push(mspacket);
	}

	void packethooks::recvpacket(maple::packet &p)
	{
		// construct packet object
		maple::inpacket *mspacket = new maple::inpacket;
		ZeroMemory(mspacket, sizeof(maple::inpacket));
		mspacket->iState = 2;
		mspacket->lpvData = new byte[p.size()];
		memcpy_s(mspacket->lpvData, p.size(), p.raw(), p.size());
		mspacket->dwTotalLength = p.size();
		mspacket->dwUnknown = 0; // 0x00CC;
		mspacket->dwValidLength = mspacket->dwTotalLength - sizeof(DWORD);
		mspacket->uOffset = 4;

		// spoof thread id
		// credits to kma4 for hinting me the correct TIB thread id offset
		//__writefsdword(0x06B8, maplethreadid);

		// send packet
		//injectpacket(&mspacket);

		inqueue.push(mspacket);
	}

	dword _stdcall packethooks::handlepacket(dword isrecv, void *retaddy, int size, byte pdata[])
	{
		//void *stack = _AddressOfReturnAddress();
		word *pheader = reinterpret_cast<word *>(pdata);

		if (isrecv == 1)
		{
			//wxMessageBox(wxString::Format("%lx", (long)stack));

			if (safeheaderlist::getblockedrecv()->contains(*pheader))
			{
				//get()->log->i(tag, strfmt() << "recv: blocked header  " << 
					//std::hex << std::uppercase << std::setw(4) << std::setfill('0') << *pheader);

				*pheader = BLOCKED_HEADER;
				return 0;
			}
		}
		else
		{
			if (safeheaderlist::getblockedsend()->contains(*pheader))
				return 1; // send packets can't be blocked by invalidating the header
		}

		boost::shared_ptr<maple::packet> p(new maple::packet(pdata, size));
		mainform::get()->queuepacket(p, isrecv == 1 ? mainform::wxID_PACKET_RECV : mainform::wxID_PACKET_SEND, true, retaddy);

		// returns 1 if the send header must be blocked
		return 0;
	}

	void __declspec(naked) packethooks::sendhook()
	{
		// hook by AIRRIDE
		__asm
		{
			pushad

			// TODO: save cpu when not logging by skipping the hook entirely here

			mov ecx, [ebp + 0x08] // pointer to packet struct
			push [ecx + 0x04] // pdata
			push [ecx + 0x08] // size
			push [ebp + 0x04] // retaddy
			push 0x00000000 // isrecv
			call handlepacket
			cmp eax, 0
			je dontblockplsicryeverytime

			leave // block the packet by skipping it completely
			ret 0004

		dontblockplsicryeverytime:
			popad
			jmp mssendhookret
		}
	}

	void __declspec(naked) packethooks::recvhook()
	{
		// hook by AIRRIDE
		__asm
		{
			push ecx
			push edi
			mov ecx,[esp + 0x38] // retaddy
			mov edi,[esp + 0x3C] // pointer to packet struct (original code)

			pushad

			// TODO: save cpu when not logging by skipping the hook entirely here

			mov eax, [edi + 0x08]
			add eax, 4
			push eax // pdata
			mov edx, [edi + 0x0C]
			sub edx, 4
			push edx // size
			push ecx // retaddy

			push 0x00000001 // isrecv
			call handlepacket

			popad
			pop edi
			pop ecx
			jmp msrecvhookret
		}
	}
}
