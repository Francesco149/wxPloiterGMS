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
#include "wsockhooks.hpp"

#include <boost/thread.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>

#define FORCE_WINSOCK 0
#define FORCE_NOSEND 0
#define FORCE_NORECV 0

namespace wxPloiter
{
	namespace detours = utils::detours;

	const std::string packethooks::tag = "wxPloiter::packethooks";
	boost::shared_ptr<packethooks> packethooks::inst;

	// TODO: make these non-static and push them as params to injectpacket
	void **packethooks::ppcclientsocket = NULL; // pointer to the CClientSocket instance
	packethooks::pfnsendpacket packethooks::mssendpacket = NULL; // maplestory's internal send func
	packethooks::pfnrecvpacket packethooks::msrecvpacket = NULL; // maplestory's internal recv func
	void *packethooks::mssendhook = NULL;
	dword packethooks::mssendhookret = 0;
	dword *packethooks::recviat = 0;
	dword packethooks::originalrecviat = 0;
	dword packethooks::recviatret = 0;
	void *packethooks::someretaddy = NULL; // for ret addy spoofing
	dword packethooks::maplethreadid;

	boost::shared_ptr<packethooks> packethooks::get()
	{
		if (!inst.get())
			inst.reset(new packethooks);

		return inst;
	}

	packethooks::packethooks()
		: log(utils::logging::get()),
		  initialized(false),
		  wsocklogging(false)
	{
		void *pmaplebase = NULL;
		size_t maplesize = 0;
		
		if (FORCE_WINSOCK)
		{
			if (!wsockhooks::get()->ishooked())
			{
				wxLogWarning("Could not hook winsock send/recv. Packet logging will not work.");
				return;
			}
			else
			{
				initialized = true;
				wsocklogging = true;
			}
		}

		if (!utils::mem::getmodulesize(GetModuleHandle(NULL), &pmaplebase, &maplesize))
		{
			log->e(tag, "packethooks: failed to retrieve maple module size & base");
			return;
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

		utils::mem::aobscan recv("E8 ? ? ? ? 8D 4C 24 ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 83 7E "
			"? ? 0F 85 ? ? ? ? 8B 4C 24 ? 64 89 0D ? ? ? ? 59 5F 5E 5D 5B", pmaplebase, maplesize);

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

		if (!FORCE_WINSOCK)
		{
			bool wsockfallback = false;

			do {
				// credits to AIRRIDE for the IAT hooking method and the send hooking method
				utils::mem::aobscan findrecvhook("8B 7C 24 ? 8B CF C7 44 24 ? ? ? ? ? E8 ? ? ? ? 0F B7 D8", pmaplebase, maplesize);

				if (!findrecvhook.result())
				{
					wxLogWarning("Could not find the IAT pointer for recv. Falling back to winsock hooks.");
					wsockfallback = true;
					break;
				}
				else
				{
					recviat = *reinterpret_cast<dword **>(findrecvhook.result() - 4);
					recviatret = reinterpret_cast<dword>(findrecvhook.result());
				}

				byte *iterator = reinterpret_cast<byte *>(mssendpacket);
				bool found = false;

				// credits to AIRRIDE for the virtualized hook method
				for (int i = 0; i < 100; i++) 
				{
					if (*iterator == 0xE9) // jmp to virtualized code
					{
						log->i(tag, strfmt() << "jump to virtualized send code at 0x" << reinterpret_cast<void *>(iterator));
						found = true;
						break;
					}

					iterator++;
				}

				if (!found) {
					wxLogWarning("Could not find jump to vm code for the virtualized send hook. Falling back to winsock hooks.");
					wsockfallback = true;
					break;
				}

				iterator = utils::mem::getjump(iterator);
				log->i(tag, strfmt() << "virtualized send code at 0x" << reinterpret_cast<void *>(iterator));

				found = false;
				for (int i = 0; i < 1000; i++) {
					if (*iterator == 0xE9 || *iterator == 0xE8) // hookable jmp or call
					{
						// todo use an actual disassembler instead of this ghetto method
						void *dst = (*iterator == 0xE8 ? utils::mem::getcall : utils::mem::getjump)(iterator);
						if (dst >= pmaplebase && dst <= reinterpret_cast<byte *>(pmaplebase) + maplesize)
						{
							log->i(tag, strfmt() << "virtualized send hook at 0x" << reinterpret_cast<void *>(iterator));
							found = true;
							break;
						}
					}

					iterator++;
				}

				if (!found) {
					wxLogWarning("Could not find hookable jump or call in the "
						"virtualized send code. Falling back to winsock hooks.");
					wsockfallback = true;
					break;
				}

				mssendhook = iterator;
				mssendhookret = reinterpret_cast<dword>(
					*iterator == 0xE9 ? 
					utils::mem::getjump(iterator) : 
					utils::mem::getcall(iterator)
				);
			} while (false);

			if (wsockfallback) 
			{
				if (!wsockhooks::get()->ishooked())
				{
					wxLogWarning("Could not hook winsock send/recv. Packet logging will not work.");
					return;
				}
				else
				{
					initialized = true;
					wsocklogging = true;
				}
			}
		}

		if (wsocklogging)
		{
			log->i(tag, 
				strfmt() << "packethooks: initialized (winsock) - "
				"maplebase = 0x" << pmaplebase << 
				" maplesize = " << maplesize << 
				" mssendpacket = 0x" << mssendpacket << 
				" msrecvpacket = 0x" << msrecvpacket << 
				" someretaddy = 0x" << someretaddy << 
				" ppcclientsocket = 0x" << ppcclientsocket
			);
		}
		else
		{
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
				" recviat = 0x" << recviat << 
				" recviatret = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << recviatret
			);
		}

		maplethreadid = GetCurrentThreadId(); // will be changed to moopla thread id as soon as it's detected
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(
			&packethooks::getmaplethreadid, GetCurrentThreadId());

		initialized = true;
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
		if (!recviat)
			return;

		if (enabled)
		{
			log->i(tag, "packethooks: IAT hooking msrecvpacket");
			utils::mem::makepagewritable(recviat, 4);
			originalrecviat = *recviat;
			log->i(tag, strfmt() << "packethooks: original IAT value: " << 
				std::hex << std::uppercase << std::setw(8) << std::setfill('0') << originalrecviat);
			*recviat = reinterpret_cast<dword>(recviathook);
		}
		else
		{
			log->i(tag, "packethooks: IAT un-hooking msrecvpacket");
			utils::mem::makepagewritable(recviat, 4);
			*recviat = originalrecviat;
		}
	}

	bool packethooks::isusingwsock()
	{
		return wsocklogging;
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
		maple::outpacket mspacket = {0};
		mspacket.cbData = pt.size();
		mspacket.pbData = pt.raw();

		// spoof thread id
		// credits to kma4 for hinting me the correct TIB thread id offset
		__writefsdword(0x06B8, maplethreadid);

		// send packet
		injectpacket(&mspacket);
	}

	void packethooks::recvpacket(maple::packet &p)
	{
		// construct packet object
		maple::inpacket mspacket = {0};
		mspacket.iState = 2;
		mspacket.lpvData = p.raw();
		mspacket.dwTotalLength = p.size();
		mspacket.dwUnknown = 0; // 0x00CC;
		mspacket.dwValidLength = mspacket.dwTotalLength - sizeof(DWORD);
		mspacket.uOffset = 4;

		// spoof thread id
		// credits to kma4 for hinting me the correct TIB thread id offset
		__writefsdword(0x06B8, maplethreadid);

		// send packet
		injectpacket(&mspacket);
	}

	dword _stdcall packethooks::handlepacket(dword isrecv, void *retaddy, int size, byte pdata[])
	{
		word *pheader = reinterpret_cast<word *>(pdata);

		if (isrecv == 1)
		{
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

	void __declspec(naked) packethooks::recviathook()
	{
		// hook by AIRRIDE
		__asm
		{
			mov eax, [recviatret]
			cmp dword ptr [esp], eax
			jne deliciouslolis
			mov eax, recvhook
			mov dword ptr [esp], eax

		deliciouslolis:
			jmp originalrecviat
		}
	}

	void __declspec(naked) packethooks::recvhook()
	{
		// hook by AIRRIDE
		__asm
		{
			mov ecx,[esp + 0x28] // retaddy
			mov edi,[esp + 0x2C] // pointer to packet struct (original code)

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
			jmp recviatret
		}
	}
}
