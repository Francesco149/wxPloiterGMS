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
			wxLogWarning("Could not find the fake return address. Will fall-back to another return address. "
				"Blocking send packets will crash, so don't even try.");

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

			// TODO: fix recv injection
			//mainform::get()->enablerecv(false);

			msrecvpacket = reinterpret_cast<pfnrecvpacket>(utils::mem::getcall(recv.result()));
		}

		// credits to AIRRIDE for the IAT hooking method and the send hooking method
		utils::mem::aobscan findrecvhook("8B 7C 24 ? 8B CF C7 44 24 ? ? ? ? ? E8 ? ? ? ? 0F B7 D8", pmaplebase, maplesize);

		if (!findrecvhook.result())
			wxLogWarning("Could not find the IAT pointer for recv. Recv log will not work.");
		else
		{
			recviat = *reinterpret_cast<dword **>(findrecvhook.result() - 4);
			recviatret = reinterpret_cast<dword>(findrecvhook.result());
		}

		/*
			AIRRIDE's virtualized send hook
			55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 ? ? ? 64 A3 00 00 00 00 ? ? ? 6A 00 E9

			1 - scroll down and follow the first jmp to 01XXXXXX (opcode at result + 0x2D)
			2 - scroll down and find the first jmp to 01XXXXXX (opcode at followed jmp + 0xE)
			    the address of the opcode is the sendhook address
				the address the jump leads to is the return address

			DWORD SendHook_Addr = 0x018AF0E1; // 101.1
			DWORD SendHook_ret = 0x019BE599;

			memory regions from 101.1:

			0057E250 - 55                    - push ebp
			0057E251 - 8B EC                 - mov ebp,esp
			0057E253 - 6A FF                 - push -01
			0057E255 - 68 0E941101           - push 0111940E : [0824548B]
			0057E25A - 64 A1 00000000        - mov eax,fs:[00000000]
			0057E260 - 50                    - push eax
			0057E261 - 83 EC 6C              - sub esp,6C
			0057E264 - 53                    - push ebx
			0057E265 - 56                    - push esi
			0057E266 - 57                    - push edi
			0057E267 - A1 D0A47E01           - mov eax,[017EA4D0] : [(float)-0.0029]
			0057E26C - 33 C5                 - xor eax,ebp
			0057E26E - 50                    - push eax
			0057E26F - 8D 45 F4              - lea eax,[ebp-0C]
			0057E272 - 64 A3 00000000        - mov fs:[00000000],eax
			0057E278 - 89 4D 88              - mov [ebp-78],ecx
			0057E27B - 6A 00                 - push 00
		->	0057E27D - E9 510E3301           - jmp 018AF0D3 <-
			0057E282 - 0FBA ED 0E            - bts ebp,0E
			0057E286 - C1 CE 11              - ror esi,11
			0057E289 - E9 0F000000           - jmp 0057E29D
			0057E28E - 89 54 24 4C           - mov [esp+4C],edx
			0057E292 - 66 0FCE               - bswap si
			0057E295 - 0FB6 F1               - movzx esi,cl
			0057E298 - E9 C9000000           - jmp 0057E366
			0057E29D - 66 F7 D5              - not bp
			0057E2A0 - 8D 6C 24 1C           - lea ebp,[esp+1C]
			0057E2A4 - 9C                    - pushfd 
			0057E2A5 - 66 89 24 24           - mov [esp],sp
			0057E2A9 - 60                    - pushad 
			0057E2AA - 8D 64 24 40           - lea esp,[esp+40]

			018AF0D3 - 9F                    - lahf 
			018AF0D4 - 10 C0                 - adc al,al
			018AF0D6 - 66 0FAD E0            - shrd ax,sp,cl
			018AF0DA - 0F31                  - rdtsc 
			018AF0DC - 8D 64 24 04           - lea esp,[esp+04]
			018AF0E0 - F8                    - clc 
		->	018AF0E1 - E9 B3F41000           - jmp 019BE599 <-
			018AF0E6 - D2 FD                 - sar ch,cl
			018AF0E8 - B2 F6                 - mov dl,-0A
			018AF0EA - 13 B9 3FA49D4A        - adc edi,[ecx+4A9DA43F]
			018AF0F0 - 99                    - cdq 
			018AF0F1 - 88 22                 - mov [edx],ah
			018AF0F3 - DCCB                  - fmul st(3),st(0)
			018AF0F5 - 14 2F                 - adc al,2F
			018AF0F7 - 54                    - push esp
			018AF0F8 - 2E FC                 - cld 

		->	019BE599 - C7 45 E0 00004000     - mov [ebp-20],00400000 : [00905A4D] <-
			019BE5A0 - 0FA3 F9               - bt ecx,edi
			019BE5A3 - D2 C6                 - rol dh,cl
			019BE5A5 - F9                    - stc 
			019BE5A6 - 66 0FA5 E0            - shld ax,cl
			019BE5AA - 8B 45 E0              - mov eax,[ebp-20]
			019BE5AD - 81 FA B9A00D51        - cmp edx,510DA0B9
			019BE5B3 - 80 E5 F1              - and ch,-0F
			019BE5B6 - 8D 14 DD 1F3691AA     - lea edx,[ebx*8-556EC9E1]
			019BE5BD - 0FC9                  - bswap ecx
			019BE5BF - 8B 4D E0              - mov ecx,[ebp-20]
			019BE5C2 - F6 DE                 - neg dh
			019BE5C4 - 66 81 CA 5CE0         - or dx,E05C
			019BE5C9 - 03 48 3C              - add ecx,[eax+3C]
			019BE5CC - 0FB6 D2               - movzx edx,dl
			019BE5CF - D2 FE                 - sar dh,cl
		*/

		// this send hook method is bypassless because it hooks virtualized code
		utils::mem::aobscan findsendhook("55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC "
			"? 53 56 57 A1 ? ? ? ? 33 C5 50 ? ? ? 64 A3 00 00 00 00 ? ? ? 6A 00 E9", pmaplebase, maplesize);

		if (!findsendhook.result() || FORCE_WINSOCK)
		{
			wxLogWarning("Could not find the virtualized send function. Falling back to decrypting "
				"raw winsock packets (not very reliable but better than nothing).");

			if (!wsockhooks::get()->ishooked())
			{
				wxLogWarning("Could not hook winsock send/recv. Packet logging will not work.");
				return;
			}
			else
			{
				wxLogWarning("Falling back to decrypting winsock packets.");
				initialized = true;
				wsocklogging = true;
				return;
			}
		}
		else
		{
			mssendhook = utils::mem::getjump(findsendhook.result() + 0x2D) + 0xE;
			mssendhookret = reinterpret_cast<dword>(utils::mem::getjump(reinterpret_cast<byte *>(mssendhook)));
		}

		log->i(tag, 
			strfmt() << "packethooks: packet injection initialized - "
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

		maplethreadid = GetCurrentThreadId(); // will be changed to moopla thread id as soon as it's detected
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(
			&packethooks::getmaplethreadid, GetCurrentThreadId());

		// hook everything
		if (mssendhook)
		{
			log->i(tag, "packethooks: hooking virtualized send");
			utils::mem::writejmp(reinterpret_cast<byte *>(mssendhook), sendhook);
		}

		if (recviat)
		{
			log->i(tag, "packethooks: IAT hooking msrecvpacket");
			utils::mem::makepagewritable(recviat, 4);
			originalrecviat = *recviat;
			log->i(tag, strfmt() << "packethooks: original IAT value: " << 
				std::hex << std::uppercase << std::setw(8) << std::setfill('0') << originalrecviat);
			*recviat = reinterpret_cast<dword>(recviathook);
		}

		initialized = true;
	}

	// NOTE: unused
	void packethooks::enablesendblock(bool enabled)
	{
		if (!mssendpacket)
			return;

		log->i(tag, "packethooks: hooking mssendpacket to block packets");

		if (!detours::hook(enabled, reinterpret_cast<PVOID *>(&mssendpacket), sendblockhook))
			wxLogWarning("Failed to hook/unhook mssendpacket. Send blocking will not work.");
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

	// non-bypassless hook of mssendpacket used to block packets
	// NOTE: unused
	void __fastcall packethooks::sendblockhook(void *instance, void *edx, maple::outpacket *ppacket)
	{
		if (safeheaderlist::getblockedsend()->contains(*ppacket->pwHeader))
		{
			//get()->log->i(tag, strfmt() << "send: blocked header  " << 
				//std::hex << std::uppercase << std::setw(4) << std::setfill('0') << *ppacket->pwHeader);
			return;
		}

		injectpacket(ppacket);
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
