// I tried to keep the code nice and clean, but this file is unreadable as fuck.
// Sorry.

#include "packethooks.hpp"

#include "mem.h"
#include "mainform.hpp"
//#include "aobscan.hpp"
#include "utils.hpp"

#include <boost/thread.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>

#include "lib/Asm.h" // temporary

namespace wxPloiter
{
	const std::string packethooks::tag = "wxPloiter::packethooks";
	boost::shared_ptr<packethooks> packethooks::inst;

	/*
	// TODO: make these non-static and push them as params to injectpacket
	void **packethooks::ppcclientsocket = NULL; // pointer to the CClientSocket instance
	packethooks::pfnsendpacket packethooks::mssendpacket = NULL; // maplestory's internal send func
	packethooks::pfnrecvpacket packethooks::msrecvpacket = NULL; // maplestory's internal recv func
	void *packethooks::someretaddy = NULL; // for ret addy spoofing
	*/

	dword packethooks::maplethreadid;
	void *packethooks::mssendpacketfunc = reinterpret_cast<void *>(0x00478020);
	void *packethooks::mssendpacket = reinterpret_cast<void *>(0x018AF0E1);
	void *packethooks::mssendpacketret = reinterpret_cast<void *>(0x019BE599);
	void *packethooks::pmsrecvpacket = reinterpret_cast<void *>(0x0127F094);
	void *packethooks::msrecvpacketret = reinterpret_cast<void *>(0x0057E931);
	void *packethooks::msrecvptrmemory;

	boost::shared_ptr<packethooks> packethooks::get()
	{
		if (!inst.get())
			inst.reset(new packethooks);

		return inst;
	}

	packethooks::packethooks()
		: log(utils::logging::get()),
		  initialized(false)
	{
		// TODO: make my own memory writing class instead of using Asm.lib and check for write failure
		Asm::Write_Hook("jmp", reinterpret_cast<dword>(mssendpacket), reinterpret_cast<dword>(sendhook));

		msrecvptrmemory = reinterpret_cast<void *>(
			Asm::Write_Pointer_Hook(reinterpret_cast<dword>(pmsrecvpacket), reinterpret_cast<dword>(recvptrhook))
		);

		//8D 0C F5 00 00 00 00 66 0B D1 0F B7 CA 2nd result of starting function(0x007... jumped by the address(0x004...
	
		//0045E400 wryyy the magic jump
		//Asm::Write_Hook("call", 0x01AA5F4F, reinterpret_cast<dword>(threadcheck), 0);
		//Asm::Write_Hook("call", 0x01ABD739, reinterpret_cast<dword>(threadcheck), 0);
	
		//64 A1 18 00 00 00
		//Asm::Write_code(0x018D0F71, "B8 00 D0 FD 7E", 1);//6B8
		//Asm::Write_code(0x01A1BAEE, "B8 00 D0 FD 7E", 1);//24
		//Asm::Write_code(0x01B17033, "B8 00 D0 FD 7E", 1);//others

		/*
		void *pmaplebase = NULL;
		size_t maplesize = 0;

		if (!utils::mem::getmodulesize(GetModuleHandle(NULL), &pmaplebase, &maplesize))
		{
			log->e(tag, "packethooks: failed to retrieve maple module size & base");
			return;
		}

		utils::mem::aobscan send("8B 0D ? ? ? ? E8 ? ? ? ? 8D 4C 24 ? E9", pmaplebase, maplesize);

		if (!send.result())
		{
			log->w(tag, "packethooks: failed to find send address. send injection will not work");
			mainform::get()->enablesend(false);
		}
		else
			mainform::get()->enablesend(true);

		mssendpacket = reinterpret_cast<pfnsendpacket>(utils::mem::getcall(send.result() + 6));
		someretaddy = reinterpret_cast<LPBYTE>(mssendpacket) - 0xA;
		ppcclientsocket = reinterpret_cast<void **>(*reinterpret_cast<dword *>(send.result() + 2));

		utils::mem::aobscan recv("E8 ? ? ? ? 8D 4C 24 ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 83 7E "
			"? ? 0F 85 ? ? ? ? 8B 4C 24 ? 64 89 0D ? ? ? ? 59 5F 5E 5D 5B", pmaplebase, maplesize);

		if (!recv.result())
		{
			log->w(tag, "packethooks: failed to find recv address. recv injection will not work");
			mainform::get()->enablerecv(false);
		}
		else
			mainform::get()->enablerecv(true);

		if (!recv.result() && !send.result())
			return;

		msrecvpacket = reinterpret_cast<pfnrecvpacket>(utils::mem::getcall(recv.result()));

		log->i(tag, 
			strfmt() << "packethooks: packet injection initialized - "
			"maplebase = 0x" << pmaplebase << 
			" maplesize = " << maplesize << 
			" mssendpacket = 0x" << mssendpacket << 
			" msrecvpacket = 0x" << msrecvpacket << 
			" someretaddy = 0x" << someretaddy << 
			" ppcclientsocket = 0x" << ppcclientsocket
		);
		*/

		maplethreadid = GetCurrentThreadId(); // will be changed to moopla thread id as soon as it's detected
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(
			&packethooks::getmaplethreadid, GetCurrentThreadId());

		initialized = true;
	}

	void _stdcall packethooks::handlepacket(int type, dword retaddy, int cb, const byte packet[])
	{
		boost::shared_ptr<maple::packet> p(new maple::packet(packet, cb));
		mainform::get()->queuepacket(p, type, true);
	}

	// TODO: find a better workaround
	const int sendtype = mainform::wxID_PACKET_SEND;
	const int recvtype = mainform::wxID_PACKET_RECV;

	void _declspec(naked) packethooks::sendhook()
	{
		// credits to AIRRIDE
		_asm
		{
			pushad
			mov ecx,[ebp+0x08] // packet struct
			push [ecx+0x04] // packet
			push [ecx+0x08] // cb
			push [ebp+0x04] // retaddy
			push [sendtype] // type
			call handlepacket
			popad
			//sub eax,ebx
			//inc ax

			jmp mssendpacketret
		}
	}


	void _declspec(naked) packethooks::recvhook()
	{
		// credits to AIRRIDE
		_asm
		{
			mov ecx,[esp+0x28] // return Address
			mov edi,[esp+0x2C] // RPacket Struct (original code)

			pushad
			mov eax,[edi+0x08]
			add eax,4
			push eax // packet
			mov edx,[edi+0x0C]
			sub edx,4
			push edx // size
			push ecx // retaddy
			push [recvtype] // type
			call handlepacket
			popad

			jmp msrecvpacketret
		}
	}


	void _declspec(naked) packethooks::recvptrhook()
	{
		// credits to AIRRIDE
		// this is an IAT hook for recv
		_asm
		{
			mov eax,[msrecvpacketret]
			cmp dword ptr [esp],eax
			jne Ending_RP
			mov eax, recvhook
			mov dword ptr [esp],eax

		Ending_RP:
			jmp msrecvptrmemory
		}
	}

	void _declspec(naked) packethooks::threadcheck()
	{
		// credits to AIRRIDE
		_asm
		{
			mov eax, 0x7EFDD000
			mov eax, [eax+0x24]
			mov ecx, eax //using ecx
			ret
		}
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
		// currently disabled
		/*
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
		*/
	}

	void packethooks::injectpacket(maple::outpacket *ppacket)
	{
		// TODO: clean this up

		int cb = ppacket->cbData;
		dword pdata = reinterpret_cast<dword>(ppacket->pbData);

		if (cb == -1 || cb < 2)
			return;

		// spoof thread id
		// credits to kma4 for hinting me the correct TIB thread id offset
		//dword oldthread = GetCurrentThreadId();
		__writefsdword(0x06B8, maplethreadid);

		// credits to AIRRIDE
		// created by airride^^
		_asm
		{
			mov eax,[pdata]
			mov ebx,[cb]
			push 0x00
			push ebx
			push eax
			push 0x00
			push esp
			call mssendpacketfunc
		}

		//__writefsdword(0x06B8, oldthread);

		/*
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
		*/
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
	}

	void packethooks::sendpacket(maple::packet &p)
	{
		// construct packet object
		maple::outpacket mspacket = {0};
		mspacket.cbData = p.size();
		mspacket.pbData = p.raw();

		// send packet
		injectpacket(&mspacket);
	}

	void packethooks::recvpacket(maple::packet &p)
	{
		// construct packet object
		maple::inpacket mspacket = {0};
		mspacket.iState = 2;
		mspacket.lpvData = p.raw();
		mspacket.usLength = p.size();
		mspacket.usRawSeq = *reinterpret_cast<dword *>(p.raw()) & 0xFFFF;
		mspacket.usDataLen = mspacket.usLength - sizeof(DWORD);
		mspacket.usUnknown = 0; // 0x00CC;
		mspacket.uOffset = 4;

		/*
		// spoof thread id
		// credits to kma4 for hinting me the correct TIB thread id offset
		__writefsdword(0x06B8, maplethreadid);
		*/

		// send packet
		injectpacket(&mspacket);
	}
}
