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
#include "checksumhack.hpp"

#include <boost/thread.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>
#include <boost/lockfree/queue.hpp>

#define WATYMETHOD
#ifdef WATYMETHOD
#include <WinSock.h>
#endif

#define FORCE_NOSEND 0
#define FORCE_NORECV 0

// this file is becoming a mess due to continue changing of injection methods
// TODO: clean up this piece of shit

namespace wxPloiter
{
	namespace detours = utils::detours;

	const std::string packethooks::tag = "wxPloiter::packethooks";
	boost::shared_ptr<packethooks> packethooks::inst;

	// function signatures of internal maplestory send/recv funcs
	// since we can't use __thiscall directly, we have to use __fastcall and add a placeholder EDX param
	// __thiscall passes the instance as a hidden first parameter in ecx
	// __fastcall passes the first two parameters in ecx and edx, the other params are pushed normally
	// so calling a __thiscall as a __fastcall requires ignoring the parameters on edx 
	// and making sure the real params are pushed
	typedef void (__fastcall* pfnsendpacket)(void *instance, void *edx, maple::outpacket* ppacket);
	typedef void (__fastcall* pfnrecvpacket)(void *instance, void *edx, maple::inpacket* ppacket);

	// Addresses for Waty's injection method
	static dword mslockaddy = 0;
	static dword msunlockaddy = 0;
	static dword innohashaddy = 0;
	static dword flushsocketaddy = 0;
	static dword makebufferlistaddy = 0;
	static dword gameversion = 160;

	// TODO: make some of these non-static?
	static void **ppcclientsocket = NULL; // pointer to the CClientSocket instance
	static void **pDispatchMessageA = NULL;
	static void *DispatchMessageAret = NULL;
	static pfnsendpacket mssendpacket = NULL; // maplestory's internal send func
	static pfnrecvpacket msrecvpacket = NULL; // maplestory's internal recv func
	static void *mssendhook = NULL;
	static dword mssendhookret = 0;
	static void *msrecvhook = NULL;
	static dword msrecvhookret = 0;
	static void *someretaddy = NULL; // for ret addy spoofing

	static boost::lockfree::queue<maple::inpacket *> inqueue;
#ifndef WATYMETHOD
	static boost::lockfree::queue<maple::outpacket *> outqueue;
#else 
	// shameless copypasta from waty's PacketSenderPlz 
	// TODO: merge this with maple::outpacket
	struct ZSocketBase
	{
		unsigned int _m_hSocket;
	};

	template <class T> struct ZList
	{
		virtual ~ZList<T>();		// 0x00
		void* baseclass_4;			// 0x04
		unsigned int _m_uCount;		// 0x08
		T* _m_pHead;				// 0x0C
		T* _m_pTail;				// 0x10	
	};								// 0x14 
	static_assert(sizeof(ZList<void>) == 0x14, "ZList is the wrong size");

	template <class T> struct ZRef
	{
		void* vfptr;
		T* data;
	};

	#pragma pack( push, 1 )
	struct COutPacket
	{
		COutPacket(uint8_t* data = NULL, uint32_t dwLength = 0) 
			: m_bLoopback(false), m_bIsEncryptedByShanda(false), m_uOffset(0)
		{
			m_lpvSendBuff = data;
			m_uDataLen = dwLength;
		}

		int32_t  m_bLoopback;							// + 0x00
		uint8_t* m_lpvSendBuff;							// + 0x04
		uint32_t m_uDataLen;							// + 0x08
		uint32_t m_uOffset;								// + 0x0C
		int32_t  m_bIsEncryptedByShanda;				// + 0x10

		void MakeBufferList(ZList<ZRef<void>> *l, unsigned __int16 uSeqBase, unsigned int *puSeqKey, int bEnc, unsigned int dwKey)
		{
			typedef void(__thiscall *MakeBufferList_t)(COutPacket *_this, ZList<ZRef<void>> *l, unsigned __int16 uSeqBase, unsigned int *puSeqKey, int bEnc, unsigned int dwKey);
			MakeBufferList_t MakeBufferList = reinterpret_cast<MakeBufferList_t>(makebufferlistaddy);
			MakeBufferList(this, l, uSeqBase, puSeqKey, bEnc, dwKey);
		}
	};

	struct CInPacket
	{
		int32_t m_bLoopback;							// + 0x00
		int32_t m_nState;								// + 0x04
		uint8_t* m_lpbRecvBuff;							// + 0x08
		uint32_t m_uLength;								// + 0x0C
		uint32_t m_uRawSeq;								// + 0x10
		uint32_t m_uDataLen;							// + 0x14
		uint32_t m_uOffset;								// + 0x18
	};
	#pragma pack( pop )

	struct ZFatalSectionData
	{
		void *_m_pTIB;									// + 0x00
		int _m_nRef;									// + 0x04
	};

	struct ZFatalSection : public ZFatalSectionData
	{

	};

	template<class T> struct ZSynchronizedHelper
	{
	public:
		__inline ZSynchronizedHelper(T* lock)
		{
			reinterpret_cast<void(__thiscall*)(ZSynchronizedHelper<T>*, T*)>(mslockaddy)(this, lock);
		}

		__inline ~ZSynchronizedHelper()
		{
			reinterpret_cast<void(__thiscall*)(ZSynchronizedHelper<T>*)>(msunlockaddy)(this);
		}

	private:
		T* m_pLock;
	};

	static unsigned int(__cdecl *CIGCipher__innoHash)(char *pSrc, int nLen, unsigned int *pdwKey) = NULL;
	struct CClientSocket
	{
		struct CONNECTCONTEXT
		{
			ZList<sockaddr_in> lAddr;
			void *posList;
			int bLogin;
		};

		virtual ~CClientSocket();
		void* ___u1;
		ZSocketBase m_sock;
		CONNECTCONTEXT m_ctxConnect;
		sockaddr_in m_addr;
		int m_tTimeout;

		ZList<ZRef<void> > m_lpRecvBuff; // ZList<ZRef<ZSocketBuffer> >
		ZList<ZRef<void> > m_lpSendBuff; // ZList<ZRef<ZSocketBuffer> >
		CInPacket m_packetRecv;
		ZFatalSection m_lockSend;
		unsigned int m_uSeqSnd;
		unsigned int m_uSeqRcv;
		char* m_URLGuestIDRegistration;
		int m_bIsGuestID;

		void Flush()
		{
			reinterpret_cast<void(__thiscall*)(CClientSocket*)>(flushsocketaddy)(this);
		}

		void SendPacket(COutPacket& oPacket)
		{
			ZSynchronizedHelper<ZFatalSection> lock(&m_lockSend);

			if (m_sock._m_hSocket != 0 && m_sock._m_hSocket != 0xFFFFFFFF && m_ctxConnect.lAddr._m_uCount == 0)
			{
				oPacket.MakeBufferList(&m_lpSendBuff, gameversion, &m_uSeqSnd, 1, m_uSeqSnd);
				m_uSeqSnd = CIGCipher__innoHash(reinterpret_cast<char*>(&m_uSeqSnd), 4, 0);
				Flush();
			}
		}
	};

	static_assert(sizeof(CClientSocket) == 0x98, "CClientSocket is the wrong size!");
#endif

	boost::shared_ptr<packethooks> packethooks::get()
	{
		CHECKSUM_HACK()
		if (!inst.get())
			inst.reset(new packethooks);

		return inst;
	}

	void findvirtualizedhook(void *pmaplebase, size_t maplesize, const char *name, 
		void *function, void **phook, dword *phookret) 
	{
		CHECKSUM_HACK()
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
		CHECKSUM_HACK()
		void *pmaplebase = NULL;
		size_t maplesize = 0;

		if (!utils::mem::getmodulesize(GetModuleHandle(NULL), &pmaplebase, &maplesize))
		{
			log->e(tag, "packethooks: failed to retrieve maple module size & base");
			return;
		}

#ifdef WATYMETHOD
		// grab maple version
		utils::mem::aobscan mapleversionaob("68 ? ? 00 00 E8 ? ? ? ? 83 ? ? 6A ? 8D", pmaplebase, maplesize);
		if (!mapleversionaob.result())
			wxLogWarning("Could not find maplestory version, packet injection will not work unless this version "
			"of the PE was released after the version of MapleStory you're using.");
		else
			gameversion = *reinterpret_cast<dword *>(mapleversionaob.result() + 1);

		// full credits to Waty for this injection method

		// (ctor) ZSynchronizedHelper<ZFatalSection>::ZSynchronizedHelper<ZFatalSection>()
		utils::mem::aobscan mslockaob("? ? 8B ? ? ? 8B ? 8B ? 89 ? FF 15 ? ? ? ? 85", pmaplebase, maplesize);
		if (!mslockaob.result())
			wxLogWarning("Could not find lockaddy, packet injection will not work.");
		else
			mslockaddy = reinterpret_cast<dword>(mslockaob.result());

		// (dtor) ZSynchronizedHelper<ZFatalSection>::~ZSynchronizedHelper<ZFatalSection>()
		utils::mem::aobscan msunlockaob("8B ? 83 ? ? ? 75 ? C7 ? ? ? ? ? C3", pmaplebase, maplesize);
		if (!msunlockaob.result())
			wxLogWarning("Could not find unlockaddy, packet injection will not work.");
		else
			msunlockaddy = reinterpret_cast<dword>(msunlockaob.result());

		// static unsigned long __cdecl CIGCipher::innoHash(unsigned char *iv, int ivsize, unsigned long *pkey)
		utils::mem::aobscan innohashaob("? 8B ? ? ? C7 ? ? ? ? ? ? 85 ? 75 ? 8D ? ? ? 8B", pmaplebase, maplesize);
		if (!innohashaob.result())
			wxLogWarning("Could not find innohashaddy, packet injection will not work.");
		else
		{
			innohashaddy = reinterpret_cast<dword>(innohashaob.result());
			CIGCipher__innoHash = reinterpret_cast<unsigned int(__cdecl *)(char *pSrc, int nLen, unsigned int *pdwKey)>(innohashaddy);
		}

		// void __thiscall CClientSocket::Flush(void)
		utils::mem::aobscan flushsocketaob("6A ? 68 ? ? ? ? 64 ? ? ? ? ? ? 83 ? ? ? ? ? ? ? ? ? ? ? 33 ? ? "
			"8D ? ? ? 64 ? ? ? ? ? 8B ? 8B ? ? 33 ? 3B ? 0F 84 ? ? ? ? 83", pmaplebase, maplesize);
		if (!flushsocketaob.result())
			wxLogWarning("Could not find flushsocketaddy, packet injection will not work.");
		else
			flushsocketaddy = reinterpret_cast<dword>(flushsocketaob.result());

		// void __thiscall COutPacket::MakeBufferList(ZList<ZRef<void>> *l, unsigned __int16 seqbase, unsigned int *pkey, int flenc, unsigned int key)const
		// alternate aob: 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC 14 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 ? ? ? ? 8B E9 89 6C 24 1C
		utils::mem::aobscan makebufferlistaob("6A ? 68 ? ? ? ? 64 ? ? ? ? ? ? 83 ? ? ? ? ? ? ? ? ? ? ? 33 ? ? "
			"8D ? ? ? 64 ? ? ? ? ? 8B ? 89 ? ? ? 8B ? ? 8D ? ? 89 ? ? ? ? ? ? ? ? 72", pmaplebase, maplesize);
		if (!makebufferlistaob.result())
			wxLogWarning("Could not find makebufferlistaddy, packet injection will not work.");
		else
			makebufferlistaddy = reinterpret_cast<dword>(makebufferlistaob.result());
#endif

		// credits to airride for this bypassless DispatchMessage hook point
		// shorter aob with registers: FF 15 ? ? ? ? 8D 55 ? 52 8B 8D ? ? ? ? E8
		utils::mem::aobscan dispatchmessage("FF 15 ? ? ? ? 8D ? ? ? 8B ? ? ? ? ? E8 ? ? ? ? ? ? 74", pmaplebase, maplesize);
		if (!dispatchmessage.result()) 
		{
			wxLogWarning("Could not find DispatchMessageA hook, packet injection will not work.");
		}
		else 
		{
			pDispatchMessageA = *reinterpret_cast<void ***>(dispatchmessage.result() + 2);
			*pDispatchMessageA = DispatchMessageA_hook;
			DispatchMessageAret = dispatchmessage.result() + 6;
		}

		// aob with registers: 8B 0D ? ? ? ? E8 ? ? ? ? 8D 4C 24 ? E9
		utils::mem::aobscan send("8B 0D ? ? ? ? E8 ? ? ? ? 8D ? ? ? E9", pmaplebase, maplesize);

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

		if (!someretaddy) 
		{
			wxLogWarning("Could not find the fake return address. Packet injection will not work.");
		}

		// shorter aob with registers: E8 ? ? ? ? 8D 4C 24 ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 83 7E
		utils::mem::aobscan recv("E8 ? ? ? ? 8D ? ? ? C7 ? ? ? ? ? ? ? E8 ? ? ? ? 83 ? ? ? 0F", pmaplebase, maplesize);

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
#ifdef WATYMETHOD
			" gameversion = " << gameversion << 
			" mslockaddy = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << mslockaddy <<
			" msunlockaddy = 0x" << msunlockaddy <<
			" innohashaddy = 0x" << innohashaddy << 
			" flushsocketaddy = 0x" << flushsocketaddy << 
			" makebufferlistaddy = 0x" << makebufferlistaddy << 
#endif
			" mssendpacket = 0x" << mssendpacket << 
			" msrecvpacket = 0x" << msrecvpacket << 
			" someretaddy = 0x" << someretaddy << 
			" ppcclientsocket = 0x" << ppcclientsocket << 
			" mssendhook = 0x" << mssendhook << 
			" mssendhookret = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << mssendhookret << 
			" msrecvhook = 0x" << msrecvhook << 
			" msrecvhookret = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << msrecvhookret
		);

#ifdef APRILFOOLS
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(&packethooks::aprilfools);
#endif

		initialized = true;
	}

	bool maple_isconnected()
	{
		CHECKSUM_HACK()
		try { return *ppcclientsocket != nullptr; }
		catch (...) { return false; }
	}

	LRESULT WINAPI packethooks::DispatchMessageA_hook(_In_ const MSG *lpmsg) 
	{
		CHECKSUM_HACK()
		if (_ReturnAddress() == DispatchMessageAret)
		{
			try {
#ifndef WATYMETHOD // I'm not sure why waty's method crashes when called from this hook
				maple::outpacket *out;
				while (outqueue.pop(out)) 
				{
					injectpacket(out);

					delete[] out->pbData;
					delete out;
				}
#endif

				maple::inpacket *in;
				while (inqueue.pop(in)) 
				{
					injectpacket(in);
					delete[] reinterpret_cast<byte *>(in->lpvData);
					delete in;
				}
			}
			catch(...)
			{
				get()->log->w(tag, "something went wrong when sending enqueued packets");
			}
		}

		return DispatchMessageA(lpmsg);
	}

	void packethooks::hooksend(bool enabled)
	{
		CHECKSUM_HACK()
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
		CHECKSUM_HACK()
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
		CHECKSUM_HACK()
		// empty
	}

	bool packethooks::isinitialized()
	{
		CHECKSUM_HACK()
		return initialized;
	}

	void __declspec(naked) packethooks::injectpacket(maple::inpacket *ppacket)
	{
		CHECKSUM_HACK()
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
		CHECKSUM_HACK()
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

#ifdef APRILFOOLS
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
#endif

	void packethooks::sendpacket(maple::packet &p)
	{
		CHECKSUM_HACK()
#ifdef WATYMETHOD
		if (!maple_isconnected())
			log->e(tag, "tried to inject packets while disconnected");

		COutPacket op;
		op.m_lpvSendBuff = p.raw();
		op.m_uDataLen = p.size();

		try { (*reinterpret_cast<CClientSocket**>(ppcclientsocket))->SendPacket(op); }
		catch (...) { log->e(tag, "something went wrong when injecting the packet"); }
#else
		maple::packet pt = p; // the raw data will be encrypted so we need to make a copy

		// construct packet object
		maple::outpacket *mspacket = new maple::outpacket;
		ZeroMemory(mspacket, sizeof(maple::outpacket));
		mspacket->cbData = pt.size();
		mspacket->pbData = new byte[pt.size()];
		memcpy_s(mspacket->pbData, pt.size(), pt.raw(), pt.size());

		outqueue.push(mspacket);
#endif
	}

	void packethooks::recvpacket(maple::packet &p)
	{
		CHECKSUM_HACK()
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

		inqueue.push(mspacket);
	}

	dword _stdcall packethooks::handlepacket(dword isrecv, void *retaddy, int size, byte pdata[])
	{
		CHECKSUM_HACK()
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
		CHECKSUM_HACK()
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
		CHECKSUM_HACK()
		// hook by AIRRIDE
		__asm
		{
			push ecx
			push edi
			mov ecx,[esp + 0x34 + 8] // retaddy
			mov edi,[esp + 0x38 + 8] // pointer to packet struct (original code)

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
