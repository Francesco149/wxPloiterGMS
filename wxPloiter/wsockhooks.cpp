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

#include "wsockhooks.hpp"

#include "mainform.hpp"
#include "utils.hpp"
#include "mem.h"

#include <tchar.h>
#include <iomanip>

/*
	// Winsock hooking method that is undetected by hackshield
	// (prevents it from getting removed, but it's still still detected when you get in-game
	// so you will still need a regular HSCRC + MSCRC bypass)
	[Enable]
	alloc(testhook, 64)
	alloc(testhook2, 64)

	WS2_32.send + 5:
	push [ebp+14]
	push [ebp+10]
	push [ebp+0C]
	push [ebp+08]
	call testhook
	nop
	nop
	nop
	nop
	nop

	testhook:
	// stdcall prolog
	push ebp
	mov ebp, esp
	push [ebp+14]
	push [ebp+10]
	push [ebp+0C]
	push [ebp+08]
	call testhook2
	pop ebp

	// we need to inject the original code we overwrited so instead of ret 10
	// we're gonna pop the 4 arguments and the return address here and
	// just jump back later on
	pop eax
	pop eax
	pop eax
	pop eax
	pop eax

	// stack is now clean

	// original asm
	mov eax,[77416054]
	sub esp,1C
	push ebx
	push esi
	push edi
	cmp dword ptr [77416078], 00
	jne 773F1616
	js 773E798D

	jmp 773E792D

	// normal stdcall hook func with the same signature as send
	testhook2:
	push ebp
	mov ebp, esp
	// do shit
	pop ebp
	ret 10

	[Disable]
	WS2_32.send + 5:
	mov eax,[77416054]
	sub esp,1C
	push ebx
	push esi
	push edi
	cmp dword ptr [77416078], 00
	jne 773F1616
	js 773E798D

	dealloc(testhook)
	dealloc(testhook2)
*/

namespace wxPloiter
{
	namespace detours = utils::detours;

	const std::string wsockhooks::tag = "maple::wsockhooks";
	const size_t wsockhooks::header_size = sizeof(dword);
	boost::shared_ptr<wsockhooks> wsockhooks::inst; // singleton

	boost::shared_ptr<wsockhooks> wsockhooks::get()
	{
		if (!inst.get())
			inst.reset(new wsockhooks);

		return inst;
	}

	wsockhooks::wsockhooks()
		: 
#ifndef STEALTH_HOOKS
		  pconnect(::connect), 
		  psend(::send), 
		  precv(::recv), 
#else
		  pconnect(reinterpret_cast<pfnconnect>(_pconnect)), 
		  psend(reinterpret_cast<pfnsend>(_psend)), 
		  precv(reinterpret_cast<pfnrecv>(_precv)), 
#endif
		  log(utils::logging::get()),
		  transition(false), 
		  targetsocket(NULL),
		  hooked(false)
	{
		// get actual addresses of send, recv and connect.
		// local ones might be messed up (local recv didn't work for example)
		HMODULE hws2_32 = GetModuleHandle(_T("ws2_32.dll"));
		pfnconnect realconnect = reinterpret_cast<pfnconnect>(GetProcAddress(hws2_32, "connect"));
		pfnsend realsend = reinterpret_cast<pfnsend>(GetProcAddress(hws2_32, "send"));
		pfnrecv realrecv = reinterpret_cast<pfnrecv>(GetProcAddress(hws2_32, "recv"));

		if (!realconnect)
		{
			log->w(tag, "wsockhooks: failed to get the real address of connect(). "
				"decryption might fail to grab the cypher keys.");
			realconnect = ::connect;
		}

		if (!realsend)
		{
			log->w(tag, "wsockhooks: failed to get the real address of send(). "
				"the send hook might not work.");
			realsend = ::send;
		}

		if (!realrecv)
		{
			log->w(tag, "wsockhooks: failed to get the real address of recv(). "
				"the recv hook might not work.");
			realrecv = ::recv;
		}

#ifndef STEALTH_HOOKS
		pconnect = realconnect;
		psend = realsend;
		precv = realrecv;

		if (!detours::hook(true, reinterpret_cast<PVOID *>(&pconnect), connect_hook))
		{
			log->e(tag, "wsockhooks: could not hook connect(). logging and decryption will not work.");
			return;
		}

		bool sendhooked = detours::hook(true, reinterpret_cast<PVOID *>(&psend), send_hook);
		bool recvhooked = detours::hook(true, reinterpret_cast<PVOID *>(&precv), recv_hook);

		if (!sendhooked)
			log->w(tag, "wsockhooks: could not hook send(). send logging will not work.");
		
		if (!recvhooked)
			log->w(tag, "wsockhooks: could not hook recv(). recv logging will not work.");

		if (!sendhooked && !recvhooked)
		{
			log->e(tag, "wsockhooks: could not hook send() and recv(). logging will not work.");
			return;
		}
#else
		connecthookret = reinterpret_cast<dword>(realconnect) + 0x13;
		sendjump1 = reinterpret_cast<dword>(utils::mem::getjump(reinterpret_cast<byte *>(realsend) + 0x15));
		sendhookret = reinterpret_cast<dword>(realsend) + 0x1B;
		sendmov1 = *reinterpret_cast<dword *>(reinterpret_cast<byte *>(realsend) + 0x6);
		sendcmp1 = *reinterpret_cast<dword *>(reinterpret_cast<byte *>(realsend) + 0x11);
		recvjump1 = reinterpret_cast<dword>(utils::mem::getjump(reinterpret_cast<byte *>(realrecv) + 0x15));
		recvhookret = reinterpret_cast<dword>(realrecv) + 0x1B;

		byte connect_bytes[14] = {
			0xFF, 0x75, 0x10, // push [ebp+10]
			0xFF, 0x75, 0x0C, // push [ebp+0C]
			0xFF, 0x75, 0x08, // push [ebp+08]
			0xE8, 0x00, 0x00, 0x00, 0x00 // call ????????
		};
		utils::mem::makepagewritable(reinterpret_cast<byte *>(realconnect) + 5, 14);
		memcpy_s(reinterpret_cast<byte *>(realconnect) + 5, 14, connect_bytes, 14);
		utils::mem::writecall(reinterpret_cast<byte *>(realconnect) + 5 + 9, connect_relay);

		byte send_bytes[22] = {
			0xFF, 0x75, 0x14, // push [ebp+14]
			0xFF, 0x75, 0x10, // push [ebp+10]
			0xFF, 0x75, 0x0C, // push [ebp+0C]
			0xFF, 0x75, 0x08, // push [ebp+08]
			0xE8, 0x00, 0x00, 0x00, 0x00, // call ????????
			0x90, 0x90, 0x90, 0x90, 0x90 // nop nop nop...
		};
		utils::mem::makepagewritable(reinterpret_cast<byte *>(realsend) + 5, 22);
		memcpy_s(reinterpret_cast<byte *>(realsend) + 5, 22, send_bytes, 22);
		utils::mem::writecall(reinterpret_cast<byte *>(realsend) + 5 + 12, send_relay);

		byte recv_bytes[22] = {
			0xFF, 0x75, 0x14, // push [ebp+14]
			0xFF, 0x75, 0x10, // push [ebp+10]
			0xFF, 0x75, 0x0C, // push [ebp+0C]
			0xFF, 0x75, 0x08, // push [ebp+08]
			0xE8, 0x00, 0x00, 0x00, 0x00, // call ????????
			0x90, 0x90, 0x90, 0x90, 0x90 // nop nop nop...
		};
		utils::mem::makepagewritable(reinterpret_cast<byte *>(realrecv) + 5, 22);
		memcpy_s(reinterpret_cast<byte *>(realrecv) + 5, 22, recv_bytes, 22);
		utils::mem::writecall(reinterpret_cast<byte *>(realrecv) + 5 + 12, recv_relay);
#endif

		hooked = true;
	}

	wsockhooks::~wsockhooks()
	{
		// empty
	}

#ifdef STEALTH_HOOKS
	dword wsockhooks::connecthookret = 0;

	void __declspec(naked) wsockhooks::_pconnect()
	{
		__asm
		{
			mov edi,edi
			push ebp
			mov ebp,esp

			sub esp,0x14
			push ebx
			push esi
			push edi
			lea eax,[ebp-0x14]
			push eax
			lea eax,[ebp-0x10]
			push eax

			jmp [connecthookret]
		}
	}

	dword wsockhooks::sendjump1 = 0;
	dword wsockhooks::sendhookret = 0;
	dword wsockhooks::sendmov1 = 0;
	dword wsockhooks::sendcmp1 = 0;

	void __declspec(naked) wsockhooks::_psend()
	{
		__asm
		{
			mov edi,edi
			push ebp
			mov ebp,esp

			mov eax,dword ptr [sendmov1]
			mov eax,[eax]
			sub esp,0x1C
			push ebx
			push esi
			push edi
			cmp eax,[sendcmp1]
			jne crap1
			jmp [sendhookret]

crap1:
			jmp [sendjump1]
		}
	}

	dword wsockhooks::recvjump1 = 0;
	dword wsockhooks::recvhookret = 0;

	void __declspec(naked) wsockhooks::_precv()
	{
		__asm
		{
			mov edi,edi
			push ebp
			mov ebp,esp

			mov eax,dword ptr [sendmov1]
			mov eax,[eax]
			sub esp,0x1C
			push ebx
			push esi
			push edi
			cmp eax,[sendcmp1]
			je crap1
			jmp [recvhookret]

crap1:
			jmp [recvjump1]
		}
	}

	void __declspec(naked) wsockhooks::connect_relay()
	{
		// hooking method is explained in send_relay
		__asm
		{
			push ebp
			mov ebp, esp

			push [ebp+0x10]
			push [ebp+0x0C]
			push [ebp+0x08]
			call connect_hook

			pop ebp

			add esp, 0x10

			pop ebp

			ret 0x0C
		}
	}

	void __declspec(naked) wsockhooks::send_relay()
	{
		__asm
		{
			// stdcall prolog
			push ebp
			mov ebp, esp

			// push params and call send hook
			push [ebp+0x14]
			push [ebp+0x10]
			push [ebp+0x0C]
			push [ebp+0x08]
			call send_hook

			// stdcall epilog of send_relay
			pop ebp

			// we need to inject code to make send() return now so instead of ret 10
			// we're gonna pop the 4 arguments and the return address here so that the 
			// status of the stack is as if send_relay returned, then we're gonna execute 
			// the epilog of send() and ret

			add esp,0x14 // pop 5 times (4 args + ret addy, same as doing ret 0x10)

			// stack is now clean as if send_relay returned

			// stdcall epilog of WS2_32.send
			pop ebp

			// return value is already in eax (returned by send_hook)
			ret 0x10
		}
	}

	void __declspec(naked) wsockhooks::recv_relay()
	{
		// hooking method is explained in send_relay
		__asm
		{
			push ebp
			mov ebp, esp

			push [ebp+0x14]
			push [ebp+0x10]
			push [ebp+0x0C]
			push [ebp+0x08]
			call recv_hook

			pop ebp

			add esp, 0x14

			pop ebp

			ret 0x10
		}
	}
#endif

	bool wsockhooks::ishooked()
	{
		return hooked;
	}

	// hooks
	int WINAPI wsockhooks::connect_hook(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen)
	{
		return get()->connect(s, name, namelen);
	}

	int WINAPI wsockhooks::send_hook(_In_ SOCKET s, _In_ const char *buf, _In_ int len, _In_ int flags)
	{
		//get()->log->i(tag, strfmt() << "send_hook(" << s << ", " << reinterpret_cast<dword>(buf) << ", " << len << ", " << flags << ")");
		return get()->send(s, buf, len, flags);
	}

	int WINAPI wsockhooks::recv_hook(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags)
	{
		return get()->recv(s, buf, len, flags);
	}

	int wsockhooks::connect(_In_ SOCKET s, _In_ const struct sockaddr *name, _In_ int namelen)
	{
		sockaddr_in sin; // we need to copy the sockaddr struct if we want to edit the ip because name is const
		memcpy_s(&sin, sizeof(sockaddr), name, sizeof(sockaddr_in));

		// store the real port
		u_short port = ntohs(sin.sin_port);

		// TODO: let the user set the ports
		if (port == 8484 || port == 8586)
		{
#ifdef WINSOCK_MUTEX
			mutex::scoped_lock lock(sendmut);
			mutex::scoped_lock lock2(recvmut);
#endif

			targetsocket = s;
			transition = true;

			wxString serv = 
				port == 8484 ? "LoginServer" :
				port == 8586 ? "ChannelServer" : wxString::Format("Unknown (%hu)", port);

			recvcrypt.reset();
			sendcrypt.reset();

			wxLogStatus(wxString::Format("Server transition to %s in progress...", serv));
		}

		// convert ip to string by casting sockaddr struct to sockaddr_in and using inet_ntoa
		std::string ip = inet_ntoa(sin.sin_addr);
		log->i(tag, strfmt() << "connect@0x" << _ReturnAddress() << ": socket=" << s << 
			", name=" << ip << ":" << port << ", namelen=" << namelen);

		return pconnect(s, name, namelen); // forward clean call
	}

	int wsockhooks::send(_In_ SOCKET s, _In_ const char *buf, _In_ int len, _In_ int flags)
	{
#ifdef WINSOCK_MUTEX
		mutex::scoped_lock lock(sendmut);
#endif

		if (s != targetsocket)
			return psend(s, buf, len, flags);

		bool dec = false;
		const byte *pcbbuf = reinterpret_cast<const byte *>(buf);
		byte *pbbuf = const_cast<byte *>(pcbbuf);

		boost::shared_ptr<maple::packet> p;

		sendbuf.insert(sendbuf.end(), pbbuf, pbbuf + len);

		//log->i(tag, strfmt() << "send@0x" << _ReturnAddress() << " to " << s);

		while (sendbuf.size() >= header_size)
		{
			word actuallen = maple::crypt::length(&sendbuf[0]);

			if (!sendcrypt.get() || actuallen < 2 || !sendcrypt->check(&sendbuf[0]))
				p.reset(new maple::packet(&sendbuf[0], len));
			else
			{
				p.reset(new maple::packet(&sendbuf[0] + header_size, actuallen));
				sendcrypt->decrypt(p->raw(), p->size());
				sendcrypt->nextiv();

				word *pheader = reinterpret_cast<word *>(p->raw());

				if (safeheaderlist::getblockedsend()->contains(*pheader))
				{
					// TODO: buffer all send/recv data and process it later on from another thread so that
					// I can block packets before part of them is already sent
				}

				dec = true;
			}

			mainform::get()->queuepacket(p, mainform::wxID_PACKET_SEND, dec, NULL);

			//log->i(tag, strfmt() << (dec ? "decrypted" : "encrypted") << ": " << p->tostring());

			sendbuf.erase(sendbuf.begin(), sendbuf.begin() + p->size());
			sendbuf.erase(sendbuf.begin(), sendbuf.begin() + header_size);
		}

		return psend(s, buf, len, flags);
	}

	int wsockhooks::recv(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags)
	{
#ifdef WINSOCK_MUTEX
		mutex::scoped_lock lock(recvmut);
#endif

		const byte *pcbbuf = reinterpret_cast<const byte *>(buf);
		int res = precv(s, buf, len, flags);

		// recieved the hello packet
		if (transition)
		{
			if (res <= 2) // hello packet header
				return res;

			// hello packet
			// 0E 00 vv vv 01 00 31 ss ss ss ss rr rr rr rr tt
			// vv = maple version
			// ss = send key
			// rr = recv key
			// tt = server type
			try
			{
#ifdef WINSOCK_MUTEX
				mutex::scoped_lock lock2(sendmut);
#endif

				word maple_version = 0;
				std::string unknown;
				byte ivsend[4] = {0};
				byte ivrecv[4] = {0};
				byte server_type = 0;

				maple::packet p(pcbbuf, res);
				maple::packet::iterator it = p.begin();
				p.read<word>(&maple_version, it);
				p.read_string(unknown, it);
				p.read<dword>(reinterpret_cast<dword *>(ivsend), it);
				p.read<dword>(reinterpret_cast<dword *>(ivrecv), it);
				p.read<byte>(&server_type, it);

				log->i(tag, 
					strfmt() <<"encryption initialized - maple version: " << maple_version << 
					", unknown string: " << unknown 
					<< std::hex << std::setfill('0') << std::uppercase 
					<< ", ivsend: 0x" << std::setw(8) << *reinterpret_cast<dword *>(ivsend) << 
					", ivrecv: 0x" << std::setw(8) << *reinterpret_cast<dword *>(ivrecv) << 
					", server type: " << std::dec << static_cast<word>(server_type)
				);

				wxLogStatus(wxString::Format(
					"Encryption initialized - MapleStory v%hu {%s, 0x%.8X, 0x%.8X, %hu}", 
					maple_version, wxString(unknown.c_str()), *reinterpret_cast<dword *>(ivsend),
					*reinterpret_cast<dword *>(ivrecv), server_type));

				sendcrypt.reset(new maple::crypt(maple_version, ivsend));
				recvcrypt.reset(new maple::crypt(0xFFFF - maple_version, ivrecv));
			}
			catch (const maple::readexception &)
			{
				log->wtf(tag, "unexpected end of initialization packet");
			}

			transition = false;
		}

		else if (res > 0 && s == targetsocket)
		{
			//log->i(tag, strfmt() << "recv@0x" << _ReturnAddress() << 
				//" from " << s << " [" << res << "/" << len << " bytes]");

			byte *pbbuf = reinterpret_cast<byte *>(buf);
			boost::shared_ptr<maple::packet> p;

			recvbuf.insert(recvbuf.end(), pbbuf, pbbuf + res);

			while (recvbuf.size() >= header_size)
			{
				bool dec = false;
				word actuallen = maple::crypt::length(&recvbuf[0]);

				if (!recvcrypt.get() || actuallen < 2 || !recvcrypt->check(&recvbuf[0]))
				{
					p.reset(new maple::packet(pcbbuf, res));
					//log->i(tag, strfmt() << "encrypted, size=" << p->size() << ": " << p->tostring());
					mainform::get()->queuepacket(p, mainform::wxID_PACKET_RECV, dec, NULL);
				}
				else
				{
					if (actuallen > recvbuf.size() - header_size)
					{
						//log->i(tag, "waiting for more data");
						break;
					}

					p.reset(new maple::packet(&recvbuf[0] + header_size, actuallen));
					recvcrypt->decrypt(p->raw(), p->size());
					recvcrypt->nextiv();

					word *pheader = reinterpret_cast<word *>(p->raw());

					if (safeheaderlist::getblockedrecv()->contains(*pheader))
					{
						// block packet
						*pheader = BLOCKED_HEADER;

						// re-encrypt modified packet and send it
						// TODO: skip the packet completely and compensate for the messed up recv cypher
						size_t cbenc = p->size() + header_size;
						recvcrypt->makeheader(pbbuf + res - recvbuf.size(), p->size());
						std::copy(p->begin(), p->end(), pbbuf + res - recvbuf.size() + header_size);
						recvcrypt->encrypt(pbbuf + res - recvbuf.size() + header_size, p->size());
					}
					else
					{
						dec = true;
						//log->i(tag, strfmt() << "decrypted, size=" << p->size() << ": " << p->tostring());
						mainform::get()->queuepacket(p, mainform::wxID_PACKET_RECV, dec, NULL);
					}
				}

				recvbuf.erase(recvbuf.begin(), recvbuf.begin() + p->size());
				recvbuf.erase(recvbuf.begin(), recvbuf.begin() + header_size);
			}
		}

		return res;
	}
}
