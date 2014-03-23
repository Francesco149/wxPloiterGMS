#include "wsockhooks.hpp"

#include "mainform.hpp"
#include "utils.hpp"

#include <tchar.h>
#include <boost/scoped_array.hpp>
#include <iomanip>

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
		: pconnect(::connect), 
		  psend(::send), 
		  precv(::recv), 
		  log(utils::logging::get()),
		  transition(false), 
		  targetsocket(NULL),
		  hooked(false)
	{
		// get actual addresses of send, recv and connect.
		// local ones might be messed up (local recv didn't work for example)
		HMODULE hws2_32 = GetModuleHandle(_T("ws2_32.dll"));
		pconnect = reinterpret_cast<pfnconnect>(GetProcAddress(hws2_32, "connect"));
		psend = reinterpret_cast<pfnsend>(GetProcAddress(hws2_32, "send"));
		precv = reinterpret_cast<pfnrecv>(GetProcAddress(hws2_32, "recv"));

		if (!pconnect)
		{
			log->w(tag, "wsockhooks: failed to get the real address of connect(). "
				"decryption might fail to grab the cypher keys.");
			pconnect = ::connect;
		}

		if (!psend)
		{
			log->w(tag, "wsockhooks: failed to get the real address of send(). "
				"the send hook might not work.");
			psend = ::send;
		}

		if (!precv)
		{
			log->w(tag, "wsockhooks: failed to get the real address of recv(). "
				"the recv hook might not work.");
			precv = ::recv;
		}

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

		hooked = true;
	}

	wsockhooks::~wsockhooks()
	{
		// empty
	}

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

		if (port == 8484 || port == 8585)
		{
			mutex::scoped_lock lock(sendmut);
			mutex::scoped_lock lock2(recvmut);

			targetsocket = s;
			transition = true;

			wxString serv = 
				port == 8484 ? "LoginServer" :
				port == 8585 ? "ChannelServer" : wxString::Format("Unknown (%hu)", port);

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
		mutex::scoped_lock lock(sendmut);

		if (s == targetsocket)
		{
			bool dec = false;
			const byte *pcbbuf = reinterpret_cast<const byte *>(buf);
			byte *pbbuf = const_cast<byte *>(pcbbuf);
			// TODO: fix const issues in the packet class -_-

			boost::shared_ptr<maple::packet> p;

			if (!sendcrypt.get() || !sendcrypt->check(pbbuf))
				p.reset(new maple::packet(pcbbuf, len));
			else
			{
				p.reset(new maple::packet(pcbbuf + header_size, maple::crypt::length(pbbuf)));
				sendcrypt->decrypt(p->raw(), p->size());
				sendcrypt->nextiv();

				word *pheader = reinterpret_cast<word *>(p->raw());

				if (safeheaderlist::getblockedsend()->contains(*pheader))
				{
					// this is probabilly not gonna work. 
					// TODO: keep track of the client and the server's cyphers and skip the packet completely

					// block packet
					*pheader = BLOCKED_HEADER;

					// re-encrypt modified packet and send it
					size_t cbenc = p->size() + header_size;
					boost::scoped_array<byte> bbuf(new byte[cbenc]);
					sendcrypt->makeheader(bbuf.get(), p->size());
					std::copy(p->begin(), p->end(), bbuf.get() + header_size);
					sendcrypt->encrypt(bbuf.get() + header_size, p->size());

					return psend(s, reinterpret_cast<const char *>(bbuf.get()), cbenc, 0);
				}

				dec = true;
			}

			mainform::get()->queuepacket(p, mainform::wxID_PACKET_SEND, dec, NULL);

			/*
			log->i(tag, strfmt() << "send@0x" << _ReturnAddress() << 
				" to " << s << ", " << (dec ? "decrypted" : "encrypted") << ": " << p->tostring());
			*/
		}

		return psend(s, buf, len, flags);
	}

	int wsockhooks::recv(_In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags)
	{
		mutex::scoped_lock lock(recvmut);

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
				mutex::scoped_lock lock2(sendmut);

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
			bool dec = false;
			byte *pbbuf = reinterpret_cast<byte *>(buf);
			boost::shared_ptr<maple::packet> p;

			if (!recvcrypt.get() || !recvcrypt->check(pbbuf))
				p.reset(new maple::packet(pcbbuf, res));
			else
			{
				p.reset(new maple::packet(pbbuf + header_size, maple::crypt::length(pbbuf)));
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
					recvcrypt->makeheader(reinterpret_cast<byte *>(buf), p->size());
					std::copy(p->begin(), p->end(), buf + header_size);
					recvcrypt->encrypt(reinterpret_cast<byte *>(buf + header_size), p->size());

					return res;
				}

				dec = true;
			}

			mainform::get()->queuepacket(p, mainform::wxID_PACKET_RECV, dec, NULL);

			/*
			log->i(tag, strfmt() << "recv@0x" << _ReturnAddress() << 
				" from " << s << " [" << res << "/" << len << " bytes], " << 
				(dec ? "decrypted" : "encrypted") << ": " << p->tostring());
			*/
		}

		return res;
	}
}
