#pragma once

#include "common.h"

namespace maple
{
	class crypt
	{
	public:
		crypt(word maple_version, byte *iv);
		virtual ~crypt();
		word getmapleversion();
		void encrypt(byte *buffer, signed_dword cb); // used to encrypt send packets
		void decrypt(byte *buffer, signed_dword cb); // used to decrypt send packets
		bool check(byte *buffer); // checks whether a packet is encrypted
		void makeheader(byte *buffer, word cb); // create an encrypted header for a send packet
		void nextiv(); // shuffles the encryption key
		static word length(byte *header); // gets the length of the packet from the encrypted header

	protected:
		word maple_version;
		byte iv[16]; // cypher key

		static void nextiv(byte *vector); // shuffles the cypher key
		static void mapledecrypt(byte *buf, signed_dword size); // custom maple decryption layer
		static void maplecrypt(byte *buf, signed_dword size); // custom maple encryption layer
	};
}
