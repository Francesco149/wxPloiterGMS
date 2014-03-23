#pragma once

#include "common.h"

#include <botan/lookup.h>

namespace maple
{
	// utility for maplestory's aes encryption
	// note: botan must be initialized before using this class
	// credits to vana for this slimmer encryption using botan
	class aes
	{
	public:
		static aes *get();
		virtual ~aes();
		void decrypt(byte *buffer, byte *iv, signed_dword cb);
		void encrypt(byte *buffer, byte *iv, signed_dword cb);

	protected:
		static const signed_dword cb_aeskey; // size of the aes key
		static const byte aeskey[]; // aes key
		static const signed_dword blocksize; // aes block size

		Botan::OctetString botankey; // symmetric key for AES encryption

		aes();
	};
}
