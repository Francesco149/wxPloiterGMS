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

#include "aes.hpp"

#include <botan/pipe.h>
#include <botan/filters.h>

namespace maple
{
	const signed_dword aes::cb_aeskey = 32;

	const byte aes::aeskey[aes::cb_aeskey] = 
	{
		0x13, 0x00, 0x00, 0x00, 
		0x08, 0x00, 0x00, 0x00, 
		0x06, 0x00, 0x00, 0x00, 
		0xB4, 0x00, 0x00, 0x00,
		0x1B, 0x00, 0x00, 0x00, 
		0x0F, 0x00, 0x00, 0x00, 
		0x33, 0x00, 0x00, 0x00, 
		0x52, 0x00, 0x00, 0x00
	};

	const signed_dword aes::blocksize = 1460;

	aes *aes::get()
	{
		static aes inst;
		return &inst;
	}

	aes::aes()
		: botankey(Botan::SymmetricKey(aeskey, cb_aeskey))
	{
		// empty
	}

	aes::~aes()
	{
		// empty
	}

	void aes::encrypt(byte *buffer, byte *iv, signed_dword cb)
	{
        signed_dword pos = 0;
        byte first = 1;
        signed_dword tpos = 0;
        signed_dword cbwrite = 0;
        Botan::InitializationVector initvec(iv, 16);

		while (cb > pos) 
		{
			tpos = blocksize - first * 4;
			cbwrite = (cb > (pos + tpos) ? tpos : (cb - pos));

			Botan::Pipe pipe(Botan::get_cipher("AES-256/OFB/NoPadding", 
				botankey, initvec, Botan::ENCRYPTION));
			pipe.start_msg();
			pipe.write(buffer + pos, cbwrite);
			pipe.end_msg();

			// process the message and write it into the buffer
			pipe.read(buffer + pos, cbwrite);

			pos += tpos;

			if (first)
				first = 0;
		}
	}

	void aes::decrypt(byte *buffer, byte *iv, signed_dword cb)
	{
		signed_dword pos = 0;
		byte first = 1;
		signed_dword tpos = 0;
		signed_dword cbread = 0;
		Botan::InitializationVector initvec(iv, 16);

		while (cb > pos) 
		{
			tpos = blocksize - first * 4;
			cbread = (cb > (pos + tpos) ? tpos : (cb - pos));

			Botan::Pipe pipe(Botan::get_cipher("AES-256/OFB/NoPadding", 
				botankey, initvec, Botan::DECRYPTION));
			pipe.start_msg();
			pipe.write(buffer + pos, cbread);
			pipe.end_msg();

			// process the message and write it into the buffer
			pipe.read(buffer + pos, cbread);

			pos += tpos;

			if (first)
				first = 0;
		}
	}
}
