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
