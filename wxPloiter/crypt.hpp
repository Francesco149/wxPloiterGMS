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
