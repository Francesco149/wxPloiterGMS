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
	// internal maplestory packet structs
	// credits to waffle or whoever made 21st century PE

	#pragma pack(push, 1)
	struct outpacket
	{
		dword fLoopback; // win32 BOOL = int. that's fucking stupid.
		union
		{
			byte *pbData;
			void *pData;
			word *pwHeader;
		};
		dword cbData;
		dword uOffset;
		dword fEncryptedByShanda;
	};

	struct inpacket
	{
		dword fLoopback; // 0
		signed_dword iState; // 2
		union
		{
			void *lpvData;
			struct 
			{
				dword dw;
				word wHeader;
			} *pHeader;
			struct 
			{
				dword dw;
				byte bData[0];
			} *pData;
		};
		dword dwTotalLength;
		dword dwUnknown;
		dword dwValidLength;
		dword uOffset;
	};
	#pragma pack(pop)
}
