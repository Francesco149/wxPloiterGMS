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
