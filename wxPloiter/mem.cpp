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

#include "mem.h"
#include "checksumhack.hpp"

#include <dbghelp.h>
#include <psapi.h>
#pragma  comment(lib, "dbghelp")
#pragma  comment(lib, "psapi")

#define jmp(frm, to) (int)(((int)to - (int)frm) - 5)

namespace utils {
namespace mem
{
	bool getmodulesize(HMODULE hModule, void **pbase, size_t *psize)
	{
		CHECKSUM_HACK()
		if (hModule == GetModuleHandle(NULL))
		{
			PIMAGE_NT_HEADERS pImageNtHeaders = ImageNtHeader((PVOID)hModule);

			if (pImageNtHeaders == NULL)
				return false;

			*pbase = reinterpret_cast<void *>(hModule);
			*psize = pImageNtHeaders->OptionalHeader.SizeOfImage;
		}
		else
		{
			MODULEINFO ModuleInfo;

			if (!GetModuleInformation(GetCurrentProcess(), hModule, &ModuleInfo, sizeof(MODULEINFO)))
				return FALSE;

			*pbase = ModuleInfo.lpBaseOfDll;
			*psize = ModuleInfo.SizeOfImage;
		}

		return true;
	}

	byte *getopcodedestination(byte opcode, byte *address)
	{
		CHECKSUM_HACK()
		if (*address == opcode)
			return (address + 5 + *reinterpret_cast<int *>(address + 1));

		return NULL;
	}

	byte *getcall(byte *address)
	{
		CHECKSUM_HACK()
		return getopcodedestination(0xE8, address);
	}

	byte *getjump(byte *address)
	{
		CHECKSUM_HACK()
		if (*address == 0x0F) // conditional jmp
			return (address + 6 + *reinterpret_cast<int *>(address + 2));

		return getopcodedestination(0xE9, address);
	}

	dword makepagewritable(void *address, size_t cb, dword flprotect) 
	{
		CHECKSUM_HACK()
		MEMORY_BASIC_INFORMATION mbi = {0};
		VirtualQuery(address, &mbi, cb);

		if (mbi.Protect != flprotect)
		{
			DWORD oldprotect;
			VirtualProtect(address, cb, flprotect, &oldprotect);
			return oldprotect;
		}

		return flprotect;
	}

	void writeopcodewithdistance(byte opcode, byte *address, void *destination, size_t nops)
	{
		CHECKSUM_HACK()
		makepagewritable(address, 5 + nops);
		*address = opcode;
		*reinterpret_cast<dword *>(address + 1) = jmp(address, destination);
		memset(address + 5, 0x90, nops);
	}

	void writejmp(byte *address, void *hook, size_t nops)
	{
		CHECKSUM_HACK()
		writeopcodewithdistance(0xE9, address, hook, nops);
	}

	void writecall(byte *address, void *hook, size_t nops)
	{
		CHECKSUM_HACK()
		writeopcodewithdistance(0xE8, address, hook, nops);
	}
}}
