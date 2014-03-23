#include "mem.h"

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
		if (*address == opcode)
			return (address + 5 + *reinterpret_cast<int *>(address + 1));

		return NULL;
	}

	byte *getcall(byte *address)
	{
		return getopcodedestination(0xE8, address);
	}

	byte *getjump(byte *address)
	{
		return getopcodedestination(0xE9, address);
	}

	dword makepagewritable(void *address, size_t cb, dword flprotect) 
	{
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
		makepagewritable(address, 5 + nops);
		*address = 0xE9;
		*reinterpret_cast<dword *>(address + 1) = jmp(address, destination);
		memset(address + 5, 0x90, nops);
	}

	void writejmp(byte *address, void *hook, size_t nops)
	{
		writeopcodewithdistance(0xE9, address, hook, nops);
	}

	void writecall(byte *address, void *hook, size_t nops)
	{
		writeopcodewithdistance(0xE8, address, hook, nops);
	}
}}
