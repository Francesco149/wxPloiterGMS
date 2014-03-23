#pragma once

#include "common.h"
#include <Windows.h>

namespace utils {
// utilities to read & write memory
namespace mem
{
	bool getmodulesize(HMODULE hModule, void **pbase, size_t *psize);
	byte *getcall(byte *address);
	byte *getjump(byte *address);
	dword makepagewritable(void *address, size_t cb, dword flprotect = PAGE_EXECUTE_READWRITE);
	void writejmp(byte *address, void *hook, size_t nops = 0);
	void writecall(byte *address, void *hook, size_t nops = 0);
}}
