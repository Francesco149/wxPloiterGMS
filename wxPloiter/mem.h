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
