/*
	Copyright 2014 Franc[e]sco (lolisamurai@tfwno.gf)
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

// inserts a block that assembles to "CC 90 CC CC 90 90 60 61 60 61 90 90 CC CC 90 CC" (16 bytes).
// the injector is then supposed to replace every occurrence of this block with random data
// so that the checksum is randomized.
#define CHECKSUM_HACK() \
	__asm {				\
	__asm jmp skip		\
	__asm int 3			\
	__asm nop			\
	__asm int 3			\
	__asm int 3			\
	__asm nop			\
	__asm nop			\
	__asm pushad		\
	__asm popad			\
	__asm pushad		\
	__asm popad			\
	__asm nop			\
	__asm nop			\
	__asm int 3			\
	__asm int 3			\
	__asm nop			\
	__asm int 3			\
	__asm skip:			\
	}