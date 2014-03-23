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

#include <cstddef>
#include <cstdint>

typedef uint8_t byte;
typedef int8_t signed_byte;
typedef uint16_t word;
typedef int16_t signed_word;
typedef uint32_t dword;
typedef int32_t signed_dword;
typedef uint64_t qword; // my 64bit integers will pierce through the heavens!
typedef int64_t signed_qword;

#define BLOCKED_HEADER -1
