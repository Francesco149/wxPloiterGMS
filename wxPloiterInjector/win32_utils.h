/*
	Copyright 2014 Franc[e]sco (lolisamurai@tfwno.gf)
	This file is part of Oppai_QuickInjector 2015.
	Oppai_QuickInjector 2015 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	Oppai_QuickInjector 2015 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with Oppai_QuickInjector 2015. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __WIN32_UTILS__
#define __WIN32_UTILS__

#include <windows.h>
#include <stdint.h>

/*
 * prints to stdout an arbitrary error message followed by GetLastError and the error code and message.
 * if GetLastError is zero, the call will be ignored and no message will be displayed.
 */
void win32_show_error(const char *msg);

/* injects the given dll into pid. returns zero on failure (check GetLastError for details). */
int win32_injectdll(uint32_t pid, const char *file);

#endif