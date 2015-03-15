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

#ifndef __PROCESS_UTILS_H__
#define __PROCESS_UTILS_H__

#include <stdint.h>

#define PROCESS_ID 0L
#define PROCESS_THREADS 1L
#define PROCESS_PARENTID 2L
#define PROCESS_PRICLASSBASE 3L
#define PROCESS_NAME 4L

/*
 * iterates the process list and finds the index-th value that matches the given key.
 * returns the value of GetLastError().
 * if the function fails, *pdw will be set to zero.
 *
 * key input:
 * - if key is PROCESS_NAME, buf must contain the process name and bufsize must be zero.
 * - for every other key value, pdw must point to a 32-bit integer that contains your input key value.
 *
 * value output:
 * - if value is PROCESS_NAME, the result will be stored in buf. in this case,
 *   buf must point to an empty buffer and bufsize must be set to the maximum capacity of the buffer.
 * - for any other type of value, the result will be stored in the 32-bit integer pointed by pdw and
 *   buf and bufsize will be ignored unless they are used for the key.
 *
 * possible values for key / value:
 * PROCESS_ID: the process identifier
 * PROCESS_THREADS: the number of execution threads started by the process
 * PROCESS_PARENTID: the identifier of the process that created this process (its parent process)
 * PROCESS_PRICLASSBASE: the base priority of any threads created by this proces
 * PROCESS_NAME: the name of the executable file for the process
 */
uint32_t process_getinfo(__inout char *buf, size_t bufsize, __inout uint32_t *pdw, uint32_t key, uint32_t value, int index);

/*
 * stores the pid of the first process that matches the given name in *ppid.
 * returns the value of GetLastError().
 * if the function fails, *ppid will be set to zero.
 */
uint32_t process_pidbyname(__in const char *processname, __out uint32_t *ppid);

/*
 * stores the pid of the first process that matches the given name in *ppid.
 * returns the value of GetLastError().
 * if the function fails, buf will contain an empty string.
 */
uint32_t process_namebypid(uint32_t pid, __out char *buf, size_t bufsize);

#endif
