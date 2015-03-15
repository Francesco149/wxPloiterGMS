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

#include "process_utils.h"

#include <windows.h>
#include <tlhelp32.h>
#include <assert.h>

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
uint32_t process_getinfo(__inout char *buf, size_t bufsize, __inout uint32_t *pdw, uint32_t key, uint32_t value, int index) {
	PROCESSENTRY32 pe;
	HANDLE snapshot;
	int found = 0;
	int matchindex = -1;
	BOOL res;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	res = Process32First(snapshot, &pe);

	while (res) {
		switch (key) {
		case PROCESS_ID:
			found = pe.th32ProcessID == *pdw;
			break;

		case PROCESS_THREADS:
			found = pe.cntThreads == *pdw;
			break;

		case PROCESS_PARENTID:
			found = pe.th32ParentProcessID == *pdw;
			break;

		case PROCESS_PRICLASSBASE:
			found = pe.pcPriClassBase == (LONG)*pdw;
			break;

		case PROCESS_NAME:
			found = strstr(pe.szExeFile, buf) != NULL;
			break;
		default:
			assert(0);
		}

		if (found) {
			matchindex++;
			if (matchindex != index) {
				continue;
			}

			/* I could also return the entire PROCESSENTRY32 struct and let
			the caller get the info it wants, but I find it simpler this way,
			as the struct has many deprecated, unused members */
			switch (value) {
			case PROCESS_ID:
				*pdw = pe.th32ProcessID;
				return ERROR_SUCCESS;

			case PROCESS_THREADS:
				*pdw = pe.cntThreads;
				return ERROR_SUCCESS;

			case PROCESS_PARENTID:
				*pdw = pe.th32ParentProcessID;
				return ERROR_SUCCESS;

			case PROCESS_PRICLASSBASE:
				*pdw = pe.pcPriClassBase;
				return ERROR_SUCCESS;

			case PROCESS_NAME:
				strcpy_s(buf, bufsize, pe.szExeFile);
				return ERROR_SUCCESS;
			default:
				assert(0);
			}
		}

		res = Process32Next(snapshot, &pe);
	}

	*pdw = 0;
	memset(buf, 0, bufsize);
	return GetLastError();
}

/*
 * stores the pid of the first process that matches the given name in *ppid.
 * returns the value of GetLastError().
 * if the function fails, *ppid will be set to zero.
 */
uint32_t process_pidbyname(__in const char *processname, __out uint32_t *ppid) {
	return process_getinfo((char *)processname, 0, ppid, PROCESS_NAME, PROCESS_ID, 0);
}

/*
 * stores the pid of the first process that matches the given name in *ppid.
 * returns the value of GetLastError().
 * if the function fails, buf will contain an empty string.
 */
uint32_t process_namebypid(uint32_t pid, __out char *buf, size_t bufsize) {
	return process_getinfo(buf, bufsize, &pid, PROCESS_ID, PROCESS_NAME, 0);
}
