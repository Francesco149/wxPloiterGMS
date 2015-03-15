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

#include "win32_utils.h"
#include <windows.h>
#include <stdio.h>

/*
* prints to stdout an arbitrary error message followed by GetLastError and the error code and message.
* if GetLastError is zero, the call will be ignored and no message will be displayed.
*/
void win32_show_error(const char *msg) {
	DWORD gle;
	char *gle_msg;

	gle = GetLastError();
	if (!gle) {
		return;
	}

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, gle,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&gle_msg,
		0, NULL
		);

	printf("%s, GLE=%.08X (%lu): %s\n", msg, gle, gle, gle_msg);
	LocalFree(gle_msg);
}

/* injects the given dll into pid. returns zero on failure (check GetLastError for details). */
int win32_injectdll(uint32_t pid, const char *fullpath) {
	HANDLE process;
	HMODULE lib;
	LPTHREAD_START_ROUTINE pfnLoadLibraryA;
	void *premotefullpath;
	size_t written;
	size_t cbwrite;
	int res;
	uint32_t gle;
	HANDLE remotethread;
	uint32_t waitevent;

	process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!process) {
		return 0;
	}

	/* using the local LoadLibraryA address might seem wrong, but in practice kernel32
	is mapped to the same address in all processes so it works */
	lib = GetModuleHandleA("kernel32.dll");
	if (!lib) {
		return 0;
	}
	pfnLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(lib, "LoadLibraryA");
	if (!pfnLoadLibraryA) {
		return 0;
	}

	cbwrite = strlen(fullpath) + 1;

	/* allocate a string that will hold the dll's full path in the target process*/
	premotefullpath = VirtualAllocEx(process, NULL, cbwrite, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!premotefullpath) {
		return 0;
	}

	res = 1;
	written = 0;
	gle = ERROR_SUCCESS;

	do {
		/* write the data to the remotely allocated string */
		if (!WriteProcessMemory(process, premotefullpath, fullpath, cbwrite, &written) || written != cbwrite) {
			gle = GetLastError();
			res = 0;
			break;
		}

		/* call LoadLibraryA with the remotely allocated string in the target process */
		remotethread = CreateRemoteThread(process, NULL, 0, pfnLoadLibraryA, premotefullpath, 0, NULL);
		if (!remotethread) {
			gle = GetLastError();
			res = 0;
			break;
		}

		/* wait for the remote thread to terminate */
		waitevent = WaitForSingleObject(remotethread, 30000);
		if (waitevent == WAIT_TIMEOUT) {
			gle = ERROR_TIMEOUT;
			res = 0;
			break;
		}
		else if (waitevent == WAIT_FAILED) {
			gle = GetLastError();
			res = 0;
			break;
		}
	} while (0);

	/* free the remote string */
	VirtualFreeEx(process, premotefullpath, cbwrite, MEM_RELEASE | MEM_DECOMMIT);

	/* close handle to the target process */
	CloseHandle(process);

	/* this ensures that if an error occurs in WriteProcessMemory or CreateRemoteThread,
	the GetLastError value is not overwritten by the VirtualFreeEx and CloseHandle calls */
	SetLastError(gle);
	return res;
}
