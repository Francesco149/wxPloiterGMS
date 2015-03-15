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


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include "process_utils.h"
#include "win32_utils.h"

#define INJECTOR_INI ".\\wxPloiterInjector.ini"
#define INJECTOR_VERSION "v1.0"

/*
 * holds the list of DLLs parsed from the injector's config file
 * usage:
 * - allocate an instance injector_settings and initialize it to zero
 * - call injector_init. this will retrieve the list of dlls from the settings file
 * - iterate the dlls array (count is the size of the array), each element will have two members: file and delay
 * - once you're done with it, free the injector_settings struct by calling injector_destroy
 */
typedef struct taginjector_settings {
	int count; /* size of the dlls array */
	struct taginjector_dll {
		char file[MAX_PATH]; /* filename (can also be a full or relative path) */
		uint32_t delay; /* delay in millisecond before the dll is injected */
	} *dlls; /* list of the dlls that will be injected */
} injector_settings;

/*
 * parses the list of DLLs from the injector's config file and stores it in the injector_settings struct pointed by pis.
 * returns zero on failure. more details about the error can be obtained by checking the value of GetLastError().
 */
static int injector_init(__inout injector_settings *pis) {
	int i;
	char key[128] = { 0 };
	static const char *sect = "Injector";

	assert(pis != NULL);

	pis->count = GetPrivateProfileIntA(sect, "Count", 0, INJECTOR_INI);
	pis->dlls = NULL;

	if (!pis->count) {
		return 1;
	}

	pis->dlls = (struct taginjector_dll *)malloc(sizeof(struct taginjector_dll) * pis->count);
	assert(pis->dlls != NULL);
	memset(pis->dlls, 0, sizeof(struct taginjector_dll) * pis->count);
	for (i = 0; i < pis->count; i++) {
		sprintf_s(key, 128, "Dll%d", i + 1);
		if (!GetPrivateProfileStringA(sect, key, "", pis->dlls[i].file, MAX_PATH, INJECTOR_INI) || !strlen(pis->dlls[i].file)) {
			return 0;
		}
		sprintf_s(key, 128, "Dll%dDelay", i + 1);
		pis->dlls[i].delay = GetPrivateProfileIntA(sect, key, 0, INJECTOR_INI);
	}

	return 1;
}

/* frees the memory for the injector_settings struct pointed by pis */
static void injector_destroy(__inout injector_settings *pis) {
	assert(pis != NULL);
	if (pis->count) {
		free(pis->dlls);
		pis->dlls = NULL;
	}
}

/*
 * creates a copy of the given file and replaces the checksum hack macro occurrences
 * with random data.
 * NOTE: this assumes that rand() has already been seeded
 */
static int randomcopy(const char *srcfile, const char *dstfile) {
	FILE *fsrc = NULL;
	FILE *fdst = NULL;
	uint8_t *buf = NULL;
	long i, j;
	int res;
	errno_t err;
	char errbuf[128] = { 0 };
	static const uint8_t checksum_hack[16] = { 
		0xCC, 0x90, 0xCC, 0xCC, 
		0x90, 0x90, 0x60, 0x61, 
		0x60, 0x61, 0x90, 0x90, 
		0xCC, 0xCC, 0x90, 0xCC 
	};
	int first = 1;
	long fsize = 0;
	int checksumcount = 0;
	size_t cbread = 0;

	res = 1;

	do {
		/* open source file */
		if (err = fopen_s(&fsrc, srcfile, "rb")) {
#if _DEBUG
			strerror_s(errbuf, 128, err);
			printf("randomcopy: failed to open %s: %s\n", srcfile, errbuf);
#endif
			res = 0;
			fsrc = NULL;
			break;
		}

		/* open destination file */
		if (err = fopen_s(&fdst, dstfile, "wb")) {
#if _DEBUG
			strerror_s(errbuf, 128, err);
			printf("randomcopy: failed to open %s: %s\n", dstfile, errbuf);
#endif
			res = 0;
			fdst = NULL;
			break;
		}

		/* load entire file in memory */
		fseek(fsrc, 0, SEEK_END);
		fsize = ftell(fsrc);
		fseek(fsrc, 0, SEEK_SET);

		buf = (uint8_t *)malloc(fsize);
		if (!buf) {
			puts("randomcopy: malloc failed! out of memory?");
			res = 0;
			break;
		}

		if (cbread = fread(buf, sizeof(uint8_t), fsize, fsrc) != fsize) {
			printf("randomcopy: unexpected read byte count of %d/%d.\n", cbread, fsize);
			res = 0;
			break;
		}

		/* replace occurrences of the checksum hack macro with random data */
		for (i = 0; i < fsize; i++) {
			if (memcmp(buf + i, checksum_hack, 16) == 0) {
				for (j = 0; j < 4; j++) {
					*(int *)(buf + i + j * 4) = rand();
				}
				checksumcount++;
			}
		}

#if _DEBUG
		printf("\nReplaced %d occurrences of the checksum macro.\n", checksumcount);
#endif

		/* write randomized file*/
		if (fwrite(buf, sizeof(uint8_t), fsize, fdst) != fsize) {
			printf("randomcopy: unexpected write byte count of %d/%d.\n", cbread, fsize);
			res = 0;
			break;
		}
	} while (0);

	if (fsrc) {
		fclose(fsrc);
	}

	if (fdst) {
		fclose(fdst);
	}

	if (buf) {
		free(buf);
	}

	return res;
}

int main(int argc, char *argv[]) {
	injector_settings is = { 0 };
	uint32_t pid;
	char buf[MAX_PATH] = { 0 };
	char processname[MAX_PATH] = { 0 };
	int exit = 0;
	int i;

	/* seeds the RNG */
	srand((unsigned int)time(NULL));

	/* parse settings */
	if (!injector_init(&is)) {
		win32_show_error("Failed to parse settings file");
	}

	puts("---------------------------------");
	printf("wxPloiterInjector for GMS %s\n", INJECTOR_VERSION);
	puts("by Franc[e]sco");
	puts("http://www.gamekiller.net/");
	putchar('\n');
	puts("DLLs to inject:");
	for (i = 0; i < is.count; i++) {
		printf("%s - %lu ms\n", is.dlls[i].file, is.dlls[i].delay);
	}
	puts("---------------------------------");
	putchar('\n');

	/* handle command line arguments */
	switch (argc) {
	case 1:
		if (!GetPrivateProfileStringA("Settings", "ExecutableName", "MapleStory.exe", processname, MAX_PATH, INJECTOR_INI)) {
			win32_show_error("GetPrivateProfileIntA failed for [Settings] ExecutableName");
			exit = 1;
			break;
		}

		/* no arguments, wait for the process name specified in the settings */
		printf("Waiting for %s...\n", processname);
		pid = 0;
		while (!pid) {
			process_pidbyname(processname, &pid);
			Sleep(100);
		}
		break;
	case 2:
		/* 1 argument, parse the PID from command line args and validate it by obtaining the process name */
		if (sscanf_s(argv[1], "%lu", &pid) != 1) {
			puts("Could not parse PID from command line arguments.");
			exit = 1;
			break;
		}

		process_namebypid(pid, processname, MAX_PATH);
		if (!strlen(processname)) {
			sprintf_s(buf, MAX_PATH, "Could not find process %lu", pid);
			win32_show_error(buf);
			exit = 1;
			break;
		}
		break;
	default:
		/* invalid count of command line arguments */
		puts("Usage: wxPloiterInjector [PID]");
		puts("Parameters:");
		puts("PID (optional): The target process id.");
		exit = 1;
	}

	if (exit) {
		system("pause"); /* this is windows-only so who cares */
		return 0;
	}

	printf("Target: %s\n", processname);
	printf("Target PID: %lu\n\n", pid);

	for (i = 0; i < is.count; i++) {
		printf("Injecting %s... ", is.dlls[i].file);
		Sleep(is.dlls[i].delay); /* sleep for the set delay */

		/* create a copy of the file and randomize the checksum macros */
		sprintf_s(buf, MAX_PATH, "%s_randomized", is.dlls[i].file);
		if (!randomcopy(is.dlls[i].file, buf)) {
			puts("Failed!");
			win32_show_error("randomcopy failed");
			continue;
		}

		/* get the full path to the randomized dll file */
		if (!GetFullPathNameA(buf, MAX_PATH, buf, NULL)) {
			puts("Failed!");
			win32_show_error("GetFullPathNameA failed");
			continue;
		}

		/* finally inject the dll*/
		if (!win32_injectdll(pid, buf)) {
			puts("Failed!");
			win32_show_error("Injection failed");
			continue;
		}

		puts("Done!");
	}

	/* free allocated memory & cleanup */
	injector_destroy(&is);

#if _DEBUG
	system("pause");
#endif
	return 0;
}