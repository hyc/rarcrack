/* Copyright 2013 (c) Howard Chu <hyc@symas.com>
 *
 * Anyone can freely use this code as long as you don't try to
 * claim you wrote it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#ifndef _WIN32
#define	_UNIX
#endif
#include "dll.hpp"

static const char hc[] = "0123456789abcdef";

#define INTVL	20

int gotsig;

void alarmer(int sig)
{
	gotsig = 1;
}

void hex(unsigned char *str) {
	unsigned char c;
	while ((c = *str++)) {
		printf("%c%c ",hc[c>>4], hc[c&0x0f]);
	}
	putchar('\n');
}

int main(int argc, char *argv[]) {
	HANDLE arch;
	struct RAROpenArchiveData darch;
	struct RARHeaderData dhead;
	char pass[1024];
	int rc, count = 0, pcount = 0;
	size_t off;
	time_t prev, now;

	printf("RarCrack 0.1 by Howard Chu <hyc@symas.com>)\n\n");
	if (argc !=2) {
		fprintf(stderr, "usage: %s <rarfile> < words\n", argv[0]);
		exit(1);
	}

	signal(SIGALRM, alarmer);
	darch.ArcName = argv[1];
	darch.OpenMode = RAR_OM_EXTRACT;
	darch.CmtBuf = NULL;
	darch.CmtBufSize = 0;

	dhead.CmtBuf = NULL;
	dhead.CmtBufSize = 0;

	arch = RAROpenArchive(&darch);
	if (!arch) {
		fprintf(stderr, "failed to open %s\n", argv[1]);
		exit(1);
	}
	time(&prev);
	alarm(INTVL);
	for(;;) {
		if (!fgets(pass, sizeof(pass), stdin)) {
			fprintf(stderr, "no more words!\n");
			exit(1);
		}
		rc = strlen(pass);
		pass[rc-1] = '\0';
		count++;
		if (gotsig) {
			time(&now);
			printf("%d passwords in %d seconds (%s)\n",
				count-pcount, now-prev, pass);
			prev = now;
			pcount = count;
			gotsig = 0;
			alarm(INTVL);
		}
		RARSetPassword(arch, pass);
		rc = RARReadHeader(arch, &dhead);
		if (!rc)
			rc = RARProcessFile(arch, RAR_TEST, NULL, NULL);
		if (rc == 0) {
			printf("GOOD: password cracked: '%s'\n", pass);
			hex(pass);
			break;
		}
		RARCloseArchive(arch);
		arch = RAROpenArchive(&darch);
	}
	return 0;
}

