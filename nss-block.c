/*
 * this file is part of nss-block.
 *
 * Copyright (c) 2015, 2016 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fnmatch.h>
#include <netdb.h>
#include <nss.h>

#include <zlib.h>

#define MAX_NAME_LEN 128
#define MAX_HOSTS (64 * 1024)

static char *aliases[] = {NULL};

static struct in_addr loopback;
static const struct in_addr *addr_list[] = {&loopback, NULL};

static struct in6_addr loopback6 = IN6ADDR_LOOPBACK_INIT;
static const struct in6_addr *addr_list6[] = {&loopback6, NULL};

static uLong *hashes = NULL;
static uLong init;
static int nhashes;

__attribute__((constructor))
static void ctor(void)
{
	char bname[MAX_NAME_LEN];
	FILE *blist;
	int len, nlen;

	blist = fopen(_PATH_HOSTS".blacklist", "r");
	if (!blist)
		return;

	hashes = malloc(sizeof(uLong) * MAX_HOSTS);
	if (hashes) {
		init = crc32(0L, Z_NULL, 0L);

		for (nhashes = 0;
		     (nhashes < MAX_HOSTS) && fgets(bname, sizeof(bname), blist);
		     ++nhashes) {
			len = strlen(bname);
			/* blank lines and ignore comments */
			if (!len || bname[0] == '#')
				continue;

			/* trim trailing line breaks */
			nlen = len - 1;
			if (bname[nlen] == '\n') {
				bname[nlen] = '\0';
				len = nlen;
			}

			hashes[nhashes] = crc32(init, (const Bytef *)bname, len);
		}

		if (!feof(blist)) {
			free(hashes);
			hashes = NULL;
		}
	}

	fclose(blist);

	loopback.s_addr = htonl(INADDR_LOOPBACK);
}

__attribute__((destructor))
static void dtor(void)
{
	if (hashes)
		free(hashes);
}

enum nss_status _nss_block_gethostbyname2_r(const char *name,
                                            int af,
                                            struct hostent *ret,
                                            char *buf,
                                            size_t buflen,
                                            int *errnop,
                                            int *h_errnop)
{
	uLong hash;
	int i;

	if (!hashes)
		return NSS_STATUS_UNAVAIL;

	if ((af == AF_INET) || (af == AF_INET6)) {
		hash = crc32(init, (const Bytef *)name, strlen(name));

		for (i = 0; i < nhashes; ++i) {
			/* if a match was found, return localhost as the address */
			if (hashes[i] == hash) {
				if (af == AF_INET) {
					ret->h_name = "localhost";
					ret->h_aliases = aliases;
					ret->h_addrtype = AF_INET;
					ret->h_length = sizeof(struct in_addr);
					ret->h_addr_list = (char **)addr_list;
				}
				else {
					ret->h_name = "localhost";
					ret->h_aliases = aliases;
					ret->h_addrtype = AF_INET6;
					ret->h_length = sizeof(struct in6_addr);
					ret->h_addr_list = (char **)addr_list6;
				}

				return NSS_STATUS_SUCCESS;
			}
		}
	}

	return NSS_STATUS_NOTFOUND;
}
