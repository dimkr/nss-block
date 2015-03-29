/*
 * this file is part of nss-block.
 *
 * Copyright (c) 2015 Dima Krasner
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

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fnmatch.h>
#include <netdb.h>
#include <nss.h>

#define MAX_NAME_LEN (128)

static char *aliases[] = {NULL};
static struct in_addr loopback;
static const struct in_addr *addr_list[] = {&loopback, NULL};
static struct hostent localhost;

static struct in6_addr loopback6 = IN6ADDR_LOOPBACK_INIT;
static const struct in6_addr *addr_list6[] = {&loopback6, NULL};
static struct hostent localhost6;

static FILE *blist;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor))
static void ctor()
{
	blist = fopen(_PATH_HOSTS".blacklist", "r");
	if (NULL == blist)
		return;

	loopback.s_addr = htonl(INADDR_LOOPBACK);

	localhost.h_name = "localhost";
	localhost.h_aliases = aliases;
	localhost.h_addrtype = AF_INET;
	localhost.h_length = sizeof(struct in_addr);
	localhost.h_addr_list = (char **) addr_list;

	localhost6.h_name = localhost.h_name;
	localhost6.h_aliases = localhost.h_aliases;
	localhost6.h_addrtype = AF_INET6;
	localhost6.h_length = sizeof(struct in6_addr);
	localhost6.h_addr_list = (char **) addr_list6;
}

__attribute__((destructor))
static void dtor()
{
	if (NULL != blist)
		(void) fclose(blist);
}

enum nss_status _nss_block_gethostbyname2_r(const char *name,
                                            int af,
                                            struct hostent *ret,
                                            char *buf,
                                            size_t buflen,
                                            int *errnop,
                                            int *h_errnop)
{
	char bname[MAX_NAME_LEN];
	int len;
	enum nss_status res = NSS_STATUS_UNAVAIL;

	if (NULL == blist)
		goto end;

	if (0 != pthread_mutex_lock(&lock))
		goto end;

	/* read the blacklist, line by line */
	if (0 != fseek(blist, 0L, SEEK_SET))
		goto end;

	do {
		if (NULL == fgets(bname, sizeof(bname), blist)) {
			if (0 != feof(blist)) {
				res = NSS_STATUS_NOTFOUND;
				break;
			}
			break;
		}

		len = strlen(bname);
		if (0 == len)
			continue;

		/* ignore comments */
		if ('#' == bname[0])
			continue;

		/* trim trailing line breaks */
		--len;
		if ('\n' == bname[len])
			bname[len] = '\0';

		/* if a match was found, return localhost as the address */
		switch (fnmatch(bname, name, FNM_PATHNAME)) {
			case FNM_NOMATCH:
				continue;

			case 0:
				break;

			default:
				goto unlock;
		}

		switch (af) {
			case AF_INET:
				(void) memcpy(ret, &localhost, sizeof(struct hostent));
				res = NSS_STATUS_SUCCESS;
				goto unlock;

			case AF_INET6:
				(void) memcpy(ret, &localhost6, sizeof(struct hostent));
				res = NSS_STATUS_SUCCESS;

				/* fall through */

			default:
				goto unlock;
		}
	} while (1);

unlock:
	(void) pthread_mutex_unlock(&lock);

end:
	return res;
}
