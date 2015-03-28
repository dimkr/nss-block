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
	localhost.h_length = sizeof(struct sockaddr_in);
	localhost.h_addr_list = (char **) addr_list;
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
                                            struct hostent **result,
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
			if (0 != feof(blist))
				break;
			goto unlock;
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
				break;

			case 0:
				(void) memcpy(ret, &localhost, sizeof(struct hostent));
				*result = ret;
				res = NSS_STATUS_SUCCESS;
				goto unlock;

			default:
				goto unlock;
		}
	} while (1);

	res = NSS_STATUS_NOTFOUND;

unlock:
	(void) pthread_mutex_unlock(&lock);

end:
	return res;
}
