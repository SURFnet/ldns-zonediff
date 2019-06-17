/*
 * Copyright (c) 2018 SURFnet bv
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * - Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * - Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include "dns_zonediff.h"

void usage(void)
{
	printf("ldns-zonediff\n");
	printf("Copyright (C) 2018 SURFnet bv\n");
	printf("All rights reserved (see LICENSE for more information)\n\n");
	printf("Usage:\n");
	printf("\tldns-zonediff [-S] [-K] [-N] [-d] [-k] [-k] [-o <origin>] <left-zone> <right-zone>\n");
	printf("\tldns-zonediff -h\n");
	printf("\n");
	printf("\tldns-zonediff will output the differences between <left-zone> and\n");
	printf("\t<right-zone> and will output textual DNS records that are only in\n");
	printf("\t<left-zone> prepended by '--', and will output textual DNS records\n");
	printf("\tthat are only in <right-zone> prepend by '++'.\n");
	printf("\n");
	printf("Optional arguments:\n");
	printf("\t-o   Set the zone origin explicitly, for zone files\n");
	printf("\t     that do not include an explicit origin\n");
	printf("\t-S   Include RRSIG records in the comparison\n");
	printf("\t-K   Include DNSKEY records in the comparison\n");
	printf("\t-N   Include NSEC(3) records in the comparison\n");
	printf("\t-d   Suppress DS records in the comparison\n");
	printf("\t-k   Output knotc commands for insertion/removal\n");
	printf("\t     of records; twice to embed in contextual transaction\n");
	printf("\n");
	printf("\t-h   Print this help message\n");
}

void cleanup_openssl(void)
{
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
}

int main(int argc, char* argv[])
{
	char*	left_zone		= NULL;
	char*	right_zone		= NULL;
	char*	origin			= NULL;
	int	c			= 0;
	int	include_sigs		= 0;
	int	include_keys		= 0;
	int	include_nsecs		= 0;
	int	include_delegs		= 1;
	int	output_knotc_commands	= 0;
	int	rv			= 0;
	int	diffcount		= 0;
	
	while ((c = getopt(argc, argv, "-SKNdko:h")) != -1)
	{
		switch(c)
		{
		case 'S':
			include_sigs = 1;
			break;
		case 'K':
			include_keys = 1;
			break;
		case 'N':
			include_nsecs = 1;
			break;
		case 'd':
			include_delegs = 0;
			break;
		case 'k':
			// May be used twice; second form suppresses zone-begin, -commit
			output_knotc_commands++;
			break;
		case 'o':
			origin = strdup(optarg);
			break;
		case '\1':
			if (left_zone == NULL)
			{
				left_zone = strdup(optarg);
			}
			else if (right_zone == NULL)
			{
				right_zone = strdup(optarg);
			}
			else
			{
				fprintf(stderr, "Too many arguments specified\n");
				usage();
				exit(1);
			}
			break;
		case 'h':
		default:
			usage();
			return 0;
		}
	}

	/* Check arguments */
	if ((left_zone == NULL) || (right_zone == NULL))
	{
		fprintf(stderr, "You must specify a two zone files to compare\n");

		usage();

		return EINVAL;
	}

	/* Perform the comparision */
	rv = do_zonediff(left_zone, right_zone, origin, include_sigs, include_keys, include_nsecs, include_delegs, output_knotc_commands, &diffcount);

	cleanup_openssl();

	free(left_zone);
	free(right_zone);
	free(origin);

	if (rv != 0)
	{
		return 2;
	}
	else
	{
		return (diffcount == 0) ? 0 : 1;
	}
}
 
