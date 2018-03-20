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
#include <assert.h>
#include <openssl/evp.h>
#include <ldns/ldns.h>
#include "dns_zonediff.h"
#include "utlist.h"

#define	RR_HASH		(EVP_sha256())
#define RR_HASH_SIZE	32

typedef struct _dnsz_ll_ent
{
	unsigned char		rr_hash[RR_HASH_SIZE];
	ldns_rr*		rr;
	struct _dnsz_ll_ent*	next;
}
dnsz_ll_ent;

/* Element comparison for sorting */
static int zd_dnsz_ll_ent_cmp(const dnsz_ll_ent* a, const dnsz_ll_ent* b)
{
	return memcmp(a->rr_hash, b->rr_hash, RR_HASH_SIZE);
}

/* Load a DNS zone from the specified file */
static int zd_load_zone(const char* zone_name, const char* explicit_origin, const int include_sigs, const int include_keys, const int include_nsecs, dnsz_ll_ent** zone_ll, ldns_rr** soa)
{
	assert(zone_name != NULL);
	assert(zone_ll != NULL);
	assert(soa != NULL);

	FILE*		zone_fd			= fopen(zone_name, "r");
	ldns_rr*	cur_rr			= NULL;
	ldns_rdf*	origin			= NULL;
	ldns_rdf*	prev			= NULL;
	uint8_t*	rr_wire			= NULL;
	size_t		rr_wire_size		= 0;
	int		line_no			= 0;
	unsigned int	digest_size		= RR_HASH_SIZE;
	int		rv			= 0;
	uint32_t	ttl			= 0;
	unsigned char	digest[RR_HASH_SIZE]	= { 0 };
	EVP_MD_CTX	ctx			= { 0 };
	int		count			= 0;

	*soa = NULL;
	*zone_ll = NULL;

	if (zone_fd == NULL)
	{
		fprintf(stderr, "Failed to open zone file %s\n", zone_name);

		return errno;
	}

	if (explicit_origin != NULL)
	{
		origin = ldns_dname_new_frm_str(explicit_origin);
	}

	while (!feof(zone_fd))
	{
		dnsz_ll_ent*	new_ent	= NULL;

		if ((rv = ldns_rr_new_frm_fp_l(&cur_rr, zone_fd, &ttl, &origin, &prev, &line_no)) != LDNS_STATUS_OK)
		{
			switch(rv)
			{
			case LDNS_STATUS_SYNTAX_EMPTY:
			case LDNS_STATUS_SYNTAX_TTL:
			case LDNS_STATUS_SYNTAX_ORIGIN:
				break;
			default:
				fprintf(stderr, "Error parsing zone file %s on line %d, aborting (%s)\n", zone_name, line_no, ldns_get_errorstr_by_id(rv));
				return rv;
			}
			
			continue;
		}

		if (cur_rr == NULL) continue;

		ldns_rr2canonical(cur_rr);

		if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA)
		{
			if (*soa != NULL)
			{
				fprintf(stderr, "Error parsing zone file %s, encountered duplicate SOA record on line %d, aborting\n", zone_name, line_no);

				return EINVAL;
			}

			*soa = cur_rr;
			continue;
		}

		if (((ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_RRSIG) && !include_sigs) ||
		    ((ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_DNSKEY) && !include_keys) ||
		    ((ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC) && !include_nsecs) ||
		    ((ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC3) && !include_nsecs) ||
		    ((ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NSEC3PARAM) && !include_nsecs))
		{
			ldns_rr_free(cur_rr);
			continue;
		}

		/* Convert the RR to wire format for hashing */
		if (ldns_rr2wire(&rr_wire, cur_rr, LDNS_SECTION_ANSWER, &rr_wire_size) != LDNS_STATUS_OK)
		{
			fprintf(stderr, "Error converting RR to wire format on line %d of %s, aborting\n", line_no, zone_name);

			return EINVAL;
		}

		if (EVP_DigestInit(&ctx, RR_HASH) != 1)
		{
			fprintf(stderr, "Failed to initialise hashing\n");

			return EINVAL;
		}

		if (EVP_DigestUpdate(&ctx, rr_wire, rr_wire_size) != 1)
		{
			fprintf(stderr, "Failed to update hash of RR\n");
			
			return EINVAL;
		}

		if (EVP_DigestFinal(&ctx, digest, &digest_size) != 1)
		{
			fprintf(stderr, "Failed to output hash of RR\n");

			return EINVAL;
		}

		free(rr_wire);
		rr_wire = NULL;
		rr_wire_size = 0;

		new_ent = (dnsz_ll_ent*) malloc(sizeof(dnsz_ll_ent));
		memset(new_ent, 0, sizeof(dnsz_ll_ent));

		/* Add the RR */
		memcpy(new_ent->rr_hash, digest, RR_HASH_SIZE);
		new_ent->rr = cur_rr;

		LL_APPEND(*zone_ll, new_ent);

		count++;
	}

	printf("; Collected %d records from %d lines of zone data in %s\n", count, line_no, zone_name);

	if (origin != NULL)
	{
		ldns_rdf_deep_free(origin);
	}

	if (prev != NULL)
	{
		ldns_rdf_deep_free(prev);
	}

	fclose(zone_fd);

	/* Finally, sort the zone data in hash order */
	LL_SORT(*zone_ll, zd_dnsz_ll_ent_cmp);

	return 0;
}

/* Free zone data */
static void zd_free_zone(dnsz_ll_ent** zone_ll)
{
	assert(zone_ll != NULL);

	dnsz_ll_ent*	ll_it	= NULL;
	dnsz_ll_ent*	ll_tmp	= NULL;

	LL_FOREACH_SAFE(*zone_ll, ll_it, ll_tmp)
	{
		ldns_rr_free(ll_it->rr);
		free(ll_it);
	}

	*zone_ll = NULL;
}

/* Output an RR that changed */
static void zd_output_rr(const ldns_rr* rr, int remove)
{
	assert(rr != NULL);

	char*	rr_str	= ldns_rr2str(rr);

	if (rr_str != NULL)
	{
		printf("%s %s", remove ? "--" : "++", rr_str);

		free(rr_str);
	}
}

/* Compute the difference between left_zone and right_zone and output to stdout */
int do_zonediff(const char* left_zone, const char* right_zone, const char* origin, const int include_sigs, const int include_keys, const int include_nsecs)
{
	dnsz_ll_ent*	left_zone_ll	= NULL;
	dnsz_ll_ent*	right_zone_ll	= NULL;
	ldns_rr*	left_soa	= NULL;
	ldns_rr*	right_soa	= NULL;
	dnsz_ll_ent*	left_it		= NULL;
	dnsz_ll_ent*	right_it	= NULL;
	int		rv		= 0;
	
	if (((rv = zd_load_zone(left_zone, origin, include_sigs, include_keys, include_nsecs, &left_zone_ll, &left_soa)) != 0) ||
	    ((rv = zd_load_zone(right_zone, origin, include_sigs, include_keys, include_nsecs, &right_zone_ll, &right_soa)) != 0))
	{
		return rv;
	}

	/* 
	 * Perform the SOA comparison; we output a changed SOA if one of the
	 * fields other than the serial has changed, or if the serial in the
	 * right file is higher than the SOA in the left file
	 */
	if ((ldns_rdf_compare(ldns_rr_rdf(left_soa, 0), ldns_rr_rdf(right_soa, 0)) != 0) ||  /* SOA MNAME changed? */
	    (ldns_rdf_compare(ldns_rr_rdf(left_soa, 1), ldns_rr_rdf(right_soa, 1)) != 0) ||  /* SOA RNAME changed? */
	    (ldns_rdf_compare(ldns_rr_rdf(left_soa, 2), ldns_rr_rdf(right_soa, 2)) < 0) ||   /* SOA serial right higher than left? */
	    (ldns_rdf_compare(ldns_rr_rdf(left_soa, 3), ldns_rr_rdf(right_soa, 3)) != 0) ||  /* SOA refresh changed? */
	    (ldns_rdf_compare(ldns_rr_rdf(left_soa, 4), ldns_rr_rdf(right_soa, 4)) != 0) ||  /* SOA retry changed? */
	    (ldns_rdf_compare(ldns_rr_rdf(left_soa, 5), ldns_rr_rdf(right_soa, 5)) != 0) ||  /* SOA expire changed? */
	    (ldns_rdf_compare(ldns_rr_rdf(left_soa, 6), ldns_rr_rdf(right_soa, 6)) != 0))    /* SOA minimum changed? */
	{
		/* Ensure the SOA we say should be added has the highest SOA */
		if (ldns_rdf_compare(ldns_rr_rdf(left_soa, 2), ldns_rr_rdf(right_soa, 2)) > 0)
		{
			ldns_rdf*	new_soa	= ldns_rdf_clone(ldns_rr_rdf(left_soa, 2));
			ldns_rdf*	old_soa	= NULL;

			old_soa = ldns_rr_set_rdf(right_soa, new_soa, 2);

			ldns_rdf_deep_free(old_soa);
		}

		zd_output_rr(left_soa, 1);
		zd_output_rr(right_soa, 0);
	}

	ldns_rr_free(left_soa);
	ldns_rr_free(right_soa);

	/* Iterate over both zones and output the differences */
	left_it = left_zone_ll;
	right_it = right_zone_ll;

	while (left_it || right_it)
	{
		if (left_it && right_it)
		{
			int lr_comp = memcmp(left_it->rr_hash, right_it->rr_hash, RR_HASH_SIZE);

			if (lr_comp == 0)
			{
				/* Left and right are in sync, advance both */
				left_it = left_it->next;
				right_it = right_it->next;
			}
			else if (lr_comp < 0)
			{
				/* Record from left zone is not in right zone */
				zd_output_rr(left_it->rr, 1);
				left_it = left_it->next;
			}
			else
			{
				/* Record from right zone is not in left zone */
				zd_output_rr(right_it->rr, 0);
				right_it = right_it->next;
			}
		}
		else if (!left_it && right_it)
		{
			/* Additional records in right zone that are not present in the left zone */
			zd_output_rr(right_it->rr, 0);

			/* Advance right iterator */
			right_it = right_it->next;
		}
		else if (left_it && !right_it)
		{
			/* Additional records in the left zone that are not present in the right zone */
			zd_output_rr(left_it->rr, 1);

			/* Advance left iterator */
			left_it = left_it->next;
		}
	}

	zd_free_zone(&left_zone_ll);
	zd_free_zone(&right_zone_ll);

	return 0;
}
 
