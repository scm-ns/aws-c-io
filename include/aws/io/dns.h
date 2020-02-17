#ifndef AWS_IO_DNS_H
#define AWS_IO_DNS_H
/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/io/io.h>

#include <aws/common/atomics.h>

struct aws_array_list;
struct aws_event_loop_group;
struct aws_string;
struct aws_dns_resolver;

/* use async destruction from the start */
typedef void(aws_dns_on_destroy_completed_fn)(struct aws_dns_resolver *resolver, void *user_data);

enum aws_dns_resource_record_type {
    AWS_DNS_RR_A = 1,
    AWS_DNS_RR_NS = 2,
    AWS_DNS_RR_MD = 3,
    AWS_DNS_RR_MF = 4,
    AWS_DNS_RR_CNAME = 5,
    AWS_DNS_RR_SOA = 6,
    AWS_DNS_RR_MB = 7,
    AWS_DNS_RR_MG = 8,
    AWS_DNS_RR_MR = 9,
    AWS_DNS_RR_NULL = 10,
    AWS_DNS_RR_WKS = 11,
    AWS_DNS_RR_PTR = 12,
    AWS_DNS_RR_HINFO = 13,
    AWS_DNS_RR_MINFO = 14,
    AWS_DNS_RR_MX = 15,
    AWS_DNS_RR_TXT = 16,
    AWS_DNS_RR_RP = 17,
    AWS_DNS_RR_AFSDB = 18,
    AWS_DNS_RR_X25 = 19,
    AWS_DNS_RR_ISDN = 20,
    AWS_DNS_RR_RT = 21,
    AWS_DNS_RR_NSAP = 22,
    AWS_DNS_RR_NSAPPTR = 23,
    AWS_DNS_RR_SIG = 24,
    AWS_DNS_RR_KEY = 25,
    AWS_DNS_RR_PX = 26,
    AWS_DNS_RR_GPOS = 27,
    AWS_DNS_RR_AAAA = 28,
    AWS_DNS_RR_LOC = 29,
    AWS_DNS_RR_NXT = 30,
    AWS_DNS_RR_EID = 31,
    AWS_DNS_RR_NIMLOC = 32, /* AWS_DNS_RR_NB erroneously defined as 32 */
    AWS_DNS_RR_SRV = 33,    /* AWS_DNS_RR_NBSTAT errorneously defined as 33 */
    AWS_DNS_RR_ATMA = 34,
    AWS_DNS_RR_NAPTR = 35,
    AWS_DNS_RR_KX = 36,
    AWS_DNS_RR_CERT = 37,
    AWS_DNS_RR_A6 = 38,
    AWS_DNS_RR_DNAME = 39,
    AWS_DNS_RR_SINK = 40,
    AWS_DNS_RR_OPT = 41,
    AWS_DNS_RR_APL = 42,
    AWS_DNS_RR_DS = 43,
    AWS_DNS_RR_SSHFP = 44,
    AWS_DNS_RR_IPSECKEY = 45,
    AWS_DNS_RR_RRSIG = 46,
    AWS_DNS_RR_NSEC = 47,
    AWS_DNS_RR_DNSKEY = 48,
    AWS_DNS_RR_DHCID = 49,
    AWS_DNS_RR_NSEC3 = 50,
    AWS_DNS_RR_NSEC3PARAM = 51,
    AWS_DNS_RR_TLSA = 52,
    AWS_DNS_RR_SMIMEA = 53,
    AWS_DNS_RR_HIP = 55,
    AWS_DNS_RR_NINFO = 56,
    AWS_DNS_RR_RKEY = 57,
    AWS_DNS_RR_TALINK = 58,
    AWS_DNS_RR_CDS = 59,
    AWS_DNS_RR_CDNSKEY = 60,
    AWS_DNS_RR_OPENPGPKEY = 61,
    AWS_DNS_RR_CSYNC = 62,
    AWS_DNS_RR_ZONEMD = 63,
    AWS_DNS_RR_SPF = 99,
    AWS_DNS_RR_UINFO = 100,
    AWS_DNS_RR_UID = 101,
    AWS_DNS_RR_GID = 102,
    AWS_DNS_RR_UNSPEC = 103,
    AWS_DNS_RR_NID = 104,
    AWS_DNS_RR_L32 = 105,
    AWS_DNS_RR_L64 = 106,
    AWS_DNS_RR_LP = 107,
    AWS_DNS_RR_EUI48 = 108,
    AWS_DNS_RR_EUI64 = 109,
    AWS_DNS_RR_TKEY = 249,
    AWS_DNS_RR_TSIG = 250,
    AWS_DNS_RR_IXFR = 251,
    AWS_DNS_RR_AXFR = 252,
    AWS_DNS_RR_MAILA = 253,
    AWS_DNS_RR_MAILB = 254,
    AWS_DNS_RR_ANY = 255,
    AWS_DNS_RR_URI = 256,
    AWS_DNS_RR_CAA = 257,
    AWS_DNS_RR_DOA = 259,
    AWS_DNS_RR_AMTRELAY = 260,
    AWS_DNS_RR_TA = 32768,
    AWS_DNS_RR_DLV = 32769,

};

struct aws_dns_resource_record {
    /* Needs to be on the record (rather than the full result/set) to support ANY-based queries */
    enum aws_dns_resource_record_type type;

    /* time-to-live in seconds */
    uint32_t ttl;

    /* raw binary data of the resource record */
    struct aws_string *data;
};

/* what kind of query to make */
enum aws_dns_query_type {
    /*
     * Make a recursive query to a single provider
     */
    AWS_DNS_QUERY_RECURSIVE,

    /*
     * Performs an iterative query starting from the closest known (name server) ancestor to the host
     * in question.
     */
    AWS_DNS_QUERY_ITERATIVE,
};

/* various configuration options for an individual query */
struct aws_dns_query_options {
    enum aws_dns_query_type query_type;

    /*
     * Retry controls
     *
     * Open Q: Move to a generic retry strategy type?
     */

    /*
     * (Iterative only) Maximum (packet-level) queries (summed across attempts?) to send before giving up.
     * If zero, defaults to something reasonable (20?)
     */
    uint16_t max_iterations;

    /*
     * Maximum number of attempts to try the query (against no response).
     * If zero, defaults to 4.
     */
    uint16_t max_retries;

    /*
     * Time to wait for a response before considering the attempt a failure and potentially retrying.
     * If zero, defaults to 4000.
     */
    uint16_t retry_interval_in_millis;

    uint32_t timeout_millis;
};

struct aws_dns_query_result {
    /* arrays of aws_dns_resource_record */
    struct aws_array_list answer_records;
    struct aws_array_list authority_records;
    struct aws_array_list additional_records;

    bool authoritative;
    bool authenticated;
};

typedef void(on_dns_query_completed_callback_fn)(struct aws_dns_query_result *result, int error_code, void *user_data);

struct aws_dns_query {
    enum aws_dns_resource_record_type query_type;
    struct aws_byte_cursor hostname;

    struct aws_dns_query_options *options; /* Optional - If null, all defaults will be used */

    on_dns_query_completed_callback_fn *on_completed_callback;
    void *user_data;
};

struct aws_dns_resolver;

struct aws_dns_resolver_vtable {
    void (*destroy)(struct aws_dns_resolver *resolver, aws_dns_on_destroy_completed_fn *callback, void *user_data);
    void (*make_query)(struct aws_dns_resolver *resolver, struct aws_dns_query *query);
};

struct aws_dns_resolver {
    struct aws_allocator *allocator;
    struct aws_dns_resolver_vtable *vtable;
    struct aws_atomic_var ref_count;
    void *impl;
};

/*
 * Configuration options for the crt's default dns resolver
 */
struct aws_dns_resolver_default_options {
    struct aws_client_bootstrap *bootstrap;

    aws_dns_on_destroy_completed_fn *destroy_completed_callback;
    void *destroy_user_data;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_dns_resolver *aws_dns_resolver_new_default(
    struct aws_allocator *allocator,
    struct aws_dns_resolver_default_options *options);

AWS_IO_API void aws_dns_resolver_acquire(struct aws_dns_resolver *resolver);

AWS_IO_API void aws_dns_resolver_release(struct aws_dns_resolver *resolver);

AWS_IO_API
int aws_dns_resolver_make_query(struct aws_dns_resolver *resolver, struct aws_dns_query *query);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_H */
