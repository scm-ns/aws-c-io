/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/clock.h>
#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/dns_impl.h>
#include <aws/io/socket.h>

#include <inttypes.h>

#define ELASTIDIG_VERSION "0.0.1"

struct aws_dns_resource_record_type_name {
    const char *record_type_name;
    enum aws_dns_resource_record_type record_type;
};

/* clang-format off */
static struct aws_dns_resource_record_type_name s_record_names [] = {
    { .record_type_name = "A", .record_type = AWS_DNS_RR_A },
    { .record_type_name = "NS", .record_type = AWS_DNS_RR_NS },
    { .record_type_name = "MD", .record_type = AWS_DNS_RR_MD },
    { .record_type_name = "MF", .record_type = AWS_DNS_RR_MF },
    { .record_type_name = "CNAME", .record_type = AWS_DNS_RR_CNAME },
    { .record_type_name = "SOA", .record_type = AWS_DNS_RR_SOA },
    { .record_type_name = "MB", .record_type = AWS_DNS_RR_MB },
    { .record_type_name = "MG", .record_type = AWS_DNS_RR_MG },
    { .record_type_name = "MR", .record_type = AWS_DNS_RR_MR },
    { .record_type_name = "NULL", .record_type = AWS_DNS_RR_NULL },
    { .record_type_name = "WKS", .record_type = AWS_DNS_RR_WKS },
    { .record_type_name = "PTR", .record_type = AWS_DNS_RR_PTR },
    { .record_type_name = "HINFO", .record_type = AWS_DNS_RR_HINFO },
    { .record_type_name = "MINFO", .record_type = AWS_DNS_RR_MINFO },
    { .record_type_name = "MX", .record_type = AWS_DNS_RR_MX },
    { .record_type_name = "TXT", .record_type = AWS_DNS_RR_TXT },
    { .record_type_name = "RP", .record_type = AWS_DNS_RR_RP },
    { .record_type_name = "AFSDB ", .record_type = AWS_DNS_RR_AFSDB },
    { .record_type_name = "X25", .record_type = AWS_DNS_RR_X25 },
    { .record_type_name = "ISDN", .record_type = AWS_DNS_RR_ISDN },
    { .record_type_name = "RT", .record_type = AWS_DNS_RR_RT },
    { .record_type_name = "NSAP", .record_type = AWS_DNS_RR_NSAP },
    { .record_type_name = "NSAPPTR", .record_type = AWS_DNS_RR_NSAPPTR },
    { .record_type_name = "SIG", .record_type = AWS_DNS_RR_SIG },
    { .record_type_name = "KEY", .record_type = AWS_DNS_RR_KEY },
    { .record_type_name = "PX", .record_type = AWS_DNS_RR_PX },
    { .record_type_name = "GPOS", .record_type = AWS_DNS_RR_GPOS },
    { .record_type_name = "AAAA", .record_type = AWS_DNS_RR_AAAA },
    { .record_type_name = "LOC", .record_type = AWS_DNS_RR_LOC },
    { .record_type_name = "NXT", .record_type = AWS_DNS_RR_NXT },
    { .record_type_name = "EID", .record_type = AWS_DNS_RR_EID },
    { .record_type_name = "NIMLOC", .record_type = AWS_DNS_RR_NIMLOC },
    { .record_type_name = "SRV", .record_type = AWS_DNS_RR_SRV },
    { .record_type_name = "ATMA", .record_type = AWS_DNS_RR_ATMA },
    { .record_type_name = "NAPTR", .record_type = AWS_DNS_RR_NAPTR },
    { .record_type_name = "KX", .record_type = AWS_DNS_RR_KX },
    { .record_type_name = "CERT", .record_type = AWS_DNS_RR_CERT },
    { .record_type_name = "A6", .record_type = AWS_DNS_RR_A6 },
    { .record_type_name = "DNAME", .record_type = AWS_DNS_RR_DNAME },
    { .record_type_name = "SINK", .record_type = AWS_DNS_RR_SINK },
    { .record_type_name = "OPT", .record_type = AWS_DNS_RR_OPT },
    { .record_type_name = "APL", .record_type = AWS_DNS_RR_APL },
    { .record_type_name = "DS", .record_type = AWS_DNS_RR_DS },
    { .record_type_name = "SSHEP", .record_type = AWS_DNS_RR_SSHFP },
    { .record_type_name = "IPSECKEY", .record_type = AWS_DNS_RR_IPSECKEY },
    { .record_type_name = "RRSIG", .record_type = AWS_DNS_RR_RRSIG },
    { .record_type_name = "NSEC", .record_type = AWS_DNS_RR_NSEC },
    { .record_type_name = "DNSKEY", .record_type = AWS_DNS_RR_DNSKEY },
    { .record_type_name = "DHCID", .record_type = AWS_DNS_RR_DHCID },
    { .record_type_name = "NSEC3", .record_type = AWS_DNS_RR_NSEC3 },
    { .record_type_name = "NSEC3PARAM", .record_type = AWS_DNS_RR_NSEC3PARAM },
    { .record_type_name = "TLSA", .record_type = AWS_DNS_RR_TLSA },
    { .record_type_name = "SMIMEA", .record_type = AWS_DNS_RR_SMIMEA },
    { .record_type_name = "HIP", .record_type = AWS_DNS_RR_HIP },
    { .record_type_name = "NINFO", .record_type = AWS_DNS_RR_NINFO },
    { .record_type_name = "RKEY", .record_type = AWS_DNS_RR_RKEY },
    { .record_type_name = "TALINK", .record_type = AWS_DNS_RR_TALINK },
    { .record_type_name = "CDS", .record_type = AWS_DNS_RR_CDS },
    { .record_type_name = "CDNSKEY", .record_type = AWS_DNS_RR_CDNSKEY },
    { .record_type_name = "OPENPGPKEY", .record_type = AWS_DNS_RR_OPENPGPKEY },
    { .record_type_name = "CSYNC", .record_type = AWS_DNS_RR_CSYNC },
    { .record_type_name = "ZONEMD", .record_type = AWS_DNS_RR_ZONEMD },
    { .record_type_name = "SPF", .record_type = AWS_DNS_RR_SPF },
    { .record_type_name = "UINFO", .record_type = AWS_DNS_RR_UINFO },
    { .record_type_name = "UID", .record_type = AWS_DNS_RR_UID },
    { .record_type_name = "GID", .record_type = AWS_DNS_RR_GID },
    { .record_type_name = "UNSPEC", .record_type = AWS_DNS_RR_UNSPEC },
    { .record_type_name = "NID", .record_type = AWS_DNS_RR_NID },
    { .record_type_name = "L32", .record_type = AWS_DNS_RR_L32 },
    { .record_type_name = "L64", .record_type = AWS_DNS_RR_L64 },
    { .record_type_name = "LP", .record_type = AWS_DNS_RR_LP },
    { .record_type_name = "EUI48", .record_type = AWS_DNS_RR_EUI48 },
    { .record_type_name = "EUI64", .record_type = AWS_DNS_RR_EUI64 },
    { .record_type_name = "TKEY", .record_type = AWS_DNS_RR_TKEY },
    { .record_type_name = "TSIG", .record_type = AWS_DNS_RR_TSIG },
    { .record_type_name = "IXFR", .record_type = AWS_DNS_RR_IXFR },
    { .record_type_name = "AXFR", .record_type = AWS_DNS_RR_AXFR },
    { .record_type_name = "MAILA", .record_type = AWS_DNS_RR_MAILA },
    { .record_type_name = "MAILB", .record_type = AWS_DNS_RR_MAILB },
    { .record_type_name = "ANY", .record_type = AWS_DNS_RR_ANY },
    { .record_type_name = "URI", .record_type = AWS_DNS_RR_URI },
    { .record_type_name = "CAA", .record_type = AWS_DNS_RR_CAA },
    { .record_type_name = "DOA", .record_type = AWS_DNS_RR_DOA },
    { .record_type_name = "AMTRELAY", .record_type = AWS_DNS_RR_AMTRELAY },
    { .record_type_name = "TA", .record_type = AWS_DNS_RR_TA },
    { .record_type_name = "DLV", .record_type = AWS_DNS_RR_DLV },
};
/* clang-format on */

enum aws_dns_resource_record_type s_aws_c_string_to_aws_dns_resource_record_type(const char *record_type_string) {
    size_t record_type_count = AWS_ARRAY_SIZE(s_record_names);
    struct aws_byte_cursor record_type_cursor = aws_byte_cursor_from_c_str(record_type_string);

    for (size_t i = 0; i < record_type_count; ++i) {
        struct aws_byte_cursor current_cursor = aws_byte_cursor_from_c_str(s_record_names[i].record_type_name);
        if (aws_byte_cursor_eq_ignore_case(&current_cursor, &record_type_cursor)) {
            return s_record_names[i].record_type;
        }
    }

    return AWS_DNS_RR_UNKNOWN;
}

const char *s_aws_dns_resource_record_type_to_c_str(enum aws_dns_resource_record_type record_type) {
    size_t record_type_count = AWS_ARRAY_SIZE(s_record_names);

    for (size_t i = 0; i < record_type_count; ++i) {
        if (record_type == s_record_names[i].record_type) {
            return s_record_names[i].record_type_name;
        }
    }

    return "UNKNOWN";
}

const char *s_opcode_names[] = {
    "QUERY",
    "IQUERY",
    "STATUS",
    "NOTIFY",
    "UPDATE",
    "FOT_DSO",
};

const char *s_aws_dns_flags_opcode_type_to_c_str(enum aws_dns_flags_opcode_type opcode) {
    size_t index = opcode;
    if (index < AWS_ARRAY_SIZE(s_opcode_names)) {
        return s_opcode_names[index];
    }

    return "UNKNOWN";
}

const char *s_result_code_names[] = {
    "NO_ERROR",        "FORMAT_ERROR",
    "SERVER_FAILURE",  "NX_DOMAIN",
    "NOT_IMPLEMENTED", "REFUSED",
    "YX_DOMAIN",       "YX_RRSET",
    "NX_RRSET",        "NOT_AUTHORITATIVE/AUTHORIZED",
    "NOT_IN_ZONE",     "DSO_TYPE_NOT_IMPLEMENTED",
    "UNKNOWN",         "UNKNOWN",
    "UNKNOWN",         "UNKNOWN",
    "BAD_OPT_VERSION", "TSIG_SIGNATURE_FAILURE",
    "RC_BAD_TIME",     "BAD_MODE",
    "BAD_NAME",        "BAD_ALGORITHM",
    "BAD_TRUNC",       "BAD_COOKIE",
};

const char *s_aws_dns_result_code_type_to_c_str(enum aws_dns_result_code_type result_code) {
    size_t index = result_code;
    if (index < AWS_ARRAY_SIZE(s_result_code_names)) {
        return s_result_code_names[index];
    }

    return "UNKNOWN";
}

struct elastidig_ctx {
    struct aws_allocator *allocator;
    const char *server;
    const char *name;
    enum aws_dns_resource_record_type record_type;
    uint64_t start_time_ns;

    struct aws_logger logger;
    struct aws_event_loop_group el_group;
    struct aws_host_resolver old_resolver;
    struct aws_client_bootstrap *bootstrap;
    struct aws_dns_resolver_udp_channel *resolver;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    bool bootstrap_shutdown_completed;
    bool query_complete;
    bool resolver_shutdown;
};

static void s_usage(int exit_code) {

    fprintf(stderr, "usage: elastidig [options] server name record_type\n");
    fprintf(stderr, " server: ipv4 address of the server to send a DNS question to\n");
    fprintf(stderr, " name: name to retrieve DNS records for\n");
    fprintf(stderr, " record_type: type of records to query\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

/* clang-format off */
static struct aws_cli_option s_long_options[] = {
    {"version", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'V'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};
/* clang-format on */

static void s_parse_options(int argc, char **argv, struct elastidig_ctx *ctx) {
    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "a:b:Vh", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null */
                break;
            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
        }
    }

    if (aws_cli_optind < argc) {
        ctx->server = argv[aws_cli_optind++];
    } else {
        fprintf(stderr, "An ip address of a DNS server must be supplied.\n");
        s_usage(1);
    }

    if (aws_cli_optind < argc) {
        ctx->name = argv[aws_cli_optind++];
    } else {
        fprintf(stderr, "A name to query must be supplied.\n");
        s_usage(1);
    }

    if (aws_cli_optind < argc) {
        ctx->record_type = s_aws_c_string_to_aws_dns_resource_record_type(argv[aws_cli_optind++]);
    } else {
        ctx->record_type = AWS_DNS_RR_A;
    }
}

static void s_client_bootstrap_shutdown_complete_fn(void *user_data) {
    struct elastidig_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->lock);
    app_ctx->bootstrap_shutdown_completed = true;
    aws_mutex_unlock(&app_ctx->lock);

    aws_condition_variable_notify_one(&app_ctx->signal);
}

static bool s_resolver_shutdown_predicate(void *user_data) {
    struct elastidig_ctx *app_ctx = user_data;

    return app_ctx->resolver_shutdown;
}

static bool s_bootstrap_shutdown_predicate(void *user_data) {
    struct elastidig_ctx *app_ctx = user_data;

    return app_ctx->bootstrap_shutdown_completed;
}

static void s_on_resolver_destroyed(void *user_data) {
    struct elastidig_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->lock);
    app_ctx->resolver_shutdown = true;
    aws_mutex_unlock(&app_ctx->lock);

    aws_condition_variable_notify_one(&app_ctx->signal);
}

static void s_print_header(struct aws_dns_query_result *result) {
    enum aws_dns_flags_opcode_type opcode = aws_dns_fixed_flags_get_opcode(result->fixed_header_flags);
    enum aws_dns_result_code_type result_code = aws_dns_fixed_flags_get_result_code(result->fixed_header_flags);

    printf(
        ";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n",
        s_aws_dns_flags_opcode_type_to_c_str(opcode),
        s_aws_dns_result_code_type_to_c_str(result_code),
        (int)result->transaction_id);

    // ;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 5
    printf(";; flags:");
    if (!aws_dns_fixed_flags_is_query(result->fixed_header_flags)) {
        printf(" qr");
    }

    if (aws_dns_fixed_flags_is_recursion_desired(result->fixed_header_flags)) {
        printf(" rd");
    }

    if (aws_dns_fixed_flags_is_recursion_available(result->fixed_header_flags)) {
        printf(" ra");
    }

    if (aws_dns_fixed_flags_is_truncated(result->fixed_header_flags)) {
        printf(" tc");
    }

    printf(
        "; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
        (int)aws_array_list_length(&result->question_records),
        (int)aws_array_list_length(&result->answer_records),
        (int)aws_array_list_length(&result->authority_records),
        (int)aws_array_list_length(&result->additional_records));
}

static void s_print_ipv4_address(struct aws_dns_resource_record *record) {
    size_t data_length = record->data.len;

    for (size_t i = 0; i < data_length; ++i) {
        printf("%d", (int)record->data.buffer[i]);
        if (i + 1 < data_length) {
            printf(".");
        }
    }
}

static void s_print_hex_char(uint8_t value) {
    if (value < 10) {
        printf("%c", '0' + (char)value);
    } else {
        printf("%c", 'a' + (char)(value - 10));
    }
}

static void s_print_ipv6_address(struct aws_dns_resource_record *record) {
    size_t data_length = record->data.len;

    for (size_t i = 0; i < data_length; ++i) {
        uint8_t value = record->data.buffer[i];
        s_print_hex_char(value >> 4);
        s_print_hex_char(value & 0x0F);

        if (i % 2 == 1 && i + 1 < data_length) {
            printf(":");
        }
    }
}

static void s_print_record_data(struct aws_dns_resource_record *record) {
    switch (record->type) {
        case AWS_DNS_RR_A:
            s_print_ipv4_address(record);
            break;

        case AWS_DNS_RR_AAAA:
            s_print_ipv6_address(record);
            break;

        case AWS_DNS_RR_NS:
        case AWS_DNS_RR_CNAME:
        case AWS_DNS_RR_DNAME: {
            if (record->data.len > 0) {
                struct aws_string *data_as_string =
                    aws_string_new_from_array(aws_default_allocator(), record->data.buffer, record->data.len);
                printf("%-40s ", (const char *)data_as_string->bytes);
                aws_string_destroy(data_as_string);
            }
            break;
        }

        default:
            printf("[%d bytes of data]", (int)record->data.len);
            break;
    }
}
static void s_print_record(struct aws_dns_resource_record *record) {
    (void)record;

    struct aws_string *name_as_string =
        aws_string_new_from_array(aws_default_allocator(), record->name.buffer, record->name.len);

    printf("%-40s ", (const char *)name_as_string->bytes);
    printf("%10d ", record->ttl);
    printf("IN ");
    printf("%-10s", s_aws_dns_resource_record_type_to_c_str(record->type));

    s_print_record_data(record);

    printf("\n");

    aws_string_destroy(name_as_string);
}

static void s_print_records(struct aws_array_list *records) {
    size_t record_count = aws_array_list_length(records);
    for (size_t i = 0; i < record_count; ++i) {
        struct aws_dns_resource_record *record = NULL;
        aws_array_list_get_at_ptr(records, (void **)&record, i);

        s_print_record(record);
    }
}

static void s_output_query_results(struct aws_dns_query_result *result, int error_code, struct elastidig_ctx *app_ctx) {

    if (error_code != AWS_ERROR_SUCCESS || result == NULL) {
        if (error_code == AWS_IO_DNS_QUERY_TIMEOUT) {
            printf(";; Query timed out; no response received\n");
        } else if (error_code != AWS_ERROR_SUCCESS) {
            printf(";; Error while making DNS query: %s\n", aws_error_debug_str(error_code));
        } else {
            printf(";; Unknown error while making DNS query\n");
        }

        return;
    }

    printf(";; Got answer:\n");

    s_print_header(result);

    printf("\n;; QUESTION SECTION:\n");
    s_print_records(&result->question_records);

    printf("\n;; ANSWER SECTION:\n");
    s_print_records(&result->answer_records);

    printf("\n;; AUTHORITY SECTION:\n");
    s_print_records(&result->authority_records);

    printf("\n;; ADDITIONAL SECTION:\n");
    s_print_records(&result->additional_records);

    uint64_t now = 0;
    aws_sys_clock_get_ticks(&now);

    uint64_t difference_ns = now - app_ctx->start_time_ns;

    printf(
        "\n;; Query Time: %" PRIu64 " msec\n",
        aws_timestamp_convert(difference_ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL));
}

static void s_on_query_complete(struct aws_dns_query_result *result, int error_code, void *user_data) {
    (void)result;
    (void)error_code;
    struct elastidig_ctx *app_ctx = user_data;

    s_output_query_results(result, error_code, app_ctx);

    aws_mutex_lock(&app_ctx->lock);
    app_ctx->query_complete = true;
    aws_mutex_unlock(&app_ctx->lock);

    aws_condition_variable_notify_one(&app_ctx->signal);
}

static bool s_query_complete_predicate(void *user_data) {
    struct elastidig_ctx *app_ctx = user_data;

    return app_ctx->query_complete;
}

static int s_init_elastidig(struct elastidig_ctx *app_ctx, struct aws_allocator *allocator, int argc, char **argv) {
    AWS_ZERO_STRUCT(*app_ctx);

    app_ctx->allocator = allocator;

    aws_io_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_NONE,
        .file = stderr,
    };

    aws_logger_init_standard(&app_ctx->logger, app_ctx->allocator, &logger_options);
    aws_logger_set(&app_ctx->logger);

    aws_mutex_init(&app_ctx->lock);
    aws_condition_variable_init(&app_ctx->signal);

    s_parse_options(argc, argv, app_ctx);

    aws_event_loop_group_default_init(&app_ctx->el_group, allocator, 1);
    aws_host_resolver_init_default(&app_ctx->old_resolver, allocator, 16, &app_ctx->el_group);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = &app_ctx->el_group,
        .host_resolver = &app_ctx->old_resolver,
        .on_shutdown_complete = s_client_bootstrap_shutdown_complete_fn,
        .user_data = app_ctx,
    };

    app_ctx->bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_dns_resolver_udp_channel_options resolver_options = {
        .bootstrap = app_ctx->bootstrap,
        .host = aws_byte_cursor_from_c_str(app_ctx->server),
        .port = 53,
        .on_destroyed_callback = s_on_resolver_destroyed,
        .on_destroyed_user_data = app_ctx,
    };

    app_ctx->resolver = aws_dns_resolver_udp_channel_new(allocator, &resolver_options);

    return AWS_OP_SUCCESS;
}

static void s_wait_on_query_complete(struct elastidig_ctx *app_ctx) {
    aws_mutex_lock(&app_ctx->lock);
    aws_condition_variable_wait_pred(&app_ctx->signal, &app_ctx->lock, s_query_complete_predicate, app_ctx);
    aws_mutex_unlock(&app_ctx->lock);
}

static void s_perform_query(struct elastidig_ctx *app_ctx) {
    struct aws_dns_query query = {
        .query_type = app_ctx->record_type,
        .hostname = aws_byte_cursor_from_c_str(app_ctx->name),
        .on_completed_callback = s_on_query_complete,
        .user_data = app_ctx,
    };

    aws_sys_clock_get_ticks(&app_ctx->start_time_ns);

    aws_dns_resolver_udp_channel_make_query(app_ctx->resolver, &query);

    s_wait_on_query_complete(app_ctx);
}

static void s_cleanup_elastidig(struct elastidig_ctx *app_ctx) {
    aws_dns_resolver_udp_channel_destroy(app_ctx->resolver);

    aws_condition_variable_wait_pred(&app_ctx->signal, &app_ctx->lock, s_resolver_shutdown_predicate, app_ctx);
    aws_mutex_unlock(&app_ctx->lock);

    aws_client_bootstrap_release(app_ctx->bootstrap);

    aws_condition_variable_wait_pred(&app_ctx->signal, &app_ctx->lock, s_bootstrap_shutdown_predicate, app_ctx);
    aws_mutex_unlock(&app_ctx->lock);

    aws_host_resolver_clean_up(&app_ctx->old_resolver);
    aws_event_loop_group_clean_up(&app_ctx->el_group);

    aws_condition_variable_clean_up(&app_ctx->signal);
    aws_mutex_clean_up(&app_ctx->lock);

    aws_io_library_clean_up();

    aws_logger_clean_up(&app_ctx->logger);
}

int main(int argc, char **argv) {
    struct aws_allocator *allocator = aws_default_allocator();

    struct elastidig_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);

    fprintf(stdout, "; <<>> elastidig %s <<>> ", ELASTIDIG_VERSION);
    for (int i = 1; i < argc; ++i) {
        printf(" %s", argv[i]);
    }
    fprintf(stdout, "\n");

    int exit_code = 0;

    if (s_init_elastidig(&app_ctx, allocator, argc, argv) == AWS_OP_SUCCESS) {
        s_perform_query(&app_ctx);
    } else {
        fprintf(stderr, "Failed to initialize elastidig\n");
        exit_code = 1;
    }

    s_cleanup_elastidig(&app_ctx);

    return exit_code;
}
