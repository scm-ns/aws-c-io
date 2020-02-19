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

#include <aws/common/command_line_parser.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>

#include <aws/io/channel_bootstrap.h>
#include <aws/io/private/dns_impl.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

#include <inttypes.h>



#define ELASTIDIG_VERSION "0.0.1"

enum aws_dns_resource_record_type s_aws_c_string_to_aws_dns_resource_record_type(const char *record_type_string) {
    (void)record_type_string;

    return AWS_DNS_RR_A;
}

struct elastidig_ctx {
    struct aws_allocator *allocator;
    const char *server;
    const char *name;
    enum aws_dns_resource_record_type record_type;

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
    fprintf(stderr, "      --version: print the version of elastidig.\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"version", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'V'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

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
            case 'V':
                fprintf(stderr, "elastidig %s\n", ELASTIDIG_VERSION);
                exit(0);
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

static void s_on_query_complete(struct aws_dns_query_result *result, int error_code, void *user_data) {
    (void)result;
    (void)error_code;
    struct elastidig_ctx *app_ctx = user_data;

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
        .level = AWS_LOG_LEVEL_TRACE,
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

    if (s_init_elastidig(&app_ctx, allocator, argc, argv) == AWS_OP_SUCCESS) {
        s_perform_query(&app_ctx);
    }

    s_cleanup_elastidig(&app_ctx);

    return 0;
}
