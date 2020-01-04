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

struct elastidig_ctx {
    struct aws_allocator *allocator;
    const char *dns_host;
    uint16_t dns_port;
    const char *host;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    bool bootstrap_shutdown_completed;
};

static void s_usage(int exit_code) {

    fprintf(stderr, "usage: elastidig [options] host_name\n");
    fprintf(stderr, " host_name: host to retrieve A and AAAA records for.\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "      --dnshost STRING: ipv4 address of the dns host to query.\n");
    fprintf(stderr, "      --dnsport INT: port on the dns host to connect to.\n");
    fprintf(stderr, "      --version: print the version of elastidig.\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"dnshost", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"dnsport", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'b'},
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
            case 'a':
                ctx->dns_host = aws_cli_optarg;
                break;
            case 'b':
                ctx->dns_port = atoi(aws_cli_optarg);
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
        ctx->host = argv[aws_cli_optind++];
    } else {
        fprintf(stderr, "A host name for the query must be supplied.\n");
        s_usage(1);
    }
}

static void s_bootstrap_on_shutdown(void *user_data) {
    struct elastidig_ctx *app_ctx = user_data;

    aws_mutex_lock(&app_ctx->lock);
    app_ctx->bootstrap_shutdown_completed = true;
    aws_mutex_unlock(&app_ctx->lock);
    aws_condition_variable_notify_all(&app_ctx->signal);
}

static bool s_bootstrap_shutdown_predicate(void *arg) {
    struct elastidig_ctx *app_ctx = arg;
    return app_ctx->bootstrap_shutdown_completed;
}

int main(int argc, char **argv) {
    struct aws_allocator *allocator = aws_default_allocator();

    aws_io_library_init(allocator);

    struct elastidig_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    aws_mutex_init(&app_ctx.lock);
    aws_condition_variable_init(&app_ctx.signal);

    s_parse_options(argc, argv, &app_ctx);

    struct aws_logger logger;
    AWS_ZERO_STRUCT(logger);

    struct aws_logger_standard_options options = {
        .level = AWS_LL_TRACE,
        .filename = "/tmp/dnslog.txt",
    };

    if (aws_logger_init_standard(&logger, allocator, &options)) {
        fprintf(stderr, "Failed to initialize logger with error %s\n", aws_error_debug_str(aws_last_error()));
        exit(1);
    }

    aws_logger_set(&logger);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 1);

    /*
     * For now we have to bootstrap our new host resolvers with the old resolver since that's the only thing we
     * have a connection creation pipeline for
     */
    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 8, &el_group);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = &el_group,
        .host_resolver = &resolver,
        .on_shutdown_complete = s_bootstrap_on_shutdown,
        .user_data = &app_ctx,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    aws_client_bootstrap_release(bootstrap);

    aws_mutex_lock(&app_ctx.lock);
    aws_condition_variable_wait_pred(&app_ctx.signal, &app_ctx.lock, s_bootstrap_shutdown_predicate, &app_ctx);
    aws_mutex_unlock(&app_ctx.lock);

    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_io_library_clean_up();

    aws_logger_clean_up(&logger);

    return 0;
}
