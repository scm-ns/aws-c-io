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

#include <aws/testing/aws_test_harness.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/io.h>
#include <aws/io/private/dns_impl.h>

struct aws_dns_resolver_udp_test {
    struct aws_allocator *allocator;
    struct aws_logger logger;
    struct aws_event_loop_group elg;
    struct aws_host_resolver old_resolver;
    struct aws_client_bootstrap *bootstrap;
    struct aws_dns_resolver_impl_udp *resolver;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    bool connected;
    bool resolver_shutdown;
    bool bootstrap_shutdown;
};

static struct aws_dns_resolver_udp_test s_test;

static void s_client_bootstrap_shutdown_complete_fn(void *user_data) {
    aws_mutex_lock(&s_test.lock);
    s_test.bootstrap_shutdown = true;
    aws_mutex_unlock(&s_test.lock);

    aws_condition_variable_notify_one(&s_test.signal);
}

static bool s_resolver_connected_predicate(void *user_data) {
    (void)user_data;

    return s_test.connected;
}

static bool s_resolver_shutdown_predicate(void *user_data) {
    (void)user_data;

    return s_test.resolver_shutdown;
}

static bool s_bootstrap_shutdown_predicate(void *user_data) {
    (void)user_data;

    return s_test.bootstrap_shutdown;
}

static void s_on_resolver_destroyed(void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_test.lock);
    s_test.resolver_shutdown = true;
    aws_mutex_unlock(&s_test.lock);

    aws_condition_variable_notify_one(&s_test.signal);
}

static void s_on_resolver_initial_connection(void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_test.lock);
    s_test.connected = true;
    aws_mutex_unlock(&s_test.lock);

    aws_condition_variable_notify_one(&s_test.signal);
}

static int s_init_udp_test(struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(s_test);

    s_test.allocator = allocator;

    aws_io_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    ASSERT_SUCCESS(aws_logger_init_standard(&s_test.logger, s_test.allocator, &logger_options));
    aws_logger_set(&s_test.logger);

    aws_mutex_init(&s_test.lock);
    aws_condition_variable_init(&s_test.signal);

    aws_event_loop_group_default_init(&s_test.elg, allocator, 1);
    aws_host_resolver_init_default(&s_test.old_resolver, allocator, 16, &s_test.elg);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = &s_test.elg,
        .host_resolver = &s_test.old_resolver,
        .on_shutdown_complete = s_client_bootstrap_shutdown_complete_fn,
    };

    s_test.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_dns_resolver_impl_udp_options resolver_options = {
        .bootstrap = s_test.bootstrap,
        .host = aws_byte_cursor_from_c_str("127.0.0.53"),
        .port = 53,
        .on_destroyed_callback = s_on_resolver_destroyed,
        .on_initial_connection_callback = s_on_resolver_initial_connection,
    };

    s_test.resolver = aws_dns_resolver_impl_udp_new(allocator, &resolver_options);

    aws_condition_variable_wait_pred(&s_test.signal, &s_test.lock, s_resolver_connected_predicate, NULL);
    aws_mutex_unlock(&s_test.lock);

    return AWS_OP_SUCCESS;
}

static void s_shutdown_udp_test(void) {

    aws_dns_resolver_impl_udp_destroy(s_test.resolver);

    aws_condition_variable_wait_pred(&s_test.signal, &s_test.lock, s_resolver_shutdown_predicate, NULL);
    aws_mutex_unlock(&s_test.lock);

    aws_client_bootstrap_release(s_test.bootstrap);

    aws_condition_variable_wait_pred(&s_test.signal, &s_test.lock, s_bootstrap_shutdown_predicate, NULL);
    aws_mutex_unlock(&s_test.lock);

    aws_host_resolver_clean_up(&s_test.old_resolver);
    aws_event_loop_group_clean_up(&s_test.elg);

    aws_condition_variable_clean_up(&s_test.signal);
    aws_mutex_clean_up(&s_test.lock);

    aws_io_library_clean_up();

    aws_logger_clean_up(&s_test.logger);
}

static int s_dns_udp_resolver_create_destroy_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    s_init_udp_test(allocator);
    s_shutdown_udp_test();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(dns_udp_resolver_create_destroy_test, s_dns_udp_resolver_create_destroy_test)