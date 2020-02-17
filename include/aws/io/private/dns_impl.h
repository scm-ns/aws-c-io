#ifndef AWS_IO_DNS_IMPL_H
#define AWS_IO_DNS_IMPL_H
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
#include <aws/common/mutex.h>
#include <aws/io/channel.h>
#include <aws/io/dns.h>

struct aws_string;
struct aws_channel_bootstrap;

typedef void(aws_dns_resolver_udp_channel_on_destroyed_callback_fn)(void *user_data);
typedef void(aws_dns_resolver_udp_channel_on_initial_connection_callback_fn)(void *user_data);

struct aws_dns_resolver_udp_channel_options {
    struct aws_client_bootstrap *bootstrap;
    struct aws_byte_cursor host;
    uint16_t port;

    aws_dns_resolver_udp_channel_on_destroyed_callback_fn *on_destroyed_callback;
    void *on_destroyed_user_data;

    aws_dns_resolver_udp_channel_on_initial_connection_callback_fn *on_initial_connection_callback;
    void *on_initial_connection_user_data;
};

enum aws_dns_resolver_udp_channel_state {
    AWS_DNS_UDP_CHANNEL_CONNECTING, /* time interval where channel is created but not initialized */
    AWS_DNS_UDP_CHANNEL_CONNECTED,
    AWS_DNS_UDP_CHANNEL_RECONNECTING, /* time interval where reconnect task is scheduled but not yet ran */
    AWS_DNS_UDP_CHANNEL_DISCONNECTING,
    AWS_DNS_UDP_CHANNEL_DISCONNECTED,
};

struct dns_resolver_udp_channel_reconnect_task;

struct aws_dns_resolver_udp_channel {
    /* immutable */
    struct aws_allocator *allocator;
    struct aws_string *host;
    uint16_t port;
    struct aws_client_bootstrap *bootstrap;
    aws_dns_resolver_udp_channel_on_destroyed_callback_fn *on_destroyed_callback;
    void *on_destroyed_user_data;
    aws_dns_resolver_udp_channel_on_initial_connection_callback_fn *on_initial_connection_callback;
    void *on_initial_connection_user_data;

    /* event-loop-only state */
    struct aws_channel_handler handler;

    /* shared state */
    struct aws_atomic_var ref_count;

    /* shared, protected state */
    struct aws_mutex lock;
    enum aws_dns_resolver_udp_channel_state state;
    struct aws_channel_slot *slot;
    bool initial_connection_callback_completed;

    struct dns_resolver_udp_channel_reconnect_task *reconnect_task;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_dns_resolver_udp_channel *aws_dns_resolver_udp_channel_new(
    struct aws_allocator *allocator,
    struct aws_dns_resolver_udp_channel_options *options);

AWS_IO_API
void aws_dns_resolver_udp_channel_destroy(struct aws_dns_resolver_udp_channel *resolver);

AWS_IO_API
int aws_dns_resolver_udp_channel_make_query(struct aws_dns_resolver_udp_channel *resolver, struct aws_dns_query *query);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_IMPL_H */
