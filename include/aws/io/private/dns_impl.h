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

#include <aws/io/dns.h>

#include <aws/common/atomics.h>
#include <aws/io/channel.h>

struct aws_dns_resolver_impl_udp_options {
    struct aws_channel_bootstrap *bootstrap;
    struct aws_byte_cursor host;
    uint16_t port;
};

enum aws_dns_resolver_state {
    AWS_DNS_RS_CONNECTING, /* time interval where channel is created but not initialized */
    AWS_DNS_RS_CONNECTED,
    AWS_DNS_RS_RECONNECTING, /* time interval where reconnect task is scheduled but not yet ran */
    AWS_DNS_RS_DISCONNECTING,
    AWS_DNS_RS_DISCONNECTED,
};

struct dns_resolver_udp_reconnect_task;

struct aws_dns_resolver_impl_udp {
    /* immutable */
    struct aws_string *host;
    uint16_t port;
    struct aws_channel_bootstrap *bootstrap;

    /* event-loop-only state */
    struct aws_channel_handler handler;

    /* shared state */
    struct aws_atomic_var ref_count;

    /* shared, protected state */
    struct aws_mutex lock;
    enum aws_dns_resolver_state state;
    struct aws_channel_slot *slot;

    struct dns_resolver_udp_reconnect_task *reconnect_task;
};

typedef int (aws_dns_resolver_impl_make_query_callback_fn)(struct aws_byte_cursor address, int error_code, void *user_data);

typedef void (aws_dns_resolver_impl_udp_on_destroyed_callback_fn)(void *user_data);

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_dns_resolver_impl_udp *aws_dns_resolver_impl_udp_new(struct aws_allocator *allocator, struct aws_dns_resolver_impl_udp_options *options);

AWS_IO_API
void aws_dns_resolver_impl_udp_destroy_destroy(struct aws_dns_resolver_impl_udp *resolver);

AWS_IO_API
int aws_dns_resolver_impl_udp_make_query(struct aws_dns_resolver_impl_udp *resolver, struct aws_byte_cursor host_name, aws_dns_resolver_impl_make_query_callback_fn *callback, void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_IMPL_H */
