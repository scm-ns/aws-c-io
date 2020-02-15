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

#include <aws/io/private/dns_impl.h>

#include <aws/common/clock.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

static void s_aws_dns_resolver_impl_udp_destroy_finalize(struct aws_dns_resolver_udp_channel *resolver) {
    if (resolver == NULL) {
        return;
    }

    aws_string_destroy(resolver->host);

    if (resolver->on_destroyed_callback) {
        (resolver->on_destroyed_callback)(resolver->on_initial_connection_user_data);
    }

    aws_mem_release(resolver->allocator, resolver);
}

static int s_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;

    return AWS_OP_SUCCESS;
}

static int s_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)handler;

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static void s_destroy(struct aws_channel_handler *handler) {
    (void)handler;
}

static size_t s_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}

static struct aws_channel_handler_vtable s_udp_vtable = {
    .process_read_message = &s_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = NULL,
    .shutdown = &s_shutdown,
    .initial_window_size = &s_initial_window_size,
    .message_overhead = &s_message_overhead,
    .destroy = &s_destroy,
};

struct dns_resolver_udp_channel_reconnect_task {
    struct aws_dns_resolver_udp_channel *resolver;
    struct aws_allocator *allocator;
    struct aws_task task;
};

static int s_connect(struct aws_dns_resolver_udp_channel *resolver);

static void s_dns_udp_reconnect_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;

    struct dns_resolver_udp_channel_reconnect_task *reconnect_task =
        AWS_CONTAINER_OF(task, struct dns_resolver_udp_reconnect_task, task);
    struct aws_dns_resolver_udp_channel *resolver = arg;

    if (resolver == NULL || status != AWS_TASK_STATUS_RUN_READY) {
        aws_mem_release(reconnect_task->allocator, task);
        return;
    }

    aws_mutex_lock(&resolver->lock);

    if (resolver->state != AWS_DNS_UDP_CHANNEL_RECONNECTING) {
        AWS_FATAL_ASSERT(
            resolver->state == AWS_DNS_UDP_CHANNEL_DISCONNECTING ||
            resolver->state == AWS_DNS_UDP_CHANNEL_DISCONNECTED);

        resolver->reconnect_task = NULL;
        aws_mem_release(reconnect_task->allocator, task);
        aws_mutex_unlock(&resolver->lock);
        return;
    }

    resolver->state = AWS_DNS_UDP_CHANNEL_CONNECTING;

    aws_mutex_unlock(&resolver->lock);

    if (s_connect(resolver)) {
        struct aws_event_loop *el = aws_event_loop_group_get_next_loop(resolver->bootstrap->event_loop_group);

        uint64_t reconnect_time_ns = 0;
        aws_event_loop_current_clock_time(el, &reconnect_time_ns);
        reconnect_time_ns += aws_timestamp_convert(2, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
        aws_event_loop_schedule_task_future(el, &resolver->reconnect_task->task, reconnect_time_ns);
    }
}

static void s_aws_dns_resolver_impl_udp_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;
    (void)user_data;

    struct aws_dns_resolver_udp_channel *resolver = user_data;

    AWS_LOGF_TRACE(
        AWS_LS_IO_DNS, "id=%p: UDP DNS Channel has been shutdown with error code %d", (void *)resolver, error_code);

    aws_mutex_lock(&resolver->lock);

    /* Always clear slot, as that's what's been shutdown */
    if (resolver->slot) {
        aws_channel_slot_remove(resolver->slot);
        resolver->slot = NULL;
    }

    bool finalize = false;

    /* If there's no error code and this wasn't user-requested, set the error code to something useful (eventually) */
    if (error_code == AWS_ERROR_SUCCESS) {
        if (resolver->state != AWS_DNS_UDP_CHANNEL_DISCONNECTING &&
            resolver->state != AWS_DNS_UDP_CHANNEL_DISCONNECTED) {
            error_code = AWS_ERROR_UNKNOWN;
        }
    }

    /*
     * ToDo - does reconnecting need any special logic here?
     */

    if (resolver->state == AWS_DNS_UDP_CHANNEL_CONNECTING || resolver->state == AWS_DNS_UDP_CHANNEL_CONNECTED) {
        /* schedule the next attempt */

        if (resolver->state == AWS_DNS_UDP_CHANNEL_CONNECTING) {
            AWS_LOGF_DEBUG(AWS_LS_IO_DNS, "id=%p: Udp DNS Connect failed, scheduling retry", (void *)resolver);
        } else {
            AWS_LOGF_DEBUG(AWS_LS_IO_DNS, "id=%p: Udp DNS Connection dropped, scheduling retry", (void *)resolver);
        }

        struct aws_event_loop *el = aws_event_loop_group_get_next_loop(resolver->bootstrap->event_loop_group);
        resolver->state = AWS_DNS_UDP_CHANNEL_RECONNECTING;

        uint64_t reconnect_time_ns = 0;
        aws_event_loop_current_clock_time(el, &reconnect_time_ns);
        reconnect_time_ns += aws_timestamp_convert(2, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
        aws_event_loop_schedule_task_future(el, &resolver->reconnect_task->task, reconnect_time_ns);
    } else if (resolver->state == AWS_DNS_UDP_CHANNEL_DISCONNECTING) {

        resolver->state = AWS_DNS_UDP_CHANNEL_DISCONNECTED;

        AWS_LOGF_DEBUG(AWS_LS_IO_DNS, "id=%p: Udp DNS Disconnect completed", (void *)resolver);

        finalize = true;
    }

    aws_mutex_unlock(&resolver->lock);

    if (finalize) {
        s_aws_dns_resolver_impl_udp_destroy_finalize(resolver);
    }
}

static void s_aws_dns_resolver_impl_udp_init(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    /* Setup callback contract is: if error_code is non-zero then channel is NULL. */
    AWS_FATAL_ASSERT((error_code != 0) == (channel == NULL));

    struct aws_dns_resolver_udp_channel *resolver = user_data;

    if (error_code != AWS_OP_SUCCESS) {
        /* client shutdown already handles this case, so just call that. */
        s_aws_dns_resolver_impl_udp_shutdown(bootstrap, error_code, channel, user_data);
        return;
    }

    bool make_initial_connection_callback = false;

    aws_mutex_lock(&resolver->lock);

    /*
     * These feel impossible, but experience may tell differently:
     *
     * AWS_DNS_RS_DISCONNECTED - a shutdown has previously happened against a DISCONNECTING state.  There's no escape
     * from disconnecting or disconnected, so how could an init callback happen afterwards?
     *
     * AWS_DNS_UDP_CHANNEL_RECONNECTING - by definition, reconnecting is when a connect task has been scheduled, but not
     * executed, so how can a connection be completed in such a state?
     *
     * AWS_DNS_UDP_CHANNEL_CONNECTED - similar to reconnecting, implies a double completion callback
     */
    AWS_FATAL_ASSERT(
        resolver->state != AWS_DNS_UDP_CHANNEL_DISCONNECTED && resolver->state != AWS_DNS_UDP_CHANNEL_RECONNECTING &&
        resolver->state != AWS_DNS_UDP_CHANNEL_CONNECTED);

    if (resolver->state == AWS_DNS_UDP_CHANNEL_DISCONNECTING) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_DNS,
            "id=%p: DNS UDP connection successfully opened, but shut down has been requested",
            (void *)resolver);
        aws_channel_shutdown(channel, AWS_ERROR_SUCCESS);
        goto done;
    } else {
        AWS_FATAL_ASSERT(resolver->state == AWS_DNS_UDP_CHANNEL_CONNECTING);

        AWS_LOGF_DEBUG(AWS_LS_IO_DNS, "id=%p: DNS UDP connection successfully opened", (void *)resolver);

        /* Create the slot and handler */
        resolver->slot = aws_channel_slot_new(channel);

        if (!resolver->slot) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_DNS,
                "id=%p: DNS UDP connection failed to create new slot, something has gone horribly wrong",
                (void *)resolver);
            aws_channel_shutdown(channel, aws_last_error());
            goto done;
        }

        aws_channel_slot_insert_end(channel, resolver->slot);
        aws_channel_slot_set_handler(resolver->slot, &resolver->handler);

        resolver->state = AWS_DNS_UDP_CHANNEL_CONNECTED;

        if (!resolver->initial_connection_callback_completed) {
            resolver->initial_connection_callback_completed = true;
            make_initial_connection_callback = true;
        }
    }

done:

    aws_mutex_unlock(&resolver->lock);

    if (make_initial_connection_callback && resolver->on_initial_connection_callback != NULL) {
        (resolver->on_initial_connection_callback)(resolver->on_initial_connection_user_data);
    }
}

static int s_connect(struct aws_dns_resolver_udp_channel *resolver) {
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_DGRAM,
        .connect_timeout_ms = 5000,
        .keep_alive_timeout_sec = 0,
        .keepalive = false,
        .keep_alive_interval_sec = 0,
    };

    return aws_client_bootstrap_new_socket_channel(
        resolver->bootstrap,
        (const char *)resolver->host->bytes,
        resolver->port,
        &socket_options,
        s_aws_dns_resolver_impl_udp_init,
        s_aws_dns_resolver_impl_udp_shutdown,
        resolver);
}

struct aws_dns_resolver_udp_channel *aws_dns_resolver_udp_channel_new(
    struct aws_allocator *allocator,
    struct aws_dns_resolver_udp_channel_options *options) {
    struct aws_dns_resolver_udp_channel *resolver =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_dns_resolver_udp_channel));
    if (resolver == NULL) {
        return NULL;
    }

    resolver->allocator = allocator;
    resolver->bootstrap = options->bootstrap;
    resolver->on_destroyed_callback = options->on_destroyed_callback;
    resolver->on_destroyed_user_data = options->on_destroyed_user_data;
    resolver->on_initial_connection_callback = options->on_initial_connection_callback;
    resolver->on_initial_connection_user_data = options->on_initial_connection_user_data;
    resolver->initial_connection_callback_completed = false;

    resolver->host = aws_string_new_from_array(allocator, options->host.ptr, options->host.len);
    if (resolver->host == NULL) {
        goto on_error;
    }

    if (aws_mutex_init(&resolver->lock)) {
        goto on_error;
    }

    resolver->reconnect_task =
        aws_mem_calloc(resolver->allocator, 1, sizeof(struct dns_resolver_udp_channel_reconnect_task));
    resolver->reconnect_task->resolver = resolver;
    resolver->reconnect_task->allocator = resolver->allocator;
    aws_task_init(
        &resolver->reconnect_task->task, s_dns_udp_reconnect_task, resolver->reconnect_task, "dns_udp_reconnect");

    resolver->state = AWS_DNS_UDP_CHANNEL_CONNECTING;
    resolver->port = options->port;

    resolver->handler.alloc = allocator;
    resolver->handler.vtable = &s_udp_vtable;
    resolver->handler.impl = resolver;

    if (s_connect(resolver)) {
        goto on_error;
    }

    return resolver;

on_error:

    s_aws_dns_resolver_impl_udp_destroy_finalize(resolver);

    return NULL;
}

struct dns_resolver_udp_shutdown_task {
    int error_code;
    struct aws_dns_resolver_udp_channel *resolver;
    struct aws_channel_task task;
};

static void s_dns_udp_disconnect_task(struct aws_channel_task *channel_task, void *arg, enum aws_task_status status) {
    (void)status;

    struct dns_resolver_udp_shutdown_task *task =
        AWS_CONTAINER_OF(channel_task, struct dns_resolver_udp_shutdown_task, task);
    struct aws_dns_resolver_udp_channel *resolver = arg;

    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "id=%p: Doing disconnect", (void *)resolver);

    aws_mutex_lock(&resolver->lock);

    /* If there is an outstanding reconnect task, cancel it */
    if (resolver->state == AWS_DNS_UDP_CHANNEL_DISCONNECTING && resolver->reconnect_task) {
        resolver->reconnect_task->resolver = NULL;

        /* If the reconnect_task isn't scheduled, free it */
        if (!resolver->reconnect_task->task.timestamp) {
            aws_mem_release(resolver->reconnect_task->allocator, resolver->reconnect_task);
        }

        resolver->reconnect_task = NULL;
    }

    if (resolver->slot && resolver->slot->channel) {
        aws_channel_shutdown(resolver->slot->channel, task->error_code);
    }

    aws_mutex_unlock(&resolver->lock);

    aws_mem_release(resolver->allocator, task);
}

void aws_dns_resolver_udp_channel_destroy(struct aws_dns_resolver_udp_channel *resolver) {
    aws_mutex_lock(&resolver->lock);

    if (resolver->state == AWS_DNS_UDP_CHANNEL_CONNECTING || resolver->state == AWS_DNS_UDP_CHANNEL_CONNECTED ||
        resolver->state == AWS_DNS_UDP_CHANNEL_RECONNECTING) {
        resolver->state = AWS_DNS_UDP_CHANNEL_DISCONNECTING;

        /* schedule a shutdown task */
        if (resolver->slot) {
            struct dns_resolver_udp_shutdown_task *shutdown_task =
                aws_mem_calloc(resolver->allocator, 1, sizeof(struct dns_resolver_udp_shutdown_task));
            shutdown_task->error_code = AWS_ERROR_SUCCESS;
            shutdown_task->resolver = resolver;
            aws_channel_task_init(&shutdown_task->task, s_dns_udp_disconnect_task, resolver, "dns_udp_disconnect");
            aws_channel_schedule_task_now(resolver->slot->channel, &shutdown_task->task);
        }
    }

    aws_mutex_unlock(&resolver->lock);
}

int aws_dns_resolver_udp_channel_make_query(
    struct aws_dns_resolver_udp_channel *resolver,
    struct aws_byte_cursor host_name,
    aws_dns_resolver_channel_make_query_callback_fn *callback,
    void *user_data) {
    (void)resolver;
    (void)host_name;
    (void)callback;
    (void)user_data;

    return AWS_OP_SUCCESS;
}
