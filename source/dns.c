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

#include <aws/io/private/dns_decoder.h>
#include <aws/io/private/dns_impl.h>

#include <aws/common/clock.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

#define DEFAULT_RETRY_INTERVAL_MS 4000
#define DEFAULT_TIMEOUT_INTERVAL_MS 5000

static void s_unlink_query(struct aws_dns_query_internal *query) {
    if (query->state == AWS_DNS_QS_INITIALIZED) {
        aws_mutex_lock(&query->channel->lock);
    }

    if (query->node.next != NULL) {
        aws_linked_list_remove(&query->node);
    }

    if (query->state == AWS_DNS_QS_INITIALIZED) {
        aws_mutex_unlock(&query->channel->lock);
    }
}

static void s_link_query(struct aws_dns_query_internal *query) {
    switch (query->state) {
        case AWS_DNS_QS_INITIALIZED:
            aws_mutex_lock(&query->channel->lock);
            aws_linked_list_push_back(&query->channel->out_of_thread_queries, &query->node);
            if (!query->channel->is_channel_driver_scheduled &&
                query->channel->state == AWS_DNS_UDP_CHANNEL_CONNECTED) {
                aws_channel_schedule_task_now(query->channel->slot->channel, &query->channel->channel_driver_task);
                query->channel->is_channel_driver_scheduled = true;
            }
            aws_mutex_unlock(&query->channel->lock);
            break;

        case AWS_DNS_QS_PENDING_REQUEST:
            aws_linked_list_push_back(&query->channel->pending_queries, &query->node);
            break;

        case AWS_DNS_QS_PENDING_RESPONSE:
            aws_linked_list_push_back(&query->channel->outstanding_queries, &query->node);
            break;

        default:
            break;
    }
}

static void s_aws_dns_resolver_impl_udp_fail_query_list(struct aws_linked_list *query_list) {
    while (!aws_linked_list_empty(query_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(query_list);
        struct aws_dns_query_internal *query = AWS_CONTAINER_OF(node, struct aws_dns_query_internal, node);

        query->on_completed_callback(NULL, AWS_IO_DNS_QUERY_INTERRUPTED, query->user_data);
        s_unlink_query(query);
        aws_dns_query_internal_destroy(query);
    }
}

static void s_cancel_all_queries(struct aws_dns_resolver_udp_channel *resolver) {
    aws_mutex_lock(&resolver->lock);
    s_aws_dns_resolver_impl_udp_fail_query_list(&resolver->out_of_thread_queries);
    aws_mutex_unlock(&resolver->lock);
    s_aws_dns_resolver_impl_udp_fail_query_list(&resolver->outstanding_queries);
    s_aws_dns_resolver_impl_udp_fail_query_list(&resolver->pending_queries);
}

static void s_aws_dns_resolver_impl_udp_destroy_finalize(struct aws_dns_resolver_udp_channel *resolver) {
    if (resolver == NULL) {
        return;
    }

    s_cancel_all_queries(resolver);

    aws_mutex_clean_up(&resolver->lock);

    aws_string_destroy(resolver->host);

    if (resolver->on_destroyed_callback) {
        (resolver->on_destroyed_callback)(resolver->on_destroyed_user_data);
    }

    aws_mem_release(resolver->allocator, resolver);
}

static struct aws_dns_query_internal *s_find_matching_query(
    struct aws_dns_resolver_udp_channel *resolver,
    struct aws_dns_query_result *response) {
    if (aws_array_list_length(&response->question_records) != 1) {
        return NULL;
    }

    struct aws_dns_resource_record *question = NULL;
    aws_array_list_get_at_ptr(&response->question_records, (void **)&question, 0);

    struct aws_linked_list_node *node = aws_linked_list_begin(&resolver->outstanding_queries);
    while (node != aws_linked_list_end(&resolver->outstanding_queries)) {
        struct aws_dns_query_internal *query = AWS_CONTAINER_OF(node, struct aws_dns_query_internal, node);
        node = aws_linked_list_next(node);

        if (response->transaction_id != query->transaction_id) {
            continue;
        }

        struct aws_byte_cursor question_name_cursor = aws_byte_cursor_from_buf(&question->name);
        struct aws_byte_cursor query_name_cursor = aws_byte_cursor_from_string(query->name);
        if (!aws_byte_cursor_eq_ignore_case(&question_name_cursor, &query_name_cursor)) {
            continue;
        }

        return query;
    }

    return NULL;
}

static int s_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)slot;

    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "Received datagram of length %d on DNS channel", (int)message->message_data.len);

    struct aws_dns_resolver_udp_channel *resolver = handler->impl;

    struct aws_dns_query_result response;
    AWS_ZERO_STRUCT(response);

    if (aws_dns_decode_response(&response, resolver->allocator, aws_byte_cursor_from_buf(&message->message_data))) {
        goto done;
    }

    struct aws_dns_query_internal *source_query = s_find_matching_query(resolver, &response);
    if (source_query != NULL) {
        AWS_LOGF_INFO(
            AWS_LS_IO_DNS,
            "Received response with transaction id %d, invoking query callback",
            (int)response.transaction_id);
        source_query->on_completed_callback(&response, AWS_ERROR_SUCCESS, source_query->user_data);
        source_query->state = AWS_DNS_QS_COMPLETE;
        s_unlink_query(source_query);
        aws_dns_query_internal_destroy(source_query);
    } else {
        AWS_LOGF_INFO(
            AWS_LS_IO_DNS,
            "Received response with transaction id %d but no matching query could be found",
            (int)response.transaction_id);
    }

done:

    aws_dns_query_result_clean_up(&response);

    aws_mem_release(message->allocator, message);

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
        AWS_CONTAINER_OF(task, struct dns_resolver_udp_channel_reconnect_task, task);
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
    (void)channel;

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

        resolver->state = AWS_DNS_UDP_CHANNEL_RECONNECTING;

        while (!aws_linked_list_empty(&resolver->outstanding_queries)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&resolver->outstanding_queries);
            struct aws_dns_query_internal *query = AWS_CONTAINER_OF(node, struct aws_dns_query_internal, node);

            s_unlink_query(query);
            query->state = AWS_DNS_QS_PENDING_REQUEST;
            s_link_query(query);
        }

        uint64_t reconnect_time_ns = 0;
        aws_event_loop_current_clock_time(resolver->loop, &reconnect_time_ns);
        reconnect_time_ns += aws_timestamp_convert(2, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
        aws_event_loop_schedule_task_future(resolver->loop, &resolver->reconnect_task->task, reconnect_time_ns);
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

static void s_schedule_channel_driver_if_needed(struct aws_dns_resolver_udp_channel *resolver) {
    if (aws_linked_list_empty(&resolver->pending_queries) && aws_linked_list_empty(&resolver->out_of_thread_queries)) {
        return;
    }

    if (resolver->state != AWS_DNS_UDP_CHANNEL_CONNECTED) {
        return;
    }

    aws_mutex_lock(&resolver->lock);

    if (!resolver->is_channel_driver_scheduled) {
        resolver->is_channel_driver_scheduled = true;
        aws_channel_schedule_task_now(resolver->slot->channel, &resolver->channel_driver_task);
    }

    aws_mutex_unlock(&resolver->lock);
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
            return;
        }

        aws_channel_slot_insert_end(channel, resolver->slot);
        aws_channel_slot_set_handler(resolver->slot, &resolver->handler);

        resolver->state = AWS_DNS_UDP_CHANNEL_CONNECTED;

        s_schedule_channel_driver_if_needed(resolver);

        if (!resolver->initial_connection_callback_completed) {
            resolver->initial_connection_callback_completed = true;
            if (resolver->on_initial_connection_callback != NULL) {
                (resolver->on_initial_connection_callback)(resolver->on_initial_connection_user_data);
            }
        }
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

    struct aws_socket_channel_bootstrap_options channel_options = {
        .bootstrap = resolver->bootstrap,
        .override_loop = resolver->loop,
        .host_name = (const char *)resolver->host->bytes,
        .port = resolver->port,
        .socket_options = &socket_options,
        .setup_callback = s_aws_dns_resolver_impl_udp_init,
        .shutdown_callback = s_aws_dns_resolver_impl_udp_shutdown,
        .user_data = resolver,
    };

    return aws_client_bootstrap_new_socket_channel(&channel_options);
}

static int s_encode_dns_fixed_header(struct aws_dns_query_internal *query, struct aws_byte_buf *data) {
    /*
     * Should be cryptographically unpredictable, but for now, just a counter
     */
    uint16_t transaction_id = query->channel->next_transaction_id++;
    query->transaction_id = transaction_id;
    if (!aws_byte_buf_write_be16(data, transaction_id)) {
        return AWS_OP_ERR;
    }

    /* all flags 0 except recursion desired */
    uint16_t flags = (1U << 8);
    if (!aws_byte_buf_write_be16(data, flags)) {
        return AWS_OP_ERR;
    }

    /* 1 question */
    if (!aws_byte_buf_write_be16(data, 1)) {
        return AWS_OP_ERR;
    }

    /* 0 answers */
    if (!aws_byte_buf_write_be16(data, 0)) {
        return AWS_OP_ERR;
    }

    /* 0 authority records */
    if (!aws_byte_buf_write_be16(data, 0)) {
        return AWS_OP_ERR;
    }

    /* 1 additional record (EDNS0 packet length control) */
    if (!aws_byte_buf_write_be16(data, 1)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_encode_name(struct aws_byte_buf *data, struct aws_byte_cursor name_cursor) {

    struct aws_byte_cursor label_cursor;
    AWS_ZERO_STRUCT(label_cursor);

    while (aws_byte_cursor_next_split(&name_cursor, '.', &label_cursor)) {
        if (label_cursor.len >= 64) {
            /* this needs to be fatal to the query */
            return AWS_OP_ERR;
        }

        uint8_t label_length = (uint8_t)label_cursor.len;
        if (!aws_byte_buf_write_u8(data, label_length)) {
            return AWS_OP_ERR;
        }

        if (aws_byte_buf_append(data, &label_cursor)) {
            return AWS_OP_ERR;
        }

        aws_byte_cursor_advance(&name_cursor, label_cursor.len + 1);
    }

    /* zero length terminator */
    if (!aws_byte_buf_write_u8(data, 0)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_encode_dns_question(struct aws_dns_query_internal *query, struct aws_byte_buf *data) {

    if (s_encode_name(data, aws_byte_cursor_from_string(query->name))) {
        return AWS_OP_ERR;
    }

    /* query type = query type enum value */
    if (!aws_byte_buf_write_be16(data, (uint16_t)query->query_type)) {
        return AWS_OP_ERR;
    }

    /* query class = Internet */
    if (!aws_byte_buf_write_be16(data, 1)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_encode_dns_extensions(struct aws_dns_query_internal *query, struct aws_byte_buf *data) {
    (void)query;

    /* NAME component, in this case just a terminator byte */
    if (!aws_byte_buf_write_u8(data, 0)) {
        return AWS_OP_ERR;
    }

    /* Type, in this case 41 for the Opt RR */
    if (!aws_byte_buf_write_be16(data, 41)) {
        return AWS_OP_ERR;
    }

    /* Requested payload size, 4096 for now, possibly adaptive later */
    if (!aws_byte_buf_write_be16(data, 4096)) {
        return AWS_OP_ERR;
    }

    /* TTL (extended RCODE and flags) (all 0) */
    if (!aws_byte_buf_write_be32(data, 0)) {
        return AWS_OP_ERR;
    }

    /* RDATA length (0) */
    if (!aws_byte_buf_write_be16(data, 0)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_encode_query(struct aws_dns_query_internal *query, struct aws_byte_buf *data) {
    if (s_encode_dns_fixed_header(query, data)) {
        return AWS_OP_ERR;
    }

    if (s_encode_dns_question(query, data)) {
        return AWS_OP_ERR;
    }

    if (s_encode_dns_extensions(query, data)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_send_query(struct aws_dns_query_internal *query) {

    /*
     *  (1) - NAME  (0)
     *  (2) - Type (41)
     *  (2) - Payload size (4096)
     *  (4) - TTL (extended RCODE and flags) (all 0)
     *  (2) - RDATA length (0 for us)
     *  (?) - RDATA (0)
     *
     *  So 1 + 2 + 2 + 4 + 2 = 11
     */
    const size_t extension_length = 11;

    /*
     * name length where '.' is replaced by length bytes
     * + 1 for final label's length
     * + 1 for terminal zero byte
     * + 4 for query type (2 bytes) and query class (2 bytes)
     */
    const size_t question_length = query->name->len + 2 + 4;

    const size_t fixed_header_length = 12;

    const size_t required_length = fixed_header_length + question_length + extension_length;

    struct aws_io_message *message = aws_channel_acquire_message_from_pool(
        query->channel->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, required_length);
    if (message == NULL) {
        return;
    }

    if (s_encode_query(query, &message->message_data)) {
        goto on_error;
    }

    if (aws_channel_slot_send_message(query->channel->slot, message, AWS_CHANNEL_DIR_WRITE)) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    query->state = AWS_DNS_QS_PENDING_RESPONSE;
    return;

on_error:

    aws_mem_release(message->allocator, message);
}

static void s_dns_resolver_driver(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_dns_resolver_udp_channel *resolver = arg;

    aws_mutex_lock(&resolver->lock);
    resolver->is_channel_driver_scheduled = false;
    aws_linked_list_swap_contents(&resolver->driver_queries, &resolver->out_of_thread_queries);
    aws_mutex_unlock(&resolver->lock);

    uint64_t now = 0;
    aws_channel_current_clock_time(resolver->slot->channel, &now);

    while (!aws_linked_list_empty(&resolver->driver_queries)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&resolver->driver_queries);
        struct aws_dns_query_internal *query = AWS_CONTAINER_OF(node, struct aws_dns_query_internal, node);
        query->state = AWS_DNS_QS_PENDING_REQUEST;
        s_link_query(query);

        uint32_t timeout_ms =
            query->options.timeout_millis > 0 ? query->options.timeout_millis : DEFAULT_TIMEOUT_INTERVAL_MS;

        query->timeout_ns = now + aws_timestamp_convert(timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
        aws_event_loop_schedule_task_future(resolver->loop, &query->timeout_task, query->timeout_ns);
        query->is_timeout_scheduled = true;
    }

    if (status == AWS_TASK_STATUS_CANCELED) {
        s_cancel_all_queries(resolver);
        return;
    }

    if (!aws_linked_list_empty(&resolver->pending_queries)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&resolver->pending_queries);
        struct aws_dns_query_internal *query = AWS_CONTAINER_OF(node, struct aws_dns_query_internal, node);

        s_send_query(query);
        s_link_query(query);
    }

    s_schedule_channel_driver_if_needed(resolver);
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
    resolver->loop = aws_event_loop_group_get_next_loop(options->bootstrap->event_loop_group);
    resolver->on_destroyed_callback = options->on_destroyed_callback;
    resolver->on_destroyed_user_data = options->on_destroyed_user_data;
    resolver->on_initial_connection_callback = options->on_initial_connection_callback;
    resolver->on_initial_connection_user_data = options->on_initial_connection_user_data;
    resolver->initial_connection_callback_completed = false;
    resolver->next_transaction_id = 0xabcd;

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

    aws_linked_list_init(&resolver->pending_queries);
    aws_linked_list_init(&resolver->outstanding_queries);
    aws_linked_list_init(&resolver->out_of_thread_queries);
    aws_linked_list_init(&resolver->driver_queries);

    aws_channel_task_init(&resolver->channel_driver_task, s_dns_resolver_driver, resolver, "dns_resolver_driver_task");

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
    struct aws_dns_query *query) {

    struct aws_dns_query_internal *internal_query = aws_dns_query_internal_new(resolver->allocator, query, resolver);
    if (internal_query == NULL) {
        return AWS_OP_ERR;
    }

    s_link_query(internal_query);

    return AWS_OP_SUCCESS;
}

static void s_dns_timeout_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_dns_query_internal *query = arg;

    query->is_timeout_scheduled = false;
    query->on_completed_callback(NULL, AWS_IO_DNS_QUERY_TIMEOUT, query->user_data);

    s_unlink_query(query);
    aws_dns_query_internal_destroy(query);
}

struct aws_dns_query_internal *aws_dns_query_internal_new(
    struct aws_allocator *allocator,
    struct aws_dns_query *query,
    struct aws_dns_resolver_udp_channel *channel) {

    struct aws_dns_query_internal *internal_query = aws_mem_calloc(allocator, 1, sizeof(struct aws_dns_query_internal));
    if (internal_query == NULL) {
        return NULL;
    }

    internal_query->allocator = allocator;
    internal_query->channel = channel;
    internal_query->state = AWS_DNS_QS_INITIALIZED;
    internal_query->timeout_ns = 0;

    aws_task_init(&internal_query->timeout_task, s_dns_timeout_task, internal_query, "dns_timeout_task");

    internal_query->name = aws_string_new_from_array(allocator, query->hostname.ptr, query->hostname.len);
    if (internal_query->name == NULL) {
        goto fail;
    }

    internal_query->query_type = query->query_type;
    if (query->options != NULL) {
        internal_query->options = *query->options;
    } else {
        internal_query->options.query_type = AWS_DNS_QUERY_RECURSIVE;
        internal_query->options.max_iterations = 1;
        internal_query->options.max_retries = 1;
        internal_query->options.retry_interval_in_millis = DEFAULT_RETRY_INTERVAL_MS;
        internal_query->options.timeout_millis = DEFAULT_TIMEOUT_INTERVAL_MS;
    }

    internal_query->on_completed_callback = query->on_completed_callback;
    internal_query->user_data = query->user_data;

    return internal_query;

fail:

    aws_dns_query_internal_destroy(internal_query);

    return NULL;
}

void aws_dns_query_internal_destroy(struct aws_dns_query_internal *query) {
    if (query == NULL) {
        return;
    }

    if (query->is_timeout_scheduled) {
        aws_event_loop_cancel_task(query->channel->loop, &query->timeout_task);

        query->is_timeout_scheduled = false;
        if (query->state != AWS_DNS_QS_COMPLETE) {
            query->on_completed_callback(NULL, AWS_IO_DNS_QUERY_INTERRUPTED, query->user_data);
        }
    }

    if (query->name != NULL) {
        aws_string_destroy(query->name);
        query->name = NULL;
    }

    aws_mem_release(query->allocator, query);
}

void aws_dns_resource_record_clean_up(struct aws_dns_resource_record *record) {
    aws_byte_buf_clean_up(&record->name);
    aws_byte_buf_clean_up(&record->data);
}

static void s_aws_dns_query_result_clean_up_resource_record_list(struct aws_array_list *records) {
    size_t record_count = aws_array_list_length(records);
    for (size_t i = 0; i < record_count; ++i) {
        struct aws_dns_resource_record *record_ptr = NULL;
        aws_array_list_get_at_ptr(records, (void **)&record_ptr, i);

        aws_dns_resource_record_clean_up(record_ptr);
    }

    aws_array_list_clean_up(records);
}

void aws_dns_query_result_clean_up(struct aws_dns_query_result *result) {
    if (result == NULL) {
        return;
    }

    s_aws_dns_query_result_clean_up_resource_record_list(&result->question_records);
    s_aws_dns_query_result_clean_up_resource_record_list(&result->answer_records);
    s_aws_dns_query_result_clean_up_resource_record_list(&result->authority_records);
    s_aws_dns_query_result_clean_up_resource_record_list(&result->additional_records);
}

#define AWS_DNS_OPCODE_MASK 0x0F
#define AWS_DNS_OPCODE_SHIFT 11
#define AWS_DNS_RESULT_CODE_MASK 0x0F

#define AWS_DNS_FIXED_HEADER_FLAG_QUERY (1U << 15)
#define AWS_DNS_FIXED_HEADER_FLAG_TRUNCATED (1U << 9)
#define AWS_DNS_FIXED_HEADER_FLAG_AUTHENTICATED (1U << 10)
#define AWS_DNS_FIXED_HEADER_FLAG_AUTHORITATIVE (1U << 5)
#define AWS_DNS_FIXED_HEADER_FLAG_RECURSION_DESIRED (1U << 8)
#define AWS_DNS_FIXED_HEADER_FLAG_RECURSION_AVAILABLE (1U << 7)

bool aws_dns_fixed_flags_is_truncated(uint16_t flags) {
    return (flags & AWS_DNS_FIXED_HEADER_FLAG_TRUNCATED) != 0;
}

bool aws_dns_fixed_flags_is_authenticated(uint16_t flags) {
    return (flags & AWS_DNS_FIXED_HEADER_FLAG_AUTHENTICATED) != 0;
}

bool aws_dns_fixed_flags_is_authoritative(uint16_t flags) {
    return (flags & AWS_DNS_FIXED_HEADER_FLAG_AUTHORITATIVE) != 0;
}

bool aws_dns_fixed_flags_is_recursion_desired(uint16_t flags) {
    return (flags & AWS_DNS_FIXED_HEADER_FLAG_RECURSION_DESIRED) != 0;
}

bool aws_dns_fixed_flags_is_recursion_available(uint16_t flags) {
    return (flags & AWS_DNS_FIXED_HEADER_FLAG_RECURSION_AVAILABLE) != 0;
}

bool aws_dns_fixed_flags_is_query(uint16_t flags) {
    return (flags & AWS_DNS_FIXED_HEADER_FLAG_QUERY) == 0;
}

enum aws_dns_flags_opcode_type aws_dns_fixed_flags_get_opcode(uint16_t flags) {
    uint16_t opcode = (flags >> AWS_DNS_OPCODE_SHIFT) & AWS_DNS_OPCODE_MASK;

    return (enum aws_dns_flags_opcode_type)opcode;
}

enum aws_dns_result_code_type aws_dns_fixed_flags_get_result_code(uint16_t flags) {
    uint16_t result_code = flags & AWS_DNS_RESULT_CODE_MASK;

    return (enum aws_dns_result_code_type)result_code;
}
