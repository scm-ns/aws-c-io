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

#include <aws/io/dns.h>

#define MAX_LABEL_LENGTH 63

static int s_decode_name(
    struct aws_byte_buf *buf,
    struct aws_byte_cursor whole_packet_cursor,
    struct aws_byte_cursor *response_packet_cursor) {

    struct aws_byte_cursor compression_dummy;
    AWS_ZERO_STRUCT(compression_dummy);

    struct aws_byte_cursor *name_cursor = response_packet_cursor;

    uint8_t label_length = 0;
    if (!aws_byte_cursor_read_u8(name_cursor, &label_length)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor dot_cursor = aws_byte_cursor_from_c_str(".");

    while (label_length > 0) {
        if ((label_length & 0xC0) == 0xC0) {
            /* compression label */
            uint8_t lower_length = 0;
            if (!aws_byte_cursor_read_u8(name_cursor, &lower_length)) {
                return AWS_OP_ERR;
            }

            uint16_t offset = (uint16_t)(label_length & 0x3F);
            offset <<= 8;
            offset |= (uint16_t)lower_length;

            if (offset >= whole_packet_cursor.len) {
                return AWS_OP_ERR;
            }

            /*
             * compression labels are essentially a "goto" within the packet.  So the safest thing to do is just
             * start fresh at the reference position.
             */
            compression_dummy = whole_packet_cursor;
            aws_byte_cursor_advance(&compression_dummy, offset + 1);
            label_length = whole_packet_cursor.ptr[offset];
            name_cursor = &compression_dummy;
            continue;
        }

        if (label_length > name_cursor->len || label_length > MAX_LABEL_LENGTH) {
            return AWS_OP_ERR;
        }

        struct aws_byte_cursor label_cursor = *name_cursor;
        label_cursor.len = label_length;

        if (aws_byte_buf_append_dynamic(buf, &label_cursor)) {
            return AWS_OP_ERR;
        }

        aws_byte_cursor_advance(name_cursor, label_length);

        if (!aws_byte_cursor_read_u8(name_cursor, &label_length)) {
            return AWS_OP_ERR;
        }

        if (label_length > 0) {
            if (aws_byte_buf_append_dynamic(buf, &dot_cursor)) {
                return AWS_OP_ERR;
            }
        }
    }

    return AWS_OP_SUCCESS;
}

#define DEFAULT_NAME_SIZE 64

static bool s_is_name_data_record(enum aws_dns_resource_record_type record_type) {
    return record_type == AWS_DNS_RR_CNAME || record_type == AWS_DNS_RR_DNAME || record_type == AWS_DNS_RR_NS;
}

static int s_decode_resource_record(
    struct aws_byte_cursor whole_packet_cursor,
    struct aws_byte_cursor *response_packet_cursor,
    struct aws_allocator *allocator,
    struct aws_dns_resource_record *record,
    bool is_question) {

    if (aws_byte_buf_init(&record->name, allocator, DEFAULT_NAME_SIZE)) {
        return AWS_OP_ERR;
    }

    if (s_decode_name(&record->name, whole_packet_cursor, response_packet_cursor)) {
        return AWS_OP_ERR;
    }

    uint16_t record_type = 0;
    if (!aws_byte_cursor_read_be16(response_packet_cursor, &record_type)) {
        return AWS_OP_ERR;
    }

    record->type = (enum aws_dns_resource_record_type)record_type;

    uint16_t class = 0;
    if (!aws_byte_cursor_read_be16(response_packet_cursor, &class)) {
        goto on_error;
    }

    if (is_question) {
        return AWS_OP_SUCCESS;
    }

    if (!aws_byte_cursor_read_be32(response_packet_cursor, &record->ttl)) {
        goto on_error;
    }

    uint16_t data_length = 0;
    if (!aws_byte_cursor_read_be16(response_packet_cursor, &data_length)) {
        goto on_error;
    }

    if (response_packet_cursor->len < data_length) {
        goto on_error;
    }

    if (aws_byte_buf_init(&record->data, allocator, data_length)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor record_data_cursor = *response_packet_cursor;
    record_data_cursor.len = data_length;

    if (s_is_name_data_record(record_type)) {
        if (s_decode_name(&record->data, whole_packet_cursor, &record_data_cursor)) {
            return AWS_OP_ERR;
        }
    } else {
        if (aws_byte_buf_append(&record->data, &record_data_cursor)) {
            return AWS_OP_ERR;
        }
    }

    aws_byte_cursor_advance(response_packet_cursor, data_length);

    return AWS_OP_SUCCESS;

on_error:

    aws_dns_resource_record_clean_up(record);

    return AWS_OP_ERR;
}

static int s_decode_resource_record_list(
    struct aws_byte_cursor whole_packet_cursor,
    struct aws_byte_cursor *response_packet_cursor,
    struct aws_allocator *allocator,
    struct aws_array_list *records,
    uint16_t record_count,
    bool is_question) {

    if (record_count == 0) {
        return AWS_OP_SUCCESS;
    }

    if (aws_array_list_init_dynamic(records, allocator, record_count, sizeof(struct aws_dns_resource_record))) {
        return AWS_OP_ERR;
    }

    for (size_t i = 0; i < record_count; ++i) {
        struct aws_dns_resource_record record;
        AWS_ZERO_STRUCT(record);

        if (s_decode_resource_record(whole_packet_cursor, response_packet_cursor, allocator, &record, is_question)) {
            return AWS_OP_ERR;
        }

        aws_array_list_set_at(records, &record, i);
    }

    return AWS_OP_SUCCESS;
}

/* assumes result is zeroed and not actually initialized, allocates records on demand */
int aws_dns_decode_response(
    struct aws_dns_query_result *result,
    struct aws_allocator *allocator,
    struct aws_byte_cursor response_packet_cursor) {

    struct aws_byte_cursor whole_packet_cursor = response_packet_cursor;

    if (!aws_byte_cursor_read_be16(&response_packet_cursor, &result->transaction_id)) {
        return AWS_OP_ERR;
    }

    if (!aws_byte_cursor_read_be16(&response_packet_cursor, &result->fixed_header_flags)) {
        return AWS_OP_ERR;
    }

    /* only responses */
    if (aws_dns_fixed_flags_is_query(result->fixed_header_flags)) {
        return AWS_OP_ERR;
    }

    /* only QUERY opcode */
    if (aws_dns_fixed_flags_get_opcode(result->fixed_header_flags) != AWS_DNS_FOT_QUERY) {
        return AWS_OP_ERR;
    }

    /* no way to handle this right now */
    if (aws_dns_fixed_flags_is_truncated(result->fixed_header_flags)) {
        return AWS_OP_ERR;
    }

    uint16_t question_count = 0;
    if (!aws_byte_cursor_read_be16(&response_packet_cursor, &question_count)) {
        return AWS_OP_ERR;
    }

    uint16_t answer_count = 0;
    if (!aws_byte_cursor_read_be16(&response_packet_cursor, &answer_count)) {
        return AWS_OP_ERR;
    }

    uint16_t authority_count = 0;
    if (!aws_byte_cursor_read_be16(&response_packet_cursor, &authority_count)) {
        return AWS_OP_ERR;
    }

    uint16_t additional_count = 0;
    if (!aws_byte_cursor_read_be16(&response_packet_cursor, &additional_count)) {
        return AWS_OP_ERR;
    }

    if (s_decode_resource_record_list(
            whole_packet_cursor, &response_packet_cursor, allocator, &result->question_records, question_count, true)) {
        return AWS_OP_ERR;
    }

    if (s_decode_resource_record_list(
            whole_packet_cursor, &response_packet_cursor, allocator, &result->answer_records, answer_count, false)) {
        return AWS_OP_ERR;
    }

    if (s_decode_resource_record_list(
            whole_packet_cursor,
            &response_packet_cursor,
            allocator,
            &result->authority_records,
            authority_count,
            false)) {
        return AWS_OP_ERR;
    }

    if (s_decode_resource_record_list(
            whole_packet_cursor,
            &response_packet_cursor,
            allocator,
            &result->additional_records,
            additional_count,
            false)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
