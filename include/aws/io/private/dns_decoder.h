#ifndef AWS_IO_DNS_DECODER_H
#define AWS_IO_DNS_DECODER_H
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

struct aws_dns_query_result;
struct aws_dns_decoder;

struct aws_dns_decoder_vtable {
    int (*decode)(struct aws_dns_decoder *, struct aws_byte_cursor response_data);
    void (*destroy)(struct aws_dns_decoder *);
};

typedef void(on_response_callback_fn)(struct aws_dns_query_result *response, int error_code, void *user_data);

struct aws_dns_decoder_options {
    on_response_callback_fn *on_response_callback;
    void *on_response_callback_user_data;
};

struct aws_dns_decoder {
    struct aws_allocator *allocator;
    struct aws_dns_decoder_vtable *vtable;
    void *impl;

    struct aws_dns_decoder_options options;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_dns_decoder *aws_dns_decoder_new_standard(
    struct aws_allocator *allocator,
    struct aws_dns_decoder_options *options);

AWS_IO_API
void aws_dns_decoder_destroy(struct aws_dns_decoder *decoder);

AWS_IO_API
int aws_dns_decoder_decode(struct aws_dns_decoder *decoder, struct aws_byte_cursor response_data);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_DECODER_H */
