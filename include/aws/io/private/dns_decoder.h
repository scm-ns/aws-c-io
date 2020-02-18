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

AWS_EXTERN_C_BEGIN

/* non-streaming since we're only doing UDP atm */
AWS_IO_API
int aws_dns_decode_response(struct aws_dns_query_result *result, struct aws_allocator *allocator, struct aws_byte_cursor response_packet_cursor);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_DECODER_H */
