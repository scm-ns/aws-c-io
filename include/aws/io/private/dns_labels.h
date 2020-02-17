#ifndef AWS_IO_DNS_LABELS_H
#define AWS_IO_DNS_LABELS_H
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

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>


struct aws_dns_name;
struct aws_dns_label_tree;
struct aws_string;

struct aws_dns_label_tree_node {
    struct aws_string *label;
    struct aws_dns_label_tree_node *parent;
    void *data;
    struct aws_hash_table children;
};

typedef int (aws_dns_label_tree_node_visitor_callback_fn)(struct aws_dns_label_tree *label_tree, struct aws_dns_label_tree_node *node, void *user_data);

AWS_EXTERN_C_BEGIN

/* aws_dns_name */
AWS_IO_API
struct aws_dns_name *aws_dns_name_new(struct aws_allocator *allocator, struct aws_byte_cursor name_cursor);

AWS_IO_API
void aws_dns_name_destroy(stuct aws_dns_name *name);

AWS_IO_API
int aws_dns_name_get_label_cursor(struct aws_nds_name *name, size_t label_index, struct aws_byte_cursor *label_cursor_out);

AWS_IO_API
size_t aws_dns_name_get_label_cursor_count(struct aws_nds_name *name);


/* aws_dns_labe_tree */
AWS_IO_API
struct aws_dns_label_tree *aws_dns_label_tree_new(struct aws_allocator *allocator);

AWS_IO_API
struct aws_dns_label_tree *aws_dns_label_tree_destroy(struct aws_dns_label_tree *label_tree);

AWS_IO_API
int aws_dns_label_tree_new_node(struct aws_dns_label_tree *label_tree, struct aws_dns_label_tree_node *parent, struct aws_byte_cursor child_label, void *node_data);

AWS_IO_API
int aws_dns_label_tree_delete_subtree(struct aws_dns_label_tree *label_tree, struct aws_dns_label_tree_node *subtree_root);

AWS_IO_API
struct aws_dns_label_tree_node *aws_dns_label_tree_get_root(struct aws_dns_label_tree *label_tree);

AWS_IO_API
struct aws_dns_label_tree_node *aws_dns_label_tree_find(struct aws_dns_label_tree *label_tree, struct aws_dns_name *name, size_t name_label_index);

AWS_IO_API
void aws_dns_label_tree_visit_ancestors(struct aws_dns_label_tree *label_tree, struct aws_dns_name *name, aws_dns_label_tree_node_visitor_callback_fn *vistor, void *user_data);

AWS_IO_API
void aws_dns_label_tree_visit_all(struct aws_dns_label_tree *label_tree, aws_dns_label_tree_node_visitor_callback_fn *vistor, void *user_data);

AWS_IO_API
void aws_dns_label_tree_visit_subtree(struct aws_dns_label_tree *label_tree, struct aws_dns_label_tree_node *node, aws_dns_label_tree_node_visitor_callback_fn *vistor, void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_LABELS_H */
