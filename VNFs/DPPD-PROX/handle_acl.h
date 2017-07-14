/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef _HANDLE_ACL_H_
#define _HANDLE_ACL_H_

#include <rte_acl.h>

struct acl4_rule {
	struct rte_acl_rule_data data;
	struct rte_acl_field fields[9];
};

int str_to_rule(struct acl4_rule *rule, char** fields, int n_rules, int use_qinq);

#endif /* _HANDLE_ACL_H_ */
