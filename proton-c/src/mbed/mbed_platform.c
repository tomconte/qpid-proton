/*
*
* Licensed to the Apache Software Foundation (ASF) under one
* or more contributor license agreements.  See the NOTICE file
* distributed with this work for additional information
* regarding copyright ownership.  The ASF licenses this file
* to you under the Apache License, Version 2.0 (the
* "License"); you may not use this file except in compliance
* with the License.  You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "mbedtime.h"
#include "platform.h"

pn_timestamp_t pn_i_now(void)
{
	return mbedtime_gettickcount();
}

char* pn_i_genuuid(void)
{
	return NULL;
}

int pn_i_error_from_errno(pn_error_t *error, const char *msg)
{
	int code = PN_ERR;
	return pn_error_format(error, code, "%s: %s", msg, strerror(errno));
}

int64_t pn_i_atoll(const char* num)
{
	return atoll(num);
}
