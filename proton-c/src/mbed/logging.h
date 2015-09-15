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

#ifndef LOGGING_H
#define LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

/* enable this to get basic info logging for the mbed port */
#define LOG_INFO_ENABLED
/* enable this to get detailed logging for the mbed port */
// #define LOG_VERBOSE_ENABLED
/* enable this to get the buffers spewed at various layers (SSL, socket, etc.) */
// #define LOG_BUFFERS_ENABLED
/* enable this to get each entry/exit logged for function calls */
// #define LOG_FUNC_CALLS_ENABLED

extern void mbed_log_init(void);
extern int mbed_log(const char*, ...);
extern void mbed_log_buffer(const void* data, int length);

#ifdef LOG_FUNC_CALLS_ENABLED
#define LOG_FUNC_START(name) mbed_log(name "- Start\r\n")
#define LOG_FUNC_END(name) mbed_log(name "- End\r\n")
#else /* LOG_FUNC_CALLS_ENABLED */
#define LOG_FUNC_START(name)
#define LOG_FUNC_END(name)
#endif

#ifdef LOG_INFO_ENABLED
#define LOG_INFO mbed_log
#else /* LOG_INFO_ENABLED */
#define LOG_INFO(...)
#endif /* LOG_INFO_ENABLED */

#ifdef LOG_VERBOSE_ENABLED
#define LOG_VERBOSE mbed_log
#else /* LOG_VERBOSE_ENABLED */
#define LOG_VERBOSE(...)
#endif /* LOG_VERBOSE_ENABLED */

#define LOG_ERROR mbed_log

#ifdef LOG_BUFFERS_ENABLED
#define LOG_BUFFER mbed_log_buffer
#else /* LOG_BUFFERS_ENABLED */
#define LOG_BUFFER(...)
#endif /* LOG_BUFFERS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* LOGGING_H */
