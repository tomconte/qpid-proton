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

#include "mbed.h"
#include "logging.h"
#include <stdarg.h>
#include <stdio.h>

Serial pc(USBTX, USBRX);

extern "C" void mbed_log_init(void)
{
	pc.baud(115200);
}

extern "C" int mbed_log(const char* format, ...)
{
	char logLine[256];
	int result;

	va_list args;
	va_start(args, format);
	result = vsprintf(logLine, format, args);
	pc.printf(logLine);
	va_end(args);

	return result;
}

extern "C" void mbed_log_buffer(const void* data, int length)
{
	int i;

	for (i = 0; i < length; i++)
	{
		mbed_log("%02x ", ((unsigned char*)data)[i]);
	}
}
