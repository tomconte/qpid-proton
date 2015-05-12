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
#include "mbedtime.h"
#include "Timer.h"
#include "logging.h"

static Timer timer;
static int millisecondsElapsed = 0;
static unsigned long oldValue = 0;
static unsigned long micros = 0;

extern "C" void mbedtime_init(void)
{
    timer.start();
    oldValue = timer.read_ms();
    micros = 0;
}

extern "C" void mbedtime_deinit(void)
{
    timer.stop();
}

extern "C" unsigned long mbedtime_gettickcount(void)
{
    unsigned long newValue = timer.read_ms();
    unsigned long deltaInMicros = (newValue - oldValue) + micros;
    millisecondsElapsed += deltaInMicros / 1000;
    micros = deltaInMicros % 1000;
    oldValue = newValue;
    return millisecondsElapsed;
}
