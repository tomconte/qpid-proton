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

#include <cstdint>
#include "mbed.h"
#include "mbedtime.h"
#include "Timer.h"

static Timer timer;
static int64_t millisecondsElapsed = 0;
static unsigned long oldTimerValue = 0;
static unsigned long carryOverMicros = 0;

extern "C" void mbedtime_init(void)
{
    timer.start();
    oldTimerValue = timer.read_ms();
    carryOverMicros = 0;
    millisecondsElapsed = 0;
}

extern "C" void mbedtime_deinit(void)
{
    timer.stop();
}

extern "C" int64_t mbedtime_gettickcount(void)
{
    /* first we get the new value of the timer (the timer value is in carryOverMicroseconds). */
    unsigned long newTimerValue = timer.read_ms();

    /* next we compute how many carryOverMicros have elapsed since the last time we took a timer snapshot and we add the leftover
    carryOverMicroseconds from the last time we ran this computation. */
    unsigned long deltaInMicros = (newTimerValue - oldTimerValue) + carryOverMicros;

    /* next we see how many milliseconds have elapsed and add them to our global milliseconds value that
    we give back to Proton. */
    millisecondsElapsed += deltaInMicros / 1000;

    /* and finally we store the extra carryOverMicroseconds and we mark the current timer snapshot as being the last timer snapshot. */
    carryOverMicros = deltaInMicros % 1000;
    oldTimerValue = newTimerValue;

    return millisecondsElapsed;
}
