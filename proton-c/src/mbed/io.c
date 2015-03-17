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

#include <proton/io.h>
#include <proton/object.h>
#include <proton/selector.h>

#include "tcpsocketconnection_c.h"
#include "logging.h"

#include <ctype.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>

#include "platform.h"

#define MAX_HOST (1024)
#define MAX_SERV (64)

struct pn_io_t {
	char host[MAX_HOST];
	char serv[MAX_SERV];
	pn_error_t *error;
	pn_selector_t *selector;
	bool wouldblock;
};

void pn_io_initialize(void *obj)
{
	pn_io_t *io = (pn_io_t *)obj;
	io->error = pn_error();
	io->wouldblock = false;
	io->selector = NULL;
}

void pn_io_finalize(void *obj)
{
	pn_io_t *io = (pn_io_t *)obj;
	pn_error_free(io->error);
}

#define pn_io_hashcode NULL
#define pn_io_compare NULL
#define pn_io_inspect

pn_io_t *pn_io(void)
{
	static const pn_class_t clazz = PN_CLASS(pn_io);
	pn_io_t *io = (pn_io_t *)pn_class_new(&clazz, sizeof(pn_io_t));
	return io;
}

void pn_io_free(pn_io_t *io)
{
	pn_free(io);
}

pn_error_t *pn_io_error(pn_io_t *io)
{
	assert(io);
	return io->error;
}

int pn_pipe(pn_io_t *io, pn_socket_t *dest)
{
	return 0;
}

pn_socket_t pn_listen(pn_io_t *io, const char *host, const char *port)
{
	LOG_FUNC_START("pn_listen");

	/* server mode not implemented for mbed */
	LOG_ERROR("server mode not implemented for mbed\r\n");

	LOG_FUNC_END("pn_listen");

	return PN_INVALID_SOCKET;
}

pn_socket_t pn_connect(pn_io_t *io, const char *host, const char *port)
{
	int portInt;
	TCPSOCKETCONNECTION_HANDLE tcpConnectionHandle;

	LOG_FUNC_START("pn_connect");

	portInt = atoi(port);

	tcpConnectionHandle = tcpsocketconnection_create();
	if (tcpConnectionHandle == NULL)
	{
		return PN_INVALID_SOCKET;
	}

	if (tcpsocketconnection_connect(tcpConnectionHandle, host, portInt) != 0)
	{
		tcpsocketconnection_destroy(tcpConnectionHandle);
		return PN_INVALID_SOCKET;
	}

	LOG_FUNC_END("pn_connect");

	return (pn_socket_t)tcpConnectionHandle;
}

pn_socket_t pn_accept(pn_io_t *io, pn_socket_t socket, char *name, size_t size)
{
	LOG_FUNC_START("pn_accept");

	/* server mode not implemented for mbed */
	LOG_ERROR("server mode not implemented for mbed\r\n");

	LOG_FUNC_END("pn_accept");

	return PN_INVALID_SOCKET;
}

ssize_t pn_send(pn_io_t *io, pn_socket_t socket, const void *buf, size_t len)
{
	LOG_FUNC_START("pn_send");

	LOG_VERBOSE("pn_send, %d bytes, tcp handle = %p\r\n", (int)len, (void*)socket);
	ssize_t count = (ssize_t)tcpsocketconnection_send((TCPSOCKETCONNECTION_HANDLE)socket, (char*)buf, len);
	LOG_VERBOSE("pn_send, result = %d\r\n", (int)count);
	io->wouldblock = count < 0;

	LOG_FUNC_END("pn_send");

	return count;
}

ssize_t pn_recv(pn_io_t *io, pn_socket_t socket, void *buf, size_t size)
{
	LOG_FUNC_START("pn_recv");
	LOG_VERBOSE("Requested to receive %d bytes\r\n", (int)size);
	int count = 0;

	tcpsocketconnection_set_blocking((TCPSOCKETCONNECTION_HANDLE)socket, false, 1000);
	count = 0;
	while (1)
	{
		int res = tcpsocketconnection_receive((TCPSOCKETCONNECTION_HANDLE)socket, (char*)buf + count, 1);
		if (res <= 0)
		{
			break;
		}
		count++;
	}

	LOG_VERBOSE("received %d bytes\r\n", (int)count);
	io->wouldblock = count < 0;

	LOG_FUNC_END("pn_recv");
	return (count < 0) ? 0 : count;
}

ssize_t pn_write(pn_io_t *io, pn_socket_t socket, const void *buf, size_t size)
{
	ssize_t result;
	LOG_FUNC_START("pn_write");
	LOG_VERBOSE("pn_write, %d bytes\r\n", (int)size);
	result = (ssize_t)tcpsocketconnection_send((TCPSOCKETCONNECTION_HANDLE)socket, (char*)buf, size);
	LOG_FUNC_END("pn_write");
	return result;
}

ssize_t pn_read(pn_io_t *io, pn_socket_t socket, void *buf, size_t size)
{
	ssize_t result;
	LOG_FUNC_START("pn_read");
	LOG_VERBOSE("read %d bytes, socket = %p\r\n", (int)size, socket);
	result = pn_recv(io, socket, buf, size);
	LOG_FUNC_END("pn_read");
	return result;
}

void pn_close(pn_io_t *io, pn_socket_t socket)
{
	LOG_FUNC_START("pn_close");
	tcpsocketconnection_destroy((TCPSOCKETCONNECTION_HANDLE)socket);
	LOG_FUNC_END("pn_close");
}

bool pn_wouldblock(pn_io_t *io)
{
	return io->wouldblock;
}

pn_selector_t *pn_io_selector(pn_io_t *io)
{
	if (io->selector == NULL)
		io->selector = pni_selector();
	return io->selector;
}
