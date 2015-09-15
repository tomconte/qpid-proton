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
#include <stdbool.h>

#include "platform.h"

#define RECV_TIMEOUT_IN_MS	1000 /* ms */

struct pn_io_t {
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
	(void)io;
	(void)dest;

	/* For MBED TcpSocketConnection IO we shall not use a pipe at all, due to the fact
	that the person writing this comment does not clearly understand from the existing docs
	what this function should do. Thus a decision was made to have a very rough shortcut here. */
	return 0;
}

pn_socket_t pn_listen(pn_io_t *io, const char *host, const char *port)
{
	(void)io;
	(void)host;
	(void)port;

	LOG_FUNC_START("pn_listen");

	/* server mode not implemented for mbed */
	LOG_ERROR("server mode not implemented for mbed\r\n");

	LOG_FUNC_END("pn_listen");

	return PN_INVALID_SOCKET;
}

pn_socket_t pn_connect(pn_io_t *io, const char *host, const char *port)
{
	int portInt;
	pn_socket_t result;

	LOG_FUNC_START("pn_connect");

	if ((io == NULL) || (port == NULL) || (host == NULL))
	{
		LOG_ERROR("NULL argument, io=%p, host=%p, port=%p\r\n", io, host, port);
		result = PN_INVALID_SOCKET;
	}
	else
	{
		TCPSOCKETCONNECTION_HANDLE tcpConnectionHandle;
		portInt = atoi(port);

		tcpConnectionHandle = tcpsocketconnection_create();
		if (tcpConnectionHandle == NULL)
		{
			LOG_ERROR("Cannot create socket\r\n");
			result = PN_INVALID_SOCKET;
		}
		else
		{
			if (tcpsocketconnection_connect(tcpConnectionHandle, host, portInt) != 0)
			{
				tcpsocketconnection_destroy(tcpConnectionHandle);
				result = PN_INVALID_SOCKET;
				LOG_ERROR("Cannot connect socket\r\n");
			}
			else
			{
				result = (pn_socket_t)tcpConnectionHandle;
			}
		}
	}

	LOG_FUNC_END("pn_connect");

	return result;
}

pn_socket_t pn_accept(pn_io_t *io, pn_socket_t socket, char *name, size_t size)
{
	(void)io;
	(void)socket;
	(void)name;
	(void)size;

	LOG_FUNC_START("pn_accept");

	/* server mode not implemented for mbed */
	LOG_ERROR("server mode not implemented for mbed\r\n");

	LOG_FUNC_END("pn_accept");

	return PN_INVALID_SOCKET;
}

ssize_t pn_send(pn_io_t *io, pn_socket_t socket, const void *buf, size_t len)
{
	ssize_t count;

	LOG_FUNC_START("pn_send");
	if ((io == NULL) || (socket == NULL) || (buf == NULL))
	{
		LOG_ERROR("NULL argument, io=%p, socket=%p, buf=%p\r\n", io, socket, buf);
		count = -1;
	}
	else
	{
		LOG_VERBOSE("pn_send, %d bytes, tcp handle = %p\r\n", (int)len, (void*)socket);
		count = (ssize_t)tcpsocketconnection_send((TCPSOCKETCONNECTION_HANDLE)socket, (char*)buf, len);
		LOG_VERBOSE("pn_send, result = %d\r\n", (int)count);
		io->wouldblock = count < 0;
	}

	LOG_FUNC_END("pn_send");

	return count;
}

ssize_t pn_recv(pn_io_t *io, pn_socket_t socket, void *buf, size_t size)
{
	ssize_t count;

	LOG_FUNC_START("pn_recv");

	if ((io == NULL) || (socket == NULL) || (buf == NULL))
	{
		LOG_ERROR("NULL argument, io=%p, socket=%p, buf=%p\r\n", io, socket, buf);
		count = -1;
	}
	else
	{
		LOG_VERBOSE("Requested to receive %d bytes\r\n", (int)size);

		tcpsocketconnection_set_blocking((TCPSOCKETCONNECTION_HANDLE)socket, false, RECV_TIMEOUT_IN_MS);
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
		io->wouldblock = (count == 0);
	}

	LOG_FUNC_END("pn_recv");

	return (count == 0) ? -1 : count;
}

ssize_t pn_write(pn_io_t *io, pn_socket_t socket, const void *buf, size_t size)
{
	ssize_t result;
	LOG_FUNC_START("pn_write");

	if ((io == NULL) || (socket == NULL) || (buf == NULL))
	{
		LOG_ERROR("NULL argument, io=%p, socket=%p, buf=%p\r\n", io, socket, buf);
		result = -1;
	}
	else
	{
		LOG_VERBOSE("pn_write, %d bytes\r\n", (int)size);
		result = (ssize_t)tcpsocketconnection_send((TCPSOCKETCONNECTION_HANDLE)socket, (char*)buf, size);
	}

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
	if ((io == NULL) || (socket == PN_INVALID_SOCKET))
	{
		LOG_ERROR("NULL argument, io=%p, socket=%p\r\n", io, socket);
	}
	else
	{
		tcpsocketconnection_destroy((TCPSOCKETCONNECTION_HANDLE)socket);
	}

	LOG_FUNC_END("pn_close");
}

bool pn_wouldblock(pn_io_t *io)
{
	bool result;

	if (io == NULL)
	{
		LOG_ERROR("NULL argument, io=%p\r\n", io);
		result = false;
	}
	else
	{
		result = io->wouldblock;
	}

	return result;
}

pn_selector_t* pn_io_selector(pn_io_t *io)
{
	pn_selector_t* result;

	if (io == NULL)
	{
		LOG_ERROR("NULL argument, io=%p\r\n", io);
		result = NULL;
	}
	else
	{
		if (io->selector == NULL)
		{
			io->selector = pni_selector();
		}

		result = io->selector;
	}

	return result;
}
