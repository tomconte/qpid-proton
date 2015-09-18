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

#include <proton/ssl.h>
#include <proton/error.h>
#include <proton/transport.h>
#include <engine/engine-internal.h>
#include "platform.h"
#include "mbed/tcpsocketconnection_c.h"
#include "mbed/logging.h"
#include "wolfssl/ssl.h"
#include "util.h"

//#define WOLFSSL_DEBUG

#define APP_BUF_SIZE    (4096)

static bool sslDomainInitialized = false;

/*------------------------------------------------------------------------------
-- types
------------------------------------------------------------------------------*/

typedef struct pn_ssl_session_t pn_ssl_session_t;

// A top-level object that stores the configuration used by one or more SSL sessions
struct pn_ssl_domain_t {
    int   ref_count;
    pn_ssl_mode_t mode;
    const char* trusted_CAs;
};

typedef struct pn_ssl_t pn_ssl_t;

// A per-connection SSL session object that performs the encryption/authentication associated with the transport (pn_ssl_t).
struct pn_ssl_t {
    pn_ssl_domain_t  *domain;
    char *peer_hostname;

    struct WOLFSSL_CTX* ctx;
    struct WOLFSSL    * ssl;

    /* This buffer is holding crypted data produced by the wolfSSL library */
    unsigned char inputBuffer[APP_BUF_SIZE];
    unsigned char outputBuffer[APP_BUF_SIZE];
    unsigned char decrypted[APP_BUF_SIZE];
    size_t outBytes;
    size_t inBytes;
    size_t appBytesPos;

    pn_trace_t trace;

    bool handshakeDone;
};

extern TCPSOCKETCONNECTION_HANDLE connHandle;

static int SocketReceive(WOLFSSL* wolfssl, char *buf, int sz, void* ctx)
{
    int n = 0;
    int i;
    pn_ssl_t* pnssl = (pn_ssl_t*)ctx;

    mbed_log("wolfssl=%p, ctx=%p, sz=%d, inBytes=%d\r\n", wolfssl, ctx, sz, pnssl->inBytes);
    LOG_FUNC_START("SocketReceive");
    LOG_VERBOSE("ctx=%p, sz=%d, inBytes=%d\r\n", ctx, sz, pnssl->inBytes);

    if (pnssl->handshakeDone == false)
    {
        /* retry 3 times getting data */
        for (i = 0; i < 3; i++)
        {
            n = tcpsocketconnection_receive(connHandle, buf, sz);
            if (n > 0)
            {
                break;
            }
        }
    }
    else
    {
        if (sz > pnssl->inBytes)
        {
            n = pnssl->inBytes;
        }
        else
        {
            n = sz;
        }
        memcpy(buf, pnssl->inputBuffer, n);
        if (pnssl->inBytes > n)
        {
            memmove(pnssl->inputBuffer, pnssl->inputBuffer + n, pnssl->inBytes - n);
        }
        pnssl->inBytes -= n;

        if (n == 0)
        {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
    }

    LOG_VERBOSE("SocketReceive: returned = %d/ requested = %d\r\n", n, sz);
    LOG_FUNC_END("SocketReceive");
    return n;
}

static int SocketSend(WOLFSSL* wolfssl, char *buf, int sz, void* ctx)
{
    int n;
    pn_ssl_t* pnssl = (pn_ssl_t*)ctx;

    LOG_FUNC_START("SocketSend");
    LOG_VERBOSE("ctx=%p\r\n", ctx);

    if (pnssl->handshakeDone == true)
    {
        LOG_VERBOSE("Copying %d bytes\r\n", sz);

        /* here we put all the out bytes in a buffer to be returned to Proton so that they get
        sent on the underlying socket */
        memcpy(pnssl->outputBuffer + pnssl->outBytes, buf, sz);
        pnssl->outBytes += sz;
        n = sz;
    }
    else
    {
        n = tcpsocketconnection_send(connHandle, buf, sz);
        if (n > 0)
        {
            LOG_VERBOSE("Sent %d bytes\r\n", n);
        }
        else
        {
            LOG_ERROR("SocketSend:%d/%d\n", n, sz);
        }
    }

    LOG_FUNC_END("SocketSend");
    return n;
}

/*------------------------------------------------------------------------------
-- pn_ssl
--
--  Create a new pn_ssl instance. Allocates any needed buffers.
------------------------------------------------------------------------------*/
pn_ssl_t *pn_ssl(pn_transport_t *transport)
{
    LOG_FUNC_START("pn_ssl");

    if (transport == NULL)
    {
        return NULL;
    }

    if (transport->ssl)
    {
        return (pn_ssl_t *)transport->ssl;
    }

    LOG_VERBOSE("SSL:       pn_ssl \n\r");

    pn_ssl_t *ssl = (pn_ssl_t *)malloc(sizeof(pn_ssl_t));
    if (ssl == NULL)
    {
        LOG_VERBOSE("pn_ssl -> MALLOC is NULL -> FAIL !\n");
    }
    else
    {
        ssl->handshakeDone = false;
        ssl->inBytes = 0;
        ssl->outBytes = 0;
        ssl->appBytesPos = 0;
        ssl->ssl = NULL;
        ssl->ctx = NULL;
        ssl->peer_hostname = NULL;
        ssl->trace = NULL;
        ssl->domain = NULL;

        transport->ssl = (pni_ssl_t*)ssl;
        LOG_VERBOSE("returning %p\r\n", ssl);
    }

    LOG_FUNC_END("pn_ssl");

    return ssl;
}

/*------------------------------------------------------------------------------
-- pn_ssl_init
--
--  Initialize an SSL session.
--  Configures an SSL object using the configuration provided by the given domain.
--  Inputs:
--    ssl - Ptr to the ssl session to configured
--    domain - Ptr to the ssl domain used to configure the SSL session.
--    session_id  - if supplied, attempt to resume a previous SSL session, or NULL
--  Returns:  0 if OK, else -1 if error
------------------------------------------------------------------------------*/
int pn_ssl_init(pn_ssl_t* ssl, pn_ssl_domain_t* domain, const char* session_id)
{
    WOLFSSL_METHOD* SSLmethod;

    LOG_FUNC_START("pn_ssl_init");

    if (!ssl || !domain || ssl->domain)
    {
        LOG_ERROR("AMQP:                       pn_ssl_init() error, objects not intialized, ssl=%p, domain=%p, ssl->domain=%p \n\r", ssl, domain, ssl->domain);
        return -1;
    }

#ifdef WOLFSSL_DEBUG
    wolfSSL_Debugging_ON();
#endif

    ssl->domain = domain;
    domain->ref_count++;

    if (session_id && domain->mode == PN_SSL_MODE_CLIENT)
    {
        LOG_INFO("Not supporting resume, reinitializing...\r\n");
    }

    SSLmethod = wolfTLSv1_client_method();
    ssl->ctx = wolfSSL_CTX_new((WOLFSSL_METHOD *)SSLmethod);

    if (ssl->ctx == NULL)
    {
        LOG_ERROR("unable to get ctx\r\n");
        return -1;
    }

    if (wolfSSL_CTX_load_verify_buffer(ssl->ctx, (unsigned char*)domain->trusted_CAs, strlen(domain->trusted_CAs) + 1, SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        LOG_ERROR("unable to load certs\r\n");
        return -1;
    }

    wolfSSL_SetIORecv(ssl->ctx, SocketReceive);
    wolfSSL_SetIOSend(ssl->ctx, SocketSend);

    if (ssl->ssl == NULL)
    {
        ssl->ssl = wolfSSL_new(ssl->ctx);
        if (ssl->ssl == NULL)
        {
            LOG_ERROR("unable to get SSL object");
            wolfSSL_CTX_free(ssl->ctx);
            wolfSSL_Cleanup();
            return -1;
        }
    }

    wolfSSL_SetIOReadCtx(ssl->ssl, ssl);
    wolfSSL_SetIOWriteCtx(ssl->ssl, ssl);

    LOG_VERBOSE("ctx=%p, ssl=%p, ssl->ctx->CBIORecv, CBIOSend=%p, %p\n",
        ssl->ctx, ssl->ssl, SocketReceive, SocketSend);
    if (wolfSSL_connect(ssl->ssl) != SSL_SUCCESS)
    {
        LOG_ERROR("SSL_connect failed");
        wolfSSL_free(ssl->ssl);
        wolfSSL_CTX_free(ssl->ctx);
        wolfSSL_Cleanup();
        return -1;
    }

    ssl->handshakeDone = true;
    LOG_FUNC_END("pn_ssl_init");

    return 0;
}

void pn_ssl_free(pn_ssl_t *ssl)
{
    LOG_FUNC_START("pn_ssl_free");

    if (ssl->domain) pn_ssl_domain_free(ssl->domain);
    if (ssl->peer_hostname) free(ssl->peer_hostname);
    free(ssl);

    LOG_FUNC_END("pn_ssl_free");
}

void pn_ssl_trace(pn_ssl_t *ssl, pn_trace_t trace)
{
    LOG_FUNC_START("pn_ssl_trace");
    ssl->trace = trace;
    LOG_FUNC_END("pn_ssl_trace");
}

ssize_t pn_ssl_input(struct pn_transport_t *transport, unsigned int layer, const char *input_data, size_t len)
{
    bool moreSSLData;
    ssize_t app_bytes_consumed = 0;
    pn_ssl_t* ssl = (pn_ssl_t*)transport->ssl;

    LOG_FUNC_START("pn_ssl_input");
    LOG_VERBOSE("ssl_input got %d bytes as input\r\n", (int)len);
    if (len > APP_BUF_SIZE - ssl->inBytes)
    {
        len = APP_BUF_SIZE - ssl->inBytes;
        LOG_VERBOSE("ssl_input len set to %d\r\n", (int)len);
    }

    memcpy(ssl->inputBuffer + ssl->inBytes, input_data, len);
    ssl->inBytes += len;

    moreSSLData = true;
    while (moreSSLData)
    {
        while (true)
        {
            int toRead = wolfSSL_peek(ssl->ssl, ssl->decrypted + ssl->appBytesPos, 1);
            if (toRead + ssl->appBytesPos > APP_BUF_SIZE)
            {
                LOG_VERBOSE("overrun, ssl->appBytesPos = %d\r\n", (int)ssl->appBytesPos);
                break;
            }
            else if (toRead <= 0)
            {
                moreSSLData = false;
                break;
            }
            else
            {
                int res = wolfSSL_read(ssl->ssl, ssl->decrypted + ssl->appBytesPos, 1);
                LOG_VERBOSE("decrypt result=%d\r\n", res);
                if (res > 0)
                {
                    ssl->appBytesPos += res;
                }
                else
                {
                    moreSSLData = false;
                    break;
                }
            }
        }

        while (ssl->appBytesPos > 0)
        {
            LOG_VERBOSE("App gets %d bytes:\r\n", (int)ssl->appBytesPos);
            LOG_VERBOSE("Bytes not used: %d bytes:\r\n", (int)ssl->inBytes);
            LOG_BUFFER(decrypted, appBytesPos);

            app_bytes_consumed = transport->io_layers[layer + 1]->process_input(transport, layer + 1, (const char*)ssl->decrypted, ssl->appBytesPos);
            LOG_VERBOSE("App consumed bytes %d\r\n", (int)app_bytes_consumed);
            if (app_bytes_consumed < 0)
            {
                ssl->appBytesPos = 0;
            }
            else
            {
                if ((ssl->appBytesPos - app_bytes_consumed) > 0)
                {
                    memmove(ssl->decrypted, ssl->decrypted + app_bytes_consumed, ssl->appBytesPos - app_bytes_consumed);
                }
                ssl->appBytesPos -= app_bytes_consumed;
            }

            if (app_bytes_consumed <= 0)
            {
                break;
            }
        }
    }

    LOG_FUNC_END("pn_ssl_input");
    return len;
}

ssize_t pn_ssl_output(struct pn_transport_t *transport, unsigned int layer, char *output_data, size_t len)
{
    pn_ssl_t* ssl = (pn_ssl_t*)transport->ssl;
    LOG_FUNC_START("pn_ssl_output");

    ssize_t app_bytes = transport->io_layers[layer + 1]->process_output(transport, layer + 1, output_data, len);
    if (app_bytes > 0)
    {
        LOG_VERBOSE("Got %d bytes from upper layer\r\n", (int)app_bytes);
        int encryptedBytes = wolfSSL_write(ssl->ssl, output_data, app_bytes);
        LOG_VERBOSE("Got %d encrypted bytes\r\n", (int)encryptedBytes);
        memcpy(output_data, ssl->outputBuffer, ssl->outBytes);
        len = ssl->outBytes;
        ssl->outBytes = 0;
    }
    else
    {
        len = 0;
    }

    LOG_FUNC_END("pn_ssl_output");

    return len;
}

const pn_io_layer_t ssl_layer = {
    pn_ssl_input,
    pn_ssl_output,
    NULL,
    NULL
};

bool pn_ssl_get_cipher_name(pn_ssl_t *ssl, char *buffer, size_t size)
{
    LOG_FUNC_START("pn_ssl_get_cipher_name");
    if (buffer)
    {
        /* not needed ... yet */
        *buffer = '\0';
    }
    LOG_FUNC_END("pn_ssl_get_cipher_name");
    return false;
}

bool pn_ssl_get_protocol_name(pn_ssl_t *ssl, char *buffer, size_t size)
{
    LOG_FUNC_START("pn_ssl_get_protocol_name");
    if (buffer)
    {
        /* not needed ... yet */
        *buffer = '\0';
    }
    LOG_FUNC_END("pn_ssl_get_protocol_name");
    return false;
}

/*------------------------------------------------------------------------------
-- pn_ssl_domain
--
--  Create the pn_ssl_domain_t object
--  Inputs:  The mode, we only support PN_SSL_MODE_CLIENT
--  Returns: Ptr to a domain object, or NULL if error
------------------------------------------------------------------------------*/
pn_ssl_domain_t *pn_ssl_domain(pn_ssl_mode_t mode)
{
    pn_ssl_domain_t *domain;

    LOG_FUNC_START("pn_ssl_domain");

    /* only one domain supported for now */
    if (sslDomainInitialized == true)
    {
        LOG_VERBOSE("pn_ssl_domain error, already initialized \n\r");
        return NULL;
    }
    sslDomainInitialized = true;

    domain = (pn_ssl_domain_t *)malloc(sizeof(pn_ssl_domain_t));
    if (!domain)
    {
        LOG_VERBOSE("AMQP:                       Error mallocing ssl_domain \n\r");
        return NULL;
    }

    domain->ref_count = 1;
    domain->mode = mode;
    domain->trusted_CAs = NULL;

    //  Init SSL library
    LOG_VERBOSE("AMQP:                       Initializing SSL client... \n\r");

    //  we only support client
    switch (mode)
    {
    case PN_SSL_MODE_CLIENT:
        break;

    case PN_SSL_MODE_SERVER:
        LOG_VERBOSE("No SSL Server code available.\n");
        free(domain);
        return NULL;

    default:
        LOG_VERBOSE("Invalid valid for pn_ssl_mode_t: %d\n", mode);
        free(domain);
        return NULL;
    }

    if (pn_ssl_domain_set_peer_authentication(domain, PN_SSL_ANONYMOUS_PEER, NULL))
    {
        pn_ssl_domain_free(domain);
        return NULL;
    }

    LOG_FUNC_END("pn_ssl_domain");
    return domain;
}

void pn_ssl_domain_free(pn_ssl_domain_t *d)
{
    LOG_FUNC_START("pn_ssl_domain_free");

    if (d == NULL)
    {
        LOG_ERROR("NULL domain\r\n");
    }
    else
    {
        d->ref_count--;
        if (d->ref_count == 0)
        {
            free(d->trusted_CAs);
            free(d);
        }
    }

    LOG_FUNC_END("pn_ssl_domain_free");
}

int pn_ssl_domain_set_credentials(pn_ssl_domain_t *domain,
    const char *certificate_file,
    const char *private_key_file,
    const char *password)
{
    LOG_FUNC_START("pn_ssl_domain_set_credentials");
    if (!domain)
    {
        return -1;
    }

    /* ignored, we only do client for now */
    LOG_FUNC_END("pn_ssl_domain_set_credentials");
    return 0;
}

int pn_ssl_domain_set_trusted_ca_db(pn_ssl_domain_t *domain,
    const char *certificate_db)
{
    LOG_FUNC_START("pn_ssl_domain_set_trusted_ca_db");
    if (!domain)
    {
        return -1;
    }

    if (certificate_db != NULL)
    {
        domain->trusted_CAs = pn_strdup(certificate_db);
    }

    // ignored, we only do client for now
    LOG_FUNC_END("pn_ssl_domain_set_trusted_ca_db");
    return 0;
}

int pn_ssl_domain_set_peer_authentication(pn_ssl_domain_t *domain,
    const pn_ssl_verify_mode_t mode,
    const char *trusted_CAs)
{
    LOG_FUNC_START("pn_ssl_domain_set_peer_authentication");
    if (!domain)
    {
        return -1;
    }

    switch (mode)
    {
    case PN_SSL_VERIFY_PEER:
    case PN_SSL_VERIFY_PEER_NAME:
        //LOG_ERROR("SSL Peer Verification: not supported.\r\n");

        break;

    case PN_SSL_ANONYMOUS_PEER:

        /* disable peer verification with wolfssl */

        break;

    default:
        LOG_ERROR(NULL, "Invalid peer authentication mode given.");
        return -1;
    }
    LOG_FUNC_END("pn_ssl_domain_set_peer_authentication");

    return 0;
}

int pn_ssl_domain_allow_unsecured_client(pn_ssl_domain_t *domain)
{
    LOG_FUNC_START("pn_ssl_domain_allow_unsecured_client");
    if (!domain)
    {
        return -1;
    }

    if (domain->mode != PN_SSL_MODE_SERVER)
    {
        LOG_ERROR("Cannot permit unsecured clients - not a server.\r\n");
        return -1;
    }

    /* server mode not supported, so well ... do nothing */

    LOG_FUNC_END("pn_ssl_domain_allow_unsecured_client");
    return 0;
}

int pn_ssl_set_peer_hostname(pn_ssl_t *ssl, const char *hostname)
{
    int result = 0;

    LOG_FUNC_START("pn_ssl_set_peer_hostname");
    if (!ssl)
    {
        LOG_VERBOSE("Error, NULL ssl\r\n");
        result = -1;
    }
    else
    {
        if (ssl->peer_hostname)
        {
            free(ssl->peer_hostname);
            ssl->peer_hostname = NULL;
        }

        if (hostname)
        {
            ssl->peer_hostname = pn_strdup(hostname);
            if (ssl->peer_hostname == NULL)
            {
                LOG_ERROR("Error allocating hostname\r\n");
                result = -2;
            }
        }
    }

    LOG_FUNC_END("pn_ssl_set_peer_hostname");

    return result;
}

int pn_ssl_get_peer_hostname(pn_ssl_t *ssl, char *hostname, size_t *bufsize)
{
    int result = 0;

    LOG_FUNC_START("pn_ssl_get_peer_hostname");

    if (ssl == NULL)
    {
        LOG_ERROR("Error, NULL ssl\r\n");
        result = -1;
    }
    else
    {
        if (!ssl->peer_hostname)
        {
            *bufsize = 0;
            if (hostname)
            {
                *hostname = '\0';
            }
        }
        else
        {
            size_t len = strlen(ssl->peer_hostname);
            if (hostname)
            {
                if (len >= *bufsize)
                {
                    LOG_ERROR("Error copying hostname\r\n");
                    result = -1;
                }
                strcpy(hostname, ssl->peer_hostname);
            }

            *bufsize = len;
        }
    }
    LOG_FUNC_END("pn_ssl_get_peer_hostname");

    return result;
}

pn_ssl_resume_status_t pn_ssl_resume_status(pn_ssl_t *s)
{
    /* This API is not implemented for wolfssl for now */

    LOG_FUNC_START("pn_ssl_resume_status");
    LOG_FUNC_END("pn_ssl_resume_status");

    return PN_SSL_RESUME_UNKNOWN;
}

bool pn_ssl_allow_unsecured(pn_transport_t *transport)
{
    /* This API is not implemented for wolfssl for now */

    LOG_FUNC_START("pn_ssl_allow_unsecured");
    LOG_FUNC_END("pn_ssl_allow_unsecured");

    return true;
}