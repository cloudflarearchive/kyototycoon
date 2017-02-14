/*************************************************************************************************
 * Interface for secure connections for Kyoto Tycoon
 *                                                               Copyright (C) 2013 Cloudflare Inc.
 * This file is part of Kyoto Tycoon.
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 *************************************************************************************************/


#include "ktsocketsec.h"
#include "myconf.h"

#if HAVE_SEC_CHANNEL

extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

}

namespace kyototycoon {                  // common namespace


/**
 * Default ECC ephemeral key
 */
#define EC_CURVE_NAME "prime256v1"


/**
 * Cipher list to be used
 */
#define CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384"


/**
 * OpenSSL implementation of SecChannel interface
 */
struct SecChannelOpenSSL {
  SecChannel::SecError error;            ///< error number
  const char* errmsg;                    ///< error message
  int32_t fd;                            ///< file descriptor
  unsigned char *key;                    ///< key
  SSL_CTX *ctx;                          ///< SSL context
  SSL *ssl;                              ///< SSL connection handle
  SecChannel::SecState state;            ///< SSL state
};


/**
 * Initialize global ssl information
 **/
static pthread_once_t g_once_control_init = PTHREAD_ONCE_INIT;
static pthread_once_t g_once_control_teardown = PTHREAD_ONCE_INIT;
static void init_ssl();
static void teardown_ssl();
static pthread_mutex_t *ssl_locks = NULL;

/**
 * Set the error message from OpenSSL.
 */
static void seterrmsg(SecChannelOpenSSL *core, SecChannel::SecError error, const char* msg);
static void seterrmsg(SecChannelOpenSSL *core, int rc);


/**
 * Helper functions for reading keys from disk.
 */
static int read_key_asn1(const char *path, unsigned char **key, long *len);
static void destroy_key_asn1(unsigned char *key);


/**
 * Default constructor.
 */
SecChannel::SecChannel() {
  _assert_(true);
  SecChannelOpenSSL* core = new SecChannelOpenSSL;
  core->error = SecChannel::SENoError;
  core->errmsg = NULL;
  core->fd = -1;
  core->key = NULL;
  core->ctx = NULL;
  core->ssl = NULL;
  core->state = SecChannel::SSUNSET;
  opq_ = core;
  pthread_once(&g_once_control_init, *init_ssl);
}


/**
 * Destructor.
 */
SecChannel::~SecChannel() {
  _assert_(true);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  core->state = SecChannel::SSUNSET;
  delete core;
}


/**
 * Teardown.
 */
void SecChannel::teardown() {
  pthread_once(&g_once_control_teardown, *teardown_ssl);
}


/**
 * Get the last happened error information.
 * @return the last happened error information.
 */
SecChannel::SecError SecChannel::error() {
  _assert_(true);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  return core->error;
}


/**
 * Get the last happened error information.
 * @return the last happened error information.
 */
const char* SecChannel::error_msg() {
  _assert_(true);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  if (!core->errmsg) return "no error";
  return core->errmsg;
}


/**
 * Complete a secure accept
 */
bool SecChannel::accept() {
  _assert_(true);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  int rc = SSL_accept(core->ssl);
  if (rc != 1) {
    seterrmsg(core, rc);
    return false;
  }
  core->state = SecChannel::SSESTABLISHED;
  return true;
}


/**
 * Accept a secure connection
 */
bool SecChannel::bind_server(int32_t fd, const char* ca, const char* pk, const char* cert) {
  _assert_(fd && ca && pk && cert);
  int rc, nid;
  long len = 0;
  STACK_OF(X509_NAME) *cert_names;
  EC_KEY *ecdh = NULL;
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  core->state = SecChannel::SSNEGOTIATING;
  core->ctx = SSL_CTX_new(TLSv1_2_server_method());
  if (core->ctx == NULL) {
    seterrmsg(core, SEInternal, "SSL_CTX_new failed");
    goto fail;
  }
  core->state = SecChannel::SSCTXCREATED;
  if (SSL_CTX_set_cipher_list(core->ctx, CIPHER_LIST) <= 0) {
    seterrmsg(core, SEInternal, "SSL_CTX_set_cipher_list failed");
    goto fail;
  }
  if (SSL_CTX_use_certificate_file(core->ctx, cert, SSL_FILETYPE_PEM) <= 0) {
    seterrmsg(core, SEFileError, "Error setting the certificate file");
    goto fail;
  }
  if (read_key_asn1(pk, &core->key, &len) != 0) {
    seterrmsg(core, SEFileError, "Error reading the key file");
    goto fail;
  }
  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, core->ctx, core->key, len) <= 0) {
    seterrmsg(core, SEFileError, "Error setting the openssl key");
    goto fail;
  }
  if (SSL_CTX_check_private_key(core->ctx) == 0) {
    seterrmsg(core, SEInternal, "Private key does not match the certificate public key");
    goto fail;
  }
  SSL_CTX_set_verify(core->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  cert_names = SSL_load_client_CA_file(ca);
  if (!cert_names) {
    seterrmsg(core, SEInternal, "Unable to load CA file");
    goto fail;
  }
  SSL_CTX_set_client_CA_list(core->ctx, cert_names);
  SSL_CTX_set_verify_depth(core->ctx, 1);
  if (SSL_CTX_load_verify_locations(core->ctx, ca, 0) != 1) {
    seterrmsg(core, SEInternal, "Unable to verify CA file");
    goto fail;
  }
  nid = OBJ_sn2nid(EC_CURVE_NAME);
  if (NID_undef == nid) {
    seterrmsg(core, SEInternal, "ECDSA curve not present");
    goto fail;
  }
  ecdh = EC_KEY_new_by_curve_name(nid);
  if (NULL == ecdh) {
    seterrmsg(core, SEInternal, "ECDSA new curve error");
    goto fail;
  }
  SSL_CTX_set_tmp_ecdh(core->ctx, ecdh);
  EC_KEY_free(ecdh);
  core->ssl = SSL_new(core->ctx);
  if (core->ssl == NULL) {
    seterrmsg(core, SEInternal, "SSL_new failed");
    goto fail;
  }
  core->state = SecChannel::SSCREATED;
  rc = SSL_set_fd(core->ssl, fd);
  if (rc != 1) {
    seterrmsg(core, SEInternal, "SSL_set_fd failed");
    goto fail;
  }
  SSL_set_accept_state(core->ssl);
  return true;
fail:
  if (core->ctx != NULL) {
    SSL_CTX_free(core->ctx);
    core->ctx = NULL;
  }
  if (core->ssl != NULL) {
    SSL_shutdown(core->ssl);
    SSL_free(core->ssl);
    core->ssl = NULL;
  }
  if (core->key != NULL) {
    destroy_key_asn1(core->key);
    core->key = NULL;
  }
  return false;
}


/**
 * Complete a secure connect
 */
bool SecChannel::connect() {
  _assert_(true);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  int rc = SSL_connect(core->ssl);
  if (rc != 1) {
    seterrmsg(core, rc);
    return false;
  }
  core->state = SecChannel::SSESTABLISHED;
  return true;
}


/**
 * Initiate a secure connection
 */
bool SecChannel::bind_client(int32_t fd, const char* ca, const char* pk, const char* cert) {
  _assert_(fd && ca && pk && cert);
  int rc, nid;
  long len = 0;
  EC_KEY *ecdh = NULL;
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  STACK_OF(X509_NAME) *cert_names;
  core->state = SecChannel::SSNEGOTIATING;
  core->ctx = SSL_CTX_new(TLSv1_2_client_method());
  if (core->ctx == NULL) {
    seterrmsg(core, SEInternal, "SSL_CTX_new failed");
    goto fail;
  }
  core->state = SecChannel::SSCTXCREATED;
  if (SSL_CTX_set_cipher_list(core->ctx, CIPHER_LIST) <= 0) {
    seterrmsg(core, SEInternal, "SSL_CTX_set_cipher_list failed");
    goto fail;
  }
  if (SSL_CTX_use_certificate_file(core->ctx, cert, SSL_FILETYPE_PEM) <= 0) {
    seterrmsg(core, SEFileError, "Error setting the certificate file");
    goto fail;
  }
  if (read_key_asn1(pk, &core->key, &len) != 0) {
    seterrmsg(core, SEFileError, "Error reading the key file");
    goto fail;
  }
  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, core->ctx, core->key, len) <= 0) {
    seterrmsg(core, SEFileError, "Error setting the openssl key");
    goto fail;
  }
  if (SSL_CTX_check_private_key(core->ctx) == 0) {
    seterrmsg(core, SEInternal, "Private key does not match the certificate public key");
    goto fail;
  }
  if (SSL_CTX_set_mode(core->ctx, SSL_MODE_AUTO_RETRY) == 0) {
    seterrmsg(core, SEInternal, "Mode cannot be set");
    goto fail;
  }
  SSL_CTX_set_verify(core->ctx, SSL_VERIFY_PEER, 0);
  cert_names = SSL_load_client_CA_file(ca);
  if (!cert_names) {
    seterrmsg(core, SEInternal, "Unable to load CA file");
    goto fail;
  }
  SSL_CTX_set_client_CA_list(core->ctx, cert_names);
  SSL_CTX_set_verify_depth(core->ctx, 1);
  if (SSL_CTX_load_verify_locations(core->ctx, ca, 0) != 1) {
    seterrmsg(core, SEInternal, "Unable to verify CA file");
    goto fail;
  }
  nid = OBJ_sn2nid(EC_CURVE_NAME);
  if (NID_undef == nid) {
    seterrmsg(core, SEInternal, "ECDSA curve not present");
    goto fail;
  }
  ecdh = EC_KEY_new_by_curve_name(nid);
  if (NULL == ecdh) {
    seterrmsg(core, SEInternal, "ECDSA new curve error");
    goto fail;
  }
  SSL_CTX_set_tmp_ecdh(core->ctx, ecdh);
  EC_KEY_free(ecdh);
  core->ssl = SSL_new(core->ctx);
  if (core->ssl == NULL) {
    seterrmsg(core, SEInternal, "SSL_new failed");
    goto fail;
  }
  core->state = SecChannel::SSCREATED;
  rc = SSL_set_fd(core->ssl, fd);
  if (rc != 1) {
    seterrmsg(core, SEInternal, "SSL_set_fd failed");
    goto fail;
  }
  SSL_set_connect_state(core->ssl);
  return true;
fail:
  if (core->ctx != NULL) {
    SSL_CTX_free(core->ctx);
    core->ctx = NULL;
  }
  if (core->ssl != NULL) {
    SSL_shutdown(core->ssl);
    SSL_free(core->ssl);
    core->ssl = NULL;
  }
  if (core->key != NULL) {
    destroy_key_asn1(core->key);
    core->key = NULL;
  }
  return false;
}


/**
 * Close a secure connection
 */
bool SecChannel::close() {
  _assert_(true);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  if (core->state >= SecChannel::SSCREATED &&
      core->ssl != NULL) {
    SSL_shutdown(core->ssl);
    SSL_free(core->ssl);
    core->ssl = NULL;
  }
  if (core->state >= SecChannel::SSCTXCREATED &&
      core->ctx != NULL) {
    SSL_CTX_free(core->ctx);
    core->ctx = NULL;
  }
  if (core->key != NULL) {
    destroy_key_asn1(core->key);
    core->key = NULL;
  }
  return true;
}


/**
 * Send a message
 */
int SecChannel::send(const void* buf, size_t size) {
  _assert_(buf);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  int rc = SSL_write(core->ssl, buf, size);
  if (rc < 1) {
    seterrmsg(core, rc);
  }
  return rc;
}


/**
 * Recieve a message
 */
int SecChannel::receive(void* buf, size_t size) {
  _assert_(buf);
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  int rc = SSL_read(core->ssl, buf, size);
  if (rc < 1) {
    seterrmsg(core, rc);
  }
  return rc;
}


/**
 * Retrieve current state
 * @return SecChannel of channel
 */
SecChannel::SecState SecChannel::secstate() {
  SecChannelOpenSSL* core = (SecChannelOpenSSL*)opq_;
  return core->state;
}


/**
 * Set the error and message from an OpenSSL rc
 */
static void seterrmsg(SecChannelOpenSSL *core, int rc) {
  _assert_(core && msg);
  int errnum = SSL_get_error(core->ssl, rc);
  switch (errnum) {
  case SSL_ERROR_NONE:
    core->error = SecChannel::SENoError;
    core->errmsg = "";
    break;
  case SSL_ERROR_WANT_READ:
    core->error = SecChannel::SEWantRead;
    core->errmsg = "SSL channel needs to be read";
    break;
  case SSL_ERROR_WANT_WRITE:
    core->error = SecChannel::SEWantWrite;
    core->errmsg = "SSL channel needs to be read";
    break;
  case SSL_ERROR_ZERO_RETURN:
    core->error = SecChannel::SEInternal;
    core->errmsg = "SSL channel has been shut down from the other side";
    break;
  case SSL_ERROR_SSL:
  case SSL_ERROR_SYSCALL:
    core->error = SecChannel::SEInternal;
    core->errmsg = ERR_reason_error_string(ERR_get_error());
    break;
  default:
    core->error = SecChannel::SEBadData;
    core->errmsg = "OpenSSL error";
    break;
  }
  ERR_clear_error();
}


/**
 * Set the error and message
 */
static void seterrmsg(SecChannelOpenSSL *core, SecChannel::SecError error,
    const char* msg) {
  _assert_(core && msg);
  core->error = error;
  core->errmsg = msg;
}

void ssl_threadid_func(CRYPTO_THREADID *id) {
  CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
void ssl_lock_func(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
      pthread_mutex_lock(&ssl_locks[n]);
  } else {
      pthread_mutex_unlock(&ssl_locks[n]);
  }
}

static void init_ssl() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  // TODO: Handle memory allocation error or error creating mutexes

  int ssl_lock_count = CRYPTO_num_locks();
  ssl_locks = (pthread_mutex_t *)calloc(ssl_lock_count,
                                        sizeof(pthread_mutex_t));
  for (int i = 0; i < ssl_lock_count; i++) {
    pthread_mutex_init(&ssl_locks[i], NULL);
  }

  CRYPTO_THREADID_set_callback(ssl_threadid_func);
  CRYPTO_set_locking_callback(ssl_lock_func);
}

static void teardown_ssl() {
  CONF_modules_unload(1);
  EVP_cleanup();
  ENGINE_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
  ERR_free_strings();

  if (ssl_locks != NULL) {
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
      pthread_mutex_destroy(&ssl_locks[i]);
    }
    free(ssl_locks);
  }
}

/**
 * Helper functions for reading keys from disk.
 */
static int read_key_asn1(const char *path, unsigned char **key, long *len) {
  _assert_(path && key && len);
  std::ifstream is;
  long localLen;
  unsigned char *localKey;
  is.open(path, std::ios::binary);
  if (!is.is_open()) {
    return -1;
  }
  is.seekg(0, is.end);
  localLen = is.tellg();
  is.seekg(0, is.beg);
  localKey = (unsigned char*)malloc(sizeof(unsigned char)*localLen);
  if (localKey == NULL) {
    return -1;
  }
  is.read((char*)localKey, localLen);
  if (!is.good()) {
    free(localKey);
    return -1;
  }
  is.close();
  *len = localLen;
  return 0;
}

static void destroy_key_asn1(unsigned char *key) {
  _assert_(key);
  free(key);
}

} // common namespace

#endif // HAVE_SEC_CHANNEL

// END OF FILE
