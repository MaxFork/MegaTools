/*
 *  megatools - Mega.nz client library and tools
 *  Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include "mega.h"
#include "http.h"
#include "sjson.h"
#include "alloc.h"

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

DEFINE_CLEANUP_FUNCTION(struct http *, http_free)
#define gc_http_free CLEANUP(http_free)

DEFINE_CLEANUP_FUNCTION_NULL(BN_CTX *, BN_CTX_free)
#define gc_bn_ctx_free CLEANUP(BN_CTX_free)

DEFINE_CLEANUP_FUNCTION_NULL(BIGNUM *, BN_free)
#define gc_bn_free CLEANUP(BN_free)

#define CACHE_FORMAT_VERSION 4

gint mega_debug = 0;

// Data structures and enums

// {{{ SRV_E*

enum { SRV_EINTERNAL = -1,
       SRV_EARGS = -2,
       SRV_EAGAIN = -3,
       SRV_ERATELIMIT = -4,
       SRV_EFAILED = -5,
       SRV_ETOOMANY = -6,
       SRV_ERANGE = -7,
       SRV_EEXPIRED = -8,

       // FS access errors
       SRV_ENOENT = -9,
       SRV_ECIRCULAR = -10,
       SRV_EACCESS = -11,
       SRV_EEXIST = -12,
       SRV_EINCOMPLETE = -13,

       // crypto errors
       SRV_EKEY = -14,

       // user errors
       SRV_ESID = -15,
       SRV_EBLOCKED = -16,
       SRV_EOVERQUOTA = -17,
       SRV_ETEMPUNAVAIL = -18,
       SRV_ETOOMANYCONNECTIONS = -19 };

// }}}
// {{{ rsa_key

struct rsa_key {
	// priv
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *d;
	BIGNUM *u; // p^-1 mod q
	// pub
	BIGNUM *m;
	BIGNUM *e;
};

// }}}
// {{{ struct mega_session

struct mega_session {
	struct http *http;

	gint max_ul;
	gint max_dl;
	gchar *proxy;
	gint max_workers;

	gint id;
	gchar *sid;
	gchar *rid;
	GHashTable *api_url_params;

	gchar *password_salt_v2; /* as returned from mega.nz (base64 string) */
	guchar *password_key;
	guchar *password_key_save; /* password key for session saver */
	guchar *master_key;
	struct rsa_key rsa_key;

	gchar *user_handle;
	gchar *user_name;
	gchar *user_email;

	GHashTable *share_keys;

	GSList *fs_nodes;

	// progress reporting
	mega_status_callback status_callback;
	gpointer status_userdata;

	gint64 last_refresh;
	gboolean create_preview;
	gboolean resume_enabled;
};

// }}}

// JSON helpers

// {{{ print_node

static void print_node(const gchar *n, const gchar *prefix)
{
	gc_free gchar *pretty = s_json_pretty(n);

	g_printerr("%s%s\n", prefix, pretty);
}

// }}}
// {{{ s_json_get_bytes

static guchar *s_json_get_bytes(const gchar *node, gsize *out_len)
{
	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(out_len != NULL, NULL);

	gc_free gchar *data = s_json_get_string(node);

	if (data) {
		gchar *b64 = g_base64_decode(data, out_len);
		return b64;
	}

	return NULL;
}

// }}}
// {{{ s_json_get_member_bytes

static guchar *s_json_get_member_bytes(const gchar *node, const gchar *name, gsize *out_len)
{
	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(out_len != NULL, NULL);

	const gchar *v = s_json_get_member(node, name);
	if (v)
		return s_json_get_bytes(v, out_len);

	return NULL;
}

// }}}
// {{{ s_json_get_member_bn

static BIGNUM *s_json_get_member_bn(const gchar *node, const gchar *name)
{
	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	gc_free gchar *data = s_json_get_member_string(node, name);
	if (data) {
		BIGNUM *n = NULL;
		if (BN_dec2bn(&n, data))
			return n;
	}

	return NULL;
}

void s_json_get_member_rsa_key(const gchar *node, const gchar *name, struct rsa_key *key)
{
	g_return_if_fail(node != NULL);
	g_return_if_fail(name != NULL);
	g_return_if_fail(key != NULL);

	const gchar *member = s_json_get_member(node, name);
	if (!member || s_json_get_type(member) != S_JSON_TYPE_OBJECT)
		return;

#define READ_COMPONENT(c) key->c = s_json_get_member_bn(member, #c)

	READ_COMPONENT(p);
	READ_COMPONENT(q);
	READ_COMPONENT(d);
	READ_COMPONENT(u);
	READ_COMPONENT(m);
	READ_COMPONENT(e);

#undef READ_COMPONENT
}

// }}}
// {{{ s_json_gen_member_bytes

static void s_json_gen_member_bytes(SJsonGen *gen, const gchar *name, guchar *data, gsize len)
{
	if (data) {
		gc_free gchar *tmp = g_base64_encode(data, len);
		s_json_gen_member_string(gen, name, tmp);
	} else {
		s_json_gen_member_null(gen, name);
	}
}

// }}}
// {{{ s_json_gen_member_rsa_key

static void s_json_gen_member_bn(SJsonGen *gen, const gchar *name, BIGNUM *n)
{
	gchar *tmp = BN_bn2dec(n);
	s_json_gen_member_string(gen, name, tmp);
	OPENSSL_free(tmp);
}

static void s_json_gen_member_rsa_key(SJsonGen *gen, const gchar *name, struct rsa_key *key)
{
	s_json_gen_member_object(gen, name);

#define ADD_COMPONENT(name)                                                                                            \
	if (key->name)                                                                                                 \
		s_json_gen_member_bn(gen, #name, key->name);

	ADD_COMPONENT(p)
	ADD_COMPONENT(q)
	ADD_COMPONENT(d)
	ADD_COMPONENT(u)
	ADD_COMPONENT(m)
	ADD_COMPONENT(e)

#undef ADD_COMPONENT

	s_json_gen_end_object(gen);
}

// }}}

// Crypto utilities

#define DW(p, n) (*((guint32 *)(p) + (n)))

// {{{ multi-precision integer macros

#define MPI_BITS(ptr) GUINT16_FROM_BE(*(guint16 *)(ptr))
#define MPI_BYTES(ptr) ((MPI_BITS(ptr) + 7) / 8)
#define MPI_SIZE(ptr) (MPI_BYTES(ptr) + MPI_HDRSIZE)
#define MPI_HDRSIZE 2
#define MPI2BN(ptr) BN_bin2bn((ptr) + MPI_HDRSIZE, MPI_BYTES(ptr), NULL)

// }}}
// {{{ base64urlencode

static gchar *base64urlencode(const guchar *data, gsize len)
{
	gint i, shl;
	gchar *she, *p;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(len > 0, NULL);

	gc_free gchar *sh = g_base64_encode(data, len);
	shl = strlen(sh);

	she = g_malloc0(shl + 1), p = she;
	for (i = 0; i < shl; i++) {
		if (sh[i] == '+')
			*p = '-';
		else if (sh[i] == '/')
			*p = '_';
		else if (sh[i] == '=')
			continue;
		else
			*p = sh[i];
		p++;
	}

	*p = '\0';

	return she;
}

// }}}
// {{{ base64urldecode

static guchar *base64urldecode(const gchar *str, gsize *len)
{
	gint i;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(len != NULL, NULL);

	gc_string_free GString *s = g_string_new(str);

	for (i = 0; i < s->len; i++) {
		if (s->str[i] == '-')
			s->str[i] = '+';
		else if (s->str[i] == '_')
			s->str[i] = '/';
	}

	gint eqs = (s->len * 3) & 0x03;
	for (i = 0; i < eqs; i++)
		g_string_append_c(s, '=');

	return g_base64_decode(s->str, len);
}

// }}}
// {{{ aes128_decrypt

G_GNUC_UNUSED static gboolean aes128_decrypt(guchar *out, const guchar *in, gsize len, const guchar *key)
{
	AES_KEY k;
	gsize off;

	g_return_val_if_fail(out != NULL, FALSE);
	g_return_val_if_fail(in != NULL, FALSE);
	g_return_val_if_fail(len % 16 == 0, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);

	AES_set_decrypt_key(key, 128, &k);

	for (off = 0; off < len; off += 16)
		AES_decrypt(in + off, out + off, &k);

	return TRUE;
}

// }}}
// {{{ aes128_encrypt

static gboolean aes128_encrypt(guchar *out, const guchar *in, gsize len, const guchar *key)
{
	AES_KEY k;
	gsize off;

	g_return_val_if_fail(out != NULL, FALSE);
	g_return_val_if_fail(in != NULL, FALSE);
	g_return_val_if_fail(len % 16 == 0, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);

	AES_set_encrypt_key(key, 128, &k);

	for (off = 0; off < len; off += 16)
		AES_encrypt(in + off, out + off, &k);

	return TRUE;
}

// }}}
// {{{ b64_aes128_decrypt

static guchar *b64_aes128_decrypt(const gchar *str, const guchar *key, gsize *outlen)
{
	AES_KEY k;
	gsize cipherlen = 0;
	gsize off;
	gc_free guchar *cipher = NULL;
	guchar *data;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	AES_set_decrypt_key(key, 128, &k);

	cipher = base64urldecode(str, &cipherlen);
	if (cipher == NULL)
		return NULL;

	if (cipherlen % 16 != 0)
		return NULL;

	data = g_malloc0(cipherlen);
	for (off = 0; off < cipherlen; off += 16)
		AES_decrypt(cipher + off, data + off, &k);

	if (outlen)
		*outlen = cipherlen;

	return data;
}

// }}}
// {{{ b64_aes128_encrypt

static gchar *b64_aes128_encrypt(const guchar *data, gsize len, const guchar *key)
{
	AES_KEY k;
	gsize off;
	gc_free guchar *cipher = NULL;
	gchar *str;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail((len % 16) == 0, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	AES_set_encrypt_key(key, 128, &k);

	cipher = g_malloc0(len);
	for (off = 0; off < len; off += 16)
		AES_encrypt(data + off, cipher + off, &k);

	return base64urlencode(cipher, len);
}

// }}}
// {{{ b64_aes128_cbc_decrypt

static guchar *b64_aes128_cbc_decrypt(const gchar *str, const guchar *key, gsize *outlen)
{
	AES_KEY k;
	gsize cipherlen = 0;
	gc_free guchar *cipher = NULL;
	guchar *data;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	AES_set_decrypt_key(key, 128, &k);

	cipher = base64urldecode(str, &cipherlen);
	if (cipher == NULL)
		return NULL;

	if (cipherlen % 16 != 0)
		return NULL;

	data = g_malloc0(cipherlen + 1);
	guchar iv[AES_BLOCK_SIZE] = { 0 };
	AES_cbc_encrypt(cipher, data, cipherlen, &k, iv, 0);

	if (outlen)
		*outlen = cipherlen;

	return data;
}

// }}}
// {{{ b64_aes128_cbc_encrypt

static gchar *b64_aes128_cbc_encrypt(const guchar *data, gsize len, const guchar *key)
{
	AES_KEY k;
	gc_free guchar *cipher = NULL;
	gchar *str;
	guchar iv[AES_BLOCK_SIZE] = { 0 };

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail((len % 16) == 0, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	AES_set_encrypt_key(key, 128, &k);

	cipher = g_malloc0(len);
	AES_cbc_encrypt(data, cipher, len, &k, iv, 1);
	return base64urlencode(cipher, len);
}

// }}}
// {{{ b64_aes128_cbc_encrypt_str

static gchar *b64_aes128_cbc_encrypt_str(const gchar *str, const guchar *key)
{
	gsize str_len, aligned_len;
	gc_free guchar *data = NULL;
	gchar *out;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	str_len = strlen(str);
	aligned_len = str_len + 1;
	if (aligned_len % 16)
		aligned_len += 16 - (aligned_len % 16);

	data = g_malloc0(aligned_len);
	memcpy(data, str, str_len);
	return b64_aes128_cbc_encrypt(data, aligned_len, key);
}

// }}}
// {{{ b64_aes128_decrypt_privk

static gboolean b64_aes128_decrypt_privk(const gchar *str, const guchar *key, struct rsa_key *rsa)
{
	gsize data_len = 0;
	gc_free guchar *data = NULL;
	guchar *p, *e;

	g_return_val_if_fail(str != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(rsa != NULL, FALSE);

	data = b64_aes128_decrypt(str, key, &data_len);
	if (!data)
		return FALSE;

	p = data;
	e = p + data_len;

	if (p + MPI_SIZE(p) > e)
		return FALSE;

	rsa->p = MPI2BN(p);
	p += MPI_SIZE(p);

	if (p + MPI_SIZE(p) > e)
		return FALSE;

	rsa->q = MPI2BN(p);
	p += MPI_SIZE(p);

	if (p + MPI_SIZE(p) > e)
		return FALSE;

	rsa->d = MPI2BN(p);
	p += MPI_SIZE(p);

	if (p + MPI_SIZE(p) > e)
		return FALSE;

	rsa->u = MPI2BN(p);

	return TRUE;
}

// }}}
// {{{ b64_decode_pubk

static gboolean b64_decode_pubk(const gchar *str, struct rsa_key *rsa)
{
	gsize data_len = 0;
	gc_free guchar *data = NULL;
	guchar *p, *e;

	g_return_val_if_fail(str != NULL, FALSE);
	g_return_val_if_fail(rsa != NULL, FALSE);

	data = base64urldecode(str, &data_len);
	if (data == NULL)
		return FALSE;

	p = data;
	e = p + data_len;

	if (p + MPI_SIZE(p) > e)
		return FALSE;

	rsa->m = MPI2BN(p);
	p += MPI_SIZE(p);

	if (p + MPI_SIZE(p) > e)
		return FALSE;

	rsa->e = MPI2BN(p);

	return TRUE;
}

// }}}
// {{{ b64_aes128_encrypt_privk

static void append_mpi_from_bn(GString *buf, BIGNUM *n)
{
	g_return_if_fail(buf != NULL);
	g_return_if_fail(n != NULL);

	gsize size = BN_num_bytes(n);
	gsize off = buf->len;

	g_string_set_size(buf, buf->len + size + MPI_HDRSIZE);

	*(guint16 *)(buf->str + off) = GUINT16_TO_BE(BN_num_bits(n));

	BN_bn2bin(n, buf->str + off + MPI_HDRSIZE);
}

static gchar *b64_aes128_encrypt_privk(const guchar *key, struct rsa_key *rsa)
{
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(rsa != NULL, FALSE);

	gc_string_free GString *data = g_string_sized_new(128 * 7);

	append_mpi_from_bn(data, rsa->p);
	append_mpi_from_bn(data, rsa->q);
	append_mpi_from_bn(data, rsa->d);
	append_mpi_from_bn(data, rsa->u);

	gsize off = data->len;
	gsize pad = data->len % 16 ? 16 - (data->len % 16) : 0;
	if (pad) {
		g_string_set_size(data, data->len + pad);
		while (off < data->len)
			data->str[off++] = 0;
	}

	return b64_aes128_encrypt(data->str, data->len, key);
}

// }}}
// {{{ b64_encode_pubk

static gchar *b64_encode_pubk(struct rsa_key *rsa)
{
	g_return_val_if_fail(rsa != NULL, FALSE);

	gc_string_free GString *data = g_string_sized_new(128 * 3);

	append_mpi_from_bn(data, rsa->m);
	append_mpi_from_bn(data, rsa->e);

	return base64urlencode(data->str, data->len);
}

// }}}
// {{{ rsa_decrypt

static BIGNUM *rsa_decrypt(BIGNUM *m, BIGNUM *d, BIGNUM *p, BIGNUM *q, BIGNUM *u)
{
	g_return_val_if_fail(m != NULL, NULL);
	g_return_val_if_fail(d != NULL, NULL);
	g_return_val_if_fail(p != NULL, NULL);
	g_return_val_if_fail(q != NULL, NULL);
	g_return_val_if_fail(u != NULL, NULL);

	gc_bn_ctx_free BN_CTX *ctx = BN_CTX_new();

	gc_bn_free BIGNUM *xp = BN_new();
	gc_bn_free BIGNUM *xq = BN_new();
	gc_bn_free BIGNUM *mod_mp = BN_new();
	gc_bn_free BIGNUM *mod_mq = BN_new();
	gc_bn_free BIGNUM *mod_dp1 = BN_new();
	gc_bn_free BIGNUM *mod_dq1 = BN_new();
	gc_bn_free BIGNUM *p1 = BN_new();
	gc_bn_free BIGNUM *q1 = BN_new();
	gc_bn_free BIGNUM *t = BN_new();
	BIGNUM *x = BN_new();

	// var xp = bmodexp(bmod(m,p), bmod(d,bsub(p,[1])), p);
	BN_mod(mod_mp, m, p, ctx);
	BN_sub(p1, p, BN_value_one());
	BN_mod(mod_dp1, d, p1, ctx);
	BN_mod_exp(xp, mod_mp, mod_dp1, p, ctx);

	// var xq = bmodexp(bmod(m,q), bmod(d,bsub(q,[1])), q);
	BN_mod(mod_mq, m, q, ctx);
	BN_sub(q1, q, BN_value_one());
	BN_mod(mod_dq1, d, q1, ctx);
	BN_mod_exp(xq, mod_mq, mod_dq1, q, ctx);

	// var t = bsub(xq,xp);
	if (BN_ucmp(xq, xp) <= 0) {
		BN_sub(t, xp, xq);
		BN_mul(x, t, u, ctx);
		BN_mod(t, x, q, ctx);
		BN_sub(t, q, t);
	} else {
		BN_sub(t, xq, xp);
		BN_mul(x, t, u, ctx);
		BN_mod(t, x, q, ctx);
	}

	BN_mul(x, t, p, ctx);
	BN_add(x, x, xp);

	return x;
}

// }}}
// {{{ rsa_encrypt

#if 0
static BIGNUM* rsa_encrypt(BIGNUM* s, BIGNUM* e, BIGNUM* m)
{
	BN_CTX* ctx;
	BIGNUM *r;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(e != NULL, NULL);
	g_return_val_if_fail(m != NULL, NULL);

	ctx = BN_CTX_new();
	r = BN_new();

	BN_mod_exp(r, s, e, m, ctx);

	BN_CTX_free(ctx);

	return r;
}
#endif

// }}}
// {{{ b64_rsa_decrypt

static guchar *b64_rsa_decrypt(const gchar *str, struct rsa_key *key, gsize *outlen)
{
	gsize cipherlen = 0;
	gc_free guchar *cipher = NULL;
	guchar *data;
	gc_bn_free BIGNUM *c = NULL, *m = NULL;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	cipher = base64urldecode(str, &cipherlen);
	if (cipher == NULL)
		return NULL;

	if (MPI_SIZE(cipher) > cipherlen)
		return NULL;

	c = MPI2BN(cipher);

	m = rsa_decrypt(c, key->d, key->p, key->q, key->u);

	if (!m)
		return NULL;

	data = g_malloc0(BN_num_bytes(m) + 1);
	BN_bn2bin(m, data);

	if (outlen)
		*outlen = BN_num_bytes(m);

	return data;
}

// }}}
// {{{ rsa_key_gen

static gboolean rsa_key_gen(struct rsa_key *k)
{
	RSA *key;

	g_return_val_if_fail(k != NULL, FALSE);
	g_return_val_if_fail(k->p == NULL, FALSE);
	g_return_val_if_fail(k->m == NULL, FALSE);

	key = RSA_new();
	if (!key)
		return FALSE;

	BIGNUM *e = BN_new();
	if (!e) {
		RSA_free(key);
		return FALSE;
	}

	BN_set_word(e, RSA_3);

	if (!RSA_generate_key_ex(key, 2048, e, NULL))
		return FALSE;

	if (RSA_check_key(key) != 1) {
		RSA_free(key);
		return FALSE;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	const BIGNUM *p, *q, *d, *u, *m, *_e;
	RSA_get0_key(key, &m, &_e, &d);
	RSA_get0_factors(key, &q, &p);
	RSA_get0_crt_params(key, NULL, NULL, &u);

	k->p = BN_dup(p);
	k->q = BN_dup(q);
	k->d = BN_dup(d);
	k->u = BN_dup(u);
	k->m = BN_dup(m);
	k->e = BN_dup(_e);
#else
	// private part
	k->p = BN_dup(key->q);
	k->q = BN_dup(key->p);
	k->d = BN_dup(key->d);
	k->u = BN_dup(key->iqmp);

	// public part
	k->m = BN_dup(key->n);
	k->e = BN_dup(key->e);
#endif

	RSA_free(key);
	BN_free(e);

	return TRUE;
}

// }}}
// {{{ rsa_key_free

static void rsa_key_free(struct rsa_key *k)
{
	if (!k)
		return;

	if (k->p)
		BN_free(k->p);
	if (k->q)
		BN_free(k->q);
	if (k->d)
		BN_free(k->d);
	if (k->u)
		BN_free(k->u);
	if (k->m)
		BN_free(k->m);
	if (k->e)
		BN_free(k->e);

	memset(k, 0, sizeof(struct rsa_key));
}

// }}}
// {{{ make_random_key

static guchar *make_random_key(void)
{
	guchar k[16];

	//XXX: error check
	RAND_bytes(k, sizeof(k));

	return g_memdup(k, 16);
}

// }}}
// {{{ make_password_key

static guchar *make_password_key(const gchar *password)
{
	guchar pkey[16] = { 0x93, 0xC4, 0x67, 0xE3, 0x7D, 0xB0, 0xC7, 0xA4,
			    0xD1, 0xBE, 0x3F, 0x81, 0x01, 0x52, 0xCB, 0x56 };
	gint i, r;
	gint len;

	g_return_val_if_fail(password != NULL, NULL);

	len = strlen(password);

	for (r = 65536; r--;) {
		for (i = 0; i < len; i += 16) {
			AES_KEY k;
			guchar key[16] = { 0 }, pkey_tmp[16];

			strncpy(key, password + i, 16); // this is fine, we don't need a NUL termination here, stfu gcc8!
			AES_set_encrypt_key(key, 128, &k);
			AES_encrypt(pkey, pkey_tmp, &k);
			memcpy(pkey, pkey_tmp, 16);
		}
	}

	return g_memdup(pkey, 16);
}

// }}}
// {{{ make_username_hash

static gchar *make_username_hash(const gchar *un, const guchar *key)
{
	AES_KEY k;
	gint l, i;
	guchar hash[16] = { 0 }, hash_tmp[16], oh[8];

	g_return_val_if_fail(un != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	AES_set_encrypt_key(key, 128, &k);

	for (i = 0, l = strlen(un); i < l; i++)
		hash[i % 16] ^= un[i];

	for (i = 16384; i--;) {
		AES_encrypt(hash, hash_tmp, &k);
		memcpy(hash, hash_tmp, 16);
	}

	memcpy(oh, hash, 4);
	memcpy(oh + 4, hash + 8, 4);

	return base64urlencode(oh, 8);
}

// }}}
// {{{ make_request_id

static guchar *make_request_id(void)
{
	const gchar chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	gchar k[11] = { 0 };
	gint i;

	for (i = 0; i < 10; i++)
		k[i] = chars[rand() % sizeof(chars)];

	return g_strdup(k);
}

// }}}
// {{{ chunk locations

static guint get_chunk_size(gsize idx)
{
	return (idx < 8 ? idx + 1 : 8) * 1024 * 128;
}

// }}}
// {{{ chunked CBC-MAC

struct chunked_cbc_mac {
	EVP_CIPHER_CTX *ctx;
	gsize chunk_idx;
	guint64 next_boundary;
	guint64 position;
	guchar chunk_mac_iv[16];
	guchar chunk_mac[16];
	guchar meta_mac[16];
};

static gboolean chunked_cbc_mac_init(struct chunked_cbc_mac *mac, guchar key[16], guchar iv[16])
{
	g_return_val_if_fail(mac != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);

	memset(mac, 0, sizeof(*mac));
	memcpy(mac->chunk_mac_iv, iv, 16);
	memcpy(mac->chunk_mac, mac->chunk_mac_iv, 16);
	mac->next_boundary = get_chunk_size(mac->chunk_idx);

	mac->ctx = EVP_CIPHER_CTX_new();
	if (!mac->ctx)
		return FALSE;

	if (!EVP_EncryptInit_ex(mac->ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
		EVP_CIPHER_CTX_free(mac->ctx);
		return FALSE;
	}

	EVP_CIPHER_CTX_set_padding(mac->ctx, 0);

	return TRUE;
}

static gboolean chunked_cbc_mac_init8(struct chunked_cbc_mac *mac, guchar key[16], guchar iv[8])
{
	g_return_val_if_fail(iv != NULL, FALSE);

	guchar mac_iv[16];
	memcpy(mac_iv, iv, 8);
	memcpy(mac_iv + 8, iv, 8);

	return chunked_cbc_mac_init(mac, key, mac_iv);
}

static gboolean chunked_cbc_mac_close_chunk(struct chunked_cbc_mac *mac)
{
	gint i;
	int out_len;

	for (i = 0; i < 16; i++)
		mac->meta_mac[i] ^= mac->chunk_mac[i];

	if (!EVP_EncryptUpdate(mac->ctx, mac->meta_mac, &out_len, mac->meta_mac, 16))
		return FALSE;

	memcpy(mac->chunk_mac, mac->chunk_mac_iv, 16);
	mac->next_boundary += get_chunk_size(++mac->chunk_idx);

	return TRUE;
}

static gboolean chunked_cbc_mac_update(struct chunked_cbc_mac *mac, const guchar *data, gsize len)
{
	gsize i;
	int out_len;

	g_return_val_if_fail(mac != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	for (i = 0; i < len; i++) {
		mac->chunk_mac[mac->position % 16] ^= data[i];
		mac->position++;

		if (G_UNLIKELY((mac->position % 16) == 0)) {
			if (!EVP_EncryptUpdate(mac->ctx, mac->chunk_mac, &out_len, mac->chunk_mac, 16))
				return FALSE;
		}

		// add chunk mac to the chunk macs list if we are at the chunk boundary
		if (G_UNLIKELY(mac->position == mac->next_boundary))
			if (!chunked_cbc_mac_close_chunk(mac))
				return FALSE;
	}

	return TRUE;
}

// on failure, the memory is freed, but mac_out can't be used
static gboolean chunked_cbc_mac_finish(struct chunked_cbc_mac *mac, guchar mac_out[16])
{
	int out_len;

	g_return_val_if_fail(mac != NULL, FALSE);

	// finish buffer if necessary
	if (mac->position % 16) {
		while (mac->position % 16) {
			mac->chunk_mac[mac->position % 16] ^= 0;
			mac->position++;
		}

		if (!EVP_EncryptUpdate(mac->ctx, mac->chunk_mac, &out_len, mac->chunk_mac, 16)) {
			EVP_CIPHER_CTX_free(mac->ctx);
			return FALSE;
		}
	}

	// if there last chunk is unfinished, finish it
	if (mac->position > (mac->next_boundary - get_chunk_size(mac->chunk_idx)))
		if (!chunked_cbc_mac_close_chunk(mac)) {
			EVP_CIPHER_CTX_free(mac->ctx);
			return FALSE;
		}


	if (mac_out)
		memcpy(mac_out, mac->meta_mac, 16);


	EVP_CIPHER_CTX_free(mac->ctx);
	memset(mac, 0, sizeof(*mac));
	return TRUE;
}

static gboolean chunked_cbc_mac_finish8(struct chunked_cbc_mac *mac, guchar mac_out[8])
{
	guchar buf[16];
	gint i;

	g_return_val_if_fail(mac_out != NULL, FALSE);

	if (!chunked_cbc_mac_finish(mac, buf))
		return FALSE;

	for (i = 0; i < 4; i++)
		mac_out[i] = buf[i] ^ buf[i + 4];
	for (i = 0; i < 4; i++)
		mac_out[i + 4] = buf[i + 8] ^ buf[i + 12];

	return TRUE;
}

// }}}
// {{{ chunked CBC-MAC (simpler interface)

gboolean chunk_mac_calculate(guchar iv[8], guchar key[16], const guchar *data, gsize len, guchar mac[16])
{
	EVP_CIPHER_CTX *ctx;
	const guchar *data_end;
	int out_len;

	g_return_val_if_fail(iv != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);
	g_return_val_if_fail(len > 0, FALSE);
	g_return_val_if_fail(mac != NULL, FALSE);

	data_end = data + len;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return FALSE;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		goto err_clean;

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	memcpy(mac, iv, 8);
	memcpy(mac + 8, iv, 8);

	// process data by 16 byte blocks (data is aligned)
	while (data + 16 < data_end) {
		*((guint64 *)&mac[0]) ^= *(guint64 *)(data);
		*((guint64 *)&mac[8]) ^= *(guint64 *)(data + 8);
		data += 16;

		if (!EVP_EncryptUpdate(ctx, mac, &out_len, mac, 16))
			goto err_clean;
	}

	if (data_end - data > 0) {
		int i = 0;
		while (data_end > data)
			mac[i++] ^= *data++;

		if (!EVP_EncryptUpdate(ctx, mac, &out_len, mac, 16))
			goto err_clean;
	}

	EVP_CIPHER_CTX_free(ctx);
	return TRUE;

err_clean:
	EVP_CIPHER_CTX_free(ctx);
	return FALSE;
}

// meta-mac is xor of all chunk macs encrypted along the way
// chunks is an ordered list of 16 byte chunk mac buffers
static gboolean meta_mac_calculate(GSList *chunks, guchar key[16], guchar meta_mac[16])
{
	GSList *ci;
	EVP_CIPHER_CTX *ctx;
	int out_len;

	g_return_val_if_fail(chunks != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(meta_mac != NULL, FALSE);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return FALSE;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		goto err_clean;

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	memset(meta_mac, 0, 16);

	for (ci = chunks; ci; ci = ci->next) {
		guchar *mac = ci->data;
		gint i;

		for (i = 0; i < 16; i++)
			meta_mac[i] ^= mac[i];

		if (!EVP_EncryptUpdate(ctx, meta_mac, &out_len, meta_mac, 16))
			goto err_clean;
	}

	EVP_CIPHER_CTX_free(ctx);
	return TRUE;

err_clean:
	EVP_CIPHER_CTX_free(ctx);
	return FALSE;
}

#if 0
static void meta_mac_pack(guchar meta_mac[16], guchar packed[8])
{
	gint i;

	for (i = 0; i < 4; i++)
		packed[i] = meta_mac[i] ^ meta_mac[i + 4];
	for (i = 0; i < 4; i++)
		packed[i + 4] = meta_mac[i + 8] ^ meta_mac[i + 12];
}
#endif

// }}}
// {{{ aes128 ctr

// data must be aligned to 16 byte block
static gboolean encrypt_aes128_ctr(guchar *out, const guchar *in, gsize len, guchar key[16], guchar iv[16])
{
	EVP_CIPHER_CTX *ctx;
	int out_len;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return FALSE;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		goto err_clean;

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (!EVP_EncryptUpdate(ctx, out, &out_len, in, len))
		goto err_clean;

	if (out_len != len)
		goto err_clean;

	EVP_CIPHER_CTX_free(ctx);
	return TRUE;

err_clean:
	EVP_CIPHER_CTX_free(ctx);
	return FALSE;
}

// }}}
// {{{ unpack_node_key

static void unpack_node_key(guchar node_key[32], guchar aes_key[16], guchar nonce[8], guchar meta_mac_xor[8])
{
	if (aes_key) {
		DW(aes_key, 0) = DW(node_key, 0) ^ DW(node_key, 4);
		DW(aes_key, 1) = DW(node_key, 1) ^ DW(node_key, 5);
		DW(aes_key, 2) = DW(node_key, 2) ^ DW(node_key, 6);
		DW(aes_key, 3) = DW(node_key, 3) ^ DW(node_key, 7);
	}

	if (nonce) {
		DW(nonce, 0) = DW(node_key, 4);
		DW(nonce, 1) = DW(node_key, 5);
	}

	if (meta_mac_xor) {
		DW(meta_mac_xor, 0) = DW(node_key, 6);
		DW(meta_mac_xor, 1) = DW(node_key, 7);
	}
}

// }}}
// {{{ pack_node_key

static void pack_node_key(guchar node_key[32], guchar aes_key[16], guchar nonce[8], guchar meta_mac[16])
{
	DW(node_key, 0) = DW(aes_key, 0) ^ DW(nonce, 0);
	DW(node_key, 1) = DW(aes_key, 1) ^ DW(nonce, 1);
	DW(node_key, 2) = DW(aes_key, 2) ^ DW(meta_mac, 0) ^ DW(meta_mac, 1);
	DW(node_key, 3) = DW(aes_key, 3) ^ DW(meta_mac, 2) ^ DW(meta_mac, 3);
	DW(node_key, 4) = DW(nonce, 0);
	DW(node_key, 5) = DW(nonce, 1);
	DW(node_key, 6) = DW(meta_mac, 0) ^ DW(meta_mac, 1);
	DW(node_key, 7) = DW(meta_mac, 2) ^ DW(meta_mac, 3);
}

// }}}
// {{{ encode_node_attrs

static gchar *encode_node_attrs(const gchar *name)
{
	g_return_val_if_fail(name != NULL, NULL);

	SJsonGen *gen = s_json_gen_new();
	s_json_gen_start_object(gen);
	s_json_gen_member_string(gen, "n", name);
	s_json_gen_end_object(gen);
	gc_free gchar *attrs_json = s_json_gen_done(gen);

	return g_strdup_printf("MEGA%s", attrs_json);
}

// }}}
// {{{ decode_node_attrs

static gboolean decode_node_attrs(const gchar *attrs, gchar **name)
{
	g_return_val_if_fail(attrs != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);

	// parse attributes
	if (!attrs || !g_str_has_prefix(attrs, "MEGA{"))
		return FALSE;

	// decode JSON
	if (!s_json_is_valid(attrs + 4))
		return FALSE;

	*name = s_json_get_member_string(attrs + 4, "n");

	return TRUE;
}

// }}}
// {{{ decrypt_node_attrs

static gboolean decrypt_node_attrs(const gchar *encrypted_attrs, const guchar *key, gchar **name)
{
	g_return_val_if_fail(encrypted_attrs != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);

	gc_free guchar *attrs = b64_aes128_cbc_decrypt(encrypted_attrs, key, NULL);

	return decode_node_attrs(attrs, name);
}

// }}}
// {{{ handle_auth

gboolean handle_auth(const gchar *handle, const gchar *b64_ha, const guchar *master_key)
{
	gsize ha_len = 0;

	g_return_val_if_fail(handle != NULL, FALSE);
	g_return_val_if_fail(b64_ha != NULL, FALSE);
	g_return_val_if_fail(master_key != NULL, FALSE);

	gc_free guchar *ha = b64_aes128_decrypt(b64_ha, master_key, &ha_len);
	if (!ha || ha_len != 16)
		return FALSE;

	return !memcmp(ha, handle, 8) && !memcmp(ha + 8, handle, 8);
}

// }}}

// Server API helpers

// {{{ srv_error_to_string

static const gchar *srv_error_to_string(gint code)
{
	switch (code) {
	case SRV_EINTERNAL:
		return "EINTERNAL";
	case SRV_EARGS:
		return "EARGS";
	case SRV_EAGAIN:
		return "EAGAIN";
	case SRV_ERATELIMIT:
		return "ERATELIMIT";
	case SRV_EFAILED:
		return "EFAILED";
	case SRV_ETOOMANY:
		return "ETOOMANY";
	case SRV_ERANGE:
		return "ERANGE";
	case SRV_EEXPIRED:
		return "EEXPIRED";
	case SRV_ENOENT:
		return "ENOENT";
	case SRV_ECIRCULAR:
		return "ECIRCULAR";
	case SRV_EACCESS:
		return "EACCESS";
	case SRV_EEXIST:
		return "EEXIST";
	case SRV_EINCOMPLETE:
		return "EINCOMPLETE";
	case SRV_EKEY:
		return "EKEY";
	case SRV_ESID:
		return "ESID";
	case SRV_EBLOCKED:
		return "EBLOCKED";
	case SRV_EOVERQUOTA:
		return "EOVERQUOTA";
	case SRV_ETEMPUNAVAIL:
		return "ETEMPUNAVAIL";
	case SRV_ETOOMANYCONNECTIONS:
		return "ETOOMANYCONNECTIONS";
	default:
		return "EUNKNOWN";
	}
}

// }}}

// {{{ api_request_unsafe

static gchar *api_request_unsafe(struct mega_session *s, const gchar *req_node, GError **err)
{
	GError *local_err = NULL;
	gc_free gchar *url = NULL;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(req_node != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	if (mega_debug & MEGA_DEBUG_API)
		print_node(req_node, "-> ");

	GString *additional_url_params = g_string_sized_new(64);
	GHashTableIter iter;
	g_hash_table_iter_init(&iter, s->api_url_params);
	gchar *key, *val;
	while (g_hash_table_iter_next(&iter, (gpointer *)&key, (gpointer *)&val))
		g_string_append_printf(additional_url_params, "&%s=%s", key, val);

	// prepare URL
	s->id++;
	if (s->sid)
		url = g_strdup_printf("https://g.api.mega.co.nz/cs?id=%u&sid=%s%s", s->id, s->sid,
				      additional_url_params->str);
	else
		url = g_strdup_printf("https://g.api.mega.co.nz/cs?id=%u%s", s->id, additional_url_params->str);

	g_string_free(additional_url_params, TRUE);

	GString *res_str = http_post(s->http, url, req_node, strlen(req_node), &local_err);

	// handle http errors
	if (!res_str) {
		if (local_err->domain == HTTP_ERROR &&
		    (local_err->code == HTTP_ERROR_NO_RESPONSE || local_err->code == HTTP_ERROR_SERVER_BUSY)) {
			// simulate SRV_EAGAIN response if server drops connection
			return g_strdup_printf("%d", SRV_EAGAIN);
		} else {
			g_propagate_prefixed_error(err, local_err, "HTTP POST failed: ");
			return NULL;
		}
	}

	// decode JSON
	if (!s_json_is_valid(res_str->str)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response JSON");
		g_string_free(res_str, TRUE);
		return NULL;
	}

	gchar *res_node = g_string_free(res_str, FALSE);

	if (mega_debug & MEGA_DEBUG_API && res_node)
		print_node(res_node, "<- ");

	return res_node;
}

// }}}
// {{{ api_request

static gchar *api_request(struct mega_session *s, const gchar *req_node, GError **err)
{
	GError *local_err = NULL;
	gchar *response;
	gint delay = 250000; // repeat after 250ms 500ms 1s ...

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(req_node != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	// some default rate limiting
	g_usleep(20000);

again:
	response = api_request_unsafe(s, req_node, &local_err);
	if (!response) {
		g_propagate_error(err, local_err);
		return NULL;
	}

	// if we are asked to repeat the call, do it with exponential backoff
	if (s_json_get_type(response) == S_JSON_TYPE_NUMBER && s_json_get_int(response, SRV_EINTERNAL) == SRV_EAGAIN) {
		g_free(response);
		g_usleep(delay);
		delay = delay * 2;

		if (delay > 4 * 64 * 1000 * 1000) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server keeps asking us for EAGAIN, giving up");
			return NULL;
		}

		goto again;
	}

	return response;
}

// }}}
// {{{ api_response_check

// check that we have and array with a response value (object or error code)
static const gchar *api_response_check(const gchar *response, gchar expects, gint *error_code, GError **err)
{
	// there was already an error returned by api_request
	if (*err)
		return NULL;

	// null response without an error, it shouldn't happen, but handle it to be sure
	if (!response) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Null response");
		return NULL;
	}

	if (error_code)
		*error_code = 0;

	SJsonType response_type = s_json_get_type(response);

	// request level error
	if (response_type == S_JSON_TYPE_NUMBER) {
		gint v = s_json_get_int(response, 0);

		// if it's negative, it's error status
		if (v < 0) {
			if (error_code)
				*error_code = v;

			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error %s",
				    srv_error_to_string(v));
			return NULL;
		}
	}
	// check that we have and array with a response value
	else if (response_type == S_JSON_TYPE_ARRAY) {
		const gchar *node = s_json_get_element(response, 0);
		if (node) {
			SJsonType node_type = s_json_get_type(node);

			// we got object
			if (node_type == S_JSON_TYPE_OBJECT) {
				if (expects == 'o')
					return node;
			} else if (node_type == S_JSON_TYPE_ARRAY) {
				if (expects == 'a')
					return node;
			} else if (node_type == S_JSON_TYPE_NUMBER) {
				// we got int number
				gint v = s_json_get_int(node, 0);

				// if it's negative, it's error status
				if (v < 0) {
					if (error_code)
						*error_code = v;

					g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error %s",
						    srv_error_to_string(v));
					return NULL;
				}

				if (expects == 'i')
					return node;
			} else if (node_type == S_JSON_TYPE_BOOL) {
				if (expects == 'b')
					return node;
			} else if (node_type == S_JSON_TYPE_STRING) {
				if (expects == 's')
					return node;
			} else if (node_type == S_JSON_TYPE_NULL) {
				if (expects == 'n')
					return node;
			}
		}
	}

	g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Unexpected response");
	return NULL;
}

// }}}
// {{{ api_call

static gchar *api_call(struct mega_session *s, gchar expects, gint *error_code, GError **err, const gchar *format, ...)
{
	const gchar *node;
	va_list args;

	g_return_val_if_fail(err != NULL && *err == NULL, NULL);
	g_return_val_if_fail(format != NULL, NULL);

	va_start(args, format);
	gc_free gchar *request = s_json_buildv(format, args);
	va_end(args);

	if (request == NULL) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid request format: %s", format);
		return NULL;
	}

	gc_free gchar *response = api_request(s, request, err);

	node = api_response_check(response, expects, error_code, err);
	if (*err) {
		const gchar *method_node = s_json_path(request, "$[0].a!string");

		if (method_node) {
			gc_free gchar *method = s_json_get_string(method_node);

			g_prefix_error(err, "API call '%s' failed: ", method);
		} else
			g_prefix_error(err, "API call failed: ");

		return NULL;
	}

	return s_json_get(node);
}

// }}}

// Remote filesystem helpers

// {{{ build_node_tree

static void mega_node_free(struct mega_node *n);

static void build_node_tree(struct mega_session *s)
{
	GSList *i, *next;
	g_return_if_fail(s != NULL);

	// node handles are assumed to be unique
	GHashTable *handle_map = g_hash_table_new(g_str_hash, g_str_equal);
	for (i = s->fs_nodes; i; i = i->next) {
		struct mega_node *n = i->data;

#if GLIB_CHECK_VERSION(2, 40, 0)
		if (!g_hash_table_insert(handle_map, n->handle, n))
			g_printerr("WARNING: Dup node handle detected %s\n", n->handle);
#else
		if (g_hash_table_lookup(handle_map, n->handle))
			g_printerr("WARNING: Dup node handle detected %s\n", n->handle);
		else
			g_hash_table_insert(handle_map, n->handle, n);
#endif
	}

	for (i = s->fs_nodes; i;) {
		struct mega_node *n = i->data;
		next = i->next;

		if (n->type == MEGA_NODE_CONTACT) {
			if (n->su_handle)
				n->parent = g_hash_table_lookup(handle_map, n->su_handle);
		} else {
			if (n->parent_handle)
				n->parent = g_hash_table_lookup(handle_map, n->parent_handle);
		}

		i = next;
	}

	g_hash_table_unref(handle_map);
}

// }}}
// {{{ rebase_node_tree

static gboolean rebase_node_tree(struct mega_session *s, const gchar *new_root)
{
	/* Remove nodes that are not decendents of nodes with their |handle| == |specific|
	// -------------------------------------------------------------------------------
	// Example with dir1 as the target, e.g. |handle| == |specific|:
	//             root
	//           /      \
	//          /        \
	//        dir1       dir2
	//        /   \        \
	//     file1  dir3    file2
	//            /
	//          file3
	//
	// This will remove 'root', 'dir2', and 'file2'; 'dir1' becomes the root node.
	// -----------------------------------------------------------------------------*/

	struct mega_node *root_node = mega_session_get_node_by_handle(s, new_root);
	if (root_node == NULL)
		return FALSE;

	if (root_node->type == MEGA_NODE_FILE) {
		// if the new root is a file, just place it under a newly
		// created root and remove everything else

		s->fs_nodes = g_slist_remove(s->fs_nodes, root_node);
		g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
		s->fs_nodes = NULL;

		// add 
		g_clear_pointer(&root_node->parent_handle, g_free);
		root_node->parent = NULL;
		s->fs_nodes = g_slist_prepend(s->fs_nodes, root_node);
	} else if (root_node->type == MEGA_NODE_FOLDER) {
		GSList *i, *i_next, **i_prev_next = &s->fs_nodes;
		GSList *free_list = NULL;

		g_clear_pointer(&root_node->parent_handle, g_free);
		root_node->parent = NULL;

		// find nodes that are not children of root_node and remove them
		for (i = s->fs_nodes; i; i = i_next) {
			struct mega_node *n = i->data;

			i_next = i->next;

			if (n != root_node && !mega_node_has_ancestor(n, root_node)) {
				// drop link
				*i_prev_next = i_next;
				g_slist_free_1(i);

				// we can't free the node right here, because it
				// needs to be available for
				// mega_node_has_ancestor checks
				free_list = g_slist_prepend(free_list, n);
			} else {
				// move next address of previously kept node
				i_prev_next = &i->next;
			}
		}

		g_slist_free_full(free_list, (GDestroyNotify)mega_node_free);
	} else {
		return FALSE;
	}

	return TRUE;
}

// }}}
// {{{ path manipulation utils

static gchar *path_sanitize_slashes(const gchar *path)
{
	g_return_val_if_fail(path != NULL, NULL);

	gchar *sanepath = g_malloc(strlen(path) + 1);
	gchar *tmp = sanepath;
	gboolean previous_was_slash = 0;

	while (*path != '\0') {
		if (*path != '/' || !previous_was_slash)
			*(tmp++) = *path;

		previous_was_slash = *path == '/' ? 1 : 0;
		path++;
	}

	*tmp = '\0';
	if (tmp > (sanepath + 1) && *(tmp - 1) == '/')
		*(tmp - 1) = '\0';

	return sanepath;
}

static gchar **path_get_elements(const gchar *path)
{
	g_return_val_if_fail(path != NULL, NULL);

	gc_free gchar *sane_path = path_sanitize_slashes(path); /* always succeeds */

	return g_strsplit(sane_path, "/", 0);
}

static gchar *path_simplify(const gchar *path)
{
	guint i, j = 0, pathv_len, subroot = 0;
	gboolean absolute;

	g_return_val_if_fail(path != NULL, NULL);

	gc_strfreev gchar **pathv = path_get_elements(path); /* should free */
	pathv_len = g_strv_length(pathv);

	gc_free gchar **sane_pathv = (gchar **)g_malloc0((pathv_len + 1) * sizeof(gchar *));
	absolute = (pathv_len > 1 && **pathv == '\0');

	for (i = 0; i < pathv_len; i++) {
		if (!strcmp(pathv[i], "."))
			continue; /* ignore curdirs in path */
		else if (!strcmp(pathv[i], "..")) {
			if (absolute) {
				if (j > 1) {
					j--;
				}
			} else {
				if (subroot &&
				    !strcmp(sane_pathv[j - 1], "..")) /* if we are off base and last item is .. */
				{
					sane_pathv[j++] = pathv[i];
				} else {
					if (j > subroot) {
						j--;
					} else {
						subroot++;
						sane_pathv[j++] = pathv[i];
					}
				}
			}
		} else {
			sane_pathv[j++] = pathv[i];
		}
	}

	sane_pathv[j] = 0;

	return g_strjoinv("/", sane_pathv);
}

// }}}

// Public API helpers

// {{{ send_status

// true to interrupt
static void send_status(struct mega_session *s, struct mega_status_data* d)
{
	if (s->status_callback)
		s->status_callback(d, s->status_userdata);
}

// }}}
// {{{ add_share_key

void add_share_key(struct mega_session *s, const gchar *handle, const guchar *key)
{
	g_return_if_fail(s != NULL);
	g_return_if_fail(handle != NULL);
	g_return_if_fail(key != NULL);

	g_hash_table_insert(s->share_keys, g_strdup(handle), g_memdup(key, 16));
}

// }}}
// {{{ mega_node_parse

static struct mega_node *mega_node_parse(struct mega_session *s, const gchar *node)
{
	gchar *tmp;
	gc_free gchar *node_h = s_json_get_member_string(node, "h");
	gc_free gchar *node_p = s_json_get_member_string(node, "p");
	gc_free gchar *node_u = s_json_get_member_string(node, "u");
	gc_free gchar *node_k = s_json_get_member_string(node, "k");
	gc_free gchar *node_a = s_json_get_member_string(node, "a");
	gc_free gchar *node_sk = s_json_get_member_string(node, "sk");
	gc_free gchar *node_su = s_json_get_member_string(node, "su");
	gint node_t = s_json_get_member_int(node, "t", -1);
	gint64 node_ts = s_json_get_member_int(node, "ts", 0);
	gint64 node_s = s_json_get_member_int(node, "s", 0);

	// sanity check parsed values
	if (!node_h || strlen(node_h) == 0) {
		g_printerr("WARNING: Skipping FS node without handle\n");
		return NULL;
	}

	// return special nodes
	if (node_t == MEGA_NODE_ROOT) {
		struct mega_node *n = g_new0(struct mega_node, 1);
		n->name = g_strdup("Root");
		n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
		n->handle = g_strdup(node_h);
		n->timestamp = node_ts;
		n->type = node_t;
		return n;
	} else if (node_t == MEGA_NODE_INBOX) {
		struct mega_node *n = g_new0(struct mega_node, 1);
		n->name = g_strdup("Inbox");
		n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
		n->handle = g_strdup(node_h);
		n->timestamp = node_ts;
		n->type = node_t;
		return n;
	} else if (node_t == MEGA_NODE_TRASH) {
		struct mega_node *n = g_new0(struct mega_node, 1);
		n->name = g_strdup("Trash");
		n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
		n->handle = g_strdup(node_h);
		n->timestamp = node_ts;
		n->type = node_t;
		return n;
	}

	// allow only file and dir nodes
	if (node_t != MEGA_NODE_FOLDER && node_t != MEGA_NODE_FILE) {
		g_printerr("WARNING: Skipping FS node %s with unknown type %d\n", node_h, node_t);
		return NULL;
	}

	// node has to have attributes
	if (!node_a || strlen(node_a) == 0) {
		g_printerr("WARNING: Skipping FS node %s without attributes\n", node_h);
		return NULL;
	}

	// node has to have a key
	if (!node_k || strlen(node_k) == 0) {
		g_printerr("WARNING: Skipping FS node %s because of missing node key\n", node_h);
		return NULL;
	}

	// process sk if available
	if (node_sk && strlen(node_sk) > 0) {
		gsize share_key_len;
		gc_free guchar *share_key = NULL;

		if (strlen(node_sk) > 22) {
			share_key = b64_rsa_decrypt(node_sk, &s->rsa_key, &share_key_len);
			if (share_key && share_key_len >= 16)
				add_share_key(s, node_h, share_key);
		} else {
			share_key = b64_aes128_decrypt(node_sk, s->master_key, &share_key_len);
			if (share_key && share_key_len == 16)
				add_share_key(s, node_h, share_key);
		}
	}

	gchar *node_share_key = NULL;
	gc_free gchar *encrypted_node_key = NULL;
	gc_strfreev gchar **parts = g_strsplit(node_k, "/", 0);
	gint i;

	for (i = 0; parts[i]; i++) {
		// split node keys
		gchar *key_value = strchr(parts[i], ':');
		if (key_value) {
			gchar *key_handle = parts[i];
			*key_value = '\0';
			key_value++;

			if (s->user_handle && !strcmp(s->user_handle, key_handle)) {
				// we found a key encrypted by me
				encrypted_node_key = g_strdup(key_value);
				node_share_key = s->master_key;
				break;
			}

			node_share_key = g_hash_table_lookup(s->share_keys, key_handle);
			if (node_share_key) {
				encrypted_node_key = g_strdup(key_value);
			}
		}
	}

	if (!encrypted_node_key) {
		g_printerr("WARNING: Skipping FS node %s because node key wasn't found\n", node_h);
		return NULL;
	}

	// keys longer than 45 chars are RSA keys
	if (strlen(encrypted_node_key) >= 46) {
		g_printerr("WARNING: Skipping FS node %s because it has RSA key\n", node_h);
		return NULL;
	}

	// decrypt node key
	gsize node_key_len = 0;
	gc_free guchar *node_key = b64_aes128_decrypt(encrypted_node_key, node_share_key, &node_key_len);
	if (!node_key) {
		g_printerr("WARNING: Skipping FS node %s because key can't be decrypted %s\n", node_h,
			   encrypted_node_key);
		return NULL;
	}

	if (node_t == MEGA_NODE_FILE && node_key_len != 32) {
		g_printerr("WARNING: Skipping FS node %s because file key doesn't have 32 bytes\n", node_h);
		return NULL;
	}

	if (node_t == MEGA_NODE_FOLDER && node_key_len != 16) {
		g_printerr("WARNING: Skipping FS node %s because folder key doesn't have 16 bytes\n", node_h);
		return NULL;
	}

	// decrypt attributes with node key
	guchar aes_key[16];
	if (node_t == MEGA_NODE_FILE)
		unpack_node_key(node_key, aes_key, NULL, NULL);
	else
		memcpy(aes_key, node_key, 16);

	gc_free gchar *node_name = NULL;
	if (!decrypt_node_attrs(node_a, aes_key, &node_name)) {
		g_printerr("WARNING: Skipping FS node %s because it has malformed attributes\n", node_h);
		return NULL;
	}

	if (!node_name) {
		g_printerr("WARNING: Skipping FS node %s because it is missing name\n", node_h);
		return NULL;
	}

	// replace invalid filename characters with whitespace
	gchar *check = node_name;
#ifdef G_OS_WIN32
	while ((check = strpbrk(check, "/\\<>:\"|?*")))
#else
	while ((check = strpbrk(check, "/")))
#endif
		*check = '_';

	// check for invalid names
	if (!strcmp(node_name, ".") || !strcmp(node_name, "..")) {
		g_printerr("WARNING: Skipping FS node %s because it's name is invalid '%s'\n", node_h, node_name);
		return NULL;
	}

#define TAKE(n) (tmp = n, n = NULL, tmp)

	struct mega_node *n = g_new0(struct mega_node, 1);

	n->s = s;
	n->name = TAKE(node_name);
	n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
	n->handle = TAKE(node_h);
	n->parent_handle = TAKE(node_p);
	n->user_handle = TAKE(node_u);
	n->su_handle = TAKE(node_su);
	n->key_len = node_key_len;
	n->key = TAKE(node_key);
	n->size = node_s;
	n->timestamp = node_ts;
	n->type = node_t;

	return n;
}

// }}}
// {{{ mega_node_parse_user

static struct mega_node *mega_node_parse_user(struct mega_session *s, const gchar *node)
{
	gc_free gchar *node_u = s_json_get_member_string(node, "u");
	gc_free gchar *node_m = s_json_get_member_string(node, "m");
	gint64 node_ts = s_json_get_member_int(node, "ts", 0);

	// sanity check parsed values
	if (!node_u || strlen(node_u) == 0)
		return NULL;

	if (!node_m || strlen(node_m) == 0)
		return NULL;

	struct mega_node *n = g_new0(struct mega_node, 1);
	n->s = s;
	n->name = node_m;
	n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
	n->handle = node_u;
	n->parent_handle = g_strdup("NETWORK");
	n->user_handle = g_strdup(node_u);
	n->timestamp = node_ts;
	n->type = MEGA_NODE_CONTACT;

	node_u = node_m = NULL;

	return n;
}

// }}}
// {{{ mega_node_is_writable

gboolean mega_node_is_writable(struct mega_session *s, struct mega_node *n)
{
	g_return_val_if_fail(n != NULL, FALSE);

	return n->type == MEGA_NODE_CONTACT ||
	       ((n->type == MEGA_NODE_FILE || n->type == MEGA_NODE_FOLDER) &&
		!strcmp(s->user_handle, n->user_handle)) ||
	       n->type == MEGA_NODE_ROOT || n->type == MEGA_NODE_NETWORK || n->type == MEGA_NODE_TRASH;
}

// }}}
// {{{ mega_node_free

static void mega_node_free(struct mega_node *n)
{
	if (n) {
		g_free(n->name);
		g_free(n->name_collate_key);
		g_free(n->handle);
		g_free(n->parent_handle);
		g_free(n->user_handle);
		g_free(n->su_handle);
		g_free(n->key);
		g_free(n->link);
		memset(n, 0, sizeof(struct mega_node));
		g_free(n);
	}
}

// }}}

// Public API

// {{{ mega_error_quark

GQuark mega_error_quark(void)
{
	return g_quark_from_static_string("mega-error-quark");
}

// }}}

// {{{ mega_session_new

struct mega_session *mega_session_new(void)
{
	struct mega_session *s = g_new0(struct mega_session, 1);

	s->http = http_new();
	http_set_content_type(s->http, "application/json");

	s->id = time(NULL);
	s->rid = make_request_id();
	s->api_url_params = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	s->share_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	s->resume_enabled = TRUE;

	return s;
}

// }}}
// {{{ mega_session_set_speed

void mega_session_set_speed(struct mega_session *s, gint ul, gint dl)
{
	g_return_if_fail(s != NULL);

	s->max_ul = ul;
	s->max_dl = dl;
}

// }}}
// {{{ mega_session_set_workers

void mega_session_set_workers(struct mega_session *s, gint workers)
{
	g_return_if_fail(s != NULL);

	s->max_workers = workers;
}

// }}}
// {{{ mega_session_set_proxy

void mega_session_set_proxy(struct mega_session *s, const gchar *proxy)
{
	g_return_if_fail(s != NULL);

	g_free(s->proxy);
	s->proxy = g_strdup(proxy);
	http_set_proxy(s->http, s->proxy);
}

// }}}
// {{{ mega_session_set_resume

void mega_session_set_resume(struct mega_session *s, gboolean enabled)
{
	g_return_if_fail(s != NULL);

	s->resume_enabled = enabled;
}

// }}}
// {{{ mega_session_free

void mega_session_free(struct mega_session *s)
{
	if (s) {
		http_free(s->http);
		g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
		g_hash_table_destroy(s->share_keys);
		g_hash_table_destroy(s->api_url_params);
		g_free(s->sid);
		g_free(s->rid);
		g_free(s->password_key);
		g_free(s->master_key);
		rsa_key_free(&s->rsa_key);
		g_free(s->user_handle);
		g_free(s->user_name);
		g_free(s->user_email);
		memset(s, 0, sizeof(struct mega_session));
		g_free(s);
	}
}

// }}}
// {{{ mega_session_watch_status

void mega_session_watch_status(struct mega_session *s, mega_status_callback cb, gpointer userdata)
{
	g_return_if_fail(s != NULL);

	s->status_callback = cb;
	s->status_userdata = userdata;
}

// }}}
// {{{ mega_session_enable_previews

void mega_session_enable_previews(struct mega_session *s, gboolean enable)
{
	g_return_if_fail(s != NULL);

	s->create_preview = enable;
}

// }}}

// {{{ mega_session_open_exp_folder

// |specific| is optional so it can be NULL
gboolean mega_session_open_exp_folder(struct mega_session *s, const gchar *n, const gchar *key, const gchar *specific,
				      GError **err)
{
	GError *local_err = NULL;
	gsize len, i, l;
	GSList *list = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(n != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	g_hash_table_replace(s->api_url_params, g_strdup("n"), g_strdup(n));

	g_free(s->master_key);
	s->master_key = base64urldecode(key, &len);
	if (len != 16)
		return FALSE;

	// login user
	gc_free gchar *f_node = api_call(s, 'o', NULL, &local_err, "[{a:f, c:1, r:1}]");
	if (!f_node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	const gchar *ff_node = s_json_get_member(f_node, "f");
	if (ff_node && s_json_get_type(ff_node) == S_JSON_TYPE_ARRAY) {
		gc_free gchar** f_elems = s_json_get_elements(ff_node);
		gchar** f_elem = f_elems;

		while (*f_elem) {
			if (s_json_get_type(*f_elem) == S_JSON_TYPE_OBJECT) {
				// first node is the root folder
				if (f_elem == f_elems) {
					gc_free gchar *node_h = s_json_get_member_string(*f_elem, "h");

					add_share_key(s, node_h, s->master_key);
				}

				// import nodes into the fs
				struct mega_node *n = mega_node_parse(s, *f_elem);
				if (n) {
					if (f_elem == f_elems) {
						g_free(n->parent_handle);
						n->parent_handle = NULL;
					}

					list = g_slist_prepend(list, n);
				}
			}

			f_elem++;
		}
	}

	g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
	s->fs_nodes = g_slist_reverse(list);

	build_node_tree(s);

	// rebase node tree
	if (specific) {
		if (!rebase_node_tree(s, specific)) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Node not found: %s", specific);
			return FALSE;
		}
	}

	return TRUE;
}

// }}}
// {{{ mega_session_open

// this has side effect of the current session being closed
static gboolean mega_session_load(struct mega_session *s,
				  const gchar *un, const gchar *pw, gint max_age,
				  gchar **last_sid, gchar** last_pwsalt_v2,
				  GError **err);

gboolean mega_session_open(struct mega_session *s, const gchar *un, const gchar *pw,
			   gint max_age, gboolean *is_new_session, GError **err)
{
	GError *local_err = NULL;
	gboolean is_loggedin = FALSE;
	gc_free gchar* sid = NULL;
	gc_free gchar* pwsalt_v2 = NULL;
	gint login_variant = 0;
	gc_free gchar *un_lower = NULL;
	gc_free gchar *uh = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(un != NULL, FALSE);
	g_return_val_if_fail(pw != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// try to load cached session data first
	if (mega_session_load(s, un, pw, max_age, &sid, &pwsalt_v2, NULL)) {
		*is_new_session = FALSE;
		return TRUE;
	}

	*is_new_session = TRUE;

	// session load failed, clean session data
	mega_session_close(s);
	s->password_key_save = make_password_key(pw);
	un_lower = g_ascii_strdown(un, -1);

	// now if mega_session_load found a previous expired cache file, it will
	// return sid and pwsalt_v2 that we can try to re-use
	if (sid) {
		// if load_session returned sid, existence of pwsalt_v2 is
		// enough to determine login variant
		login_variant = pwsalt_v2 ? 2 : 0;

		g_free(s->sid);
		s->sid = g_strdup(sid);

		g_free(s->password_salt_v2);
		s->password_salt_v2 = g_strdup(pwsalt_v2);
	} else {
		// no previous session data found, we need to call us0 to determine the login
		// variant in use
		gc_free gchar *pre_login_node =	api_call(s, 'o', NULL, &local_err, "[{a:us0, user:%s}]", un_lower);
		if (!pre_login_node) {
			g_propagate_error(err, local_err);
			return FALSE;
		}

		login_variant = s_json_get_member_int(pre_login_node, "v", 0);
		if (login_variant == 2) {
			// get the password salt for the login v2
			g_free(pwsalt_v2);
			pwsalt_v2 = s_json_get_member_string(pre_login_node, "s");
			if (pwsalt_v2 == NULL) {
				g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Missing salt (v2)");
				return FALSE;
			}

			g_free(s->password_salt_v2);
			s->password_salt_v2 = g_strdup(pwsalt_v2);
		}
	}

	// session is not valid or is missing, we need to login again via 'us'
	// call

	if (login_variant == 2) {
		// login variant 2:
		// - uses PKCS5_PBKDF2_HMAC which requires a salt that is generated during registration
		//   and stored on the server (also returned by 'us0' call in the 's' field)
		// - PKCS5_PBKDF2_HMAC produces a 32byte value:
		//   - first half is a password key
		//   - second half is user hash for the 'us' call

		// decode salt from base64
		gsize salt_len;
		gc_free gchar *salt = base64urldecode(pwsalt_v2, &salt_len);
		if (salt == NULL) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to decode salt (v2)");
			return FALSE;
		}

		// derive password key and user hash
		guchar key[32];
		PKCS5_PBKDF2_HMAC(pw, strlen(pw),
				  salt, salt_len,
				  100000, EVP_sha512(),
				  sizeof(key), key);

		g_free(s->password_key);
		s->password_key = g_memdup(key, 16);

		uh = base64urlencode(key + 16, 16);
	} else {
		// make password key and user hash for v1 login
		g_free(s->password_key);
		s->password_key = make_password_key(pw);

		uh = make_username_hash(un_lower, s->password_key);
	}

	if (uh == NULL) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Faield to encode user hash");
		return FALSE;
	}

	if (sid) {
		// try to fetch user data, this will verify the session id
		if (mega_session_get_user(s, NULL))
			return TRUE;

		g_free(s->sid);
		s->sid = NULL;
	}

	// login user
	gc_free gchar *login_node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s, uh:%s}]", un_lower, uh);
	if (!login_node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	gc_free gchar *login_k = s_json_get_member_string(login_node, "k");
	gc_free gchar *login_privk = s_json_get_member_string(login_node, "privk");
	gc_free gchar *login_csid = s_json_get_member_string(login_node, "csid");

	// decrypt master key
	gc_free guchar *master_key = b64_aes128_decrypt(login_k, s->password_key, NULL);
	if (!master_key) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read master key during login");
		return FALSE;
	}

	// decrypt private key with master key
	struct rsa_key privk;
	memset(&privk, 0, sizeof(privk));
	if (!b64_aes128_decrypt_privk(login_privk, master_key, &privk)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read private key during login");
		rsa_key_free(&privk);
		return FALSE;
	}

	// decrypt session id
	gsize sid_len = 0;
	gc_free guchar *sid_binary = b64_rsa_decrypt(login_csid, &privk, &sid_len);
	if (!sid_binary || sid_len < 43) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read session id during login");
		rsa_key_free(&privk);
		return FALSE;
	}

	// save session id
	g_free(s->sid);
	s->sid = base64urlencode(sid_binary, 43);

	// cleanup
	rsa_key_free(&privk);

	return mega_session_get_user(s, err);
}

// }}}
// {{{ mega_session_close

void mega_session_close(struct mega_session *s)
{
	g_return_if_fail(s != NULL);

	g_free(s->password_key);
	g_free(s->password_key_save);
	g_free(s->password_salt_v2);
	g_free(s->master_key);
	g_free(s->sid);
	rsa_key_free(&s->rsa_key);
	g_free(s->user_handle);
	g_free(s->user_name);
	g_free(s->user_email);

	g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);

	g_hash_table_remove_all(s->share_keys);
	g_hash_table_remove_all(s->api_url_params);

	s->password_key = NULL;
	s->password_key_save = NULL;
	s->password_salt_v2 = NULL;
	s->master_key = NULL;
	s->sid = NULL;
	s->user_handle = NULL;
	s->user_email = NULL;
	s->user_name = NULL;
	s->fs_nodes = NULL;
	s->last_refresh = 0;

	s->status_callback = NULL;
}

// }}}
// {{{ mega_session_get_sid

const gchar *mega_session_get_sid(struct mega_session *s)
{
	g_return_val_if_fail(s != NULL, NULL);

	return s->sid;
}

// }}}
// {{{ mega_session_get_user

gboolean mega_session_get_user(struct mega_session *s, GError **err)
{
	GError *local_err = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(s->sid != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// prepare request
	gc_free gchar *user_node = api_call(s, 'o', NULL, &local_err, "[{a:ug}]");
	if (!user_node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// store information about the user
	g_free(s->user_handle);
	s->user_handle = s_json_get_member_string(user_node, "u");
	if (!s->user_handle) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read user's handle");
		return FALSE;
	}

	g_free(s->user_email);
	s->user_email = s_json_get_member_string(user_node, "email");

	g_free(s->user_name);
	s->user_name = s_json_get_member_string(user_node, "name");

	gc_free gchar *user_privk = s_json_get_member_string(user_node, "privk");
	gc_free gchar *user_pubk = s_json_get_member_string(user_node, "pubk");
	gc_free gchar *user_k = s_json_get_member_string(user_node, "k");

	// load master key
	g_free(s->master_key);
	s->master_key = b64_aes128_decrypt(user_k, s->password_key, NULL);
	if (!s->master_key) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read master key");
		return FALSE;
	}

	rsa_key_free(&s->rsa_key);

	// decrypt private key with master key
	if (!b64_aes128_decrypt_privk(user_privk, s->master_key, &s->rsa_key)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read private key");
		return FALSE;
	}

	// load public key
	if (!b64_decode_pubk(user_pubk, &s->rsa_key)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read public key");
		return FALSE;
	}

	s->last_refresh = time(NULL);

	return TRUE;
}

// }}}
// {{{ mega_session_refresh

gboolean mega_session_refresh(struct mega_session *s, GError **err)
{
	GError *local_err = NULL;
	GSList *list = NULL;
	gint i, l;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// prepare request
	gc_free gchar *f_node = api_call(s, 'o', NULL, &local_err, "[{a:f, c:1}]");
	if (!f_node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	if (mega_debug & MEGA_DEBUG_FS)
		print_node(f_node, "FS: ");

	// process 'ok' array
	const gchar *ok_node = s_json_get_member(f_node, "ok");
	if (ok_node && s_json_get_type(ok_node) == S_JSON_TYPE_ARRAY) {
		gc_free gchar **oks = s_json_get_elements(ok_node);

		for (i = 0, l = g_strv_length(oks); i < l; i++) {
			const gchar *ok = oks[i];
			if (s_json_get_type(ok) != S_JSON_TYPE_OBJECT)
				continue;

			gc_free gchar *ok_h = s_json_get_member_string(ok, "h"); // h.8
			gc_free gchar *ok_ha = s_json_get_member_string(ok, "ha"); // b64(aes(h.8 h.8, master_key))
			gc_free gchar *ok_k =
				s_json_get_member_string(ok, "k"); // b64(aes(share_key_for_h, master_key))

			if (!ok_h || !ok_ha || !ok_k) {
				g_printerr(
					"WARNING: Skipping import of a key %s because it's missing required attributes\n",
					ok_h);
				continue;
			}

			if (!handle_auth(ok_h, ok_ha, s->master_key)) {
				g_printerr("WARNING: Skipping import of a key %s because it's authentication failed\n",
					   ok_h);
				continue;
			}

			//g_print("Importing key %s:%s\n", ok_h, ok_k);

			gc_free guchar *key = b64_aes128_decrypt(ok_k, s->master_key, NULL);

			add_share_key(s, ok_h, key);
		}
	}

	// process 'f' array
	const gchar *ff_node = s_json_get_member(f_node, "f");
	if (!ff_node || s_json_get_type(ff_node) != S_JSON_TYPE_ARRAY) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote filesystem 'f' node is invalid");
		return FALSE;
	}

	gc_free gchar **ff_arr = s_json_get_elements(ff_node);
	for (i = 0, l = g_strv_length(ff_arr); i < l; i++) {
		const gchar *f = ff_arr[i];
		if (s_json_get_type(f) != S_JSON_TYPE_OBJECT)
			continue;

		struct mega_node *n = mega_node_parse(s, f);
		if (n)
			list = g_slist_prepend(list, n);
	}

	// import special root node for contacts
	struct mega_node *n = g_new0(struct mega_node, 1);
	n->s = s;
	n->name = g_strdup("Contacts");
	n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
	n->handle = g_strdup("NETWORK");
	n->type = MEGA_NODE_NETWORK;
	list = g_slist_prepend(list, n);

	// process 'u' array
	const gchar *u_node = s_json_get_member(f_node, "u");
	if (u_node && s_json_get_type(u_node) == S_JSON_TYPE_ARRAY) {
		gc_free gchar **u_arr = s_json_get_elements(u_node);
		for (i = 0, l = g_strv_length(u_arr); i < l; i++) {
			const gchar *u = u_arr[i];
			if (s_json_get_type(u) != S_JSON_TYPE_OBJECT)
				continue;

			gint64 u_c = s_json_get_member_int(u, "c", 0);

			// skip self and removed
			if (u_c != 1)
				continue;

			struct mega_node *n = mega_node_parse_user(s, u);
			if (n)
				list = g_slist_prepend(list, n);
		}
	}

	// replace existing nodes
	g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
	s->fs_nodes = g_slist_reverse(list);

	build_node_tree(s);

	s->last_refresh = time(NULL);

	return TRUE;
}

// }}}
// {{{ mega_session_addlinks

gboolean mega_session_addlinks(struct mega_session *s, GSList *nodes, GError **err)
{
	GError *local_err = NULL;
	GSList *i;
	gc_ptr_array_unref GPtrArray *rnodes = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	if (g_slist_length(nodes) == 0)
		return TRUE;

	rnodes = g_ptr_array_sized_new(g_slist_length(nodes));

	// prepare request
	SJsonGen *gen = s_json_gen_new();
	s_json_gen_start_array(gen);
	for (i = nodes; i; i = i->next) {
		struct mega_node *n = i->data;

		if (n->type == MEGA_NODE_FILE) {
			s_json_gen_start_object(gen);
			s_json_gen_member_string(gen, "a", "l");
			s_json_gen_member_string(gen, "n", n->handle);
			s_json_gen_end_object(gen);

			g_ptr_array_add(rnodes, n);
		}
	}
	s_json_gen_end_array(gen);
	gc_free gchar *request = s_json_gen_done(gen);

	// perform request
	gc_free gchar *response = api_request(s, request, &local_err);

	// process response
	if (!response) {
		g_propagate_prefixed_error(err, local_err, "API call 'l' failed: ");
		return FALSE;
	}

	if (s_json_get_type(response) == S_JSON_TYPE_ARRAY) {
		gc_free gchar **nodes_arr = s_json_get_elements(response);
		gint i, l = g_strv_length(nodes_arr);

		if (l != rnodes->len) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "API call 'l' results mismatch");
			return FALSE;
		}

		for (i = 0; i < l; i++) {
			gchar *link = s_json_get_string(nodes_arr[i]);

			struct mega_node *n = g_ptr_array_index(rnodes, i);

			g_free(n->link);
			n->link = link;
		}
	}

	return TRUE;
}

// }}}
// {{{ mega_session_user_quota

struct mega_user_quota *mega_session_user_quota(struct mega_session *s, GError **err)
{
	GError *local_err = NULL;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	// prepare request
	gc_free gchar *quota_node = api_call(s, 'o', NULL, &local_err, "[{a:uq, strg:1, xfer:1, pro:1}]");
	if (!quota_node) {
		g_propagate_error(err, local_err);
		return NULL;
	}

	struct mega_user_quota *q = g_new0(struct mega_user_quota, 1);

	q->total = s_json_get_member_int(quota_node, "mstrg", 0);
	q->used = s_json_get_member_int(quota_node, "cstrg", 0);

	return q;
}

// }}}

// {{{ mega_session_ls_all

// free gslist, not the data
GSList *mega_session_ls_all(struct mega_session *s)
{
	GSList *list = NULL;

	g_return_val_if_fail(s != NULL, NULL);

	return g_slist_copy(s->fs_nodes);
}

// }}}
// {{{ mega_session_ls

struct ls_data {
	GSList *list;
	gchar *path;
	gboolean recursive;
};

static void _ls(struct mega_node *n, struct ls_data *data)
{
	gchar path[4096];
	if (mega_node_get_path(n, path, sizeof(path))) {
		if (g_str_has_prefix(path, data->path) && (data->recursive || !strchr(path + strlen(data->path), '/')))
			data->list = g_slist_prepend(data->list, n);
	}
}

// free gslist, not the data
GSList *mega_session_ls(struct mega_session *s, const gchar *path, gboolean recursive)
{
	struct ls_data data;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(path != NULL, NULL);

	gc_free gchar *tmp = path_simplify(path);

	if (!strcmp(tmp, "/"))
		data.path = g_strdup("/");
	else
		data.path = g_strdup_printf("%s/", tmp);
	data.recursive = recursive;
	data.list = NULL;

	g_slist_foreach(s->fs_nodes, (GFunc)_ls, &data);

	g_free(data.path);
	return data.list;
}

// }}}
// {{{ mega_session_stat

struct mega_node *mega_session_stat(struct mega_session *s, const gchar *path)
{
	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(path != NULL, NULL);

	gc_free gchar *tmp = path_simplify(path);

	GSList *iter;
	gchar n_path[4096];
	for (iter = s->fs_nodes; iter; iter = iter->next) {
		struct mega_node *n = iter->data;

		if (mega_node_get_path(n, n_path, sizeof(n_path))) {
			if (!strcmp(n_path, tmp))
				return n;
		}
	}

	return NULL;
}

// }}}
// {{{ mega_session_get_node_chilren

static gint node_name_compare(const struct mega_node *a, const struct mega_node *b)
{
	if (a->name_collate_key == NULL && b->name_collate_key == NULL)
		return 0;
	if (a->name_collate_key == NULL)
		return -1;
	if (b->name_collate_key == NULL)
		return 1;

	return strcmp(a->name_collate_key, b->name_collate_key);
}

GSList *mega_session_get_node_chilren(struct mega_session *s, struct mega_node *node)
{
	GSList *list = NULL, *i;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(node->handle != NULL, NULL);

	for (i = s->fs_nodes; i; i = i->next) {
		struct mega_node *child = i->data;

		if (child->parent_handle && !strcmp(child->parent_handle, node->handle))
			list = g_slist_insert_sorted(list, child, (GCompareFunc)node_name_compare);
	}

	return list;
}

// }}}
// {{{ mega_session_mkdir

struct mega_node *mega_session_mkdir(struct mega_session *s, const gchar *path, GError **err)
{
	GError *local_err = NULL;
	struct mega_node *n = NULL;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(path != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	struct mega_node *d = mega_session_stat(s, path);
	if (d) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory already exists: %s", path);
		return NULL;
	}

	gc_free gchar *tmp = path_simplify(path);
	gc_free gchar *parent_path = g_path_get_dirname(tmp);

	if (!strcmp(parent_path, "/")) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't create toplevel dir: %s", path);
		return NULL;
	}

	struct mega_node *p = mega_session_stat(s, parent_path);
	if (!p || p->type == MEGA_NODE_FILE || p->type == MEGA_NODE_INBOX) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory doesn't exist: %s", parent_path);
		return NULL;
	}

	if (!mega_node_is_writable(s, p)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory is not writable: %s", parent_path);
		return NULL;
	}

	if (p->type == MEGA_NODE_NETWORK) {
		// prepare contact add request
		gc_free gchar *ur_node = api_call(s, 'o', NULL, &local_err, "[{a:ur, u:%S, l:1, i:%s}]",
						  g_path_get_basename(tmp), s->rid);
		if (!ur_node) {
			g_propagate_error(err, local_err);
			return NULL;
		}

		// parse response
		n = mega_node_parse_user(s, ur_node);
		if (!n) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
			return NULL;
		}
	} else {
		gc_free guchar *node_key = make_random_key();
		gc_free gchar *basename = g_path_get_basename(tmp);
		gc_free gchar *attrs = encode_node_attrs(basename);
		gc_free gchar *dir_attrs = b64_aes128_cbc_encrypt_str(attrs, node_key);
		gc_free gchar *dir_key = b64_aes128_encrypt(node_key, 16, s->master_key);

		// prepare request
		gc_free gchar *mkdir_node =
			api_call(s, 'o', NULL, &local_err, "[{a:p, t:%s, i:%s, n: [{h:xxxxxxxx, t:1, k:%s, a:%s}]}]",
				 p->handle, s->rid, dir_key, dir_attrs);
		if (!mkdir_node) {
			g_propagate_error(err, local_err);
			return NULL;
		}

		const gchar *f_arr = s_json_get_member(mkdir_node, "f");
		if (s_json_get_type(f_arr) != S_JSON_TYPE_ARRAY) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
			return NULL;
		}

		const gchar *f_el = s_json_get_element(f_arr, 0);
		if (!f_el || s_json_get_type(f_el) != S_JSON_TYPE_OBJECT) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
			return NULL;
		}

		n = mega_node_parse(s, f_el);
		if (!n) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
			return NULL;
		}
	}

	// add mkdired node to the filesystem
	s->fs_nodes = g_slist_append(s->fs_nodes, n);
	build_node_tree(s);

	return n;
}

// }}}
// {{{ mega_session_rm

gboolean mega_session_rm(struct mega_session *s, const gchar *path, GError **err)
{
	GError *local_err = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	struct mega_node *mn = mega_session_stat(s, path);
	if (!mn) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File not found: %s", path);
		return FALSE;
	}

	if (!mega_node_is_writable(s, mn)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File is not removable: %s", path);
		return FALSE;
	}

	if (mn->type == MEGA_NODE_FILE || mn->type == MEGA_NODE_FOLDER) {
		// prepare request
		gc_free gchar *rm_node = api_call(s, 'i', NULL, &local_err, "[{a:d, i:%s, n:%s}]", s->rid, mn->handle);
		if (!rm_node) {
			g_propagate_error(err, local_err);
			return FALSE;
		}
	} else if (mn->type == MEGA_NODE_CONTACT) {
		gc_free gchar *ur_node =
			api_call(s, 'i', NULL, &local_err, "[{a:ur, u:%s, l:0, i:%s}]", mn->handle, s->rid);
		if (!ur_node) {
			g_propagate_error(err, local_err);
			return FALSE;
		}
	} else {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't remove system dir %s", path);
		return FALSE;
	}

	GSList *i, *i_next, **i_prev_next = &s->fs_nodes;
	GSList *free_list = NULL;

	// remove node and all the children from the list
	for (i = s->fs_nodes; i; i = i_next) {
		struct mega_node *n = i->data;

		i_next = i->next;

		if (n == mn || mega_node_has_ancestor(n, mn)) {
			// drop link
			*i_prev_next = i_next;
			g_slist_free_1(i);

			// we can't free the node right here, because it
			// needs to be available for
			// mega_node_has_ancestor checks
			free_list = g_slist_prepend(free_list, n);
		} else {
			// move next address of previously kept node
			i_prev_next = &i->next;
		}
	}

	g_slist_free_full(free_list, (GDestroyNotify)mega_node_free);

	return TRUE;
}

// }}}
// {{{ mega_session_new_node_attribute

gchar *mega_session_new_node_attribute(struct mega_session *s, const guchar *data, gsize len, const gchar *type,
				       const guchar *key, GError **err)
{
	GError *local_err = NULL;
	AES_KEY k;
	guchar iv[AES_BLOCK_SIZE] = { 0 };
	gsize pad = len % 16 ? 16 - (len % 16) : 0;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(len > 0, NULL);
	g_return_val_if_fail(type != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	gc_free gchar *ufa_node = api_call(s, 'o', NULL, &local_err, "[{a:ufa, s:%i, ssl:0}]", (gint64)len + pad);
	if (!ufa_node) {
		g_propagate_error(err, local_err);
		return NULL;
	}

	gc_free gchar *p_url = s_json_get_member_string(ufa_node, "p");

	// encrypt
	AES_set_encrypt_key(key, 128, &k);
	gc_free guchar *plain = g_memdup(data, len);
	plain = g_realloc(plain, len + pad);
	memset(plain + len, 0, pad);
	gc_free guchar *cipher = g_malloc0(len + pad);
	AES_cbc_encrypt(plain, cipher, len + pad, &k, iv, 1);

	// upload
	gc_http_free struct http *h = http_new();
	http_set_proxy(h, s->proxy);
	http_set_content_type(h, "application/octet-stream");
	gc_string_free GString *handle = http_post(h, p_url, cipher, len + pad, &local_err);

	if (!handle) {
		g_propagate_prefixed_error(err, local_err, "Node attribute data upload failed: ");
		return NULL;
	}

	if (handle->len != 8) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Node attribute handle is invalid");
		return NULL;
	}

	gc_free gchar *b64_handle = base64urlencode(handle->str, handle->len);

	return g_strdup_printf("%s*%s", type, b64_handle);
}

// }}}

// {{{ Data transfer manager
// ---------------------
//
// ATM this supports parallel chunked transfer of data without breaking the
// assumptions of the original code about upload/downlad call being a blocking
// operation.
//
// How it works:
//
// - It uses threaded design where threads communicate by passing messages to
//   each other. Threads never modify other threads' data while the other
//   threads are running.
// - Main thread issues transfer requests to the transfer manager thread and
//   waits for messages about progress/completion on the submitter_mailbox,
//   which is part of the transfer. When it gets a message about transfer
//   completion it returns.
// - Manager thread picks up a manager_mailbox and processes transfer
//   submissions from the main thread, prepares incomming transfer submissions
//   by splitting transfers into chunks and by keeping the list of queued
//   transfers. It also schedules chunk transfers by passing chunks for
//   actual download or upload to the worker pool. It also listens for messages
//   about chunk status changes from the worker threads and schedules
//   new trasnfers or processes transfer completions.
// - Worker threads are started to download or upload the chunk and report
//   the progress and the final result to the manager.
//
// Memory:
//
// - Messages are allocated by the sender and freed by the receiver.
// - Transfer is allocated on the stack of the main thread ATM.
// - Chunks are allocated and freed by the manager thread.
// - Worker threads allocate and free the http client and temporary
//   buffer for the chunk data.
//
// Locking:
//
// - It is necessary to serialize access to the file data stream via stream_lock.
// - Workers need to sycnhronize access to transfer data:
//   - upload_handle
//   - transfered_size
// - Other than that, all synchronization is handled by the message queues.

#define tman_debug(fmt, args...)                                                                                       \
	G_STMT_START                                                                                                   \
	{                                                                                                              \
		if (mega_debug & MEGA_DEBUG_TMAN)                                                                     \
			g_print("%" G_GINT64_FORMAT ": " fmt, g_get_monotonic_time(), ##args);                         \
	}                                                                                                              \
	G_STMT_END

enum { 
	CHUNK_STATE_QUEUED = 0,
	CHUNK_STATE_IN_PROGRESS,
	CHUNK_STATE_DONE,
};

struct transfer_chunk_mac {
	guchar mac[16];
	guint off;
	guint size;
};

struct transfer_chunk {
	gint status;
	gint failures_count; // number of failures when retrying
	struct transfer *transfer;

	goffset offset;
	goffset size;
	goffset transfered_size;
	guint index;

	gint64 start_at;

	int n_macs;
	struct transfer_chunk_mac macs[];
};

enum {
	TRANSFER_WORKER_MSG_STOP = 1,
	TRANSFER_WORKER_MSG_UPLOAD_CHUNK,
};

struct transfer_worker_msg {
	gint type;

	struct transfer_chunk* chunk;
	//GError *error;
};

struct transfer_worker {
	gint index;
	gboolean busy;
	GThread* thread;
	GAsyncQueue* mailbox;
};

enum {
	TRANSFER_MSG_DONE = 1,
	TRANSFER_MSG_PROGRESS,
	TRANSFER_MSG_ERROR,
};

struct transfer_msg {
	gint type;

	gchar *upload_handle;
	guchar meta_mac[16];

	goffset total_size;
	goffset transfered_size;

	GError *error;
};

struct transfer {
	// queue for sending mesages to a submitter
	GAsyncQueue *submitter_mailbox;

	GSList *chunks;
	goffset total_size;
	goffset transfered_size;

	AES_KEY k;
	guchar file_key[16];
	guchar nonce[16];

	// file access is serialized with this mutex
	GMutex stream_lock;

	// for upload
	GFileInputStream *istream;
	const gchar *upload_url;
	gchar *upload_handle;

	// for download
	GFileOutputStream *ostream;
	const gchar *download_url;

	// HTTP options
	gint max_ul;
	gint max_dl;
	gchar *proxy;

	// transfer is in error state, will be aborted
	GError *error;
};

enum { 
	TRANSFER_MANAGER_MSG_SUBMIT_TRANSFER = 1,
	TRANSFER_MANAGER_MSG_CHUNK_PROGRESS,
	TRANSFER_MANAGER_MSG_CHUNK_FAILED,
	TRANSFER_MANAGER_MSG_CHUNK_DONE,
	TRANSFER_MANAGER_MSG_STOP,
};

struct transfer_manager_msg {
	gint type;
	struct transfer *transfer;
	struct transfer_chunk *chunk;
	struct transfer_worker* worker;
	goffset transfered_size; // how many bytes of a chunk have been transfered
	gchar *upload_handle; // can be sent with the last chunk update
	GError *error;
};

struct transfer_manager {
	GAsyncQueue *manager_mailbox;
	GThread *manager_thread;

	// only manager thread accesses these after it is started:
	struct transfer_worker *workers;
	int max_workers;
	int current_workers;
	GList *transfers;
};

static struct transfer_manager tman;

static gboolean tman_transfer_progress(goffset dltotal, goffset dlnow, goffset ultotal, goffset ulnow,
				       gpointer user_data)
{
	struct transfer_chunk *c = user_data;
	struct transfer_manager_msg *msg;

	//tman_debug("W: progress for chunk %d (status=%d)\n", c->index, c->status);

	msg = g_new0(struct transfer_manager_msg, 1);
	msg->type = TRANSFER_MANAGER_MSG_CHUNK_PROGRESS;
	msg->chunk = c;
	msg->transfered_size = MIN(ulnow, c->size);
	g_async_queue_push(tman.manager_mailbox, msg);

	return TRUE;
}

static gchar* upload_checksum(const guchar* data, gsize len)
{
	guchar crc[12] = {0};
	gsize i;

	for (i = 0; i < len; i++)
		crc[i % sizeof crc] ^= data[i];

	return base64urlencode(crc, sizeof crc);
}

// accesses:
// - chunk: size, index, offset, mac
// - transfer: stream_lock, istream, nonce, file_key, upload_url, max_ul, max_dl, proxy
static void tman_worker_upload_chunk(struct transfer_chunk *c, struct transfer_worker* worker, struct http* h)
{
	struct transfer *t = c->transfer;
	struct transfer_manager_msg *msg;
	gsize bytes_read;
	GError *err = NULL;
	GError *local_err = NULL;
	gc_free gchar *url = NULL;
	gc_string_free GString *response = NULL;
	gc_free gchar* chksum = NULL;

	tman_debug("W[%d]: started for chunk %d\n", worker->index, c->index);

	// load plaintext data into a buffer from the file

	gc_free guchar *buf = g_malloc(c->size);

	g_mutex_lock(&t->stream_lock);

	if (!g_seekable_seek(G_SEEKABLE(t->istream), c->offset, G_SEEK_SET, NULL, &local_err)) {
		g_mutex_unlock(&t->stream_lock);
		err = g_error_new(MEGA_ERROR, MEGA_ERROR_OTHER, "Failed seeking in the stream: %s", local_err->message);
		g_clear_error(&local_err);
		goto err;
	}

	if (!g_input_stream_read_all(G_INPUT_STREAM(t->istream), buf, c->size, &bytes_read, NULL, &local_err)) {
		g_mutex_unlock(&t->stream_lock);
		err = g_error_new(MEGA_ERROR, MEGA_ERROR_OTHER, "Failed reading from the stream: %s",
				  local_err->message);
		g_clear_error(&local_err);
		goto err;
	}

	g_mutex_unlock(&t->stream_lock);

	if (bytes_read != c->size) {
		err = g_error_new(MEGA_ERROR, MEGA_ERROR_OTHER, "Failed reading from the stream (premature end)");
		goto err;
	}

	// perform encryption and chunk mac calculation
	guchar iv[AES_BLOCK_SIZE] = { 0 };
	memcpy(iv, t->nonce, 8);
	*((guint64 *)&iv[8]) = GUINT64_TO_BE((guint64)(c->offset / 16)); // this is ok, because chunks are 16b aligned

	for (int i = 0; i < c->n_macs; i++)
		chunk_mac_calculate(t->nonce, t->file_key, buf + c->macs[i].off, c->macs[i].size, c->macs[i].mac);

	if (!encrypt_aes128_ctr(buf, buf, c->size, t->file_key, iv)) {
		err = g_error_new(MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to encrypt data");
		goto err;
	}

	// prepare URL including chunk offset
	chksum = upload_checksum(buf, c->size);
	url = g_strdup_printf("%s/%" G_GOFFSET_FORMAT "?c=%s", t->upload_url, c->offset, chksum);

	// perform upload POST
	http_set_content_type(h, "application/octet-stream");
	http_set_progress_callback(h, tman_transfer_progress, c);
	http_set_speed(h, t->max_ul, t->max_dl);
	http_set_proxy(h, t->proxy);
	response = http_post(h, url, buf, c->size, &local_err);
	if (!response) {
		g_propagate_prefixed_error(&err, local_err, "Chunk upload failed: ");
		goto err;
	}

	gchar *upload_handle = NULL;

	if (response->len > 0) {
		// check for numeric error code
		if (response->len < 10 && g_regex_match_simple("^-(\\d+)$", response->str, 0, 0)) {
			int code = atoi(response->str);
			const char* err_str = "???";

			switch (code) {
				case -3:
					err_str = "EAGAIN";
					break;
				case -4:
					err_str = "EFAILED";
					break;
				case -5:
					err_str = "ENOTFOUND";
					break;
				case -6:
					err_str = "ETOOMANY";
					break;
				case -7:
					err_str = "ERANGE";
					break;
				case -8:
					err_str = "EEXPIRED";
					break;
				case -14:
					err_str = "EKEY";
					break;
			}

			err = g_error_new(MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error code %d (%s)", code, err_str);
			goto err;
		}

		if (response->len == 36) {
			upload_handle = base64urlencode(response->str, response->len);

			// we've got the handle
			tman_debug("W[%d]: got upload data handle with chunk %d: '%s'\n", worker->index, c->index, upload_handle);
		} else {
			err = g_error_new(MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned something that does not look like upload handle");
			goto err;
		}
	}

	tman_debug("W[%d]: success for chunk %d\n", worker->index, c->index);

	// final progress update for 100%
	msg = g_new0(struct transfer_manager_msg, 1);
	msg->type = TRANSFER_MANAGER_MSG_CHUNK_PROGRESS;
	msg->chunk = c;
	msg->transfered_size = c->size;
	g_async_queue_push(tman.manager_mailbox, msg);

	// send success to the manager
	msg = g_new0(struct transfer_manager_msg, 1);
	msg->type = TRANSFER_MANAGER_MSG_CHUNK_DONE;
	msg->chunk = c;
	msg->worker = worker;
	msg->upload_handle = upload_handle;
	g_async_queue_push(tman.manager_mailbox, msg);
	return;

err:
	tman_debug("W[%d]: error for chunk %d: %s\n", worker->index, c->index, err->message);

	// final progress update for 0% (because we failed to transfer the chunk)
	msg = g_new0(struct transfer_manager_msg, 1);
	msg->type = TRANSFER_MANAGER_MSG_CHUNK_PROGRESS;
	msg->chunk = c;
	msg->transfered_size = 0;
	g_async_queue_push(tman.manager_mailbox, msg);

	// send error to the manager
	msg = g_new0(struct transfer_manager_msg, 1);
	msg->type = TRANSFER_MANAGER_MSG_CHUNK_FAILED;
	msg->chunk = c;
	msg->worker = worker;
	msg->error = err;
	g_async_queue_push(tman.manager_mailbox, msg);
}

// performs single http send operation
static gpointer tman_worker_thread_fn(gpointer data)
{
	struct transfer_worker* w = data;
	gc_http_free struct http *h = NULL;

	h = http_new();
	http_expect_short_running(h);
	http_set_max_connects(h, 2);

	while (TRUE) {
		struct transfer_worker_msg *msg = g_async_queue_timeout_pop(w->mailbox, 1000);
		if (!msg) {
			continue;
		}

		switch (msg->type) {
		case TRANSFER_WORKER_MSG_STOP:
			g_free(msg);
			return NULL;

		case TRANSFER_WORKER_MSG_UPLOAD_CHUNK:
			tman_worker_upload_chunk(msg->chunk, w, h);
			g_free(msg);
			break;
		}
	}

	return NULL;
}

static void schedule_chunk_transfers(void)
{
	GList *ti, *ti_next;
	GSList *ci;
	struct transfer_msg *tmsg;
	gint64 now = g_get_monotonic_time();

	// first submit chunks to workers
	for (ti = tman.transfers; ti; ti = ti->next) {
		struct transfer *t = ti->data;

		// skip errored out transfers
		if (t->error)
			continue;

		for (ci = t->chunks; ci; ci = ci->next) {
			struct transfer_chunk *c = ci->data;

			// if the chunk is scheduled to be started in the
			// future, skip it
                        if (c->start_at > now)
				continue;

			// stop if we can't start more chunk transfers
			if (tman.current_workers >= tman.max_workers)
				goto check_completed;

			// start chunk transfer
			if (c->status == CHUNK_STATE_QUEUED) {
				tman_debug("M: chunk %d pushed to worker\n", c->index);

				for (int i = 0; i < tman.max_workers; i++) {
					if (!tman.workers[i].busy) {
						tman.workers[i].busy = TRUE;

						c->status = CHUNK_STATE_IN_PROGRESS;
						tman.current_workers++;

						struct transfer_worker_msg *msg = g_new0(struct transfer_worker_msg, 1);
						msg->type = TRANSFER_WORKER_MSG_UPLOAD_CHUNK;
						msg->chunk = c;
						g_async_queue_push(tman.workers[i].mailbox, msg);
						goto queued;
					}
				}

				goto check_completed;

queued:;
			}
		}
	}

check_completed:

	// next check for finished transfers
	for (ti = tman.transfers; ti; ti = ti_next) {
		struct transfer *t = ti->data;

		ti_next = ti->next;

		// if some chunks are in flight or queued and transfer is not
		// aborted, we are not done yet
		gboolean is_finished = TRUE;
		for (ci = t->chunks; ci; ci = ci->next) {
			struct transfer_chunk *c = ci->data;

			if (c->status == CHUNK_STATE_IN_PROGRESS || (c->status == CHUNK_STATE_QUEUED && !t->error)) {
				is_finished = FALSE;
				break;
			}
		}

		if (!is_finished)
			continue;

		if (!t->error && !t->upload_handle) {
			// mega did not return upload handle with the last
			// uploaded chunk, WTF?
			t->error = g_error_new(MEGA_ERROR, MEGA_ERROR_NO_HANDLE, "Mega didn't return an upload handle");
		}

		// remove transfer from the list
		tman.transfers = g_list_delete_link(tman.transfers, ti);

		tmsg = g_new0(struct transfer_msg, 1);

		if (t->error) {
			tman_debug("M: transfer %s failed\n", t->upload_url);

			tmsg->type = TRANSFER_MSG_ERROR;
			tmsg->error = t->error;
			t->error = NULL;
		} else {
			tman_debug("M: transfer %s succeeded\n", t->upload_url);

			tmsg->type = TRANSFER_MSG_DONE;

			// calculate meta_mac
			GSList *macs = NULL;
			for (ci = t->chunks; ci; ci = ci->next) {
				struct transfer_chunk *c = ci->data;
				for (int i = 0; i < c->n_macs; i++)
					macs = g_slist_prepend(macs, c->macs[i].mac);
			}
			macs = g_slist_reverse(macs);
			meta_mac_calculate(macs, t->file_key, tmsg->meta_mac);
                        g_slist_free(macs);

			tmsg->upload_handle = t->upload_handle;
		}

		g_slist_free_full(t->chunks, g_free);
		t->chunks = NULL;

		g_async_queue_push(t->submitter_mailbox, tmsg);
	}
}

static int get_n_chunks(guint idx, guint size, guint* rounded_size)
{
	if (idx < 7) {
		// special algo
		guint i = 0;
		guint csize = 0;

		while (csize < size) {
			csize += get_chunk_size(idx);
			idx++;
			i++;
		}

		*rounded_size = csize;
		return i;
	} else {
		guint rem = size % (1024 * 1024);
		int n = size / (1024 * 1024) + (rem > 0 ? 1 : 0);

		*rounded_size = n * 1024 * 1024;

		return n;
	}
}

static void prepare_transfer(struct transfer *t)
{
	// create list of chunks and initialize it
	// get number of chunks from total size
	gint64 now = g_get_monotonic_time();
	goffset off = 0;
	guint chunk_idx = 0, mac_idx = 0;

	// Here we create a list of chunks that will be used for transfer.
	// For bigger files, we can create bigger chunks. When creating
	// bigger chunks we need to account for a fact that chunk mac is
	// calculated from a fixed pattern of chunk sizes that we can't modify.
	//
	// First 8 chunks are 128 kiB * index sized, the rest is 1 MiB sized.
	//
	// We pre-define this pattern in the macs array of n_macs size.

	//XXX: mega largely works, but craps out EFAILs on too many connections when coalescing chunks so
	// let's disable boost for now.
	gboolean boost = FALSE;
        if (boost) {
		while (off < t->total_size) {
			goffset max_size = 16 * 1024 * 1024;
			if (chunk_idx < 3)
				max_size = 4 * 1024 * 1024;

			guint size = MIN(t->total_size - off, max_size);
			guint rounded_size;
			int num_mac_chunks = get_n_chunks(mac_idx, size, &rounded_size);
			size = MIN(t->total_size - off, rounded_size);

			struct transfer_chunk *c = g_malloc0(sizeof(struct transfer_chunk) + sizeof(struct transfer_chunk_mac) * num_mac_chunks);

			c->offset = off;
			c->size = size;
			c->index = chunk_idx;
			c->status = CHUNK_STATE_QUEUED;
			c->transfer = t;
			c->start_at = now + (chunk_idx < 4 ? chunk_idx : 4) * 200000;

			c->n_macs = num_mac_chunks;

			guint mac_off = 0;
			for (int i = 0; i < num_mac_chunks; i++) {
				c->macs[i].off = mac_off;
				c->macs[i].size = MIN(get_chunk_size(mac_idx), size - mac_off);

				mac_idx++;
				mac_off += c->macs[i].size;
			}

			t->chunks = g_slist_prepend(t->chunks, c);

			chunk_idx++;
			off += c->size;

			// curiously, I found that if the last chunk
			// is not coalesced, mega will not hang
			if (off == t->total_size && c->n_macs > 1) {
				off -= c->macs[c->n_macs - 1].size;
				c->size -= c->macs[c->n_macs - 1].size;
				c->n_macs--;
			}
		}
	} else {
		for (chunk_idx = 0; off < t->total_size; chunk_idx++) {
			struct transfer_chunk *c = g_malloc0(sizeof(struct transfer_chunk) + sizeof(struct transfer_chunk_mac) * 1);

			c->offset = off;
			c->size = MIN(t->total_size - off, get_chunk_size(chunk_idx));
			c->index = chunk_idx;
			c->status = CHUNK_STATE_QUEUED;
			c->transfer = t;
			c->start_at = now + (chunk_idx < 4 ? chunk_idx : 4) * 200000;

			c->n_macs = 1;
			c->macs[0].off = 0;
			c->macs[0].size = c->size;

			t->chunks = g_slist_prepend(t->chunks, c);

			off += c->size;
		}
	}

	t->chunks = g_slist_reverse(t->chunks);

#if 0
	GSList* it;
	for (it = t->chunks; it; it = it->next) {
		struct transfer_chunk *c = it->data;

		g_print("CH[%d] = { off=%" G_GOFFSET_FORMAT " size=%" G_GOFFSET_FORMAT " macs=%d }\n", c->index, c->offset, c->size, c->n_macs);
		for (int i = 0; i < c->n_macs; i++)
			g_print("  CMAC { off=%u size=%u }\n", c->macs[i].off, c->macs[i].size);
	}
#endif
}

static gpointer tman_manager_thread_fn(gpointer data)
{
	// keeps track of the workers
	//  - submits transfer_chunks to the workers
	// keeps tab on the individual trasnfers and
	//  - notifies transfer submitter when done
	//  - sends progress updates

	while (TRUE) {
		struct transfer_manager_msg *msg = g_async_queue_timeout_pop(tman.manager_mailbox, 100);
		struct transfer_msg *tmsg;
		struct transfer *t;
		struct transfer_chunk *c;

		if (!msg) {
			schedule_chunk_transfers();
			continue;
		}

		switch (msg->type) {
		case TRANSFER_MANAGER_MSG_STOP:
			g_free(msg);
			return NULL;

		case TRANSFER_MANAGER_MSG_SUBMIT_TRANSFER:
			t = msg->transfer;

			tman_debug("M: transfer submitted %s\n", t->upload_url);

			prepare_transfer(t);
			tman.transfers = g_list_append(tman.transfers, t);
			schedule_chunk_transfers();
			break;

		case TRANSFER_MANAGER_MSG_CHUNK_PROGRESS:
			c = msg->chunk;
			t = c->transfer;

			//tman_debug("M: chunk progress for %d\n", c->index);
			tmsg = g_new0(struct transfer_msg, 1);
			tmsg->type = TRANSFER_MSG_PROGRESS;

			// update overall progress
			t->transfered_size += msg->transfered_size - c->transfered_size;
			c->transfered_size = msg->transfered_size;

			tmsg->total_size = t->total_size;
			tmsg->transfered_size = t->transfered_size;

			g_async_queue_push(t->submitter_mailbox, tmsg);
			break;

		case TRANSFER_MANAGER_MSG_CHUNK_DONE:
			c = msg->chunk;
			t = c->transfer;

			tman_debug("M: chunk done %d\n", c->index);

			msg->worker->busy = FALSE;
			tman.current_workers--;

			c->status = CHUNK_STATE_DONE;
			if (msg->upload_handle) {
				g_free(t->upload_handle);
				t->upload_handle = msg->upload_handle;
			}

			schedule_chunk_transfers();
			break;
		case TRANSFER_MANAGER_MSG_CHUNK_FAILED: {
			c = msg->chunk;
			t = c->transfer;

			tman_debug("M: chunk fail %d\n", c->index);

			msg->worker->busy = FALSE;
			tman.current_workers--;

			// re-queue chunk
			c->status = CHUNK_STATE_QUEUED;

			gint64 now = g_get_monotonic_time();

			if (t->error) {
				// transfer is in error state and is being aborted
				tman_debug("M: transfer is being aborted, chunk %d fail ignored\n", c->index);
			} else {
				if (g_error_matches(msg->error, HTTP_ERROR, HTTP_ERROR_COMM_FAILURE)
						|| g_error_matches(msg->error, HTTP_ERROR, HTTP_ERROR_TIMEOUT)
						|| g_error_matches(msg->error, HTTP_ERROR, HTTP_ERROR_SERVER_BUSY)
						|| g_error_matches(msg->error, HTTP_ERROR, HTTP_ERROR_NO_RESPONSE)) {
					if (c->failures_count > 8) {
						g_printerr("WARNING: chunk upload failed too many times (%s), aborting transfer\n", msg->error->message);

						// mark transfer as aborted
						t->error = msg->error;
						msg->error = NULL;
					} else {
						g_printerr("WARNING: chunk upload failed (%s), re-trying after %d seconds\n", msg->error->message, (1 << c->failures_count));
						c->start_at = g_get_monotonic_time() + 1000 * 1000 * ((1 << c->failures_count));
						c->failures_count++;
					}
				} else if (g_error_matches(msg->error, HTTP_ERROR, HTTP_ERROR_BANDWIDTH_LIMIT)) {
					// we need to defer all further
					// transfers by a lot
					g_printerr("WARNING: over upload quota, delaying all transfers by 5 minutes\n");
					GSList* ci;
					for (ci = t->chunks; ci; ci = ci->next) {
						struct transfer_chunk *c = ci->data;

						c->start_at = now + 1000 * (5*60*1000 + g_random_int_range(0, 2000));
					}
				} else {
					g_printerr("WARNING: chunk upload failed (%s), aborting transfer\n", msg->error->message);

					// mark transfer as aborted
					t->error = msg->error;
					msg->error = NULL;
				}
			}

			schedule_chunk_transfers();
			break;
		}

		default:
			g_assert_not_reached();
			break;
		}

		g_clear_error(&msg->error);
		g_free(msg);
	}

	return NULL;
}

static void tman_init(int max_workers)
{
	GError *local_err = NULL;

	// check if we are already initialized
	if (tman.manager_thread)
		return;

	memset(&tman, 0, sizeof tman);

	tman.manager_mailbox = g_async_queue_new();

	// start workers
	tman.max_workers = max_workers;
	tman.workers = g_new0(struct transfer_worker, max_workers);
	for (int i = 0; i < max_workers; i++) {
		tman.workers[i].index = i;
		tman.workers[i].mailbox = g_async_queue_new();
		tman.workers[i].thread = g_thread_new("transfer worker", tman_worker_thread_fn, &tman.workers[i]);
	}

	// start manager
	tman.manager_thread = g_thread_new("transfer manager", tman_manager_thread_fn, &tman);
}

static void tman_fini(void)
{
	if (tman.manager_thread) {
		// ask manager to stop
		struct transfer_manager_msg *msg = g_new0(struct transfer_manager_msg, 1);
		msg->type = TRANSFER_MANAGER_MSG_STOP;
		g_async_queue_push(tman.manager_mailbox, msg);

		g_thread_join(tman.manager_thread);

		for (int i = 0; i < tman.max_workers; i++) {
			struct transfer_worker_msg *msg = g_new0(struct transfer_worker_msg, 1);
			msg->type = TRANSFER_WORKER_MSG_STOP;
			g_async_queue_push(tman.workers[i].mailbox, msg);
		}

		for (int i = 0; i < tman.max_workers; i++) {
			g_thread_join(tman.workers[i].thread);
			g_async_queue_unref(tman.workers[i].mailbox);
		}

		g_free(tman.workers);
		g_async_queue_unref(tman.manager_mailbox);

		memset(&tman, 0, sizeof tman);
	}
}

static gboolean tman_run_upload_transfer(
	// in:
	struct mega_session *s, guchar file_key[16], guchar nonce[8], const gchar *upload_url,
	GFileInputStream *istream, goffset file_size,
	// out:
	gchar **upload_handle, guchar meta_mac[16], GError **err)
{
	struct transfer t = { 0 };
	gboolean retval = FALSE;
	struct mega_status_data status_data;

	g_return_val_if_fail(file_key != NULL, FALSE);
	g_return_val_if_fail(nonce != NULL, FALSE);
	g_return_val_if_fail(upload_url != NULL, FALSE);
	g_return_val_if_fail(istream != NULL, FALSE);
	g_return_val_if_fail(upload_handle != NULL, FALSE);
	g_return_val_if_fail(meta_mac != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// initialize transfer data
	t.submitter_mailbox = g_async_queue_new();
	t.total_size = file_size;
	AES_set_encrypt_key(file_key, 128, &t.k);
	memcpy(t.file_key, file_key, 16);
	memcpy(t.nonce, nonce, 8);
	g_mutex_init(&t.stream_lock);
	t.istream = istream;
	t.upload_url = upload_url;
	t.max_ul = s->max_ul;
	t.max_dl = s->max_dl;
	t.proxy = s->proxy;

	// tell the manager to start the transfer
	struct transfer_manager_msg *msg = g_new0(struct transfer_manager_msg, 1);
	msg->type = TRANSFER_MANAGER_MSG_SUBMIT_TRANSFER;
	msg->transfer = &t;
	g_async_queue_push(tman.manager_mailbox, msg);

	// send initial progress report
	status_data = (struct mega_status_data){
		.type = MEGA_STATUS_PROGRESS,
		.progress.total = file_size,
		.progress.done = -1,
	};

	send_status(s, &status_data);

	// wait until the transfer finishes
	while (TRUE) {
		struct transfer_msg *msg = g_async_queue_pop(t.submitter_mailbox);

		switch (msg->type) {
		case TRANSFER_MSG_DONE:
			*upload_handle = msg->upload_handle;
			memcpy(meta_mac, msg->meta_mac, 16);
			g_free(msg);
			retval = TRUE;
			goto out;

		case TRANSFER_MSG_ERROR:
			g_propagate_prefixed_error(err, msg->error, "Upload transfer failed: ");
			g_free(msg);
			goto out;

		case TRANSFER_MSG_PROGRESS:
			status_data = (struct mega_status_data){
				.type = MEGA_STATUS_PROGRESS,
				.progress.total = msg->total_size,
				.progress.done = msg->transfered_size,
			};

			send_status(s, &status_data);
			break;

		default:
			g_assert_not_reached();
		}

		g_free(msg);
	}

out:
	// send final progress report
	status_data = (struct mega_status_data){
		.type = MEGA_STATUS_PROGRESS,
		.progress.total = file_size,
		.progress.done = -2,
	};

	send_status(s, &status_data);

	// cleanup
	g_async_queue_unref(t.submitter_mailbox);
	g_mutex_clear(&t.stream_lock);
	return retval;
}

// }}}

// Download/upload:

// {{{ create_preview

static gint has_convert = -1;
static gint has_ffmpegthumbnailer = -1;

static gchar *create_preview(struct mega_session *s, const gchar *local_path, const guchar *key, GError **err)
{
	gchar *handle = NULL;
#ifndef G_OS_WIN32
	GError *local_err = NULL;
	gc_free gchar *tmp1 = NULL, *tmp2 = NULL;

	if (has_ffmpegthumbnailer < 0) {
		gc_free gchar *prg = g_find_program_in_path("ffmpegthumbnailer");

		has_ffmpegthumbnailer = prg ? 1 : 0;
	}

	if (has_convert < 0) {
		gc_free gchar *prg = g_find_program_in_path("convert");

		has_convert = prg ? 1 : 0;
	}

	if (has_ffmpegthumbnailer && g_regex_match_simple("\\.(mpg|mpeg|avi|mkv|flv|rm|mp4|wmv|asf|ram|mov)$",
							  local_path, G_REGEX_CASELESS, 0)) {
		gchar buf[50] = "/tmp/megatools.XXXXXX";
		gchar *dir = g_mkdtemp(buf);
		if (dir) {
			gint status = 1;
			gc_free gchar *thumb_path = g_strdup_printf("%s/thumb.jpg", dir);
			gc_free gchar *qpath = g_shell_quote(local_path);
			gc_free gchar *tmp = g_strdup_printf(
				"ffmpegthumbnailer -t 5 -i %s -o %s/thumb.jpg -s 128 -f -a", qpath, dir);

			if (g_spawn_command_line_sync(tmp, &tmp1, &tmp2, &status, &local_err)) {
				if (g_file_test(thumb_path, G_FILE_TEST_IS_REGULAR)) {
					gc_free gchar *thumb_data = NULL;
					gsize thumb_len;

					if (g_file_get_contents(thumb_path, &thumb_data, &thumb_len, NULL)) {
						handle = mega_session_new_node_attribute(s, thumb_data, thumb_len, "0",
											 key, &local_err);
						if (!handle)
							g_propagate_error(err, local_err);
					}

					g_unlink(thumb_path);
				}
			} else {
				g_propagate_error(err, local_err);
			}

			g_rmdir(dir);
		}
	} else if (has_convert && g_regex_match_simple("\\.(jpe?g|png|gif|bmp|tiff|svg|pnm|eps|ico|pdf)$", local_path,
						       G_REGEX_CASELESS, 0)) {
		gchar buf[50] = "/tmp/megatools.XXXXXX";
		gchar *dir = g_mkdtemp(buf);
		if (dir) {
			gint status = 1;
			gc_free gchar *thumb_path = g_strdup_printf("%s/thumb.jpg", dir);
			gc_free gchar *qpath = NULL;

			if (g_regex_match_simple("\\.pdf$", local_path, G_REGEX_CASELESS, 0)) {
				gc_free gchar *local_path_page = g_strdup_printf("%s[0]", local_path);

				qpath = g_shell_quote(local_path_page);
			} else {
				qpath = g_shell_quote(local_path);
			}

			gc_free gchar *tmp = g_strdup_printf(
				"convert %s -strip -background white -flatten -resize 128x128^ -gravity center -crop 128x128+0+0 +repage %s/thumb.jpg",
				qpath, dir);

			if (g_spawn_command_line_sync(tmp, &tmp1, &tmp2, &status, &local_err)) {
				if (g_file_test(thumb_path, G_FILE_TEST_IS_REGULAR)) {
					gc_free gchar *thumb_data = NULL;
					gsize thumb_len;

					if (g_file_get_contents(thumb_path, &thumb_data, &thumb_len, NULL)) {
						handle = mega_session_new_node_attribute(s, thumb_data, thumb_len, "0",
											 key, &local_err);
						if (!handle)
							g_propagate_error(err, local_err);
					}

					g_unlink(thumb_path);
				}
			} else {
				g_propagate_error(err, local_err);
			}

			g_rmdir(dir);
		}
	} else {
		return NULL;
	}

	if (!handle && err && !*err)
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't create preview");

#endif
	return handle;
}

// }}}
// {{{ mega_session_put

struct mega_node *mega_session_put(struct mega_session *s, struct mega_node *parent_node, const gchar* remote_name, GFileInputStream *stream, const gchar* local_path, GError **err)
{
	GError *local_err = NULL;
	gc_free gchar *up_handle = NULL;
	gc_free gchar *up_node = NULL;
	gc_free gchar *p_url = NULL;

	g_return_val_if_fail(s != NULL, NULL);
	g_return_val_if_fail(parent_node != NULL, NULL);
	g_return_val_if_fail(remote_name != NULL, NULL);
	g_return_val_if_fail(stream != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	gc_object_unref GFileInfo *info =
		g_file_input_stream_query_info(stream, G_FILE_ATTRIBUTE_STANDARD_SIZE, NULL, &local_err);
	if (!info) {
		g_propagate_prefixed_error(err, local_err, "Can't get stream info: ");
		return NULL;
	}

	goffset file_size = g_file_info_get_size(info);

	// setup encryption
	gc_free guchar *aes_key = make_random_key();
	gc_free guchar *nonce = make_random_key();
	guchar meta_mac[16];
	int retries = 3;
	gboolean transfer_ok;

	tman_init(s->max_workers);

try_again:
	// ask for upload url - [{"a":"u","ssl":0,"ms":0,"s":<SIZE>,"r":0,"e":0}]
	g_free(up_node);
	up_node = api_call(s, 'o', NULL, &local_err, "[{a:u, e:0, ms:0, r:0, s:%i, ssl:0, v:2}]", (gint64)file_size);
	if (!up_node) {
		g_propagate_error(err, local_err);
		return NULL;
	}

	g_free(p_url);
	p_url = s_json_get_member_string(up_node, "p");

	transfer_ok = tman_run_upload_transfer(
		/* in: */ s, aes_key, nonce, p_url, stream, file_size,
		/* out: */ &up_handle, meta_mac, &local_err);

	if (!transfer_ok) {
		if (retries-- > 0) {
			g_printerr("WARNING: Mega upload failed (%s), retrying transfer (%d retries left)\n", local_err ? local_err->message : "???", retries);
			g_clear_error(&local_err);
			goto try_again;
		}

		g_propagate_prefixed_error(err, local_err, "Data upload failed: ");
		return NULL;
	}

	// create preview
	gc_free gchar *fa = NULL;
	if (s->create_preview)
		fa = create_preview(s, local_path, aes_key, NULL);

	gc_free gchar *attrs = encode_node_attrs(remote_name);
	gc_free gchar *attrs_enc = b64_aes128_cbc_encrypt_str(attrs, aes_key);

	guchar node_key[32];
	pack_node_key(node_key, aes_key, nonce, meta_mac);

	gc_free gchar *node_key_enc = b64_aes128_encrypt(node_key, 32, s->master_key);

	// prepare request
	gc_free gchar *put_node =
		api_call(s, 'o', NULL, &local_err, "[{a:p, t:%s, n:[{h:%s, t:0, k:%s, a:%s, fa:%s}]}]",
			 parent_node->handle, up_handle, node_key_enc, attrs_enc, fa);
	if (!put_node) {
		g_propagate_error(err, local_err);
		return NULL;
	}

	const gchar *f_arr = s_json_get_member(put_node, "f");
	if (s_json_get_type(f_arr) != S_JSON_TYPE_ARRAY) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
		return NULL;
	}

	const gchar *f_el = s_json_get_element(f_arr, 0);
	if (!f_el || s_json_get_type(f_el) != S_JSON_TYPE_OBJECT) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
		return NULL;
	}

	struct mega_node *nn = mega_node_parse(s, f_el);
	if (!nn) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
		return NULL;
	}

	// add uploaded node to the filesystem
	s->fs_nodes = g_slist_append(s->fs_nodes, nn);
	nn->parent = parent_node;

	return nn;
}

// }}}
// {{{ mega_session_download_data

struct get_data_state {
	struct mega_session *s;
	GOutputStream *ostream;
	EVP_CIPHER_CTX *ctx;
	struct chunked_cbc_mac mac;
	struct chunked_cbc_mac mac_saved;
	guint64 progress_offset;
	guint64 progress_total;
};

static gboolean progress_dl(goffset dltotal, goffset dlnow, goffset ultotal, goffset ulnow, gpointer user_data)
{
	struct get_data_state *data = user_data;
	struct mega_status_data status_data = {
		.type = MEGA_STATUS_PROGRESS,
		.progress.total = data->progress_total,
		.progress.done = data->progress_offset + dlnow,
	};

	send_status(data->s, &status_data);

	return TRUE;
}

static gsize get_data_cb(gpointer buffer, gsize size, gpointer user_data)
{
	struct get_data_state *data = user_data;
	gc_error_free GError *local_err = NULL;
	int out_len;

	if (!EVP_EncryptUpdate(data->ctx, buffer, &out_len, buffer, size)) {
		g_printerr("ERROR: Failed to decrypt data during download\n");
		return 0;
	}

	if (out_len != size) {
		g_printerr("ERROR: Failed to decrypt data during download (out_len != size)\n");
		return 0;
	}

	if (!chunked_cbc_mac_update(&data->mac, buffer, size)) {
		g_printerr("ERROR: Failed to run mac calculator during download\n");
		return 0;
	}

	struct mega_status_data status_data = {
		.type = MEGA_STATUS_DATA,
		.data.size = size,
		.data.buf = buffer,
	};

	send_status(data->s, &status_data);

	if (!data->ostream)
		return size;

	if (!g_output_stream_write_all(data->ostream, buffer, size, NULL, NULL, &local_err)) {
		g_printerr("ERROR: Failed writing to stream: %s\n", local_err->message);
		return 0;
	}

	return size;
}

static gboolean evp_set_ctr_postion(EVP_CIPHER_CTX* ctx, guint64 off, guchar* nonce, guchar* key, GError** err)
{
	g_return_val_if_fail(ctx != NULL, FALSE);
	g_return_val_if_fail(nonce != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	union {
		guchar iv[16];
		struct {
			guchar nonce[8];
			guint64 ctr;
		};
	} iv;

	_Static_assert(sizeof(iv) == 16, "iv union is not 16bytes long, you're using an interesting architecture");

	memcpy(iv.nonce, nonce, 8);
	iv.ctr = GUINT64_TO_BE(off / 16);

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv.iv)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to init aes-ctr decryptor");
		return FALSE;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	// offset may be up to 15 bytes into a block, do some dummy decryption,
	// to put EVP into a correct state
	guchar scratch[16];
	int out_len;
	int ib_off = off % 16;

	if (ib_off > 0) {
		if (!EVP_EncryptUpdate(ctx, scratch, &out_len, scratch, ib_off) || out_len != ib_off) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to init aes-ctr decryptor (intra-block)");
			return FALSE;
		}
	}

	return TRUE;
}

#define RESUME_BUF_SIZE (1024 * 1024)

gboolean mega_session_download_data(struct mega_session *s, struct mega_download_data_params *params, GFile *file,
				    GError **err)
{
	GError *local_err = NULL;
	gc_object_unref GFile *dir = NULL;
	gc_object_unref GFile *tmp_file = NULL;
	gc_object_unref GFileIOStream *iostream = NULL;
	gc_object_unref GFileOutputStream *ostream = NULL;
	GSeekable* seekable = NULL;
	struct get_data_state state = { .s = s };
	gc_free gchar *tmp_path = NULL, *file_path = NULL, *tmp_name = NULL;
	guint64 download_from = 0;
	gssize bytes_read;
	gc_free guchar *buf = NULL;
	struct mega_status_data status_data;

	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	status_data = (struct mega_status_data) {
		.type = MEGA_STATUS_FILEINFO,
		.fileinfo.name = params->node_name,
		.fileinfo.size = params->node_size,
	};

	send_status(s, &status_data);

	// initialize decrytpion key/state
	guchar aes_key[16], meta_mac_xor[8], nonce[8];
	unpack_node_key(params->node_key, aes_key, nonce, meta_mac_xor);
	if (!chunked_cbc_mac_init8(&state.mac, aes_key, nonce)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to init mac calculator");
		return FALSE;
	}

	if (file) {
		file_path = g_file_get_path(file);

		dir = g_file_get_parent(file);
		if (!dir) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File %s does not have a parent directory",
				    file_path);
			return FALSE;
		}

		tmp_name = g_strdup_printf(".megatmp.%s", params->node_handle);
		tmp_file = g_file_get_child(dir, tmp_name);
		if (tmp_file == NULL) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't get temporary file %s", tmp_name);
			return FALSE;
		}

		tmp_path = g_file_get_path(tmp_file);

		if (s->resume_enabled) {
			// if temporary file exists, read it and initialize the
			// meta mac calculator state with the contents
			if (g_file_query_exists(tmp_file, NULL)) {
				iostream = g_file_open_readwrite(tmp_file, NULL, &local_err);
				if (iostream == NULL) {
					g_propagate_prefixed_error(err, local_err,
								   "Can't open previous temporary file for resume %s",
								   tmp_path);
					return FALSE;
				}

				buf = g_malloc(RESUME_BUF_SIZE);
				GInputStream* istream = g_io_stream_get_input_stream(G_IO_STREAM(iostream));
				state.ostream = g_io_stream_get_output_stream(G_IO_STREAM(iostream));
				seekable = G_SEEKABLE(iostream);

				while (TRUE) {
					bytes_read = g_input_stream_read(istream, buf, RESUME_BUF_SIZE, NULL, &local_err);
					if (bytes_read == 0)
						break;
					if (bytes_read < 0) {
						g_propagate_prefixed_error(
							err, local_err,
							"Can't read previous temporary file for resume %s", tmp_path);
						return FALSE;
					}

					// update cbc-mac
					if (!chunked_cbc_mac_update(&state.mac, buf, bytes_read)) {
						g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to run mac calculator during resume");
						return FALSE;
					}

					download_from += bytes_read;
				}

				if (download_from > params->node_size) {
					g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Unfinished downloaded data is larger than the node being downloaded (you can eg. remove %s to fix the issue)", tmp_path);
					return FALSE;
				}
			} else {
				// create a new temporary file
				ostream = g_file_create(tmp_file, 0, NULL, &local_err);
				if (!ostream) {
					g_propagate_prefixed_error(err, local_err,
								   "Can't open local file %s for writing: ", tmp_path);
					return FALSE;
				}

				seekable = G_SEEKABLE(ostream);
				state.ostream = G_OUTPUT_STREAM(ostream);
			}
		} else {// !resume_enabled
			// if temporary file exists, delete it
			if (g_file_query_exists(tmp_file, NULL) && !g_file_delete(tmp_file, NULL, &local_err)) {
				g_propagate_prefixed_error(err, local_err, "Can't delete previous temporary file %s",
							   tmp_name);
				return FALSE;
			}

			// create temporary file
			ostream = g_file_create(tmp_file, 0, NULL, &local_err);
			if (!ostream) {
				g_propagate_prefixed_error(err, local_err,
							   "Can't open local file %s for writing: ", tmp_path);
				return FALSE;
			}

			seekable = G_SEEKABLE(ostream);
			state.ostream = G_OUTPUT_STREAM(ostream);
		}
	}

	// init decryptor
	state.ctx = EVP_CIPHER_CTX_new();
	if (!state.ctx) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to init aes-ctr decryptor");
		return FALSE;
	}

	if (!EVP_EncryptInit_ex(state.ctx, EVP_aes_128_ctr(), NULL, NULL, NULL)) {
		EVP_CIPHER_CTX_free(state.ctx);
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to init aes-ctr decryptor");
		return FALSE;
	}

	EVP_CIPHER_CTX_set_padding(state.ctx, 0);

	if (!evp_set_ctr_postion(state.ctx, download_from, nonce, aes_key, &local_err)) {
		EVP_CIPHER_CTX_free(state.ctx);
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// send initial progress report
	status_data = (struct mega_status_data) {
		.type = MEGA_STATUS_PROGRESS,
		.progress.total = params->node_size - download_from,
		.progress.done = -1,
	};

	send_status(s, &status_data);

	// We'll download the file sequentially in 256MB increments (chunks),
	// re-trying if a chunk fails. We will pre-encrypt and pre-calculate mac
	// for the chunk so that we don't need to do it again when download
	// fails.
	//
	// It's a big chunk, because mega takes ~800ms to respond to a POST
	// request for data. So if we use 16MB we'd naturally limit ourselves
	// to ~18MiB/s on an infinitely fast network. With big chunk size,
	// the limit is proportionally higher.
	//
	// Because meta-mac calculation can't be reversed in case of a chunk
	// download failure, we save its state prior to chunk download and
	// restore it from saved state in case we need to rewind.

        state.progress_total = params->node_size - download_from;
	state.progress_offset = 0;

	const guint64 chunk_size = 256 * 1024 * 1024;
	while (download_from < params->node_size) {
		guint64 from = download_from;
		guint64 to = download_from + MIN(params->node_size - download_from, chunk_size);
		state.mac_saved = state.mac;
		guint tries = 0;
		gboolean download_ok;
		struct http *h;
		gc_free gchar *url = g_strdup_printf("%s/%" G_GUINT64_FORMAT "-%" G_GUINT64_FORMAT,
						     params->download_url,
						     from, to - 1);
		// 640 minutes should be enough for everyone
		const gint64 retry_timeout = 1000ll * 1000 * 60 * 640;
		gint64 end_time = g_get_monotonic_time() + retry_timeout;

retry:
		// perform download
		h = http_new();
		http_set_progress_callback(h, progress_dl, &state);
		http_set_speed(h, s->max_ul, s->max_dl);
		http_set_proxy(h, s->proxy);
		download_ok = http_post_stream_download(h, url, get_data_cb, &state, &local_err);
		http_free(h);

		if (!download_ok) {
			// retry timeout reached
			if (g_get_monotonic_time() > end_time) {
				g_propagate_prefixed_error(err, local_err, "Data download failed: ");
				goto err_noremove;
			}

			// we wait at most 256 seconds between retries (~4 minutes)
			tries = MIN(tries + 1, 8);

			// we only retry if we can seek the stream
			if (seekable) {
				g_printerr("WARNING: chunk download failed (%s), re-trying after %d seconds\n", local_err ? local_err->message : "?", (1 << tries));
				g_clear_error(&local_err);
			}

			// restore saved mac calculation state
			state.mac = state.mac_saved;

			// seek back the stream
			if (!g_seekable_seek(seekable, from, G_SEEK_SET, NULL, &local_err)) {
				g_propagate_prefixed_error(err, local_err, "Failed to rewind the temporary file after chunk download failure");
				goto err_noremove;
			}

			// restore CTR encryption state
			if (!evp_set_ctr_postion(state.ctx, from, nonce, aes_key, &local_err)) {
				g_propagate_prefixed_error(err, local_err, "Failed to rewind the temporary file after chunk download failure");
				goto err_noremove;
			}

			g_usleep(1000 * 1000 * (1 << tries));
			goto retry;
		}

		// move to the next chunk
		state.progress_offset += to - from;
		download_from = to;
	}

	status_data = (struct mega_status_data){
		.type = MEGA_STATUS_PROGRESS,
		.progress.total = params->node_size - download_from,
		.progress.done = -2,
	};

	send_status(s, &status_data);

	// check mac of the downloaded file
	guchar meta_mac_xor_calc[8];
	if (!chunked_cbc_mac_finish8(&state.mac, meta_mac_xor_calc)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Failed to finish mac calculator");
		goto err;
	}

	if (memcmp(meta_mac_xor, meta_mac_xor_calc, 8) != 0) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "MAC mismatch");
		goto err;
	}

	if (ostream && !g_output_stream_close(G_OUTPUT_STREAM(ostream), NULL, &local_err)) {
		g_propagate_prefixed_error(err, local_err, "Can't close downloaded file: ");
		goto err_noremove;
	}

	if (iostream && !g_io_stream_close(G_IO_STREAM(iostream), NULL, &local_err)) {
		g_propagate_prefixed_error(err, local_err, "Can't close downloaded file: ");
		goto err_noremove;
	}

	EVP_CIPHER_CTX_free(state.ctx);

	if (file && !g_file_move(tmp_file, file, G_FILE_COPY_NOFOLLOW_SYMLINKS | G_FILE_COPY_NO_FALLBACK_FOR_MOVE, NULL,
				 NULL, NULL, &local_err)) {
		g_propagate_prefixed_error(
			err, local_err,
			"Can't rename downloaded temporary file %s to %s (downloaded data is good!): ", tmp_path,
			file_path);
		return FALSE;
	}

	return TRUE;

err:
	if (tmp_file)
		g_file_delete(tmp_file, NULL, NULL);

err_noremove:
	EVP_CIPHER_CTX_free(state.ctx);
	return FALSE;
}

void mega_download_data_free(struct mega_download_data_params *params)
{
	g_clear_pointer(&params->download_url, g_free);
	g_clear_pointer(&params->node_handle, g_free);
	g_clear_pointer(&params->node_name, g_free);
}

// }}}
// {{{ mega_session_get

gboolean mega_session_get(struct mega_session *s, GFile *file, struct mega_node *node, GError **err)
{
	GError *local_err = NULL;
	gc_free gchar *get_node = NULL, *url = NULL;
	struct mega_download_data_params p = {};

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(node != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// prepare request
	get_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, n:%s}]", node->handle);
	if (!get_node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	gint64 node_size = s_json_get_member_int(get_node, "s", -1);
	if (node_size < 0) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
		return FALSE;
	}

	url = s_json_get_member_string(get_node, "g");
	if (!url) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
		return FALSE;
	}

	// sanity, caller should never pass non-file node
	g_assert(node->key_len == sizeof p.node_key);

	memcpy(p.node_key, node->key, node->key_len);
	p.download_url = url;
	p.node_handle = node->handle;
	p.node_name = node->name;
	p.node_size = node_size;

	return mega_session_download_data(s, &p, file, err);
}

// }}}
// {{{ mega_session_dl_prepare

gboolean mega_session_dl_prepare(struct mega_session *s, struct mega_download_data_params *params, const gchar *handle,
				 const gchar *key, GError **err)
{
	GError *local_err = NULL;
	gc_free gchar *node_name = NULL, *dl_node = NULL, *url = NULL, *at = NULL;
	gc_free guchar *node_key = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(handle != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// prepare request
	dl_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, p:%s}]", handle);
	if (!dl_node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// get file size
	gint64 node_size = s_json_get_member_int(dl_node, "s", -1);
	if (node_size < 0) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
		return FALSE;
	}

	url = s_json_get_member_string(dl_node, "g");
	if (!url) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
		return FALSE;
	}

	at = s_json_get_member_string(dl_node, "at");
	if (!at) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't get file attributes");
		return FALSE;
	}

	// decode node_key
	gsize node_key_len = 0;
	node_key = base64urldecode(key, &node_key_len);
	if (!node_key || node_key_len != 32) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't retrieve file key");
		return FALSE;
	}

	// initialize decrytpion key
	guchar aes_key[16];
	unpack_node_key(node_key, aes_key, NULL, NULL);

	// decrypt attributes with aes_key
	if (!decrypt_node_attrs(at, aes_key, &node_name)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid key");
		return FALSE;
	}

	if (!node_name) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't retrieve remote file name");
		return FALSE;
	}

	// replace invalid filename characters with whitespace
	gchar *check = node_name;
#ifdef G_OS_WIN32
	while ((check = strpbrk(check, "/\\<>:\"|?*")))
#else
	while ((check = strpbrk(check, "/")))
#endif
		*check = '_';

	// check for invalid names
	if (!strcmp(node_name, ".") || !strcmp(node_name, "..")) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file name is invalid: '%s'", node_name);
		return FALSE;
	}

	memcpy(params->node_key, node_key, sizeof params->node_key);
	params->download_url = url;
	params->node_handle = g_strdup(handle);
	params->node_name = node_name;
	params->node_size = node_size;

	url = node_name = NULL;

	return TRUE;
}

// }}}

// {{{ mega_session_get_node_by_handle

struct mega_node* mega_session_get_node_by_handle(struct mega_session *s, const gchar* handle)
{
	GSList *i;

	g_return_val_if_fail(s != NULL, NULL);

	for (i = s->fs_nodes; i; i = i->next) {
		struct mega_node *n = i->data;

		if (n->handle && g_str_equal(n->handle, handle))
			return n;
	}

	return NULL;
}

// }}}
// {{{ mega_node_get_link

gchar *mega_node_get_link(struct mega_node *n, gboolean include_key)
{
	g_return_val_if_fail(n != NULL, NULL);

	if (n->link) {
		if (include_key && n->key) {
			gc_free gchar *key = mega_node_get_key(n);

			return g_strdup_printf("https://mega.nz/#!%s!%s", n->link, key);
		}

		return g_strdup_printf("https://mega.nz/#!%s", n->link);
	}

	return NULL;
}

// }}}
// {{{ mega_node_get_key

gchar *mega_node_get_key(struct mega_node *n)
{
	g_return_val_if_fail(n != NULL, NULL);

	if (n->key)
		return base64urlencode(n->key, n->key_len);

	return NULL;
}

// }}}
// {{{ mega_node_get_path

gchar *mega_node_get_path_dup(struct mega_node *n)
{
	gchar path[4096];

	if (mega_node_get_path(n, path, sizeof(path)))
		return g_strndup(path, sizeof(path));

	return NULL;
}

gboolean mega_node_get_path(struct mega_node *n, gchar *buf, gsize len)
{
	g_return_val_if_fail(n != NULL, FALSE);

	// count parents
	gint n_parents = 0;
	struct mega_node *it = n;
	while (it && n_parents < 64) {
		n_parents++;
		it = it->parent;
	}

	if (n_parents >= 64)
		return FALSE;

	// allocate pointer list on stack
	struct mega_node *parents[64];

	// get parents into the pointer list
	it = n;
	n_parents = 0;
	while (it) {
		parents[n_parents++] = it;
		it = it->parent;
	}

	// reverse iteration
	gint i;
	gchar *p = buf;
	for (i = n_parents - 1; i >= 0; i--) {
		it = parents[i];
		gint name_len = strlen(it->name);
		gint remaining_buf_len = len - (p - buf);

		if (remaining_buf_len < name_len + 2)
			return FALSE;

		*p = '/';
		p += 1;

		memcpy(p, it->name, name_len);
		p += name_len;
	}

	*p = '\0';

	return TRUE;
}

// }}}
// {{{ mega_node_is_container

gboolean mega_node_is_container(struct mega_node *n)
{
	return n && n->type != MEGA_NODE_FILE;
}

// }}}
// {{{ mega_node_has_ancestor

gboolean mega_node_has_ancestor(struct mega_node *n, struct mega_node *ancestor)
{
	g_return_val_if_fail(n != NULL, FALSE);
	g_return_val_if_fail(ancestor != NULL, FALSE);

	struct mega_node* it = n->parent;

	while (it) {
		if (it == ancestor)
			return TRUE;

		it = it->parent;
	}

	return FALSE;
}

// }}}

// {{{ mega_session_save

static void save_share_keys(gchar *handle, gchar *key, SJsonGen *gen)
{
	s_json_gen_start_object(gen);
	s_json_gen_member_string(gen, "handle", handle);
	s_json_gen_member_bytes(gen, "key", key, 16);
	s_json_gen_end_object(gen);
}

gboolean mega_session_save(struct mega_session *s, GError **err)
{
	GError *local_err = NULL;
	GSList *i;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(s->user_email != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// calculate cache file path
	gc_free gchar *un = g_ascii_strdown(s->user_email, -1);
	gc_checksum_free GChecksum *cs = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(cs, un, -1);
	gc_free gchar *filename = g_strconcat(g_checksum_get_string(cs), ".megatools.cache", NULL);
	gc_free gchar *path = g_build_filename(g_get_tmp_dir(), filename, NULL);

	SJsonGen *gen = s_json_gen_new();
	s_json_gen_start_object(gen);

	// serialize session object
	s_json_gen_member_int(gen, "version", CACHE_FORMAT_VERSION);
	s_json_gen_member_int(gen, "last_refresh", s->last_refresh);

	s_json_gen_member_string(gen, "sid", s->sid);
	s_json_gen_member_string(gen, "password_salt_v2", s->password_salt_v2);
	s_json_gen_member_bytes(gen, "password_key", s->password_key, 16);
	s_json_gen_member_bytes(gen, "master_key", s->master_key, 16);
	s_json_gen_member_rsa_key(gen, "rsa_key", &s->rsa_key);
	s_json_gen_member_string(gen, "user_handle", s->user_handle);
	s_json_gen_member_string(gen, "user_name", s->user_name);
	s_json_gen_member_string(gen, "user_email", s->user_email);

	s_json_gen_member_array(gen, "share_keys");
	g_hash_table_foreach(s->share_keys, (GHFunc)save_share_keys, gen);
	s_json_gen_end_array(gen);

	s_json_gen_member_array(gen, "fs_nodes");
	for (i = s->fs_nodes; i; i = i->next) {
		struct mega_node *n = i->data;

		s_json_gen_start_object(gen);
		s_json_gen_member_string(gen, "name", n->name);
		s_json_gen_member_string(gen, "handle", n->handle);
		s_json_gen_member_string(gen, "parent_handle", n->parent_handle);
		s_json_gen_member_string(gen, "user_handle", n->user_handle);
		s_json_gen_member_string(gen, "su_handle", n->su_handle);
		s_json_gen_member_bytes(gen, "key", n->key, n->key_len);
		s_json_gen_member_int(gen, "type", n->type);
		s_json_gen_member_int(gen, "size", n->size);
		s_json_gen_member_int(gen, "timestamp", n->timestamp);
		s_json_gen_member_string(gen, "link", n->link);
		s_json_gen_end_object(gen);
	}
	s_json_gen_end_array(gen);

	s_json_gen_end_object(gen);
	gc_free gchar *cache_data = s_json_gen_done(gen);

	if (mega_debug & MEGA_DEBUG_CACHE)
		print_node(cache_data, "SAVE CACHE: ");

	gc_free gchar *tmp = g_strconcat("MEGA", cache_data, NULL);
	gc_free gchar *cipher = b64_aes128_cbc_encrypt_str(tmp, s->password_key_save);

	if (!g_file_set_contents(path, cipher, -1, &local_err)) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	return TRUE;
}

// }}}
// {{{ mega_session_load

static gboolean mega_session_load(struct mega_session *s,
				  const gchar *un, const gchar *pw, gint max_age,
				  gchar **last_sid, gchar** last_pwsalt_v2,
				  GError **err)
{
	GError *local_err = NULL;
	gc_free gchar *cipher = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(un != NULL, FALSE);
	g_return_val_if_fail(pw != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	mega_session_close(s);
	s->password_key_save = make_password_key(pw);

	// calculate cache file path
	gc_free gchar *un_lower = g_ascii_strdown(un, -1);
	gc_checksum_free GChecksum *cs = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(cs, un_lower, -1);
	gc_free gchar *filename = g_strconcat(g_checksum_get_string(cs), ".megatools.cache", NULL);
	gc_free gchar *path = g_build_filename(g_get_tmp_dir(), filename, NULL);

	// load cipher data
	if (!g_file_get_contents(path, &cipher, NULL, &local_err)) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// calculate password key
	gsize len = 0;
	gc_free gchar *data = b64_aes128_cbc_decrypt(cipher, s->password_key_save, &len);

	if (!data || len < 4) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Corrupted cache file");
		return FALSE;
	}

	if (memcmp(data, "MEGA", 4) != 0) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Incorrect password");
		return FALSE;
	}

	if (!s_json_is_valid(data + 4)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Corrupted cache file");
		return FALSE;
	}

	gc_free gchar *cache_obj = s_json_get(data + 4);

	if (mega_debug & MEGA_DEBUG_CACHE)
		print_node(cache_obj, "LOAD CACHE: ");

	if (s_json_get_type(cache_obj) == S_JSON_TYPE_OBJECT) {
		gint64 version = s_json_get_member_int(cache_obj, "version", 0);
		gint64 last_refresh = s_json_get_member_int(cache_obj, "last_refresh", 0);

		if (version != CACHE_FORMAT_VERSION) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Cache version mismatch");
			return FALSE;
		}

		// return sid value if available
		gc_free gchar *sid = s_json_get_member_string(cache_obj, "sid");
		if (last_sid)
			*last_sid = g_strdup(sid);

		gc_free gchar *password_salt_v2 = s_json_get_member_string(cache_obj, "password_salt_v2");
		if (last_pwsalt_v2)
			*last_pwsalt_v2 = g_strdup(password_salt_v2);

		// check max_age
		if (max_age > 0) {
			if (!last_refresh || ((last_refresh + max_age) < time(NULL))) {
				g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Cache timed out");
				return FALSE;
			}
		}

		// cache is valid, load it
		gsize len;

		s->last_refresh = last_refresh;

		s->sid = sid;
		sid = NULL;

		s->password_salt_v2 = password_salt_v2;
		password_salt_v2 = NULL;

		s->password_key = s_json_get_member_bytes(cache_obj, "password_key", &len);
		s->master_key = s_json_get_member_bytes(cache_obj, "master_key", &len);
		s_json_get_member_rsa_key(cache_obj, "rsa_key", &s->rsa_key);
		s->user_handle = s_json_get_member_string(cache_obj, "user_handle");
		s->user_name = s_json_get_member_string(cache_obj, "user_name");
		s->user_email = s_json_get_member_string(cache_obj, "user_email");

		if (!s->sid || !s->password_key || !s->master_key || !s->user_handle || !s->user_email ||
		    !s->rsa_key.p || !s->rsa_key.q || !s->rsa_key.d || !s->rsa_key.u) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Incomplete cache data");
			return FALSE;
		}

		const gchar *sk_nodes = s_json_get_member(cache_obj, "share_keys");
		if (s_json_get_type(sk_nodes) == S_JSON_TYPE_ARRAY) {
			S_JSON_FOREACH_ELEMENT(sk_nodes, sk_node)
			gc_free gchar *handle = s_json_get_member_string(sk_node, "handle");
			gc_free guchar *key = s_json_get_member_bytes(sk_node, "key", &len);

			add_share_key(s, handle, key);
			S_JSON_FOREACH_END()
		}

		const gchar *fs_nodes = s_json_get_member(cache_obj, "fs_nodes");
		if (s_json_get_type(fs_nodes) == S_JSON_TYPE_ARRAY) {
			S_JSON_FOREACH_ELEMENT(fs_nodes, fs_node)
			struct mega_node *n = g_new0(struct mega_node, 1);

			n->type = -1;

			S_JSON_FOREACH_MEMBER(fs_node, k, v)
			if (s_json_string_match(k, "name")) {
				n->name = s_json_get_string(v);
				n->name_collate_key = g_utf8_collate_key_for_filename(n->name, -1);
			} else if (s_json_string_match(k, "handle"))
				n->handle = s_json_get_string(v);
			else if (s_json_string_match(k, "parent_handle"))
				n->parent_handle = s_json_get_string(v);
			else if (s_json_string_match(k, "user_handle"))
				n->user_handle = s_json_get_string(v);
			else if (s_json_string_match(k, "su_handle"))
				n->su_handle = s_json_get_string(v);
			else if (s_json_string_match(k, "key"))
				n->key = s_json_get_bytes(v, &n->key_len);
			else if (s_json_string_match(k, "type"))
				n->type = s_json_get_int(v, -1);
			else if (s_json_string_match(k, "size"))
				n->size = s_json_get_int(v, 0);
			else if (s_json_string_match(k, "timestamp"))
				n->timestamp = s_json_get_int(v, 0);
			else if (s_json_string_match(k, "link"))
				n->link = s_json_get_string(v);
			S_JSON_FOREACH_END()

			s->fs_nodes = g_slist_prepend(s->fs_nodes, n);
			S_JSON_FOREACH_END()

			s->fs_nodes = g_slist_reverse(s->fs_nodes);
		}
	} else {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Corrupt cache");
		return FALSE;
	}

	build_node_tree(s);

	return TRUE;
}

// }}}

// {{{ mega_session_register

gboolean mega_session_register(struct mega_session *s, const gchar *email, const gchar *password, const gchar *name,
			       struct mega_reg_state **state, GError **err)
{
	GError *local_err = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(email != NULL, FALSE);
	g_return_val_if_fail(password != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(state != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// logout
	mega_session_close(s);

	// create new master key
	gc_free guchar *master_key = make_random_key();

	// create password key
	gc_free guchar *password_key = make_password_key(password);

	// create username hash
	//gc_free gchar* email_lower = g_ascii_strdown(email, -1);
	//gc_free gchar* uh = make_username_hash(email_lower, password_key);

	// create ssc (session self challenge) and ts
	gc_free guchar *ssc = make_random_key();
	guchar ts_data[32];
	memcpy(ts_data, ssc, 16);
	aes128_encrypt(ts_data + 16, ts_data, 16, master_key);

	// create anon user - [{"a":"up","k":"cHl8JeeSqgBOiURQL_Dvug","ts":"W9fg4kOw8p44KWoWICbgEd3rfMovr5HoSjI1vN7845s"}] -> ["-a1DHeWfguY"]
	gc_free gchar *node = api_call(s, 's', NULL, &local_err, "[{a:up, k:%S, ts:%S}]",
				       b64_aes128_encrypt(master_key, 16, password_key), base64urlencode(ts_data, 32));
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	gc_free gchar *user_handle = s_json_get_string(node);

	// login as an anon user - [{"a":"us","user":"-a1DHeWfguY"}] -> [{"tsid":"W9fg4kOw8p44KWoWICbgES1hMURIZVdmZ3VZ3et8yi-vkehKMjW83vzjmw","k":"cHl8JeeSqgBOiURQL_Dvug"}]
	g_free(node);
	node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s}]", user_handle);
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// from now on, tsid is used as session ID
	s->sid = s_json_get_member_string(node, "tsid");

	// get user info - [{"a":"ug"}] -> [{"u":"-a1DHeWfguY","s":1,"n":0,"k":"cHl8JeeSqgBOiURQL_Dvug","c":0,"ts":"W9fg4kOw8p44KWoWICbgEd3rfMovr5HoSjI1vN7845s"}]
	g_free(node);
	node = api_call(s, 'o', NULL, &local_err, "[{a:ug}]");
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// set user name - [{"a":"up","name":"Bob Brown"}] -> ["-a1DHeWfguY"]
	g_free(node);
	node = api_call(s, 's', NULL, &local_err, "[{a:up, name:%s}]", name);
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// request signup link - [{"a":"uc","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ic","n":"Qm9iIEJyb3du","m":"bWVnb3VzQGVtYWlsLmN6"}] -> [0]
	guchar c_data[32] = { 0 }; // aes(master_key, pw_key) + aes(verify, pw_key)
	memcpy(c_data, master_key, 16);
	RAND_bytes(c_data + 16, 4);
	RAND_bytes(c_data + 16 + 12, 4);

	// this will set new k from the first 16 bytes of c
	g_free(node);
	node = api_call(s, 'i', NULL, &local_err, "[{a:uc, c:%S, n:%S, m:%S}]",
			b64_aes128_encrypt(c_data, 32, password_key), base64urlencode(name, strlen(name)),
			base64urlencode(email, strlen(email)));
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// save state
	struct mega_reg_state *st = *state = g_new0(struct mega_reg_state, 1);
	st->user_handle = user_handle;
	user_handle = NULL;
	memcpy(st->password_key, password_key, 16);
	memcpy(st->challenge, c_data + 16, 16);

	return TRUE;
}

// }}}
// {{{ mega_session_register_verify

gboolean mega_session_register_verify(struct mega_session *s, struct mega_reg_state *state, const gchar *signup_key,
				      GError **err)
{
	GError *local_err = NULL;
	gc_free gchar *node = NULL;

	g_return_val_if_fail(s != NULL, FALSE);
	g_return_val_if_fail(state != NULL, FALSE);
	g_return_val_if_fail(state->user_handle != NULL, FALSE);
	g_return_val_if_fail(signup_key != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	mega_session_close(s);

	// generate RSA key
	struct rsa_key key;
	memset(&key, 0, sizeof(key));
	if (!rsa_key_gen(&key)) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't generate RSA key");
		return FALSE;
	}

	// u_types:
	//   0: not registered (!u.email)
	//   1: not sent confirmation email (!u.c)
	//   2: not yet set RSA key (!u.privk)
	//   3: full account

	// login as an anon user - [{"a":"us","user":"-a1DHeWfguY"}] -> [{"tsid":"W9fg4kOw8p44KWoWICbgES1hMURIZVdmZ3VZ3et8yi-vkehKMjW83vzjmw","k":"cHl8JeeSqgBOiURQL_Dvug"}]
	node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s}]", state->user_handle);
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// from now on, tsid is used as session ID
	s->sid = s_json_get_member_string(node, "tsid");

	// send confirmation
	//
	// https://mega.nz/#confirmZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg
	//
	// [{"a":"ud","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg"}]
	//
	// -> [["bWVnb3VzQGVtYWlsLmN6","Qm9iIEJyb3du","-a1DHeWfguY","ZOB7VJrNXFvCzyZBIcdWhg","vmXh0lq2takSMSkCYfXuJw"]]
	//            ^                       ^            ^                    ^                       ^
	//          email                    name        handle       enc(master_key, pwkey)   enc(challenge, pwkey)

	g_free(node);
	node = api_call(s, 'a', NULL, &local_err, "[{a:ud, c:%s}]", signup_key);
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	gc_free gchar **arr = s_json_get_elements(node);
	if (g_strv_length(arr) != 5) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Wrong number of elements in retval from 'ud' (%d)",
			    g_strv_length(arr));
		return FALSE;
	}

	gc_free gchar *b64_email = s_json_get_string(arr[0]);
	gc_free gchar *b64_name = s_json_get_string(arr[1]);
	gc_free gchar *b64_master_key = s_json_get_string(arr[3]);
	gc_free gchar *b64_challenge = s_json_get_string(arr[4]);

	if (b64_email == NULL || b64_name == NULL || b64_master_key == NULL || b64_challenge == NULL) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid retval type from 'ud'");
		return FALSE;
	}

	gsize len;
	gc_free gchar *email = base64urldecode(b64_email, &len);
	gc_free gchar *name = base64urldecode(b64_name, &len);
	gc_free guchar *master_key = b64_aes128_decrypt(b64_master_key, state->password_key, NULL);
	gc_free guchar *challenge = b64_aes128_decrypt(b64_challenge, state->password_key, NULL);

	if (email == NULL || name == NULL || master_key == NULL || challenge == NULL) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid retval type from 'ud'");
		return FALSE;
	}

	// check challenge response
	if (memcmp(challenge, state->challenge, 16) != 0) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid challenge response");
		return FALSE;
	}

	// create username hash
	gc_free gchar *email_lower = g_ascii_strdown(email, -1);
	gc_free gchar *uh = make_username_hash(email_lower, state->password_key);

	// save uh and c
	// [{"uh":"VcWbhpU9cb0","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg","a":"up"}] -> ["-a1DHeWfguY"]
	g_free(node);
	node = api_call(s, 's', NULL, &local_err, "[{a:up, c:%s, uh:%s}]", signup_key, uh);
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	// relogin using email + uh
	// [{"a":"us","user":"megous@email.cz","uh":"VcWbhpU9cb0"}] -> [{"tsid":"W9fg4kOw8p44KWoWICbgES1hMURIZVdmZ3VZ3et8yi-vkehKMjW83vzjmw","k":"ZOB7VJrNXFvCzyZBIcdWhg"}]

	g_free(node);
	node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s, uh:%s}]", email_lower, uh);
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	g_free(s->sid);
	s->sid = s_json_get_member_string(node, "tsid");

	// set RSA key pair
	// [{"a":"up", "privk":"...", "pubk":"..."}] -> ["-a1DHeWfguY"]
	g_free(node);
	node = api_call(s, 's', NULL, &local_err, "[{a:up, pubk:%S, privk:%S}]", b64_encode_pubk(&key),
			b64_aes128_encrypt_privk(master_key, &key));
	if (!node) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	//[{"a":"ug"}] -> [{"u":"-a1DHeWfguY","s":1,"email":"megous@email.cz","name":"Bob Brown","k":"ZOB7VJrNXFvCzyZBIcdWhg","c":1,"ts":"W9fg4kOw8p44KWoWICbgEd3rfMovr5HoSjI1vN7845s"}]
	//[{"a":"up","privk":"KSUujv7KB8QYL2At2sWeMPi2DQd_e09FwbR2RwileC9NxYw0MxFTKFj7Yxha__borDmBUacxaWXRCnMnAmMlsyWc8zw_ml9tysYHOsL4cQEzpBJtCCIrhnRjwnQk8JUVK--5fyQRS6G2RiOVdeFjkKQyifmXgBsiAlhHKhzSY0VD6ruR9htGfDsgImim_S-MzuWaHQN8TJkBkSZRAgXy6O2tUh0Bk4aEp8NaEV0GHdV7ec1S1jbR9FzwKB7cNkKxk2nd7wRS9rnl_QPz4MTv84dS6qHxahT0ebU5njC2_IkFLxuVlloyO2UTPRPHa9JHaPa3R2BrEmb-eWMmsZ5icNwJl8PLzuc9YlSI09-IR5rHZLm2uW-V05GI1IHIjw9LGzqli6WL7tzlMVhHrsq-xj70iXjVvOXJ3XhwbbW99S8O-3sQ2gG36fSHUcg0WMSD-8KiD-DhmhfqX8iqg-2YDfXrsYUNhq_VHJF83Zm0itPdRIkgUtBR9MFdASSPe_8uxlEBsCATTHNGIWbH0wiKRo2tEqbUTZCJjXhAyTyMhdjbSdS1ARKNr12YHkLKi12uhIJRO73VJGmjZD8De59cPduGihLGt3ipIKVIxsm-Xy6f9p29BtDHE1go_yacqbW1n8d1anN8WhmG8Q_1PwY1h-opagpd-Nf0geFti_3PI8dY75NPAuDyknv0kgn8OZ4ItzO10-4H3_GgLa5m8zb6usk-eeVCo4lkC4Z2YHHlY4YLRIL7rWC0m_kFcsyvVi1-PVNJ8GauLt9PYmW9hj20yJLwCYkEVSQyM4Yxgh55hSa3La3FnUt3Nls_ImOdcDWtYpB0UKJSKN_IYH4NlD60VwvFUifJndRB_JlJGvqzR4s","pubk":"B_9lGyG4ImN-3idVOARGr6dk-4Nn6VwVYxCTSk1nDvXztCNQ-eFwxIJoS3ykODSH_AjHhst_Loj_erSgX-AUOBAjkh5rQuriA4ciT76tIh_IarC5Yf2Zey8Ao_gLPgaqrLTIWPxDhSAmCLd3pa3X9weAuGK_7eiVxmXU4tK_5j7dyn949C4OMNhxp9vRgZqaOzcjouwKm8xH9nWqXTR7F2WKW2BcXxeBkRnFVJz6cd5IqmJENabhDH1-UDf9eCW7GeD2MHU8xnbJk2fXqnru35nxz9OG6VvVDMzrS6dtQU8mC7xnIut_N6eyMRWsHpm8N1bSxHgz1XWCodnOBHFIJSoJAAUR"}] -> ["-a1DHeWfguY"]

	return TRUE;
}

// }}}

// {{{ Compatibility: old interfaces

struct mega_node *mega_session_put_compat(struct mega_session *s, const gchar *remote_path, const gchar *local_path,
					  GError **err)
{
	GError *local_err = NULL;
	struct mega_node *node, *parent_node;
	gc_object_unref GFile *file = NULL;
	gc_free gchar *file_name = NULL;
	gc_free gchar *file_path = NULL;
	gc_object_unref GFileInputStream *stream = NULL;

	node = mega_session_stat(s, remote_path);
	if (node) {
		// reote path exists
		if (node->type == MEGA_NODE_FILE) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_EXISTS, "File already exists: %s", remote_path);
			return NULL;
		} else {
			// it's a directory, so we need to check if file with
			// basename(local_path) already exists there
			parent_node = node;

			// remote filename will be a basename(local_path)
			file_name = g_path_get_basename(local_path);
			gc_free gchar *tmp = g_strconcat(remote_path, "/", file_name, NULL);
			node = mega_session_stat(s, tmp);
			if (node) {
				g_set_error(err, MEGA_ERROR, MEGA_ERROR_EXISTS, "File already exists: %s", tmp);
				return NULL;
			}
		}
	} else {
		// remote path doesn't exists, check the parent dir
		gc_free gchar *tmp = path_simplify(remote_path);
		gc_free gchar *parent_path = g_path_get_dirname(tmp);
		// remote filename will be a basename(remote_path)
		file_name = g_path_get_basename(tmp);

		if (!strcmp(parent_path, "/")) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't upload to toplevel dir: %s", remote_path);
			return NULL;
		}

		parent_node = mega_session_stat(s, parent_path);
		if (!parent_node || parent_node->type == MEGA_NODE_FILE) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory doesn't exist: %s",
				    parent_path);
			return NULL;
		}
	}

	if (!mega_node_is_writable(s, parent_node) || parent_node->type == MEGA_NODE_NETWORK ||
			parent_node->type == MEGA_NODE_CONTACT) {
		gchar path[4096];
		if (!mega_node_get_path(parent_node, path, sizeof(path)))
			snprintf(path, sizeof path, "???");

		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory is not writable: %s", path);
		return NULL;
	}

	file = g_file_new_for_path(local_path);
	stream = g_file_read(file, NULL, &local_err);
	if (!stream) {
		g_propagate_prefixed_error(err, local_err, "Can't read local file %s: ", local_path);
		return NULL;
	}

	return mega_session_put(s, parent_node, file_name, stream, local_path, err);
}

gboolean mega_session_get_compat(struct mega_session *s, const gchar *local_path, const gchar *remote_path,
				 GError **err)
{
	gc_object_unref GFile *file = NULL;

	struct mega_node *node = mega_session_stat(s, remote_path);
	if (!node) {
		g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file not found: %s", remote_path);
		return FALSE;
	}

	if (local_path) {
		file = g_file_new_for_path(local_path);
		if (g_file_query_exists(file, NULL)) {
			if (g_file_query_file_type(file, 0, NULL) == G_FILE_TYPE_DIRECTORY) {
				gc_object_unref GFile *child = g_file_get_child(file, node->name);
				if (g_file_query_exists(child, NULL)) {
					g_set_error(err, MEGA_ERROR, MEGA_ERROR_EXISTS,
						    "Local file already exists: %s/%s", local_path, node->name);
					return FALSE;
				} else {
					file = child;
					child = NULL;
				}
			} else {
				g_set_error(err, MEGA_ERROR, MEGA_ERROR_EXISTS, "Local file already exists: %s",
					    local_path);
				return FALSE;
			}
		}
	}

	return mega_session_get(s, file, node, err);
}

gboolean mega_session_dl_compat(struct mega_session *s, const gchar *handle, const gchar *key, const gchar *local_path,
				GError **err)
{
	GError *local_err = NULL;
	gc_object_unref GFile *file = NULL, *parent_dir = NULL;

	if (local_path) {
		// get dir and filename to download to
		file = g_file_new_for_path(local_path);
		if (g_file_query_exists(file, NULL)) {
			if (g_file_query_file_type(file, 0, NULL) != G_FILE_TYPE_DIRECTORY) {
				g_set_error(err, MEGA_ERROR, MEGA_ERROR_EXISTS, "File already exists: %s", local_path);
				return FALSE;
			} else {
				parent_dir = file;
				file = NULL;
			}
		} else {
			parent_dir = g_file_get_parent(file);

			if (g_file_query_file_type(parent_dir, 0, NULL) != G_FILE_TYPE_DIRECTORY) {
				g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't download file into: %s",
					    g_file_get_path(parent_dir));
				return FALSE;
			}
		}
	}

	struct mega_download_data_params params = {};
	if (!mega_session_dl_prepare(s, &params, handle, key, &local_err)) {
		g_propagate_error(err, local_err);
		return FALSE;
	}

	if (local_path) {
		if (!file)
			file = g_file_get_child(parent_dir, params.node_name);

		if (g_file_query_exists(file, NULL)) {
			g_set_error(err, MEGA_ERROR, MEGA_ERROR_EXISTS,
				    "Local file already exists: %s/%s", local_path, params.node_name);
			mega_download_data_free(&params);
			return FALSE;
		}
	}

	gboolean status = mega_session_download_data(s, &params, file, err);

	mega_download_data_free(&params);

	return status;
}

// }}}

// {{{ mega_cleanup

void mega_cleanup(void)
{
	tman_fini();
	http_cleanup();
}

// }}}
