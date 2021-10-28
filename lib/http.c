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

#include "http.h"
#include "mega.h"
#include "config.h"
#include <curl/curl.h>
#include <string.h>
/*
Warning solved by Max Base (https://github.com/BaseMax) :

lib/http.c: In function ‘http_new’:
lib/http.c:161:4: warning: implicit declaration of function ‘exit’ [-Wimplicit-function-declaration]
    exit(1);
    ^
lib/http.c:161:4: warning: incompatible implicit declaration of built-in function ‘exit’
lib/http.c:161:4: note: include ‘<stdlib.h>’ or provide a declaration of ‘exit’
  CC       lib/mega.o
lib/mega.c: In function ‘tman_worker_upload_chunk’:
lib/mega.c:3268:2: warning: dereferencing type-punned pointer will break strict-aliasing rules [-Wstrict-aliasing]
  *((guint64 *)&iv[8]) = GUINT64_TO_BE((guint64)(c->offset / 16)); // this is ok, because chunks are 16b aligned
*/
#include <stdlib.h> // exit

char* http_netif = NULL;
int http_ipproto = HTTP_IPPROTO_ANY;

#define MEGA_NZ_API_PUBKEY_PIN "sha256//0W38e765pAfPqS3DqSVOrPsC4MEOvRBaXQ7nY1AJ47E="

// curlver.h: this macro was added in May 14, 2015
#ifndef CURL_AT_LEAST_VERSION
#define CURL_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | z)
#define CURL_AT_LEAST_VERSION(x, y, z) (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS(x, y, z))
#endif

//#define STEALTH_MODE

#if CURL_AT_LEAST_VERSION(7, 12, 0)
static CURLSH *http_share;
static GRWLock http_locks[CURL_LOCK_DATA_LAST];

static void http_lock_cb(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr)
{
	if (access == CURL_LOCK_ACCESS_SHARED)
		g_rw_lock_reader_lock(&http_locks[data]);
	else
		g_rw_lock_writer_lock(&http_locks[data]);
}

static void http_unlock_cb(CURL *handle, curl_lock_data data, void *userptr)
{
	// the implementation is the same for reader/writer unlock (so we just use
	// writer_unlock)
	g_rw_lock_writer_unlock(&http_locks[data]);
}

G_LOCK_DEFINE_STATIC(http_init);

void http_init(void)
{
	G_LOCK(http_init);

	if (!http_share) {
		http_share = curl_share_init();

		//curl_share_setopt(http_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
		curl_share_setopt(http_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
		//curl_share_setopt(http_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
		//curl_share_setopt(http_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);

		for (int i = 0; i < G_N_ELEMENTS(http_locks); i++)
			g_rw_lock_init(&http_locks[i]);

		curl_share_setopt(http_share, CURLSHOPT_LOCKFUNC, http_lock_cb);
		curl_share_setopt(http_share, CURLSHOPT_UNLOCKFUNC, http_unlock_cb);
	}

	G_UNLOCK(http_init);
}

void http_cleanup(void)
{
	G_LOCK(http_init);

	if (http_share) {
		curl_share_cleanup(http_share);
		http_share = NULL;

		for (int i = 0; i < G_N_ELEMENTS(http_locks); i++)
			g_rw_lock_clear(&http_locks[i]);
	}

	G_UNLOCK(http_init);
}
#else
void http_init(void) {}
void http_cleanup(void) {}
#endif

struct http {
	CURL *curl;
	GHashTable *headers;

	http_progress_fn progress_cb;
	gpointer progress_data;
};


struct http *http_new(void)
{
	struct http *h = g_new0(struct http, 1);

	h->curl = curl_easy_init();
	if (!h->curl) {
		g_free(h);
		return NULL;
	}

#if CURL_AT_LEAST_VERSION(7, 57, 0)
	http_init();
	curl_easy_setopt(h->curl, CURLOPT_SHARE, http_share);
#endif

#if CURL_AT_LEAST_VERSION(7, 21, 6)
	curl_easy_setopt(h->curl, CURLOPT_ACCEPT_ENCODING, "");
#else
	curl_easy_setopt(h->curl, CURLOPT_ENCODING, "");
#endif

	switch (http_ipproto) {
		case HTTP_IPPROTO_V4:
			curl_easy_setopt(h->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
			break;
		case HTTP_IPPROTO_V6:
			curl_easy_setopt(h->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
			break;
	}

	if (http_netif)
		curl_easy_setopt(h->curl, CURLOPT_INTERFACE, http_netif);

	if (mega_debug & MEGA_DEBUG_HTTP)
		curl_easy_setopt(h->curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(h->curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(h->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(h->curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

	curl_easy_setopt(h->curl, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(h->curl, CURLOPT_TCP_KEEPIDLE, 120L);
	curl_easy_setopt(h->curl, CURLOPT_TCP_KEEPINTVL, 60L);

	curl_easy_setopt(h->curl, CURLOPT_BUFFERSIZE, 256 * 1024L);

	curl_easy_setopt(h->curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);

#if CURL_AT_LEAST_VERSION(7, 44, 0)
	const gchar* pkp_disable = g_getenv("MEGATOOLS_PKP_DISABLE");
	if (pkp_disable == NULL || strcmp(pkp_disable, "1")) {
		if (curl_easy_setopt(h->curl, CURLOPT_PINNEDPUBLICKEY, MEGA_NZ_API_PUBKEY_PIN) != CURLE_OK) {
			g_printerr("ERROR: Failed to setup public key pinning, aborting! You probably need a newer cURL library.\n");
			exit(1);
		} else {
			curl_easy_setopt(h->curl, CURLOPT_CAINFO, NULL);
			curl_easy_setopt(h->curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}
	}
#endif

	h->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

#if STEALTH_MODE
	// we are Firefox!
	http_set_header(h, "User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0");
	http_set_header(h, "Referer", "https://mega.nz/");
	http_set_header(h, "Origin", "https://mega.nz");
	http_set_header(h, "Accept", "*/*");
	http_set_header(h, "Accept-Language", "en-US;q=0.8,en;q=0.3");
	http_set_header(h, "Cache-Control", "no-cache");
	http_set_header(h, "Pragma", "no-cache");
	http_set_header(h, "DNT", "1");
#else
	// set default headers
	http_set_header(h, "User-Agent", "Megatools (" VERSION ")");
#endif
	// Disable 100-continue (because it causes needless roundtrips)
	http_set_header(h, "Expect", "");

	return h;
}

void http_set_max_connects(struct http *h, long max)
{
	g_return_if_fail(h != NULL);

	curl_easy_setopt(h->curl, CURLOPT_MAXCONNECTS, max);
}

void http_expect_short_running(struct http *h)
{
	g_return_if_fail(h != NULL);

	// don't use alarm signal to time out dns queries
	curl_easy_setopt(h->curl, CURLOPT_TIMEOUT, 10*60L); // 10 minutes max per connection
	curl_easy_setopt(h->curl, CURLOPT_LOW_SPEED_TIME, 60L); // 60s max of very low speed
	curl_easy_setopt(h->curl, CURLOPT_LOW_SPEED_LIMIT, 10L);
}

void http_set_header(struct http *h, const gchar *name, const gchar *value)
{
	g_return_if_fail(h != NULL);
	g_return_if_fail(name != NULL);
	g_return_if_fail(value != NULL);

	g_hash_table_insert(h->headers, g_strdup(name), g_strdup(value));
}

void http_set_content_type(struct http *h, const gchar *type)
{
	http_set_header(h, "Content-Type", type);
}

void http_set_content_length(struct http *h, goffset len)
{
	gchar *tmp = g_strdup_printf("%" G_GOFFSET_FORMAT, len);
	http_set_header(h, "Content-Length", tmp);
	g_free(tmp);
}

static int curl_progress(struct http *h, double dltotal, double dlnow, double ultotal, double ulnow)
{
	if (h->progress_cb) {
		if (!h->progress_cb(dltotal, dlnow, ultotal, ulnow, h->progress_data))
			return 1; // cancel
	}

	return 0;
}

void http_set_speed(struct http *h, gint max_ul, gint max_dl)
{
	if (max_ul >= 0)
		curl_easy_setopt(h->curl, CURLOPT_MAX_SEND_SPEED_LARGE, (curl_off_t)max_ul * 1024);
	if (max_dl >= 0)
		curl_easy_setopt(h->curl, CURLOPT_MAX_RECV_SPEED_LARGE, (curl_off_t)max_dl * 1024);
}

void http_set_proxy(struct http *h, const gchar *proxy)
{
	curl_easy_setopt(h->curl, CURLOPT_PROXY, proxy);
}

void http_set_progress_callback(struct http *h, http_progress_fn cb, gpointer data)
{
	if (cb) {
		h->progress_cb = cb;
		h->progress_data = data;

		curl_easy_setopt(h->curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(h->curl, CURLOPT_PROGRESSFUNCTION, (curl_progress_callback)curl_progress);
		curl_easy_setopt(h->curl, CURLOPT_PROGRESSDATA, h);
	} else {
		curl_easy_setopt(h->curl, CURLOPT_NOPROGRESS, 1L);
	}
}

static void add_header(gchar *key, gchar *val, struct curl_slist **l)
{
	gchar *tmp = g_strdup_printf("%s: %s", key, val);
	*l = curl_slist_append(*l, tmp);
	g_free(tmp);
}

static size_t append_gstring(void *buffer, size_t size, size_t nmemb, GString *str)
{
	if (size * nmemb > 0)
		g_string_append_len(str, buffer, size * nmemb);

	return nmemb;
}

static gboolean to_error(struct http* h, CURLcode res, GError** err)
{
	glong http_status = 0;

	if (res == CURLE_OK) {
		if (curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &http_status) == CURLE_OK) {
			if (http_status == 200 || http_status == 201)
				return FALSE;
			else if (http_status == 500)
				g_set_error(err, HTTP_ERROR, HTTP_ERROR_SERVER_BUSY,
					    "Server returned %ld (probably busy)", http_status);
			else if (http_status == 509)
				g_set_error(err, HTTP_ERROR, HTTP_ERROR_BANDWIDTH_LIMIT,
					    "Server returned %ld (over quota)", http_status);
			else
				g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Server returned %ld", http_status);
		} else
			g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Can't get http status code");
	} else if (res == CURLE_OPERATION_TIMEDOUT)
		g_set_error(err, HTTP_ERROR, HTTP_ERROR_TIMEOUT, "CURL timeout: %s", curl_easy_strerror(res));
	else if (res == CURLE_RECV_ERROR
			|| res == CURLE_SEND_ERROR
			|| res == CURLE_SSL_CONNECT_ERROR
			|| res == CURLE_UPLOAD_FAILED
#if CURL_AT_LEAST_VERSION(7, 50, 3)
			|| res == CURLE_WEIRD_SERVER_REPLY
#endif
#if CURL_AT_LEAST_VERSION(7, 49, 0)
			|| res == CURLE_HTTP2_STREAM
#endif
#if CURL_AT_LEAST_VERSION(7, 38, 0)
			|| res == CURLE_HTTP2
#endif
			|| res == CURLE_COULDNT_CONNECT)
		g_set_error(err, HTTP_ERROR, HTTP_ERROR_COMM_FAILURE, "CURL error: %s", curl_easy_strerror(res));
	else if (res == CURLE_GOT_NOTHING)
		g_set_error(err, HTTP_ERROR, HTTP_ERROR_NO_RESPONSE, "CURL error: %s", curl_easy_strerror(res));
	else
		g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "CURL error: %s", curl_easy_strerror(res));

	return TRUE;
}

GString *http_post(struct http *h, const gchar *url, const gchar *body, gssize body_len, GError **err)
{
	struct curl_slist *headers = NULL;
	GString *response;
	CURLcode res;

	g_return_val_if_fail(h != NULL, NULL);
	g_return_val_if_fail(url != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	// setup post headers and url
	curl_easy_setopt(h->curl, CURLOPT_POST, 1L);
	curl_easy_setopt(h->curl, CURLOPT_URL, url);
	g_hash_table_foreach(h->headers, (GHFunc)add_header, &headers);
	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, headers);

	// pass request body
	if (body) {
		curl_easy_setopt(h->curl, CURLOPT_NOBODY, 0L);
		curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
	} else {
		curl_easy_setopt(h->curl, CURLOPT_NOBODY, 1L);
		curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, NULL);
		curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, 0L);
	}

	// prepare buffer for the response body
	response = g_string_sized_new(1024);
	curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, (curl_write_callback)append_gstring);
	curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, response);

	// perform HTTP request
	res = curl_easy_perform(h->curl);
	if (to_error(h, res, err)) {
		g_string_free(response, TRUE);
		response = NULL;
	}

	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(headers);

	return response;
}

struct stream_data {
	http_data_fn cb;
	gpointer user_data;
};

static size_t curl_read(void *buffer, size_t size, size_t nmemb, struct stream_data *data)
{
	return data->cb(buffer, size * nmemb, data->user_data);
}

GString *http_post_stream_upload(struct http *h, const gchar *url, goffset len, http_data_fn read_cb,
				 gpointer user_data, GError **err)
{
	struct curl_slist *headers = NULL;
	GString *response;
	CURLcode res;
	struct stream_data data;

	g_return_val_if_fail(h != NULL, NULL);
	g_return_val_if_fail(url != NULL, NULL);
	g_return_val_if_fail(err == NULL || *err == NULL, NULL);

	// setup post headers and url
	curl_easy_setopt(h->curl, CURLOPT_POST, 1L);
	curl_easy_setopt(h->curl, CURLOPT_URL, url);

	// setup request post body writer
	http_set_content_length(h, len);
	curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE_LARGE, len);

	data.cb = read_cb;
	data.user_data = user_data;
	curl_easy_setopt(h->curl, CURLOPT_READFUNCTION, (curl_read_callback)curl_read);
	curl_easy_setopt(h->curl, CURLOPT_READDATA, &data);

	// prepare buffer for the response body
	response = g_string_sized_new(512);
	curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, (curl_write_callback)append_gstring);
	curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, response);

	g_hash_table_foreach(h->headers, (GHFunc)add_header, &headers);
	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, headers);

	// perform HTTP request
	res = curl_easy_perform(h->curl);
	if (to_error(h, res, err)) {
		g_string_free(response, TRUE);
		response = NULL;
	}

	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(headers);

	return response;
}

static size_t curl_write(void *buffer, size_t size, size_t nmemb, struct stream_data *data)
{
	return data->cb(buffer, size * nmemb, data->user_data);
}

static CURLcode curl_easy_perform_retry_empty(CURL *curl)
{
	gint delay = 250000; // repeat after 250ms 500ms 1s ...
	CURLcode res;

again:
	res = curl_easy_perform(curl);
	if (res == CURLE_GOT_NOTHING) {
		g_usleep(delay);
		delay = delay * 2;

		if (delay > 4 * 1000 * 1000)
			return CURLE_GOT_NOTHING;

		goto again;
	}

	return res;
}

gboolean http_post_stream_download(struct http *h, const gchar *url, http_data_fn write_cb, gpointer user_data,
				   GError **err)
{
	struct curl_slist *headers = NULL;
	CURLcode res;
	struct stream_data data;
	gboolean status = TRUE;

	g_return_val_if_fail(h != NULL, FALSE);
	g_return_val_if_fail(url != NULL, FALSE);
	g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

	// setup post headers and url
	curl_easy_setopt(h->curl, CURLOPT_POST, 1L);
	curl_easy_setopt(h->curl, CURLOPT_URL, url);

	// request is empty
	curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, 0);

	// setup response writer
	data.cb = write_cb;
	data.user_data = user_data;
	curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, (curl_write_callback)curl_write);
	curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, &data);

	g_hash_table_foreach(h->headers, (GHFunc)add_header, &headers);
	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, headers);

	// perform HTTP request
	res = curl_easy_perform_retry_empty(h->curl);
	if (to_error(h, res, err))
		status = FALSE;

	curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(headers);
	return status;
}

void http_free(struct http *h)
{
	if (!h)
		return;

	g_hash_table_unref(h->headers);
	curl_easy_cleanup(h->curl);

	memset(h, 0, sizeof(struct http));
	g_free(h);
}

GQuark http_error_quark(void)
{
	return g_quark_from_static_string("http-error-quark");
}
