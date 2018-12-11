/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 */

/*! \defgroup jws JSON Web Signature
 * ## JSON Web Signature API
 *
 * Lws provides an API to check and create RFC7515 JSON Web Signatures
 *
 * SHA256/384/512 HMAC, and RSA 256/384/512 are supported.
 *
 * The API uses your TLS library crypto, but works exactly the same no matter
 * what you TLS backend is.
 */
///@{

struct lws_jws {
	const struct lws_jose_jwe_alg *args; /* algorithm info used for sig */
	struct lws_jwk *jwk; /* the struct lws_jwk containing the signing key */
	struct lws_context *context; /* the lws context (used to get random) */

	const char *b64_hdr; /* protected header encoded in b64, may be NULL */
	const char *b64_pay; /* payload encoded in b64 */
	char *b64_sig; /* buffer to write the b64 encoded signature into */
	const char *b64_unprot_hdr; /* unprotected header in b64, may be NULL */
	size_t hdr_len; /* bytes in b64 coding of protected header */
	size_t pay_len; /* bytes in b64 coding of payload */
	size_t sig_len; /* max bytes we can write at b64_sig */
	size_t b64_unprot_hdr_len; /* bytes in unprotected JSON hdr */
};

LWS_VISIBLE LWS_EXTERN int
lws_jws_confirm_sig(const char *in, size_t len, struct lws_jwk *jwk,
		    struct lws_context *context);

/**
 * lws_jws_sign_from_b64() - add b64 sig to b64 hdr + payload
 *
 * \param jws: information to include in the signature
 *
 * This adds a b64-coded JWS signature of the b64-encoded protected header
 * and b64-encoded payload, at \p b64_sig.  The signature will be as large
 * as the N element of the RSA key when the RSA key is used, eg, 512 bytes for
 * a 4096-bit key, and then b64-encoding on top.
 *
 * In some special cases, there is only payload to sign and no header, in that
 * case \p b64_hdr may be NULL, and only the payload will be hashed before
 * signing.
 *
 * Returns the length of the encoded signature written to \p b64_sig, or -1.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sign_from_b64(struct lws_jws *jws);

/**
 * lws_jws_write_flattened_json() - create flattened JSON sig
 *
 * \param jws: information to include in the signature
 * \param flattened: output buffer for JSON
 * \param len: size of \p flattened output buffer
 *
 */

LWS_VISIBLE int
lws_jws_write_flattened_json(struct lws_jws *jws, char *flattened, size_t len);

/**
 * lws_jws_base64_enc() - encode input data into b64url data
 *
 * \param in: the incoming plaintext
 * \param in_len: the length of the incoming plaintext in bytes
 * \param out: the buffer to store the b64url encoded data to
 * \param out_max: the length of \p out in bytes
 *
 * Returns either -1 if problems, or the number of bytes written to \p out.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max);

/**
 * lws_jws_encode_section() - encode input data into b64url data, prepending . if not first
 *
 * \param in: the incoming plaintext
 * \param in_len: the length of the incoming plaintext in bytes
 * \param first: nonzero if the first section
 * \param out: the buffer to store the b64url encoded data to
 * \param out_max: the length of \p out in bytes
 *
 * Returns either -1 if problems, or the number of bytes written to \p out.
 * If the section is not the first one, '.' is prepended.
 */

LWS_VISIBLE LWS_EXTERN int
lws_jws_encode_section(const char *in, size_t in_len, int first, char **p,
		       char *end);
///@}
