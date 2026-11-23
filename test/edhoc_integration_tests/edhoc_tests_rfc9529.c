/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <edhoc.h>
#include "txrx_wrapper.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "common/crypto_wrapper.h"

#include <psa/crypto.h>

volatile uint8_t msg_cnt = 1;

/* Messages of the RFC 9529 trace that the tx/rx callbacks expect or replay */
struct rfc9529_messages {
	const uint8_t *msg[4];
	const uint32_t *len[4];
};

static const struct rfc9529_messages t1_messages = {
	.msg = { T1_RFC9529__MESSAGE_1, T1_RFC9529__MESSAGE_2,
		 T1_RFC9529__MESSAGE_3, T1_RFC9529__MESSAGE_4 },
	.len = { &T1_RFC9529__MESSAGE_1_LEN, &T1_RFC9529__MESSAGE_2_LEN,
		 &T1_RFC9529__MESSAGE_3_LEN, &T1_RFC9529__MESSAGE_4_LEN },
};

static const struct rfc9529_messages t2_messages = {
	.msg = { T2_RFC9529__MESSAGE_1, T2_RFC9529__MESSAGE_2,
		 T2_RFC9529__MESSAGE_3, T2_RFC9529__MESSAGE_4 },
	.len = { &T2_RFC9529__MESSAGE_1_LEN, &T2_RFC9529__MESSAGE_2_LEN,
		 &T2_RFC9529__MESSAGE_3_LEN, &T2_RFC9529__MESSAGE_4_LEN },
};

/* RFC 9529 Section 3 with C_R = h'', see edhoc_test_vectors_rfc9529.c */
static const struct rfc9529_messages t2_empty_c_r_messages = {
	.msg = { T2_EMPTY_C_R__MESSAGE_1, T2_EMPTY_C_R__MESSAGE_2,
		 T2_EMPTY_C_R__MESSAGE_3, T2_EMPTY_C_R__MESSAGE_4 },
	.len = { &T2_EMPTY_C_R__MESSAGE_1_LEN, &T2_EMPTY_C_R__MESSAGE_2_LEN,
		 &T2_EMPTY_C_R__MESSAGE_3_LEN, &T2_EMPTY_C_R__MESSAGE_4_LEN },
};

static const struct rfc9529_messages *messages = &t1_messages;

enum err tx_fkt(void *sock, struct byte_array *data)
{
	if (msg_cnt >= 1 && msg_cnt <= 4) {
		zassert_equal(data->len, *messages->len[msg_cnt - 1],
			      "wrong message%d length", msg_cnt);
		zassert_mem_equal__(data->ptr, messages->msg[msg_cnt - 1],
				    data->len, "wrong message%d", msg_cnt);
	}

	msg_cnt++;
	return ok;
}

enum err rx_fkt(void *sock, struct byte_array *data)
{
	if (msg_cnt >= 1 && msg_cnt <= 4) {
		TRY(_memcpy_s(data->ptr, data->len, messages->msg[msg_cnt - 1],
			      *messages->len[msg_cnt - 1]));
		data->len = *messages->len[msg_cnt - 1];
	}

	msg_cnt++;
	return ok;
}

enum err ead_fkt(void *params, struct byte_array *ead13)
{
	return ok;
}

void test_edhoc_initiator_x509_x5t_rfc9529(void)
{
	messages = &t1_messages;
	msg_cnt = 1;
	enum err r;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t I_PRK_out_buf[32];
	struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
					.len = sizeof(I_PRK_out_buf) };

	uint8_t I_err_msg_buf[0];
	struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
					.len = sizeof(I_err_msg_buf) };

	c_i.sock = NULL;
	c_i.c_i.len = T1_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T1_RFC9529__C_I;
	c_i.method = (enum method_type)T1_RFC9529__METHOD;
	c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;
	c_i.g_i.len = 0;
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;
	c_i.i.ptr = NULL;
	c_i.sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i.sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i.pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i.pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;

	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.pk.len = T1_RFC9529__PK_R_LEN;
	cred_r.pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);

	zassert_mem_equal__(I_PRK_out.ptr, T1_RFC9529__PRK_out, I_PRK_out.len,
			    "wrong PRK_out");

	msg_cnt = 1;
}

void test_edhoc_responder_x509_x5t_rfc9529(void)
{
	messages = &t1_messages;
	msg_cnt = 1;
	enum err r;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t R_PRK_out_buf[32];
	struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
					.len = sizeof(R_PRK_out_buf) };

	uint8_t R_err_msg_buf[0];
	struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
					.len = sizeof(R_err_msg_buf) };

	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)T1_RFC9529__C_R;
	c_r.c_r.len = T1_RFC9529__C_R_LEN;
	c_r.suites_r.len = T1_RFC9529__SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T1_RFC9529__SUITES_R;
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	c_r.g_y.len = T1_RFC9529__G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T1_RFC9529__G_Y;
	c_r.y.len = T1_RFC9529__Y_LEN;
	c_r.y.ptr = (uint8_t *)T1_RFC9529__Y;
	c_r.g_r.len = 0;
	c_r.g_r.ptr = NULL;
	c_r.r.len = 0;
	c_r.r.ptr = NULL;
	c_r.sk_r.len = T1_RFC9529__SK_R_LEN;
	c_r.sk_r.ptr = (uint8_t *)T1_RFC9529__SK_R;
	c_r.pk_r.len = T1_RFC9529__PK_R_LEN;
	c_r.pk_r.ptr = (uint8_t *)T1_RFC9529__PK_R;

	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i.g.len = 0;
	cred_i.g.ptr = NULL;
	cred_i.pk.len = T1_RFC9529__PK_I_LEN;
	cred_i.pk.ptr = (uint8_t *)T1_RFC9529__PK_I;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);

	zassert_mem_equal__(R_PRK_out.ptr, T1_RFC9529__PRK_out, R_PRK_out.len,
			    "wrong PRK_out");

	msg_cnt = 1;
}

static void initiator_static_dh_kid(const struct rfc9529_messages *m,
				    const uint8_t *prk_out, uint32_t x_key_id,
				    uint32_t i_key_id)
{
	enum err r;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t I_PRK_out_buf[32];
	struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
					.len = sizeof(I_PRK_out_buf) };

	uint8_t I_err_msg_buf[0];
	struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
					.len = sizeof(I_err_msg_buf) };

	messages = m;
	msg_cnt = 1;

	c_i.sock = NULL;
	c_i.c_i.len = T2_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T2_RFC9529__C_I;
	c_i.method = (enum method_type)T2_RFC9529__METHOD;
	c_i.suites_i.len = T2_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T2_RFC9529__SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T2_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T2_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T2_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T2_RFC9529__CRED_I;
	c_i.g_x.len = T2_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T2_RFC9529__G_X;
	c_i.x.len = (0 == x_key_id) ? T2_RFC9529__X_LEN : 0;
	c_i.x.ptr = (0 == x_key_id) ? (uint8_t *)T2_RFC9529__X : NULL;
	c_i.x_key_id = x_key_id;
	c_i.g_i.len = T2_RFC9529__G_I_LEN;
	c_i.g_i.ptr = (uint8_t *)T2_RFC9529__G_I;
	c_i.i.len = (0 == i_key_id) ? T2_RFC9529__I_LEN : 0;
	c_i.i.ptr = (0 == i_key_id) ? (uint8_t *)T2_RFC9529__I : NULL;
	c_i.i_key_id = i_key_id;
	c_i.sk_i.len = 0;
	c_i.sk_i.ptr = NULL;
	c_i.pk_i.len = 0;
	c_i.pk_i.ptr = NULL;

	cred_r.id_cred.len = T2_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T2_RFC9529__ID_CRED_R;
	cred_r.cred.len = T2_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T2_RFC9529__CRED_R;
	cred_r.g.len = T2_RFC9529__G_R_LEN;
	cred_r.g.ptr = (uint8_t *)T2_RFC9529__G_R;
	cred_r.pk.len = 0;
	cred_r.pk.ptr = NULL;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);

	zassert_equal(r, ok, "edhoc_initiator_run failed: %d", r);
	zassert_mem_equal__(I_PRK_out.ptr, prk_out, I_PRK_out.len,
			    "wrong PRK_out");

	msg_cnt = 1;
}

static void responder_static_dh_kid(const struct rfc9529_messages *m,
				    const uint8_t *id_c_r, uint32_t id_c_r_len,
				    const uint8_t *prk_out, uint32_t y_key_id,
				    uint32_t r_key_id)
{
	enum err r;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t R_PRK_out_buf[32];
	struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
					.len = sizeof(R_PRK_out_buf) };

	uint8_t R_err_msg_buf[0];
	struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
					.len = sizeof(R_err_msg_buf) };

	messages = m;
	msg_cnt = 1;

	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)id_c_r;
	c_r.c_r.len = id_c_r_len;
	c_r.suites_r.len = T2_RFC9529__SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T2_RFC9529__SUITES_R;
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;
	c_r.id_cred_r.len = T2_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T2_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T2_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T2_RFC9529__CRED_R;
	c_r.g_y.len = T2_RFC9529__G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T2_RFC9529__G_Y;
	c_r.y.len = (0 == y_key_id) ? T2_RFC9529__Y_LEN : 0;
	c_r.y.ptr = (0 == y_key_id) ? (uint8_t *)T2_RFC9529__Y : NULL;
	c_r.y_key_id = y_key_id;
	c_r.g_r.len = T2_RFC9529__G_R_LEN;
	c_r.g_r.ptr = (uint8_t *)T2_RFC9529__G_R;
	c_r.r.len = (0 == r_key_id) ? T2_RFC9529__R_LEN : 0;
	c_r.r.ptr = (0 == r_key_id) ? (uint8_t *)T2_RFC9529__R : NULL;
	c_r.r_key_id = r_key_id;
	c_r.sk_r.len = 0;
	c_r.sk_r.ptr = NULL;
	c_r.pk_r.len = 0;
	c_r.pk_r.ptr = NULL;

	cred_i.id_cred.len = T2_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T2_RFC9529__ID_CRED_I;
	cred_i.cred.len = T2_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T2_RFC9529__CRED_I;
	cred_i.g.len = T2_RFC9529__G_I_LEN;
	cred_i.g.ptr = (uint8_t *)T2_RFC9529__G_I;
	cred_i.pk.len = 0;
	cred_i.pk.ptr = NULL;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);

	zassert_equal(r, ok, "edhoc_responder_run failed: %d", r);
	zassert_mem_equal__(R_PRK_out.ptr, prk_out, R_PRK_out.len,
			    "wrong PRK_out");

	msg_cnt = 1;
}

void test_edhoc_initiator_static_dh_kid_rfc9529(void)
{
	initiator_static_dh_kid(&t2_messages, T2_RFC9529__PRK_out, 0, 0);
}

void test_edhoc_responder_static_dh_kid_rfc9529(void)
{
	responder_static_dh_kid(&t2_messages, T2_RFC9529__C_R,
				T2_RFC9529__C_R_LEN, T2_RFC9529__PRK_out, 0, 0);
}

void test_edhoc_initiator_empty_c_r(void)
{
	initiator_static_dh_kid(&t2_empty_c_r_messages, T2_EMPTY_C_R__PRK_out,
				0, 0);
}

void test_edhoc_responder_empty_c_r(void)
{
	/* non-NULL pointer, as an application would pass a buffer */
	static const uint8_t empty_c_r[1];

	responder_static_dh_kid(&t2_empty_c_r_messages, empty_c_r, 0,
				T2_EMPTY_C_R__PRK_out, 0, 0);
}

static psa_key_id_t import_p256_key(const uint8_t *sk, uint32_t sk_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS, "psa_crypto_init failed");
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	zassert_equal(psa_import_key(&attr, sk, sk_len, &key_id), PSA_SUCCESS,
		      "psa_import_key failed");
	return key_id;
}

void test_edhoc_initiator_static_dh_kid_psa_rfc9529(void)
{
	psa_key_id_t x_key_id =
		import_p256_key(T2_RFC9529__X, T2_RFC9529__X_LEN);
	psa_key_id_t i_key_id =
		import_p256_key(T2_RFC9529__I, T2_RFC9529__I_LEN);

	initiator_static_dh_kid(&t2_messages, T2_RFC9529__PRK_out, x_key_id,
				i_key_id);

	psa_destroy_key(x_key_id);
	psa_destroy_key(i_key_id);
}

void test_edhoc_responder_static_dh_kid_psa_rfc9529(void)
{
	psa_key_id_t y_key_id =
		import_p256_key(T2_RFC9529__Y, T2_RFC9529__Y_LEN);
	psa_key_id_t r_key_id =
		import_p256_key(T2_RFC9529__R, T2_RFC9529__R_LEN);

	responder_static_dh_kid(&t2_messages, T2_RFC9529__C_R,
				T2_RFC9529__C_R_LEN, T2_RFC9529__PRK_out,
				y_key_id, r_key_id);

	psa_destroy_key(y_key_id);
	psa_destroy_key(r_key_id);
}

void test_ephemeral_dh_key_gen_psa(void)
{
	enum err r;
	uint32_t sk_id;
	uint8_t pk_buf[32];
	uint8_t psa_secret[32];
	uint8_t raw_secret[32];
	struct byte_array pk = BYTE_ARRAY_INIT(pk_buf, sizeof(pk_buf));
	struct byte_array peer_sk =
		BYTE_ARRAY_INIT((uint8_t *)T2_RFC9529__I, T2_RFC9529__I_LEN);
	struct byte_array peer_pk = BYTE_ARRAY_INIT((uint8_t *)T2_RFC9529__G_I,
						    T2_RFC9529__G_I_LEN);

	r = ephemeral_dh_key_gen_psa(P256, &sk_id, &pk);
	zassert_equal(r, ok, "ephemeral_dh_key_gen_psa failed: %d", r);
	zassert_not_equal(sk_id, 0, "no key ID");
	zassert_equal(pk.len, sizeof(pk_buf), "wrong public key length");

	r = shared_secret_derive_key(P256, &EMPTY_ARRAY, sk_id, &peer_pk,
				     psa_secret);
	zassert_equal(r, ok, "shared_secret_derive_key failed: %d", r);

	r = shared_secret_derive(P256, &peer_sk, &pk, raw_secret);
	zassert_equal(r, ok, "shared_secret_derive failed: %d", r);

	zassert_mem_equal__(psa_secret, raw_secret, sizeof(psa_secret),
			    "ECDH mismatch");

	psa_destroy_key(sk_id);

	r = ephemeral_dh_key_gen_psa(X25519, &sk_id, &pk);
	zassert_equal(r, unsupported_ecdh_curve, "X25519 must be rejected");
}
