/* Щуп: замер подписи, сличения и обмена ключами ГОСТ 34.10 у эталона OpenSSL */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static double now(void){
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

static void fail(const char * what){
	fprintf(stderr, "отказ: %s\n", what);
	ERR_print_errors_fp(stderr);
	exit(1);
}

static EVP_PKEY * keygen(OSSL_LIB_CTX * ctx){
	EVP_PKEY_CTX * kc = EVP_PKEY_CTX_new_from_name(ctx, "gost2012_256", NULL);
	if(kc == NULL) fail("EVP_PKEY_CTX_new_from_name");
	if(EVP_PKEY_keygen_init(kc) <= 0) fail("keygen_init");
	if(EVP_PKEY_CTX_ctrl_str(kc, "paramset", "A") <= 0) fail("paramset");
	EVP_PKEY * key = NULL;
	if(EVP_PKEY_keygen(kc, &key) <= 0) fail("keygen");
	EVP_PKEY_CTX_free(kc);
	return key;
}

int main(void){
	OSSL_LIB_CTX * ctx = OSSL_LIB_CTX_new();
	if(OSSL_PROVIDER_load(ctx, "default") == NULL) fail("провайдер default");
	if(OSSL_PROVIDER_load(ctx, "gostprov") == NULL) fail("провайдер gostprov");

	EVP_PKEY * mine = keygen(ctx);
	EVP_PKEY * peer = keygen(ctx);

	unsigned char digest[32];
	for(size_t i = 0; i < sizeof(digest); i++) digest[i] = (unsigned char) i;

	unsigned char sig[128];
	size_t siglen = sizeof(sig);

	/* подпись */
	EVP_PKEY_CTX * sc = EVP_PKEY_CTX_new_from_pkey(ctx, mine, NULL);
	if(sc == NULL || EVP_PKEY_sign_init(sc) <= 0) fail("sign_init");
	if(EVP_PKEY_sign(sc, sig, &siglen, digest, sizeof(digest)) <= 0) fail("sign");

	size_t rounds = 2000;
	double t = now();
	for(size_t i = 0; i < rounds; i++){
		size_t len = sizeof(sig);
		if(EVP_PKEY_sign(sc, sig, &len, digest, sizeof(digest)) <= 0) fail("sign loop");
	}
	printf("подпись            %8.0f раз/с\n", (double) rounds / (now() - t));

	/* сличение */
	EVP_PKEY_CTX * vc = EVP_PKEY_CTX_new_from_pkey(ctx, mine, NULL);
	if(vc == NULL || EVP_PKEY_verify_init(vc) <= 0) fail("verify_init");
	if(EVP_PKEY_verify(vc, sig, siglen, digest, sizeof(digest)) <= 0) fail("verify");
	t = now();
	for(size_t i = 0; i < rounds; i++){
		if(EVP_PKEY_verify(vc, sig, siglen, digest, sizeof(digest)) <= 0) fail("verify loop");
	}
	printf("сличение подписи   %8.0f раз/с\n", (double) rounds / (now() - t));

	/* обмен ключами VKO */
	EVP_PKEY_CTX * dc = EVP_PKEY_CTX_new_from_pkey(ctx, mine, NULL);
	if(dc == NULL || EVP_PKEY_derive_init(dc) <= 0) fail("derive_init");
	if(EVP_PKEY_derive_set_peer(dc, peer) <= 0) fail("set_peer");
	/* VKO требует пользовательского значения: без него провайдер отвечает «ukm not set» */
	unsigned char ukm[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string("ukm", ukm, sizeof(ukm)),
		OSSL_PARAM_construct_end()
	};
	if(EVP_PKEY_CTX_set_params(dc, params) <= 0) fail("ukm");
	unsigned char shared[64];
	size_t shlen = sizeof(shared);
	if(EVP_PKEY_derive(dc, shared, &shlen) <= 0) fail("derive");
	t = now();
	for(size_t i = 0; i < rounds; i++){
		size_t len = sizeof(shared);
		if(EVP_PKEY_derive(dc, shared, &len) <= 0) fail("derive loop");
	}
	printf("обмен ключами VKO  %8.0f раз/с\n", (double) rounds / (now() - t));
	return 0;
}
