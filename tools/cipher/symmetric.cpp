/**
 * @file symmetric.cpp
 * @date 2026-09-23
 * @brief Щуп симметричных ядер по составляющим: ChaCha20, Poly1305, ChaCha20-Poly1305, гамма
 *        счётчика AES, GHASH и AES-GCM порознь на длинах записи (1 200 и 16 384 байта) и на 64 КиБ;
 *        эталон OpenSSL через EVP
 * @details Каждый замер повторяет и заведение заполнения, и саму работу - так же, как режим ведёт
 *          запись связи; полоса берётся лучшей из семи прогонов, а всякая работа прежде замера
 *          проводится один раз и обязана удаться (молчаливый отказ мерился бы мгновением). Снятие
 *          GCM и ChaCha20-Poly1305 меряется поточным путём (restart, associate, decrypt, verify) -
 *          так снимает записи слой защиты. Собирается из корня дерева: c++ -std=c++17 -O3 -DNDEBUG
 *          -I include tools/cipher/symmetric.cpp build/libnts.a -lpthread; с эталоном - ещё
 *          -DWITH_OPENSSL и -lcrypto (Poly1305 порознь у эталона доступен с OpenSSL 3.0 через EVP_MAC).
 *          Числа круга 37 (23.09.2026, 64 КиБ, МБ/с, наше → после круга при эталоне): M4 - ChaCha20 1 878 → 2 827 при 3 024,
 *          Poly1305 4 671 → 5 246 при 8 194, ChaCha20-Poly1305 1 331 → 1 823 при 2 170, AES-256-GCM 7 972 → 8 097 при 9 141,
 *          гамма счётчика 1 263 → 9 094 при 13 748; Xeon E5-2630 v4 (AVX2, PCLMULQDQ) - Poly1305 928 → 3 041 при 3 384,
 *          ChaCha20-Poly1305 564 → 987 при 1 141, GHASH 2 811 → 5 379 при 6 299, AES-256-GCM 1 234 → 1 565 при 1 983,
 *          гамма счётчика 284 → 1 562 при 2 387; стенды QEMU (AES-NI без PCLMULQDQ и AVX2) - Poly1305 1 016…1 074 →
 *          2 120…2 302 при 2 203…2 227, ChaCha20-Poly1305 456…462 → 585…623 при 668…676; Эльбрус - гамма счётчика 62 →
 *          120 при 188, ChaCha20-Poly1305 428 при 109
 * @copyright Copyright © 2026
 */

#include <cipher/aes.hpp>
#include <cipher/gcm.hpp>
#include <cipher/mode.hpp>
#include <cipher/chacha.hpp>
#include <cipher/poly1305.hpp>
#include <cipher/chachapoly.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#if defined(WITH_OPENSSL)
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#endif
using namespace std;
using namespace nts;
/**
 * Лучшая полоса из семи прогонов в МБ/с: каждый прогон гонит около восьми мегабайтов; работа
 * прежде замера проводится один раз и обязана удаться
 */
template <typename F>
static double band(const char * name, const size_t bytes, F && f){
	if(!f()){ printf("%s на %zu байтах не удалась\n", name, bytes); exit(1); }
	const size_t n = max <size_t> (1, (8u << 20) / bytes);
	double result = 0;
	for(int r = 0; r < 7; r++){
		auto t0 = chrono::steady_clock::now();
		for(size_t i = 0; i < n; i++) f();
		auto t1 = chrono::steady_clock::now();
		const double seconds = chrono::duration <double> (t1 - t0).count();
		result = max(result, (static_cast <double> (bytes) * n) / seconds / 1e6);
	}
	return result;
}
static void show(const char * name, const size_t bytes, const double ours, const double ref){
	if(ref > 0) printf("%-30s %6zu %9.1f МБ/с  эталон %9.1f  %5.2f\n", name, bytes, ours, ref, ref / ours);
	else printf("%-30s %6zu %9.1f МБ/с\n", name, bytes, ours);
}
int main(){
	static const size_t SIZES[3] = {1200, 16384, 65536};
	uint8_t key[32], nonce[16], tag[16];
	for(size_t i = 0; i < 32; i++) key[i] = static_cast <uint8_t> (i * 7 + 1);
	for(size_t i = 0; i < 16; i++) nonce[i] = static_cast <uint8_t> (i * 3 + 5);
	vector <uint8_t> data(65536), result(65536), plain(65536);
	for(size_t i = 0; i < data.size(); i++) data[i] = static_cast <uint8_t> (i * 31 + 7);
#if defined(WITH_OPENSSL)
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC * mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
	EVP_MAC_CTX * mctx = (mac != nullptr ? EVP_MAC_CTX_new(mac) : nullptr);
	#endif
#endif
	cipher::chacha_t chacha;
	cipher::poly1305_t poly;
	cipher::chachapoly_t chachapoly;
	cipher::aes_t aes256, aes128;
	if(!aes256.key(view_t(key, 32)) || !aes128.key(view_t(key, 16))){ printf("Ключ AES не установился\n"); return 1; }
	const cipher::block_t block256(aes256), block128(aes128);
	cipher::counter_t counter;
	cipher::gcm_t gcm, gcm128;
	if(!gcm.start(block256, view_t(nonce, 12)) || !gcm128.start(block128, view_t(nonce, 12)) || !chachapoly.start(view_t(key, 32), view_t(nonce, 12))){ printf("Режимы не завелись\n"); return 1; }
	// Проверка сходимости с эталоном до замеров: ChaCha20-Poly1305 и AES-256-GCM на 1 200 байтах
	{
		uint8_t ourTag[16];
		if(!chachapoly.encrypt(view_t(nullptr, 0), view_t(data.data(), 1200), result.data(), ourTag)){ printf("ChaCha20-Poly1305 не завёлся\n"); return 1; }
#if defined(WITH_OPENSSL)
		int len = 0; uint8_t refTag[16];
		EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
		EVP_EncryptUpdate(ctx, plain.data(), &len, data.data(), 1200);
		EVP_EncryptFinal_ex(ctx, plain.data() + len, &len);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, refTag);
		if(memcmp(plain.data(), result.data(), 1200) != 0 || memcmp(refTag, ourTag, 16) != 0){ printf("ChaCha20-Poly1305 расходится с эталоном\n"); return 1; }
#endif
		if(!gcm.restart(view_t(nonce, 12)) || !gcm.encrypt(view_t(nullptr, 0), view_t(data.data(), 1200), result.data(), ourTag)){ printf("AES-256-GCM не завёлся\n"); return 1; }
#if defined(WITH_OPENSSL)
		EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, nonce);
		EVP_EncryptUpdate(ctx, plain.data(), &len, data.data(), 1200);
		EVP_EncryptFinal_ex(ctx, plain.data() + len, &len);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, refTag);
		if(memcmp(plain.data(), result.data(), 1200) != 0 || memcmp(refTag, ourTag, 16) != 0){ printf("AES-256-GCM расходится с эталоном\n"); return 1; }
#endif
	}
	printf("%-30s %6s %9s       %16s  %5s\n", "работа", "байтов", "наша", "OpenSSL", "раз");
	for(size_t s = 0; s < 3; s++){
		const size_t n = SIZES[s];
		const int len32 = static_cast <int> (n);
		double ref = 0;
		// ChaCha20: гамма
		const double ours1 = band("ChaCha20", n, [&]{ return chacha.start(view_t(key, 32), view_t(nonce, 12), 1) && chacha.encrypt(view_t(data.data(), n), result.data()); });
#if defined(WITH_OPENSSL)
		ref = band("ChaCha20 эталона", n, [&]{ int len = 0; return (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, nonce) == 1) && (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), len32) == 1); });
#endif
		show("ChaCha20", n, ours1, ref);
		// Poly1305: имитовставка
		const double ours2 = band("Poly1305", n, [&]{ return poly.start(view_t(key, 32)) && poly.update(view_t(data.data(), n)) && poly.finish(tag); });
		ref = 0;
#if defined(WITH_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		if(mctx != nullptr) ref = band("Poly1305 эталона", n, [&]{ size_t len = 0; return (EVP_MAC_init(mctx, key, 32, nullptr) == 1) && (EVP_MAC_update(mctx, data.data(), n) == 1) && (EVP_MAC_final(mctx, tag, &len, 16) == 1); });
#endif
		show("Poly1305", n, ours2, ref);
		// ChaCha20-Poly1305: наложение
		const double ours3 = band("ChaCha20-Poly1305 seal", n, [&]{ return chachapoly.start(view_t(key, 32), view_t(nonce, 12)) && chachapoly.encrypt(view_t(nullptr, 0), view_t(data.data(), n), result.data(), tag); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("ChaCha20-Poly1305 seal эталона", n, [&]{ int len = 0; return (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce) == 1) && (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), len32) == 1) && (EVP_EncryptFinal_ex(ctx, result.data() + len, &len) == 1) && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1); });
#endif
		show("ChaCha20-Poly1305 seal", n, ours3, ref);
		// ChaCha20-Poly1305: снятие поточным путём, как у слоя защиты
		chachapoly.start(view_t(key, 32), view_t(nonce, 12)); chachapoly.encrypt(view_t(nullptr, 0), view_t(data.data(), n), result.data(), tag);
		const double ours3b = band("ChaCha20-Poly1305 open", n, [&]{ return chachapoly.start(view_t(key, 32), view_t(nonce, 12)) && chachapoly.decrypt(view_t(result.data(), n), plain.data()) && chachapoly.verify(view_t(tag, 16)); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("ChaCha20-Poly1305 open эталона", n, [&]{ int len = 0; return (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce) == 1) && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1) && (EVP_DecryptUpdate(ctx, plain.data(), &len, result.data(), len32) == 1) && (EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) == 1); });
#endif
		show("ChaCha20-Poly1305 open", n, ours3b, ref);
		// AES-256-CTR: гамма счётчика, синхропосылка в половину блока
		const double ours4 = band("AES-256-CTR", n, [&]{ return counter.start(block256, view_t(nonce, 8)) && counter.encrypt(view_t(data.data(), n), result.data()); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("AES-256-CTR эталона", n, [&]{ int len = 0; return (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, nonce) == 1) && (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), len32) == 1); });
#endif
		show("AES-256-CTR", n, ours4, ref);
		// GHASH: связанные данные без текста
		const double ours5 = band("GHASH", n, [&]{ return gcm.restart(view_t(nonce, 12)) && gcm.encrypt(view_t(data.data(), n), view_t(nullptr, 0), nullptr, tag); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("GHASH эталона", n, [&]{ int len = 0; return (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, nonce) == 1) && (EVP_EncryptUpdate(ctx, nullptr, &len, data.data(), len32) == 1) && (EVP_EncryptFinal_ex(ctx, result.data(), &len) == 1) && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1); });
#endif
		show("GHASH (GCM, только AAD)", n, ours5, ref);
		// AES-256-GCM: наложение
		const double ours6 = band("AES-256-GCM seal", n, [&]{ return gcm.restart(view_t(nonce, 12)) && gcm.encrypt(view_t(nullptr, 0), view_t(data.data(), n), result.data(), tag); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("AES-256-GCM seal эталона", n, [&]{ int len = 0; return (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, nonce) == 1) && (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), len32) == 1) && (EVP_EncryptFinal_ex(ctx, result.data() + len, &len) == 1) && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1); });
#endif
		show("AES-256-GCM seal", n, ours6, ref);
		// AES-256-GCM: снятие поточным путём, как у слоя защиты
		gcm.restart(view_t(nonce, 12)); gcm.encrypt(view_t(nullptr, 0), view_t(data.data(), n), result.data(), tag);
		const double ours6b = band("AES-256-GCM open", n, [&]{ return gcm.restart(view_t(nonce, 12)) && gcm.decrypt(view_t(result.data(), n), plain.data()) && gcm.verify(view_t(tag, 16)); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("AES-256-GCM open эталона", n, [&]{ int len = 0; return (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, nonce) == 1) && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1) && (EVP_DecryptUpdate(ctx, plain.data(), &len, result.data(), len32) == 1) && (EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) == 1); });
#endif
		show("AES-256-GCM open", n, ours6b, ref);
		// AES-128-GCM: наложение
		const double ours7 = band("AES-128-GCM seal", n, [&]{ return gcm128.restart(view_t(nonce, 12)) && gcm128.encrypt(view_t(nullptr, 0), view_t(data.data(), n), result.data(), tag); });
		ref = 0;
#if defined(WITH_OPENSSL)
		ref = band("AES-128-GCM seal эталона", n, [&]{ int len = 0; return (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, nonce) == 1) && (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), len32) == 1) && (EVP_EncryptFinal_ex(ctx, result.data() + len, &len) == 1) && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1); });
#endif
		show("AES-128-GCM seal", n, ours7, ref);
		printf("\n");
	}
#if defined(WITH_OPENSSL)
	EVP_CIPHER_CTX_free(ctx);
	#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if(mctx != nullptr) EVP_MAC_CTX_free(mctx);
	if(mac != nullptr) EVP_MAC_free(mac);
	#endif
#endif
	return 0;
}
