/**
 * @file mlkem.cpp
 * @date 2026-09-23
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Щуп ML-KEM-768 по составляющим: выборка матрицы и шума, NTT, умножение в области
 *        NTT, упаковка, хеши SHA-3 и губка SHAKE128 порознь; эталон OpenSSL через EVP
 * @details Файл src/agreement/mlkem.cpp включается целиком ради доступа к служебным функциям
 *          безымянного пространства имён - иначе доли составляющих не измерить. Собирается из
 *          корня дерева: c++ -std=c++17 -O3 -DNDEBUG -I include -I src -I . tools/agreement/mlkem.cpp
 *          build/libnts.a -lpthread; с эталоном - ещё -DWITH_OPENSSL и -lcrypto (OpenSSL 3.5 и
 *          новее, где есть ML-KEM). Числа круга 35 (23.09.2026, M4): выработка пары 28,9 → 15,5 мкс
 *          при 23,6 у OpenSSL, инкапсуляция 29,2 → 14,3 при 15,4, раскрытие 37,3 → 19,6 при 24,2;
 *          доли: выборка многочлена матрицы 1 119 → 557 нс, биномиальная 524 → 171, прямое NTT
 *          1 005 → 583, обратное 465 → 357, умножение в NTT 239 → 108, SHA3-256 ключа 2 913 → 1 365.
 *          Круг 36 (23.09.2026): умножение в области NTT на подготовленном сомножителе (prepare,
 *          multiply, settle - скалярное произведение k = 3 на M4 339 → 126 нс, FreeBSD 3 633 → 284),
 *          упаковка узорами (M4 250 → 64), ядра Keccak на ассемблере x86-64 и на командах SHA-3
 *          AArch64 (FreeBSD перестановка 705 → 615, M4 145 → 127), губка блоками, векторное NTT на
 *          SSE2 и пакетных командах Эльбруса (FreeBSD прямое 1 177 → 324, Эльбрус 9 402 → 2 249):
 *          M4 12,7 / 12,9 / 16,8 → 11,4 / 9,9 / 12,7 мкс при 23,8 / 15,4 / 24,2 у OpenSSL, FreeBSD
 *          63,8 / 75,3 / 98,3 → 44,0 / 43,0 / 56,7 при 78,0 / 53,2 / 74,1. Оговорка сличения:
 *          OpenSSL считает H(ek) и разворачивает матрицу при разборе ключа (parse_pubkey), а не в
 *          инкапсуляции и раскрытии - в его числах этой работы нет, в наших есть
 * @copyright Copyright © 2026
 *
 */

#include "src/agreement/mlkem.cpp"
#include <chrono>
#include <cstdio>
#include <algorithm>
/**
 * Эталон подключается сборкой
 */
#if defined(WITH_OPENSSL)
#include <openssl/evp.h>
#endif
/**
 * Подключаем стандартные имена без повторов
 */
using namespace std;
// Объявляем шаблон метода замера
template <typename F>
static double best(F && f, size_t n, int reps = 7){
	// Начинаем с заведомо большого времени
	double result = 1e30;
	/**
	 * Выполняем заданное число прогонов
	 */
	for(int r = 0; r < reps; r++){
		// Запоминаем момент начала прогона
		auto t0 = chrono::steady_clock::now();
		/**
		 * Выполняем заданное число повторов
		 */
		for(size_t i = 0; i < n; i++) f();
		// Запоминаем момент конца прогона
		auto t1 = chrono::steady_clock::now();
		// Запоминаем лучшее время прогона
		result = min(result, chrono::duration <double, nano> (t1 - t0).count() / n);
	}
	// Возвращаем лучшее время
	return result;
}
// Печатаем время одного действия в наносекундах
static void show(const char * name, double ns){ printf("%-48s %10.1f нс\n", name, ns); }
// Точка входа щупа
int main(){
	// Набор параметров ML-KEM-768
	const agreement::kem_t kem = agreement::kem_t::MLKEM768;
	// Места ключей, шифртекста и общих секретов
	uint8_t key[1184], secret[2400], cipher[1088], shared1[32], shared2[32];
	// Выполняем полный цикл ML-KEM и сличаем общие секреты
	if(!agreement::generate(kem, key, secret) || !agreement::encapsulate(kem, view_t(key, sizeof(key)), cipher, shared1) || !agreement::decapsulate(kem, view_t(secret, sizeof(secret)), view_t(cipher, sizeof(cipher)), shared2) || ::memcmp(shared1, shared2, 32) != 0){ printf("ML-KEM не сошёлся\n"); return 1; }
	// Число повторов замера
	const size_t N1 = 2000;
	// Замеряем полный цикл ML-KEM-768
	show("ML-KEM-768 generate (наш)", best([&]{ agreement::generate(kem, key, secret); }, N1));
	show("ML-KEM-768 encapsulate (наш)", best([&]{ agreement::encapsulate(kem, view_t(key, sizeof(key)), cipher, shared1); }, N1));
	show("ML-KEM-768 decapsulate (наш)", best([&]{ agreement::decapsulate(kem, view_t(secret, sizeof(secret)), view_t(cipher, sizeof(cipher)), shared2); }, N1));
	// Составляющие
	const sample_t sample = describe(kem);
	// Вынимаем зерно матрицы и шум из ключей
	uint8_t rho[32], sigma[32]; ::memcpy(rho, key + 1152, 32); ::memcpy(sigma, secret, 32);
	// Многочлены матрицы, шума и произведения
	poly_t a, b, c;
	// Замеряем выборку многочлена матрицы
	show("sampling (матрица, один многочлен, SHAKE128)", best([&]{ sampling(rho, 0, 1, a); }, N1 * 5));
	show("binomial eta=2 (SHAKE256, 128 байт)", best([&]{ binomial(sigma, 3, 2, b); }, N1 * 5));
	show("forward NTT", best([&]{ forward(a); }, N1 * 20));
	show("inverse NTT", best([&]{ inverse(a); }, N1 * 20));
	// Готовим сомножитель и накопитель произведения
	twisted_t prepared; wide_t wide; ::memset(wide.values, 0, sizeof(wide.values));
	// Замеряем подготовку сомножителя
	show("prepare (сомножитель к умножению)", best([&]{ prepare(b, prepared); }, N1 * 20));
	show("multiply (умножение в NTT с накоплением)", best([&]{ multiply(a, prepared, wide); ::memset(wide.values, 0, sizeof(wide.values)); }, N1 * 20));
	show("settle (приведение накопителя)", best([&]{ settle(wide, c); }, N1 * 20));
	// Замеряем скалярное произведение на подготовленном сомножителе
	show("multiply ×3 + settle (скалярное произведение k=3)", best([&]{ ::memset(wide.values, 0, sizeof(wide.values)); multiply(a, prepared, wide); multiply(b, prepared, wide); multiply(c, prepared, wide); settle(wide, c); }, N1 * 20));
	// Место упакованного многочлена
	uint8_t out[384];
	// Замеряем кодирование многочлена
	show("encode", best([&]{ encode(a, out); }, N1 * 20));
	show("decode", best([&]{ decode(out, a); }, N1 * 20));
	show("pack du=10", best([&]{ pack(a, 10, out); }, N1 * 20));
	// Место сводки хеша
	uint8_t h[64];
	// Замеряем хеш ключа
	show("SHA3-256 ключа 1184 байт (H)", best([&]{ digest::sha3(digest::sha3_t::SHA3_256, view_t(key, 1184), h, 32); }, N1 * 5));
	show("SHA3-512 64 байт (G)", best([&]{ digest::sha3(digest::sha3_t::SHA3_512, view_t(key, 64), h, 64); }, N1 * 5));
	// Перестановка и губка
	digest::keccak_t xof(digest::sha3_t::SHAKE128);
	// Засеваем губку перестановки зерном матрицы
	xof.update(view_t(rho, 32));
	// Отводим место под блок губки
	uint8_t block[168];
	// Замеряем выдачу блока губкой
	show("SHAKE128 squeeze 168 байт (перестановка + выдача)", best([&]{ xof.squeeze(block, 168); }, N1 * 20));
	show("SHAKE128 squeeze 3 байта (как в sampling)", best([&]{ xof.squeeze(block, 3); }, N1 * 100));
	// Заводим вторую губку для поглощения
	digest::keccak_t abs(digest::sha3_t::SHAKE128);
	// Замеряем поглощение блока губкой
	show("SHAKE128 update 168 байт (поглощение + перестановка)", best([&]{ abs.update(view_t(key, 168)); }, N1 * 20));
	/**
	 * Сличение с эталоном подключается сборкой
	 */
	#if defined(WITH_OPENSSL)
		// Обнуляем ключевую пару эталона
		EVP_PKEY * pkey = nullptr;
		// Заводим контекст выработки ключа эталона
		EVP_PKEY_CTX * kctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr);
		// Вырабатываем ключевую пару ML-KEM-768 эталона
		EVP_PKEY_keygen_init(kctx); EVP_PKEY_keygen(kctx, &pkey);
		// Замеряем выработку ключа эталона
		show("ML-KEM-768 keygen (OpenSSL)", best([&]{ EVP_PKEY * p = nullptr; EVP_PKEY_keygen(kctx, &p); EVP_PKEY_free(p); }, N1));
		// Заводим контекст инкапсуляции эталона
		EVP_PKEY_CTX * ectx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
		// Заводим инкапсуляцию эталона
		EVP_PKEY_encapsulate_init(ectx, nullptr);
		// Отводим места шифртекста и общих секретов эталона
		size_t clen = 1088, slen = 32; uint8_t oc[1088], os[32], os2[32];
		// Выполняем инкапсуляцию эталона
		EVP_PKEY_encapsulate(ectx, oc, &clen, os, &slen);
		// Замеряем инкапсуляцию эталона
		show("ML-KEM-768 encaps (OpenSSL)", best([&]{ size_t cl = 1088, sl = 32; EVP_PKEY_encapsulate(ectx, oc, &cl, os, &sl); }, N1));
		// Заводим контекст декапсуляции эталона
		EVP_PKEY_CTX * dctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
		// Заводим декапсуляцию эталона
		EVP_PKEY_decapsulate_init(dctx, nullptr);
		// Замеряем декапсуляцию эталона
		show("ML-KEM-768 decaps (OpenSSL)", best([&]{ size_t sl = 32; EVP_PKEY_decapsulate(dctx, os2, &sl, oc, 1088); }, N1));
		// Заводим контекст хеширования эталона
		EVP_MD_CTX * md = EVP_MD_CTX_new();
		// Замеряем хеширование эталоном
		show("SHA3-256 1184 байт (OpenSSL)", best([&]{ unsigned l = 0; EVP_Digest(key, 1184, h, &l, EVP_sha3_256(), nullptr); }, N1 * 5));
		// Освобождаем контекст хеширования эталона
		EVP_MD_CTX_free(md);
	#endif
	// Возвращаем успех
	return 0;
}
