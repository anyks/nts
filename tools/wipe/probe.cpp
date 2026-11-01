/**
 * @file probe.cpp
 * @date 2026-09-23
 * @license{LicenseRef-A-NTS-1.0}
 * @author Yuriy Lobarev
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 * @email forman@anyks.com
 * @site https://anyks.com
 * @brief Щуп механизма затирания памяти: удерживает ли собиратель затирание ключа на
 *        стеке и какой полосой затирание идёт
 * @details Пять способов затирания области: голый memset, memset с барьером собирателя
 *          (BoringSSL, libsodium), пословная изменчивая запись (sys::wipe до круга 32),
 *          та же развёрнутая по четыре слова и memset через изменчивый указатель на
 *          функцию (OpenSSL, crypto/mem_clr.c; sys::wipe с круга 32 - он же с барьером).
 *          Каждый способ встраивается в функцию, где ключ на стеке отживает своё, и
 *          разбор порождённого кода (probe.sh) показывает, осталось ли затирание.
 *          Замер полосы идёт по области в 16 КиБ - длине записи TLS
 * @note Программа эта в сборку библиотеки не входит: она собирается щупом probe.sh
 *       тем собирателем и теми ключами, которые нужно проверить, в том числе с -flto
 * @note Разбор порождённого кода - единственный способ проверки: программа не может
 *       наблюдать, выброшена ли мёртвая запись, и проверкой набора это не ловится
 * @copyright Copyright © 2026
 *
 */

#include <cstring>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <chrono>
#include <vector>
/**
 * A: голый memset - собиратель вправе выбросить по правилу «как если бы»
 */
static inline void wipeA(void * p, size_t n){ ::memset(p, 0, n); }
/**
 * B: memset с барьером собирателя - путь BoringSSL, libsodium и explicit_bzero glibc
 */
static inline void wipeB(void * p, size_t n){ ::memset(p, 0, n); __asm__ __volatile__("" : : "r"(p) : "memory"); }
/**
 * C: пословная изменчивая запись - sys::wipe до круга 32
 */
static inline void wipeC(void * data, size_t size){
	// Ведём изменчивый указатель на затираемую область
	volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
	// Считаем сдвиг головы до выравнивания области на восемь байтов
	const size_t head = ((8 - (reinterpret_cast <uintptr_t> (data) & 7)) & 7);
	// Начинаем обход области с нуля
	size_t offset = 0;
	/**
	 * Затираем голову области посимвольно до выравнивания
	 */
	for(; (offset < head) && (offset < size); offset++) item[offset] = 0;
	/**
	 * Затираем выровненную часть области пословно
	 */
	for(; (offset + 8) <= size; offset += 8)
		// Затираем очередное слово области
		*reinterpret_cast <volatile uint64_t *> (static_cast <uint8_t *> (data) + offset) = 0;
	/**
	 * Затираем хвост области посимвольно
	 */
	for(; offset < size; offset++) item[offset] = 0;
}
/**
 * D: пословная изменчивая запись, развёрнутая по четыре слова
 */
static inline void wipeD(void * data, size_t size){
	// Ведём изменчивый указатель на затираемую область
	volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
	// Считаем сдвиг головы до выравнивания области на восемь байтов
	const size_t head = ((8 - (reinterpret_cast <uintptr_t> (data) & 7)) & 7);
	// Начинаем обход области с нуля
	size_t offset = 0;
	/**
	 * Затираем голову области посимвольно до выравнивания
	 */
	for(; (offset < head) && (offset < size); offset++) item[offset] = 0;
	/**
	 * Затираем середину области четвёрками слов
	 */
	for(; (offset + 32) <= size; offset += 32){
		// Ведём изменчивый указатель на четвёрку слов
		volatile uint64_t * w = reinterpret_cast <volatile uint64_t *> (static_cast <uint8_t *> (data) + offset);
		// Затираем четыре слова подряд
		w[0] = 0; w[1] = 0; w[2] = 0; w[3] = 0;
	}
	/**
	 * Затираем остаток области пословно
	 */
	for(; (offset + 8) <= size; offset += 8)
		// Затираем очередное слово области
		*reinterpret_cast <volatile uint64_t *> (static_cast <uint8_t *> (data) + offset) = 0;
	/**
	 * Затираем хвост области посимвольно
	 */
	for(; offset < size; offset++) item[offset] = 0;
}
/**
 * E: memset через изменчивый указатель на функцию - путь OpenSSL без ассемблера
 *    (crypto/mem_clr.c) и sys::wipe с круга 32 (там ещё и барьер B следом)
 */
typedef void * (* memset_t)(void *, int, size_t);
// Изменчивый указатель на memset не даёт собрать вызов на этапе сборки
static volatile memset_t memsetFunc = memset;
// Затираем область вызовом через изменчивый указатель
static inline void wipeE(void * p, size_t n){ memsetFunc(p, 0, n); }
/**
 * Ключ на стеке: остаётся ли затирание после встраивания способа в функцию
 */
#define KEYUSE(NAME, W) \
extern "C" __attribute__((noinline)) uint64_t NAME(const uint8_t * seed){ \
	uint8_t key[32]; uint64_t acc = 0; for(size_t i = 0; i < 32; i++) key[i] = (uint8_t)(seed[i] ^ 0x5a); for(size_t i = 0; i < 32; i++) acc = (acc * 31) + key[i]; \
	W(key, sizeof(key)); return acc; }
// Встраиваем способ A в щуп ключа на стеке
KEYUSE(keyA, wipeA)
KEYUSE(keyB, wipeB)
KEYUSE(keyC, wipeC)
KEYUSE(keyD, wipeD)
KEYUSE(keyE, wipeE)
/**
 * Замер полосы затирания области в 16 КиБ
 */
#define BENCH(NAME, W) \
__attribute__((noinline)) double NAME(uint8_t * buf, size_t n, size_t rounds){ \
	auto t0 = std::chrono::steady_clock::now(); for(size_t r = 0; r < rounds; r++){ buf[r & (n - 1)] = static_cast <uint8_t> (r); W(buf, n); } \
	auto t1 = std::chrono::steady_clock::now(); \
	double s = std::chrono::duration <double> (t1 - t0).count(); \
	return ((double) n * rounds) / s / 1e9; }
// Встраиваем способ A в щуп полосы затирания
BENCH(benchA, wipeA)
BENCH(benchB, wipeB)
BENCH(benchC, wipeC)
BENCH(benchD, wipeD)
BENCH(benchE, wipeE)
// Точка входа щупа
int main(int argc, char **){
	// Собираем зерно из доводов приложения
	uint8_t seed[32]; for(int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 7 + argc);
	// Отводим область затирания в 16 КиБ
	std::vector <uint8_t> buf(16384, 1);
	// Печатаем ключи, затёртые каждым способом
	printf("keys %llu %llu %llu %llu %llu\n", (unsigned long long) keyA(seed), (unsigned long long) keyB(seed), (unsigned long long) keyC(seed), (unsigned long long) keyD(seed), (unsigned long long) keyE(seed));
	// Число прогонов замера
	const size_t rounds = 100000;
	/**
	 * Выполняем два прохода замера полосы
	 */
	for(int pass = 0; pass < 2; pass++)
		// Печатаем полосу каждого способа затирания
		printf("16K GB/s: memset %.1f | memset+barrier %.1f | volatile x1 %.1f | volatile x4 %.1f | memset via volatile fn %.1f\n",
			benchA(buf.data(), 16384, rounds), benchB(buf.data(), 16384, rounds), benchC(buf.data(), 16384, rounds), benchD(buf.data(), 16384, rounds), benchE(buf.data(), 16384, rounds));
	// Возвращаем успех
	return 0;
}
