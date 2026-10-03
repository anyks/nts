/**
 * @file slhdsa.cpp
 * @date 2026-10-03
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
 * @brief Исходный файл модуля выработки и проверки электронной подписи
 *        SLH-DSA (безсостоянная хешированная подпись) по FIPS 205
 *
 * @details Устройство модуля:
 *
 * 1. Дерево подписи - гипердерево из d деревьев XMSS высотой h′: корень
 *    гипердерева и есть корень ключа проверки PK.root; лес FORS из k деревьев
 *    по 2^a листьев подписывает дайджест сообщения, а гипердерево подписывает
 *    корень FORS. Подпись - R ‖ k × (значение sk ‖ путь из a узлов) ‖ d
 *    подписей XMSS; цепочки WOTS+ (w = 16, len = 2n + 3) - внутри XMSS.
 * 2. Семейства хешей раздела 11 FIPS 205: у SHAKE все функции строятся на
 *    SHAKE-256 с адресом в 32 байта; у SHA2-128 (категория 1) - на SHA-256 с
 *    сжатым адресом в 22 байта и HMAC-SHA-256, H_MSG через MGF1-SHA-256; у
 *    SHA2-192/256 (категории 3 и 5) - F и PRF на SHA-256, H и T на SHA-512,
 *    HMAC-SHA-512, H_MSG через MGF1-SHA-512.
 * 3. Запись ключа подписи - форма стандарта SK.seed ‖ SK.prf ‖ PK.seed ‖
 *    PK.root без перекладки при установке: выработка подписи читает значения
 *    как есть. Зерно порождения - SK.seed ‖ SK.prf ‖ PK.seed, корень
 *    вычисляется вершиной дерева верхнего слоя. Вся рабочая память на стеке.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/slhdsa.hpp>
#include <digest/sha2.hpp>
#include <digest/sha3.hpp>
#include <digest/hmac.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Число значений цепочки WOTS+ (w = 16)
	 */
	static constexpr size_t CHAIN = 16;
	/**
	 * Число контрольных полубайтов WOTS+
	 */
	static constexpr size_t CHECKSUM = 3;
	/**
	 * Наибольшая длина значения n в байтах (наборы 256)
	 */
	static constexpr size_t MAX_N = 32;
	/**
	 * Наибольшая длина дайджеста сообщения в байтах (m набора 256f)
	 */
	static constexpr size_t MAX_M = 49;
	/**
	 * Наибольшее число деревьев FORS (k набора 128f и 192f, 256f - 35)
	 */
	static constexpr size_t MAX_K = 35;

	/**
	 * @brief Параметры набора параметров стандарта
	 *
	 */
	typedef struct {
		// Длина значения n в байтах
		uint8_t n;
		// Число деревьев гипердерева d
		uint8_t d;
		// Высота дерева XMSS h′
		uint8_t hm;
		// Число уровней дерева FORS a
		uint8_t a;
		// Число деревьев FORS k
		uint8_t k;
		// Длина дайджеста сообщения m в байтах
		uint8_t m;
		// Семейство хешей: SHAKE256, SHA2 категории 1, SHA2 категорий 3 и 5
		uint8_t family;
		// Размер ключа проверки в байтах (2n)
		uint16_t pub;
		// Размер подписи в байтах
		uint32_t signature;
	} Params;
	/**
	 * Семейство хешей SHAKE256
	 */
	static constexpr uint8_t FAMILY_SHAKE = 1;
	/**
	 * Семейство хешей SHA2 категории 1 (наборы 128)
	 */
	static constexpr uint8_t FAMILY_SHA2_1 = 2;
	/**
	 * Семейство хешей SHA2 категорий 3 и 5 (наборы 192 и 256)
	 */
	static constexpr uint8_t FAMILY_SHA2_35 = 3;

	/**
	 * @brief Метод получения параметров набора
	 *
	 * @param set набор параметров
	 *
	 * @return    параметры набора, нулевые у несуществующего
	 *
	 */
	static Params params(const sign::Slhdsa::set_t set) noexcept {
		switch(set){
			case sign::Slhdsa::set_t::SHA2_128S:  return {16, 7, 9, 12, 14, 30, FAMILY_SHA2_1, 32, 7856};
			case sign::Slhdsa::set_t::SHAKE_128S: return {16, 7, 9, 12, 14, 30, FAMILY_SHAKE, 32, 7856};
			case sign::Slhdsa::set_t::SHA2_128F:  return {16, 22, 3, 6, 33, 34, FAMILY_SHA2_1, 32, 17088};
			case sign::Slhdsa::set_t::SHAKE_128F: return {16, 22, 3, 6, 33, 34, FAMILY_SHAKE, 32, 17088};
			case sign::Slhdsa::set_t::SHA2_192S:  return {24, 7, 9, 14, 17, 39, FAMILY_SHA2_35, 48, 16224};
			case sign::Slhdsa::set_t::SHAKE_192S: return {24, 7, 9, 14, 17, 39, FAMILY_SHAKE, 48, 16224};
			case sign::Slhdsa::set_t::SHA2_192F:  return {24, 22, 3, 8, 33, 42, FAMILY_SHA2_35, 48, 35664};
			case sign::Slhdsa::set_t::SHAKE_192F: return {24, 22, 3, 8, 33, 42, FAMILY_SHAKE, 48, 35664};
			case sign::Slhdsa::set_t::SHA2_256S:  return {32, 8, 8, 14, 22, 47, FAMILY_SHA2_35, 64, 29792};
			case sign::Slhdsa::set_t::SHAKE_256S: return {32, 8, 8, 14, 22, 47, FAMILY_SHAKE, 64, 29792};
			case sign::Slhdsa::set_t::SHA2_256F:  return {32, 17, 4, 9, 35, 49, FAMILY_SHA2_35, 64, 49856};
			case sign::Slhdsa::set_t::SHAKE_256F: return {32, 17, 4, 9, 35, 49, FAMILY_SHAKE, 64, 49856};
			default: return {0, 0, 0, 0, 0, 0, 0, 0, 0};
		}
	}

	/**
	 * Адрес в 32 байта хеширования (раздел 4.2 FIPS 205): поля слоя (4),
	 * дерева (12), вида (4), пары (4), цепочки (4), шага (4) старшим байтом вперёд
	 */
	typedef uint8_t adrs_t[32];

	/**
	 * @brief Метод обнуления адреса
	 *
	 * @param adrs адрес
	 *
	 */
	static void zero(adrs_t adrs) noexcept {
		::memset(adrs, 0, sizeof(adrs_t));
	}
	/**
	 * @brief Метод копирования адреса
	 *
	 * @param dst приёмник
	 * @param src источник
	 *
	 */
	static void copyAdrs(adrs_t dst, const adrs_t src) noexcept {
		::memcpy(dst, src, sizeof(adrs_t));
	}
	/**
	 * @brief Метод установки адреса слоя
	 *
	 * @param p     параметры набора (сжатый адрес у SHA2)
	 * @param adrs  адрес
	 * @param layer адрес слоя
	 *
	 */
	static void setLayer(const Params & p, adrs_t adrs, const uint32_t layer) noexcept {
		// У семейства SHA2 слой занимает байт, у SHAKE - четыре старшим байтом вперёд
		if(p.family == FAMILY_SHAKE){
			adrs[0] = static_cast <uint8_t> (layer >> 24);
			adrs[1] = static_cast <uint8_t> (layer >> 16);
			adrs[2] = static_cast <uint8_t> (layer >> 8);
			adrs[3] = static_cast <uint8_t> (layer);
		} else
			adrs[0] = static_cast <uint8_t> (layer);
	}
	/**
	 * @brief Метод установки адреса дерева
	 *
	 * @param p     параметры набора
	 * @param adrs  адрес
	 * @param tree  адрес дерева, до 64 разрядов
	 *
	 */
	static void setTree(const Params & p, adrs_t adrs, const uint64_t tree) noexcept {
		// У семейства SHAKE дерево лежит в последних восьми байтах поля двенадцати
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 8 : 1);
		for(size_t i = 0; i < 8; i++)
			adrs[offset + i] = static_cast <uint8_t> (tree >> (56 - (8 * i)));
	}
	/**
	 * @brief Метод установки вида адреса с очисткой хвоста
	 *
	 * @param p    параметры набора
	 * @param adrs адрес
	 * @param type вид адреса
	 *
	 */
	static void setType(const Params & p, adrs_t adrs, const uint32_t type) noexcept {
		// У семейства SHAKE вид занимает четыре байта старшим байтом вперёд, у SHA2 - один
		if(p.family == FAMILY_SHAKE){
			adrs[16] = static_cast <uint8_t> (type >> 24);
			adrs[17] = static_cast <uint8_t> (type >> 16);
			adrs[18] = static_cast <uint8_t> (type >> 8);
			adrs[19] = static_cast <uint8_t> (type);
			// Хвост после вида обнуляется по правилу стандарта
			::memset((adrs + 20), 0, 12);
		} else {
			adrs[9] = static_cast <uint8_t> (type);
			// Хвост после вида обнуляется по правилу стандарта
			::memset((adrs + 10), 0, 12);
		}
	}
	/**
	 * @brief Метод установки адреса пары
	 *
	 * @param p      параметры набора
	 * @param adrs   адрес
	 * @param keypair адрес пары
	 *
	 */
	static void setKeypair(const Params & p, adrs_t adrs, const uint32_t keypair) noexcept {
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 20 : 10);
		for(size_t i = 0; i < 4; i++)
			adrs[offset + i] = static_cast <uint8_t> (keypair >> (24 - (8 * i)));
	}
	/**
	 * @brief Метод копирования адреса пары между адресами
	 *
	 * @param p   параметры набора
	 * @param dst приёмник
	 * @param src источник
	 *
	 */
	static void copyKeypair(const Params & p, adrs_t dst, const adrs_t src) noexcept {
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 20 : 10);
		::memcpy((dst + offset), (src + offset), 4);
	}
	/**
	 * @brief Метод установки адреса цепочки (он же высота дерева)
	 *
	 * @param p     параметры набора
	 * @param adrs  адрес
	 * @param chain адрес цепочки
	 *
	 */
	static void setChain(const Params & p, adrs_t adrs, const uint32_t chain) noexcept {
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 24 : 14);
		for(size_t i = 0; i < 4; i++)
			adrs[offset + i] = static_cast <uint8_t> (chain >> (24 - (8 * i)));
	}
	/**
	 * @brief Метод установки адреса шага (он же индекс дерева)
	 *
	 * @param p    параметры набора
	 * @param adrs адрес
	 * @param step адрес шага
	 *
	 */
	static void setStep(const Params & p, adrs_t adrs, const uint32_t step) noexcept {
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 28 : 18);
		for(size_t i = 0; i < 4; i++)
			adrs[offset + i] = static_cast <uint8_t> (step >> (24 - (8 * i)));
	}
	/**
	 * @brief Метод получения занятой длины адреса
	 *
	 * @param p параметры набора
	 *
	 * @return  длина адреса в байтах: 32 у SHAKE, 22 у SHA2
	 *
	 */
	static size_t adrsSize(const Params & p) noexcept {
		return ((p.family == FAMILY_SHAKE) ? 32 : 22);
	}

	/**
	 * @brief Метод функции F (по одному значению)
	 *
	 * @param p      параметры набора
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес
	 * @param m1     значение
	 * @param out    место результата, n байтов
	 *
	 */
	static void F(const Params & p, const uint8_t * pkSeed, const adrs_t adrs, const view_t & m1, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(p.family == FAMILY_SHAKE){
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(m1);
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 функция строится на SHA-256 с добивкой зерна нулями до 64 байтов
		} else {
			digest::sha2_t sha(digest::sha_t::SHA256);
			uint8_t full[32];
			const uint8_t padding[48] = {0};
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(m1);
			(void) sha.finish(full, sizeof(full));
			::memcpy(out, full, p.n);
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Метод функции H (по двум значениям)
	 *
	 * @param p      параметры набора
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес
	 * @param m1     первое значение, n байтов
	 * @param m2     второе значение, n байтов
	 * @param out    место результата, n байтов
	 *
	 */
	static void H(const Params & p, const uint8_t * pkSeed, const adrs_t adrs, const uint8_t * m1, const uint8_t * m2, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(p.family == FAMILY_SHAKE){
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(view_t(m1, p.n));
			xof.update(view_t(m2, p.n));
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 категорий 3 и 5 функция H строится на SHA-512 с добивкой зерна нулями до 128 байтов
		} else if(p.family == FAMILY_SHA2_35){
			digest::sha2_t sha(digest::sha_t::SHA512);
			uint8_t full[64];
			const uint8_t padding[128] = {0};
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (128 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(view_t(m1, p.n));
			sha.update(view_t(m2, p.n));
			(void) sha.finish(full, sizeof(full));
			::memcpy(out, full, p.n);
			sys::wipe(full, sizeof(full));
		// У семейства SHA2 категории 1 функция H строится на SHA-256
		} else {
			digest::sha2_t sha(digest::sha_t::SHA256);
			uint8_t full[32];
			const uint8_t padding[48] = {0};
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(view_t(m1, p.n));
			sha.update(view_t(m2, p.n));
			(void) sha.finish(full, sizeof(full));
			::memcpy(out, full, p.n);
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Метод функции T (по значению переменной длины)
	 *
	 * @param p      параметры набора
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес
	 * @param ml     значение переменной длины
	 * @param out    место результата, n байтов
	 *
	 */
	static void T(const Params & p, const uint8_t * pkSeed, const adrs_t adrs, const view_t & ml, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(p.family == FAMILY_SHAKE){
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(ml);
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 категорий 3 и 5 функция T строится на SHA-512
		} else if(p.family == FAMILY_SHA2_35){
			digest::sha2_t sha(digest::sha_t::SHA512);
			uint8_t full[64];
			const uint8_t padding[128] = {0};
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (128 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(ml);
			(void) sha.finish(full, sizeof(full));
			::memcpy(out, full, p.n);
			sys::wipe(full, sizeof(full));
		// У семейства SHA2 категории 1 функция T строится на SHA-256
		} else {
			digest::sha2_t sha(digest::sha_t::SHA256);
			uint8_t full[32];
			const uint8_t padding[48] = {0};
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(ml);
			(void) sha.finish(full, sizeof(full));
			::memcpy(out, full, p.n);
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Метод функции PRF (выработка значений из секретного зерна)
	 *
	 * @param p      параметры набора
	 * @param pkSeed открытое зерно ключа
	 * @param skSeed секретное зерно ключа
	 * @param adrs   адрес
	 * @param out    место результата, n байтов
	 *
	 */
	static void PRF(const Params & p, const uint8_t * pkSeed, const uint8_t * skSeed, const adrs_t adrs, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(p.family == FAMILY_SHAKE){
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(view_t(skSeed, p.n));
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 функция PRF строится на SHA-256
		} else {
			digest::sha2_t sha(digest::sha_t::SHA256);
			uint8_t full[32];
			const uint8_t padding[48] = {0};
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(view_t(skSeed, p.n));
			(void) sha.finish(full, sizeof(full));
			::memcpy(out, full, p.n);
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Метод порождения маски MGF1 по RFC 8017
	 *
	 * @param sha  разновидность хеша порождения
	 * @param seed зерно порождения
	 * @param out  место результата
	 * @param size длина результата в байтах
	 *
	 */
	static void MGF1(const digest::sha_t sha, const view_t & seed, uint8_t * out, const size_t size) noexcept {
		// Полный хеш очередного счётчика
		uint8_t full[64];
		// Длина полного хеша разновидности
		const size_t length = ((sha == digest::sha_t::SHA512) ? 64 : 32);
		// Счётчик блоков порождения старшим байтом вперёд
		uint8_t counter[4] = {0, 0, 0, 0};
		// Набранная длина результата
		size_t done = 0;
		while(done < size){
			// Порождаем очередной блок маски
			digest::sha2_t hash(sha);
			hash.update(seed);
			hash.update(view_t(counter, sizeof(counter)));
			(void) hash.finish(full, sizeof(full));
			// Переносим блок в результат
			const size_t take = (((size - done) < length) ? (size - done) : length);
			::memcpy((out + done), full, take);
			done += take;
			// Увеличиваем счётчик блоков
			for(size_t i = 4; (i > 0) && (++counter[i - 1] == 0); i--);
		}
		sys::wipe(full, sizeof(full));
	}
	/**
	 * @brief Метод цепочки WOTS+ (алгоритм 5 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param pkSeed открытое зерно ключа
	 * @param in     входное значение, n байтов
	 * @param start  индекс начала цепочки
	 * @param steps  число шагов от начала
	 * @param adrs   адрес вида WOTS_HASH с адресом цепочки
	 * @param out    место результата, n байтов
	 *
	 */
	static void wotsChain(const Params & p, const uint8_t * pkSeed, const uint8_t * in, const size_t start, const size_t steps, adrs_t adrs, uint8_t * out) noexcept {
		// Без шагов значение переносится как есть
		if(steps == 0){
			::memcpy(out, in, p.n);
			return;
		}
		// Первый шаг со входного значения
		setStep(p, adrs, static_cast <uint32_t> (start));
		F(p, pkSeed, adrs, view_t(in, p.n), out);
		// Остальные шаги по цепочке
		for(size_t j = (start + 1); j < (start + steps); j++){
			setStep(p, adrs, static_cast <uint32_t> (j));
			F(p, pkSeed, adrs, view_t(out, p.n), out);
		}
	}
	/**
	 * @brief Метод выработки открытого ключа WOTS+ (алгоритм 6 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя, дерева и пары ключа
	 * @param out    место результата, n байтов
	 *
	 */
	static void wotsPkGen(const Params & p, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Число цепочек ключа: 2n значений сообщения и 3 контрольных
		const size_t len = ((2 * p.n) + CHECKSUM);
		// Значения концов всех цепочек
		uint8_t values[MAX_N * 67];
		// Секретное значение цепочки
		uint8_t sk[MAX_N];
		adrs_t skAdrs, chain;
		copyAdrs(skAdrs, adrs);
		setType(p, skAdrs, 5);
		copyKeypair(p, skAdrs, adrs);
		for(size_t i = 0; i < len; i++){
			setChain(p, skAdrs, static_cast <uint32_t> (i));
			// Секрет цепочки из секретного зерна
			PRF(p, pkSeed, skSeed, skAdrs, sk);
			copyAdrs(chain, adrs);
			setChain(p, chain, static_cast <uint32_t> (i));
			// Конец цепочки по всем шагам
			wotsChain(p, pkSeed, sk, 0, (CHAIN - 1), chain, (values + (i * p.n)));
		}
		adrs_t pkAdrs;
		copyAdrs(pkAdrs, adrs);
		setType(p, pkAdrs, 1);
		copyKeypair(p, pkAdrs, adrs);
		// Открытый ключ - функция T над концами цепочек
		T(p, pkSeed, pkAdrs, view_t(values, (len * p.n)), out);
		sys::wipe(values, sizeof(values));
		sys::wipe(sk, sizeof(sk));
		sys::wipe(skAdrs, sizeof(skAdrs));
		sys::wipe(chain, sizeof(chain));
		sys::wipe(pkAdrs, sizeof(pkAdrs));
	}
	/**
	 * @brief Метод выкладки сообщения и контрольной суммы полубайтами
	 *
	 * @param p   параметры набора
	 * @param msg сообщение, n байтов
	 * @param out место полубайтов сообщения и контрольной суммы, 2n + 3 значений
	 *
	 */
	static void wotsMessage(const Params & p, const uint8_t * msg, uint8_t * out) noexcept {
		// Сообщение раскладывается на 2n полубайтов, старший вперёд
		for(size_t i = 0; i < p.n; i++){
			out[2 * i] = (msg[i] >> 4);
			out[(2 * i) + 1] = (msg[i] & 0x0F);
		}
		// Контрольная сумма: 15·2n минус сумма полубайтов сообщения, тремя полубайтами
		uint16_t sum = 0;
		for(size_t i = 0; i < (2 * p.n); i++)
			sum += out[i];
		sum = static_cast <uint16_t> ((15 * 2 * p.n) - sum);
		out[2 * p.n] = static_cast <uint8_t> ((sum >> 8) & 0x0F);
		out[(2 * p.n) + 1] = static_cast <uint8_t> ((sum >> 4) & 0x0F);
		out[(2 * p.n) + 2] = static_cast <uint8_t> (sum & 0x0F);
	}
	/**
	 * @brief Метод подписи WOTS+ (алгоритм 7 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя, дерева и пары ключа
	 * @param out    место записи подписи, по n байтов на цепочку; возвращается за ним
	 *
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * wotsSign(const Params & p, const uint8_t * msg, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Полубайты сообщения и контрольной суммы
		uint8_t nibbles[67];
		wotsMessage(p, msg, nibbles);
		// Число цепочек подписи
		const size_t len = ((2 * p.n) + CHECKSUM);
		// Секретное значение цепочки
		uint8_t sk[MAX_N];
		adrs_t skAdrs, chain;
		copyAdrs(skAdrs, adrs);
		setType(p, skAdrs, 5);
		copyKeypair(p, skAdrs, adrs);
		for(size_t i = 0; i < len; i++){
			setChain(p, skAdrs, static_cast <uint32_t> (i));
			// Секрет цепочки из секретного зерна
			PRF(p, pkSeed, skSeed, skAdrs, sk);
			copyAdrs(chain, adrs);
			setChain(p, chain, static_cast <uint32_t> (i));
			// Подпись цепочки по числу шагов полубайта
			wotsChain(p, pkSeed, sk, 0, nibbles[i], chain, out);
			out += p.n;
		}
		sys::wipe(nibbles, sizeof(nibbles));
		sys::wipe(sk, sizeof(sk));
		sys::wipe(skAdrs, sizeof(skAdrs));
		sys::wipe(chain, sizeof(chain));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Метод восстановления открытого ключа WOTS+ из подписи (алгоритм 8 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param sig    подпись WOTS+, по n байтов на цепочку
	 * @param msg    сообщение, n байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя, дерева и пары ключа
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 *
	 * @return       место за прочитанной подписью
	 *
	 */
	static const uint8_t * wotsPkFromSig(const Params & p, const uint8_t * sig, const uint8_t * msg, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Полубайты сообщения и контрольной суммы
		uint8_t nibbles[67];
		wotsMessage(p, msg, nibbles);
		// Число цепочек подписи
		const size_t len = ((2 * p.n) + CHECKSUM);
		// Значения концов всех цепочек
		uint8_t values[MAX_N * 67];
		adrs_t chain;
		for(size_t i = 0; i < len; i++){
			copyAdrs(chain, adrs);
			setChain(p, chain, static_cast <uint32_t> (i));
			// Конец цепочки доигрывается от значения подписи до верха
			wotsChain(p, pkSeed, sig, nibbles[i], ((CHAIN - 1) - nibbles[i]), chain, (values + (i * p.n)));
			sig += p.n;
		}
		adrs_t pkAdrs;
		copyAdrs(pkAdrs, adrs);
		setType(p, pkAdrs, 1);
		copyKeypair(p, pkAdrs, adrs);
		// Открытый ключ - функция T над концами цепочек
		T(p, pkSeed, pkAdrs, view_t(values, (len * p.n)), out);
		sys::wipe(nibbles, sizeof(nibbles));
		sys::wipe(values, sizeof(values));
		sys::wipe(chain, sizeof(chain));
		sys::wipe(pkAdrs, sizeof(pkAdrs));
		// Выводим место за прочитанной подписью
		return sig;
	}

	/**
	 * @brief Метод вычисления узла дерева XMSS (алгоритм 9 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param skSeed секретное зерно ключа
	 * @param node   индекс узла на своём уровне
	 * @param height высота узла
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя и дерева
	 * @param out    место результата, n байтов
	 *
	 */
	static void xmssNode(const Params & p, const uint8_t * skSeed, const uint32_t node, const uint32_t height, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Лист дерева: открытый ключ WOTS+ пары под номером узла
		if(height == 0){
			setType(p, adrs, 0);
			setKeypair(p, adrs, node);
			wotsPkGen(p, skSeed, pkSeed, adrs, out);
		// Узел выше листа: функция H над детьми
		} else {
			uint8_t left[MAX_N], right[MAX_N];
			adrs_t children;
			copyAdrs(children, adrs);
			xmssNode(p, skSeed, (2 * node), (height - 1), pkSeed, children, left);
			copyAdrs(children, adrs);
			xmssNode(p, skSeed, ((2 * node) + 1), (height - 1), pkSeed, children, right);
			setType(p, adrs, 2);
			setChain(p, adrs, height);
			setStep(p, adrs, node);
			H(p, pkSeed, adrs, left, right, out);
			sys::wipe(left, sizeof(left));
			sys::wipe(right, sizeof(right));
		}
	}
	/**
	 * @brief Метод подписи XMSS (алгоритм 10 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param leaf   индекс пары ключа в дереве
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя и дерева
	 * @param out    место записи подписи: WOTS+ и путь из h′ узлов; возвращается за ним
	 *
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * xmssSign(const Params & p, const uint8_t * msg, const uint8_t * skSeed, const uint32_t leaf, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		adrs_t wots;
		copyAdrs(wots, adrs);
		setType(p, wots, 0);
		setKeypair(p, wots, leaf);
		// Подпись WOTS+ сообщения
		uint8_t * result = wotsSign(p, msg, skSeed, pkSeed, wots, out);
		// Путь из h′ узлов: брат узла на каждом уровне
		uint32_t node = leaf;
		for(uint32_t height = 0; height < p.hm; height++){
			xmssNode(p, skSeed, (node ^ 1), height, pkSeed, adrs, result);
			result += p.n;
			node >>= 1;
		}
		sys::wipe(wots, sizeof(wots));
		// Выводим место за подписью
		return result;
	}
	/**
	 * @brief Метод восстановления корня XMSS из подписи (алгоритм 11 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param sig    подпись XMSS: WOTS+ и путь из h′ узлов
	 * @param leaf   индекс пары ключа в дереве
	 * @param msg    сообщение, n байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя и дерева
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 *
	 * @return       место за прочитанной подписью
	 *
	 */
	static const uint8_t * xmssPkFromSig(const Params & p, const uint8_t * sig, const uint32_t leaf, const uint8_t * msg, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		adrs_t wots;
		copyAdrs(wots, adrs);
		setType(p, wots, 0);
		setKeypair(p, wots, leaf);
		// Открытый ключ WOTS+ из подписи
		const uint8_t * result = wotsPkFromSig(p, sig, msg, pkSeed, wots, out);
		uint32_t node = leaf;
		adrs_t tree;
		copyAdrs(tree, adrs);
		setType(p, tree, 2);
		for(uint32_t height = 0; height < p.hm; height++){
			setChain(p, tree, (height + 1));
			// Узел складывается с братом пути по стороне индекса
			if((node & 1) == 0){
				node >>= 1;
				setStep(p, tree, node);
				H(p, pkSeed, tree, out, result, out);
			} else {
				node = (node - 1) >> 1;
				setStep(p, tree, node);
				H(p, pkSeed, tree, result, out, out);
			}
			result += p.n;
		}
		sys::wipe(wots, sizeof(wots));
		sys::wipe(tree, sizeof(tree));
		// Выводим место за прочитанной подписью
		return result;
	}

	/**
	 * @brief Метод секретного значения FORS (алгоритм 14 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес вида FORS_TREE с парой ключа
	 * @param id     индекс значения в лесу
	 * @param out    место результата, n байтов
	 *
	 */
	static void forsSecret(const Params & p, const uint8_t * skSeed, const uint8_t * pkSeed, const adrs_t adrs, const uint32_t id, uint8_t * out) noexcept {
		adrs_t skAdrs;
		copyAdrs(skAdrs, adrs);
		setType(p, skAdrs, 6);
		copyKeypair(p, skAdrs, adrs);
		setStep(p, skAdrs, id);
		PRF(p, pkSeed, skSeed, skAdrs, out);
		sys::wipe(skAdrs, sizeof(skAdrs));
	}
	/**
	 * @brief Метод вычисления узла дерева FORS (алгоритм 15 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес вида FORS_TREE с парой ключа
	 * @param node   индекс узла на своём уровне леса
	 * @param height высота узла
	 * @param out    место результата, n байтов
	 *
	 */
	static void forsNode(const Params & p, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, const uint32_t node, const uint32_t height, uint8_t * out) noexcept {
		// Лист дерева: функция F над секретным значением
		if(height == 0){
			uint8_t sk[MAX_N];
			forsSecret(p, skSeed, pkSeed, adrs, node, sk);
			setChain(p, adrs, 0);
			setStep(p, adrs, node);
			F(p, pkSeed, adrs, view_t(sk, p.n), out);
			sys::wipe(sk, sizeof(sk));
		// Узел выше листа: функция H над детьми
		} else {
			uint8_t left[MAX_N], right[MAX_N];
			adrs_t children;
			copyAdrs(children, adrs);
			forsNode(p, skSeed, pkSeed, children, (2 * node), (height - 1), left);
			copyAdrs(children, adrs);
			forsNode(p, skSeed, pkSeed, children, ((2 * node) + 1), (height - 1), right);
			setChain(p, adrs, height);
			setStep(p, adrs, node);
			H(p, pkSeed, adrs, left, right, out);
			sys::wipe(left, sizeof(left));
			sys::wipe(right, sizeof(right));
		}
	}
	/**
	 * @brief Метод раскладки дайджеста по основанию 2^a (алгоритм 4 FIPS 205)
	 *
	 * @param in     дайджест, первые (k·a + 7) / 8 байтов
	 * @param a      основание раскладки
	 * @param out    место k значений по a разрядов
	 * @param k      число значений
	 *
	 */
	static void base2b(const uint8_t * in, const uint32_t a, uint32_t * out, const size_t k) noexcept {
		uint32_t bits = 0, total = 0;
		const uint32_t mask = ((1u << a) - 1);
		for(size_t i = 0; i < k; i++){
			while(bits < a){
				total <<= 8;
				total += *in++;
				bits += 8;
			}
			bits -= a;
			*out++ = ((total >> bits) & mask);
		}
	}
	/**
	 * @brief Метод подписи FORS (алгоритм 16 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param md     дайджест, первые (k·a + 7) / 8 байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес вида FORS_TREE с парой ключа
	 * @param out    место записи подписи: k × (значение ‖ путь из a узлов); возвращается за ним
	 *
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * forsSign(const Params & p, const uint8_t * md, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Значения листьев по k деревьям
		uint32_t ids[MAX_K];
		base2b(md, p.a, ids, p.k);
		uint8_t value[MAX_N];
		// Смещение леса по уровням: каждое дерево занимает свою полосу индексов
		uint32_t forest = 0;
		for(size_t tree = 0; tree < p.k; tree++){
			uint32_t node = ids[tree];
			// Секретное значение листа
			forsSecret(p, skSeed, pkSeed, adrs, (node + forest), value);
			::memcpy(out, value, p.n);
			out += p.n;
			uint32_t offset = forest;
			// Путь из a узлов: брат узла на каждом уровне
			for(uint32_t height = 0; height < p.a; height++){
				forsNode(p, skSeed, pkSeed, adrs, ((node ^ 1) + offset), height, out);
				out += p.n;
				node >>= 1;
				offset >>= 1;
			}
			forest += (1u << p.a);
		}
		sys::wipe(value, sizeof(value));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Метод восстановления открытого ключа FORS из подписи (алгоритм 17 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param sig    подпись FORS: k × (значение ‖ путь из a узлов)
	 * @param md     дайджест, первые (k·a + 7) / 8 байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес вида FORS_TREE с парой ключа
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 *
	 * @return       место за прочитанной подписью
	 *
	 */
	static const uint8_t * forsPkFromSig(const Params & p, const uint8_t * sig, const uint8_t * md, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Значения листьев по k деревьям
		uint32_t ids[MAX_K];
		base2b(md, p.a, ids, p.k);
		// Корни всех деревьев леса
		uint8_t roots[MAX_K * MAX_N];
		// Смещение леса по деревьям
		uint32_t forest = 0;
		for(size_t tree = 0; tree < p.k; tree++){
			uint32_t id = ids[tree];
			uint32_t node = (id + forest);
			uint8_t * node0 = (roots + (tree * p.n));
			setChain(p, adrs, 0);
			setStep(p, adrs, node);
			// Лист из значения подписи
			F(p, pkSeed, adrs, view_t(sig, p.n), node0);
			sig += p.n;
			uint8_t * node1 = node0;
			for(uint32_t height = 0; height < p.a; height++){
				setChain(p, adrs, (height + 1));
				// Узел складывается с братом пути по стороне индекса
				if((id & 1) == 0){
					node >>= 1;
					setStep(p, adrs, node);
					H(p, pkSeed, adrs, node0, sig, node1);
				} else {
					node = (node - 1) >> 1;
					setStep(p, adrs, node);
					H(p, pkSeed, adrs, sig, node0, node1);
				}
				sig += p.n;
				id >>= 1;
			}
			forest += (1u << p.a);
		}
		adrs_t pkAdrs;
		copyAdrs(pkAdrs, adrs);
		setType(p, pkAdrs, 4);
		copyKeypair(p, pkAdrs, adrs);
		// Открытый ключ FORS - функция T над корнями всех деревьев
		T(p, pkSeed, pkAdrs, view_t(roots, (p.k * p.n)), out);
		sys::wipe(roots, sizeof(roots));
		sys::wipe(pkAdrs, sizeof(pkAdrs));
		// Выводим место за прочитанной подписью
		return sig;
	}

	/**
	 * @brief Метод подписи гипердерева (алгоритм 12 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param tree   индекс дерева нижнего слоя
	 * @param leaf   индекс пары ключа в дереве нижнего слоя
	 * @param out    место записи подписи: d подписей XMSS; возвращается за ним
	 *
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * htSign(const Params & p, const uint8_t * msg, const uint8_t * skSeed, const uint8_t * pkSeed, uint64_t tree, uint32_t leaf, uint8_t * out) noexcept {
		// Маска пары ключа дерева слоя
		const uint32_t mask = ((1u << p.hm) - 1);
		adrs_t adrs;
		zero(adrs);
		// Подписываемое слоем значение: сперва корень FORS
		uint8_t root[MAX_N];
		::memcpy(root, msg, p.n);
		for(uint32_t layer = 0; layer < p.d; layer++){
			setLayer(p, adrs, layer);
			setTree(p, adrs, tree);
			uint8_t * layer_sig = out;
			out = xmssSign(p, root, skSeed, leaf, pkSeed, adrs, out);
			// Корень следующего слоя - открытый ключ только что подписанного дерева
			if(layer < (p.d - 1)){
				(void) xmssPkFromSig(p, layer_sig, leaf, root, pkSeed, adrs, root);
				leaf = (tree & mask);
				tree >>= p.hm;
			}
		}
		sys::wipe(root, sizeof(root));
		sys::wipe(adrs, sizeof(adrs));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Метод проверки подписи гипердерева (алгоритм 13 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param sig    подпись гипердерева: d подписей XMSS
	 * @param pkSeed открытое зерно ключа
	 * @param tree   индекс дерева нижнего слоя
	 * @param leaf   индекс пары ключа в дереве нижнего слоя
	 * @param pkRoot корень ключа проверки
	 *
	 * @return       признак того, что гипердерево сошлось с корнем
	 *
	 */
	static bool htVerify(const Params & p, const uint8_t * msg, const uint8_t * sig, const uint8_t * pkSeed, uint64_t tree, uint32_t leaf, const uint8_t * pkRoot) noexcept {
		// Маска пары ключа дерева слоя
		const uint32_t mask = ((1u << p.hm) - 1);
		adrs_t adrs;
		zero(adrs);
		// Проверяемое слоем значение: сперва корень FORS
		uint8_t node[MAX_N];
		::memcpy(node, msg, p.n);
		for(uint32_t layer = 0; layer < p.d; layer++){
			setLayer(p, adrs, layer);
			setTree(p, adrs, tree);
			sig = xmssPkFromSig(p, sig, leaf, node, pkSeed, adrs, node);
			leaf = (tree & mask);
			tree >>= p.hm;
		}
		// Сверху дерева обязан лежать корень ключа проверки
		const bool result = (::memcmp(node, pkRoot, p.n) == 0);
		sys::wipe(node, sizeof(node));
		sys::wipe(adrs, sizeof(adrs));
		// Выводим признак схождения
		return result;
	}

	/**
	 * @brief Метод получения целого из байтов старшим байтом вперёд
	 *
	 * @param in   байты
	 * @param size число байтов
	 *
	 * @return     целое число
	 *
	 */
	static uint64_t bytesToInt(const uint8_t * in, const size_t size) noexcept {
		uint64_t result = 0;
		for(size_t i = 0; i < size; i++)
			result = ((result << 8) + in[i]);
		return result;
	}

	/**
	 * @brief Метод выработки корня ключа проверки (алгоритм 18 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param out    место результата, n байтов
	 *
	 */
	static void pkRoot(const Params & p, const uint8_t * skSeed, const uint8_t * pkSeed, uint8_t * out) noexcept {
		adrs_t adrs;
		zero(adrs);
		setLayer(p, adrs, (p.d - 1));
		xmssNode(p, skSeed, 0, p.hm, pkSeed, adrs, out);
		sys::wipe(adrs, sizeof(adrs));
	}

	/**
	 * @brief Метод порождения ключа из зерна (раздел 10.1 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param seed   зерно: SK.seed ‖ SK.prf ‖ PK.seed (3n байтов)
	 * @param key    место ключа проверки: PK.seed ‖ PK.root (2n байтов)
	 * @param secret место ключа подписи: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root (4n байтов)
	 *
	 */
	static void keygen(const Params & p, const uint8_t * seed, uint8_t * key, uint8_t * secret) noexcept {
		// Запись ключа подписи: зерно целиком в первые три значения
		::memcpy(secret, seed, (3 * p.n));
		// Корень ключа вычисляется вершиной дерева верхнего слоя
		pkRoot(p, (secret), (secret + (2 * p.n)), (secret + (3 * p.n)));
		// Ключ проверки: PK.seed ‖ PK.root
		::memcpy(key, (secret + (2 * p.n)), (2 * p.n));
	}

	/**
	 * @brief Метод выработки подписи (раздел 10.2 FIPS 205)
	 *
	 * @param p       параметры набора
	 * @param secret  запись ключа подписи
	 * @param rnd     случайность подписи, 32 байта (нули дают детерминированный вариант)
	 * @param message подписываемое сообщение
	 * @param context контекст подписи
	 * @param result  место записи подписи: R ‖ FORS ‖ HT
	 *
	 */
	static void signing(const Params & p, const uint8_t * secret, const uint8_t * rnd, const view_t & message, const view_t & context, uint8_t * result) noexcept {
		const uint8_t * skSeed = secret;
		const uint8_t * skPrf = (secret + p.n);
		const uint8_t * pkSeed = (secret + (2 * p.n));
		const uint8_t * pkRoot = (secret + (3 * p.n));
		// Случайность opt_rand: нули заменяются открытым зерном ключа (детерминированный вариант)
		uint32_t noisy = 0;
		for(size_t i = 0; i < 32; i++)
			noisy |= rnd[i];
		const uint8_t * optRand = ((noisy == 0) ? pkSeed : rnd);
		// Сообщение с обвязкой: 0x00 ‖ длина контекста ‖ контекст ‖ сообщение
		uint8_t r[MAX_N], m[MAX_M];
		// Случайность подписи R = PRFmsg(SK.prf, opt_rand, обвязанное сообщение)
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			if(p.family == FAMILY_SHAKE){
				xof.update(view_t(skPrf, p.n));
				xof.update(view_t(optRand, p.n));
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				xof.update(view_t(prefix, sizeof(prefix)));
				xof.update(context);
				xof.update(message);
				(void) xof.squeeze(r, p.n);
			} else {
				digest::mac_t hmac;
				uint8_t full[64];
				const size_t length = ((p.family == FAMILY_SHA2_35) ? 64 : 32);
				if(hmac.start(((p.family == FAMILY_SHA2_35) ? digest::hash_t::SHA512 : digest::hash_t::SHA256), view_t(skPrf, p.n))){
					hmac.update(view_t(optRand, p.n));
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					hmac.update(view_t(prefix, sizeof(prefix)));
					hmac.update(context);
					hmac.update(message);
					if(hmac.finish(full, length))
						::memcpy(r, full, p.n);
					sys::wipe(full, sizeof(full));
				}
			}
		}
		// Дайджест сообщения m байтов: Hmsg(R ‖ PK.seed ‖ PK.root ‖ обвязанное сообщение)
		{
			if(p.family == FAMILY_SHAKE){
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				xof.update(view_t(r, p.n));
				xof.update(view_t(pkSeed, p.n));
				xof.update(view_t(pkRoot, p.n));
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				xof.update(view_t(prefix, sizeof(prefix)));
				xof.update(context);
				xof.update(message);
				(void) xof.squeeze(m, p.m);
			} else {
				// Зерно порождения: случайность, открытое зерно и хеш сообщения
				uint8_t seed[(2 * MAX_N) + 64];
				const size_t length = ((p.family == FAMILY_SHA2_35) ? 64 : 32);
				::memcpy(seed, r, p.n);
				::memcpy((seed + p.n), pkSeed, p.n);
				{
					digest::sha2_t sha(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256));
					sha.update(view_t(r, p.n));
					sha.update(view_t(pkSeed, p.n));
					sha.update(view_t(pkRoot, p.n));
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					sha.update(view_t(prefix, sizeof(prefix)));
					sha.update(context);
					sha.update(message);
					(void) sha.finish((seed + (2 * p.n)), length);
				}
				MGF1(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256), view_t(seed, ((2 * p.n) + length)), m, p.m);
				sys::wipe(seed, sizeof(seed));
			}
		}
		// Дайджест раскладывается: md, индекс дерева, индекс пары ключа
		const size_t mdLen = (((static_cast <size_t> (p.k) * p.a) + 7) >> 3);
		const size_t treeLen = (((static_cast <size_t> (p.d) * p.hm - p.hm) + 7) >> 3);
		const size_t leafLen = ((p.hm + 7) >> 3);
		const uint64_t tree = (bytesToInt((m + mdLen), treeLen) & ((~(uint64_t) 0) >> (64 - ((p.d * p.hm) - p.hm))));
		const uint32_t leaf = static_cast <uint32_t> (bytesToInt((m + mdLen + treeLen), leafLen) & ((static_cast <uint64_t> (1) << p.hm) - 1));
		// Запись подписи: R ‖ FORS ‖ HT
		uint8_t * out = result;
		::memcpy(out, r, p.n);
		out += p.n;
		adrs_t adrs;
		zero(adrs);
		setTree(p, adrs, tree);
		setType(p, adrs, 3);
		setKeypair(p, adrs, leaf);
		uint8_t * fors = out;
		out = forsSign(p, m, skSeed, pkSeed, adrs, out);
		// Корень FORS из только что выработанной подписи
		uint8_t pkFors[MAX_N];
		(void) forsPkFromSig(p, fors, m, pkSeed, adrs, pkFors);
		(void) htSign(p, pkFors, skSeed, pkSeed, tree, leaf, out);
		sys::wipe(r, sizeof(r));
		sys::wipe(m, sizeof(m));
		sys::wipe(pkFors, sizeof(pkFors));
		sys::wipe(adrs, sizeof(adrs));
	}

	/**
	 * @brief Метод проверки подписи (раздел 10.3 FIPS 205)
	 *
	 * @param p         параметры набора
	 * @param key       запись ключа проверки: PK.seed ‖ PK.root
	 * @param message   подписанное сообщение
	 * @param context   контекст подписи
	 * @param signature проверяемая подпись: R ‖ FORS ‖ HT
	 *
	 * @return          признак того, что подпись сошлась
	 *
	 */
	static bool checking(const Params & p, const uint8_t * key, const view_t & message, const view_t & context, const uint8_t * signature) noexcept {
		const uint8_t * pkSeed = key;
		const uint8_t * pkRoot = (key + p.n);
		const uint8_t * r = signature;
		// Дайджест сообщения m байтов: Hmsg(R ‖ PK.seed ‖ PK.root ‖ обвязанное сообщение)
		uint8_t m[MAX_M];
		{
			if(p.family == FAMILY_SHAKE){
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				xof.update(view_t(r, p.n));
				xof.update(view_t(pkSeed, p.n));
				xof.update(view_t(pkRoot, p.n));
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				xof.update(view_t(prefix, sizeof(prefix)));
				xof.update(context);
				xof.update(message);
				(void) xof.squeeze(m, p.m);
			} else {
				// Зерно порождения: случайность, открытое зерно и хеш сообщения
				uint8_t seed[(2 * MAX_N) + 64];
				const size_t length = ((p.family == FAMILY_SHA2_35) ? 64 : 32);
				::memcpy(seed, r, p.n);
				::memcpy((seed + p.n), pkSeed, p.n);
				{
					digest::sha2_t sha(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256));
					sha.update(view_t(r, p.n));
					sha.update(view_t(pkSeed, p.n));
					sha.update(view_t(pkRoot, p.n));
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					sha.update(view_t(prefix, sizeof(prefix)));
					sha.update(context);
					sha.update(message);
					(void) sha.finish((seed + (2 * p.n)), length);
				}
				MGF1(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256), view_t(seed, ((2 * p.n) + length)), m, p.m);
				sys::wipe(seed, sizeof(seed));
			}
		}
		// Дайджест раскладывается: md, индекс дерева, индекс пары ключа
		const size_t mdLen = (((static_cast <size_t> (p.k) * p.a) + 7) >> 3);
		const size_t treeLen = (((static_cast <size_t> (p.d) * p.hm - p.hm) + 7) >> 3);
		const size_t leafLen = ((p.hm + 7) >> 3);
		const uint64_t tree = (bytesToInt((m + mdLen), treeLen) & ((~(uint64_t) 0) >> (64 - ((p.d * p.hm) - p.hm))));
		const uint32_t leaf = static_cast <uint32_t> (bytesToInt((m + mdLen + treeLen), leafLen) & ((static_cast <uint64_t> (1) << p.hm) - 1));
		adrs_t adrs;
		zero(adrs);
		setTree(p, adrs, tree);
		setType(p, adrs, 3);
		setKeypair(p, adrs, leaf);
		const uint8_t * sig = (signature + p.n);
		// Корень FORS из подписи
		uint8_t pkFors[MAX_N];
		sig = forsPkFromSig(p, sig, m, pkSeed, adrs, pkFors);
		// Гипердерево обязано сойтись с корнем ключа проверки
		const bool result = htVerify(p, pkFors, sig, pkSeed, tree, leaf, pkRoot);
		sys::wipe(m, sizeof(m));
		sys::wipe(pkFors, sizeof(pkFors));
		sys::wipe(adrs, sizeof(adrs));
		// Выводим признак схождения
		return result;
	}

	/**
	 * @brief Метод проверки подлинности записи ключа подписи
	 *
	 * @param p      параметры набора
	 * @param secret запись ключа подписи
	 *
	 * @return       признак того, что корень записи сходится с пересчитанным из зерна
	 *
	 */
	static bool consistent(const Params & p, const uint8_t * secret) noexcept {
		// Корень, пересчитанный из зерна записи
		uint8_t root[MAX_N];
		pkRoot(p, secret, (secret + (2 * p.n)), root);
		// Сличаем корень с записанным в записи
		const bool result = (::memcmp(root, (secret + (3 * p.n)), p.n) == 0);
		sys::wipe(root, sizeof(root));
		// Выводим признак подлинности записи
		return result;
	}
};

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод получения набора параметров ключа
 *
 * @return набор параметров ключа, NONE без ключа
 *
 */
sign::Slhdsa::set_t sign::Slhdsa::set() const noexcept {
	// Если ключ не установлен, набора нет
	if(!this->_secret && !this->_public)
		return set_t::NONE;
	// Возвращаем набор параметров ключа
	return this->_set;
}

/**
 * @brief Метод получения размера подписи
 *
 * @return размер подписи в байтах, ноль без ключа
 *
 */
size_t sign::Slhdsa::size() const noexcept {
	// Если ключ не установлен, размера нет
	if(!this->_secret && !this->_public)
		return 0;
	// Возвращаем размер подписи набора
	return signatureSize(this->_set);
}

/**
 * @brief Метод получения верхнего предела длины подписи в записанном виде
 *
 * @return верхний предел длины подписи в байтах, ноль без ключа
 *
 */
size_t sign::Slhdsa::limit() const noexcept {
	// Если ключ не установлен, предела нет
	if(!this->_secret && !this->_public)
		return 0;
	// Подпись уходит наружу записью постоянной длины по набору
	return signatureSize(this->_set);
}

/**
 * @brief Метод сброса состояния модуля
 *
 */
void sign::Slhdsa::clear() noexcept {
	// Затираем запись ключа подписи
	sys::wipe(this->_key, sizeof(this->_key));
	// Затираем запись ключа проверки подписи
	sys::wipe(this->_pkey, sizeof(this->_pkey));
	// Сбрасываем признаки ключей и набор
	this->_secret = false;
	this->_public = false;
	this->_set = set_t::NONE;
}

/**
 * @brief Метод получения размера зерна порождения набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер зерна порождения в байтах (3n), ноль у несуществующего набора
 *
 */
size_t sign::Slhdsa::seedSize(const set_t set) noexcept {
	// Размер зерна порождения: три значения по n байтов
	return (3 * params(set).n);
}

/**
 * @brief Метод получения размера ключа подписи набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер ключа подписи в байтах (4n), ноль у несуществующего набора
 *
 */
size_t sign::Slhdsa::secretSize(const set_t set) noexcept {
	// Размер ключа подписи: четыре значения по n байтов
	return (4 * params(set).n);
}

/**
 * @brief Метод получения размера ключа проверки набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер ключа проверки в байтах (2n), ноль у несуществующего набора
 *
 */
size_t sign::Slhdsa::publicSize(const set_t set) noexcept {
	// Размер ключа проверки: два значения по n байтов
	return (2 * params(set).n);
}

/**
 * @brief Метод получения размера подписи набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер подписи в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Slhdsa::signatureSize(const set_t set) noexcept {
	// Размер подписи набора из таблицы параметров
	return params(set).signature;
}

/**
 * @brief Метод порождения долговременного ключа подписи из зерна
 *
 * @param set    набор параметров
 * @param seed   зерно выработки длиной 3n байтов
 * @param key    место, в которое помещается ключ проверки
 * @param secret место, в которое помещается ключ подписи
 *
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Slhdsa::generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и зерно верной длины
	const Params p = params(set);
	if((p.n != 0) && (seed.size == (3 * p.n))){
		// Порождаем ключ из зерна
		keygen(p, static_cast <const uint8_t *> (seed.data), key, secret);
		result = true;
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод порождения долговременного ключа подписи из источника случайности
 *
 * @param set    набор параметров
 * @param key    место, в которое помещается ключ проверки
 * @param secret место, в которое помещается ключ подписи
 *
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Slhdsa::generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют
	const Params p = params(set);
	if(p.n != 0){
		// Зерно порождения из источника случайности
		uint8_t seed[3 * MAX_N];
		if(entropy::bytes(seed, (3 * p.n))){
			// Порождаем ключ из зерна
			keygen(p, seed, key, secret);
			result = true;
		}
		// Затираем зерно порождения
		sys::wipe(seed, sizeof(seed));
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод установки ключа подписи
 *
 * @param set    набор параметров ключа
 * @param secret запись ключа подписи по набору
 *
 * @return       признак успешности установки ключа подписи
 *
 */
bool sign::Slhdsa::secret(const set_t set, const view_t & secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	const Params p = params(set);
	if((p.n != 0) && (secret.size == (4 * p.n))){
		// Подлинность записи проверяется пересчётом корня из зерна записи
		if(consistent(p, static_cast <const uint8_t *> (secret.data))){
			::memcpy(this->_key, secret.data, (4 * p.n));
			::memcpy(this->_pkey, (static_cast <const uint8_t *> (secret.data) + (2 * p.n)), (2 * p.n));
			this->_set = set;
			this->_secret = true;
			this->_public = true;
			result = true;
		}
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод установки ключа проверки подписи
 *
 * @param set набор параметров ключа
 * @param key запись ключа проверки по набору
 *
 * @return    признак успешности установки ключа проверки подписи
 *
 */
bool sign::Slhdsa::key(const set_t set, const view_t & key) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	const Params p = params(set);
	if((p.n != 0) && (key.size == (2 * p.n))){
		// Если ключ подписи установлен, поданный обязан совпасть с записанным
		if(this->_secret && (this->_set == set)){
			if(::memcmp(this->_pkey, key.data, (2 * p.n)) == 0)
				result = true;
		} else {
			// Иначе устанавливаем ключ проверки
			::memcpy(this->_pkey, key.data, (2 * p.n));
			this->_set = set;
			this->_public = true;
			result = true;
		}
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод получения ключа проверки подписи
 *
 * @param result место, в которое записывается ключ проверки по набору
 * @param size   размер места, не меньше размера ключа проверки набора
 *
 * @return       признак успешности получения ключа проверки подписи
 *
 */
bool sign::Slhdsa::key(uint8_t * result, const size_t size) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ проверки установлен и места хватает
	if(this->_public && (size >= (2 * params(this->_set).n))){
		// Выводим ключ проверки
		::memcpy(result, this->_pkey, (2 * params(this->_set).n));
		outcome = true;
	}
	// Выводим признак успешности
	return outcome;
}

/**
 * @brief Метод выработки подписи со случайностью от источника
 *
 * @param message подписываемое сообщение целиком
 * @param context контекст подписи, до 255 байтов, в TLS пустой
 * @param result  место, в которое помещается подпись по набору
 *
 * @return        признак успешности выработки подписи
 *
 */
bool sign::Slhdsa::make(const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен и контекст в пределе
	if(this->_secret && (context.size < 256)){
		// Случайность подписи из источника
		uint8_t rnd[32];
		if(entropy::bytes(rnd, sizeof(rnd))){
			// Вырабатываем подпись
			signing(params(this->_set), this->_key, rnd, message, context, result);
			outcome = true;
		}
		// Затираем случайность подписи
		sys::wipe(rnd, sizeof(rnd));
	}
	// Выводим признак успешности
	return outcome;
}

/**
 * @brief Метод выработки подписи с заданной случайностью
 *
 * @param rnd     случайность подписи, читаются первые n байтов
 * @param message подписываемое сообщение целиком
 * @param context контекст подписи, до 255 байтов, в TLS пустой
 * @param result  место, в которое помещается подпись по набору
 *
 * @return        признак успешности выработки подписи
 *
 */
bool sign::Slhdsa::make(const view_t & rnd, const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен, случайность верной длины и контекст в пределе
	if(this->_secret && (rnd.size == 32) && (context.size < 256)){
		// Вырабатываем подпись
		signing(params(this->_set), this->_key, static_cast <const uint8_t *> (rnd.data), message, context, result);
		outcome = true;
	}
	// Выводим признак успешности
	return outcome;
}

/**
 * @brief Метод проверки подписи
 *
 * @param message   подписанное сообщение целиком
 * @param context   контекст подписи, до 255 байтов, в TLS пустой
 * @param signature проверяемая подпись по набору
 *
 * @return          признак того, что подпись сошлась
 *
 */
bool sign::Slhdsa::check(const view_t & message, const view_t & context, const view_t & signature) const noexcept {
	// Результат работы
	bool result = false;
	// Ключ проверки установлен, запись подписи верной длины и контекст в пределе
	const Params p = params(this->_set);
	if(this->_public && (signature.size == p.signature) && (context.size < 256)){
		// Проверяем подпись
		result = checking(p, this->_pkey, message, context, static_cast <const uint8_t *> (signature.data));
	}
	// Выводим признак схождения
	return result;
}

/**
 * @brief Конструктор
 *
 */
sign::Slhdsa::Slhdsa() noexcept :
	_set(set_t::NONE),
	_secret(false),
	_public(false){
	// Обнуляем записи ключей
	::memset(this->_key, 0, sizeof(this->_key));
	::memset(this->_pkey, 0, sizeof(this->_pkey));
}

/**
 * @brief Деструктор
 *
 */
sign::Slhdsa::~Slhdsa() noexcept {
	// Затираем записи ключей
	sys::wipe(this->_key, sizeof(this->_key));
	sys::wipe(this->_pkey, sizeof(this->_pkey));
}
