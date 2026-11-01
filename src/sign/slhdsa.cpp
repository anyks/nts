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
	 * @brief Функция получения параметров набора
	 *
	 * @param set набор параметров
	 * @return    параметры набора, нулевые у несуществующего
	 *
	 */
	static Params params(const sign::Slhdsa::set_t set) noexcept {
		/**
		 * Выбираем параметры набора по его значению
		 */
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
	 * @brief Функция обнуления адреса
	 *
	 * @param adrs адрес
	 *
	 */
	static void zero(adrs_t adrs) noexcept {
		// Обнуляем все байты адреса
		::memset(adrs, 0, sizeof(adrs_t));
	}
	/**
	 * @brief Функция копирования адреса
	 *
	 * @param dst приёмник
	 * @param src источник
	 *
	 */
	static void copyAdrs(adrs_t dst, const adrs_t src) noexcept {
		// Копируем адрес целиком
		::memcpy(dst, src, sizeof(adrs_t));
	}
	/**
	 * @brief Функция установки адреса слоя
	 *
	 * @param p     параметры набора (сжатый адрес у SHA2)
	 * @param adrs  адрес
	 * @param layer адрес слоя
	 *
	 */
	static void setLayer(const Params & p, adrs_t adrs, const uint32_t layer) noexcept {
		// У семейства SHA2 слой занимает байт, у SHAKE - четыре старшим байтом вперёд
		if(p.family == FAMILY_SHAKE){
			// Старший байт слоя
			adrs[0] = static_cast <uint8_t> (layer >> 24);
			// Следующий байт слоя
			adrs[1] = static_cast <uint8_t> (layer >> 16);
			// Третий байт слоя
			adrs[2] = static_cast <uint8_t> (layer >> 8);
			// Младший байт слоя
			adrs[3] = static_cast <uint8_t> (layer);
		} else
			adrs[0] = static_cast <uint8_t> (layer);
	}
	/**
	 * @brief Функция установки адреса дерева
	 *
	 * @param p     параметры набора
	 * @param adrs  адрес
	 * @param tree  адрес дерева, до 64 разрядов
	 *
	 */
	static void setTree(const Params & p, adrs_t adrs, const uint64_t tree) noexcept {
		// У семейства SHAKE дерево лежит в последних восьми байтах поля двенадцати
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 8 : 1);
		/**
		 * Записываем восемь байтов дерева старшим вперёд
		 */
		for(size_t i = 0; i < 8; i++)
			// Очередной байт дерева
			adrs[offset + i] = static_cast <uint8_t> (tree >> (56 - (8 * i)));
	}
	/**
	 * @brief Функция установки вида адреса с очисткой хвоста
	 *
	 * @param p    параметры набора
	 * @param adrs адрес
	 * @param type вид адреса
	 *
	 */
	static void setType(const Params & p, adrs_t adrs, const uint32_t type) noexcept {
		// У семейства SHAKE вид занимает четыре байта старшим байтом вперёд, у SHA2 - один
		if(p.family == FAMILY_SHAKE){
			// Старший байт вида
			adrs[16] = static_cast <uint8_t> (type >> 24);
			// Следующий байт вида
			adrs[17] = static_cast <uint8_t> (type >> 16);
			// Третий байт вида
			adrs[18] = static_cast <uint8_t> (type >> 8);
			// Младший байт вида
			adrs[19] = static_cast <uint8_t> (type);
			// Хвост после вида обнуляется по правилу стандарта
			::memset((adrs + 20), 0, 12);
		} else {
			// Вид занимает один байт
			adrs[9] = static_cast <uint8_t> (type);
			// Хвост после вида обнуляется по правилу стандарта
			::memset((adrs + 10), 0, 12);
		}
	}
	/**
	 * @brief Функция установки адреса пары
	 *
	 * @param p      параметры набора
	 * @param adrs   адрес
	 * @param keypair адрес пары
	 *
	 */
	static void setKeypair(const Params & p, adrs_t adrs, const uint32_t keypair) noexcept {
		// Смещение пары ключа в адресе
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 20 : 10);
		/**
		 * Записываем четыре байта пары старшим вперёд
		 */
		for(size_t i = 0; i < 4; i++)
			// Очередной байт пары
			adrs[offset + i] = static_cast <uint8_t> (keypair >> (24 - (8 * i)));
	}
	/**
	 * @brief Функция копирования адреса пары между адресами
	 *
	 * @param p   параметры набора
	 * @param dst приёмник
	 * @param src источник
	 *
	 */
	static void copyKeypair(const Params & p, adrs_t dst, const adrs_t src) noexcept {
		// Смещение пары ключа в адресе
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 20 : 10);
		// Копируем четыре байта пары
		::memcpy((dst + offset), (src + offset), 4);
	}
	/**
	 * @brief Функция установки адреса цепочки (он же высота дерева)
	 *
	 * @param p     параметры набора
	 * @param adrs  адрес
	 * @param chain адрес цепочки
	 *
	 */
	static void setChain(const Params & p, adrs_t adrs, const uint32_t chain) noexcept {
		// Смещение цепочки в адресе
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 24 : 14);
		/**
		 * Записываем четыре байта цепочки старшим вперёд
		 */
		for(size_t i = 0; i < 4; i++)
			// Очередной байт цепочки
			adrs[offset + i] = static_cast <uint8_t> (chain >> (24 - (8 * i)));
	}
	/**
	 * @brief Функция установки адреса шага (он же индекс дерева)
	 *
	 * @param p    параметры набора
	 * @param adrs адрес
	 * @param step адрес шага
	 *
	 */
	static void setStep(const Params & p, adrs_t adrs, const uint32_t step) noexcept {
		// Смещение шага в адресе
		const size_t offset = ((p.family == FAMILY_SHAKE) ? 28 : 18);
		/**
		 * Записываем четыре байта шага старшим вперёд
		 */
		for(size_t i = 0; i < 4; i++)
			// Очередной байт шага
			adrs[offset + i] = static_cast <uint8_t> (step >> (24 - (8 * i)));
	}
	/**
	 * @brief Функция получения занятой длины адреса
	 *
	 * @param p параметры набора
	 * @return  длина адреса в байтах: 32 у SHAKE, 22 у SHA2
	 *
	 */
	static size_t adrsSize(const Params & p) noexcept {
		// Длина адреса: тридцать два у SHAKE, двадцать два у SHA2
		return ((p.family == FAMILY_SHAKE) ? 32 : 22);
	}

	/**
	 * @brief Функция функции F (по одному значению)
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
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(m1);
			// Выжимаем результат нужной длины
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 функция строится на SHA-256 с добивкой зерна нулями до 64 байтов
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(m1);
			// Доводим хеш до конца
			(void) sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, p.n);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция функции H (по двум значениям)
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
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(view_t(m1, p.n));
			xof.update(view_t(m2, p.n));
			// Выжимаем результат нужной длины
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 категорий 3 и 5 функция H строится на SHA-512 с добивкой зерна нулями до 128 байтов
		} else if(p.family == FAMILY_SHA2_35){
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA512);
			// Полное значение хеша
			uint8_t full[64];
			// Добивка зерна нулями до блока
			const uint8_t padding[128] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (128 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(view_t(m1, p.n));
			sha.update(view_t(m2, p.n));
			// Доводим хеш до конца
			(void) sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, p.n);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		// У семейства SHA2 категории 1 функция H строится на SHA-256
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(view_t(m1, p.n));
			sha.update(view_t(m2, p.n));
			// Доводим хеш до конца
			(void) sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, p.n);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция функции T (по значению переменной длины)
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
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(ml);
			// Выжимаем результат нужной длины
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 категорий 3 и 5 функция T строится на SHA-512
		} else if(p.family == FAMILY_SHA2_35){
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA512);
			// Полное значение хеша
			uint8_t full[64];
			// Добивка зерна нулями до блока
			const uint8_t padding[128] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (128 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(ml);
			// Доводим хеш до конца
			(void) sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, p.n);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		// У семейства SHA2 категории 1 функция T строится на SHA-256
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(ml);
			// Доводим хеш до конца
			(void) sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, p.n);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция функции PRF (выработка значений из секретного зерна)
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
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, p.n));
			xof.update(view_t(adrs, adrsSize(p)));
			xof.update(view_t(skSeed, p.n));
			// Выжимаем результат нужной длины
			(void) xof.squeeze(out, p.n);
		// У семейства SHA2 функция PRF строится на SHA-256
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, p.n));
			sha.update(view_t(padding, (64 - p.n)));
			sha.update(view_t(adrs, adrsSize(p)));
			sha.update(view_t(skSeed, p.n));
			// Доводим хеш до конца
			(void) sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, p.n);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция порождения маски MGF1 по RFC 8017
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
		/**
		 * Порождаем блоки маски, пока не наберётся длина
		 */
		while(done < size){
			// Порождаем очередной блок маски
			digest::sha2_t hash(sha);
			// Хеш очередного счётчика
			hash.update(seed);
			hash.update(view_t(counter, sizeof(counter)));
			// Доводим хеш до конца
			(void) hash.finish(full, sizeof(full));
			// Переносим блок в результат
			const size_t take = (((size - done) < length) ? (size - done) : length);
			// Переносим часть блока по остатку длины
			::memcpy((out + done), full, take);
			// Прибавляем длину перенесённого
			done += take;
			/**
			 * Увеличиваем счётчик блоков
			 */
			for(size_t i = 4; (i > 0) && (++counter[i - 1] == 0); i--);
		}
		// Затираем полное значение хеша
		sys::wipe(full, sizeof(full));
	}
	/**
	 * @brief Функция цепочки WOTS+ (алгоритм 5 FIPS 205)
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
			// Значение переносится без изменений
			::memcpy(out, in, p.n);
			// Выходим с перенесённым значением
			return;
		}
		// Первый шаг со входного значения
		setStep(p, adrs, static_cast <uint32_t> (start));
		// Вырабатываем первое значение цепочки
		F(p, pkSeed, adrs, view_t(in, p.n), out);
		/**
		 * Остальные шаги по цепочке
		 */
		for(size_t j = (start + 1); j < (start + steps); j++){
			// Адрес очередного шага
			setStep(p, adrs, static_cast <uint32_t> (j));
			// Вырабатываем следующее значение цепочки
			F(p, pkSeed, adrs, view_t(out, p.n), out);
		}
	}
	/**
	 * @brief Функция выработки открытого ключа WOTS+ (алгоритм 6 FIPS 205)
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
		// Адреса секретного значения и цепочки
		adrs_t skAdrs, chain;
		// Копируем исходный адрес
		copyAdrs(skAdrs, adrs);
		// Вид адреса секретного значения
		setType(p, skAdrs, 5);
		// Пара ключа в адресе значения
		copyKeypair(p, skAdrs, adrs);
		/**
		 * Проходим по всем цепочкам ключа
		 */
		for(size_t i = 0; i < len; i++){
			// Адрес цепочки в адресе значения
			setChain(p, skAdrs, static_cast <uint32_t> (i));
			// Секрет цепочки из секретного зерна
			PRF(p, pkSeed, skSeed, skAdrs, sk);
			// Копируем исходный адрес
			copyAdrs(chain, adrs);
			// Адрес цепочки
			setChain(p, chain, static_cast <uint32_t> (i));
			// Конец цепочки по всем шагам
			wotsChain(p, pkSeed, sk, 0, (CHAIN - 1), chain, (values + (i * p.n)));
		}
		// Адрес открытого ключа
		adrs_t pkAdrs;
		// Копируем исходный адрес
		copyAdrs(pkAdrs, adrs);
		// Вид адреса открытого ключа
		setType(p, pkAdrs, 1);
		// Пара ключа в адресе ключа
		copyKeypair(p, pkAdrs, adrs);
		// Открытый ключ - функция T над концами цепочек
		T(p, pkSeed, pkAdrs, view_t(values, (len * p.n)), out);
		// Затираем массив значений цепочек
		sys::wipe(values, sizeof(values));
		sys::wipe(sk, sizeof(sk));
		sys::wipe(skAdrs, sizeof(skAdrs));
		sys::wipe(chain, sizeof(chain));
		sys::wipe(pkAdrs, sizeof(pkAdrs));
	}
	/**
	 * @brief Функция выкладки сообщения и контрольной суммы полубайтами
	 *
	 * @param p   параметры набора
	 * @param msg сообщение, n байтов
	 * @param out место полубайтов сообщения и контрольной суммы, 2n + 3 значений
	 *
	 */
	static void wotsMessage(const Params & p, const uint8_t * msg, uint8_t * out) noexcept {
		/**
		 * Сообщение раскладывается на 2n полубайтов, старший вперёд
		 */
		for(size_t i = 0; i < p.n; i++){
			// Старший полубайт байта сообщения
			out[2 * i] = (msg[i] >> 4);
			// Младший полубайт байта сообщения
			out[(2 * i) + 1] = (msg[i] & 0x0F);
		}
		// Контрольная сумма: 15·2n минус сумма полубайтов сообщения, тремя полубайтами
		uint16_t sum = 0;
		/**
		 * Складываем полубайты сообщения
		 */
		for(size_t i = 0; i < (2 * p.n); i++)
			// Прибавляем очередной полубайт
			sum += out[i];
		// Вычитаем сумму из предела пятнадцати
		sum = static_cast <uint16_t> ((15 * 2 * p.n) - sum);
		// Старший полубайт суммы
		out[2 * p.n] = static_cast <uint8_t> ((sum >> 8) & 0x0F);
		// Следующий полубайт суммы
		out[(2 * p.n) + 1] = static_cast <uint8_t> ((sum >> 4) & 0x0F);
		// Младший полубайт суммы
		out[(2 * p.n) + 2] = static_cast <uint8_t> (sum & 0x0F);
	}
	/**
	 * @brief Функция подписи WOTS+ (алгоритм 7 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя, дерева и пары ключа
	 * @param out    место записи подписи, по n байтов на цепочку; возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * wotsSign(const Params & p, const uint8_t * msg, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Полубайты сообщения и контрольной суммы
		uint8_t nibbles[67];
		// Раскладываем сообщение на полубайты
		wotsMessage(p, msg, nibbles);
		// Число цепочек подписи
		const size_t len = ((2 * p.n) + CHECKSUM);
		// Секретное значение цепочки
		uint8_t sk[MAX_N];
		// Адреса секретного значения и цепочки
		adrs_t skAdrs, chain;
		// Копируем исходный адрес
		copyAdrs(skAdrs, adrs);
		// Вид адреса секретного значения
		setType(p, skAdrs, 5);
		// Пара ключа в адресе значения
		copyKeypair(p, skAdrs, adrs);
		/**
		 * Проходим по всем цепочкам подписи
		 */
		for(size_t i = 0; i < len; i++){
			// Адрес цепочки в адресе значения
			setChain(p, skAdrs, static_cast <uint32_t> (i));
			// Секрет цепочки из секретного зерна
			PRF(p, pkSeed, skSeed, skAdrs, sk);
			// Копируем исходный адрес
			copyAdrs(chain, adrs);
			// Адрес цепочки
			setChain(p, chain, static_cast <uint32_t> (i));
			// Подпись цепочки по числу шагов полубайта
			wotsChain(p, pkSeed, sk, 0, nibbles[i], chain, out);
			// Сдвигаем место записи на значение
			out += p.n;
		}
		// Затираем полубайты сообщения
		sys::wipe(nibbles, sizeof(nibbles));
		sys::wipe(sk, sizeof(sk));
		sys::wipe(skAdrs, sizeof(skAdrs));
		sys::wipe(chain, sizeof(chain));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Функция восстановления открытого ключа WOTS+ из подписи (алгоритм 8 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param sig    подпись WOTS+, по n байтов на цепочку
	 * @param msg    сообщение, n байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя, дерева и пары ключа
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 * @return       место за прочитанной подписью
	 *
	 */
	static const uint8_t * wotsPkFromSig(const Params & p, const uint8_t * sig, const uint8_t * msg, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Полубайты сообщения и контрольной суммы
		uint8_t nibbles[67];
		// Раскладываем сообщение на полубайты
		wotsMessage(p, msg, nibbles);
		// Число цепочек подписи
		const size_t len = ((2 * p.n) + CHECKSUM);
		// Значения концов всех цепочек
		uint8_t values[MAX_N * 67];
		// Адрес цепочки
		adrs_t chain;
		/**
		 * Проходим по всем цепочкам подписи
		 */
		for(size_t i = 0; i < len; i++){
			// Копируем исходный адрес
			copyAdrs(chain, adrs);
			// Адрес цепочки
			setChain(p, chain, static_cast <uint32_t> (i));
			// Конец цепочки доигрывается от значения подписи до верха
			wotsChain(p, pkSeed, sig, nibbles[i], ((CHAIN - 1) - nibbles[i]), chain, (values + (i * p.n)));
			// Сдвигаем чтение подписи на значение
			sig += p.n;
		}
		// Адрес открытого ключа
		adrs_t pkAdrs;
		// Копируем исходный адрес
		copyAdrs(pkAdrs, adrs);
		// Вид адреса открытого ключа
		setType(p, pkAdrs, 1);
		// Пара ключа в адресе ключа
		copyKeypair(p, pkAdrs, adrs);
		// Открытый ключ - функция T над концами цепочек
		T(p, pkSeed, pkAdrs, view_t(values, (len * p.n)), out);
		// Затираем полубайты сообщения
		sys::wipe(nibbles, sizeof(nibbles));
		sys::wipe(values, sizeof(values));
		sys::wipe(chain, sizeof(chain));
		sys::wipe(pkAdrs, sizeof(pkAdrs));
		// Выводим место за прочитанной подписью
		return sig;
	}

	/**
	 * @brief Функция вычисления узла дерева XMSS (алгоритм 9 FIPS 205)
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
			// Вид адреса листа дерева
			setType(p, adrs, 0);
			// Пара ключа листа дерева
			setKeypair(p, adrs, node);
			// Вырабатываем открытый ключ пары
			wotsPkGen(p, skSeed, pkSeed, adrs, out);
		// Узел выше листа: функция H над детьми
		} else {
			// Значения детей узла
			uint8_t left[MAX_N], right[MAX_N];
			// Адрес детей узла
			adrs_t children;
			// Копируем исходный адрес
			copyAdrs(children, adrs);
			// Вычисляем значение левого ребёнка
			xmssNode(p, skSeed, (2 * node), (height - 1), pkSeed, children, left);
			// Копируем исходный адрес
			copyAdrs(children, adrs);
			// Вычисляем значение правого ребёнка
			xmssNode(p, skSeed, ((2 * node) + 1), (height - 1), pkSeed, children, right);
			// Вид адреса узла дерева
			setType(p, adrs, 2);
			// Высота узла в адресе
			setChain(p, adrs, height);
			// Индекс узла в адресе
			setStep(p, adrs, node);
			// Вырабатываем значение узла
			H(p, pkSeed, adrs, left, right, out);
			// Затираем значение левого ребёнка
			sys::wipe(left, sizeof(left));
			sys::wipe(right, sizeof(right));
		}
	}
	/**
	 * @brief Функция подписи XMSS (алгоритм 10 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param leaf   индекс пары ключа в дереве
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя и дерева
	 * @param out    место записи подписи: WOTS+ и путь из h′ узлов; возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * xmssSign(const Params & p, const uint8_t * msg, const uint8_t * skSeed, const uint32_t leaf, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Адрес подписи WOTS+
		adrs_t wots;
		// Копируем исходный адрес
		copyAdrs(wots, adrs);
		// Вид адреса подписи
		setType(p, wots, 0);
		// Пара ключа в адресе подписи
		setKeypair(p, wots, leaf);
		// Подпись WOTS+ сообщения
		uint8_t * result = wotsSign(p, msg, skSeed, pkSeed, wots, out);
		// Путь из h′ узлов: брат узла на каждом уровне
		uint32_t node = leaf;
		/**
		 * Поднимаемся по уровням дерева
		 */
		for(uint32_t height = 0; height < p.hm; height++){
			// Вырабатываем брата узла уровня
			xmssNode(p, skSeed, (node ^ 1), height, pkSeed, adrs, result);
			// Сдвигаем место записи на значение
			result += p.n;
			// Поднимаемся к родителю узла
			node >>= 1;
		}
		// Затираем адрес подписи
		sys::wipe(wots, sizeof(wots));
		// Выводим место за подписью
		return result;
	}
	/**
	 * @brief Функция восстановления корня XMSS из подписи (алгоритм 11 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param sig    подпись XMSS: WOTS+ и путь из h′ узлов
	 * @param leaf   индекс пары ключа в дереве
	 * @param msg    сообщение, n байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес слоя и дерева
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 * @return       место за прочитанной подписью
	 *
	 */
	static const uint8_t * xmssPkFromSig(const Params & p, const uint8_t * sig, const uint32_t leaf, const uint8_t * msg, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Адрес подписи WOTS+
		adrs_t wots;
		// Копируем исходный адрес
		copyAdrs(wots, adrs);
		// Вид адреса подписи
		setType(p, wots, 0);
		// Пара ключа в адресе подписи
		setKeypair(p, wots, leaf);
		// Открытый ключ WOTS+ из подписи
		const uint8_t * result = wotsPkFromSig(p, sig, msg, pkSeed, wots, out);
		// Начинаем путь с пары ключа
		uint32_t node = leaf;
		// Адрес дерева
		adrs_t tree;
		// Копируем исходный адрес
		copyAdrs(tree, adrs);
		// Вид адреса узла дерева
		setType(p, tree, 2);
		/**
		 * Поднимаемся по уровням дерева
		 */
		for(uint32_t height = 0; height < p.hm; height++){
			// Высота узла в адресе
			setChain(p, tree, (height + 1));
			// Узел складывается с братом пути по стороне индекса
			if((node & 1) == 0){
				// Поднимаемся к родителю узла
				node >>= 1;
				// Индекс родителя в адресе
				setStep(p, tree, node);
				// Значение складывается с братом справа
				H(p, pkSeed, tree, out, result, out);
			} else {
				// Узел нечётный: брат слева
				node = (node - 1) >> 1;
				// Индекс родителя в адресе
				setStep(p, tree, node);
				// Значение складывается с братом слева
				H(p, pkSeed, tree, result, out, out);
			}
			// Сдвигаем чтение подписи на значение
			result += p.n;
		}
		// Затираем адрес подписи
		sys::wipe(wots, sizeof(wots));
		sys::wipe(tree, sizeof(tree));
		// Выводим место за прочитанной подписью
		return result;
	}

	/**
	 * @brief Функция секретного значения FORS (алгоритм 14 FIPS 205)
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
		// Адрес секретного значения
		adrs_t skAdrs;
		// Копируем исходный адрес
		copyAdrs(skAdrs, adrs);
		// Вид адреса секретного значения
		setType(p, skAdrs, 6);
		// Пара ключа в адресе значения
		copyKeypair(p, skAdrs, adrs);
		// Индекс значения в адресе
		setStep(p, skAdrs, id);
		// Вырабатываем секретное значение
		PRF(p, pkSeed, skSeed, skAdrs, out);
		// Затираем адрес значения
		sys::wipe(skAdrs, sizeof(skAdrs));
	}
	/**
	 * @brief Функция вычисления узла дерева FORS (алгоритм 15 FIPS 205)
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
			// Секретное значение листа
			uint8_t sk[MAX_N];
			// Вырабатываем секретное значение
			forsSecret(p, skSeed, pkSeed, adrs, node, sk);
			// Высота листа в адресе
			setChain(p, adrs, 0);
			// Индекс листа в адресе
			setStep(p, adrs, node);
			// Вырабатываем значение листа
			F(p, pkSeed, adrs, view_t(sk, p.n), out);
			// Затираем секретное значение
			sys::wipe(sk, sizeof(sk));
		// Узел выше листа: функция H над детьми
		} else {
			// Значения детей узла
			uint8_t left[MAX_N], right[MAX_N];
			// Адрес детей узла
			adrs_t children;
			// Копируем исходный адрес
			copyAdrs(children, adrs);
			// Вычисляем значение левого ребёнка
			forsNode(p, skSeed, pkSeed, children, (2 * node), (height - 1), left);
			// Копируем исходный адрес
			copyAdrs(children, adrs);
			// Вычисляем значение правого ребёнка
			forsNode(p, skSeed, pkSeed, children, ((2 * node) + 1), (height - 1), right);
			// Высота узла в адресе
			setChain(p, adrs, height);
			// Индекс узла в адресе
			setStep(p, adrs, node);
			// Вырабатываем значение узла
			H(p, pkSeed, adrs, left, right, out);
			// Затираем значение левого ребёнка
			sys::wipe(left, sizeof(left));
			sys::wipe(right, sizeof(right));
		}
	}
	/**
	 * @brief Функция раскладки дайджеста по основанию 2^a (алгоритм 4 FIPS 205)
	 *
	 * @param in     дайджест, первые (k·a + 7) / 8 байтов
	 * @param a      основание раскладки
	 * @param out    место k значений по a разрядов
	 * @param k      число значений
	 *
	 */
	static void base2b(const uint8_t * in, const uint32_t a, uint32_t * out, const size_t k) noexcept {
		// Набранные разряды и накопленное значение
		uint32_t bits = 0, total = 0;
		// Маска разрядов значения
		const uint32_t mask = ((1u << a) - 1);
		/**
		 * Раскладываем дайджест на k значений
		 */
		for(size_t i = 0; i < k; i++){
			/**
			 * Набираем разряды до полного значения
			 */
			while(bits < a){
				// Прибавляем очередной байт
				total <<= 8;
				// Считаем набранные разряды
				total += *in++;
				// Отрезаем разряды значения
				bits += 8;
			}
			// Отрезаем разряды значения
			bits -= a;
			// Записываем очередное значение
			*out++ = ((total >> bits) & mask);
		}
	}
	/**
	 * @brief Функция подписи FORS (алгоритм 16 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param md     дайджест, первые (k·a + 7) / 8 байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес вида FORS_TREE с парой ключа
	 * @param out    место записи подписи: k × (значение ‖ путь из a узлов); возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * forsSign(const Params & p, const uint8_t * md, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Значения листьев по k деревьям
		uint32_t ids[MAX_K];
		// Раскладываем дайджест на индексы листьев
		base2b(md, p.a, ids, p.k);
		// Секретное значение листа
		uint8_t value[MAX_N];
		// Смещение леса по уровням: каждое дерево занимает свою полосу индексов
		uint32_t forest = 0;
		/**
		 * Проходим по всем деревьям леса
		 */
		for(size_t tree = 0; tree < p.k; tree++){
			// Индекс листа дерева
			uint32_t node = ids[tree];
			// Секретное значение листа
			forsSecret(p, skSeed, pkSeed, adrs, (node + forest), value);
			// Записываем секретное значение листа
			::memcpy(out, value, p.n);
			// Сдвигаем место записи на значение
			out += p.n;
			// Смещение дерева в лесу
			uint32_t offset = forest;
			/**
			 * Путь из a узлов: брат узла на каждом уровне
			 */
			for(uint32_t height = 0; height < p.a; height++){
				// Вырабатываем брата узла уровня
				forsNode(p, skSeed, pkSeed, adrs, ((node ^ 1) + offset), height, out);
				// Сдвигаем место записи на значение
				out += p.n;
				// Поднимаемся к родителю узла
				node >>= 1;
				// Смещение поднимается вместе с нами
				offset >>= 1;
			}
			// Дерево занимает свою полосу леса
			forest += (1u << p.a);
		}
		// Затираем секретное значение листа
		sys::wipe(value, sizeof(value));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Функция восстановления открытого ключа FORS из подписи (алгоритм 17 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param sig    подпись FORS: k × (значение ‖ путь из a узлов)
	 * @param md     дайджест, первые (k·a + 7) / 8 байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес вида FORS_TREE с парой ключа
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 * @return       место за прочитанной подписью
	 *
	 */
	static const uint8_t * forsPkFromSig(const Params & p, const uint8_t * sig, const uint8_t * md, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Значения листьев по k деревьям
		uint32_t ids[MAX_K];
		// Раскладываем дайджест на индексы листьев
		base2b(md, p.a, ids, p.k);
		// Корни всех деревьев леса
		uint8_t roots[MAX_K * MAX_N];
		// Смещение леса по деревьям
		uint32_t forest = 0;
		/**
		 * Проходим по всем деревьям леса
		 */
		for(size_t tree = 0; tree < p.k; tree++){
			// Индекс листа дерева
			uint32_t id = ids[tree];
			// Индекс листа в лесу
			uint32_t node = (id + forest);
			// Место корня дерева
			uint8_t * node0 = (roots + (tree * p.n));
			// Высота листа в адресе
			setChain(p, adrs, 0);
			// Индекс листа в адресе
			setStep(p, adrs, node);
			// Лист из значения подписи
			F(p, pkSeed, adrs, view_t(sig, p.n), node0);
			// Сдвигаем чтение подписи на значение
			sig += p.n;
			// Место очередного узла дерева
			uint8_t * node1 = node0;
			/**
			 * Поднимаемся по уровням дерева
			 */
			for(uint32_t height = 0; height < p.a; height++){
				// Высота узла в адресе
				setChain(p, adrs, (height + 1));
				// Узел складывается с братом пути по стороне индекса
				if((id & 1) == 0){
					// Поднимаемся к родителю узла
					node >>= 1;
					// Индекс родителя в адресе
					setStep(p, adrs, node);
					// Значение складывается с братом справа
					H(p, pkSeed, adrs, node0, sig, node1);
				} else {
					// Узел нечётный: брат слева
					node = (node - 1) >> 1;
					// Индекс родителя в адресе
					setStep(p, adrs, node);
					// Значение складывается с братом слева
					H(p, pkSeed, adrs, sig, node0, node1);
				}
				// Сдвигаем чтение подписи на значение
				sig += p.n;
				// Индекс поднимается к корню дерева
				id >>= 1;
			}
			// Дерево занимает свою полосу леса
			forest += (1u << p.a);
		}
		// Адрес открытого ключа
		adrs_t pkAdrs;
		// Копируем исходный адрес
		copyAdrs(pkAdrs, adrs);
		// Вид адреса открытого ключа
		setType(p, pkAdrs, 4);
		// Пара ключа в адресе ключа
		copyKeypair(p, pkAdrs, adrs);
		// Открытый ключ FORS - функция T над корнями всех деревьев
		T(p, pkSeed, pkAdrs, view_t(roots, (p.k * p.n)), out);
		// Затираем корни всех деревьев
		sys::wipe(roots, sizeof(roots));
		sys::wipe(pkAdrs, sizeof(pkAdrs));
		// Выводим место за прочитанной подписью
		return sig;
	}

	/**
	 * @brief Функция подписи гипердерева (алгоритм 12 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param tree   индекс дерева нижнего слоя
	 * @param leaf   индекс пары ключа в дереве нижнего слоя
	 * @param out    место записи подписи: d подписей XMSS; возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static uint8_t * htSign(const Params & p, const uint8_t * msg, const uint8_t * skSeed, const uint8_t * pkSeed, uint64_t tree, uint32_t leaf, uint8_t * out) noexcept {
		// Маска пары ключа дерева слоя
		const uint32_t mask = ((1u << p.hm) - 1);
		// Адрес дерева слоя
		adrs_t adrs;
		// Обнуляем адрес
		zero(adrs);
		// Подписываемое слоем значение: сперва корень FORS
		uint8_t root[MAX_N];
		// Копируем сообщение в подписываемое значение
		::memcpy(root, msg, p.n);
		/**
		 * Проходим по всем слоям гипердерева
		 */
		for(uint32_t layer = 0; layer < p.d; layer++){
			// Адрес слоя в адресе
			setLayer(p, adrs, layer);
			// Адрес дерева в адресе
			setTree(p, adrs, tree);
			// Запоминаем начало подписи слоя
			uint8_t * layerSig = out;
			// Подписываем значение деревом слоя
			out = xmssSign(p, root, skSeed, leaf, pkSeed, adrs, out);
			// Корень следующего слоя - открытый ключ только что подписанного дерева
			if(layer < (p.d - 1)){
				// Восстанавливаем корень подписанного дерева
				(void) xmssPkFromSig(p, layerSig, leaf, root, pkSeed, adrs, root);
				// Пара следующего слоя из дерева
				leaf = (tree & mask);
				// Дерево поднимается на слой выше
				tree >>= p.hm;
			}
		}
		// Затираем подписываемое значение
		sys::wipe(root, sizeof(root));
		sys::wipe(adrs, sizeof(adrs));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Функция проверки подписи гипердерева (алгоритм 13 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param msg    сообщение, n байтов
	 * @param sig    подпись гипердерева: d подписей XMSS
	 * @param pkSeed открытое зерно ключа
	 * @param tree   индекс дерева нижнего слоя
	 * @param leaf   индекс пары ключа в дереве нижнего слоя
	 * @param pkRoot корень ключа проверки
	 * @return       признак того, что гипердерево сошлось с корнем
	 *
	 */
	static bool htVerify(const Params & p, const uint8_t * msg, const uint8_t * sig, const uint8_t * pkSeed, uint64_t tree, uint32_t leaf, const uint8_t * pkRoot) noexcept {
		// Маска пары ключа дерева слоя
		const uint32_t mask = ((1u << p.hm) - 1);
		// Адрес дерева слоя
		adrs_t adrs;
		// Обнуляем адрес
		zero(adrs);
		// Проверяемое слоем значение: сперва корень FORS
		uint8_t node[MAX_N];
		// Копируем сообщение в проверяемое значение
		::memcpy(node, msg, p.n);
		/**
		 * Проходим по всем слоям гипердерева
		 */
		for(uint32_t layer = 0; layer < p.d; layer++){
			// Адрес слоя в адресе
			setLayer(p, adrs, layer);
			// Адрес дерева в адресе
			setTree(p, adrs, tree);
			// Восстанавливаем корень дерева слоя
			sig = xmssPkFromSig(p, sig, leaf, node, pkSeed, adrs, node);
			// Пара следующего слоя из дерева
			leaf = (tree & mask);
			// Дерево поднимается на слой выше
			tree >>= p.hm;
		}
		// Сверху дерева обязан лежать корень ключа проверки
		const bool result = (::memcmp(node, pkRoot, p.n) == 0);
		// Сверяем восстановленный корень с ключом
		sys::wipe(node, sizeof(node));
		sys::wipe(adrs, sizeof(adrs));
		// Выводим признак схождения
		return result;
	}

	/**
	 * @brief Функция получения целого из байтов старшим байтом вперёд
	 *
	 * @param in   байты
	 * @param size число байтов
	 * @return     целое число
	 *
	 */
	static uint64_t bytesToInt(const uint8_t * in, const size_t size) noexcept {
		// Накопленное значение
		uint64_t result = 0;
		/**
		 * Складываем байты старшим вперёд
		 */
		for(size_t i = 0; i < size; i++)
			// Прибавляем очередной байт
			result = ((result << 8) + in[i]);
		// Выводим накопленное значение
		return result;
	}

	/**
	 * @brief Функция выработки корня ключа проверки (алгоритм 18 FIPS 205)
	 *
	 * @param p      параметры набора
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param out    место результата, n байтов
	 *
	 */
	static void pkRoot(const Params & p, const uint8_t * skSeed, const uint8_t * pkSeed, uint8_t * out) noexcept {
		// Адрес дерева верхнего слоя
		adrs_t adrs;
		// Обнуляем адрес
		zero(adrs);
		// Адрес верхнего слоя
		setLayer(p, adrs, (p.d - 1));
		// Вырабатываем корень вершиной дерева
		xmssNode(p, skSeed, 0, p.hm, pkSeed, adrs, out);
		// Затираем адрес
		sys::wipe(adrs, sizeof(adrs));
	}

	/**
	 * @brief Функция порождения ключа из зерна (раздел 10.1 FIPS 205)
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
	 * @brief Функция выработки подписи (раздел 10.2 FIPS 205)
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
		// Секретное зерно ключа
		const uint8_t * skSeed = secret;
		// Секретный ключ случайности
		const uint8_t * skPrf = (secret + p.n);
		// Открытое зерно ключа
		const uint8_t * pkSeed = (secret + (2 * p.n));
		// Корень ключа проверки
		const uint8_t * pkRoot = (secret + (3 * p.n));
		// Случайность opt_rand: нули заменяются открытым зерном ключа (детерминированный вариант)
		uint32_t noisy = 0;
		/**
		 * Сличаем случайность подписи с нулями
		 */
		for(size_t i = 0; i < 32; i++)
			// Прибавляем очередной байт
			noisy |= rnd[i];
		// Нули заменяются открытым зерном ключа
		const uint8_t * optRand = ((noisy == 0) ? pkSeed : rnd);
		// Сообщение с обвязкой: 0x00 ‖ длина контекста ‖ контекст ‖ сообщение
		uint8_t r[MAX_N], m[MAX_M];
		// Случайность подписи R = PRFmsg(SK.prf, opt_rand, обвязанное сообщение)
		{
			// Губка выработки случайности
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Ветвь выработки семейства SHAKE
			if(p.family == FAMILY_SHAKE){
				// Подаём секретный ключ случайности
				xof.update(view_t(skPrf, p.n));
				xof.update(view_t(optRand, p.n));
				// Префикс: ноль и длина контекста
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				// Подаём префикс обвязки
				xof.update(view_t(prefix, sizeof(prefix)));
				xof.update(context);
				xof.update(message);
				// Выжимаем случайность нужной длины
				(void) xof.squeeze(r, p.n);
			} else {
				// Ветвь выработки семейства SHA2
				digest::mac_t hmac;
				// Код выработки аутентификации
				uint8_t full[64];
				// Полное значение хеша
				const size_t length = ((p.family == FAMILY_SHA2_35) ? 64 : 32);
				// Начинаем код с секретным ключом
				if(hmac.start(((p.family == FAMILY_SHA2_35) ? digest::hash_t::SHA512 : digest::hash_t::SHA256), view_t(skPrf, p.n))){
					// Подаём случайность выработки
					hmac.update(view_t(optRand, p.n));
					// Префикс: ноль и длина контекста
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					// Подаём префикс обвязки
					hmac.update(view_t(prefix, sizeof(prefix)));
					hmac.update(context);
					hmac.update(message);
					// Доводим код до конца
					if(hmac.finish(full, length))
						// Переносим случайность из кода
						::memcpy(r, full, p.n);
					// Затираем полное значение хеша
					sys::wipe(full, sizeof(full));
				}
			}
		}
		// Дайджест сообщения m байтов: Hmsg(R ‖ PK.seed ‖ PK.root ‖ обвязанное сообщение)
		{
			// Ветвь выработки семейства SHAKE
			if(p.family == FAMILY_SHAKE){
				// Губка выработки дайджеста
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				// Подаём случайность подписи
				xof.update(view_t(r, p.n));
				xof.update(view_t(pkSeed, p.n));
				xof.update(view_t(pkRoot, p.n));
				// Префикс: ноль и длина контекста
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				// Подаём префикс обвязки
				xof.update(view_t(prefix, sizeof(prefix)));
				xof.update(context);
				xof.update(message);
				// Выжимаем дайджест нужной длины
				(void) xof.squeeze(m, p.m);
			} else {
				// Зерно порождения: случайность, открытое зерно и хеш сообщения
				uint8_t seed[(2 * MAX_N) + 64];
				// Ветвь выработки семейства SHA2
				const size_t length = ((p.family == FAMILY_SHA2_35) ? 64 : 32);
				// Переносим случайность в зерно
				::memcpy(seed, r, p.n);
				::memcpy((seed + p.n), pkSeed, p.n);
				{
					// Хеш сжатия зерна порождения
					digest::sha2_t sha(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256));
					// Подаём случайность подписи
					sha.update(view_t(r, p.n));
					sha.update(view_t(pkSeed, p.n));
					sha.update(view_t(pkRoot, p.n));
					// Префикс: ноль и длина контекста
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					// Подаём префикс обвязки
					sha.update(view_t(prefix, sizeof(prefix)));
					sha.update(context);
					sha.update(message);
					// Сжимаем обвязанное сообщение в зерно
					(void) sha.finish((seed + (2 * p.n)), length);
				}
				// Порождаем дайджест из зерна
				MGF1(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256), view_t(seed, ((2 * p.n) + length)), m, p.m);
				// Затираем зерно порождения
				sys::wipe(seed, sizeof(seed));
			}
		}
		// Дайджест раскладывается: md, индекс дерева, индекс пары ключа
		const size_t mdLen = (((static_cast <size_t> (p.k) * p.a) + 7) >> 3);
		// Длина индекса дерева в байтах
		const size_t treeLen = (((static_cast <size_t> (p.d) * p.hm - p.hm) + 7) >> 3);
		// Длина индекса пары в байтах
		const size_t leafLen = ((p.hm + 7) >> 3);
		// Индекс дерева из дайджеста
		const uint64_t tree = (bytesToInt((m + mdLen), treeLen) & ((~static_cast <uint64_t> (0)) >> (64 - ((p.d * p.hm) - p.hm))));
		// Индекс пары ключа из дайджеста
		const uint32_t leaf = static_cast <uint32_t> (bytesToInt((m + mdLen + treeLen), leafLen) & ((static_cast <uint64_t> (1) << p.hm) - 1));
		// Запись подписи: R ‖ FORS ‖ HT
		uint8_t * out = result;
		// Записываем случайность подписи
		::memcpy(out, r, p.n);
		// Сдвигаем место записи на значение
		out += p.n;
		// Адрес дерева подписи
		adrs_t adrs;
		// Обнуляем адрес
		zero(adrs);
		// Адрес дерева в адресе
		setTree(p, adrs, tree);
		// Вид адреса дерева подписи
		setType(p, adrs, 3);
		// Пара ключа в адресе
		setKeypair(p, adrs, leaf);
		// Запоминаем начало подписи FORS
		uint8_t * fors = out;
		// Подписываем дайджест лесом FORS
		out = forsSign(p, m, skSeed, pkSeed, adrs, out);
		// Корень FORS из только что выработанной подписи
		uint8_t pkFors[MAX_N];
		// Восстанавливаем корень FORS из подписи
		(void) forsPkFromSig(p, fors, m, pkSeed, adrs, pkFors);
		// Подписываем корень FORS гипердеревом
		(void) htSign(p, pkFors, skSeed, pkSeed, tree, leaf, out);
		// Затираем случайность подписи
		sys::wipe(r, sizeof(r));
		sys::wipe(m, sizeof(m));
		sys::wipe(pkFors, sizeof(pkFors));
		sys::wipe(adrs, sizeof(adrs));
	}

	/**
	 * @brief Функция проверки подписи (раздел 10.3 FIPS 205)
	 *
	 * @param p         параметры набора
	 * @param key       запись ключа проверки: PK.seed ‖ PK.root
	 * @param message   подписанное сообщение
	 * @param context   контекст подписи
	 * @param signature проверяемая подпись: R ‖ FORS ‖ HT
	 * @return          признак того, что подпись сошлась
	 *
	 */
	static bool checking(const Params & p, const uint8_t * key, const view_t & message, const view_t & context, const uint8_t * signature) noexcept {
		// Открытое зерно ключа
		const uint8_t * pkSeed = key;
		// Корень ключа проверки
		const uint8_t * pkRoot = (key + p.n);
		// Случайность подписи
		const uint8_t * r = signature;
		// Дайджест сообщения m байтов: Hmsg(R ‖ PK.seed ‖ PK.root ‖ обвязанное сообщение)
		uint8_t m[MAX_M];
		{
			// Ветвь выработки семейства SHAKE
			if(p.family == FAMILY_SHAKE){
				// Губка выработки дайджеста
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				// Подаём случайность подписи
				xof.update(view_t(r, p.n));
				xof.update(view_t(pkSeed, p.n));
				xof.update(view_t(pkRoot, p.n));
				// Префикс: ноль и длина контекста
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				// Подаём префикс обвязки
				xof.update(view_t(prefix, sizeof(prefix)));
				xof.update(context);
				xof.update(message);
				// Выжимаем дайджест нужной длины
				(void) xof.squeeze(m, p.m);
			} else {
				// Зерно порождения: случайность, открытое зерно и хеш сообщения
				uint8_t seed[(2 * MAX_N) + 64];
				// Ветвь выработки семейства SHA2
				const size_t length = ((p.family == FAMILY_SHA2_35) ? 64 : 32);
				// Зерно порождения маски
				::memcpy(seed, r, p.n);
				::memcpy((seed + p.n), pkSeed, p.n);
				{
					// Хеш сжатия зерна порождения
					digest::sha2_t sha(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256));
					// Подаём случайность подписи
					sha.update(view_t(r, p.n));
					sha.update(view_t(pkSeed, p.n));
					sha.update(view_t(pkRoot, p.n));
					// Префикс: ноль и длина контекста
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					// Подаём префикс обвязки
					sha.update(view_t(prefix, sizeof(prefix)));
					sha.update(context);
					sha.update(message);
					// Сжимаем обвязанное сообщение в зерно
					(void) sha.finish((seed + (2 * p.n)), length);
				}
				// Порождаем дайджест из зерна
				MGF1(((p.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256), view_t(seed, ((2 * p.n) + length)), m, p.m);
				// Затираем зерно порождения
				sys::wipe(seed, sizeof(seed));
			}
		}
		// Дайджест раскладывается: md, индекс дерева, индекс пары ключа
		const size_t mdLen = (((static_cast <size_t> (p.k) * p.a) + 7) >> 3);
		// Длина индекса дерева в байтах
		const size_t treeLen = (((static_cast <size_t> (p.d) * p.hm - p.hm) + 7) >> 3);
		// Длина индекса пары в байтах
		const size_t leafLen = ((p.hm + 7) >> 3);
		// Индекс дерева из дайджеста
		const uint64_t tree = (bytesToInt((m + mdLen), treeLen) & ((~static_cast <uint64_t> (0)) >> (64 - ((p.d * p.hm) - p.hm))));
		// Индекс пары ключа из дайджеста
		const uint32_t leaf = static_cast <uint32_t> (bytesToInt((m + mdLen + treeLen), leafLen) & ((static_cast <uint64_t> (1) << p.hm) - 1));
		// Адрес дерева подписи
		adrs_t adrs;
		// Обнуляем адрес
		zero(adrs);
		// Адрес дерева в адресе
		setTree(p, adrs, tree);
		// Вид адреса дерева подписи
		setType(p, adrs, 3);
		// Пара ключа в адресе
		setKeypair(p, adrs, leaf);
		// Подпись за случайностью
		const uint8_t * sig = (signature + p.n);
		// Корень FORS из подписи
		uint8_t pkFors[MAX_N];
		// Восстанавливаем корень FORS из подписи
		sig = forsPkFromSig(p, sig, m, pkSeed, adrs, pkFors);
		// Гипердерево обязано сойтись с корнем ключа проверки
		const bool result = htVerify(p, pkFors, sig, pkSeed, tree, leaf, pkRoot);
		// Затираем дайджест сообщения
		sys::wipe(m, sizeof(m));
		sys::wipe(pkFors, sizeof(pkFors));
		sys::wipe(adrs, sizeof(adrs));
		// Выводим признак схождения
		return result;
	}

	/**
	 * @brief Функция проверки подлинности записи ключа подписи
	 *
	 * @param p      параметры набора
	 * @param secret запись ключа подписи
	 * @return       признак того, что корень записи сходится с пересчитанным из зерна
	 *
	 */
	static bool consistent(const Params & p, const uint8_t * secret) noexcept {
		// Корень, пересчитанный из зерна записи
		uint8_t root[MAX_N];
		// Пересчитываем корень из зерна записи
		pkRoot(p, secret, (secret + (2 * p.n)), root);
		// Сличаем корень с записанным в записи
		const bool result = (::memcmp(root, (secret + (3 * p.n)), p.n) == 0);
		// Затираем пересчитанный корень
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
		// Набора нет без ключа
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
		// Размера нет без ключа
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
		// Предела нет без ключа
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
	// Сбрасываем признак ключа проверки
	this->_public = false;
	// Сбрасываем набор параметров ключа
	this->_set = set_t::NONE;
}

/**
 * @brief Метод получения размера зерна порождения набора в байтах
 *
 * @param set набор параметров
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
 * @param seed   зерно выработки длиной 3n байтов: SK.seed ‖ SK.prf ‖ PK.seed
 * @param key    место, в которое помещается ключ проверки PK.seed ‖ PK.root
 * @param secret место, в которое помещается ключ подписи SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Slhdsa::generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и зерно верной длины
	const Params p = params(set);
	// Набор существует и зерно верной длины
	if((p.n != 0) && (seed.size == (3 * p.n))){
		// Порождаем ключ из зерна
		keygen(p, static_cast <const uint8_t *> (seed.data), key, secret);
		// Порождение ключа прошло успешно
		result = true;
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод порождения долговременного ключа подписи из источника случайности
 *
 * @param set    набор параметров
 * @param key    место, в которое помещается ключ проверки PK.seed ‖ PK.root
 * @param secret место, в которое помещается ключ подписи SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Slhdsa::generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют
	const Params p = params(set);
	// Набор параметров существует
	if(p.n != 0){
		// Зерно порождения из источника случайности
		uint8_t seed[3 * MAX_N];
		// Зерно порождается источником случайности
		if(entropy::bytes(seed, (3 * p.n))){
			// Порождаем ключ из зерна
			keygen(p, seed, key, secret);
			// Порождение ключа прошло успешно
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
 * @param secret запись ключа подписи SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root по набору
 * @return       признак успешности установки ключа подписи
 *
 */
bool sign::Slhdsa::secret(const set_t set, const view_t & secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	const Params p = params(set);
	// Набор существует и запись верной длины
	if((p.n != 0) && (secret.size == (4 * p.n))){
		// Подлинность записи проверяется пересчётом корня из зерна записи
		if(consistent(p, static_cast <const uint8_t *> (secret.data))){
			// Запоминаем запись ключа подписи
			::memcpy(this->_key, secret.data, (4 * p.n));
			::memcpy(this->_pkey, (static_cast <const uint8_t *> (secret.data) + (2 * p.n)), (2 * p.n));
			// Запоминаем набор параметров ключа
			this->_set = set;
			// Устанавливаем признак ключа подписи
			this->_secret = true;
			// Устанавливаем признак ключа проверки
			this->_public = true;
			// Установка ключа прошла успешно
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
 * @param key запись ключа проверки PK.seed ‖ PK.root по набору
 * @return    признак успешности установки ключа проверки подписи
 *
 */
bool sign::Slhdsa::key(const set_t set, const view_t & key) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	const Params p = params(set);
	// Набор существует и запись верной длины
	if((p.n != 0) && (key.size == (2 * p.n))){
		// Если ключ подписи установлен, поданный обязан совпасть с записанным
		if(this->_secret && (this->_set == set)){
			if(::memcmp(this->_pkey, key.data, (2 * p.n)) == 0)
				// Поданный ключ совпал с записанным
				result = true;
		} else {
			// Иначе устанавливаем ключ проверки
			::memcpy(this->_pkey, key.data, (2 * p.n));
			// Запоминаем набор параметров ключа
			this->_set = set;
			// Устанавливаем признак ключа проверки
			this->_public = true;
			// Установка ключа прошла успешно
			result = true;
		}
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод получения ключа проверки подписи
 *
 * @param result место, в которое записывается ключ проверки PK.seed ‖ PK.root по набору
 * @param size   размер места, не меньше размера ключа проверки набора
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
		// Ключ проверки выведен
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
 * @param result  место, в которое помещается подпись R ‖ FORS ‖ HT по набору
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
		// Случайность порождается источником
		if(entropy::bytes(rnd, sizeof(rnd))){
			// Вырабатываем подпись
			signing(params(this->_set), this->_key, rnd, message, context, result);
			// Подпись выработана успешно
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
 * @param result  место, в которое помещается подпись R ‖ FORS ‖ HT по набору
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
		// Подпись выработана успешно
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
 * @param signature проверяемая подпись R ‖ FORS ‖ HT по набору
 * @return          признак того, что подпись сошлась
 *
 */
bool sign::Slhdsa::check(const view_t & message, const view_t & context, const view_t & signature) const noexcept {
	// Результат работы
	bool result = false;
	// Ключ проверки установлен, запись подписи верной длины и контекст в пределе
	const Params p = params(this->_set);
	// Ключ проверки установлен и запись верной длины
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
