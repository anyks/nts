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
 *  1. Дерево подписи - гипердерево из d деревьев XMSS высотой h′: корень
 *    гипердерева и есть корень ключа проверки PK.root; лес FORS из k деревьев
 *    по 2^a листьев подписывает дайджест сообщения, а гипердерево подписывает
 *    корень FORS. Подпись - R ‖ k × (значение sk ‖ путь из a узлов) ‖ d
 *    подписей XMSS; цепочки WOTS+ (w = 16, len = 2n + 3) - внутри XMSS.
 *  2. Семейства хешей раздела 11 FIPS 205: у SHAKE все функции строятся на
 *    SHAKE-256 с адресом в 32 байта; у SHA2-128 (категория 1) - на SHA-256 со
 *    сжатым адресом в 22 байта и HMAC-SHA-256, H_MSG через MGF1 на SHA-256;
 *    у SHA2-192/256 (категории 3 и 5) - сжатие одного значения и выработка
 *    из зерна на SHA-256, сжатие пары и переменной длины на SHA-512,
 *    HMAC-SHA-512, H_MSG через MGF1 на SHA-512.
 *  3. Запись ключа подписи - форма стандарта SK.seed ‖ SK.prf ‖ PK.seed ‖
 *    PK.root без перекладки при установке: выработка подписи читает значения
 *    как есть. Зерно порождения - SK.seed ‖ SK.prf ‖ PK.seed, корень
 *    вычисляется вершиной дерева верхнего слоя. Вся рабочая память на стеке.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартный заголовочный файл
 */
#include <tuple>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "sys/wipe.hpp"
#include "digest/sha2.hpp"
#include "digest/sha3.hpp"
#include "digest/hmac.hpp"
#include "entropy/entropy.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "sign/slhdsa.hpp"

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
	 * Количество значений цепочки WOTS+ (w = 16)
	 */
	static constexpr size_t CHAIN = 16;
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
	 * Количество контрольных полубайтов WOTS+
	 */
	static constexpr size_t CHECKSUM = 3;

	/**
	 * @brief Структура набора параметров стандарта
	 *
	 */
	typedef struct Params {
		// Семейство хешей: SHAKE256, SHA2 категории 1, SHA2 категорий 3 и 5
		uint8_t family = 0;
		// Длина дайджеста сообщения m в байтах
		uint8_t message = 0;
		// Длина значения n в байтах
		uint8_t security = 0;
		// Число деревьев FORS k
		uint8_t forsTrees = 0;
		// Количество уровней дерева FORS a
		uint8_t forsLevels = 0;
		// Число деревьев гипердерева d
		uint8_t hypertrees = 0;
		// Высота дерева XMSS h′
		uint8_t xmssHeight = 0;
		// Размер ключа проверки в байтах (2n)
		uint16_t pub = 0;
		// Размер подписи в байтах
		uint32_t signature = 0;
	} params_t;

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
	 * @param set номер набора параметров из таблицы 2 FIPS 205
	 * @return    параметры набора, нулевые у несуществующего
	 *
	 */
	static constexpr params_t __nts_params__(const sign::SLH_DSA::set_t set) noexcept {
		/**
		 * Выбираем параметры набора по его значению
		 */
		switch(static_cast <uint16_t> (set)){
			// Параметры SLH-DSA-SHA2-128s из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHA2_128S):
				// Формируем параметры набора
				return {FAMILY_SHA2_1, 30, 16, 14, 12, 7, 9, 32, 7856};
			// Параметры SLH-DSA-SHAKE-128s из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHAKE_128S):
				// Формируем параметры набора
				return {FAMILY_SHAKE, 30, 16, 14, 12, 7, 9, 32, 7856};
			// Параметры SLH-DSA-SHA2-128f из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHA2_128F):
				// Формируем параметры набора
				return {FAMILY_SHA2_1, 34, 16, 33, 6, 22, 3, 32, 17088};
			// Параметры SLH-DSA-SHAKE-128f из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHAKE_128F):
				// Формируем параметры набора
				return {FAMILY_SHAKE, 34, 16, 33, 6, 22, 3, 32, 17088};
			// Параметры SLH-DSA-SHA2-192s из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHA2_192S):
				// Формируем параметры набора
				return {FAMILY_SHA2_35, 39, 24, 17, 14, 7, 9, 48, 16224};
			// Параметры SLH-DSA-SHAKE-192s из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHAKE_192S):
				// Формируем параметры набора
				return {FAMILY_SHAKE, 39, 24, 17, 14, 7, 9, 48, 16224};
			// Параметры SLH-DSA-SHA2-192f из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHA2_192F):
				// Формируем параметры набора
				return {FAMILY_SHA2_35, 42, 24, 33, 8, 22, 3, 48, 35664};
			// Параметры SLH-DSA-SHAKE-192f из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHAKE_192F):
				// Формируем параметры набора
				return {FAMILY_SHAKE, 42, 24, 33, 8, 22, 3, 48, 35664};
			// Параметры SLH-DSA-SHA2-256s из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHA2_256S):
				// Формируем параметры набора
				return {FAMILY_SHA2_35, 47, 32, 22, 14, 8, 8, 64, 29792};
			// Параметры SLH-DSA-SHAKE-256s из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHAKE_256S):
				// Формируем параметры набора
				return {FAMILY_SHAKE, 47, 32, 22, 14, 8, 8, 64, 29792};
			// Параметры SLH-DSA-SHA2-256f из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHA2_256F):
				// Формируем параметры набора
				return {FAMILY_SHA2_35, 49, 32, 35, 9, 17, 4, 64, 49856};
			// Параметры SLH-DSA-SHAKE-256f из таблицы 2 FIPS 205
			case static_cast <uint16_t> (sign::SLH_DSA::set_t::SHAKE_256F):
				// Формируем параметры набора
				return {FAMILY_SHAKE, 49, 32, 35, 9, 17, 4, 64, 49856};
			// Несуществующий набор выдаёт нулевые параметры
			default: return {0, 0, 0, 0, 0, 0, 0, 0, 0};
		}
	}

	/**
	 * Создаём тип данных адреса в 32 байта хеширования (раздел 4.2 FIPS 205): поля слоя (4),
	 * дерева (12), вида (4), пары (4), цепочки (4), шага (4) старшим байтом вперёд
	 */
	using adrs_t = uint8_t[32];

	/**
	 * @brief Функция обнуления адреса
	 *
	 * @param adrs обнуляемый адрес хеширования
	 *
	 */
	static __NTS_INLINE__ void __nts_zero__(adrs_t adrs) noexcept {
		// Обнуляем все байты адреса
		::memset(adrs, 0, sizeof(adrs_t));
	}
	/**
	 * @brief Функция копирования адреса
	 *
	 * @param dst адрес-приёмник копии
	 * @param src копируемый адрес хеширования
	 *
	 */
	static __NTS_INLINE__ void __nts_copy_adrs__(adrs_t dst, const adrs_t src) noexcept {
		// Копируем адрес целиком
		::memcpy(dst, src, sizeof(adrs_t));
	}
	/**
	 * @brief Функция установки адреса слоя
	 *
	 * @param setup параметры набора (семейство задаёт ширину поля слоя)
	 * @param adrs  изменяемый адрес хеширования
	 * @param layer номер слоя гипердерева, от нуля до d − 1
	 *
	 */
	static __NTS_INLINE__ void __nts_set_layer__(const params_t & setup, adrs_t adrs, const uint32_t layer) noexcept {
		// У семейства SHAKE слой занимает четыре байта старшим байтом вперёд
		if(setup.family == FAMILY_SHAKE){
			// Старший байт слоя
			adrs[0] = static_cast <uint8_t> (layer >> 24);
			// Следующий байт слоя
			adrs[1] = static_cast <uint8_t> (layer >> 16);
			// Третий байт слоя
			adrs[2] = static_cast <uint8_t> (layer >> 8);
			// Младший байт слоя
			adrs[3] = static_cast <uint8_t> (layer);
		// У семейства SHA2 слой записывается одним байтом
		} else adrs[0] = static_cast <uint8_t> (layer);
	}
	/**
	 * @brief Функция установки адреса дерева
	 *
	 * @param setup параметры набора (семейство задаёт смещение поля дерева)
	 * @param adrs  изменяемый адрес хеширования
	 * @param tree  номер дерева внутри слоя, до 64 разрядов
	 *
	 */
	static __NTS_INLINE__ void __nts_set_tree__(const params_t & setup, adrs_t adrs, const uint64_t tree) noexcept {
		// У семейства SHAKE дерево лежит в последних восьми байтах поля двенадцати
		const size_t offset = ((setup.family == FAMILY_SHAKE) ? 8 : 1);
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
	 * @param setup параметры набора (семейство задаёт разметку вида)
	 * @param adrs  изменяемый адрес хеширования
	 * @param type  вид адреса: 0 подпись WOTS+, 1 открытый ключ WOTS+, 2 узел дерева,
	 *              3 лист FORS, 4 корни FORS, 5 секрет WOTS+, 6 секрет FORS
	 *
	 */
	static __NTS_INLINE__ void __nts_set_type__(const params_t & setup, adrs_t adrs, const uint32_t type) noexcept {
		// У семейства SHAKE вид занимает четыре байта старшим байтом вперёд
		if(setup.family == FAMILY_SHAKE){
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
		// У семейства SHA2 вид записывается одним байтом
		} else {
			// Записываем вид одним байтом
			adrs[9] = static_cast <uint8_t> (type);
			// Хвост после вида обнуляется по правилу стандарта
			::memset((adrs + 10), 0, 12);
		}
	}
	/**
	 * @brief Функция установки адреса пары
	 *
	 * @param setup   параметры набора (семейство задаёт смещение пары)
	 * @param adrs    изменяемый адрес хеширования
	 * @param keypair номер пары ключа WOTS+ в дереве
	 *
	 */
	static __NTS_INLINE__ void __nts_set_keypair__(const params_t & setup, adrs_t adrs, const uint32_t keypair) noexcept {
		// Смещение пары ключа в адресе
		const size_t offset = ((setup.family == FAMILY_SHAKE) ? 20 : 10);
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
	 * @param setup параметры набора (семейство задаёт смещение пары)
	 * @param dst   адрес-приёмник копии пары
	 * @param src   адрес-источник копии пары
	 *
	 */
	static __NTS_INLINE__ void __nts_copy_keypair__(const params_t & setup, adrs_t dst, const adrs_t src) noexcept {
		// Смещение пары ключа в адресе
		const size_t offset = ((setup.family == FAMILY_SHAKE) ? 20 : 10);
		// Копируем четыре байта пары
		::memcpy((dst + offset), (src + offset), 4);
	}
	/**
	 * @brief Функция установки адреса цепочки (он же высота дерева)
	 *
	 * @param setup параметры набора (семейство задаёт смещение цепочки)
	 * @param adrs  изменяемый адрес хеширования
	 * @param chain номер цепочки WOTS+ либо высота узла дерева
	 *
	 */
	static __NTS_INLINE__ void __nts_set_chain__(const params_t & setup, adrs_t adrs, const uint32_t chain) noexcept {
		// Смещение цепочки в адресе
		const size_t offset = ((setup.family == FAMILY_SHAKE) ? 24 : 14);
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
	 * @param setup параметры набора (семейство задаёт смещение шага)
	 * @param adrs  изменяемый адрес хеширования
	 * @param step  номер шага цепочки либо индекс узла или листа
	 *
	 */
	static __NTS_INLINE__ void __nts_set_step__(const params_t & setup, adrs_t adrs, const uint32_t step) noexcept {
		// Смещение шага в адресе
		const size_t offset = ((setup.family == FAMILY_SHAKE) ? 28 : 18);
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
	 * @param setup параметры набора (семейство задаёт длину адреса)
	 * @return      длина адреса в байтах: 32 у SHAKE, 22 у SHA2
	 *
	 */
	static __NTS_INLINE__ size_t __nts_adrs_size__(const params_t & setup) noexcept {
		// Длина адреса: тридцать два у SHAKE, двадцать два у SHA2
		return ((setup.family == FAMILY_SHAKE) ? 32 : 22);
	}
	/**
	 * @brief Функция сжатия хеша по одному значению (F раздела 11 FIPS 205)
	 *
	 * @param setup  параметры набора (семейство хешей и длина значения n)
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования
	 * @param value  значение, n байтов
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_compress_single__(const params_t & setup, const uint8_t * pkSeed, const adrs_t adrs, const view_t & value, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(setup.family == FAMILY_SHAKE){
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, setup.security));
			// Подаём адрес
			xof.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём сжимаемое значение
			xof.update(value);
			// Выжимаем результат нужной длины
			std::ignore = xof.squeeze(out, setup.security);
		// У семейства SHA2 функция строится на SHA-256 с добивкой зерна нулями до 64 байтов
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, setup.security));
			// Подаём добивку зерна нулями
			sha.update(view_t(padding, (64 - setup.security)));
			// Подаём адрес
			sha.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём сжимаемое значение
			sha.update(value);
			// Доводим хеш до конца
			std::ignore = sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, setup.security);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция сжатия хеша по паре значений (H раздела 11 FIPS 205)
	 *
	 * @param setup  параметры набора (семейство хешей и длина значения n)
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования
	 * @param first  первое значение, n байтов
	 * @param second второе значение, n байтов
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_compress_pair__(const params_t & setup, const uint8_t * pkSeed, const adrs_t adrs, const uint8_t * first, const uint8_t * second, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(setup.family == FAMILY_SHAKE){
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, setup.security));
			// Подаём адрес
			xof.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём первое значение
			xof.update(view_t(first, setup.security));
			// Подаём второе значение
			xof.update(view_t(second, setup.security));
			// Выжимаем результат нужной длины
			std::ignore = xof.squeeze(out, setup.security);
		// У семейства SHA2 категорий 3 и 5 сжатие строится на SHA-512 с добивкой зерна нулями до 128 байтов
		} else if(setup.family == FAMILY_SHA2_35) {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA512);
			// Полное значение хеша
			uint8_t full[64];
			// Добивка зерна нулями до блока
			const uint8_t padding[128] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, setup.security));
			// Подаём добивку зерна нулями
			sha.update(view_t(padding, (128 - setup.security)));
			// Подаём адрес
			sha.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём первое значение
			sha.update(view_t(first, setup.security));
			// Подаём второе значение
			sha.update(view_t(second, setup.security));
			// Доводим хеш до конца
			std::ignore = sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, setup.security);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		// У семейства SHA2 категории 1 сжатие строится на SHA-256 с добивкой зерна нулями до 64 байтов
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, setup.security));
			// Подаём добивку зерна нулями
			sha.update(view_t(padding, (64 - setup.security)));
			// Подаём адрес
			sha.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём первое значение
			sha.update(view_t(first, setup.security));
			// Подаём второе значение
			sha.update(view_t(second, setup.security));
			// Доводим хеш до конца
			std::ignore = sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, setup.security);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция сжатия хеша по значению переменной длины (T раздела 11 FIPS 205)
	 *
	 * @param setup  параметры набора (семейство хешей и длина значения n)
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования
	 * @param value  значение переменной длины
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_compress_wide__(const params_t & setup, const uint8_t * pkSeed, const adrs_t adrs, const view_t & value, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(setup.family == FAMILY_SHAKE){
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, setup.security));
			// Подаём адрес
			xof.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём сжимаемое значение
			xof.update(value);
			// Выжимаем результат нужной длины
			std::ignore = xof.squeeze(out, setup.security);
		// У семейства SHA2 категорий 3 и 5 сжатие строится на SHA-512
		} else if(setup.family == FAMILY_SHA2_35) {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA512);
			// Полное значение хеша
			uint8_t full[64];
			// Добивка зерна нулями до блока
			const uint8_t padding[128] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, setup.security));
			// Подаём добивку зерна нулями
			sha.update(view_t(padding, (128 - setup.security)));
			// Подаём адрес
			sha.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём сжимаемое значение
			sha.update(value);
			// Доводим хеш до конца
			std::ignore = sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, setup.security);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		// У семейства SHA2 категории 1 сжатие строится на SHA-256
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, setup.security));
			// Подаём добивку зерна нулями
			sha.update(view_t(padding, (64 - setup.security)));
			// Подаём адрес
			sha.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём сжимаемое значение
			sha.update(value);
			// Доводим хеш до конца
			std::ignore = sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, setup.security);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция выработки значения из секретного зерна (PRF раздела 11 FIPS 205)
	 *
	 * @param setup  параметры набора (семейство хешей и длина значения n)
	 * @param pkSeed открытое зерно ключа
	 * @param skSeed секретное зерно ключа
	 * @param adrs   адрес хеширования
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_prf__(const params_t & setup, const uint8_t * pkSeed, const uint8_t * skSeed, const adrs_t adrs, uint8_t * out) noexcept {
		// У семейства SHAKE все функции строятся губкой SHAKE256
		if(setup.family == FAMILY_SHAKE){
			// Губка выработки значения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём открытое зерно ключа
			xof.update(view_t(pkSeed, setup.security));
			// Подаём адрес
			xof.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём секретное зерно ключа
			xof.update(view_t(skSeed, setup.security));
			// Выжимаем результат нужной длины
			std::ignore = xof.squeeze(out, setup.security);
		// У семейства SHA2 выработка строится на SHA-256
		} else {
			// Хеш выработки значения
			digest::sha2_t sha(digest::sha_t::SHA256);
			// Полное значение хеша
			uint8_t full[32];
			// Добивка зерна нулями до блока
			const uint8_t padding[48] = {0};
			// Подаём открытое зерно ключа
			sha.update(view_t(pkSeed, setup.security));
			// Подаём добивку зерна нулями
			sha.update(view_t(padding, (64 - setup.security)));
			// Подаём адрес
			sha.update(view_t(adrs, ::__nts_adrs_size__(setup)));
			// Подаём секретное зерно ключа
			sha.update(view_t(skSeed, setup.security));
			// Доводим хеш до конца
			std::ignore = sha.finish(full, sizeof(full));
			// Переносим первые n байтов результата
			::memcpy(out, full, setup.security);
			// Затираем полное значение хеша
			sys::wipe(full, sizeof(full));
		}
	}
	/**
	 * @brief Функция порождения маски MGF1 по RFC 8017
	 *
	 * @param sha  разновидность хеша порождения: SHA-256 либо SHA-512
	 * @param seed зерно порождения
	 * @param out  место результата
	 * @param size длина результата в байтах
	 *
	 */
	static __NTS_INLINE__ void __nts_mgf1__(const digest::sha_t sha, const view_t & seed, uint8_t * out, const size_t size) noexcept {
		// Набранная длина результата
		size_t done = 0;
		// Полный хеш очередного счётчика
		uint8_t full[64];
		// Счётчик блоков порождения старшим байтом вперёд
		uint8_t counter[4] = {0, 0, 0, 0};
		// Длина полного хеша разновидности
		const size_t length = ((sha == digest::sha_t::SHA512) ? 64 : 32);
		/**
		 * Порождаем блоки маски, пока не наберётся длина
		 */
		while(done < size){
			// Порождаем очередной блок маски
			digest::sha2_t hash(sha);
			// Хеш очередного счётчика
			hash.update(seed);
			// Подаём счётчик блока
			hash.update(view_t(counter, sizeof(counter)));
			// Доводим хеш до конца
			std::ignore = hash.finish(full, sizeof(full));
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
	 * @param setup  параметры набора (семейство хешей и длина значения n)
	 * @param pkSeed открытое зерно ключа
	 * @param in     входное значение, n байтов
	 * @param start  индекс начала цепочки
	 * @param steps  количество шагов от начала
	 * @param adrs   адрес хеширования вида WOTS_HASH с адресом цепочки
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_wots_chain__(const params_t & setup, const uint8_t * pkSeed, const uint8_t * in, const size_t start, const size_t steps, adrs_t adrs, uint8_t * out) noexcept {
		// Без шагов значение переносится как есть
		if(steps == 0){
			// Значение переносится без изменений
			::memcpy(out, in, setup.security);
			// Выходим с перенесённым значением
			return;
		}
		// Первый шаг со входного значения
		::__nts_set_step__(setup, adrs, static_cast <uint32_t> (start));
		// Вырабатываем первое значение цепочки
		::__nts_compress_single__(setup, pkSeed, adrs, view_t(in, setup.security), out);
		/**
		 * Остальные шаги по цепочке
		 */
		for(size_t j = (start + 1); j < (start + steps); j++){
			// Адрес очередного шага
			::__nts_set_step__(setup, adrs, static_cast <uint32_t> (j));
			// Вырабатываем следующее значение цепочки
			::__nts_compress_single__(setup, pkSeed, adrs, view_t(out, setup.security), out);
		}
	}
	/**
	 * @brief Функция выработки открытого ключа WOTS+ (алгоритм 6 FIPS 205)
	 *
	 * @param setup  параметры набора (длина значения n задаёт количество цепочек ключа)
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования слоя, дерева и пары ключа
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_wots_pk_gen__(const params_t & setup, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Количество цепочек ключа: 2n значений сообщения и 3 контрольных
		const size_t len = ((2 * setup.security) + CHECKSUM);
		// Значения концов всех цепочек
		uint8_t values[MAX_N * 67];
		// Секретное значение цепочки
		uint8_t sk[MAX_N];
		// Адреса секретного значения и цепочки
		adrs_t skAdrs, chain;
		// Копируем исходный адрес
		::__nts_copy_adrs__(skAdrs, adrs);
		// Вид адреса секретного значения
		::__nts_set_type__(setup, skAdrs, 5);
		// Пара ключа в адресе значения
		::__nts_copy_keypair__(setup, skAdrs, adrs);
		/**
		 * Проходим по всем цепочкам ключа
		 */
		for(size_t i = 0; i < len; i++){
			// Адрес цепочки в адресе значения
			::__nts_set_chain__(setup, skAdrs, static_cast <uint32_t> (i));
			// Секрет цепочки из секретного зерна
			::__nts_prf__(setup, pkSeed, skSeed, skAdrs, sk);
			// Копируем исходный адрес
			::__nts_copy_adrs__(chain, adrs);
			// Адрес цепочки
			::__nts_set_chain__(setup, chain, static_cast <uint32_t> (i));
			// Конец цепочки по всем шагам
			::__nts_wots_chain__(setup, pkSeed, sk, 0, (CHAIN - 1), chain, (values + (i * setup.security)));
		}
		// Адрес открытого ключа
		adrs_t pkAdrs;
		// Копируем исходный адрес
		::__nts_copy_adrs__(pkAdrs, adrs);
		// Вид адреса открытого ключа
		::__nts_set_type__(setup, pkAdrs, 1);
		// Пара ключа в адресе ключа
		::__nts_copy_keypair__(setup, pkAdrs, adrs);
		// Выжимаем открытый ключ из концов всех цепочек
		::__nts_compress_wide__(setup, pkSeed, pkAdrs, view_t(values, (len * setup.security)), out);
		// Затираем значения концов цепочек
		sys::wipe(values, sizeof(values));
		// Затираем секретное значение цепочки
		sys::wipe(sk, sizeof(sk));
		// Затираем адрес секретного значения
		sys::wipe(skAdrs, sizeof(skAdrs));
		// Затираем адрес цепочки
		sys::wipe(chain, sizeof(chain));
		// Затираем адрес открытого ключа
		sys::wipe(pkAdrs, sizeof(pkAdrs));
	}
	/**
	 * @brief Функция выкладки сообщения и контрольной суммы полубайтами
	 *
	 * @param setup параметры набора (длина значения n задаёт число полубайтов)
	 * @param msg   сообщение, n байтов
	 * @param out   место полубайтов сообщения и контрольной суммы, 2n + 3 значений
	 *
	 */
	static __NTS_INLINE__ void __nts_wots_message__(const params_t & setup, const uint8_t * msg, uint8_t * out) noexcept {
		/**
		 * Сообщение раскладывается на 2n полубайтов, старший вперёд
		 */
		for(size_t i = 0; i < setup.security; i++){
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
		for(size_t i = 0; i < (2 * setup.security); i++)
			// Прибавляем очередной полубайт
			sum += out[i];
		// Вычитаем сумму из предела 15·2n
		sum = static_cast <uint16_t> ((15 * 2 * setup.security) - sum);
		// Старший полубайт суммы
		out[2 * setup.security] = static_cast <uint8_t> ((sum >> 8) & 0x0F);
		// Следующий полубайт суммы
		out[(2 * setup.security) + 1] = static_cast <uint8_t> ((sum >> 4) & 0x0F);
		// Младший полубайт суммы
		out[(2 * setup.security) + 2] = static_cast <uint8_t> (sum & 0x0F);
	}
	/**
	 * @brief Функция подписи WOTS+ (алгоритм 7 FIPS 205)
	 *
	 * @param setup  параметры набора (длина значения n задаёт длину подписи)
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования слоя, дерева и пары ключа
	 * @param out    место записи подписи, по n байтов на цепочку; возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static __NTS_INLINE__ uint8_t * __nts_wots_sign__(const params_t & setup, const uint8_t * msg, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Полубайты сообщения и контрольной суммы
		uint8_t nibbles[67];
		// Раскладываем сообщение на полубайты
		::__nts_wots_message__(setup, msg, nibbles);
		// Количество цепочек подписи
		const size_t len = ((2 * setup.security) + CHECKSUM);
		// Секретное значение цепочки
		uint8_t sk[MAX_N];
		// Адреса секретного значения и цепочки
		adrs_t skAdrs, chain;
		// Копируем исходный адрес
		::__nts_copy_adrs__(skAdrs, adrs);
		// Вид адреса секретного значения
		::__nts_set_type__(setup, skAdrs, 5);
		// Пара ключа в адресе значения
		::__nts_copy_keypair__(setup, skAdrs, adrs);
		/**
		 * Проходим по всем цепочкам подписи
		 */
		for(size_t i = 0; i < len; i++){
			// Адрес цепочки в адресе значения
			::__nts_set_chain__(setup, skAdrs, static_cast <uint32_t> (i));
			// Секрет цепочки из секретного зерна
			::__nts_prf__(setup, pkSeed, skSeed, skAdrs, sk);
			// Копируем исходный адрес
			::__nts_copy_adrs__(chain, adrs);
			// Адрес цепочки
			::__nts_set_chain__(setup, chain, static_cast <uint32_t> (i));
			// Подпись цепочки по количеству шагов полубайта
			::__nts_wots_chain__(setup, pkSeed, sk, 0, nibbles[i], chain, out);
			// Сдвигаем место записи на значение
			out += setup.security;
		}
		// Затираем полубайты сообщения
		sys::wipe(nibbles, sizeof(nibbles));
		// Затираем секретное значение цепочки
		sys::wipe(sk, sizeof(sk));
		// Затираем адрес секретного значения
		sys::wipe(skAdrs, sizeof(skAdrs));
		// Затираем адрес цепочки
		sys::wipe(chain, sizeof(chain));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Функция восстановления открытого ключа WOTS+ из подписи (алгоритм 8 FIPS 205)
	 *
	 * @param setup  параметры набора (длина значения n задаёт длину подписи)
	 * @param sig    подпись WOTS+, по n байтов на цепочку
	 * @param msg    сообщение, n байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования слоя, дерева и пары ключа
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 * @return       место за прочитанной подписью
	 *
	 */
	static __NTS_INLINE__ const uint8_t * __nts_wots_pk_from_sig__(const params_t & setup, const uint8_t * sig, const uint8_t * msg, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Адрес цепочки
		adrs_t chain;
		// Полубайты сообщения и контрольной суммы
		uint8_t nibbles[67];
		// Значения концов всех цепочек
		uint8_t values[MAX_N * 67];
		// Раскладываем сообщение на полубайты
		::__nts_wots_message__(setup, msg, nibbles);
		// Количество цепочек подписи
		const size_t len = ((2 * setup.security) + CHECKSUM);
		/**
		 * Проходим по всем цепочкам подписи
		 */
		for(size_t i = 0; i < len; i++){
			// Копируем исходный адрес
			::__nts_copy_adrs__(chain, adrs);
			// Адрес цепочки
			::__nts_set_chain__(setup, chain, static_cast <uint32_t> (i));
			// Конец цепочки доигрывается от значения подписи до верха
			::__nts_wots_chain__(setup, pkSeed, sig, nibbles[i], ((CHAIN - 1) - nibbles[i]), chain, (values + (i * setup.security)));
			// Сдвигаем чтение подписи на значение
			sig += setup.security;
		}
		// Адрес открытого ключа
		adrs_t pkAdrs;
		// Копируем исходный адрес
		::__nts_copy_adrs__(pkAdrs, adrs);
		// Вид адреса открытого ключа
		::__nts_set_type__(setup, pkAdrs, 1);
		// Пара ключа в адресе ключа
		::__nts_copy_keypair__(setup, pkAdrs, adrs);
		// Выжимаем открытый ключ из концов всех цепочек
		::__nts_compress_wide__(setup, pkSeed, pkAdrs, view_t(values, (len * setup.security)), out);
		// Затираем полубайты сообщения
		sys::wipe(nibbles, sizeof(nibbles));
		// Затираем значения концов цепочек
		sys::wipe(values, sizeof(values));
		// Затираем адрес цепочки
		sys::wipe(chain, sizeof(chain));
		// Затираем адрес открытого ключа
		sys::wipe(pkAdrs, sizeof(pkAdrs));
		// Выводим место за прочитанной подписью
		return sig;
	}
	/**
	 * @brief Функция вычисления узла дерева XMSS (алгоритм 9 FIPS 205)
	 *
	 * @param setup  параметры набора (высота дерева h′ и длина значения n)
	 * @param skSeed секретное зерно ключа
	 * @param node   индекс узла на своём уровне
	 * @param height высота узла
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования слоя и дерева
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_xmss_node__(const params_t & setup, const uint8_t * skSeed, const uint32_t node, const uint32_t height, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Лист дерева: открытый ключ WOTS+ пары под номером узла
		if(height == 0){
			// Вид адреса листа дерева
			::__nts_set_type__(setup, adrs, 0);
			// Пара ключа листа дерева
			::__nts_set_keypair__(setup, adrs, node);
			// Вырабатываем открытый ключ пары
			::__nts_wots_pk_gen__(setup, skSeed, pkSeed, adrs, out);
		// Узел выше листа: значение выжимается из пары детей
		} else {
			// Значения детей узла
			uint8_t left[MAX_N], right[MAX_N];
			// Адрес детей узла
			adrs_t children;
			// Копируем исходный адрес
			::__nts_copy_adrs__(children, adrs);
			// Вычисляем значение левого ребёнка
			::__nts_xmss_node__(setup, skSeed, (2 * node), (height - 1), pkSeed, children, left);
			// Копируем исходный адрес
			::__nts_copy_adrs__(children, adrs);
			// Вычисляем значение правого ребёнка
			::__nts_xmss_node__(setup, skSeed, ((2 * node) + 1), (height - 1), pkSeed, children, right);
			// Вид адреса узла дерева
			::__nts_set_type__(setup, adrs, 2);
			// Высота узла в адресе
			::__nts_set_chain__(setup, adrs, height);
			// Индекс узла в адресе
			::__nts_set_step__(setup, adrs, node);
			// Вырабатываем значение узла
			::__nts_compress_pair__(setup, pkSeed, adrs, left, right, out);
			// Затираем значение левого ребёнка
			sys::wipe(left, sizeof(left));
			// Затираем значение правого ребёнка
			sys::wipe(right, sizeof(right));
		}
	}
	/**
	 * @brief Функция подписи XMSS (алгоритм 10 FIPS 205)
	 *
	 * @param setup  параметры набора (высота дерева h′ задаёт путь подписи)
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param leaf   индекс пары ключа в дереве
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования слоя и дерева
	 * @param out    место записи подписи: WOTS+ и путь из h′ узлов; возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static __NTS_INLINE__ uint8_t * __nts_xmss_sign__(const params_t & setup, const uint8_t * msg, const uint8_t * skSeed, const uint32_t leaf, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Адрес подписи WOTS+
		adrs_t wots;
		// Копируем исходный адрес
		::__nts_copy_adrs__(wots, adrs);
		// Вид адреса подписи
		::__nts_set_type__(setup, wots, 0);
		// Пара ключа в адресе подписи
		::__nts_set_keypair__(setup, wots, leaf);
		// Подпись WOTS+ сообщения
		uint8_t * result = ::__nts_wots_sign__(setup, msg, skSeed, pkSeed, wots, out);
		// Путь из h′ узлов: брат узла на каждом уровне
		uint32_t node = leaf;
		/**
		 * Поднимаемся по уровням дерева
		 */
		for(uint32_t height = 0; height < setup.xmssHeight; height++){
			// Вырабатываем брата узла уровня
			::__nts_xmss_node__(setup, skSeed, (node ^ 1), height, pkSeed, adrs, result);
			// Сдвигаем место записи на значение
			result += setup.security;
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
	 * @param setup  параметры набора (высота дерева h′ задаёт путь подписи)
	 * @param sig    подпись XMSS: WOTS+ и путь из h′ узлов
	 * @param leaf   индекс пары ключа в дереве
	 * @param msg    сообщение, n байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования слоя и дерева
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 * @return       место за прочитанной подписью
	 *
	 */
	static __NTS_INLINE__ const uint8_t * __nts_xmss_pk_from_sig__(const params_t & setup, const uint8_t * sig, const uint32_t leaf, const uint8_t * msg, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Адрес подписи WOTS+
		adrs_t wots;
		// Адрес дерева
		adrs_t tree;
		// Начинаем путь с пары ключа
		uint32_t node = leaf;
		// Копируем исходный адрес
		::__nts_copy_adrs__(wots, adrs);
		// Вид адреса подписи
		::__nts_set_type__(setup, wots, 0);
		// Пара ключа в адресе подписи
		::__nts_set_keypair__(setup, wots, leaf);
		// Открытый ключ WOTS+ из подписи
		const uint8_t * result = ::__nts_wots_pk_from_sig__(setup, sig, msg, pkSeed, wots, out);
		// Копируем исходный адрес
		::__nts_copy_adrs__(tree, adrs);
		// Вид адреса узла дерева
		::__nts_set_type__(setup, tree, 2);
		/**
		 * Поднимаемся по уровням дерева
		 */
		for(uint32_t height = 0; height < setup.xmssHeight; height++){
			// Высота узла в адресе
			::__nts_set_chain__(setup, tree, (height + 1));
			// Узел складывается с братом пути по стороне индекса
			if((node & 1) == 0){
				// Поднимаемся к родителю узла
				node >>= 1;
				// Индекс родителя в адресе
				::__nts_set_step__(setup, tree, node);
				// Значение складывается с братом справа
				::__nts_compress_pair__(setup, pkSeed, tree, out, result, out);
			// Нечётный узел: брат пути лежит слева
			} else {
				// Поднимаемся к родителю узла
				node = (node - 1) >> 1;
				// Индекс родителя в адресе
				::__nts_set_step__(setup, tree, node);
				// Значение складывается с братом слева
				::__nts_compress_pair__(setup, pkSeed, tree, result, out, out);
			}
			// Сдвигаем чтение подписи на значение
			result += setup.security;
		}
		// Затираем адрес подписи
		sys::wipe(wots, sizeof(wots));
		// Затираем адрес дерева
		sys::wipe(tree, sizeof(tree));
		// Выводим место за прочитанной подписью
		return result;
	}
	/**
	 * @brief Функция секретного значения FORS (алгоритм 14 FIPS 205)
	 *
	 * @param setup  параметры набора (семейство хешей и длина значения n)
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования вида FORS_TREE с парой ключа
	 * @param id     индекс значения в лесу
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_fors_secret__(const params_t & setup, const uint8_t * skSeed, const uint8_t * pkSeed, const adrs_t adrs, const uint32_t id, uint8_t * out) noexcept {
		// Адрес секретного значения
		adrs_t skAdrs;
		// Копируем исходный адрес
		::__nts_copy_adrs__(skAdrs, adrs);
		// Вид адреса секретного значения
		::__nts_set_type__(setup, skAdrs, 6);
		// Пара ключа в адресе значения
		::__nts_copy_keypair__(setup, skAdrs, adrs);
		// Индекс значения в адресе
		::__nts_set_step__(setup, skAdrs, id);
		// Вырабатываем секретное значение
		::__nts_prf__(setup, pkSeed, skSeed, skAdrs, out);
		// Затираем адрес значения
		sys::wipe(skAdrs, sizeof(skAdrs));
	}
	/**
	 * @brief Функция вычисления узла дерева FORS (алгоритм 15 FIPS 205)
	 *
	 * @param setup  параметры набора (количество уровней a и длина значения n)
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования вида FORS_TREE с парой ключа
	 * @param node   индекс узла на своём уровне леса
	 * @param height высота узла
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_fors_node__(const params_t & setup, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, const uint32_t node, const uint32_t height, uint8_t * out) noexcept {
		// Лист дерева: значение выжимается из секретного значения
		if(height == 0){
			// Секретное значение листа
			uint8_t sk[MAX_N];
			// Вырабатываем секретное значение
			::__nts_fors_secret__(setup, skSeed, pkSeed, adrs, node, sk);
			// Высота листа в адресе
			::__nts_set_chain__(setup, adrs, 0);
			// Индекс листа в адресе
			::__nts_set_step__(setup, adrs, node);
			// Вырабатываем значение листа
			::__nts_compress_single__(setup, pkSeed, adrs, view_t(sk, setup.security), out);
			// Затираем секретное значение
			sys::wipe(sk, sizeof(sk));
		// Узел выше листа: значение выжимается из пары детей
		} else {
			// Адрес детей узла
			adrs_t children;
			// Значения детей узла
			uint8_t left[MAX_N], right[MAX_N];
			// Копируем исходный адрес
			::__nts_copy_adrs__(children, adrs);
			// Вычисляем значение левого ребёнка
			::__nts_fors_node__(setup, skSeed, pkSeed, children, (2 * node), (height - 1), left);
			// Копируем исходный адрес
			::__nts_copy_adrs__(children, adrs);
			// Вычисляем значение правого ребёнка
			::__nts_fors_node__(setup, skSeed, pkSeed, children, ((2 * node) + 1), (height - 1), right);
			// Высота узла в адресе
			::__nts_set_chain__(setup, adrs, height);
			// Индекс узла в адресе
			::__nts_set_step__(setup, adrs, node);
			// Вырабатываем значение узла
			::__nts_compress_pair__(setup, pkSeed, adrs, left, right, out);
			// Затираем значение левого ребёнка
			sys::wipe(left, sizeof(left));
			// Затираем значение правого ребёнка
			sys::wipe(right, sizeof(right));
		}
	}
	/**
	 * @brief Функция раскладки дайджеста по основанию 2^a (алгоритм 4 FIPS 205)
	 *
	 * @param in    дайджест, первые (k·a + 7) / 8 байтов
	 * @param width разрядность одного значения
	 * @param out   место count значений по width разрядов
	 * @param count количество значений
	 *
	 */
	static __NTS_INLINE__ void __nts_base2b__(const uint8_t * in, const uint32_t width, uint32_t * out, const size_t count) noexcept {
		// Набранные разряды и накопленное значение
		uint32_t bits = 0, total = 0;
		// Маска разрядов значения
		const uint32_t mask = ((1u << width) - 1);
		/**
		 * Раскладываем дайджест на count значений
		 */
		for(size_t i = 0; i < count; i++){
			/**
			 * Набираем разряды до полного значения
			 */
			while(bits < width){
				// Прибавляем очередной байт
				total <<= 8;
				// Считаем набранные разряды
				total += (* in++);
				// Отрезаем разряды значения
				bits += 8;
			}
			// Отрезаем разряды значения
			bits -= width;
			// Записываем очередное значение
			(* out++) = ((total >> bits) & mask);
		}
	}
	/**
	 * @brief Функция подписи FORS (алгоритм 16 FIPS 205)
	 *
	 * @param setup  параметры набора (число деревьев k и уровней a леса)
	 * @param digest дайджест, первые (k·a + 7) / 8 байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования вида FORS_TREE с парой ключа
	 * @param out    место записи подписи: k × (значение ‖ путь из a узлов); возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static __NTS_INLINE__ uint8_t * __nts_fors_sign__(const params_t & setup, const uint8_t * digest, const uint8_t * skSeed, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Смещение леса по уровням: каждое дерево занимает свою полосу индексов
		uint32_t forest = 0;
		// Значения листьев по k деревьям
		uint32_t ids[MAX_K];
		// Секретное значение листа
		uint8_t value[MAX_N];
		// Раскладываем дайджест на индексы листьев
		::__nts_base2b__(digest, setup.forsLevels, ids, setup.forsTrees);
		/**
		 * Проходим по всем деревьям леса
		 */
		for(size_t tree = 0; tree < setup.forsTrees; tree++){
			// Индекс листа дерева
			uint32_t node = ids[tree];
			// Секретное значение листа
			::__nts_fors_secret__(setup, skSeed, pkSeed, adrs, (node + forest), value);
			// Записываем секретное значение листа
			::memcpy(out, value, setup.security);
			// Сдвигаем место записи на значение
			out += setup.security;
			// Смещение дерева в лесу
			uint32_t offset = forest;
			/**
			 * Путь из a узлов: брат узла на каждом уровне
			 */
			for(uint32_t height = 0; height < setup.forsLevels; height++){
				// Вырабатываем брата узла уровня
				::__nts_fors_node__(setup, skSeed, pkSeed, adrs, ((node ^ 1) + offset), height, out);
				// Сдвигаем место записи на значение
				out += setup.security;
				// Поднимаемся к родителю узла
				node >>= 1;
				// Смещение поднимается вместе с нами
				offset >>= 1;
			}
			// Дерево занимает свою полосу леса
			forest += (1u << setup.forsLevels);
		}
		// Затираем секретное значение листа
		sys::wipe(value, sizeof(value));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Функция восстановления открытого ключа FORS из подписи (алгоритм 17 FIPS 205)
	 *
	 * @param setup  параметры набора (число деревьев k и уровней a леса)
	 * @param sig    подпись FORS: k × (значение ‖ путь из a узлов)
	 * @param digest дайджест, первые (k·a + 7) / 8 байтов
	 * @param pkSeed открытое зерно ключа
	 * @param adrs   адрес хеширования вида FORS_TREE с парой ключа
	 * @param out    место результата, n байтов; возвращается место за прочитанной подписью
	 * @return       место за прочитанной подписью
	 *
	 */
	static __NTS_INLINE__ const uint8_t * __nts_fors_pk_from_sig__(const params_t & setup, const uint8_t * sig, const uint8_t * digest, const uint8_t * pkSeed, adrs_t adrs, uint8_t * out) noexcept {
		// Смещение леса по деревьям
		uint32_t forest = 0;
		// Значения листьев по k деревьям
		uint32_t ids[MAX_K];
		// Корни всех деревьев леса
		uint8_t roots[MAX_K * MAX_N];
		// Раскладываем дайджест на индексы листьев
		::__nts_base2b__(digest, setup.forsLevels, ids, setup.forsTrees);
		/**
		 * Проходим по всем деревьям леса
		 */
		for(size_t tree = 0; tree < setup.forsTrees; tree++){
			// Индекс листа дерева
			uint32_t id = ids[tree];
			// Индекс листа в лесу
			uint32_t node = (id + forest);
			// Место корня дерева
			uint8_t * node0 = (roots + (tree * setup.security));
			// Высота листа в адресе
			::__nts_set_chain__(setup, adrs, 0);
			// Индекс листа в адресе
			::__nts_set_step__(setup, adrs, node);
			// Лист из значения подписи
			::__nts_compress_single__(setup, pkSeed, adrs, view_t(sig, setup.security), node0);
			// Сдвигаем чтение подписи на значение
			sig += setup.security;
			// Место очередного узла дерева
			uint8_t * node1 = node0;
			/**
			 * Поднимаемся по уровням дерева
			 */
			for(uint32_t height = 0; height < setup.forsLevels; height++){
				// Высота узла в адресе
				::__nts_set_chain__(setup, adrs, (height + 1));
				// Узел складывается с братом пути по стороне индекса
				if((id & 1) == 0){
					// Поднимаемся к родителю узла
					node >>= 1;
					// Индекс родителя в адресе
					::__nts_set_step__(setup, adrs, node);
					// Значение складывается с братом справа
					::__nts_compress_pair__(setup, pkSeed, adrs, node0, sig, node1);
				// Нечётный лист: брат пути лежит слева
				} else {
					// Поднимаемся к родителю листа
					node = (node - 1) >> 1;
					// Индекс родителя в адресе
					::__nts_set_step__(setup, adrs, node);
					// Значение складывается с братом слева
					::__nts_compress_pair__(setup, pkSeed, adrs, sig, node0, node1);
				}
				// Сдвигаем чтение подписи на значение
				sig += setup.security;
				// Индекс поднимается к корню дерева
				id >>= 1;
			}
			// Дерево занимает свою полосу леса
			forest += (1u << setup.forsLevels);
		}
		// Адрес открытого ключа
		adrs_t pkAdrs;
		// Копируем исходный адрес
		::__nts_copy_adrs__(pkAdrs, adrs);
		// Вид адреса открытого ключа
		::__nts_set_type__(setup, pkAdrs, 4);
		// Пара ключа в адресе ключа
		::__nts_copy_keypair__(setup, pkAdrs, adrs);
		// Выжимаем открытый ключ FORS из корней всех деревьев
		::__nts_compress_wide__(setup, pkSeed, pkAdrs, view_t(roots, (setup.forsTrees * setup.security)), out);
		// Затираем корни всех деревьев
		sys::wipe(roots, sizeof(roots));
		// Затираем адрес открытого ключа
		sys::wipe(pkAdrs, sizeof(pkAdrs));
		// Выводим место за прочитанной подписью
		return sig;
	}
	/**
	 * @brief Функция подписи гипердерева (алгоритм 12 FIPS 205)
	 *
	 * @param setup  параметры набора (количество слоёв d и высота дерева h′)
	 * @param msg    сообщение, n байтов
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param tree   индекс дерева нижнего слоя
	 * @param leaf   индекс пары ключа в дереве нижнего слоя
	 * @param out    место записи подписи: d подписей XMSS; возвращается за ним
	 * @return       место за записанной подписью
	 *
	 */
	static __NTS_INLINE__ uint8_t * __nts_ht_sign__(const params_t & setup, const uint8_t * msg, const uint8_t * skSeed, const uint8_t * pkSeed, uint64_t tree, uint32_t leaf, uint8_t * out) noexcept {
		// Адрес дерева слоя
		adrs_t adrs;
		// Обнуляем адрес
		::__nts_zero__(adrs);
		// Подписываемое слоем значение: сперва корень FORS
		uint8_t root[MAX_N];
		// Копируем сообщение в подписываемое значение
		::memcpy(root, msg, setup.security);
		// Маска пары ключа дерева слоя
		const uint32_t mask = ((1u << setup.xmssHeight) - 1);
		/**
		 * Проходим по всем слоям гипердерева
		 */
		for(uint32_t layer = 0; layer < setup.hypertrees; layer++){
			// Адрес слоя в адресе
			::__nts_set_layer__(setup, adrs, layer);
			// Адрес дерева в адресе
			::__nts_set_tree__(setup, adrs, tree);
			// Запоминаем начало подписи слоя
			uint8_t * layerSig = out;
			// Подписываем значение деревом слоя
			out = ::__nts_xmss_sign__(setup, root, skSeed, leaf, pkSeed, adrs, out);
			// Корень следующего слоя - открытый ключ только что подписанного дерева
			if(layer < (static_cast <uint32_t> (setup.hypertrees) - 1)){
				// Восстанавливаем корень подписанного дерева
				std::ignore = ::__nts_xmss_pk_from_sig__(setup, layerSig, leaf, root, pkSeed, adrs, root);
				// Пара следующего слоя из дерева
				leaf = (tree & mask);
				// Дерево поднимается на слой выше
				tree >>= setup.xmssHeight;
			}
		}
		// Затираем подписываемое значение
		sys::wipe(root, sizeof(root));
		// Затираем адрес дерева
		sys::wipe(adrs, sizeof(adrs));
		// Выводим место за подписью
		return out;
	}
	/**
	 * @brief Функция проверки подписи гипердерева (алгоритм 13 FIPS 205)
	 *
	 * @param setup  параметры набора (количество слоёв d и высота дерева h′)
	 * @param msg    сообщение, n байтов
	 * @param sig    подпись гипердерева: d подписей XMSS
	 * @param pkSeed открытое зерно ключа
	 * @param tree   индекс дерева нижнего слоя
	 * @param leaf   индекс пары ключа в дереве нижнего слоя
	 * @param pkRoot корень ключа проверки
	 * @return       признак того, что гипердерево сошлось с корнем
	 *
	 */
	static __NTS_INLINE__ bool __nts_ht_verify__(const params_t & setup, const uint8_t * msg, const uint8_t * sig, const uint8_t * pkSeed, uint64_t tree, uint32_t leaf, const uint8_t * pkRoot) noexcept {
		// Адрес дерева слоя
		adrs_t adrs;
		// Обнуляем адрес
		::__nts_zero__(adrs);
		// Проверяемое слоем значение: сперва корень FORS
		uint8_t node[MAX_N];
		// Копируем сообщение в проверяемое значение
		::memcpy(node, msg, setup.security);
		// Маска пары ключа дерева слоя
		const uint32_t mask = ((1u << setup.xmssHeight) - 1);
		/**
		 * Проходим по всем слоям гипердерева
		 */
		for(uint32_t layer = 0; layer < setup.hypertrees; layer++){
			// Адрес слоя в адресе
			::__nts_set_layer__(setup, adrs, layer);
			// Адрес дерева в адресе
			::__nts_set_tree__(setup, adrs, tree);
			// Восстанавливаем корень дерева слоя
			sig = ::__nts_xmss_pk_from_sig__(setup, sig, leaf, node, pkSeed, adrs, node);
			// Пара следующего слоя из дерева
			leaf = (tree & mask);
			// Дерево поднимается на слой выше
			tree >>= setup.xmssHeight;
		}
		// Сверху дерева обязан лежать корень ключа проверки
		const bool result = (::memcmp(node, pkRoot, setup.security) == 0);
		// Затираем проверяемое значение
		sys::wipe(node, sizeof(node));
		// Затираем адрес дерева
		sys::wipe(adrs, sizeof(adrs));
		// Выводим признак схождения
		return result;
	}
	/**
	 * @brief Функция получения целого из байтов старшим байтом вперёд
	 *
	 * @param in   байты числа старшим байтом вперёд
	 * @param size количество байтов числа
	 * @return     целое число
	 *
	 */
	static __NTS_INLINE__ uint64_t __nts_bytes_to_int__(const uint8_t * in, const size_t size) noexcept {
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
	 * @param setup  параметры набора (номер верхнего слоя и высота дерева h′)
	 * @param skSeed секретное зерно ключа
	 * @param pkSeed открытое зерно ключа
	 * @param out    место результата, n байтов
	 *
	 */
	static __NTS_INLINE__ void __nts_pk_root__(const params_t & setup, const uint8_t * skSeed, const uint8_t * pkSeed, uint8_t * out) noexcept {
		// Адрес дерева верхнего слоя
		adrs_t adrs;
		// Обнуляем адрес
		::__nts_zero__(adrs);
		// Адрес верхнего слоя
		::__nts_set_layer__(setup, adrs, (setup.hypertrees - 1));
		// Вырабатываем корень вершиной дерева
		::__nts_xmss_node__(setup, skSeed, 0, setup.xmssHeight, pkSeed, adrs, out);
		// Затираем адрес
		sys::wipe(adrs, sizeof(adrs));
	}
	/**
	 * @brief Функция порождения ключа из зерна (раздел 10.1 FIPS 205)
	 *
	 * @param setup  параметры набора (длина значения n задаёт размеры ключей)
	 * @param seed   зерно: SK.seed ‖ SK.prf ‖ PK.seed (3n байтов)
	 * @param key    место ключа проверки: PK.seed ‖ PK.root (2n байтов)
	 * @param secret место ключа подписи: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root (4n байтов)
	 *
	 */
	static __NTS_INLINE__ void __nts_keygen__(const params_t & setup, const uint8_t * seed, uint8_t * key, uint8_t * secret) noexcept {
		// Запись ключа подписи: зерно целиком в первые три значения
		::memcpy(secret, seed, (3 * setup.security));
		// Корень ключа вычисляется вершиной дерева верхнего слоя
		::__nts_pk_root__(setup, (secret), (secret + (2 * setup.security)), (secret + (3 * setup.security)));
		// Ключ проверки: PK.seed ‖ PK.root
		::memcpy(key, (secret + (2 * setup.security)), (2 * setup.security));
	}
	/**
	 * @brief Функция выработки подписи (раздел 10.2 FIPS 205)
	 *
	 * @param setup   параметры набора (слой гипердерева, лес FORS и длины значений)
	 * @param secret  запись ключа подписи
	 * @param rnd     случайность подписи, 32 байта (нули дают детерминированный вариант)
	 * @param message подписываемое сообщение
	 * @param context контекст подписи
	 * @param result  место записи подписи: R ‖ FORS ‖ HT
	 *
	 */
	static __NTS_INLINE__ void __nts_signing__(const params_t & setup, const uint8_t * secret, const uint8_t * rnd, const view_t & message, const view_t & context, uint8_t * result) noexcept {
		// Накопитель отличия случайности от нулей
		uint32_t noisy = 0;
		// Секретное зерно ключа
		const uint8_t * skSeed = secret;
		// Секретный ключ случайности
		const uint8_t * skPrf = (secret + setup.security);
		// Открытое зерно ключа
		const uint8_t * pkSeed = (secret + (2 * setup.security));
		// Корень ключа проверки
		const uint8_t * pkRoot = (secret + (3 * setup.security));
		/**
		 * Сличаем случайность подписи с нулями
		 */
		for(size_t i = 0; i < 32; i++)
			// Прибавляем очередной байт
			noisy |= rnd[i];
		// Нули заменяются открытым зерном ключа
		const uint8_t * optRand = ((noisy == 0) ? pkSeed : rnd);
		// Сообщение с обвязкой: 0x00 ‖ длина контекста ‖ контекст ‖ сообщение
		uint8_t randomness[MAX_N], messageDigest[MAX_M];
		// Случайность подписи R = PRFmsg(SK.prf, opt_rand, обвязанное сообщение)
		{
			// Губка выработки случайности
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Ветвь выработки семейства SHAKE
			if(setup.family == FAMILY_SHAKE){
				// Подаём секретный ключ случайности
				xof.update(view_t(skPrf, setup.security));
				// Подаём случайность выработки
				xof.update(view_t(optRand, setup.security));
				// Префикс: ноль и длина контекста
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				// Подаём префикс обвязки
				xof.update(view_t(prefix, sizeof(prefix)));
				// Подаём контекст
				xof.update(context);
				// Подаём сообщение
				xof.update(message);
				// Выжимаем случайность нужной длины
				std::ignore = xof.squeeze(randomness, setup.security);
			// У семейства SHA2 случайность вырабатывается кодом HMAC
			} else {
				// Объект кода HMAC
				digest::mac_t hmac;
				// Полный код HMAC выработки случайности
				uint8_t full[64];
				// Длина кода семейства: 64 у категорий 3 и 5, 32 у категории 1
				const size_t length = ((setup.family == FAMILY_SHA2_35) ? 64 : 32);
				// Начинаем код с секретным ключом
				if(hmac.start(((setup.family == FAMILY_SHA2_35) ? digest::hash_t::SHA512 : digest::hash_t::SHA256), view_t(skPrf, setup.security))){
					// Подаём случайность выработки
					hmac.update(view_t(optRand, setup.security));
					// Префикс: ноль и длина контекста
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					// Подаём префикс обвязки
					hmac.update(view_t(prefix, sizeof(prefix)));
					// Подаём контекст
					hmac.update(context);
					// Подаём сообщение
					hmac.update(message);
					// Доводим код до конца
					if(hmac.finish(full, length))
						// Переносим случайность из кода
						::memcpy(randomness, full, setup.security);
					// Затираем полное значение хеша
					sys::wipe(full, sizeof(full));
				}
			}
		}
		// Дайджест подписываемого сообщения длиной m байтов: Hmsg(R ‖ PK.seed ‖ PK.root ‖ обвязанное сообщение)
		{
			// Ветвь выработки семейства SHAKE
			if(setup.family == FAMILY_SHAKE){
				// Губка выработки дайджеста
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				// Подаём случайность подписи
				xof.update(view_t(randomness, setup.security));
				// Подаём открытое зерно ключа
				xof.update(view_t(pkSeed, setup.security));
				// Подаём корень ключа проверки
				xof.update(view_t(pkRoot, setup.security));
				// Префикс: ноль и длина контекста
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				// Подаём префикс обвязки
				xof.update(view_t(prefix, sizeof(prefix)));
				// Подаём контекст
				xof.update(context);
				// Подаём сообщение
				xof.update(message);
				// Выжимаем дайджест нужной длины
				std::ignore = xof.squeeze(messageDigest, setup.message);
			// У семейства SHA2 дайджест вырабатывается из зерна порождения
			} else {
				// Зерно порождения: случайность ‖ открытое зерно ‖ хеш обвязанного сообщения
				uint8_t seed[(2 * MAX_N) + 64];
				// Длина хеша семейства: 64 у категорий 3 и 5, 32 у категории 1
				const size_t length = ((setup.family == FAMILY_SHA2_35) ? 64 : 32);
				// Переносим случайность в зерно
				::memcpy(seed, randomness, setup.security);
				// Переносим открытое зерно в зерно
				::memcpy((seed + setup.security), pkSeed, setup.security);
				{
					// Хеш сжатия зерна порождения
					digest::sha2_t sha(((setup.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256));
					// Подаём случайность подписи
					sha.update(view_t(randomness, setup.security));
					// Подаём открытое зерно ключа
					sha.update(view_t(pkSeed, setup.security));
					// Подаём корень ключа проверки
					sha.update(view_t(pkRoot, setup.security));
					// Префикс: ноль и длина контекста
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					// Подаём префикс обвязки
					sha.update(view_t(prefix, sizeof(prefix)));
					// Подаём контекст
					sha.update(context);
					// Подаём сообщение
					sha.update(message);
					// Сжимаем обвязанное сообщение в зерно
					std::ignore = sha.finish((seed + (2 * setup.security)), length);
				}
				// Порождаем дайджест из зерна
				::__nts_mgf1__(((setup.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256), view_t(seed, ((2 * setup.security) + length)), messageDigest, setup.message);
				// Затираем зерно порождения
				sys::wipe(seed, sizeof(seed));
			}
		}
		// Дайджест раскладывается на часть FORS, индекс дерева и индекс пары ключа
		const size_t mdLen = (((static_cast <size_t> (setup.forsTrees) * setup.forsLevels) + 7) >> 3);
		// Длина индекса дерева в байтах
		const size_t treeLen = (((static_cast <size_t> (setup.hypertrees) * setup.xmssHeight - setup.xmssHeight) + 7) >> 3);
		// Длина индекса пары в байтах
		const size_t leafLen = ((setup.xmssHeight + 7) >> 3);
		// Индекс дерева из дайджеста
		const uint64_t tree = (::__nts_bytes_to_int__((messageDigest + mdLen), treeLen) & ((~static_cast <uint64_t> (0)) >> (64 - ((setup.hypertrees * setup.xmssHeight) - setup.xmssHeight))));
		// Индекс пары ключа из дайджеста
		const uint32_t leaf = static_cast <uint32_t> (::__nts_bytes_to_int__((messageDigest + mdLen + treeLen), leafLen) & ((static_cast <uint64_t> (1) << setup.xmssHeight) - 1));
		// Запись подписи: R ‖ FORS ‖ HT
		uint8_t * out = result;
		// Записываем случайность подписи
		::memcpy(out, randomness, setup.security);
		// Сдвигаем место записи на значение
		out += setup.security;
		// Адрес дерева подписи
		adrs_t adrs;
		// Обнуляем адрес
		::__nts_zero__(adrs);
		// Адрес дерева в адресе
		::__nts_set_tree__(setup, adrs, tree);
		// Вид адреса дерева подписи
		::__nts_set_type__(setup, adrs, 3);
		// Пара ключа в адресе
		::__nts_set_keypair__(setup, adrs, leaf);
		// Запоминаем начало подписи FORS
		uint8_t * fors = out;
		// Подписываем дайджест лесом FORS
		out = ::__nts_fors_sign__(setup, messageDigest, skSeed, pkSeed, adrs, out);
		// Корень FORS из только что выработанной подписи
		uint8_t pkFors[MAX_N];
		// Восстанавливаем корень FORS из подписи
		std::ignore = ::__nts_fors_pk_from_sig__(setup, fors, messageDigest, pkSeed, adrs, pkFors);
		// Подписываем корень FORS гипердеревом
		std::ignore = ::__nts_ht_sign__(setup, pkFors, skSeed, pkSeed, tree, leaf, out);
		// Затираем случайность подписи
		sys::wipe(randomness, sizeof(randomness));
		// Затираем дайджест сообщения
		sys::wipe(messageDigest, sizeof(messageDigest));
		// Затираем корень FORS
		sys::wipe(pkFors, sizeof(pkFors));
		// Затираем адрес дерева
		sys::wipe(adrs, sizeof(adrs));
	}
	/**
	 * @brief Функция проверки подписи (раздел 10.3 FIPS 205)
	 *
	 * @param setup     параметры набора (слой гипердерева, лес FORS и длины значений)
	 * @param key       запись ключа проверки: PK.seed ‖ PK.root
	 * @param message   подписанное сообщение
	 * @param context   контекст подписи
	 * @param signature проверяемая подпись: R ‖ FORS ‖ HT
	 * @return          признак того, что подпись сошлась
	 *
	 */
	static __NTS_INLINE__ bool __nts_checking__(const params_t & setup, const uint8_t * key, const view_t & message, const view_t & context, const uint8_t * signature) noexcept {
		// Открытое зерно ключа
		const uint8_t * pkSeed = key;
		// Корень ключа проверки
		const uint8_t * pkRoot = (key + setup.security);
		// Случайность подписи
		const uint8_t * cursor = signature;
		// Дайджест подписываемого сообщения длиной m байтов: Hmsg(R ‖ PK.seed ‖ PK.root ‖ обвязанное сообщение)
		uint8_t messageDigest[MAX_M];
		{
			// Ветвь выработки семейства SHAKE
			if(setup.family == FAMILY_SHAKE){
				// Губка выработки дайджеста
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				// Подаём случайность подписи
				xof.update(view_t(cursor, setup.security));
				// Подаём открытое зерно ключа
				xof.update(view_t(pkSeed, setup.security));
				// Подаём корень ключа проверки
				xof.update(view_t(pkRoot, setup.security));
				// Префикс: ноль и длина контекста
				const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
				// Подаём префикс обвязки
				xof.update(view_t(prefix, sizeof(prefix)));
				// Подаём контекст
				xof.update(context);
				// Подаём сообщение
				xof.update(message);
				// Выжимаем дайджест нужной длины
				std::ignore = xof.squeeze(messageDigest, setup.message);
			// У семейства SHA2 дайджест вырабатывается из зерна порождения
			} else {
				// Зерно порождения: случайность ‖ открытое зерно ‖ хеш обвязанного сообщения
				uint8_t seed[(2 * MAX_N) + 64];
				// Длина хеша семейства: 64 у категорий 3 и 5, 32 у категории 1
				const size_t length = ((setup.family == FAMILY_SHA2_35) ? 64 : 32);
				// Переносим случайность в зерно
				::memcpy(seed, cursor, setup.security);
				// Переносим открытое зерно в зерно
				::memcpy((seed + setup.security), pkSeed, setup.security);
				{
					// Хеш сжатия зерна порождения
					digest::sha2_t sha(((setup.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256));
					// Подаём случайность подписи
					sha.update(view_t(cursor, setup.security));
					// Подаём открытое зерно ключа
					sha.update(view_t(pkSeed, setup.security));
					// Подаём корень ключа проверки
					sha.update(view_t(pkRoot, setup.security));
					// Префикс: ноль и длина контекста
					const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
					// Подаём префикс обвязки
					sha.update(view_t(prefix, sizeof(prefix)));
					// Подаём контекст
					sha.update(context);
					// Подаём сообщение
					sha.update(message);
					// Сжимаем обвязанное сообщение в зерно
					std::ignore = sha.finish((seed + (2 * setup.security)), length);
				}
				// Порождаем дайджест из зерна
				::__nts_mgf1__(((setup.family == FAMILY_SHA2_35) ? digest::sha_t::SHA512 : digest::sha_t::SHA256), view_t(seed, ((2 * setup.security) + length)), messageDigest, setup.message);
				// Затираем зерно порождения
				sys::wipe(seed, sizeof(seed));
			}
		}
		// Дайджест раскладывается на часть FORS, индекс дерева и индекс пары ключа
		const size_t mdLen = (((static_cast <size_t> (setup.forsTrees) * setup.forsLevels) + 7) >> 3);
		// Длина индекса дерева в байтах
		const size_t treeLen = (((static_cast <size_t> (setup.hypertrees) * setup.xmssHeight - setup.xmssHeight) + 7) >> 3);
		// Длина индекса пары в байтах
		const size_t leafLen = ((setup.xmssHeight + 7) >> 3);
		// Индекс дерева из дайджеста
		const uint64_t tree = (::__nts_bytes_to_int__((messageDigest + mdLen), treeLen) & ((~static_cast <uint64_t> (0)) >> (64 - ((setup.hypertrees * setup.xmssHeight) - setup.xmssHeight))));
		// Индекс пары ключа из дайджеста
		const uint32_t leaf = static_cast <uint32_t> (::__nts_bytes_to_int__((messageDigest + mdLen + treeLen), leafLen) & ((static_cast <uint64_t> (1) << setup.xmssHeight) - 1));
		// Адрес дерева подписи
		adrs_t adrs;
		// Обнуляем адрес
		::__nts_zero__(adrs);
		// Адрес дерева в адресе
		::__nts_set_tree__(setup, adrs, tree);
		// Вид адреса дерева подписи
		::__nts_set_type__(setup, adrs, 3);
		// Пара ключа в адресе
		::__nts_set_keypair__(setup, adrs, leaf);
		// Подпись за случайностью
		const uint8_t * sig = (signature + setup.security);
		// Корень FORS из подписи
		uint8_t pkFors[MAX_N];
		// Восстанавливаем корень FORS из подписи
		sig = ::__nts_fors_pk_from_sig__(setup, sig, messageDigest, pkSeed, adrs, pkFors);
		// Гипердерево обязано сойтись с корнем ключа проверки
		const bool result = ::__nts_ht_verify__(setup, pkFors, sig, pkSeed, tree, leaf, pkRoot);
		// Затираем дайджест сообщения
		sys::wipe(messageDigest, sizeof(messageDigest));
		// Затираем корень FORS
		sys::wipe(pkFors, sizeof(pkFors));
		// Затираем адрес дерева
		sys::wipe(adrs, sizeof(adrs));
		// Выводим признак схождения
		return result;
	}
	/**
	 * @brief Функция проверки подлинности записи ключа подписи
	 *
	 * @param setup  параметры набора (длина значения n задаёт разметку записи)
	 * @param secret запись ключа подписи
	 * @return       признак того, что корень записи сходится с пересчитанным из зерна
	 *
	 */
	static __NTS_INLINE__ bool __nts_consistent__(const params_t & setup, const uint8_t * secret) noexcept {
		// Корень, пересчитанный из зерна записи
		uint8_t root[MAX_N];
		// Пересчитываем корень из зерна записи
		::__nts_pk_root__(setup, secret, (secret + (2 * setup.security)), root);
		// Сличаем корень с записанным в записи
		const bool result = (::memcmp(root, (secret + (3 * setup.security)), setup.security) == 0);
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
sign::SLH_DSA::set_t sign::SLH_DSA::set() const noexcept {
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
size_t sign::SLH_DSA::size() const noexcept {
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
size_t sign::SLH_DSA::limit() const noexcept {
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
void sign::SLH_DSA::clear() noexcept {
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
size_t sign::SLH_DSA::seedSize(const set_t set) noexcept {
	// Размер зерна порождения: три значения по n байтов
	return (3 * ::__nts_params__(set).security);
}
/**
 * @brief Метод получения размера ключа подписи набора в байтах
 *
 * @param set набор параметров
 * @return    размер ключа подписи в байтах (4n), ноль у несуществующего набора
 *
 */
size_t sign::SLH_DSA::secretSize(const set_t set) noexcept {
	// Размер ключа подписи: четыре значения по n байтов
	return (4 * ::__nts_params__(set).security);
}
/**
 * @brief Метод получения размера ключа проверки набора в байтах
 *
 * @param set набор параметров
 * @return    размер ключа проверки в байтах (2n), ноль у несуществующего набора
 *
 */
size_t sign::SLH_DSA::publicSize(const set_t set) noexcept {
	// Размер ключа проверки: два значения по n байтов
	return (2 * ::__nts_params__(set).security);
}
/**
 * @brief Метод получения размера подписи набора в байтах
 *
 * @param set набор параметров
 * @return    размер подписи в байтах, ноль у несуществующего набора
 *
 */
size_t sign::SLH_DSA::signatureSize(const set_t set) noexcept {
	// Размер подписи набора из таблицы параметров
	return ::__nts_params__(set).signature;
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
bool sign::SLH_DSA::generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Получаем параметры набора
	const params_t setup = ::__nts_params__(set);
	// Набор существует и зерно верной длины
	if((setup.security != 0) && (seed.size == (3 * setup.security))){
		// Порождаем ключ из зерна
		::__nts_keygen__(setup, static_cast <const uint8_t *> (seed.data), key, secret);
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
bool sign::SLH_DSA::generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Получаем параметры набора
	const params_t setup = ::__nts_params__(set);
	// Набор параметров существует
	if(setup.security != 0){
		// Зерно порождения из источника случайности
		uint8_t seed[3 * MAX_N];
		// Зерно порождается источником случайности
		if(entropy::bytes(seed, (3 * setup.security))){
			// Порождаем ключ из зерна
			::__nts_keygen__(setup, seed, key, secret);
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
bool sign::SLH_DSA::secret(const set_t set, const view_t & secret) noexcept {
	// Результат работы
	bool result = false;
	// Получаем параметры набора
	const params_t setup = ::__nts_params__(set);
	// Набор существует и запись верной длины
	if((setup.security != 0) && (secret.size == (4 * setup.security))){
		// Подлинность записи проверяется пересчётом корня из зерна записи
		if(::__nts_consistent__(setup, static_cast <const uint8_t *> (secret.data))){
			// Запоминаем запись ключа подписи
			::memcpy(this->_key, secret.data, (4 * setup.security));
			// Запоминаем запись ключа проверки
			::memcpy(this->_pkey, (static_cast <const uint8_t *> (secret.data) + (2 * setup.security)), (2 * setup.security));
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
bool sign::SLH_DSA::key(const set_t set, const view_t & key) noexcept {
	// Результат работы
	bool result = false;
	// Получаем параметры набора
	const params_t setup = ::__nts_params__(set);
	// Набор существует и запись верной длины
	if((setup.security != 0) && (key.size == (2 * setup.security))){
		// Если ключ подписи установлен, поданный обязан совпасть с записанным
		if(this->_secret && (this->_set == set)){
			// Сравниваем поданный ключ с записанным в секретный
			if(::memcmp(this->_pkey, key.data, (2 * setup.security)) == 0)
				// Поданный ключ совпал с записанным
				result = true;
		// Ключ подписи не установлен либо набор другой: устанавливаем поданный ключ
		} else {
			// Запоминаем поданный ключ проверки
			::memcpy(this->_pkey, key.data, (2 * setup.security));
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
bool sign::SLH_DSA::key(uint8_t * result, const size_t size) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ проверки установлен и места хватает
	if((outcome = (this->_public && (size >= (2 * ::__nts_params__(this->_set).security)))))
		// Выводим ключ проверки
		::memcpy(result, this->_pkey, (2 * ::__nts_params__(this->_set).security));
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
bool sign::SLH_DSA::make(const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен и контекст в пределе
	if(this->_secret && (context.size < 256)){
		// Случайность подписи из источника
		uint8_t rnd[32];
		// Случайность порождается источником
		if((outcome = entropy::bytes(rnd, sizeof(rnd))))
			// Вырабатываем подпись
			::__nts_signing__(::__nts_params__(this->_set), this->_key, rnd, message, context, result);
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
bool sign::SLH_DSA::make(const view_t & rnd, const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен, случайность верной длины и контекст в пределе
	if((outcome = (this->_secret && (rnd.size == 32) && (context.size < 256))))
		// Вырабатываем подпись
		::__nts_signing__(::__nts_params__(this->_set), this->_key, static_cast <const uint8_t *> (rnd.data), message, context, result);
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
bool sign::SLH_DSA::check(const view_t & message, const view_t & context, const view_t & signature) const noexcept {
	// Результат работы
	bool result = false;
	// Получаем параметры набора
	const params_t setup = ::__nts_params__(this->_set);
	// Ключ проверки установлен и запись верной длины
	if(this->_public && (signature.size == setup.signature) && (context.size < 256))
		// Проверяем подпись
		result = ::__nts_checking__(setup, this->_pkey, message, context, static_cast <const uint8_t *> (signature.data));
	// Выводим признак схождения
	return result;
}
/**
 * @brief Конструктор
 *
 */
sign::SLH_DSA::SLH_DSA() noexcept :
 _set(set_t::NONE), _secret(false), _public(false) {
	// Обнуляем запись ключа подписи
	::memset(this->_key, 0, sizeof(this->_key));
	// Обнуляем запись ключа проверки
	::memset(this->_pkey, 0, sizeof(this->_pkey));
}
/**
 * @brief Деструктор
 *
 */
sign::SLH_DSA::~SLH_DSA() noexcept {
	// Затираем запись ключа подписи
	sys::wipe(this->_key, sizeof(this->_key));
	// Затираем запись ключа проверки
	sys::wipe(this->_pkey, sizeof(this->_pkey));
}
