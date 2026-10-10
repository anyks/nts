/**
 * @file umac.hpp
 * @date 2026-10-10
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
 * @brief Модуль имитовставки UMAC (RFC 4418) с итогом в 64 и 128 разрядов
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модулей хеширования
	 *
	 * \~english
	 * @brief Namespace of the hashing modules
	 *
	 * \~
	 */
	namespace digest {
		/**
		 * \~russian
		 * @brief Длина ключа UMAC в байтах
		 *
		 * \~english
		 * @brief Length of the UMAC key in bytes
		 *
		 * \~
		 */
		static constexpr size_t UMAC_KEY = 16;
		/**
		 * \~russian
		 * @brief Длина итога UMAC-64 в байтах
		 *
		 * \~english
		 * @brief Length of the UMAC-64 result in bytes
		 *
		 * \~
		 */
		static constexpr size_t UMAC_64 = 8;
		/**
		 * \~russian
		 * @brief Длина итога UMAC-128 в байтах
		 *
		 * \~english
		 * @brief Length of the UMAC-128 result in bytes
		 *
		 * \~
		 */
		static constexpr size_t UMAC_128 = 16;
		/**
		 * \~russian
		 * @brief Метод вычисления имитовставки UMAC
		 *
		 * @details Имитовставка считается по RFC 4418: универсальное хеширование UHASH
		 *          (слои NH, POLY и L3) поверх ключа, выводимого из ключа связи блочным
		 *          шифром AES, и наложение псевдослучайной подложки от одноразового числа.
		 *          Назначение - метки целостности сообщений (umac-64@openssh.com,
		 *          umac-128@openssh.com у SSH), не замена HMAC на общий случай
		 *
		 * @param key    ключ в шестнадцать байтов
		 * @param nonce  одноразовое число (от одного до шестнадцати байтов)
		 * @param data   сообщение любой длины
		 * @param result место, в которое помещается итог
		 * @param size   длина итога: 8 (UMAC-64) или 16 (UMAC-128)
		 *
		 * @return       признак того, что итог вычислен
		 *
		 * \~english
		 * @brief Method of the computation of the UMAC message authentication code
		 *
		 * @details The code is computed by RFC 4418: the UHASH universal hashing (the
		 *          NH, POLY and L3 layers) over the key derived from the connection key
		 *          by the AES block cipher, and the application of the pseudo-random pad
		 *          from the nonce. The purpose is the message authenticity tags
		 *          (umac-64@openssh.com, umac-128@openssh.com of SSH), not a replacement
		 *          of HMAC for the general case
		 *
		 * @param key    key of sixteen bytes
		 * @param nonce  nonce (from one to sixteen bytes)
		 * @param data   message of any length
		 * @param result place into which the result is put
		 * @param size   length of the result: 8 (UMAC-64) or 16 (UMAC-128)
		 *
		 * @return       sign that the result is computed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool umac(const view_t & key, const view_t & nonce, const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};
