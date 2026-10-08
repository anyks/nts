/**
 * @file cshake.hpp
 * @date 2026-10-05
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
 * \~russian
 * @brief Заголовочный файл модуля настраиваемых функций переменного выхода cSHAKE
 *        и имитовставок KMAC по SP 800-185
 *
 * \~english
 * @brief Header file of the module of the customizable extendable-output functions
 *        cSHAKE and the message authentication codes KMAC by SP 800-185
 *
 * \~
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
#include <digest/sha3.hpp>

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
		 * @brief Метод вычисления cSHAKE за один вызов
		 *
		 * @param type   разновидность функции: SHAKE128 либо SHAKE256
		 * @param data   сообщение
		 * @param name   имя функции N; пустое вместе с пустой настройкой даёт ровно SHAKE
		 * @param custom настройка S, задаваемая потребителем
		 * @param result место, в которое помещается итог
		 * @param size   длина итога в байтах
		 *
		 * @return       признак того, что итог вычислен
		 *
		 * @details Раздел 3 SP 800-185: при непустом имени либо настройке сообщению
		 *          предшествует запись bytepad(encode_string(N) ‖ encode_string(S), rate),
		 *          а дополнение идёт байтом 0x04 вместо 0x1F; при обоих пустых функция
		 *          есть ровно SHAKE той же разновидности
		 *
		 * \~english
		 * @brief Method of the computation of cSHAKE by one call
		 * @param type   kind of the function: SHAKE128 or SHAKE256
		 * @param data   message
		 * @param name   the function name N; empty together with an empty customization gives exactly SHAKE
		 * @param custom the customization S appointed by the consumer
		 * @param result place into which the result is put
		 * @param size   length of the result in bytes
		 * @return       sign that the result is computed
		 * @details The section 3 of SP 800-185: at a non-empty name or customization the message
		 *          is preceded by the record bytepad(encode_string(N) ‖ encode_string(S), rate),
		 *          and the padding goes by the byte 0x04 instead of 0x1F; at both empty the
		 *          function is exactly SHAKE of the same kind
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool cshake(const sha3_t type, const view_t & data, const view_t & name, const view_t & custom, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод вычисления имитовставки KMAC за один вызов
		 *
		 * @param type   разновидность функции: SHAKE128 либо SHAKE256
		 * @param key    ключ имитовставки
		 * @param data   сообщение
		 * @param custom настройка S, задаваемая потребителем
		 * @param result место, в которое помещается имитовставка
		 * @param size   длина имитовставки в байтах
		 *
		 * @return       признак того, что имитовставка вычислена
		 *
		 * @details Раздел 4 SP 800-185: KMAC есть cSHAKE с именем «KMAC» от сообщения
		 *          bytepad(encode_string(K), rate) ‖ X ‖ right_encode(L), где L - длина
		 *          имитовставки в разрядах
		 *
		 * \~english
		 * @brief Method of the computation of the message authentication code KMAC by one call
		 * @param type   kind of the function: SHAKE128 or SHAKE256
		 * @param key    the key of the message authentication code
		 * @param data   message
		 * @param custom the customization S appointed by the consumer
		 * @param result place into which the message authentication code is put
		 * @param size   length of the message authentication code in bytes
		 * @return       sign that the message authentication code is computed
		 * @details The section 4 of SP 800-185: KMAC is cSHAKE with the name «KMAC» of the
		 *          message bytepad(encode_string(K), rate) ‖ X ‖ right_encode(L), where L is
		 *          the length of the code in bits
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool kmac(const sha3_t type, const view_t & key, const view_t & data, const view_t & custom, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод вычисления имитовставки KMAC переменной длины за один вызов
		 *
		 * @param type   разновидность функции: SHAKE128 либо SHAKE256
		 * @param key    ключ имитовставки
		 * @param data   сообщение
		 * @param custom настройка S, задаваемая потребителем
		 * @param result место, в которое помещается имитовставка
		 * @param size   длина имитовставки в байтах
		 *
		 * @return       признак того, что имитовставка вычислена
		 *
		 * @details Раздел 4 SP 800-185: KMACXOF отличается от KMAC записью right_encode(0)
		 *          на месте длины итога, и итоги разной длины у него совпадают в начале
		 *
		 * \~english
		 * @brief Method of the computation of the message authentication code KMAC of a variable length by one call
		 * @param type   kind of the function: SHAKE128 or SHAKE256
		 * @param key    the key of the message authentication code
		 * @param data   message
		 * @param custom the customization S appointed by the consumer
		 * @param result place into which the message authentication code is put
		 * @param size   length of the message authentication code in bytes
		 * @return       sign that the message authentication code is computed
		 * @details The section 4 of SP 800-185: KMACXOF differs from KMAC by the record
		 *          right_encode(0) in the place of the length of the result, and its results
		 *          of different lengths coincide at the beginning
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool kmacxof(const sha3_t type, const view_t & key, const view_t & data, const view_t & custom, uint8_t * result, const size_t size) noexcept;
	};
};

