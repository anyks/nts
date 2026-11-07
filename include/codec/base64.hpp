/**
 * @file base64.hpp
 * @date 2026-11-07
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
 * @brief Заголовочный файл модуля кодирования основания 64 по RFC 4648
 *
 * \~english
 * @brief Header file of the base 64 encoding module by RFC 4648
 *
 * \~
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
#include <vector>
#include <string>

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
	 * @brief Пространство имён кодеков записей
	 *
	 * \~english
	 * @brief Namespace of the record codecs
	 *
	 * \~
	 */
	namespace codec {
		/**
		 * \~russian
		 * @brief Алфавит кодирования основания 64
		 *
		 * @details Раздел 4 RFC 4648 задаёт основание 62 знаком и «+» со «/», раздел 5 -
		 *          основание URL с «-» и «_»: знаки, не меняющие смысла в адресах
		 *
		 * \~english
		 * @brief The alphabet of the base 64 encoding
		 *
		 * @details The section 4 of RFC 4648 sets the base with 62 signs and «+» with «/»,
		 *          the section 5 - the URL base with «-» and «_»: the signs that keep
		 *          their meaning in the addresses
		 *
		 * \~
		 */
		enum class alphabet_t : uint8_t {
			// Основание знаками раздела 4 RFC 4648: «+» и «/»
			STANDARD = 0x00,
			// Основание URL знаками раздела 5 RFC 4648: «-» и «_»
			URL = 0x01
		};
		/**
		 * \~russian
		 * @brief Функция кодирования основания 64
		 *
		 * @details Всякие три байта уходят четырьмя знаками; недостающие разряды
		 *          дополняются нулями, и последний кусок добирается знаками «=» до
		 *          кратности четырём, коли заполнение заказано. Кодирование идёт
		 *          машинными ядрами перестановок при их наличии
		 *
		 * @param data     кодируемые данные
		 * @param result   строка, в которую помещается запись
		 * @param padding  признак заполнения записи знаками «=» до кратности четырём
		 * @param alphabet алфавит записи
		 * @return         признак успешности кодирования
		 *
		 * \~english
		 * @brief Function of the base 64 encoding
		 *
		 * @details Every three bytes leave as four signs; the missing digits are padded
		 *          with zeros, and the last chunk is filled with the «=» signs up to the
		 *          multiplicity of four when the padding is ordered. The encoding goes
		 *          by the machine permutation kernels when they are present
		 *
		 * @param data     the data being encoded
		 * @param result   the string the record is put into
		 * @param padding  the flag of the padding of the record with the «=» signs up to the multiplicity of four
		 * @param alphabet the alphabet of the record
		 * @return         the success flag of the encoding
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encode(const view_t & data, string & result, const bool padding = true, const alphabet_t alphabet = alphabet_t::STANDARD) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора записи основания 64
		 *
		 * @details Разбор строгий: посторонний знак, «=» вне хвоста, неверный счёт
		 *          заполнения и ненулевые отброшенные разряды отвергаются. Запись без
		 *          заполнения принимается, коли её длина даёт два либо три по модулю
		 *          четырёх; длина с остатком один отвергается. Пробельные знаки
		 *          пропускаются, коли это заказано. Заполнение отвергается целиком,
		 *          коли это заказано: издания вроде RFC 7515 и RFC 9106 велит запись
		 *          без заполнителей, и всякий знак «=» в ней - порча
		 *
		 * @param text     разбираемая запись
		 * @param result   место, в которое помещаются разобранные байты
		 * @param alphabet алфавит записи
		 * @param spaces   признак пропуска пробельных знаков записи
		 * @param padding  признак допущения знаков «=» в хвосте записи
		 * @return         признак успешности разбора
		 *
		 * \~english
		 * @brief Function of parsing of the base 64 record
		 *
		 * @details The parsing is strict: a foreign sign, an «=» outside the tail, a wrong
		 *          count of the padding and the non-zero discarded digits are rejected.
		 *          A record without the padding is accepted when its length leaves two or
		 *          three modulo four; a length with the remainder of one is rejected.
		 *          The whitespace signs are skipped when that is ordered. The padding is
		 *          rejected wholly when that is ordered: the editions like RFC 7515 and
		 *          RFC 9106 order the record without the padding signs, and every «=»
		 *          in it is a corruption
		 *
		 * @param text     the record being parsed
		 * @param result   the place the parsed bytes are put into
		 * @param alphabet the alphabet of the record
		 * @param spaces   the flag of the skipping of the whitespace signs of the record
		 * @param padding  the flag of the admission of the «=» signs in the tail of the record
		 * @return         the success flag of the parsing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool decode(const view_t & text, vector <uint8_t> & result, const alphabet_t alphabet = alphabet_t::STANDARD, const bool spaces = false, const bool padding = true) noexcept;
	};
};
