/**
 * @file parameters.hpp
 * @date 2026-08-29
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
 * @brief Заголовочный файл наборов параметров эллиптических кривых ГОСТ Р 34.10-2012
 *
 * \~english
 * @brief Header file of the sets of the parameters of the elliptic curves of GOST R 34.10-2012
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
#include <string>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <curve/curve.hpp>

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
	 * @brief Пространство имён модулей эллиптических кривых
	 *
	 * \~english
	 * @brief Namespace of the elliptic curve modules
	 *
	 * \~
	 */
	namespace curve {
		/**
		 * \~russian
		 * @brief Функция установки кривой по опознавателю набора параметров
		 *
		 * @param oid    опознаватель набора параметров в записи через точку
		 * @param result место, в которое помещается установленная кривая
		 * @return       признак того, что набор параметров известен и кривая установлена
		 *
		 * @details Известны наборы разделов 5.1 и 5.2 RFC 7836, наборы криптографии
		 *          открытого ключа раздела 11.4 RFC 4357 и их опознаватели по RFC 9215:
		 *          три набора RFC 4357 повторно опознаны как paramSetB, paramSetC и
		 *          paramSetD, что там и оговорено дословно.
		 *
		 * @note Известны и два испытательных набора: id-GostR3410-2001-TestParamSet и
		 *       id-tc26-gost-3410-2012-512-paramSetTest. Раздел 5 RFC 9215 прямо
		 *       запрещает применять их вне испытаний, и сама библиотека их годными не
		 *       считает: решение о допуске набора остаётся за потребителем, которому
		 *       опознаватель известен
		 *
		 * @note Кривые, заданные в скрученной форме Эдвардса, устанавливаются в форме
		 *       Вейерштрасса: она задана для них теми же разделами, а вид кривой на
		 *       выработку и проверку подписи не влияет
		 *
		 * \~english
		 * @brief Function of setting a curve by the identifier of a set of the parameters
		 *
		 * @param oid    the identifier of the set of the parameters in the notation through a dot
		 * @param result the place the set curve is put into
		 * @return       the flag of the set of the parameters being known and the curve being set
		 *
		 * @details The sets of the sections 5.1 and 5.2 of RFC 7836, the sets of the public key
		 *          cryptography of the section 11.4 of RFC 4357 and their identifiers according to
		 *          RFC 9215 are known: the three sets of RFC 4357 are repeatedly identified as
		 *          paramSetB, paramSetC and paramSetD, which is stated there verbatim.
		 *
		 * @note Two test sets are also known: id-GostR3410-2001-TestParamSet and
		 *       id-tc26-gost-3410-2012-512-paramSetTest. The section 5 of RFC 9215 directly
		 *       forbids to apply them outside the tests, and the library itself does not consider them
		 *       valid: the decision about the admission of a set remains with the consumer to whom
		 *       the identifier is known
		 *
		 * @note The curves given in the twisted Edwards form are set in the Weierstrass form: it is
		 *       given for them by the same sections, while the form of the curve does not influence
		 *       the production and the check of a signature
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool parameters(const string & oid, curve_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция установки кривой по опознавателю-литералу набора параметров
		 *
		 * Не строит временную строку: на libstdc++ строка длиннее 15 байтов (а с прежним
		 * устройством строк - любая) выделяет память, и под noexcept это оборачивалось броском
		 *
		 * @param oid    опознаватель набора параметров в записи через точку
		 * @param result место, в которое помещается установленная кривая
		 * @return       признак того, что набор параметров известен и кривая установлена
		 *
		 * \~english
		 * @brief Function of setting a curve by a literal identifier of a set of the parameters
		 *
		 * Does not build a temporary string: on libstdc++ a string longer than 15 bytes (and with the
		 * former string layout - any string) allocates, and under noexcept that turned into a throw
		 *
		 * @param oid    the identifier of the set of the parameters in the notation through a dot
		 * @param result the place the set curve is put into
		 * @return       the flag of the set of the parameters being known and the curve being set
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool parameters(const char * oid, curve_t & result) noexcept;
	};
};

