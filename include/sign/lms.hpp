/**
 * @file lms.hpp
 * @date 2026-10-06
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
 * @brief Заголовочный файл модуля подписей Лейтона-Микали —
 *        проверка подписи LMS и HSS по RFC 8554 и SP 800-208
 *
 * \~english
 * @brief Header file of the Leighton-Micali signatures module —
 *        the verification of the LMS and HSS signatures according to RFC 8554
 *        and SP 800-208
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
	 * @brief Пространство имён модулей подписи
	 *
	 * \~english
	 * @brief Namespace of the signature modules
	 *
	 * \~
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Пространство имён модуля подписей Лейтона-Микали
		 *
		 * @details Модуль проверяет подписи LMS и HSS по RFC 8554 и SP 800-208:
		 *          одноразовые подписи LM-OTS по цепочкам Винтерница и деревья
		 *          Меркла LMS, а также многоуровневые деревья HSS. Подпись
		 *          носит состояние (номер листа), потому выработка её модулем
		 *          сознательно не делается: назначение модуля - проверка
		 *          подписей прошивок по CNSA 2.0, где подписывает изготовитель,
		 *          а проверяет сторона загрузки.
		 *
		 * \~english
		 * @brief Namespace of the Leighton-Micali signatures module
		 *
		 * @details The module verifies the LMS and HSS signatures according to
		 *          RFC 8554 and SP 800-208: the LM-OTS one-time signatures by
		 *          the Winternitz chains and the LMS Merkle trees, and the
		 *          HSS multi-level trees as well. The signature carries a state
		 *          (the leaf number), so the module deliberately does not make
		 *          one: the purpose of the module is the verification of the
		 *          firmware signatures according to CNSA 2.0, where the vendor
		 *          signs and the loading side verifies.
		 *
		 * \~
		 */
		namespace lms {
			/**
			 * \~russian
			 * @brief Функция проверки подписи LMS либо HSS
			 *
			 * @param key       открытый ключ: запись LMS (тип, тип LM-OTS, I, K)
			 *                  либо HSS (число уровней, запись LMS верхнего уровня)
			 * @param message   проверяемое сообщение
			 * @param signature проверяемая подпись: запись LMS либо HSS
			 * @return          признак подлинности подписи
			 *
			 * @details Алгоритмы 4б, 6 и 6а RFC 8554: по подписи LM-OTS
			 *          вычисляется ключ-кандидат цепочками Винтерница, по нему
			 *          и пути Меркла - корень-кандидат дерева, который сличается
			 *          с открытым ключом; у HSS подпись нижнего уровня
			 *          заверяется открытым ключом, подписанным уровнем выше.
			 *          Проверка идёт в переменном времени: тайн она не касается
			 *
			 * \~english
			 * @brief Function of the verification of an LMS or HSS signature
			 *
			 * @param key       the public key: an LMS record (type, LM-OTS type, I, K)
			 *                  or an HSS one (the number of levels, the top-level LMS record)
			 * @param message   the message being verified
			 * @param signature the signature being verified: an LMS or HSS record
			 * @return          the flag of the authenticity of the signature
			 *
			 * @details The algorithms 4b, 6 and 6a of RFC 8554: a candidate key is
			 *          computed from the LM-OTS signature by the Winternitz chains,
			 *          a candidate tree root is computed from it and the Merkle path,
			 *          and it is compared with the public key; at HSS the lower-level
			 *          signature is verified by the public key signed by the level above.
			 *          The verification goes in a variable time: it touches no secrets
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool verify(const view_t & key, const view_t & message, const view_t & signature) noexcept;
		} // namespace lms
	} // namespace sign
} // namespace nts

