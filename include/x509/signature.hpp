/**
 * @file signature.hpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
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
 * @brief Заголовочный файл модуля проверки подписи сертификата X.509
 *
 * \~english
 * @brief Header file of the module of the check of the signature of an X.509 certificate
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_X509_SIGNATURE__
#define __ANYKS_TLS_X509_SIGNATURE__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <x509/x509.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace anyks {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модулей сертификатов X.509
	 *
	 * \~english
	 * @brief Namespace of the X.509 certificate modules
	 *
	 * \~
	 */
	namespace x509 {
		/**
		 * \~russian
		 * @brief Метод проверки подписи сертификата
		 *
		 * @param certificate сертификат, подпись которого проверяется
		 * @param key         сведения об открытом ключе издателя сертификата
		 *
		 * @return признак того, что подпись сертификата сошлась
		 *
		 * @details Проверяются лишь подписи по ГОСТ Р 34.10-2012 с хешем по
		 *          ГОСТ Р 34.11-2012: опознаватели и порядок записи величин заданы
		 *          разделами 2 и 4 RFC 9215. Подписи по устаревшему ГОСТ Р 34.11-94
		 *          не проверяются: хеш этот в проекте не заведён и заводиться не будет.
		 *
		 * @note Метод проверяет одну лишь подпись. Ни срок действия сертификата, ни
		 *       право издателя подписывать, ни цепочка доверия здесь не проверяются: это
		 *       разные вопросы, и смешивать их в одном ответе нельзя
		 *
		 * @note Сертификат, подписанный своим же ключом, проверяется передачей его
		 *       собственных сведений об открытом ключе
		 *
		 * \~english
		 * @brief Method of the check of the signature of a certificate
		 * @param certificate the certificate the signature of which is checked
		 * @param key         the info of the public key of the issuer of the certificate
		 * @return the flag of the signature of the certificate having converged
		 * @details Only the signatures according to GOST R 34.10-2012 with a hash according to
		 *          GOST R 34.11-2012 are checked: the identifiers and the order of the writing
		 *          of the values are given by the sections 2 and 4 of RFC 9215. The signatures
		 *          according to the outdated GOST R 34.11-94 are not checked: this hash is not
		 *          started in the project and will not be started.
		 * @note The method checks the signature alone. Neither the term of the validity of the
		 *       certificate, nor the right of the issuer to sign, nor the chain of the trust are
		 *       checked here: these are different questions and it is forbidden to mix them in a single answer
		 * @note A certificate signed by its own key is checked by a passing of its own info of the public key
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ bool verify(const certificate_t & certificate, const key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки подписи записи
		 *
		 * @param body      подписанная запись
		 * @param signature проверяемая подпись
		 * @param algorithm опознаватель алгоритма подписи
		 * @param key       сведения об открытом ключе подписавшей стороны
		 *
		 * @return признак того, что подпись записи сошлась
		 *
		 * @note Метод годится и для запросов на сертификат, и для списков отзыва: запись
		 *       подписи у них та же, что и у сертификата
		 *
		 * \~english
		 * @brief Method of the check of the signature of a record
		 * @param body      the signed record
		 * @param signature the signature being checked
		 * @param algorithm the identifier of the algorithm of the signature
		 * @param key       the info of the public key of the side that signed
		 * @return the flag of the signature of the record having converged
		 * @note The method is suitable both for the certificate requests and for the revocation
		 *       lists: the writing of the signature of them is the same as of a certificate
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ bool verify(const view_t & body, const view_t & signature, const string & algorithm, const key_t & key) noexcept;
	};
};

#endif // __ANYKS_TLS_X509_SIGNATURE__
