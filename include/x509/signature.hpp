/**
 * @file signature.hpp
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
#ifndef __ANTS_X509_SIGNATURE__
#define __ANTS_X509_SIGNATURE__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <x509/x509.hpp>
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
		 * @return отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *         непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
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
		 * @return the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *         unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
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
		__ANTS_SHARED_EXPORT__ error_t verify(const certificate_t & certificate, const key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки подписи записи
		 *
		 * @param body      подписанная запись
		 * @param signature проверяемая подпись
		 * @param algorithm опознаватель алгоритма подписи
		 * @param key       сведения об открытом ключе подписавшей стороны
		 *
		 * @return отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *         непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
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
		 * @return the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *         unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
		 * @note The method is suitable both for the certificate requests and for the revocation
		 *       lists: the writing of the signature of them is the same as of a certificate
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const view_t & body, const view_t & signature, const string & algorithm, const key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения опознавателя набора параметров кривой ключа
		 *
		 * @param key    сведения об открытом ключе, набор параметров которого извлекается
		 * @param result строка, в которую помещается опознаватель набора параметров
		 *
		 * @return       отказ извлечения опознавателя: KEY - ключ чужого алгоритма либо
		 *               негодная запись настроек, MEMORY - памяти под опознаватель не хватило
		 *
		 * \~english
		 * @brief Method of the extraction of the identifier of the set of the parameters of the curve of a key
		 * @param key    the info of the public key the set of the parameters of which is extracted
		 * @param result the string the identifier of the set of the parameters is put into
		 * @return       the failure of the extraction of the identifier: KEY - a key of a foreign algorithm
		 *               or an unsuitable record of the parameters, MEMORY - there was not enough memory
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t identifier(const key_t & key, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод заведения кривой открытого ключа
		 *
		 * @param key    сведения об открытом ключе, кривая которого заводится
		 * @param result кривая, в которую помещается набор параметров ключа
		 *
		 * @return       отказ заведения кривой: KEY - ключ чужого алгоритма либо неизвестной
		 *               кривой, MEMORY - памяти под опознаватель не хватило
		 *
		 * @details Набор параметров кривой объявлен настройками алгоритма ключа: раздел
		 *          2.1 RFC 9215
		 *
		 * \~english
		 * @brief Method of the establishment of the curve of a public key
		 * @param key    the info of the public key the curve of which is established
		 * @param result the curve the set of the parameters of the key is put into
		 * @return       the failure of the establishment of the curve: KEY - a key of a foreign algorithm or
		 *               of an unknown curve, MEMORY - there was not enough memory
		 * @details The set of the parameters of the curve is declared by the settings of the algorithm
		 *          of the key: the section 2.1 of RFC 9215
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parameters(const key_t & key, curve::curve_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки подписи содержимого открытым ключом
		 *
		 * @param key       сведения об открытом ключе подписавшей стороны
		 * @param content   подписанное содержимое
		 * @param signature проверяемая подпись, записанная числами r и s подряд
		 *
		 * @return          отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *                  непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
		 *
		 * @details Тем же ключом, что и сертификат, сторона подписывает и владение им: длина
		 *          хеша содержимого берётся из размера координаты кривой открытого ключа
		 *
		 * @note Подпись подаётся тем порядком, каким её выдаёт выработка, - сперва число r,
		 *       затем число s. Порядок записи подписи в сертификате и в протоколе от этого
		 *       отличается, и разворот делает тот, кто подпись оттуда извлёк
		 *
		 * \~english
		 * @brief Method of the check of the signature of a content by a public key
		 * @param key       the info of the public key of the side that signed
		 * @param content   the signed content
		 * @param signature the signature being checked written by the numbers r and s in a row
		 * @return          the failure of the check: NONE - the signature has converged, SIGNATURE - it has not
		 *                  or is unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
		 * @details By the same key as the certificate a side signs the possession of it as well: the
		 *          length of the hash of the content is taken from the size of the coordinate of the
		 *          curve of the public key
		 * @note The signature is given by the same order the production outputs it — first the number r,
		 *       then the number s. The order of the writing of the signature in a certificate and in the
		 *       protocol differs from it, and the reversal is done by the one who extracted the signature
		 *       from there
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t check(const key_t & key, const view_t & content, const view_t & signature) noexcept;
	};
};

#endif // __ANTS_X509_SIGNATURE__
