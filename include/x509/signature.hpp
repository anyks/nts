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
#include <x509/x509.hpp>
#include <curve/curve.hpp>
#include <digest/hash.hpp>

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
		 * @details Проверяются подписи по ГОСТ Р 34.10-2012 с хешем по ГОСТ Р 34.11-2012
		 *          (опознаватели и порядок записи величин заданы разделами 2 и 4 RFC 9215),
		 *          подписи ECDSA с хешами SHA-2 (RFC 5758, ключ по RFC 5480), подписи RSA
		 *          PKCS #1 v1.5 с хешами SHA-1 и SHA-2 и RSASSA-PSS (RFC 4055, ключ по
		 *          RFC 3279) и подписи Ed25519 (RFC 8410). Подписи по устаревшему
		 *          ГОСТ Р 34.11-94 не проверяются: хеш этот в проекте не заведён и
		 *          заводиться не будет.
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
		 * @details The signatures according to GOST R 34.10-2012 with a hash according to
		 *          GOST R 34.11-2012 (the identifiers and the order of the writing of the values
		 *          are given by the sections 2 and 4 of RFC 9215), the ECDSA signatures with the
		 *          SHA-2 hashes (RFC 5758, the key according to RFC 5480), the RSA signatures
		 *          PKCS #1 v1.5 with the SHA-1 and SHA-2 hashes and RSASSA-PSS (RFC 4055, the key
		 *          according to RFC 3279) and the Ed25519 signatures (RFC 8410) are checked. The
		 *          signatures according to the outdated GOST R 34.11-94 are not checked: this
		 *          hash is not started in the project and will not be started.
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
		 * @brief Метод проверки голой подписи RSA PKCS #1 v1.5 над готовым хешем (TLS 1.1)
		 *
		 * @param digest    готовый хеш: 36 байтов MD5 ‖ SHA-1 у изданий TLS 1.0 и 1.1
		 * @param signature проверяемая подпись
		 * @param key       открытый ключ RSA из сертификата
		 *
		 * @return          отказ проверки подписи
		 *
		 * @details Раздел 7.4.3 RFC 4346: подпись без DigestInfo; нужна лишь изданию DTLS 1.0
		 *
		 * \~english
		 * @brief Method of the check of a bare RSA PKCS #1 v1.5 signature over a ready hash (TLS 1.1)
		 * @param digest    the ready hash: 36 bytes MD5 ‖ SHA-1 at the TLS 1.0 and 1.1 editions
		 * @param signature the signature being checked
		 * @param key       the RSA public key from the certificate
		 * @return          the failure of the check of the signature
		 * @details The section 7.4.3 of RFC 4346: a signature without DigestInfo; needed only by the DTLS 1.0 edition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const view_t & digest, const view_t & signature, const key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки подписи записи с настройками алгоритма подписи
		 *
		 * @param body       подписанная запись
		 * @param signature  проверяемая подпись
		 * @param algorithm  опознаватель алгоритма подписи
		 * @param parameters запись настроек алгоритма подписи целиком либо пустой просмотр
		 * @param key        сведения об открытом ключе подписавшей стороны
		 *
		 * @return отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *         непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
		 *
		 * @details Настройки нужны одной лишь подписи RSASSA-PSS: запись RSASSA-PSS-params
		 *          раздела 3.1 RFC 4055 задаёт хеш, порождение маски и длину соли. При
		 *          пустой записи настроек берутся умолчания того же раздела: хеш SHA-1 и
		 *          соль в двадцать байтов. Прочие алгоритмы настроек не имеют, и запись
		 *          их не рассматривается
		 *
		 * \~english
		 * @brief Method of the check of the signature of a record with the settings of the algorithm of the signature
		 * @param body       the signed record
		 * @param signature  the signature being checked
		 * @param algorithm  the identifier of the algorithm of the signature
		 * @param parameters the record of the settings of the algorithm of the signature as a whole or an empty view
		 * @param key        the info of the public key of the side that signed
		 * @return the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *         unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
		 * @details The settings are needed by the RSASSA-PSS signature alone: the record RSASSA-PSS-params
		 *          of the section 3.1 of RFC 4055 sets the hash, the generation of the mask and the length
		 *          of the salt. With an empty record of the settings the defaults of the same section are
		 *          taken: the hash SHA-1 and a salt of twenty bytes. The other algorithms have no settings,
		 *          and the record of them is not considered
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const view_t & body, const view_t & signature, const string & algorithm, const view_t & parameters, const key_t & key) noexcept;
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
		/**
		 * \~russian
		 * @brief Метод проверки подписи содержимого открытым ключом с заданным хешем
		 *
		 * @param key       сведения об открытом ключе подписавшей стороны
		 * @param algorithm алгоритм хеша подписанного содержимого
		 * @param content   подписанное содержимое
		 * @param signature проверяемая подпись в записи, отвечающей алгоритму ключа
		 *
		 * @return          отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *                  непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
		 *
		 * @details Запись подписи задана разделом 4.2.3 RFC 8446 по виду ключа: у ключа ECDSA
		 *          подпись записана набором SEQUENCE {r, s} кодировкой DER, у ключа RSA подпись
		 *          по схеме RSASSA-PSS с солью длиной в хеш, у ключа Ed25519 подпись сырая в
		 *          шестьдесят четыре байта, а хеш не считается вовсе, - алгоритм хеша у неё не
		 *          рассматривается. Ключу ГОСТ Р 34.10-2012 алгоритм хеша не нужен: длина хеша
		 *          «Стрибог» берётся размером координаты кривой, и проверка идёт тем же путём,
		 *          что и без алгоритма
		 *
		 * \~english
		 * @brief Method of the check of the signature of a content by a public key with a given hash
		 * @param key       the info of the public key of the side that signed
		 * @param algorithm the algorithm of the hash of the signed content
		 * @param content   the signed content
		 * @param signature the signature being checked in the writing corresponding to the algorithm of the key
		 * @return          the failure of the check: NONE - the signature has converged, SIGNATURE - it has not
		 *                  or is unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
		 * @details The writing of the signature is set by the section 4.2.3 of RFC 8446 by the kind of the key:
		 *          with an ECDSA key the signature is written as the set SEQUENCE {r, s} in the DER encoding,
		 *          with an RSA key the signature is according to the RSASSA-PSS scheme with a salt of the length
		 *          of the hash, with an Ed25519 key the signature is raw of sixty four bytes and no hash is
		 *          computed at all - the algorithm of the hash is not considered for it. A GOST R 34.10-2012 key
		 *          does not need the algorithm of the hash: the length of the «Streebog» hash is taken by the size
		 *          of the coordinate of the curve, and the check goes the same way as without the algorithm
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t check(const key_t & key, const digest::hash_t algorithm, const view_t & content, const view_t & signature) noexcept;
	};
};

