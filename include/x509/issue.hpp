/**
 * @file issue.hpp
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
 * @brief Заголовочный файл модуля выпуска сертификатов X.509 —
 *        сборка TBSCertificate и подпись (самоподписанный и ЦС)
 *
 * \~english
 * @brief Header file of the X.509 certificate issuance module —
 *        building of TBSCertificate and signing (self-signed and CA)
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
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <x509/x509.hpp>
#include <x509/request.hpp>
#include <keys/keys.hpp>
#include <digest/hash.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 *
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
		 * @brief Метод выпуска самоподписанного сертификата
		 *
		 * @param subject    имя владельца сертификата (оно же имя издателя)
		 * @param key        сведения об открытом ключе владельца
		 * @param signer     подготовленный секретный ключ подписи (тот же, что и у владельца)
		 * @param hash       алгоритм хеша подписи (для ECDSA и RSA; у Ed25519, ML-DSA, SM2 и ГОСТ не рассматривается)
		 * @param serial     порядковый номер сертификата (не нулевой)
		 * @param before     начало срока действия в секундах от начала эпохи
		 * @param after      окончание срока действия в секундах от начала эпохи
		 * @param extensions набор расширений сертификата (пустой набор - без расширений, сертификат v1)
		 * @param result     место, в которое помещается запись сертификата в кодировке DER
		 *
		 * @return           отказ выпуска сертификата
		 *
		 * @details Собирается TBSCertificate {version, serialNumber, signature, issuer, validity, subject,
		 *          subjectPublicKeyInfo, extensions [3]}, подписывается ключом signer, и оборачивается в
		 *          Certificate {tbsCertificate, signatureAlgorithm, signatureValue}. При пустом наборе
		 *          расширений сертификат выходит первого издания (v1), при непустом - третьего (v3).
		 *
		 * \~english
		 * @brief Method of issuing a self-signed certificate
		 * @param subject    the name of the subject of the certificate (the same as the issuer name)
		 * @param key        the public key info of the subject
		 * @param signer     the prepared secret key of the signature (the same as of the subject)
		 * @param hash       the hash algorithm of the signature (for ECDSA and RSA; not considered at Ed25519, ML-DSA, SM2 and GOST)
		 * @param serial     the serial number of the certificate (not zero)
		 * @param before     the beginning of the validity in seconds since the epoch
		 * @param after      the end of the validity in seconds since the epoch
		 * @param extensions the set of the extensions of the certificate (an empty set - without extensions, a v1 certificate)
		 * @param result     the place the certificate encoding in DER is put into
		 * @return           the failure of the issuance of the certificate
		 * @details The TBSCertificate {version, serialNumber, signature, issuer, validity, subject,
		 *          subjectPublicKeyInfo, extensions [3]} is built, signed by the signer key, and wrapped into
		 *          Certificate {tbsCertificate, signatureAlgorithm, signatureValue}. With an empty set of
		 *          extensions the certificate comes out of the first version (v1), with a non-empty one - of the third (v3).
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t issueSelfSigned(const name_t & subject, const key_t & key, const keys::signer_t & signer, const digest::hash_t hash, const view_t & serial, const int64_t before, const int64_t after, const vector <extension_t> & extensions, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод выпуска сертификата по запросу PKCS #10 подписью ЦС
		 *
		 * @param request    разобранный запрос на сертификат (подпись уже проверена вызывающим)
		 * @param issuer     имя издателя сертификата (из сертификата ЦС)
		 * @param signer     подготовленный секретный ключ ЦС
		 * @param hash       алгоритм хеша подписи (для ECDSA и RSA; у Ed25519, ML-DSA, SM2 и ГОСТ не рассматривается)
		 * @param serial     порядковый номер сертификата (не нулевой)
		 * @param before     начало срока действия в секундах от начала эпохи
		 * @param after      окончание срока действия в секундах от начала эпохи
		 * @param extensions набор расширений сертификата (пустой набор - без расширений, сертификат v1)
		 * @param result     место, в которое помещается запись сертификата в кодировке DER
		 *
		 * @return           отказ выпуска сертификата
		 *
		 * @details Имя владельца и сведения об открытом ключе берутся из запроса, имя издателя - из
		 *          сертификата ЦС. Подпись ставится ключом ЦС. Расширения запроса не копируются:
		 *          вызывающий сам решает, какие расширения выдать.
		 *
		 * \~english
		 * @brief Method of issuing a certificate by a PKCS #10 request with a CA signature
		 * @param request    the parsed certificate request (the signature already checked by the caller)
		 * @param issuer     the name of the issuer of the certificate (from the CA certificate)
		 * @param signer     the prepared secret key of the CA
		 * @param hash       the hash algorithm of the signature (for ECDSA and RSA; not considered at Ed25519, ML-DSA, SM2 and GOST)
		 * @param serial     the serial number of the certificate (not zero)
		 * @param before     the beginning of the validity in seconds since the epoch
		 * @param after      the end of the validity in seconds since the epoch
		 * @param extensions the set of the extensions of the certificate (an empty set - without extensions, a v1 certificate)
		 * @param result     the place the certificate encoding in DER is put into
		 * @return           the failure of the issuance of the certificate
		 * @details The subject name and the public key info are taken from the request, the issuer name - from
		 *          the CA certificate. The signature is put by the CA key. The extensions of the request are not copied:
		 *          the caller decides which extensions to issue.
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t issueByCA(const request_t & request, const name_t & issuer, const keys::signer_t & signer, const digest::hash_t hash, const view_t & serial, const int64_t before, const int64_t after, const vector <extension_t> & extensions, vector <uint8_t> & result) noexcept;
	};
};

