/**
 * @file request.hpp
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
 * @brief Заголовочный файл модуля запроса на сертификат PKCS #10 —
 *        разбор и запись CertificationRequest по RFC 2986
 *
 * \~english
 * @brief Header file of the PKCS #10 certificate request module —
 *        parsing and writing of a CertificationRequest according to RFC 2986
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
		 * @brief Запрос на сертификат PKCS #10
		 *
		 * @details Разобранный запрос хранит просмотры внутрь разбираемой записи:
		 *          запись обязана пережить объект. Подпись проверяется отдельным
		 *          вызовом verify тем же ключом, что лежит в сведениях об открытом
		 *          ключе запроса.
		 *
		 * \~english
		 * @brief PKCS #10 certificate request
		 * @details The parsed request keeps views inside the encoding being parsed:
		 *          the encoding must outlive the object. The signature is checked by
		 *          a separate call of verify with the same key that lies in the public
		 *          key info of the request.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Request {
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Просмотр записи запроса целиком
				view_t _element;
				// Просмотр подписываемой части запроса
				view_t _body;
			private:
				// Просмотр записи подписи
				view_t _signature;
				// Число неиспользуемых разрядов последнего байта подписи
				uint8_t _unused;
			private:
				// Опознаватель алгоритма подписи
				string _algorithm;
				// Просмотр записи настроек алгоритма подписи
				view_t _parameters;
			private:
				// Имя владельца запрашиваемого сертификата
				name_t _subject;
				// Сведения об открытом ключе запроса
				key_t _key;
			private:
				// Набор расширений, запрошенных у издателя
				vector <extension_t> _extensions;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи запроса на сертификат
				 *
				 * @param data просмотр разбираемой записи запроса
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект запроса
				 *
				 * \~english
				 * @brief Method of parsing a certificate request encoding
				 * @param data the view of the certificate request encoding being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
				 */
				error_t parse(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод очистки разобранных сведений
				 *
				 * \~english
				 * @brief Method of clearing the parsed info
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод извлечения причины последнего отказа
				 *
				 * @return причина последнего отказа
				 *
				 * \~english
				 * @brief Method of getting the reason of the last failure
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписываемой части запроса
				 *
				 * @return просмотр подписываемой части запроса
				 *
				 * \~english
				 * @brief Method of getting the signed part of the request
				 * @return the view of the signed part of the request
				 *
				 * \~
				 */
				const view_t & body() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписи запроса
				 *
				 * @param unused число неиспользуемых разрядов последнего байта подписи
				 * @return       просмотр записи подписи
				 *
				 * \~english
				 * @brief Method of getting the signature of the request
				 * @param unused the number of unused bits in the last byte of the signature
				 * @return       the view of the signature encoding
				 *
				 * \~
				 */
				const view_t & sign(uint8_t & unused) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя алгоритма подписи
				 *
				 * @return опознаватель алгоритма подписи
				 *
				 * \~english
				 * @brief Method of getting the identifier of the signature algorithm
				 * @return the identifier of the signature algorithm
				 *
				 * \~
				 */
				const string & algorithms() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения записи настроек алгоритма подписи
				 *
				 * @return просмотр записи настроек либо пустой просмотр
				 *
				 * \~english
				 * @brief Method of getting the encoding of the parameters of the signature algorithm
				 * @return the view of the encoding of the parameters or an empty view
				 *
				 * \~
				 */
				const view_t & settings() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения имени владельца запрашиваемого сертификата
				 *
				 * @return имя владельца запрашиваемого сертификата
				 *
				 * \~english
				 * @brief Method of getting the name of the subject of the requested certificate
				 * @return the name of the subject of the requested certificate
				 *
				 * \~
				 */
				const name_t & subjects() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения сведений об открытом ключе запроса
				 *
				 * @return сведения об открытом ключе запроса
				 *
				 * \~english
				 * @brief Method of getting the public key info of the request
				 * @return the public key info of the request
				 *
				 * \~
				 */
				const key_t & key() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора запрошенных расширений
				 *
				 * @return набор запрошенных расширений
				 *
				 * \~english
				 * @brief Method of getting the set of the requested extensions
				 * @return the set of the requested extensions
				 *
				 * \~
				 */
				const vector <extension_t> & extension() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор запроса
				 *
				 * \~english
				 * @brief Constructor of a request
				 *
				 * \~
				 */
				Request() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Request() noexcept {}
		} request_t;

		/**
		 * \~russian
		 * @brief Метод записи запроса на сертификат PKCS #10
		 *
		 * @param subject    имя владельца запрашиваемого сертификата
		 * @param key        сведения об открытом ключе запроса
		 * @param extensions набор запрашиваемых расширений (пустой набор - без расширений)
		 * @param signer     подготовленный секретный ключ подписи запроса
		 * @param hash       алгоритм хеша подписи (для ECDSA и RSA; у Ed25519, ML-DSA, SM2 и ГОСТ не рассматривается)
		 * @param result     место, в которое помещается запись запроса в кодировке DER
		 *
		 * @return           отказ записи запроса
		 *
		 * @details Собирается CertificationRequestInfo {version, subject, subjectPKInfo, attributes [0]},
		 *          подписывается ключом signer, и оборачивается в CertificationRequest {certificationRequestInfo,
		 *          signatureAlgorithm, signature}. Атрибут extensionRequest (1.2.840.113549.1.9.14) записывается
		 *          всегда, даже при пустом наборе расширений - так велит раздел 4 RFC 2986.
		 *
		 * \~english
		 * @brief Method of writing a PKCS #10 certificate request
		 * @param subject    the name of the subject of the requested certificate
		 * @param key        the public key info of the request
		 * @param extensions the set of the requested extensions (an empty set - without extensions)
		 * @param signer     the prepared secret key of the signature of the request
		 * @param hash       the hash algorithm of the signature (for ECDSA and RSA; not considered at Ed25519, ML-DSA, SM2 and GOST)
		 * @param result     the place the request encoding in DER is put into
		 * @return           the failure of the writing of the request
		 * @details The CertificationRequestInfo {version, subject, subjectPKInfo, attributes [0]} is built,
		 *          signed by the signer key, and wrapped into CertificationRequest {certificationRequestInfo,
		 *          signatureAlgorithm, signature}. The extensionRequest attribute (1.2.840.113549.1.9.14) is
		 *          always written, even with an empty set of extensions - as the section 4 of RFC 2986 orders.
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const name_t & subject, const key_t & key, const vector <extension_t> & extensions, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод проверки подписи запроса на сертификат
		 *
		 * @param request запрос, подпись которого проверяется
		 * @param key     сведения об открытом ключе подписавшей стороны
		 *
		 * @return        отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *                непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
		 *
		 * \~english
		 * @brief Method of the check of the signature of a certificate request
		 * @param request the request the signature of which is checked
		 * @param key     the info of the public key of the side that signed
		 * @return        the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *                unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const request_t & request, const key_t & key) noexcept;
	};
};

