/**
 * @file acme.hpp
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
 * @brief Заголовочный файл модуля протокола ACME —
 *        сообщения управления сертификатами по RFC 8555
 *
 * \~english
 * @brief Header file of the ACME protocol module —
 *        the certificate management messages according to RFC 8555
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_ACME__
#define __ANTS_ACME__

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
#include <jws/jws.hpp>

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
	 * @brief Пространство имён модуля протокола ACME
	 *
	 * \~english
	 * @brief Namespace of the ACME protocol module
	 *
	 * \~
	 *
	 */
	namespace acme {
		/**
		 * \~russian
		 * @brief Отказы работы с сообщениями ACME
		 *
		 * \~english
		 * @brief Failures of the work with the ACME messages
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			EMPTY     = 0x01, /*!< \~russian Сообщение пусто либо ключ не установлен \~english The message is empty or the key is not set \~ */
			STRUCTURE = 0x02, /*!< \~russian Сообщение не отвечает устройству своего вида \~english The message does not meet the structure of its kind \~ */
			ALGORITHM = 0x03, /*!< \~russian Алгоритм подписи неизвестен либо ключ ему не отвечает \~english The signature algorithm is unknown or the key does not meet it \~ */
			SIGNATURE = 0x04, /*!< \~russian Подпись не сошлась либо выработать её не удалось \~english The signature has not converged or its production has failed \~ */
			MEMORY    = 0x05  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Виды идентификаторов ACME
		 *
		 * \~english
		 * @brief Kinds of the ACME identifiers
		 *
		 * \~
		 */
		enum class identifier_t : uint8_t {
			NONE = 0x00, /*!< \~russian Идентификатор не установлен \~english The identifier is not set \~ */
			DNS  = 0x01, /*!< \~russian Доменное имя по разделу 9.7.7 RFC 8555 \~english A domain name according to the section 9.7.7 of RFC 8555 \~ */
			IP   = 0x02  /*!< \~russian Адрес IP по RFC 8738 \~english An IP address according to RFC 8738 \~ */
		};

		/**
		 * \~russian
		 * @brief Запись каталога службы ACME
		 *
		 * @details Разобранный ответ ресурса directory по разделу 7.1.1 RFC 8555:
		 *          адреса ресурсов службы. Поля, которых ответ не несёт, остаются пустыми
		 *
		 * \~english
		 * @brief Record of the ACME service directory
		 * @details The parsed answer of the directory resource according to the section
		 *          7.1.1 of RFC 8555: the addresses of the service resources. The fields
		 *          the answer does not carry stay empty
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Directory {
			// Адрес ресурса выдачи метки новизны
			string newNonce;
			// Адрес ресурса заведения учётной записи
			string newAccount;
			// Адрес ресурса заведения заказа
			string newOrder;
			// Адрес ресурса заведения заказа с немедленным выпуском по RFC 8737
			string newAuthz;
			// Адрес ресурса отзыва сертификата
			string revokeCert;
			// Адрес ресурса смены ключа учётной записи
			string keyChange;
			// Адрес ресурса продления записи по черновику арифметики продления
			string renewalInfo;
			/**
			 * \~russian
			 * @brief Метод разбора ответа ресурса directory
			 *
			 * @param data просмотр разбираемого ответа
			 * @return     причина отказа либо error_t::NONE
			 *
			 * \~english
			 * @brief Method of parsing the answer of the directory resource
			 * @param data the view of the answer being parsed
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
		} directory_t;

		/**
		 * \~russian
		 * @brief Запись учётной записи ACME
		 *
		 * @details Разобранный ответ ресурса учётной записи по разделу 7.1.2 RFC 8555
		 *
		 * \~english
		 * @brief Record of the ACME account
		 * @details The parsed answer of the account resource according to the section
		 *          7.1.2 of RFC 8555
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Account {
			// Состояние записи: valid, deactivated, revoked
			string status;
			// Набор адресов заказов записи
			vector <string> orders;
			/**
			 * \~russian
			 * @brief Метод разбора ответа ресурса учётной записи
			 *
			 * @param data просмотр разбираемого ответа
			 * @return     причина отказа либо error_t::NONE
			 *
			 * \~english
			 * @brief Method of parsing the answer of the account resource
			 * @param data the view of the answer being parsed
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
		} account_t;

		/**
		 * \~russian
		 * @brief Запись заказа ACME
		 *
		 * @details Разобранный ответ ресурса заказа по разделу 7.1.3 RFC 8555
		 *
		 * \~english
		 * @brief Record of the ACME order
		 * @details The parsed answer of the order resource according to the section
		 *          7.1.3 of RFC 8555
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Order {
			// Состояние заказа: pending, ready, processing, valid, invalid
			string status;
			// Срок действия заказа в записи RFC 3339, пустой при его отсутствии
			string expires;
			// Набор идентификаторов заказа: вид и значение
			vector <pair <identifier_t, string>> identifiers;
			// Набор адресов записей полномочий заказа
			vector <string> authorizations;
			// Адрес ресурса завершения заказа
			string finalize;
			// Адрес ресурса выданного сертификата, пустой до выдачи
			string certificate;
			/**
			 * \~russian
			 * @brief Метод разбора ответа ресурса заказа
			 *
			 * @param data просмотр разбираемого ответа
			 * @return     причина отказа либо error_t::NONE
			 *
			 * \~english
			 * @brief Method of parsing the answer of the order resource
			 * @param data the view of the answer being parsed
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
		} order_t;

		/**
		 * \~russian
		 * @brief Запись испытания ACME
		 *
		 * @details Разобранная запись испытания записи полномочий по разделу 7.1.5 RFC 8555
		 *
		 * \~english
		 * @brief Record of the ACME challenge
		 * @details The parsed record of a challenge of the authorization record according
		 *          to the section 7.1.5 of RFC 8555
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Challenge {
			// Вид испытания: http-01, dns-01, tls-alpn-01 и прочие
			string type;
			// Адрес ресурса испытания
			string url;
			// Состояние испытания: pending, processing, valid, invalid
			string status;
			// Метка испытания
			string token;
			// Дата проверки испытания в записи RFC 3339, пустая до проверки
			string validated;
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
		} challenge_t;

		/**
		 * \~russian
		 * @brief Запись полномочий ACME
		 *
		 * @details Разобранный ответ ресурса записи полномочий по разделу 7.1.4 RFC 8555
		 *
		 * \~english
		 * @brief Record of the ACME authorization
		 * @details The parsed answer of the authorization resource according to the
		 *          section 7.1.4 of RFC 8555
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Authorization {
			// Состояние записи: pending, valid, invalid, deactivated, expired, revoked
			string status;
			// Срок действия записи в записи RFC 3339, пустой при его отсутствии
			string expires;
			// Идентификатор записи: вид и значение
			pair <identifier_t, string> identifier;
			// Признак записи с маской
			bool wildcard;
			// Набор испытаний записи
			vector <challenge_t> challenges;
			/**
			 * \~russian
			 * @brief Метод разбора ответа ресурса записи полномочий
			 *
			 * @param data просмотр разбираемого ответа
			 * @return     причина отказа либо error_t::NONE
			 *
			 * \~english
			 * @brief Method of parsing the answer of the authorization resource
			 * @param data the view of the answer being parsed
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
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Authorization() noexcept;
		} authorization_t;

		/**
		 * \~russian
		 * @brief Запись отказа службы ACME
		 *
		 * @details Разобранный ответ application/problem+json по RFC 7807
		 *          и разделу 6.7 RFC 8555
		 *
		 * \~english
		 * @brief Record of the failure of the ACME service
		 * @details The parsed application/problem+json answer according to RFC 7807
		 *          and the section 6.7 of RFC 8555
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Problem {
			// Опознаватель вида отказа: urn:ietf:params:acme:error:…
			string type;
			// Краткое описание отказа
			string detail;
			// Состояние ответа HTTP, ноль при его отсутствии
			uint32_t status;
			/**
			 * \~russian
			 * @brief Метод разбора ответа об отказе
			 *
			 * @param data просмотр разбираемого ответа
			 * @return     причина отказа либо error_t::NONE
			 *
			 * \~english
			 * @brief Method of parsing the failure answer
			 * @param data the view of the answer being parsed
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
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Problem() noexcept;
		} problem_t;

		/**
		 * \~russian
		 * @brief Метод сборки запроса ACME
		 *
		 * @param url     адрес ресурса запроса
		 * @param nonce   метка новизны из ответа службы
		 * @param kid     адрес учётной записи, пустой при записи ключа JWK
		 * @param key     сведения об открытом ключе учётной записи для записи JWK
		 * @param payload полезная нагрузка запроса, пустая у запроса POST-as-GET
		 * @param signer  подготовленный секретный ключ учётной записи
		 * @param result  строка, в которую помещается тело запроса application/jose+json
		 *
		 * @return        причина отказа либо error_t::NONE
		 *
		 * @details Запрос собирается по разделу 6.2 RFC 8555: заголовок JWS несёт
		 *          члены alg, nonce, url и kid либо jwk (у запросов newAccount и
		 *          revokeCert ключом учётной записи), полезная нагрузка и подпись
		 *          кодируются в base64url. Пустая полезная нагрузка записывается
		 *          пустой строкой, как велит раздел 6.3
		 *
		 * \~english
		 * @brief Method of assembling an ACME request
		 * @param url     the address of the resource of the request
		 * @param nonce   the nonce from the answer of the service
		 * @param kid     the address of the account, empty at a record of the JWK key
		 * @param key     the info of the public key of the account for the JWK record
		 * @param payload the payload of the request, empty at a POST-as-GET request
		 * @param signer  the prepared secret key of the account
		 * @param result  the string the application/jose+json request body is put into
		 * @return        the reason of the failure or error_t::NONE
		 * @details The request is assembled according to the section 6.2 of RFC 8555:
		 *          the JWS header carries the members alg, nonce, url and either kid or
		 *          jwk (at the requests newAccount and revokeCert by the account key),
		 *          the payload and the signature are encoded into base64url. An empty
		 *          payload is written by an empty string, as the section 6.3 orders
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t request(const string & url, const string & nonce, const string & kid, const keys::key_t & key, const view_t & payload, const keys::signer_t & signer, string & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод сборки полезной нагрузки заведения учётной записи
		 *
		 * @param contacts          набор адресов связи («mailto:…»), вправе быть пустым
		 * @param termsOfServiceAgreed признак согласия с условиями службы
		 * @param onlyReturnExisting   признак запроса лишь существующей записи
		 * @param result            строка, в которую помещается полезная нагрузка
		 *
		 * @details Полезная нагрузка запроса newAccount по разделу 7.3 RFC 8555
		 *
		 * \~english
		 * @brief Method of assembling the payload of the account creation
		 * @param contacts             the set of the contact addresses («mailto:…»), may be empty
		 * @param termsOfServiceAgreed the flag of the agreement with the terms of the service
		 * @param onlyReturnExisting   the flag of the request of an existing account alone
		 * @param result               the string the payload is put into
		 * @details The payload of the newAccount request according to the section 7.3 of RFC 8555
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void newAccount(const vector <string> & contacts, const bool termsOfServiceAgreed, const bool onlyReturnExisting, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки полезной нагрузки заведения заказа
		 *
		 * @param identifiers набор идентификаторов заказа: вид и значение
		 * @param result      строка, в которую помещается полезная нагрузка
		 * @return            причина отказа либо error_t::NONE
		 *
		 * @details Полезная нагрузка запроса newOrder по разделу 7.4 RFC 8555
		 *
		 * \~english
		 * @brief Method of assembling the payload of the order creation
		 * @param identifiers the set of the identifiers of the order: kind and value
		 * @param result      the string the payload is put into
		 * @return            the reason of the failure or error_t::NONE
		 * @details The payload of the newOrder request according to the section 7.4 of RFC 8555
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t newOrder(const vector <pair <identifier_t, string>> & identifiers, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки полезной нагрузки завершения заказа
		 *
		 * @param csr    запись запроса на сертификат в кодировке DER
		 * @param result строка, в которую помещается полезная нагрузка
		 *
		 * @details Полезная нагрузка запроса finalize по разделу 7.4 RFC 8555:
		 *          запись запроса кодируется в base64url
		 *
		 * \~english
		 * @brief Method of assembling the payload of the order finalization
		 * @param csr    the certificate request record in the DER encoding
		 * @param result the string the payload is put into
		 * @details The payload of the finalize request according to the section 7.4
		 *          of RFC 8555: the request record is encoded into base64url
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void finalize(const view_t & csr, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки полезной нагрузки отзыва сертификата
		 *
		 * @param certificate запись сертификата в кодировке DER
		 * @param reason      причина отзыва по разделу 5.3.1 RFC 5280
		 * @param result      строка, в которую помещается полезная нагрузка
		 *
		 * @details Полезная нагрузка запроса revokeCert по разделу 7.6 RFC 8555:
		 *          запись сертификата кодируется в base64url
		 *
		 * \~english
		 * @brief Method of assembling the payload of the certificate revocation
		 * @param certificate the certificate record in the DER encoding
		 * @param reason      the reason of the revocation according to the section 5.3.1 of RFC 5280
		 * @param result      the string the payload is put into
		 * @details The payload of the revokeCert request according to the section 7.6
		 *          of RFC 8555: the certificate record is encoded into base64url
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void revokeCert(const view_t & certificate, const uint8_t reason, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод сборки полезной нагрузки ответа на испытание
		 *
		 * @param result строка, в которую помещается полезная нагрузка
		 *
		 * @details Ответ на испытание по разделу 7.5.1 RFC 8555: пустой объект
		 *
		 * \~english
		 * @brief Method of assembling the payload of the answer to a challenge
		 * @param result the string the payload is put into
		 * @details The answer to a challenge according to the section 7.5.1 of RFC 8555:
		 *          an empty object
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void answer(string & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод выработки полномочного ключа испытания
		 *
		 * @param token  метка испытания
		 * @param key    сведения об открытом ключе учётной записи
		 * @param result строка, в которую помещается ключ в base64url
		 * @return       причина отказа либо error_t::NONE
		 *
		 * @details Полномочный ключ по разделу 8.1 RFC 8555: base64url(SHA-256(token
		 *          ‖ '.' ‖ отпечаток JWK ключа учётной записи)). Им отвечают на
		 *          испытания http-01 и dns-01
		 *
		 * \~english
		 * @brief Method of the production of the key authorization of a challenge
		 * @param token  the token of the challenge
		 * @param key    the info of the public key of the account
		 * @param result the string the key in base64url is put into
		 * @return       the reason of the failure or error_t::NONE
		 * @details The key authorization according to the section 8.1 of RFC 8555:
		 *          base64url(SHA-256(token ‖ '.' ‖ the JWK thumbprint of the account
		 *          key)). The challenges http-01 and dns-01 are answered by it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t keyAuthorization(const string & token, const keys::key_t & key, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки владения ключом испытания
		 *
		 * @param token  метка испытания
		 * @param key    сведения об открытом ключе учётной записи
		 * @param result строка, в которую помещается владение
		 * @return       причина отказа либо error_t::NONE
		 *
		 * @details Владение ключом по разделу 8.1 RFC 8555: token ‖ '.' ‖ отпечаток
		 *          JWK ключа учётной записи. Им отвечают на испытание http-01
		 *
		 * \~english
		 * @brief Method of the production of the key possession of a challenge
		 * @param token  the token of the challenge
		 * @param key    the info of the public key of the account
		 * @param result the string the possession is put into
		 * @return       the reason of the failure or error_t::NONE
		 * @details The key possession according to the section 8.1 of RFC 8555: token
		 *          ‖ '.' ‖ the JWK thumbprint of the account key. The challenge
		 *          http-01 is answered by it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t keyPossession(const string & token, const keys::key_t & key, string & result) noexcept;
	}
}

#endif // __ANTS_ACME__
