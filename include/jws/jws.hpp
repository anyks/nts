/**
 * @file jws.hpp
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
 * @brief Заголовочный файл модуля подписей JWS —
 *        компактная запись подписи по RFC 7515, ключи JWK по RFC 7517
 *        и отпечатки ключей по RFC 7638
 *
 * \~english
 * @brief Header file of the JWS signature module —
 *        the compact serialization of a signature according to RFC 7515, the JWK keys
 *        according to RFC 7517 and the key thumbprints according to RFC 7638
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
#include <keys/keys.hpp>

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
	 * @brief Пространство имён модуля подписей JWS
	 *
	 * \~english
	 * @brief Namespace of the JWS signature module
	 *
	 * \~
	 *
	 */
	namespace jws {
		/**
		 * \~russian
		 * @brief Отказы работы с записями JWS
		 *
		 * \~english
		 * @brief Failures of the work with the JWS records
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE       = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			EMPTY      = 0x01, /*!< \~russian Запись пуста либо ключ не установлен \~english The record is empty or the key is not set \~ */
			STRUCTURE  = 0x02, /*!< \~russian Запись не отвечает устройству компактной записи JWS \~english The record does not meet the structure of the JWS compact serialization \~ */
			ALGORITHM  = 0x03, /*!< \~russian Алгоритм подписи неизвестен либо ключ ему не отвечает \~english The signature algorithm is unknown or the key does not meet it \~ */
			SIGNATURE  = 0x04, /*!< \~russian Подпись не сошлась либо выработать её не удалось \~english The signature has not converged or its production has failed \~ */
			MEMORY     = 0x05  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Алгоритмы подписи JWS
		 *
		 * @details Набор по разделу 3.1 RFC 7518 из алгоритмов, заведённых в проекте:
		 *          HMAC не заводится — подписи JWS в ACME идут лишь ключами асимметричными
		 *
		 * \~english
		 * @brief The signature algorithms of JWS
		 * @details The set according to the section 3.1 of RFC 7518 out of the algorithms
		 *          started in the project: HMAC is not started — the JWS signatures in ACME
		 *          go by the asymmetric keys alone
		 *
		 * \~
		 */
		enum class algorithm_t : uint8_t {
			NONE   = 0x00, /*!< \~russian Алгоритм не установлен \~english The algorithm is not set \~ */
			RS256  = 0x01, /*!< \~russian RSASSA-PKCS1-v1_5 с SHA-256 по разделу 3.3 RFC 7518 \~english RSASSA-PKCS1-v1_5 with SHA-256 according to the section 3.3 of RFC 7518 \~ */
			RS384  = 0x02, /*!< \~russian RSASSA-PKCS1-v1_5 с SHA-384 по разделу 3.3 RFC 7518 \~english RSASSA-PKCS1-v1_5 with SHA-384 according to the section 3.3 of RFC 7518 \~ */
			RS512  = 0x03, /*!< \~russian RSASSA-PKCS1-v1_5 с SHA-512 по разделу 3.3 RFC 7518 \~english RSASSA-PKCS1-v1_5 with SHA-512 according to the section 3.3 of RFC 7518 \~ */
			ES256  = 0x04, /*!< \~russian ECDSA на P-256 с SHA-256 по разделу 3.4 RFC 7518 \~english ECDSA on P-256 with SHA-256 according to the section 3.4 of RFC 7518 \~ */
			ES384  = 0x05, /*!< \~russian ECDSA на P-384 с SHA-384 по разделу 3.4 RFC 7518 \~english ECDSA on P-384 with SHA-384 according to the section 3.4 of RFC 7518 \~ */
			ES512  = 0x06, /*!< \~russian ECDSA на P-521 с SHA-512 по разделу 3.4 RFC 7518 \~english ECDSA on P-521 with SHA-512 according to the section 3.4 of RFC 7518 \~ */
			EDDSA  = 0x07  /*!< \~russian Ed25519 по RFC 8037 \~english Ed25519 according to RFC 8037 \~ */
		};

		/**
		 * \~russian
		 * @brief Разобранная компактная запись JWS
		 *
		 * @details Разобранная запись хранит просмотры внутрь разбираемого текста:
		 *          текст обязан пережить объект. Подпись проверяется методом verify
		 *          сведениями об открытом ключе подписавшей стороны
		 *
		 * \~english
		 * @brief A parsed JWS compact record
		 * @details The parsed record keeps views inside the text being parsed:
		 *          the text must outlive the object. The signature is checked by the
		 *          method verify with the public key info of the side that signed
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Signature {
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Алгоритм подписи из заголовка записи
				algorithm_t _algorithm;
			private:
				// Просмотр записи заголовка в base64url
				view_t _protected;
				// Просмотр разобранного текста заголовка JSON
				string _header;
			private:
				// Просмотр записи полезной нагрузки в base64url
				view_t _payload;
			private:
				// Подпись в разобранном виде
				vector <uint8_t> _signature;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора компактной записи JWS
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @details Запись вида protected '.' payload '.' signature разбирается по
				 *          разделу 7.2.2 RFC 7515: заголовок декодируется, из него извлекается
				 *          член alg, подпись декодируется из base64url. Просмотры заголовка и
				 *          полезной нагрузки остаются указывать внутрь переданной записи
				 *
				 * \~english
				 * @brief Method of parsing a JWS compact record
				 * @param data the view of the record being parsed
				 * @return     the reason of the failure or error_t::NONE
				 * @details A record of the form protected '.' payload '.' signature is parsed
				 *          according to the section 7.2.2 of RFC 7515: the header is decoded,
				 *          the member alg is extracted from it, the signature is decoded from
				 *          base64url. The views of the header and of the payload keep pointing
				 *          inside the record passed
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
				 * @brief Метод извлечения алгоритма подписи
				 *
				 * @return алгоритм подписи из заголовка записи
				 *
				 * \~english
				 * @brief Method of getting the signature algorithm
				 * @return the signature algorithm from the header of the record
				 *
				 * \~
				 */
				algorithm_t algorithm() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения текста заголовка
				 *
				 * @return разобранный текст заголовка JSON
				 *
				 * \~english
				 * @brief Method of getting the text of the header
				 * @return the parsed JSON text of the header
				 *
				 * \~
				 */
				const string & header() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения полезной нагрузки
				 *
				 * @param result место, в которое помещается декодированная полезная нагрузка
				 * @return       причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of getting the payload
				 * @param result the place the decoded payload is put into
				 * @return       the reason of the failure or error_t::NONE
				 *
				 * \~
				 */
				error_t payload(vector <uint8_t> & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписи
				 *
				 * @return подпись в разобранном виде
				 *
				 * \~english
				 * @brief Method of getting the signature
				 * @return the signature in the parsed form
				 *
				 * \~
				 */
				const vector <uint8_t> & sign() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки подписи записи
				 *
				 * @param key сведения об открытом ключе подписавшей стороны
				 * @return    причина отказа либо error_t::NONE
				 *
				 * @details Подписываемая запись собирается по разделу 5.1 RFC 7515:
				 *          ASCII(protected '.' payload). Подпись ECDSA несёт пару r ‖ s
				 *          по разделу 3.4 RFC 7518 и перед проверкой переводится в запись DER
				 *
				 * \~english
				 * @brief Method of the check of the signature of the record
				 * @param key the info of the public key of the side that signed
				 * @return    the reason of the failure or error_t::NONE
				 * @details The record being signed is assembled according to the section 5.1
				 *          of RFC 7515: ASCII(protected '.' payload). The ECDSA signature carries
				 *          the pair r ‖ s according to the section 3.4 of RFC 7518 and is translated
				 *          into a DER record before the check
				 *
				 * \~
				 */
				error_t verify(const keys::key_t & key) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Signature() noexcept;
		} signature_t;

		/**
		 * \~russian
		 * @brief Метод кодирования base64url
		 *
		 * @param data   просмотр кодируемых данных
		 * @param result строка, в которую помещается итог
		 *
		 * @details Кодировка по разделу 5 RFC 4648 без заполнителей: алфавит
		 *          с '-' и '_' вместо '+' и '/', как велит раздел 2 RFC 7515
		 *
		 * \~english
		 * @brief Method of the base64url encoding
		 * @param data   the view of the data being encoded
		 * @param result the string the result is put into
		 * @details The encoding according to the section 5 of RFC 4648 without the padding
		 *          characters: the alphabet with '-' and '_' instead of '+' and '/', as the
		 *          section 2 of RFC 7515 orders
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void base64url(const view_t & data, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод декодирования base64url
		 *
		 * @param text   просмотр кодируемой строки
		 * @param result место, в которое помещается итог
		 * @return       признак успешности разбора
		 *
		 * @details Заполнители отвергаются: раздел 2 RFC 7515 велит запись без них;
		 *          символы вне алфавита base64url отвергаются
		 *
		 * \~english
		 * @brief Method of the base64url decoding
		 * @param text   the view of the string being decoded
		 * @param result the place the result is put into
		 * @return       the flag of the success of the parsing
		 * @details The padding characters are rejected: the section 2 of RFC 7515 orders
		 *          the record without them; the characters outside the base64url alphabet
		 *          are rejected
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool unbase64url(const view_t & text, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод получения имени алгоритма подписи
		 *
		 * @param algorithm алгоритм подписи
		 * @return          имя алгоритма («ES256» и прочие), пустое у неустановленного
		 *
		 * \~english
		 * @brief Method of getting the name of a signature algorithm
		 * @param algorithm the signature algorithm
		 * @return          the name of the algorithm («ES256» and the others), empty at an unset one
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * name(const algorithm_t algorithm) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения алгоритма подписи по его имени
		 *
		 * @param name имя алгоритма
		 * @return     алгоритм подписи, algorithm_t::NONE у неизвестного имени
		 *
		 * \~english
		 * @brief Method of getting a signature algorithm by its name
		 * @param name the name of the algorithm
		 * @return     the signature algorithm, algorithm_t::NONE at an unknown name
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ algorithm_t algorithm(const view_t & name) noexcept;
		/**
		 * \~russian
		 * @brief Метод определения алгоритма подписи по ключу
		 *
		 * @param key сведения о ключе
		 * @return    алгоритм подписи, algorithm_t::NONE у ключа неподходящего вида
		 *
		 * @details По виду и размеру ключа выбирается алгоритм умолчания: RSA - RS256,
		 *          EC - ES256/ES384/ES512 по кривой, Ed25519 - EdDSA
		 *
		 * \~english
		 * @brief Method of the determination of the signature algorithm by the key
		 * @param key the info of the key
		 * @return    the signature algorithm, algorithm_t::NONE at a key of an unfit kind
		 * @details By the kind and the size of the key the default algorithm is chosen:
		 *          RSA - RS256, EC - ES256/ES384/ES512 by the curve, Ed25519 - EdDSA
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ algorithm_t algorithm(const keys::key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Метод определения алгоритма подписи по подготовленному ключу
		 *
		 * @param signer подготовленный секретный ключ подписи
		 * @return       алгоритм подписи, algorithm_t::NONE у ключа неподходящего вида
		 *
		 * \~english
		 * @brief Method of the determination of the signature algorithm by the prepared key
		 * @param signer the prepared secret signature key
		 * @return       the signature algorithm, algorithm_t::NONE at a key of an unfit kind
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ algorithm_t algorithm(const keys::signer_t & signer) noexcept;

		/**
		 * \~russian
		 * @brief Метод сборки компактной записи JWS
		 *
		 * @param algorithm алгоритм подписи
		 * @param header    текст заголовка JSON целиком (без alg: он вписывается сам)
		 * @param payload   полезная нагрузка
		 * @param signer    подготовленный секретный ключ подписи
		 * @param result    строка, в которую помещается запись
		 *
		 * @return          причина отказа либо error_t::NONE
		 *
		 * @details Запись собирается по разделу 7.2.1 RFC 7515: заголовок дополняется
		 *          членом alg, кодируется в base64url, подписывается запись
		 *          ASCII(protected '.' payload), подпись кодируется в base64url.
		 *          Подпись ECDSA переводится из записи DER в пару r ‖ s размером
		 *          в удвоенное число кривой по разделу 3.4 RFC 7518
		 *
		 * \~english
		 * @brief Method of assembling a JWS compact record
		 * @param algorithm the signature algorithm
		 * @param header    the text of the JSON header as a whole (without alg: it is written in by itself)
		 * @param payload   the payload
		 * @param signer    the prepared secret signature key
		 * @param result    the string the record is put into
		 * @return          the reason of the failure or error_t::NONE
		 * @details The record is assembled according to the section 7.2.1 of RFC 7515: the
		 *          header is complemented with the member alg, encoded into base64url, the
		 *          record ASCII(protected '.' payload) is signed, the signature is encoded
		 *          into base64url. The ECDSA signature is translated from the DER record into
		 *          the pair r ‖ s of the size of the doubled number of the curve according to
		 *          the section 3.4 of RFC 7518
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t encode(const algorithm_t algorithm, const string & header, const view_t & payload, const keys::signer_t & signer, string & result) noexcept;

		/**
		 * \~russian
		 * @brief Метод сборки записи открытого ключа JWK
		 *
		 * @param key    сведения об открытом ключе
		 * @param result строка, в которую помещается текст JSON
		 * @return       причина отказа либо error_t::NONE
		 *
		 * @details Запись по RFC 7517 с членами по RFC 7518 и RFC 8037: у RSA - kty,
		 *          n, e; у EC - kty, crv, x, y; у Ed25519 - kty, crv, x. Числа кодируются
		 *          в base64url порядком от старшего байта без ведущих нулей, координаты -
		 *          дополненные до размера кривой
		 *
		 * \~english
		 * @brief Method of assembling a JWK public key record
		 * @param key    the info of the public key
		 * @param result the string the JSON text is put into
		 * @return       the reason of the failure or error_t::NONE
		 * @details The record according to RFC 7517 with the members according to RFC 7518
		 *          and RFC 8037: at RSA - kty, n, e; at EC - kty, crv, x, y; at Ed25519 - kty,
		 *          crv, x. The numbers are encoded into base64url in the order from the senior
		 *          byte without the leading zeros, the coordinates - padded to the size of the curve
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t jwk(const keys::key_t & key, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора записи открытого ключа JWK
		 *
		 * @param text   просмотр текста JSON
		 * @param result ключ, в который помещается итог разбора
		 * @return       причина отказа либо error_t::NONE
		 *
		 * @details Разбираются записи RSA (kty, n, e), EC (kty, crv, x, y с кривыми
		 *          P-256, P-384, P-521) и Ed25519 (kty, crv, x). Члены, чужие виду
		 *          ключа, отвергаются
		 *
		 * \~english
		 * @brief Method of parsing a JWK public key record
		 * @param text   the view of the JSON text
		 * @param result the key the result of the parsing is put into
		 * @return       the reason of the failure or error_t::NONE
		 * @details The records RSA (kty, n, e), EC (kty, crv, x, y with the curves P-256,
		 *          P-384, P-521) and Ed25519 (kty, crv, x) are parsed. The members foreign
		 *          to the kind of the key are rejected
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t unjwk(const view_t & text, keys::key_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки отпечатка открытого ключа JWK
		 *
		 * @param key    сведения об открытом ключе
		 * @param result строка, в которую помещается отпечаток в base64url
		 * @return       причина отказа либо error_t::NONE
		 *
		 * @details Отпечаток по разделу 3 RFC 7638: SHA-256 от канонического текста JSON
		 *          с обязательными членами в порядке словаря, записанный в base64url.
		 *          Отпечаток ключа учётной записи лежит в основе привязки ACME
		 *
		 * \~english
		 * @brief Method of the production of the JWK public key thumbprint
		 * @param key    the info of the public key
		 * @param result the string the thumbprint in base64url is put into
		 * @return       the reason of the failure or error_t::NONE
		 * @details The thumbprint according to the section 3 of RFC 7638: SHA-256 of the
		 *          canonical JSON text with the required members in the lexicographic order,
		 *          written in base64url. The thumbprint of the account key lies at the heart
		 *          of the ACME binding
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t thumbprint(const keys::key_t & key, string & result) noexcept;
	}
}

