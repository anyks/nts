/**
 * @file ocsp.hpp
 * @date 2026-09-04
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
 * @brief Заголовочный файл модуля состояния сертификата по RFC 6960 — разбор ответа
 *        OCSP, его проверка против сертификата и издателя, составление запроса и
 *        извлечение адреса ответчика из сертификата
 *
 * \~english
 * @brief Header file of the module of the certificate status according to RFC 6960 —
 *        parsing of an OCSP response, its check against the certificate and the issuer,
 *        composition of a request and extraction of the address of the responder from a certificate
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
#include <asn1/asn1.hpp>
#include <x509/x509.hpp>
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
	 * @brief Пространство имён модуля состояния сертификата OCSP
	 *
	 * @details Модуль ввода и вывода не ведёт вовсе: ответ ответчика получает и подаёт
	 *          октетами потребитель, а модуль его разбирает, проверяет и отдаёт
	 *          состояние сертификата. Разбор идёт по RFC 6960 поверх модуля ASN.1 и, как
	 *          и он, ничего не копирует сверх необходимого: двоичные поля отдаются
	 *          просмотром внутрь разбираемой записи, и время жизни записи обязан
	 *          обеспечить вызывающий.
	 *
	 *          Часов модуль не читает: миг проверки подаётся ему доводом, иначе проверку
	 *          нельзя было бы ни повторить, ни проверить.
	 *
	 * \~english
	 * @brief Namespace of the module of the certificate status OCSP
	 * @details The module does not lead the input and the output at all: the response of the
	 *          responder is obtained and given as octets by the consumer, and the module parses
	 *          it, checks it and gives out the status of the certificate. The parsing follows
	 *          RFC 6960 on top of the ASN.1 module and, like it, copies nothing beyond the
	 *          necessary: the binary fields are given out as views inside the encoding being
	 *          parsed, and the lifetime of the encoding is up to the caller.
	 *          The module does not read the clock: the moment of the check is given to it by an
	 *          argument, otherwise the check could be neither repeated nor checked.
	 *
	 * \~
	 *
	 */
	namespace ocsp {
		/**
		 * \~russian
		 * @brief Предел давности мига верности ответа без обещанного срока, в секундах
		 *
		 * @details Раздел 4.2.2.1 RFC 6960: без nextUpdate свежесть ответа судит клиент;
		 *          ответ старше десяти суток негоден - иначе перехваченный ответ «good»
		 *          воспроизводился бы годами
		 *
		 * \~english
		 * @brief Limit of the age of the moment of the validity of a response without a promised term, in seconds
		 * @details The section 4.2.2.1 of RFC 6960: without nextUpdate the freshness of the response is
		 *          judged by the client; a response older than ten days is unfit - otherwise an intercepted
		 *          "good" response would be replayed for years
		 *
		 * \~
		 */
		static constexpr int64_t OCSP_STALE = (10 * 24 * 60 * 60);

		/**
		 * \~russian
		 * @brief Причина отказа разбора либо проверки ответа
		 *
		 * \~english
		 * @brief Reason of a failure of the parsing or of the check of a response
		 *
		 * \~
		 *
		 */
		enum class error_t : uint8_t {
			NONE      = 0x00, /*!< \~russian Отказа не произошло \~english No failure has occurred \~ */
			ENCODING  = 0x01, /*!< \~russian Запись не отвечает правилам кодировки DER \~english The record does not meet the rules of the DER encoding \~ */
			STRUCTURE = 0x02, /*!< \~russian Состав записи не отвечает устройству ответа либо запроса \~english The composition of the record does not meet the structure of a response or of a request \~ */
			VERSION   = 0x03, /*!< \~russian Издание ответа не поддерживается либо записано неверно \~english The version of the response is not supported or is written incorrectly \~ */
			STATUS    = 0x04, /*!< \~russian Ответчик ответил отказом вместо ответа \~english The responder answered with a refusal instead of a response \~ */
			TIME      = 0x05, /*!< \~russian Метка времени записана неверно \~english A time stamp is written incorrectly \~ */
			HASH      = 0x06, /*!< \~russian Алгоритм хеша опознавателя сертификата не поддерживается \~english The hash algorithm of the certificate identifier is not supported \~ */
			KEY       = 0x07, /*!< \~russian Сертификат либо издатель разобрать не удалось \~english It was not possible to parse the certificate or the issuer \~ */
			MEMORY    = 0x08, /*!< \~russian Не удалось выделить память под разобранные сведения \~english It was not possible to allocate memory for the parsed information \~ */
			SIGNATURE = 0x09, /*!< \~russian Подпись ответчика не сошлась либо непригодна для проверки \~english The signature of the responder has not converged or is unsuitable for the check \~ */
			RESPONDER = 0x0A, /*!< \~russian Подписавшая сторона ответчиком за сертификат быть не вправе \~english The side that signed is not entitled to be the responder for the certificate \~ */
			IDENTITY  = 0x0B, /*!< \~russian Ответ относится не к проверяемому сертификату \~english The response relates not to the certificate being checked \~ */
			EXPIRED   = 0x0C, /*!< \~russian Срок ответа на этот миг не идёт \~english The validity of the response does not go at this moment \~ */
			NONCE     = 0x0D, /*!< \~russian Неповторимое значение ответа с запрошенным разошлось \~english The nonce of the response has diverged with the requested one \~ */
			EXTENSION = 0x0E, /*!< \~russian Расширение записано неверно \~english The extension is written incorrectly \~ */
			WEAK      = 0x0F  /*!< \~russian Подпись ответа хешем MD5/SHA-1 либо ключ подписавшего RSA короче 2048 разрядов: стойкости на звено доверия недостаёт (RFC 9155, SP 800-131A), политика та же, что у цепочки \~english The response is signed with an MD5/SHA-1 hash or the key of the signer is RSA shorter than 2048 bits: the strength does not suffice for a link of the trust (RFC 9155, SP 800-131A), the policy is the same as for a chain \~ */
		};

		/**
		 * \~russian
		 * @brief Исход обращения к ответчику
		 *
		 * @details Значения отвечают перечислению OCSPResponseStatus раздела 4.2.1 RFC 6960
		 *
		 * \~english
		 * @brief Outcome of the appeal to the responder
		 * @details The values correspond to the OCSPResponseStatus enumeration of the section 4.2.1 of RFC 6960
		 *
		 * \~
		 *
		 */
		enum class outcome_t : uint8_t {
			SUCCESSFUL   = 0x00, /*!< \~russian Ответ получен \~english The response is obtained \~ */
			MALFORMED    = 0x01, /*!< \~russian Запрос сложен не по правилам \~english The request is composed not by the rules \~ */
			INTERNAL     = 0x02, /*!< \~russian Внутренний отказ ответчика \~english An internal failure of the responder \~ */
			LATER        = 0x03, /*!< \~russian Ответчик просит обратиться позже \~english The responder asks to appeal later \~ */
			UNSIGNED     = 0x05, /*!< \~russian Ответчик требует подписанный запрос \~english The responder requires a signed request \~ */
			UNAUTHORIZED = 0x06  /*!< \~russian Запросу отказано в праве \~english The request is refused the right \~ */
		};

		/**
		 * \~russian
		 * @brief Состояние сертификата
		 *
		 * @details Значения отвечают меткам выбора CertStatus раздела 4.2.1 RFC 6960
		 *
		 * \~english
		 * @brief Status of a certificate
		 * @details The values correspond to the choice tags of CertStatus of the section 4.2.1 of RFC 6960
		 *
		 * \~
		 *
		 */
		enum class status_t : uint8_t {
			GOOD    = 0x00, /*!< \~russian Сертификат не отозван \~english The certificate is not revoked \~ */
			REVOKED = 0x01, /*!< \~russian Сертификат отозван \~english The certificate is revoked \~ */
			UNKNOWN = 0x02, /*!< \~russian Сертификат ответчику неведом \~english The certificate is unknown to the responder \~ */
			NONE    = 0xFF  /*!< \~russian Состояние не установлено: ответа нет либо он не проверялся \~english The status is not set: there is no response or it was not checked \~ */
		};

		/**
		 * \~russian
		 * @brief Опознаватель сертификата
		 *
		 * @details Запись CertID раздела 4.1.1 RFC 6960: сертификат опознаётся хешем имени
		 *          издателя, хешем его открытого ключа и порядковым номером
		 *
		 * \~english
		 * @brief Identifier of a certificate
		 * @details The CertID record of the section 4.1.1 of RFC 6960: a certificate is identified by the
		 *          hash of the name of the issuer, by the hash of its public key and by the serial number
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Identifier {
			// Опознаватель алгоритма хеша
			string algorithm;
			// Просмотр хеша имени издателя
			view_t name;
			// Просмотр хеша открытого ключа издателя
			view_t key;
			// Просмотр порядкового номера сертификата
			view_t serial;
		} identifier_t;

		/**
		 * \~russian
		 * @brief Ответ по одному сертификату
		 *
		 * @details Запись SingleResponse раздела 4.2.1 RFC 6960
		 *
		 * \~english
		 * @brief Response about a single certificate
		 * @details The SingleResponse record of the section 4.2.1 of RFC 6960
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Single {
			// Опознаватель сертификата
			identifier_t identifier;
			// Состояние сертификата
			status_t status;
			// Миг отзыва сертификата в секундах от начала эпохи, ноль у неотозванного
			int64_t revocation;
			// Миг, на который состояние заведомо верно
			int64_t updated;
			// Миг, до которого состояние обещано верным, ноль без обещания
			int64_t next;
			// Набор расширений ответа по сертификату
			vector <x509::extension_t> extensions;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Single() noexcept : status(status_t::NONE), revocation(0), updated(0), next(0) {}
		} single_t;

		/**
		 * \~russian
		 * @brief Ответ OCSP
		 *
		 * @details Объект хранит разобранные сведения ответа и просмотры внутрь разбираемой
		 *          записи. Запись обязана пережить объект. Разбирается запись OCSPResponse
		 *          с вложенной BasicOCSPResponse раздела 4.2.1 RFC 6960; иные виды ответа
		 *          отвергаются
		 *
		 * \~english
		 * @brief OCSP response
		 * @details The object keeps the parsed info of the response and the views inside the encoding
		 *          being parsed. The encoding must outlive the object. The OCSPResponse record with the
		 *          nested BasicOCSPResponse of the section 4.2.1 of RFC 6960 is parsed; other kinds of
		 *          the response are rejected
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Response {
			private:
				// Причина последнего отказа
				error_t _error;
				// Исход обращения к ответчику
				outcome_t _outcome;
			private:
				// Просмотр записи ответа целиком
				view_t _element;
				// Просмотр подписываемой части ответа
				view_t _body;
			private:
				// Опознаватель алгоритма подписи ответчика
				string _algorithm;
				// Просмотр записи настроек алгоритма подписи
				view_t _parameters;
				// Просмотр записи подписи
				view_t _signature;
				// Число неиспользуемых разрядов последнего байта подписи
				uint8_t _unused;
			private:
				// Признак того, что ответчик назван хешем ключа, а не именем
				bool _hashed;
				// Просмотр записи опознавателя ответчика: имени либо хеша ключа
				view_t _responder;
			private:
				// Миг составления ответа в секундах от начала эпохи
				int64_t _produced;
			private:
				// Ответы по сертификатам
				vector <single_t> _responses;
				// Набор расширений ответа
				vector <x509::extension_t> _extensions;
				// Сертификаты, приложенные ответчиком
				vector <view_t> _certificates;
			private:
				/**
				 * @brief Метод разбора ответа по одному сертификату
				 *
				 * @param element элемент записи ответа по сертификату
				 * @param result  ответ, в который производится разбор
				 * @return        причина отказа либо error_t::NONE
				 *
				 */
				error_t single(const asn1::element_t & element, single_t & result) noexcept;
				/**
				 * @brief Метод разбора подписываемой части ответа
				 *
				 * @param element элемент записи подписываемой части
				 * @return        причина отказа либо error_t::NONE
				 *
				 */
				error_t content(const asn1::element_t & element) noexcept;
				/**
				 * @brief Метод разбора основного ответа
				 *
				 * @param data просмотр записи основного ответа
				 * @return     причина отказа либо error_t::NONE
				 *
				 */
				error_t basic(const view_t & data) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи ответа
				 *
				 * @param data просмотр разбираемой записи ответа
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект ответа
				 * @note Отказ ответчика (исход не SUCCESSFUL) разбирается успешно: исход
				 *       доступен вызовом outcome, а ответов по сертификатам у него нет
				 *
				 * \~english
				 * @brief Method of parsing a response encoding
				 * @param data the view of the response encoding being parsed
				 * @return     the reason of the failure or error_t::NONE
				 * @note A refusal of the responder (an outcome other than SUCCESSFUL) is parsed successfully:
				 *       the outcome is available by the call of outcome, and it has no responses about certificates
				 *
				 * \~
				 *
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
				 *
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
				 *
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения исхода обращения к ответчику
				 *
				 * @return исход обращения к ответчику
				 *
				 * \~english
				 * @brief Method of getting the outcome of the appeal to the responder
				 * @return the outcome of the appeal to the responder
				 *
				 * \~
				 *
				 */
				outcome_t outcome() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписываемой части ответа
				 *
				 * @return просмотр подписываемой части ответа
				 *
				 * \~english
				 * @brief Method of getting the signed part of the response
				 * @return the view of the signed part of the response
				 *
				 * \~
				 *
				 */
				const view_t & body() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписи ответчика
				 *
				 * @param unused число неиспользуемых разрядов последнего байта подписи
				 * @return       просмотр записи подписи
				 *
				 * \~english
				 * @brief Method of getting the signature of the responder
				 * @param unused the number of unused bits in the last byte of the signature
				 * @return       the view of the signature encoding
				 *
				 * \~
				 *
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
				 *
				 */
				const string & algorithms() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения записи настроек алгоритма подписи
				 *
				 * @return просмотр записи настроек алгоритма подписи либо пустой просмотр
				 *
				 * \~english
				 * @brief Method of getting the record of the settings of the signature algorithm
				 * @return the view of the record of the settings of the signature algorithm or an empty view
				 *
				 * \~
				 *
				 */
				const view_t & parameters() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя ответчика
				 *
				 * @param hashed признак того, что ответчик назван хешем ключа, а не именем
				 * @return       просмотр записи имени ответчика либо хеша его ключа
				 *
				 * \~english
				 * @brief Method of getting the identifier of the responder
				 * @param hashed the flag that the responder is named by the hash of the key rather than by the name
				 * @return       the view of the record of the name of the responder or of the hash of its key
				 *
				 * \~
				 *
				 */
				const view_t & responder(bool & hashed) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения мига составления ответа
				 *
				 * @return миг составления ответа в секундах от начала эпохи
				 *
				 * \~english
				 * @brief Method of getting the moment of the production of the response
				 * @return the moment of the production of the response in seconds since the epoch
				 *
				 * \~
				 *
				 */
				int64_t produced() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения ответов по сертификатам
				 *
				 * @return ответы по сертификатам
				 *
				 * \~english
				 * @brief Method of getting the responses about the certificates
				 * @return the responses about the certificates
				 *
				 * \~
				 *
				 */
				const vector <single_t> & responses() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора расширений ответа
				 *
				 * @return набор расширений ответа
				 *
				 * \~english
				 * @brief Method of getting the set of the extensions of the response
				 * @return the set of the extensions of the response
				 *
				 * \~
				 *
				 */
				const vector <x509::extension_t> & extension() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения сертификатов, приложенных ответчиком
				 *
				 * @return просмотры записей приложенных сертификатов
				 *
				 * \~english
				 * @brief Method of getting the certificates attached by the responder
				 * @return the views of the records of the attached certificates
				 *
				 * \~
				 *
				 */
				const vector <view_t> & certificates() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор ответа
				 *
				 * \~english
				 * @brief Constructor of a response
				 *
				 * \~
				 *
				 */
				Response() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 *
				 */
				~Response() noexcept {}
		} response_t;

		/**
		 * \~russian
		 * @brief Метод извлечения неповторимого значения из набора расширений
		 *
		 * @param extensions набор расширений ответа либо ответа по сертификату
		 * @param result     просмотр, в который помещается неповторимое значение
		 * @return           причина отказа либо error_t::NONE
		 *
		 * @details Раздел 4.4.1 RFC 6960 и RFC 8954: значение лежит строкой байтов внутри
		 *          содержимого расширения с опознавателем 1.3.6.1.5.5.7.48.1.2. Отсутствие
		 *          расширения отказом не считается: просмотр остаётся пустым
		 *
		 * \~english
		 * @brief Method of getting the nonce from a set of extensions
		 * @param extensions the set of the extensions of the response or of the single response
		 * @param result     the view the nonce is put into
		 * @return           the reason of the failure or error_t::NONE
		 * @details The section 4.4.1 of RFC 6960 and RFC 8954: the value lies as an octet string inside
		 *          the content of the extension with the identifier 1.3.6.1.5.5.7.48.1.2. The absence of
		 *          the extension is not considered a failure: the view stays empty
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t nonce(const vector <x509::extension_t> & extensions, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки ответа против сертификата и его издателя
		 *
		 * @param response    разобранный ответ ответчика
		 * @param certificate запись проверяемого сертификата
		 * @param issuer      запись сертификата издателя проверяемого сертификата
		 * @param moment      миг проверки в секундах от начала эпохи, ноль сроки не судит
		 * @param leeway      дозволенный люфт сроков в секундах в обе стороны
		 * @param nonce       ожидаемое неповторимое значение либо пустой просмотр
		 * @param result      место, в которое помещается состояние сертификата
		 * @return            причина отказа либо error_t::NONE
		 *
		 * @details Проверяются: исход обращения (STATUS), наличие ответа с опознавателем
		 *          проверяемого сертификата — хеши имени и ключа издателя по объявленному
		 *          алгоритму и порядковый номер (IDENTITY), подпись ответчика (SIGNATURE) и
		 *          его право отвечать (RESPONDER): ответчиком вправе быть сам издатель либо
		 *          сторона из приложенных сертификатов с расширенным назначением ключа
		 *          id-kp-OCSPSigning, изданная тем же издателем и действующая на миг
		 *          проверки (раздел 4.2.2.2 RFC 6960), сроки thisUpdate и nextUpdate с
		 *          люфтом (EXPIRED, раздел 4.2.2.1) и неповторимое значение (NONCE)
		 *
		 * @note Состояние сертификата отказом не считается: отозванный сертификат — это
		 *       успешно проверенный ответ с состоянием REVOKED, и решение о связи
		 *       принимает вызывающий
		 *
		 * \~english
		 * @brief Method of the check of a response against a certificate and its issuer
		 * @param response    the parsed response of the responder
		 * @param certificate the record of the certificate being checked
		 * @param issuer      the record of the certificate of the issuer of the certificate being checked
		 * @param moment      the moment of the check in seconds since the epoch, zero does not judge the validity
		 * @param leeway      the allowed slack of the validity in seconds in both directions
		 * @param nonce       the expected nonce or an empty view
		 * @param result      the place the status of the certificate is put into
		 * @return            the reason of the failure or error_t::NONE
		 * @details The following are checked: the outcome of the appeal (STATUS), the presence of a response
		 *          with the identifier of the certificate being checked — the hashes of the name and of the key
		 *          of the issuer by the declared algorithm and the serial number (IDENTITY), the signature of
		 *          the responder (SIGNATURE) and its right to respond (RESPONDER): the responder may be the
		 *          issuer itself or a side from the attached certificates with the extended key usage
		 *          id-kp-OCSPSigning issued by the same issuer and valid at the moment of the check (the
		 *          section 4.2.2.2 of RFC 6960), the validity thisUpdate and nextUpdate with the slack
		 *          (EXPIRED, the section 4.2.2.1) and the nonce (NONCE)
		 * @note The status of the certificate is not considered a failure: a revoked certificate is a
		 *       successfully checked response with the status REVOKED, and the decision about the connection
		 *       is made by the caller
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const response_t & response, const view_t & certificate, const view_t & issuer, const int64_t moment, const int64_t leeway, const view_t & nonce, status_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки ответов о состоянии сертификатов цепочки по местам
		 *
		 * @param chain   цепочка сертификатов собеседника от листа к издателю
		 * @param status  запись принятого ответа OCSP листа цепочки либо пустой накопитель
		 * @param statuses записи принятых ответов OCSP иных записей цепочки по их местам, пустой элемент - нет ответа; место листа не занято
		 * @param anchors записи доверенных сертификатов запаса для розыска издателя
		 * @param moment  миг проверки в секундах от начала эпохи, ноль сроки не судит
		 * @param leeway  дозволенный люфт сроков в секундах в обе стороны
		 * @param results место, в которое помещаются состояния сертификатов по местам
		 * @return        причина первого отказа либо error_t::NONE
		 *
		 * @details RFC 8446 §4.4.2.1: status_request в каждом CertificateEntry, ответ
		 *          относится к сертификату своей записи. Ответ листа подаётся отдельно:
		 *          связь хранит его раздельно от ответов иных записей (вызов status у
		 *          client и server против мест в statuses). Для каждого места с непустым
		 *          ответом издатель разыскивается по имени сперва в остальных звеньях
		 *          цепочки, потом - самим сертификатом, если он самоподписанный, и в
		 *          запасе доверенных; ответ проверяется вызовом проверки против
		 *          сертификата и издателя. Состояния мест без ответа остаются NONE
		 *
		 * @note Состояние сертификата отказом не считается: отозванное звено - это
		 *       успешно проверенный ответ с состоянием REVOKED, и решение о связи
		 *       принимает вызывающий
		 *
		 * \~english
		 * @brief Method of the check of the responses about the status of the certificates of a chain by the places
		 * @param chain   the chain of the certificates of the peer from the leaf to the issuer
		 * @param status  the received OCSP response of the leaf of the chain or an empty accumulator
		 * @param statuses the received OCSP responses of the other entries of the chain by the places, an empty element - no response
		 * @param anchors the records of the trusted certificates of the store for the search of the issuer
		 * @param moment  the moment of the check in seconds since the epoch, zero does not judge the validity
		 * @param leeway  the allowed slack of the validity in seconds in both directions
		 * @param results the place the statuses of the certificates are put into by the places
		 * @return        the reason of the first failure or error_t::NONE
		 * @details RFC 8446 §4.4.2.1: status_request in each CertificateEntry, the response refers to
		 *          the certificate of its entry. The response of the leaf is given separately: the
		 *          connection keeps it apart from the responses of the other entries (the call status
		 *          at client and server versus the places in statuses). For each place with a non-empty
		 *          response the issuer is searched by the name first in the other links of the chain,
		 *          then by the certificate itself if it is self-signed, and in the store of the trusted
		 *          ones; the response is checked by the call of the check against the certificate and
		 *          the issuer. The statuses of the places without a response stay NONE
		 * @note The status of a certificate is not considered a failure: a revoked link is a successfully
		 *       checked response with the status REVOKED, and the decision about the connection is made
		 *       by the caller
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const vector <vector <uint8_t>> & chain, const vector <uint8_t> & status, const vector <vector <uint8_t>> & statuses, const vector <vector <uint8_t>> & anchors, const int64_t moment, const int64_t leeway, vector <status_t> & results) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления запроса состояния сертификата
		 *
		 * @param certificate запись сертификата, состояние которого запрашивается
		 * @param issuer      запись сертификата издателя
		 * @param algorithm   алгоритм хеша опознавателя сертификата
		 * @param nonce       неповторимое значение запроса либо пустой просмотр
		 * @param result      накопитель, в который помещается запись запроса
		 * @return            причина отказа либо error_t::NONE
		 *
		 * @details Раздел 4.1 RFC 6960: запись OCSPRequest без подписи с одним опознавателем
		 *          сертификата; неповторимое значение идёт расширением запроса по RFC 8954
		 *
		 * \~english
		 * @brief Method of the composition of a request of the status of a certificate
		 * @param certificate the record of the certificate whose status is requested
		 * @param issuer      the record of the certificate of the issuer
		 * @param algorithm   the hash algorithm of the certificate identifier
		 * @param nonce       the nonce of the request or an empty view
		 * @param result      the accumulator the record of the request is put into
		 * @return            the reason of the failure or error_t::NONE
		 * @details The section 4.1 of RFC 6960: the OCSPRequest record without a signature with a single
		 *          certificate identifier; the nonce goes as an extension of the request according to RFC 8954
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t request(const view_t & certificate, const view_t & issuer, const digest::hash_t algorithm, const view_t & nonce, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения адреса ответчика из сертификата
		 *
		 * @param certificate запись сертификата
		 * @param result      строка, в которую помещается адрес ответчика
		 * @return            причина отказа либо error_t::NONE
		 *
		 * @details Раздел 4.2.2.1 RFC 5280: адрес берётся из расширения сведений о доступе
		 *          к издателю по способу id-ad-ocsp (1.3.6.1.5.5.7.48.1) с адресом вида
		 *          единого указателя ресурса. Отсутствие адреса отказом не считается:
		 *          строка остаётся пустой
		 *
		 * \~english
		 * @brief Method of getting the address of the responder from a certificate
		 * @param certificate the record of the certificate
		 * @param result      the string the address of the responder is put into
		 * @return            the reason of the failure or error_t::NONE
		 * @details The section 4.2.2.1 of RFC 5280: the address is taken from the authority information
		 *          access extension by the method id-ad-ocsp (1.3.6.1.5.5.7.48.1) with an address of the
		 *          kind of a uniform resource identifier. The absence of the address is not considered a
		 *          failure: the string stays empty
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t responder(const view_t & certificate, string & result) noexcept;
	};
};

