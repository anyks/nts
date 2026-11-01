/**
 * @file cmp.hpp
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
 * @brief Заголовочный файл модуля CMP — разбор и сборка сообщений управления
 *        сертификатами по RFC 4210 без применения исключений
 *
 * \~english
 * @brief Header file of the CMP module — parsing and building of certificate
 *        management protocol messages according to RFC 4210 without the use of exceptions
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
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <digest/hash.hpp>
#include <keys/keys.hpp>
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
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модуля протокола управления сертификатами
	 *
	 * @details Модуль разбирает и собирает записи PKIMessage по RFC 4210: заголовок
	 *          PKIHeader, тело PKIBody всех видов (запросы ir/cr/kur/krr/ccr, ответы
	 *          ip/cp/kup/krp/ccp, запрос PKCS #10 p10cr, подтверждения certConf/pkiConf,
	 *          отзыв rr/rp, объявления ckuann/cann/rann/crlann, общие genm/genp, отказ
	 *          error, опрос pollReq/pollRep, вызовы подтверждения владения popdecc/popdecr,
	 *          вложение nested), защита подписью ключом keys::signer_t и парольной
	 *          имитовставкой PBM по разделу 5.1.3.1. Транспортом (HTTP) модуль не
	 *          занимается: запись приходит просмотром и уходит набором байтов.
	 *
	 * \~english
	 * @brief Namespace of the certificate management protocol module
	 *
	 * @details The module parses and builds PKIMessage records according to RFC 4210:
	 *          the PKIHeader header, the PKIBody body of all kinds (requests
	 *          ir/cr/kur/krr/ccr, responses ip/cp/kup/krp/ccp, the PKCS #10 request
	 *          p10cr, confirmations certConf/pkiConf, revocation rr/rp, announcements
	 *          ckuann/cann/rann/crlann, general genm/genp, the error failure, polling
	 *          pollReq/pollRep, proof-of-possession challenges popdecc/popdecr, the
	 *          nesting nested), the protection by a signature with a keys::signer_t
	 *          key and by the password-based MAC PBM according to the section 5.1.3.1.
	 *          The module does not deal with the transport (HTTP): the record comes
	 *          as a view and leaves as a byte array.
	 *
	 * \~
	 */
	namespace cmp {
		/**
		 * \~russian
		 * @brief Причина отказа работы модуля
		 *
		 * \~english
		 * @brief Reason of a failure of the module work
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			// Отказа нет, работа удалась
			NONE       = 0x00, /*!< \~russian Отказа нет, работа удалась \~english There is no failure, the work has succeeded \~ */
			// Запись, ключ либо пароль не установлены
			EMPTY      = 0x01, /*!< \~russian Запись, ключ либо пароль не установлены \~english The record, the key or the password is not set \~ */
			// Запись не отвечает устройству своего вида
			STRUCTURE  = 0x02, /*!< \~russian Запись не отвечает устройству своего вида \~english The record does not meet the structure of its kind \~ */
			// Издание протокола не поддерживается
			VERSION    = 0x03, /*!< \~russian Издание протокола не поддерживается \~english The protocol version is not supported \~ */
			// Алгоритм защиты, хеша либо подписи неизвестен
			ALGORITHM  = 0x04, /*!< \~russian Алгоритм защиты, хеша либо подписи неизвестен \~english The algorithm of the protection, the hash or the signature is unknown \~ */
			// Защита не сошлась либо непригодна для проверки
			PROTECTION = 0x05, /*!< \~russian Защита не сошлась либо непригодна для проверки \~english The protection has not converged or is unsuitable for the check \~ */
			// Ключ чужого алгоритма либо не несёт нужной части
			KEY        = 0x06, /*!< \~russian Ключ чужого алгоритма либо не несёт нужной части \~english The key is of a foreign algorithm or does not carry the needed part \~ */
			// Случайные байты выработать не удалось
			RANDOM     = 0x07, /*!< \~russian Случайные байты выработать не удалось \~english Failed to produce the random bytes \~ */
			// Не удалось выделить память под итог работы
			MEMORY     = 0x08  /*!< \~russian Не удалось выделить память под итог работы \~english Failed to allocate the memory for the result of the work \~ */
		};

		/**
		 * \~russian
		 * @brief Вид тела сообщения PKIBody
		 *
		 * @details Номера видов повторяют номера меток выбора PKIBody по разделу 5.1.2
		 *          RFC 4210: тело ir несёт метку [0], тело pollRep - метку [26].
		 *
		 * \~english
		 * @brief Kind of the PKIBody message body
		 *
		 * @details The numbers of the kinds repeat the numbers of the PKIBody choice
		 *          tags according to the section 5.1.2 of RFC 4210: the ir body carries
		 *          the [0] tag, the pollRep body carries the [26] tag.
		 *
		 * \~
		 */
		enum class body_t : uint8_t {
			// Запись не разобрана
			NONE     = 0xFF, /*!< \~russian Запись не разобрана \~english The record is not parsed \~ */
			// Запрос инициализации [0] CertReqMessages
			IR       = 0x00, /*!< \~russian Запрос инициализации [0] CertReqMessages \~english Initialization request [0] CertReqMessages \~ */
			// Ответ инициализации [1] CertRepMessage
			IP       = 0x01, /*!< \~russian Ответ инициализации [1] CertRepMessage \~english Initialization response [1] CertRepMessage \~ */
			// Запрос сертификата [2] CertReqMessages
			CR       = 0x02, /*!< \~russian Запрос сертификата [2] CertReqMessages \~english Certification request [2] CertReqMessages \~ */
			// Ответ сертификата [3] CertRepMessage
			CP       = 0x03, /*!< \~russian Ответ сертификата [3] CertRepMessage \~english Certification response [3] CertRepMessage \~ */
			// Запрос PKCS #10 [4] CertificationRequest
			P10CR    = 0x04, /*!< \~russian Запрос PKCS #10 [4] CertificationRequest \~english PKCS #10 request [4] CertificationRequest \~ */
			// Вызов подтверждения владения [5] POPODecKeyChallContent
			POPDECC  = 0x05, /*!< \~russian Вызов подтверждения владения [5] POPODecKeyChallContent \~english Possession challenge [5] POPODecKeyChallContent \~ */
			// Ответ подтверждения владения [6] POPODecKeyRespContent
			POPDECR  = 0x06, /*!< \~russian Ответ подтверждения владения [6] POPODecKeyRespContent \~english Possession response [6] POPODecKeyRespContent \~ */
			// Запрос обновления ключа [7] CertReqMessages
			KUR      = 0x07, /*!< \~russian Запрос обновления ключа [7] CertReqMessages \~english Key update request [7] CertReqMessages \~ */
			// Ответ обновления ключа [8] CertRepMessage
			KUP      = 0x08, /*!< \~russian Ответ обновления ключа [8] CertRepMessage \~english Key update response [8] CertRepMessage \~ */
			// Запрос восстановления ключа [9] CertReqMessages
			KRR      = 0x09, /*!< \~russian Запрос восстановления ключа [9] CertReqMessages \~english Key recovery request [9] CertReqMessages \~ */
			// Ответ восстановления ключа [10] KeyRecRepContent
			KRP      = 0x0A, /*!< \~russian Ответ восстановления ключа [10] KeyRecRepContent \~english Key recovery response [10] KeyRecRepContent \~ */
			// Запрос отзыва [11] RevReqContent
			RR       = 0x0B, /*!< \~russian Запрос отзыва [11] RevReqContent \~english Revocation request [11] RevReqContent \~ */
			// Ответ отзыва [12] RevRepContent
			RP       = 0x0C, /*!< \~russian Ответ отзыва [12] RevRepContent \~english Revocation response [12] RevRepContent \~ */
			// Запрос перекрёстного сертификата [13] CertReqMessages
			CCR      = 0x0D, /*!< \~russian Запрос перекрёстного сертификата [13] CertReqMessages \~english Cross-certification request [13] CertReqMessages \~ */
			// Ответ перекрёстного сертификата [14] CertRepMessage
			CCP      = 0x0E, /*!< \~russian Ответ перекрёстного сертификата [14] CertRepMessage \~english Cross-certification response [14] CertRepMessage \~ */
			// Объявление обновления ключа ЦС [15] CAKeyUpdAnnContent
			CKUANN   = 0x0F, /*!< \~russian Объявление обновления ключа ЦС [15] CAKeyUpdAnnContent \~english CA key update announcement [15] CAKeyUpdAnnContent \~ */
			// Объявление сертификата [16] CertAnnContent
			CANN     = 0x10, /*!< \~russian Объявление сертификата [16] CertAnnContent \~english Certificate announcement [16] CertAnnContent \~ */
			// Объявление отзыва [17] RevAnnContent
			RANN     = 0x11, /*!< \~russian Объявление отзыва [17] RevAnnContent \~english Revocation announcement [17] RevAnnContent \~ */
			// Объявление списка отзыва [18] CRLAnnContent
			CRLANN   = 0x12, /*!< \~russian Объявление списка отзыва [18] CRLAnnContent \~english CRL announcement [18] CRLAnnContent \~ */
			// Подтверждение [19] PKIConfirmContent
			PKICONF  = 0x13, /*!< \~russian Подтверждение [19] PKIConfirmContent \~english Confirmation [19] PKIConfirmContent \~ */
			// Вложенные сообщения [20] NestedMessageContent
			NESTED   = 0x14, /*!< \~russian Вложенные сообщения [20] NestedMessageContent \~english Nested messages [20] NestedMessageContent \~ */
			// Общее сообщение [21] GenMsgContent
			GENM     = 0x15, /*!< \~russian Общее сообщение [21] GenMsgContent \~english General message [21] GenMsgContent \~ */
			// Общий ответ [22] GenRepContent
			GENP     = 0x16, /*!< \~russian Общий ответ [22] GenRepContent \~english General response [22] GenRepContent \~ */
			// Сообщение об отказе [23] ErrorMsgContent
			ERROR    = 0x17, /*!< \~russian Сообщение об отказе [23] ErrorMsgContent \~english Error message [23] ErrorMsgContent \~ */
			// Подтверждение сертификата [24] CertConfirmContent
			CERTCONF = 0x18, /*!< \~russian Подтверждение сертификата [24] CertConfirmContent \~english Certificate confirmation [24] CertConfirmContent \~ */
			// Запрос опроса [25] PollReqContent
			POLLREQ  = 0x19, /*!< \~russian Запрос опроса [25] PollReqContent \~english Polling request [25] PollReqContent \~ */
			// Ответ опроса [26] PollRepContent
			POLLREP  = 0x1A  /*!< \~russian Ответ опроса [26] PollRepContent \~english Polling response [26] PollRepContent \~ */
		};

		/**
		 * \~russian
		 * @brief Статус ответа PKIStatus
		 *
		 * \~english
		 * @brief Status of a PKIStatus response
		 *
		 * \~
		 */
		enum class status_t : uint8_t {
			// Принято
			ACCEPTED                = 0x00, /*!< \~russian Принято \~english Accepted \~ */
			// Выдано с изменениями
			GRANTED_WITH_MODS       = 0x01, /*!< \~russian Выдано с изменениями \~english Granted with modifications \~ */
			// Отклонено
			REJECTION               = 0x02, /*!< \~russian Отклонено \~english Rejected \~ */
			// Ожидание
			WAITING                 = 0x03, /*!< \~russian Ожидание \~english Waiting \~ */
			// Предупреждение об отзыве
			REVOCATION_WARNING      = 0x04, /*!< \~russian Предупреждение об отзыве \~english Revocation warning \~ */
			// Извещение об отзыве
			REVOCATION_NOTIFICATION = 0x05, /*!< \~russian Извещение об отзыве \~english Revocation notification \~ */
			// Предупреждение об обновлении ключа
			KEY_UPDATE_WARNING      = 0x06, /*!< \~russian Предупреждение об обновлении ключа \~english Key update warning \~ */
			// Статус неизвестен
			UNKNOWN                 = 0xFF  /*!< \~russian Статус неизвестен \~english The status is unknown \~ */
		};

		/**
		 * \~russian
		 * @brief Сведения о статусе PKIStatusInfo
		 *
		 * @details Строки статуса отдаются в кодировке UTF-8, сведения об отказе -
		 *          битовой строкой по разделу 5.2.3 RFC 4210 (бит 0 - badAlg, бит 26 -
		 *          duplicateCertReq).
		 *
		 * \~english
		 * @brief Info of a PKIStatusInfo status
		 *
		 * @details The status strings are given in the UTF-8 encoding, the failure info
		 *          is given as a bit string according to the section 5.2.3 of RFC 4210
		 *          (bit 0 is badAlg, bit 26 is duplicateCertReq).
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Status {
			// Статус ответа
			status_t status;
			// Строки статуса в кодировке UTF-8
			vector <string> strings;
			// Сведения об отказе: битовая строка содержимого (без байта неиспользуемых разрядов)
			vector <uint8_t> failure;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Status() noexcept;
		} status_info_t;

		/**
		 * \~russian
		 * @brief Заголовок сообщения PKIHeader
		 *
		 * @details Просмотры полей указывают внутрь разбираемой записи: запись обязана
		 *          пережить объект. Имена отправителя и получателя отдаются записями
		 *          GeneralName целиком (чаще всего directoryName [4] с именем X.501).
		 *
		 * \~english
		 * @brief Header of a PKIHeader message
		 *
		 * @details The views of the fields point inside the record being parsed: the
		 *          record must outlive the object. The names of the sender and the
		 *          recipient are given as whole GeneralName records (most often a
		 *          directoryName [4] with an X.501 name).
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Header {
			// Издание протокола (2 - cmp2000)
			int64_t pvno;
			// Просмотр записи GeneralName отправителя
			view_t sender;
			// Просмотр записи GeneralName получателя
			view_t recipient;
			// Время создания сообщения, ноль при отсутствии
			int64_t messageTime;
			// Признак наличия времени создания
			bool hasTime;
			// Опознаватель алгоритма защиты, пустой при её отсутствии
			string protection;
			// Просмотр записи настроек алгоритма защиты
			view_t parameters;
			// Просмотр опознавателя ключа отправителя senderKID
			view_t senderKID;
			// Просмотр опознавателя ключа получателя recipKID
			view_t recipKID;
			// Просмотр опознавателя сделки transactionID
			view_t transaction;
			// Просмотр метки новизны отправителя senderNonce
			view_t senderNonce;
			// Просмотр метки новизны получателя recipNonce
			view_t recipNonce;
			// Строки свободного текста freeText в кодировке UTF-8
			vector <string> text;
			// Просмотр записи общих сведений generalInfo
			view_t info;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Header() noexcept;
		} header_t;

		/**
		 * \~russian
		 * @brief Сообщение PKIMessage
		 *
		 * @details Объект хранит разобранные сведения сообщения и просмотры внутрь
		 *          разбираемой записи. Запись обязана пережить объект. Тело отдаётся
		 *          просмотром содержимого выбора PKIBody (без метки вида): его разбор
		 *          ведут свободные методы requests, response и прочие по виду тела.
		 *
		 * \~english
		 * @brief A PKIMessage message
		 *
		 * @details The object keeps the parsed info of the message and the views inside
		 *          the record being parsed. The record must outlive the object. The body
		 *          is given as a view of the content of the PKIBody choice (without the
		 *          kind tag): it is parsed by the free methods requests, response and
		 *          others according to the kind of the body.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Message {
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Вид тела сообщения
				body_t _kind;
			private:
				// Заголовок сообщения
				header_t _header;
			private:
				// Просмотр содержимого тела (без метки вида)
				view_t _body;
			private:
				// Просмотр содержимого строки битов защиты (без байта неиспользуемых разрядов)
				view_t _protection;
			private:
				// Просмотр записи защищаемой части ProtectedPart (заголовок и тело)
				view_t _protected;
			private:
				// Просмотры записей дополнительных сертификатов extraCerts
				vector <view_t> _certificates;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи PKIMessage
				 *
				 * @param data просмотр разбираемой записи
				 * @return     причина отказа либо error_t::NONE
				 *
				 * \~english
				 * @brief Method of parsing a PKIMessage record
				 *
				 * @param data the view of the record being parsed
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
				 *
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения вида тела сообщения
				 *
				 * @return вид тела, body_t::NONE у неразобранной записи
				 *
				 * \~english
				 * @brief Method of getting the kind of the message body
				 *
				 * @return the kind of the body, body_t::NONE at an unparsed record
				 *
				 * \~
				 */
				body_t kind() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод извлечения заголовка сообщения
				 *
				 * @return заголовок сообщения
				 *
				 * \~english
				 * @brief Method of getting the message header
				 *
				 * @return the message header
				 *
				 * \~
				 */
				const header_t & header() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения содержимого тела
				 *
				 * @return просмотр содержимого тела (без метки вида)
				 *
				 * \~english
				 * @brief Method of getting the body content
				 *
				 * @return the view of the body content (without the kind tag)
				 *
				 * \~
				 */
				const view_t & body() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения защиты сообщения
				 *
				 * @return просмотр содержимого строки битов защиты, пустой при её отсутствии
				 *
				 * \~english
				 * @brief Method of getting the message protection
				 *
				 * @return the view of the protection bit string content, empty at its absence
				 *
				 * \~
				 */
				const view_t & protection() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения записи защищаемой части ProtectedPart
				 *
				 * @return просмотр записи защищаемой части (заголовок и тело), пустой у неразобранной записи
				 *
				 * \~english
				 * @brief Method of getting the ProtectedPart record
				 *
				 * @return the view of the protected part record (the header and the body), empty at an unparsed record
				 *
				 * \~
				 */
				const view_t & part() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения записей дополнительных сертификатов
				 *
				 * @return просмотры записей сертификатов extraCerts
				 *
				 * \~english
				 * @brief Method of getting the extra certificate records
				 *
				 * @return the views of the extraCerts certificate records
				 *
				 * \~
				 */
				const vector <view_t> & certificates() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор сообщения
				 *
				 * \~english
				 * @brief Constructor of the message
				 *
				 * \~
				 */
				Message() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Message() noexcept;
		} message_t;

		/**
		 * \~russian
		 * @brief Запрос сертификата CertReqMsg
		 *
		 * @details Шаблон сертификата CertTemplate отдаётся просмотром записи целиком:
		 *          поля шаблона все необязательны, и вызывающий разбирает те, что
		 *          присутствуют. Просмотры указывают внутрь разбираемой записи тела.
		 *
		 * \~english
		 * @brief A CertReqMsg certificate request
		 *
		 * @details The CertTemplate certificate template is given as a view of the
		 *          whole record: the template fields are all optional, and the caller
		 *          parses the ones present. The views point inside the body record
		 *          being parsed.
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Request {
			// Опознаватель запроса certReqId
			int64_t id;
			// Просмотр записи шаблона сертификата CertTemplate
			view_t certTemplate;
			// Просмотр записи подтверждения владения ProofOfPossession, пустой при отсутствии
			view_t popo;
			// Просмотр записи регистрационных сведений regInfo, пустой при отсутствии
			view_t regInfo;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Request() noexcept;
		} request_t;

		/**
		 * \~russian
		 * @brief Ответ о сертификате CertResponse
		 *
		 * \~english
		 * @brief A CertResponse certificate response
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Response {
			// Опознаватель запроса certReqId
			int64_t id;
			// Сведения о статусе
			status_info_t status;
			// Просмотр записи сертификата (certOrEncCert.certificate [0]), пустой при отсутствии
			view_t certificate;
			// Просмотр записи зашифрованного сертификата (certOrEncCert.encryptedCert [1]), пустой при отсутствии
			view_t encrypted;
			// Просмотр записи зашифрованного секретного ключа privateKey [0], пустой при отсутствии
			view_t privateKey;
			// Просмотр содержимого rspInfo
			view_t info;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Response() noexcept;
		} response_t;

		/**
		 * \~russian
		 * @brief Пара «тип и значение» общих сведений InfoTypeAndValue
		 *
		 * \~english
		 * @brief An InfoTypeAndValue info type and value pair
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Info {
			// Опознаватель вида сведений infoType
			string oid;
			// Просмотр записи значения infoValue целиком, пустой при отсутствии
			view_t value;
		} info_t;

		/**
		 * \~russian
		 * @brief Функция разбора запросов сертификатов CertReqMessages
		 *
		 * @param body   просмотр содержимого тела (для видов ir/cr/kur/krr/ccr)
		 * @param result место, в которое помещаются запросы
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the CertReqMessages certificate requests
		 *
		 * @param body   the view of the body content (for the ir/cr/kur/krr/ccr kinds)
		 * @param result the place the requests are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t requests(const view_t & body, vector <request_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора ответа о сертификатах CertRepMessage
		 *
		 * @param body   просмотр содержимого тела (для видов ip/cp/kup/ccp)
		 * @param caPubs место, в которое помещаются просмотры записей сертификатов ЦС
		 * @param result место, в которое помещаются ответы
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the CertRepMessage certificate response
		 *
		 * @param body   the view of the body content (for the ip/cp/kup/ccp kinds)
		 * @param caPubs the place the views of the CA certificate records are put into
		 * @param result the place the responses are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t response(const view_t & body, vector <view_t> & caPubs, vector <response_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора сведений о статусе PKIStatusInfo
		 *
		 * @param element разбираемый элемент записи статуса
		 * @param result  место, в которое помещаются сведения
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the PKIStatusInfo status info
		 *
		 * @param element the element of the status record being parsed
		 * @param result  the place the info is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t statusInfo(const asn1::element_t & element, status_info_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора общих сведений GenMsgContent/GenRepContent
		 *
		 * @param body   просмотр содержимого тела (для видов genm/genp)
		 * @param result место, в которое помещаются сведения
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the GenMsgContent/GenRepContent general info
		 *
		 * @param body   the view of the body content (for the genm/genp kinds)
		 * @param result the place the info is put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t infos(const view_t & body, vector <info_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Вызов подтверждения владения Challenge
		 *
		 * \~english
		 * @brief A Challenge possession challenge
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Challenge {
			// Опознаватель алгоритма односторонней функции, пустой при отсутствии
			string owf;
			// Просмотр содержимого свидетеля witness
			view_t witness;
			// Просмотр содержимого вызова challenge
			view_t challenge;
		} challenge_t;

		/**
		 * \~russian
		 * @brief Ответ восстановления ключа KeyRecRepContent
		 *
		 * \~english
		 * @brief A KeyRecRepContent key recovery response
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Recovery {
			// Сведения о статусе
			status_info_t status;
			// Просмотр записи нового сертификата подписи newSigCert, пустой при отсутствии
			view_t certificate;
			// Просмотры записей сертификатов ЦС caCerts
			vector <view_t> caCertificates;
			// Просмотры записей пар ключей keyPairHist (CertifiedKeyPair)
			vector <view_t> history;
		} recovery_t;

		/**
		 * \~russian
		 * @brief Ответ отзыва RevRepContent
		 *
		 * \~english
		 * @brief A RevRepContent revocation response
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Revoked {
			// Сведения о статусах
			vector <status_info_t> statuses;
			// Просмотры записей опознавателей сертификатов revCerts (CertId)
			vector <view_t> certificates;
			// Просмотры записей списков отзыва crls (CertificateList)
			vector <view_t> crls;
		} revoked_t;

		/**
		 * \~russian
		 * @brief Объявление отзыва RevAnnContent
		 *
		 * \~english
		 * @brief A RevAnnContent revocation announcement
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Announcement {
			// Статус отзыва
			status_t status;
			// Просмотр записи опознавателя сертификата CertId
			view_t certificate;
			// Время занесения в список отзыва willBeRevokedAt
			int64_t willBeRevokedAt;
			// Время компрометации badSinceDate
			int64_t badSinceDate;
			// Просмотр записи расширений crlDetails, пустой при отсутствии
			view_t crlDetails;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Announcement() noexcept;
		} announcement_t;

		/**
		 * \~russian
		 * @brief Ответ опроса PollRepContent (запись одного запроса)
		 *
		 * \~english
		 * @brief A PollRepContent polling response (a single request record)
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Poll {
			// Опознаватель запроса certReqId
			int64_t id;
			// Время ожидания в секундах checkAfter (для pollRep), ноль для pollReq
			int64_t checkAfter;
			// Строки причины reason (для pollRep)
			vector <string> reason;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Poll() noexcept;
		} poll_t;

		/**
		 * \~russian
		 * @brief Функция разбора вызовов подтверждения владения POPODecKeyChallContent
		 *
		 * @param body   просмотр содержимого тела (для вида popdecc)
		 * @param result место, в которое помещаются вызовы
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the POPODecKeyChallContent possession challenges
		 *
		 * @param body   the view of the body content (for the popdecc kind)
		 * @param result the place the challenges are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t challenges(const view_t & body, vector <challenge_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора ответов подтверждения владения POPODecKeyRespContent
		 *
		 * @param body   просмотр содержимого тела (для вида popdecr)
		 * @param result место, в которое помещаются числа ответов
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the POPODecKeyRespContent possession responses
		 *
		 * @param body   the view of the body content (for the popdecr kind)
		 * @param result the place the response numbers are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t challengeAnswers(const view_t & body, vector <int64_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора ответа восстановления ключа KeyRecRepContent
		 *
		 * @param body   просмотр содержимого тела (для вида krp)
		 * @param result место, в которое помещается ответ
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the KeyRecRepContent key recovery response
		 *
		 * @param body   the view of the body content (for the krp kind)
		 * @param result the place the response is put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t recovery(const view_t & body, recovery_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора ответа отзыва RevRepContent
		 *
		 * @param body   просмотр содержимого тела (для вида rp)
		 * @param result место, в которое помещается ответ
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the RevRepContent revocation response
		 *
		 * @param body   the view of the body content (for the rp kind)
		 * @param result the place the response is put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t revoked(const view_t & body, revoked_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора объявления обновления ключа ЦС CAKeyUpdAnnContent
		 *
		 * @param body       просмотр содержимого тела (для вида ckuann)
		 * @param oldWithNew место, в которое помещается запись сертификата oldWithNew
		 * @param newWithOld место, в которое помещается запись сертификата newWithOld
		 * @param newWithNew место, в которое помещается запись сертификата newWithNew
		 * @return           причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the CAKeyUpdAnnContent CA key update announcement
		 *
		 * @param body       the view of the body content (for the ckuann kind)
		 * @param oldWithNew the place the oldWithNew certificate record is put into
		 * @param newWithOld the place the newWithOld certificate record is put into
		 * @param newWithNew the place the newWithNew certificate record is put into
		 * @return           the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t caKeyUpdate(const view_t & body, view_t & oldWithNew, view_t & newWithOld, view_t & newWithNew) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора объявления отзыва RevAnnContent
		 *
		 * @param body   просмотр содержимого тела (для вида rann)
		 * @param result место, в которое помещается объявление
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the RevAnnContent revocation announcement
		 *
		 * @param body   the view of the body content (for the rann kind)
		 * @param result the place the announcement is put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t announcement(const view_t & body, announcement_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора записей списков отзыва CRLAnnContent
		 *
		 * @param body   просмотр содержимого тела (для вида crlann)
		 * @param result место, в которое помещаются просмотры записей CertificateList
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the CRLAnnContent CRL announcement
		 *
		 * @param body   the view of the body content (for the crlann kind)
		 * @param result the place the views of the CertificateList records are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t crlAnnouncement(const view_t & body, vector <view_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора вложенных сообщений NestedMessageContent
		 *
		 * @param body   просмотр содержимого тела (для вида nested)
		 * @param result место, в которое помещаются просмотры записей PKIMessage
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the NestedMessageContent nested messages
		 *
		 * @param body   the view of the body content (for the nested kind)
		 * @param result the place the views of the PKIMessage records are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t nested(const view_t & body, vector <view_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция разбора опроса PollReqContent/PollRepContent
		 *
		 * @param body   просмотр содержимого тела (для видов pollReq/pollRep)
		 * @param result место, в которое помещаются записи опроса
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of parsing the PollReqContent/PollRepContent polling
		 *
		 * @param body   the view of the body content (for the pollReq/pollRep kinds)
		 * @param result the place the polling records are put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t poll(const view_t & body, vector <poll_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки заголовка сообщения
		 *
		 * @param sender    запись GeneralName отправителя (пустая - «NULL»-имя)
		 * @param recipient запись GeneralName получателя
		 * @param result    место, в которое помещается заголовок
		 *
		 * \~english
		 * @brief Function of building a message header
		 *
		 * @param sender    the GeneralName record of the sender (empty is the "NULL" name)
		 * @param recipient the GeneralName record of the recipient
		 * @param result    the place the header is put into
		 *
		 * \~
		 */
		/**
		 * \~russian
		 * @brief Функция сборки записи GeneralName вида directoryName
		 *
		 * @param name   запись имени X.501 (просмотр element из name_t)
		 * @param result место, в которое помещается запись GeneralName
		 * @return       причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a directoryName GeneralName record
		 *
		 * @param name   the X.501 name record (the element view of a name_t)
		 * @param result the place the GeneralName record is put into
		 * @return       the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t directoryName(const view_t & name, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения с телом запросов сертификатов
		 *
		 * @param kind      вид тела (ir/cr/kur/krr/ccr)
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param templates записи шаблонов CertTemplate (по одной на запрос, опознаватели 0, 1, ...)
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * @note Подтверждение владения ставится видом signature по разделу 5.2.8.4:
		 *       подпись ключом signer над записью CertReq, как велит примечание к
		 *       POPOSigningKey в RFC 4211 (шаблон несёт и subject, и publicKey)
		 *
		 * \~english
		 * @brief Function of building a message with a certificate requests body
		 *
		 * @param kind      the kind of the body (ir/cr/kur/krr/ccr)
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param templates the CertTemplate records (one per request, ids 0, 1, ...)
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * @note The proof of possession is made by the signature kind according to the section 5.2.8.4:
		 *       the signature with the signer key over the CertReq encoding, as the note to
		 *       POPOSigningKey in RFC 4211 orders (the template carries both subject and publicKey)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t request(const body_t kind, const view_t & sender, const view_t & recipient, const vector <view_t> & templates, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения с телом запросов сертификатов под защитой PBM
		 *
		 * @param kind      вид тела (ir/cr/kur/krr/ccr)
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param templates записи шаблонов CertTemplate (по одной на запрос, опознаватели 0, 1, ...)
		 * @param kid       опознаватель ключа отправителя senderKID
		 * @param password  пароль общего секрета
		 * @param hash      алгоритм хеша односторонней функции и имитовставки
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a message with a certificate requests body under PBM protection
		 *
		 * @param kind      the kind of the body (ir/cr/kur/krr/ccr)
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param templates the CertTemplate records (one per request, ids 0, 1, ...)
		 * @param kid       the senderKID key identifier of the sender
		 * @param password  the password of the shared secret
		 * @param hash      the hashing algorithm of the one-way function and the MAC
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t request(const body_t kind, const view_t & sender, const view_t & recipient, const vector <view_t> & templates, const view_t & kid, const view_t & password, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки шаблона сертификата CertTemplate
		 *
		 * @param subject запись имени владельца (пустая - поле опущено)
		 * @param key     запись сведений об открытом ключе SubjectPublicKeyInfo
		 * @param result  место, в которое помещается запись шаблона
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a CertTemplate certificate template
		 *
		 * @param subject the subject name record (empty - the field is omitted)
		 * @param key     the SubjectPublicKeyInfo public key info record
		 * @param result  the place the template record is put into
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certTemplate(const view_t & subject, const view_t & key, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения certConf
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param hashes    хеши принимаемых сертификатов (SHA-256 записи сертификата)
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a certConf message
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param hashes    the hashes of the accepted certificates (SHA-256 of the certificate record)
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certConfirm(const view_t & sender, const view_t & recipient, const vector <view_t> & hashes, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения pkiConf
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a pkiConf message
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t confirm(const view_t & sender, const view_t & recipient, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения rr (запрос отзыва)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param issuer    запись имени издателя отзываемого сертификата
		 * @param serial    содержимое порядкового номера отзываемого сертификата
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building an rr message (revocation request)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param issuer    the issuer name record of the certificate being revoked
		 * @param serial    the serial number content of the certificate being revoked
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t revoke(const view_t & sender, const view_t & recipient, const view_t & issuer, const view_t & serial, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения genm
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param infos     общие сведения (пара опознаватель и запись значения, пустая - значение опущено)
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a genm message
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param infos     the general info (a pair of the identifier and the value record, empty - the value is omitted)
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t general(const view_t & sender, const view_t & recipient, const vector <info_t> & infos, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения ip/cp/kup (ответ о сертификатах)
		 *
		 * @param kind      вид тела (ip/cp/kup/ccp)
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param responses ответы о сертификатах (статус и запись сертификата)
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building an ip/cp/kup message (certificate response)
		 *
		 * @param kind      the kind of the body (ip/cp/kup/ccp)
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param responses the certificate responses (the status and the certificate record)
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t respond(const body_t kind, const view_t & sender, const view_t & recipient, const vector <response_t> & responses, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения error
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param status    сведения о статусе отказа
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building an error message
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param status    the failure status info
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t failure(const view_t & sender, const view_t & recipient, const status_info_t & status, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция сборки сообщения p10cr (запрос PKCS #10)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param csr       запись CertificationRequest по RFC 2986
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a p10cr message (PKCS #10 request)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param csr       the CertificationRequest record according to RFC 2986
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t requestPkcs10(const view_t & sender, const view_t & recipient, const view_t & csr, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения popdecc (вызовы подтверждения владения)
		 *
		 * @param sender     запись GeneralName отправителя
		 * @param recipient  запись GeneralName получателя
		 * @param challenges вызовы (свидетель и вызов)
		 * @param signer     подготовленный секретный ключ защиты подписью
		 * @param hash       алгоритм хеша подписи
		 * @param result     место, в которое помещается запись PKIMessage
		 * @return           причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a popdecc message (possession challenges)
		 *
		 * @param sender     the GeneralName record of the sender
		 * @param recipient  the GeneralName record of the recipient
		 * @param challenges the challenges (the witness and the challenge)
		 * @param signer     the prepared secret key of the signature protection
		 * @param hash       the hashing algorithm of the signature
		 * @param result     the place the PKIMessage record is put into
		 * @return           the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t challenge(const view_t & sender, const view_t & recipient, const vector <challenge_t> & challenges, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения popdecr (ответы подтверждения владения)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param answers   числа ответов
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a popdecr message (possession responses)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param answers   the response numbers
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t challengeReply(const view_t & sender, const view_t & recipient, const vector <int64_t> & answers, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения krp (ответ восстановления ключа)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param recovery  ответ восстановления ключа
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a krp message (key recovery response)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param recovery  the key recovery response
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t recovered(const view_t & sender, const view_t & recipient, const recovery_t & recovery, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения rp (ответ отзыва)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param statuses  сведения о статусах отзыва
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building an rp message (revocation response)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param statuses  the revocation status info
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t revoked(const view_t & sender, const view_t & recipient, const vector <status_info_t> & statuses, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения ckuann (объявление обновления ключа ЦС)
		 *
		 * @param sender     запись GeneralName отправителя
		 * @param recipient  запись GeneralName получателя
		 * @param oldWithNew запись сертификата oldWithNew
		 * @param newWithOld запись сертификата newWithOld
		 * @param newWithNew запись сертификата newWithNew
		 * @param signer     подготовленный секретный ключ защиты подписью
		 * @param hash       алгоритм хеша подписи
		 * @param result     место, в которое помещается запись PKIMessage
		 * @return           причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a ckuann message (CA key update announcement)
		 *
		 * @param sender     the GeneralName record of the sender
		 * @param recipient  the GeneralName record of the recipient
		 * @param oldWithNew the oldWithNew certificate record
		 * @param newWithOld the newWithOld certificate record
		 * @param newWithNew the newWithNew certificate record
		 * @param signer     the prepared secret key of the signature protection
		 * @param hash       the hashing algorithm of the signature
		 * @param result     the place the PKIMessage record is put into
		 * @return           the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t caKeyUpdate(const view_t & sender, const view_t & recipient, const view_t & oldWithNew, const view_t & newWithOld, const view_t & newWithNew, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения cann (объявление сертификата)
		 *
		 * @param sender      запись GeneralName отправителя
		 * @param recipient   запись GeneralName получателя
		 * @param certificate запись сертификата
		 * @param signer      подготовленный секретный ключ защиты подписью
		 * @param hash        алгоритм хеша подписи
		 * @param result      место, в которое помещается запись PKIMessage
		 * @return            причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a cann message (certificate announcement)
		 *
		 * @param sender      the GeneralName record of the sender
		 * @param recipient   the GeneralName record of the recipient
		 * @param certificate the certificate record
		 * @param signer      the prepared secret key of the signature protection
		 * @param hash        the hashing algorithm of the signature
		 * @param result      the place the PKIMessage record is put into
		 * @return            the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t announce(const view_t & sender, const view_t & recipient, const view_t & certificate, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения rann (объявление отзыва)
		 *
		 * @param sender       запись GeneralName отправителя
		 * @param recipient    запись GeneralName получателя
		 * @param announcement объявление отзыва
		 * @param signer       подготовленный секретный ключ защиты подписью
		 * @param hash         алгоритм хеша подписи
		 * @param result       место, в которое помещается запись PKIMessage
		 * @return             причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a rann message (revocation announcement)
		 *
		 * @param sender       the GeneralName record of the sender
		 * @param recipient    the GeneralName record of the recipient
		 * @param announcement the revocation announcement
		 * @param signer       the prepared secret key of the signature protection
		 * @param hash         the hashing algorithm of the signature
		 * @param result       the place the PKIMessage record is put into
		 * @return             the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t announceRevocation(const view_t & sender, const view_t & recipient, const announcement_t & announcement, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения crlann (объявление списков отзыва)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param crls      записи списков отзыва CertificateList
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a crlann message (CRL announcement)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param crls      the CertificateList CRL records
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t announceCrls(const view_t & sender, const view_t & recipient, const vector <view_t> & crls, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения nested (вложенные сообщения)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param messages  записи вложенных PKIMessage
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a nested message (nested messages)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param messages  the nested PKIMessage records
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t nest(const view_t & sender, const view_t & recipient, const vector <view_t> & messages, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения pollReq (запрос опроса)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param ids       опознаватели запросов
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a pollReq message (polling request)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param ids       the request identifiers
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t pollRequest(const view_t & sender, const view_t & recipient, const vector <int64_t> & ids, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция сборки сообщения pollRep (ответ опроса)
		 *
		 * @param sender    запись GeneralName отправителя
		 * @param recipient запись GeneralName получателя
		 * @param polls     записи опроса (опознаватель и время ожидания)
		 * @param signer    подготовленный секретный ключ защиты подписью
		 * @param hash      алгоритм хеша подписи
		 * @param result    место, в которое помещается запись PKIMessage
		 * @return          причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of building a pollRep message (polling response)
		 *
		 * @param sender    the GeneralName record of the sender
		 * @param recipient the GeneralName record of the recipient
		 * @param polls     the polling records (the identifier and the wait time)
		 * @param signer    the prepared secret key of the signature protection
		 * @param hash      the hashing algorithm of the signature
		 * @param result    the place the PKIMessage record is put into
		 * @return          the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t pollReply(const view_t & sender, const view_t & recipient, const vector <poll_t> & polls, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept;

		/**
		 * \~russian
		 * @brief Функция проверки защиты сообщения подписью
		 *
		 * @param message разобранное сообщение
		 * @param key     сведения об открытом ключе подписи
		 * @return        причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of checking the message signature protection
		 *
		 * @param message the parsed message
		 * @param key     the public key info of the signature
		 * @return        the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const message_t & message, const x509::key_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки защиты сообщения парольной имитовставкой PBM
		 *
		 * @param message  разобранное сообщение
		 * @param password пароль общего секрета
		 * @return         причина отказа либо error_t::NONE
		 *
		 * \~english
		 * @brief Function of checking the message PBM password MAC protection
		 *
		 * @param message  the parsed message
		 * @param password the password of the shared secret
		 * @return         the reason of the failure or error_t::NONE
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const message_t & message, const view_t & password) noexcept;
	};
};

