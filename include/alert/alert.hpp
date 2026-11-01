/**
 * @file alert.hpp
 * @date 2026-08-30
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
 * @brief Заголовочный файл модуля извещений протокола TLS — уровень, описание
 *        и правило разрыва связи по полученному извещению
 *
 * \~english
 * @brief Header file of the module of the alerts of the TLS protocol — the level, the
 *        description and the rule of the tearing of the connection by a received alert
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
	 * @brief Пространство имён модуля извещений протокола TLS
	 *
	 * @details Раздел 6 RFC 8446: извещение занимает ровно два байта и передаётся записью
	 *          вида ALERT. Первый байт объявляет уровень, второй — описание события.
	 *
	 * @note Модуль не занимается ни обвязкой записи, ни её защитой: извещение о смертельном
	 *       отказе шлётся теми же ключами, какими защищаются прочие записи на этот миг
	 *
	 * \~english
	 * @brief Namespace of the module of the alerts of the TLS protocol
	 *
	 * @details The section 6 of RFC 8446: an alert occupies exactly two bytes and is transferred
	 *          by a record of the ALERT type. The first byte declares the level, the second one —
	 *          the description of the event.
	 *
	 * @note The module deals neither with the framing of a record nor with its protection: an alert
	 *       about a fatal failure is sent by the same keys the other records are protected by at
	 *       this moment
	 *
	 * \~
	 */
	namespace alert {
		/**
		 * \~russian
		 * @brief Длина извещения в байтах
		 *
		 * \~english
		 * @brief Length of an alert in bytes
		 *
		 * \~
		 */
		static constexpr size_t ALERT_LENGTH = 2;

		/**
		 * \~russian
		 * @brief Отказы модуля извещений
		 *
		 * \~english
		 * @brief Failures of the module of the alerts
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			// Отказа нет
			NONE   = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			// Данных для целого извещения не набралось
			HUNGRY = 0x01, /*!< \~russian Данных для целого извещения не набралось \~english The data for a whole alert has not accumulated \~ */
			// Длина извещения отлична от объявленной протоколом
			LENGTH = 0x02, /*!< \~russian Длина извещения отлична от объявленной протоколом \~english The length of the alert differs from the one declared by the protocol \~ */
			// Уровень извещения протоколом не определён
			LEVEL  = 0x03, /*!< \~russian Уровень извещения протоколом не определён \~english The level of the alert is not defined by the protocol \~ */
			// Место для записи извещения не передано
			EMPTY  = 0x04  /*!< \~russian Место для записи извещения не передано \~english The place for the writing of the alert is not passed \~ */
		};

		/**
		 * \~russian
		 * @brief Уровни извещения
		 *
		 * @details Раздел 6 RFC 8446: перечисление AlertLevel
		 *
		 * \~english
		 * @brief Levels of an alert
		 *
		 * @details The section 6 of RFC 8446: the AlertLevel enumeration
		 *
		 * \~
		 */
		enum class level_t : uint8_t {
			// Уровень извещения не установлен
			NONE    = 0x00, /*!< \~russian Уровень извещения не установлен \~english The level of the alert is not set \~ */
			// Предупреждение
			WARNING = 0x01, /*!< \~russian Предупреждение \~english A warning \~ */
			// Смертельный отказ
			FATAL   = 0x02  /*!< \~russian Смертельный отказ \~english A fatal failure \~ */
		};

		/**
		 * \~russian
		 * @brief Описания извещения
		 *
		 * @details Раздел 6 RFC 8446: перечисление AlertDescription. Описания, оставленные
		 *          протоколом ради старых изданий, перечислены наравне с прочими: связь вправе
		 *          получить их от встречной стороны и обязана уметь их назвать.
		 *
		 * \~english
		 * @brief Descriptions of an alert
		 *
		 * @details The section 6 of RFC 8446: the AlertDescription enumeration. The descriptions
		 *          left by the protocol for the sake of the old editions are listed on a par with
		 *          the others: a connection is entitled to receive them from the opposite side and
		 *          is obliged to be able to name them.
		 *
		 * \~
		 */
		enum class description_t : uint8_t {
			// Сторона завершила передачу данных
			CLOSE       = 0,   /*!< \~russian Сторона завершила передачу данных \~english The side has finished the transfer of the data \~ */
			// Получено сообщение не в свой черёд
			UNEXPECTED  = 10,  /*!< \~russian Получено сообщение не в свой черёд \~english A message is received out of its turn \~ */
			// Проверка целостности записи не прошла
			MAC         = 20,  /*!< \~russian Проверка целостности записи не прошла \~english The check of the integrity of a record has not passed \~ */
			// Расшифрование записи не удалось
			DECRYPTION  = 21,  /*!< \~russian Расшифрование записи не удалось \~english The decryption of a record has failed \~ */
			// Длина записи превышает дозволенную
			OVERSIZE    = 22,  /*!< \~russian Длина записи превышает дозволенную \~english The length of a record exceeds the allowed one \~ */
			// Развёртывание сжатого содержимого не удалось
			COMPRESSION = 30,  /*!< \~russian Развёртывание сжатого содержимого не удалось \~english The decompression of the compressed content has failed \~ */
			// Согласовать условия связи не удалось
			HANDSHAKE   = 40,  /*!< \~russian Согласовать условия связи не удалось \~english It has not been possible to agree upon the conditions of the connection \~ */
			// Годного сертификата у стороны не нашлось
			NOSIGNER    = 41,  /*!< \~russian Годного сертификата у стороны не нашлось \~english The side has not found a suitable certificate \~ */
			// Сертификат испорчен
			BADCERT     = 42,  /*!< \~russian Сертификат испорчен \~english The certificate is corrupted \~ */
			// Вид сертификата не поддерживается
			UNSUPPORTED = 43,  /*!< \~russian Вид сертификата не поддерживается \~english The type of the certificate is not supported \~ */
			// Сертификат отозван издателем
			REVOKED     = 44,  /*!< \~russian Сертификат отозван издателем \~english The certificate is revoked by its issuer \~ */
			// Срок действия сертификата истёк
			EXPIRED     = 45,  /*!< \~russian Срок действия сертификата истёк \~english The validity period of the certificate has expired \~ */
			// Сертификат отвергнут по неназванной причине
			UNKNOWNCERT = 46,  /*!< \~russian Сертификат отвергнут по неназванной причине \~english The certificate is rejected for an unnamed reason \~ */
			// Значение поля вышло за дозволенные пределы
			PARAMETER   = 47,  /*!< \~russian Значение поля вышло за дозволенные пределы \~english The value of a field has gone beyond the allowed limits \~ */
			// Издатель сертификата доверия не имеет
			AUTHORITY   = 48,  /*!< \~russian Издатель сертификата доверия не имеет \~english The issuer of the certificate has no trust \~ */
			// Доступ по предъявленной подлинности запрещён
			ACCESS      = 49,  /*!< \~russian Доступ по предъявленной подлинности запрещён \~english The access by the presented authenticity is forbidden \~ */
			// Сообщение разобрать не удалось
			DECODE      = 50,  /*!< \~russian Сообщение разобрать не удалось \~english It has not been possible to parse the message \~ */
			// Проверка подписи или обмена ключами не прошла
			DECRYPT     = 51,  /*!< \~russian Проверка подписи или обмена ключами не прошла \~english The check of a signature or of a key exchange has not passed \~ */
			// Издание протокола не поддерживается
			VERSION     = 70,  /*!< \~russian Издание протокола не поддерживается \~english The edition of the protocol is not supported \~ */
			// Согласованные условия недостаточно стойки
			SECURITY    = 71,  /*!< \~russian Согласованные условия недостаточно стойки \~english The agreed conditions are not sufficiently strong \~ */
			// Внутренний отказ, к встречной стороне не относящийся
			INTERNAL    = 80,  /*!< \~russian Внутренний отказ, к встречной стороне не относящийся \~english An internal failure not related to the opposite side \~ */
			// Сторона отступила к изданию ниже доступного
			FALLBACK    = 86,  /*!< \~russian Сторона отступила к изданию ниже доступного \~english The side has fallen back to an edition lower than the available one \~ */
			// Рукопожатие прервано по причине вне протокола
			CANCELED    = 90,  /*!< \~russian Рукопожатие прервано по причине вне протокола \~english The handshake is interrupted for a reason outside of the protocol \~ */
			// Обязательное расширение в сообщении отсутствует
			MISSING     = 109, /*!< \~russian Обязательное расширение в сообщении отсутствует \~english A mandatory extension is absent in the message \~ */
			// Прислано расширение, о котором не просили
			EXTENSION   = 110, /*!< \~russian Прислано расширение, о котором не просили \~english An extension nobody asked for is sent \~ */
			// Запрошенное имя стороне неизвестно
			NAME        = 112, /*!< \~russian Запрошенное имя стороне неизвестно \~english The requested name is unknown to the side \~ */
			// Ответ о состоянии сертификата негоден либо сертификат отозван
			STATUS      = 113, /*!< \~russian Ответ о состоянии сертификата негоден либо сертификат отозван \~english The certificate status response is unsuitable or the certificate is revoked \~ */
			// Опознаватель заранее разделённого ключа неизвестен
			PSK         = 115, /*!< \~russian Опознаватель заранее разделённого ключа неизвестен \~english The identifier of the pre-shared key is unknown \~ */
			// Пересогласование связи не дозволено (RFC 5746, TLS 1.2)
			RENEGOTIATION = 100, /*!< \~russian Пересогласование связи не дозволено (RFC 5746, TLS 1.2) \~english The renegotiation of the connection is not allowed (RFC 5746, TLS 1.2) \~ */
			// Зашифрованное приветствие ECH отвергнуто сервером, а клиент требует ECH (раздел 6.1.7 RFC 9849)
			ECH_REQUIRED = 121, /*!< \~russian Зашифрованное приветствие ECH отвергнуто сервером, а клиент требует ECH (раздел 6.1.7 RFC 9849) \~english The encrypted client hello ECH has been rejected by the server while the client requires ECH (the section 6.1.7 of RFC 9849) \~ */
			// Подлинность стороны обязательна, но не подтверждена
			REQUIRED    = 116, /*!< \~russian Подлинность стороны обязательна, но не подтверждена \~english The authenticity of the side is mandatory but not confirmed \~ */
			// Ни один из предложенных протоколов не поддержан
			PROTOCOL    = 120  /*!< \~russian Ни один из предложенных протоколов не поддержан \~english None of the offered protocols is supported \~ */
		};

		/**
		 * \~russian
		 * @brief Извещение протокола TLS
		 *
		 * \~english
		 * @brief Alert of the TLS protocol
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Alert {
			// Уровень извещения
			level_t level;
			// Описание извещения
			description_t description;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Alert() noexcept;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param level       уровень извещения
			 * @param description описание извещения
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * @param level       the level of the alert
			 * @param description the description of the alert
			 *
			 * \~
			 */
			Alert(const level_t level, const description_t description) noexcept;
		} alert_t;

		/**
		 * \~russian
		 * @brief Функция разбора извещения
		 *
		 * @param data   разбираемая область байтов
		 * @param result извещение, в которое помещается итог разбора
		 * @return       отказ разбора извещения
		 *
		 * @details Описание извещения не сличается с перечислением протокола: раздел 6 RFC 8446
		 *          велит принимать неизвестное описание и разрывать по нему связь, а не отвечать
		 *          на него отказом разбора
		 *
		 * \~english
		 * @brief Function of the parsing of an alert
		 *
		 * @param data   the byte area being parsed
		 * @param result the alert the outcome of the parsing is put into
		 * @return       the failure of the parsing of the alert
		 *
		 * @details The description of the alert is not compared against the enumeration of the
		 *          protocol: the section 6 of RFC 8446 orders to accept an unknown description and
		 *          to tear the connection by it and not to answer it by a failure of the parsing
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t parse(const view_t & data, alert_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Функция записи извещения
		 *
		 * @param alert  записываемое извещение
		 * @param result место, в которое помещается записанное извещение
		 * @return       отказ записи извещения
		 *
		 * @note Место для записи обязано вмещать ALERT_LENGTH байтов
		 *
		 * \~english
		 * @brief Function of the writing of an alert
		 *
		 * @param alert  the alert being written
		 * @param result the place the written alert is put into
		 * @return       the failure of the writing of the alert
		 *
		 * @note The place for the writing is obliged to hold ALERT_LENGTH bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t build(const alert_t & alert, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки известности описания извещения
		 *
		 * @param description проверяемое описание извещения
		 * @return            признак того, что описание определено протоколом
		 *
		 * \~english
		 * @brief Function of the checking of the knownness of the description of an alert
		 *
		 * @param description the description of the alert being checked
		 * @return            the flag of the description being defined by the protocol
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool known(const description_t description) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки смертельности извещения
		 *
		 * @param alert проверяемое извещение
		 * @return      признак того, что связь после извещения продолжена быть не вправе
		 *
		 * @details Раздел 6.2 RFC 8446: издание TLS 1.3 уровень извещения при этом решении не
		 *          учитывает вовсе, и смертельным считается всякое извещение, кроме завершения
		 *          передачи и отмены рукопожатия
		 *
		 * \~english
		 * @brief Function of the checking of the fatality of an alert
		 *
		 * @param alert the alert being checked
		 * @return      the flag of the connection not being entitled to be continued after the alert
		 *
		 * @details The section 6.2 of RFC 8446: the TLS 1.3 edition does not take the level of the
		 *          alert into account at all during this decision, and every alert is considered
		 *          fatal except for the finishing of the transfer and the cancellation of the handshake
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool fatal(const alert_t & alert) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки, объявлено ли описание извещения смертельным всегда
		 *
		 * @param description проверяемое описание
		 * @return            признак описания, смертельного при любом уровне
		 *
		 * @details Раздел 7.2.2 RFC 5246 и раздел 3 RFC 7507: у изданий до 1.3 связь рвёт
		 *          смертельный уровень либо описание, объявленное смертельным всегда;
		 *          предупреждение прочих описаний (no_renegotiation, unrecognized_name по
		 *          разделу 3 RFC 6066) связь не рвёт
		 *
		 * \~english
		 * @brief Function of the checking whether the description of an alert is declared always fatal
		 *
		 * @param description the description being checked
		 * @return            the flag of a description fatal at any level
		 *
		 * @details The section 7.2.2 of RFC 5246 and the section 3 of RFC 7507: at the editions before 1.3
		 *          the connection is broken by the fatal level or by a description declared always fatal;
		 *          a warning of the other descriptions (no_renegotiation, unrecognized_name by the section 3
		 *          of RFC 6066) does not break the connection
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool grave(const description_t description) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения названия описания извещения
		 *
		 * @param description описание извещения, название которого запрашивается
		 * @return            название описания извещения из перечисления протокола
		 *
		 * @note Выводится именно название из текста стандарта, а не перевод: по нему извещение
		 *       сличается с журналами встречной стороны, кем бы она ни была написана
		 *
		 * \~english
		 * @brief Function of getting the name of the description of an alert
		 *
		 * @param description the description of the alert the name of which is requested
		 * @return            the name of the description of the alert from the enumeration of the protocol
		 *
		 * @note It is exactly the name from the text of the standard that is output and not a translation:
		 *       an alert is compared by it against the logs of the opposite side, no matter by whom it is
		 *       written
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * name(const description_t description) noexcept;
	};
};

