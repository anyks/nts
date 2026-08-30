/**
 * @file context.hpp
 * @date 2026-08-30
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
 * @brief Заголовочный файл общих объявлений фасадов связи — состояние связи, отказы
 *        и подлинность стороны, предъявляемая собеседнику
 *
 * \~english
 * @brief Header file of the common declarations of the facades of a connection — the state of
 *        the connection, the failures and the authenticity of a side presented to the interlocutor
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_CONTEXT__
#define __ANYKS_TLS_CONTEXT__

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
#include <alert/alert.hpp>
#include <protect/protect.hpp>
#include <extension/extension.hpp>

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
	 * @brief Пространство имён общих объявлений фасадов связи
	 *
	 * @details Фасады клиента и сервера ведут одну и ту же связь с разных её концов, и
	 *          состояние, отказы и подлинность у них общие: расходятся лишь порядок
	 *          сообщений да настройки, которые всякой роли доступны
	 *
	 * @note Связь не занимается вводом и выводом вовсе: принятые байты подаются ей
	 *       вызовом, а отправляемые она складывает в накопитель. Откуда байты пришли
	 *       и куда уйдут - дело того, кто связь ведёт
	 *
	 * \~english
	 * @brief Namespace of the common declarations of the facades of a connection
	 * @details The facades of the client and of the server lead one and the same connection from
	 *          the different ends of it, and the state, the failures and the authenticity are common
	 *          to them: only the order of the messages and the settings available to every role differ
	 * @note The connection does not deal with the input and the output at all: the received bytes are
	 *       given to it by a call, and it puts the sent ones into an accumulator. Where the bytes came
	 *       from and where they will go is the business of the one who leads the connection
	 *
	 * \~
	 */
	namespace context {
		/**
		 * \~russian
		 * @brief Отказы связи
		 *
		 * \~english
		 * @brief Failures of a connection
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			STATE       = 0x01, /*!< \~russian Вызов сделан не в том состоянии связи \~english The call is made in a wrong state of the connection \~ */
			SETTINGS    = 0x02, /*!< \~russian Настроек для заведения связи не хватает \~english There are not enough settings for the establishment of the connection \~ */
			MEMORY      = 0x03, /*!< \~russian Памяти под накопитель не хватило \~english There was not enough memory for the accumulator \~ */
			RECORD      = 0x04, /*!< \~russian Запись протокола сложена не по правилам \~english A record of the protocol is composed not by the rules \~ */
			PROTECTION  = 0x05, /*!< \~russian Защиту записи наложить либо снять не удалось \~english It was not possible to impose or to remove the protection of a record \~ */
			MESSAGE     = 0x06, /*!< \~russian Сообщение рукопожатия разобрать не удалось \~english It was not possible to parse a message of the handshake \~ */
			ORDER       = 0x07, /*!< \~russian Сообщение рукопожатия пришло не в свой черёд \~english A message of the handshake came out of its turn \~ */
			VERSION     = 0x08, /*!< \~russian Издание протокола собеседником не поддержано \~english The edition of the protocol is not supported by the interlocutor \~ */
			SUITE       = 0x09, /*!< \~russian Общего набора шифрования у сторон не нашлось \~english The sides have not found a common cipher suite \~ */
			GROUP       = 0x0A, /*!< \~russian Общей кривой обмена ключами у сторон не нашлось \~english The sides have not found a common curve of the key exchange \~ */
			EXCHANGE    = 0x0B, /*!< \~russian Общее значение обмена ключами выработать не удалось \~english It was not possible to produce the shared value of the key exchange \~ */
			SCHEDULE    = 0x0C, /*!< \~russian Ключевой материал связи вывести не удалось \~english It was not possible to derive the key material of the connection \~ */
			CERTIFICATE = 0x0D, /*!< \~russian Цепочка сертификатов собеседника непригодна \~english The chain of the certificates of the interlocutor is unsuitable \~ */
			SIGNATURE   = 0x0E, /*!< \~russian Подпись владения ключом не сошлась \~english The signature of the possession of the key has not matched \~ */
			COMPLETION  = 0x0F, /*!< \~russian Завершение рукопожатия собеседника не сошлось \~english The completion of the handshake of the interlocutor has not matched \~ */
			ALERT       = 0x10, /*!< \~russian Собеседник оборвал связь извещением \~english The interlocutor has torn the connection by an alert \~ */
			CLOSED      = 0x11  /*!< \~russian Связь уже закрыта \~english The connection is already closed \~ */
		};

		/**
		 * \~russian
		 * @brief Состояния связи
		 *
		 * \~english
		 * @brief States of a connection
		 *
		 * \~
		 */
		enum class state_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Связь ещё не заведена \~english The connection is not established yet \~ */
			HANDSHAKE   = 0x01, /*!< \~russian Рукопожатие связи идёт \~english The handshake of the connection is going on \~ */
			ESTABLISHED = 0x02, /*!< \~russian Связь установлена, идут прикладные данные \~english The connection is established, the application data is going \~ */
			CLOSED      = 0x03, /*!< \~russian Связь закрыта одной из сторон \~english The connection is closed by one of the sides \~ */
			FAILED      = 0x04  /*!< \~russian Связь оборвана отказом \~english The connection is torn by a failure \~ */
		};

		/**
		 * \~russian
		 * @brief Подлинность стороны связи
		 *
		 * @details Раздел 4.4.2 RFC 8446: цепочка сертификатов идёт от своего сертификата к
		 *          сертификату издателя, и секретный ключ отвечает именно первому из них
		 *
		 * @note Секретный ключ записывается тем же порядком, каким открытый ключ лежит в
		 *       сертификате, — от старшего байта к младшему
		 *
		 * \~english
		 * @brief Authenticity of a side of a connection
		 * @details The section 4.4.2 of RFC 8446: the chain of the certificates goes from one's own
		 *          certificate to the certificate of the issuer, and the secret key corresponds exactly
		 *          to the first of them
		 * @note The secret key is written by the same order the public key lies in the certificate by —
		 *       from the senior byte to the junior one
		 *
		 * \~
		 */
		typedef struct __ANYKS_TLS_SHARED_EXPORT__ Credential {
			// Секретный ключ своего сертификата
			vector <uint8_t> secret;
			// Цепочка сертификатов своей стороны
			vector <vector <uint8_t>> chain;
		} credential_t;
	};
};

#endif // __ANYKS_TLS_CONTEXT__
