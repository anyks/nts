/**
 * @file flow.hpp
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
 * @brief Заголовочный файл модуля хода рукопожатия протокола TLS 1.3 — порядок сообщений
 *        и пора ключей, которыми защищаются записи всякой стороны
 *
 * \~english
 * @brief Header file of the module of the course of the handshake of the TLS 1.3 protocol —
 *        the order of the messages and the epoch of the keys the records of every side are
 *        protected by
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_FLOW__
#define __ANTS_FLOW__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <session/session.hpp>
#include <handshake/handshake.hpp>

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
	 * @brief Пространство имён хода рукопожатия протокола TLS
	 *
	 * @details Раздел 4.4.1 RFC 8446: сообщения рукопожатия идут в заданном порядке, и
	 *          сторона, принявшая сообщение не в свой черёд, обязана прервать связь. Порядок
	 *          этот у обеих сторон один и тот же: обе видят одну переписку и различаются лишь
	 *          тем, кто какое сообщение шлёт.
	 *
	 * @note Ход рукопожатия сам ничего не составляет и не разбирает: он лишь отвечает, вправе
	 *       ли сообщение идти сейчас, и называет пору ключей, которыми защищаются записи
	 *
	 * \~english
	 * @brief Namespace of the course of the handshake of the TLS protocol
	 * @details The section 4.4.1 of RFC 8446: the messages of the handshake go in a set order, and a
	 *          party which has received a message out of its turn is obliged to abort the connection.
	 *          This order is one and the same at both parties: both see the same transcript and differ
	 *          only by who sends which message.
	 * @note The course of the handshake itself neither composes nor parses anything: it only answers
	 *       whether a message is entitled to go now, and names the epoch of the keys the records are
	 *       protected by
	 *
	 * \~
	 */
	namespace flow {
		/**
		 * \~russian
		 * @brief Отказы хода рукопожатия
		 *
		 * \~english
		 * @brief Failures of the course of the handshake
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE   = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			STATE  = 0x01, /*!< \~russian Ход рукопожатия не заведён либо уже прерван \~english The course of the handshake is not set up or is already aborted \~ */
			ORDER  = 0x02, /*!< \~russian Сообщение пришло не в свой черёд \~english The message has come out of its turn \~ */
			SIDE   = 0x03, /*!< \~russian Эта сторона слать такое сообщение не вправе \~english This side is not entitled to send such a message \~ */
			REPEAT = 0x04  /*!< \~russian Просьба о повторе приветствия объявлена дважды \~english The request of a repetition of the greeting is declared twice \~ */
		};

		/**
		 * \~russian
		 * @brief Роли сторон связи
		 *
		 * \~english
		 * @brief Roles of the sides of a connection
		 *
		 * \~
		 */
		enum class role_t : uint8_t {
			NONE   = 0x00, /*!< \~russian Роль стороны не установлена \~english The role of the side is not set \~ */
			CLIENT = 0x01, /*!< \~russian Сторона ведёт связь клиентом \~english The side conducts the connection as a client \~ */
			SERVER = 0x02  /*!< \~russian Сторона ведёт связь сервером \~english The side conducts the connection as a server \~ */
		};

		/**
		 * \~russian
		 * @brief Поры ключей, которыми защищаются записи
		 *
		 * @details Раздел 2 RFC 8446: записи защищаются тремя разными ключевыми материалами
		 *          подряд, и всякий следующий сменяет предыдущий не сразу у обеих сторон
		 *
		 * \~english
		 * @brief Epochs of the keys the records are protected by
		 * @details The section 2 of RFC 8446: the records are protected by three different key materials
		 *          in a row, and every next one replaces the previous one not simultaneously at both parties
		 *
		 * \~
		 */
		enum class epoch_t : uint8_t {
			PLAIN       = 0x00, /*!< \~russian Записи идут без защиты \~english The records go without a protection \~ */
			HANDSHAKE   = 0x01, /*!< \~russian Записи защищены ключами рукопожатия \~english The records are protected by the keys of the handshake \~ */
			APPLICATION = 0x02  /*!< \~russian Записи защищены ключами прикладных данных \~english The records are protected by the keys of the application data \~ */
		};

		/**
		 * \~russian
		 * @brief Ступени хода рукопожатия
		 *
		 * @details Ступень называет то сообщение, которого ход рукопожатия ждёт следующим
		 *
		 * \~english
		 * @brief Stages of the course of the handshake
		 * @details A stage names the message which the course of the handshake awaits next
		 *
		 * \~
		 */
		enum class stage_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Ход рукопожатия ещё не заведён \~english The course of the handshake is not set up yet \~ */
			GREETING    = 0x01, /*!< \~russian Ожидается приветствие клиента \~english The greeting of the client is awaited \~ */
			ANSWER      = 0x02, /*!< \~russian Ожидается приветствие сервера \~english The greeting of the server is awaited \~ */
			EXTENSIONS  = 0x03, /*!< \~russian Ожидаются защищённые расширения \~english The encrypted extensions are awaited \~ */
			CREDENTIALS = 0x04, /*!< \~russian Ожидается запрос сертификата либо цепочка сервера \~english The request of a certificate or the chain of the server is awaited \~ */
			VERIFY      = 0x05, /*!< \~russian Ожидается подпись владения ключом сервера \~english The signature of the possession of the key of the server is awaited \~ */
			COMPLETION  = 0x06, /*!< \~russian Ожидается завершение рукопожатия сервером \~english The completion of the handshake by the server is awaited \~ */
			ANSWERING   = 0x07, /*!< \~russian Ожидается ответ клиента на запрос сертификата \~english The answer of the client to the request of a certificate is awaited \~ */
			CONFIRMING  = 0x08, /*!< \~russian Ожидается подпись владения ключом клиента \~english The signature of the possession of the key of the client is awaited \~ */
			FINISHING   = 0x09, /*!< \~russian Ожидается завершение рукопожатия клиентом \~english The completion of the handshake by the client is awaited \~ */
			ESTABLISHED = 0x0A, /*!< \~russian Рукопожатие завершено, связь установлена \~english The handshake is completed, the connection is established \~ */
			FAILED      = 0x0B  /*!< \~russian Ход рукопожатия прерван отказом \~english The course of the handshake is aborted by a failure \~ */
		};

		/**
		 * \~russian
		 * @brief Ход рукопожатия связи
		 *
		 * @details Сообщения объявляются ходу рукопожатия вызовом accept в том порядке, в
		 *          каком они прошли по связи, и каждое из них либо принимается, либо
		 *          отвергается вместе со всем рукопожатием. Ход рукопожатия при этом сам
		 *          подвигает пору ключей всякой стороны: одна и та же запись, отправленная
		 *          до и после завершения, защищается разными ключами.
		 *
		 * @note Ход рукопожатия одинаков у обеих сторон: клиент и сервер видят одну и ту же
		 *       переписку, и различает их лишь то, кто какое сообщение шлёт
		 *
		 * \~english
		 * @brief Course of the handshake of a connection
		 * @details The messages are declared to the course of the handshake by a call of accept in the
		 *          order in which they have passed over the connection, and each of them is either
		 *          accepted or rejected together with the whole handshake. The course of the handshake at
		 *          that moves the epoch of the keys of every side by itself: one and the same record sent
		 *          before and after the completion is protected by different keys.
		 * @note The course of the handshake is identical at both parties: the client and the server see one
		 *       and the same transcript, and they are distinguished only by who sends which message
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Machine {
			private:
				// Роль стороны, ведущей ход рукопожатия
				role_t _role;
			private:
				// Ступень, до которой дошло рукопожатие
				stage_t _stage;
			private:
				// Признак того, что просьба о повторе приветствия уже объявлялась
				bool _retried;
			private:
				// Признак того, что сервер запросил сертификат клиента
				bool _requested;
			private:
				// Признак того, что клиент прислал непустую цепочку сертификатов
				bool _certified;
			private:
				// Пора ключей записей, отправляемых клиентом
				epoch_t _client;
			private:
				// Пора ключей записей, отправляемых сервером
				epoch_t _server;
			public:
				/**
				 * \~russian
				 * @brief Метод получения роли стороны, ведущей ход рукопожатия
				 *
				 * @return роль стороны связи
				 *
				 * \~english
				 * @brief Method of getting the role of the side conducting the course of the handshake
				 * @return the role of the side of the connection
				 *
				 * \~
				 */
				role_t role() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ступени, до которой дошло рукопожатие
				 *
				 * @return ступень хода рукопожатия
				 *
				 * \~english
				 * @brief Method of getting the stage the handshake has reached
				 * @return the stage of the course of the handshake
				 *
				 * \~
				 */
				stage_t stage() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки завершённости рукопожатия
				 *
				 * @return признак того, что рукопожатие завершено и связь установлена
				 *
				 * \~english
				 * @brief Method of checking the completeness of the handshake
				 * @return the flag of the handshake being completed and the connection being established
				 *
				 * \~
				 */
				bool established() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подтверждения подлинности клиентом
				 *
				 * @return признак того, что клиент подтвердил владение ключом сертификата
				 *
				 * @details Раздел 4.4.2 RFC 8446: подлинность клиента подтверждается лишь тогда,
				 *          когда сервер её запросил, а клиент прислал непустую цепочку сертификатов
				 *          и подписал владение её ключом. Пустая цепочка означает, что годного
				 *          сертификата у клиента не нашлось
				 *
				 * \~english
				 * @brief Method of checking the authentication by the client
				 * @return the flag of the client having confirmed the possession of the key of the certificate
				 * @details The section 4.4.2 of RFC 8446: the authenticity of the client is confirmed only when
				 *          the server has requested it, while the client has sent a non-empty chain of the
				 *          certificates and has signed the possession of its key. An empty chain means that no
				 *          suitable certificate has been found at the client
				 *
				 * \~
				 */
				bool certified() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения поры ключей стороны связи
				 *
				 * @param side сторона, чья пора ключей запрашивается
				 *
				 * @return     пора ключей записей, отправляемых этой стороной
				 *
				 * @details Поры сторон сменяются не разом: сторона переходит к ключам прикладных
				 *          данных, отправив своё завершение рукопожатия, а собеседник её - лишь
				 *          отправив своё
				 *
				 * \~english
				 * @brief Method of getting the epoch of the keys of a side of the connection
				 * @param side the side whose epoch of the keys is being requested
				 * @return     the epoch of the keys of the records sent by this side
				 * @details The epochs of the sides do not change simultaneously: a side passes to the keys of
				 *          the application data having sent its completion of the handshake, while its peer
				 *          does so only having sent its own
				 *
				 * \~
				 */
				epoch_t epoch(const session::side_t side) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения хода рукопожатия
				 *
				 * @param role роль стороны, ведущей ход рукопожатия
				 *
				 * @return     признак успешности заведения хода рукопожатия
				 *
				 * \~english
				 * @brief Method of the setting up of the course of the handshake
				 * @param role the role of the side conducting the course of the handshake
				 * @return     the flag of the success of the setting up of the course of the handshake
				 *
				 * \~
				 */
				bool start(const role_t role) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса хода рукопожатия
				 *
				 * \~english
				 * @brief Method of the reset of the course of the handshake
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод объявления сообщения рукопожатия
				 *
				 * @param type вид объявляемого сообщения рукопожатия
				 * @param side сторона, отправившая объявляемое сообщение
				 *
				 * @return     отказ объявления сообщения рукопожатия
				 *
				 * @details Сообщение объявляется и той стороной, что его отправила, и той, что
				 *          его приняла: ход рукопожатия у обеих один и тот же. Отказ означает, что
				 *          рукопожатие прервано и продолжать его нечем
				 *
				 * \~english
				 * @brief Method of the declaration of a message of the handshake
				 * @param type the type of the message of the handshake being declared
				 * @param side the side which has sent the message being declared
				 * @return     the failure of the declaration of the message of the handshake
				 * @details A message is declared both by the party which has sent it and by the one which has
				 *          received it: the course of the handshake is the same at both. A failure means that
				 *          the handshake is aborted and there is nothing to continue it with
				 *
				 * \~
				 */
				error_t accept(const handshake::type_t type, const session::side_t side) noexcept;
				/**
				 * \~russian
				 * @brief Метод объявления просьбы о повторе приветствия клиента
				 *
				 * @return отказ объявления просьбы о повторе приветствия
				 *
				 * @details Раздел 4.1.4 RFC 8446: просьба о повторе приветствия идёт тем же
				 *          сообщением, что и приветствие сервера, и отличить их разбором тела -
				 *          дело слоя выше. Объявляется просьба сразу за приветствием сервера, и
				 *          дозволена она за рукопожатие лишь однажды
				 *
				 * \~english
				 * @brief Method of the declaration of a request of a repetition of the greeting of the client
				 * @return the failure of the declaration of the request of a repetition of the greeting
				 * @details The section 4.1.4 of RFC 8446: a request of a repetition of the greeting goes by the
				 *          same message as the greeting of the server, and to distinguish them by the parsing of
				 *          the body is the business of the layer above. The request is declared right after the
				 *          greeting of the server, and it is allowed only once per handshake
				 *
				 * \~
				 */
				error_t retry() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Machine() noexcept;
		} machine_t;
	};
};

#endif // __ANTS_FLOW__
