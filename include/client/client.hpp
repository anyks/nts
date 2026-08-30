/**
 * @file client.hpp
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
 * @brief Заголовочный файл фасада связи клиента протокола TLS 1.3
 *
 * \~english
 * @brief Header file of the facade of a connection of the client of the TLS 1.3 protocol
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_CLIENT__
#define __ANYKS_TLS_CLIENT__

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
#include <context/context.hpp>

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
	 * @brief Пространство имён внутренних модулей библиотеки
	 *
	 * \~english
	 * @brief Namespace of the internal modules of the library
	 *
	 * \~
	 */
	namespace internal {
		/**
		 * \~russian
		 * @brief Ведение связи протокола TLS 1.3
		 *
		 * @note Устройство ведения связи наружному договору библиотеки не принадлежит:
		 *       здесь оно лишь объявлено, а лежит во внутренних модулях
		 *
		 * \~english
		 * @brief Leading of a connection of the TLS 1.3 protocol
		 * @note The structure of the leading of a connection does not belong to the outward contract
		 *       of the library: here it is only declared, and it lies in the internal modules
		 *
		 * \~
		 */
		class Engine;
	};

	/**
	 * \~russian
	 * @brief Пространство имён фасада связи клиента
	 *
	 * \~english
	 * @brief Namespace of the facade of a connection of the client
	 *
	 * \~
	 */
	namespace client {
		/**
		 * \~russian
		 * @brief Связь протокола TLS 1.3 со стороны клиента
		 *
		 * @details Ввода и вывода связь не ведёт вовсе: принятые байты подаются ей вызовом
		 *          push, а отправляемые она складывает в накопитель, откуда их забирают
		 *          вызовами output и consume. Сеть, файл или память - дело того, кто связь ведёт.
		 *
		 * @note Настройки устанавливаются до заведения связи вызовом start: за ним они уже
		 *       не действуют
		 *
		 * \~english
		 * @brief Connection of the TLS 1.3 protocol from the side of the client
		 * @details The connection does not lead the input and the output at all: the received bytes are
		 *          given to it by a call of push, and it puts the sent ones into an accumulator they are
		 *          taken from by the calls of output and consume. A network, a file or a memory is the
		 *          business of the one who leads the connection.
		 * @note The settings are set before the establishment of the connection by a call of start: after
		 *       it they do not take effect any more
		 *
		 * \~
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Context {
			private:
				// Объект ведения связи протокола
				internal::Engine * _engine;
			public:
				/**
				 * \~russian
				 * @brief Метод получения состояния связи
				 *
				 * @return состояние связи
				 *
				 * \~english
				 * @brief Method of getting the state of the connection
				 * @return the state of the connection
				 *
				 * \~
				 */
				context::state_t state() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения отказа, которым связь оборвана
				 *
				 * @return отказ, которым связь оборвана
				 *
				 * \~english
				 * @brief Method of getting the failure the connection is torn by
				 * @return the failure the connection is torn by
				 *
				 * \~
				 */
				context::error_t error() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки установленности связи
				 *
				 * @return признак того, что рукопожатие пройдено обеими сторонами
				 *
				 * \~english
				 * @brief Method of checking the establishment of the connection
				 * @return the flag of the handshake being passed by both sides
				 *
				 * \~
				 */
				bool established() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения извещения, которым связь оборвана
				 *
				 * @return извещение, которым связь оборвана
				 *
				 * @note Извещение выводится и своё, и принятое от собеседника: связь рвёт та
				 *       сторона, которая отказ заметила первой
				 *
				 * \~english
				 * @brief Method of getting the alert the connection is torn by
				 * @return the alert the connection is torn by
				 * @note Both one's own alert and the one received from the interlocutor are output: the
				 *       connection is torn by the side which noticed the failure first
				 *
				 * \~
				 */
				const alert::alert_t & alert() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения набора шифрования связи
				 *
				 * @return согласованный сторонами набор шифрования
				 *
				 * \~english
				 * @brief Method of getting the cipher suite of the connection
				 * @return the cipher suite agreed upon by the sides
				 *
				 * \~
				 */
				protect::suite_t suite() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения цепочки сертификатов собеседника
				 *
				 * @return цепочка сертификатов, предъявленная собеседником
				 *
				 * @details Связь сличает подпись владения ключом с ключом первого сертификата
				 *          цепочки: этим рукопожатие и привязано к предъявившей его стороне
				 *
				 * @note Доверие к издателю цепочки связь не проверяет: запас доверенных
				 *       сертификатов принадлежит тому, кто связь ведёт, и решение это его
				 *
				 * \~english
				 * @brief Method of getting the chain of the certificates of the interlocutor
				 * @return the chain of the certificates presented by the interlocutor
				 * @details The connection compares the signature of the possession of the key against the
				 *          key of the first certificate of the chain: by this the handshake is tied to the
				 *          side which presented it
				 * @note The connection does not check the trust to the issuer of the chain: the store of the
				 *       trusted certificates belongs to the one who leads the connection, and this decision
				 *       is theirs
				 *
				 * \~
				 */
				const vector <vector <uint8_t>> & peer() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых наборов шифрования
				 *
				 * @param suites устанавливаемые наборы шифрования
				 *
				 * @note Наборы перечисляются от предпочтительного к запасному
				 *
				 * \~english
				 * @brief Method of setting the offered cipher suites
				 * @param suites the cipher suites being set
				 * @note The suites are listed from the preferable one to the spare one
				 *
				 * \~
				 */
				void suites(const vector <protect::suite_t> & suites) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых кривых обмена ключами
				 *
				 * @param groups устанавливаемые кривые обмена ключами
				 *
				 * @note Кривые перечисляются от предпочтительной к запасной
				 *
				 * \~english
				 * @brief Method of setting the offered curves of the key exchange
				 * @param groups the curves of the key exchange being set
				 * @note The curves are listed from the preferable one to the spare one
				 *
				 * \~
				 */
				void groups(const vector <extension::group_t> & groups) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки подлинности своей стороны связи
				 *
				 * @param credential устанавливаемая подлинность своей стороны
				 *
				 * @note Подлинность клиента нужна лишь тогда, когда её запрашивает сервер: без запроса
				 *       цепочка не отправляется вовсе
				 *
				 * \~english
				 * @brief Method of setting the authenticity of one's own side of the connection
				 * @param credential the authenticity of one's own side being set
				 * @note The authenticity of the client is needed only when the server requests it: without a
				 *       request the chain is not sent at all
				 *
				 * \~
				 */
				void credential(const context::credential_t & credential) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки имени узла, запрашиваемого у сервера
				 *
				 * @param name устанавливаемое имя узла
				 *
				 * @details Раздел 3 RFC 6066: имя объявляет серверу, за каким из узлов клиент
				 *          пришёл, - по нему сервер выбирает, какой подлинностью отвечать
				 *
				 * \~english
				 * @brief Method of setting the name of the node requested from the server
				 * @param name the name of the node being set
				 * @details The section 3 of RFC 6066: the name declares to the server which of the nodes the
				 *          client came for — by it the server chooses which authenticity to answer by
				 *
				 * \~
				 */
				void name(const string & name) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения связи
				 *
				 * @return отказ заведения связи
				 *
				 * @details Приветствие клиента складывается в накопитель сразу же: связь заводится тем,
				 *          что клиент первым и говорит
				 *
				 * \~english
				 * @brief Method of the establishment of the connection
				 * @return the failure of the establishment of the connection
				 * @details The greeting of the client is put into the accumulator right away: the connection is
				 *          established by what the client says first
				 *
				 * \~
				 */
				context::error_t start() noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния связи
				 *
				 * @note Настройки связи сбросом не затрагиваются: связь заводится заново теми же
				 *
				 * \~english
				 * @brief Method of the reset of the state of the connection
				 * @note The settings of the connection are not affected by the reset: the connection is
				 *       established anew by the same ones
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи связи принятых байтов
				 *
				 * @param data принятые от собеседника байты
				 *
				 * @return     отказ разбора принятых байтов
				 *
				 * @note Байты подаются как пришли: границы записей протокола связь
				 *       восстанавливает сама
				 *
				 * \~english
				 * @brief Method of the giving of the received bytes to the connection
				 * @param data the bytes received from the interlocutor
				 * @return     the failure of the parsing of the received bytes
				 * @note The bytes are given as they came: the connection restores the boundaries of the
				 *       records of the protocol itself
				 *
				 * \~
				 */
				context::error_t push(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения байтов, отправляемых собеседнику
				 *
				 * @return накопленные байты, отправляемые собеседнику
				 *
				 * @note Просмотр смотрит внутрь накопителя связи: снятие байтов вызовом consume
				 *       его обесценивает
				 *
				 * \~english
				 * @brief Method of getting the bytes sent to the interlocutor
				 * @return the accumulated bytes sent to the interlocutor
				 * @note The view looks inside the accumulator of the connection: the removal of the bytes
				 *       by a call of consume invalidates it
				 *
				 * \~
				 */
				view_t output() const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия отправленных байтов с накопителя
				 *
				 * @param size размер снимаемых байтов
				 *
				 * @note Снимается ровно столько, сколько ушло собеседнику: связь не знает, дошло
				 *       ли отправленное, и судит об этом лишь по этому вызову
				 *
				 * \~english
				 * @brief Method of the removal of the sent bytes from the accumulator
				 * @param size the size of the bytes being removed
				 * @note Exactly as much is removed as went to the interlocutor: the connection does not know
				 *       whether the sent has arrived and judges of it only by this call
				 *
				 * \~
				 */
				void consume(const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод отправки прикладных данных собеседнику
				 *
				 * @param data отправляемые прикладные данные
				 *
				 * @return     отказ отправки прикладных данных
				 *
				 * @note Данные нарезаются на записи протокола сами: длина записи протоколом
				 *       ограничена, а длина отправляемого - нет
				 *
				 * \~english
				 * @brief Method of the sending of the application data to the interlocutor
				 * @param data the application data being sent
				 * @return     the failure of the sending of the application data
				 * @note The data is cut into the records of the protocol by itself: the length of a record is
				 *       limited by the protocol, and the length of the sent is not
				 *
				 * \~
				 */
				context::error_t write(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения принятых прикладных данных
				 *
				 * @param result накопитель, в который переносятся принятые данные
				 *
				 * @return       отказ получения принятых прикладных данных
				 *
				 * @note Принятые данные с накопителя связи снимаются: повторный вызов выдаст
				 *       лишь то, что пришло после
				 *
				 * \~english
				 * @brief Method of getting the received application data
				 * @param result the accumulator the received data is transferred into
				 * @return       the failure of getting the received application data
				 * @note The received data is removed from the accumulator of the connection: a repeated call
				 *       will output only what came after
				 *
				 * \~
				 */
				context::error_t read(vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод смены ключевого материала своего направления связи
				 *
				 * @param request просьба к собеседнику сменить свои ключи в ответ
				 *
				 * @return        отказ смены ключевого материала своего направления
				 *
				 * @details Раздел 4.6.3 RFC 8446: сторона вправе сменить ключи своего направления
				 *          связи в любой миг после рукопожатия, и счётчик записей направления при
				 *          этом начинается заново
				 *
				 * @note Сообщение о смене уходит прежними ключами, а новые ставятся уже за ним:
				 *       иначе собеседник не смог бы прочесть само извещение о смене
				 *
				 * \~english
				 * @brief Method of the change of the key material of one’s own direction of the connection
				 * @param request the request to the interlocutor to change their keys in return
				 * @return        the failure of the change of the key material of one’s own direction
				 * @details The section 4.6.3 of RFC 8446: a side is entitled to change the keys of its direction
				 *          of the connection at any moment after the handshake, and the counter of the records of
				 *          the direction starts anew at that
				 * @note The message about the change goes by the previous keys, and the new ones are set already
				 *       behind it: otherwise the interlocutor would not be able to read the very notification
				 *       about the change
				 *
				 * \~
				 */
				context::error_t update(const bool request = false) noexcept;
				/**
				 * \~russian
				 * @brief Метод закрытия связи
				 *
				 * @return отказ закрытия связи
				 *
				 * @note Извещение о завершении передачи складывается в накопитель: отправить его
				 *       собеседнику - дело того, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of the closing of the connection
				 * @return the failure of the closing of the connection
				 * @note The alert about the finishing of the transfer is put into the accumulator: to send it
				 *       to the interlocutor is the business of the one who leads the connection
				 *
				 * \~
				 */
				context::error_t close() noexcept;
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
				Context() noexcept;
				/**
				 * \~russian
				 * @brief Конструктор копирования
				 *
				 * @note Связь копированию не подлежит: два её списка вели бы одно и то же
				 *       состояние защиты записей, а счётчик записей у него один
				 *
				 * \~english
				 * @brief Copy constructor
				 * @note The connection is not subject to the copying: two copies of it would lead one and the
				 *       same state of the protection of the records, while the counter of the records of it
				 *       is a single one
				 *
				 * \~
				 */
				Context(const Context &) = delete;
				/**
				 * \~russian
				 * @brief Оператор присваивания
				 *
				 * @return связь, которой присваивается значение
				 *
				 * \~english
				 * @brief Assignment operator
				 * @return the connection the value is assigned to
				 *
				 * \~
				 */
				Context & operator = (const Context &) = delete;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Context() noexcept;
		} context_t;
	};
};

#endif // __ANYKS_TLS_CLIENT__
