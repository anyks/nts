/**
 * @file server.hpp
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
 * @brief Заголовочный файл фасада связи сервера протокола TLS 1.3
 *
 * \~english
 * @brief Header file of the facade of a connection of the server of the TLS 1.3 protocol
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_SERVER__
#define __ANTS_SERVER__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <ocsp/ocsp.hpp>
#include <trust/trust.hpp>
#include <context/context.hpp>
#include <fingerprint/fingerprint.hpp>
#include <datagram/datagram.hpp>
#include <hpke/hpke.hpp>

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
	 * @brief Пространство имён фасада связи сервера
	 *
	 * \~english
	 * @brief Namespace of the facade of a connection of the server
	 *
	 * \~
	 */
	namespace server {
		/**
		 * \~russian
		 * @brief Связь протокола TLS 1.3 со стороны сервера
		 *
		 * @details Ввода и вывода связь не ведёт вовсе: принятые байты подаются ей вызовом
		 *          push, а отправляемые она складывает в накопитель, откуда их забирают
		 *          вызовами output и consume. Сеть, файл или память - дело того, кто связь ведёт.
		 *
		 * @note Настройки устанавливаются до заведения связи вызовом start: за ним они уже
		 *       не действуют
		 *
		 * \~english
		 * @brief Connection of the TLS 1.3 protocol from the side of the server
		 * @details The connection does not lead the input and the output at all: the received bytes are
		 *          given to it by a call of push, and it puts the sent ones into an accumulator they are
		 *          taken from by the calls of output and consume. A network, a file or a memory is the
		 *          business of the one who leads the connection.
		 * @note The settings are set before the establishment of the connection by a call of start: after
		 *       it they do not take effect any more
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Context {
			private:
				// Объект ведения связи протокола
				unique_ptr <internal::Engine> _engine;
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
				 * @note Здесь лишь отказы самой связи: обрыв рукопожатия либо приёма. Отказ
				 *       заведения `start()` (например MEMORY при нехватке памяти под настройки)
				 *       выводится возвратом `start()`, а `error()` при этом отвечает NONE и
				 *       `state()` остаётся NONE - судить о заведении по возврату `start()`
				 *
				 * \~english
				 * @brief Method of getting the failure the connection is torn by
				 * @return the failure the connection is torn by
				 * @note Only the failures of the connection itself are here: the abort of the handshake or of
				 *       the reception. The failure of the start `start()` (for example MEMORY at the lack of
				 *       memory for the settings) is given by the return of `start()`, while `error()` answers
				 *       NONE and `state()` stays NONE - judge the start by the return of `start()`
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
				 * @brief Метод отправки запроса сердцебиения (RFC 6520)
				 *
				 * @param payload нагрузка запроса: ответ собеседника обязан вернуть её слово в слово
				 *
				 * @details Запрос идёт лишь по установленной связи издания TLS 1.2 либо DTLS 1.2, при
				 *          предложенном расширении heartbeat (0x000F, из профиля отпечатка) и дозволении
				 *          собеседника peer_allowed_to_send, по одному до ответа (раздел 4 RFC 6520). Сообщение
				 *          несёт вид, длину нагрузки, нагрузку и шестнадцать случайных байтов заполнения.
				 *          Ответ с ожидаемой нагрузкой считается в `pulses()`, иной роняется молча
				 *
				 * @return  отказ отправки: STATE вне установленной связи либо при запросе в пути, SETTINGS без
				 *          расширения либо дозволения, LIMIT при нагрузке шире записи
				 *
				 * \~english
				 * @brief Method of sending a heartbeat request (RFC 6520)
				 *
				 * @param payload the payload of the request: the response of the peer must return it word for word
				 *
				 * @details The request goes only over an established connection of the edition TLS 1.2 or DTLS 1.2,
				 *          with the heartbeat extension offered (0x000F, from a fingerprint profile) and the
				 *          peer_allowed_to_send permission of the peer, one at a time until a response (the section 4
				 *          of RFC 6520). The message carries the type, the length of the payload, the payload and
				 *          sixteen random bytes of padding. A response with the expected payload is counted in
				 *          `pulses()`, another one is dropped silently
				 *
				 * @return  the failure of the sending: STATE outside an established connection or with a request in
				 *          flight, SETTINGS without the extension or the permission, LIMIT at a payload wider than a record
				 *
				 * \~
				 */
				context::error_t heartbeat(const view_t & payload) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа принятых ответов на свои запросы сердцебиения
				 *
				 * @return число ответов с ожидаемой нагрузкой
				 *
				 * \~english
				 * @brief Method of getting the number of the received responses to one's own heartbeat requests
				 *
				 * @return the number of the responses with the expected payload
				 *
				 * \~
				 */
				size_t pulses() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения предела длины открытого содержимого отправляемой записи
				 *
				 * @details Предел, объявленный собеседником расширением record_size_limit (RFC 8449)
				 *          либо max_fragment_length (раздел 4 RFC 6066); без договора - предел
				 *          протокола RECORD_PLAINTEXT. Учитывается нарезкой всякой записи связи
				 *
				 * @return  предел в байтах
				 *
				 * \~english
				 * @brief Method of getting the limit of the length of the plaintext content of a record being sent
				 *
				 * @details The limit declared by the peer with the record_size_limit (RFC 8449) or
				 *          max_fragment_length (the section 4 of RFC 6066) extension; without an agreement,
				 *          the protocol limit RECORD_PLAINTEXT. Respected by the splitting of every record
				 *
				 * @return  the limit in bytes
				 *
				 * \~
				 */
				size_t ceiling() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения предела длины открытого содержимого принимаемой записи
				 *
				 * @details Свой предел, объявленный и подтверждённый собеседником; без договора -
				 *          предел протокола RECORD_PLAINTEXT. Запись длиннее отвергается извещением
				 *          record_overflow
				 *
				 * @return  предел в байтах
				 *
				 * \~english
				 * @brief Method of getting the limit of the length of the plaintext content of a record being received
				 *
				 * @details The own limit declared and confirmed by the peer; without an agreement, the
				 *          protocol limit RECORD_PLAINTEXT. A longer record is rejected with the
				 *          record_overflow alert
				 *
				 * @return  the limit in bytes
				 *
				 * \~
				 */
				size_t threshold() const noexcept;
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
				 * @brief Метод получения группы обмена ключами связи
				 *
				 * @return согласованная сторонами группа обмена ключами
				 *
				 * @note До установления связи и у возобновления по билету без обмена ключами - NONE;
				 *       у гибрида X25519MLKEM768 отдаётся именно он - так потребитель считает,
				 *       сколько связей сложилось постквантовым обменом
				 *
				 * \~english
				 * @brief Method of getting the key exchange group of the connection
				 * @return the key exchange group agreed upon by the sides
				 * @note Before the establishment of the connection and at a resumption by a ticket without a key
				 *       exchange - NONE; at the X25519MLKEM768 hybrid it is the one given - so the
				 *       consumer counts how many connections were made by the post-quantum exchange
				 *
				 * \~
				 */
				extension::group_t group() const noexcept;
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
				 * @note У связи издания 1.2, возобновлённой билетом RFC 5077, цепочка состоит из
				 *       одного сертификата клиента, унаследованного билетом от выдавшей связи с
				 *       проверенной подлинностью; при запросе подлинности билет без неё
				 *       возобновления не даёт, и подлинность запрашивается полным рукопожатием
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
				 * @note At a connection of the 1.2 edition resumed by a ticket of RFC 5077 the chain consists of
				 *       the single certificate of the client inherited by the ticket from the issuing connection
				 *       with the verified authenticity; at the request of the authenticity a ticket without it
				 *       gives no resumption, and the authenticity is requested by a full handshake
				 *
				 * \~
				 */
				const vector <vector <uint8_t>> & peer() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения алгоритма сжатия цепочки сертификатов направления
				 *
				 * @param direction направление связи относительно своей стороны
				 *
				 * @return          опознаватель алгоритма по реестру RFC 8879, ноль у несжатой цепочки
				 *
				 * @details Чтение отвечает цепочке собеседника: ноль означает, что она пришла обычным
				 *          сообщением Certificate. Запись отвечает своей цепочке: ноль означает, что
				 *          общего алгоритма не нашлось либо сжатие у потребителя отказало
				 *
				 * \~english
				 * @brief Method of getting the algorithm of the compression of the chain of the certificates of a direction
				 * @param direction the direction of the connection relative to one's own side
				 * @return          the identifier of the algorithm by the registry of RFC 8879, zero at an uncompressed chain
				 * @details The reading answers to the chain of the interlocutor: zero means that it came by the
				 *          ordinary Certificate message. The writing answers to one's own chain: zero means that
				 *          no common algorithm was found or the compression at the consumer has refused
				 *
				 * \~
				 */
				uint16_t compression(const context::direction_t direction) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения прикладного протокола связи
				 *
				 * @return прикладной протокол, выбранный сторонами связи
				 *
				 * @details Раздел 3.2 RFC 7301: протокол выбирается сервером из предложенного
				 *          клиентом, и объявляется он под защитой рукопожатия
				 *
				 * @note Пустое название значит, что протокол сторонами не выбирался вовсе:
				 *       предлагать его связи никто не поручал
				 *
				 * \~english
				 * @brief Method of getting the application protocol of the connection
				 * @return the application protocol chosen by the sides of the connection
				 * @details The section 3.2 of RFC 7301: the protocol is chosen by the server out of the one
				 *          offered by the client, and it is declared under the protection of the handshake
				 * @note An empty name means that the protocol was not chosen by the sides at all: nobody
				 *       instructed the connection to offer it
				 *
				 * \~
				 */
				const string & protocol() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки согласования прикладных настроек ALPS
				 *
				 * @return признак того, что прикладные настройки сторонами согласованы
				 *
				 * @details Черновик draft-vvv-tls-alps: настройки согласованы, когда обе стороны
				 *          объявили их для выбранного прикладного протокола одной точкой кода;
				 *          при принятых упреждающих данных состояние унаследовано от билета
				 *
				 * \~english
				 * @brief Method of checking the negotiation of the application settings ALPS
				 * @return the flag of the application settings having been negotiated by the sides
				 * @details The draft-vvv-tls-alps: the settings are negotiated when both sides have declared
				 *          them for the chosen application protocol by one code point; with the accepted
				 *          early data the state is inherited from the ticket
				 *
				 * \~
				 */
				bool settled() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения прикладных настроек собеседника
				 *
				 * @return прикладные настройки собеседника как есть
				 *
				 * @note Пустые настройки означают либо пустые настройки собеседника, либо их
				 *       отсутствие - различать их велит settled()
				 *
				 * \~english
				 * @brief Method of getting the application settings of the peer
				 * @return the application settings of the peer as they are
				 * @note Empty settings mean either the empty settings of the peer or their absence -
				 *       settled() tells them apart
				 *
				 * \~
				 */
				const vector <uint8_t> & settings() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения точки кода расширения прикладных настроек ALPS
				 *
				 * @return вид расширения, которым ведётся связь: SETTINGS либо SETTINGS_OLD
				 *
				 * \~english
				 * @brief Method of getting the code point of the extension of the application settings ALPS
				 * @return the type of the extension by which the connection goes: SETTINGS or SETTINGS_OLD
				 *
				 * \~
				 */
				extension::type_t codepoint() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения имени узла, запрошенного клиентом
				 *
				 * @return имя узла, за которым клиент пришёл
				 *
				 * @details Раздел 3 RFC 6066: по этому имени сервер и выбирает, какой
				 *          подлинностью отвечать клиенту
				 *
				 * @note Связь имя лишь принимает: выбор подлинности по нему принадлежит тому,
				 *       кто связь ведёт, - подлинность устанавливает он
				 *
				 * \~english
				 * @brief Method of getting the name of the host requested by the client
				 * @return the name of the host the client came for
				 * @details The section 3 of RFC 6066: by this name the server chooses which authenticity to
				 *          answer the client by
				 * @note The connection only accepts the name: the choice of the authenticity by it belongs
				 *       to the one who leads the connection — they set the authenticity
				 *
				 * \~
				 */
				const string & name() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения билетов возобновления связи
				 *
				 * @return билеты возобновления связи, выданные клиенту
				 *
				 * @note Билет и ключ к нему хранит тот, кто связь ведёт: связь их лишь выдаёт,
				 *       а держать их между связями ей негде
				 *
				 * \~english
				 * @brief Method of getting the tickets of the resumption of the connection
				 * @return the tickets of the resumption of the connection issued to the client
				 * @note The ticket and the key to it are kept by the one who leads the connection: the connection
				 *       only outputs them, and it has nowhere to keep them between the connections
				 *
				 * \~
				 */
				const vector <context::ticket_t> & tickets() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки возобновления связи билетом
				 *
				 * @return признак того, что связь возобновлена заранее разделённым ключом
				 *
				 * @note При возобновлении цепочки сертификатов не бывает вовсе: подлинность
				 *       сторон подтверждена билетом, а не сертификатом
				 *
				 * \~english
				 * @brief Method of checking the resumption of the connection by a ticket
				 * @return the flag of the connection being resumed by a pre-shared key
				 * @note At a resumption there is no chain of the certificates at all: the authenticity of the
				 *       sides is confirmed by the ticket and not by a certificate
				 *
				 * \~
				 */
				bool shared() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых наборов шифрования
				 *
				 * @param suites устанавливаемые наборы шифрования
				 *
				 * @note Наборы перечисляются от предпочтительного к запасному
				 * @note Пустой список установку пропускает, сохраняя набор, установленный прежде
				 * @note Умолчание - классика без ГОСТ; наборы ГОСТ («Кузнечик» и «Магма» в MGM)
				 *       объявляет сам потребитель: как поддержку, дописав их к перечню из
				 *       получателя suites(), либо как единственный вариант, заменив перечень целиком
				 *
				 * \~english
				 * @brief Method of setting the offered cipher suites
				 * @param suites the cipher suites being set
				 * @note The suites are listed from the preferable one to the spare one
				 * @note An empty list skips the setting, keeping the set having been set before
				 * @note The default is the classic without GOST; the GOST suites (Kuznyechik and Magma in MGM)
				 *       are declared by the consumer itself: as a support, appending them to the list from the
				 *       getter suites(), or as the only option, replacing the list wholly
				 *
				 * \~
				 */
				void suites(const vector <protect::suite_t> & suites) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки журнала секретов связи
				 *
				 * @param keylog журнал секретов: вызов и контекст потребителя
				 *
				 * @details NSS Key Log Format: записи CLIENT_RANDOM (TLS 1.2),
				 *          CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET,
				 *          CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 (TLS 1.3)
				 *          для Wireshark
				 *
				 * \~english
				 * @brief Method of setting the connection secrets log
				 *
				 * @param keylog the secrets log: the call and the context of the consumer
				 *
				 * @details NSS Key Log Format: records CLIENT_RANDOM (TLS 1.2),
				 *          CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET,
				 *          CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 (TLS 1.3)
				 *          for Wireshark
				 *
				 * \~
				 */
				void keylog(const context::keylog_t & keylog) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения предлагаемых наборов шифрования
				 *
				 * @return перечень наборов шифрования: назначенный потребителем либо умолчание
				 *
				 * @note Умолчание - классика: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM и
				 *       наборы издания 1.2; наборов ГОСТ в нём нет, их потребитель объявляет
				 *       сам вызовом suites(), дописав к этому перечню либо заменив его целиком
				 *
				 * \~english
				 * @brief Method of getting the offered cipher suites
				 * @return the list of the cipher suites: the one set by the consumer or the default
				 * @note The default is the classic: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM and the suites
				 *       of the 1.2 edition; there are no GOST suites in it, the consumer declares them by the
				 *       call of suites(), appending to this list or replacing it wholly
				 *
				 * \~
				 */
				const vector <protect::suite_t> & suites() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки пределов издания протокола
				 *
				 * @param lowest  наименьшее дозволенное издание: 0x0303 (издание 1.2) либо 0x0304 (издание 1.3)
				 * @param highest наибольшее дозволенное издание: 0x0303 либо 0x0304
				 *
				 * @return        отказ установки: SETTINGS у издания ниже TLS 1.2 либо перевёрнутых
				 *                пределов, STATE у уже заведённой связи
				 *
				 * @details Раздел 4.2.1 RFC 8446 и приложение D RFC 8446: клиент объявляет издания
				 *          расширением supported_versions, сервер выбирает высшее общее; чужая
				 *          сторона без расширения ведёт связь изданием заголовка приветствия -
				 *          TLS 1.2. Умолчание - от 1.2 до 1.3; режим «только 1.3» - оба предела
				 *          0x0304; ниже 1.2 связь не опускается никогда
				 *
				 * @note Издания задаются и отдаются кодами TLS 0x0303/0x0304 на любом переносе; на
				 *       проводе DTLS они ложатся как 0xFEFD/0xFEFC. Поверх дейтаграмм 0x0303 отвечает
				 *       DTLS 1.2 (RFC 6347), 0x0304 - DTLS 1.3 (RFC 9147); под QUIC связь знает одно
				 *       издание 1.3. Коды провода DTLS на входе НЕ принимаются: versions(0xFEFD, 0xFEFD)
				 *       отвечает SETTINGS - издание DTLS 1.2 закрепляется как versions(0x0303, 0x0303)
				 *       . Когда предлагается одно лишь издание 1.2 (оба предела 0x0303), приветствие клиента
				 *       идёт без расширения supported_versions, как у openssl: издание сервер берёт из
				 *       заголовка приветствия (раздел 4.2.1 RFC 8446); с изданием 1.3 либо DTLS 1.0 в
				 *       перечне расширение кладётся
				 *
				 * \~english
				 * @brief Method of setting the limits of the edition of the protocol
				 * @param lowest  the lowest allowed edition: 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3)
				 * @param highest the highest allowed edition: 0x0303 or 0x0304
				 * @return        the failure of the setting: SETTINGS at an edition below TLS 1.2 or at inverted
				 *                limits, STATE at an already established connection
				 * @details The section 4.2.1 of RFC 8446 and the appendix D of RFC 8446: the client announces the
				 *          editions by the supported_versions extension, the server chooses the highest common one;
				 *          a foreign side without the extension conducts the connection by the edition of the header
				 *          of the greeting - TLS 1.2. The default is from 1.2 to 1.3; the «1.3 only» mode - both
				 *          limits 0x0304; the connection never goes below 1.2
				 * @note The editions are set and returned by the TLS codes 0x0303/0x0304 on any transport; on the
				 *       DTLS wire they are laid as 0xFEFD/0xFEFC. Over datagrams 0x0303 stands for DTLS 1.2
				 *       (RFC 6347), 0x0304 - for DTLS 1.3 (RFC 9147); under QUIC the connection knows the 1.3
				 *       edition alone. The DTLS wire codes are NOT accepted as input: versions(0xFEFD, 0xFEFD)
				 *       answers SETTINGS - the DTLS 1.2 edition is pinned as versions(0x0303, 0x0303)
				 *       . When the 1.2 edition alone is offered (both limits 0x0303), the greeting of the client
				 *       goes without the supported_versions extension, like at openssl: the server takes the
				 *       edition from the header of the greeting (the section 4.2.1 of RFC 8446); with the 1.3
				 *       or the DTLS 1.0 edition in the list the extension is put
				 *
				 * \~
				 */
				context::error_t versions(const uint16_t lowest, const uint16_t highest) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки обязательности расширенного главного секрета издания 1.2
				 *
				 * @param mandatory отвергается ли собеседник без расширения RFC 7627
				 *
				 * @details Решение 16 движка: расширение extended_master_secret предлагается и
				 *          подтверждается всегда; умолчанием, как у openssl и BoringSSL, собеседник без
				 *          него ведёт связь обычным главным секретом (раздел 8.1 RFC 5246) - иначе издание
				 *          1.2 не сходилось бы со стеками без RFC 7627 (LibreSSL). Обязательность закрывает
				 *          тройное рукопожатие: собеседник без расширения отвергается handshake_failure
				 *
				 * @note Значимо лишь изданию 1.2; у издания 1.3 главный секрет расширен по устройству
				 *
				 * \~english
				 * @brief Method of setting the obligation of the extended master secret of the 1.2 edition
				 * @param mandatory whether a peer without the RFC 7627 extension is rejected
				 * @details Decision 16 of the engine: the extended_master_secret extension is always offered and
				 *          confirmed; by default, like at openssl and BoringSSL, a peer without it conducts the
				 *          connection by the ordinary master secret (the section 8.1 of RFC 5246) - otherwise the
				 *          1.2 edition would not converge with the stacks without RFC 7627 (LibreSSL). The obligation
				 *          closes the triple handshake: a peer without the extension is rejected by handshake_failure
				 * @note Matters only to the 1.2 edition; at the 1.3 edition the master secret is extended by design
				 *
				 * \~
				 */
				void master(const bool mandatory) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки обязательности расширенного главного секрета издания 1.2
				 *
				 * @return признак того, что собеседник без расширения RFC 7627 отвергается
				 *
				 * \~english
				 * @brief Method of checking the obligation of the extended master secret of the 1.2 edition
				 * @return the sign that a peer without the RFC 7627 extension is rejected
				 *
				 * \~
				 */
				bool master() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения наименьшего дозволенного издания протокола
				 *
				 * @return наименьшее дозволенное издание протокола
				 *
				 * \~english
				 * @brief Method of getting the lowest allowed edition of the protocol
				 * @return the lowest allowed edition of the protocol
				 *
				 * \~
				 */
				uint16_t lowest() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения наибольшего дозволенного издания протокола
				 *
				 * @return наибольшее дозволенное издание протокола
				 *
				 * \~english
				 * @brief Method of getting the highest allowed edition of the protocol
				 * @return the highest allowed edition of the protocol
				 *
				 * \~
				 */
				uint16_t highest() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения издания протокола, согласованного сторонами
				 *
				 * @return 0x0304 у издания 1.3, 0x0303 у издания 1.2, ноль до согласования
				 *
				 * @note Издания задаются и отдаются кодами TLS 0x0303/0x0304 на любом переносе; на
				 *       проводе DTLS они ложатся как 0xFEFD/0xFEFC. Проводное издание наружу не
				 *       показывается: 0x0303 поверх дейтаграмм означает DTLS 1.2, 0x0304 - DTLS 1.3
				 *
				 * \~english
				 * @brief Method of getting the edition of the protocol agreed by the sides
				 * @return 0x0304 at the 1.3 edition, 0x0303 at the 1.2 edition, a zero before the agreement
				 * @note The editions are set and returned by the TLS codes 0x0303/0x0304 on any transport; on the
				 *       DTLS wire they are laid as 0xFEFD/0xFEFC. The wire edition is not shown outside: 0x0303
				 *       over datagrams means DTLS 1.2, 0x0304 - DTLS 1.3
				 *
				 * \~
				 */
				uint16_t version() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки порядка выбора набора шифрования и кривой обмена ключами
				 *
				 * @param own выбираются ли набор и кривая порядком сервера (умолчание), а не клиента
				 *
				 * @details Разделы 7.4.1.2 RFC 5246 и 4.1.1 RFC 8446 велят выбирать серверу; порядком
				 *          клиента сервер выбирает, когда потребитель так велел. Настройка ведёт выбор
				 *          набора обоих изданий и кривой обмена издания 1.3: своим порядком сервер
				 *          берёт первую свою кривую, по которой у клиента есть доля, порядком клиента -
				 *          первую его долю, которую сам поддерживает; просьба о повторе идёт лишь без
				 *          единой общей доли. Порядок перечней - это и есть предпочтение: сервер с ГОСТ
				 *          впереди перечня берёт у клиента с поддержкой ГОСТ именно ГОСТ
				 *
				 * \~english
				 * @brief Method of setting the order of the choice of the cipher suite and of the curve of the key exchange
				 * @param own whether the suite and the curve are chosen by the order of the server (the default) and not of the client
				 * @details The sections 7.4.1.2 of RFC 5246 and 4.1.1 of RFC 8446 order the server to choose; the
				 *          server chooses by the order of the client when the consumer has told so. The setting leads
				 *          the choice of the suite of both editions and of the curve of the exchange of the 1.3
				 *          edition: by its own order the server takes its first curve the client has a share for, by
				 *          the order of the client - its first share the server supports itself; a request of a retry
				 *          goes only without a single common share. The order of the lists is the preference itself:
				 *          a server with GOST ahead of its list takes exactly GOST from a client with the GOST support
				 *
				 * \~
				 */
				void preference(const bool own) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых кривых обмена ключами
				 *
				 * @param groups устанавливаемые кривые обмена ключами
				 *
				 * @note Кривые перечисляются от предпочтительной к запасной
				 * @note Пустой список установку пропускает, сохраняя набор, установленный прежде
				 * @note Умолчание - классика без ГОСТ; кривые ГОСТ (GC256A…GC512C) объявляет сам
				 *       потребитель: как поддержку, дописав их к перечню из получателя groups(),
				 *       либо как единственный вариант, заменив перечень целиком
				 *
				 * \~english
				 * @brief Method of setting the offered curves of the key exchange
				 * @param groups the curves of the key exchange being set
				 * @note The curves are listed from the preferable one to the spare one
				 * @note An empty list skips the setting, keeping the set having been set before
				 * @note The default is the classic without GOST; the GOST curves (GC256A…GC512C) are declared by
				 *       the consumer itself: as a support, appending them to the list from the getter groups(),
				 *       or as the only option, replacing the list wholly
				 *
				 * \~
				 */
				void groups(const vector <extension::group_t> & groups) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения предлагаемых кривых обмена ключами
				 *
				 * @return перечень кривых обмена ключами: назначенный потребителем либо умолчание
				 *
				 * @note Умолчание - то, что предлагают браузеры и OpenSSL 3.5: X25519MLKEM768,
				 *       X25519, secp256r1, secp384r1; кривых ГОСТ в нём нет, их потребитель
				 *       объявляет сам вызовом groups(), дописав к этому перечню либо заменив его
				 *       целиком
				 *
				 * \~english
				 * @brief Method of getting the offered curves of the key exchange
				 * @return the list of the curves of the key exchange: the one set by the consumer or the default
				 * @note The default is what the browsers and OpenSSL 3.5 offer: X25519MLKEM768, X25519,
				 *       secp256r1, secp384r1; there are no GOST curves in it, the consumer declares them by the
				 *       call of groups(), appending to this list or replacing it wholly
				 *
				 * \~
				 */
				const vector <extension::group_t> & groups() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки признаваемых схем подписи
				 *
				 * @param schemes устанавливаемые схемы подписи
				 *
				 * @note Схемы перечисляются от предпочтительной к запасной; перечень объявляется
				 *       собеседнику и им же выбирается схема своей подписи по своему ключу
				 * @note Пустой список установку пропускает, сохраняя набор, установленный прежде
				 * @note Умолчание - классика без ГОСТ; схемы ГОСТ (S256A…S512C) объявляет сам
				 *       потребитель: как поддержку, дописав их к перечню из получателя schemes(),
				 *       либо как единственный вариант, заменив перечень целиком. Подлинность ГОСТ
				 *       без объявленных обеими сторонами схем ГОСТ подписать ничего не сможет
				 *
				 * \~english
				 * @brief Method of setting the recognized signature schemes
				 * @param schemes the signature schemes being set
				 * @note The schemes are listed from the preferable one to the spare one; the list is declared
				 *       to the peer and by it the scheme of the own signature is chosen by the own key
				 * @note An empty list skips the setting, keeping the set having been set before
				 * @note The default is the classic without GOST; the GOST schemes (S256A…S512C) are declared by
				 *       the consumer itself: as a support, appending them to the list from the getter schemes(),
				 *       or as the only option, replacing the list wholly. A GOST credential without the GOST
				 *       schemes declared by both sides is unable to sign anything
				 *
				 * \~
				 */
				void schemes(const vector <extension::scheme_t> & schemes) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения признаваемых схем подписи
				 *
				 * @return перечень схем подписи: назначенный потребителем либо умолчание
				 *
				 * @note Умолчание - классика: ECDSA, RSA-PSS, Ed25519, RSA PKCS #1; схем ГОСТ в нём
				 *       нет, их потребитель объявляет сам вызовом schemes(), дописав к этому
				 *       перечню либо заменив его целиком. Подлинность ГОСТ без объявленных схем
				 *       ГОСТ подписать ничего не сможет
				 *
				 * \~english
				 * @brief Method of getting the recognized signature schemes
				 * @return the list of the signature schemes: the one set by the consumer or the default
				 * @note The default is the classic: ECDSA, RSA-PSS, Ed25519, RSA PKCS #1; there are no GOST
				 *       schemes in it, the consumer declares them by the call of schemes(), appending to this
				 *       list or replacing it wholly. A GOST credential without the declared GOST schemes is
				 *       unable to sign anything
				 *
				 * \~
				 */
				const vector <extension::scheme_t> & schemes() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки алгоритмов сжатия цепочки сертификатов
				 *
				 * @param codecs    устанавливаемые алгоритмы в порядке предпочтения
				 * @param inflation предел длины цепочки после распаковки в байтах, ноль оставляет умолчание 65536
				 *
				 * @details RFC 8879: алгоритмы предоставляет потребитель, библиотека ни одного не
				 *          несёт. Сервер выбирает алгоритм из объявленных клиентом и объявляет свой
				 *          перечень запросом подлинности клиента.
				 *          Цепочка сжимается первым общим алгоритмом по порядку объявившей стороны;
				 *          неведомые значения собеседника пропускаются молча
				 *
				 * @note Пустой перечень выключает сжатие: расширение не объявляется, и рукопожатие
				 *       идёт байт в байт как без него
				 * @note Алгоритм без обоих вызовов либо с нулевым опознавателем заводить связь не
				 *       даёт: отказ настроек
				 *
				 * \~english
				 * @brief Method of setting the algorithms of the compression of the chain of the certificates
				 * @param codecs    the algorithms being set in the order of the preference
				 * @param inflation the limit of the length of the chain after the decompression in bytes, zero keeps the default of 65536
				 * @details RFC 8879: the algorithms are provided by the consumer, the library carries none.
				 *          The server chooses the algorithm from the ones announced by the client and
				 *          announces its own list by the request of the authenticity of the client.
				 *          The chain is compressed by the first common algorithm in the order of the announcing
				 *          side; the values of the peer unknown to the connection are skipped silently
				 * @note An empty list switches the compression off: the extension is not announced, and the
				 *       handshake goes byte for byte as without it
				 * @note An algorithm without both calls or with a zero identifier does not let the connection
				 *       be established: the failure of the settings
				 *
				 * \~
				 */
				void codecs(const vector <context::codec_t> & codecs, const size_t inflation) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки запроса состояния сертификата собеседника
				 *
				 * @param request запрашивается ли состояние сертификата собеседника
				 *
				 * @details Раздел 4.4.2.1 RFC 8446 и раздел 8 RFC 6066: запрос идёт расширением
				 *          status_request (0x0005) запроса подлинности клиента; ответ приходит расширением записи
				 *          цепочки сертификатов собеседника и доступен вызовом status()
				 *
				 * @note Отсутствие ответа при запросе отказом не считается: собеседник вправе
				 *       не отвечать, а потребитель узнаёт об этом пустым ответом
				 *
				 * @note Запрос самодостаточен: расширение уходит и без иных настроек связи,
				 *       а полученный ответ сам по себе связь не судит - проверка включается
				 *       только явно вызовом verification(), иначе ответ лишь отдаётся наружу
				 *
				 * \~english
				 * @brief Method of setting the request of the certificate status of the peer
				 * @param request whether the certificate status of the peer is requested
				 * @details The section 4.4.2.1 of RFC 8446 and the section 8 of RFC 6066: the request goes as the
				 *          extension status_request (0x0005) of the certificate request; the response comes as an extension of the
				 *          entry of the certificate chain of the peer and is available by the call of status()
				 * @note The absence of a response upon the request is not considered a failure: the peer is entitled
				 *       not to respond, and the consumer learns about it by an empty response
				 * @note The request is self-sufficient: the extension goes without any other settings of the connection,
				 *       and a received response does not judge the connection by itself - the check is enabled only
				 *       explicitly by the call of verification(), otherwise the response is merely given outside
				 *
				 * \~
				 */
				void status(const bool request) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ответа о состоянии своего сертификата для сшивки
				 *
				 * @param response запись ответа OCSP по RFC 6960, пустая снимает ответ
				 * @param index    место сертификата в своей цепочке, ноль - лист
				 *
				 * @details Ответ ответчика получает потребитель сам (адрес - ocsp::responder,
				 *          запрос - ocsp::request) и подаёт октетами; связь его не разбирает,
				 *          а сшивает в расширение status_request записи цепочки по запросу
				 *          собеседника (раздел 4.4.2.1 RFC 8446, раздел 8 RFC 6066)
				 *
				 * \~english
				 * @brief Method of setting the status response of the own certificate for the stapling
				 * @param response the record of the OCSP response according to RFC 6960, an empty one removes the response
				 * @param index    the place of the certificate in the own chain, zero is the leaf
				 * @details The response of the responder is obtained by the consumer itself (the address is
				 *          ocsp::responder, the request is ocsp::request) and is given as octets; the connection
				 *          does not parse it but staples it into the extension status_request of the entry of the
				 *          chain upon the request of the peer (the section 4.4.2.1 of RFC 8446, the section 8 of RFC 6066)
				 *
				 * \~
				 */
				void status(const vector <uint8_t> & response, const size_t index = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки перечня меток времени своего сертификата для выдачи по запросу
				 *
				 * @param list перечень SignedCertificateTimestampList как записан (RFC 6962, раздел 3.3)
				 *
				 * @details Перечень идёт лишь по запросу клиента расширением signed_certificate_timestamp:
				 *          изданием 1.3 - расширением записи листа цепочки, изданием 1.2 - расширением
				 *          приветствия сервера, не при возобновлении и лишь при подлинности сертификатом
				 *
				 * @note Негодная запись перечня (пустой перечень, пустая запись, хвост) отвергается
				 *       заведением связи отказом SETTINGS; сами метки связь не толкует
				 *
				 * \~english
				 * @brief Method of setting the list of the timestamps of the own certificate for giving out upon request
				 * @param list the SignedCertificateTimestampList as it is written (RFC 6962, the section 3.3)
				 * @details The list goes only upon the request of the client by the signed_certificate_timestamp
				 *          extension: in the 1.3 edition as an extension of the leaf entry of the chain, in the 1.2
				 *          edition as an extension of the server hello, not on resumption and only with the
				 *          authenticity by a certificate
				 * @note An unfit record of the list (an empty list, an empty entry, a tail) is rejected by the
				 *       start of the connection with the SETTINGS failure; the timestamps themselves are not
				 *       interpreted by the connection
				 *
				 * \~
				 */
				void timestamps(const vector <uint8_t> & list) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ответа о состоянии сертификата собеседника
				 *
				 * @return запись ответа OCSP по RFC 6960 либо пустой накопитель
				 *
				 * @note Ответ отдаётся как принят - и без проверки, и с ней; разобрать его
				 *       потребитель вправе модулем ocsp
				 *
				 * \~english
				 * @brief Method of getting the certificate status response of the peer
				 * @return the record of the OCSP response according to RFC 6960 or an empty accumulator
				 * @note The response is given out as received - both without the check and with it; the consumer
				 *       is entitled to parse it by the ocsp module
				 *
				 * \~
				 */
				const vector <uint8_t> & status() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки проверки принятого ответа о состоянии сертификата
				 *
				 * @param verify проверяется ли принятый ответ связью
				 * @param leeway дозволенный люфт сроков ответа в секундах в обе стороны
				 * @param store  запас доверенных сертификатов для розыска издателя собеседника
				 *
				 * @details Ответ проверяется модулем ocsp против первого сертификата цепочки
				 *          собеседника и его издателя: издатель берётся вторым звеном цепочки,
				 *          у самоподписанного сертификата - им самим, а у цепочки из одного
				 *          сертификата - из запаса по имени издателя. Сроки судятся мигом,
				 *          установленным вызовом moment(); нулевой миг сроки не судит,
				 *          а миг, отстоящий от срока ответа, законно даёт отказ EXPIRED - это
				 *          не порок ответчика, а часы потребителя.
				 *          Негодный ответ и отозванный сертификат обрывают связь извещением
				 *          «bad_certificate_status_response» (113); неведомый ответчику
				 *          сертификат связь не обрывает - состояние доступно вызовом certified()
				 *
				 * \~english
				 * @brief Method of setting the check of the received certificate status response
				 * @param verify whether the received response is checked by the connection
				 * @param leeway the allowed slack of the validity of the response in seconds in both directions
				 * @param store  the store of the trusted certificates for the search of the issuer of the peer
				 * @details The response is checked by the ocsp module against the first certificate of the chain of
				 *          the peer and its issuer: the issuer is taken as the second link of the chain, for a
				 *          self-signed certificate - as itself, and for a chain of a single certificate - from the
				 *          store by the name of the issuer. The validity is judged by the moment set by the call of
				 *          moment(); a zero moment does not judge the validity, while a moment away from the
				 *          validity of the response lawfully yields the failure EXPIRED - that is not a fault of the
				 *          responder but the clock of the consumer. An unsuitable response and a revoked
				 *          certificate tear the connection by the alert «bad_certificate_status_response» (113); a
				 *          certificate unknown to the responder does not tear the connection - the status is
				 *          available by the call of certified()
				 *
				 * \~
				 */
				void verification(const bool verify, const int64_t leeway, const trust::store_t & store) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения состояния сертификата собеседника
				 *
				 * @return состояние по проверенному ответу либо ocsp::status_t::NONE
				 *
				 * \~english
				 * @brief Method of getting the certificate status of the peer
				 * @return the status by the checked response or ocsp::status_t::NONE
				 *
				 * \~
				 */
				ocsp::status_t certified() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки подлинности своей стороны связи
				 *
				 * @param credential устанавливаемая подлинность своей стороны
				 *
				 * @note Подлинность сервера обязательна: без своего сертификата и ключа связь не
				 *       заводится вовсе
				 *
				 * @note Ключ подлинности стоит подготовить один раз (credential_t::prepare()):
				 *       подготовленный ключ разделяется всеми связями, а без подготовки связь
				 *       готовит его сама при первой надобности
				 *
				 * \~english
				 * @brief Method of setting the authenticity of one's own side of the connection
				 * @param credential the authenticity of one's own side being set
				 * @note The authenticity of the server is obligatory: without one’s own certificate and key the
				 *       connection is not established at all
				 * @note The key of the authenticity is worth preparing once (credential_t::prepare()): a
				 *       prepared key is shared by all the connections, and without the preparation the
				 *       connection prepares it itself at the first need
				 *
				 * \~
				 */
				void credential(const context::credential_t & credential) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки предлагаемых прикладных протоколов
				 *
				 * @param protocols устанавливаемые прикладные протоколы
				 *
				 * @details Раздел 3.1 RFC 7301: порядок перечня объявляет предпочтение стороны,
				 *          а выбор из него делает сервер
				 *
				 * @note Пустой перечень отключает выбор прикладного протокола вовсе
				 *
				 * \~english
				 * @brief Method of setting the offered application protocols
				 * @param protocols the application protocols being set
				 * @details The section 3.1 of RFC 7301: the order of the list declares the preference of the
				 *          side, and the choice out of it is made by the server
				 * @note An empty list disables the choice of the application protocol at all
				 *
				 * \~
				 */
				void protocols(const vector <string> & protocols) noexcept;
				/**
				 * \~russian
				 * @brief Метод объявления прикладных настроек ALPS для прикладного протокола
				 *
				 * @param protocol прикладной протокол, для которого объявляются настройки
				 * @param value    прикладные настройки как есть
				 *
				 * @details Черновик draft-vvv-tls-alps: настройки прикладного уровня согласуются
				 *          рукопожатием издания 1.3 для выбранного протокола; вызовы копятся по
				 *          протоколам, повтор по тому же протоколу заменяет настройки. Протокол
				 *          обязан значиться в protocols(), иначе заведение связи отвечает PROTOCOL
				 *
				 * @note Смысл настроек за потребителем: связь несёт их байтами как есть; пустые
				 *       настройки согласуются наравне с непустыми
				 *
				 * \~english
				 * @brief Method of declaring the application settings ALPS for an application protocol
				 * @param protocol the application protocol for which the settings are declared
				 * @param value    the application settings as they are
				 * @details The draft-vvv-tls-alps: the settings of the application layer are negotiated by
				 *          the handshake of the 1.3 edition for the chosen protocol; the calls accumulate by
				 *          protocols, a repeat for the same protocol replaces the settings. The protocol must
				 *          be listed in protocols(), otherwise the start of the connection answers PROTOCOL
				 * @note The meaning of the settings is up to the consumer: the connection carries them as
				 *       bytes as they are; empty settings are negotiated on a par with non-empty ones
				 *
				 * \~
				 */
				void settings(const string & protocol, const vector <uint8_t> & value) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки точки кода расширения прикладных настроек ALPS
				 *
				 * @param type вид расширения: SETTINGS (0x44CD, новая точка) либо SETTINGS_OLD (0x4469, прежняя)
				 *
				 * @details Точки кода сторон обязаны совпасть, иначе связь идёт без настроек молча;
				 *          умолчание - новая точка, как у BoringSSL. Профиль отпечатка с расширением
				 *          ALPS выставляет точку профиля сам
				 *
				 * @note Иной вид расширения точку не меняет
				 *
				 * \~english
				 * @brief Method of setting the code point of the extension of the application settings ALPS
				 * @param type the type of the extension: SETTINGS (0x44CD, the new point) or SETTINGS_OLD (0x4469, the former)
				 * @details The code points of the sides must coincide, otherwise the connection goes without
				 *          the settings silently; the default is the new point, as at BoringSSL. A fingerprint
				 *          profile with the ALPS extension sets the point of the profile itself
				 * @note Another type of the extension does not change the point
				 *
				 * \~
				 */
				void codepoint(const extension::type_t type) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки метки возврата состояния сервера
				 *
				 * @param cookie устанавливаемая метка возврата состояния
				 *
				 * @details Раздел 4.2.2 RFC 8446: меткой сервер возвращает себе своё состояние,
				 *          не храня его у себя между приветствиями клиента
				 *
				 * @note Содержимое метки складывает потребитель: связь несёт её дословно и
				 *       ничего в ней не разбирает. Метка уходит лишь просьбой о повторе
				 *       приветствия, а пустая метка отключает её выдачу вовсе
				 *
				 * \~english
				 * @brief Method of setting the label of the return of the state of the server
				 * @param cookie the label of the return of the state being set
				 * @details The section 4.2.2 of RFC 8446: by the label the server returns its state
				 *          to itself without storing it at itself between the greetings of the client
				 * @note The content of the label is composed by the consumer: the connection carries
				 *       it verbatim and parses nothing in it. The label goes only with the request of
				 *       the repetition of the greeting, and an empty label disables its issuing at all
				 *
				 * \~
				 */
				void cookie(const vector <uint8_t> & cookie) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения метки возврата состояния сервера
				 *
				 * @return метка возврата состояния, повторённая клиентом
				 *
				 * @note Пустая метка означает, что клиент её не повторил: судит о том, годна
				 *       ли метка и та ли она вовсе, сам потребитель
				 *
				 * \~english
				 * @brief Method of getting the label of the return of the state of the server
				 * @return the label of the return of the state repeated by the client
				 * @note An empty label means that the client has not repeated it: the consumer
				 *       itself judges whether the label is suitable and whether it is the same one
				 *
				 * \~
				 */
				const vector <uint8_t> & cookie() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки мига, которым судятся сроки билетов
				 *
				 * @param moment устанавливаемый миг в секундах
				 *
				 * @details Раздел 4.6.1 RFC 8446: билет годен не дольше объявленного срока,
				 *          а раздел 4.2.10 велит сличать объявленный возраст билета с
				 *          наблюдаемым, прежде чем принимать упреждающие данные
				 *
				 * @note Часов связь не читает: миг подаётся ей доводом, оттого ход её
				 *       повторим и проверяем. Нулевой миг сроки судить запрещает вовсе -
				 *       билет тогда идёт в дело как есть
				 *
				 * @note Повторную подачу упреждающих данных этот миг не ловит: второй раз
				 *       билет предъявляется уже другой связи, и заслон от повтора ставит
				 *       тот, кому принадлежат билеты
				 *
				 * \~english
				 * @brief Method of setting the moment the terms of the tickets are judged by
				 * @param moment the moment being set in the seconds
				 * @details The section 4.6.1 of RFC 8446: a ticket is valid no longer than the declared term,
				 *          and the section 4.2.10 orders to compare the declared age of a ticket against the
				 *          observed one before accepting the early data
				 * @note The connection does not read the clock: the moment is given to it by an argument, so
				 *       its course is repeatable and checkable. A zero moment forbids judging the terms at
				 *       all — a ticket then goes into the work as it is
				 * @note This moment does not catch the repeated submission of the early data: the second time
				 *       a ticket is presented to a different connection already, and the guard against the
				 *       repetition is set by the one the tickets belong to
				 *
				 * \~
				 */
				void moment(const int64_t moment) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки срока жизни выдаваемых билетов
				 *
				 * @param lifetime устанавливаемый срок в секундах
				 *
				 * @details Раздел 4.6.1 RFC 8446 кладёт сроку билета семь суток: больший срок
				 *          усекается до семи суток, а нулевой возвращает срок по умолчанию -
				 *          два часа
				 *
				 * @note Срок действует на билеты, выдаваемые после его установки; уже
				 *       выданные билеты своего срока не меняют
				 *
				 * \~english
				 * @brief Method of setting the lifetime of the tickets being issued
				 * @param lifetime the term being set in the seconds
				 * @details The section 4.6.1 of RFC 8446 lays seven days to the term of a ticket: a bigger
				 *          term is cut to seven days, and a zero one returns the default term — two hours
				 * @note The term acts on the tickets issued after its setting; the tickets already issued
				 *       do not change their term
				 *
				 * \~
				 */
				void lifetime(const uint32_t lifetime) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки требования подлинности клиента
				 *
				 * @param request устанавливаемое требование подлинности клиента
				 *
				 * @details Раздел 4.3.2 RFC 8446: сервер вправе запросить у клиента подлинность,
				 *          а клиент вправе ответить пустой цепочкой, годного сертификата не найдя
				 *
				 * @note Пустой ответ клиента связь отказом не считает: решение о допуске такого
				 *       клиента принадлежит тому, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of setting the requirement of the authenticity of the client
				 * @param request the requirement of the authenticity of the client being set
				 * @details The section 4.3.2 of RFC 8446: the server is entitled to request the authenticity
				 *          from the client, and the client is entitled to answer by an empty chain, having not
				 *          found a suitable certificate
				 * @note The connection does not consider an empty answer of the client a failure: the decision
				 *       about the admission of such a client belongs to the one who leads the connection
				 *
				 * \~
				 */
				void request(const bool request) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки перечня доверенных удостоверяющих центров для запроса подлинности
				 *
				 * @param names имена центров как записаны (DER X.501 Name)
				 *
				 * @details Раздел 4.2.4 RFC 8446 и раздел 7.4.4 RFC 5246: перечень идёт запросом
				 *          подлинности - изданием 1.3 расширением certificate_authorities (0x002F),
				 *          изданием 1.2 полем запроса - и говорит клиенту, чьи сертификаты сервер
				 *          примет; имя владельца сертификата центра даёт
				 *          x509::certificate_t::subjects().element
				 *
				 * @note Пустое имя либо имя не SEQUENCE отвергается заведением связи отказом SETTINGS;
				 *       без перечня запрос идёт без расширения (издание 1.2 - с пустым полем)
				 *
				 * \~english
				 * @brief Method of setting the list of the trusted certificate authorities for the request of the authenticity
				 * @param names the names of the authorities as they are written (DER X.501 Name)
				 * @details The section 4.2.4 of RFC 8446 and the section 7.4.4 of RFC 5246: the list goes by the request
				 *          of the authenticity - in the 1.3 edition by the certificate_authorities extension (0x002F),
				 *          in the 1.2 edition by the field of the request - and tells the client whose certificates the
				 *          server accepts; the name of the subject of the certificate of an authority is given by
				 *          x509::certificate_t::subjects().element
				 * @note An empty name or a name which is not a SEQUENCE is rejected by the start of the connection
				 *       with the SETTINGS failure; without the list the request goes without the extension (the 1.2
				 *       edition - with an empty field)
				 *
				 * \~
				 */
				void authorities(const vector <vector <uint8_t>> & names) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки выработки следующего протокола NPN
				 *
				 * @param negotiation объявляется ли перечень протоколов по запросу клиента
				 *
				 * @details Черновик draft-agl-tls-nextprotoneg: по пустому расширению 0x3374 клиента
				 *          издания 1.2 сервер объявляет protocols() в своём порядке приветствием, а
				 *          клиент отвечает сообщением NextProtocol с выбранным протоколом; итог в protocol()
				 *
				 * @note Объявление идёт лишь когда ALPN не выбран; изданием 1.3 расширение
				 *       клиента пропускается; завершение клиента без NextProtocol - unexpected_message
				 *
				 * \~english
				 * @brief Method of setting the next protocol negotiation NPN
				 * @param negotiation whether the list of the protocols is declared upon the request of the client
				 * @details The draft-agl-tls-nextprotoneg: upon the empty extension 0x3374 of a 1.2 client the
				 *          server declares protocols() in its order by the hello, and the client answers by the
				 *          NextProtocol message with the chosen protocol; the result is in protocol()
				 * @note The declaration goes only when ALPN is not chosen; in the 1.3 edition the extension of
				 *       the client is skipped; a completion of the client without NextProtocol - unexpected_message
				 *
				 * \~
				 */
				void negotiation(const bool negotiation) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки выработки протокола связи через NPN
				 *
				 * @return признак того, что protocol() взят выработкой NPN, а не ALPN
				 *
				 * \~english
				 * @brief Method of checking the negotiation of the protocol of the connection by NPN
				 * @return the flag of protocol() having been taken by the NPN negotiation, not by ALPN
				 *
				 * \~
				 */
				bool negotiated() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки признаваемых билетов возобновления связи
				 *
				 * @param tickets признаваемые билеты возобновления связи
				 *
				 * @details Раздел 4.6.1 RFC 8446: билеты сервер выдал сам прошлыми связями, а
				 *          хранил их между связями тот, кто связь ведёт: связи их и подавать
				 *
				 * @note Предъявленный билет признаётся лишь тогда, когда сошлась его привязка:
				 *       ею клиент и доказывает владение ключом билета, а не одним его телом
				 * @note Выданные билеты сервер сам не помнит: `vault()` лишь выводит ключи, а
				 *       билеты, взятые из `tickets()` после `issue()`, сервер признаёт только этим
				 *       вызовом - без него возобновление идёт полным рукопожатием
				 *
				 * \~english
				 * @brief Method of setting the recognized tickets of the resumption of a connection
				 * @param tickets the recognized tickets of the resumption of the connection
				 * @details The section 4.6.1 of RFC 8446: the tickets were issued by the server itself by the
				 *          past connections, and they were kept between the connections by the one who leads
				 *          the connection: it is for them to give them to the connection
				 * @note A presented ticket is recognized only when its binder has converged: by it the client
				 *       proves the possession of the key of the ticket and not of its body alone
				 * @note The server does not remember the issued tickets itself: `vault()` only derives the
				 *       keys, and the tickets taken from `tickets()` after `issue()` are recognized by the
				 *       server only by this call - without it the resumption goes by a full handshake
				 *
				 * \~
				 */
				void resume(const vector <context::ticket_t> & tickets) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки заранее разделённого ключа издания TLS 1.2
				 *
				 * @param psk настройки заранее разделённого ключа: вызов respond «дано identity - ключ либо отказ», необязательная подсказка identity и признак disclose
				 *
				 * @details RFC 4279 и RFC 5489: наборы PSK-AES128/256-CBC-SHA, ECDHE-PSK-AES128/256-CBC-SHA
				 *          и ECDHE-PSK-CHACHA20-POLY1305 ведут рукопожатие без сертификатов; сервер признаёт их лишь при заданном вызове respond, сертификат при них не шлётся; неизвестный опознаватель отвечается извещением unknown_psk_identity (115) при disclose либо продолжается случайным ключом до decrypt_error (51) на завершении (раздел 2 RFC 4279)
				 *
				 * @note Раздел 5.3 RFC 4279: опознаватель не длиннее 128 байтов, ключ - не длиннее 64,
				 *       иное заведение связи отвергает отказом SETTINGS; неверный ключ обрывает
				 *       рукопожатие на завершении извещением decrypt_error (51)
				 *
				 * \~english
				 * @brief Method of setting the pre-shared key of the TLS 1.2 edition
				 * @param psk the settings of the pre-shared key: the respond call «given the identity - the key or a refusal», the optional hint identity and the disclose flag
				 * @details RFC 4279 and RFC 5489: the PSK-AES128/256-CBC-SHA, ECDHE-PSK-AES128/256-CBC-SHA and
				 *          ECDHE-PSK-CHACHA20-POLY1305 suites conduct the handshake without certificates; the server recognizes them only at a set respond call, the certificate is not sent with them; an unknown identity is answered by the unknown_psk_identity alert (115) at disclose or continued with a random key up to decrypt_error (51) at the completion (the section 2 of RFC 4279)
				 * @note The section 5.3 of RFC 4279: the identity is not longer than 128 bytes, the key - not longer
				 *       than 64, otherwise the establishment refuses by SETTINGS; a wrong key tears the handshake at
				 *       the completion by the decrypt_error alert (51)
				 *
				 * \~
				 */
				void psk(const context::psk_t & psk) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки требования порядка «шифрование, затем имитовставка» RFC 7366
				 *
				 * @param required обязателен ли порядок encrypt_then_mac при наборе CBC
				 *
				 * @details Раздел 3 RFC 7366: порядок предлагается клиентом и подтверждается сервером
				 *          всегда, когда в деле набор CBC, - без него запись идёт в порядке
				 *          MAC-then-encrypt раздела 6.2.3.2 RFC 5246 (защита от Lucky13 постоянным
				 *          временем разбора). Требование обрывает рукопожатие извещением
				 *          handshake_failure и отказом ETM, если собеседник выбрал набор CBC, а
				 *          порядка не поддержал; наборов AEAD требование не касается
				 *
				 * \~english
				 * @brief Method of setting the requirement of the «encrypt, then MAC» order of RFC 7366
				 * @param required whether the encrypt_then_mac order is mandatory at a CBC suite
				 * @details The section 3 of RFC 7366: the order is offered by the client and confirmed by the server
				 *          whenever a CBC suite is in play - without it a record goes in the MAC-then-encrypt order
				 *          of the section 6.2.3.2 of RFC 5246 (the protection against Lucky13 by a constant-time
				 *          parsing). The requirement tears the handshake by the handshake_failure alert and the ETM
				 *          failure when the interlocutor chose a CBC suite but did not support the order; the AEAD
				 *          suites are not concerned by the requirement
				 *
				 * \~
				 */
				void etm(const bool required) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки согласованного порядка «шифрование, затем имитовставка»
				 *
				 * @return признак того, что записи CBC идут в порядке encrypt_then_mac RFC 7366
				 *
				 * @note У наборов AEAD и до согласования набора признак ложен: потребитель судит по
				 *       нему, идёт ли связь набором CBC в порядке MAC-then-encrypt
				 *
				 * \~english
				 * @brief Method of checking the negotiated «encrypt, then MAC» order
				 * @return the flag of the CBC records going in the encrypt_then_mac order of RFC 7366
				 * @note At the AEAD suites and before the negotiation of the suite the flag is false: the consumer
				 *       judges by it whether the connection goes by a CBC suite in the MAC-then-encrypt order
				 *
				 * \~
				 */
				bool etm() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки вставки своих значений GREASE (RFC 8701)
				 *
				 * @param grease вставляются ли значения GREASE
				 *
				 * @details Раздел 3.2 RFC 8701, поведение BoringSSL при SSL_CTX_set_grease_enabled:
				 *          сервер издания TLS 1.3 несёт пустое расширение GREASE в билете
				 *          возобновления связи (за пределом упреждающих данных) и первым в запросе
				 *          подлинности клиента. Значения вида 0x?A?A выводятся из энтропии на связь
				 *
				 * @note По умолчанию выключено: байты сообщений прежние. Значения GREASE клиента
				 *       сервер не выбирает ни при каких условиях; издание TLS 1.2 расширений у билета
				 *       и запроса подлинности не имеет, и там вставки нет
				 *
				 * \~english
				 * @brief Method of setting the insertion of the own GREASE values (RFC 8701)
				 * @param grease whether the GREASE values are inserted
				 * @details The section 3.2 of RFC 8701, the behaviour of BoringSSL at SSL_CTX_set_grease_enabled:
				 *          the server of the 1.3 edition carries an empty GREASE extension in the ticket of the
				 *          resumption of the connection (behind the limit of the early data) and first in the request
				 *          of the authenticity of the client. The values of the form 0x?A?A are derived from the
				 *          entropy per connection
				 * @note Disabled by default: the bytes of the messages are the former ones. The server never selects
				 *       a GREASE value of the client; the 1.2 edition has no extensions at the ticket and at the
				 *       request of the authenticity, and there is no insertion there
				 *
				 * \~
				 */
				void grease(const bool grease) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки вставки своих значений GREASE
				 *
				 * @return признак того, что значения GREASE вставляются
				 *
				 * \~english
				 * @brief Method of checking the insertion of the own GREASE values
				 * @return the flag of the GREASE values being inserted
				 *
				 * \~
				 */
				bool grease() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки классов затирания памяти связи
				 *
				 * @param classes классы затирания context::wiping_t
				 *
				 * @details Умолчание связи - только SECRETS: секреты рукопожатия и ключи
				 *          затираются сразу, как только из них нечего более выводить. Класс
				 *          PLAINTEXT добавляет затирание открытого текста принятых записей
				 *          между записями, после выдачи вызовом read и при закрытии - на
				 *          каждую запись, как SSL_OP_CLEANSE_PLAINTEXT у OpenSSL. Пустой
				 *          перечень выключает затирания связи вовсе; укрытое хранилище,
				 *          объекты-значения и примитивы затирают своё всегда
				 *
				 * @note Копия принятых данных, выданная вызовом read, - потребителя: её
				 *       затирание за ним (sys::wipe)
				 *
				 * \~english
				 * @brief Method of setting the classes of the wiping of the memory of the connection
				 * @param classes the classes of the wiping context::wiping_t
				 * @details The default of a connection is SECRETS only: the secrets of the handshake and the
				 *          keys are wiped as soon as there is nothing more to derive from them. The PLAINTEXT
				 *          class adds the wiping of the plaintext of the received records between the records,
				 *          after the hand-over by the read call and on closing - per record, like
				 *          SSL_OP_CLEANSE_PLAINTEXT of OpenSSL. An empty list disables the wipings of the
				 *          connection at all; the sheltered vault, the value objects and the primitives always
				 *          wipe their own
				 * @note The copy of the received data handed over by the read call is the consumer's: its
				 *       wiping is up to them (sys::wipe)
				 *
				 * \~
				 */
				void wiping(const vector <context::wiping_t> & classes) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения классов затирания памяти связи
				 *
				 * @return классы затирания, объявленные потребителем; умолчание - SECRETS
				 *
				 * \~english
				 * @brief Method of getting the classes of the wiping of the memory of the connection
				 * @return the classes of the wiping declared by the consumer; the default is SECRETS
				 *
				 * \~
				 */
				const vector <context::wiping_t> & wiping() const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия профиля отпечатка с принятого приветствия клиента
				 *
				 * @param profile место, в которое помещается разобранный профиль приветствия
				 * @return        отказ снятия: STATE до приёма приветствия, иначе отказ разбора
				 *                (`fingerprint::error_t` сведён к MESSAGE, MEMORY при нехватке памяти)
				 *
				 * @details Профиль доступен с момента приёма приветствия клиента: до завершения
				 *          рукопожатия, после него и до сброса связи. По профилю потребитель
				 *          считает отпечатки `fingerprint::imprint` (JA3, JA4, PeetPrint). Сырые
				 *          байты приветствия для своего разбора отдаёт `greeting()`
				 *
				 * \~english
				 * @brief Method of taking the fingerprint profile from the accepted greeting of the client
				 * @param profile the place the parsed profile of the greeting is put into
				 * @return        the failure of the taking: STATE before the acceptance of the greeting, otherwise
				 *                the failure of the parsing (`fingerprint::error_t` reduced to MESSAGE, MEMORY at the lack of memory)
				 * @details The profile is available from the moment of the acceptance of the greeting of the client:
				 *          before the completion of the handshake, after it and until the reset of the connection.
				 *          By the profile the consumer computes the fingerprints `fingerprint::imprint` (JA3, JA4,
				 *          PeetPrint). The raw bytes of the greeting for an own parsing are given by `greeting()`
				 *
				 * \~
				 */
				context::error_t profile(fingerprint::profile_t & profile) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения принятого приветствия клиента байтами
				 *
				 * @return байты приветствия клиента вместе с обвязкой сообщения рукопожатия (пусто до приёма)
				 *
				 * @details Для своего разбора помимо `profile()`: сообщение рукопожатия с четырёхбайтовой
				 *          обвязкой записями и с двенадцатибайтовой поверх дейтаграмм, без заголовка записи
				 *
				 * \~english
				 * @brief Method of getting the accepted greeting of the client by bytes
				 * @return the bytes of the greeting of the client together with the framing of the handshake message (empty before the acceptance)
				 * @details For an own parsing besides `profile()`: the handshake message with the four-byte framing over
				 *          records and with the twelve-byte one over datagrams, without the header of the record
				 *
				 * \~
				 */
				view_t greeting() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа зашифрованного приветствия ECH серверу (RFC 9849)
				 *
				 * @param secret секретный ключ X25519 (32 байта) либо пусто - ключ порождается
				 * @param name   публичное имя конфигурации: им идёт внешнее приветствие клиента
				 * @param id     опознаватель конфигурации (один случайный байт у потребителя)
				 * @param length наибольшая длина имени узла в множестве анонимности: правит заполнение клиента
				 * @return       отказ установки: STATE после `start()`, SETTINGS при негодном ключе либо имени, MEMORY
				 *
				 * @details Сервер складывает конфигурацию издания 0xFE0D с KEM X25519 и наборами
				 *          AES-128-GCM и ChaCha20-Poly1305 на HKDF-SHA256; всякий вызов добавляет конфигурацию
				 *          с новым опознавателем либо заменяет прежнюю с тем же, служатся все; перечень ECHConfigList для
				 *          записи DNS HTTPS отдаёт `ech()`, секретный ключ наружу не отдаётся. Принятое
				 *          внешнее приветствие раскрывается, рукопожатие идёт по внутреннему, подтверждение
				 *          вписывается в приветствие сервера либо просьбу о повторе; нераскрываемое либо
				 *          чужое ECH отвергается - связь идёт по внешнему приветствию, а свои конфигурации
				 *          уходят клиенту как retry_configs. `greeting()` и `profile()` отдают внешнее
				 *          приветствие, как оно шло на проводе
				 *
				 * \~english
				 * @brief Method of setting the key of the encrypted client hello ECH at the server (RFC 9849)
				 * @param secret the X25519 secret key (32 bytes) or empty - the key is generated
				 * @param name   the public name of the configuration: the outer greeting of the client goes by it
				 * @param id     the identifier of the configuration (a single random byte at the consumer)
				 * @param length the greatest length of a host name in the anonymity set: rules the padding of the client
				 * @return       the failure of the setting: STATE after `start()`, SETTINGS at an invalid key or name, MEMORY
				 * @details The server composes a configuration of the edition 0xFE0D with the X25519 KEM and the
				 *          AES-128-GCM and ChaCha20-Poly1305 suites on HKDF-SHA256; every call adds a configuration with
				 *          a new identifier or replaces the former one with the same, all of them are served; the ECHConfigList list for the DNS HTTPS
				 *          record is given by `ech()`, the secret key is not given out. The accepted outer greeting is
				 *          opened, the handshake goes by the inner one, the confirmation is written into the greeting of the
				 *          server or the retry request; an unopenable or foreign ECH is rejected - the connection goes by the
				 *          outer greeting while the own configurations go to the client as retry_configs. `greeting()` and
				 *          `profile()` give the outer greeting as it went on the wire
				 *
				 * \~
				 */
				context::error_t ech(const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа ECH серверу со способом инкапсуляции (RFC 9849)
				 *
				 * @param kem    способ инкапсуляции ключа HPKE
				 * @param secret секретный ключ способа либо пусто - ключ порождается
				 * @param name   публичное имя конфигурации: им идёт внешнее приветствие клиента
				 * @param id     опознаватель конфигурации (один случайный байт у потребителя)
				 * @param length наибольшая длина имени узла в множестве анонимности: правит заполнение клиента
				 * @return       отказ установки: STATE после `start()`, SETTINGS при негодном ключе, имени либо способе, MEMORY
				 *
				 * @details Сервер складывает конфигурацию издания 0xFE0D с заданным способом инкапсуляции
				 *          (постквантовые ML-KEM и гибриды ML-KEM с ECDH по draft-ietf-hpke-pq) и наборами
				 *          AES-128-GCM и ChaCha20-Poly1305 на HKDF-SHA256
				 *
				 * \~english
				 * @brief Method of setting the key of the encrypted client hello ECH at the server with an encapsulation mechanism (RFC 9849)
				 * @param kem    the HPKE key encapsulation mechanism
				 * @param secret the secret key of the mechanism or empty - the key is generated
				 * @param name   the public name of the configuration: the outer greeting of the client goes by it
				 * @param id     the identifier of the configuration (a single random byte at the consumer)
				 * @param length the greatest length of a host name in the anonymity set: rules the padding of the client
				 * @return       the failure of the setting: STATE after `start()`, SETTINGS at an invalid key, name or mechanism, MEMORY
				 * @details The server composes a configuration of the edition 0xFE0D with the given encapsulation
				 *          mechanism (the post-quantum ML-KEM and the hybrids of ML-KEM with ECDH by draft-ietf-hpke-pq)
				 *          and the AES-128-GCM and ChaCha20-Poly1305 suites on HKDF-SHA256
				 *
				 * \~
				 */
				context::error_t ech(const hpke::kem_t kem, const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки удержанной конфигурации ECH серверу: принимается, но не объявляется
				 *
				 * @param secret секретный ключ X25519 (32 байта) либо пусто - ключ порождается
				 * @param name   публичное имя конфигурации
				 * @param id     опознаватель конфигурации: занятый прежней конфигурацией заменяет её
				 * @param length наибольшая длина имени узла
				 *
				 * @details Ротация ключей по разделу 7.1 RFC 9849: новая конфигурация ставится `ech()` и
				 *          уходит в перечень DNS и retry_configs, прежняя удерживается `retain()` - клиенты со
				 *          старой записью DNS раскрываются ещё, но в перечень не попадают. Служимых
				 *          конфигураций вправе быть несколько, подбор идёт по опознавателю и набору
				 *
				 * @return  отказ установки: STATE после `start()`, SETTINGS при негодном ключе либо имени, MEMORY
				 *
				 * \~english
				 * @brief Method of setting a retained ECH configuration at the server: accepted but not advertised
				 *
				 * @param secret the X25519 secret key (32 bytes) or empty - the key is generated
				 * @param name   the public name of the configuration
				 * @param id     the identifier of the configuration: one taken by a former configuration replaces it
				 * @param length the greatest length of a host name
				 *
				 * @details The rotation of the keys by the section 7.1 of RFC 9849: a new configuration is set by `ech()`
				 *          and goes into the DNS list and retry_configs, the former one is retained by `retain()` - the
				 *          clients with the old DNS record are still opened but do not get into the list. There may be
				 *          several served configurations, the selection goes by the identifier and the suite
				 *
				 * @return  the failure of the setting: STATE after `start()`, SETTINGS at an invalid key or name, MEMORY
				 *
				 * \~
				 */
				context::error_t retain(const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки удержанной конфигурации ECH серверу со способом инкапсуляции: принимается, но не объявляется
				 *
				 * @param kem    способ инкапсуляции ключа HPKE
				 * @param secret секретный ключ способа либо пусто - ключ порождается
				 * @param name   публичное имя конфигурации
				 * @param id     опознаватель конфигурации: занятый прежней конфигурацией заменяет её
				 * @param length наибольшая длина имени узла
				 * @return       отказ установки: STATE после `start()`, SETTINGS при негодном ключе, имени либо способе, MEMORY
				 *
				 * \~english
				 * @brief Method of setting a retained ECH configuration at the server with an encapsulation mechanism: accepted but not advertised
				 * @param kem    the HPKE key encapsulation mechanism
				 * @param secret the secret key of the mechanism or empty - the key is generated
				 * @param name   the public name of the configuration
				 * @param id     the identifier of the configuration: one taken by a former configuration replaces it
				 * @param length the greatest length of a host name
				 * @return       the failure of the setting: STATE after `start()`, SETTINGS at an invalid key, name or mechanism, MEMORY
				 *
				 * \~
				 */
				context::error_t retain(const hpke::kem_t kem, const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения перечня конфигураций ECH для записи DNS HTTPS
				 *
				 * @return перечень ECHConfigList байтами (пусто без ключа)
				 *
				 * \~english
				 * @brief Method of getting the list of the ECH configurations for the DNS HTTPS record
				 * @return the ECHConfigList list by bytes (empty without a key)
				 *
				 * \~
				 */
				const vector <uint8_t> & ech() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки принятия ECH связью
				 *
				 * @return признак того, что рукопожатие идёт по раскрытому внутреннему приветствию
				 *
				 * \~english
				 * @brief Method of checking the acceptance of ECH by the connection
				 * @return the flag of the handshake going by the opened inner greeting
				 *
				 * \~
				 */
				bool shrouded() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа билетов сеансов издания TLS 1.2
				 *
				 * @param secret секрет любой длины, из которого выводятся имя ключа, ключ шифрования и ключ имитовставки
				 *
				 * @details Раздел 4 RFC 5077: билет сеанса - имя ключа, вектор замены, состояние под
				 *          AES-128-CBC и имитовставка HMAC-SHA256; сервер кэша сеансов не ведёт, всё
				 *          состояние лежит в билете. Всякий вызов открывает новое поколение ключа, а
				 *          прежнее остаётся признаваемым - живы два, как у метки возврата состояния.
				 *          Соседние узлы с тем же секретом признают билеты друг друга
				 *
				 * @note Не заданный ключ порождается энтропией при заведении связи: билеты тогда
				 *       признаёт лишь та же связь. Выданные билеты отдаёт tickets() в единой с
				 *       изданием 1.3 записи, а клиент предъявляет их через resume
				 *
				 * \~english
				 * @brief Method of setting the key of the session tickets of the TLS 1.2 edition
				 * @param secret a secret of any length the name of the key, the encryption key and the key of the authentication code are derived from
				 * @details The section 4 of RFC 5077: a session ticket is the name of the key, an initialization vector,
				 *          the state under AES-128-CBC and an HMAC-SHA256; the server keeps no session cache, all the
				 *          state lies in the ticket. Every call opens a new generation of the key, and the previous
				 *          one remains recognized - two are alive, as at the label of the return of the state.
				 *          Neighbouring nodes with the same secret recognize the tickets of each other
				 * @note A key not set is generated from the entropy at the establishment of the connection: the tickets
				 *       are then recognized by the same connection alone. The issued tickets are given by tickets() in
				 *       the record common with the 1.3 edition, and the client presents them through resume
				 *
				 * \~
				 */
				void vault(const vector <uint8_t> & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки приёма упреждающих данных клиента
				 *
				 * @param advance принимаются ли упреждающие данные
				 * @param limit   предел упреждающих данных в байтах, объявляемый билетом
				 *
				 * @details Раздел 2.3 RFC 8446: упреждающие данные уходят вместе с приветствием
				 *          клиента, не дожидаясь ответа сервера, и защищены ключами, выведенными
				 *          из одного лишь билета возобновления связи.
				 *
				 * @note Повтор упреждающих данных протоколом не отсекается: та же запись, посланная
				 *       злоумышленником заново, будет принята повторно, и заслон этому ставит тот,
				 *       кто связь ведёт, - повторяемые запросы упреждающими данными не принимать
				 *
				 * \~english
				 * @brief Method of setting the acceptance of the early data of the client
				 * @param advance whether the early data is accepted
				 * @param limit   the limit of the early data in the bytes declared by a ticket
				 * @details The section 2.3 of RFC 8446: the early data goes together with the greeting of the
				 *          client without waiting for the answer of the server, and it is protected by the keys
				 *          derived from the ticket of the resumption of the connection alone.
				 * @note A repetition of the early data is not cut off by the protocol: the same record sent
				 *       anew by an attacker will be accepted repeatedly, and the barrier to it is set by the
				 *       one who leads the connection — not to accept repeatable requests by the early data
				 *
				 * \~
				 */
				void advance(const bool advance, const uint32_t limit = 16384) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки приёма упреждающих данных связью
				 *
				 * @return признак того, что упреждающие данные связью приняты
				 *
				 * @note Упреждающие данные связь вправе и отвергнуть: расхождение объявленного
				 *       возраста билета с наблюдаемым, иной набор шифрования либо иной прикладной
				 *       протокол приёму их препятствуют. Отвергнутые записи связь пропускает молча,
				 *       как и велит раздел 4.2.10 RFC 8446, и по пустоте прочитанного отказ приёма
				 *       от их отсутствия неотличим - оттого о приёме и объявляется отдельно
				 *
				 * @note Принятые упреждающие данные могли быть поданы повторно: протокол повтора не
				 *       отсекает, и знать о приёме нужно затем, чтобы решить, как с таким повтором
				 *       обходиться
				 *
				 * \~english
				 * @brief Method of checking the acceptance of the early data by the connection
				 * @return the flag of the early data being accepted by the connection
				 * @note The connection has the right to reject the early data as well: a divergence of the
				 *       declared age of a ticket from the observed one, another cipher suite or another
				 *       application protocol prevent its acceptance. The rejected records are skipped by the
				 *       connection silently as the section 4.2.10 of RFC 8446 prescribes, and by the emptiness
				 *       of what has been read a rejection is indistinguishable from an absence — that is why
				 *       the acceptance is announced separately
				 * @note The accepted early data could have been submitted repeatedly: the protocol does not cut
				 *       off a repetition, and the acceptance needs to be known in order to decide how to deal
				 *       with such a repetition
				 *
				 * \~
				 */
				bool accepted() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки порядка смены ключей по счётчику записей
				 *
				 * @param automatic сменяет ли движок ключи сам по счётчику записей
				 * @param records   число записей направления, по которому идёт смена
				 *
				 * @details Раздел 5.5 RFC 8446: смена ключевого материала обязана идти впереди
				 *          предела порядковых номеров записей. В самодеятельном порядке движок
				 *          сменяет ключи своего направления сам, дойдя счётчиком до порога, а у
				 *          собеседника испрашивает смену просьбою в KeyUpdate; в ручном порядке
				 *          за счётчиком следит тот, кто связь ведёт, методами sequence() и update()
				 *
				 * @note Нулевое число записей означает половину предела набора шифрования: столько
				 *       же места остаётся собеседнику ответить на просьбу, сколько берёт своё
				 *       направление. По умолчанию порядок самодеятельный
				 *
				 * \~english
				 * @brief Method of setting the order of the change of the keys by the counter of the records
				 * @param automatic whether the engine changes the keys itself by the counter of the records
				 * @param records   the number of the records of a direction at which the change goes
				 * @details The section 5.5 of RFC 8446: the change of the key material must go ahead of the
				 *          limit of the sequence numbers of the records. In the automatic order the engine
				 *          changes the keys of its own direction itself having reached the threshold by the
				 *          counter, and asks the interlocutor for the change by the request in KeyUpdate; in
				 *          the manual order the one who leads the connection watches the counter by the
				 *          methods sequence() and update()
				 * @note The zero number of the records means a half of the limit of the cipher suite: as much
				 *       room is left to the interlocutor to answer the request as one's own direction takes.
				 *       The automatic order is the default
				 *
				 * \~
				 */
				void renewal(const bool automatic, const uint64_t records = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения счётчика записей направления связи
				 *
				 * @param incoming запрашивается ли направление собеседника
				 *
				 * @return         число записей направления на текущих ключах
				 *
				 * @details Раздел 5.3 RFC 8446: счётчик начинается заново с каждой сменой ключей
				 *          направления, оттого он равен числу записей, прошедших на текущих ключах
				 *
				 * \~english
				 * @brief Method of getting the counter of the records of a direction of the connection
				 * @param incoming whether the direction of the interlocutor is requested
				 * @return         the number of the records of the direction under the current keys
				 * @details The section 5.3 of RFC 8446: the counter starts anew with each change of the keys of
				 *          the direction, hence it equals the number of the records passed under the current keys
				 *
				 * \~
				 */
				uint64_t sequence(const bool incoming = false) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки способа переноса рукопожатия
				 *
				 * @param transport устанавливаемый способ переноса
				 *
				 * @details Записями протокола (умолчание) связь ведёт TLS поверх потока: сама
				 *          защищает записи и разбирает их заголовки. Сообщениями по уровням она
				 *          ведёт рукопожатие под QUIC (RFC 9001): принимает и выдаёт голые
				 *          сообщения рукопожатия с пометкой уровня защиты, а записи, извещения,
				 *          смена ключей KeyUpdate и конец упреждающих данных в этом переносе не
				 *          идут вовсе - их берёт на себя перенос QUIC
				 *
				 * @note Способ переноса устанавливается до заведения связи
				 *
				 * @note Перенос по уровням без прикладных протоколов protocols() и без
				 *       параметров переноса parameters() связь не заводит (отказ SETTINGS):
				 *       под QUIC и то, и другое обязательно, и молчание тут было бы дефектом
				 *
				 * \~english
				 * @brief Method of setting the way of the transport of the handshake
				 * @param transport the way of the transport being set
				 * @details By the records of the protocol (the default) the connection leads TLS over a stream:
				 *          it protects the records and parses their headers itself. By the messages by levels it
				 *          leads the handshake under QUIC (RFC 9001): it accepts and gives out bare messages of
				 *          the handshake marked with a protection level, while the records, the alerts, the change
				 *          of the keys by KeyUpdate and the end of the early data do not go in this transport at
				 *          all — the QUIC transport takes them upon itself
				 * @note The way of the transport is set before the establishment of the connection
				 * @note The transport by levels without the application protocols protocols() and without the
				 *       transport parameters parameters() does not establish the connection (the failure SETTINGS):
				 *       under QUIC both are mandatory, and silence here would be a defect
				 *
				 * \~
				 */
				void transport(const context::transport_t transport) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения способа переноса рукопожатия
				 *
				 * @return способ переноса рукопожатия связи
				 *
				 * \~english
				 * @brief Method of getting the way of the transport of the handshake
				 * @return the way of the transport of the handshake of the connection
				 *
				 * \~
				 */
				context::transport_t transport() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки своих параметров переноса QUIC
				 *
				 * @param parameters устанавливаемые параметры переноса в записи QUIC
				 *
				 * @details Раздел 8.2 RFC 9001: параметры уходят расширением
				 *          quic_transport_parameters как есть - связь их не толкует. Клиент кладёт
				 *          их в приветствие, сервер - в защищённые расширения
				 *
				 * @note Расширение идёт лишь при переносе по уровням; переносу записями оно не
				 *       положено, и принятое там отвергается
				 *
				 * \~english
				 * @brief Method of setting one's own QUIC transport parameters
				 * @param parameters the transport parameters being set in the QUIC encoding
				 * @details The section 8.2 of RFC 9001: the parameters go by the quic_transport_parameters
				 *          extension as they are — the connection does not interpret them. The client puts them
				 *          into the greeting, the server — into the encrypted extensions
				 * @note The extension goes only at the transport by levels; the transport by records is not
				 *       entitled to it, and one received there is rejected
				 *
				 * \~
				 */
				void parameters(const vector <uint8_t> & parameters) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения параметров переноса QUIC собеседника
				 *
				 * @return параметры переноса, принятые от собеседника как есть
				 *
				 * @note Приняты ли параметры вовсе, говорит acquired(): пустые параметры от
				 *       отсутствующих пустотой не отличить
				 *
				 * \~english
				 * @brief Method of getting the QUIC transport parameters of the interlocutor
				 * @return the transport parameters received from the interlocutor as they are
				 * @note Whether the parameters are received at all is told by acquired(): empty parameters
				 *       cannot be distinguished from absent ones by the emptiness
				 *
				 * \~
				 */
				const vector <uint8_t> & parameters() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки приёма параметров переноса собеседника
				 *
				 * @return признак того, что параметры переноса собеседника приняты
				 *
				 * \~english
				 * @brief Method of checking the receipt of the transport parameters of the interlocutor
				 * @return the flag of the transport parameters of the interlocutor being received
				 *
				 * \~
				 */
				bool acquired() const noexcept;
				/**
				 * \~russian
				 * @brief Метод подачи связи сообщений рукопожатия уровня защиты
				 *
				 * @param level уровень защиты, на котором сообщения приняты
				 * @param data  принятые сообщения рукопожатия без обвязки записей (данные CRYPTO)
				 *
				 * @return      отказ разбора принятых сообщений
				 *
				 * @details Раздел 4.1.3 RFC 9001: сообщения подаются как пришли по потоку CRYPTO
				 *          уровня, границы сообщений связь восстанавливает сама. Раздел 4.1.4:
				 *          сообщение не на своём уровне обрывает связь отказом LEVEL с извещением
				 *          unexpected_message; уровень упреждающих данных сообщений не несёт
				 *
				 * @note Подача переносу записями отвечает отказом LEVEL без обрыва связи
				 *
				 * \~english
				 * @brief Method of the giving of the messages of the handshake of a protection level to the connection
				 * @param level the protection level the messages are received at
				 * @param data  the received messages of the handshake without the records framing (the CRYPTO data)
				 * @return      the failure of the parsing of the received messages
				 * @details The section 4.1.3 of RFC 9001: the messages are given as they came by the CRYPTO stream
				 *          of the level, the connection restores the boundaries of the messages itself. The section
				 *          4.1.4: a message not at its level tears the connection by the LEVEL failure with the
				 *          unexpected_message alert; the level of the early data carries no messages
				 * @note The giving to the transport by records answers by the LEVEL failure without tearing the connection
				 *
				 * \~
				 */
				context::error_t push(const context::level_t level, const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения сообщений рукопожатия, отправляемых на уровне защиты
				 *
				 * @param level уровень защиты, сообщения которого запрашиваются
				 *
				 * @return      накопленные сообщения рукопожатия уровня без обвязки записей
				 *
				 * \~english
				 * @brief Method of getting the messages of the handshake sent at a protection level
				 * @param level the protection level whose messages are requested
				 * @return      the accumulated messages of the handshake of the level without the records framing
				 *
				 * \~
				 */
				view_t output(const context::level_t level) const noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия отправленных сообщений с накопителя уровня защиты
				 *
				 * @param level уровень защиты, с накопителя которого снимаются сообщения
				 * @param size  размер снимаемых байтов
				 *
				 * \~english
				 * @brief Method of the removal of the sent messages from the accumulator of a protection level
				 * @param level the protection level whose accumulator the messages are removed from
				 * @param size  the size of the bytes being removed
				 *
				 * \~
				 */
				void consume(const context::level_t level, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения значения направления связи уровня защиты
				 *
				 * @param level     уровень защиты: EARLY, HANDSHAKE либо APPLICATION
				 * @param direction направление связи относительно своей стороны
				 * @param result    место, в которое помещается значение; nullptr - лишь опрос длины
				 * @param size      место, в которое помещается длина значения по хешу набора
				 *
				 * @return          признак того, что значение уровня уже выведено
				 *
				 * @details Раздел 7.1 RFC 8446: выдаются client_early_traffic_secret,
				 *          {client,server}_handshake_traffic_secret и
				 *          {client,server}_application_traffic_secret; ключ, вектор и защиту
				 *          заголовка (метки «quic key», «quic iv», «quic hp» по разделу 5.1 RFC
				 *          9001) выводит из них тот, кто связь ведёт. Значения прикладных данных
				 *          доступны и после рукопожатия: следующее поколение по разделу 6 RFC 9001
				 *          («quic ku») выводится из текущего
				 *
				 * @note Место под значение обязано вмещать schedule::SCHEDULE_WIDEST байтов
				 *
				 * \~english
				 * @brief Method of getting the traffic secret of a direction of the connection of a protection level
				 * @param level     the protection level: EARLY, HANDSHAKE or APPLICATION
				 * @param direction the direction of the connection relative to one's own side
				 * @param result    the place the secret is put into; nullptr — only the query of the length
				 * @param size      the place the length of the secret by the hash of the suite is put into
				 * @return          the flag of the secret of the level being already derived
				 * @details The section 7.1 of RFC 8446: client_early_traffic_secret,
				 *          {client,server}_handshake_traffic_secret and {client,server}_application_traffic_secret
				 *          are given out; the key, the vector and the header protection (the labels «quic key»,
				 *          «quic iv», «quic hp» by the section 5.1 of RFC 9001) are derived from them by the one who
				 *          leads the connection. The secrets of the application data are available after the
				 *          handshake too: the next generation by the section 6 of RFC 9001 («quic ku») is derived
				 *          from the current one
				 * @note The place for the secret must hold schedule::SCHEDULE_WIDEST bytes
				 *
				 * \~
				 */
				bool secret(const context::level_t level, const context::direction_t direction, uint8_t * result, size_t & size) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения уровня защиты, ключи которого готовы направлению
				 *
				 * @param direction направление связи относительно своей стороны
				 *
				 * @return          наивысший уровень защиты, ключи которого у направления есть
				 *
				 * @note Упреждающие данные клиента объявляются уровнем EARLY, пока стороны не
				 *       перешли к ключам рукопожатия
				 *
				 * \~english
				 * @brief Method of getting the protection level whose keys are ready for a direction
				 * @param direction the direction of the connection relative to one's own side
				 * @return          the highest protection level whose keys the direction has
				 * @note The early data of the client is announced by the EARLY level until the sides have moved
				 *       to the keys of the handshake
				 *
				 * \~
				 */
				context::level_t level(const context::direction_t direction) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки хода упреждающих данных прямо сейчас
				 *
				 * @return признак того, что упреждающие данные идут прямо сейчас
				 *
				 * \~english
				 * @brief Method of checking the early data going right now
				 * @return the flag of the early data going right now
				 *
				 * \~
				 */
				bool earlying() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки размера дейтаграммы связи
				 *
				 * @param mtu устанавливаемый размер дейтаграммы в байтах
				 *
				 * @details Раздел 4.4 RFC 9147: поверх дейтаграмм всякая выдаваемая дейтаграмма не
				 *          длиннее этого размера, а сообщения рукопожатия дробятся под него на
				 *          куски. Умолчание - 1200 байтов; размер ниже наименьшего дозволенного
				 *          (DATAGRAM_MTU_LEAST) поднимается до него, верхнего предела нет: по SCTP
				 *          сообщения бывают длиннее 1500 байтов, а запись протокола и так не
				 *          шире 2^14 байтов. Принимаемые дейтаграммы этим размером не
				 *          ограничены: стороны с разным размером сходятся
				 *
				 * @note Размер устанавливается до заведения связи и значим лишь переносу дейтаграммами
				 *
				 * \~english
				 * @brief Method of setting the size of a datagram of the connection
				 * @param mtu the size of a datagram in bytes being set
				 * @details The section 4.4 of RFC 9147: over datagrams every datagram given out is not longer
				 *          than this size, and the messages of the handshake are split into fragments under it.
				 *          The default is 1200 bytes; a size below the least allowed one (DATAGRAM_MTU_LEAST) is
				 *          raised up to it, there is no upper limit: over SCTP the messages happen to be longer
				 *          than 1500 bytes, and a record of the protocol is not wider than 2^14 bytes anyway. The
				 *          received datagrams are not bound by this size: the sides with different sizes converge
				 * @note The size is set before the establishment of the connection and matters only to the
				 *       transport by datagrams
				 *
				 * \~
				 */
				void mtu(const size_t mtu) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера дейтаграммы связи
				 *
				 * @return размер дейтаграммы в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of a datagram of the connection
				 * @return the size of a datagram in bytes
				 *
				 * \~
				 */
				size_t mtu() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки строгого сервера без состояния издания DTLS 1.2
				 *
				 * @param strict принимается ли приветствие клиента до метки лишь целиком одним куском
				 *
				 * @details Раздел 4.2.1 RFC 6347: до принятой метки сервер состояния по связи не держит.
				 *          Умолчанием дроблёное повторное приветствие собирается под жёсткими пределами
				 *          (DATAGRAM_GREETING байтов на сборку, DATAGRAM_GREETINGS сборок, привязка к
				 *          адресу), ибо чужие клиенты - openssl со стандартными настройками - дробят его
				 *          умолчанием, и без сборки они не связались бы никогда. Строгий сервер принимает
				 *          приветствие лишь целиком одним куском, как DTLSv1_listen, и куски отбрасывает
				 *          молча: он годен для связи своих клиентов со своими серверами, где дробления
				 *          не бывает, и не держит памяти по чужому слову вовсе
				 *
				 * @note Строгость устанавливается до заведения связи и значима лишь серверу издания
				 *       DTLS 1.2 поверх дейтаграмм
				 *
				 * \~english
				 * @brief Method of setting the strict stateless server of the DTLS 1.2 edition
				 * @param strict whether the greeting of the client before the label is accepted only whole in one fragment
				 * @details The section 4.2.1 of RFC 6347: before the accepted label the server holds no state of the
				 *          connection. By default a fragmented repeated greeting is assembled under hard limits
				 *          (DATAGRAM_GREETING bytes per assembly, DATAGRAM_GREETINGS assemblies, binding to the
				 *          address), because foreign clients — openssl with the default settings — fragment it by
				 *          default, and without the assembly they would never connect. The strict server accepts the
				 *          greeting only whole in one fragment, like DTLSv1_listen, and discards the fragments silently:
				 *          it is fit for the connections of own clients with own servers, where there is no
				 *          fragmentation, and holds no memory by a foreign word at all
				 * @note The strictness is set before the establishment of the connection and matters only to the
				 *       server of the DTLS 1.2 edition over datagrams
				 *
				 * \~
				 */
				void strict(const bool strict) noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки строгости сервера без состояния издания DTLS 1.2
				 *
				 * @return признак того, что приветствие клиента до метки принимается лишь целиком
				 *
				 * \~english
				 * @brief Method of checking the strictness of the stateless server of the DTLS 1.2 edition
				 * @return the sign that the greeting of the client before the label is accepted only whole
				 *
				 * \~
				 */
				bool strict() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения срока ожидания повторной передачи
				 *
				 * @return срок ожидания в миллисекундах, ноль, когда ждать нечего
				 *
				 * @details Раздел 5.8.2 RFC 9147: часов у связи нет - срок отдаётся тому, кто связь
				 *          ведёт, а по его истечении зовётся elapsed. Начальный срок - секунда,
				 *          всякая попытка его удваивает до шестидесяти секунд, продвижение залпа
				 *          возвращает его к начальному
				 *
				 * \~english
				 * @brief Method of getting the term of the waiting for a retransmission
				 * @return the term of the waiting in milliseconds, a zero when there is nothing to wait for
				 * @details The section 5.8.2 of RFC 9147: the connection has no clock — the term is given to the
				 *          one who leads the connection, and on its expiry elapsed is called. The initial term is
				 *          a second, every attempt doubles it up to sixty seconds, a progress of the flight
				 *          returns it to the initial one
				 *
				 * \~
				 */
				uint32_t timeout() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извещения связи об истечении срока ожидания
				 *
				 * @return отказ повторной передачи: TIMEOUT по исчерпании попыток
				 *
				 * @details Неподтверждённые куски последнего залпа нарезаются заново и раскладываются по
				 *          дейтаграммам новыми номерами записей; по исчерпании попыток связь обрывается
				 *
				 * \~english
				 * @brief Method of notifying the connection about the expiry of the term of the waiting
				 * @return the failure of the retransmission: TIMEOUT on the exhaustion of the attempts
				 * @details The unacknowledged fragments of the last flight are split anew and laid out over the
				 *          datagrams by new numbers of the records; on the exhaustion of the attempts the
				 *          connection is torn
				 *
				 * \~
				 */
				context::error_t elapsed() noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа молча отброшенных записей и дейтаграмм
				 *
				 * @return число отброшенных записей и дейтаграмм
				 *
				 * @details Раздел 4.5.2 RFC 9147: порча записи, повтор, неведомая пора ключей,
				 *          чужая метка возврата состояния и опознаватель связи отбрасываются молча,
				 *          без извещений; счётчик даёт о них знать тому, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of getting the number of the records and datagrams discarded silently
				 * @return the number of the discarded records and datagrams
				 * @details The section 4.5.2 of RFC 9147: a corruption of a record, a repetition, an unknown epoch,
				 *          a foreign label of the return of the state and a connection identifier are discarded
				 *          silently, without alerts; the counter lets the one who leads the connection know about them
				 *
				 * \~
				 */
				uint64_t discarded() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа отброшенного по причине
				 *
				 * @param reason причина отброса
				 *
				 * @return       число записей и дейтаграмм, отброшенных по этой причине
				 *
				 * @note Сумма по всем причинам равна общему счётчику discarded
				 *
				 * \~english
				 * @brief Method of getting the number of the discarded by a reason
				 * @param reason the reason of the discarding
				 * @return       the number of the records and datagrams discarded by this reason
				 * @note The sum over all the reasons equals the total counter discarded
				 *
				 * \~
				 */
				uint64_t discarded(const datagram::reason_t reason) const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки адреса собеседника для метки возврата состояния
				 *
				 * @param address адрес либо иной опознаватель собеседника
				 *
				 * @return        признак того, что адрес принят
				 *
				 * @details Раздел 5.1 RFC 9147: метка возврата состояния привязывается к адресу, с
				 *          которого пришло приветствие, и повторное приветствие с иного адреса
				 *          отвергается. Содержимое адреса непрозрачно: связь его не разбирает, а
				 *          сличает побайтно - ведущий подаёт, к примеру, два октета порта с четырьмя
				 *          либо шестнадцатью октетами адреса, а по SCTP опознаватель связи
				 *          sinfo_assoc_id. Адрес не длиннее DATAGRAM_ADDRESS байтов, иначе
				 *          отвергается; пустой снимает адрес
				 *
				 * @note Адрес подаётся до заведения связи: без него start отвечает SETTINGS;
				 *       сброс связи вызовом clear снимает и адрес. Молча отбрасывается лишь
				 *       повторное приветствие чужого клиента с негодной меткой
				 *
				 * \~english
				 * @brief Method of setting the address of the interlocutor for the label of the return of the state
				 * @param address the address or another identifier of the interlocutor
				 * @return        the flag of the address being accepted
				 * @details The section 5.1 of RFC 9147: the label of the return of the state is bound to the address
				 *          the greeting came from, and a repeated greeting from another address is rejected. The
				 *          content of the address is opaque: the connection does not parse it but compares byte by
				 *          byte — the leader gives, for instance, two octets of the port with four or sixteen
				 *          octets of the address, or over SCTP the association identifier sinfo_assoc_id. The
				 *          address is not longer than DATAGRAM_ADDRESS bytes, otherwise it is rejected; an empty
				 *          one removes the address
				 * @note The address is given before the establishment of the connection: without it start answers
				 *       SETTINGS; the reset of the connection by clear removes the address too. Only a repeated
				 *       greeting of a foreign client with an unfit label is discarded silently
				 *
				 * \~
				 */
				bool address(const view_t & address) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки секрета метки возврата состояния
				 *
				 * @param secret устанавливаемый секрет любой длины
				 *
				 * @details Секрет сворачивается хешем и служит ключом имитовставки метки; не заданный
				 *          секрет порождается энтропией при заведении связи
				 *
				 * \~english
				 * @brief Method of setting the secret of the label of the return of the state
				 * @param secret the secret of any length being set
				 * @details The secret is folded by a hash and serves as the key of the authentication code of the
				 *          label; a secret not set is generated from the entropy at the establishment of the connection
				 *
				 * \~
				 */
				void stamp(const vector <uint8_t> & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод смены поколения секрета метки возврата состояния
				 *
				 * @details Часов у связи нет, и срок жизни метки судится поколениями: живы два -
				 *          нынешнее и предыдущее, а смену поколения зовёт тот, кто связь ведёт
				 *
				 * \~english
				 * @brief Method of the change of the generation of the secret of the label of the return of the state
				 * @details The connection has no clock, and the lifetime of the label is judged by generations: two
				 *          are alive — the current and the previous one, and the change of the generation is called
				 *          by the one who leads the connection
				 *
				 * \~
				 */
				void restamp() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения связи
				 *
				 * @return отказ заведения связи
				 *
				 * @details Сервер говорит вторым: заведение связи лишь готовит её к приветствию клиента,
				 *          а в накопитель до него ничего не складывается
				 *
				 * \~english
				 * @brief Method of the establishment of the connection
				 * @return the failure of the establishment of the connection
				 * @details The server speaks second: the establishment of the connection only prepares it for the
				 *          greeting of the client, and nothing is put into the accumulator before it
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
				 * @details Поверх дейтаграмм вызов отдаёт ровно одну готовую дейтаграмму - первую
				 *          из очереди; за одну подачу либо отправку готовых дейтаграмм может быть
				 *          несколько, и звать output и consume надлежит, пока просмотр не
				 *          опустеет, иначе остальные дейтаграммы ждут в очереди. Всякая готовая
				 *          запись прикладных данных либо извещения уходит своей дейтаграммой,
				 *          ни одна не теряется и с соседней не сливается
				 *
				 * @note Просмотр смотрит внутрь накопителя связи: снятие байтов вызовом consume
				 *       его обесценивает
				 *
				 * \~english
				 * @brief Method of getting the bytes sent to the interlocutor
				 * @return the accumulated bytes sent to the interlocutor
				 * @details Over datagrams the call gives out exactly one ready datagram — the first of the queue;
				 *          per a single feeding or sending there may be several ready datagrams, and output and
				 *          consume are to be called until the view gets empty, otherwise the rest of the datagrams
				 *          wait in the queue. Every ready record of the application data or of an alert goes by
				 *          its own datagram, none is lost and none merges with the neighbouring one
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
				 *       лишь то, что пришло после. Выдача идёт обменом накопителей без копии:
				 *       прежнее содержимое накопителя result уходит связи под следующие записи
				 *       и затирается по классу PLAINTEXT
				 *
				 * \~english
				 * @brief Method of getting the received application data
				 * @param result the accumulator the received data is transferred into
				 * @return       the failure of getting the received application data
				 * @note The received data is removed from the accumulator of the connection: a repeated call
				 *       will output only what came after. The hand-over swaps the accumulators without a copy:
				 *       the previous contents of result go to the connection for the following records and
				 *       are wiped by the PLAINTEXT class
				 *
				 * \~
				 */
				context::error_t read(vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод выдачи билета возобновления связи клиенту
				 *
				 * @return отказ выдачи билета возобновления связи
				 *
				 * @details Раздел 4.6.1 RFC 8446: билет выдаётся за рукопожатием и годится клиенту
				 *          на будущую связь. Число выдаваемых билетов сервер выбирает сам, и всякому
				 *          из них отвечает свой ключ.
				 *
				 * @note Тело выданного билета назначается связью случайно: опознавать по нему связь
				 *       - дело того, кто связь ведёт, и запись эта принадлежит ему
				 *
				 * \~english
				 * @brief Method of the issue of a ticket of the resumption of the connection to the client
				 * @return the failure of the issue of the ticket of the resumption of the connection
				 * @details The section 4.6.1 of RFC 8446: a ticket is issued after the handshake and is suitable
				 *          for the client for a future connection. The number of the issued tickets is chosen by
				 *          the server itself, and every one of them corresponds to its own key.
				 * @note The body of an issued ticket is appointed by the connection at random: to identify the
				 *       connection by it is the business of the one who leads the connection, and this record
				 *       belongs to them
				 *
				 * \~
				 */
				context::error_t issue() noexcept;
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
				 * @details Раздел 6.1 RFC 8446: закрытие завершает лишь свою передачу. Отправка
				 *          после него отвергается, а приём идёт дальше, пока собеседник не
				 *          завершит свою передачу таким же извещением; принятое извещение
				 *          о закрытии связь отвечает своим сама и после него принятое
				 *          пропускает
				 *
				 * @note Извещение о завершении передачи складывается в накопитель: отправить его
				 *       собеседнику - дело того, кто связь ведёт
				 *
				 * @note Состояние закрытия наступает по любой из сторон; кончился ли приём,
				 *       говорит не оно, а отсутствие принятых данных после подачи
				 *
				 * \~english
				 * @brief Method of the closing of the connection
				 * @return the failure of the closing of the connection
				 * @details The section 6.1 of RFC 8446: the closing finishes only the own transfer. The sending
				 *          after it is refused, and the receiving goes on until the interlocutor finishes its
				 *          transfer by the same alert; the connection answers a received alert about the closing
				 *          by its own one itself and skips what is received after it
				 * @note The alert about the finishing of the transfer is put into the accumulator: to send it
				 *       to the interlocutor is the business of the one who leads the connection
				 * @note The state of the closing comes by any of the sides; whether the receiving is over is
				 *       told not by it but by the absence of the received data after a submission
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

#endif // __ANTS_SERVER__
