/**
 * @file trust.hpp
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
 * @brief Заголовочный файл модуля доверия цепочке сертификатов — запас доверенных
 *        сертификатов, проверка цепочки и сличение имени узла
 *
 * \~english
 * @brief Header file of the module of the trust to a chain of the certificates — the store of
 *        the trusted certificates, the check of a chain and the comparison of the name of a host
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_TRUST__
#define __ANTS_TRUST__

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
	 * @brief Пространство имён модуля доверия цепочке сертификатов
	 *
	 * @details Связь цепочку собеседника лишь принимает и сличает подпись владения ключом
	 *          с первым её сертификатом. Доверие же к издателю решается запасом доверенных
	 *          сертификатов, который принадлежит не связи, а тому, кто её ведёт: этим модулем
	 *          он это решение и принимает.
	 *
	 * @note Часов модуль не читает: миг проверки подаётся ему доводом. Иначе проверку нельзя
	 *       было бы ни повторить, ни проверить, а связи с истёкшим сроком вели бы себя по-разному
	 *       в зависимости от того, когда их проверяют
	 *
	 * \~english
	 * @brief Namespace of the module of the trust to a chain of the certificates
	 * @details A connection only accepts the chain of the interlocutor and compares the signature of the
	 *          possession of the key against the first certificate of it. The trust to the issuer is decided
	 *          by the store of the trusted certificates which belongs not to the connection but to the one
	 *          who leads it: by this module they make this decision.
	 * @note The module does not read the clock: the moment of the check is given to it by an argument.
	 *       Otherwise the check could be neither repeated nor checked, and the connections with an expired
	 *       validity would behave differently depending on when they are checked
	 *
	 * \~
	 */
	namespace trust {
		/**
		 * \~russian
		 * @brief Предел длины проверяемой цепочки сертификатов
		 *
		 * @details Раздел 6.1 RFC 5280 длины цепочки не ограничивает, но всякая проверка
		 *          стоит проверки подписи: без предела цепочка обращается в трату времени,
		 *          назначаемую встречной стороной
		 *
		 * \~english
		 * @brief Limit of the length of a chain of the certificates being checked
		 * @details The section 6.1 of RFC 5280 does not limit the length of a chain, but every check costs
		 *          a check of a signature: without a limit a chain turns into a waste of the time appointed
		 *          by the opposite side
		 *
		 * \~
		 */
		static constexpr size_t TRUST_DEPTH = 8;

		/**
		 * \~russian
		 * @brief Отказы доверия цепочке сертификатов
		 *
		 * \~english
		 * @brief Failures of the trust to a chain of the certificates
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE       = 0x00, /*!< \~russian Отказа нет, цепочка доверия сложилась \~english There is no failure, the chain of the trust has formed \~ */
			EMPTY      = 0x01, /*!< \~russian Проверяемая цепочка пуста \~english The chain being checked is empty \~ */
			DEPTH      = 0x02, /*!< \~russian Длина цепочки превышает дозволенную \~english The length of the chain exceeds the allowed one \~ */
			PARSE      = 0x03, /*!< \~russian Сертификат цепочки разобрать не удалось \~english It was not possible to parse a certificate of the chain \~ */
			EXPIRED    = 0x04, /*!< \~russian Срок действия сертификата на этот миг не идёт \~english The validity of a certificate does not go at this moment \~ */
			ISSUER     = 0x05, /*!< \~russian Издатель сертификата с владельцем следующего разошёлся \~english The issuer of a certificate has diverged with the subject of the next one \~ */
			CONSTRAINT = 0x06, /*!< \~russian Сертификат издавать другие сертификаты не вправе \~english A certificate is not entitled to issue other certificates \~ */
			SIGNATURE  = 0x07, /*!< \~russian Подпись сертификата издателем не сошлась \~english The signature of a certificate by its issuer has not converged \~ */
			AUTHORITY  = 0x08, /*!< \~russian Издателя цепочки в запасе доверенных нет \~english There is no issuer of the chain in the store of the trusted ones \~ */
			NAME       = 0x09, /*!< \~russian Имя узла ни одному имени сертификата не отвечает \~english The name of the host corresponds to no name of the certificate \~ */
			MEMORY     = 0x0A, /*!< \~russian Памяти под разбор цепочки не хватило \~english There was not enough memory for the parsing of the chain \~ */
			CRITICAL   = 0x0B, /*!< \~russian Сертификат несёт неизвестное расширение, объявленное критичным \~english A certificate carries an unknown extension declared critical \~ */
			PURPOSE    = 0x0C, /*!< \~russian Назначение ключа сертификата подписи владения не дозволяет \~english The purpose of the key of the certificate does not allow the signature of the possession \~ */
			CONSTRAINED = 0x0D /*!< \~russian Имя сертификата нарушает ограничения имён издателя (раздел 4.2.1.10 RFC 5280) либо ограничения не разобрать \~english A name of a certificate violates the name constraints of an issuer (the section 4.2.1.10 of RFC 5280) or the constraints cannot be parsed \~ */
		};

		/**
		 * \~russian
		 * @brief Запас доверенных сертификатов
		 *
		 * @details Запас владеет записями сертификатов: цепочка, поданная на проверку, живёт
		 *          ровно столько, сколько длится связь, а запас переживает всякую из них
		 *
		 * \~english
		 * @brief Store of the trusted certificates
		 * @details The store owns the records of the certificates: a chain given for a check lives exactly
		 *          as long as a connection lasts, while the store outlives every one of them
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Store {
			private:
				// Записи доверенных сертификатов запаса
				vector <vector <uint8_t>> _chain;
			public:
				/**
				 * \~russian
				 * @brief Метод получения числа доверенных сертификатов запаса
				 *
				 * @return число доверенных сертификатов запаса
				 *
				 * \~english
				 * @brief Method of getting the number of the trusted certificates of the store
				 * @return the number of the trusted certificates of the store
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения доверенного сертификата запаса
				 *
				 * @param index место запрашиваемого сертификата в запасе
				 *
				 * @return      запись запрашиваемого сертификата
				 *
				 * \~english
				 * @brief Method of getting a trusted certificate of the store
				 * @param index the place of the requested certificate in the store
				 * @return      the record of the requested certificate
				 *
				 * \~
				 */
				view_t get(const size_t index) const noexcept;
				/**
				 * \~russian
				 * @brief Метод добавления доверенного сертификата в запас
				 *
				 * @param certificate запись добавляемого сертификата
				 *
				 * @return            признак успешности добавления сертификата
				 *
				 * @note Сертификат разбирается при добавлении: непригодной записью запас
				 *       доверия пополнять нечего
				 *
				 * \~english
				 * @brief Method of the addition of a trusted certificate to the store
				 * @param certificate the record of the certificate being added
				 * @return            the flag of the success of the addition of the certificate
				 * @note The certificate is parsed at the addition: there is no point in replenishing the store
				 *       of the trust by an unsuitable record
				 *
				 * \~
				 */
				bool add(const view_t & certificate) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса запаса доверенных сертификатов
				 *
				 * \~english
				 * @brief Method of the reset of the store of the trusted certificates
				 *
				 * \~
				 */
				void clear() noexcept;
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
				Store() noexcept {}
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
				~Store() noexcept {}
		} store_t;

		/**
		 * \~russian
		 * @brief Роль собеседника, чья цепочка проверяется
		 *
		 * @details Раздел 4.2.1.12 RFC 5280: назначение extendedKeyUsage листа обязано отвечать роли -
		 *          serverAuth у сервера, clientAuth у клиента; anyExtendedKeyUsage годится обеим
		 *
		 * \~english
		 * @brief Role of the peer whose chain is being checked
		 *
		 * @details The section 4.2.1.12 of RFC 5280: the extendedKeyUsage purpose of the leaf must match the
		 *          role - serverAuth at a server, clientAuth at a client; anyExtendedKeyUsage suits both
		 *
		 * \~
		 */
		enum class role_t : uint8_t {
			ANY    = 0x00, /*!< \~russian Роль не судится: годится любое из назначений \~english The role is not judged: any of the purposes suits \~ */
			SERVER = 0x01, /*!< \~russian Проверяется сервер: нужен serverAuth \~english A server is being checked: serverAuth is needed \~ */
			CLIENT = 0x02  /*!< \~russian Проверяется клиент: нужен clientAuth \~english A client is being checked: clientAuth is needed \~ */
		};
		/**
		 * \~russian
		 * @brief Метод проверки цепочки сертификатов запасом доверенных
		 *
		 * @param chain  проверяемая цепочка сертификатов от своего к издателю
		 * @param store  запас доверенных сертификатов
		 * @param moment миг проверки в секундах от начала эпохи
		 *
		 * @return       отказ доверия цепочке сертификатов
		 *
		 * @details Раздел 6.1 RFC 5280: цепочка проверяется звено за звеном - срок действия,
		 *          совпадение издателя с владельцем следующего, право издавать сертификаты и
		 *          подпись, - а замыкается она сертификатом из запаса доверенных
		 *
		 * @note Списки отзыва здесь не проверяются: они добываются по сети, а модуль ввода и
		 *       вывода не ведёт вовсе
		 *
		 * \~english
		 * @brief Method of the check of a chain of the certificates by a store of the trusted ones
		 * @param chain  the chain of the certificates being checked from one's own to the issuer
		 * @param store  the store of the trusted certificates
		 * @param moment the moment of the check in seconds from the beginning of the epoch
		 * @return       the failure of the trust to the chain of the certificates
		 * @details The section 6.1 of RFC 5280: a chain is checked link by link — the validity, the
		 *          coincidence of the issuer with the subject of the next one, the right to issue the
		 *          certificates and the signature — and it is closed by a certificate from the store
		 * @note The revocation lists are not checked here: they are obtained over a network, and the module
		 *       does not lead the input and the output at all
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const vector <vector <uint8_t>> & chain, const store_t & store, const int64_t moment) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки цепочки сертификатов по запасу доверенных с учётом роли собеседника
		 *
		 * @param chain  проверяемая цепочка сертификатов от своего к издателю
		 * @param store  запас доверенных сертификатов
		 * @param moment миг проверки в секундах от начала эпохи
		 * @param role   роль собеседника: назначение листа обязано ей отвечать
		 *
		 * @return       отказ доверия цепочке сертификатов: PURPOSE при назначении не по роли
		 *
		 * \~english
		 * @brief Method of the check of a chain of the certificates by a store of the trusted ones with the role of the peer
		 * @param chain  the chain of the certificates being checked from one's own to the issuer
		 * @param store  the store of the trusted certificates
		 * @param moment the moment of the check in seconds from the beginning of the epoch
		 * @param role   the role of the peer: the purpose of the leaf must match it
		 * @return       the failure of the trust to the chain of the certificates: PURPOSE at a purpose not by the role
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const vector <vector <uint8_t>> & chain, const store_t & store, const int64_t moment, const role_t role) noexcept;
		/**
		 * \~russian
		 * @brief Метод сличения имени узла с именами сертификата
		 *
		 * @param certificate запись сличаемого сертификата
		 * @param name        имя узла, за которым пришли
		 *
		 * @return            отказ сличения имени узла
		 *
		 * @details Раздел 6.4 RFC 6125: имя разыскивается среди дополнительных имён владельца,
		 *          а общее имя владельца берётся лишь тогда, когда дополнительных имён нет вовсе
		 *
		 * @note Звёздочка дозволена лишь в самой левой части имени и лишь целой частью: имя
		 *       вида «*.anyks.com» отвечает «www.anyks.com», но не «www.dev.anyks.com»
		 *
		 * \~english
		 * @brief Method of the comparison of the name of a host with the names of a certificate
		 * @param certificate the record of the certificate being compared
		 * @param name        the name of the host one came for
		 * @return            the failure of the comparison of the name of the host
		 * @details The section 6.4 of RFC 6125: the name is searched for among the alternative names of the
		 *          subject, and the common name of the subject is taken only when there are no alternative
		 *          names at all
		 * @note An asterisk is allowed only in the leftmost part of a name and only as a whole part: a name
		 *       of the kind «*.anyks.com» corresponds to «www.anyks.com» but not to «www.dev.anyks.com»
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t belongs(const view_t & certificate, const string & name) noexcept;
	};
};

#endif // __ANTS_TRUST__
