/**
 * @file engine.hpp
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
 * @brief Заголовочный файл внутреннего модуля ведения связи протокола TLS 1.3
 *
 * @note Модуль внутренний: он лежит в src и наружному договору библиотеки не
 *       принадлежит. Наружу его выводят фасады клиента и сервера, а он сам ведёт
 *       обе роли сразу - расходятся они лишь порядком сообщений
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_ENGINE__
#define __ANYKS_TLS_ENGINE__

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
#include <flow/flow.hpp>
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <curve/curve.hpp>
#include <record/record.hpp>
#include <context/context.hpp>
#include <message/message.hpp>
#include <protect/protect.hpp>
#include <session/session.hpp>
#include <extension/extension.hpp>
#include <handshake/handshake.hpp>

/**
 * @brief Основное пространство имён
 *
 */
namespace anyks {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * @brief Пространство имён внутренних модулей библиотеки
	 *
	 */
	namespace internal {
		/**
		 * @brief Ведение связи протокола TLS 1.3
		 *
		 * @details Связь принимает байты вызовом push и складывает отправляемые в
		 *          накопитель: ввода и вывода в ней нет вовсе
		 *
		 */
		typedef class Engine {
			private:
				// Признак того, что связь ведётся стороной сервера
				bool _server;
				// Признак того, что подлинность клиента запрашивается сервером
				bool _request;
				// Признак того, что подлинность клиента запрошена собеседником
				bool _requested;
				// Признак того, что повтор приветствия уже был
				bool _retried;
			private:
				// Состояние связи
				context::state_t _state;
				// Отказ, которым связь оборвана
				context::error_t _error;
				// Извещение, которым связь оборвана
				alert::alert_t _alert;
			private:
				// Ход рукопожатия связи
				flow::machine_t _machine;
				// Переписка рукопожатия связи
				session::transcript_t _transcript;
				// Значения расписания ключей связи
				session::secrets_t _secrets;
			private:
				// Сборщик входящих записей связи
				record::reader_t _records;
				// Сборщик входящих сообщений рукопожатия
				handshake::reader_t _messages;
			private:
				// Защита отправляемых записей связи
				protect::protection_t _output;
				// Защита принимаемых записей связи
				protect::protection_t _input;
			private:
				// Поры ключей, установленных защите записей
				flow::epoch_t _epoch[2];
			private:
				// Набор шифрования, которым защищаются записи связи
				protect::suite_t _suite;
				// Кривая обмена мимолётными ключами связи
				extension::group_t _group;
			private:
				// Эллиптическая кривая обмена мимолётными ключами
				curve::curve_t _curve;
			private:
				// Секретный мимолётный ключ своей стороны
				vector <uint8_t> _secret;
				// Открытый мимолётный ключ своей стороны
				vector <uint8_t> _opened;
			private:
				// Ключи завершения рукопожатия сторон связи
				uint8_t _completion[2][32];
				// Ключевой материал прикладных данных сторон связи
				uint8_t _key[2][protect::PROTECT_KEY], _vector[2][protect::PROTECT_VECTOR];
			private:
				// Случайное значение своего приветствия
				uint8_t _random[32];
				// Опознаватель связи, доставшийся от предыдущих изданий
				vector <uint8_t> _session;
			private:
				// Накопитель отправляемых байтов связи
				vector <uint8_t> _wire;
				// Накопитель принятых прикладных данных
				vector <uint8_t> _plain;
			private:
				// Наборы шифрования, предлагаемые связью
				vector <protect::suite_t> _suites;
				// Кривые обмена ключами, предлагаемые связью
				vector <extension::group_t> _groups;
			private:
				// Подлинность своей стороны связи
				context::credential_t _credential;
				// Имя узла, запрашиваемое клиентом у сервера
				string _name;
			private:
				// Прикладные протоколы, предлагаемые связью
				vector <string> _protocols;
				// Прикладной протокол, выбранный сторонами связи
				string _protocol;
			private:
				// Признак того, что связь возобновлена заранее разделённым ключом
				bool _shared;
			private:
				// Место выбранного сервером ключа в предложении клиента
				uint16_t _chosen;
			private:
				// Признак того, что упреждающие данные связью предлагаются либо принимаются
				bool _advance;
				// Признак того, что упреждающие данные идут прямо сейчас
				bool _earlying;
				// Признак того, что упреждающие данные приняты собеседником
				bool _accepted;
			private:
				// Набор шифрования билета, из которого выводятся ключи упреждения
				protect::suite_t _ticket;
			private:
				// Число записей, пропущенных отвергнутыми упреждающими данными
				size_t _skipped;
			private:
				// Защита записей упреждающих данных связи
				protect::protection_t _early;
			private:
				// Билет, предъявляемый клиентом на возобновление связи
				context::ticket_t _resume;
				// Билеты, признаваемые сервером на возобновление связи
				vector <context::ticket_t> _store;
			private:
				// Билеты возобновления связи, выданные либо принятые
				vector <context::ticket_t> _tickets;
			private:
				// Цепочка сертификатов собеседника
				vector <vector <uint8_t>> _peer;
			private:
				/**
				 * @brief Метод обрыва связи отказом
				 *
				 * @param error       отказ, которым связь обрывается
				 * @param description описание извещения, отправляемого собеседнику
				 *
				 * @return            отказ, которым связь оборвана
				 *
				 */
				context::error_t abort(const context::error_t error, const alert::description_t description) noexcept;
				/**
				 * @brief Метод складывания записи в накопитель отправляемых байтов
				 *
				 * @param type вид содержимого отправляемой записи
				 * @param data содержимое отправляемой записи
				 *
				 * @return     отказ складывания записи в накопитель
				 *
				 */
				context::error_t emit(const record::type_t type, const view_t & data) noexcept;
				/**
				 * @brief Метод отправки сообщения рукопожатия собеседнику
				 *
				 * @param type вид отправляемого сообщения рукопожатия
				 * @param body тело отправляемого сообщения рукопожатия
				 *
				 * @return     отказ отправки сообщения рукопожатия
				 *
				 */
				context::error_t send(const handshake::type_t type, const view_t & body) noexcept;
			private:
				/**
				 * @brief Метод согласования ключевого материала защиты записей
				 *
				 * @return отказ согласования ключевого материала
				 *
				 * @details Ключевой материал устанавливается защите записей тогда, когда пора
				 *          ключей стороны переменилась ходом рукопожатия
				 *
				 */
				context::error_t refresh() noexcept;
				/**
				 * @brief Метод вывода ключей рукопожатия связи
				 *
				 * @param key открытый мимолётный ключ собеседника
				 *
				 * @return    отказ вывода ключей рукопожатия
				 *
				 */
				context::error_t derive(const view_t & key) noexcept;
				/**
				 * @brief Метод вывода ключей прикладных данных связи
				 *
				 * @return отказ вывода ключей прикладных данных
				 *
				 */
				context::error_t mature() noexcept;
				/**
				 * @brief Метод заведения защиты записей упреждающих данных
				 *
				 * @return отказ заведения защиты записей упреждающих данных
				 *
				 */
				context::error_t earliest() noexcept;
			private:
				/**
				 * @brief Метод выработки мимолётной пары ключей своей стороны
				 *
				 * @param group кривая, для которой вырабатывается пара ключей
				 *
				 * @return      отказ выработки мимолётной пары ключей
				 *
				 */
				context::error_t exchange(const extension::group_t group) noexcept;
			private:
				/**
				 * @brief Метод отправки приветствия клиента
				 *
				 * @return отказ отправки приветствия клиента
				 *
				 */
				context::error_t greeting() noexcept;
				/**
				 * @brief Метод отправки приветствия сервера
				 *
				 * @param session опознаватель связи, повторяемый за приветствием клиента
				 * @param retry   признак того, что отправляется просьба о повторе приветствия
				 *
				 * @return        отказ отправки приветствия сервера
				 *
				 */
				context::error_t answer(const vector <uint8_t> & session, const bool retry) noexcept;
				/**
				 * @brief Метод отправки подтверждения подлинности своей стороны
				 *
				 * @return отказ отправки подтверждения подлинности
				 *
				 */
				context::error_t authenticate() noexcept;
				/**
				 * @brief Метод отправки завершения рукопожатия своей стороной
				 *
				 * @return отказ отправки завершения рукопожатия
				 *
				 */
				context::error_t complete() noexcept;
			private:
				/**
				 * @brief Метод разбора принятого сообщения рукопожатия
				 *
				 * @param type    вид принятого сообщения рукопожатия
				 * @param body    тело принятого сообщения рукопожатия
				 * @param message принятое сообщение рукопожатия вместе с обвязкой
				 *
				 * @return        отказ разбора сообщения рукопожатия
				 *
				 */
				context::error_t handle(const handshake::type_t type, const view_t & body, const view_t & message) noexcept;
				/**
				 * @brief Метод разбора предложения заранее разделённых ключей клиента
				 *
				 * @param extensions перечень расширений принятого приветствия клиента
				 * @param message    принятое приветствие клиента вместе с обвязкой
				 *
				 * @return           отказ разбора предложения заранее разделённых ключей
				 *
				 */
				context::error_t offered(const vector <hello::extension_t> & extensions, const view_t & message) noexcept;
				/**
				 * @brief Метод разбора принятого приветствия клиента
				 *
				 * @param body    тело принятого приветствия клиента
				 * @param message принятое приветствие клиента вместе с обвязкой
				 *
				 * @return        отказ разбора приветствия клиента
				 *
				 */
				context::error_t incoming(const view_t & body, const view_t & message) noexcept;
				/**
				 * @brief Метод разбора принятого приветствия сервера
				 *
				 * @param body    тело принятого приветствия сервера
				 * @param message принятое приветствие сервера вместе с обвязкой
				 *
				 * @return        отказ разбора приветствия сервера
				 *
				 */
				context::error_t outgoing(const view_t & body, const view_t & message) noexcept;
				/**
				 * @brief Метод разбора принятой цепочки сертификатов собеседника
				 *
				 * @param body тело принятого сообщения цепочки сертификатов
				 *
				 * @return     отказ разбора цепочки сертификатов
				 *
				 */
				context::error_t chain(const view_t & body) noexcept;
				/**
				 * @brief Метод проверки принятой подписи владения ключом
				 *
				 * @param body тело принятого сообщения подписи владения ключом
				 *
				 * @return     отказ проверки подписи владения ключом
				 *
				 */
				context::error_t possession(const view_t & body) noexcept;
				/**
				 * @brief Метод проверки принятого завершения рукопожатия
				 *
				 * @param body тело принятого сообщения завершения рукопожатия
				 *
				 * @return     отказ проверки завершения рукопожатия
				 *
				 */
				context::error_t confirm(const view_t & body) noexcept;
				/**
				 * @brief Метод смены ключевого материала направления связи
				 *
				 * @param side сторона, чьё направление связи сменяется
				 *
				 * @return     отказ смены ключевого материала направления
				 *
				 */
				context::error_t rotate(const session::side_t side) noexcept;
				/**
				 * @brief Метод разбора принятой смены ключевого материала
				 *
				 * @param body тело принятого сообщения смены ключевого материала
				 *
				 * @return     отказ разбора смены ключевого материала
				 *
				 */
				context::error_t renew(const view_t & body) noexcept;
				/**
				 * @brief Метод вывода значения возобновления связи
				 *
				 * @return отказ вывода значения возобновления связи
				 *
				 */
				context::error_t keeping() noexcept;
				/**
				 * @brief Метод разбора принятого билета возобновления связи
				 *
				 * @param body тело принятого сообщения билета
				 *
				 * @return     отказ разбора билета возобновления связи
				 *
				 */
				context::error_t accept(const view_t & body) noexcept;
				/**
				 * @brief Метод разбора принятого извещения
				 *
				 * @param data принятое извещение
				 *
				 * @return     отказ разбора принятого извещения
				 *
				 */
				context::error_t notice(const view_t & data) noexcept;
			public:
				/**
				 * @brief Метод получения состояния связи
				 *
				 * @return состояние связи
				 *
				 */
				context::state_t state() const noexcept;
				/**
				 * @brief Метод получения отказа, которым связь оборвана
				 *
				 * @return отказ, которым связь оборвана
				 *
				 */
				context::error_t error() const noexcept;
				/**
				 * @brief Метод получения извещения, которым связь оборвана
				 *
				 * @return извещение, которым связь оборвана
				 *
				 */
				const alert::alert_t & alert() const noexcept;
				/**
				 * @brief Метод получения набора шифрования связи
				 *
				 * @return согласованный сторонами набор шифрования
				 *
				 */
				protect::suite_t suite() const noexcept;
				/**
				 * @brief Метод получения цепочки сертификатов собеседника
				 *
				 * @return цепочка сертификатов, предъявленная собеседником
				 *
				 */
				const vector <vector <uint8_t>> & peer() const noexcept;
				/**
				 * @brief Метод получения имени узла связи
				 *
				 * @return имя узла, запрошенное клиентом у сервера
				 *
				 */
				const string & name() const noexcept;
				/**
				 * @brief Метод получения прикладного протокола связи
				 *
				 * @return прикладной протокол, выбранный сторонами связи
				 *
				 */
				const string & protocol() const noexcept;
			public:
				/**
				 * @brief Метод установки предлагаемых наборов шифрования
				 *
				 * @param suites устанавливаемые наборы шифрования
				 *
				 */
				void suites(const vector <protect::suite_t> & suites) noexcept;
				/**
				 * @brief Метод установки предлагаемых кривых обмена ключами
				 *
				 * @param groups устанавливаемые кривые обмена ключами
				 *
				 */
				void groups(const vector <extension::group_t> & groups) noexcept;
				/**
				 * @brief Метод установки подлинности своей стороны связи
				 *
				 * @param credential устанавливаемая подлинность своей стороны
				 *
				 */
				void credential(const context::credential_t & credential) noexcept;
				/**
				 * @brief Метод установки имени узла, запрашиваемого у сервера
				 *
				 * @param name устанавливаемое имя узла
				 *
				 */
				void name(const string & name) noexcept;
				/**
				 * @brief Метод установки предлагаемых прикладных протоколов
				 *
				 * @param protocols устанавливаемые прикладные протоколы
				 *
				 */
				void protocols(const vector <string> & protocols) noexcept;
				/**
				 * @brief Метод установки билета возобновления связи клиентом
				 *
				 * @param ticket предъявляемый билет возобновления связи
				 *
				 */
				void resume(const context::ticket_t & ticket) noexcept;
				/**
				 * @brief Метод установки билетов, признаваемых сервером
				 *
				 * @param tickets признаваемые билеты возобновления связи
				 *
				 */
				void resume(const vector <context::ticket_t> & tickets) noexcept;
				/**
				 * @brief Метод проверки возобновления связи заранее разделённым ключом
				 *
				 * @return признак того, что связь возобновлена билетом
				 *
				 */
				bool shared() const noexcept;
				/**
				 * @brief Метод установки предложения упреждающих данных
				 *
				 * @param advance устанавливаемое предложение упреждающих данных
				 *
				 */
				void advance(const bool advance) noexcept;
				/**
				 * @brief Метод проверки приёма упреждающих данных собеседником
				 *
				 * @return признак того, что упреждающие данные приняты
				 *
				 */
				bool accepted() const noexcept;
				/**
				 * @brief Метод установки требования подлинности клиента
				 *
				 * @param request устанавливаемое требование подлинности клиента
				 *
				 */
				void request(const bool request) noexcept;
			public:
				/**
				 * @brief Метод заведения связи
				 *
				 * @return отказ заведения связи
				 *
				 */
				context::error_t start() noexcept;
				/**
				 * @brief Метод сброса состояния связи
				 *
				 */
				void clear() noexcept;
			public:
				/**
				 * @brief Метод подачи связи принятых байтов
				 *
				 * @param data принятые байты связи
				 *
				 * @return     отказ разбора принятых байтов
				 *
				 */
				context::error_t push(const view_t & data) noexcept;
				/**
				 * @brief Метод получения байтов, отправляемых собеседнику
				 *
				 * @return накопленные байты, отправляемые собеседнику
				 *
				 */
				view_t output() const noexcept;
				/**
				 * @brief Метод снятия отправленных байтов с накопителя
				 *
				 * @param size размер снимаемых байтов
				 *
				 */
				void consume(const size_t size) noexcept;
			public:
				/**
				 * @brief Метод отправки прикладных данных собеседнику
				 *
				 * @param data отправляемые прикладные данные
				 *
				 * @return     отказ отправки прикладных данных
				 *
				 */
				context::error_t write(const view_t & data) noexcept;
				/**
				 * @brief Метод получения принятых прикладных данных
				 *
				 * @param result накопитель, в который переносятся принятые данные
				 *
				 * @return       отказ получения принятых прикладных данных
				 *
				 */
				context::error_t read(vector <uint8_t> & result) noexcept;
				/**
				 * @brief Метод смены ключевого материала своего направления связи
				 *
				 * @param request признак просьбы к собеседнику сменить свои ключи в ответ
				 *
				 * @return        отказ смены ключевого материала своего направления
				 *
				 */
				context::error_t update(const bool request) noexcept;
				/**
				 * @brief Метод выдачи билета возобновления связи
				 *
				 * @return отказ выдачи билета возобновления связи
				 *
				 */
				context::error_t issue() noexcept;
				/**
				 * @brief Метод получения билетов возобновления связи
				 *
				 * @return выданные либо принятые билеты возобновления связи
				 *
				 */
				const vector <context::ticket_t> & tickets() const noexcept;
				/**
				 * @brief Метод закрытия связи
				 *
				 * @return отказ закрытия связи
				 *
				 */
				context::error_t close() noexcept;
			public:
				/**
				 * @brief Конструктор
				 *
				 * @param server признак того, что связь ведётся стороной сервера
				 *
				 */
				Engine(const bool server) noexcept;
				/**
				 * @brief Деструктор
				 *
				 */
				~Engine() noexcept;
		} engine_t;
	};
};

#endif // __ANYKS_TLS_ENGINE__
