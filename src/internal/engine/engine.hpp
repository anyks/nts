/**
 * @file engine.hpp
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
#ifndef __ANTS_ENGINE__
#define __ANTS_ENGINE__

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
#include <ocsp/ocsp.hpp>
#include <trust/trust.hpp>
#include <datagram/datagram.hpp>

/**
 * @brief Основное пространство имён
 *
 */
namespace nts {
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
		 * @brief Мимолётная пара ключей своей стороны по одной группе обмена
		 *
		 */
		typedef struct Exchange {
			// Группа обмена ключами
			extension::group_t group;
			// Секретный мимолётный ключ своей стороны
			vector <uint8_t> secret;
			// Открытый мимолётный ключ своей стороны в записи протокола
			vector <uint8_t> opened;
			/**
			 * @brief Конструктор
			 *
			 */
			Exchange() noexcept : group(extension::group_t::NONE) {}
		} exchange_t;
		/**
		 * @brief Пора ключей одного направления связи поверх дейтаграмм
		 *
		 * @details Раздел 4.2.1 RFC 9147: всякая смена ключей направления открывает новую
		 *          пору со своим номером, своим счётом записей и своим окном повторов;
		 *          нулевая пора идёт без защиты
		 *
		 */
		typedef struct Era {
			// Признак того, что пора заведена
			bool held;
			// Номер поры ключей
			uint16_t epoch;
			// Порядковый номер очередной отправляемой записи поры
			uint64_t next;
			// Защита записей поры
			protect::protection_t protection;
			// Ключ шифрования номера записи поры
			uint8_t sn[protect::PROTECT_KEY];
			// Окно защиты от повторов принимаемых записей поры
			datagram::window_t window;
			/**
			 * @brief Конструктор
			 *
			 */
			Era() noexcept;
		} era_t;
		/**
		 * @brief Сообщение рукопожатия последнего отправленного залпа
		 *
		 * @details Раздел 5.8 RFC 9147: залп хранится целиком до подтверждения, ибо
		 *          повторная передача заново нарезает его на куски под размер дейтаграммы
		 *
		 */
		typedef struct Dispatch {
			// Признак того, что сообщение уже нарезано на записи
			bool dispatched;
			// Пора ключей, которой сообщение отправляется
			uint16_t epoch;
			// Порядковый номер сообщения рукопожатия
			uint16_t sequence;
			// Сообщение рукопожатия вместе с обвязкой TLS
			vector <uint8_t> message;
			/**
			 * @brief Конструктор
			 *
			 */
			Dispatch() noexcept : dispatched(false), epoch(0), sequence(0) {}
		} dispatch_t;
		/**
		 * @brief Кусок сообщения залпа, отправленный одной записью
		 *
		 * @details Раздел 7 RFC 9147: подтверждение приходит номерами записей, оттого
		 *          всякий кусок помнит запись, которой ушёл
		 *
		 */
		typedef struct Piece {
			// Признак того, что запись куска подтверждена собеседником
			bool acked;
			// Пора ключей записи куска
			uint16_t epoch;
			// Порядковый номер записи куска
			uint64_t sequence;
			// Место сообщения куска в залпе
			size_t index;
			// Смещение куска в теле сообщения
			size_t offset;
			// Длина куска в байтах
			size_t length;
			/**
			 * @brief Конструктор
			 *
			 */
			Piece() noexcept : acked(false), epoch(0), sequence(0), index(0), offset(0), length(0) {}
		} piece_t;
		/**
		 * @brief Область тела сообщения, покрытая принятыми кусками
		 *
		 */
		typedef struct Span {
			// Смещение области в теле сообщения
			size_t offset;
			// Длина области в байтах
			size_t length;
			/**
			 * @brief Конструктор
			 *
			 * @param offset смещение области в теле сообщения
			 * @param length длина области в байтах
			 *
			 */
			Span(const size_t offset, const size_t length) noexcept : offset(offset), length(length) {}
		} span_t;
		/**
		 * @brief Сборка принимаемого сообщения рукопожатия из кусков
		 *
		 * @details Раздел 5.5 RFC 9147: куски приходят с любым перекрытием и в любом
		 *          порядке, и сообщение считается собранным, когда покрыто целиком
		 *
		 */
		typedef struct Assembly {
			// Вид сообщения рукопожатия
			handshake::type_t type;
			// Порядковый номер сообщения рукопожатия
			uint16_t sequence;
			// Тело сообщения, заполняемое кусками
			vector <uint8_t> body;
			// Области тела, покрытые принятыми кусками, по возрастанию смещения
			vector <span_t> spans;
			/**
			 * @brief Конструктор
			 *
			 */
			Assembly() noexcept : type(handshake::type_t::NONE), sequence(0) {}
		} assembly_t;
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
				// Мимолётные пары ключей своей стороны по группам обмена
				vector <exchange_t> _exchanges;
			private:
				// Ключи завершения рукопожатия сторон связи
				uint8_t _completion[2][schedule::SCHEDULE_WIDEST];
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
				// Группы обмена, по которым связь шлёт доли ключа приветствием
				vector <extension::group_t> _shares;
			private:
				// Подлинность своей стороны связи
				context::credential_t _credential;
				// Имя узла, запрашиваемое клиентом у сервера
				string _name;
			private:
				// Миг, которым связь судит сроки билетов возобновления
				int64_t _moment;
			private:
				// Предел упреждающих данных, объявляемый сервером билетом
				uint32_t _limit;
				// Размер упреждающих данных, прошедших через связь
				uint32_t _passed;
			private:
				// Виды расширений, предложенных клиентом приветствием
				vector <uint16_t> _offered;
				// Метка возврата состояния сервера, повторяемая приветствием
				vector <uint8_t> _cookie;
				// Метка возврата состояния, принятая сервером от клиента
				vector <uint8_t> _label;
			private:
				// Схемы подписи, признаваемые собеседником
				vector <extension::scheme_t> _schemes;
				// Схемы подписи, признаваемые связью
				vector <extension::scheme_t> _signatures;
				// Опознаватель принятого запроса подлинности, повторяемый цепочкой
				vector <uint8_t> _binding;
				// Прикладной протокол связи, выдавшей признанный сервером билет
				string _previous;
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
				// Признак того, что ключи сменяются движком самим по счётчику записей
				bool _automatic;
				// Признак того, что смена ключей у собеседника уже испрошена
				bool _asked;
				// Признак того, что ответная смена ключей собеседнику задолжена
				bool _owed;
				// Признак того, что упреждение отвергнуто расхождением возраста билета
				bool _misaged;
				// Предел упреждающих данных, объявленный признанным билетом
				uint32_t _granted;
				// Число записей направления, по которому сменяются ключи
				uint64_t _renewal;
			private:
				// Признак того, что своя передача завершена извещением о закрытии
				bool _closed;
				// Признак того, что собеседник завершил передачу извещением о закрытии
				bool _drained;
			private:
				// Срок жизни выдаваемых билетов возобновления связи в секундах
				uint32_t _lifetime;
			private:
				// Набор шифрования билета, из которого выводятся ключи упреждения
				protect::suite_t _ticket;
			private:
				// Число записей, пропущенных отвергнутыми упреждающими данными
				size_t _skipped;
			private:
				/**
				 * Признак того, что настройкам связи памяти не хватило: установщики
				 * настроек отказа не выводят, и нехватка памяти при них помнится до
				 * заведения связи, которое на неё и отвечает отказом памяти
				 */
				bool _starved;
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
				// Способ переноса рукопожатия связи
				context::transport_t _transport;
			private:
				// Свои параметры переноса QUIC, объявляемые рукопожатием
				vector <uint8_t> _parameters;
				// Параметры переноса QUIC, принятые от собеседника
				vector <uint8_t> _received;
				// Признак того, что параметры переноса собеседника приняты
				bool _acquired;
			private:
				// Накопители отправляемых сообщений рукопожатия по уровням защиты
				vector <uint8_t> _levels[4];
				// Уровень защиты, на котором подано недособранное сообщение
				context::level_t _pushed;
			private:
				// Значения направлений связи по уровням защиты и сторонам
				uint8_t _traffic[3][2][schedule::SCHEDULE_WIDEST];
				// Признаки готовности значений направлений по уровням защиты
				uint8_t _ready[3];
				// Длина значений направлений связи в байтах
				size_t _width;
			private:
				// Признак того, что упреждающие данные связью предлагались
				bool _ventured;
				// Признак того, что решение сервера об упреждающих данных получено
				bool _judged;
			private:
				// Алгоритмы сжатия цепочки сертификатов, предоставленные потребителем
				vector <context::codec_t> _codecs;
				// Алгоритмы сжатия, объявленные собеседником, в его порядке предпочтения
				vector <uint16_t> _compressible;
				// Предел длины цепочки сертификатов после распаковки в байтах
				size_t _inflation;
				// Алгоритм, которым сжата отправленная цепочка сертификатов своей стороны
				uint16_t _squeezed;
				// Алгоритм, которым была сжата принятая цепочка сертификатов собеседника
				uint16_t _inflated;
			private:
				// Признак того, что состояние сертификата собеседника связью запрашивается
				bool _inquiring;
				// Признак того, что состояние своего сертификата собеседником запрошено
				bool _inquired;
				// Признак того, что принятый ответ о состоянии связью проверяется
				bool _verifying;
				// Дозволенный люфт сроков ответа о состоянии в секундах
				int64_t _leeway;
				// Состояние сертификата собеседника по проверенному ответу
				ocsp::status_t _certified;
				// Ответы о состоянии своих сертификатов по местам в цепочке
				vector <vector <uint8_t>> _staples;
				// Ответ о состоянии сертификата собеседника, принятый связью
				vector <uint8_t> _status;
				// Запас доверенных сертификатов для розыска издателя собеседника
				trust::store_t _anchors;
			private:
				// Размер дейтаграммы связи в байтах
				size_t _mtu;
				// Срок ожидания повторной передачи в миллисекундах
				uint32_t _timeout;
				// Число попыток повторной передачи залпа
				uint32_t _attempts;
				// Признак того, что срок ожидания повторной передачи идёт
				bool _timing;
				// Признак того, что залп составлен просьбою о повторе и часов не ждёт
				bool _challenged;
				// Признак того, что за подачу залп рукопожатия пополнился
				bool _replied;
				// Признак того, что своя смена ключей ждёт подтверждения залпа
				bool _rotating;
				// Признак того, что просьба о повторе просит долю ключа
				bool _reshare;
				// Признак того, что секрет метки возврата состояния задан
				bool _stamped;
				// Поколение секрета метки возврата состояния
				uint8_t _generation;
				// Секреты метки возврата состояния двух живых поколений
				uint8_t _stamps[2][32];
				// Адрес собеседника, привязываемый к метке возврата состояния
				vector <uint8_t> _address;
				// Нулевые поры направлений связи: записи без защиты
				era_t _plains[2];
				// Защищённые поры ключей направлений связи: запись и чтение, по два места
				era_t _eras[2][2];
				// Места текущих пор ключей направлений
				uint8_t _slots[2];
				// Сообщения последнего отправленного залпа
				vector <dispatch_t> _flight;
				// Куски залпа, ушедшие записями
				vector <piece_t> _pieces;
				// Порядковый номер очередного отправляемого сообщения рукопожатия
				uint16_t _outgoing;
				// Порядковый номер очередного ожидаемого сообщения рукопожатия
				uint16_t _incoming;
				// Сборки принимаемых сообщений рукопожатия
				vector <assembly_t> _assemblies;
				// Номера принятых записей рукопожатия, ждущих подтверждения
				vector <datagram::number_t> _acknowledgeable;
				// Собираемая дейтаграмма
				vector <uint8_t> _packet;
				// Пора ключей записей собираемой дейтаграммы
				uint16_t _bundle;
				// Готовые к отправке дейтаграммы
				vector <vector <uint8_t>> _datagrams;
				// Записи следующей поры, отложенные до прихода её ключей
				vector <vector <uint8_t>> _deferred;
				// Число записей и дейтаграмм, молча отброшенных связью
				uint64_t _discarded;
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
				 * @brief Метод затирания ключевого материала связи
				 *
				 * @note Зовётся при обрыве связи: ключи оборванной связи ни к чему, и
				 *       держать их в памяти до сброса состояния незачем
				 *
				 */
				void shred() noexcept;
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
				 * @brief Метод получения уровня защиты, на котором идут сообщения стороны
				 *
				 * @param side сторона связи, уровень которой запрашивается
				 *
				 * @return     уровень защиты сообщений стороны по поре её ключей
				 *
				 */
				context::level_t layer(const session::side_t side) const noexcept;
				/**
				 * @brief Метод сохранения значений направлений уровня защиты для выдачи наружу
				 *
				 * @param level уровень защиты, значения которого сохраняются
				 *
				 * @return      отказ сохранения значений направлений
				 *
				 */
				context::error_t store(const context::level_t level) noexcept;
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
				 * @param group группа обмена, выбранная собеседником
				 * @param key   открытый мимолётный ключ собеседника в записи протокола
				 *
				 * @return      отказ вывода ключей рукопожатия
				 *
				 */
				context::error_t derive(const extension::group_t group, const view_t & key) noexcept;
				/**
				 * @brief Метод выбора хеша переписки и расписания по набору шифрования
				 *
				 * @return отказ выбора хеша
				 *
				 */
				context::error_t hashing() noexcept;
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
				 * @param group группа обмена, для которой вырабатывается пара ключей
				 *
				 * @return      отказ выработки мимолётной пары ключей
				 *
				 * @note Пара добавляется к прежним: клиент шлёт доли по нескольким группам
				 * @note У группы, связи неведомой, доля шлётся произвольной (RFC 8701)
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
				 * @param proposed   перечень наборов шифрования, предложенных клиентом
				 * @param message    принятое приветствие клиента вместе с обвязкой
				 *
				 * @return           отказ разбора предложения заранее разделённых ключей
				 *
				 */
				context::error_t offered(const vector <hello::extension_t> & extensions, const vector <uint16_t> & proposed, const view_t & message) noexcept;
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
				 * @brief Метод разбора принятого запроса подлинности клиента
				 *
				 * @param body тело принятого сообщения запроса подлинности
				 *
				 * @return     отказ разбора запроса подлинности
				 *
				 */
				context::error_t requesting(const view_t & body) noexcept;
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
				 * @brief Метод распаковки принятой сжатой цепочки сертификатов собеседника
				 *
				 * @param body   тело принятого сообщения сжатой цепочки сертификатов
				 * @param result накопитель, в который помещается тело цепочки после распаковки
				 *
				 * @return       отказ распаковки цепочки сертификатов
				 *
				 * @details Раздел 4 RFC 8879: алгоритм обязан быть из объявленных связью
				 *          (иначе COMPRESSION), длина после распаковки обязана сойтись с
				 *          объявленной и не выйти за предел (иначе CERTIFICATE)
				 *
				 */
				context::error_t unpack(const view_t & body, vector <uint8_t> & result) noexcept;
				/**
				 * @brief Метод разбора принятого ответа о состоянии сертификата собеседника
				 *
				 * @param data тело расширения записи цепочки с ответом о состоянии
				 *
				 * @return     отказ разбора либо проверки ответа о состоянии
				 *
				 * @details Раздел 8 RFC 6066: CertificateStatus несёт вид состояния (лишь
				 *          ocsp) и запись ответа по RFC 6960 с трёхбайтовой длиной; при
				 *          включённой проверке ответ сличается с сертификатом собеседника
				 *          и его издателем, а отозванный сертификат обрывает связь
				 *
				 */
				context::error_t stapled(const view_t & data) noexcept;
				/**
				 * @brief Метод разбора принятого запроса состояния сертификата
				 *
				 * @param data тело расширения запроса состояния сертификата
				 *
				 * @return     отказ разбора запроса состояния
				 *
				 * @details Раздел 8 RFC 6066: CertificateStatusRequest несёт вид состояния,
				 *          перечень ответчиков и расширения запроса; запрошенным считается
				 *          лишь вид ocsp, прочие виды пропускаются молча
				 *
				 */
				context::error_t inquiry(const view_t & data) noexcept;
				/**
				 * @brief Метод сжатия отправляемой цепочки сертификатов своей стороны
				 *
				 * @param body      тело сообщения цепочки сертификатов
				 * @param result    накопитель, в который помещается тело сжатого сообщения
				 * @param algorithm место, в которое помещается выбранный алгоритм, ноль без сжатия
				 *
				 * @return          отказ сжатия цепочки сертификатов
				 *
				 * @details Раздел 3 RFC 8879: алгоритм берётся первым общим по порядку
				 *          объявившей стороны; отказ сжатия у потребителя шлёт цепочку
				 *          несжатой, и отказом связи он не считается
				 *
				 */
				context::error_t squeeze(const vector <uint8_t> & body, vector <uint8_t> & result, uint16_t & algorithm) noexcept;
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
				 * @brief Метод смены ключей своего направления по счётчику записей
				 *
				 * @return отказ смены ключевого материала своего направления
				 *
				 */
				context::error_t refreshing() noexcept;
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
			private:
				/**
				 * @brief Метод получения издания протокола, согласуемого связью
				 *
				 * @return 0x0304 у TLS 1.3 и 0xFEFC у DTLS 1.3
				 *
				 */
				uint16_t edition() const noexcept;
				/**
				 * @brief Метод заведения поры ключей направления связи поверх дейтаграмм
				 *
				 * @param side  сторона связи, чьё направление заводится
				 * @param level уровень защиты, ключи которого кладутся в пору
				 *
				 * @return      отказ заведения поры ключей
				 *
				 * @details Раздел 4.2.1 RFC 9147: ключи рукопожатия открывают вторую пору,
				 *          прикладные - третью, всякая смена ключей - следующую; прежняя
				 *          пора чтения держится ради запоздалых записей
				 *
				 */
				context::error_t adopt(const session::side_t side, const context::level_t level) noexcept;
				/**
				 * @brief Метод составления записи поверх дейтаграммы
				 *
				 * @param type   вид содержимого записи
				 * @param data   содержимое записи
				 * @param era    пора ключей, которой запись защищается
				 * @param result накопитель, в конец которого дописывается запись
				 *
				 * @return       отказ составления записи
				 *
				 */
				context::error_t shield(const record::type_t type, const view_t & data, era_t & era, vector <uint8_t> & result) noexcept;
				/**
				 * @brief Метод получения поры ключей записи по её номеру
				 *
				 * @param direction место направления: ноль у записи, единица у чтения
				 * @param epoch     номер поры ключей
				 *
				 * @return          пора ключей либо nullptr, если пора связью не держится
				 *
				 */
				era_t * era(const size_t direction, const uint16_t epoch) noexcept;
				/**
				 * @brief Метод получения текущей поры ключей направления
				 *
				 * @param direction место направления: ноль у записи, единица у чтения
				 *
				 * @return          текущая защищённая пора либо нулевая, пока защищённой нет
				 *
				 */
				era_t & current(const size_t direction) noexcept;
				/**
				 * @brief Метод закрытия собираемой дейтаграммы
				 *
				 * @return отказ закрытия дейтаграммы
				 *
				 */
				context::error_t settle() noexcept;
				/**
				 * @brief Метод нарезки области сообщения залпа на записи дейтаграмм
				 *
				 * @param index  место сообщения в залпе
				 * @param offset смещение области в теле сообщения
				 * @param length длина области в байтах
				 *
				 * @return       отказ нарезки области сообщения
				 *
				 */
				context::error_t carve(const size_t index, const size_t offset, const size_t length) noexcept;
				/**
				 * @brief Метод раскладки залпа и подтверждения по дейтаграммам
				 *
				 * @param resend признак повторной передачи неподтверждённых кусков
				 *
				 * @return       отказ раскладки залпа
				 *
				 */
				context::error_t dispatch(const bool resend) noexcept;
				/**
				 * @brief Метод разбора принятой дейтаграммы
				 *
				 * @param data принятая дейтаграмма
				 *
				 * @return     отказ разбора дейтаграммы
				 *
				 */
				context::error_t receive(const view_t & data) noexcept;
				/**
				 * @brief Метод разбора кусков сообщений рукопожатия из принятой записи
				 *
				 * @param content открытое содержимое записи рукопожатия
				 * @param epoch   пора ключей принятой записи
				 *
				 * @return        отказ разбора кусков сообщений
				 *
				 */
				context::error_t fragments(const view_t & content, const uint16_t epoch) noexcept;
				/**
				 * @brief Метод выдачи собранных сообщений рукопожатия разбору по порядку
				 *
				 * @return отказ разбора выданных сообщений
				 *
				 */
				context::error_t deliver() noexcept;
				/**
				 * @brief Метод разбора принятого подтверждения записей
				 *
				 * @param body тело принятого сообщения подтверждения
				 *
				 * @return     отказ разбора подтверждения
				 *
				 */
				context::error_t acknowledged(const view_t & body) noexcept;
				/**
				 * @brief Метод составления метки возврата состояния сервера
				 *
				 * @param message принятое приветствие клиента вместе с обвязкой
				 * @param result  накопитель, в который складывается метка
				 *
				 * @return        отказ составления метки
				 *
				 * @details Раздел 5.1 RFC 9147: метка несёт поколение секрета, хеш приветствия
				 *          и имитовставку по секрету поколения над ними и адресом собеседника
				 *
				 */
				context::error_t stamp(const view_t & message, vector <uint8_t> & result) noexcept;
				/**
				 * @brief Метод проверки метки возврата состояния сервера
				 *
				 * @param label проверяемая метка, повторённая клиентом
				 *
				 * @return      признак того, что метка сложена сервером для этого собеседника
				 *
				 */
				bool verify(const view_t & label) const noexcept;
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
				/**
				 * @brief Метод получения алгоритма сжатия цепочки сертификатов направления
				 *
				 * @param direction направление связи относительно своей стороны
				 *
				 * @return          опознаватель алгоритма по RFC 8879, ноль у несжатой цепочки
				 *
				 */
				uint16_t compression(const context::direction_t direction) const noexcept;
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
				 * @brief Метод установки групп обмена, по которым приветствием шлются доли ключа
				 *
				 * @param shares устанавливаемые группы долей ключа
				 *
				 */
				void shares(const vector <extension::group_t> & shares) noexcept;
				/**
				 * @brief Метод установки признаваемых схем подписи
				 *
				 * @param schemes устанавливаемые схемы подписи
				 *
				 */
				void schemes(const vector <extension::scheme_t> & schemes) noexcept;
				/**
				 * @brief Метод установки алгоритмов сжатия цепочки сертификатов
				 *
				 * @param codecs    устанавливаемые алгоритмы в порядке предпочтения
				 * @param inflation предел длины цепочки после распаковки, ноль оставляет умолчание
				 *
				 * @note Пустой перечень выключает сжатие: расширение не объявляется вовсе
				 *
				 */
				void codecs(const vector <context::codec_t> & codecs, const size_t inflation) noexcept;
				/**
				 * @brief Метод установки запроса состояния сертификата собеседника
				 *
				 * @param inquire запрашивается ли состояние сертификата собеседника
				 *
				 */
				void inquire(const bool inquire) noexcept;
				/**
				 * @brief Метод установки ответа о состоянии своего сертификата
				 *
				 * @param response запись ответа OCSP, пустая снимает ответ
				 * @param index    место сертификата в своей цепочке
				 *
				 */
				void staple(const vector <uint8_t> & response, const size_t index) noexcept;
				/**
				 * @brief Метод получения ответа о состоянии сертификата собеседника
				 *
				 * @return запись принятого ответа OCSP либо пустой накопитель
				 *
				 */
				const vector <uint8_t> & status() const noexcept;
				/**
				 * @brief Метод установки проверки принятого ответа о состоянии
				 *
				 * @param verify проверяется ли принятый ответ
				 * @param leeway дозволенный люфт сроков ответа в секундах
				 * @param store  запас доверенных сертификатов для розыска издателя
				 *
				 */
				void verification(const bool verify, const int64_t leeway, const trust::store_t & store) noexcept;
				/**
				 * @brief Метод получения состояния сертификата собеседника
				 *
				 * @return состояние по проверенному ответу либо NONE
				 *
				 */
				ocsp::status_t certified() const noexcept;
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
				 * @brief Метод установки метки возврата состояния сервера
				 *
				 * @param cookie устанавливаемая метка возврата состояния
				 *
				 */
				void cookie(const vector <uint8_t> & cookie) noexcept;
				/**
				 * @brief Метод получения метки возврата состояния сервера
				 *
				 * @return метка возврата состояния, принятая от собеседника
				 *
				 */
				const vector <uint8_t> & cookie() const noexcept;
				/**
				 * @brief Метод установки мига, которым судятся сроки билетов
				 *
				 * @param moment устанавливаемый миг в секундах
				 *
				 */
				void moment(const int64_t moment) noexcept;
				/**
				 * @brief Метод установки срока жизни выдаваемых билетов
				 *
				 * @param lifetime устанавливаемый срок в секундах
				 *
				 */
				void lifetime(const uint32_t lifetime) noexcept;
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
				void advance(const bool advance, const uint32_t limit) noexcept;
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
				/**
				 * @brief Метод установки порядка смены ключей по счётчику записей
				 *
				 * @param automatic сменяет ли движок ключи сам по счётчику записей
				 * @param records   число записей направления, по которому идёт смена
				 *
				 */
				void renewal(const bool automatic, const uint64_t records) noexcept;
				/**
				 * @brief Метод получения счётчика записей направления связи
				 *
				 * @param incoming запрашивается ли направление собеседника
				 *
				 * @return         число записей направления на текущих ключах
				 *
				 */
				uint64_t sequence(const bool incoming) const noexcept;
			public:
				/**
				 * @brief Метод установки способа переноса рукопожатия
				 *
				 * @param transport устанавливаемый способ переноса
				 *
				 */
				void transport(const context::transport_t transport) noexcept;
				/**
				 * @brief Метод получения способа переноса рукопожатия
				 *
				 * @return способ переноса рукопожатия связи
				 *
				 */
				context::transport_t transport() const noexcept;
				/**
				 * @brief Метод установки своих параметров переноса QUIC
				 *
				 * @param parameters устанавливаемые параметры переноса
				 *
				 */
				void parameters(const vector <uint8_t> & parameters) noexcept;
				/**
				 * @brief Метод получения параметров переноса QUIC собеседника
				 *
				 * @return параметры переноса, принятые от собеседника
				 *
				 */
				const vector <uint8_t> & parameters() const noexcept;
				/**
				 * @brief Метод проверки приёма параметров переноса собеседника
				 *
				 * @return признак того, что параметры переноса собеседника приняты
				 *
				 */
				bool acquired() const noexcept;
				/**
				 * @brief Метод подачи связи сообщений рукопожатия уровня защиты
				 *
				 * @param level уровень защиты, на котором сообщения приняты
				 * @param data  принятые сообщения рукопожатия без обвязки записей
				 *
				 * @return      отказ разбора принятых сообщений
				 *
				 */
				context::error_t push(const context::level_t level, const view_t & data) noexcept;
				/**
				 * @brief Метод получения сообщений рукопожатия, отправляемых на уровне защиты
				 *
				 * @param level уровень защиты, сообщения которого запрашиваются
				 *
				 * @return      накопленные сообщения рукопожатия уровня
				 *
				 */
				view_t output(const context::level_t level) const noexcept;
				/**
				 * @brief Метод снятия отправленных сообщений с накопителя уровня защиты
				 *
				 * @param level уровень защиты, с накопителя которого снимаются сообщения
				 * @param size  размер снимаемых байтов
				 *
				 */
				void consume(const context::level_t level, const size_t size) noexcept;
				/**
				 * @brief Метод получения значения направления связи уровня защиты
				 *
				 * @param level     уровень защиты, значение которого запрашивается
				 * @param direction направление связи относительно своей стороны
				 * @param result    место, в которое помещается значение направления
				 * @param size      место, в которое помещается длина значения по хешу набора
				 *
				 * @return          признак того, что значение уровня уже выведено
				 *
				 */
				bool secret(const context::level_t level, const context::direction_t direction, uint8_t * result, size_t & size) const noexcept;
				/**
				 * @brief Метод получения уровня защиты, ключи которого готовы направлению
				 *
				 * @param direction направление связи относительно своей стороны
				 *
				 * @return          наивысший уровень защиты, ключи которого у направления есть
				 *
				 */
				context::level_t level(const context::direction_t direction) const noexcept;
				/**
				 * @brief Метод проверки хода упреждающих данных прямо сейчас
				 *
				 * @return признак того, что упреждающие данные идут прямо сейчас
				 *
				 */
				bool earlying() const noexcept;
				/**
				 * @brief Метод проверки отказа сервера от предложенных упреждающих данных
				 *
				 * @return признак того, что упреждение предлагалось и сервером отвергнуто
				 *
				 */
				bool rejected() const noexcept;
			public:
				/**
				 * @brief Метод установки размера дейтаграммы связи
				 *
				 * @param mtu устанавливаемый размер дейтаграммы в байтах
				 *
				 * @note Размер меньше наименьшего дозволенного поднимается до него
				 *
				 */
				void mtu(const size_t mtu) noexcept;
				/**
				 * @brief Метод получения размера дейтаграммы связи
				 *
				 * @return размер дейтаграммы в байтах
				 *
				 */
				size_t mtu() const noexcept;
				/**
				 * @brief Метод получения срока ожидания повторной передачи
				 *
				 * @return срок в миллисекундах, ноль, когда ждать нечего
				 *
				 */
				uint32_t timeout() const noexcept;
				/**
				 * @brief Метод извещения связи об истечении срока ожидания
				 *
				 * @return отказ повторной передачи: TIMEOUT по исчерпании попыток
				 *
				 */
				context::error_t elapsed() noexcept;
				/**
				 * @brief Метод получения числа молча отброшенных записей и дейтаграмм
				 *
				 * @return число отброшенных записей и дейтаграмм
				 *
				 */
				uint64_t discarded() const noexcept;
				/**
				 * @brief Метод установки адреса собеседника для метки возврата состояния
				 *
				 * @param address адрес либо иной опознаватель собеседника
				 *
				 */
				void address(const view_t & address) noexcept;
				/**
				 * @brief Метод установки секрета метки возврата состояния
				 *
				 * @param secret устанавливаемый секрет
				 *
				 */
				void stamp(const vector <uint8_t> & secret) noexcept;
				/**
				 * @brief Метод смены поколения секрета метки возврата состояния
				 *
				 * @note Прежнее поколение остаётся живым до следующей смены
				 *
				 */
				void restamp() noexcept;
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

#endif // __ANTS_ENGINE__
