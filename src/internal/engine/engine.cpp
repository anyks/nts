/**
 * @file engine.cpp
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
 * @brief Исходный файл внутреннего модуля ведения связи протокола TLS 1.3
 *
 * @section Намеренные решения
 *
 * 1. Обе роли ведёт один модуль. Клиент и сервер проходят одно и то же рукопожатие с
 *    разных его концов, и почти всё у них общее: расписание ключей, защита записей,
 *    переписка и проверки. Две отдельные связи пришлось бы держать согласованными вручную.
 *
 * 2. Пора ключей записи берётся до объявления сообщения ходу рукопожатия. Приветствие
 *    сервера уходит открытым, а защита появляется лишь за ним: объяви сообщение раньше -
 *    и приветствие ушло бы ключами, которых у встречной стороны ещё нет.
 *
 * 3. Цепочка сертификатов собеседника не проверяется на доверие. Связь сличает подпись
 *    владения ключом с ключом предъявленного сертификата - этим рукопожатие и привязано к
 *    той стороне, - а вот доверие к издателю решается запасом доверенных сертификатов,
 *    которого у связи нет и который принадлежит тому, кто связь ведёт.
 *
 * 4. Ключи завершения рукопожатия снимаются сразу за выводом ступени рукопожатия.
 *    Переход к ступени прикладных данных значения направлений связи переписывает, а
 *    завершение клиента идёт уже после этого перехода.
 *
 * 5. Отказ связи необратим. Всякий отказ рукопожатия смертелен по разделу 6.2 RFC 8446, и
 *    единственное, что после него делают, - отправляют извещение и рвут связь.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/gost.hpp>
#include <x509/x509.hpp>
#include <field/field.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>
#include <x509/signature.hpp>
#include <digest/streebog.hpp>
#include <agreement/ecdhe.hpp>
#include <internal/engine/engine.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Случайное значение приветствия сервера, объявляющее просьбу о повторе
	 */
	/**
	 * Заслоны понижения издания протокола
	 *
	 * @details Раздел 4.1.3 RFC 8446: сервер, знающий издание 1.3, но выбравший
	 *          издание пониже, кладёт эти восемь байтов в хвост своего случайного
	 *          значения - и клиент, знающий издание 1.3, обязан на них оборваться
	 *
	 */
	static const uint8_t DOWNGRADE[2][8] = {
		{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01},
		{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00}
	};

	static const uint8_t RETRY[32] = {
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
	};

	/**
	 * Схемы подписи, предлагаемые связью по умолчанию
	 */
	static const extension::scheme_t SCHEMES[] = {
		extension::scheme_t::S256A, extension::scheme_t::S256B,
		extension::scheme_t::S256C, extension::scheme_t::S256D,
		extension::scheme_t::S512A, extension::scheme_t::S512B,
		extension::scheme_t::S512C
	};

	/**
	 * Место расширения: приветствие сервера
	 */
	static constexpr uint8_t PLACE_HELLO = 0x01;
	/**
	 * Место расширения: просьба о повторе приветствия клиента
	 */
	static constexpr uint8_t PLACE_RETRY = 0x02;
	/**
	 * Место расширения: защищённые расширения сервера
	 */
	static constexpr uint8_t PLACE_GUARDED = 0x04;
	/**
	 * Место расширения: запрос подлинности клиента
	 */
	static constexpr uint8_t PLACE_REQUEST = 0x08;
	/**
	 * Место расширения: билет возобновления связи
	 */
	static constexpr uint8_t PLACE_TICKET = 0x10;

	/**
	 * @brief Описание мест, в которых расширению идти дозволено
	 *
	 */
	typedef struct Placement {
		// Вид расширения приветствия
		uint16_t type;
		// Места, в которых расширению идти дозволено
		uint8_t places;
	} placement_t;

	/**
	 * Места расширений, признаваемых движком, среди сообщений сервера
	 *
	 * @details Раздел 4.2 RFC 8446 отводит всякому расширению свой перечень сообщений,
	 *          и расширение, признаваемое стороной, но пришедшее не в своём сообщении,
	 *          обрывает связь извещением «illegal_parameter». Здесь перечислены места
	 *          среди сообщений, которые разбирает клиент; приветствие клиента не
	 *          значится вовсе, ибо оттуда расширения и берут своё начало
	 *
	 */
	static const placement_t PLACEMENTS[] = {
		{static_cast <uint16_t> (extension::type_t::NAME),      PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::GROUPS),    PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::SCHEMES),   PLACE_REQUEST},
		{static_cast <uint16_t> (extension::type_t::PROTOCOLS), PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::SECRET),    PLACE_HELLO},
		{static_cast <uint16_t> (extension::type_t::EARLY),     (PLACE_GUARDED | PLACE_TICKET)},
		{static_cast <uint16_t> (extension::type_t::COOKIE),    PLACE_RETRY},
		{static_cast <uint16_t> (extension::type_t::VERSIONS),  (PLACE_HELLO | PLACE_RETRY)},
		{static_cast <uint16_t> (extension::type_t::MODES),     0},
		{static_cast <uint16_t> (extension::type_t::SHARE),     (PLACE_HELLO | PLACE_RETRY)}
	};

	/**
	 * @brief Метод получения мест, в которых расширению идти дозволено
	 *
	 * @param type   вид расширения, места которого запрашиваются
	 * @param result место, в которое помещается набор дозволенных мест
	 *
	 * @return       признак того, что вид расширения движку известен
	 *
	 */
	static bool placement(const uint16_t type, uint8_t & places) noexcept {
		/**
		 * Выполняем перебор описаний мест признаваемых расширений
		 */
		for(size_t i = 0; i < (sizeof(PLACEMENTS) / sizeof(placement_t)); i++){
			// Если описание мест разыскиваемого расширения найдено
			if(PLACEMENTS[i].type == type){
				// Запоминаем набор дозволенных мест расширения
				places = PLACEMENTS[i].places;
				// Выводим признак того, что вид расширения известен
				return true;
			}
		}
		// Выводим признак того, что вид расширения движку неизвестен
		return false;
	}
	/**
	 * @brief Метод затирания области памяти
	 *
	 * @param data затираемая область памяти
	 * @param size размер затираемой области памяти
	 *
	 */
	static void wipe(void * data, const size_t size) noexcept {
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
		/**
		 * Выполняем перебор байтов затираемой области памяти
		 */
		for(size_t i = 0; i < size; i++)
			// Обнуляем очередной байт области памяти
			item[i] = 0;
	}
	/**
	 * @brief Метод получения места стороны связи в наборах связи
	 *
	 * @param side сторона связи, место которой запрашивается
	 *
	 * @return     место стороны связи в наборах связи
	 *
	 */
	static size_t index(const session::side_t side) noexcept {
		// Выводим место стороны связи в наборах связи
		return ((side == session::side_t::CLIENT) ? 0 : 1);
	}
	/**
	 * @brief Метод составления записи перечня расширений
	 *
	 * @param extensions составляемый перечень расширений
	 * @param result     накопитель, в который складывается запись перечня
	 *
	 * @return           признак успешности составления записи перечня
	 *
	 */
	static bool block(const vector <hello::extension_t> & extensions, vector <uint8_t> & result) noexcept {
		// Объект составителя записи перечня расширений
		field::builder_t builder;
		// Если место под длину перечня расширений занять не удалось
		if(builder.open(2) != field::error_t::NONE)
			// Выводим отказ составления записи перечня
			return false;
		/**
		 * Выполняем перебор составляемых расширений перечня
		 */
		for(size_t i = 0; i < extensions.size(); i++){
			// Если вид расширения записать не удалось
			if(builder.number(extensions[i].type, 2) != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
			// Если место под длину тела расширения занять не удалось
			if(builder.open(2) != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
			// Если тело расширения записать не удалось
			if(builder.bytes(extensions[i].data) != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
			// Если длину тела расширения проставить не удалось
			if(builder.close() != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
		}
		// Если длину перечня расширений проставить не удалось
		if(builder.close() != field::error_t::NONE)
			// Выводим отказ составления записи перечня
			return false;
		// Получаем составленную запись перечня расширений
		const view_t data = builder.data();
		// Выполняем перенос составленной записи перечня в накопитель
		result.assign(data.data, data.data + data.size);
		// Выводим успешность составления записи перечня расширений
		return true;
	}
	/**
	 * Окно расхождения объявленного возраста билета с наблюдаемым в миллисекундах
	 *
	 * @details Раздел 4.2.10 RFC 8446 велит сличать объявленный клиентом возраст билета
	 *          с наблюдаемым и отвергать упреждающие данные при расхождении: сеть даёт
	 *          задержку, оттого сличение и ведётся окном, а не точным равенством
	 *
	 */
	static constexpr int64_t WINDOW = 10000;
	/**
	 * @brief Предел срока жизни билета возобновления связи в секундах
	 *
	 * @note Раздел 4.6.1 RFC 8446 кладёт сроку билета семь суток
	 *
	 */
	static constexpr uint32_t LIFETIME = 604800;

	/**
	 * @brief Метод проверки того, что срок билета возобновления связи вышел
	 *
	 * @param ticket проверяемый билет возобновления связи
	 * @param moment миг, которым судится срок билета
	 *
	 * @return       признак того, что срок билета вышел
	 *
	 * @note Часов связь не читает: миг подаётся ей настройкой. Не заданный миг судить
	 *       сроки не позволяет вовсе, и билет тогда идёт в дело как есть
	 *
	 */
	static bool expired(const context::ticket_t & ticket, const int64_t moment) noexcept {
		// Если миг суждения либо миг выдачи билета не задан
		if((moment == 0) || (ticket.moment == 0))
			// Выводим признак того, что срок билета не вышел
			return false;
		// Выводим признак того, что срок билета вышел
		return ((moment < ticket.moment) || ((moment - ticket.moment) > static_cast <int64_t> (ticket.lifetime)));
	}
	/**
	 * @brief Метод извлечения тела расширения из записи перечня расширений
	 *
	 * @param data   разбираемая запись перечня расширений
	 * @param type   разыскиваемый вид расширения
	 * @param result просмотр, в который помещается тело найденного расширения
	 *
	 * @return       признак того, что расширение в перечне объявлено
	 *
	 */
	static bool announced(const view_t & data, const uint16_t type, view_t & result) noexcept {
		// Объект разборщика записи перечня расширений
		field::scanner_t scanner;
		// Устанавливаем разбираемую запись перечня расширений
		scanner.start(data);
		// Содержимое перечня расширений
		view_t body;
		// Если перечень расширений прочитать не удалось
		if(scanner.vector(body, 2) != field::error_t::NONE)
			// Выводим признак того, что расширение не объявлено
			return false;
		// Объект разборщика записей перечня расширений
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня расширений
		reader.start(body);
		/**
		 * Выполняем перебор объявленных расширений перечня
		 */
		while(reader.left() > 0){
			// Вид очередного расширения перечня
			uint32_t item = 0;
			// Если вид расширения прочитать не удалось
			if(reader.number(item, 2) != field::error_t::NONE)
				// Выводим признак того, что расширение не объявлено
				return false;
			// Тело очередного расширения перечня
			view_t content;
			// Если тело расширения прочитать не удалось
			if(reader.vector(content, 2) != field::error_t::NONE)
				// Выводим признак того, что расширение не объявлено
				return false;
			// Если вид расширения совпал с разыскиваемым
			if(static_cast <uint16_t> (item) == type){
				// Устанавливаем тело найденного расширения
				result = content;
				// Выводим признак того, что расширение объявлено
				return true;
			}
		}
		// Выводим признак того, что расширение не объявлено
		return false;
	}
	/**
	 * @brief Метод разыскания расширения в записи перечня расширений
	 *
	 * @param data разбираемая запись перечня расширений
	 * @param type разыскиваемый вид расширения
	 *
	 * @return     признак того, что расширение в перечне объявлено
	 *
	 */
	static bool declared(const view_t & data, const uint16_t type) noexcept {
		// Тело разыскиваемого расширения перечня
		view_t content;
		// Выводим признак того, что расширение в перечне объявлено
		return announced(data, type, content);
	}
	/**
	 * @brief Метод перечисления видов расширений записи перечня расширений
	 *
	 * @param data   разбираемая запись перечня расширений
	 * @param result перечень, в который помещаются виды объявленных расширений
	 *
	 * @return       признак успешности разбора перечня расширений
	 *
	 * @note Тела расширений здесь не читаются: перечисляются лишь их виды
	 *
	 */
	static bool enumerate(const view_t & data, vector <uint16_t> & result) noexcept {
		// Объект разборщика записи перечня расширений
		field::scanner_t scanner;
		// Устанавливаем разбираемую запись перечня расширений
		scanner.start(data);
		// Содержимое перечня расширений
		view_t body;
		// Если перечень расширений прочитать не удалось
		if(scanner.vector(body, 2) != field::error_t::NONE)
			// Выводим признак неуспешности разбора перечня расширений
			return false;
		// Объект разборщика записей перечня расширений
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня расширений
		reader.start(body);
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			/**
			 * Выполняем перебор объявленных расширений перечня
			 */
			while(reader.left() > 0){
				// Вид очередного расширения перечня
				uint32_t item = 0;
				// Если вид расширения прочитать не удалось
				if(reader.number(item, 2) != field::error_t::NONE)
					// Выводим признак неуспешности разбора перечня расширений
					return false;
				// Тело очередного расширения перечня
				view_t content;
				// Если тело расширения прочитать не удалось
				if(reader.vector(content, 2) != field::error_t::NONE)
					// Выводим признак неуспешности разбора перечня расширений
					return false;
				// Добавляем вид расширения в перечень объявленных
				result.push_back(static_cast <uint16_t> (item));
			}
		/**
		 * Если памяти под перечень видов расширений не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим признак неуспешности разбора перечня расширений
			return false;
		}
		// Выводим признак успешности разбора перечня расширений
		return true;
	}
	/**
	 * @brief Метод поиска схемы подписи по опознавателю набора параметров кривой
	 *
	 * @param oid    опознаватель набора параметров кривой открытого ключа
	 * @param result схема подписи, в которую помещается итог поиска
	 *
	 * @return       признак того, что схема подписи для кривой найдена
	 *
	 */
	static bool scheme(const string & oid, extension::scheme_t & result) noexcept {
		/**
		 * Выполняем перебор известных схем подписи
		 */
		for(size_t i = 0; i < (sizeof(SCHEMES) / sizeof(extension::scheme_t)); i++){
			// Получаем опознаватель кривой очередной схемы подписи
			const char * item = extension::curve(SCHEMES[i]);
			/**
			 * Слагаемое (item != nullptr) ложно всегда: опознаватель кривой отсутствует
			 * лишь у схемы, описания которой нет вовсе, а перебор идёт по SCHEMES, и
			 * описана там всякая. Слагаемое оставлено ради самостоятельности розыска:
			 * пополнись перечень схемой без кривой - сличение пошло бы по nullptr
			 */
			// Если опознаватель кривой схемы совпал с искомым
			if((item != nullptr) && (oid.compare(item) == 0)){
				// Запоминаем найденную схему подписи
				result = SCHEMES[i];
				// Выводим признак того, что схема подписи найдена
				return true;
			}
		}
		// Выводим признак того, что схема подписи не найдена
		/**
		 * Заслон этот в тени: опознаватель ключа, схемам не отвечающий, отвергает ещё
		 * извлечение опознавателя из листа, и сюда неведомый не доходит. Стоит он ради
		 * связности поиска: неведомая схема без отказа была бы хуже
		 */
		return false;
	}
};

/**
 * @brief Метод обрыва связи отказом
 *
 * @param error       отказ, которым связь обрывается
 * @param description описание извещения, отправляемого собеседнику
 *
 * @return            отказ, которым связь оборвана
 *
 */
context::error_t nts::internal::Engine::abort(const context::error_t error, const alert::description_t description) noexcept {
	// Составляем извещение об обрыве связи
	const alert::alert_t alert(alert::level_t::FATAL, description);
	// Место, в которое записывается извещение об обрыве связи
	uint8_t buffer[alert::ALERT_LENGTH];
	// Если извещение об обрыве связи записать удалось
	if(alert::build(alert, buffer) == alert::error_t::NONE)
		// Выполняем складывание извещения в накопитель отправляемых байтов
		this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
	// Запоминаем извещение, которым связь оборвана
	this->_alert = alert;
	// Запоминаем отказ, которым связь оборвана
	this->_error = error;
	// Переводим связь в состояние обрыва
	this->_state = context::state_t::FAILED;
	// Выводим отказ, которым связь оборвана
	return error;
}
/**
 * @brief Метод складывания записи в накопитель отправляемых байтов
 *
 * @param type вид содержимого отправляемой записи
 * @param data содержимое отправляемой записи
 *
 * @return     отказ складывания записи в накопитель
 *
 */
context::error_t nts::internal::Engine::emit(const record::type_t type, const view_t & data) noexcept {
	// Получаем сторону связи, отправляющую запись
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	/**
	 * Выполняем складывание записи в накопитель
	 */
	try {
		/**
		 * Записи упреждающих данных защищаются своими ключами: сервер о них ещё
		 * ничего не ответил, и ключей рукопожатия у клиента на этот миг нет вовсе
		 */
		if(!this->_server && this->_earlying){
			// Накопитель, в который складывается защищённая запись
			vector <uint8_t> sealed;
			// Если наложить защиту упреждающих данных на запись не удалось
			if(this->_early.seal(type, data, sealed) != protect::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return context::error_t::PROTECTION;
			// Выполняем складывание защищённой записи в накопитель
			this->_wire.insert(this->_wire.end(), sealed.begin(), sealed.end());
		// Если записи своей стороны защищены ключами связи
		} else if(this->_machine.epoch(side) != flow::epoch_t::PLAIN){
			// Накопитель, в который складывается защищённая запись
			vector <uint8_t> sealed;
			// Если наложить защиту на запись не удалось
			if(this->_output.seal(type, data, sealed) != protect::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return context::error_t::PROTECTION;
			// Выполняем складывание защищённой записи в накопитель
			this->_wire.insert(this->_wire.end(), sealed.begin(), sealed.end());
		// Если записи своей стороны идут без защиты
		} else {
			// Объект нарезчика отправляемых записей
			record::writer_t writer;
			// Если содержимое на записи нарезать не удалось
			if(writer.push(type, record::version_t::TLS12, data) != record::error_t::NONE)
				// Выводим отказ нарезки содержимого на записи
				return context::error_t::RECORD;
			// Получаем нарезанные записи содержимого
			const view_t records = writer.data();
			// Выполняем складывание нарезанных записей в накопитель
			this->_wire.insert(this->_wire.end(), records.data, records.data + records.size);
		}
	// Если памяти под накопитель не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность складывания записи в накопитель
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки сообщения рукопожатия собеседнику
 *
 * @param type вид отправляемого сообщения рукопожатия
 * @param body тело отправляемого сообщения рукопожатия
 *
 * @return     отказ отправки сообщения рукопожатия
 *
 */
context::error_t nts::internal::Engine::send(const handshake::type_t type, const view_t & body) noexcept {
	// Получаем сторону связи, отправляющую сообщение
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если сообщение рукопожатия составить не удалось
	if(writer.push(type, body) != handshake::error_t::NONE)
		// Выводим отказ составления сообщения рукопожатия
		return context::error_t::MESSAGE;
	// Получаем составленное сообщение рукопожатия
	const view_t message = writer.data();
	/**
	 * Запись складывается ключами той поры, которая идёт до объявления сообщения:
	 * приветствие сервера уходит открытым, а защита появляется лишь за ним
	 */
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, message);
	// Если складывание записи в накопитель не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ складывания записи в накопитель
		return error;
	// Если сообщение в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если сообщение ходу рукопожатия объявить не удалось
	if(this->_machine.accept(type, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return context::error_t::ORDER;
	// Выводим итог согласования ключевого материала защиты записей
	return this->refresh();
}
/**
 * @brief Метод согласования ключевого материала защиты записей
 *
 * @return отказ согласования ключевого материала
 *
 */
context::error_t nts::internal::Engine::refresh() noexcept {
	/**
	 * Ключевой материал прикладных данных выводится за завершением рукопожатия
	 * сервером, а пора ключей стороны переменяется самим этим завершением: до вывода
	 * ставить защите записей нечего
	 */
	if(this->_secrets.stage() != session::stage_t::APPLICATION)
		// Выводим успешность согласования ключевого материала
		return context::error_t::NONE;
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	/**
	 * Выполняем перебор сторон связи
	 */
	for(size_t i = 0; i < 2; i++){
		// Получаем очередную сторону связи
		const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
		// Получаем пору ключей записей стороны связи
		const flow::epoch_t epoch = this->_machine.epoch(side);
		// Если пора ключей стороны связи не переменилась
		if((epoch != flow::epoch_t::APPLICATION) || (this->_epoch[i] == epoch))
			// Переходим к следующей стороне связи
			continue;
		// Получаем объект защиты записей стороны связи
		protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
		// Если ключевой материал прикладных данных установить не удалось
		if(!protection.start(this->_suite, view_t(this->_key[i], protect::PROTECT_KEY), view_t(this->_vector[i], protect::block(this->_suite))))
			// Выводим отказ установки ключевого материала
			return context::error_t::SCHEDULE;
		// Запоминаем пору ключей, установленную защите записей
		this->_epoch[i] = epoch;
	}
	// Выводим успешность согласования ключевого материала
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода ключей рукопожатия связи
 *
 * @param key открытый мимолётный ключ собеседника
 *
 * @return    отказ вывода ключей рукопожатия
 *
 */
context::error_t nts::internal::Engine::derive(const view_t & key) noexcept {
	/**
	 * Место под общее значение берётся размером числа арифметики: выработка кладёт
	 * туда одну координату кривой, а шире числа координата быть не может. Постоянная
	 * эта взята вместо числа нарочно - иначе расширение арифметики оставило бы место
	 * прежним, а выработка стала бы писать за него
	 */
	uint8_t shared[math::NUMBER_SIZE];
	// Если общее значение обмена мимолётными ключами выработать не удалось
	if(!agreement::ecdhe(this->_curve, view_t(this->_secret.data(), this->_secret.size()), key, shared))
		// Выводим отказ выработки общего значения обмена
		return context::error_t::EXCHANGE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Признак успешности вывода ключей рукопожатия связи
	bool ok = (this->_transcript.digest(transcript) == session::error_t::NONE);
	/**
	 * Начальная ступень расписания ключей заводится лишь тогда, когда её ещё нет:
	 * при возобновлении связи билетом в неё уже вложен заранее разделённый ключ
	 */
	/**
	 * Слагаемое ok здесь истинно всегда: хеш переписки отказывает лишь у незаведённой
	 * переписки, а ключи рукопожатия выводятся не прежде приветствий. Слагаемое
	 * оставлено ради цепочки: заведение ступени после отказавшего хеша шло бы уже по
	 * мусору
	 */
	if(ok && (this->_secrets.stage() == session::stage_t::NONE))
		// Выполняем заведение начальной ступени расписания ключей
		ok = (this->_secrets.start(view_t(nullptr, 0)) == session::error_t::NONE);
	// Если начальная ступень расписания ключей заведена
	if(ok)
		// Выполняем вывод ступени рукопожатия расписания ключей
		ok = (this->_secrets.handshake(view_t(shared, this->_curve.size()), view_t(transcript, sizeof(transcript))) == session::error_t::NONE);
	// Выполняем затирание общего значения обмена мимолётными ключами
	wipe(shared, sizeof(shared));
	// Если ступень рукопожатия расписания ключей вывести не удалось
	if(!ok)
		// Выводим отказ вывода ключевого материала связи
		return context::error_t::SCHEDULE;
	/**
	 * Выполняем перебор сторон связи
	 */
	for(size_t i = 0; i < 2; i++){
		// Получаем очередную сторону связи
		const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
		/**
		 * Ключи завершения рукопожатия снимаются сразу: переход к ступени прикладных
		 * данных значения направлений связи переписывает
		 */
		if(this->_secrets.finished(side, this->_completion[i]) != session::error_t::NONE)
			// Выводим отказ вывода ключей завершения рукопожатия
			return context::error_t::SCHEDULE;
		// Корневой ключ направления связи
		uint8_t material[protect::PROTECT_KEY];
		// Вектор замены направления связи
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи вывести не удалось
		if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала направления
			return context::error_t::SCHEDULE;
		// Получаем сторону связи, которую ведёт модуль
		const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
		// Получаем объект защиты записей стороны связи
		protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
		// Признак успешности установки ключевого материала направления
		const bool installed = protection.start(this->_suite, view_t(material, sizeof(material)), view_t(element, protect::block(this->_suite)));
		// Выполняем затирание вектора замены направления связи
		wipe(element, sizeof(element));
		// Выполняем затирание корневого ключа направления связи
		wipe(material, sizeof(material));
		// Если ключевой материал направления связи установить не удалось
		if(!installed)
			// Выводим отказ установки ключевого материала направления
			return context::error_t::SCHEDULE;
		// Запоминаем пору ключей, установленную защите записей
		this->_epoch[i] = flow::epoch_t::HANDSHAKE;
	}
	// Выводим успешность вывода ключей рукопожатия связи
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода ключей прикладных данных связи
 *
 * @return отказ вывода ключей прикладных данных
 *
 */
context::error_t nts::internal::Engine::mature() noexcept {
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	// Если ступень прикладных данных расписания ключей вывести не удалось
	if(this->_secrets.application(view_t(transcript, sizeof(transcript))) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала связи
		return context::error_t::SCHEDULE;
	/**
	 * Выполняем перебор сторон связи
	 */
	for(size_t i = 0; i < 2; i++){
		// Получаем очередную сторону связи
		const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
		// Если ключевой материал направления связи вывести не удалось
		if(this->_secrets.material(side, this->_suite, this->_key[i], this->_vector[i]) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала направления
			return context::error_t::SCHEDULE;
	}
	// Выводим успешность вывода ключей прикладных данных связи
	return context::error_t::NONE;
}
/**
 * @brief Метод заведения защиты записей упреждающих данных
 *
 * @return отказ заведения защиты записей упреждающих данных
 *
 */
context::error_t nts::internal::Engine::earliest() noexcept {
	/**
	 * Ключи упреждающих данных выводятся набором шифрования билета, а не набором
	 * этой связи: раздел 4.2.10 RFC 8446 велит брать тот, каким билет выдан, - иного
	 * согласования на этот миг ещё и не было
	 */
	if(protect::block(this->_ticket) == 0)
		// Выводим отказ неизвестности набора шифрования билета
		return context::error_t::SUITE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	// Если значение упреждающих данных вывести не удалось
	if(this->_secrets.early(view_t(transcript, sizeof(transcript))) != session::error_t::NONE)
		// Выводим отказ вывода значения расписания ключей
		return context::error_t::SCHEDULE;
	// Значение упреждающих данных связи
	uint8_t traffic[schedule::SCHEDULE_SECRET];
	// Если значение упреждающих данных получить не удалось
	if(this->_secrets.early(traffic) != session::error_t::NONE)
		// Выводим отказ вывода значения расписания ключей
		return context::error_t::SCHEDULE;
	// Место, в которое помещается корневой ключ упреждающих данных
	uint8_t material[protect::PROTECT_KEY];
	// Место, в которое помещается вектор замены упреждающих данных
	uint8_t element[protect::PROTECT_VECTOR];
	// Признак успешности вывода ключевого материала упреждающих данных
	bool ok = (session::material(view_t(traffic, sizeof(traffic)), this->_ticket, material, element) == session::error_t::NONE);
	// Если ключевой материал упреждающих данных выведен
	if(ok)
		// Выполняем установку ключевого материала упреждающих данных
		ok = this->_early.start(this->_ticket, view_t(material, sizeof(material)), view_t(element, protect::block(this->_ticket)));
	// Выполняем затирание вектора замены упреждающих данных
	wipe(element, sizeof(element));
	// Выполняем затирание корневого ключа упреждающих данных
	wipe(material, sizeof(material));
	// Выполняем затирание значения упреждающих данных связи
	wipe(traffic, sizeof(traffic));
	// Если ключевой материал упреждающих данных установить не удалось
	if(!ok)
		// Выводим отказ установки ключевого материала
		return context::error_t::SCHEDULE;
	// Запоминаем, что упреждающие данные идут прямо сейчас
	this->_earlying = true;
	// Выводим успешность заведения защиты записей упреждающих данных
	return context::error_t::NONE;
}
/**
 * @brief Метод выработки мимолётной пары ключей своей стороны
 *
 * @param group кривая, для которой вырабатывается пара ключей
 *
 * @return      отказ выработки мимолётной пары ключей
 *
 */
context::error_t nts::internal::Engine::exchange(const extension::group_t group) noexcept {
	// Получаем опознаватель набора параметров кривой обмена ключами
	const char * oid = extension::curve(group);
	// Если кривая обмена ключами протоколом не определена
	if(oid == nullptr)
		// Выводим отказ неизвестности кривой обмена ключами
		return context::error_t::GROUP;
	// Если кривую обмена мимолётными ключами завести не удалось
	if(!curve::parameters(oid, this->_curve))
		// Выводим отказ заведения кривой обмена ключами
		return context::error_t::GROUP;
	/**
	 * Выполняем выработку мимолётной пары ключей своей стороны
	 */
	try {
		// Занимаем место под секретный мимолётный ключ своей стороны
		this->_secret.assign(this->_curve.size(), 0);
		// Занимаем место под открытый мимолётный ключ своей стороны
		this->_opened.assign(this->_curve.size() * 2, 0);
	// Если памяти под ключи не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если мимолётную пару ключей своей стороны выработать не удалось
	if(!agreement::generate(this->_curve, this->_secret.data(), this->_opened.data()))
		// Выводим отказ выработки мимолётной пары ключей
		return context::error_t::EXCHANGE;
	// Запоминаем кривую обмена мимолётными ключами связи
	this->_group = group;
	// Выводим успешность выработки мимолётной пары ключей
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки приветствия клиента
 *
 * @return отказ отправки приветствия клиента
 *
 */
context::error_t nts::internal::Engine::greeting() noexcept {
	// Составляемое приветствие клиента
	hello::client_t greeting;
	// Устанавливаем версию протокола, доставшуюся от предыдущих изданий
	greeting.version = 0x0303;
	// Переносим случайное значение своего приветствия
	::memcpy(greeting.random, this->_random, sizeof(this->_random));
	// Устанавливаем опознаватель связи, доставшийся от предыдущих изданий
	greeting.session = this->_session;
	// Устанавливаем перечень способов сжатия
	greeting.methods = {0x00};
	/**
	 * Выполняем перебор предлагаемых наборов шифрования
	 */
	for(size_t i = 0; i < this->_suites.size(); i++)
		// Добавляем очередной набор шифрования в приветствие
		greeting.suites.push_back(static_cast <uint16_t> (this->_suites[i]));
	// Накопители, в которых лежат тела расширений приветствия
	vector <uint8_t> versions, groups, schemes, shares, name, protocols;
	// Если перечень изданий протокола составить не удалось
	if(extension::versions(vector <uint16_t> {0x0304}, versions) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Если перечень кривых обмена ключами составить не удалось
	if(extension::groups(this->_groups, groups) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Перечень предлагаемых схем подписи
	vector <extension::scheme_t> list(SCHEMES, SCHEMES + (sizeof(SCHEMES) / sizeof(extension::scheme_t)));
	// Если перечень схем подписи составить не удалось
	if(extension::schemes(list, schemes) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Открытая часть ключа обмена своей стороны
	const extension::share_t share(this->_group, view_t(this->_opened.data(), this->_opened.size()));
	// Если перечень открытых частей ключей обмена составить не удалось
	if(extension::shares(vector <extension::share_t> {share}, shares) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Добавляем расширение перечня изданий протокола
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(versions.data(), versions.size())));
	// Добавляем расширение перечня кривых обмена ключами
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
	// Добавляем расширение перечня схем подписи
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
	// Добавляем расширение открытых частей ключей обмена
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(shares.data(), shares.size())));
	// Если имя узла у сервера запрашивается
	if(!this->_name.empty()){
		// Если имя запрашиваемого узла составить не удалось
		if(extension::name(view_t(reinterpret_cast <const uint8_t *> (this->_name.data()), this->_name.size()), name) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение имени запрашиваемого узла
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(name.data(), name.size())));
	}
	// Если прикладные протоколы связью предлагаются
	if(!this->_protocols.empty()){
		// Если перечень прикладных протоколов составить не удалось
		if(extension::protocols(this->_protocols, protocols) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение перечня прикладных протоколов
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocols.data(), protocols.size())));
	}
	// Если метка возврата состояния сервера связью получена
	if(!this->_cookie.empty())
		// Повторяем метку возврата состояния сервера дословно
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(this->_cookie.data(), this->_cookie.size())));
	// Накопители, в которых лежат тела расширений возобновления связи
	vector <uint8_t> modes, secret;
	// Место, в которое помещается пустая привязка предъявляемого билета
	uint8_t empty[schedule::SCHEDULE_SECRET];
	/**
	 * Билет с вышедшим сроком серверу не предъявляется вовсе: раздел 4.6.1 RFC 8446
	 * велит держать его не дольше объявленного срока, и связь идёт полным рукопожатием
	 */
	const bool resume = (!this->_resume.identity.empty() && !expired(this->_resume, this->_moment));
	// Если билет возобновления связи предъявляется серверу
	if(resume)
		// Запоминаем набор шифрования предъявляемого билета
		this->_ticket = this->_resume.suite;
	// Если билет возобновления связи предъявляется серверу
	if(resume){
		// Способы обмена, при которых билет годен связи
		const vector <extension::mode_t> list = {extension::mode_t::SHARED};
		// Если перечень способов обмена составить не удалось
		if(extension::modes(list, modes) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение способов обмена заранее разделённым ключом
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(modes.data(), modes.size())));
		// Выполняем обнуление привязки предъявляемого билета
		::memset(empty, 0, sizeof(empty));
		// Если упреждающие данные связью предлагаются и дозволены билетом
		if(this->_advance && (this->_resume.advance > 0))
			/**
			 * Расширение упреждающих данных в приветствии пусто: раздел 4.2.10 RFC 8446
			 * велит объявлять им лишь само намерение, а предел объявлен билетом
			 */
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
		/**
		 * Возраст билета объявляется скрытым: раздел 4.2.11 RFC 8446 велит складывать
		 * наблюдаемый возраст в миллисекундах с добавкой, назначенной сервером
		 */
		uint32_t age = this->_resume.age;
		// Если сроки билетов связи судить дозволено
		if((this->_moment != 0) && (this->_resume.moment != 0))
			// Складываем наблюдаемый возраст билета с добавкой сервера
			age = static_cast <uint32_t> ((static_cast <uint64_t> (this->_moment - this->_resume.moment) * 1000) + static_cast <uint64_t> (this->_resume.age));
		// Опознаватель предъявляемого билета возобновления связи
		const extension::identity_t identity(view_t(this->_resume.identity.data(), this->_resume.identity.size()), age);
		// Привязка предъявляемого билета возобновления связи
		const vector <view_t> binders = {view_t(empty, sizeof(empty))};
		// Если предложение заранее разделённых ключей составить не удалось
		if(extension::identities(vector <extension::identity_t> {identity}, binders, secret) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		/**
		 * Расширение заранее разделённых ключей идёт последним: раздел 4.2.11 RFC 8446
		 * велит ставить его в самый конец, ибо привязка покрывает всё, что идёт до неё
		 */
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(secret.data(), secret.size())));
	}
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Выполняем сброс прежнего перечня предложенных расширений
		this->_offered.clear();
		/**
		 * Выполняем перебор расширений составленного приветствия клиента
		 */
		for(size_t i = 0; i < greeting.extensions.size(); i++)
			// Запоминаем вид очередного расширения, предложенного связью
			this->_offered.push_back(greeting.extensions[i].type);
	/**
	 * Если памяти под перечень предложенных расширений не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Накопитель, в который складывается тело приветствия клиента
	vector <uint8_t> body;
	// Если тело приветствия клиента составить не удалось
	if(hello::build(greeting, body) != hello::error_t::NONE)
		// Выводим отказ составления приветствия клиента
		return context::error_t::MESSAGE;
	// Если билет возобновления связи серверу не предъявляется
	if(!resume)
		// Выводим итог отправки приветствия клиента
		return this->send(handshake::type_t::CLIENT, view_t(body.data(), body.size()));
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если приветствие клиента составить не удалось
	if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
		// Выводим отказ составления приветствия клиента
		return context::error_t::MESSAGE;
	// Получаем составленное приветствие клиента
	const view_t data = writer.data();
	// Накопитель, в котором приветствие клиента правится привязкой билета
	vector <uint8_t> message;
	/**
	 * Выполняем перенос составленного приветствия клиента
	 */
	try {
		// Выполняем перенос составленного приветствия в накопитель
		message.assign(data.data, data.data + data.size);
	// Если памяти под приветствие не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	/**
	 * Приветствие усекается перед перечнем привязок: два байта длины перечня, байт
	 * длины привязки и сама привязка себя же покрывать не вправе
	 */
	const size_t truncation = (message.size() - (sizeof(empty) + 3));
	// Если начальную ступень расписания ключей завести не удалось
	if(this->_secrets.start(view_t(this->_resume.secret.data(), this->_resume.secret.size())) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала связи
		return context::error_t::SCHEDULE;
	// Место, в которое помещается хеш усечённого приветствия клиента
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш усечённого приветствия получить не удалось
	if(this->_transcript.digest(view_t(message.data(), truncation), transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если привязку предъявляемого билета выработать не удалось
	if(this->_secrets.binder(view_t(transcript, sizeof(transcript)), message.data() + (message.size() - sizeof(empty))) != session::error_t::NONE)
		// Выводим отказ выработки привязки билета
		return context::error_t::SCHEDULE;
	// Выполняем складывание приветствия клиента в накопитель отправляемых байтов
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, view_t(message.data(), message.size()));
	// Если приветствие клиента отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки приветствия клиента
		return error;
	// Если приветствие в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(view_t(message.data(), message.size())) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если приветствие клиента ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return context::error_t::ORDER;
	// Если упреждающие данные связью не предлагаются
	if(!this->_advance)
		// Выводим успешность отправки приветствия клиента
		return context::error_t::NONE;
	// Выводим итог заведения защиты записей упреждающих данных
	return this->earliest();
}
/**
 * @brief Метод отправки приветствия сервера
 *
 * @param session опознаватель связи, повторяемый за приветствием клиента
 * @param retry   признак того, что отправляется просьба о повторе приветствия
 *
 * @return        отказ отправки приветствия сервера
 *
 */
context::error_t nts::internal::Engine::answer(const vector <uint8_t> & session, const bool retry) noexcept {
	// Составляемое приветствие сервера
	hello::server_t answer;
	// Устанавливаем версию протокола, доставшуюся от предыдущих изданий
	answer.version = 0x0303;
	/**
	 * Просьба о повторе приветствия объявляется заранее назначенным случайным
	 * значением: раздел 4.1.3 RFC 8446
	 */
	if(retry)
		// Переносим случайное значение просьбы о повторе приветствия
		::memcpy(answer.random, RETRY, sizeof(RETRY));
	// Если отправляется само приветствие сервера
	else ::memcpy(answer.random, this->_random, sizeof(this->_random));
	// Устанавливаем опознаватель связи, повторяемый за приветствием клиента
	answer.session = session;
	// Устанавливаем выбранный набор шифрования
	answer.suite = static_cast <uint16_t> (this->_suite);
	// Устанавливаем выбранный способ сжатия
	answer.method = 0x00;
	// Накопители, в которых лежат тела расширений приветствия
	vector <uint8_t> version, share;
	// Если издание протокола составить не удалось
	if(extension::version(0x0304, version) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Накопитель, в котором лежит тело расширения метки возврата состояния
	vector <uint8_t> label;
	// Если отправляется просьба о повторе приветствия
	if(retry){
		// Если выбранную кривую обмена ключами составить не удалось
		if(extension::selected(this->_group, share) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
	// Если отправляется само приветствие сервера
	} else {
		// Открытая часть ключа обмена своей стороны
		const extension::share_t item(this->_group, view_t(this->_opened.data(), this->_opened.size()));
		// Если открытую часть ключа обмена составить не удалось
		if(extension::share(item, share) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
	}
	// Добавляем расширение издания протокола
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
	// Добавляем расширение открытой части ключа обмена
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(share.data(), share.size())));
	/**
	 * Метка возврата состояния идёт лишь просьбой о повторе: раздел 4.2.2 RFC 8446
	 * велит сервером, состояния у себя не держащим, возвращать его этой меткой
	 */
	if(retry && !this->_cookie.empty()){
		// Если метку возврата состояния составить не удалось
		if(extension::cookie(view_t(this->_cookie.data(), this->_cookie.size()), label) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение метки возврата состояния сервера
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
	}
	// Накопитель, в котором лежит тело расширения выбранного ключа
	vector <uint8_t> selected;
	// Если связь возобновляется заранее разделённым ключом
	if(this->_shared && !retry){
		// Если выбранный заранее разделённый ключ составить не удалось
		if(extension::chosen(this->_chosen, selected) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение выбранного заранее разделённого ключа
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(selected.data(), selected.size())));
	}
	// Накопитель, в который складывается тело приветствия сервера
	vector <uint8_t> body;
	// Если тело приветствия сервера составить не удалось
	if(hello::build(answer, body) != hello::error_t::NONE)
		// Выводим отказ составления приветствия сервера
		return context::error_t::MESSAGE;
	// Выводим итог отправки приветствия сервера
	return this->send(handshake::type_t::SERVER, view_t(body.data(), body.size()));
}
/**
 * @brief Метод отправки подтверждения подлинности своей стороны
 *
 * @return отказ отправки подтверждения подлинности
 *
 */
context::error_t nts::internal::Engine::authenticate() noexcept {
	// Составляемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	/**
	 * Раздел 4.4.2 RFC 8446: сервер шлёт опознаватель запроса пустым, а клиент
	 * повторяет им опознаватель принятого запроса подлинности дословно
	 */
	/**
	 * Слагаемое (!this->_binding.empty()) истинным своим сервером не задевается: запрос
	 * подлинности он шлёт с пустым опознавателем, как и велит раздел 4.3.2 RFC 8446 по
	 * ходу рукопожатия. Непустым его шлёт лишь собеседник - либо своя же сторона, когда
	 * подтверждение подлинности за рукопожатием будет заведено
	 */
	if(!this->_server && !this->_binding.empty())
		// Устанавливаем опознаватель принятого запроса подлинности
		certificate.context = view_t(this->_binding.data(), this->_binding.size());
	/**
	 * Выполняем перебор сертификатов цепочки своей стороны
	 */
	for(size_t i = 0; i < this->_credential.chain.size(); i++){
		// Составляемая запись цепочки сертификатов
		message::entry_t entry;
		// Устанавливаем тело сертификата записи цепочки
		entry.data = view_t(this->_credential.chain[i].data(), this->_credential.chain[i].size());
		// Добавляем запись в цепочку сертификатов
		certificate.entries.push_back(entry);
	}
	// Накопитель, в который складывается тело сообщения цепочки
	vector <uint8_t> body;
	// Если тело сообщения цепочки сертификатов составить не удалось
	if(message::build(certificate, body) != message::error_t::NONE)
		// Выводим отказ составления сообщения цепочки сертификатов
		return context::error_t::MESSAGE;
	// Выполняем отправку цепочки сертификатов своей стороны
	const context::error_t error = this->send(handshake::type_t::CERTIFICATE, view_t(body.data(), body.size()));
	// Если цепочку сертификатов отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки цепочки сертификатов
		return error;
	/**
	 * Пустая цепочка сертификатов подписи владения ключом за собою не влечёт: раздел
	 * 4.4.2 RFC 8446 дозволяет её клиенту, у которого годного сертификата не нашлось
	 */
	if(this->_credential.chain.empty())
		// Выводим успешность отправки подтверждения подлинности
		return context::error_t::NONE;
	// Объект разбора своего сертификата
	x509::certificate_t leaf;
	// Если свой сертификат разобрать не удалось
	if(leaf.parse(view_t(this->_credential.chain[0].data(), this->_credential.chain[0].size())) != x509::error_t::NONE)
		// Выводим отказ разбора своего сертификата
		return context::error_t::CERTIFICATE;
	// Опознаватель набора параметров кривой своего ключа
	string oid;
	// Если опознаватель набора параметров кривой извлечь не удалось
	if(!x509::identifier(leaf.key(), oid))
		// Выводим отказ разбора своего сертификата
		return context::error_t::CERTIFICATE;
	// Схема подписи владения своим ключом
	extension::scheme_t item = extension::scheme_t::NONE;
	// Если схему подписи для кривой своего ключа подобрать не удалось
	if(!scheme(oid, item))
		// Выводим отказ подбора схемы подписи
		return context::error_t::CERTIFICATE;
	// Признак того, что схема подписи собеседником признаётся
	bool suitable = false;
	/**
	 * Выполняем перебор схем подписи, признаваемых собеседником
	 */
	for(size_t i = 0; (i < this->_schemes.size()) && !suitable; i++)
		// Запоминаем совпадение схемы подписи с признаваемой собеседником
		suitable = (item == this->_schemes[i]);
	/**
	 * Раздел 4.4.3 RFC 8446 велит подписывать владение ключом лишь той схемой, какую
	 * собеседник объявил признаваемой: подписи схемой, ему неведомой, он не сличит, и
	 * оборвётся рукопожатие тогда у него - позже и невнятнее, чем здесь
	 */
	if(!suitable)
		// Выводим отказ непризнания схемы подписи собеседником
		return context::error_t::SCHEME;
	// Эллиптическая кривая подписи владения ключом
	curve::curve_t curve;
	// Если кривую своего ключа завести не удалось
	if(!x509::parameters(leaf.key(), curve))
		// Выводим отказ заведения кривой своего ключа
		return context::error_t::CERTIFICATE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Накопитель, в который складывается подписываемое содержимое
	vector <uint8_t> content;
	// Если подписываемое содержимое составить не удалось
	if(message::content(view_t(transcript, sizeof(transcript)), this->_server, content) != message::error_t::NONE)
		// Выводим отказ составления подписываемого содержимого
		return context::error_t::MESSAGE;
	// Место, в которое помещается хеш подписываемого содержимого
	uint8_t digest[64];
	// Определяем длину хеша подписываемого содержимого
	const digest::type_t type = ((curve.size() == 32) ? digest::type_t::SHORT : digest::type_t::LONG);
	// Если хеш подписываемого содержимого выработать не удалось
	if(!digest::streebog(type, view_t(content.data(), content.size()), digest, curve.size(), digest::order_t::VECTOR))
		// Выводим отказ выработки хеша подписываемого содержимого
		return context::error_t::SIGNATURE;
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Если эллиптическую кривую подписи установить не удалось
	if(!gost.start(curve))
		// Выводим отказ установки кривой подписи
		return context::error_t::SIGNATURE;
	// Если секретный ключ своей стороны установить не удалось
	if(!gost.secret(view_t(this->_credential.secret.data(), this->_credential.secret.size())))
		// Выводим отказ установки секретного ключа
		return context::error_t::SIGNATURE;
	// Место, в которое помещается выработанная подпись владения ключом
	uint8_t signature[math::NUMBER_SIZE * 2];
	// Если подпись владения ключом выработать не удалось
	if(!gost.make(view_t(digest, curve.size()), signature))
		// Выводим отказ выработки подписи владения ключом
		return context::error_t::SIGNATURE;
	// Место, в которое помещается подпись в записи протокола
	uint8_t reversed[math::NUMBER_SIZE * 2];
	/**
	 * Раздел 5.3 описания наборов шифрования: обе половины подписи записываются в
	 * протокол младшим байтом вперёд, тогда как выработка даёт их обратной записью
	 */
	if(message::reverse(view_t(signature, gost.size()), reversed) != message::error_t::NONE)
		// Выводим отказ разворота записи подписи
		return context::error_t::SIGNATURE;
	// Составляемое сообщение подписи владения ключом
	message::verify_t verify;
	// Устанавливаем схему подписи владения ключом
	verify.scheme = item;
	// Устанавливаем значение подписи владения ключом
	verify.signature = view_t(reversed, gost.size());
	// Выполняем сброс накопителя тела сообщения
	body.clear();
	// Если тело сообщения подписи владения ключом составить не удалось
	if(message::build(verify, body) != message::error_t::NONE)
		// Выводим отказ составления сообщения подписи владения ключом
		return context::error_t::MESSAGE;
	// Выводим итог отправки подписи владения ключом
	return this->send(handshake::type_t::VERIFY, view_t(body.data(), body.size()));
}
/**
 * @brief Метод отправки завершения рукопожатия своей стороной
 *
 * @return отказ отправки завершения рукопожатия
 *
 */
context::error_t nts::internal::Engine::complete() noexcept {
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Место, в которое помещается завершение рукопожатия своей стороной
	uint8_t completion[32];
	// Если завершение рукопожатия выработать не удалось
	if(message::finished(view_t(this->_completion[index(side)], sizeof(this->_completion[0])), view_t(transcript, sizeof(transcript)), completion) != message::error_t::NONE)
		// Выводим отказ выработки завершения рукопожатия
		return context::error_t::COMPLETION;
	// Выводим итог отправки завершения рукопожатия своей стороной
	return this->send(handshake::type_t::FINISHED, view_t(completion, sizeof(completion)));
}
/**
 * @brief Метод разбора принятого запроса подлинности клиента
 *
 * @param body тело принятого сообщения запроса подлинности
 *
 * @return     отказ разбора запроса подлинности
 *
 */
context::error_t nts::internal::Engine::requesting(const view_t & body) noexcept {
	// Объект разборщика тела запроса подлинности клиента
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело запроса подлинности клиента
	scanner.start(body);
	// Опознаватель запроса подлинности клиента
	view_t binding;
	// Если опознаватель запроса подлинности прочитать не удалось
	if(scanner.vector(binding, 1) != field::error_t::NONE)
		// Выводим отказ разбора запроса подлинности клиента
		return context::error_t::MESSAGE;
	// Перечень расширений запроса подлинности клиента
	view_t extensions;
	// Если перечень расширений запроса прочитать не удалось
	if(scanner.vector(extensions, 2) != field::error_t::NONE)
		// Выводим отказ разбора запроса подлинности клиента
		return context::error_t::MESSAGE;
	// Если за телом запроса подлинности идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ разбора запроса подлинности клиента
		return context::error_t::MESSAGE;
	// Объект разборщика записей перечня расширений запроса
	field::scanner_t reader;
	// Устанавливаем разбираемое содержимое перечня расширений
	reader.start(extensions);
	// Тело расширения схем подписи, признаваемых сервером
	view_t offer(nullptr, 0);
	/**
	 * Выполняем перебор расширений, объявленных запросом подлинности
	 */
	while(reader.left() > 0){
		// Вид очередного расширения запроса подлинности
		uint32_t type = 0;
		// Если вид расширения прочитать не удалось
		if(reader.number(type, 2) != field::error_t::NONE)
			// Выводим отказ разбора запроса подлинности клиента
			return context::error_t::MESSAGE;
		// Тело очередного расширения запроса подлинности
		view_t content;
		// Если тело расширения прочитать не удалось
		if(reader.vector(content, 2) != field::error_t::NONE)
			// Выводим отказ разбора запроса подлинности клиента
			return context::error_t::MESSAGE;
		// Места, в которых объявленному расширению идти дозволено
		uint8_t places = 0;
		/**
		 * Раздел 4.2 RFC 8446 кладёт запросу подлинности свой перечень расширений, и
		 * признаваемое расширение вне его обрывает связь извещением
		 * «illegal_parameter»: из тех, что движок признаёт, запросу положены одни
		 * лишь схемы подписи
		 */
		if(placement(static_cast <uint16_t> (type), places) && ((places & PLACE_REQUEST) == 0))
			// Выводим отказ объявления расширения не в своём сообщении
			return context::error_t::EXTENSION;
		// Если объявлено расширение схем подписи
		if(type == static_cast <uint32_t> (extension::type_t::SCHEMES))
			// Запоминаем тело расширения схем подписи
			offer = content;
	}
	/**
	 * Раздел 4.3.2 RFC 8446 велит запросу подлинности нести схемы подписи всегда:
	 * без них клиенту нечем узнать, какую подпись сервер сличить сумеет
	 */
	if(offer.data == nullptr)
		// Выводим отказ отсутствия схем подписи в запросе подлинности
		return context::error_t::SCHEME;
	// Если схемы подписи, признаваемые сервером, разобрать не удалось
	if(extension::schemes(offer, this->_schemes) != extension::error_t::NONE)
		// Выводим отказ разбора запроса подлинности клиента
		return context::error_t::MESSAGE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Раздел 4.4.2 RFC 8446 велит клиенту повторить опознаватель принятого запроса
		 * своей цепочкой сертификатов дословно: им сервер и опознаёт, какому запросу
		 * цепочка отвечает
		 */
		this->_binding.assign(binding.data, binding.data + binding.size);
	// Если памяти под опознаватель запроса не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность разбора запроса подлинности клиента
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятой цепочки сертификатов собеседника
 *
 * @param body тело принятого сообщения цепочки сертификатов
 *
 * @return     отказ разбора цепочки сертификатов
 *
 */
context::error_t nts::internal::Engine::chain(const view_t & body) noexcept {
	// Разбираемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	// Если сообщение цепочки сертификатов разобрать не удалось
	if(message::parse(body, certificate) != message::error_t::NONE)
		// Выводим отказ разбора сообщения цепочки сертификатов
		return context::error_t::MESSAGE;
	/**
	 * Раздел 4.4.2 RFC 8446 велит серверу оставлять опознаватель запроса пустым, а
	 * клиенту - повторять им опознаватель принятого запроса подлинности. Модуль шлёт
	 * запрос подлинности с пустым опознавателем всегда, оттого пустым обязан быть и
	 * повтор: опознаватель, набитый содержимым, отвечает не тому запросу
	 */
	if(certificate.context.size > 0)
		// Выводим отказ непустого опознавателя запроса подлинности
		return context::error_t::MESSAGE;
	/**
	 * Раздел 4.4.2 RFC 8446 велит серверу присылать цепочку непустой: пустая цепочка
	 * означает отказ от подлинности, а он серверу не дозволен вовсе
	 */
	if(!this->_server && certificate.entries.empty())
		// Выводим отказ отсутствия сертификатов в цепочке сервера
		return context::error_t::CERTIFICATE;
	/**
	 * Выполняем перебор записей принятой цепочки сертификатов
	 */
	for(size_t i = 0; i < certificate.entries.size(); i++){
		/**
		 * Выполняем перебор расширений очередной записи цепочки
		 */
		for(size_t j = 0; j < certificate.entries[i].extensions.size(); j++){
			// Признак того, что расширение записи цепочки связью предлагалось
			bool suitable = false;
			/**
			 * Выполняем перебор расширений, предложенных связью приветствием
			 */
			for(size_t k = 0; (k < this->_offered.size()) && !suitable; k++)
				// Запоминаем, предлагалось ли расширение записи цепочки связью
				suitable = (certificate.entries[i].extensions[j].type == this->_offered[k]);
			/**
			 * Раздел 4.4.2 RFC 8446 велит расширениям записи цепочки отвечать
			 * предложенным: клиент судит их по своему приветствию, а сервер - по
			 * запросу подлинности, в котором расширений, годных записи цепочки, нет
			 * вовсе. Оттого у сервера перечень предложенных пуст, и всякое расширение
			 * записи он отвергает
			 */
			if(!suitable)
				// Выводим отказ объявления непрошенного расширения записи цепочки
				return context::error_t::EXTENSION;
		}
	}
	/**
	 * Выполняем перенос цепочки сертификатов собеседника
	 */
	try {
		// Выполняем сброс прежней цепочки сертификатов собеседника
		this->_peer.clear();
		/**
		 * Выполняем перебор записей принятой цепочки сертификатов
		 */
		for(size_t i = 0; i < certificate.entries.size(); i++){
			// Получаем тело сертификата очередной записи цепочки
			const view_t & data = certificate.entries[i].data;
			// Добавляем сертификат в цепочку собеседника
			this->_peer.push_back(vector <uint8_t> (data.data, data.data + data.size));
		}
	// Если памяти под цепочку сертификатов не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность разбора цепочки сертификатов собеседника
	return context::error_t::NONE;
}
/**
 * @brief Метод проверки принятой подписи владения ключом
 *
 * @param body тело принятого сообщения подписи владения ключом
 *
 * @return     отказ проверки подписи владения ключом
 *
 */
context::error_t nts::internal::Engine::possession(const view_t & body) noexcept {
	// Если цепочка сертификатов собеседника пуста
	if(this->_peer.empty())
		// Выводим отказ отсутствия сертификата собеседника
		return context::error_t::CERTIFICATE;
	// Разбираемое сообщение подписи владения ключом
	message::verify_t verify;
	// Если сообщение подписи владения ключом разобрать не удалось
	if(message::parse(body, verify) != message::error_t::NONE)
		// Выводим отказ разбора сообщения подписи владения ключом
		return context::error_t::MESSAGE;
	// Объект разбора сертификата собеседника
	x509::certificate_t leaf;
	// Если сертификат собеседника разобрать не удалось
	if(leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())) != x509::error_t::NONE)
		// Выводим отказ разбора сертификата собеседника
		return context::error_t::CERTIFICATE;
	// Опознаватель набора параметров кривой ключа собеседника
	string identifier;
	// Если опознаватель набора параметров кривой извлечь не удалось
	if(!x509::identifier(leaf.key(), identifier))
		// Выводим отказ разбора сертификата собеседника
		return context::error_t::CERTIFICATE;
	// Получаем опознаватель кривой, отвечающей объявленной схеме подписи
	const char * declared = extension::curve(verify.scheme);
	/**
	 * Раздел 4.4.3 RFC 8446 велит схеме подписи отвечать ключу сертификата: подпись
	 * по кривой, которой в сертификате нет, проверялась бы не тем ключом, которым
	 * объявлена, и объявление схемы не значило бы ничего вовсе
	 *
	 * Сличения схемы с предложением связи здесь нет намеренно: связь предлагает все
	 * схемы, какие модуль знает, и неизвестная схема кривой не имеет вовсе - её
	 * отвергает это же сличение
	 */
	if((declared == nullptr) || (identifier.compare(declared) != 0))
		// Выводим отказ несоответствия схемы подписи ключу сертификата
		return context::error_t::SCHEME;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Накопитель, в который складывается подписанное содержимое
	vector <uint8_t> content;
	// Если подписанное содержимое составить не удалось
	if(message::content(view_t(transcript, sizeof(transcript)), !this->_server, content) != message::error_t::NONE)
		// Выводим отказ составления подписанного содержимого
		return context::error_t::MESSAGE;
	// Место, в которое помещается подпись в записи выработки
	uint8_t signature[math::NUMBER_SIZE * 2];
	/**
	 * Длина подписи приходит с той стороны связи: раздел 4.4.3 RFC 8446 кладёт полю
	 * подписи два байта длины, то есть до 65535 байтов, тогда как место под подпись
	 * отведено на стеке размером в два числа. Разворот записи переносит подпись
	 * ЦЕЛИКОМ, и сверка длины обязана идти прежде него - иначе подпись, объявленная
	 * непомерной, вынесла бы разворот за отведённое место.
	 *
	 * Сверка эта стережёт лишь память; точная же длина, ключу собеседника отвечающая,
	 * сверяется дальше самой проверкой подписи
	 */
	if(verify.signature.size > sizeof(signature))
		// Выводим отказ непомерной длины подписи владения ключом
		return context::error_t::SIGNATURE;
	// Если запись подписи развернуть не удалось
	if(message::reverse(verify.signature, signature) != message::error_t::NONE)
		// Выводим отказ разворота записи подписи
		return context::error_t::SIGNATURE;
	// Если подпись владения ключом не сошлась
	if(!x509::check(leaf.key(), view_t(content.data(), content.size()), view_t(signature, verify.signature.size)))
		// Выводим отказ проверки подписи владения ключом
		return context::error_t::SIGNATURE;
	// Выводим успешность проверки подписи владения ключом
	return context::error_t::NONE;
}
/**
 * @brief Метод проверки принятого завершения рукопожатия
 *
 * @param body тело принятого сообщения завершения рукопожатия
 *
 * @return     отказ проверки завершения рукопожатия
 *
 */
context::error_t nts::internal::Engine::confirm(const view_t & body) noexcept {
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Место, в которое помещается ожидаемое завершение рукопожатия
	uint8_t completion[32];
	// Если ожидаемое завершение рукопожатия выработать не удалось
	if(message::finished(view_t(this->_completion[index(side)], sizeof(this->_completion[0])), view_t(transcript, sizeof(transcript)), completion) != message::error_t::NONE)
		// Выводим отказ выработки завершения рукопожатия
		return context::error_t::COMPLETION;
	/**
	 * Сличение ведётся за постоянное время: по времени сличения восстанавливается
	 * ожидаемое завершение, а с ним и подделка рукопожатия
	 */
	if(!message::compare(body, view_t(completion, sizeof(completion))))
		// Выводим отказ схождения завершения рукопожатия
		return context::error_t::COMPLETION;
	// Выводим успешность проверки завершения рукопожатия
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора предложения заранее разделённых ключей клиента
 *
 * @param extensions перечень расширений принятого приветствия клиента
 * @param message    принятое приветствие клиента вместе с обвязкой
 *
 * @return           отказ разбора предложения заранее разделённых ключей
 *
 */
context::error_t nts::internal::Engine::offered(const vector <hello::extension_t> & extensions, const view_t & message) noexcept {
	// Разыскиваем расширение заранее разделённых ключей клиента
	const hello::extension_t * offer = hello::extension(extensions, static_cast <uint16_t> (extension::type_t::SECRET));
	// Если заранее разделённых ключей клиент не предлагает либо признавать их нечем
	if((offer == nullptr) || this->_store.empty())
		// Выводим успешность разбора предложения заранее разделённых ключей
		return context::error_t::NONE;
	// Разыскиваем расширение способов обмена заранее разделённым ключом
	const hello::extension_t * item = hello::extension(extensions, static_cast <uint16_t> (extension::type_t::MODES));
	// Если способы обмена заранее разделённым ключом клиент не объявил
	if(item == nullptr)
		// Выводим отказ отсутствия обязательного расширения
		return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
	// Способы обмена, объявленные клиентом
	vector <extension::mode_t> modes;
	// Если способы обмена разобрать не удалось
	if(extension::modes(item->data, modes) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Признак того, что обмен ключом кривой вместе с билетом клиентом объявлен
	bool suitable = false;
	/**
	 * Выполняем перебор способов обмена, объявленных клиентом
	 */
	for(size_t i = 0; (i < modes.size()) && !suitable; i++)
		// Запоминаем объявление обмена ключом кривой вместе с билетом
		suitable = (modes[i] == extension::mode_t::SHARED);
	/**
	 * Обмен одним лишь билетом связью не ведётся: без ключа кривой хищение билета
	 * выдаёт всё, что этим билетом когда-либо защищено
	 */
	if(!suitable)
		// Выводим успешность разбора предложения заранее разделённых ключей
		return context::error_t::NONE;
	// Перечень опознавателей заранее разделённых ключей клиента
	vector <extension::identity_t> identities;
	// Перечень привязок заранее разделённых ключей клиента
	vector <view_t> binders;
	// Длина усечения приветствия от начала тела расширения
	size_t truncation = 0;
	// Если предложение заранее разделённых ключей разобрать не удалось
	if(extension::identities(offer->data, identities, binders, truncation) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Место найденного билета в перечне признаваемых
	size_t found = this->_store.size();
	// Место предъявленного ключа в предложении клиента
	size_t chosen = 0;
	/**
	 * Выполняем перебор опознавателей ключей, предложенных клиентом
	 */
	for(size_t i = 0; (i < identities.size()) && (found == this->_store.size()); i++){
		/**
		 * Выполняем перебор билетов, признаваемых сервером
		 */
		for(size_t j = 0; j < this->_store.size(); j++){
			// Если длина опознавателя с длиной признаваемого билета не совпала
			if(identities[i].identity.size != this->_store[j].identity.size())
				// Переходим к следующему признаваемому билету
				continue;
			// Если опознаватель с признаваемым билетом не совпал
			if(::memcmp(identities[i].identity.data, this->_store[j].identity.data(), identities[i].identity.size) != 0)
				// Переходим к следующему признаваемому билету
				continue;
			/**
			 * Билет с вышедшим сроком в дело не идёт: раздел 4.6.1 RFC 8446 велит
			 * серверу и клиенту держать его не дольше объявленного срока, и связь
			 * с таким билетом идёт полным рукопожатием
			 */
			if(expired(this->_store[j], this->_moment))
				// Переходим к следующему признаваемому билету
				continue;
			// Если опознаватель совпал с признаваемым билетом
			{
				// Запоминаем место найденного билета в перечне признаваемых
				found = j;
				// Запоминаем место предъявленного ключа в предложении клиента
				chosen = i;
				// Прекращаем перебор признаваемых билетов
				break;
			}
		}
	}
	// Если ни один из предложенных ключей сервером не признан
	if(found == this->_store.size())
		// Выводим успешность разбора предложения: связь идёт полным рукопожатием
		return context::error_t::NONE;
	/**
	 * Объявленный возраст билета сличается с наблюдаемым: раздел 4.2.10 RFC 8446 велит
	 * отвергать упреждающие данные при расхождении, а самому возобновлению связи
	 * расхождение это не мешает - для него довольно совпадения привязки
	 */
	if((this->_moment != 0) && (this->_store[found].moment != 0)){
		// Получаем объявленный клиентом возраст билета в миллисекундах
		const int64_t declared = static_cast <int64_t> (static_cast <uint32_t> (identities[chosen].age - this->_store[found].age));
		// Получаем наблюдаемый сервером возраст билета в миллисекундах
		const int64_t observed = ((this->_moment - this->_store[found].moment) * 1000);
		// Если объявленный возраст с наблюдаемым разошёлся шире окна
		if(((declared - observed) > WINDOW) || ((observed - declared) > WINDOW))
			// Прекращаем ход упреждающих данных связи
			this->_advance = false;
	}
	// Если начальную ступень расписания ключей завести не удалось
	if(this->_secrets.start(view_t(this->_store[found].secret.data(), this->_store[found].secret.size())) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала связи
		return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
	/**
	 * Длина усечения отсчитывается от начала сообщения: тело расширения лежит внутри
	 * него, и место его начала к длине усечения и прибавляется
	 */
	const size_t offset = (static_cast <size_t> (offer->data.data - message.data) + truncation);
	/**
	 * Заслон этот оборонительный: длина усечения берётся смещением внутри тела
	 * расширения, а тело лежит просмотром внутри самого приветствия - сумма их за
	 * приветствие выйти не может, и через связь заслон недостижим. Стоит он на
	 * случай, если тело расширения перестанет быть просмотром внутрь приветствия
	 */
	if(offset > message.size)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Место, в которое помещается хеш усечённого приветствия клиента
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш усечённого приветствия получить не удалось
	if(this->_transcript.digest(view_t(message.data, offset), transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Место, в которое помещается ожидаемая привязка билета
	uint8_t expected[schedule::SCHEDULE_SECRET];
	// Если ожидаемую привязку билета выработать не удалось
	if(this->_secrets.binder(view_t(transcript, sizeof(transcript)), expected) != session::error_t::NONE)
		// Выводим отказ выработки привязки билета
		return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
	/**
	 * Привязка сличается за постоянное время: по времени сличения восстанавливается
	 * ожидаемая привязка, а с нею и подделка владения билетом
	 */
	if(!message::compare(binders[chosen], view_t(expected, sizeof(expected)))){
		// Выполняем сброс значений расписания ключей связи
		this->_secrets.clear();
		// Выводим отказ схождения привязки предъявленного билета
		return this->abort(context::error_t::SIGNATURE, alert::description_t::DECRYPT);
	}
	// Запоминаем набор шифрования признанного билета
	this->_ticket = this->_store[found].suite;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Запоминаем прикладной протокол связи, выдавшей признанный билет
		this->_previous = this->_store[found].protocol;
	// Если памяти под прикладной протокол не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
	// Запоминаем место выбранного ключа в предложении клиента
	this->_chosen = static_cast <uint16_t> (chosen);
	// Запоминаем возобновление связи заранее разделённым ключом
	this->_shared = true;
	// Выводим успешность разбора предложения заранее разделённых ключей
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого приветствия клиента
 *
 * @param body    тело принятого приветствия клиента
 * @param message принятое приветствие клиента вместе с обвязкой
 *
 * @return        отказ разбора приветствия клиента
 *
 */
context::error_t nts::internal::Engine::incoming(const view_t & body, const view_t & message) noexcept {
	// Разбираемое приветствие клиента
	hello::client_t greeting;
	// Если приветствие клиента разобрать не удалось
	if(hello::parse(body, greeting) != hello::error_t::NONE)
		// Выводим отказ разбора приветствия клиента
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	/**
	 * Способ сжатия у издания 1.3 остался один и тот же - никакого: раздел 4.1.2
	 * RFC 8446 велит оборвать связь, если клиент объявил иное
	 */
	if((greeting.methods.size() != 1) || (greeting.methods[0] != 0x00))
		// Выводим отказ негодного перечня способов сжатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	/**
	 * Заранее разделённые ключи идут последним расширением приветствия: раздел 4.2.11
	 * RFC 8446 велит класть их именно туда, ибо привязка их считается по переписке,
	 * усечённой ровно до начала этого расширения
	 */
	/**
	 * Слагаемое (!greeting.extensions.empty()) истинно всегда: приветствие без единого
	 * расширения не объявляет и перечня изданий протокола, а без него оно отвергается
	 * много раньше. Слагаемое оставлено ради самостоятельности выражения: розыск по
	 * пустому перечню и обращение к его последнему расширению стоят рядом
	 */
	if(!greeting.extensions.empty() && (hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SECRET)) != nullptr) && (greeting.extensions.back().type != static_cast <uint16_t> (extension::type_t::SECRET)))
		// Выводим отказ места расширения заранее разделённых ключей
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	// Разыскиваем расширение метки возврата состояния сервера
	const hello::extension_t * returned = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::COOKIE));
	// Если метка возврата состояния приветствием повторена
	if(returned != nullptr){
		/**
		 * Метку сервер судит сам: раздел 4.2.2 RFC 8446 не кладёт на её содержимое
		 * никаких правил, ибо складывал её тот же сервер, что её и читает
		 */
		// Тело принятой метки возврата состояния сервера
		view_t label;
		// Если метку возврата состояния разобрать не удалось
		if(extension::cookie(returned->data, label) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Переносим принятую метку возврата состояния сервера
			this->_label.assign(label.data, label.data + label.size);
		/**
		 * Если памяти под метку возврата состояния не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
		}
	}
	// Разыскиваем расширение перечня изданий протокола
	const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
	/**
	 * Приложение D.2 RFC 8446: при отсутствующем перечне изданий сервер обязан вести
	 * переговоры по наименьшему из объявленного приветствием и TLS 1.2, а не
	 * поддерживая ни того ни другого - обрывать связь извещением protocol_version.
	 *
	 * Извещение missing_extension сюда НЕ относится, сколь бы ни было оно похоже:
	 * раздел 9.2 держит его для приветствия, ведущего переговоры по ЭТОМУ стандарту, а
	 * таковым он числит лишь приветствие, несущее перечень изданий с 0x0304 в теле.
	 * Приветствие без перечня переговоров по этому стандарту не ведёт вовсе, и требовать
	 * с него обязательных расширений не с чего
	 */
	if(extension == nullptr)
		// Выводим отказ несовпадения издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
	// Перечень изданий протокола, предлагаемых клиентом
	vector <uint16_t> versions;
	// Если перечень изданий протокола разобрать не удалось
	if(extension::versions(extension->data, versions) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Признак того, что издание протокола связи клиентом предложено
	bool suitable = false;
	/**
	 * Выполняем перебор изданий протокола, предлагаемых клиентом
	 */
	for(size_t i = 0; (i < versions.size()) && !suitable; i++)
		// Запоминаем предложение издания протокола связи
		suitable = (versions[i] == 0x0304);
	// Если издание протокола связи клиентом не предложено
	if(!suitable)
		// Выводим отказ несовпадения издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
	// Признак того, что общий набор шифрования у сторон нашёлся
	suitable = false;
	/**
	 * Выполняем перебор наборов шифрования, предлагаемых связью
	 */
	for(size_t i = 0; (i < this->_suites.size()) && !suitable; i++){
		/**
		 * Выполняем перебор наборов шифрования, предлагаемых клиентом
		 */
		for(size_t j = 0; (j < greeting.suites.size()) && !suitable; j++){
			// Если набор шифрования предложен обеими сторонами
			if(greeting.suites[j] == static_cast <uint16_t> (this->_suites[i])){
				// Запоминаем выбранный набор шифрования связи
				this->_suite = this->_suites[i];
				// Запоминаем, что общий набор шифрования нашёлся
				suitable = true;
			}
		}
	}
	// Если общего набора шифрования у сторон не нашлось
	if(!suitable)
		// Выводим отказ отсутствия общего набора шифрования
		return this->abort(context::error_t::SUITE, alert::description_t::HANDSHAKE);
	// Разыскиваем расширение имени запрашиваемого узла
	extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::NAME));
	// Если имя запрашиваемого узла приветствием объявлено
	if(extension != nullptr){
		// Имя узла, запрошенное клиентом у сервера
		view_t host;
		// Если имя запрашиваемого узла разобрать не удалось
		if(extension::name(extension->data, host) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			/**
			 * Имя узла сервером лишь принимается: раздел 3 RFC 6066 велит выбирать по нему
			 * подлинность своей стороны, а выбор этот принадлежит потребителю, который
			 * подлинность и устанавливает
			 */
			this->_name.assign(reinterpret_cast <const char *> (host.data), host.size);
		/**
		 * Если памяти под имя запрашиваемого узла не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
		}
	}
	// Если прикладные протоколы сервером признаются
	if(!this->_protocols.empty()){
		// Разыскиваем расширение перечня прикладных протоколов
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::PROTOCOLS));
		// Если прикладные протоколы приветствием объявлены
		if(extension != nullptr){
			// Перечень прикладных протоколов, предложенных клиентом
			vector <string> offer;
			// Если перечень прикладных протоколов разобрать не удалось
			if(extension::protocols(extension->data, offer) != extension::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			/**
			 * Выполняем перехват ошибок работы с памятью
			 */
			try {
				/**
				 * Выбор идёт порядком сервера, а не клиента: раздел 3.2 RFC 7301 велит
				 * выбирать протокол серверу, и порядок его перечня - это и есть его
				 * предпочтение
				 */
				for(size_t i = 0; (i < this->_protocols.size()) && this->_protocol.empty(); i++){
					/**
					 * Выполняем перебор прикладных протоколов, предложенных клиентом
					 */
					for(size_t j = 0; (j < offer.size()) && this->_protocol.empty(); j++){
						// Если прикладной протокол предложен обеими сторонами
						if(offer[j].compare(this->_protocols[i]) == 0)
							// Запоминаем выбранный сторонами прикладной протокол
							this->_protocol = this->_protocols[i];
					}
				}
			/**
			 * Если памяти под название протокола не хватило
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
			}
			// Если общего прикладного протокола у сторон не нашлось
			if(this->_protocol.empty())
				// Выводим отказ отсутствия общего прикладного протокола
				return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
		}
	}
	// Разыскиваем расширение схем подписи, признаваемых клиентом
	extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SCHEMES));
	// Если схемы подписи приветствием клиента объявлены
	if(extension != nullptr){
		// Если схемы подписи, признаваемые клиентом, разобрать не удалось
		if(extension::schemes(extension->data, this->_schemes) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	}
	// Выполняем разбор предложения заранее разделённых ключей клиента
	const context::error_t offered = this->offered(greeting.extensions, message);
	// Если предложение заранее разделённых ключей разобрать не удалось
	if(offered != context::error_t::NONE)
		// Выводим отказ разбора предложения заранее разделённых ключей
		return offered;
	/**
	 * Раздел 9.2 RFC 8446 велит клиенту объявлять схемы подписи всякий раз, когда
	 * сервер подтверждает подлинность сертификатом: без них сервер подписать владение
	 * ключом не вправе ничем. Возобновление заранее разделённым ключом сертификата не
	 * требует, и там расширение это не нужно вовсе
	 */
	/**
	 * Слагаемое (!this->_shared) ложным своим клиентом не задевается: схемы подписи он
	 * объявляет всякий раз, и приветствие без них приходит лишь от собеседника.
	 * Задеть его способен собеседник, возобновляющий связь билетом и схем не
	 * объявляющий, - такому приветствие проходит законно
	 */
	if(this->_schemes.empty() && !this->_shared)
		// Выводим отказ отсутствия схем подписи в приветствии клиента
		return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
	/**
	 * Приветствие ложится в переписку лишь теперь: привязка билета берётся от
	 * переписки без него, и добавь его раньше - привязка не сошлась бы
	 */
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Если приветствие клиента ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Если упреждающие данные клиентом предложены
	if(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::EARLY)) != nullptr){
		/**
		 * Упреждающие данные принимаются лишь при возобновлении связи билетом: ключи
		 * их выводятся из заранее разделённого ключа, которого при полном рукопожатии
		 * попросту нет
		 *
		 * Раздел 4.2.10 RFC 8446 кладёт приёму ещё два условия: признанным обязан быть
		 * первый из предложенных клиентом ключей, а набор шифрования связи - совпасть с
		 * тем, каким выдан билет. Клиент шлёт упреждающие данные до ответа сервера и
		 * шифрует их набором билета, ибо иного на тот миг не знает; выбери сервер иной
		 * набор и прими данные - он читал бы их набором, о котором клиент не уславливался.
		 * Третьим условием идёт прикладной протокол: упреждающие данные сложены по тому
		 * протоколу, каким шла выдавшая билет связь, и разойдись он с протоколом новой -
		 * сервер разобрал бы их не тем разборщиком
		 *
		 * Условие о первом ключе своим клиентом не задевается вовсе: он предлагает
		 * один-единственный билет, и место выбранного ключа у него всегда нулевое.
		 * Задеть это условие способен лишь собеседник, предлагающий несколько билетов
		 * разом, оттого закреплённой проверки на него и нет
		 */
		if(this->_advance && this->_shared && (this->_chosen == 0) && (this->_suite == this->_ticket) && (this->_protocol == this->_previous)){
			/**
			 * Ключи упреждающих данных выводятся от переписки с одним лишь приветствием
			 * клиента: ответа сервера в ней на этот миг ещё нет, и завестись им надо
			 * прежде вывода ключей рукопожатия
			 */
			const context::error_t outcome = this->earliest();
			// Если защиту записей упреждающих данных завести не удалось
			if(outcome != context::error_t::NONE)
				// Выводим отказ заведения защиты записей
				return this->abort(outcome, alert::description_t::INTERNAL);
			// Запоминаем приём упреждающих данных клиента
			this->_accepted = true;
		/**
		 * Отвергнутые упреждающие данные прочесть нечем, и записи их пропускаются:
		 * число пропусков ограничено, иначе им открылся бы бесконечный поток
		 */
		} else this->_skipped = 16;
	}
	// Разыскиваем расширение открытых частей ключей обмена
	extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
	// Перечень открытых частей ключей обмена, объявленных клиентом
	vector <extension::share_t> shares;
	// Если открытые части ключей обмена приветствием объявлены
	if(extension != nullptr){
		// Если перечень открытых частей ключей обмена разобрать не удалось
		if(extension::shares(extension->data, shares) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Разыскиваем расширение перечня кривых обмена ключами
		const hello::extension_t * declared = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
		// Если перечень кривых обмена ключами приветствием объявлен
		if(declared != nullptr){
			// Перечень кривых обмена ключами, поддерживаемых клиентом
			vector <extension::group_t> supported;
			// Если перечень кривых обмена ключами разобрать не удалось
			if(extension::groups(declared->data, supported) != extension::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			/**
			 * Выполняем перебор открытых частей ключей обмена клиента
			 */
			for(size_t i = 0; i < shares.size(); i++){
				// Признак того, что кривая ключа объявлена клиентом поддержанной
				bool known = false;
				/**
				 * Выполняем перебор кривых обмена ключами, поддерживаемых клиентом
				 */
				for(size_t j = 0; (j < supported.size()) && !known; j++)
					// Запоминаем совпадение кривой ключа с поддержанной клиентом
					known = (shares[i].group == supported[j]);
				/**
				 * Ключ по кривой, которой клиент не объявил поддержанной, в дело не
				 * идёт: раздел 4.2.8 RFC 8446 велит оборвать связь, ибо приветствие
				 * само себе противоречит
				 */
				if(!known)
					// Выводим отказ кривой ключа вне объявленной поддержки
					return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
			}
		}
	}
	// Открытая часть ключа обмена, выбранная сервером
	const extension::share_t * selected = nullptr;
	/**
	 * Выполняем перебор кривых обмена ключами, предлагаемых связью
	 */
	for(size_t i = 0; (i < this->_groups.size()) && (selected == nullptr); i++){
		/**
		 * Выполняем перебор открытых частей ключей обмена клиента
		 */
		for(size_t j = 0; (j < shares.size()) && (selected == nullptr); j++){
			// Если открытая часть ключа обмена отвечает предлагаемой кривой
			if(shares[j].group == this->_groups[i])
				// Запоминаем выбранную открытую часть ключа обмена
				selected = &shares[j];
		}
	}
	// Если открытой части ключа обмена по общей кривой у клиента не нашлось
	if(selected == nullptr){
		// Если повтор приветствия клиента уже был
		if(this->_retried)
			// Выводим отказ отсутствия общей кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
		// Разыскиваем расширение перечня кривых обмена ключами
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
		// Если перечень кривых обмена ключами приветствием не объявлен
		if(extension == nullptr)
			// Выводим отказ отсутствия кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::MISSING);
		// Перечень кривых обмена ключами, поддерживаемых клиентом
		vector <extension::group_t> groups;
		// Если перечень кривых обмена ключами разобрать не удалось
		if(extension::groups(extension->data, groups) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Признак того, что общая кривая обмена ключами у сторон нашлась
		suitable = false;
		/**
		 * Выполняем перебор кривых обмена ключами, предлагаемых связью
		 */
		for(size_t i = 0; (i < this->_groups.size()) && !suitable; i++){
			/**
			 * Выполняем перебор кривых обмена ключами, поддерживаемых клиентом
			 */
			for(size_t j = 0; (j < groups.size()) && !suitable; j++){
				// Если кривая обмена ключами поддержана обеими сторонами
				if(groups[j] == this->_groups[i]){
					// Запоминаем выбранную кривую обмена ключами
					this->_group = this->_groups[i];
					// Запоминаем, что общая кривая обмена ключами нашлась
					suitable = true;
				}
			}
		}
		// Если общей кривой обмена ключами у сторон не нашлось
		if(!suitable)
			// Выводим отказ отсутствия общей кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
		/**
		 * Переписка рукопожатия заменяется хешем приветствия клиента: раздел 4.4.1
		 * RFC 8446 велит поступать так всякий раз при просьбе о повторе приветствия
		 */
		if(this->_transcript.replace() != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Выполняем отправку просьбы о повторе приветствия клиента
		const context::error_t error = this->answer(greeting.session, true);
		// Если просьбу о повторе приветствия отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки просьбы о повторе приветствия
			return this->abort(error, alert::description_t::INTERNAL);
		/**
		 * Повторность просьбы сличена выше собственным признаком связи, и второй раз
		 * сюда управление не приходит: через связь заслон недостижим. Лежит он за
		 * отправкой самой просьбы нарочно - объявление ходу идёт в паре с заменою
		 * переписки, а не с составлением сообщения
		 */
		if(this->_machine.retry() != flow::error_t::NONE)
			// Выводим отказ объявления просьбы не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Запоминаем, что повтор приветствия клиента уже был
		this->_retried = true;
		// Выводим успешность разбора приветствия клиента
		return context::error_t::NONE;
	}
	/**
	 * Слагаемое (selected->key.data == nullptr) ложно всегда: разбор доли обмена место
	 * ей отводит непременно, а пустую долю выдаёт нулевая длина, за которую отвечает
	 * вторая половина. Слагаемое оставлено ради самостоятельности заслона
	 */
	// Если открытая часть ключа обмена клиента непригодна
	if((selected->key.data == nullptr) || (selected->key.size == 0))
		// Выводим отказ непригодности открытой части ключа обмена
		return this->abort(context::error_t::EXCHANGE, alert::description_t::PARAMETER);
	// Открытая часть ключа обмена клиента, из которой выводятся ключи связи
	const vector <uint8_t> key(selected->key.data, selected->key.data + selected->key.size);
	// Выполняем выработку мимолётной пары ключей своей стороны
	context::error_t error = this->exchange(selected->group);
	// Если мимолётную пару ключей выработать не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ выработки мимолётной пары ключей
		return this->abort(error, alert::description_t::HANDSHAKE);
	// Выполняем выработку случайного значения своего приветствия
	if(!entropy::bytes(this->_random, sizeof(this->_random)))
		// Выводим отказ выработки случайного значения приветствия
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Выполняем отправку приветствия сервера
	error = this->answer(greeting.session, false);
	// Если приветствие сервера отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки приветствия сервера
		return this->abort(error, alert::description_t::INTERNAL);
	// Выполняем вывод ключей рукопожатия связи
	error = this->derive(view_t(key.data(), key.size()));
	// Если ключи рукопожатия связи вывести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ вывода ключей рукопожатия связи
		return this->abort(error, alert::description_t::HANDSHAKE);
	// Перечень расширений, объявляемых сервером под защитой
	vector <hello::extension_t> items;
	// Накопитель, в котором лежит тело расширения прикладного протокола
	vector <uint8_t> protocol;
	// Если упреждающие данные клиента приняты
	if(this->_accepted)
		// Объявляем клиенту приём упреждающих данных
		items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
	/**
	 * Имя узла подтверждается пустым расширением: раздел 3 RFC 6066 велит серверу лишь
	 * объявить, что имя принято, а самого имени в ответ не возвращать
	 */
	if(!this->_name.empty())
		// Объявляем клиенту приём имени запрашиваемого узла
		items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(nullptr, 0)));
	// Если прикладной протокол сторонами выбран
	if(!this->_protocol.empty()){
		// Если выбранный прикладной протокол составить не удалось
		if(extension::protocol(this->_protocol, protocol) != extension::error_t::NONE)
			// Выводим отказ составления сообщения защищённых расширений
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Объявляем клиенту выбранный прикладной протокол
		items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocol.data(), protocol.size())));
	}
	// Накопитель, в который складывается тело защищённых расширений
	vector <uint8_t> extensions;
	// Если тело сообщения защищённых расширений составить не удалось
	if(!block(items, extensions))
		// Выводим отказ составления сообщения защищённых расширений
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Выполняем отправку защищённых расширений сервера
	error = this->send(handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size()));
	// Если защищённые расширения отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки защищённых расширений
		return this->abort(error, alert::description_t::INTERNAL);
	// Если подлинность клиента сервером запрашивается
	if(this->_request){
		// Объект составителя тела запроса подлинности клиента
		field::builder_t builder;
		// Если пустую привязку запроса записать не удалось
		if(builder.number(0, 1) != field::error_t::NONE)
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Накопитель, в который складывается тело расширения схем подписи
		vector <uint8_t> schemes;
		// Перечень предлагаемых схем подписи
		const vector <extension::scheme_t> offer(SCHEMES, SCHEMES + (sizeof(SCHEMES) / sizeof(extension::scheme_t)));
		// Если перечень схем подписи составить не удалось
		if(extension::schemes(offer, schemes) != extension::error_t::NONE)
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Перечень расширений запроса подлинности клиента
		vector <hello::extension_t> list;
		// Добавляем расширение перечня схем подписи
		list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Накопитель, в который складывается запись перечня расширений
		vector <uint8_t> record;
		// Если запись перечня расширений составить не удалось
		if(!block(list, record))
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если запись перечня расширений в тело запроса добавить не удалось
		if(builder.bytes(view_t(record.data(), record.size())) != field::error_t::NONE)
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Получаем составленное тело запроса подлинности клиента
		const view_t request = builder.data();
		// Выполняем отправку запроса подлинности клиента
		error = this->send(handshake::type_t::REQUEST, request);
		// Если запрос подлинности клиента отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки запроса подлинности клиента
			return this->abort(error, alert::description_t::INTERNAL);
	}
	/**
	 * Подлинность сервера предъявляется лишь вне возобновления связи: раздел 2.2
	 * RFC 8446 велит при возобновлении опираться на заранее разделённый ключ, которым
	 * стороны уже опознали друг друга прошлой связью
	 */
	if(!this->_shared){
		// Выполняем отправку подтверждения подлинности сервера
		error = this->authenticate();
		// Если подтверждение подлинности сервера отправить не удалось
		if(error != context::error_t::NONE)
			/**
			 * Раздел 4.4.3 RFC 8446: отсутствие схемы подписи, признаваемой обеими
			 * сторонами, есть несхождение сторон, а не внутренний отказ
			 */
			return this->abort(error, ((error == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::INTERNAL));
	}
	// Выполняем отправку завершения рукопожатия сервером
	error = this->complete();
	// Если завершение рукопожатия сервером отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки завершения рукопожатия
		return this->abort(error, alert::description_t::INTERNAL);
	// Выполняем вывод ключей прикладных данных связи
	error = this->mature();
	// Если ключи прикладных данных вывести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ вывода ключей прикладных данных
		return this->abort(error, alert::description_t::INTERNAL);
	// Выполняем согласование ключевого материала защиты записей
	error = this->refresh();
	// Если ключевой материал защиты записей согласовать не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ согласования ключевого материала
		return this->abort(error, alert::description_t::INTERNAL);
	// Выводим успешность разбора приветствия клиента
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого приветствия сервера
 *
 * @param body    тело принятого приветствия сервера
 * @param message принятое приветствие сервера вместе с обвязкой
 *
 * @return        отказ разбора приветствия сервера
 *
 */
context::error_t nts::internal::Engine::outgoing(const view_t & body, const view_t & message) noexcept {
	// Разбираемое приветствие сервера
	hello::server_t answer;
	// Если приветствие сервера разобрать не удалось
	if(hello::parse(body, answer) != hello::error_t::NONE)
		// Выводим отказ разбора приветствия сервера
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	/**
	 * Опознаватель связи сервер обязан вернуть тем же, каким его прислал клиент:
	 * раздел 4.1.3 RFC 8446 велит оборвать связь, если он вернулся иным
	 */
	/**
	 * Слагаемое (!answer.session.empty()) ложным не задевается: свой клиент шлёт
	 * опознаватель связи длиною ровно в HELLO_SESSION, и приветствие, прошедшее
	 * сверку длин, несёт его непустым. Слагаемое оставлено оттого, что сличение
	 * пустого места через memcmp опирается на непереданный указатель
	 */
	if((answer.session.size() != this->_session.size()) || (!answer.session.empty() && (::memcmp(answer.session.data(), this->_session.data(), answer.session.size()) != 0)))
		// Выводим отказ несовпадения опознавателя связи
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	/**
	 * Способ сжатия достался изданию 1.3 от предыдущих и назначения в нём не имеет:
	 * раздел 4.1.3 RFC 8446 велит серверу слать нуль, а всякое иное значение выдаёт
	 * собеседника, ведущего иное издание протокола под видом нынешнего
	 */
	if(answer.method != 0x00)
		// Выводим отказ негодного способа сжатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	// Признак того, что выбранный сервером набор шифрования связью предложен
	bool suitable = false;
	/**
	 * Выполняем перебор наборов шифрования, предлагаемых связью
	 */
	for(size_t i = 0; (i < this->_suites.size()) && !suitable; i++)
		// Запоминаем совпадение выбранного набора шифрования с предложенным
		suitable = (answer.suite == static_cast <uint16_t> (this->_suites[i]));
	// Если сервер выбрал набор шифрования, связью не предложенный
	if(!suitable)
		// Выводим отказ несовпадения набора шифрования
		return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
	/**
	 * За просьбой о повторе сервер обязан выбрать тот же набор шифрования, каким
	 * объявил самоё просьбу: раздел 4.1.4 RFC 8446 менять его между просьбой и
	 * приветствием запрещает. Заслон этот не украшение: переписка рукопожатия
	 * хешируется набором, и сменой его сервер развёл бы стороны по разным хешам
	 */
	if(this->_retried && (answer.suite != static_cast <uint16_t> (this->_suite)))
		// Выводим отказ смены набора шифрования за просьбой о повторе
		return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
	// Запоминаем выбранный сервером набор шифрования
	this->_suite = static_cast <protect::suite_t> (answer.suite);
	// Если приветствие сервера просьбой о повторе не является
	if(!hello::retry(answer)){
		/**
		 * Выполняем перебор заслонов понижения издания протокола
		 */
		for(size_t i = 0; i < (sizeof(DOWNGRADE) / sizeof(DOWNGRADE[0])); i++){
			/**
			 * Заслон лежит в хвосте случайного значения сервера: раздел 4.1.3 RFC 8446
			 * велит клиенту, знающему издание 1.3, оборваться на нём, а не понижать
			 * издание вслед за сервером
			 */
			if(::memcmp(answer.random + (sizeof(answer.random) - sizeof(DOWNGRADE[i])), DOWNGRADE[i], sizeof(DOWNGRADE[i])) == 0)
				// Выводим отказ понижения издания протокола
				return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
		}
	}
	// Определяем место, которым идут разбираемые расширения
	const uint8_t place = (hello::retry(answer) ? PLACE_RETRY : PLACE_HELLO);
	/**
	 * Выполняем перебор расширений, объявленных приветствием сервера
	 */
	for(size_t i = 0; i < answer.extensions.size(); i++){
		// Места, в которых объявленному расширению идти дозволено
		uint8_t places = 0;
		/**
		 * Раздел 4.1.3 RFC 8446 кладёт приветствию сервера всего три расширения, а
		 * просьбе о повторе - три своих: всё прочее принадлежит защищённым расширениям
		 * и открытым приветствием идти не вправе.
		 *
		 * Извещения тут ДВА, и раздел 4.2 RFC 8446 их разводит: расширение, стороне
		 * ИЗВЕСТНОЕ, но пришедшее не в своём сообщении, обрывает связь извещением
		 * «illegal_parameter», а расширение, о котором сторона не просила вовсе, -
		 * извещением «unsupported_extension»
		 */
		if(placement(answer.extensions[i].type, places)){
			// Если известному расширению это место не отведено
			if((places & place) == 0)
				// Выводим отказ объявления расширения не в своём сообщении
				return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Выводим отказ объявления расширения, связью не предлагавшегося
		} else return this->abort(context::error_t::MESSAGE, alert::description_t::EXTENSION);
	}
	/**
	 * Раздел 4.2.1 RFC 8446 велит клиенту сверять расширение издания ПРЕЖДЕ разбора
	 * всего прочего в приветствии сервера, а раздел 9.2 требует расширения этого и от
	 * просьбы о повторе приветствия. Оттого сверка и стоит выше разветвления на
	 * приветствие и просьбу: ниже она просьбу о повторе не задевала бы вовсе, и связь
	 * шла бы по ней на новый круг, издания так и не сверив
	 */
	// Разыскиваем расширение издания протокола
	const hello::extension_t * item = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
	/**
	 * Приветствие сервера без расширения издания означает выбор издания, объявленного
	 * заголовком приветствия, - то есть TLS 1.2 либо более раннего. Приложение D.1 RFC
	 * 8446 велит клиенту обрывать связь по неподдерживаемому изданию извещением
	 * protocol_version, а не missing_extension: последнее раздел 9.2 держит для
	 * СЕРВЕРА, принявшего негодное приветствие клиента
	 */
	if(item == nullptr)
		// Выводим отказ несовпадения издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
	// Издание протокола, выбранное сервером
	uint16_t version = 0;
	// Если издание протокола разобрать не удалось
	if(extension::version(item->data, version) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	/**
	 * Раздел 4.2.1 RFC 8446 велит обрывать связь извещением illegal_parameter, если
	 * расширение издания несёт издание, клиентом не предложенное либо предшествующее
	 * TLS 1.3. Связь предлагает единственное издание, оттого оба случая и сходятся в
	 * одну сверку. Извещение здесь ИНОЕ, нежели при вовсе отсутствующем расширении:
	 * там сервер издания не объявлял и остался при заголовке, а тут объявил негодное
	 */
	if(version != 0x0304)
		// Выводим отказ негодного издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
	// Разыскиваем расширение открытой части ключа обмена
	const hello::extension_t * extension = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
	// Если открытая часть ключа обмена приветствием не объявлена
	if(extension == nullptr)
		// Выводим отказ отсутствия открытой части ключа обмена
		return this->abort(context::error_t::EXCHANGE, alert::description_t::MISSING);
	/**
	 * Просьба о повторе приветствия идёт тем же сообщением, что и приветствие сервера,
	 * и отличается лишь заранее назначенным случайным значением
	 */
	if(hello::retry(answer)){
		// Кривая обмена ключами, выбранная сервером
		extension::group_t group = extension::group_t::NONE;
		// Если выбранную сервером кривую обмена ключами разобрать не удалось
		if(extension::selected(extension->data, group) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Просить повтора сервер вправе лишь на кривой, которую клиент предложил и
		 * ключа по которой ещё не прислал: раздел 4.1.4 RFC 8446 запрещает и просьбу
		 * о кривой вне предложения, и просьбу о той, ключ по которой уже отправлен
		 */
		if(group == this->_group)
			// Выводим отказ просьбы о кривой, ключ по которой уже отправлен
			return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
		// Признак того, что выбранная сервером кривая связью предложена
		bool offered = false;
		/**
		 * Выполняем перебор кривых обмена ключами, предлагаемых связью
		 */
		for(size_t i = 0; (i < this->_groups.size()) && !offered; i++)
			// Запоминаем совпадение выбранной кривой с предложенной
			offered = (group == this->_groups[i]);
		// Если сервер попросил повтора на кривой, связью не предложенной
		if(!offered)
			// Выводим отказ просьбы о кривой вне предложения связи
			return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
		// Разыскиваем расширение метки возврата состояния сервера
		const hello::extension_t * label = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::COOKIE));
		// Если метка возврата состояния сервера просьбой объявлена
		if(label != nullptr){
			/**
			 * Выполняем перехват ошибок работы с памятью
			 */
			try {
				/**
				 * Раздел 4.2.2 RFC 8446 велит клиенту повторить метку в новом
				 * приветствии дословно: ею сервер возвращает себе состояние, которого
				 * он у себя не держал, и без неё повторное приветствие бесполезно
				 */
				this->_cookie.assign(label->data.data, label->data.data + label->data.size);
			/**
			 * Если памяти под метку возврата состояния не хватило
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
			}
		}
		/**
		 * Переписка рукопожатия заменяется хешем приветствия клиента: раздел 4.4.1
		 * RFC 8446 велит поступать так всякий раз при просьбе о повторе приветствия
		 */
		if(this->_transcript.replace() != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если просьбу о повторе в переписку рукопожатия добавить не удалось
		if(this->_transcript.update(message) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если просьбу о повторе ходу рукопожатия объявить не удалось
		if(this->_machine.accept(handshake::type_t::SERVER, session::side_t::SERVER) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Если просьба о повторе приветствия ходом рукопожатия отвергнута
		if(this->_machine.retry() != flow::error_t::NONE)
			// Выводим отказ объявления просьбы не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Выполняем выработку мимолётной пары ключей на выбранной кривой
		context::error_t error = this->exchange(group);
		// Если мимолётную пару ключей выработать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ выработки мимолётной пары ключей
			return this->abort(error, alert::description_t::HANDSHAKE);
		// Выполняем отправку повторного приветствия клиента
		error = this->greeting();
		// Если повторное приветствие клиента отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки приветствия клиента
			return this->abort(error, alert::description_t::INTERNAL);
		// Запоминаем, что повтор приветствия клиента уже был
		this->_retried = true;
		// Выводим успешность разбора просьбы о повторе приветствия
		return context::error_t::NONE;
	}
	// Разыскиваем расширение выбранного заранее разделённого ключа
	const hello::extension_t * selected = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SECRET));
	// Если сервер выбрал заранее разделённый ключ клиента
	if(selected != nullptr){
		// Место выбранного сервером ключа в предложении клиента
		uint16_t chosen = 0;
		// Если выбранный сервером ключ разобрать не удалось
		if(extension::chosen(selected->data, chosen) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Клиент предлагает единственный ключ, и всякое иное его место есть выбор
		 * того, чего клиент не предлагал вовсе. Той же сверкой удовлетворено и
		 * требование раздела 4.2.11 RFC 8446 о нулевом месте при объявленных сервером
		 * упреждающих данных: нулю здесь равно всякое принимаемое место.
		 *
		 * Сверки хеша набора шифрования с хешем ключа тут нет, и вот почему: все
		 * четыре набора, связью признаваемые, ведут расписание ключей на «Стрибоге»
		 * длиной 256 разрядов, и требование раздела 4.2.11 удовлетворено само собою.
		 * Появись набор с иным хешем - сверку эту заводить обязательно
		 */
		if((chosen != 0) || this->_resume.identity.empty())
			// Выводим отказ несовпадения заранее разделённого ключа
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Запоминаем возобновление связи заранее разделённым ключом
		this->_shared = true;
	/**
	 * Сервер вправе билет и не признать: тогда связь идёт полным рукопожатием, а
	 * начальная ступень расписания заводится заново - уже без ключа билета
	 */
	} else if(this->_secrets.stage() != session::stage_t::NONE)
		// Выполняем сброс значений расписания ключей связи
		this->_secrets.clear();
	// Открытая часть ключа обмена сервера
	extension::share_t share;
	// Если открытую часть ключа обмена сервера разобрать не удалось
	if(extension::share(extension->data, share) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Если сервер выбрал кривую обмена ключами, о которой его не просили
	if(share.group != this->_group)
		// Выводим отказ несовпадения кривой обмена ключами
		return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
	// Открытая часть ключа обмена сервера, из которой выводятся ключи связи
	const vector <uint8_t> key(share.key.data, share.key.data + share.key.size);
	// Если приветствие сервера в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Если приветствие сервера ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::SERVER, session::side_t::SERVER) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Выполняем вывод ключей рукопожатия связи
	const context::error_t error = this->derive(view_t(key.data(), key.size()));
	// Если ключи рукопожатия связи вывести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ вывода ключей рукопожатия связи
		return this->abort(error, alert::description_t::HANDSHAKE);
	// Выводим успешность разбора приветствия сервера
	return context::error_t::NONE;
}
/**
 * @brief Метод смены ключевого материала направления связи
 *
 * @param side сторона, чьё направление связи сменяется
 *
 * @return     отказ смены ключевого материала направления
 *
 */
context::error_t nts::internal::Engine::rotate(const session::side_t side) noexcept {
	// Если значение направления связи сменить не удалось
	if(this->_secrets.renew(side) != session::error_t::NONE)
		// Выводим отказ смены значения направления связи
		return context::error_t::SCHEDULE;
	// Место, в которое помещается корневой ключ направления связи
	uint8_t material[protect::PROTECT_KEY];
	// Место, в которое помещается вектор замены направления связи
	uint8_t element[protect::PROTECT_VECTOR];
	// Если ключевой материал направления связи вывести не удалось
	if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала направления
		return context::error_t::SCHEDULE;
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Получаем объект защиты записей стороны связи
	protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
	/**
	 * Установка ключевого материала обнуляет и счётчик записей направления: раздел
	 * 5.3 RFC 8446 велит считать записи заново от смены ключей
	 */
	const bool installed = protection.start(this->_suite, view_t(material, sizeof(material)), view_t(element, protect::block(this->_suite)));
	// Выполняем затирание вектора замены направления связи
	wipe(element, sizeof(element));
	// Выполняем затирание корневого ключа направления связи
	wipe(material, sizeof(material));
	// Выводим итог установки ключевого материала направления связи
	return (installed ? context::error_t::NONE : context::error_t::SCHEDULE);
}
/**
 * @brief Метод разбора принятой смены ключевого материала
 *
 * @param body тело принятого сообщения смены ключевого материала
 *
 * @return     отказ разбора смены ключевого материала
 *
 */
context::error_t nts::internal::Engine::renew(const view_t & body) noexcept {
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ прихода смены ключей не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	// Разбираемый вид смены ключевого материала
	message::update_t update = message::update_t::NOTIFY;
	// Если сообщение смены ключевого материала разобрать не удалось
	if(message::parse(body, update) != message::error_t::NONE)
		// Выводим отказ разбора сообщения смены ключевого материала
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	/**
	 * Ход рукопожатия за установленной связью смену ключевого материала принимает от
	 * всякой стороны, а состояние связи сличено выше: через связь заслон этот
	 * недостижим и стоит обороною на случай расхождения состояния с ходом
	 */
	if(this->_machine.accept(handshake::type_t::UPDATE, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Выполняем смену ключевого материала направления собеседника
	const context::error_t error = this->rotate(side);
	// Если ключевой материал направления собеседника сменить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ смены ключевого материала направления
		return this->abort(error, alert::description_t::INTERNAL);
	// Сбрасываем признак испрошенной у собеседника смены ключей: ключи сменены
	this->_asked = false;
	// Если собеседник просит сменить ключи своего направления в ответ
	if(update == message::update_t::REQUEST)
		// Выводим итог смены ключевого материала своего направления
		return this->update(false);
	// Выводим успешность разбора смены ключевого материала
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода значения возобновления связи
 *
 * @return отказ вывода значения возобновления связи
 *
 */
context::error_t nts::internal::Engine::keeping() noexcept {
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	// Если значение возобновления связи вывести не удалось
	if(this->_secrets.resumption(view_t(transcript, sizeof(transcript))) != session::error_t::NONE)
		// Выводим отказ вывода значения расписания ключей
		return context::error_t::SCHEDULE;
	// Выводим успешность вывода значения возобновления связи
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого билета возобновления связи
 *
 * @param body тело принятого сообщения билета
 *
 * @return     отказ разбора билета возобновления связи
 *
 */
context::error_t nts::internal::Engine::accept(const view_t & body) noexcept {
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ прихода билета не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Разбираемый билет возобновления связи
	message::ticket_t ticket;
	// Если билет возобновления связи разобрать не удалось
	if(message::parse(body, ticket) != message::error_t::NONE)
		// Выводим отказ разбора билета возобновления связи
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	/**
	 * Сторона задана здесь постоянной, и ход рукопожатия за установленной связью
	 * сличает её сам с собою: через связь заслон недостижим. Постоянная эта верна -
	 * билет от сервера, и приход его серверу отвергается разбором раньше
	 */
	if(this->_machine.accept(handshake::type_t::TICKET, session::side_t::SERVER) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	/**
	 * Раздел 4.6.1 RFC 8446 кладёт сроку билета предел в семь суток и запрещает
	 * держать билет дольше: билет с большим сроком означает сервер, зовущий связь
	 * возобновляться ключом, которому давно вышел срок
	 */
	if(ticket.lifetime > LIFETIME)
		// Выводим отказ выхода срока билета за дозволенный предел
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	// Принятый билет возобновления связи
	context::ticket_t item;
	// Устанавливаем набор шифрования связи, выдавшей билет
	item.suite = this->_suite;
	// Устанавливаем миг выдачи принятого билета
	item.moment = this->_moment;
	// Устанавливаем срок жизни принятого билета
	item.lifetime = ticket.lifetime;
	/**
	 * Выполняем перебор расширений принятого билета
	 */
	for(size_t i = 0; i < ticket.extensions.size(); i++){
		// Места, в которых объявленному расширению идти дозволено
		uint8_t places = 0;
		/**
		 * Раздел 4.2 RFC 8446 кладёт билету возобновления связи одно-единственное
		 * расширение - предел упреждающих данных, - и признаваемое расширение вне его
		 * обрывает связь извещением «illegal_parameter»
		 */
		if(placement(ticket.extensions[i].type, places) && ((places & PLACE_TICKET) == 0))
			// Выводим отказ объявления расширения не в своём сообщении
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Если расширение билета предела упреждающих данных не объявляет
		if(ticket.extensions[i].type != static_cast <uint16_t> (extension::type_t::EARLY))
			// Переходим к следующему расширению билета
			continue;
		// Если предел упреждающих данных разобрать не удалось
		if(extension::early(ticket.extensions[i].data, item.advance) != extension::error_t::NONE)
			// Выводим отказ разбора билета возобновления связи
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	}
	// Устанавливаем добавку к возрасту принятого билета
	item.age = ticket.age;
	// Место, в которое помещается ключ принятого билета
	uint8_t secret[schedule::SCHEDULE_SECRET];
	// Если ключ принятого билета вывести не удалось
	if(this->_secrets.ticket(ticket.nonce, secret) != session::error_t::NONE)
		// Выводим отказ вывода ключа билета возобновления связи
		return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
	/**
	 * Выполняем складывание принятого билета возобновления связи
	 */
	try {
		// Запоминаем прикладной протокол связи, принявшей билет
		item.protocol = this->_protocol;
		// Переносим тело принятого билета возобновления связи
		item.identity.assign(ticket.data.data, ticket.data.data + ticket.data.size);
		// Переносим ключ принятого билета возобновления связи
		item.secret.assign(secret, secret + sizeof(secret));
		// Добавляем принятый билет в перечень билетов связи
		this->_tickets.push_back(item);
	// Если памяти под билет не хватило
	} catch(const bad_alloc &) {
		// Выполняем затирание ключа принятого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем затирание ключа принятого билета
	wipe(secret, sizeof(secret));
	// Выводим успешность разбора билета возобновления связи
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого извещения
 *
 * @param data принятое извещение
 *
 * @return     отказ разбора принятого извещения
 *
 */
context::error_t nts::internal::Engine::notice(const view_t & data) noexcept {
	// Разбираемое извещение собеседника
	alert::alert_t alert;
	// Если извещение собеседника разобрать не удалось
	if(alert::parse(data, alert) != alert::error_t::NONE)
		// Выводим отказ разбора извещения собеседника
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Запоминаем извещение, принятое от собеседника
	this->_alert = alert;
	/**
	 * Решение о разрыве связи принимается по описанию извещения: раздел 6.2 RFC 8446
	 * объявляет уровень извещения в издании TLS 1.3 не имеющим значения
	 */
	if(alert::fatal(alert)){
		// Запоминаем отказ, которым связь оборвана
		this->_error = context::error_t::ALERT;
		// Переводим связь в состояние обрыва
		this->_state = context::state_t::FAILED;
		// Выводим отказ обрыва связи собеседником
		return context::error_t::ALERT;
	}
	// Если собеседник завершил передачу данных
	if(alert.description == alert::description_t::CLOSE)
		// Переводим связь в состояние закрытия
		this->_state = context::state_t::CLOSED;
	// Выводим успешность разбора извещения собеседника
	return context::error_t::NONE;
}
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
context::error_t nts::internal::Engine::handle(const handshake::type_t type, const view_t & body, const view_t & message) noexcept {
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	// Если принят билет возобновления связи
	if(type == handshake::type_t::TICKET)
		// Выводим итог разбора билета возобновления связи
		return (this->_server ? this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED) : this->accept(body));
	// Если принята смена ключевого материала собеседника
	if(type == handshake::type_t::UPDATE)
		// Выводим итог разбора смены ключевого материала
		return this->renew(body);
	// Если принято приветствие стороны связи
	if(type == handshake::type_t::CLIENT)
		// Выводим итог разбора приветствия клиента
		return (this->_server ? this->incoming(body, message) : this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED));
	// Если принято приветствие сервера
	if(type == handshake::type_t::SERVER)
		// Выводим итог разбора приветствия сервера
		return (this->_server ? this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED) : this->outgoing(body, message));
	// Отказ разбора принятого сообщения рукопожатия
	context::error_t error = context::error_t::NONE;
	/**
	 * Выполняем определение вида принятого сообщения рукопожатия
	 */
	switch(static_cast <uint8_t> (type)){
		// Если приняты защищённые расширения сервера
		case static_cast <uint8_t> (handshake::type_t::EXTENSIONS): {
			// Если связь ведётся стороной сервера
			if(this->_server)
				// Выводим отказ прихода сообщения не от той стороны
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Перечень видов расширений, объявленных сервером
			vector <uint16_t> types;
			// Если перечень защищённых расширений сервера разобрать не удалось
			if(!enumerate(body, types))
				// Выводим отказ разбора защищённых расширений сервера
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			/**
			 * Выполняем перебор расширений, объявленных сервером
			 */
			for(size_t i = 0; i < types.size(); i++){
				// Места, в которых объявленному расширению идти дозволено
				uint8_t places = 0;
				/**
				 * Раздел 4.2 RFC 8446 отводит защищённым расширениям свой перечень
				 * видов, и признаваемое расширение вне его обрывает связь извещением
				 * «illegal_parameter». Заслон этот НЕ покрывается сверкой с
				 * предложенным ниже: открытая часть ключа обмена, издание протокола,
				 * заранее разделённый ключ, способы обмена им, метка возврата состояния
				 * и схемы подписи связью предлагаются все, а защищённым расширениям не
				 * положено ни одно из них
				 */
				if(placement(types[i], places) && ((places & PLACE_GUARDED) == 0))
					// Выводим отказ объявления расширения не в своём сообщении
					return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
				// Признак того, что объявленное сервером расширение связью предлагалось
				bool suitable = false;
				/**
				 * Выполняем перебор расширений, предложенных связью приветствием
				 */
				for(size_t j = 0; (j < this->_offered.size()) && !suitable; j++)
					// Запоминаем, предлагалось ли объявленное сервером расширение связью
					suitable = (types[i] == this->_offered[j]);
				/**
				 * Раздел 4.2 RFC 8446 велит клиенту оборваться на расширении, которого
				 * он не просил, извещением «unsupported_extension»: ответ на
				 * непрошенное означает, что сервер отвечает не тому приветствию
				 */
				if(!suitable)
					// Выводим отказ объявления непрошенного расширения
					return this->abort(context::error_t::EXTENSION, alert::description_t::EXTENSION);
			}
			/**
			 * Приём упреждающих данных сервер объявляет расширением: раздел 4.2.10
			 * RFC 8446 велит объявлять его именно здесь, а не приветствием
			 */
			this->_accepted = (this->_earlying && declared(body, static_cast <uint16_t> (extension::type_t::EARLY)));
			/**
			 * Отвергнутые упреждающие данные пропали: связь возвращается к ключам
			 * рукопожатия, а посланное ими сервер не прочтёт вовсе
			 */
			if(!this->_accepted)
				// Прекращаем ход упреждающих данных связи
				this->_earlying = false;
			// Тело расширения выбранного сервером прикладного протокола
			view_t chosen;
			// Если прикладной протокол сервером объявлен
			if(announced(body, static_cast <uint16_t> (extension::type_t::PROTOCOLS), chosen)){
				// Название прикладного протокола, выбранного сервером
				string selected;
				// Если выбранный сервером прикладной протокол разобрать не удалось
				if(extension::protocol(chosen, selected) != extension::error_t::NONE)
					// Выводим отказ разбора защищённых расширений сервера
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				// Признак того, что выбранный протокол связью предлагался
				bool suitable = false;
				/**
				 * Выполняем перебор прикладных протоколов, предложенных связью
				 */
				for(size_t i = 0; (i < this->_protocols.size()) && !suitable; i++)
					// Запоминаем, предлагался ли выбранный сервером протокол связью
					suitable = (selected.compare(this->_protocols[i]) == 0);
				/**
				 * Раздел 3.2 RFC 7301: сервер выбирает лишь из того, что ему предложено,
				 * и протокол вне предложения принимать нельзя - им связь пошла бы
				 * протоколом, которого сторона не понимает
				 */
				if(!suitable)
					// Выводим отказ отсутствия общего прикладного протокола
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
				/**
				 * Выполняем перехват ошибок работы с памятью
				 */
				try {
					// Запоминаем выбранный сторонами прикладной протокол
					this->_protocol = ::move(selected);
				/**
				 * Если памяти под название протокола не хватило
				 */
				} catch(const std::bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
			}
		} break;
		// Если принят конец упреждающих данных клиента
		case static_cast <uint8_t> (handshake::type_t::EARLY): {
			// Если связь ведётся стороной клиента
			if(!this->_server)
				// Выводим отказ прихода сообщения не от той стороны
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			/**
			 * Раздел 4.5 RFC 8446: конец упреждающих данных закрывает поток, идущий
			 * ключами упреждения, и слать его клиенту дозволено лишь тогда, когда
			 * сервер упреждающие данные принял. Не принял - потока нет, закрывать
			 * нечего, а сообщение это идёт уже ключами рукопожатия и означает
			 * собеседника, ведущего свой счёт ходу связи
			 */
			if(!this->_earlying)
				// Выводим отказ прихода конца упреждающих данных не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			/**
			 * Раздел 4.5 RFC 8446 кладёт концу упреждающих данных пустое тело: всё,
			 * что за ним идёт, объявляется извещением «decode_error»
			 */
			if(body.size > 0)
				// Выводим отказ лишних байтов за телом сообщения
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			// Прекращаем приём упреждающих данных клиента
			this->_earlying = false;
		} break;
		// Если принят запрос подлинности клиента
		case static_cast <uint8_t> (handshake::type_t::REQUEST): {
			// Выполняем разбор запроса подлинности клиента
			error = this->requesting(body);
			// Если запрос подлинности клиента разобрать не удалось
			if(error != context::error_t::NONE)
				/**
				 * Раздел 4.3.2 RFC 8446: отсутствие схем подписи объявляется извещением
				 * «missing_extension», расширение не в своём сообщении -
				 * «illegal_parameter», а негодная запись запроса - «decode_error»
				 */
				return this->abort(error, ((error == context::error_t::SCHEME) ? alert::description_t::MISSING :
					((error == context::error_t::EXTENSION) ? alert::description_t::PARAMETER : alert::description_t::DECODE)));
			// Запоминаем, что подлинность клиента запрошена сервером
			this->_requested = true;
		} break;
		// Если принята цепочка сертификатов собеседника
		case static_cast <uint8_t> (handshake::type_t::CERTIFICATE): {
			// Выполняем разбор цепочки сертификатов собеседника
			error = this->chain(body);
			// Если цепочку сертификатов собеседника разобрать не удалось
			if(error != context::error_t::NONE)
				/**
				 * Раздел 4.2 RFC 8446: непрошенное расширение объявляется извещением
				 * «unsupported_extension», а негодная цепочка - «bad_certificate»
				 */
				return this->abort(error, ((error == context::error_t::EXTENSION) ? alert::description_t::EXTENSION : alert::description_t::BADCERT));
		} break;
		// Если принята подпись владения ключом собеседника
		case static_cast <uint8_t> (handshake::type_t::VERIFY): {
			/**
			 * Подпись владения ключом сличается с перепиской до этого сообщения:
			 * себя самоё подпись не покрывает
			 */
			error = this->possession(body);
			// Если подпись владения ключом не сошлась
			if(error != context::error_t::NONE)
				/**
				 * Раздел 4.4.3 RFC 8446: несошедшаяся подпись объявляется извещением
				 * «decrypt_error», а непригодная схема подписи - «illegal_parameter»
				 */
				return this->abort(error, ((error == context::error_t::SCHEME) ? alert::description_t::PARAMETER : alert::description_t::DECRYPT));
		} break;
		// Если принято завершение рукопожатия собеседником
		case static_cast <uint8_t> (handshake::type_t::FINISHED): {
			/**
			 * Завершение рукопожатия сличается с перепиской до этого сообщения:
			 * себя самоё завершение не покрывает
			 */
			error = this->confirm(body);
			// Если завершение рукопожатия собеседника не сошлось
			if(error != context::error_t::NONE)
				// Выводим отказ схождения завершения рукопожатия
				return this->abort(error, alert::description_t::DECRYPT);
		} break;
		// Если принято сообщение, связью не поддержанное
		default: return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	}
	// Если сообщение в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Если сообщение ходу рукопожатия объявить не удалось
	if(this->_machine.accept(type, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Если принято не завершение рукопожатия собеседником
	if(type != handshake::type_t::FINISHED)
		// Выводим успешность разбора сообщения рукопожатия
		return context::error_t::NONE;
	// Если связь ведётся стороной клиента
	if(!this->_server){
		// Выполняем вывод ключей прикладных данных связи
		error = this->mature();
		// Если ключи прикладных данных вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода ключей прикладных данных
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем согласование ключевого материала защиты записей
		error = this->refresh();
		// Если ключевой материал защиты записей согласовать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ согласования ключевого материала
			return this->abort(error, alert::description_t::INTERNAL);
		// Если упреждающие данные связи приняты сервером
		if(this->_earlying){
			/**
			 * Конец упреждающих данных уходит их же ключами: раздел 4.5 RFC 8446 велит
			 * закрывать поток теми ключами, какими он и шёл
			 */
			error = this->send(handshake::type_t::EARLY, view_t(nullptr, 0));
			// Если конец упреждающих данных отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки конца упреждающих данных
				return this->abort(error, alert::description_t::INTERNAL);
			// Прекращаем ход упреждающих данных связи
			this->_earlying = false;
		}
		// Если подлинность клиента запрошена сервером
		if(this->_requested){
			// Выполняем отправку подтверждения подлинности клиента
			error = this->authenticate();
			// Если подтверждение подлинности клиента отправить не удалось
			if(error != context::error_t::NONE)
				/**
				 * Раздел 4.4.3 RFC 8446: отсутствие схемы подписи, признаваемой обеими
				 * сторонами, есть несхождение сторон, а не внутренний отказ
				 */
				return this->abort(error, ((error == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::INTERNAL));
		}
		// Выполняем отправку завершения рукопожатия клиентом
		error = this->complete();
		// Если завершение рукопожатия клиентом отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки завершения рукопожатия
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем вывод значения возобновления связи
		error = this->keeping();
		// Если значение возобновления связи вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода значения возобновления связи
			return this->abort(error, alert::description_t::INTERNAL);
	// Если связь ведётся стороной сервера
	} else {
		// Выполняем согласование ключевого материала защиты записей
		error = this->refresh();
		// Если ключевой материал защиты записей согласовать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ согласования ключевого материала
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем вывод значения возобновления связи
		error = this->keeping();
		// Если значение возобновления связи вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода значения возобновления связи
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Если рукопожатие связи завершено обеими сторонами
	if(this->_machine.established())
		// Переводим связь в состояние установленной связи
		this->_state = context::state_t::ESTABLISHED;
	// Выводим успешность разбора сообщения рукопожатия
	return context::error_t::NONE;
}
/**
 * @brief Метод получения состояния связи
 *
 * @return состояние связи
 *
 */
context::state_t nts::internal::Engine::state() const noexcept {
	// Выводим состояние связи
	return this->_state;
}
/**
 * @brief Метод получения отказа, которым связь оборвана
 *
 * @return отказ, которым связь оборвана
 *
 */
context::error_t nts::internal::Engine::error() const noexcept {
	// Выводим отказ, которым связь оборвана
	return this->_error;
}
/**
 * @brief Метод получения извещения, которым связь оборвана
 *
 * @return извещение, которым связь оборвана
 *
 */
const alert::alert_t & nts::internal::Engine::alert() const noexcept {
	// Выводим извещение, которым связь оборвана
	return this->_alert;
}
/**
 * @brief Метод получения набора шифрования связи
 *
 * @return согласованный сторонами набор шифрования
 *
 */
protect::suite_t nts::internal::Engine::suite() const noexcept {
	// Выводим согласованный сторонами набор шифрования
	return this->_suite;
}
/**
 * @brief Метод получения цепочки сертификатов собеседника
 *
 * @return цепочка сертификатов, предъявленная собеседником
 *
 */
const vector <vector <uint8_t>> & nts::internal::Engine::peer() const noexcept {
	// Выводим цепочку сертификатов, предъявленную собеседником
	return this->_peer;
}
/**
 * @brief Метод получения имени узла связи
 *
 * @return имя узла, запрошенное клиентом у сервера
 *
 */
const string & nts::internal::Engine::name() const noexcept {
	// Выводим имя узла, запрошенное клиентом у сервера
	return this->_name;
}
/**
 * @brief Метод получения прикладного протокола связи
 *
 * @return прикладной протокол, выбранный сторонами связи
 *
 */
const string & nts::internal::Engine::protocol() const noexcept {
	// Выводим прикладной протокол, выбранный сторонами связи
	return this->_protocol;
}
/**
 * @brief Метод установки предлагаемых наборов шифрования
 *
 * @param suites устанавливаемые наборы шифрования
 *
 */
void nts::internal::Engine::suites(const vector <protect::suite_t> & suites) noexcept {
	// Если предлагаемые наборы шифрования переданы
	if(!suites.empty())
		// Запоминаем предлагаемые наборы шифрования
		this->_suites = suites;
}
/**
 * @brief Метод установки предлагаемых кривых обмена ключами
 *
 * @param groups устанавливаемые кривые обмена ключами
 *
 */
void nts::internal::Engine::groups(const vector <extension::group_t> & groups) noexcept {
	// Если предлагаемые кривые обмена ключами переданы
	if(!groups.empty())
		// Запоминаем предлагаемые кривые обмена ключами
		this->_groups = groups;
}
/**
 * @brief Метод установки подлинности своей стороны связи
 *
 * @param credential устанавливаемая подлинность своей стороны
 *
 */
void nts::internal::Engine::credential(const context::credential_t & credential) noexcept {
	// Запоминаем подлинность своей стороны связи
	this->_credential = credential;
}
/**
 * @brief Метод установки имени узла, запрашиваемого у сервера
 *
 * @param name устанавливаемое имя узла
 *
 */
void nts::internal::Engine::name(const string & name) noexcept {
	// Запоминаем имя узла, запрашиваемое у сервера
	this->_name = name;
}
/**
 * @brief Метод установки предлагаемых прикладных протоколов
 *
 * @param protocols устанавливаемые прикладные протоколы
 *
 */
void nts::internal::Engine::protocols(const vector <string> & protocols) noexcept {
	// Запоминаем предлагаемые прикладные протоколы связи
	this->_protocols = protocols;
}
/**
 * @brief Метод установки метки возврата состояния сервера
 *
 * @param cookie устанавливаемая метка возврата состояния
 *
 */
void nts::internal::Engine::cookie(const vector <uint8_t> & cookie) noexcept {
	// Запоминаем метку возврата состояния, выдаваемую просьбой о повторе
	this->_cookie = cookie;
}
/**
 * @brief Метод получения метки возврата состояния сервера
 *
 * @return метка возврата состояния, принятая от собеседника
 *
 */
const vector <uint8_t> & nts::internal::Engine::cookie() const noexcept {
	/**
	 * Сервер получает метку повтором приветствия клиента, а клиент - самой просьбой
	 * о повторе: сторонам возвращается то, что каждая из них приняла
	 */
	return (this->_server ? this->_label : this->_cookie);
}
/**
 * @brief Метод установки мига, которым судятся сроки билетов
 *
 * @param moment устанавливаемый миг в секундах
 *
 */
void nts::internal::Engine::moment(const int64_t moment) noexcept {
	// Запоминаем миг, которым связь судит сроки билетов
	this->_moment = moment;
}
/**
 * @brief Метод установки билета возобновления связи клиентом
 *
 * @param ticket предъявляемый билет возобновления связи
 *
 */
void nts::internal::Engine::resume(const context::ticket_t & ticket) noexcept {
	// Запоминаем билет, предъявляемый на возобновление связи
	this->_resume = ticket;
}
/**
 * @brief Метод установки билетов, признаваемых сервером
 *
 * @param tickets признаваемые билеты возобновления связи
 *
 */
void nts::internal::Engine::resume(const vector <context::ticket_t> & tickets) noexcept {
	// Запоминаем билеты, признаваемые на возобновление связи
	this->_store = tickets;
}
/**
 * @brief Метод проверки возобновления связи заранее разделённым ключом
 *
 * @return признак того, что связь возобновлена билетом
 *
 */
bool nts::internal::Engine::shared() const noexcept {
	// Выводим признак возобновления связи билетом
	return this->_shared;
}
/**
 * @brief Метод установки предложения упреждающих данных
 *
 * @param advance устанавливаемое предложение упреждающих данных
 *
 */
void nts::internal::Engine::advance(const bool advance, const uint32_t limit) noexcept {
	// Запоминаем предложение упреждающих данных связи
	this->_advance = advance;
	// Запоминаем предел упреждающих данных связи
	this->_limit = limit;
}
/**
 * @brief Метод проверки приёма упреждающих данных собеседником
 *
 * @return признак того, что упреждающие данные приняты
 *
 */
bool nts::internal::Engine::accepted() const noexcept {
	// Выводим признак приёма упреждающих данных собеседником
	return this->_accepted;
}
/**
 * @brief Метод установки требования подлинности клиента
 *
 * @param request устанавливаемое требование подлинности клиента
 *
 */
void nts::internal::Engine::request(const bool request) noexcept {
	// Запоминаем требование подлинности клиента
	this->_request = request;
}
/**
 * @brief Метод установки порядка смены ключей по счётчику записей
 *
 * @param automatic сменяет ли движок ключи сам по счётчику записей
 * @param records   число записей направления, по которому идёт смена
 *
 */
void nts::internal::Engine::renewal(const bool automatic, const uint64_t records) noexcept {
	// Запоминаем порядок смены ключей по счётчику записей
	this->_automatic = automatic;
	// Запоминаем число записей направления, по которому сменяются ключи
	this->_renewal = records;
}
/**
 * @brief Метод получения счётчика записей направления связи
 *
 * @param incoming запрашивается ли направление собеседника
 *
 * @return         число записей направления на текущих ключах
 *
 */
uint64_t nts::internal::Engine::sequence(const bool incoming) const noexcept {
	// Выводим счётчик записей запрошенного направления связи
	return (incoming ? this->_input.sequence() : this->_output.sequence());
}
/**
 * @brief Метод смены ключей своего направления по счётчику записей
 *
 * @return отказ смены ключевого материала своего направления
 *
 */
context::error_t nts::internal::Engine::refreshing() noexcept {
	// Если ключи по счётчику записей движком не сменяются либо связь не установлена
	if(!this->_automatic || (this->_state != context::state_t::ESTABLISHED))
		// Выводим успешность: смена ключей остаётся за тем, кто связь ведёт
		return context::error_t::NONE;
	/**
	 * Раздел 5.5 RFC 8446 велит сменять ключи впереди предела порядковых номеров.
	 * По умолчанию смена идёт с половины предела набора шифрования: столько же
	 * места остаётся собеседнику ответить на просьбу о встречной смене, сколько
	 * берёт себе своё направление
	 */
	const uint64_t threshold = ((this->_renewal > 0) ? this->_renewal : (protect::limit(this->_suite) / 2));
	// Если счётчик записей своего направления до смены ключей не дошёл
	if(this->_output.sequence() < threshold)
		// Выводим успешность: ключи менять рано
		return context::error_t::NONE;
	// Выводим итог смены ключевого материала своего направления связи
	return this->update(false);
}
/**
 * @brief Метод заведения связи
 *
 * @return отказ заведения связи
 *
 */
context::error_t nts::internal::Engine::start() noexcept {
	// Если связь уже заведена
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Заслон этот через общедоступный договор недостижим: установщики наборов
	 * шифрования и кривых обмена ключами пустой список пропускают, сохраняя
	 * умолчания, и опустошить наборы потребителю нечем. Стоит он ради самого движка,
	 * если наборы эти когда-либо станут опустошаемы
	 */
	/**
	 * Заслон этот через фасад недостижим: сеттеры перечней пустой перечень пропускают,
	 * оставляя умолчание, и пустыми перечни быть не могут. Стоит он ради связности:
	 * рукопожатие без единого набора шифрования молча начинаться не должно
	 */
	if(this->_suites.empty() || this->_groups.empty())
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Сервер без своей подлинности связь завести не вправе: подтверждать её ему нечем,
	 * а рукопожатие на заранее разделённом ключе связью пока не ведётся
	 */
	if(this->_server && (this->_credential.chain.empty() || this->_credential.secret.empty()))
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	// Если ход рукопожатия связи завести не удалось
	if(!this->_machine.start(this->_server ? flow::role_t::SERVER : flow::role_t::CLIENT))
		// Выводим отказ заведения хода рукопожатия
		return context::error_t::STATE;
	// Выполняем начало переписки рукопожатия связи
	this->_transcript.start();
	// Переводим связь в состояние рукопожатия
	this->_state = context::state_t::HANDSHAKE;
	// Выполняем выработку случайного значения своего приветствия
	if(!entropy::bytes(this->_random, sizeof(this->_random)))
		// Выводим отказ выработки случайного значения приветствия
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Если связь ведётся стороной сервера
	if(this->_server)
		// Выводим успешность заведения связи: сервер ждёт приветствия клиента
		return context::error_t::NONE;
	/**
	 * Выполняем заведение опознавателя связи, доставшегося от предыдущих изданий
	 */
	try {
		// Занимаем место под опознаватель связи
		this->_session.assign(hello::HELLO_SESSION, 0);
	// Если памяти под опознаватель связи не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если опознаватель связи выработать не удалось
	if(!entropy::bytes(this->_session.data(), this->_session.size()))
		// Выводим отказ выработки опознавателя связи
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Выполняем выработку мимолётной пары ключей своей стороны
	const context::error_t error = this->exchange(this->_groups[0]);
	// Если мимолётную пару ключей выработать не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ выработки мимолётной пары ключей
		return this->abort(error, alert::description_t::INTERNAL);
	// Выводим итог отправки приветствия клиента
	return this->greeting();
}
/**
 * @brief Метод сброса состояния связи
 *
 */
void nts::internal::Engine::clear() noexcept {
	// Выполняем сброс состояния связи
	this->_state = context::state_t::NONE;
	// Выполняем сброс отказа, которым связь оборвана
	this->_error = context::error_t::NONE;
	// Выполняем сброс признака запроса подлинности клиента
	this->_requested = false;
	// Выполняем сброс признака повтора приветствия клиента
	this->_retried = false;
	// Выполняем сброс признака возобновления связи билетом
	this->_shared = false;
	// Выполняем сброс признака хода упреждающих данных
	this->_earlying = false;
	// Выполняем сброс набора шифрования билета возобновления связи
	this->_ticket = protect::suite_t::NONE;
	// Выполняем сброс признака приёма упреждающих данных
	this->_accepted = false;
	// Выполняем сброс числа пропущенных записей упреждающих данных
	this->_skipped = 0;
	// Выполняем сброс признака испрошенной у собеседника смены ключей
	this->_asked = false;
	// Выполняем сброс размера прошедших упреждающих данных
	this->_passed = 0;
	// Выполняем сброс перечня расширений, предложенных приветствием
	this->_offered.clear();
	// Выполняем сброс метки возврата состояния, принятой от собеседника
	this->_label.clear();
	// Выполняем сброс схем подписи, признаваемых собеседником
	this->_schemes.clear();
	// Выполняем сброс опознавателя принятого запроса подлинности
	this->_binding.clear();
	// Выполняем сброс прикладного протокола связи, выдавшей билет
	this->_previous.clear();
	// Выполняем сброс защиты записей упреждающих данных
	this->_early.clear();
	// Выполняем сброс хода рукопожатия связи
	this->_machine.clear();
	// Выполняем сброс переписки рукопожатия связи
	this->_transcript.clear();
	// Выполняем сброс значений расписания ключей связи
	this->_secrets.clear();
	// Выполняем сброс сборщика входящих записей связи
	this->_records.clear();
	// Выполняем сброс сборщика входящих сообщений рукопожатия
	this->_messages.clear();
	// Выполняем сброс защиты отправляемых записей связи
	this->_output.clear();
	// Выполняем сброс защиты принимаемых записей связи
	this->_input.clear();
	// Выполняем сброс поры ключей записей клиента
	this->_epoch[0] = flow::epoch_t::PLAIN;
	// Выполняем сброс поры ключей записей сервера
	this->_epoch[1] = flow::epoch_t::PLAIN;
	// Выполняем затирание ключей завершения рукопожатия сторон
	wipe(this->_completion, sizeof(this->_completion));
	// Выполняем затирание ключевого материала прикладных данных
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание векторов замены прикладных данных
	wipe(this->_vector, sizeof(this->_vector));
	// Если секретный мимолётный ключ своей стороны выработан
	if(!this->_secret.empty())
		// Выполняем затирание секретного мимолётного ключа
		wipe(this->_secret.data(), this->_secret.size());
	// Выполняем сброс секретного мимолётного ключа своей стороны
	this->_secret.clear();
	// Выполняем сброс открытого мимолётного ключа своей стороны
	this->_opened.clear();
	// Если накопитель принятых прикладных данных не пуст
	if(!this->_plain.empty())
		// Выполняем затирание принятых прикладных данных
		wipe(this->_plain.data(), this->_plain.size());
	// Выполняем сброс накопителя принятых прикладных данных
	this->_plain.clear();
	// Выполняем сброс накопителя отправляемых байтов связи
	this->_wire.clear();
	// Выполняем сброс цепочки сертификатов собеседника
	this->_peer.clear();
	// Выполняем сброс прикладного протокола, выбранного сторонами
	this->_protocol.clear();
	/**
	 * Имя узла сбрасывается лишь стороной сервера: у клиента оно объявляет, за каким
	 * узлом он идёт, и настройкой этой связь распоряжаться не вправе
	 */
	if(this->_server)
		// Выполняем сброс имени узла, запрошенного клиентом
		this->_name.clear();
	/**
	 * Метка возврата состояния сбрасывается лишь стороной клиента: у сервера она
	 * настройка, которой связь распоряжаться не вправе, а у клиента - состояние,
	 * доставшееся от просьбы о повторе приветствия
	 */
	if(!this->_server)
		// Выполняем сброс метки возврата состояния сервера
		this->_cookie.clear();
	/**
	 * Выполняем перебор билетов возобновления связи
	 */
	for(size_t i = 0; i < this->_tickets.size(); i++)
		// Выполняем затирание ключа очередного билета возобновления связи
		wipe(this->_tickets[i].secret.data(), this->_tickets[i].secret.size());
	// Выполняем сброс билетов возобновления связи
	this->_tickets.clear();
	// Выполняем сброс опознавателя связи
	this->_session.clear();
	// Выполняем затирание случайного значения своего приветствия
	wipe(this->_random, sizeof(this->_random));
	// Выполняем сброс эллиптической кривой обмена ключами
	this->_curve.clear();
}
/**
 * @brief Метод подачи связи принятых байтов
 *
 * @param data принятые байты связи
 *
 * @return     отказ разбора принятых байтов
 *
 */
context::error_t nts::internal::Engine::push(const view_t & data) noexcept {
	// Если связь ещё не заведена либо уже оборвана
	if((this->_state == context::state_t::NONE) || (this->_state == context::state_t::FAILED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Сборщик записей отказывает единственно нехваткой памяти под накопитель: сам
	 * разбор идёт позже, отдельным вызовом. Отвечать здесь извещением о переросшей
	 * записи значило бы выдавать свою беду за оплошность собеседника, и раздел 6.2
	 * RFC 8446 велит на свои беды отвечать извещением о внутреннем отказе
	 */
	if(this->_records.push(data) != record::error_t::NONE)
		// Выводим отказ нехватки памяти под накопитель записей
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	// Заголовок принятой записи связи
	record::header_t header;
	// Содержимое принятой записи связи
	view_t payload;
	/**
	 * Выполняем перебор принятых записей связи
	 */
	while(true){
		// Выполняем сборку очередной принятой записи связи
		const record::error_t taken = this->_records.next(header, payload);
		// Если данных для целой записи ещё не набралось
		if(taken == record::error_t::HUNGRY)
			// Прекращаем перебор принятых записей связи
			break;
		/**
		 * Негодная запись прежде молча оставалась в накопителе, и связь на ней
		 * замирала: раздел 5.1 RFC 8446 велит отвечать на неё извещением, а слишком
		 * длинной записи - именно извещением «record_overflow»
		 */
		if(taken != record::error_t::NONE)
			// Выводим отказ разбора принятой записи связи
			return this->abort(context::error_t::RECORD, ((taken == record::error_t::LENGTH) ? alert::description_t::OVERSIZE : alert::description_t::UNEXPECTED));
		// Если принята запись смены набора шифрования
		if(header.type == record::type_t::CHANGE){
			/**
			 * Раздел 5 RFC 8446 велит пропускать эту запись лишь по ходу рукопожатия и
			 * лишь с единственным дозволенным значением: за установленной связью она
			 * не значит ничего, а иное её содержимое - это уже не она
			 */
			if((this->_state == context::state_t::ESTABLISHED) || (payload.size != 1) || (payload.data[0] != 0x01))
				// Выводим отказ прихода записи смены набора не в свой черёд
				return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
			// Пропускаем запись, доставшуюся от предыдущих изданий протокола
			continue;
		}
		// Получаем сторону связи собеседника
		const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
		// Вид содержимого принятой записи связи
		record::type_t type = header.type;
		// Накопитель, в который складывается открытое содержимое записи
		vector <uint8_t> opened;
		// Просмотр открытого содержимого принятой записи
		view_t content = payload;
		// Если принимаются упреждающие данные клиента
		if(this->_server && this->_earlying){
			// Если снять защиту упреждающих данных с принятой записи не удалось
			if(this->_early.open(header, payload, type, opened) != protect::error_t::NONE)
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(context::error_t::PROTECTION, alert::description_t::MAC);
			// Получаем открытое содержимое принятой записи
			content = view_t(opened.data(), opened.size());
		// Если записи собеседника защищены ключами связи
		} else if(this->_machine.epoch(side) != flow::epoch_t::PLAIN){
			// Если снять защиту с принятой записи не удалось
			if(this->_input.open(header, payload, type, opened) != protect::error_t::NONE){
				/**
				 * Упреждающие данные, сервером отвергнутые, прочесть нечем: раздел 4.2.10
				 * RFC 8446 велит такие записи пропускать, а не рвать по ним связь
				 */
				if(this->_server && (this->_skipped > 0)){
					// Уменьшаем число записей, дозволенных к пропуску
					this->_skipped--;
					// Переходим к следующей принятой записи связи
					continue;
				}
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(context::error_t::PROTECTION, alert::description_t::MAC);
			}
			/**
			 * Первая прочтённая запись закрывает пропуск отвергнутых упреждающих
			 * данных: за нею идут записи, защищённые ключами рукопожатия
			 */
			this->_skipped = 0;
			// Получаем открытое содержимое принятой записи
			content = view_t(opened.data(), opened.size());
			/**
			 * Раздел 5.5 RFC 8446 велит сменять ключи впереди предела порядковых номеров.
			 * Направление собеседника сменить самим нельзя - оттого у него испрашивается
			 * смена просьбою в собственном KeyUpdate, и просьба повторяется лишь после
			 * того, как собеседник ключи сменил. Записи рукопожатия за установленной
			 * связью - сама смена ключей и билеты - просьбы не будят: по ним счётчик
			 * собеседника вот-вот обнулится либо будет испрошен следующей записью
			 */
			if(this->_automatic && !this->_asked && (this->_state == context::state_t::ESTABLISHED) && (type != record::type_t::HANDSHAKE)){
				// Определяем число записей, по которому сменяются ключи
				const uint64_t threshold = ((this->_renewal > 0) ? this->_renewal : (protect::limit(this->_suite) / 2));
				// Если счётчик записей собеседника дошёл до смены ключей
				if(this->_input.sequence() >= threshold){
					// Запоминаем, что смена ключей у собеседника испрошена
					this->_asked = true;
					// Выполняем смену своих ключей с просьбою о встречной смене
					const context::error_t error = this->update(true);
					/**
					 * Заслон этот недостижим извне: смена ключей за установленной связью
					 * отказывает лишь на составлении собственного сообщения либо на
					 * нехватке памяти, а данными собеседника не управляется
					 */
					if(error != context::error_t::NONE)
						// Выводим отказ смены ключевого материала своего направления
						return this->abort(error, alert::description_t::INTERNAL);
				}
			}
		}
		/**
		 * Раздел 5.1 RFC 8446 запрещает перемежать сообщения рукопожатия записями
		 * иного содержимого: недособранное сообщение, разорванное чужой записью,
		 * означает собеседника, складывающего поток не по правилам
		 */
		if((type != record::type_t::HANDSHAKE) && (this->_messages.pending() > 0))
			// Выводим отказ разрыва сообщения рукопожатия чужой записью
			return this->abort(context::error_t::MESSAGE, alert::description_t::UNEXPECTED);
		/**
		 * Раздел 5.4 RFC 8446: запись рукопожатия либо извещения с пустым содержимым
		 * обрывает связь извещением unexpected_message. Заслон этот стережёт ИМЕННО
		 * защищённый путь: у незащищённой записи пустоту отвергает разбор заголовка,
		 * а у защищённой длину заголовка составляют шифртекст с меткой целостности, и
		 * пустота вскрывается лишь по снятии защиты
		 */
		if((content.size == 0) && !record::empty(type))
			// Выводим отказ пустого содержимого принятой записи
			return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
		/**
		 * Раздел 5.2 RFC 8446 кладёт открытому содержимому записи предел в 16384 байта:
		 * защита вправе раздуть запись набивкой, и предел этот стережёт уже вскрытое
		 * содержимое, а не пришедшую запись
		 */
		if(content.size > record::RECORD_PLAINTEXT)
			// Выводим отказ выхода открытого содержимого за дозволенный предел
			return this->abort(context::error_t::RECORD, alert::description_t::OVERSIZE);
		/**
		 * Раздел 6.1 RFC 8446 велит пропускать всё, что пришло за извещением о
		 * закрытии: собеседник свою передачу завершил, и пришедшее следом означает
		 * либо его собственную оплошность, либо чужую подделку. Обрыв связи здесь был
		 * бы неверен - стандарт велит именно пропускать
		 */
		if(this->_state == context::state_t::CLOSED)
			// Переходим к следующей принятой записи
			continue;
		// Отказ разбора открытого содержимого принятой записи
		context::error_t error = context::error_t::NONE;
		/**
		 * Выполняем определение вида содержимого принятой записи
		 */
		switch(static_cast <uint8_t> (type)){
			// Если принято извещение собеседника
			case static_cast <uint8_t> (record::type_t::ALERT): {
				// Выполняем разбор принятого извещения собеседника
				error = this->notice(content);
				// Если связь оборвана извещением собеседника
				if(error != context::error_t::NONE)
					// Выводим отказ обрыва связи собеседником
					return error;
			} break;
			// Если приняты сообщения рукопожатия собеседника
			case static_cast <uint8_t> (record::type_t::HANDSHAKE): {
				/**
				 * Сборщик сообщений отказывает единственно нехваткой памяти под
				 * накопитель: сам разбор идёт позже, отдельным вызовом. Извещение о
				 * негодном разборе выдало бы свою беду за оплошность собеседника
				 */
				if(this->_messages.push(content) != handshake::error_t::NONE)
					// Выводим отказ нехватки памяти под накопитель сообщений
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				// Заголовок принятого сообщения рукопожатия
				handshake::header_t item;
				// Тело принятого сообщения рукопожатия
				view_t body;
				// Отказ, которым сборщик ответил на выдачу очередного сообщения
				handshake::error_t outcome = handshake::error_t::NONE;
				/**
				 * Выполняем перебор принятых сообщений рукопожатия
				 */
				while((outcome = this->_messages.next(item, body)) == handshake::error_t::NONE){
					// Выполняем разбор принятого сообщения рукопожатия
					error = this->handle(item.type, body, this->_messages.message());
					// Если сообщение рукопожатия разобрать не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ разбора сообщения рукопожатия
						return error;
				}
				/**
				 * Нехваткой данных круг разбора кончается законно: остаток дождётся
				 * следующих записей. Прочие же отказы означают оплошность собеседника,
				 * и молчать о них нельзя: сборщик неразобранного сообщения с места не
				 * сдвигает, оттого связь после него не оборвалась бы, а замерла
				 * навсегда, приняв всё дальнейшее рукопожатие и не разобрав ничего
				 */
				if(outcome != handshake::error_t::HUNGRY){
					// Если сборщику довелось столкнуться с неведомым видом сообщения
					if(outcome == handshake::error_t::TYPE)
						// Выводим отказ неведомого вида сообщения рукопожатия
						return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
					// Если памяти сборщику сообщений не хватило
					else if(outcome == handshake::error_t::MEMORY)
						// Выводим отказ нехватки памяти под накопитель сообщений
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					/**
					 * Превышение дозволенной длины тела сообщения: движок предела
					 * сборщику не понижает, и его собственный предел равен наибольшему,
					 * какой вмещает трёхбайтовое поле длины, - оттого через связь эта
					 * ветвь недостижима. Стоит она ради потребителей фреймворка,
					 * понижающих предел открытым методом limit()
					 */
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				}
			} break;
			// Если приняты прикладные данные собеседника
			case static_cast <uint8_t> (record::type_t::APPLICATION): {
				/**
				 * Упреждающие данные приходят до установления связи: тем они и
				 * упреждающие, что посланы, не дождавшись ответа сервера
				 */
				const bool early = (this->_server && this->_earlying);
				// Если связь ещё не установлена и упреждающие данные не идут
				if(!early && (this->_state != context::state_t::ESTABLISHED))
					// Выводим отказ прихода прикладных данных не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Если упреждающие данные связью принимаются
				if(early){
					// Считаем размер прошедших через связь упреждающих данных
					this->_passed += static_cast <uint32_t> (content.size);
					/**
					 * Предел упреждающих данных объявлен билетом: раздел 4.2.10 RFC 8446
					 * велит серверу оборвать связь, если клиент за него вышел
					 */
					if(this->_passed > this->_limit)
						// Выводим отказ выхода за предел упреждающих данных
						return this->abort(context::error_t::LIMIT, alert::description_t::UNEXPECTED);
				}
				/**
				 * Выполняем складывание принятых прикладных данных в накопитель
				 */
				try {
					// Выполняем перенос принятых прикладных данных в накопитель
					this->_plain.insert(this->_plain.end(), content.data, content.data + content.size);
				// Если памяти под накопитель не хватило
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return context::error_t::MEMORY;
				}
			} break;
			/**
			 * Ветвь эта недостижима: разбор заголовка записи сличает вид содержимого
			 * сам, и признаёт он ровно те четыре вида, что разобраны выше. Стоит она
			 * обороною на случай, если перечни разойдутся
			 */
				/**
				 * Ветвь эта в тени: неведомый вид содержимого отвергает ещё снятие защиты
				 * записи, и сюда он не доходит. Стоит она ради связности переключателя
				 */
			default: return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
		}
	}
	// Выводим успешность разбора принятых байтов связи
	return context::error_t::NONE;
}
/**
 * @brief Метод получения байтов, отправляемых собеседнику
 *
 * @return накопленные байты, отправляемые собеседнику
 *
 */
view_t nts::internal::Engine::output() const noexcept {
	// Выводим накопленные байты, отправляемые собеседнику
	return view_t(this->_wire.data(), this->_wire.size());
}
/**
 * @brief Метод снятия отправленных байтов с накопителя
 *
 * @param size размер снимаемых байтов
 *
 */
void nts::internal::Engine::consume(const size_t size) noexcept {
	// Если снимается весь накопитель отправляемых байтов
	if(size >= this->_wire.size())
		// Выполняем сброс накопителя отправляемых байтов
		this->_wire.clear();
	// Если снимается часть накопителя отправляемых байтов
	else this->_wire.erase(this->_wire.begin(), this->_wire.begin() + size);
}
/**
 * @brief Метод отправки прикладных данных собеседнику
 *
 * @param data отправляемые прикладные данные
 *
 * @return     отказ отправки прикладных данных
 *
 */
context::error_t nts::internal::Engine::write(const view_t & data) noexcept {
	/**
	 * Упреждающие данные уходят до установления связи: тем они и упреждающие, что
	 * посылаются, не дождавшись ответа сервера
	 */
	const bool early = (!this->_server && this->_earlying && (this->_state == context::state_t::HANDSHAKE));
	// Если связь ещё не установлена и упреждающие данные не идут
	if(!early && (this->_state != context::state_t::ESTABLISHED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Предел упреждающих данных объявлен билетом: раздел 4.2.10 RFC 8446 велит клиенту
	 * за него не выходить, а сервер за выход обрывает связь
	 */
	if(early && ((static_cast <uint64_t> (this->_passed) + data.size) > static_cast <uint64_t> (this->_resume.advance)))
		// Выводим отказ выхода за предел упреждающих данных
		return context::error_t::LIMIT;
	// Если отправляемые прикладные данные не переданы
	if((data.data == nullptr) || (data.size == 0))
		// Выводим успешность отправки прикладных данных
		return context::error_t::NONE;
	// Если упреждающие данные связью отправляются
	if(early)
		// Считаем размер прошедших через связь упреждающих данных
		this->_passed += static_cast <uint32_t> (data.size);
	// Размер отправленных прикладных данных
	size_t offset = 0;
	/**
	 * Выполняем нарезку прикладных данных на записи протокола
	 */
	while(offset < data.size){
		// Определяем размер очередной отправляемой записи
		const size_t size = ((data.size - offset) > record::RECORD_PLAINTEXT ? record::RECORD_PLAINTEXT : (data.size - offset));
		// Выполняем складывание очередной записи в накопитель
		const context::error_t error = this->emit(record::type_t::APPLICATION, view_t(data.data + offset, size));
		// Если запись прикладных данных сложить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки прикладных данных
			return error;
		// Увеличиваем размер отправленных прикладных данных
		offset += size;
	}
	// Выводим итог смены ключей своего направления по счётчику записей
	return this->refreshing();
}
/**
 * @brief Метод получения принятых прикладных данных
 *
 * @param result накопитель, в который переносятся принятые данные
 *
 * @return       отказ получения принятых прикладных данных
 *
 */
context::error_t nts::internal::Engine::read(vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перенос принятых прикладных данных
	 */
	try {
		// Выполняем перенос принятых прикладных данных в накопитель
		result.assign(this->_plain.begin(), this->_plain.end());
	// Если памяти под накопитель не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если накопитель принятых прикладных данных не пуст
	if(!this->_plain.empty())
		// Выполняем затирание принятых прикладных данных
		wipe(this->_plain.data(), this->_plain.size());
	// Выполняем сброс накопителя принятых прикладных данных
	this->_plain.clear();
	// Выводим успешность получения принятых прикладных данных
	return context::error_t::NONE;
}
/**
 * @brief Метод смены ключевого материала своего направления связи
 *
 * @param request признак просьбы к собеседнику сменить свои ключи в ответ
 *
 * @return        отказ смены ключевого материала своего направления
 *
 */
context::error_t nts::internal::Engine::update(const bool request) noexcept {
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Накопитель, в который складывается тело сообщения смены ключей
	vector <uint8_t> body;
	// Если тело сообщения смены ключевого материала составить не удалось
	if(message::build((request ? message::update_t::REQUEST : message::update_t::NOTIFY), body) != message::error_t::NONE)
		// Выводим отказ составления сообщения смены ключевого материала
		return context::error_t::MESSAGE;
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если сообщение смены ключевого материала составить не удалось
	if(writer.push(handshake::type_t::UPDATE, view_t(body.data(), body.size())) != handshake::error_t::NONE)
		// Выводим отказ составления сообщения смены ключевого материала
		return context::error_t::MESSAGE;
	/**
	 * Сообщение уходит прежними ключами, а новые ставятся уже за ним: раздел 4.6.3
	 * RFC 8446 велит сменять ключи отправки лишь после отправки самого сообщения
	 */
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, writer.data());
	// Если сообщение смены ключевого материала отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки сообщения смены ключевого материала
		return error;
	/**
	 * Сообщения, идущие за рукопожатием, в переписку не добавляются: переписка
	 * закрыта завершениями сторон, и ключи из неё больше не выводятся
	 */
	if(this->_machine.accept(handshake::type_t::UPDATE, side) != flow::error_t::NONE)
		/**
		 * Заслон недостижим тем же доводом, что и у приёма чужой смены ключей.
		 * Лежит он нарочно за отправкой: раздел 4.6.3 RFC 8446 велит сменять ключи
		 * отправки лишь после ухода самого сообщения, и объявление ходу идёт в паре
		 * со сменою, а не с составлением
		 */
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Выводим итог смены ключевого материала своего направления связи
	return this->rotate(side);
}
/**
 * @brief Метод выдачи билета возобновления связи
 *
 * @return отказ выдачи билета возобновления связи
 *
 */
context::error_t nts::internal::Engine::issue() noexcept {
	// Если связь ведётся стороной клиента
	if(!this->_server)
		// Выводим отказ негодной стороны связи: билеты выдаёт сервер
		return context::error_t::STATE;
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Выдаваемый билет возобновления связи
	context::ticket_t item;
	// Устанавливаем набор шифрования связи, выдавшей билет
	item.suite = this->_suite;
	// Устанавливаем миг выдачи билета
	item.moment = this->_moment;
	// Устанавливаем срок жизни выдаваемого билета
	item.lifetime = 7200;
	/**
	 * Предел упреждающих данных объявляется билетом: раздел 4.6.1 RFC 8446 велит
	 * объявлять его расширением билета, а не приветствием, - и клиент по нему судит,
	 * дозволено ли ему упреждение вовсе и сколько его дозволено
	 */
	if(this->_advance)
		// Устанавливаем предел упреждающих данных выдаваемого билета
		item.advance = this->_limit;
	/**
	 * Неповторимое значение билета берётся числом выданных билетов: раздел 4.6.1
	 * RFC 8446 велит разводить ключи билетов одной связи именно им
	 */
	const uint8_t nonce[4] = {
		static_cast <uint8_t> ((this->_tickets.size() >> 24) & 0xFF),
		static_cast <uint8_t> ((this->_tickets.size() >> 16) & 0xFF),
		static_cast <uint8_t> ((this->_tickets.size() >> 8) & 0xFF),
		static_cast <uint8_t> (this->_tickets.size() & 0xFF)
	};
	// Место, в которое помещается тело выдаваемого билета
	uint8_t identity[32];
	// Если тело выдаваемого билета выработать не удалось
	if(!entropy::bytes(identity, sizeof(identity)))
		// Выводим отказ выработки тела билета
		return context::error_t::SETTINGS;
	// Место, в которое помещается добавка к возрасту билета
	uint8_t addition[4];
	// Если добавку к возрасту билета выработать не удалось
	if(!entropy::bytes(addition, sizeof(addition)))
		// Выводим отказ выработки добавки к возрасту билета
		return context::error_t::SETTINGS;
	// Устанавливаем добавку к возрасту выдаваемого билета
	item.age = ((static_cast <uint32_t> (addition[0]) << 24) | (static_cast <uint32_t> (addition[1]) << 16) | (static_cast <uint32_t> (addition[2]) << 8) | static_cast <uint32_t> (addition[3]));
	// Место, в которое помещается ключ выдаваемого билета
	uint8_t secret[schedule::SCHEDULE_SECRET];
	// Если ключ выдаваемого билета вывести не удалось
	if(this->_secrets.ticket(view_t(nonce, sizeof(nonce)), secret) != session::error_t::NONE)
		// Выводим отказ вывода ключа билета возобновления связи
		return context::error_t::SCHEDULE;
	// Составляемый билет возобновления связи
	message::ticket_t ticket;
	// Устанавливаем срок жизни составляемого билета
	ticket.lifetime = item.lifetime;
	// Устанавливаем добавку к возрасту составляемого билета
	ticket.age = item.age;
	// Устанавливаем неповторимое значение составляемого билета
	ticket.nonce = view_t(nonce, sizeof(nonce));
	// Устанавливаем тело составляемого билета
	ticket.data = view_t(identity, sizeof(identity));
	// Накопитель, в который складывается тело расширения упреждающих данных
	vector <uint8_t> advance;
	// Если упреждающие данные билетом дозволяются
	if(item.advance > 0){
		// Если предел упреждающих данных составить не удалось
		if(extension::early(item.advance, advance) != extension::error_t::NONE){
			// Выполняем затирание ключа выдаваемого билета
			wipe(secret, sizeof(secret));
			// Выводим отказ составления сообщения билета
			return context::error_t::MESSAGE;
		}
		// Добавляем расширение предела упреждающих данных
		ticket.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(advance.data(), advance.size())));
	}
	// Накопитель, в который складывается тело сообщения билета
	vector <uint8_t> body;
	// Если тело сообщения билета составить не удалось
	if(message::build(ticket, body) != message::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ составления сообщения билета
		return context::error_t::MESSAGE;
	}
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если сообщение билета возобновления связи составить не удалось
	if(writer.push(handshake::type_t::TICKET, view_t(body.data(), body.size())) != handshake::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ составления сообщения билета
		return context::error_t::MESSAGE;
	}
	// Выполняем складывание сообщения билета в накопитель отправляемых байтов
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, writer.data());
	// Если сообщение билета отправить не удалось
	if(error != context::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ отправки сообщения билета
		return error;
	}
	/**
	 * Сообщения, идущие за рукопожатием, в переписку не добавляются: значение
	 * возобновления связи выведено и от них уже не зависит
	 */
	if(this->_machine.accept(handshake::type_t::TICKET, session::side_t::SERVER) != flow::error_t::NONE){
		/**
		 * Сторона задана постоянной, и ход рукопожатия за установленной связью
		 * сличает её сам с собою: заслон недостижим и стоит обороною
		 */
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	}
	/**
	 * Выполняем складывание выданного билета возобновления связи
	 */
	try {
		// Запоминаем прикладной протокол связи, выдающей билет
		item.protocol = this->_protocol;
		// Переносим тело выданного билета возобновления связи
		item.identity.assign(identity, identity + sizeof(identity));
		// Переносим ключ выданного билета возобновления связи
		item.secret.assign(secret, secret + sizeof(secret));
		// Добавляем выданный билет в перечень билетов связи
		this->_tickets.push_back(item);
	// Если памяти под билет не хватило
	} catch(const bad_alloc &) {
		// Выполняем затирание ключа выданного билета
		wipe(secret, sizeof(secret));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем затирание ключа выданного билета
	wipe(secret, sizeof(secret));
	// Выводим успешность выдачи билета возобновления связи
	return context::error_t::NONE;
}
/**
 * @brief Метод получения билетов возобновления связи
 *
 * @return выданные либо принятые билеты возобновления связи
 *
 */
const vector <context::ticket_t> & nts::internal::Engine::tickets() const noexcept {
	// Выводим выданные либо принятые билеты возобновления связи
	return this->_tickets;
}
/**
 * @brief Метод закрытия связи
 *
 * @return отказ закрытия связи
 *
 */
context::error_t nts::internal::Engine::close() noexcept {
	// Если связь уже закрыта либо оборвана
	if((this->_state == context::state_t::CLOSED) || (this->_state == context::state_t::FAILED))
		// Выводим отказ закрытия закрытой связи
		return context::error_t::CLOSED;
	// Составляем извещение о завершении передачи данных
	const alert::alert_t alert(alert::level_t::WARNING, alert::description_t::CLOSE);
	// Место, в которое записывается извещение о завершении передачи
	uint8_t buffer[alert::ALERT_LENGTH];
	// Если извещение о завершении передачи записать не удалось
	if(alert::build(alert, buffer) != alert::error_t::NONE)
		// Выводим отказ составления извещения
		return context::error_t::MESSAGE;
	// Выполняем складывание извещения в накопитель отправляемых байтов
	const context::error_t error = this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
	// Если извещение о завершении передачи сложить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки извещения
		return error;
	// Переводим связь в состояние закрытия
	this->_state = context::state_t::CLOSED;
	// Выводим успешность закрытия связи
	return context::error_t::NONE;
}
/**
 * @brief Конструктор
 *
 * @param server признак того, что связь ведётся стороной сервера
 *
 */
nts::internal::Engine::Engine(const bool server) noexcept :
 _server(server), _request(false), _requested(false), _retried(false),
 _state(context::state_t::NONE), _error(context::error_t::NONE),
 _suite(protect::suite_t::NONE), _group(extension::group_t::NONE),
 _moment(0), _limit(0), _passed(0),
 _shared(false), _chosen(0), _advance(false), _earlying(false), _accepted(false),
 _automatic(true), _asked(false), _renewal(0), _ticket(protect::suite_t::NONE), _skipped(0) {
	// Выполняем сброс поры ключей записей клиента
	this->_epoch[0] = flow::epoch_t::PLAIN;
	// Выполняем сброс поры ключей записей сервера
	this->_epoch[1] = flow::epoch_t::PLAIN;
	// Выполняем обнуление ключей завершения рукопожатия сторон
	::memset(this->_completion, 0, sizeof(this->_completion));
	// Выполняем обнуление ключевого материала прикладных данных
	::memset(this->_key, 0, sizeof(this->_key));
	// Выполняем обнуление векторов замены прикладных данных
	::memset(this->_vector, 0, sizeof(this->_vector));
	// Выполняем обнуление случайного значения своего приветствия
	::memset(this->_random, 0, sizeof(this->_random));
	/**
	 * Наборы шифрования по умолчанию идут от стойкого к быстрому: раздел 4 описания
	 * наборов шифрования на алгоритмах ГОСТ
	 */
	this->_suites = {
		protect::suite_t::KUZNYECHIK_MGM_L, protect::suite_t::MAGMA_MGM_L,
		protect::suite_t::KUZNYECHIK_MGM_S, protect::suite_t::MAGMA_MGM_S
	};
	// Кривые обмена ключами по умолчанию идут от длинного ключа к короткому
	this->_groups = {
		extension::group_t::GC512C, extension::group_t::GC512A,
		extension::group_t::GC256B, extension::group_t::GC256A
	};
}
/**
 * @brief Деструктор
 *
 */
nts::internal::Engine::~Engine() noexcept {
	// Выполняем сброс состояния связи
	this->clear();
}
