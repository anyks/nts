/**
 * @file context.cpp
 * @date 2026-08-31
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
 * @brief Исходный файл общих объявлений фасадов связи
 *
 * @note Заголовочный файл модуля несёт одни объявления: перечисления отказов и
 *       состояний связи, да две записи под подлинность стороны и билет
 *       возобновления. Исходный файл несёт приведение билета к началу и кодек
 *       билета в октеты: билет уходит в другой процесс записью, от процесса не
 *       зависящей
 *
 * @section Намеренные решения
 *
 * 1. Запись билета своя, а не запись NewSessionTicket протокола. Сообщение протокола
 *    несёт лишь то, что сервер сказал клиенту, а билету у клиента нужны ещё набор
 *    шифрования, миг выдачи, ключ, выведенный из значения возобновления, и параметры
 *    переноса QUIC собеседника - ничего этого в сообщении нет.
 *
 * 2. Издание записи идёт первым байтом. Поле, добавленное будущим изданием, читалось бы
 *    прежним чтением как порча длины; байт издания даёт отвергнуть чужую запись вслух.
 *
 * 3. Лишние байты за хвостом записи отвергаются. Молчаливый пропуск хвоста прятал бы
 *    склейку двух записей и порчу длины последнего поля.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <field/field.hpp>
#include <context/context.hpp>
#include <sys/wipe.hpp>

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
	 * Издание записи билета возобновления связи
	 */
	static constexpr uint32_t EDITION = 0x04;
	/**
	 * Предел длины ключа билета: ключ выводится хешем набора, а шире хеша он не бывает
	 */
	static constexpr size_t SECRET_WIDEST = 64;
	/**
	 * @brief Метод перевода отказа модуля полей в отказ связи
	 *
	 * @param error отказ модуля полей
	 *
	 * @return      отказ связи, отвечающий отказу модуля
	 *
	 */
	static context::error_t translate(const field::error_t error) noexcept {
		// Если отказа у модуля нет
		if(error == field::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == field::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::TICKET);
	}
	/**
	 * @brief Метод записи поля переменной длины с двухбайтовой длиной впереди
	 *
	 * @param builder составитель записи билета
	 * @param data    записываемое содержимое поля
	 *
	 * @return        отказ записи поля
	 *
	 */
	static context::error_t field(field::builder_t & builder, const view_t & data) noexcept {
		// Отказ занятия места под длину поля
		context::error_t failure = translate(builder.open(2));
		// Если место под длину поля занять не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ записи поля
			return failure;
		// Если содержимое поля не пусто
		if(data.size > 0){
			// Отказ записи содержимого поля
			failure = translate(builder.bytes(data));
			// Если содержимое поля записать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ записи поля
				return failure;
		}
		// Выводим итог проставления длины поля
		return translate(builder.close());
	}
};

/**
 * @brief Конструктор
 *
 */
nts::context::Ticket::Ticket() noexcept :
	suite(protect::suite_t::NONE), moment(0), lifetime(0), advance(0), age(0), etm(false), ancient(false), authenticated(0), settled(false) {}
/**
 * @brief Деструктор настроек заранее разделённого ключа
 *
 */
nts::context::Psk::~Psk() noexcept {
	// Выполняем затирание ключа: в освобождённой памяти ему не место
	sys::wipe(this->key.data(), this->key.size());
	// Опустошаем ключ
	this->key.clear();
}
/**
 * @brief Конструктор копирования билета
 *
 * @param other копируемый билет
 *
 */
nts::context::Ticket::Ticket(const Ticket & other) : suite(other.suite), moment(other.moment), lifetime(other.lifetime), advance(other.advance), age(other.age), etm(other.etm), ancient(other.ancient), authenticated(other.authenticated), protocol(other.protocol), settled(other.settled), settings(other.settings), obtained(other.obtained), identity(other.identity), secret(other.secret), parameters(other.parameters) {}
/**
 * @brief Конструктор перемещения билета
 *
 * @param other перемещаемый билет
 *
 */
nts::context::Ticket::Ticket(Ticket && other) noexcept : suite(other.suite), moment(other.moment), lifetime(other.lifetime), advance(other.advance), age(other.age), etm(other.etm), ancient(other.ancient), authenticated(other.authenticated), protocol(::move(other.protocol)), settled(other.settled), settings(::move(other.settings)), obtained(::move(other.obtained)), identity(::move(other.identity)), secret(::move(other.secret)), parameters(::move(other.parameters)) {
	// Если у источника ключ остался (перемещение вправе оставить копию)
	if(!other.secret.empty())
		// Затираем ключ источника
		sys::wipe(other.secret.data(), other.secret.size());
	// Сбрасываем источник
	other.secret.clear();
}
/**
 * @brief Оператор присваивания билета копированием
 *
 * @param other копируемый билет
 *
 * @return      сам билет
 *
 */
nts::context::Ticket & nts::context::Ticket::operator = (const Ticket & other) {
	// Если билет присваивается сам себе
	if(this == &other)
		// Выводим сам билет
		return (* this);
	// Затираем прежний ключ до замены: рост буфера освободил бы его незатёртым
	if(!this->secret.empty())
		// Затирание
		sys::wipe(this->secret.data(), this->secret.size());
	// Опустошаем ключ: отказ памяти на прочих полях не оставит билета с нулевым ключом прежней длины
	this->secret.clear();
	// Переносим поля
	this->suite = other.suite;
	this->moment = other.moment;
	this->lifetime = other.lifetime;
	this->advance = other.advance;
	this->age = other.age;
	this->etm = other.etm;
	// Переносим признак издания выдавшей связи
	this->ancient = other.ancient;
	// Переносим миг первичного удостоверения
	this->authenticated = other.authenticated;
	this->protocol = other.protocol;
	this->settled = other.settled;
	this->settings = other.settings;
	this->obtained = other.obtained;
	this->identity = other.identity;
	this->secret = other.secret;
	this->parameters = other.parameters;
	// Выводим сам билет
	return (* this);
}
/**
 * @brief Оператор присваивания билета перемещением
 *
 * @param other перемещаемый билет
 *
 * @return      сам билет
 *
 */
nts::context::Ticket & nts::context::Ticket::operator = (Ticket && other) noexcept {
	// Если билет присваивается сам себе
	if(this == &other)
		// Выводим сам билет
		return (* this);
	// Затираем прежний ключ
	if(!this->secret.empty())
		// Затирание
		sys::wipe(this->secret.data(), this->secret.size());
	// Переносим поля
	this->suite = other.suite;
	this->moment = other.moment;
	this->lifetime = other.lifetime;
	this->advance = other.advance;
	this->age = other.age;
	this->etm = other.etm;
	// Переносим признак издания выдавшей связи
	this->ancient = other.ancient;
	// Переносим миг первичного удостоверения
	this->authenticated = other.authenticated;
	this->protocol = ::move(other.protocol);
	this->settled = other.settled;
	this->settings = ::move(other.settings);
	this->obtained = ::move(other.obtained);
	this->identity = ::move(other.identity);
	this->secret = ::move(other.secret);
	this->parameters = ::move(other.parameters);
	// Если у источника ключ остался
	if(!other.secret.empty())
		// Затираем ключ источника
		sys::wipe(other.secret.data(), other.secret.size());
	// Сбрасываем источник
	other.secret.clear();
	// Выводим сам билет
	return (* this);
}
/**
 * @brief Деструктор билета
 *
 */
nts::context::Ticket::~Ticket() noexcept {
	// Затираем ключ билета
	if(!this->secret.empty())
		// Затирание
		sys::wipe(this->secret.data(), this->secret.size());
}
/**
 * @brief Метод записи билета возобновления связи в октеты
 *
 * @param ticket записываемый билет возобновления связи
 * @param result накопитель, в который складывается запись билета
 *
 * @return       отказ записи билета
 *
 */
nts::context::error_t nts::context::encode(const ticket_t & ticket, vector <uint8_t> & result) noexcept {
	/**
	 * Поля переменной длины идут с двухбайтовой длиной, а ключ билета шире хеша не
	 * бывает: билет, в запись не входящий, отвергается прежде составления
	 */
	if((ticket.protocol.size() > 0xFFFF) || (ticket.identity.size() > 0xFFFF) || (ticket.parameters.size() > 0xFFFF) || (ticket.settings.size() > 0xFFFF) || (ticket.obtained.size() > 0xFFFF) || (ticket.secret.size() > SECRET_WIDEST))
		// Выводим отказ записи билета
		return error_t::TICKET;
	// Объект составителя записи билета
	field::builder_t builder;
	// Отказ записи издания записи билета
	error_t failure = translate(builder.number(EDITION, 1));
	// Если издание записи билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи набора шифрования билета
	failure = translate(builder.number(static_cast <uint32_t> (ticket.suite), 2));
	// Если набор шифрования билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Миг выдачи билета в записи без знака
	const uint64_t moment = static_cast <uint64_t> (ticket.moment);
	// Отказ записи старшей половины мига выдачи билета
	failure = translate(builder.number(static_cast <uint32_t> (moment >> 32), 4));
	// Если старшую половину мига выдачи записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи младшей половины мига выдачи билета
	failure = translate(builder.number(static_cast <uint32_t> (moment & 0xFFFFFFFF), 4));
	// Если младшую половину мига выдачи записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи срока жизни билета
	failure = translate(builder.number(ticket.lifetime, 4));
	// Если срок жизни билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи предела упреждающих данных билета
	failure = translate(builder.number(ticket.advance, 4));
	// Если предел упреждающих данных записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи добавки к возрасту билета
	failure = translate(builder.number(ticket.age, 4));
	// Если добавку к возрасту билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи признака порядка «шифрование, затем имитовставка»
	failure = translate(builder.number((ticket.etm ? 1 : 0), 1));
	// Если признак порядка записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи признака издания выдавшей связи
	failure = translate(builder.number((ticket.ancient ? 1 : 0), 1));
	// Если признак издания записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Миг первичного удостоверения в записи
	const uint64_t authenticated = static_cast <uint64_t> (ticket.authenticated);
	// Отказ записи старшей половины мига удостоверения
	failure = translate(builder.number(static_cast <uint32_t> (authenticated >> 32), 4));
	// Если старшая половина записана
	if(failure == error_t::NONE)
		// Отказ записи младшей половины мига удостоверения
		failure = translate(builder.number(static_cast <uint32_t> (authenticated & 0xFFFFFFFF), 4));
	// Если миг удостоверения записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи прикладного протокола билета
	failure = ::field(builder, view_t(reinterpret_cast <const uint8_t *> (ticket.protocol.data()), ticket.protocol.size()));
	// Если прикладной протокол билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи тела билета
	failure = ::field(builder, view_t(ticket.identity.data(), ticket.identity.size()));
	// Если тело билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи ключа билета
	failure = ::field(builder, view_t(ticket.secret.data(), ticket.secret.size()));
	// Если ключ билета записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи параметров переноса собеседника
	failure = ::field(builder, view_t(ticket.parameters.data(), ticket.parameters.size()));
	// Если параметры переноса собеседника записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи признака согласования прикладных настроек ALPS
	failure = translate(builder.number((ticket.settled ? 1 : 0), 1));
	// Если признак согласования записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи своих прикладных настроек
	failure = ::field(builder, view_t(ticket.settings.data(), ticket.settings.size()));
	// Если свои прикладные настройки записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Отказ записи прикладных настроек собеседника
	failure = ::field(builder, view_t(ticket.obtained.data(), ticket.obtained.size()));
	// Если прикладные настройки собеседника записать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ записи билета
		return failure;
	// Получаем составленную запись билета
	const view_t data = builder.data();
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Выполняем перенос составленной записи билета в накопитель
		result.assign(data.data, data.data + data.size);
	/**
	 * Если памяти под запись билета не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность записи билета
	return error_t::NONE;
}
/**
 * @brief Метод чтения билета возобновления связи из октетов
 *
 * @param data   читаемая запись билета возобновления связи
 * @param result билет, в который помещается прочитанное
 *
 * @return       отказ чтения билета
 *
 */
nts::context::error_t nts::context::decode(const view_t & data, ticket_t & result) noexcept {
	// Если запись билета не передана
	if((data.data == nullptr) || (data.size == 0))
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Объект разборщика записи билета
	field::scanner_t scanner;
	// Устанавливаем разбираемую запись билета
	scanner.start(data);
	// Издание разбираемой записи билета
	uint32_t edition = 0;
	// Если издание записи билета прочитать не удалось
	if(scanner.number(edition, 1) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если запись сложена чужим изданием
	if(edition != EDITION)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Читаемый билет возобновления связи
	ticket_t ticket;
	// Набор шифрования билета
	uint32_t suite = 0;
	// Если набор шифрования билета прочитать не удалось
	if(scanner.number(suite, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Устанавливаем набор шифрования билета
	ticket.suite = static_cast <protect::suite_t> (suite);
	// Половины мига выдачи билета
	uint32_t upper = 0, lower = 0;
	// Если старшую половину мига выдачи прочитать не удалось
	if(scanner.number(upper, 4) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если младшую половину мига выдачи прочитать не удалось
	if(scanner.number(lower, 4) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Устанавливаем миг выдачи билета
	ticket.moment = static_cast <int64_t> ((static_cast <uint64_t> (upper) << 32) | static_cast <uint64_t> (lower));
	// Если срок жизни билета прочитать не удалось
	if(scanner.number(ticket.lifetime, 4) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если предел упреждающих данных прочитать не удалось
	if(scanner.number(ticket.advance, 4) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если добавку к возрасту билета прочитать не удалось
	if(scanner.number(ticket.age, 4) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Признак порядка «шифрование, затем имитовставка» в записи
	uint32_t etm = 0;
	// Если признак порядка прочитать не удалось либо он не ноль и не единица
	if((scanner.number(etm, 1) != field::error_t::NONE) || (etm > 1))
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Переносим признак порядка
	ticket.etm = (etm == 1);
	// Признак издания выдавшей связи в записи
	uint32_t ancient = 0;
	// Если признак издания прочитать не удалось либо он не ноль и не единица
	if((scanner.number(ancient, 1) != field::error_t::NONE) || (ancient > 1))
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Переносим признак издания
	ticket.ancient = (ancient == 1);
	// Половины мига первичного удостоверения
	uint32_t senior = 0, junior = 0;
	// Если миг удостоверения прочитать не удалось
	if((scanner.number(senior, 4) != field::error_t::NONE) || (scanner.number(junior, 4) != field::error_t::NONE))
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Переносим миг первичного удостоверения
	ticket.authenticated = static_cast <int64_t> ((static_cast <uint64_t> (senior) << 32) | junior);
	// Поля билета переменной длины
	view_t protocol, identity, secret, parameters, settings, obtained;
	// Если прикладной протокол билета прочитать не удалось
	if(scanner.vector(protocol, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если тело билета прочитать не удалось
	if(scanner.vector(identity, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если ключ билета прочитать не удалось
	if(scanner.vector(secret, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если параметры переноса собеседника прочитать не удалось
	if(scanner.vector(parameters, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Признак согласования прикладных настроек ALPS
	uint32_t settled = 0;
	// Если признак согласования прочитать не удалось либо он вне 0..1
	if((scanner.number(settled, 1) != field::error_t::NONE) || (settled > 1))
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Устанавливаем признак согласования прикладных настроек
	ticket.settled = (settled == 1);
	// Если свои прикладные настройки прочитать не удалось
	if(scanner.vector(settings, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	// Если прикладные настройки собеседника прочитать не удалось
	if(scanner.vector(obtained, 2) != field::error_t::NONE)
		// Выводим отказ чтения билета
		return error_t::TICKET;
	/**
	 * Ключ билета шире хеша не бывает, а лишние байты за хвостом записи означают
	 * склейку записей либо порчу длины последнего поля
	 */
	if((secret.size > SECRET_WIDEST) || (scanner.left() > 0))
		// Выводим отказ чтения билета
		return error_t::TICKET;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Переносим прикладной протокол билета
		ticket.protocol.assign(reinterpret_cast <const char *> (protocol.data), protocol.size);
		// Переносим тело билета
		ticket.identity.assign(identity.data, identity.data + identity.size);
		// Переносим ключ билета
		ticket.secret.assign(secret.data, secret.data + secret.size);
		// Переносим параметры переноса собеседника
		ticket.parameters.assign(parameters.data, parameters.data + parameters.size);
		// Переносим свои прикладные настройки
		ticket.settings.assign(settings.data, settings.data + settings.size);
		// Переносим прикладные настройки собеседника
		ticket.obtained.assign(obtained.data, obtained.data + obtained.size);
		// Переносим прочитанный билет на место итога
		result = ::move(ticket);
	/**
	 * Если памяти под билет не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность чтения билета
	return error_t::NONE;
}
