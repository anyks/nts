/**
 * @file client.cpp
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
 * @brief Исходный файл фасада связи клиента протокола TLS 1.3
 *
 * @section Намеренные решения
 *
 * 1. Фасад ведения связи в себе не держит. Клиент и сервер проходят одно и то же
 *    рукопожатие с разных его концов, и ведёт их один внутренний модуль: фасад лишь
 *    объявляет ту часть его вызовов, которая этой роли принадлежит.
 *
 * 2. Ведение связи заводится конструктором, а не первым вызовом. Нехватка памяти на
 *    заведении вида связи заметна сразу, тогда как отложенное заведение потребовало бы
 *    проверки указателя у всякого вызова фасада.
 *
 * 3. Связь копированию не подлежит. Защита записей ведёт счётчик записей, единый на
 *    направление связи, и две копии одной связи повторили бы его значение - а повтор
 *    значения счётчика при том же ключе выдаёт открытое содержимое обеих записей.
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
#include <client/client.hpp>
#include <internal/engine/engine.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace anyks;

/**
 * @brief Метод получения состояния связи
 *
 * @return состояние связи
 *
 */
context::state_t anyks::client::Context::state() const noexcept {
	// Выводим состояние связи
	return (this->_engine != nullptr ? this->_engine->state() : context::state_t::NONE);
}
/**
 * @brief Метод получения отказа, которым связь оборвана
 *
 * @return отказ, которым связь оборвана
 *
 */
context::error_t anyks::client::Context::error() const noexcept {
	// Выводим отказ, которым связь оборвана
	return (this->_engine != nullptr ? this->_engine->error() : context::error_t::MEMORY);
}
/**
 * @brief Метод проверки установленности связи
 *
 * @return признак того, что рукопожатие пройдено обеими сторонами
 *
 */
bool anyks::client::Context::established() const noexcept {
	// Выводим признак установленности связи
	return (this->state() == context::state_t::ESTABLISHED);
}
/**
 * @brief Метод получения извещения, которым связь оборвана
 *
 * @return извещение, которым связь оборвана
 *
 */
const alert::alert_t & anyks::client::Context::alert() const noexcept {
	// Извещение, выводимое при незаведённом ведении связи
	static const alert::alert_t alert;
	// Выводим извещение, которым связь оборвана
	return (this->_engine != nullptr ? this->_engine->alert() : alert);
}
/**
 * @brief Метод получения набора шифрования связи
 *
 * @return согласованный сторонами набор шифрования
 *
 */
protect::suite_t anyks::client::Context::suite() const noexcept {
	// Выводим согласованный сторонами набор шифрования
	return (this->_engine != nullptr ? this->_engine->suite() : protect::suite_t::NONE);
}
/**
 * @brief Метод получения цепочки сертификатов собеседника
 *
 * @return цепочка сертификатов, предъявленная собеседником
 *
 */
const vector <vector <uint8_t>> & anyks::client::Context::peer() const noexcept {
	// Цепочка, выводимая при незаведённом ведении связи
	static const vector <vector <uint8_t>> chain;
	// Выводим цепочку сертификатов, предъявленную собеседником
	return (this->_engine != nullptr ? this->_engine->peer() : chain);
}
/**
 * @brief Метод получения прикладного протокола связи
 *
 * @return прикладной протокол, выбранный сторонами связи
 *
 */
const string & anyks::client::Context::protocol() const noexcept {
	// Название, выводимое при незаведённом ведении связи
	static const string empty;
	// Выводим прикладной протокол, выбранный сторонами связи
	return (this->_engine != nullptr ? this->_engine->protocol() : empty);
}
/**
 * @brief Метод получения билетов возобновления связи
 *
 * @return билеты возобновления связи
 *
 */
const vector <context::ticket_t> & anyks::client::Context::tickets() const noexcept {
	// Билеты, выводимые при незаведённом ведении связи
	static const vector <context::ticket_t> tickets;
	// Выводим билеты возобновления связи
	return (this->_engine != nullptr ? this->_engine->tickets() : tickets);
}
/**
 * @brief Метод установки предлагаемых наборов шифрования
 *
 * @param suites устанавливаемые наборы шифрования
 *
 */
void anyks::client::Context::suites(const vector <protect::suite_t> & suites) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых наборов шифрования
		this->_engine->suites(suites);
}
/**
 * @brief Метод установки предлагаемых кривых обмена ключами
 *
 * @param groups устанавливаемые кривые обмена ключами
 *
 */
void anyks::client::Context::groups(const vector <extension::group_t> & groups) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых кривых обмена ключами
		this->_engine->groups(groups);
}
/**
 * @brief Метод установки подлинности своей стороны связи
 *
 * @param credential устанавливаемая подлинность своей стороны
 *
 */
void anyks::client::Context::credential(const context::credential_t & credential) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку подлинности своей стороны связи
		this->_engine->credential(credential);
}
/**
 * @brief Метод установки имени узла, запрашиваемого у сервера
 *
 * @param name устанавливаемое имя узла
 *
 */
void anyks::client::Context::name(const string & name) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку имени узла, запрашиваемого у сервера
		this->_engine->name(name);
}
/**
 * @brief Метод установки предлагаемых прикладных протоколов
 *
 * @param protocols устанавливаемые прикладные протоколы
 *
 */
void anyks::client::Context::protocols(const vector <string> & protocols) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых прикладных протоколов
		this->_engine->protocols(protocols);
}
/**
 * @brief Метод установки мига, которым судятся сроки билетов
 *
 * @param moment устанавливаемый миг в секундах
 *
 */
void anyks::client::Context::moment(const int64_t moment) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку мига суждения о сроках билетов
		this->_engine->moment(moment);
}
/**
 * @brief Метод предъявления билета возобновления связи
 *
 * @param ticket предъявляемый серверу билет возобновления связи
 *
 */
void anyks::client::Context::resume(const context::ticket_t & ticket) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку билетов возобновления связи
		this->_engine->resume(ticket);
}
/**
 * @brief Метод проверки возобновления связи билетом
 *
 * @return признак того, что связь возобновлена заранее разделённым ключом
 *
 */
bool anyks::client::Context::shared() const noexcept {
	// Выводим признак возобновления связи заранее разделённым ключом
	return (this->_engine != nullptr ? this->_engine->shared() : false);
}
/**
 * @brief Метод установки предложения упреждающих данных
 *
 * @param advance предлагаются либо принимаются ли упреждающие данные
 *
 */
void anyks::client::Context::advance(const bool advance, const uint32_t limit) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предложения упреждающих данных
		this->_engine->advance(advance, limit);
}
/**
 * @brief Метод проверки приёма упреждающих данных сервером
 *
 * @return признак того, что упреждающие данные сервером приняты
 *
 */
bool anyks::client::Context::accepted() const noexcept {
	// Выводим признак приёма упреждающих данных сервером
	return (this->_engine != nullptr ? this->_engine->accepted() : false);
}
/**
 * @brief Метод заведения связи
 *
 * @return отказ заведения связи
 *
 */
context::error_t anyks::client::Context::start() noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог заведения связи
	return this->_engine->start();
}
/**
 * @brief Метод сброса состояния связи
 *
 */
void anyks::client::Context::clear() noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем сброс состояния связи
		this->_engine->clear();
}
/**
 * @brief Метод подачи связи принятых байтов
 *
 * @param data принятые от собеседника байты
 *
 * @return     отказ разбора принятых байтов
 *
 */
context::error_t anyks::client::Context::push(const view_t & data) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог разбора принятых байтов связи
	return this->_engine->push(data);
}
/**
 * @brief Метод получения байтов, отправляемых собеседнику
 *
 * @return накопленные байты, отправляемые собеседнику
 *
 */
view_t anyks::client::Context::output() const noexcept {
	// Выводим накопленные байты, отправляемые собеседнику
	return (this->_engine != nullptr ? this->_engine->output() : view_t());
}
/**
 * @brief Метод снятия отправленных байтов с накопителя
 *
 * @param size размер снимаемых байтов
 *
 */
void anyks::client::Context::consume(const size_t size) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем снятие отправленных байтов с накопителя
		this->_engine->consume(size);
}
/**
 * @brief Метод отправки прикладных данных собеседнику
 *
 * @param data отправляемые прикладные данные
 *
 * @return     отказ отправки прикладных данных
 *
 */
context::error_t anyks::client::Context::write(const view_t & data) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог отправки прикладных данных собеседнику
	return this->_engine->write(data);
}
/**
 * @brief Метод получения принятых прикладных данных
 *
 * @param result накопитель, в который переносятся принятые данные
 *
 * @return       отказ получения принятых прикладных данных
 *
 */
context::error_t anyks::client::Context::read(vector <uint8_t> & result) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог получения принятых прикладных данных
	return this->_engine->read(result);
}
/**
 * @brief Метод смены ключевого материала своего направления связи
 *
 * @param request просьба к собеседнику сменить свои ключи в ответ
 *
 * @return        отказ смены ключевого материала своего направления
 *
 */
context::error_t anyks::client::Context::update(const bool request) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог смены ключевого материала своего направления связи
	return this->_engine->update(request);
}
/**
 * @brief Метод закрытия связи
 *
 * @return отказ закрытия связи
 *
 */
context::error_t anyks::client::Context::close() noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог закрытия связи
	return this->_engine->close();
}
/**
 * @brief Конструктор
 *
 */
anyks::client::Context::Context() noexcept : _engine(nullptr) {
	/**
	 * Выполняем заведение ведения связи
	 */
	try {
		// Выполняем создание объекта ведения связи
		this->_engine = new internal::engine_t(false);
	// Если памяти под ведение связи не хватило
	} catch(const bad_alloc &) {
		// Выполняем сброс объекта ведения связи
		this->_engine = nullptr;
	}
}
/**
 * @brief Деструктор
 *
 */
anyks::client::Context::~Context() noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем удаление объекта ведения связи
		delete this->_engine;
}
