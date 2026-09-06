/**
 * @file client.cpp
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
using namespace nts;

/**
 * @brief Метод получения состояния связи
 *
 * @return состояние связи
 *
 */
context::state_t nts::client::Context::state() const noexcept {
	// Выводим состояние связи
	return (this->_engine != nullptr ? this->_engine->state() : context::state_t::NONE);
}
/**
 * @brief Метод получения отказа, которым связь оборвана
 *
 * @return отказ, которым связь оборвана
 *
 */
context::error_t nts::client::Context::error() const noexcept {
	// Выводим отказ, которым связь оборвана
	return (this->_engine != nullptr ? this->_engine->error() : context::error_t::MEMORY);
}
/**
 * @brief Метод проверки установленности связи
 *
 * @return признак того, что рукопожатие пройдено обеими сторонами
 *
 */
bool nts::client::Context::established() const noexcept {
	// Выводим признак установленности связи
	return (this->state() == context::state_t::ESTABLISHED);
}
/**
 * @brief Метод получения извещения, которым связь оборвана
 *
 * @return извещение, которым связь оборвана
 *
 */
const alert::alert_t & nts::client::Context::alert() const noexcept {
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
protect::suite_t nts::client::Context::suite() const noexcept {
	// Выводим согласованный сторонами набор шифрования
	return (this->_engine != nullptr ? this->_engine->suite() : protect::suite_t::NONE);
}
/**
 * @brief Метод получения цепочки сертификатов собеседника
 *
 * @return цепочка сертификатов, предъявленная собеседником
 *
 */
const vector <vector <uint8_t>> & nts::client::Context::peer() const noexcept {
	// Цепочка, выводимая при незаведённом ведении связи
	static const vector <vector <uint8_t>> chain;
	// Выводим цепочку сертификатов, предъявленную собеседником
	return (this->_engine != nullptr ? this->_engine->peer() : chain);
}
/**
 * @brief Метод получения алгоритма сжатия цепочки сертификатов направления
 *
 * @param direction направление связи относительно своей стороны
 *
 * @return          опознаватель алгоритма по реестру RFC 8879, ноль у несжатой цепочки
 *
 */
uint16_t nts::client::Context::compression(const context::direction_t direction) const noexcept {
	// Выводим алгоритм сжатия цепочки направления, ноль без ведения связи
	return ((this->_engine != nullptr) ? this->_engine->compression(direction) : 0);
}
/**
 * @brief Метод получения прикладного протокола связи
 *
 * @return прикладной протокол, выбранный сторонами связи
 *
 */
const string & nts::client::Context::protocol() const noexcept {
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
const vector <context::ticket_t> & nts::client::Context::tickets() const noexcept {
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
void nts::client::Context::suites(const vector <protect::suite_t> & suites) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых наборов шифрования
		this->_engine->suites(suites);
}
/**
 * @brief Метод установки пределов издания протокола
 *
 * @param lowest  наименьшее дозволенное издание протокола
 * @param highest наибольшее дозволенное издание протокола
 *
 * @return        отказ установки пределов издания протокола
 *
 */
context::error_t nts::client::Context::versions(const uint16_t lowest, const uint16_t highest) noexcept {
	// Выводим итог установки пределов издания протокола
	return (this->_engine != nullptr ? this->_engine->versions(lowest, highest) : context::error_t::MEMORY);
}
/**
 * @brief Метод получения наименьшего дозволенного издания протокола
 *
 * @return наименьшее дозволенное издание протокола
 *
 */
uint16_t nts::client::Context::lowest() const noexcept {
	// Выводим наименьшее дозволенное издание протокола
	return (this->_engine != nullptr ? this->_engine->lowest() : 0);
}
/**
 * @brief Метод получения наибольшего дозволенного издания протокола
 *
 * @return наибольшее дозволенное издание протокола
 *
 */
uint16_t nts::client::Context::highest() const noexcept {
	// Выводим наибольшее дозволенное издание протокола
	return (this->_engine != nullptr ? this->_engine->highest() : 0);
}
/**
 * @brief Метод получения издания протокола, согласованного сторонами
 *
 * @return согласованное издание протокола
 *
 */
uint16_t nts::client::Context::version() const noexcept {
	// Выводим согласованное издание протокола
	return (this->_engine != nullptr ? this->_engine->version() : 0);
}
/**
 * @brief Метод установки предлагаемых кривых обмена ключами
 *
 * @param groups устанавливаемые кривые обмена ключами
 *
 */
void nts::client::Context::groups(const vector <extension::group_t> & groups) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых кривых обмена ключами
		this->_engine->groups(groups);
}
/**
 * @brief Метод установки групп обмена, по которым приветствием шлются доли ключа
 *
 * @param shares устанавливаемые группы долей ключа
 *
 */
void nts::client::Context::shares(const vector <extension::group_t> & shares) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку групп долей ключа
		this->_engine->shares(shares);
}
/**
 * @brief Метод установки признаваемых схем подписи
 *
 * @param schemes устанавливаемые схемы подписи
 *
 */
void nts::client::Context::schemes(const vector <extension::scheme_t> & schemes) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку признаваемых схем подписи
		this->_engine->schemes(schemes);
}
/**
 * @brief Метод установки алгоритмов сжатия цепочки сертификатов
 *
 * @param codecs    устанавливаемые алгоритмы в порядке предпочтения
 * @param inflation предел длины цепочки после распаковки в байтах, ноль оставляет умолчание
 *
 */
void nts::client::Context::codecs(const vector <context::codec_t> & codecs, const size_t inflation) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку алгоритмов сжатия цепочки сертификатов
		this->_engine->codecs(codecs, inflation);
}
/**
 * @brief Метод установки запроса состояния сертификата собеседника
 *
 * @param request запрашивается ли состояние сертификата собеседника
 *
 */
void nts::client::Context::status(const bool request) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку запроса состояния сертификата собеседника
		this->_engine->inquire(request);
}
/**
 * @brief Метод установки ответа о состоянии своего сертификата для сшивки
 *
 * @param response запись ответа OCSP, пустая снимает ответ
 * @param index    место сертификата в своей цепочке
 *
 */
void nts::client::Context::status(const vector <uint8_t> & response, const size_t index) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку ответа о состоянии своего сертификата
		this->_engine->staple(response, index);
}
/**
 * @brief Метод получения ответа о состоянии сертификата собеседника
 *
 * @return запись ответа OCSP либо пустой накопитель
 *
 */
const vector <uint8_t> & nts::client::Context::status() const noexcept {
	// Пустой накопитель на случай незаведённой связи
	static const vector <uint8_t> empty;
	// Выводим ответ о состоянии сертификата собеседника
	return ((this->_engine != nullptr) ? this->_engine->status() : empty);
}
/**
 * @brief Метод установки проверки принятого ответа о состоянии сертификата
 *
 * @param verify проверяется ли принятый ответ связью
 * @param leeway дозволенный люфт сроков ответа в секундах
 * @param store  запас доверенных сертификатов для розыска издателя собеседника
 *
 */
void nts::client::Context::verification(const bool verify, const int64_t leeway, const trust::store_t & store) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку проверки принятого ответа о состоянии
		this->_engine->verification(verify, leeway, store);
}
/**
 * @brief Метод получения состояния сертификата собеседника
 *
 * @return состояние по проверенному ответу либо NONE
 *
 */
nts::ocsp::status_t nts::client::Context::certified() const noexcept {
	// Выводим состояние сертификата собеседника
	return ((this->_engine != nullptr) ? this->_engine->certified() : ocsp::status_t::NONE);
}
/**
 * @brief Метод установки подлинности своей стороны связи
 *
 * @param credential устанавливаемая подлинность своей стороны
 *
 */
void nts::client::Context::credential(const context::credential_t & credential) noexcept {
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
void nts::client::Context::name(const string & name) noexcept {
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
void nts::client::Context::protocols(const vector <string> & protocols) noexcept {
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
void nts::client::Context::moment(const int64_t moment) noexcept {
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
void nts::client::Context::resume(const context::ticket_t & ticket) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку билетов возобновления связи
		this->_engine->resume(ticket);
}
/**
 * @brief Метод установки заранее разделённого ключа издания TLS 1.2
 *
 * @param psk настройки заранее разделённого ключа
 *
 */
void nts::client::Context::psk(const context::psk_t & psk) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку заранее разделённого ключа
		this->_engine->psk(psk);
}
/**
 * @brief Метод установки требования порядка «шифрование, затем имитовставка» RFC 7366
 *
 * @param required обязателен ли порядок encrypt_then_mac при наборе CBC
 *
 */
void nts::client::Context::etm(const bool required) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку требования порядка
		this->_engine->etm(required);
}
/**
 * @brief Метод проверки согласованного порядка «шифрование, затем имитовставка»
 *
 * @return признак того, что записи CBC идут в порядке encrypt_then_mac RFC 7366
 *
 */
bool nts::client::Context::etm() const noexcept {
	// Выводим согласованный порядок
	return ((this->_engine != nullptr) && this->_engine->etm());
}
/**
 * @brief Метод установки вставки своих значений GREASE (RFC 8701)
 *
 * @param grease вставляются ли значения GREASE
 *
 */
void nts::client::Context::grease(const bool grease) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку вставки значений GREASE
		this->_engine->grease(grease);
}
/**
 * @brief Метод проверки вставки своих значений GREASE
 *
 * @return признак того, что значения GREASE вставляются
 *
 */
bool nts::client::Context::grease() const noexcept {
	// Выводим признак вставки значений GREASE
	return ((this->_engine != nullptr) && this->_engine->grease());
}
/**
 * @brief Метод установки профиля отпечатка, по которому складывается приветствие клиента
 *
 * @param profile профиль отпечатка, снятый с приветствия обозревателя
 *
 * @return        отказ установки
 *
 */
context::error_t nts::client::Context::profile(const fingerprint::profile_t & profile) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог установки профиля
	return this->_engine->profile(profile);
}
/**
 * @brief Метод проверки возобновления связи билетом
 *
 * @return признак того, что связь возобновлена заранее разделённым ключом
 *
 */
bool nts::client::Context::shared() const noexcept {
	// Выводим признак возобновления связи заранее разделённым ключом
	return (this->_engine != nullptr ? this->_engine->shared() : false);
}
/**
 * @brief Метод установки предложения упреждающих данных
 *
 * @param advance предлагаются либо принимаются ли упреждающие данные
 *
 */
void nts::client::Context::advance(const bool advance, const uint32_t limit) noexcept {
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
bool nts::client::Context::accepted() const noexcept {
	// Выводим признак приёма упреждающих данных сервером
	return (this->_engine != nullptr ? this->_engine->accepted() : false);
}
/**
 * @brief Метод установки порядка смены ключей по счётчику записей
 *
 * @param automatic сменяет ли движок ключи сам по счётчику записей
 * @param records   число записей направления, по которому идёт смена
 *
 */
void nts::client::Context::renewal(const bool automatic, const uint64_t records) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку порядка смены ключей по счётчику записей
		this->_engine->renewal(automatic, records);
}
/**
 * @brief Метод получения счётчика записей направления связи
 *
 * @param incoming запрашивается ли направление собеседника
 *
 * @return         число записей направления на текущих ключах
 *
 */
uint64_t nts::client::Context::sequence(const bool incoming) const noexcept {
	// Выводим счётчик записей запрошенного направления связи
	return (this->_engine != nullptr ? this->_engine->sequence(incoming) : 0);
}
/**
 * @brief Метод установки способа переноса рукопожатия
 *
 * @param transport устанавливаемый способ переноса
 *
 */
void nts::client::Context::transport(const context::transport_t transport) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Устанавливаем способ переноса рукопожатия
		this->_engine->transport(transport);
}
/**
 * @brief Метод получения способа переноса рукопожатия
 *
 * @return способ переноса рукопожатия связи
 *
 */
context::transport_t nts::client::Context::transport() const noexcept {
	// Выводим способ переноса рукопожатия связи
	return (this->_engine != nullptr ? this->_engine->transport() : context::transport_t::RECORDS);
}
/**
 * @brief Метод установки своих параметров переноса QUIC
 *
 * @param parameters устанавливаемые параметры переноса
 *
 */
void nts::client::Context::parameters(const vector <uint8_t> & parameters) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Устанавливаем свои параметры переноса QUIC
		this->_engine->parameters(parameters);
}
/**
 * @brief Метод получения параметров переноса QUIC собеседника
 *
 * @return параметры переноса, принятые от собеседника
 *
 */
const vector <uint8_t> & nts::client::Context::parameters() const noexcept {
	// Параметры, выводимые при незаведённом ведении связи
	static const vector <uint8_t> parameters;
	// Выводим параметры переноса, принятые от собеседника
	return (this->_engine != nullptr ? this->_engine->parameters() : parameters);
}
/**
 * @brief Метод проверки приёма параметров переноса собеседника
 *
 * @return признак того, что параметры переноса собеседника приняты
 *
 */
bool nts::client::Context::acquired() const noexcept {
	// Выводим признак приёма параметров переноса собеседника
	return (this->_engine != nullptr ? this->_engine->acquired() : false);
}
/**
 * @brief Метод подачи связи сообщений рукопожатия уровня защиты
 *
 * @param level уровень защиты, на котором сообщения приняты
 * @param data  принятые сообщения рукопожатия без обвязки записей
 *
 * @return      отказ разбора принятых сообщений
 *
 */
context::error_t nts::client::Context::push(const context::level_t level, const view_t & data) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог разбора принятых сообщений уровня
	return this->_engine->push(level, data);
}
/**
 * @brief Метод получения сообщений рукопожатия, отправляемых на уровне защиты
 *
 * @param level уровень защиты, сообщения которого запрашиваются
 *
 * @return      накопленные сообщения рукопожатия уровня
 *
 */
view_t nts::client::Context::output(const context::level_t level) const noexcept {
	// Выводим накопленные сообщения рукопожатия уровня
	return (this->_engine != nullptr ? this->_engine->output(level) : view_t());
}
/**
 * @brief Метод снятия отправленных сообщений с накопителя уровня защиты
 *
 * @param level уровень защиты, с накопителя которого снимаются сообщения
 * @param size  размер снимаемых байтов
 *
 */
void nts::client::Context::consume(const context::level_t level, const size_t size) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем снятие отправленных сообщений с накопителя уровня
		this->_engine->consume(level, size);
}
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
bool nts::client::Context::secret(const context::level_t level, const context::direction_t direction, uint8_t * result, size_t & size) const noexcept {
	// Выводим итог получения значения направления связи уровня
	return (this->_engine != nullptr ? this->_engine->secret(level, direction, result, size) : false);
}
/**
 * @brief Метод получения уровня защиты, ключи которого готовы направлению
 *
 * @param direction направление связи относительно своей стороны
 *
 * @return          наивысший уровень защиты, ключи которого у направления есть
 *
 */
context::level_t nts::client::Context::level(const context::direction_t direction) const noexcept {
	// Выводим уровень защиты, ключи которого готовы направлению
	return (this->_engine != nullptr ? this->_engine->level(direction) : context::level_t::NONE);
}
/**
 * @brief Метод проверки хода упреждающих данных прямо сейчас
 *
 * @return признак того, что упреждающие данные идут прямо сейчас
 *
 */
bool nts::client::Context::earlying() const noexcept {
	// Выводим признак хода упреждающих данных
	return (this->_engine != nullptr ? this->_engine->earlying() : false);
}
/**
 * @brief Метод проверки отказа сервера от предложенных упреждающих данных
 *
 * @return признак того, что упреждение предлагалось и сервером отвергнуто
 *
 */
bool nts::client::Context::rejected() const noexcept {
	// Выводим признак отвергнутого сервером упреждения
	return (this->_engine != nullptr ? this->_engine->rejected() : false);
}
/**
 * @brief Метод установки размера дейтаграммы связи
 *
 * @param mtu устанавливаемый размер дейтаграммы в байтах
 *
 */
void nts::client::Context::mtu(const size_t mtu) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку размера дейтаграммы связи
		this->_engine->mtu(mtu);
}
/**
 * @brief Метод получения размера дейтаграммы связи
 *
 * @return размер дейтаграммы в байтах
 *
 */
size_t nts::client::Context::mtu() const noexcept {
	// Выводим размер дейтаграммы связи
	return (this->_engine != nullptr ? this->_engine->mtu() : 0);
}
/**
 * @brief Метод получения срока ожидания повторной передачи
 *
 * @return срок ожидания в миллисекундах, ноль, когда ждать нечего
 *
 */
uint32_t nts::client::Context::timeout() const noexcept {
	// Выводим срок ожидания повторной передачи
	return (this->_engine != nullptr ? this->_engine->timeout() : 0);
}
/**
 * @brief Метод извещения связи об истечении срока ожидания
 *
 * @return отказ повторной передачи
 *
 */
context::error_t nts::client::Context::elapsed() noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог повторной передачи залпа
	return this->_engine->elapsed();
}
/**
 * @brief Метод получения числа молча отброшенных записей и дейтаграмм
 *
 * @return число отброшенных записей и дейтаграмм
 *
 */
uint64_t nts::client::Context::discarded() const noexcept {
	// Выводим число отброшенных записей и дейтаграмм
	return (this->_engine != nullptr ? this->_engine->discarded() : 0);
}
/**
 * @brief Метод получения числа отброшенного по причине
 *
 * @param reason причина отброса
 *
 * @return       число записей и дейтаграмм, отброшенных по этой причине
 *
 */
uint64_t nts::client::Context::discarded(const datagram::reason_t reason) const noexcept {
	// Выводим число отброшенного по причине
	return (this->_engine != nullptr ? this->_engine->discarded(reason) : 0);
}
/**
 * @brief Метод заведения связи
 *
 * @return отказ заведения связи
 *
 */
context::error_t nts::client::Context::start() noexcept {
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
void nts::client::Context::clear() noexcept {
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
context::error_t nts::client::Context::push(const view_t & data) noexcept {
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
view_t nts::client::Context::output() const noexcept {
	// Выводим накопленные байты, отправляемые собеседнику
	return (this->_engine != nullptr ? this->_engine->output() : view_t());
}
/**
 * @brief Метод снятия отправленных байтов с накопителя
 *
 * @param size размер снимаемых байтов
 *
 */
void nts::client::Context::consume(const size_t size) noexcept {
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
context::error_t nts::client::Context::write(const view_t & data) noexcept {
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
context::error_t nts::client::Context::read(vector <uint8_t> & result) noexcept {
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
context::error_t nts::client::Context::update(const bool request) noexcept {
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
context::error_t nts::client::Context::close() noexcept {
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
nts::client::Context::Context() noexcept : _engine(nullptr) {
	/**
	 * Выполняем заведение ведения связи
	 */
	try {
		// Выполняем создание объекта ведения связи
		this->_engine = make_unique <internal::engine_t> (false);
	/**
	 * Если памяти под ведение связи не хватило
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс объекта ведения связи
		this->_engine = nullptr;
	}
}
/**
 * @brief Деструктор
 *
 */
nts::client::Context::~Context() noexcept {
	// Уничтожаем объект ведения связи здесь, где его тип полон
	this->_engine.reset();
}
