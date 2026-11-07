/**
 * @file server.cpp
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
 * @brief Исходный файл фасада связи сервера протокола TLS 1.3
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
#include <server/server.hpp>
#include <record/record.hpp>
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
context::state_t nts::server::Context::state() const noexcept {
	// Выводим состояние связи
	return (this->_engine != nullptr ? this->_engine->state() : context::state_t::NONE);
}
/**
 * @brief Метод получения отказа, которым связь оборвана
 *
 * @return отказ, которым связь оборвана
 *
 */
context::error_t nts::server::Context::error() const noexcept {
	// Выводим отказ, которым связь оборвана
	return (this->_engine != nullptr ? this->_engine->error() : context::error_t::MEMORY);
}
/**
 * @brief Метод проверки установленности связи
 *
 * @return признак того, что рукопожатие пройдено обеими сторонами
 *
 */
bool nts::server::Context::established() const noexcept {
	// Выводим признак установленности связи
	return (this->state() == context::state_t::ESTABLISHED);
}
/**
 * @brief Метод отправки запроса сердцебиения (RFC 6520)
 *
 * @param payload нагрузка запроса: ответ собеседника обязан вернуть её слово в слово
 * @return  отказ отправки: STATE вне установленной связи либо при запросе в пути, SETTINGS без
 *          расширения либо дозволения, LIMIT при нагрузке шире записи
 *
 *          расширения либо дозволения, LIMIT при нагрузке шире записи
 *
 */
context::error_t nts::server::Context::heartbeat(const view_t & payload) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог отправки запроса
	return this->_engine->heartbeat(payload);
}
/**
 * @brief Метод получения числа принятых ответов на свои запросы сердцебиения
 *
 * @return число ответов с ожидаемой нагрузкой
 *
 */
size_t nts::server::Context::pulses() const noexcept {
	// Выводим число ответов движка либо ноль
	return ((this->_engine != nullptr) ? this->_engine->pulses() : 0);
}
/**
 * @brief Метод получения предела длины открытого содержимого отправляемой записи
 *
 * @return  предел в байтах
 *
 */
size_t nts::server::Context::ceiling() const noexcept {
	// Выводим предел отправки движка либо предел протокола
	return ((this->_engine != nullptr) ? this->_engine->ceiling() : record::RECORD_PLAINTEXT);
}
/**
 * @brief Метод получения предела длины открытого содержимого принимаемой записи
 *
 * @return  предел в байтах
 *
 */
size_t nts::server::Context::threshold() const noexcept {
	// Выводим предел приёма движка либо предел протокола
	return ((this->_engine != nullptr) ? this->_engine->threshold() : record::RECORD_PLAINTEXT);
}
/**
 * @brief Метод получения извещения, которым связь оборвана
 *
 * @return извещение, которым связь оборвана
 *
 */
const alert::alert_t & nts::server::Context::alert() const noexcept {
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
protect::suite_t nts::server::Context::suite() const noexcept {
	// Выводим согласованный сторонами набор шифрования
	return (this->_engine != nullptr ? this->_engine->suite() : protect::suite_t::NONE);
}
/**
 * @brief Метод получения группы обмена ключами связи
 *
 * @return согласованная сторонами группа обмена ключами
 *
 */
extension::group_t nts::server::Context::group() const noexcept {
	// Выводим согласованную сторонами группу обмена ключами
	return (this->_engine != nullptr ? this->_engine->group() : extension::group_t::NONE);
}
/**
 * @brief Метод получения цепочки сертификатов собеседника
 *
 * @return цепочка сертификатов, предъявленная собеседником
 *
 */
const vector <vector <uint8_t>> & nts::server::Context::peer() const noexcept {
	// Цепочка, выводимая при незаведённом ведении связи
	static const vector <vector <uint8_t>> chain;
	// Выводим цепочку сертификатов, предъявленную собеседником
	return (this->_engine != nullptr ? this->_engine->peer() : chain);
}
/**
 * @brief Метод получения имени узла, запрошенного клиентом
 *
 * @return имя узла, за которым клиент пришёл
 *
 */
const string & nts::server::Context::name() const noexcept {
	// Имя, выводимое при незаведённом ведении связи
	static const string empty;
	// Выводим имя узла, запрошенное клиентом у сервера
	return (this->_engine != nullptr ? this->_engine->name() : empty);
}
/**
 * @brief Метод получения алгоритма сжатия цепочки сертификатов направления
 *
 * @param direction направление связи относительно своей стороны
 * @return          опознаватель алгоритма по реестру RFC 8879, ноль у несжатой цепочки
 *
 */
uint16_t nts::server::Context::compression(const context::direction_t direction) const noexcept {
	// Выводим алгоритм сжатия цепочки направления, ноль без ведения связи
	return ((this->_engine != nullptr) ? this->_engine->compression(direction) : 0);
}
/**
 * @brief Метод получения прикладного протокола связи
 *
 * @return прикладной протокол, выбранный сторонами связи
 *
 */
const string & nts::server::Context::protocol() const noexcept {
	// Название, выводимое при незаведённом ведении связи
	static const string empty;
	// Выводим прикладной протокол, выбранный сторонами связи
	return (this->_engine != nullptr ? this->_engine->protocol() : empty);
}
/**
 * @brief Метод получения билетов возобновления связи
 *
 * @return билеты возобновления связи, выданные клиенту
 *
 */
const vector <context::ticket_t> & nts::server::Context::tickets() const noexcept {
	// Билеты, выводимые при незаведённом ведении связи
	static const vector <context::ticket_t> tickets;
	// Выводим билеты возобновления связи
	return (this->_engine != nullptr ? this->_engine->tickets() : tickets);
}
/**
 * @brief Метод выдачи билета возобновления связи клиенту
 *
 * @return отказ выдачи билета возобновления связи
 *
 */
context::error_t nts::server::Context::issue() noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог выдачи билета возобновления связи
	return this->_engine->issue();
}
/**
 * @brief Метод установки предлагаемых наборов шифрования
 *
 * @param suites устанавливаемые наборы шифрования
 * @return перечень наборов шифрования: назначенный потребителем либо умолчание
 *
 */
void nts::server::Context::suites(const vector <protect::suite_t> & suites) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых наборов шифрования
		this->_engine->suites(suites);
}
/**
 * @brief Метод установки журнала секретов связи
 *
 * @param keylog журнал секретов: вызов и контекст потребителя
 *
 */
void nts::server::Context::keylog(const context::keylog_t & keylog) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку журнала секретов
		this->_engine->keylog(keylog);
}
/**
 * @brief Метод установки закреплённого сырого открытого ключа клиента
 *
 * @param pinned закреплённый ключ SPKI DER; пустой - проверка X.509
 *
 */
void nts::server::Context::pinned(const view_t & pinned) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку закреплённого ключа
		this->_engine->pinned(pinned);
}
/**
 * @brief Метод получения предлагаемых наборов шифрования
 *
 * @return перечень наборов шифрования: назначенный потребителем либо умолчание
 *
 */
const vector <nts::protect::suite_t> & nts::server::Context::suites() const noexcept {
	// Пустой перечень на случай незаведённого ведения связи
	static const vector <protect::suite_t> empty;
	// Выводим перечень предлагаемых наборов шифрования
	return (this->_engine != nullptr ? this->_engine->suites() : empty);
}
/**
 * @brief Метод установки пределов издания протокола
 *
 * @param lowest  наименьшее дозволенное издание: 0x0303 (издание 1.2) либо 0x0304 (издание 1.3)
 * @param highest наибольшее дозволенное издание: 0x0303 либо 0x0304
 * @return        отказ установки: SETTINGS у издания ниже TLS 1.2 либо перевёрнутых
 *                пределов, STATE у уже заведённой связи
 *
 *                пределов, STATE у уже заведённой связи
 *
 */
context::error_t nts::server::Context::versions(const uint16_t lowest, const uint16_t highest) noexcept {
	// Выводим итог установки пределов издания протокола
	return (this->_engine != nullptr ? this->_engine->versions(lowest, highest) : context::error_t::MEMORY);
}
/**
 * @brief Метод установки обязательности расширенного главного секрета издания 1.2
 *
 * @param mandatory отвергается ли собеседник без расширения RFC 7627
 * @return признак того, что собеседник без расширения RFC 7627 отвергается
 *
 */
void nts::server::Context::master(const bool mandatory) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку обязательности расширенного главного секрета
		this->_engine->master(mandatory);
}
/**
 * @brief Метод проверки обязательности расширенного главного секрета издания 1.2
 *
 * @return признак того, что собеседник без расширения RFC 7627 отвергается
 *
 */
bool nts::server::Context::master() const noexcept {
	// Выводим обязательность расширенного главного секрета
	return ((this->_engine != nullptr) && this->_engine->master());
}
/**
 * @brief Метод получения наименьшего дозволенного издания протокола
 *
 * @return наименьшее дозволенное издание протокола
 *
 */
uint16_t nts::server::Context::lowest() const noexcept {
	// Выводим наименьшее дозволенное издание протокола
	return (this->_engine != nullptr ? this->_engine->lowest() : 0);
}
/**
 * @brief Метод получения наибольшего дозволенного издания протокола
 *
 * @return наибольшее дозволенное издание протокола
 *
 */
uint16_t nts::server::Context::highest() const noexcept {
	// Выводим наибольшее дозволенное издание протокола
	return (this->_engine != nullptr ? this->_engine->highest() : 0);
}
/**
 * @brief Метод получения издания протокола, согласованного сторонами
 *
 * @return 0x0304 у издания 1.3, 0x0303 у издания 1.2, ноль до согласования
 *
 */
uint16_t nts::server::Context::version() const noexcept {
	// Выводим согласованное издание протокола
	return (this->_engine != nullptr ? this->_engine->version() : 0);
}
/**
 * @brief Метод установки порядка выбора набора шифрования и кривой обмена ключами
 *
 * @param own выбираются ли набор и кривая порядком сервера (умолчание), а не клиента
 *
 */
void nts::server::Context::preference(const bool own) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку порядка выбора набора шифрования
		this->_engine->preference(own);
}
/**
 * @brief Метод установки предлагаемых кривых обмена ключами
 *
 * @param groups устанавливаемые кривые обмена ключами
 * @return перечень кривых обмена ключами: назначенный потребителем либо умолчание
 *
 */
void nts::server::Context::groups(const vector <extension::group_t> & groups) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых кривых обмена ключами
		this->_engine->groups(groups);
}
/**
 * @brief Метод получения предлагаемых кривых обмена ключами
 *
 * @return перечень кривых обмена ключами: назначенный потребителем либо умолчание
 *
 */
const vector <nts::extension::group_t> & nts::server::Context::groups() const noexcept {
	// Пустой перечень на случай незаведённого ведения связи
	static const vector <extension::group_t> empty;
	// Выводим перечень предлагаемых кривых обмена ключами
	return (this->_engine != nullptr ? this->_engine->groups() : empty);
}
/**
 * @brief Метод установки признаваемых схем подписи
 *
 * @param schemes устанавливаемые схемы подписи
 * @return перечень схем подписи: назначенный потребителем либо умолчание
 *
 */
void nts::server::Context::schemes(const vector <extension::scheme_t> & schemes) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку признаваемых схем подписи
		this->_engine->schemes(schemes);
}
/**
 * @brief Метод получения признаваемых схем подписи
 *
 * @return перечень схем подписи: назначенный потребителем либо умолчание
 *
 */
const vector <nts::extension::scheme_t> & nts::server::Context::schemes() const noexcept {
	// Пустой перечень на случай незаведённого ведения связи
	static const vector <extension::scheme_t> empty;
	// Выводим перечень признаваемых схем подписи
	return (this->_engine != nullptr ? this->_engine->schemes() : empty);
}
/**
 * @brief Метод установки алгоритмов сжатия цепочки сертификатов
 *
 * @param codecs    устанавливаемые алгоритмы в порядке предпочтения
 * @param inflation предел длины цепочки после распаковки в байтах, ноль оставляет умолчание 65536
 *
 */
void nts::server::Context::codecs(const vector <context::codec_t> & codecs, const size_t inflation) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку алгоритмов сжатия цепочки сертификатов
		this->_engine->codecs(codecs, inflation);
}
/**
 * @brief Метод установки запроса состояния сертификата собеседника
 *
 * @param request запрашивается ли состояние сертификата собеседника
 * @return запись ответа OCSP либо пустой накопитель
 *
 */
void nts::server::Context::status(const bool request) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку запроса состояния сертификата собеседника
		this->_engine->inquire(request);
}
/**
 * @brief Метод установки ответа о состоянии своего сертификата для сшивки
 *
 * @param response запись ответа OCSP по RFC 6960, пустая снимает ответ
 * @param index    место сертификата в своей цепочке, ноль - лист
 * @return запись ответа OCSP либо пустой накопитель
 *
 */
void nts::server::Context::status(const vector <uint8_t> & response, const size_t index) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку ответа о состоянии своего сертификата
		this->_engine->staple(response, index);
}
/**
 * @brief Метод установки перечня меток времени своего сертификата для выдачи по запросу
 *
 * @param list перечень SignedCertificateTimestampList как записан (RFC 6962, раздел 3.3)
 *
 */
void nts::server::Context::timestamps(const vector <uint8_t> & list) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку перечня меток времени
		this->_engine->timestamps(list);
}
/**
 * @brief Метод получения ответа о состоянии сертификата собеседника
 *
 * @return запись ответа OCSP по RFC 6960 либо пустой накопитель
 *
 */
const vector <uint8_t> & nts::server::Context::status() const noexcept {
	// Пустой накопитель на случай незаведённой связи
	static const vector <uint8_t> empty;
	// Выводим ответ о состоянии сертификата собеседника
	return ((this->_engine != nullptr) ? this->_engine->status() : empty);
}
/**
 * @brief Метод получения ответов о состоянии сертификатов цепочки собеседника
 *
 * @return записи принятых ответов OCSP по местам в цепочке либо пустой накопитель
 *
 */
const vector <vector <uint8_t>> & nts::server::Context::statuses() const noexcept {
	// Пустой накопитель на случай незаведённой связи
	static const vector <vector <uint8_t>> empty;
	// Выводим ответы о состоянии сертификатов цепочки собеседника
	return ((this->_engine != nullptr) ? this->_engine->statuses() : empty);
}
/**
 * @brief Метод вывода экспортируемого ключевого материала связи
 *
 * @param label   метка назначения экспортируемого материала
 * @param context привязка экспортируемого материала к потребителю
 * @param result  место, в которое помещается экспортируемый материал
 * @param size    требуемая длина экспортируемого материала в байтах
 * @param early   признак раннего вывода из значения раннего экспорта
 * @return        отказ вывода экспортируемого материала
 *
 */
context::error_t nts::server::Context::exporting(const view_t & label, const view_t & context, uint8_t * result, const size_t size, const bool early) const noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ вызова не в том состоянии связи
		return context::error_t::STATE;
	// Выводим итог вывода экспортируемого материала связи
	return this->_engine->exporting(label, context, result, size, early);
}
/**
 * @brief Метод установки профилей защиты RTP, предлагаемых связью
 *
 * @param profiles предлагаемые профили защиты RTP
 *
 */
void nts::server::Context::profiles(const vector <uint16_t> & profiles) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Устанавливаем перечень предлагаемых профилей защиты RTP
		this->_engine->profiles(profiles);
}
/**
 * @brief Метод получения профиля защиты RTP, выбранного сторонами связи
 *
 * @return выбранный профиль защиты RTP; 0, если профиль не выбран
 * @param profile место, в которое помещается разобранный профиль приветствия
 *
 *                (`fingerprint::error_t` сведён к MESSAGE, MEMORY при нехватке памяти)
 *
 */
uint16_t nts::server::Context::profile() const noexcept {
	// Выводим выбранный профиль защиты RTP либо ноль без связи
	return ((this->_engine != nullptr) ? this->_engine->profile() : 0);
}
/**
 * @brief Метод установки проверки принятого ответа о состоянии сертификата
 *
 * @param verify проверяется ли принятый ответ связью
 * @param leeway дозволенный люфт сроков ответа в секундах в обе стороны
 * @param store  запас доверенных сертификатов для розыска издателя собеседника
 *
 */
void nts::server::Context::verification(const bool verify, const int64_t leeway, const trust::store_t & store) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку проверки принятого ответа о состоянии
		this->_engine->verification(verify, leeway, store);
}
/**
 * @brief Метод получения состояния сертификата собеседника
 *
 * @return состояние по проверенному ответу либо ocsp::status_t::NONE
 *
 */
nts::ocsp::status_t nts::server::Context::certified() const noexcept {
	// Выводим состояние сертификата собеседника
	return ((this->_engine != nullptr) ? this->_engine->certified() : ocsp::status_t::NONE);
}
/**
 * @brief Метод установки подлинности своей стороны связи
 *
 * @param credential устанавливаемая подлинность своей стороны
 *
 */
void nts::server::Context::credential(const context::credential_t & credential) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку подлинности своей стороны связи
		this->_engine->credential(credential);
}
/**
 * @brief Метод установки предлагаемых прикладных протоколов
 *
 * @param protocols устанавливаемые прикладные протоколы
 *
 */
void nts::server::Context::protocols(const vector <string> & protocols) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предлагаемых прикладных протоколов
		this->_engine->protocols(protocols);
}
/**
 * @brief Метод объявления прикладных настроек ALPS для прикладного протокола
 *
 * @param protocol прикладной протокол, для которого объявляются настройки
 * @param value    прикладные настройки как есть
 * @return прикладные настройки собеседника как есть
 *
 */
void nts::server::Context::settings(const string & protocol, const vector <uint8_t> & value) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем объявление прикладных настроек
		this->_engine->settings(protocol, value);
}
/**
 * @brief Метод установки точки кода расширения прикладных настроек ALPS
 *
 * @param type вид расширения: SETTINGS (0x44CD, новая точка) либо SETTINGS_OLD (0x4469, прежняя)
 * @return вид расширения, которым ведётся связь
 *
 */
void nts::server::Context::codepoint(const extension::type_t type) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку точки кода
		this->_engine->codepoint(static_cast <uint16_t> (type));
}
/**
 * @brief Метод проверки согласования прикладных настроек ALPS
 *
 * @return признак того, что прикладные настройки сторонами согласованы
 *
 */
bool nts::server::Context::settled() const noexcept {
	// Выводим признак согласования прикладных настроек
	return (this->_engine != nullptr ? this->_engine->settled() : false);
}
/**
 * @brief Метод получения прикладных настроек собеседника
 *
 * @return прикладные настройки собеседника как есть
 *
 */
const vector <uint8_t> & nts::server::Context::settings() const noexcept {
	// Пустые настройки на случай незаведённой связи
	static const vector <uint8_t> empty;
	// Выводим прикладные настройки собеседника
	return (this->_engine != nullptr ? this->_engine->settings() : empty);
}
/**
 * @brief Метод получения точки кода расширения прикладных настроек ALPS
 *
 * @return вид расширения, которым ведётся связь: SETTINGS либо SETTINGS_OLD
 *
 */
extension::type_t nts::server::Context::codepoint() const noexcept {
	// Выводим точку кода
	return (this->_engine != nullptr ? static_cast <extension::type_t> (this->_engine->codepoint()) : extension::type_t::SETTINGS);
}
/**
 * @brief Метод установки метки возврата состояния сервера
 *
 * @param cookie устанавливаемая метка возврата состояния
 * @return метка возврата состояния, повторённая клиентом
 *
 */
void nts::server::Context::cookie(const vector <uint8_t> & cookie) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку метки возврата состояния сервера
		this->_engine->cookie(cookie);
}
/**
 * @brief Метод получения метки возврата состояния сервера
 *
 * @return метка возврата состояния, повторённая клиентом
 *
 */
const vector <uint8_t> & nts::server::Context::cookie() const noexcept {
	// Пустая метка возврата состояния, выдаваемая до заведения связи
	static const vector <uint8_t> empty;
	// Выводим метку возврата состояния, повторённую клиентом
	return (this->_engine != nullptr ? this->_engine->cookie() : empty);
}
/**
 * @brief Метод установки мига, которым судятся сроки билетов
 *
 * @param moment устанавливаемый миг в секундах
 *
 */
void nts::server::Context::moment(const int64_t moment) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку мига суждения о сроках билетов
		this->_engine->moment(moment);
}
/**
 * @brief Метод установки срока жизни выдаваемых билетов
 *
 * @param lifetime устанавливаемый срок в секундах
 *
 */
void nts::server::Context::lifetime(const uint32_t lifetime) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку срока жизни выдаваемых билетов
		this->_engine->lifetime(lifetime);
}
/**
 * @brief Метод установки требования подлинности клиента
 *
 * @param request устанавливаемое требование подлинности клиента
 *
 */
void nts::server::Context::request(const bool request) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку требования подлинности клиента
		this->_engine->request(request);
}
/**
 * @brief Метод установки перечня доверенных удостоверяющих центров для запроса подлинности
 *
 * @param names имена центров как записаны (DER X.501 Name)
 *
 */
void nts::server::Context::authorities(const vector <vector <uint8_t>> & names) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку перечня доверенных центров
		this->_engine->authorities(names);
}
/**
 * @brief Метод установки выработки следующего протокола NPN
 *
 * @param negotiation объявляется ли перечень протоколов по запросу клиента
 *
 */
void nts::server::Context::negotiation(const bool negotiation) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку выработки NPN
		this->_engine->negotiation(negotiation);
}
/**
 * @brief Метод проверки выработки протокола связи через NPN
 *
 * @return признак того, что protocol() взят выработкой NPN, а не ALPN
 *
 */
bool nts::server::Context::negotiated() const noexcept {
	// Выводим признак выработки NPN
	return (this->_engine != nullptr ? this->_engine->negotiated() : false);
}
/**
 * @brief Метод установки признаваемых билетов возобновления связи
 *
 * @param tickets признаваемые билеты возобновления связи
 *
 */
void nts::server::Context::resume(const vector <context::ticket_t> & tickets) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку билетов возобновления связи
		this->_engine->resume(tickets);
}
/**
 * @brief Метод установки заранее разделённого ключа издания TLS 1.2
 *
 * @param psk настройки заранее разделённого ключа: вызов respond «дано identity - ключ либо отказ», необязательная подсказка identity и признак disclose
 *
 */
void nts::server::Context::psk(const context::psk_t & psk) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку заранее разделённого ключа
		this->_engine->psk(psk);
}
/**
 * @brief Метод установки выбора подлинности по имени узла из приветствия клиента
 *
 * @param select настройки выбора подлинности: вызов «дано имя - подлинность, общая подлинность либо отказ»
 *
 */
void nts::server::Context::select(const context::select_t & select) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку выбора подлинности по имени узла
		this->_engine->select(select);
}
/**
 * @brief Метод установки требования порядка «шифрование, затем имитовставка» RFC 7366
 *
 * @param required обязателен ли порядок encrypt_then_mac при наборе CBC
 * @return признак того, что записи CBC идут в порядке encrypt_then_mac RFC 7366
 *
 */
void nts::server::Context::etm(const bool required) noexcept {
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
bool nts::server::Context::etm() const noexcept {
	// Выводим согласованный порядок
	return ((this->_engine != nullptr) && this->_engine->etm());
}
/**
 * @brief Метод установки вставки своих значений GREASE (RFC 8701)
 *
 * @param grease вставляются ли значения GREASE
 * @return признак того, что значения GREASE вставляются
 *
 */
void nts::server::Context::grease(const bool grease) noexcept {
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
bool nts::server::Context::grease() const noexcept {
	// Выводим признак вставки значений GREASE
	return ((this->_engine != nullptr) && this->_engine->grease());
}
/**
 * @brief Метод установки классов затирания памяти связи
 *
 * @param classes классы затирания context::wiping_t
 * @return классы затирания, объявленные потребителем; умолчание - SECRETS
 *
 */
void nts::server::Context::wiping(const vector <context::wiping_t> & classes) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку классов затирания
		this->_engine->wiping(classes);
}
/**
 * @brief Метод получения классов затирания памяти связи
 *
 * @return классы затирания, объявленные потребителем; умолчание - SECRETS
 *
 */
const vector <context::wiping_t> & nts::server::Context::wiping() const noexcept {
	// Пустой перечень на случай незаведённого ведения связи
	static const vector <context::wiping_t> NOTHING;
	// Выводим классы затирания
	return ((this->_engine != nullptr) ? this->_engine->wiping() : NOTHING);
}
/**
 * @brief Метод снятия профиля отпечатка с принятого приветствия клиента
 *
 * @param profile место, в которое помещается разобранный профиль приветствия
 * @return        отказ снятия: STATE до приёма приветствия, иначе отказ разбора
 *                (`fingerprint::error_t` сведён к MESSAGE, MEMORY при нехватке памяти)
 *
 *                (`fingerprint::error_t` сведён к MESSAGE, MEMORY при нехватке памяти)
 *
 */
context::error_t nts::server::Context::profile(fingerprint::profile_t & profile) const noexcept {
	// Если ведение связи не заведено либо приветствие не принято
	if((this->_engine == nullptr) || this->_engine->received().empty())
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Отказ разбора приветствия
	const fingerprint::error_t failure = fingerprint::parse(view_t(this->_engine->received().data(), this->_engine->received().size()), profile, (this->_engine->transport() == context::transport_t::DATAGRAMS));
	// Выводим итог разбора: нехватка памяти своим кодом, прочие отказы - сообщением
	return ((failure == fingerprint::error_t::NONE) ? context::error_t::NONE : ((failure == fingerprint::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::MESSAGE));
}
/**
 * @brief Метод получения принятого приветствия клиента байтами
 *
 * @return байты приветствия клиента вместе с обвязкой сообщения рукопожатия (пусто до приёма)
 *
 */
view_t nts::server::Context::greeting() const noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим пустоту
		return view_t(nullptr, 0);
	// Выводим принятое приветствие
	return view_t(this->_engine->received().data(), this->_engine->received().size());
}
/**
 * @brief Метод установки ключа зашифрованного приветствия ECH серверу (RFC 9849)
 *
 * @param secret секретный ключ X25519 (32 байта) либо пусто - ключ порождается
 * @param name   публичное имя конфигурации: им идёт внешнее приветствие клиента
 * @param id     опознаватель конфигурации (один случайный байт у потребителя)
 * @param length наибольшая длина имени узла в множестве анонимности: правит заполнение клиента
 * @return       отказ установки: STATE после `start()`, SETTINGS при негодном ключе либо имени, MEMORY
 *
 */
context::error_t nts::server::Context::ech(const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог установки ключа
	return this->_engine->ech(view_t(secret.data(), secret.size()), name, id, length);
}
/**
 * @brief Метод установки удержанной конфигурации ECH серверу: принимается, но не объявляется
 *
 * @param secret секретный ключ X25519 (32 байта) либо пусто - ключ порождается
 * @param name   публичное имя конфигурации
 * @param id     опознаватель конфигурации: занятый прежней конфигурацией заменяет её
 * @param length наибольшая длина имени узла
 * @return  отказ установки: STATE после `start()`, SETTINGS при негодном ключе либо имени, MEMORY
 *
 */
context::error_t nts::server::Context::retain(const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог установки удержанной конфигурации
	return this->_engine->retain(view_t(secret.data(), secret.size()), name, id, length);
}
/**
 * @brief Метод установки ключа ECH серверу со способом инкапсуляции (RFC 9849)
 *
 * @param kem    способ инкапсуляции ключа HPKE
 * @param secret секретный ключ способа либо пусто - ключ порождается
 * @param name   публичное имя конфигурации: им идёт внешнее приветствие клиента
 * @param id     опознаватель конфигурации (один случайный байт у потребителя)
 * @param length наибольшая длина имени узла в множестве анонимности: правит заполнение клиента
 * @return       отказ установки: STATE после `start()`, SETTINGS при негодном ключе, имени либо способе, MEMORY
 *
 */
context::error_t nts::server::Context::ech(const hpke::kem_t kem, const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог установки ключа со способом
	return this->_engine->ech(kem, view_t(secret.data(), secret.size()), name, id, length);
}
/**
 * @brief Метод установки удержанной конфигурации ECH серверу со способом инкапсуляции: принимается, но не объявляется
 *
 * @param kem    способ инкапсуляции ключа HPKE
 * @param secret секретный ключ способа либо пусто - ключ порождается
 * @param name   публичное имя конфигурации
 * @param id     опознаватель конфигурации: занятый прежней конфигурацией заменяет её
 * @param length наибольшая длина имени узла
 * @return       отказ установки: STATE после `start()`, SETTINGS при негодном ключе, имени либо способе, MEMORY
 *
 */
context::error_t nts::server::Context::retain(const hpke::kem_t kem, const vector <uint8_t> & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Если ведение связи не заведено
	if(this->_engine == nullptr)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Выводим итог установки удержанной конфигурации со способом
	return this->_engine->retain(kem, view_t(secret.data(), secret.size()), name, id, length);
}
/**
 * @brief Метод получения перечня конфигураций ECH для записи DNS HTTPS
 *
 * @return перечень ECHConfigList байтами (пусто без ключа)
 *
 */
const vector <uint8_t> & nts::server::Context::ech() const noexcept {
	// Пустой перечень
	static const vector <uint8_t> NOTHING;
	// Выводим перечень
	return ((this->_engine != nullptr) ? this->_engine->ech() : NOTHING);
}
/**
 * @brief Метод проверки принятия ECH связью
 *
 * @return признак того, что рукопожатие идёт по раскрытому внутреннему приветствию
 *
 */
bool nts::server::Context::shrouded() const noexcept {
	// Выводим признак принятия
	return ((this->_engine != nullptr) && this->_engine->shrouded());
}
/**
 * @brief Метод установки ключа билетов сеансов издания TLS 1.2
 *
 * @param secret секрет любой длины, из которого выводятся имя ключа, ключ шифрования и ключ имитовставки
 *
 */
void nts::server::Context::vault(const vector <uint8_t> & secret) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку ключа билетов сеансов
		this->_engine->vault(secret);
}
/**
 * @brief Метод проверки возобновления связи билетом
 *
 * @return признак того, что связь возобновлена заранее разделённым ключом
 *
 */
bool nts::server::Context::shared() const noexcept {
	// Выводим признак возобновления связи заранее разделённым ключом
	return (this->_engine != nullptr ? this->_engine->shared() : false);
}
/**
 * @brief Метод установки приёма упреждающих данных клиента
 *
 * @param advance принимаются ли упреждающие данные
 * @param limit   предел упреждающих данных в байтах, объявляемый билетом
 *
 */
void nts::server::Context::advance(const bool advance, const uint32_t limit) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку предложения упреждающих данных
		this->_engine->advance(advance, limit);
}
/**
 * @brief Метод проверки приёма упреждающих данных связью
 *
 * @return признак того, что упреждающие данные связью приняты
 *
 */
bool nts::server::Context::accepted() const noexcept {
	// Выводим признак приёма упреждающих данных связью
	return (this->_engine != nullptr ? this->_engine->accepted() : false);
}
/**
 * @brief Метод установки порядка смены ключей по счётчику записей
 *
 * @param automatic сменяет ли движок ключи сам по счётчику записей
 * @param records   число записей направления, по которому идёт смена
 *
 */
void nts::server::Context::renewal(const bool automatic, const uint64_t records) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку порядка смены ключей по счётчику записей
		this->_engine->renewal(automatic, records);
}
/**
 * @brief Метод получения счётчика записей направления связи
 *
 * @param incoming запрашивается ли направление собеседника
 * @return         число записей направления на текущих ключах
 *
 */
uint64_t nts::server::Context::sequence(const bool incoming) const noexcept {
	// Выводим счётчик записей запрошенного направления связи
	return (this->_engine != nullptr ? this->_engine->sequence(incoming) : 0);
}
/**
 * @brief Метод установки способа переноса рукопожатия
 *
 * @param transport устанавливаемый способ переноса
 * @return способ переноса рукопожатия связи
 *
 */
void nts::server::Context::transport(const context::transport_t transport) noexcept {
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
context::transport_t nts::server::Context::transport() const noexcept {
	// Выводим способ переноса рукопожатия связи
	return (this->_engine != nullptr ? this->_engine->transport() : context::transport_t::RECORDS);
}
/**
 * @brief Метод установки своих параметров переноса QUIC
 *
 * @param parameters устанавливаемые параметры переноса в записи QUIC
 * @return параметры переноса, принятые от собеседника
 *
 */
void nts::server::Context::parameters(const vector <uint8_t> & parameters) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Устанавливаем свои параметры переноса QUIC
		this->_engine->parameters(parameters);
}
/**
 * @brief Метод получения параметров переноса QUIC собеседника
 *
 * @return параметры переноса, принятые от собеседника как есть
 *
 */
const vector <uint8_t> & nts::server::Context::parameters() const noexcept {
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
bool nts::server::Context::acquired() const noexcept {
	// Выводим признак приёма параметров переноса собеседника
	return (this->_engine != nullptr ? this->_engine->acquired() : false);
}
/**
 * @brief Метод подачи связи сообщений рукопожатия уровня защиты
 *
 * @param level уровень защиты, на котором сообщения приняты
 * @param data  принятые сообщения рукопожатия без обвязки записей (данные CRYPTO)
 * @return      отказ разбора принятых сообщений
 *
 */
context::error_t nts::server::Context::push(const context::level_t level, const view_t & data) noexcept {
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
 * @return      накопленные сообщения рукопожатия уровня без обвязки записей
 *
 */
view_t nts::server::Context::output(const context::level_t level) const noexcept {
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
void nts::server::Context::consume(const context::level_t level, const size_t size) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем снятие отправленных сообщений с накопителя уровня
		this->_engine->consume(level, size);
}
/**
 * @brief Метод получения значения направления связи уровня защиты
 *
 * @param level     уровень защиты: EARLY, HANDSHAKE либо APPLICATION
 * @param direction направление связи относительно своей стороны
 * @param result    место, в которое помещается значение; nullptr - лишь опрос длины
 * @param size      место, в которое помещается длина значения по хешу набора
 * @return          признак того, что значение уровня уже выведено
 *
 */
bool nts::server::Context::secret(const context::level_t level, const context::direction_t direction, uint8_t * result, size_t & size) const noexcept {
	// Выводим итог получения значения направления связи уровня
	return (this->_engine != nullptr ? this->_engine->secret(level, direction, result, size) : false);
}
/**
 * @brief Метод получения уровня защиты, ключи которого готовы направлению
 *
 * @param direction направление связи относительно своей стороны
 * @return          наивысший уровень защиты, ключи которого у направления есть
 *
 */
context::level_t nts::server::Context::level(const context::direction_t direction) const noexcept {
	// Выводим уровень защиты, ключи которого готовы направлению
	return (this->_engine != nullptr ? this->_engine->level(direction) : context::level_t::NONE);
}
/**
 * @brief Метод проверки хода упреждающих данных прямо сейчас
 *
 * @return признак того, что упреждающие данные идут прямо сейчас
 *
 */
bool nts::server::Context::earlying() const noexcept {
	// Выводим признак хода упреждающих данных
	return (this->_engine != nullptr ? this->_engine->earlying() : false);
}
/**
 * @brief Метод установки размера дейтаграммы связи
 *
 * @param mtu устанавливаемый размер дейтаграммы в байтах
 * @return размер дейтаграммы в байтах
 *
 */
void nts::server::Context::mtu(const size_t mtu) noexcept {
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
size_t nts::server::Context::mtu() const noexcept {
	// Выводим размер дейтаграммы связи
	return (this->_engine != nullptr ? this->_engine->mtu() : 0);
}
/**
 * @brief Метод установки строгого сервера без состояния издания DTLS 1.2
 *
 * @param strict принимается ли приветствие клиента до метки лишь целиком одним куском
 * @return признак того, что приветствие клиента до метки принимается лишь целиком
 *
 */
void nts::server::Context::strict(const bool strict) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку строгости сервера без состояния
		this->_engine->strict(strict);
}
/**
 * @brief Метод проверки строгости сервера без состояния издания DTLS 1.2
 *
 * @return признак того, что приветствие клиента до метки принимается лишь целиком
 *
 */
bool nts::server::Context::strict() const noexcept {
	// Выводим строгость сервера без состояния
	return ((this->_engine != nullptr) && this->_engine->strict());
}
/**
 * @brief Метод получения срока ожидания повторной передачи
 *
 * @return срок ожидания в миллисекундах, ноль, когда ждать нечего
 *
 */
uint32_t nts::server::Context::timeout() const noexcept {
	// Выводим срок ожидания повторной передачи
	return (this->_engine != nullptr ? this->_engine->timeout() : 0);
}
/**
 * @brief Метод извещения связи об истечении срока ожидания
 *
 * @return отказ повторной передачи: TIMEOUT по исчерпании попыток
 *
 */
context::error_t nts::server::Context::elapsed() noexcept {
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
 * @param reason причина отброса
 *
 */
uint64_t nts::server::Context::discarded() const noexcept {
	// Выводим число отброшенных записей и дейтаграмм
	return (this->_engine != nullptr ? this->_engine->discarded() : 0);
}
/**
 * @brief Метод получения числа отброшенного по причине
 *
 * @param reason причина отброса
 * @return       число записей и дейтаграмм, отброшенных по этой причине
 *
 */
uint64_t nts::server::Context::discarded(const datagram::reason_t reason) const noexcept {
	// Выводим число отброшенного по причине
	return (this->_engine != nullptr ? this->_engine->discarded(reason) : 0);
}
/**
 * @brief Метод установки адреса собеседника для метки возврата состояния
 *
 * @param address адрес либо иной опознаватель собеседника
 * @return        признак того, что адрес принят
 *
 */
bool nts::server::Context::address(const view_t & address) noexcept {
	// Выводим итог установки адреса собеседника
	return ((this->_engine != nullptr) && this->_engine->address(address));
}
/**
 * @brief Метод установки секрета метки возврата состояния
 *
 * @param secret устанавливаемый секрет любой длины
 *
 */
void nts::server::Context::stamp(const vector <uint8_t> & secret) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем установку секрета метки возврата состояния
		this->_engine->stamp(secret);
}
/**
 * @brief Метод смены поколения секрета метки возврата состояния
 *
 */
void nts::server::Context::restamp() noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем смену поколения секрета метки
		this->_engine->restamp();
}
/**
 * @brief Метод заведения связи
 *
 * @return отказ заведения связи
 *
 */
context::error_t nts::server::Context::start() noexcept {
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
void nts::server::Context::clear() noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем сброс состояния связи
		this->_engine->clear();
}
/**
 * @brief Метод подачи связи принятых байтов
 *
 * @param data принятые от собеседника байты
 * @return     отказ разбора принятых байтов
 *
 */
context::error_t nts::server::Context::push(const view_t & data) noexcept {
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
view_t nts::server::Context::output() const noexcept {
	// Выводим накопленные байты, отправляемые собеседнику
	return (this->_engine != nullptr ? this->_engine->output() : view_t());
}
/**
 * @brief Метод снятия отправленных байтов с накопителя
 *
 * @param size размер снимаемых байтов
 *
 */
void nts::server::Context::consume(const size_t size) noexcept {
	// Если ведение связи заведено
	if(this->_engine != nullptr)
		// Выполняем снятие отправленных байтов с накопителя
		this->_engine->consume(size);
}
/**
 * @brief Метод отправки прикладных данных собеседнику
 *
 * @param data отправляемые прикладные данные
 * @return     отказ отправки прикладных данных
 *
 */
context::error_t nts::server::Context::write(const view_t & data) noexcept {
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
 * @return       отказ получения принятых прикладных данных
 *
 */
context::error_t nts::server::Context::read(vector <uint8_t> & result) noexcept {
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
 * @return        отказ смены ключевого материала своего направления
 *
 */
context::error_t nts::server::Context::update(const bool request) noexcept {
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
context::error_t nts::server::Context::close() noexcept {
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
nts::server::Context::Context() noexcept : _engine(nullptr) {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Выполняем создание объекта ведения связи
		this->_engine = make_unique <internal::engine_t> (true);
	/**
	 * Выполняем перехват ошибок
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
nts::server::Context::~Context() noexcept {
	// Уничтожаем объект ведения связи здесь, где его тип полон
	this->_engine.reset();
}
