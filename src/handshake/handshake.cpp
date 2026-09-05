/**
 * @file handshake.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Исходный файл модуля обвязки сообщений рукопожатия протокола TLS
 *
 * @section Намеренные решения
 *
 * 1. Сообщение выдаётся лишь целиком. Раздел 4 RFC 8446 длину сообщения объявляет
 *    вперёд, а тела сообщений разбираются полями переменной длины, вложенными друг в
 *    друга: разбор по кускам вынудил бы всякий разборщик тела уметь останавливаться
 *    посреди поля. Ценой тому накопитель длиной в сообщение, и потому у него есть предел.
 *
 * 2. Сообщение выдаётся и целиком вместе с обвязкой. Хеш переписки рукопожатия по
 *    разделу 4.4.1 RFC 8446 берётся именно от такой записи, и складывать её заново из
 *    обвязки и тела значило бы повторять работу, уже сделанную сборщиком.
 *
 * 3. Предел длины тела сообщения отделён от предела протокола. Предел протокола задан
 *    тремя байтами длины и равен шестнадцати мегабайтам, а связь столько принимать не
 *    обязана: объявить длину дешевле, чем её прислать.
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
#include <handshake/handshake.hpp>
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
	 * Пространство имён модуля
	 */
	using namespace nts::handshake;

	/**
	 * @brief Отказы работы модуля
	 *
	 * @note Имя заведено своё намеренно: у glibc есть собственный error_t в глобальном
	 *       пространстве имён (расширение GNU в <errno.h>), а помощники лежат в
	 *       безымянном пространстве, откуда поиск имени уходит сразу в глобальное - и
	 *       всякое обращение к error_t выходит там двусмысленным. Своё имя поиск
	 *       находит прежде глобального, и двусмысленности не возникает
	 *
	 */
	typedef handshake::error_t error_t;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
};

/**
 * @brief Метод проверки известности вида сообщения рукопожатия
 *
 * @param type проверяемый вид сообщения рукопожатия
 *
 * @return     признак того, что вид сообщения определён протоколом
 *
 */
bool nts::handshake::known(const type_t type) noexcept {
	/**
	 * Выполняем определение вида сообщения рукопожатия
	 */
	switch(static_cast <uint8_t> (type)){
		// Если это один из известных видов сообщения рукопожатия
		case static_cast <uint8_t> (type_t::HELLO_REQUEST):
		case static_cast <uint8_t> (type_t::CLIENT):
		case static_cast <uint8_t> (type_t::SERVER):
		case static_cast <uint8_t> (type_t::TICKET):
		case static_cast <uint8_t> (type_t::EARLY):
		case static_cast <uint8_t> (type_t::EXTENSIONS):
		case static_cast <uint8_t> (type_t::CERTIFICATE):
		case static_cast <uint8_t> (type_t::AGREEMENT):
		case static_cast <uint8_t> (type_t::REQUEST):
		case static_cast <uint8_t> (type_t::DONE):
		case static_cast <uint8_t> (type_t::VERIFY):
		case static_cast <uint8_t> (type_t::PREMASTER):
		case static_cast <uint8_t> (type_t::FINISHED):
		case static_cast <uint8_t> (type_t::STATUS):
		case static_cast <uint8_t> (type_t::UPDATE):
		case static_cast <uint8_t> (type_t::COMPRESSED):
		case static_cast <uint8_t> (type_t::DIGEST):
			// Выводим признак известности вида сообщения рукопожатия
			return true;
	}
	// Выводим признак того, что вид сообщения рукопожатия неизвестен
	return false;
}
/**
 * @brief Метод разбора обвязки сообщения рукопожатия
 *
 * @param data   разбираемая область байтов
 * @param result обвязка, в которую помещается итог разбора
 *
 * @return       отказ разбора обвязки сообщения
 *
 */
nts::handshake::error_t nts::handshake::parse(const view_t & data, header_t & result) noexcept {
	// Если разбираемая область байтов обвязки сообщения не вмещает
	if((data.data == nullptr) || (data.size < HANDSHAKE_HEADER))
		// Выводим отказ нехватки данных для разбора
		return error_t::HUNGRY;
	// Получаем вид сообщения рукопожатия
	const type_t type = static_cast <type_t> (data.data[0]);
	// Если вид сообщения рукопожатия протоколом не определён
	if(!known(type))
		// Выводим отказ неизвестности вида сообщения рукопожатия
		return error_t::TYPE;
	// Устанавливаем вид сообщения рукопожатия
	result.type = type;
	// Устанавливаем длину тела сообщения рукопожатия
	result.size = ((static_cast <size_t> (data.data[1]) << 16) | (static_cast <size_t> (data.data[2]) << 8) | static_cast <size_t> (data.data[3]));
	// Выводим успешность разбора обвязки сообщения рукопожатия
	return error_t::NONE;
}
/**
 * @brief Метод записи обвязки сообщения рукопожатия
 *
 * @param header записываемая обвязка сообщения
 * @param result место, в которое помещается обвязка сообщения
 *
 * @return       отказ записи обвязки сообщения
 *
 */
nts::handshake::error_t nts::handshake::build(const header_t & header, uint8_t * result) noexcept {
	// Если место для обвязки сообщения не передано
	if(result == nullptr)
		// Выводим отказ нехватки места под обвязку сообщения
		return error_t::HUNGRY;
	// Если вид сообщения рукопожатия протоколом не определён
	if(!known(header.type))
		// Выводим отказ неизвестности вида сообщения рукопожатия
		return error_t::TYPE;
	// Если длина тела сообщения превышает предел протокола
	if(header.size > HANDSHAKE_LIMIT)
		// Выводим отказ превышения дозволенной длины тела сообщения
		return error_t::LENGTH;
	// Записываем вид сообщения рукопожатия
	result[0] = static_cast <uint8_t> (header.type);
	// Записываем старший байт длины тела сообщения
	result[1] = static_cast <uint8_t> ((header.size >> 16) & 0xFF);
	// Записываем средний байт длины тела сообщения
	result[2] = static_cast <uint8_t> ((header.size >> 8) & 0xFF);
	// Записываем младший байт длины тела сообщения
	result[3] = static_cast <uint8_t> (header.size & 0xFF);
	// Выводим успешность записи обвязки сообщения рукопожатия
	return error_t::NONE;
}
/**
 * @brief Метод получения предела длины тела принимаемого сообщения
 *
 * @return предел длины тела сообщения в байтах
 *
 */
size_t nts::handshake::Reader::limit() const noexcept {
	// Выводим предел длины тела принимаемого сообщения
	return this->_limit;
}
/**
 * @brief Метод установки предела длины тела принимаемого сообщения
 *
 * @param limit устанавливаемый предел длины тела сообщения в байтах
 *
 * @return      признак успешности установки предела
 *
 */
bool nts::handshake::Reader::limit(const size_t limit) noexcept {
	// Если предел длины тела сообщения протоколом не дозволен
	if((limit == 0) || (limit > HANDSHAKE_LIMIT))
		// Выводим отказ установки предела
		return false;
	// Устанавливаем предел длины тела принимаемого сообщения
	this->_limit = limit;
	// Выводим успешность установки предела
	return true;
}
/**
 * @brief Метод получения объёма ещё не разобранных данных
 *
 * @return объём ещё не разобранных данных в байтах
 *
 */
size_t nts::handshake::Reader::pending() const noexcept {
	// Выводим объём ещё не разобранных данных накопителя
	return (this->_buffer.size() - this->_offset);
}
/**
 * @brief Метод получения последнего собранного сообщения целиком
 *
 * @return просмотр собранного сообщения вместе с его обвязкой
 *
 */
view_t nts::handshake::Reader::message() const noexcept {
	// Если сообщения ещё не выдавалось
	if(this->_length == 0)
		// Выводим пустой просмотр собранного сообщения
		return view_t();
	// Выводим просмотр последнего собранного сообщения вместе с его обвязкой
	return view_t((this->_buffer.data() + this->_offset - this->_length), this->_length);
}
/**
 * @brief Метод сброса состояния сборщика
 *
 */
void nts::handshake::Reader::clear() noexcept {
	// Если накопитель сборщика не пустой
	if(!this->_buffer.empty())
		// Выполняем затирание содержимого накопителя
		wipe(this->_buffer.data(), this->_buffer.size());
	// Выполняем сброс накопителя сборщика
	this->_buffer.clear();
	// Выполняем сброс смещения начала неразобранных данных
	this->_offset = 0;
	// Выполняем сброс длины последнего выданного сообщения
	this->_length = 0;
}
/**
 * @brief Метод подачи содержимого принятой записи рукопожатия
 *
 * @param data подаваемое содержимое записи рукопожатия
 *
 * @return     отказ подачи содержимого записи
 *
 */
nts::handshake::error_t nts::handshake::Reader::push(const view_t & data) noexcept {
	// Если содержимое записи рукопожатия не передано
	if((data.data == nullptr) || (data.size == 0))
		// Выводим успешность подачи содержимого записи
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Если разобранные данные в накопителе есть
		if(this->_offset > 0){
			// Выполняем затирание уже разобранных данных накопителя
			wipe(this->_buffer.data(), this->_offset);
			// Выполняем снятие разобранных данных с начала накопителя
			this->_buffer.erase(this->_buffer.begin(), this->_buffer.begin() + static_cast <ptrdiff_t> (this->_offset));
			// Выполняем сброс смещения начала неразобранных данных
			this->_offset = 0;
			// Выполняем сброс длины последнего выданного сообщения
			this->_length = 0;
		}
		// Выполняем добавление содержимого записи рукопожатия в накопитель
		this->_buffer.insert(this->_buffer.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность подачи содержимого записи
	return error_t::NONE;
}
/**
 * @brief Метод получения очередного собранного сообщения
 *
 * @param header  обвязка, в которую помещается обвязка собранного сообщения
 * @param payload просмотр, в который помещается тело собранного сообщения
 *
 * @return        отказ получения собранного сообщения
 *
 */
nts::handshake::error_t nts::handshake::Reader::next(header_t & header, view_t & payload) noexcept {
	// Получаем объём ещё не разобранных данных накопителя
	const size_t pending = this->pending();
	// Если данных для обвязки сообщения ещё не набралось
	if(pending < HANDSHAKE_HEADER)
		// Выводим отказ нехватки данных для целого сообщения
		return error_t::HUNGRY;
	// Получаем указатель на начало неразобранных данных накопителя
	const uint8_t * data = (this->_buffer.data() + this->_offset);
	// Выполняем разбор обвязки очередного сообщения
	const error_t error = nts::handshake::parse(view_t(data, pending), header);
	// Если обвязку сообщения разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора обвязки сообщения
		return error;
	// Если длина тела сообщения превышает предел, принятый связью
	if(header.size > this->_limit)
		// Выводим отказ превышения дозволенной длины тела сообщения
		return error_t::LENGTH;
	// Если тело сообщения набралось ещё не целиком
	if(pending < (HANDSHAKE_HEADER + header.size))
		// Выводим отказ нехватки данных для целого сообщения
		return error_t::HUNGRY;
	// Устанавливаем просмотр тела собранного сообщения
	payload = view_t((data + HANDSHAKE_HEADER), header.size);
	// Запоминаем длину последнего выданного сообщения вместе с обвязкой
	this->_length = (HANDSHAKE_HEADER + header.size);
	// Сдвигаем начало неразобранных данных за собранное сообщение
	this->_offset += this->_length;
	// Выводим успешность получения собранного сообщения
	return error_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::handshake::Reader::Reader() noexcept : _offset(0), _length(0), _limit(HANDSHAKE_LIMIT) {}
/**
 * @brief Деструктор
 *
 */
nts::handshake::Reader::~Reader() noexcept {
	// Выполняем сброс состояния сборщика
	this->clear();
}
/**
 * @brief Метод получения объёма составленных сообщений
 *
 * @return объём составленных сообщений в байтах
 *
 */
size_t nts::handshake::Writer::pending() const noexcept {
	// Выводим объём составленных сообщений
	return this->_buffer.size();
}
/**
 * @brief Метод получения составленных сообщений
 *
 * @return просмотр составленных сообщений
 *
 */
view_t nts::handshake::Writer::data() const noexcept {
	// Если составленных сообщений в накопителе нет
	if(this->_buffer.empty())
		// Выводим пустой просмотр составленных сообщений
		return view_t();
	// Выводим просмотр составленных сообщений
	return view_t(this->_buffer.data(), this->_buffer.size());
}
/**
 * @brief Метод сброса накопителя составленных сообщений
 *
 */
void nts::handshake::Writer::clear() noexcept {
	// Если накопитель составителя не пустой
	if(!this->_buffer.empty())
		// Выполняем затирание содержимого накопителя
		wipe(this->_buffer.data(), this->_buffer.size());
	// Выполняем сброс накопителя составленных сообщений
	this->_buffer.clear();
}
/**
 * @brief Метод составления сообщения рукопожатия
 *
 * @param type вид составляемого сообщения рукопожатия
 * @param data тело составляемого сообщения рукопожатия
 *
 * @return     отказ составления сообщения рукопожатия
 *
 */
nts::handshake::error_t nts::handshake::Writer::push(const type_t type, const view_t & data) noexcept {
	// Обвязка составляемого сообщения рукопожатия
	header_t header;
	// Устанавливаем вид составляемого сообщения рукопожатия
	header.type = type;
	// Устанавливаем длину тела составляемого сообщения
	header.size = ((data.data != nullptr) ? data.size : 0);
	// Место, в которое записывается обвязка составляемого сообщения
	uint8_t buffer[HANDSHAKE_HEADER];
	// Выполняем запись обвязки составляемого сообщения
	const error_t error = nts::handshake::build(header, buffer);
	// Если обвязку сообщения составить не удалось
	if(error != error_t::NONE)
		// Выводим отказ составления сообщения рукопожатия
		return error;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Выполняем добавление обвязки сообщения в накопитель
		this->_buffer.insert(this->_buffer.end(), buffer, buffer + HANDSHAKE_HEADER);
		// Если тело составляемого сообщения передано
		if(header.size > 0)
			// Выполняем добавление тела сообщения в накопитель
			this->_buffer.insert(this->_buffer.end(), data.data, data.data + header.size);
	/**
	 * Если памяти под накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления сообщения рукопожатия
	return error_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::handshake::Writer::Writer() noexcept {}
/**
 * @brief Деструктор
 *
 */
nts::handshake::Writer::~Writer() noexcept {
	// Выполняем сброс накопителя составленных сообщений
	this->clear();
}
