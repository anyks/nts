/**
 * @file hmac.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл модуля имитовставки HMAC и порождающей функции протокола TLS
 *
 * @note Длина блока сжатия у обеих длин хеша одна и та же - шестьдесят четыре байта,
 *       оттого ключ дополняется до неё независимо от длины вырабатываемой имитовставки
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/hmac.hpp>
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
	using namespace nts::digest;

	/**
	 * @brief Размер блока сжатия хеша в байтах
	 *
	 */
	static constexpr size_t BLOCK = 64;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод выработки блоков ключа имитовставки
	 *
	 * @details Раздел 2 RFC 2104: ключ длиннее блока сжатия заменяется своим хешем, а
	 *          короткий дополняется нулями до длины блока
	 *
	 * @param type  длина хеша, на котором вырабатывается имитовставка
	 * @param key   ключ выработки имитовставки
	 * @param inner место, в которое помещается внутренний блок ключа
	 * @param outer место, в которое помещается внешний блок ключа
	 *
	 * @return      признак успешности выработки блоков ключа
	 *
	 */
	static bool prepare(const type_t type, const view_t & key, uint8_t * inner, uint8_t * outer) noexcept {
		// Дополняемый нулями ключ выработки имитовставки
		uint8_t buffer[BLOCK];
		// Выполняем обнуление дополняемого ключа
		::memset(buffer, 0, sizeof(buffer));
		// Если ключ выработки имитовставки длиннее блока сжатия
		if(key.size > BLOCK){
			// Заменяем ключ его хешем
			if(!streebog(type, key, buffer, static_cast <size_t> (type))){
				// Выполняем затирание дополняемого ключа
				wipe(buffer, sizeof(buffer));
				// Выводим отказ выработки блоков ключа
				return false;
			}
		// Если ключ выработки имитовставки в блок сжатия укладывается
		} else if(key.size > 0)
			// Записываем ключ выработки имитовставки
			::memcpy(buffer, key.data, key.size);
		/**
		 * Выполняем перебор байтов блока сжатия
		 */
		for(size_t i = 0; i < BLOCK; i++){
			// Складываем очередной байт ключа с внутренним дополнением
			inner[i] = static_cast <uint8_t> (buffer[i] ^ 0x36);
			// Складываем очередной байт ключа с внешним дополнением
			outer[i] = static_cast <uint8_t> (buffer[i] ^ 0x5C);
		}
		// Выполняем затирание дополняемого ключа
		wipe(buffer, sizeof(buffer));
		// Выводим успешность выработки блоков ключа
		return true;
	}
};

/**
 * @brief Метод выработки имитовставки HMAC
 *
 * @param type   длина хеша, на котором вырабатывается имитовставка
 * @param key    ключ выработки имитовставки
 * @param data   сообщение, на котором вырабатывается имитовставка
 * @param result место, в которое помещается имитовставка
 * @param size   требуемая длина имитовставки в байтах
 *
 * @return       признак успешности выработки имитовставки
 *
 */
bool nts::digest::hmac(const type_t type, const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Определяем длину хеша выработки имитовставки
	const size_t length = static_cast <size_t> (type);
	// Если длина хеша не установлена либо место имитовставки не передано
	if((length == 0) || (result == nullptr) || (size == 0) || (size > length))
		// Выводим отказ выработки имитовставки
		return false;
	// Если ключ выработки имитовставки передан неверно
	if((key.size > 0) && (key.data == nullptr))
		// Выводим отказ выработки имитовставки
		return false;
	// Если сообщение выработки имитовставки передано неверно
	if((data.size > 0) && (data.data == nullptr))
		// Выводим отказ выработки имитовставки
		return false;
	// Внутренний и внешний блоки ключа выработки имитовставки
	uint8_t inner[BLOCK], outer[BLOCK];
	// Если блоки ключа выработки имитовставки выработать не удалось
	if(!prepare(type, key, inner, outer)){
		// Выполняем затирание блоков ключа выработки имитовставки
		wipe(inner, sizeof(inner));
		// Выполняем затирание внешнего блока ключа
		wipe(outer, sizeof(outer));
		// Выводим отказ выработки имитовставки
		return false;
	}
	// Место, в которое помещается внутренний хеш
	uint8_t buffer[64];
	// Признак успешности выработки имитовставки
	bool ok = true;
	// Объект выработки внутреннего хеша
	streebog_t hash(type);
	// Выполняем подачу внутреннего блока ключа
	hash.update(view_t(inner, BLOCK));
	// Выполняем подачу сообщения выработки имитовставки
	hash.update(data);
	// Если внутренний хеш снять не удалось
	if((ok = hash.finish(buffer, sizeof(buffer)))){
		// Выполняем приведение объекта хеширования к началу выработки внешнего хеша
		hash.reset(type);
		// Выполняем подачу внешнего блока ключа
		hash.update(view_t(outer, BLOCK));
		// Выполняем подачу внутреннего хеша
		hash.update(view_t(buffer, length));
		// Выполняем снятие внешнего хеша
		if((ok = hash.finish(buffer, sizeof(buffer))))
			// Записываем выработанную имитовставку
			::memcpy(result, buffer, size);
	}
	// Выполняем затирание внутреннего хеша
	wipe(buffer, sizeof(buffer));
	// Выполняем затирание внешнего блока ключа
	wipe(outer, sizeof(outer));
	// Выполняем затирание внутреннего блока ключа
	wipe(inner, sizeof(inner));
	// Выводим признак успешности выработки имитовставки
	return ok;
}
/**
 * @brief Метод проверки готовности к выработке
 *
 * @return признак того, что ключ установлен
 *
 */
bool nts::digest::Mac::ready() const noexcept {
	// Выводим признак установленного ключа
	return this->_ready;
}
/**
 * @brief Метод установки ключа и начала выработки
 *
 * @param algorithm алгоритм хеширования
 * @param key       ключ выработки имитовставки, вправе быть пустым
 *
 * @return          признак успешности установки ключа
 *
 */
bool nts::digest::Mac::start(const hash_t algorithm, const view_t & key) noexcept {
	// Выполняем сброс прежнего ключа
	this->clear();
	// Размер блока сжатия выбранного алгоритма
	const size_t width = digest::block(algorithm);
	// Если алгоритм не установлен либо ключ объявлен непустым, но не передан
	if((width == 0) || ((key.size > 0) && (key.data == nullptr)))
		// Выводим отказ установки ключа
		return false;
	// Ключ, приведённый к размеру блока сжатия
	uint8_t padded[128];
	// Выполняем обнуление приведённого ключа
	wipe(padded, sizeof(padded));
	// Если ключ длиннее блока сжатия
	if(key.size > width){
		// Если хеш ключа выработать не удалось
		if(!hash(algorithm, key, padded, sizeof(padded))){
			// Выполняем затирание приведённого ключа
			wipe(padded, sizeof(padded));
			// Выводим отказ установки ключа
			return false;
		}
	// Если ключ передан
	} else if(key.size > 0)
		// Переносим ключ в приведённый
		::memcpy(padded, key.data, key.size);
	/**
	 * Выполняем перебор байтов блока сжатия
	 */
	for(size_t i = 0; i < width; i++){
		// Складываем внутреннее заполнение
		this->_inner[i] = static_cast <uint8_t> (padded[i] ^ 0x36);
		// Складываем внешнее заполнение
		this->_outer[i] = static_cast <uint8_t> (padded[i] ^ 0x5C);
	}
	// Выполняем затирание приведённого ключа
	wipe(padded, sizeof(padded));
	// Запоминаем алгоритм хеширования
	this->_type = algorithm;
	// Запоминаем размер блока сжатия
	this->_width = width;
	// Запоминаем, что ключ установлен
	this->_ready = true;
	// Выводим итог начала выработки
	return this->restart();
}
/**
 * @brief Метод повторного начала выработки на установленном ключе
 *
 * @return признак того, что ключ установлен
 *
 */
bool nts::digest::Mac::restart() noexcept {
	// Если ключ не установлен
	if(!this->_ready)
		// Выводим отказ начала выработки
		return false;
	// Выполняем сброс хеширования под внутренний хеш
	this->_hasher.reset(this->_type);
	// Выполняем подачу внутреннего заполнения
	this->_hasher.update(view_t(this->_inner, this->_width));
	// Выводим успешность начала выработки
	return true;
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Mac::update(const view_t & data) noexcept {
	// Если ключ установлен
	if(this->_ready)
		// Выполняем подачу куска хешированию
		this->_hasher.update(data);
}
/**
 * @brief Метод снятия имитовставки
 *
 * @param result место, в которое записывается имитовставка
 * @param size   требуемая длина имитовставки, от одного байта до длины хеша
 *
 * @return       признак успешности снятия
 *
 */
bool nts::digest::Mac::finish(uint8_t * result, const size_t size) noexcept {
	// Длина хеша алгоритма
	const size_t length = digest::length(this->_type);
	// Если ключ не установлен, либо места нет, либо длина негодна
	if(!this->_ready || (result == nullptr) || (size == 0) || (size > length))
		// Выводим отказ снятия имитовставки
		return false;
	// Место, в которое записывается внутренний хеш
	uint8_t buffer[64];
	// Признак успешности выработки
	bool ok = this->_hasher.finish(buffer, sizeof(buffer));
	// Если внутренний хеш снят
	if(ok){
		// Выполняем сброс хеширования под внешний хеш
		this->_hasher.reset(this->_type);
		// Выполняем подачу внешнего заполнения
		this->_hasher.update(view_t(this->_outer, this->_width));
		// Выполняем подачу внутреннего хеша
		this->_hasher.update(view_t(buffer, length));
		// Если внешний хеш снят
		if((ok = this->_hasher.finish(buffer, sizeof(buffer))))
			// Переносим имитовставку в требуемую длину
			::memcpy(result, buffer, size);
	}
	// Выполняем затирание внутреннего хеша
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки
	return ok;
}
/**
 * @brief Метод сброса ключа
 *
 */
void nts::digest::Mac::clear() noexcept {
	// Сбрасываем признак установленного ключа
	this->_ready = false;
	// Сбрасываем алгоритм хеширования
	this->_type = hash_t::NONE;
	// Сбрасываем размер блока сжатия
	this->_width = 0;
	// Выполняем затирание внутреннего заполнения
	wipe(this->_inner, sizeof(this->_inner));
	// Выполняем затирание внешнего заполнения
	wipe(this->_outer, sizeof(this->_outer));
	// Выполняем сброс хеширования
	this->_hasher.reset(hash_t::NONE);
}
/**
 * @brief Конструктор
 *
 */
nts::digest::Mac::Mac() noexcept : _ready(false), _type(hash_t::NONE), _width(0) {
	// Выполняем затирание внутреннего заполнения
	wipe(this->_inner, sizeof(this->_inner));
	// Выполняем затирание внешнего заполнения
	wipe(this->_outer, sizeof(this->_outer));
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Mac::~Mac() noexcept {
	// Выполняем сброс ключа
	this->clear();
}
/**
 * @brief Метод выработки имитовставки HMAC выбранным алгоритмом хеширования
 *
 * @param algorithm алгоритм хеширования, на котором вырабатывается имитовставка
 * @param key       ключ выработки имитовставки
 * @param data      сообщение, на котором вырабатывается имитовставка
 * @param result    место, в которое помещается имитовставка
 * @param size      требуемая длина имитовставки в байтах, не больше длины хеша
 *
 * @return          признак успешности выработки имитовставки
 *
 */
bool nts::digest::hmac(const hash_t algorithm, const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Если сообщение объявлено непустым, но не передано
	if((data.size > 0) && (data.data == nullptr))
		// Выводим отказ выработки имитовставки
		return false;
	// Объект поточной выработки имитовставки
	mac_t mac;
	// Если ключ установить не удалось
	if(!mac.start(algorithm, key))
		// Выводим отказ выработки имитовставки
		return false;
	// Выполняем подачу сообщения
	mac.update(data);
	// Выводим итог снятия имитовставки
	return mac.finish(result, size);
}
/**
 * @brief Метод выработки порождающей последовательности протокола TLS
 *
 * @param type   длина хеша, на котором вырабатывается последовательность
 * @param key    ключ выработки последовательности
 * @param label  метка назначения последовательности
 * @param seed   затравка выработки последовательности
 * @param result место, в которое помещается выработанная последовательность
 * @param size   требуемая длина последовательности в байтах
 *
 * @return       признак успешности выработки последовательности
 *
 */
bool nts::digest::prf(const type_t type, const view_t & key, const view_t & label, const view_t & seed, uint8_t * result, const size_t size) noexcept {
	// Определяем длину хеша выработки последовательности
	const size_t length = static_cast <size_t> (type);
	// Если длина хеша не установлена либо место последовательности не передано
	if((length == 0) || (result == nullptr) || (size == 0))
		// Выводим отказ выработки последовательности
		return false;
	// Если метка назначения последовательности передана неверно
	if((label.size > 0) && (label.data == nullptr))
		// Выводим отказ выработки последовательности
		return false;
	// Если затравка выработки последовательности передана неверно
	if((seed.size > 0) && (seed.data == nullptr))
		// Выводим отказ выработки последовательности
		return false;
	/**
	 * Метка и затравка идут подряд одной строкой: раздел 5 RFC 5246 подаёт их
	 * порождающей функции слитно
	 */
	uint8_t buffer[512];
	// Если метка и затравка вместе в отведённое место не укладываются
	if((label.size + seed.size) > sizeof(buffer))
		// Выводим отказ выработки последовательности
		return false;
	// Если метка назначения последовательности передана
	if(label.size > 0)
		// Записываем метку назначения последовательности
		::memcpy(buffer, label.data, label.size);
	// Если затравка выработки последовательности передана
	if(seed.size > 0)
		// Записываем затравку выработки последовательности
		::memcpy(buffer + label.size, seed.data, seed.size);
	// Определяем длину слитной строки метки и затравки
	const size_t total = (label.size + seed.size);
	// Промежуточное значение выработки последовательности
	uint8_t item[64];
	// Место, в которое помещается очередная часть последовательности
	uint8_t part[64];
	// Признак успешности выработки последовательности
	bool ok = true;
	/**
	 * Начальным промежуточным значением служит сама слитная строка метки и затравки:
	 * так задано определение A(0) в разделе 5 RFC 5246
	 */
	if((ok = nts::digest::hmac(type, key, view_t(buffer, total), item, length))){
		// Число уже выработанных байтов последовательности
		size_t offset = 0;
		/**
		 * Выполняем выработку последовательности до набора требуемой длины
		 */
		while(ok && (offset < size)){
			// Объект выработки очередной части последовательности
			streebog_t hash(type);
			// Место, в которое помещается слитная строка промежуточного значения
			uint8_t block[64 + 512];
			// Записываем промежуточное значение выработки последовательности
			::memcpy(block, item, length);
			// Записываем слитную строку метки и затравки
			::memcpy(block + length, buffer, total);
			// Если очередную часть последовательности выработать не удалось
			if(!(ok = nts::digest::hmac(type, key, view_t(block, length + total), part, length))){
				// Выполняем затирание слитной строки промежуточного значения
				wipe(block, sizeof(block));
				// Выходим из выработки последовательности
				break;
			}
			// Определяем размер переносимой части последовательности
			const size_t count = ((size - offset) < length ? (size - offset) : length);
			// Переносим очередную часть последовательности
			::memcpy(result + offset, part, count);
			// Увеличиваем число выработанных байтов последовательности
			offset += count;
			// Выполняем выработку следующего промежуточного значения
			ok = nts::digest::hmac(type, key, view_t(item, length), item, length);
			// Выполняем затирание слитной строки промежуточного значения
			wipe(block, sizeof(block));
		}
	}
	// Выполняем затирание очередной части последовательности
	wipe(part, sizeof(part));
	// Выполняем затирание промежуточного значения выработки последовательности
	wipe(item, sizeof(item));
	// Выполняем затирание слитной строки метки и затравки
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки последовательности
	return ok;
}
/**
 * @brief Метод выработки порождающей последовательности протокола TLS 1.2 выбранным хешем
 *
 * @param algorithm хеш, на имитовставке которого вырабатывается последовательность
 * @param key       ключ выработки последовательности
 * @param label     метка назначения последовательности
 * @param seed      затравка выработки последовательности
 * @param result    место, в которое помещается выработанная последовательность
 * @param size      требуемая длина последовательности в байтах
 *
 * @return          признак успешности выработки последовательности
 *
 */
bool nts::digest::prf(const hash_t algorithm, const view_t & key, const view_t & label, const view_t & seed, uint8_t * result, const size_t size) noexcept {
	// Определяем длину хеша выработки последовательности
	const size_t length = nts::digest::length(algorithm);
	// Если хеш неведом либо место последовательности не передано
	if((length == 0) || (length > 64) || (result == nullptr) || (size == 0))
		// Выводим отказ выработки последовательности
		return false;
	// Если метка назначения последовательности передана неверно
	if((label.size > 0) && (label.data == nullptr))
		// Выводим отказ выработки последовательности
		return false;
	// Если затравка выработки последовательности передана неверно
	if((seed.size > 0) && (seed.data == nullptr))
		// Выводим отказ выработки последовательности
		return false;
	/**
	 * Метка и затравка идут подряд одной строкой: раздел 5 RFC 5246 подаёт их
	 * порождающей функции слитно
	 */
	uint8_t buffer[512];
	// Если метка и затравка вместе в отведённое место не укладываются
	if((label.size + seed.size) > sizeof(buffer))
		// Выводим отказ выработки последовательности
		return false;
	// Если метка назначения последовательности передана
	if(label.size > 0)
		// Записываем метку назначения последовательности
		::memcpy(buffer, label.data, label.size);
	// Если затравка выработки последовательности передана
	if(seed.size > 0)
		// Записываем затравку выработки последовательности
		::memcpy(buffer + label.size, seed.data, seed.size);
	// Определяем длину слитной строки метки и затравки
	const size_t total = (label.size + seed.size);
	// Промежуточное значение выработки последовательности
	uint8_t item[64];
	// Место, в которое помещается очередная часть последовательности
	uint8_t part[64];
	// Место, в которое помещается слитная строка промежуточного значения
	uint8_t block[64 + 512];
	/**
	 * Начальным промежуточным значением служит сама слитная строка метки и затравки:
	 * так задано определение A(0) в разделе 5 RFC 5246
	 */
	bool ok = nts::digest::hmac(algorithm, key, view_t(buffer, total), item, length);
	// Число уже выработанных байтов последовательности
	size_t offset = 0;
	/**
	 * Выполняем выработку последовательности до набора требуемой длины
	 */
	while(ok && (offset < size)){
		// Записываем промежуточное значение выработки последовательности
		::memcpy(block, item, length);
		// Записываем слитную строку метки и затравки
		::memcpy(block + length, buffer, total);
		// Выполняем выработку очередной части последовательности
		ok = nts::digest::hmac(algorithm, key, view_t(block, length + total), part, length);
		// Если очередная часть последовательности выработана
		if(ok){
			// Определяем размер переносимой части последовательности
			const size_t count = ((size - offset) < length ? (size - offset) : length);
			// Переносим очередную часть последовательности
			::memcpy(result + offset, part, count);
			// Увеличиваем число выработанных байтов последовательности
			offset += count;
			// Выполняем выработку следующего промежуточного значения
			ok = nts::digest::hmac(algorithm, key, view_t(item, length), item, length);
		}
	}
	// Выполняем затирание слитной строки промежуточного значения
	wipe(block, sizeof(block));
	// Выполняем затирание очередной части последовательности
	wipe(part, sizeof(part));
	// Выполняем затирание промежуточного значения
	wipe(item, sizeof(item));
	// Выполняем затирание слитной строки метки и затравки
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки последовательности
	return ok;
}
