/**
 * @file hkdf.cpp
 * @date 2026-09-04
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
 * @brief Модуль вывода ключей HKDF по RFC 5869 над любым хешем библиотеки
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
#include <digest/hkdf.hpp>
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

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
};

/**
 * @brief Функция извлечения псевдослучайного ключа из исходного материала
 *
 * @param algorithm алгоритм хеширования
 * @param salt      соль: пустая соль заменяется нулями в длину хеша
 * @param material  исходный ключевой материал
 * @param result    место, в которое помещается псевдослучайный ключ
 * @param size      размер места в байтах, не меньше длины хеша
 * @return          признак успешности извлечения
 *
 */
bool nts::digest::extract(const hash_t algorithm, const view_t & salt, const view_t & material, uint8_t * result, const size_t size) noexcept {
	// Длина хеша выбранного алгоритма
	const size_t length = digest::length(algorithm);
	// Если алгоритм не установлен либо места под ключ не хватает
	if((length == 0) || (result == nullptr) || (size < length))
		// Выводим отказ извлечения
		return false;
	// Нулевая соль в длину хеша: раздел 2.2 RFC 5869
	uint8_t zeros[64];
	// Выполняем обнуление нулевой соли
	::memset(zeros, 0, sizeof(zeros));
	// Соль, идущая ключом имитовставки: переданная либо нулевая
	const view_t key = ((salt.size > 0) ? salt : view_t(zeros, length));
	// Выводим итог выработки имитовставки материала на соли
	return hmac(algorithm, key, material, result, length);
}
/**
 * @brief Функция развёртывания псевдослучайного ключа в ключевой материал
 *
 * @param algorithm алгоритм хеширования
 * @param key       псевдослучайный ключ длиной не короче хеша
 * @param info      привязка выводимого материала, вправе быть пустой
 * @param result    место, в которое помещается выведенный материал
 * @param size      требуемая длина материала, не больше 255 длин хеша
 * @return          признак успешности развёртывания
 *
 */
bool nts::digest::expand(const hash_t algorithm, const view_t & key, const view_t & info, uint8_t * result, const size_t size) noexcept {
	// Длина хеша выбранного алгоритма
	const size_t length = digest::length(algorithm);
	// Если алгоритм не установлен, либо ключ короче хеша, либо длина материала негодна
	if((length == 0) || (key.data == nullptr) || (key.size < length) || (result == nullptr) || (size == 0) || (size > (255 * length)))
		// Выводим отказ развёртывания
		return false;
	// Если привязка объявлена непустой, но не передана
	if((info.size > 0) && (info.data == nullptr))
		// Выводим отказ развёртывания
		return false;
	// Объект поточной выработки имитовставки: привязка любой длины подаётся куском
	mac_t mac;
	// Если ключ установить не удалось
	if(!mac.start(algorithm, key))
		// Выводим отказ развёртывания
		return false;
	// Место, в которое записывается очередной блок материала
	uint8_t block[64];
	// Число уже выведенных байтов материала
	size_t produced = 0;
	// Длина прежнего блока: у первого блока прежнего нет
	size_t previous = 0;
	// Признак успешности развёртывания
	bool ok = true;
	/**
	 * Выполняем вывод блоков материала, пока его не хватает
	 */
	for(uint8_t index = 1; ok && (produced < size); index++){
		// Выполняем начало выработки очередного блока
		mac.restart();
		// Если прежний блок есть
		if(previous > 0)
			// Выполняем подачу прежнего блока
			mac.update(view_t(block, previous));
		// Выполняем подачу привязки
		mac.update(info);
		// Выполняем подачу номера блока
		mac.update(view_t(&index, 1));
		// Если очередной блок снять не удалось
		if(!(ok = mac.finish(block, length)))
			// Прерываем вывод
			break;
		// Число байтов блока, идущих в материал
		const size_t taken = (((size - produced) < length) ? (size - produced) : length);
		// Переносим блок в материал
		::memcpy(result + produced, block, taken);
		// Считаем выведенные байты
		produced += taken;
		// Запоминаем длину прежнего блока: в цепочку идёт весь блок
		previous = length;
	}
	// Выполняем затирание блока
	wipe(block, sizeof(block));
	// Если вывод не удался
	if(!ok)
		// Выполняем затирание недовыведенного материала
		wipe(result, size);
	// Выводим признак успешности развёртывания
	return ok;
}
/**
 * @brief Функция развёртывания секрета с меткой по разделу 7.1 RFC 8446
 *
 * @param algorithm алгоритм хеширования
 * @param secret    развёртываемый секрет длиной не короче хеша
 * @param label     метка без приставки «tls13 », от 1 до 249 байтов
 * @param context   привязка к переписке, до 255 байтов, вправе быть пустой
 * @param result    место, в которое помещается выведенный материал
 * @param size      требуемая длина материала, не больше 255 длин хеша
 * @return          признак успешности развёртывания
 *
 */
bool nts::digest::label(const hash_t algorithm, const view_t & secret, const view_t & label, const view_t & context, uint8_t * result, const size_t size) noexcept {
	// Если метка не передана либо длиннее дозволенного
	if((label.data == nullptr) || (label.size == 0) || (label.size > 249))
		// Выводим отказ развёртывания
		return false;
	// Если привязка длиннее дозволенного либо объявлена непустой, но не передана
	if((context.size > 255) || ((context.size > 0) && (context.data == nullptr)))
		// Выводим отказ развёртывания
		return false;
	// Если требуемая длина не умещается в два байта
	if(size > 0xFFFF)
		// Выводим отказ развёртывания
		return false;
	// Приставка метки
	static const uint8_t PREFIX[6] = {'t', 'l', 's', '1', '3', ' '};
	// Запись HkdfLabel: длина, метка с приставкой, привязка
	uint8_t info[2 + 1 + 6 + 249 + 1 + 255];
	// Длина записи
	size_t offset = 0;
	// Записываем старший байт требуемой длины
	info[offset++] = static_cast <uint8_t> (size >> 8);
	// Записываем младший байт требуемой длины
	info[offset++] = static_cast <uint8_t> (size);
	// Записываем длину метки с приставкой
	info[offset++] = static_cast <uint8_t> (sizeof(PREFIX) + label.size);
	// Переносим приставку метки
	::memcpy(info + offset, PREFIX, sizeof(PREFIX));
	// Считаем приставку
	offset += sizeof(PREFIX);
	// Переносим метку
	::memcpy(info + offset, label.data, label.size);
	// Считаем метку
	offset += label.size;
	// Записываем длину привязки
	info[offset++] = static_cast <uint8_t> (context.size);
	// Если привязка передана
	if(context.size > 0){
		// Переносим привязку
		::memcpy(info + offset, context.data, context.size);
		// Считаем привязку
		offset += context.size;
	}
	// Выполняем развёртывание секрета с записью HkdfLabel привязкой
	const bool ok = expand(algorithm, secret, view_t(info, offset), result, size);
	// Выполняем затирание записи: в ней нет секрета, но есть привязка к переписке
	wipe(info, sizeof(info));
	// Выводим признак успешности развёртывания
	return ok;
}
/**
 * @brief Функция вывода ключевого материала из исходного за один вызов
 *
 * @param algorithm алгоритм хеширования
 * @param salt      соль, вправе быть пустой
 * @param material  исходный ключевой материал
 * @param info      привязка выводимого материала, вправе быть пустой
 * @param result    место, в которое помещается выведенный материал
 * @param size      требуемая длина материала, не больше 255 длин хеша
 * @return          признак успешности вывода
 *
 */
bool nts::digest::hkdf(const hash_t algorithm, const view_t & salt, const view_t & material, const view_t & info, uint8_t * result, const size_t size) noexcept {
	// Псевдослучайный ключ
	uint8_t key[64];
	// Признак успешности вывода
	bool ok = extract(algorithm, salt, material, key, sizeof(key));
	// Если псевдослучайный ключ извлечён
	if(ok)
		// Выполняем развёртывание ключа в материал
		ok = expand(algorithm, view_t(key, digest::length(algorithm)), info, result, size);
	// Выполняем затирание псевдослучайного ключа
	wipe(key, sizeof(key));
	// Выводим признак успешности вывода
	return ok;
}
