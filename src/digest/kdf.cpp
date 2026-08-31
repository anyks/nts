/**
 * @file kdf.cpp
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
 * @brief Исходный файл модуля функции выработки производного ключа по RFC 7836
 *
 * @note Слитная строка складывается на стеке и затирается: через неё проходит затравка
 *       выработки ключа, а у протокола TLS затравкой служит порядковый номер записи
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
#include <digest/kdf.hpp>
#include <digest/hmac.hpp>

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
};

/**
 * @brief Метод выработки производного ключа
 *
 * @param key    ключ выработки производного ключа
 * @param label  метка назначения производного ключа
 * @param seed   затравка выработки производного ключа
 * @param result место, в которое помещается производный ключ
 *
 * @return       признак успешности выработки производного ключа
 *
 */
bool nts::digest::kdf(const view_t & key, const view_t & label, const view_t & seed, uint8_t * result) noexcept {
	// Если место для производного ключа не передано
	if(result == nullptr)
		// Выводим отказ выработки производного ключа
		return false;
	// Если метка или затравка выработки ключа длиннее дозволенного
	if((label.size > KDF_LIMIT) || (seed.size > KDF_LIMIT))
		// Выводим отказ выработки производного ключа
		return false;
	// Слитная строка, на которой вырабатывается производный ключ
	uint8_t buffer[(KDF_LIMIT * 2) + 4];
	// Число уже записанных байтов слитной строки
	size_t offset = 0;
	// Записываем порядковый номер части производного ключа
	buffer[offset++] = 0x01;
	// Если метка назначения производного ключа передана
	if((label.data != nullptr) && (label.size > 0)){
		// Записываем метку назначения производного ключа
		::memcpy(buffer + offset, label.data, label.size);
		// Увеличиваем число записанных байтов слитной строки
		offset += label.size;
	}
	// Записываем разделитель метки и затравки
	buffer[offset++] = 0x00;
	// Если затравка выработки производного ключа передана
	if((seed.data != nullptr) && (seed.size > 0)){
		// Записываем затравку выработки производного ключа
		::memcpy(buffer + offset, seed.data, seed.size);
		// Увеличиваем число записанных байтов слитной строки
		offset += seed.size;
	}
	// Записываем старший байт длины вырабатываемого ключа в разрядах
	buffer[offset++] = 0x01;
	// Записываем младший байт длины вырабатываемого ключа в разрядах
	buffer[offset++] = 0x00;
	// Выполняем выработку производного ключа
	const bool ok = nts::digest::hmac(type_t::SHORT, key, view_t(buffer, offset), result, KDF_KEY);
	// Выполняем затирание слитной строки выработки ключа
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки производного ключа
	return ok;
}
