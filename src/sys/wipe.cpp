/**
 * @file wipe.cpp
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
 * @brief Затирание областей памяти с тайнами
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Метод затирания области памяти
 *
 * @param data затираемая область памяти
 * @param size размер затираемой области памяти в байтах
 *
 */
void nts::sys::wipe(void * data, const size_t size) noexcept {
	// Если область памяти задана
	if((data != nullptr) && (size > 0)){
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
		/**
		 * Выполняем перебор байтов затираемой области памяти
		 */
		for(size_t i = 0; i < size; i++)
			// Обнуляем очередной байт области памяти
			item[i] = 0;
	}
}
/**
 * @brief Метод затирания набора байтов с его опустошением
 *
 * @param data затираемый набор байтов; после затирания пуст
 *
 */
void nts::sys::wipe(vector <uint8_t> & data) noexcept {
	// Затираем содержимое набора байтов
	wipe(data.data(), data.size());
	// Опустошаем набор байтов
	data.clear();
}
/**
 * @brief Метод затирания строки с её опустошением
 *
 * @param data затираемая строка; после затирания пуста
 *
 */
void nts::sys::wipe(string & data) noexcept {
	// Затираем содержимое строки: у строки собственный буфер, и запись в него законна
	wipe(&data[0], data.size());
	// Опустошаем строку
	data.clear();
}
