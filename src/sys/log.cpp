/**
 * @file log.cpp
 * @date 2026-09-17
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
 * \~russian
 * @brief Исходный файл стока журнала библиотеки
 *
 * \~english
 * @brief Source file of the log sink of the library
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstdio>
#include <cstdarg>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/log.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * Сток журнала процесса и контекст потребителя
 */
static sys::log::sink_t ants_sink = nullptr;
static void * ants_context = nullptr;

/**
 * sink Метод установки стока журнала
 */
void sys::log::sink(const sink_t sink, void * context) noexcept {
	// Запоминаем контекст потребителя прежде стока: сток без контекста хуже, чем контекст без стока
	ants_context = context;
	// Запоминаем сток журнала
	ants_sink = sink;
}
/**
 * enabled Метод проверки того, что сток поставлен
 */
bool sys::log::enabled() noexcept {
	// Выводим признак поставленного стока
	return (ants_sink != nullptr);
}
/**
 * emit Метод передачи готовой строки в сток
 */
void sys::log::emit(const level_t level, const char * text) noexcept {
	// Если сток поставлен и строка задана
	if((ants_sink != nullptr) && (text != nullptr))
		// Передаём строку стоку
		ants_sink(level, text, ants_context);
}
/**
 * emitf Метод передачи сообщения по образцу printf
 */
void sys::log::emitf(const level_t level, const char * format, ...) noexcept {
	// Если сток не поставлен либо образец не задан, строка не собирается вовсе
	if((ants_sink == nullptr) || (format == nullptr))
		// Выходим из метода
		return;
	// Буфер строки на стеке: сообщения библиотеки коротки, длиннее обрезаются
	char buffer[512];
	// Перечень доводов
	va_list args;
	// Начинаем разбор доводов
	va_start(args, format);
	// Собираем строку
	const int written = ::vsnprintf(buffer, sizeof(buffer), format, args);
	// Завершаем разбор доводов
	va_end(args);
	// Если строка собрана
	if(written >= 0)
		// Передаём строку стоку
		ants_sink(level, buffer, ants_context);
}
