/**
 * @file common.hpp
 * @date 2026-11-19
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
 * @brief Общие помощники консольной утилиты a-nts: разбор флагов, чтение и запись
 *        областей байтов, шестнадцатеричное представление
 *
 * @details Утилита повторяет устройство командной строки OpenSSL: одиночные флаги
 *          вида -in, -out, -hex, а данные принимаются из файла либо со стандартного
 *          ввода, когда имя файла не задано
 *
 * @copyright Copyright © 2026
 *
 */

#pragma once

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "sys/global.hpp"

/**
 * Основное пространство имён
 */
namespace nts {
	/**
	 * Пространство имён помощников консольной утилиты
	 */
	namespace cli {
		/**
		 * @brief Функция проверки наличия флага в списке параметров
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @param name имя искомого флага
		 * @return     признак наличия флага
		 *
		 */
		bool flag(const int argc, const char * const argv[], const char * name) noexcept;
		/**
		 * @brief Функция получения значения флага из списка параметров
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @param name имя искомого флага
		 * @return     значение флага либо пустой указатель, когда флага нет
		 *
		 */
		const char * value(const int argc, const char * const argv[], const char * name) noexcept;
		/**
		 * @brief Функция чтения файла либо стандартного ввода в область байтов
		 *
		 * @param path   путь к файлу, пустой для стандартного ввода
		 * @param result место, в которое записываются прочитанные байты
		 * @return       признак успешности чтения
		 *
		 */
		bool readBytes(const char * path, std::vector <uint8_t> & result) noexcept;
		/**
		 * @brief Функция записи области байтов в файл либо на стандартный вывод
		 *
		 * @param path путь к файлу, пустой для стандартного вывода
		 * @param data записываемая область байтов
		 * @param size размер записываемой области байтов
		 * @return     признак успешности записи
		 *
		 */
		bool writeBytes(const char * path, const uint8_t * data, const size_t size) noexcept;
		/**
		 * @brief Функция перевода области байтов в шестнадцатеричную строку
		 *
		 * @param data переводимая область байтов
		 * @param size размер переводимой области байтов
		 * @return     шестнадцатеричная строка области байтов
		 *
		 */
		std::string hex(const uint8_t * data, const size_t size) noexcept;
		/**
		 * @brief Функция перевода шестнадцатеричной строки в область байтов
		 *
		 * @param text   переводимая шестнадцатеричная строка
		 * @param result место, в которое записываются байты
		 * @return       признак успешности перевода
		 *
		 */
		bool unhex(const std::string & text, std::vector <uint8_t> & result) noexcept;
	}
}
