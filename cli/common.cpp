/**
 * @file common.cpp
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
 * @brief Общие помощники консольной утилиты a-nts
 *
 * @details Разбор флагов командной строки, чтение областей байтов из файла и со
 *          стандартного ввода, запись их обратно, шестнадцатеричное представление
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "common.hpp"

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Основное пространство имён
 */
namespace nts {
	/**
	 * Пространство имён помощников консольной утилиты
	 */
	namespace cli {
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
			using namespace nts::cli;
		}
		/**
		 * @brief Функция проверки наличия флага в списке параметров
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @param name имя искомого флага
		 * @return     признак наличия флага
		 *
		 */
		bool flag(const int argc, const char * const argv[], const char * name) noexcept {
			/**
			 * Перебираем параметры командной строки
			 */
			for(int i = 1; i < argc; i++){
				// Если очередной параметр совпадает с искомым флагом
				if(::strcmp(argv[i], name) == 0)
					// Сообщаем, что флаг найден
					return true;
			}
			// Сообщаем, что флага нет
			return false;
		}
		/**
		 * @brief Функция получения значения флага из списка параметров
		 *
		 * @param argc длина списка параметров
		 * @param argv список параметров
		 * @param name имя искомого флага
		 * @return     значение флага либо пустой указатель, когда флага нет
		 *
		 */
		const char * value(const int argc, const char * const argv[], const char * name) noexcept {
			/**
			 * Перебираем параметры командной строки
			 */
			for(int i = 1; i < argc; i++){
				// Если очередной параметр совпадает с искомым флагом
				if(::strcmp(argv[i], name) == 0){
					// Если за флагом есть значение
					if((i + 1) < argc)
						// Выводим значение флага
						return argv[i + 1];
					// Значения за флагом нет
					return nullptr;
				}
			}
			// Флага в параметрах нет
			return nullptr;
		}
		/**
		 * @brief Функция чтения файла либо стандартного ввода в область байтов
		 *
		 * @param path   путь к файлу, пустой для стандартного ввода
		 * @param result место, в которое записываются прочитанные байты
		 * @return       признак успешности чтения
		 *
		 */
		bool readBytes(const char * path, vector <uint8_t> & result) noexcept {
			// Очищаем место чтения
			result.clear();
			// Если имя файла задано
			if((path != nullptr) && (path[0] != '\0')){
				// Открываем файл на чтение в двоичном режиме
				ifstream file(path, ios::binary);
				// Если файл открыть не удалось
				if(!file.is_open())
					// Сообщаем об отказе чтения
					return false;
				// Читаем содержимое файла в область байтов
				result.assign((istreambuf_iterator <char> (file)), istreambuf_iterator <char> ());
			// Иначе читаем стандартный ввод
			} else {
				// Читаем содержимое стандартного ввода в область байтов
				result.assign((istreambuf_iterator <char> (cin)), istreambuf_iterator <char> ());
			}
			// Сообщаем об успешности чтения
			return true;
		}
		/**
		 * @brief Функция записи области байтов в файл либо на стандартный вывод
		 *
		 * @param path путь к файлу, пустой для стандартного вывода
		 * @param data записываемая область байтов
		 * @param size размер записываемой области байтов
		 * @return     признак успешности записи
		 *
		 */
		bool writeBytes(const char * path, const uint8_t * data, const size_t size) noexcept {
			// Если имя файла задано
			if((path != nullptr) && (path[0] != '\0')){
				// Открываем файл на запись в двоичном режиме
				ofstream file(path, ios::binary);
				// Если файл открыть не удалось
				if(!file.is_open())
					// Сообщаем об отказе записи
					return false;
				// Записываем область байтов в файл
				file.write(reinterpret_cast <const char *> (data), static_cast <streamsize> (size));
				// Сообщаем об успешности записи
				return file.good();
			}
			// Записываем область байтов на стандартный вывод
			cout.write(reinterpret_cast <const char *> (data), static_cast <streamsize> (size));
			// Сообщаем об успешности записи
			return true;
		}
		/**
		 * @brief Функция перевода области байтов в шестнадцатеричную строку
		 *
		 * @param data переводимая область байтов
		 * @param size размер переводимой области байтов
		 * @return     шестнадцатеричная строка области байтов
		 *
		 */
		string hex(const uint8_t * data, const size_t size) noexcept {
			// Поток шестнадцатеричного представления
			ostringstream stream;
			// Настраиваем поток на шестнадцатеричный вывод без разделителей
			stream << std::hex << std::setfill('0');
			/**
			 * Перебираем байты переводимой области
			 */
			for(size_t i = 0; i < size; i++)
				// Записываем очередной байт двумя шестнадцатеричными разрядами
				stream << setw(2) << static_cast <unsigned> (data[i]);
			// Выводим шестнадцатеричную строку
			return stream.str();
		}
		/**
		 * @brief Функция перевода шестнадцатеричной строки в область байтов
		 *
		 * @param text   переводимая шестнадцатеричная строка
		 * @param result место, в которое записываются байты
		 * @return       признак успешности перевода
		 *
		 */
		bool unhex(const string & text, vector <uint8_t> & result) noexcept {
			// Очищаем место перевода
			result.clear();
			// Если строка нечётной длины
			if((text.size() % 2) != 0)
				// Сообщаем об отказе перевода
				return false;
			/**
			 * Перебираем пары шестнадцатеричных разрядов
			 */
			for(size_t i = 0; i < text.size(); i += 2){
				// Собираем байт из пары разрядов
				char buffer[3] = {text[i], text[i + 1], '\0'};
				// Указатель конца разбора
				char * end = nullptr;
				// Переводим пару разрядов в байт
				const unsigned long byte = ::strtoul(buffer, &end, 16);
				// Если разбор не дошёл до конца пары
				if((end == nullptr) || (end != (buffer + 2)))
					// Сообщаем об отказе перевода
					return false;
				// Записываем переведённый байт
				result.push_back(static_cast <uint8_t> (byte));
			}
			// Сообщаем об успешности перевода
			return true;
		}
	}
}
