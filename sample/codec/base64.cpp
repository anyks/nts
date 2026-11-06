/**
 * @file base64.cpp
 * @date 2026-11-07
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
 * @brief Пример работы с кодированием основания 64 - запись и разбор обоих алфавитов,
 *        без заполнения и с заполнением, пропуск пробельных знаков и отказы разбора
 *
 * @details Кодек принадлежит открытому договору: потребитель выбирает алфавит записи,
 *          заполнение хвоста знаками «=» и терпимость к пробельным знакам при разборе
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <codec/base64.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Кодируемые данные образца
	const uint8_t data[] = " Man is distinguished by his reason";
	// Запись основания с заполнением
	string standard;
	// Кодируем данные алфавитом раздела 4 RFC 4648
	if(!codec::encode(view_t(data, sizeof(data) - 1), standard)){
		// Сообщаем об отказе кодирования
		cout << "Кодирование не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем запись с заполнением
	cout << "Запись: " << standard << endl;
	// Запись без заполнения
	string stripped;
	// Кодируем данные без заполнения хвоста
	if(!codec::encode(view_t(data, sizeof(data) - 1), stripped, false)){
		// Сообщаем об отказе кодирования
		cout << "Кодирование без заполнения не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем запись без заполнения
	cout << "Без заполнения: " << stripped << endl;
	// Запись основания URL
	string url;
	// Кодируем данные алфавитом раздела 5 RFC 4648
	if(!codec::encode(view_t(data, sizeof(data) - 1), url, false, codec::alphabet_t::URL)){
		// Сообщаем об отказе кодирования
		cout << "Кодирование URL не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем запись основания URL
	cout << "Основание URL: " << url << endl;
	// Разобранные байты
	vector <uint8_t> bytes;
	// Разбираем запись с пробельными знаками
	if(!codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zm9v YmFy"), 9), bytes, codec::alphabet_t::STANDARD, true)){
		// Сообщаем об отказе разбора
		cout << "Разбор не удался" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем разобранные байты
	cout << "Разбор с пробелом: " << string(bytes.begin(), bytes.end()) << endl;
	// Отказ разбора постороннего знака
	if(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zm9v?"), 5), bytes)){
		// Сообщаем о неверном принятии записи
		cout << "Посторонний знак принят" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем отказ постороннего знака
	cout << "Посторонний знак отвергнут" << endl;
	// Выходим с успехом
	return EXIT_SUCCESS;
}
