/**
 * @file alert.cpp
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
 * @brief Пример работы с извещениями протокола TLS — составление извещения, передача его
 *        записью слоя записей и решение о продолжении связи по полученному извещению
 *
 * @details Извещение занимает всего два байта, и весь смысл его в решении, которое сторона
 *          принимает, получив его. Издание TLS 1.3 велит принимать это решение по описанию
 *          извещения, а объявленный уровень не учитывать вовсе: здесь это видно на извещении
 *          о смертельном отказе, присланном под уровнем предупреждения
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
#include <alert/alert.hpp>
#include <record/record.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace anyks;

/**
 * @brief Пространство имён образца
 *
 */
namespace {
	/**
	 * @brief Метод передачи извещения записью слоя записей
	 *
	 * @param alert  передаваемое извещение
	 * @param result извещение, в которое помещается принятое встречной стороной
	 *
	 * @return       признак успешности передачи извещения
	 *
	 */
	static bool transfer(const alert::alert_t & alert, alert::alert_t & result) noexcept {
		// Место для записи извещения
		uint8_t buffer[alert::ALERT_LENGTH] = {0};
		// Выполняем запись извещения
		if(alert::build(alert, buffer) != alert::error_t::NONE)
			// Выводим признак неудачной передачи извещения
			return false;
		// Объект сборщика записей передающей стороны
		record::writer_t writer;
		// Выполняем упаковку извещения в запись протокола
		if(writer.push(record::type_t::ALERT, record::version_t::TLS12, view_t(buffer, sizeof(buffer))) != record::error_t::NONE)
			// Выводим признак неудачной передачи извещения
			return false;
		// Объект нарезчика записей принимающей стороны
		record::reader_t reader;
		// Передаём составленную запись принимающей стороне
		if(reader.push(writer.data()) != record::error_t::NONE)
			// Выводим признак неудачной передачи извещения
			return false;
		// Заголовок принятой записи
		record::header_t header;
		// Содержимое принятой записи
		view_t payload;
		// Выполняем получение принятой записи
		if(reader.next(header, payload) != record::error_t::NONE)
			// Выводим признак неудачной передачи извещения
			return false;
		// Если принята запись не с извещением
		if(header.type != record::type_t::ALERT)
			// Выводим признак неудачной передачи извещения
			return false;
		// Выводим итог разбора принятого извещения
		return (alert::parse(payload, result) == alert::error_t::NONE);
	}
	/**
	 * @brief Метод вывода решения, принятого по полученному извещению
	 *
	 * @param title заголовок выводимого решения
	 * @param alert полученное извещение
	 *
	 */
	static void decide(const char * title, const alert::alert_t & alert) noexcept {
		// Выводим заголовок принятого решения
		cout << title << ": " << alert::name(alert.description);
		// Если описание извещения протоколом не определено
		if(!alert::known(alert.description))
			// Сообщаем о том, что описание извещения неизвестно
			cout << " (" << static_cast <uint16_t> (alert.description) << ", описание неизвестно)";
		// Выводим решение, принятое по полученному извещению
		cout << (alert::fatal(alert) ? ", связь разорвана" : ", связь продолжена") << endl;
	}
};

/**
 * @brief Функция запуска приложения
 *
 * @param argc длина массива параметров
 * @param argv массив параметров
 *
 * @return     код выхода из приложения
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Блокируем неиспользуемую переменную
	(void) argc;
	// Блокируем неиспользуемую переменную
	(void) argv;
	// Принятое встречной стороной извещение
	alert::alert_t result;
	// Выполняем передачу извещения о завершении передачи данных
	if(!transfer(alert::alert_t(alert::level_t::WARNING, alert::description_t::CLOSE), result)){
		// Выводим сообщение об ошибке
		cout << "Передать извещение о завершении передачи данных не удалось" << endl;
		// Выходим из приложения
		return EXIT_FAILURE;
	}
	// Выводим решение по извещению о завершении передачи данных
	decide("Завершение передачи   ", result);
	// Выполняем передачу извещения об отказе проверки целостности записи
	if(!transfer(alert::alert_t(alert::level_t::FATAL, alert::description_t::MAC), result)){
		// Выводим сообщение об ошибке
		cout << "Передать извещение об отказе целостности не удалось" << endl;
		// Выходим из приложения
		return EXIT_FAILURE;
	}
	// Выводим решение по извещению об отказе проверки целостности записи
	decide("Целостность записи    ", result);
	// Выполняем передачу смертельного отказа под уровнем предупреждения
	if(!transfer(alert::alert_t(alert::level_t::WARNING, alert::description_t::PARAMETER), result)){
		// Выводим сообщение об ошибке
		cout << "Передать извещение о недозволенном значении поля не удалось" << endl;
		// Выходим из приложения
		return EXIT_FAILURE;
	}
	// Выводим решение по извещению о недозволенном значении поля
	decide("Значение поля         ", result);
	// Извещение с описанием, протоколом не определённым
	const uint8_t unknown[alert::ALERT_LENGTH] = {0x02, 0xFF};
	// Выполняем разбор извещения с неизвестным описанием
	if(alert::parse(view_t(unknown, sizeof(unknown)), result) != alert::error_t::NONE){
		// Выводим сообщение об ошибке
		cout << "Разобрать извещение с неизвестным описанием не удалось" << endl;
		// Выходим из приложения
		return EXIT_FAILURE;
	}
	// Выводим решение по извещению с неизвестным описанием
	decide("Неизвестное извещение ", result);
	// Выводим результат
	return EXIT_SUCCESS;
}
