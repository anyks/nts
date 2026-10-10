/**
 * @file cshake.cpp
 * @date 2026-10-10
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
 * @brief Пример работы с настраиваемой функцией переменного выхода cSHAKE и выработкой
 *        имитовставки KMAC по SP 800-185 — хеширование с меткой назначения и имитовставка
 *
 * @details Функция cSHAKE отличается от SHAKE меткой назначения: тот же вход с иной
 *          меткой даёт иной выход, и связать их нельзя - этим разводятся потоки разных
 *          назначений от одного ключа. KMAC стоит на ней же и служит имитовставкой с
 *          ключом, как HMAC над обычным хешем
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/cshake.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Пространство имён образца
 *
 */
namespace {
	/**
	 * @brief Метод вывода области байтов шестнадцатеричной записью
	 *
	 * @param title заголовок выводимой области байтов
	 * @param data  выводимая область байтов
	 * @param size  размер выводимой области байтов
	 *
	 */
	void print(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Выводим заголовок области байтов
		cout << title << ": ";
		/**
		 * Выполняем перебор байтов выводимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Выводим очередной байт шестнадцатеричной записью
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Выполняем перевод строки за областью байтов
		cout << dec << endl;
	}
	/**
	 * @brief Метод получения просмотра строки знаков
	 *
	 * @param text строка знаков, на которую заводится просмотр
	 *
	 * @return     просмотр области байтов строки знаков
	 *
	 */
	view_t text(const char * text) noexcept {
		// Выводим просмотр области байтов строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
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
	// Не используем параметры приложения
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Хешируемое сообщение образца
	const char * message = "Сообщение, которое требуется захешировать";
	// Место, в которое помещается выход функции в тридцать два байта
	uint8_t result[32];
	/**
	 * Выполняем хеширование сообщения функцией cSHAKE128 с меткой назначения
	 *
	 * @note Метка назначения входит в выход наравне со входом: тот же вход с иной
	 *       меткой даёт иной выход, и связать их между собою нельзя
	 */
	if(!digest::cshake(digest::sha3_t::SHAKE128, ::text(message), ::text("метка назначения"), view_t(), result, sizeof(result))){
		// Выводим сообщение об отказе хеширования
		cout << "Захешировать сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим выход функции cSHAKE128
	::print("cSHAKE128 метка", result, sizeof(result));
	// Выполняем хеширование того же сообщения с иной меткой назначения
	digest::cshake(digest::sha3_t::SHAKE128, ::text(message), ::text("иная метка"), view_t(), result, sizeof(result));
	// Выводим выход функции cSHAKE128 с иной меткой
	::print("cSHAKE128 иная ", result, sizeof(result));
	// Ключ выработки имитовставки образца
	const char * secret = "ключ выработки имитовставки";
	/**
	 * Выполняем выработку имитовставки сообщения функцией KMAC128
	 *
	 * @note KMAC стоит на cSHAKE и служит имитовставкой с ключом: без ключа итог не
	 *       сойдётся, как и у HMAC над обычным хешем
	 */
	if(!digest::kmac(digest::sha3_t::SHAKE128, ::text(secret), ::text(message), view_t(), result, sizeof(result))){
		// Выводим сообщение об отказе выработки имитовставки
		cout << "Выработать имитовставку не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим имитовставку сообщения
	::print("Имитовставка KMAC", result, sizeof(result));
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
