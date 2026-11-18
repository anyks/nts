/**
 * @file ripemd.cpp
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
 * @brief Пример работы с хешем RIPEMD-160 — хеширование потоком и разом, хеширование
 *        выбором алгоритма и выработка имитовставки
 *
 * @details Хеш устарел и в новых протоколах не применяется: он здесь ради связи с
 *          устаревшими собеседниками (hmac-ripemd160@openssh.com у SSH). Выбором
 *          алгоритма он доступен наравне с остальными хешами, и имитовставка HMAC
 *          над ним вырабатывается тем же вызовом, что и над любым иным
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
#include "digest/hash.hpp"
#include "digest/hmac.hpp"
#include "digest/ripemd.hpp"

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
	 * @brief Функция вывода области байтов шестнадцатеричной записью
	 *
	 * @param title заголовок выводимой области байтов
	 * @param data  выводимая область байтов
	 * @param size  размер выводимой области байтов
	 *
	 */
	void __nts_print__(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Выводим заголовок области байтов
		cout << title << ": ";
		/**
		 * Перебираем байтов выводимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Выводим очередной байт шестнадцатеричной записью
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Переводим строки за областью байтов
		cout << dec << endl;
	}
	/**
	 * @brief Функция получения просмотра строки знаков
	 *
	 * @param text строка знаков, на которую заводится просмотр
	 * @return     просмотр области байтов строки знаков
	 *
	 */
	view_t __nts_text__(const char * text) noexcept {
		// Выводим просмотр области байтов строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
};

/**
 * @brief Функция запуска приложения
 *
 * @param argc длина массива параметров
 * @param argv массив параметров
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
	// Место, в которое помещается хеш
	uint8_t result[digest::RIPEMD160];
	// Хешируем сообщения разом
	if(!digest::ripemd160(::__nts_text__(message), result, sizeof(result))){
		// Выводим сообщение об отказе хеширования
		cout << "Захешировать сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим хеш сообщения
	::__nts_print__("Хеш разом         ", result, sizeof(result));
	// Объект хеширования сообщения потоком
	digest::ripemd_t ripemd;
	/**
	 * Перебираем знаков хешируемого сообщения
	 *
	 * @note Сообщение подаётся по одному знаку нарочно: хеш обязан выйти тем же, что
	 *       и у хеширования разом, - разбиение на куски на итог не влияет
	 *
	 */
	for(const char * item = message; *item != '\0'; item++)
		// Подаём очередного знака сообщения
		ripemd.update(view_t(reinterpret_cast <const uint8_t *> (item), 1));
	// Завершаем хеширования сообщения
	ripemd.finish(result, sizeof(result));
	// Выводим хеш сообщения, захешированного потоком
	::__nts_print__("Хеш потоком       ", result, sizeof(result));
	// Объект хеширования выбором алгоритма
	digest::hasher_t hasher(digest::hash_t::RIPEMD160);
	// Подаём сообщения хешированию выбором алгоритма
	hasher.update(::__nts_text__(message));
	// Завершаем хеширования сообщения выбором алгоритма
	hasher.finish(result, sizeof(result));
	// Выводим хеш сообщения, захешированного выбором алгоритма
	::__nts_print__("Хеш выбором       ", result, sizeof(result));
	// Ключ выработки имитовставки образца
	const char * secret = "ключ выработки имитовставки";
	// Вырабатываем имитовставки сообщения
	if(!digest::hmac(digest::hash_t::RIPEMD160, ::__nts_text__(secret), ::__nts_text__(message), result, sizeof(result))){
		// Выводим сообщение об отказе выработки имитовставки
		cout << "Выработать имитовставку не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим имитовставку сообщения
	::__nts_print__("Имитовставка HMAC ", result, sizeof(result));
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
