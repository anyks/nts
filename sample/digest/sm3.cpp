/**
 * @file sm3.cpp
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
 * @brief Пример работы с хешем SM3 по GB/T 32905-2016 — хеширование потоком и разом
 *
 * @details SM3 - национальный хеш КНР, устройством близок к SHA-256: блок в шестьдесят
 *          четыре байта, восемь слов состояния, шестьдесят четыре круга. В TLS он входит
 *          наборами TLS_SM4_GCM_SM3 и TLS_SM4_CCM_SM3 по RFC 8998 и схемой sm2sig_sm3
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
#include <digest/sm3.hpp>

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
	 * @brief Функция получения просмотра строки знаков
	 *
	 * @param text строка знаков, на которую заводится просмотр
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
	// Место, в которое помещается хеш в тридцать два байта
	uint8_t result[32];
	// Выполняем хеширование сообщения разом
	if(!digest::sm3(::text(message), result, sizeof(result))){
		// Выводим сообщение об отказе хеширования
		cout << "Захешировать сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим хеш сообщения
	::print("Хеш разом ", result, sizeof(result));
	// Объект хеширования сообщения потоком
	digest::sm3_t hash;
	/**
	 * Выполняем перебор знаков хешируемого сообщения
	 *
	 * @note Сообщение подаётся по одному знаку нарочно: хеш обязан выйти тем же, что
	 *       и у хеширования разом, - разбиение на куски на итог не влияет
	 *
	 */
	for(const char * item = message; *item != '\0'; item++)
		// Выполняем подачу очередного знака сообщения
		hash.update(view_t(reinterpret_cast <const uint8_t *> (item), 1));
	// Выполняем завершение хеширования сообщения
	hash.finish(result, sizeof(result));
	// Выводим хеш сообщения, захешированного потоком
	::print("Хеш потоком", result, sizeof(result));
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
