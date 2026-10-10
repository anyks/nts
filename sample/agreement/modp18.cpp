/**
 * @file modp18.cpp
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
 * @brief Пример работы с обменом Диффи-Хеллмана на группе modp18 RFC 3526 —
 *        выработка пары ключей и общего секрета на модуле в 8192 разряда
 *
 * @details Группа modp18 - наибольшая из групп RFC 3526: модуль у неё в 8192
 *          разряда (1024 байта), образующая равна двум. У SSH она идёт именем
 *          diffie-hellman-group18-sha512. Обмен строится по произвольному модулю
 *          и образующей теми же примитивами, что и у групп RFC 7919
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <vector>
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <agreement/ffdhe.hpp>

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
	// Простой модуль группы modp18 RFC 3526 - 1024 байта от старшего к младшему
	const view_t prime = agreement::prime3526(18);
	// Образующая группы modp18 равна двум
	const uint8_t gen[1] = {2};
	const view_t generator(gen, sizeof(gen));
	// Если модуль группы modp18 не найден
	if(prime.data == nullptr){
		// Выводим сообщение об отказе получения модуля
		cout << "Получить модуль modp18 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим длину модуля группы modp18
	cout << "Модуль modp18      : " << prime.size << " байтов (" << (prime.size * 8) << " разрядов)" << endl;
	// Длина секретного показателя группы modp18 - как у ffdhe8192
	const size_t length = agreement::exponent3526(18);
	// Секретные показатели и открытые ключи обеих сторон
	vector <uint8_t> secretA(length), keyA(prime.size), secretB(length), keyB(prime.size);
	/**
	 * Выполняем порождение пары ключей первой стороны
	 *
	 * @details Показатель берётся случайными байтами длиной exponent3526(18), старший
	 *          разряд выставляется; открытый ключ есть 2^x mod p длиной в модуль
	 */
	if(!agreement::pairffdhe(prime, generator, length, secretA.data(), keyA.data())){
		// Выводим сообщение об отказе порождения пары
		cout << "Породить пару первой стороны не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем порождение пары ключей второй стороны
	if(!agreement::pairffdhe(prime, generator, length, secretB.data(), keyB.data())){
		// Выводим сообщение об отказе порождения пары
		cout << "Породить пару второй стороны не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало открытого ключа первой стороны
	::print("Открытый ключ A    ", keyA.data(), 16);
	// Общие значения у первой и у второй стороны
	vector <uint8_t> sharedA(prime.size), sharedB(prime.size);
	/**
	 * Выполняем выработку общего значения первой стороной
	 *
	 * @details Общее значение есть Y^x mod p: встречный открытый ключ возводится в свой
	 *          показатель, и у обеих сторон выходит одно значение. Встречный ключ сверяется
	 *          прежде выработки: 1 < Y < p − 1, а значения 1 и p − 1 отвергаются как вырожденные
	 */
	if(!agreement::ffdhe(prime, generator, view_t(secretA.data(), secretA.size()), view_t(keyB.data(), keyB.size()), sharedA.data())){
		// Выводим сообщение об отказе выработки общего значения
		cout << "Выработать общее значение первой стороны не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем выработку общего значения второй стороной
	if(!agreement::ffdhe(prime, generator, view_t(secretB.data(), secretB.size()), view_t(keyA.data(), keyA.size()), sharedB.data())){
		// Выводим сообщение об отказе выработки общего значения
		cout << "Выработать общее значение второй стороны не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начала общих значений сторон
	::print("Общее значение A   ", sharedA.data(), 16);
	::print("Общее значение B   ", sharedB.data(), 16);
	// Если общие значения сторон разошлись
	if(::memcmp(sharedA.data(), sharedB.data(), sharedA.size()) != 0){
		// Выводим сообщение о расхождении общих значений
		cout << "Общие значения сторон разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о совпадении общих значений
	cout << "Общий секрет       : значения сторон сошлись" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
