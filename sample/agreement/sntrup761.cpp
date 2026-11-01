/**
 * @file sntrup761.cpp
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
 * @brief Пример работы с механизмом инкапсуляции ключа sntrup761 и гибридом
 *        sntrup761x25519 — выработка пары, инкапсуляция и декапсуляция общего секрета
 *
 * @details Механизм sntrup761 стоит на задаче о коротком векторе в решётке и устойчив
 *          к квантовому разложению: он применяется у SSH (sntrup761x25519-sha512) там,
 *          где секрету сессии предстоит пережить появление большого квантового
 *          компьютера. Гибрид складывает его с классическим X25519: общий секрет
 *          стоит, пока стоит хотя бы одна из половин
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
#include <agreement/sntrup761.hpp>
#include <agreement/sntrup761x25519.hpp>

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
	// Открытый ключ получателя
	uint8_t key[agreement::SNTRUP761_PUBLIC];
	// Секретный ключ получателя
	uint8_t secret[agreement::SNTRUP761_SECRET];
	/**
	 * Выполняем выработку пары ключей получателя
	 *
	 * @details Арифметика в Z/4591[x]/(x^761 − x − 1): секретный ключ хранит f, ginv,
	 *          открытый ключ, зерно rho и кэш хеша открытого ключа для декапсуляции
	 *
	 */
	if(!agreement::pair(key, secret)){
		// Выводим сообщение об отказе выработки пары
		cout << "Выработать пару sntrup761 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало открытого ключа получателя
	::print("Открытый ключ      ", key, 16);
	// Шифртекст инкапсуляции отправителя
	uint8_t cipher[agreement::SNTRUP761_CIPHERTEXT];
	// Общий секрет у отправителя и у получателя
	uint8_t mine[agreement::SNTRUP761_SHARED], theirs[agreement::SNTRUP761_SHARED];
	// Выполняем инкапсуляцию свежего секрета на открытом ключе получателя
	if(!agreement::encaps(view_t(key, sizeof(key)), cipher, mine)){
		// Выводим сообщение об отказе инкапсуляции
		cout << "Выработать инкапсуляцию не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем декапсуляцию секрета своим секретным ключом
	if(!agreement::decaps(view_t(cipher, sizeof(cipher)), view_t(secret, sizeof(secret)), theirs)){
		// Выводим сообщение об отказе декапсуляции
		cout << "Выработать декапсуляцию не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим общие секреты сторон
	::print("Секрет отправителя ", mine, sizeof(mine));
	::print("Секрет получателя  ", theirs, sizeof(theirs));
	// Если общие секреты сторон разошлись
	if(::memcmp(mine, theirs, sizeof(mine)) != 0){
		// Выводим сообщение о расхождении общих секретов
		cout << "Общие секреты сторон разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о совпадении общих секретов
	cout << "Общий секрет       : секреты сторон сошлись" << endl;
	/**
	 * Выполняем гибридный обмен sntrup761x25519 как у SSH
	 *
	 * @details Открытое значение клиента - ключ sntrup761 и ключ X25519 подряд, решётка
	 *          впереди; сервер инкапсулирует секрет решётки и вырабатывает общее значение
	 *          X25519, общий секрет - SHA-512 от сложения обеих половин
	 *
	 */
	uint8_t clientKey[agreement::SNTRUP761X25519_CLIENT], clientSecret[agreement::SNTRUP761_SECRET + 32];
	// Выполняем выработку открытого значения клиента гибрида
	if(!agreement::pairSntrup761x25519(clientKey, clientSecret)){
		// Выводим сообщение об отказе выработки клиента
		cout << "Выработать клиента гибрида не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Открытое значение сервера, его мимолётный секрет и общий секрет сервера
	uint8_t serverKey[agreement::SNTRUP761X25519_SERVER], serverSecret[32], serverShared[agreement::SNTRUP761X25519_SHARED];
	// Выполняем ответ сервера гибридного обмена
	if(!agreement::encapsSntrup761x25519(view_t(clientKey, sizeof(clientKey)), serverKey, serverSecret, serverShared)){
		// Выводим сообщение об отказе ответа сервера
		cout << "Выработать ответ сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Общий секрет клиента гибридного обмена
	uint8_t clientShared[agreement::SNTRUP761X25519_SHARED];
	// Выполняем завершение гибридного обмена клиентом
	if(!agreement::decapsSntrup761x25519(view_t(serverKey, sizeof(serverKey)), view_t(clientSecret, sizeof(clientSecret)), clientShared)){
		// Выводим сообщение об отказе завершения клиента
		cout << "Завершить обмен клиента не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало общего секрета гибрида у сервера
	::print("Гибрид сервера     ", serverShared, 16);
	// Выводим начало общего секрета гибрида у клиента
	::print("Гибрид клиента     ", clientShared, 16);
	// Если общие секреты гибрида разошлись
	if(::memcmp(serverShared, clientShared, sizeof(serverShared)) != 0){
		// Выводим сообщение о расхождении общих секретов гибрида
		cout << "Общие секреты гибрида разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о совпадении общих секретов гибрида
	cout << "Гибрид             : секреты сторон сошлись" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
