/**
 * @file sm2mlkem.cpp
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
 * @brief Пример работы с гибридной группой curveSM2MLKEM768 — выработка общего
 *        секрета обменом ECDHE на кривой curveSM2 вместе с инкапсуляцией ML-KEM-768
 *
 * @details Гибрид curveSM2MLKEM768 по RFC 10024 складывает классический обмен на
 *          кривой curveSM2 с постквантовой инкапсуляцией ML-KEM-768: доля кривой идёт
 *          впереди, а общий секрет есть сложение обеих половин - он стоит, пока стоит
 *          хотя бы одна из них. Здесь гибрид собран из тех же примитивов, что и в
 *          движке: agreement::ecdhe на curveSM2 и agreement::encapsulate ML-KEM-768
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
#include <agreement/ecdhe.hpp>
#include <agreement/mlkem.hpp>
#include <curve/parameters.hpp>

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
	// Эллиптическая кривая curveSM2 по GB/T 32918.5-2017
	curve::curve_t curve;
	// Если параметры кривой curveSM2 установить не удалось
	if(!curve::parameters("1.2.156.10197.1.301", curve)){
		// Выводим сообщение об отказе установки кривой
		cout << "Установить кривую curveSM2 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Мимолётная пара ключей кривой стороны клиента
	uint8_t secretA[32] = {0}, pointA[64] = {0};
	// Мимолётная пара ключей кривой стороны сервера
	uint8_t secretB[32] = {0}, pointB[64] = {0};
	/**
	 * Выполняем выработку мимолётных пар ключей кривой обеих сторон
	 *
	 * @details Открытый ключ кривой записывается двумя координатами точки подряд,
	 *          каждая младшим байтом вперёд; у записи протокола впереди идёт знак 0x04
	 *
	 */
	if(!agreement::generate(curve, secretA, pointA)){
		// Выводим сообщение об отказе выработки пары клиента
		cout << "Выработать пару кривой клиента не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем выработку мимолётной пары ключей кривой сервера
	if(!agreement::generate(curve, secretB, pointB)){
		// Выводим сообщение об отказе выработки пары сервера
		cout << "Выработать пару кривой сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Общие значения кривой, выработанные обеими сторонами
	uint8_t curveA[32] = {0}, curveB[32] = {0};
	// Выполняем выработку общего значения кривой стороной клиента
	if(!agreement::ecdhe(curve, view_t(secretA, sizeof(secretA)), view_t(pointB, sizeof(pointB)), curveA)){
		// Выводим сообщение об отказе выработки общего значения
		cout << "Выработать общее значение кривой клиента не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем выработку общего значения кривой стороной сервера
	if(!agreement::ecdhe(curve, view_t(secretB, sizeof(secretB)), view_t(pointA, sizeof(pointA)), curveB)){
		// Выводим сообщение об отказе выработки общего значения
		cout << "Выработать общее значение кривой сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если общие значения кривой разошлись
	if(::memcmp(curveA, curveB, sizeof(curveA)) != 0){
		// Выводим сообщение о расхождении общих значений
		cout << "Общие значения кривой разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало общего значения кривой
	::print("Половина кривой    ", curveA, 16);
	// Длины ключа инкапсуляции, ключа декапсуляции и шифртекста ML-KEM-768
	const size_t opened = agreement::encapsulation(agreement::kem_t::MLKEM768);
	// Запоминаем длину ключа декапсуляции ML-KEM-768
	const size_t closed = agreement::decapsulation(agreement::kem_t::MLKEM768);
	// Запоминаем длину шифртекста ML-KEM-768
	const size_t cipher = agreement::ciphertext(agreement::kem_t::MLKEM768);
	// Пара ключей ML-KEM-768 стороны клиента
	vector <uint8_t> kemKey(opened), kemSecret(closed);
	/**
	 * Выполняем выработку пары ключей ML-KEM-768 стороны клиента
	 *
	 * @details Ключ инкапсуляции уходит серверу долей клиента, ключ декапсуляции
	 *          остаётся у клиента до завершения обмена
	 *
	 */
	if(!agreement::generate(agreement::kem_t::MLKEM768, kemKey.data(), kemSecret.data())){
		// Выводим сообщение об отказе выработки пары ML-KEM
		cout << "Выработать пару ML-KEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Шифртекст инкапсуляции сервера и общие секреты ML-KEM обеих сторон
	vector <uint8_t> kemCipher(cipher);
	// Места общих секретов ML-KEM сервера и клиента
	uint8_t kemServer[agreement::MLKEM_SHARED], kemClient[agreement::MLKEM_SHARED];
	// Выполняем инкапсуляцию секрета сервером на ключе клиента
	if(!agreement::encapsulate(agreement::kem_t::MLKEM768, view_t(kemKey.data(), kemKey.size()), kemCipher.data(), kemServer)){
		// Выводим сообщение об отказе инкапсуляции
		cout << "Выработать инкапсуляцию ML-KEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем декапсуляцию секрета клиентом своим ключом
	if(!agreement::decapsulate(agreement::kem_t::MLKEM768, view_t(kemSecret.data(), kemSecret.size()), view_t(kemCipher.data(), kemCipher.size()), kemClient)){
		// Выводим сообщение об отказе декапсуляции
		cout << "Выработать декапсуляцию ML-KEM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если общие секреты ML-KEM разошлись
	if(::memcmp(kemServer, kemClient, sizeof(kemServer)) != 0){
		// Выводим сообщение о расхождении общих секретов
		cout << "Общие секреты ML-KEM разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало общего секрета ML-KEM
	::print("Половина ML-KEM    ", kemServer, 16);
	// Общий секрет гибрида у обеих сторон: сложение половин, кривая впереди
	uint8_t sharedA[64], sharedB[64];
	// Складываем общий секрет гибрида стороны A: кривая впереди
	::memcpy(sharedA, curveA, sizeof(curveA));
	::memcpy(sharedA + sizeof(curveA), kemClient, sizeof(kemClient));
	::memcpy(sharedB, curveB, sizeof(curveB));
	::memcpy(sharedB + sizeof(curveB), kemServer, sizeof(kemServer));
	// Выводим начало общего секрета гибрида
	::print("Гибрид общий       ", sharedA, 16);
	// Если общие секреты гибрида разошлись
	if(::memcmp(sharedA, sharedB, sizeof(sharedA)) != 0){
		// Выводим сообщение о расхождении общих секретов гибрида
		cout << "Общие секреты гибрида разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о совпадении общих секретов гибрида
	cout << "Общий секрет       : секреты сторон сошлись" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
