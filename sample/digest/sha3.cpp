/**
 * @file sha3.cpp
 * @date 2026-09-08
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
 * @brief Пример работы с SHA-3 и SHAKE по FIPS 202 — четыре разрядности хеша разом, SHAKE с
 *        выходом переменной длины, хеширование потоком через общий hasher и BLAKE2 с ключом
 *
 * @details Хеши FIPS 202 и RFC 7693 стоят рядом с SHA-2: те же вызовы, иные алгоритмы;
 *          SHAKE отличается лишь тем, что длину выхода задаёт вызывающий
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
#include <digest/sha3.hpp>
#include <digest/blake2.hpp>
#include <digest/siphash.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты образца
 *
 */
namespace {
	/**
	 * @brief Метод печати области байтов шестнадцатеричной записью
	 *
	 * @param title подпись
	 * @param data  область байтов
	 * @param size  длина области
	 *
	 */
	void print(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Печатаем подпись
		cout << title << ": ";
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Печатаем байт
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Завершаем строку
		cout << dec << endl;
	}
	/**
	 * @brief Метод получения просмотра текста
	 *
	 * @param text текст
	 *
	 * @return     просмотр
	 *
	 */
	view_t text(const char * text) noexcept {
		// Выводим просмотр текста
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
};

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы
 *
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Доводы образцу не нужны
	(void) argc;
	(void) argv;
	// Сообщение, которое хешируется
	const char * message = "Сообщение под SHA-3 и SHAKE по FIPS 202";
	// Место под хеш наибольшей разрядности
	uint8_t result[64];
	// Разрядности SHA-3
	static const digest::sha3_t KINDS[] = {digest::sha3_t::SHA3_224, digest::sha3_t::SHA3_256, digest::sha3_t::SHA3_384, digest::sha3_t::SHA3_512};
	// Подписи разрядностей
	static const char * TITLES[] = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
	/**
	 * Выполняем перебор разрядностей
	 */
	for(size_t i = 0; i < 4; i++){
		// Длина хеша разрядности
		const size_t size = digest::length(KINDS[i]);
		// Если захешировать не удалось
		if(!digest::sha3(KINDS[i], ::text(message), result, size)){
			// Печатаем отказ
			cout << "Захешировать сообщение " << TITLES[i] << " не удалось" << endl;
			// Выходим с отказом
			return EXIT_FAILURE;
		}
		// Печатаем хеш
		::print(TITLES[i], result, size);
	}
	// SHAKE128 с выходом в 16 байтов и SHAKE256 с выходом в 64 байта: длину задаёт вызывающий
	if(!digest::sha3(digest::sha3_t::SHAKE128, ::text(message), result, 16))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем выход SHAKE128
	::print("SHAKE128 (16)", result, 16);
	// Если выход SHAKE256 выработать не удалось
	if(!digest::sha3(digest::sha3_t::SHAKE256, ::text(message), result, 64))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем выход SHAKE256
	::print("SHAKE256 (64)", result, 64);
	// Хеширование потоком через губку Keccak: SHA3-256 по одному байту
	digest::keccak_t hasher(digest::sha3_t::SHA3_256);
	/**
	 * Выполняем перебор байтов сообщения
	 */
	for(const char * item = message; *item != '\0'; item++)
		// Подаём байт хешу
		hasher.update(view_t(reinterpret_cast <const uint8_t *> (item), 1));
	// Место под хеш потока
	uint8_t streamed[32];
	// Если хеш потока получить не удалось
	if(!hasher.finish(streamed, sizeof(streamed)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Если хеш потоком разошёлся с хешем разом
	if(!digest::sha3(digest::sha3_t::SHA3_256, ::text(message), result, 32) || (::memcmp(result, streamed, 32) != 0)){
		// Печатаем отказ
		cout << "Хеш потоком разошёлся с хешем разом" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем хеш потока
	::print("SHA3-256 потоком", streamed, 32);
	// BLAKE2b с ключом (RFC 7693): ключ до 64 байтов, выход до 64 байтов; BLAKE2s - до 32 и 32
	const char * key = "ключ имитовставки";
	// Если BLAKE2b с ключом выработать не удалось
	if(!digest::blake2(digest::blake_t::BLAKE2B, ::text(key), ::text(message), result, 64))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем BLAKE2b
	::print("BLAKE2b-512 с ключом", result, 64);
	// Если BLAKE2s без ключа выработать не удалось
	if(!digest::blake2(digest::blake_t::BLAKE2S, view_t(), ::text(message), result, 32))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем BLAKE2s
	::print("BLAKE2s-256 без ключа", result, 32);
	// SipHash-2-4: ключевая хеш-функция коротких меток, ключ ровно 16 байтов
	static const uint8_t SIPKEY[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	// Метка числом
	uint64_t mark = 0;
	// Если метку выработать не удалось
	if(!digest::siphash(view_t(SIPKEY, sizeof(SIPKEY)), ::text(message), mark))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем метку
	cout << "SipHash-2-4 (64): 0x" << hex << mark << dec << endl;
	// Если 128-разрядную метку выработать не удалось
	if(!digest::siphash(view_t(SIPKEY, sizeof(SIPKEY)), ::text(message), result, 16))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем метку
	::print("SipHash-2-4 (128)", result, 16);
	// Выходим успешно
	return EXIT_SUCCESS;
}
