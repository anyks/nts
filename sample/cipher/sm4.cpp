/**
 * @file sm4.cpp
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
 * @brief Пример работы с блочным шифром SM4 по GB/T 32907-2016 — преобразование одного
 *        блока и шифрование сообщения с проверкой целостности в режиме GCM
 *
 * @details SM4 - национальный блочный шифр КНР: блок и ключ по сто двадцать восемь
 *          разрядов, тридцать два круга. В TLS он входит наборами TLS_SM4_GCM_SM3 и
 *          TLS_SM4_CCM_SM3 по RFC 8998, и режим GCM здесь тот же, что и у AES
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
#include <cipher/gcm.hpp>
#include <cipher/mode.hpp>
#include <cipher/sm4.hpp>

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
	// Ключ шифрования образца
	uint8_t key[cipher::SM4_KEY];
	/**
	 * Выполняем перебор байтов ключа шифрования
	 */
	for(size_t i = 0; i < sizeof(key); i++)
		// Заполняем очередной байт ключа шифрования
		key[i] = static_cast <uint8_t> (i);
	// Объект блочного шифра SM4
	cipher::sm4_t cipher;
	// Если ключ шифрования установить не удалось
	if(!cipher.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ шифрования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Преобразуемый блок открытого текста
	uint8_t block[cipher::SM4_BLOCK] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	// Место, в которое помещается преобразованный блок
	uint8_t result[cipher::SM4_BLOCK];
	// Выполняем зашифрование одного блока
	cipher.encrypt(block, result);
	// Выводим зашифрованный блок
	::print("Блок зашифрованный ", result, sizeof(result));
	// Выполняем расшифрование того же блока
	cipher.decrypt(result, result);
	// Выводим расшифрованный блок
	::print("Блок расшифрованный", result, sizeof(result));
	// Описываем базовый алгоритм блочного шифрования для режимов работы
	const cipher::block_t base(cipher);
	// Шифруемое сообщение образца
	const char * message = "Сообщение, которое требуется зашифровать";
	// Получаем длину шифруемого сообщения
	const size_t length = ::strlen(message);
	// Место, в которое помещается зашифрованное сообщение
	uint8_t buffer[64];
	// Одноразовое значение режима GCM в двенадцать байтов
	const uint8_t nonce[12] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98};
	// Связанные данные, целостность которых проверяется без их шифрования
	const char * associated = "заголовок, который шифровать не нужно";
	// Место, в которое помещается метка целостности сообщения
	uint8_t tag[cipher::SM4_BLOCK];
	// Объект режима шифрования с проверкой целостности
	cipher::gcm_t galois;
	/**
	 * Выполняем запуск режима шифрования с проверкой целостности
	 *
	 * @note Режим GCM не дополняет сообщение до блока: длина шифртекста равна длине
	 *       открытого текста, а целостность заверяет отдельная метка
	 */
	if(!galois.start(base, view_t(nonce, sizeof(nonce)))){
		// Выводим сообщение об отказе запуска режима
		cout << "Запустить режим GCM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем зашифрование сообщения с выработкой метки целостности
	galois.encrypt(view_t(reinterpret_cast <const uint8_t *> (associated), ::strlen(associated)), view_t(reinterpret_cast <const uint8_t *> (message), length), buffer, tag);
	// Выводим зашифрованное режимом GCM сообщение
	::print("Шифртекст GCM      ", buffer, length);
	// Выводим метку целостности сообщения
	::print("Метка целостности  ", tag, sizeof(tag));
	// Объект режима снятия шифрования с проверкой целостности
	cipher::gcm_t opener;
	// Выполняем запуск режима снятия шифрования
	opener.start(base, view_t(nonce, sizeof(nonce)));
	/**
	 * Выполняем расшифрование сообщения с проверкой метки целостности
	 *
	 * @note Открытый текст записывается лишь после того, как метка сошлась: расходящаяся
	 *       метка означает, что сообщение подменили, и выдавать наверх нечего
	 */
	if(!opener.decrypt(view_t(reinterpret_cast <const uint8_t *> (associated), ::strlen(associated)), view_t(buffer, length), buffer, view_t(tag, sizeof(tag)))){
		// Выводим сообщение об отказе проверки метки целостности
		cout << "Метка целостности сообщения не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим расшифрованное режимом GCM сообщение
	cout << "Открытый текст     : " << string(reinterpret_cast <const char *> (buffer), length) << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
