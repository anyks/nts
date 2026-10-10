/**
 * @file des.cpp
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
 * @brief Пример работы с блочным шифром DES и 3DES (FIPS 46-3) — преобразование одного
 *        блока и шифрование сообщения в режиме зацепления блоков
 *
 * @details Шифр устарел и слаб: одиночный DES вскрывается перебором за сутки, а 3DES
 *          держится лишь на длине ключа. Он здесь ради связи с устаревшими собеседниками
 *          (3des-cbc у SSH), и новые протоколы на нём строить нельзя
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
#include <cipher/des.hpp>
#include <cipher/mode.hpp>

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
	// Ключ шифрования 3DES образца (три ключа DES)
	uint8_t key[cipher::DES3_KEY];
	/**
	 * Выполняем перебор байтов ключа шифрования
	 */
	for(size_t i = 0; i < sizeof(key); i++)
		// Заполняем очередной байт ключа шифрования
		key[i] = static_cast <uint8_t> (i);
	// Объект блочного шифра 3DES
	cipher::des_t cipher;
	// Если ключ шифрования установить не удалось
	if(!cipher.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ шифрования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Преобразуемый блок открытого текста
	uint8_t block[cipher::DES_BLOCK] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
	// Место, в которое помещается преобразованный блок
	uint8_t result[cipher::DES_BLOCK];
	// Выполняем зашифрование одного блока
	cipher.encrypt(block, result);
	// Выводим зашифрованный блок
	::print("Блок зашифрованный ", result, sizeof(result));
	// Выполняем расшифрование того же блока
	cipher.decrypt(result, result);
	// Выводим расшифрованный блок
	::print("Блок расшифрованный", result, sizeof(result));
	/**
	 * Описываем базовый алгоритм блочного шифрования для режимов работы
	 *
	 * @note Описание это и есть вся связь режима с шифром: тот же код режима работает
	 *       и с AES, разница лишь в длине блока
	 */
	const cipher::block_t base(cipher);
	// Шифруемое сообщение образца длиной в целое число блоков
	const char * message = "0123456789ABCDEF";
	// Получаем длину шифруемого сообщения
	const size_t length = ::strlen(message);
	// Место, в которое помещается зашифрованное сообщение
	uint8_t buffer[64];
	// Синхропосылка режима зацепления блоков длиной в блок шифра
	const uint8_t iv[cipher::DES_BLOCK] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	// Объект режима зацепления блоков
	cipher::chaining_t chaining;
	/**
	 * Выполняем запуск режима зацепления блоков
	 *
	 * @note Зацепление сообщения длиной не в целое число блоков не дополняет: дополнение
	 *       до блока - забота протокола, как и у 3des-cbc у SSH
	 */
	if(!chaining.start(base, view_t(iv, sizeof(iv)))){
		// Выводим сообщение об отказе запуска режима зацепления
		cout << "Запустить режим зацепления не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем зашифрование сообщения зацеплением блоков
	chaining.encrypt(view_t(reinterpret_cast <const uint8_t *> (message), length), buffer);
	// Выводим зашифрованное зацеплением блоков сообщение
	::print("Шифртекст CBC      ", buffer, length);
	// Объект режима снятия шифрования зацеплением блоков
	cipher::chaining_t opener;
	// Выполняем запуск режима снятия шифрования
	opener.start(base, view_t(iv, sizeof(iv)));
	// Выполняем расшифрование сообщения зацеплением блоков
	opener.decrypt(view_t(buffer, length), buffer);
	// Выводим расшифрованное зацеплением блоков сообщение
	cout << "Открытый текст     : " << string(reinterpret_cast <const char *> (buffer), length) << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
