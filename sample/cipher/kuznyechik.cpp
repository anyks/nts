/**
 * @file kuznyechik.cpp
 * @date 2026-08-29
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
 * @brief Пример работы с блочным шифром «Кузнечик» — преобразование одного блока, режимы
 *        гаммирования и зацепления, выработка имитовставки и шифрование с проверкой
 *        целостности
 *
 * @details Шифр преобразует единственный блок и о сообщениях не знает вовсе: сообщение
 *          шифруется режимом работы, и режим этот от выбранного шифра не зависит - тот же
 *          самый код работает и с «Магмой», разница лишь в длине блока
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
#include <cipher/mgm.hpp>
#include <cipher/mode.hpp>
#include <cipher/kuznyechik.hpp>

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
	uint8_t key[cipher::KUZNYECHIK_KEY];
	/**
	 * Выполняем перебор байтов ключа шифрования
	 */
	for(size_t i = 0; i < sizeof(key); i++)
		// Заполняем очередной байт ключа шифрования
		key[i] = static_cast <uint8_t> (i);
	// Объект блочного шифра «Кузнечик»
	cipher::kuznyechik_t cipher;
	// Если ключ шифрования установить не удалось
	if(!cipher.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ шифрования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Преобразуемый блок открытого текста
	uint8_t block[cipher::KUZNYECHIK_BLOCK] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
	};
	// Место, в которое помещается преобразованный блок
	uint8_t result[cipher::KUZNYECHIK_BLOCK];
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
	 * @note Описание это и есть вся связь режима с шифром: виртуальности здесь нет, а
	 *       ветвление по виду шифра не легло бы на путь, зависящий от секретного значения
	 */
	const cipher::block_t base(cipher);
	// Шифруемое сообщение образца
	const char * message = "Сообщение длиной не в целое число блоков шифра";
	// Получаем длину шифруемого сообщения
	const size_t length = ::strlen(message);
	// Место, в которое помещается зашифрованное сообщение
	uint8_t buffer[128];
	// Начальное заполнение счётчика режима гаммирования
	const uint8_t nonce[cipher::KUZNYECHIK_BLOCK / 2] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCE, 0xF0};
	// Объект режима гаммирования со счётчиком
	cipher::counter_t counter;
	/**
	 * Выполняем запуск режима гаммирования со счётчиком
	 *
	 * @note Гаммирование сообщения длиной не в целое число блоков не дополняет: длина
	 *       шифртекста равна длине открытого текста
	 */
	if(!counter.start(base, view_t(nonce, sizeof(nonce)))){
		// Выводим сообщение об отказе запуска режима гаммирования
		cout << "Запустить режим гаммирования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем зашифрование сообщения гаммированием
	counter.encrypt(view_t(reinterpret_cast <const uint8_t *> (message), length), buffer);
	// Выводим зашифрованное гаммированием сообщение
	::print("Гаммирование       ", buffer, length);
	// Объект выработки имитовставки сообщения
	cipher::imitation_t imitation;
	// Выполняем запуск выработки имитовставки сообщения
	imitation.start(base);
	// Выполняем подачу сообщения выработке имитовставки
	imitation.update(view_t(reinterpret_cast <const uint8_t *> (message), length));
	// Выполняем завершение выработки имитовставки сообщения
	imitation.finish(result, sizeof(result));
	// Выводим имитовставку сообщения
	::print("Имитовставка OMAC1 ", result, sizeof(result));
	// Одноразовое значение режима шифрования с проверкой целостности
	uint8_t single[cipher::KUZNYECHIK_BLOCK];
	/**
	 * Выполняем перебор байтов одноразового значения
	 *
	 * @note Старший разряд одноразового значения занят самим режимом и обязан быть
	 *       нулевым: им разделяются ветвь выработки гаммы и ветвь выработки метки
	 */
	for(size_t i = 0; i < sizeof(single); i++)
		// Заполняем очередной байт одноразового значения
		single[i] = static_cast <uint8_t> (i);
	// Связанные данные, целостность которых проверяется без их шифрования
	const char * associated = "заголовок, который шифровать не нужно";
	// Место, в которое помещается метка целостности сообщения
	uint8_t tag[cipher::KUZNYECHIK_BLOCK];
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Если режим шифрования с проверкой целостности запустить не удалось
	if(!galois.start(base, view_t(single, sizeof(single)))){
		// Выводим сообщение об отказе запуска режима
		cout << "Запустить режим MGM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем зашифрование сообщения с выработкой метки целостности
	galois.encrypt(view_t(reinterpret_cast <const uint8_t *> (associated), ::strlen(associated)), view_t(reinterpret_cast <const uint8_t *> (message), length), buffer, tag);
	// Выводим зашифрованное режимом MGM сообщение
	::print("Шифртекст MGM      ", buffer, length);
	// Выводим метку целостности сообщения
	::print("Метка целостности  ", tag, sizeof(tag));
	// Объект режима снятия шифрования с проверкой целостности
	cipher::galois_t opener;
	// Выполняем запуск режима снятия шифрования
	opener.start(base, view_t(single, sizeof(single)));
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
	// Выводим расшифрованное режимом MGM сообщение
	cout << "Открытый текст     : " << string(reinterpret_cast <const char *> (buffer), length) << endl;
	// Портим один байт метки целостности сообщения
	tag[0] = static_cast <uint8_t> (tag[0] ^ 0x01);
	// Объект режима снятия шифрования с испорченной меткой
	cipher::galois_t broken;
	// Выполняем запуск режима снятия шифрования
	broken.start(base, view_t(single, sizeof(single)));
	// Если испорченная метка целостности отвергнута
	if(!broken.decrypt(view_t(reinterpret_cast <const uint8_t *> (associated), ::strlen(associated)), view_t(buffer, length), buffer, view_t(tag, sizeof(tag))))
		// Выводим сообщение об отвержении испорченной метки
		cout << "Испорченная метка целостности отвергнута" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
