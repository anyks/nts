/**
 * @file modes.cpp
 * @date 2026-11-11
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
 * @brief Пример поточного договора режимов работы ГОСТ Р 34.13-2015 — подача
 *        сообщения кусками произвольной длины в режимах простой замены, гаммирования,
 *        гаммирования с обратной связью по выходу и по шифртексту и зацепления блоков
 *
 * @details Все пять режимов держат своё состояние между вызовами, оттого сообщение
 *          вправе подаваться кусками: остаток блока гаммы, регистр сдвига и регистр
 *          зацепления переносятся из вызова в вызов, и нарезка на итог не влияет.
 *          Разница между режимами лишь в том, какие куски они принимают: режимы
 *          гаммирования берут кусок любой длины, а режимы простой замены и зацепления
 *          блоков требуют кратности длине блока шифра
 *
 * @note Длины синхропосылок у режимов разные: режим гаммирования берёт половину блока,
 *       режимы с регистром сдвига — целое число блоков. Синхропосылка короче либо
 *       длиннее дозволенной отвергается запуском режима
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
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
	 * @brief Функция вывода признака схождения двух областей байтов
	 *
	 * @param title заголовок выводимого признака
	 * @param first первая сравниваемая область байтов
	 * @param second вторая сравниваемая область байтов
	 * @param size  размер сравниваемых областей байтов
	 *
	 */
	void equal(const char * title, const uint8_t * first, const uint8_t * second, const size_t size) noexcept {
		// Выводим заголовок признака и результат сличения областей байтов
		cout << title << ": " << ((::memcmp(first, second, size) == 0) ? "итог тот же" : "итог разошёлся") << endl;
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
	// Ключ шифрования «Кузнечика» образца
	uint8_t secret[cipher::KUZNYECHIK_KEY];
	// Синхропосылка режимов с регистром сдвига длиной в два блока шифра
	uint8_t iv[cipher::KUZNYECHIK_BLOCK * 2];
	/**
	 * Выполняем заполнение ключа шифрования и синхропосылки
	 */
	for(size_t i = 0; i < sizeof(secret); i++){
		// Заполняем очередной байт ключа шифрования
		secret[i] = static_cast <uint8_t> ((i * 7) + 1);
		// Заполняем очередной байт синхропосылки
		iv[i] = static_cast <uint8_t> ((i * 11) + 3);
		// Заполняем старшую половину синхропосылки
		if(i < cipher::KUZNYECHIK_BLOCK)
			// Заполняем очередной байт старшей половины синхропосылки
			iv[i + cipher::KUZNYECHIK_BLOCK] = static_cast <uint8_t> ((i * 13) + 5);
	}
	// Объект блочного шифра «Кузнечик»
	cipher::kuznyechik_t base;
	// Если ключ шифрования установить не удалось
	if(!base.key(view_t(secret, sizeof(secret)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ шифрования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описатель базового алгоритма блочного шифрования
	const cipher::block_t block(base);
	// Шифруемое сообщение образца длиной в целое число блоков
	uint8_t message[cipher::KUZNYECHIK_BLOCK * 4];
	/**
	 * Выполняем заполнение шифруемого сообщения
	 */
	for(size_t i = 0; i < sizeof(message); i++)
		// Заполняем очередной байт шифруемого сообщения
		message[i] = static_cast <uint8_t> ((i * 29) + 7);
	// Место шифртекста, снятого одним вызовом, и место шифртекста, снятого кусками
	uint8_t whole[sizeof(message)], pieces[sizeof(message)];
	// Синхропосылка режима гаммирования: половина блока шифра
	const view_t sync(iv, cipher::KUZNYECHIK_BLOCK / 2);
	// Синхропосылка режимов с регистром сдвига: целое число блоков шифра
	const view_t full(iv, sizeof(iv));
	// Выводим заголовок раздела режима простой замены
	cout << "Простая замена (ECB), куски кратны блоку" << endl;
	// Объект режима простой замены, шифрующий сообщение одним вызовом
	cipher::codebook_t codebook;
	// Выполняем запуск режима простой замены
	codebook.start(block);
	// Выполняем зашифрование сообщения одним вызовом
	codebook.encrypt(view_t(message, sizeof(message)), whole);
	// Объект режима простой замены, шифрующий сообщение кусками
	cipher::codebook_t books;
	// Выполняем запуск режима простой замены на кусках
	books.start(block);
	// Проверяем отказ зашифрования куска длиной не в целое число блоков
	cout << "  Кусок не в блок    : " << (books.encrypt(view_t(message, cipher::KUZNYECHIK_BLOCK - 1), pieces) ? "принят" : "отвергнут") << endl;
	/**
	 * Выполняем зашифрование сообщения кусками по два блока
	 */
	for(size_t offset = 0; offset < sizeof(message); offset += (cipher::KUZNYECHIK_BLOCK * 2))
		// Выполняем зашифрование очередного куска сообщения
		books.encrypt(view_t(message + offset, cipher::KUZNYECHIK_BLOCK * 2), pieces + offset);
	// Выводим признак схождения шифртекстов обоих ходов
	::equal("  Целое против кусков", whole, pieces, sizeof(message));
	// Выводим заголовок раздела режима гаммирования
	cout << "Гаммирование (CTR), куски любой длины" << endl;
	// Объект режима гаммирования, шифрующий сообщение одним вызовом
	cipher::counter_t counter;
	// Выполняем запуск режима гаммирования
	counter.start(block, sync);
	// Выполняем зашифрование сообщения одним вызовом
	counter.encrypt(view_t(message, sizeof(message)), whole);
	// Объект режима гаммирования, шифрующий сообщение кусками
	cipher::counter_t counters;
	// Выполняем запуск режима гаммирования на кусках
	counters.start(block, sync);
	/**
	 * Выполняем зашифрование сообщения кусками по семь байтов: длина куска не кратна
	 * блоку шифра, оттого остаток блока гаммы переносится из куска в кусок
	 */
	for(size_t offset = 0; offset < sizeof(message); offset += 7){
		// Определяем длину очередного куска сообщения
		const size_t count = (((sizeof(message) - offset) < 7) ? (sizeof(message) - offset) : 7);
		// Выполняем зашифрование очередного куска сообщения
		counters.encrypt(view_t(message + offset, count), pieces + offset);
	}
	// Выводим признак схождения шифртекстов обоих ходов
	::equal("  Целое против кусков", whole, pieces, sizeof(message));
	// Объект режима снятия гаммирования
	cipher::counter_t opener;
	// Выполняем запуск режима снятия гаммирования на той же синхропосылке
	opener.start(block, sync);
	/**
	 * Выполняем расшифрование шифртекста кусками по пять байтов на месте
	 */
	for(size_t offset = 0; offset < sizeof(pieces); offset += 5){
		// Определяем длину очередного куска шифртекста
		const size_t count = (((sizeof(pieces) - offset) < 5) ? (sizeof(pieces) - offset) : 5);
		// Выполняем расшифрование очередного куска шифртекста
		opener.decrypt(view_t(pieces + offset, count), pieces + offset);
	}
	// Выводим признак схождения расшифрованного сообщения с исходным
	::equal("  Расшифровано кусками", message, pieces, sizeof(message));
	// Выводим заголовок раздела режима гаммирования с обратной связью по выходу
	cout << "Обратная связь по выходу (OFB), куски любой длины" << endl;
	// Объект режима гаммирования с обратной связью по выходу, шифрующий одним вызовом
	cipher::output_t output;
	// Выполняем запуск режима гаммирования с обратной связью по выходу
	output.start(block, full);
	// Выполняем зашифрование сообщения одним вызовом
	output.encrypt(view_t(message, sizeof(message)), whole);
	// Объект режима гаммирования с обратной связью по выходу, шифрующий кусками
	cipher::output_t outputs;
	// Выполняем запуск режима гаммирования с обратной связью по выходу на кусках
	outputs.start(block, full);
	/**
	 * Выполняем зашифрование сообщения кусками по девять байтов
	 */
	for(size_t offset = 0; offset < sizeof(message); offset += 9){
		// Определяем длину очередного куска сообщения
		const size_t count = (((sizeof(message) - offset) < 9) ? (sizeof(message) - offset) : 9);
		// Выполняем зашифрование очередного куска сообщения
		outputs.encrypt(view_t(message + offset, count), pieces + offset);
	}
	// Выводим признак схождения шифртекстов обоих ходов
	::equal("  Целое против кусков", whole, pieces, sizeof(message));
	// Выводим заголовок раздела режима зацепления блоков
	cout << "Зацепление блоков (CBC), куски кратны блоку" << endl;
	// Объект режима зацепления блоков, шифрующий сообщение одним вызовом
	cipher::chaining_t chaining;
	// Выполняем запуск режима зацепления блоков
	chaining.start(block, full);
	// Выполняем зашифрование сообщения одним вызовом
	chaining.encrypt(view_t(message, sizeof(message)), whole);
	// Объект режима зацепления блоков, шифрующий сообщение кусками
	cipher::chaining_t chains;
	// Выполняем запуск режима зацепления блоков на кусках
	chains.start(block, full);
	/**
	 * Выполняем зашифрование сообщения блоками: регистр зацепления переносится из
	 * вызова в вызов, оттого последний блок прежнего куска служит звеном зацепления
	 * первому блоку следующего
	 */
	for(size_t offset = 0; offset < sizeof(message); offset += cipher::KUZNYECHIK_BLOCK)
		// Выполняем зашифрование очередного блока сообщения
		chains.encrypt(view_t(message + offset, cipher::KUZNYECHIK_BLOCK), pieces + offset);
	// Выводим признак схождения шифртекстов обоих ходов
	::equal("  Целое против кусков", whole, pieces, sizeof(message));
	// Выводим заголовок раздела режима гаммирования с обратной связью по шифртексту
	cout << "Обратная связь по шифртексту (CFB), куски любой длины" << endl;
	// Объект режима гаммирования с обратной связью по шифртексту, шифрующий одним вызовом
	cipher::feedback_t feedback;
	// Выполняем запуск режима гаммирования с обратной связью по шифртексту
	feedback.start(block, full);
	// Выполняем зашифрование сообщения одним вызовом
	feedback.encrypt(view_t(message, sizeof(message)), whole);
	// Объект режима гаммирования с обратной связью по шифртексту, шифрующий кусками
	cipher::feedback_t feedbacks;
	// Выполняем запуск режима гаммирования с обратной связью по шифртексту на кусках
	feedbacks.start(block, full);
	/**
	 * Выполняем зашифрование сообщения кусками по три байта
	 */
	for(size_t offset = 0; offset < sizeof(message); offset += 3){
		// Определяем длину очередного куска сообщения
		const size_t count = (((sizeof(message) - offset) < 3) ? (sizeof(message) - offset) : 3);
		// Выполняем зашифрование очередного куска сообщения
		feedbacks.encrypt(view_t(message + offset, count), pieces + offset);
	}
	// Выводим признак схождения шифртекстов обоих ходов
	::equal("  Целое против кусков", whole, pieces, sizeof(message));
	// Выполняем затирание ключа шифрования
	sys::wipe(secret, sizeof(secret));
	// Выполняем затирание синхропосылки
	sys::wipe(iv, sizeof(iv));
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
