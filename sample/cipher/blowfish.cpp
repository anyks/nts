/**
 * @file blowfish.cpp
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
 * @brief Пример работы с блочным шифром Blowfish (Шнайер) — преобразование блока,
 *        обращение шифра через описатель режимов работы и шифрование сообщения
 *        режимами гаммирования и MGM
 *
 * @details Контекст Blowfish заводится парой вызовов: init кладёт в массив P и в
 *          таблицы S цифры числа π, а expand0 разворачивает в них ключ. Дальше контекст
 *          передаётся режимам работы описателем block_t — тем же самым, каким режиму
 *          передаются «Кузнечик», «Магма» и AES, оттого код режима от выбора шифра не
 *          зависит. Шифр держит блок в восемь байтов, и MGM на нём даёт метку
 *          целостности той же длины
 *
 * @note Шифр учебный и для новых протоколов не годится: блок в шестьдесят четыре
 *       разряда наполняется столкновениями уже на десятках гигабайтов. Здесь он ради
 *       bcrypt и связи с устаревшими собеседниками
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
#include <sys/wipe.hpp>
#include <cipher/mode.hpp>
#include <cipher/mgm.hpp>
#include <cipher/blowfish.hpp>

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
	 * @brief Функция записи двух половин блока байтами от старшего
	 *
	 * @param words  записываемые половины блока
	 * @param result место, в которое записывается блок в восемь байтов
	 *
	 */
	void store(const uint32_t * words, uint8_t * result) noexcept {
		/**
		 * Выполняем запись обеих половин блока от старшего байта к младшему
		 */
		for(size_t i = 0; i < 4; i++){
			// Записываем очередной байт левой половины блока
			result[i] = static_cast <uint8_t> (words[0] >> (24 - (i * 8)));
			// Записываем очередной байт правой половины блока
			result[i + 4] = static_cast <uint8_t> (words[1] >> (24 - (i * 8)));
		}
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
	// Ключ шифрования Blowfish образца
	uint8_t secret[16];
	/**
	 * Выполняем перебор байтов ключа шифрования
	 */
	for(size_t i = 0; i < sizeof(secret); i++)
		// Заполняем очередной байт ключа шифрования
		secret[i] = static_cast <uint8_t> ((i * 7) + 1);
	// Контекст блочного шифра Blowfish
	cipher::blowfish_t base;
	// Выполняем инициализацию контекста константами числа π
	cipher::init(&base);
	// Выполняем расширение ключа без соли
	cipher::expand0(&base, secret, sizeof(secret));
	// Преобразуемый блок открытого текста
	uint8_t block[cipher::BLOWFISH_BLOCK] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
	// Место, в которое помещается преобразованный блок
	uint8_t result[cipher::BLOWFISH_BLOCK];
	// Обе половины преобразуемого блока словами от старшего байта
	uint32_t words[2] = {0, 0};
	/**
	 * Выполняем разбор блока на две половины словами от старшего байта к младшему
	 */
	for(size_t i = 0; i < 4; i++){
		// Дополняем левую половину очередным байтом блока
		words[0] = static_cast <uint32_t> ((words[0] << 8) | block[i]);
		// Дополняем правую половину очередным байтом блока
		words[1] = static_cast <uint32_t> ((words[1] << 8) | block[i + 4]);
	}
	// Выполняем зашифрование блока шифром Blowfish
	cipher::encrypt(&base, words, 1);
	// Выполняем запись зашифрованных половин блока байтами от старшего
	::store(words, result);
	// Выводим зашифрованный блок
	::print("Блок зашифрованный ", result, sizeof(result));
	// Выполняем расшифрование того же блока
	cipher::decrypt(&base, words, 1);
	// Выполняем запись расшифрованных половин блока байтами от старшего
	::store(words, result);
	// Выводим расшифрованный блок
	::print("Блок расшифрованный", result, sizeof(result));
	/**
	 * Описываем базовый алгоритм блочного шифрования для режимов работы
	 *
	 * @note Описание это и есть вся связь режима с шифром: тот же код режима работает
	 *       и с AES, разница лишь в длине блока и длине синхропосылки
	 *
	 */
	const cipher::block_t descriptor(base);
	// Место, в которое помещается блок, преобразованный через описатель
	uint8_t sealed[cipher::BLOWFISH_BLOCK];
	// Выполняем зашифрование блока через описатель базового шифра
	descriptor.encrypt(descriptor.cipher, block, sealed);
	// Выводим блок, зашифрованный через описатель
	::print("Блок через описатель", sealed, sizeof(sealed));
	// Выполняем расшифрование блока через описатель базового шифра
	descriptor.decrypt(descriptor.cipher, sealed, result);
	// Выводим признак схождения расшифрованного блока с исходным
	cout << "Обращение блока    : " << ((::memcmp(result, block, sizeof(block)) == 0) ? "сошлось" : "разошлось") << endl;
	// Шифруемое сообщение образца
	const char * message = "Сообщение, шифруемое Blowfish в режиме гаммирования";
	// Получаем длину шифруемого сообщения
	const size_t length = ::strlen(message);
	// Место, в которое помещается зашифрованное сообщение
	uint8_t buffer[128];
	/**
	 * Синхропосылка режима гаммирования занимает половину блока шифра: у Blowfish
	 * это четыре байта, тогда как режимы с регистром сдвига просят не меньше блока
	 */
	const uint8_t sync[cipher::BLOWFISH_BLOCK / 2] = {0xFE, 0xDC, 0xBA, 0x98};
	// Объект режима гаммирования
	cipher::counter_t counter;
	// Выполняем запуск режима гаммирования
	if(!counter.start(descriptor, view_t(sync, sizeof(sync)))){
		// Выводим сообщение об отказе запуска режима гаммирования
		cout << "Запустить режим гаммирования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	/**
	 * Выполняем зашифрование сообщения кусками по семь байтов
	 *
	 * @note Состояние гаммы переносится между вызовами, оттого нарезка сообщения на
	 *       итог не влияет: куски вправе быть любой длины
	 *
	 */
	for(size_t offset = 0; offset < length; offset += 7){
		// Определяем длину очередного куска сообщения
		const size_t count = (((length - offset) < 7) ? (length - offset) : 7);
		// Выполняем зашифрование очередного куска сообщения
		counter.encrypt(view_t(reinterpret_cast <const uint8_t *> (message) + offset, count), buffer + offset);
	}
	// Выводим зашифрованное кусками сообщение
	::print("Шифртекст CTR      ", buffer, length);
	// Объект режима снятия гаммирования
	cipher::counter_t opener;
	// Выполняем запуск режима снятия гаммирования на той же синхропосылке
	opener.start(descriptor, view_t(sync, sizeof(sync)));
	// Выполняем расшифрование сообщения одним куском на месте
	opener.decrypt(view_t(buffer, length), buffer);
	// Выводим расшифрованное сообщение
	cout << "Открытый текст     : " << string(reinterpret_cast <const char *> (buffer), length) << endl;
	/**
	 * Режим MGM на восьмибайтовом блоке: метка целостности занимает блок шифра, а
	 * начальное заполнение счётчика обязано иметь нулевой старший разряд
	 */
	const uint8_t nonce[cipher::BLOWFISH_BLOCK] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
	// Метка целостности длиной в блок шифра
	uint8_t tag[cipher::BLOWFISH_BLOCK];
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Выполняем запуск режима MGM
	galois.start(descriptor, view_t(nonce, sizeof(nonce)));
	// Выполняем зашифрование сообщения с выработкой метки целостности
	galois.encrypt(view_t(sync, sizeof(sync)), view_t(reinterpret_cast <const uint8_t *> (message), length), buffer, tag);
	// Выводим метку целостности режима MGM
	::print("Метка MGM          ", tag, sizeof(tag));
	// Объект режима снятия шифрования с проверкой целостности
	cipher::galois_t checker;
	// Выполняем запуск режима MGM на стороне проверки
	checker.start(descriptor, view_t(nonce, sizeof(nonce)));
	// Выполняем расшифрование сообщения с проверкой метки целостности
	const bool trusted = checker.decrypt(view_t(sync, sizeof(sync)), view_t(buffer, length), buffer, view_t(tag, sizeof(tag)));
	// Выводим признак подлинности расшифрованного сообщения
	cout << "Метка MGM сошлась  : " << (trusted ? "да" : "нет") << endl;
	// Выполняем затирание контекста шифра, держащего развёрнутый ключ
	sys::wipe(&base, sizeof(base));
	// Выполняем затирание ключа шифрования
	sys::wipe(secret, sizeof(secret));
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
