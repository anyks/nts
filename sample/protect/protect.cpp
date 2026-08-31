/**
 * @file protect.cpp
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
 * @brief Пример защиты записей протокола TLS 1.3 — наложение защиты, снятие её встречной
 *        стороной, дополнение против разбора обмена по его виду и отвержение подмены
 *
 * @details Защита ведётся на двух объектах: один хранит ключевой материал отправляющей
 *          стороны, другой - принимающей. Порядковый номер записи ведут оба сами, и
 *          сбиться им нельзя: разошедшийся номер даёт иное одноразовое значение, и метка
 *          целостности не сойдётся
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
#include <entropy/entropy.hpp>
#include <protect/protect.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace anyks;

/**
 * @brief Пространство имён образца
 *
 */
namespace {
	/**
	 * @brief Набор шифрования образца
	 *
	 * @details «Кузнечик» в режиме MGM с частой сменой ключа записи: ключ этого набора
	 *          уходит безвозвратно всякие восемь записей
	 *
	 */
	static const protect::suite_t SUITE = protect::suite_t::KUZNYECHIK_MGM_S;

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
	// Корневой ключ направления связи
	uint8_t key[protect::PROTECT_KEY];
	// Вектор замены направления связи
	uint8_t vector[protect::PROTECT_VECTOR];
	/**
	 * Выполняем выработку ключевого материала направления связи
	 *
	 * @note В настоящей связи ключ и вектор замены не вырабатываются случайно, а
	 *       выводятся расписанием ключей из хода рукопожатия: здесь они взяты случайными
	 *       лишь затем, чтобы образец обошёлся без рукопожатия вовсе
	 */
	if(!entropy::bytes(key, sizeof(key)) || !entropy::bytes(vector, protect::block(SUITE))){
		// Выводим сообщение об отказе выработки ключевого материала
		cout << "Выработать ключевой материал не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Объект защиты записей отправляющей стороны
	protect::protection_t sender;
	// Объект защиты записей принимающей стороны
	protect::protection_t receiver;
	// Если ключевой материал отправляющей стороны установить не удалось
	if(!sender.start(SUITE, view_t(key, sizeof(key)), view_t(vector, protect::block(SUITE)))){
		// Выводим сообщение об отказе установки ключевого материала
		cout << "Установить ключевой материал не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем установку того же ключевого материала принимающей стороне
	receiver.start(SUITE, view_t(key, sizeof(key)), view_t(vector, protect::block(SUITE)));
	// Выводим длину блока базового шифра набора шифрования
	cout << "Длина блока шифра  : " << protect::block(SUITE) << " байтов" << endl;
	// Выводим наибольший порядковый номер записи набора шифрования
	cout << "Записей на ключе   : " << protect::limit(SUITE) << endl;
	// Защищаемые сообщения образца
	const char * messages[3] = {
		"Первое сообщение прикладного протокола",
		"Второе",
		"Третье сообщение, длиною своей отличное от первых двух"
	};
	/**
	 * Выполняем перебор защищаемых сообщений образца
	 */
	for(size_t i = 0; i < 3; i++){
		// Накопитель, в который складывается защищённая запись
		std::vector <uint8_t> sealed;
		/**
		 * Определяем длину дополнения защищаемой записи
		 *
		 * @note Дополнением скрывается истинная длина содержимого: без него длина записи
		 *       выдаёт длину сообщения, а по ней разбирают обмен, не расшифровывая его
		 */
		const size_t padding = (32 - (::strlen(messages[i]) % 32));
		// Получаем длину защищаемого сообщения
		const size_t length = ::strlen(messages[i]);
		// Если наложить защиту на запись не удалось
		if(sender.seal(record::type_t::APPLICATION, view_t(reinterpret_cast <const uint8_t *> (messages[i]), length), sealed, padding) != protect::error_t::NONE){
			// Выводим сообщение об отказе наложения защиты
			cout << "Наложить защиту на запись не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим порядковый номер и длину защищённой записи
		cout << endl << "Запись " << i << ": длина сообщения " << length << ", длина записи " << sealed.size() << endl;
		// Выводим заголовок защищённой записи
		::print("  Заголовок        ", sealed.data(), record::RECORD_HEADER);
		// Объект сборщика входящих записей
		record::reader_t reader;
		// Выполняем подачу защищённой записи сборщику
		reader.push(view_t(sealed.data(), sealed.size()));
		// Заголовок принятой защищённой записи
		record::header_t header;
		// Содержимое принятой защищённой записи
		view_t payload;
		// Если принятую запись собрать не удалось
		if(reader.next(header, payload) != record::error_t::NONE){
			// Выводим сообщение об отказе сборки принятой записи
			cout << "Собрать принятую запись не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Истинный вид содержимого принятой записи
		record::type_t type = record::type_t::NONE;
		// Накопитель, в который складывается открытое содержимое записи
		std::vector <uint8_t> opened;
		// Если снять защиту с принятой записи не удалось
		if(receiver.open(header, payload, type, opened) != protect::error_t::NONE){
			// Выводим сообщение об отказе снятия защиты
			cout << "Снять защиту с записи не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим истинный вид содержимого принятой записи
		cout << "  Истинный вид     : " << hex << static_cast <uint32_t> (type) << dec << endl;
		// Выводим открытое содержимое принятой записи
		cout << "  Открытый текст   : " << string(reinterpret_cast <const char *> (opened.data()), opened.size()) << endl;
	}
	// Накопитель, в который складывается подменяемая запись
	std::vector <uint8_t> sealed;
	// Выполняем наложение защиты на подменяемую запись
	sender.seal(record::type_t::APPLICATION, view_t(reinterpret_cast <const uint8_t *> ("Подменяемое сообщение"), 21), sealed);
	// Портим один байт содержимого защищённой записи
	sealed[record::RECORD_HEADER] = static_cast <uint8_t> (sealed[record::RECORD_HEADER] ^ 0x01);
	// Заголовок подменённой записи
	record::header_t header;
	// Устанавливаем вид содержимого подменённой записи
	header.type = record::type_t::APPLICATION;
	// Устанавливаем версию протокола подменённой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем длину содержимого подменённой записи
	header.size = (sealed.size() - record::RECORD_HEADER);
	// Истинный вид содержимого подменённой записи
	record::type_t type = record::type_t::NONE;
	// Накопитель, в который складывается открытое содержимое записи
	std::vector <uint8_t> opened;
	// Если подменённая запись отвергнута
	if(receiver.open(header, view_t(sealed.data() + record::RECORD_HEADER, header.size), type, opened) == protect::error_t::TAG){
		// Выводим сообщение об отвержении подменённой записи
		cout << endl << "Подмена            : запись отвергнута, метка целостности не сошлась" << endl;
		// Выводим порядковый номер очередной записи принимающей стороны
		cout << "Номер после отказа : " << receiver.sequence() << " - отказ номера не сдвинул" << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
