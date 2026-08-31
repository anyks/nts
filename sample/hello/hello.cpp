/**
 * @file hello.cpp
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
 * @brief Пример составления приветствия клиента с расширениями и разбора его обратно —
 *        от тел расширений до готового сообщения рукопожатия
 *
 * @details Приветствие складывается снизу вверх: сперва тела расширений, затем перечень
 *          расширений внутри приветствия, затем обвязка сообщения рукопожатия. Разбор
 *          идёт тем же путём в обратную сторону, и тела расширений при этом не
 *          переписываются, а смотрят внутрь разобранного приветствия
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
#include <hello/hello.hpp>
#include <entropy/entropy.hpp>
#include <extension/extension.hpp>
#include <handshake/handshake.hpp>

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
	 * @brief Метод добавления расширения в перечень расширений приветствия
	 *
	 * @details Тело расширения кладётся в накопитель образца, а в перечень уходит
	 *          просмотр на него: сами тела перечень не хранит
	 *
	 * @param type       вид добавляемого расширения
	 * @param body       тело добавляемого расширения
	 * @param bodies     накопитель тел расширений образца
	 * @param extensions перечень расширений приветствия
	 *
	 */
	void append(const extension::type_t type, const vector <uint8_t> & body, vector <vector <uint8_t>> & bodies, vector <hello::extension_t> & extensions) noexcept {
		// Добавляем тело расширения в накопитель тел расширений
		bodies.push_back(body);
		// Добавляем расширение в перечень расширений приветствия
		extensions.push_back(hello::extension_t(static_cast <uint16_t> (type), view_t(bodies.back().data(), bodies.back().size())));
	}
	/**
	 * @brief Метод получения названия вида расширения приветствия
	 *
	 * @param type вид расширения приветствия
	 *
	 * @return     название вида расширения приветствия
	 *
	 */
	const char * title(const uint16_t type) noexcept {
		/**
		 * Выполняем определение вида расширения приветствия
		 */
		switch(type){
			// Если это расширение имени запрашиваемого узла
			case static_cast <uint16_t> (extension::type_t::NAME): return "имя узла";
			// Если это расширение поддерживаемых групп обмена ключами
			case static_cast <uint16_t> (extension::type_t::GROUPS): return "группы обмена";
			// Если это расширение поддерживаемых схем подписи
			case static_cast <uint16_t> (extension::type_t::SCHEMES): return "схемы подписи";
			// Если это расширение поддерживаемых изданий протокола
			case static_cast <uint16_t> (extension::type_t::VERSIONS): return "издания протокола";
			// Если это расширение открытой части ключа обмена
			case static_cast <uint16_t> (extension::type_t::SHARE): return "ключ обмена";
		}
		// Выводим название неизвестного вида расширения
		return "неизвестно";
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
	// Накопитель тел расширений составляемого приветствия
	vector <vector <uint8_t>> bodies;
	// Перечень расширений составляемого приветствия
	vector <hello::extension_t> extensions;
	// Тело составляемого расширения приветствия
	vector <uint8_t> body;
	// Имя запрашиваемого у сервера узла
	const char * host = "gost.example.com";
	// Выполняем составление тела расширения имени узла
	extension::name(view_t(reinterpret_cast <const uint8_t *> (host), ::strlen(host)), body);
	// Добавляем расширение имени узла в перечень расширений
	::append(extension::type_t::NAME, body, bodies, extensions);
	// Выполняем сброс тела составляемого расширения
	body.clear();
	/**
	 * Выполняем составление тела расширения поддерживаемых изданий протокола
	 *
	 * @note Издание TLS 1.3 объявляется именно расширением, а не полем приветствия: поле
	 *       приветствия досталось от предыдущих изданий и своего назначения не имеет
	 */
	extension::versions(vector <uint16_t> {0x0304}, body);
	// Добавляем расширение поддерживаемых изданий в перечень расширений
	::append(extension::type_t::VERSIONS, body, bodies, extensions);
	// Выполняем сброс тела составляемого расширения
	body.clear();
	// Предлагаемые сервером группы обмена ключами
	const vector <extension::group_t> groups = {extension::group_t::GC256A, extension::group_t::GC512C};
	// Выполняем составление тела расширения поддерживаемых групп обмена
	extension::groups(groups, body);
	// Добавляем расширение поддерживаемых групп в перечень расширений
	::append(extension::type_t::GROUPS, body, bodies, extensions);
	// Выполняем сброс тела составляемого расширения
	body.clear();
	// Выполняем составление тела расширения поддерживаемых схем подписи
	extension::schemes(vector <extension::scheme_t> {extension::scheme_t::S256A, extension::scheme_t::S512C}, body);
	// Добавляем расширение поддерживаемых схем подписи в перечень расширений
	::append(extension::type_t::SCHEMES, body, bodies, extensions);
	// Выполняем сброс тела составляемого расширения
	body.clear();
	// Открытая часть ключа обмена на кривой длиной 256 разрядов
	uint8_t share[64];
	/**
	 * Выполняем выработку открытой части ключа обмена
	 *
	 * @note В настоящей связи открытая часть ключа не берётся случайной, а вычисляется
	 *       из закрытой умножением точки кривой: здесь она случайна лишь затем, чтобы
	 *       образец не вёл обмена ключами вовсе
	 */
	entropy::bytes(share, sizeof(share));
	// Выполняем составление тела расширения открытой части ключа обмена
	extension::shares(vector <extension::share_t> {extension::share_t(extension::group_t::GC256A, view_t(share, sizeof(share)))}, body);
	// Добавляем расширение открытой части ключа обмена в перечень расширений
	::append(extension::type_t::SHARE, body, bodies, extensions);
	// Составляемое приветствие клиента
	hello::client_t hello;
	/**
	 * Устанавливаем версию протокола приветствия клиента
	 *
	 * @note Издание TLS 1.2 записывается сюда всеми издания TLS 1.3 без изъятия: поле
	 *       это разбирают заслоны в сети, и всякое иное значение они отбрасывают
	 */
	hello.version = 0x0303;
	// Выполняем выработку случайного значения приветствия клиента
	entropy::bytes(hello.random, hello::HELLO_RANDOM);
	// Устанавливаем предлагаемые наборы шифрования
	hello.suites = {0xC103, 0xC104, 0xC105, 0xC106};
	// Устанавливаем перечень способов сжатия, доставшийся от предыдущих изданий
	hello.methods = {0x00};
	// Устанавливаем перечень расширений приветствия клиента
	hello.extensions = extensions;
	// Накопитель, в который складывается тело приветствия клиента
	vector <uint8_t> composed;
	// Если тело приветствия клиента составить не удалось
	if(hello::build(hello, composed) != hello::error_t::NONE){
		// Выводим сообщение об отказе составления приветствия
		cout << "Составить приветствие клиента не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Объект составителя исходящих сообщений рукопожатия
	handshake::writer_t writer;
	// Выполняем составление сообщения приветствия клиента
	if(writer.push(handshake::type_t::CLIENT, view_t(composed.data(), composed.size())) != handshake::error_t::NONE){
		// Выводим сообщение об отказе составления сообщения
		cout << "Составить сообщение рукопожатия не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Получаем составленное сообщение приветствия клиента
	const view_t message = writer.data();
	// Выводим длину составленного сообщения приветствия
	cout << "Длина сообщения    : " << message.size << " байтов" << endl;
	// Выводим первые байты составленного сообщения приветствия
	cout << "Начало сообщения   : ";
	/**
	 * Выполняем перебор первых байтов составленного сообщения
	 */
	for(size_t i = 0; i < 16; i++)
		// Выводим очередной байт сообщения шестнадцатеричной записью
		cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (message.data[i]);
	// Выполняем перевод строки за первыми байтами сообщения
	cout << dec << endl;
	// Обвязка разбираемого сообщения рукопожатия
	handshake::header_t header;
	// Выполняем разбор обвязки сообщения рукопожатия
	if(handshake::parse(message, header) != handshake::error_t::NONE){
		// Выводим сообщение об отказе разбора обвязки
		cout << "Разобрать обвязку сообщения не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разобранное приветствие клиента
	hello::client_t parsed;
	// Если тело приветствия клиента разобрать не удалось
	if(hello::parse(view_t(message.data + handshake::HANDSHAKE_HEADER, header.size), parsed) != hello::error_t::NONE){
		// Выводим сообщение об отказе разбора приветствия
		cout << "Разобрать приветствие клиента не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим число предложенных наборов шифрования
	cout << "Наборов шифрования : " << parsed.suites.size() << endl;
	// Выводим число объявленных расширений приветствия
	cout << "Расширений         : " << parsed.extensions.size() << endl;
	/**
	 * Выполняем перебор расширений разобранного приветствия
	 */
	for(auto & item : parsed.extensions)
		// Выводим вид и длину тела очередного расширения приветствия
		cout << "  " << ::title(item.type) << ": " << item.data.size << " байтов" << endl;
	// Разобранное имя запрашиваемого узла
	view_t name;
	// Получаем расширение имени запрашиваемого узла
	const hello::extension_t * extension = hello::extension(parsed.extensions, static_cast <uint16_t> (extension::type_t::NAME));
	// Если расширение имени запрашиваемого узла объявлено
	if((extension != nullptr) && (extension::name(extension->data, name) == extension::error_t::NONE))
		// Выводим разобранное имя запрашиваемого узла
		cout << "Имя узла           : " << string(reinterpret_cast <const char *> (name.data), name.size) << endl;
	// Разобранный перечень поддерживаемых групп обмена ключами
	vector <extension::group_t> parsedGroups;
	// Получаем расширение поддерживаемых групп обмена ключами
	extension = hello::extension(parsed.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
	// Если расширение поддерживаемых групп обмена объявлено
	if((extension != nullptr) && (extension::groups(extension->data, parsedGroups) == extension::error_t::NONE)){
		/**
		 * Выполняем перебор разобранных групп обмена ключами
		 */
		for(auto & item : parsedGroups)
			// Выводим опознаватель кривой очередной группы обмена ключами
			cout << "Группа обмена      : " << extension::curve(item) << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
