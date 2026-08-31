/**
 * @file session.cpp
 * @date 2026-08-30
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
 * @brief Пример работы с состоянием связи — переписка рукопожатия, прохождение расписания
 *        ключей и передача записи, защищённой выведенными ключами
 *
 * @details Здесь связь доводится до того мига, ради которого затевалось всё остальное:
 *          обе стороны, ничего друг другу не передав, кроме приветствий и открытых частей
 *          ключей, приходят к одному и тому же ключевому материалу. Обмен ключами здесь
 *          не ведётся - общее значение взято случайным, будто он уже прошёл
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
#include <session/session.hpp>
#include <message/message.hpp>
#include <protect/protect.hpp>
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
	 * @brief Набор шифрования связи образца
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
	/**
	 * @brief Метод составления сообщения приветствия
	 *
	 * @param type   вид составляемого сообщения приветствия
	 * @param suite  набор шифрования, объявляемый приветствием
	 * @param result накопитель, в который складывается сообщение приветствия
	 *
	 * @return       признак успешности составления сообщения приветствия
	 *
	 */
	bool greeting(const handshake::type_t type, const uint16_t suite, vector <uint8_t> & result) noexcept {
		// Накопитель, в который складывается тело приветствия
		vector <uint8_t> body;
		// Если составляется приветствие клиента
		if(type == handshake::type_t::CLIENT){
			// Составляемое приветствие клиента
			hello::client_t hello;
			// Устанавливаем версию протокола приветствия клиента
			hello.version = 0x0303;
			// Выполняем выработку случайного значения приветствия
			entropy::bytes(hello.random, hello::HELLO_RANDOM);
			// Устанавливаем предлагаемый набор шифрования
			hello.suites = {suite};
			// Устанавливаем перечень способов сжатия
			hello.methods = {0x00};
			// Если тело приветствия клиента составить не удалось
			if(hello::build(hello, body) != hello::error_t::NONE)
				// Выводим отказ составления сообщения приветствия
				return false;
		// Если составляется приветствие сервера
		} else {
			// Составляемое приветствие сервера
			hello::server_t hello;
			// Устанавливаем версию протокола приветствия сервера
			hello.version = 0x0303;
			// Выполняем выработку случайного значения приветствия
			entropy::bytes(hello.random, hello::HELLO_RANDOM);
			// Устанавливаем выбранный набор шифрования
			hello.suite = suite;
			// Если тело приветствия сервера составить не удалось
			if(hello::build(hello, body) != hello::error_t::NONE)
				// Выводим отказ составления сообщения приветствия
				return false;
		}
		// Объект составителя исходящих сообщений рукопожатия
		handshake::writer_t writer;
		// Если сообщение приветствия составить не удалось
		if(writer.push(type, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ составления сообщения приветствия
			return false;
		// Получаем составленное сообщение приветствия
		const view_t data = writer.data();
		// Выполняем перенос составленного сообщения в накопитель
		result.assign(data.data, data.data + data.size);
		// Выводим успешность составления сообщения приветствия
		return true;
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
	// Сообщение приветствия клиента
	vector <uint8_t> client;
	// Сообщение приветствия сервера
	vector <uint8_t> server;
	// Если приветствия сторон составить не удалось
	if(!::greeting(handshake::type_t::CLIENT, static_cast <uint16_t> (SUITE), client) || !::greeting(handshake::type_t::SERVER, static_cast <uint16_t> (SUITE), server)){
		// Выводим сообщение об отказе составления приветствий
		cout << "Составить приветствия сторон не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим длины составленных приветствий сторон
	cout << "Приветствия        : клиент " << client.size() << ", сервер " << server.size() << " байтов" << endl;
	/**
	 * Переписку рукопожатия ведут обе стороны, каждая у себя
	 *
	 * @note Ключи обеих сторон сойдутся лишь тогда, когда сойдутся и переписки: тем
	 *       рукопожатие и защищено от подмены по дороге
	 */
	session::transcript_t sending;
	// Объект переписки рукопожатия принимающей стороны
	session::transcript_t receiving;
	// Выполняем начало переписки рукопожатия отправляющей стороны
	sending.start();
	// Выполняем начало переписки рукопожатия принимающей стороны
	receiving.start();
	// Добавляем приветствие клиента в переписку отправляющей стороны
	sending.update(view_t(client.data(), client.size()));
	// Добавляем приветствие сервера в переписку отправляющей стороны
	sending.update(view_t(server.data(), server.size()));
	// Добавляем приветствие клиента в переписку принимающей стороны
	receiving.update(view_t(client.data(), client.size()));
	// Добавляем приветствие сервера в переписку принимающей стороны
	receiving.update(view_t(server.data(), server.size()));
	// Хеш переписки рукопожатия отправляющей стороны
	uint8_t first[32];
	// Хеш переписки рукопожатия принимающей стороны
	uint8_t second[32];
	// Выполняем получение хеша переписки отправляющей стороны
	sending.digest(first);
	// Выполняем получение хеша переписки принимающей стороны
	receiving.digest(second);
	// Выводим хеш переписки рукопожатия сторон
	::print("Хеш переписки      ", first, sizeof(first));
	// Если переписки сторон разошлись
	if(::memcmp(first, second, sizeof(first)) != 0){
		// Выводим сообщение о расхождении переписок сторон
		cout << "Переписки сторон разошлись" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Общее значение обмена ключами
	uint8_t shared[64];
	/**
	 * Выполняем выработку общего значения обмена ключами
	 *
	 * @note В настоящей связи это значение вычисляют обе стороны сами, умножая открытую
	 *       часть ключа собеседника на свою закрытую: по связи оно не передаётся вовсе
	 */
	entropy::bytes(shared, sizeof(shared));
	// Объект значений расписания ключей отправляющей стороны
	session::secrets_t outgoing;
	// Объект значений расписания ключей принимающей стороны
	session::secrets_t incoming;
	// Выполняем заведение начальной ступени расписания обеих сторон
	if((outgoing.start(view_t(nullptr, 0)) != session::error_t::NONE) || (incoming.start(view_t(nullptr, 0)) != session::error_t::NONE)){
		// Выводим сообщение об отказе заведения расписания ключей
		cout << "Завести расписание ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем вывод ступени рукопожатия расписания отправляющей стороны
	if(outgoing.handshake(view_t(shared, sizeof(shared)), view_t(first, sizeof(first))) != session::error_t::NONE){
		// Выводим сообщение об отказе вывода ступени рукопожатия
		cout << "Вывести ступень рукопожатия не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем вывод ступени рукопожатия расписания принимающей стороны
	incoming.handshake(view_t(shared, sizeof(shared)), view_t(second, sizeof(second)));
	// Выводим пройденную ступень расписания ключей
	cout << "Ступень расписания : рукопожатие" << endl;
	// Корневой ключ направления связи от сервера
	uint8_t key[protect::PROTECT_KEY];
	// Вектор замены направления связи от сервера
	uint8_t replacement[protect::PROTECT_VECTOR];
	// Выполняем вывод ключевого материала направления связи от сервера
	if(outgoing.material(session::side_t::SERVER, SUITE, key, replacement) != session::error_t::NONE){
		// Выводим сообщение об отказе вывода ключевого материала
		cout << "Вывести ключевой материал не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим корневой ключ направления связи от сервера
	::print("Ключ сервера       ", key, sizeof(key));
	// Выводим вектор замены направления связи от сервера
	::print("Вектор замены      ", replacement, protect::block(SUITE));
	// Объект защиты записей отправляющей стороны
	protect::protection_t sender;
	// Выполняем установку ключевого материала отправляющей стороны
	sender.start(SUITE, view_t(key, sizeof(key)), view_t(replacement, protect::block(SUITE)));
	// Корневой ключ направления связи, выведенный принимающей стороной
	uint8_t peer[protect::PROTECT_KEY];
	// Вектор замены направления связи, выведенный принимающей стороной
	uint8_t element[protect::PROTECT_VECTOR];
	// Выполняем вывод ключевого материала принимающей стороной
	incoming.material(session::side_t::SERVER, SUITE, peer, element);
	// Объект защиты записей принимающей стороны
	protect::protection_t receiver;
	// Выполняем установку ключевого материала принимающей стороны
	receiver.start(SUITE, view_t(peer, sizeof(peer)), view_t(element, protect::block(SUITE)));
	// Передаваемое сообщение рукопожатия
	const char * text = "Защищённые расширения, отправленные ключами рукопожатия";
	// Накопитель, в который складывается защищённая запись
	vector <uint8_t> sealed;
	// Если наложить защиту на запись не удалось
	if(sender.seal(record::type_t::HANDSHAKE, view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text)), sealed) != protect::error_t::NONE){
		// Выводим сообщение об отказе наложения защиты
		cout << "Наложить защиту на запись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим длину защищённой записи
	cout << "Защищённая запись  : " << sealed.size() << " байтов" << endl;
	// Объект сборщика входящих записей
	record::reader_t reader;
	// Выполняем подачу защищённой записи сборщику
	reader.push(view_t(sealed.data(), sealed.size()));
	// Заголовок принятой защищённой записи
	record::header_t header;
	// Содержимое принятой защищённой записи
	view_t payload;
	// Выполняем сборку принятой защищённой записи
	reader.next(header, payload);
	// Истинный вид содержимого принятой записи
	record::type_t type = record::type_t::NONE;
	// Накопитель, в который складывается открытое содержимое записи
	vector <uint8_t> opened;
	// Если снять защиту с принятой записи не удалось
	if(receiver.open(header, payload, type, opened) != protect::error_t::NONE){
		// Выводим сообщение об отказе снятия защиты
		cout << "Снять защиту с записи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим открытое содержимое принятой записи
	cout << "Принято            : " << string(reinterpret_cast <const char *> (opened.data()), opened.size()) << endl;
	// Ключ завершения рукопожатия отправляющей стороны
	uint8_t outgoingKey[32];
	// Ключ завершения рукопожатия принимающей стороны
	uint8_t incomingKey[32];
	// Выполняем вывод ключа завершения рукопожатия обеих сторон
	outgoing.finished(session::side_t::SERVER, outgoingKey);
	// Выполняем вывод ключа завершения рукопожатия принимающей стороной
	incoming.finished(session::side_t::SERVER, incomingKey);
	// Тело сообщения завершения рукопожатия отправляющей стороны
	uint8_t outgoingFinished[32];
	// Тело сообщения завершения рукопожатия принимающей стороны
	uint8_t incomingFinished[32];
	// Выполняем выработку завершения рукопожатия отправляющей стороной
	message::finished(view_t(outgoingKey, sizeof(outgoingKey)), view_t(first, sizeof(first)), outgoingFinished);
	// Выполняем выработку завершения рукопожатия принимающей стороной
	message::finished(view_t(incomingKey, sizeof(incomingKey)), view_t(second, sizeof(second)), incomingFinished);
	// Если завершения рукопожатия сторон сошлись
	if(message::compare(view_t(outgoingFinished, sizeof(outgoingFinished)), view_t(incomingFinished, sizeof(incomingFinished))))
		// Выводим сообщение о схождении завершений рукопожатия сторон
		cout << "Завершение         : стороны пришли к одному ключевому материалу" << endl;
	// Хеш переписки рукопожатия на миг перехода к прикладным данным
	uint8_t transcript[32];
	// Добавляем защищённое сообщение в переписку рукопожатия
	sending.update(view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text)));
	// Выполняем получение хеша переписки рукопожатия
	sending.digest(transcript);
	// Если ступень прикладных данных расписания вывести не удалось
	if(outgoing.application(view_t(transcript, sizeof(transcript))) != session::error_t::NONE){
		// Выводим сообщение об отказе вывода ступени прикладных данных
		cout << "Вывести ступень прикладных данных не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем вывод ключевого материала прикладных данных
	outgoing.material(session::side_t::SERVER, SUITE, peer, element);
	// Выводим корневой ключ направления связи на поре прикладных данных
	::print("Ключ прикладной    ", peer, sizeof(peer));
	/**
	 * Ключ прикладных данных с ключом рукопожатия не совпадает и из него не выводится
	 * обратно: раскрытие позднего ключа раннего не выдаёт
	 */
	if(::memcmp(peer, key, sizeof(key)) != 0)
		// Выводим сообщение о расхождении ключей пор связи
		cout << "Ключи пор связи    : ключ прикладных данных с ключом рукопожатия разошёлся" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
