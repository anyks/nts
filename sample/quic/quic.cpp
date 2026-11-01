/**
 * @file quic.cpp
 * @date 2026-09-06
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
 * @brief Пример рукопожатия по уровням защиты для QUIC (RFC 9001) - перенос сообщений
 *        по уровням, прикладной протокол и параметры переноса, секреты уровней в обе
 *        стороны и отказ подачи не на своём уровне
 *
 * @details Под QUIC связь записей не защищает и заголовков не разбирает: она принимает и
 *          выдаёт голые сообщения рукопожатия с пометкой уровня, а шифрование пакетов,
 *          извещения и смена ключей остаются за переносом QUIC. Ключ, вектор и защиту
 *          заголовка (метки «quic key», «quic iv», «quic hp» раздела 5.1 RFC 9001) тот,
 *          кто связь ведёт, выводит сам из секретов уровней, которые связь отдаёт
 *
 * @note Раздел 8.1 RFC 9001 велит обеим сторонам объявлять прикладной протокол, а раздел
 *       8.2 - параметры переноса: без того и другого связь по уровням не заводится вовсе,
 *       и здесь это показано отказом SETTINGS
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <schedule/schedule.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

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
	 * @brief Функция чтения файла набора ключей целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое файла, пустое при отказе чтения
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Содержимое файла
		vector <uint8_t> result;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Поток чтения файла набора
			ifstream file(string(ANTS_CORPUS) + "/" + name, ios::binary);
			// Если файл открыт
			if(file.is_open())
				// Читаем файл целиком
				result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Файл не прочитан
			result.clear();
		}
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Функция составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ набора в записи PEM
		result.secret = corpus((string(name) + ".pem").c_str());
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus((string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * Уровни защиты, несущие сообщения рукопожатия, в порядке подачи
	 */
	static const context::level_t LEVELS[] = {context::level_t::INITIAL, context::level_t::HANDSHAKE, context::level_t::APPLICATION};
	/**
	 * @brief Функция получения названия уровня защиты
	 *
	 * @param level уровень защиты
	 * @return      название уровня защиты
	 *
	 */
	const char * naming(const context::level_t level) noexcept {
		/**
		 * Выполняем определение уровня защиты
		 */
		switch(static_cast <uint8_t> (level)){
			// Если уровень начальный
			case static_cast <uint8_t> (context::level_t::INITIAL):
				// Выводим название уровня
				return "INITIAL    ";
			// Если уровень упреждающих данных
			case static_cast <uint8_t> (context::level_t::EARLY):
				// Выводим название уровня
				return "EARLY      ";
			// Если уровень рукопожатия
			case static_cast <uint8_t> (context::level_t::HANDSHAKE):
				// Выводим название уровня
				return "HANDSHAKE  ";
			// Если уровень прикладных данных
			case static_cast <uint8_t> (context::level_t::APPLICATION):
				// Выводим название уровня
				return "APPLICATION";
		}
		// Выводим название неустановленного уровня
		return "NONE       ";
	}
	/**
	 * @brief Функция получения усечённой шестнадцатеричной записи области байтов
	 *
	 * @param data область байтов
	 * @param size длина области байтов
	 * @return     первые восемь байтов записью и многоточие
	 *
	 */
	string glimpse(const uint8_t * data, const size_t size) noexcept {
		// Знаки шестнадцатеричной записи
		static const char DIGITS[] = "0123456789ABCDEF";
		// Составляемая запись
		string result;
		/**
		 * Выполняем перебор первых восьми байтов области
		 */
		for(size_t i = 0; (i < size) && (i < 8); i++){
			// Добавляем старший полубайт
			result.push_back(DIGITS[data[i] >> 4]);
			// Добавляем младший полубайт
			result.push_back(DIGITS[data[i] & 0x0F]);
		}
		// Выводим запись с многоточием, если область длиннее
		return (result + ((size > 8) ? "…" : ""));
	}
	/**
	 * @brief Функция переноса сообщений одного уровня от одной стороны к другой
	 *
	 * @param from  связь стороны, отдающей сообщения
	 * @param to    связь стороны, принимающей сообщения
	 * @param level уровень защиты переносимых сообщений
	 * @param name  название отдающей стороны для печати хода
	 * @return      признак того, что сообщения переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const context::level_t level, const char * name) noexcept {
		// Получаем сообщения, отправляемые на уровне
		const view_t data = from.output(level);
		// Если отправлять на уровне нечего
		if(data.size == 0)
			// Выводим признак того, что сообщения не переносились
			return false;
		// Выполняем перенос отправляемых сообщений
		const vector <uint8_t> buffer(data.data, data.data + data.size);
		// Снимаем отправленные сообщения с накопителя уровня
		from.consume(level, buffer.size());
		// Выводим ход переноса
		cout << "  " << name << " → " << naming(level) << " : " << setw(5) << buffer.size() << " байт данных CRYPTO" << endl;
		// Выполняем подачу сообщений принимающей стороне на том же уровне
		to.push(level, view_t(buffer.data(), buffer.size()));
		// Выводим признак того, что сообщения переносились
		return true;
	}
	/**
	 * @brief Функция передачи сообщений между сторонами по всем уровням защиты
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что сообщения между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что сообщения между сторонами передавались
		bool moved = false;
		/**
		 * Выполняем перебор уровней защиты в порядке их следования
		 */
		for(size_t i = 0; i < (sizeof(LEVELS) / sizeof(LEVELS[0])); i++)
			// Переносим сообщения уровня от клиента к серверу
			moved = (carry(client, server, LEVELS[i], "клиент") || moved);
		/**
		 * Выполняем перебор уровней защиты в порядке их следования
		 */
		for(size_t i = 0; i < (sizeof(LEVELS) / sizeof(LEVELS[0])); i++)
			// Переносим сообщения уровня от сервера к клиенту
			moved = (carry(server, client, LEVELS[i], "сервер") || moved);
		// Выводим признак того, что сообщения между сторонами передавались
		return moved;
	}
	/**
	 * @brief Функция вывода секрета уровня стороны связи
	 *
	 * @param context   связь стороны
	 * @param level     уровень защиты
	 * @param direction направление относительно стороны
	 * @param name      название стороны и направления для печати
	 * @return          признак того, что секрет выведен
	 *
	 */
	template <typename T>
	bool reveal(const T & context, const context::level_t level, const context::direction_t direction, const char * name) noexcept {
		// Место, в которое помещается секрет: не короче самого широкого хеша
		uint8_t buffer[schedule::SCHEDULE_WIDEST];
		// Длина секрета
		size_t size = 0;
		// Если секрет уровня ещё не выведен
		if(!context.secret(level, direction, buffer, size)){
			// Выводим отсутствие секрета
			cout << "  " << name << " " << naming(level) << " : не выведен" << endl;
			// Выводим отсутствие секрета
			return false;
		}
		// Выводим усечённый секрет уровня
		cout << "  " << name << " " << naming(level) << " : " << size << " байт, " << glimpse(buffer, size) << endl;
		// Выводим наличие секрета
		return true;
	}
	/**
	 * Параметры переноса клиента: содержимое связью не толкуется
	 */
	static const vector <uint8_t> CLIENT_PARAMETERS = {0x01, 0x04, 0x80, 0x00, 0xFF, 0xFF, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00};
	/**
	 * Параметры переноса сервера: содержимое связью не толкуется
	 */
	static const vector <uint8_t> SERVER_PARAMETERS = {0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x03, 0x02, 0x45, 0xAC};
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
	// Подлинность стороны сервера
	context::credential_t credential;
	// Если подлинность стороны сервера прочитать не удалось
	if(!identity("ec256", credential)){
		// Выводим сообщение об отказе чтения подлинности
		cout << "Прочитать подлинность сервера из набора ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим заголовок прогона без обязательных настроек
	cout << "== Перенос по уровням без прикладного протокола и параметров ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Перенос по уровням
		client.transport(context::transport_t::LEVELS);
		// Заводим связь: без протоколов и параметров заведение обязано отказать
		const context::error_t outcome = client.start();
		// Если заведение прошло
		if(outcome != context::error_t::SETTINGS){
			// Выводим сообщение о расхождении
			cout << "Связь по уровням завелась без обязательных настроек" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог
		cout << "Отказ SETTINGS      : под QUIC прикладной протокол и параметры переноса обязательны" << endl;
	}
	// Выводим заголовок прогона рукопожатия
	cout << endl << "== Рукопожатие по уровням ==" << endl;
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Перенос по уровням у клиента
	client.transport(context::transport_t::LEVELS);
	// Перенос по уровням у сервера
	server.transport(context::transport_t::LEVELS);
	// Набор шифрования клиента
	client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Набор шифрования сервера
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Прикладные протоколы клиента: раздел 8.1 RFC 9001
	client.protocols(vector <string> {"h3", "hq-interop"});
	// Прикладные протоколы сервера
	server.protocols(vector <string> {"h3"});
	// Параметры переноса клиента: раздел 8.2 RFC 9001, уходят приветствием как есть
	client.parameters(CLIENT_PARAMETERS);
	// Параметры переноса сервера: уходят защищёнными расширениями
	server.parameters(SERVER_PARAMETERS);
	// Имя узла, запрашиваемого клиентом
	client.name("anyks.com");
	// Подлинность сервера
	server.credential(credential);
	// Если связь завести не удалось
	if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
		// Выводим сообщение об отказе заведения связи
		cout << "Завести связь по уровням не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим уровни ключей до рукопожатия
	cout << "Ключи клиента       : запись " << naming(client.level(context::direction_t::WRITE)) << ", чтение " << naming(client.level(context::direction_t::READ)) << endl;
	// Число кругов передачи сообщений между сторонами
	size_t rounds = 0;
	/**
	 * Выполняем передачу сообщений между сторонами, пока им есть что сказать
	 */
	while((rounds < 16) && pump(client, server))
		// Считаем круги передачи сообщений
		rounds++;
	// Если рукопожатие не пройдено
	if(!client.established() || !server.established()){
		// Выводим сообщение об отказе рукопожатия
		cout << "Рукопожатие по уровням не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог рукопожатия
	cout << "Рукопожатие         : пройдено за " << rounds << " круга, прикладной протокол «" << client.protocol() << "»" << endl;
	// Выводим уровни ключей после рукопожатия
	cout << "Ключи клиента       : запись " << naming(client.level(context::direction_t::WRITE)) << ", чтение " << naming(client.level(context::direction_t::READ)) << endl;
	// Если параметры переноса собеседника не приняты
	if(!client.acquired() || !server.acquired() || (client.parameters() != SERVER_PARAMETERS) || (server.parameters() != CLIENT_PARAMETERS)){
		// Выводим сообщение о расхождении
		cout << "Параметры переноса собеседника не дошли как есть" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим параметры переноса собеседника
	cout << "Параметры сервера   : у клиента " << client.parameters().size() << " байт, " << glimpse(client.parameters().data(), client.parameters().size()) << endl;
	// Выводим параметры переноса клиента
	cout << "Параметры клиента   : у сервера " << server.parameters().size() << " байт, " << glimpse(server.parameters().data(), server.parameters().size()) << endl;
	// Выводим заголовок секретов уровней
	cout << endl << "== Секреты уровней (раздел 7.1 RFC 8446, из них выводятся ключи пакетов QUIC) ==" << endl;
	// Уровни, секреты которых выдаются
	static const context::level_t SECRETS[] = {context::level_t::HANDSHAKE, context::level_t::APPLICATION};
	/**
	 * Выполняем перебор уровней, секреты которых выдаются
	 */
	for(size_t i = 0; i < (sizeof(SECRETS) / sizeof(SECRETS[0])); i++){
		// Если секрет записи клиента не выведен
		if(!reveal(client, SECRETS[i], context::direction_t::WRITE, "клиент, запись ")){
			// Выводим сообщение о расхождении
			cout << "Секрет уровня записи клиента не выведен" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим секрет чтения сервера: он же секрет записи клиента
		reveal(server, SECRETS[i], context::direction_t::READ, "сервер, чтение ");
		// Выводим секрет записи сервера
		reveal(server, SECRETS[i], context::direction_t::WRITE, "сервер, запись ");
		// Выводим секрет чтения клиента: он же секрет записи сервера
		reveal(client, SECRETS[i], context::direction_t::READ, "клиент, чтение ");
	}
	// Секрет упреждающих данных: билета не было, потому его нет
	reveal(client, context::level_t::EARLY, context::direction_t::WRITE, "клиент, запись ");
	// Выводим заголовок прогона подачи не на своём уровне
	cout << endl << "== Подача не тем способом переноса ==" << endl;
	{
		// Связь записями
		client::context_t streamed;
		// Подлинность здесь не нужна: связь заводится приветствием клиента
		if(streamed.start() != context::error_t::NONE){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести связь записями не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Байт, поданный связи записями как сообщение уровня
		const uint8_t stray[1] = {0x00};
		// Подаём сообщение уровня связи записями: отказ LEVEL без обрыва связи
		const context::error_t outcome = streamed.push(context::level_t::INITIAL, view_t(stray, sizeof(stray)));
		// Если отказ не тот либо связь оборвана
		if((outcome != context::error_t::LEVEL) || (streamed.state() == context::state_t::FAILED)){
			// Выводим сообщение о расхождении
			cout << "Подача уровня связи записями отвечена не отказом LEVEL" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог
		cout << "Связь записями      : push(level) отвечает отказом LEVEL, связь не оборвана" << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
