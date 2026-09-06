/**
 * @file tls12.cpp
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
 * @brief Пример рукопожатия издания TLS 1.2 (RFC 5246) - пределы изданий, порядок выбора
 *        набора шифрования, обмен данными, обязательность расширенного главного секрета
 *        и второй прогон с билетом сеанса RFC 5077
 *
 * @details Обе стороны ведутся в одном приложении, а связь между ними - передача
 *          накопленных байтов из рук в руки; сети в образце нет вовсе. Издание 1.2 у
 *          связи не отдельный режим, а нижний предел: клиент объявляет пределы вызовом
 *          versions, и сервер, умеющий оба издания, спускается к общему. Ключи и
 *          сертификаты берутся из набора tests/corpus: ECDSA на кривой P-256
 *
 * @note Билет сеанса издания 1.2 хранит всё состояние сам (раздел 4 RFC 5077): серверу
 *       нужен лишь ключ билетов vault, и тот же ключ у соседнего сервера признаёт билет
 *       чужой связи - здесь это показано вторым сервером
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
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
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
	 * @brief Метод чтения файла набора ключей целиком
	 *
	 * @param name имя файла в наборе
	 *
	 * @return     содержимое файла, пустое при отказе чтения
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Содержимое файла
		vector <uint8_t> result;
		/**
		 * Выполняем чтение файла: поток и накопитель занимают память
		 */
		try {
			// Поток чтения файла набора
			ifstream file(string(ANTS_CORPUS) + "/" + name, ios::binary);
			// Если файл открыт
			if(file.is_open())
				// Читаем файл целиком
				result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		/**
		 * Если памяти под файл не хватило
		 */
		} catch(const bad_alloc &) {
			// Файл не прочитан
			result.clear();
		}
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора: ec256, ec384 либо rsa2048
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ набора в записи PEM: связь принимает и её
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
	 * @brief Метод передачи накопленных байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		// Получаем байты, отправляемые клиентом
		view_t data = client.output();
		// Если клиенту есть что отправить серверу
		if(data.size > 0){
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя клиента
			client.consume(buffer.size());
			// Выполняем подачу отправленных байтов серверу
			server.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Получаем байты, отправляемые сервером
		data = server.output();
		// Если серверу есть что отправить клиенту
		if(data.size > 0){
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя сервера
			server.consume(buffer.size());
			// Выполняем подачу отправленных байтов клиенту
			client.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения связи сторон до тишины
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       число кругов передачи байтов между сторонами
	 *
	 */
	size_t converse(client::context_t & client, server::context_t & server) noexcept {
		// Число кругов передачи байтов между сторонами
		size_t rounds = 0;
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		while((rounds < 16) && pump(client, server))
			// Считаем круги передачи байтов
			rounds++;
		// Выводим число кругов передачи байтов
		return rounds;
	}
	/**
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос по связи издания TLS 1.2";
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ по связи издания TLS 1.2";
		// Если прикладные данные клиента отправить не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Если прикладные данные сервера отправить не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Если сервер принял не то, что послал клиент
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отказ обмена
			return false;
		// Выводим принятые сервером прикладные данные
		cout << "Сервер принял       : " << string(received.begin(), received.end()) << endl;
		// Если клиент принял не то, что послал сервер
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Выводим отказ обмена
			return false;
		// Выводим принятые клиентом прикладные данные
		cout << "Клиент принял       : " << string(received.begin(), received.end()) << endl;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Метод составления приветствия чужого клиента издания 1.2 руками
	 *
	 * @param master объявляется ли расширенный главный секрет RFC 7627
	 * @param result накопитель, в который складывается запись приветствия
	 *
	 * @return       признак успешности составления приветствия
	 *
	 * @note Приветствие складывается из тел расширений, сообщения рукопожатия и записи
	 *       протокола - тем же путём, каким его складывает связь; так виден чужой
	 *       клиент, расширенного главного секрета не знающий
	 *
	 */
	bool greeting(const bool master, vector <uint8_t> & result) noexcept {
		// Составляемое приветствие клиента
		hello::client_t hello;
		// Издание TLS 1.2 заголовком, без перечня изданий - как у чужого клиента
		hello.version = 0x0303;
		/**
		 * Выполняем заполнение случайного значения: у образца оно предсказуемо нарочно
		 */
		for(size_t i = 0; i < sizeof(hello.random); i++)
			// Записываем очередной байт
			hello.random[i] = static_cast <uint8_t> (i);
		// Набор шифрования приветствия
		hello.suites = {static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256)};
		// Способ сжатия: без сжатия
		hello.methods = {0x00};
		// Тела расширений групп обмена и схем подписи
		vector <uint8_t> groups, schemes;
		// Если тела расширений составить не удалось
		if((extension::groups(vector <extension::group_t> {extension::group_t::X25519}, groups) != extension::error_t::NONE) || (extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, schemes) != extension::error_t::NONE))
			// Выводим отказ составления приветствия
			return false;
		// Добавляем расширение групп обмена
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		// Добавляем расширение схем подписи
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Если расширенный главный секрет объявляется
		if(master)
			// Добавляем пустое расширение extended_master_secret
			hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Тело приветствия
		vector <uint8_t> body;
		// Если тело приветствия составить не удалось
		if(hello::build(hello, body) != hello::error_t::NONE)
			// Выводим отказ составления приветствия
			return false;
		// Составитель сообщения рукопожатия
		handshake::writer_t writer;
		// Если сообщение рукопожатия составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ составления приветствия
			return false;
		// Нарезчик записей протокола
		record::writer_t records;
		// Если запись протокола составить не удалось
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ составления приветствия
			return false;
		// Получаем составленную запись
		const view_t data = records.data();
		// Переносим запись в накопитель
		result.assign(data.data, data.data + data.size);
		// Выводим успешность составления приветствия
		return true;
	}
	/**
	 * @brief Метод получения названия набора шифрования
	 *
	 * @param suite набор шифрования
	 *
	 * @return      название набора шифрования
	 *
	 */
	const char * naming(const protect::suite_t suite) noexcept {
		/**
		 * Выполняем определение набора шифрования
		 */
		switch(static_cast <uint16_t> (suite)){
			// Если набор ECDHE-ECDSA с AES-128-GCM
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256):
				// Выводим название набора
				return "ECDHE-ECDSA-AES128-GCM-SHA256";
			// Если набор ECDHE-ECDSA с ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256):
				// Выводим название набора
				return "ECDHE-ECDSA-CHACHA20-POLY1305";
		}
		// Выводим название неизвестного набора
		return "иной";
	}
	/**
	 * @brief Метод настройки сторон под издание 1.2 с разным порядком наборов
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 *
	 * @return           признак успешности настройки
	 *
	 */
	bool arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential) noexcept {
		// Наборы клиента: ChaCha20 первым, AES вторым
		client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Наборы сервера: AES первым, ChaCha20 вторым
		server.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256});
		// Группа обмена обеих сторон
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Группа обмена сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность сервера
		server.credential(credential);
		// Клиент ведёт лишь издание 1.2: сервер умеет оба и спустится к общему
		return (client.versions(0x0303, 0x0303) == context::error_t::NONE);
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
	// Подлинность стороны сервера
	context::credential_t credential;
	// Если подлинность стороны сервера прочитать не удалось
	if(!identity("ec256", credential)){
		// Выводим сообщение об отказе чтения подлинности
		cout << "Прочитать подлинность сервера из набора ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим заголовок первого прогона
	cout << "== Пределы изданий и порядок выбора набора ==" << endl;
	/**
	 * Выполняем перебор порядка выбора набора: порядком сервера и порядком клиента
	 */
	for(size_t own = 0; own < 2; own++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось
		if(!arrange(client, server, credential)){
			// Выводим сообщение об отказе настройки
			cout << "Установить пределы изданий клиента не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Устанавливаем порядок выбора набора: раздел 7.4.1.2 RFC 5246 отдаёт выбор серверу
		server.preference(own == 0);
		// Выводим пределы изданий сторон
		cout << "Пределы клиента     : 0x" << hex << uppercase << client.lowest() << "…0x" << client.highest() << ", сервера: 0x" << server.lowest() << "…0x" << server.highest() << dec << endl;
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести связь не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие
		const size_t rounds = converse(client, server);
		// Если рукопожатие не пройдено
		if(!client.established() || !server.established()){
			// Выводим сообщение об отказе рукопожатия
			cout << "Рукопожатие не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим согласованное издание
		cout << "Издание связи       : 0x" << hex << uppercase << client.version() << dec << " (TLS 1.2), рукопожатие за " << rounds << " круга" << endl;
		// Выводим выбранный набор
		cout << "Порядок выбора      : " << ((own == 0) ? "сервера" : "клиента") << ", набор " << naming(server.suite()) << endl;
		// Ожидаемый набор по порядку стороны, ведущей выбор
		const protect::suite_t expected = ((own == 0) ? protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256 : protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256);
		// Если набор выбран не порядком ведущей стороны
		if(server.suite() != expected){
			// Выводим сообщение о расхождении
			cout << "Набор выбран не тем порядком" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим порядок RFC 7366: у наборов AEAD он не значится
		cout << "Порядок RFC 7366    : " << (client.etm() ? "encrypt_then_mac" : "не применим, набор AEAD") << endl;
		// Если обмен прикладными данными не удался
		if(!barter(client, server)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим счётчики записей: завершение и запрос прикладных данных
		cout << "Записи клиента      : " << client.sequence() << " отправлено, у сервера принято " << server.sequence(true) << endl;
		// Выводим, чего у издания 1.2 нет
		cout << "Смена ключей        : " << ((client.update(true) == context::error_t::STATE) ? "изданию 1.2 неведома (отказ STATE)" : "прошла") << endl;
	}
	// Выводим заголовок прогона расширенного главного секрета
	cout << endl << "== Расширенный главный секрет RFC 7627 ==" << endl;
	/**
	 * Выполняем перебор приветствий чужого клиента: без расширения и с ним
	 */
	for(size_t master = 0; master < 2; master++){
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Запись приветствия чужого клиента
		vector <uint8_t> wire;
		// Если приветствие составить либо сервер завести не удалось
		if(!greeting(master == 1, wire) || (server.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Составить приветствие чужого клиента не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Подаём приветствие серверу
		server.push(view_t(wire.data(), wire.size()));
		// Если расширения нет: сервер обязан оборвать связь
		if(master == 0){
			// Если сервер связь не оборвал
			if((server.error() != context::error_t::MASTER) || (server.alert().description != alert::description_t::HANDSHAKE)){
				// Выводим сообщение о расхождении
				cout << "Сервер принял приветствие без расширенного главного секрета" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог
			cout << "Без расширения      : отказ MASTER, извещение handshake_failure (" << static_cast <int> (server.alert().description) << ")" << endl;
		// Если расширение есть: сервер отвечает залпом
		} else {
			// Если сервер оборвал связь
			if(server.error() != context::error_t::NONE){
				// Выводим сообщение о расхождении
				cout << "Сервер отверг приветствие с расширенным главным секретом" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог
			cout << "С расширением       : сервер ответил залпом в " << server.output().size << " байт, издание 0x" << hex << uppercase << server.version() << dec << endl;
		}
	}
	// Выводим заголовок прогона с билетом
	cout << endl << "== Билет сеанса RFC 5077 ==" << endl;
	// Секрет ключа билетов: общий у двух серверов
	const vector <uint8_t> vault(reinterpret_cast <const uint8_t *> ("ticket vault secret shared by the servers"), reinterpret_cast <const uint8_t *> ("ticket vault secret shared by the servers") + 41);
	// Запись билета октетами: так он уходит в другой процесс
	vector <uint8_t> octets;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось
		if(!arrange(client, server, credential)){
			// Выводим сообщение об отказе настройки
			cout << "Установить пределы изданий клиента не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Ключ билетов сервера: без него билеты признаёт лишь та же связь
		server.vault(vault);
		// Миг, которым судятся сроки билетов: часов связь не читает
		client.moment(1790000000);
		// Миг сервера
		server.moment(1790000000);
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести связь не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие
		converse(client, server);
		// Если рукопожатие не пройдено либо билет не выдан
		if(!client.established() || !server.established() || client.tickets().empty()){
			// Выводим сообщение об отказе
			cout << "Полное рукопожатие с билетом не прошло" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Билет, принятый клиентом
		const context::ticket_t & ticket = client.tickets()[0];
		// Выводим сведения о билете
		cout << "Полное рукопожатие  : сертификатов " << client.peer().size() << ", возобновление " << (client.shared() ? "да" : "нет") << endl;
		// Выводим тело билета
		cout << "Билет               : тело " << ticket.identity.size() << " байт, секрет " << ticket.secret.size() << " байт, срок " << ticket.lifetime << " с, набор 0x" << hex << uppercase << static_cast <uint16_t> (ticket.suite) << dec << endl;
		// Если билет записать октетами не удалось
		if(context::encode(ticket, octets) != context::error_t::NONE){
			// Выводим сообщение об отказе записи
			cout << "Записать билет октетами не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим длину записи билета
		cout << "Запись билета       : " << octets.size() << " байт, уходит «в другой процесс»" << endl;
		// Если обмен прикладными данными не удался
		if(!barter(client, server)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
	}
	// Билет, прочитанный из октетов
	context::ticket_t ticket;
	// Если запись билета прочитать не удалось
	if(context::decode(view_t(octets.data(), octets.size()), ticket) != context::error_t::NONE){
		// Выводим сообщение об отказе чтения
		cout << "Прочитать билет из октетов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	{
		// Связь клиента, возобновляющая прошлую
		client::context_t client;
		// Соседний сервер с тем же ключом билетов
		server::context_t server;
		// Если настроить стороны не удалось
		if(!arrange(client, server, credential)){
			// Выводим сообщение об отказе настройки
			cout << "Установить пределы изданий клиента не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Тот же ключ билетов: соседи с одним секретом признают билеты друг друга
		server.vault(vault);
		// Миг спустя минуту после выдачи билета
		client.moment(1790000060);
		// Миг сервера
		server.moment(1790000060);
		// Предъявляем билет
		client.resume(ticket);
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести возобновляемую связь не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим сокращённое рукопожатие
		const size_t rounds = converse(client, server);
		// Если рукопожатие не пройдено либо билет не признан
		if(!client.established() || !server.established() || !client.shared() || !server.shared()){
			// Выводим сообщение об отказе
			cout << "Возобновление билетом не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог возобновления: сертификатов при нём не бывает
		cout << "Возобновление       : билет признан соседним сервером за " << rounds << " круга, сертификатов " << client.peer().size() << ", набор " << naming(client.suite()) << endl;
		// Выводим новый билет: раздел 3.3 RFC 5077 выдаёт его во всяком рукопожатии
		cout << "Новый билет         : " << (client.tickets().empty() ? "не выдан" : "выдан заново") << endl;
		// Если обмен прикладными данными не удался
		if(!barter(client, server)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными по возобновлённой связи не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Закрываем связь клиентом
		client.close();
		// Доставляем извещение о закрытии
		converse(client, server);
		// Выводим состояние сервера после закрытия
		cout << "Закрытие связи      : " << ((server.state() == context::state_t::CLOSED) ? "сервер извещён клиентом" : "извещение не дошло") << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
