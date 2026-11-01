/**
 * @file cbc.cpp
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
 * @brief Пример наборов CBC издания TLS 1.2 с порядком «шифрование, затем имитовставка»
 *        RFC 7366 - согласование порядка сторонами, требование etm(true) против чужого
 *        клиента без расширения и порядок MAC-then-encrypt без требования
 *
 * @details Раздел 3 RFC 7366: порядок предлагается клиентом пустым расширением
 *          encrypt_then_mac и подтверждается сервером всякий раз, когда выбран набор
 *          CBC. Без него запись идёт в порядке MAC-then-encrypt раздела 6.2.3.2 RFC 5246,
 *          и разбор её обязан идти за постоянное время (Lucky13). Кому этот порядок
 *          неприемлем, требует RFC 7366 вызовом etm(true): собеседник без расширения
 *          тогда отвергается извещением handshake_failure
 *
 * @note Обе стороны ведутся в одном приложении; чужой клиент без расширения складывается
 *       руками из тел расширений, сообщения рукопожатия и записи протокола
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
	 * @brief Функция передачи накопленных байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
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
	 * @brief Функция проведения связи сторон до тишины
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
	}
	/**
	 * @brief Функция составления приветствия чужого клиента без расширения encrypt_then_mac
	 *
	 * @param suite  предлагаемый набор шифрования
	 * @param result накопитель, в который складывается запись приветствия
	 * @return       признак успешности составления приветствия
	 *
	 * @note Расширенный главный секрет RFC 7627 объявляется: без него сервер отверг бы
	 *       приветствие раньше, чем дошёл до порядка защиты записей
	 *
	 */
	bool greeting(const protect::suite_t suite, vector <uint8_t> & result) noexcept {
		// Составляемое приветствие клиента
		hello::client_t hello;
		// Издание TLS 1.2 заголовком
		hello.version = 0x0303;
		/**
		 * Выполняем заполнение случайного значения: у образца оно предсказуемо нарочно
		 */
		for(size_t i = 0; i < sizeof(hello.random); i++)
			// Записываем очередной байт
			hello.random[i] = static_cast <uint8_t> (i);
		// Набор шифрования приветствия
		hello.suites = {static_cast <uint16_t> (suite)};
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
	 * @brief Функция настройки сторон под набор издания 1.2
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param credential подлинность сервера
	 * @return           признак успешности настройки
	 *
	 */
	bool arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const context::credential_t & credential) noexcept {
		// Набор шифрования клиента
		client.suites(vector <protect::suite_t> {suite});
		// Набор шифрования сервера
		server.suites(vector <protect::suite_t> {suite});
		// Группа обмена клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Группа обмена сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность сервера
		server.credential(credential);
		// Клиент ведёт лишь издание 1.2
		return (client.versions(0x0303, 0x0303) == context::error_t::NONE);
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
	cout << "== Набор CBC: порядок RFC 7366 согласован сторонами ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны под набор CBC не удалось
		if(!arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, credential) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе настройки
			cout << "Настроить и завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим порядок до согласования: признак ложен
		cout << "До рукопожатия      : etm() = " << (client.etm() ? "истина" : "ложь") << endl;
		// Проводим рукопожатие
		converse(client, server);
		// Если рукопожатие не пройдено либо порядок не согласован
		if(!client.established() || !server.established() || !client.etm() || !server.etm()){
			// Выводим сообщение об отказе
			cout << "Рукопожатие набором CBC не прошло либо порядок RFC 7366 не согласован: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим согласованный порядок
		cout << "После рукопожатия   : набор 0x" << hex << uppercase << static_cast <uint16_t> (client.suite()) << dec << " (ECDHE-ECDSA-AES128-CBC-SHA256), etm() у клиента и сервера = истина" << endl;
		// Прикладные данные, отправляемые клиентом
		const string request = "Запись CBC в порядке encrypt_then_mac";
		// Если прикладные данные клиента отправить не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE){
			// Выводим сообщение об отказе отправки
			cout << "Отправить прикладные данные не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Запись на проводе: заголовок, явный вектор замены, шифртекст с дополнением, имитовставка поверх
		cout << "Запись на проводе   : " << client.output().size << " байт под " << request.size() << " байт данных (заголовок 5, вектор 16, шифртекст с дополнением до блока, имитовставка 32)" << endl;
		// Передаём запись серверу
		pump(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Если сервер принял не то, что послал клиент
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request)){
			// Выводим сообщение об отказе
			cout << "Сервер принял не то, что послал клиент" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим принятые сервером прикладные данные
		cout << "Сервер принял       : " << string(received.begin(), received.end()) << endl;
	}
	// Выводим заголовок прогона с требованием порядка
	cout << endl << "== Чужой клиент без расширения encrypt_then_mac ==" << endl;
	/**
	 * Выполняем перебор требования порядка у сервера: без требования и с ним
	 */
	for(size_t strict = 0; strict < 2; strict++){
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Требование порядка RFC 7366 при наборе CBC
		server.etm(strict == 1);
		// Запись приветствия чужого клиента: набор CBC, расширения нет
		vector <uint8_t> wire;
		// Если приветствие составить либо сервер завести не удалось
		if(!greeting(protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, wire) || (server.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Составить приветствие чужого клиента не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Подаём приветствие серверу
		const context::error_t outcome = server.push(view_t(wire.data(), wire.size()));
		// Если порядок требуется: сервер обязан оборвать связь
		if(strict == 1){
			// Если сервер связь не оборвал
			if((outcome != context::error_t::ETM) || (server.alert().description != alert::description_t::HANDSHAKE)){
				// Выводим сообщение о расхождении
				cout << "Сервер с требованием принял клиента без расширения" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог
			cout << "etm(true)           : отказ ETM, извещение handshake_failure (" << static_cast <int> (server.alert().description) << ") сложено в накопитель" << endl;
		// Если порядок не требуется: рукопожатие идёт в порядке MAC-then-encrypt
		} else {
			// Если сервер оборвал связь либо порядок объявлен
			if((outcome != context::error_t::NONE) || (server.suite() != protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256) || server.etm()){
				// Выводим сообщение о расхождении
				cout << "Сервер без требования отверг клиента без расширения: отказ " << static_cast <int> (outcome) << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог
			cout << "etm(false)          : набор CBC выбран, etm() = ложь - записи пойдут в порядке MAC-then-encrypt раздела 6.2.3.2 RFC 5246, залп сервера " << server.output().size << " байт" << endl;
		}
	}
	// Выводим заголовок прогона с набором AEAD
	cout << endl << "== Требование порядка наборов AEAD не касается ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны под набор AEAD не удалось
		if(!arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential)){
			// Выводим сообщение об отказе настройки
			cout << "Настроить стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Требование порядка у клиента
		client.etm(true);
		// Требование порядка у сервера
		server.etm(true);
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести связь не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие
		converse(client, server);
		// Если рукопожатие не пройдено либо порядок объявлен
		if(!client.established() || !server.established() || client.etm() || server.etm()){
			// Выводим сообщение об отказе
			cout << "Рукопожатие набором AEAD с требованием порядка не прошло" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог
		cout << "AES-128-GCM         : связь установлена при etm(true) у обеих сторон, etm() = ложь - у AEAD порядка RFC 7366 нет" << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
