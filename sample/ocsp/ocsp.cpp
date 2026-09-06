/**
 * @file ocsp.cpp
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
 * @brief Пример состояния сертификата OCSP (RFC 6960) со сшивкой в рукопожатие
 *        (раздел 4.4.2.1 RFC 8446): сервер сшивает готовый ответ ответчика, клиент
 *        запрашивает его, проверяет и читает состояние; отозванный сертификат обрывает
 *        связь извещением bad_certificate_status_response; составление запроса
 *        ответчику и извлечение его адреса из сертификата
 *
 * @details Ответ ответчика связь не добывает: обращение по сети - дело того, кто связь
 *          ведёт. Он составляет запрос вызовом ocsp::request, узнаёт адрес ответчика
 *          вызовом ocsp::responder, получает ответ и подаёт его серверу октетами. Ответы
 *          здесь берутся из набора tests/corpus, выработанного openssl; сроки судятся
 *          заданным мигом, а не часами, оттого набор не стареет
 *
 * @note Проверка ответа включается лишь явно вызовом verification: без неё ответ лишь
 *       отдаётся наружу как принят, а судить о нём потребитель волен модулем ocsp сам
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
#include <ocsp/ocsp.hpp>
#include <trust/trust.hpp>
#include <digest/hash.hpp>
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
	 * Миг проверки: 21 сентября 2026 года, внутри десятилетнего срока ответов набора
	 */
	static constexpr int64_t MOMENT = 1790000000;
	/**
	 * @brief Метод чтения файла набора целиком
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
	 * @brief Метод чтения сертификата набора в кодировке DER из записи PEM
	 *
	 * @param name имя файла сертификата в наборе
	 *
	 * @return     запись сертификата в кодировке DER, пустая при отказе
	 *
	 */
	vector <uint8_t> certified(const char * name) noexcept {
		// Текст сертификата в записи PEM
		const vector <uint8_t> text = corpus(name);
		// Разобранные сертификаты
		vector <vector <uint8_t>> chain;
		// Если сертификат не прочитан либо не разобран
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Выводим пустую запись
			return vector <uint8_t> ();
		// Выводим первый сертификат записи
		return chain[0];
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 *
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
	 * @brief Метод получения названия состояния сертификата
	 *
	 * @param status состояние сертификата
	 *
	 * @return       название состояния сертификата
	 *
	 */
	const char * naming(const ocsp::status_t status) noexcept {
		/**
		 * Выполняем определение состояния сертификата
		 */
		switch(static_cast <uint8_t> (status)){
			// Если сертификат не отозван
			case static_cast <uint8_t> (ocsp::status_t::GOOD):
				// Выводим название состояния
				return "GOOD";
			// Если сертификат отозван
			case static_cast <uint8_t> (ocsp::status_t::REVOKED):
				// Выводим название состояния
				return "REVOKED";
			// Если сертификат ответчику неведом
			case static_cast <uint8_t> (ocsp::status_t::UNKNOWN):
				// Выводим название состояния
				return "UNKNOWN";
		}
		// Выводим название неустановленного состояния
		return "NONE";
	}
	/**
	 * @brief Метод проведения связи со сшитым ответом
	 *
	 * @param credential подлинность сервера
	 * @param answer     ответ ответчика, сшиваемый сервером
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 *
	 * @return           признак того, что стороны заведены и переписка проведена
	 *
	 */
	bool stapled(const context::credential_t & credential, const vector <uint8_t> & answer, client::context_t & client, server::context_t & server) noexcept {
		// Пустой запас доверия: издатель самоподписанного сертификата - он сам
		const trust::store_t store;
		// Подлинность сервера
		server.credential(credential);
		// Сервер сшивает ответ ответчика о своём листе
		server.status(answer);
		// Клиент запрашивает состояние расширением status_request
		client.status(true);
		// Клиент проверяет принятый ответ модулем ocsp без люфта сроков
		client.verification(true, 0, store);
		// Миг, которым судятся сроки ответа: часов связь не читает
		client.moment(MOMENT);
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отказ заведения связи
			return false;
		// Проводим рукопожатие
		converse(client, server);
		// Выводим успешность проведения связи
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
	// Подлинность стороны сервера: самоподписанный лист, он же свой издатель
	context::credential_t credential;
	// Если подлинность стороны сервера прочитать не удалось
	if(!identity("ec256", credential)){
		// Выводим сообщение об отказе чтения подлинности
		cout << "Прочитать подлинность сервера из набора ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Ответ ответчика о неотозванном сертификате
	const vector <uint8_t> good = corpus("ocsp/ec256.good.der");
	// Ответ ответчика об отозванном сертификате
	const vector <uint8_t> revoked = corpus("ocsp/ec256.revoked.der");
	// Если ответы не прочитаны
	if(good.empty() || revoked.empty()){
		// Выводим сообщение об отказе чтения ответов
		cout << "Прочитать ответы ответчика из набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим заголовок первого прогона
	cout << "== Сшивка ответа о неотозванном сертификате ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если связь провести не удалось
		if(!stapled(credential, good, client, server) || !client.established() || !server.established()){
			// Выводим сообщение об отказе
			cout << "Рукопожатие со сшитым ответом не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Если ответ дошёл не байт в байт либо состояние не проверено
		if((client.status() != good) || (client.certified() != ocsp::status_t::GOOD)){
			// Выводим сообщение о расхождении
			cout << "Ответ дошёл не байт в байт либо состояние не GOOD: " << naming(client.certified()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог сшивки
		cout << "Ответ у клиента     : " << client.status().size() << " байт, дошёл байт в байт, состояние по проверке " << naming(client.certified()) << endl;
		// Разобранный ответ: потребитель волен разобрать его сам
		ocsp::response_t response;
		// Если ответ разобрать не удалось
		if((response.parse(view_t(client.status().data(), client.status().size())) != ocsp::error_t::NONE) || response.responses().empty()){
			// Выводим сообщение об отказе разбора
			cout << "Разобрать принятый ответ не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Ответ по сертификату
		const ocsp::single_t & single = response.responses()[0];
		// Выводим сведения разобранного ответа
		cout << "Разбор ответа       : составлен " << response.produced() << ", состояние " << naming(single.status) << ", верно с " << single.updated << " до " << single.next << ", алгоритм подписи " << response.algorithms() << endl;
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос по связи со сшитым ответом";
		// Если прикладные данные отправить не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE){
			// Выводим сообщение об отказе отправки
			cout << "Отправить прикладные данные не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Передаём запись серверу
		pump(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Выполняем получение принятых сервером прикладных данных
		server.read(received);
		// Выводим принятые сервером прикладные данные
		cout << "Сервер принял       : " << string(received.begin(), received.end()) << endl;
	}
	// Выводим заголовок прогона с отозванным сертификатом
	cout << endl << "== Сшивка ответа об отозванном сертификате ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если связь провести не удалось
		if(!stapled(credential, revoked, client, server)){
			// Выводим сообщение об отказе
			cout << "Завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Если связь установилась либо оборвана не тем
		if(client.established() || (client.error() != context::error_t::STATUS) || (client.alert().description != alert::description_t::STATUS) || (client.certified() != ocsp::status_t::REVOKED)){
			// Выводим сообщение о расхождении
			cout << "Отозванный сертификат не отвергнут: отказ " << static_cast <int> (client.error()) << ", состояние " << naming(client.certified()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог: ответ проверен успешно, состояние REVOKED, связь оборвана
		cout << "Клиент              : отказ STATUS, состояние " << naming(client.certified()) << ", извещение bad_certificate_status_response (" << static_cast <int> (client.alert().description) << ")" << endl;
		// Выводим итог у сервера
		cout << "Сервер              : " << ((server.error() == context::error_t::ALERT) ? "принял извещение клиента" : "извещения не получил") << ", описание " << static_cast <int> (server.alert().description) << endl;
	}
	// Выводим заголовок прогона без проверки
	cout << endl << "== Ответ без проверки: отдаётся как принят ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Сервер сшивает ответ об отозванном сертификате
		server.status(revoked);
		// Клиент запрашивает состояние, но проверки не включает
		client.status(true);
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие
		converse(client, server);
		// Если связь не установилась либо ответ не отдан
		if(!client.established() || (client.status() != revoked) || (client.certified() != ocsp::status_t::NONE)){
			// Выводим сообщение о расхождении
			cout << "Без проверки связь не установилась либо ответ не отдан" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог: суждение об ответе остаётся за потребителем
		cout << "Связь установлена   : ответ в " << client.status().size() << " байт отдан как принят, состояние по проверке " << naming(client.certified()) << " - судить о нём потребителю" << endl;
		// Разобранный ответ
		ocsp::response_t response;
		// Состояние сертификата по своей проверке
		ocsp::status_t status = ocsp::status_t::NONE;
		// Лист сервера: он же свой издатель
		const view_t leaf(client.peer()[0].data(), client.peer()[0].size());
		// Если ответ разобрать либо проверить не удалось
		if((response.parse(view_t(client.status().data(), client.status().size())) != ocsp::error_t::NONE) || (ocsp::verify(response, leaf, leaf, MOMENT, 0, view_t(), status) != ocsp::error_t::NONE)){
			// Выводим сообщение об отказе проверки
			cout << "Проверить ответ модулем ocsp не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог своей проверки
		cout << "Своя проверка       : ocsp::verify отвечает NONE, состояние " << naming(status) << ", отозван с " << response.responses()[0].revocation << endl;
	}
	// Выводим заголовок прогона составления запроса
	cout << endl << "== Запрос ответчику и его адрес ==" << endl;
	{
		// Лист цепочки набора и его издатель
		const vector <uint8_t> leaf = certified("leaf-ec.crt"), issuer = certified("mid-ec.crt");
		// Лист с расширением сведений о доступе к издателю
		const vector <uint8_t> aia = certified("ocsp/aia-ec.crt");
		// Запрос, выработанный openssl без неповторимого значения
		const vector <uint8_t> reference = corpus("ocsp/leaf-ec.req.der");
		// Если сертификаты набора не прочитаны
		if(leaf.empty() || issuer.empty() || aia.empty() || reference.empty()){
			// Выводим сообщение об отказе чтения
			cout << "Прочитать сертификаты набора не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Составленный запрос состояния
		vector <uint8_t> request;
		// Если запрос составить не удалось: опознаватель сертификата хешем SHA-1, как у openssl по умолчанию
		if(ocsp::request(view_t(leaf.data(), leaf.size()), view_t(issuer.data(), issuer.size()), digest::hash_t::SHA1, view_t(), request) != ocsp::error_t::NONE){
			// Выводим сообщение об отказе составления
			cout << "Составить запрос ответчику не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог составления запроса
		cout << "Запрос состояния    : " << request.size() << " байт, " << ((request == reference) ? "сходится байт в байт с запросом openssl" : "с запросом openssl расходится") << endl;
		// Неповторимое значение запроса по RFC 8954
		static const uint8_t NONCE[16] = {0x87, 0x7D, 0x8E, 0xA1, 0x97, 0x62, 0x89, 0xF0, 0x8D, 0xDE, 0x91, 0x09, 0xE4, 0x79, 0xCC, 0x21};
		// Если запрос с неповторимым значением составить не удалось
		if(ocsp::request(view_t(leaf.data(), leaf.size()), view_t(issuer.data(), issuer.size()), digest::hash_t::SHA256, view_t(NONCE, sizeof(NONCE)), request) != ocsp::error_t::NONE){
			// Выводим сообщение об отказе составления
			cout << "Составить запрос с неповторимым значением не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог составления запроса с неповторимым значением
		cout << "Запрос с nonce      : " << request.size() << " байт, опознаватель хешем SHA-256, неповторимое значение 16 байт" << endl;
		// Адрес ответчика из сертификата
		string address;
		// Если адрес ответчика извлечь не удалось
		if((ocsp::responder(view_t(aia.data(), aia.size()), address) != ocsp::error_t::NONE) || address.empty()){
			// Выводим сообщение об отказе извлечения
			cout << "Извлечь адрес ответчика из сертификата не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим адрес ответчика
		cout << "Адрес ответчика     : " << address << " (расширение сведений о доступе к издателю, раздел 4.2.2.1 RFC 5280)" << endl;
		// Адрес ответчика из листа без расширения
		string missing;
		// Извлекаем адрес из листа без расширения: отсутствие адреса отказом не считается
		const ocsp::error_t outcome = ocsp::responder(view_t(leaf.data(), leaf.size()), missing);
		// Выводим итог извлечения
		cout << "Лист без расширения : отказ " << static_cast <int> (outcome) << ", адрес " << (missing.empty() ? "пуст" : missing) << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
