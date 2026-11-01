/**
 * @file psk.cpp
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
 * @brief Пример связи издания TLS 1.2 заранее разделённым ключом (RFC 4279, RFC 5489) -
 *        сервер отвечает на опознаватель вызовом respond и шлёт подсказку, клиент
 *        выбирает опознаватель по подсказке вызовом advise; неизвестный опознаватель
 *        с раскрытием и без, неверный ключ
 *
 * @details Сертификатов при заранее разделённом ключе не бывает вовсе: подлинность
 *          сторон доказывается знанием ключа, а общее значение обмена выводится из
 *          него. Сервер держит много ключей одним контекстом, оттого ключа не хранит,
 *          а отвечает на опознаватель клиента вызовом: дано identity - ключ либо отказ
 *
 * @note Раздел 2 RFC 4279 оставляет серверу выбор: сказать клиенту, что опознаватель
 *       неизвестен (извещение unknown_psk_identity), либо промолчать и оборвать связь на
 *       завершении, не выдавая, какие опознаватели у него есть. Выбор за ручкой disclose
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
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
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
	 * @brief Связка заранее разделённых ключей стороны
	 *
	 * @details У сервера связка - весь запас ключей по опознавателям; у клиента -
	 *          свой опознаватель с ключом да запасная пара, выбираемая по подсказке
	 *
	 */
	typedef struct Keyring {
		// Основной опознаватель и ключ
		vector <uint8_t> identity, key;
		// Запасные опознаватель и ключ
		vector <uint8_t> alternative, spare;
		// Опознаватель, увиденный сервером, и подсказка, увиденная клиентом
		vector <uint8_t> seen, hint;
		/**
		 * @brief Конструктор
		 *
		 */
		Keyring() noexcept = default;
	} keyring_t;
	/**
	 * @brief Функция перевода строки в набор байтов
	 *
	 * @param text переводимая строка
	 * @return     набор байтов строки
	 *
	 */
	vector <uint8_t> bytes(const char * text) noexcept {
		// Выводим набор байтов строки
		return vector <uint8_t> (reinterpret_cast <const uint8_t *> (text), reinterpret_cast <const uint8_t *> (text) + ::strlen(text));
	}
	/**
	 * @brief Вызов сервера: ключ по опознавателю клиента
	 *
	 * @param identity опознаватель, предъявленный клиентом
	 * @param key      накопитель, в который помещается ключ
	 * @param context  указатель связки сервера
	 * @return         признак того, что опознаватель известен и ключ выдан
	 *
	 * @note Вызов не noexcept намеренно: нехватку памяти в накопителе перехватывает связь
	 *
	 */
	bool responding(const view_t & identity, vector <uint8_t> & key, void * context) {
		// Связка сервера
		keyring_t * ring = reinterpret_cast <keyring_t *> (context);
		// Запоминаем увиденный опознаватель
		ring->seen.assign(identity.data, identity.data + identity.size);
		// Если опознаватель основной
		if(ring->seen == ring->identity){
			// Выдаём основной ключ
			key = ring->key;
			// Опознаватель известен
			return true;
		}
		// Если опознаватель запасной
		if(!ring->alternative.empty() && (ring->seen == ring->alternative)){
			// Выдаём запасной ключ
			key = ring->spare;
			// Опознаватель известен
			return true;
		}
		// Опознаватель неизвестен
		return false;
	}
	/**
	 * @brief Вызов клиента: опознаватель и ключ по подсказке сервера
	 *
	 * @param hint     подсказка psk_identity_hint сервера
	 * @param identity накопитель, в который помещается опознаватель
	 * @param key      накопитель, в который помещается ключ
	 * @param context  указатель связки клиента
	 * @return         признак того, что опознаватель и ключ выбраны заново
	 *
	 * @note Вызов не noexcept намеренно: нехватку памяти в накопителе перехватывает связь
	 *
	 */
	bool advising(const view_t & hint, vector <uint8_t> & identity, vector <uint8_t> & key, void * context) {
		// Связка клиента
		keyring_t * ring = reinterpret_cast <keyring_t *> (context);
		// Запоминаем подсказку сервера
		ring->hint.assign(hint.data, hint.data + hint.size);
		// Если подсказка велит взять запасную пару и она есть
		if(!ring->alternative.empty() && (ring->hint == bytes("use-spare"))){
			// Выбираем запасной опознаватель
			identity = ring->alternative;
			// Выбираем запасной ключ
			key = ring->spare;
			// Выбрано заново
			return true;
		}
		// Остаются настроенные опознаватель и ключ
		return false;
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
	 * @brief Функция настройки сторон под заранее разделённый ключ
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param suite    набор шифрования обеих сторон
	 * @param theirs   связка сервера
	 * @param ours     связка клиента
	 * @param hint     подсказка сервера, пустая не шлётся
	 * @param disclose раскрывается ли неизвестный опознаватель извещением
	 * @return         признак успешности настройки
	 *
	 */
	bool presharing(client::context_t & client, server::context_t & server, const protect::suite_t suite, keyring_t & theirs, keyring_t & ours, const char * hint, const bool disclose) noexcept {
		// Набор шифрования клиента
		client.suites(vector <protect::suite_t> {suite});
		// Набор шифрования сервера
		server.suites(vector <protect::suite_t> {suite});
		// Группа обмена клиента: нужна лишь наборам ECDHE_PSK
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Группа обмена сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Настройки заранее разделённого ключа сервера
		context::psk_t mine;
		// Вызов ключа по опознавателю
		mine.respond = responding;
		// Связка сервера
		mine.context = &theirs;
		// Подсказка psk_identity_hint
		mine.identity = bytes(hint);
		// Ручка раскрытия неизвестного опознавателя
		mine.disclose = disclose;
		// Устанавливаем настройки серверу: сертификата ему теперь не нужно
		server.psk(mine);
		// Настройки заранее разделённого ключа клиента
		context::psk_t yours;
		// Опознаватель клиента
		yours.identity = ours.identity;
		// Ключ клиента
		yours.key.assign(ours.key.begin(), ours.key.end());
		// Вызов выбора по подсказке
		yours.advise = advising;
		// Связка клиента
		yours.context = &ours;
		// Устанавливаем настройки клиенту
		client.psk(yours);
		// Клиент ведёт лишь издание 1.2: наборы PSK живут в нём
		return (client.versions(0x0303, 0x0303) == context::error_t::NONE);
	}
	/**
	 * @brief Функция обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос по связи заранее разделённым ключом";
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ по связи заранее разделённым ключом";
		// Если прикладные данные сторон отправить не удалось
		if((client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE) || (server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE))
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
	 * @brief Функция получения названия набора шифрования
	 *
	 * @param suite набор шифрования
	 * @return      название набора шифрования
	 *
	 */
	const char * naming(const protect::suite_t suite) noexcept {
		/**
		 * Выполняем определение набора шифрования
		 */
		switch(static_cast <uint16_t> (suite)){
			// Если набор чистого PSK с AES-128-CBC
			case static_cast <uint16_t> (protect::suite_t::PSK_AES_128_CBC_SHA):
				// Выводим название набора
				return "PSK-AES128-CBC-SHA";
			// Если набор ECDHE_PSK с ChaCha20-Poly1305
			case static_cast <uint16_t> (protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256):
				// Выводим название набора
				return "ECDHE-PSK-CHACHA20-POLY1305";
			// Если набор ECDHE_PSK с AES-128-CBC
			case static_cast <uint16_t> (protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA):
				// Выводим название набора
				return "ECDHE-PSK-AES128-CBC-SHA";
		}
		// Выводим название неизвестного набора
		return "иной";
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
	// Заранее разделённый ключ сторон: не длиннее 64 байтов (раздел 5.3 RFC 4279)
	const vector <uint8_t> secret = bytes("pre-shared key of the anyks client");
	// Запасной ключ, выбираемый по подсказке
	const vector <uint8_t> reserve = bytes("spare pre-shared key of the anyks client");
	// Наборы перебора: чистый PSK без кривой и два набора ECDHE_PSK
	static const protect::suite_t SUITES[] = {protect::suite_t::PSK_AES_128_CBC_SHA, protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA};
	// Выводим заголовок первого прогона
	cout << "== Связь заранее разделённым ключом ==" << endl;
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связка сервера
		keyring_t theirs;
		// Связка клиента
		keyring_t ours;
		// Опознаватель сервера
		theirs.identity = bytes("anyks");
		// Ключ сервера по опознавателю
		theirs.key.assign(secret.begin(), secret.end());
		// Опознаватель клиента
		ours.identity = bytes("anyks");
		// Ключ клиента
		ours.key.assign(secret.begin(), secret.end());
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось
		if(!presharing(client, server, SUITES[s], theirs, ours, "anyks realm", false)){
			// Выводим сообщение об отказе настройки
			cout << "Настроить стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Если связь завести не удалось: сервер без сертификата, но с вызовом respond заводится
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести связь не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие
		converse(client, server);
		// Если рукопожатие не пройдено
		if(!client.established() || !server.established()){
			// Выводим сообщение об отказе рукопожатия
			cout << "Рукопожатие " << naming(SUITES[s]) << " не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим набор и отсутствие сертификатов
		cout << "Набор               : " << naming(client.suite()) << ", сертификатов у клиента " << client.peer().size() << ", издание 0x" << hex << uppercase << client.version() << dec << endl;
		// Выводим опознаватель, увиденный сервером
		cout << "Сервер увидел       : «" << string(theirs.seen.begin(), theirs.seen.end()) << "»" << endl;
		// Выводим подсказку, увиденную клиентом
		cout << "Клиент увидел       : подсказку «" << string(ours.hint.begin(), ours.hint.end()) << "»" << endl;
		// Выводим порядок RFC 7366 у наборов CBC
		cout << "Порядок RFC 7366    : " << (client.etm() ? "encrypt_then_mac" : "не применим, набор AEAD") << endl;
		// Если обмен прикладными данными не удался
		if(!barter(client, server)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
	}
	// Выводим заголовок прогона с выбором по подсказке
	cout << endl << "== Выбор опознавателя по подсказке сервера ==" << endl;
	{
		// Связка сервера
		keyring_t theirs;
		// Связка клиента
		keyring_t ours;
		// Основной опознаватель сервера
		theirs.identity = bytes("anyks");
		// Ключ сервера
		theirs.key.assign(secret.begin(), secret.end());
		// Запасной опознаватель, известный серверу
		theirs.alternative = bytes("anyks-spare");
		// Запасной ключ сервера
		theirs.spare = reserve;
		// Клиент настроен на основной опознаватель
		ours.identity = bytes("anyks");
		// Ключ клиента
		ours.key.assign(secret.begin(), secret.end());
		// Запасной опознаватель клиента
		ours.alternative = bytes("anyks-spare");
		// Запасной ключ клиента
		ours.spare = reserve;
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось: подсказка велит взять запасную пару
		if(!presharing(client, server, protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, theirs, ours, "use-spare", false) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе настройки
			cout << "Настроить стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие
		converse(client, server);
		// Если рукопожатие не пройдено либо сервер увидел не запасной опознаватель
		if(!client.established() || !server.established() || (theirs.seen != ours.alternative)){
			// Выводим сообщение об отказе
			cout << "Выбор по подсказке не сработал: сервер увидел «" << string(theirs.seen.begin(), theirs.seen.end()) << "»" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог выбора по подсказке
		cout << "Подсказка «" << string(ours.hint.begin(), ours.hint.end()) << "»: клиент предъявил «" << string(theirs.seen.begin(), theirs.seen.end()) << "», связь установлена" << endl;
	}
	// Выводим заголовок прогона с неизвестным опознавателем
	cout << endl << "== Неизвестный опознаватель: ручка disclose ==" << endl;
	/**
	 * Выполняем перебор ручки disclose: без раскрытия и с раскрытием
	 */
	for(size_t disclose = 0; disclose < 2; disclose++){
		// Связка сервера
		keyring_t theirs;
		// Связка клиента
		keyring_t ours;
		// Опознаватель сервера
		theirs.identity = bytes("anyks");
		// Ключ сервера
		theirs.key.assign(secret.begin(), secret.end());
		// Клиент с опознавателем, серверу неизвестным
		ours.identity = bytes("stranger");
		// Ключ клиента
		ours.key.assign(secret.begin(), secret.end());
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось
		if(!presharing(client, server, protect::suite_t::PSK_AES_128_CBC_SHA, theirs, ours, "", disclose == 1) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе настройки
			cout << "Настроить стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие до обрыва
		converse(client, server);
		// Если связь установилась: опознаватель неизвестен, этого быть не должно
		if(client.established() || server.established()){
			// Выводим сообщение о расхождении
			cout << "Связь с неизвестным опознавателем установилась" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Если неизвестный опознаватель раскрывается
		if(disclose == 1){
			// Если сервер ответил не отказом IDENTITY с извещением unknown_psk_identity
			if((server.error() != context::error_t::IDENTITY) || (server.alert().description != alert::description_t::PSK) || (client.alert().description != alert::description_t::PSK)){
				// Выводим сообщение о расхождении
				cout << "Раскрытие неизвестного опознавателя не сработало" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог
			cout << "disclose = true     : отказ IDENTITY, извещение unknown_psk_identity (" << static_cast <int> (client.alert().description) << ") дошло клиенту" << endl;
		// Если не раскрывается: случайный ключ и обрыв на завершении
		} else {
			// Если сервер оборвался не на завершении извещением bad_record_mac
			if((server.error() != context::error_t::PROTECTION) || (server.alert().description != alert::description_t::MAC)){
				// Выводим сообщение о расхождении
				cout << "Сокрытие неизвестного опознавателя не сработало: отказ " << static_cast <int> (server.error()) << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог
			cout << "disclose = false    : сервер продолжил случайным ключом и оборвался на завершении, извещение bad_record_mac (" << static_cast <int> (server.alert().description) << ")" << endl;
		}
	}
	// Выводим заголовок прогона с неверным ключом
	cout << endl << "== Неверный ключ ==" << endl;
	{
		// Связка сервера
		keyring_t theirs;
		// Связка клиента
		keyring_t ours;
		// Опознаватель сервера
		theirs.identity = bytes("anyks");
		// Ключ сервера
		theirs.key.assign(secret.begin(), secret.end());
		// Тот же опознаватель у клиента
		ours.identity = bytes("anyks");
		// Иной ключ у клиента
		{ const vector <uint8_t> wrong = bytes("wrong pre-shared key"); ours.key.assign(wrong.begin(), wrong.end()); }
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось
		if(!presharing(client, server, protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, theirs, ours, "", true) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе настройки
			cout << "Настроить стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие до обрыва
		converse(client, server);
		// Если связь установилась либо оборвана не на завершении
		if(client.established() || (server.error() != context::error_t::PROTECTION) || (client.error() != context::error_t::ALERT)){
			// Выводим сообщение о расхождении
			cout << "Неверный ключ не отвергнут: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог: опознаватель известен, потому раскрытие ни при чём - ключи разошлись на завершении
		cout << "Неверный ключ       : опознаватель известен, завершение клиента не расшифровано, извещение " << static_cast <int> (server.alert().description) << " дошло клиенту (отказ ALERT)" << endl;
	}
	// Выводим заголовок прогона пределов настроек
	cout << endl << "== Пределы раздела 5.3 RFC 4279 ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Настройки с опознавателем длиннее 128 байтов
		context::psk_t wide;
		// Опознаватель в 129 байтов
		wide.identity.assign(129, 'a');
		// Ключ
		wide.key.assign(secret.begin(), secret.end());
		// Устанавливаем настройки
		client.psk(wide);
		// Заводим связь: заведение обязано отказать
		const context::error_t outcome = client.start();
		// Если заведение прошло
		if(outcome != context::error_t::SETTINGS){
			// Выводим сообщение о расхождении
			cout << "Опознаватель длиннее 128 байтов принят" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог
		cout << "Опознаватель 129 байт: отказ SETTINGS при заведении связи" << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
