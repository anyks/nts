/**
 * @file dtls.cpp
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
 * @brief Пример связи поверх дейтаграмм - DTLS 1.3 (RFC 9147) и DTLS 1.2 (RFC 6347):
 *        перенос дейтаграммами, размер дейтаграммы, адрес собеседника и секрет метки
 *        возврата состояния, просьба о повторе приветствия с меткой, часы повторной
 *        передачи с потерей дейтаграммы, счётчики молча отброшенного и выбор издания
 *
 * @details Обе стороны ведутся в одном приложении, а перенос дейтаграмм - дело того,
 *          кто связь ведёт: она выдаёт целые дейтаграммы по одной и принимает их
 *          целыми, часов не читает, а срок ожидания отдаёт наружу вызовом timeout и
 *          ждёт извещения elapsed. Здесь путь между сторонами ещё и теряет дейтаграммы
 *          по просьбе образца, чтобы повторная передача была видна
 *
 * @note Издание поверх дейтаграмм выбирается теми же пределами versions, что и на потоке:
 *       0x0304 отвечает DTLS 1.3, 0x0303 - DTLS 1.2; проводные 0xFEFC и 0xFEFD наружу не
 *       показываются. Первый ответ сервера в обоих изданиях - просьба подтвердить адрес:
 *       HelloRetryRequest с меткой у 1.3, HelloVerifyRequest у 1.2, и сервер до неё
 *       состояния не держит
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
#include <datagram/datagram.hpp>
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
	 * @brief Описание пути между сторонами: потери и счётчики дейтаграмм
	 *
	 */
	typedef struct Path {
		// Число ближайших дейтаграмм клиента, которые путь теряет
		size_t losses;
		// Число потерянных дейтаграмм
		size_t dropped;
		// Число доставленных дейтаграмм
		size_t moved;
		// Наибольшая длина перенесённой дейтаграммы
		size_t largest;
		// Число ходов часов повторной передачи
		size_t fired;
		/**
		 * @brief Конструктор
		 *
		 */
		Path() noexcept : losses(0), dropped(0), moved(0), largest(0), fired(0) {}
	} path_t;
	/**
	 * @brief Метод снятия всех готовых дейтаграмм со стороны связи
	 *
	 * @param from   связь стороны, отдающей дейтаграммы
	 * @param result перечень, в который помещаются дейтаграммы
	 *
	 */
	template <typename T>
	void drain(T & from, vector <vector <uint8_t>> & result) noexcept {
		/**
		 * Выполняем снятие дейтаграмм по одной: просмотр отдаёт первую из очереди
		 */
		while(from.output().size > 0){
			// Получаем очередную дейтаграмму
			const view_t data = from.output();
			// Переносим дейтаграмму в перечень
			result.push_back(vector <uint8_t> (data.data, data.data + data.size));
			// Снимаем дейтаграмму с накопителя
			from.consume(data.size);
		}
	}
	/**
	 * @brief Метод переноса дейтаграмм от одной стороны к другой по описанному пути
	 *
	 * @param from   связь стороны, отдающей дейтаграммы
	 * @param to     связь стороны, принимающей дейтаграммы
	 * @param path   описание пути между сторонами
	 * @param losing теряет ли путь дейтаграммы этого направления
	 *
	 * @return       признак того, что хоть одна дейтаграмма снята со стороны
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, path_t & path, const bool losing) noexcept {
		// Снятые дейтаграммы
		vector <vector <uint8_t>> datagrams;
		// Снимаем дейтаграммы со стороны
		drain(from, datagrams);
		// Если переносить нечего
		if(datagrams.empty())
			// Выводим признак того, что дейтаграммы не переносились
			return false;
		/**
		 * Выполняем перебор снятых дейтаграмм
		 */
		for(size_t i = 0; i < datagrams.size(); i++){
			// Запоминаем наибольшую длину дейтаграммы
			path.largest = ((datagrams[i].size() > path.largest) ? datagrams[i].size() : path.largest);
			// Если путь теряет дейтаграмму направления
			if(losing && (path.losses > 0)){
				// Считаем потерянную дейтаграмму
				path.dropped++;
				// Уменьшаем число ближайших потерь
				path.losses--;
				// Переходим к следующей дейтаграмме
				continue;
			}
			// Подаём дейтаграмму принимающей стороне
			to.push(view_t(datagrams[i].data(), datagrams[i].size()));
			// Считаем доставленную дейтаграмму
			path.moved++;
		}
		// Выводим признак того, что дейтаграммы переносились
		return true;
	}
	/**
	 * @brief Метод проведения связи сторон до тишины: перенос дейтаграмм и ход часов
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param path   описание пути между сторонами
	 *
	 * @return       число кругов, ушедших на перенос
	 *
	 */
	size_t converse(client::context_t & client, server::context_t & server, path_t & path) noexcept {
		// Число пройденных кругов
		size_t round = 0;
		/**
		 * Выполняем перенос дейтаграмм, пока сторонам есть что сказать либо чего ждать
		 */
		for(; round < 200; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Переносим дейтаграммы клиента серверу
			bool moved = carry(client, server, path, true);
			// Переносим дейтаграммы сервера клиенту
			moved = (carry(server, client, path, false) || moved);
			// Если дейтаграммы переносились
			if(moved)
				// Переходим к следующему кругу
				continue;
			// Признак того, что часы одной из сторон истекли
			bool fired = false;
			// Если клиент ждёт повторной передачи
			if(client.timeout() > 0){
				// Извещаем клиента об истечении срока: путь молчит, значит, срок вышел
				client.elapsed();
				// Запоминаем ход часов
				fired = true;
			}
			// Если сервер ждёт повторной передачи
			if(server.timeout() > 0){
				// Извещаем сервер об истечении срока
				server.elapsed();
				// Запоминаем ход часов
				fired = true;
			}
			// Если ждать нечего
			if(!fired)
				// Прекращаем перенос
				break;
			// Считаем ход часов
			path.fired++;
		}
		// Выводим число пройденных кругов
		return round;
	}
	/**
	 * @brief Метод настройки сторон под перенос дейтаграммами
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param credential подлинность сервера
	 * @param legacy     ведётся ли связь изданием DTLS 1.2
	 *
	 * @return           признак успешности настройки
	 *
	 */
	bool arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const context::credential_t & credential, const bool legacy) noexcept {
		// Перенос дейтаграммами у клиента
		client.transport(context::transport_t::DATAGRAMS);
		// Перенос дейтаграммами у сервера
		server.transport(context::transport_t::DATAGRAMS);
		// Размер дейтаграммы клиента: сообщения рукопожатия дробятся под него
		client.mtu(datagram::DATAGRAM_MTU);
		// Размер дейтаграммы сервера
		server.mtu(datagram::DATAGRAM_MTU);
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
		// Адрес собеседника: четыре октета адреса и два октета порта, связью не толкуется
		static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
		// Если адрес собеседника серверу установить не удалось
		if(!server.address(view_t(ADDRESS, sizeof(ADDRESS))))
			// Выводим отказ настройки
			return false;
		// Секрет метки возврата состояния: общий у соседних серверов
		const vector <uint8_t> stamp(reinterpret_cast <const uint8_t *> ("stamp secret of the datagram servers"), reinterpret_cast <const uint8_t *> ("stamp secret of the datagram servers") + 36);
		// Устанавливаем секрет метки серверу
		server.stamp(stamp);
		// Пределы издания: 0x0303 у DTLS 1.2, 0x0304 у DTLS 1.3
		const uint16_t edition = (legacy ? 0x0303 : 0x0304);
		// Выводим итог установки пределов издания обеим сторонам
		return ((client.versions(edition, edition) == context::error_t::NONE) && (server.versions(edition, edition) == context::error_t::NONE));
	}
	/**
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param path   описание пути между сторонами
	 *
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool exchange(client::context_t & client, server::context_t & server, path_t & path) noexcept {
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос по дейтаграммам";
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ по дейтаграммам";
		// Если прикладные данные сторон отправить не удалось
		if((client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE) || (server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE))
			// Выводим отказ обмена
			return false;
		// Переносим дейтаграммы
		converse(client, server, path);
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
	 * @brief Метод разбора первой открытой записи дейтаграммы сервера
	 *
	 * @param datagram разбираемая дейтаграмма
	 * @param fragment обвязка куска сообщения, в которую помещается итог разбора
	 *
	 * @return         признак успешности разбора
	 *
	 */
	bool heading(const vector <uint8_t> & datagram, datagram::fragment_t & fragment) noexcept {
		// Если дейтаграмма короче открытого заголовка с обвязкой куска
		if(datagram.size() <= (datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER))
			// Выводим отказ разбора
			return false;
		// Выводим итог разбора обвязки куска за открытым заголовком записи
		return (datagram::parse(view_t(datagram.data() + datagram::DATAGRAM_PLAIN_HEADER, datagram.size() - datagram::DATAGRAM_PLAIN_HEADER), fragment) == datagram::error_t::NONE);
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
	cout << "== DTLS 1.3: просьба о повторе с меткой и рукопожатие ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить и завести стороны не удалось
		if(!arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, credential, false) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Настроить и завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим размер дейтаграммы и срок ожидания
		cout << "Размер дейтаграммы  : " << client.mtu() << " байт, приветствие клиента ждёт ответа " << client.timeout() << " мс" << endl;
		// Путь между сторонами
		path_t path;
		// Переносим приветствие клиента серверу
		carry(client, server, path, false);
		// Дейтаграммы ответа сервера
		vector <vector <uint8_t>> answer;
		// Снимаем ответ сервера
		drain(server, answer);
		// Обвязка куска первого сообщения ответа
		datagram::fragment_t fragment;
		// Разобранное приветствие сервера
		hello::server_t reply;
		// Если ответ сервера не одна дейтаграмма с приветствием сервера
		if((answer.size() != 1) || !heading(answer[0], fragment) || (fragment.type != handshake::type_t::SERVER) || (hello::parse(view_t(answer[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), reply) != hello::error_t::NONE)){
			// Выводим сообщение о расхождении
			cout << "Первый ответ сервера разобрать не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Метка возврата состояния в просьбе о повторе
		const hello::extension_t * cookie = hello::extension(reply.extensions, static_cast <uint16_t> (extension::type_t::COOKIE));
		// Если ответ не просьба о повторе с меткой
		if(!hello::retry(reply) || (cookie == nullptr)){
			// Выводим сообщение о расхождении
			cout << "Первый ответ сервера не просьба о повторе с меткой" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим сведения о просьбе: раздел 5.1 RFC 9147
		cout << "Первый ответ        : HelloRetryRequest с меткой в " << cookie->data.size << " байт, сервер состояния не держит (ждёт " << server.timeout() << " мс)" << endl;
		// Сменяем поколение секрета метки: живы два, и метка прежнего поколения ещё признаётся
		server.restamp();
		// Подаём просьбу клиенту
		client.push(view_t(answer[0].data(), answer[0].size()));
		// Доводим рукопожатие до тишины
		const size_t rounds = converse(client, server, path);
		// Если рукопожатие не пройдено
		if(!client.established() || !server.established()){
			// Выводим сообщение об отказе
			cout << "Рукопожатие DTLS 1.3 не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог рукопожатия
		cout << "Рукопожатие         : пройдено за " << rounds << " круга, издание 0x" << hex << uppercase << client.version() << dec << " (DTLS 1.3), дейтаграмм " << path.moved << ", наибольшая " << path.largest << " байт" << endl;
		// Выводим часы после рукопожатия
		cout << "Часы                : клиент " << client.timeout() << " мс, сервер " << server.timeout() << " мс - залпы подтверждены" << endl;
		// Если обмен прикладными данными не удался
		if(!exchange(client, server, path)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Прикладные данные для повторной подачи
		const string again = "Дейтаграмма, поданная дважды";
		// Если прикладные данные отправить не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (again.data()), again.size())) != context::error_t::NONE){
			// Выводим сообщение об отказе отправки
			cout << "Отправить прикладные данные не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Дейтаграмма прикладных данных
		const view_t data = client.output();
		// Копия дейтаграммы для повторной подачи
		const vector <uint8_t> twice(data.data, data.data + data.size);
		// Снимаем дейтаграмму с накопителя клиента
		client.consume(twice.size());
		// Подаём дейтаграмму серверу дважды: повтор отбрасывается окном молча
		server.push(view_t(twice.data(), twice.size()));
		// Повторная подача
		server.push(view_t(twice.data(), twice.size()));
		// Выводим счётчики отброшенного: раздел 4.5.2 RFC 9147
		cout << "Отброшено сервером  : всего " << server.discarded() << ", повторов " << server.discarded(datagram::reason_t::REPLAY) << ", порчи " << server.discarded(datagram::reason_t::DAMAGE) << endl;
		// Если повтор не отброшен
		if(server.discarded(datagram::reason_t::REPLAY) != 1){
			// Выводим сообщение о расхождении
			cout << "Повтор дейтаграммы не отброшен" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
	}
	// Выводим заголовок прогона с потерей
	cout << endl << "== DTLS 1.3: потеря дейтаграммы и повторная передача ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить и завести стороны не удалось
		if(!arrange(client, server, protect::suite_t::CHACHA20_POLY1305_SHA256, credential, false) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Настроить и завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Путь, теряющий первую дейтаграмму клиента
		path_t path;
		// Первая дейтаграмма клиента теряется
		path.losses = 1;
		// Переносим приветствие: оно теряется, сервер молчит
		carry(client, server, path, true);
		// Выводим итог потери
		cout << "Потеря              : приветствие клиента потеряно, сервер молчит, клиент ждёт " << client.timeout() << " мс" << endl;
		// Извещаем клиента об истечении срока: раздел 5.8.2 RFC 9147
		const context::error_t outcome = client.elapsed();
		// Если повторная передача не прошла
		if((outcome != context::error_t::NONE) || (client.output().size == 0)){
			// Выводим сообщение о расхождении
			cout << "Повторная передача не прошла: отказ " << static_cast <int> (outcome) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог повторной передачи: срок удвоен
		cout << "Срок истёк          : приветствие повторено новым номером записи, следующий срок " << client.timeout() << " мс" << endl;
		// Доводим рукопожатие до тишины
		const size_t rounds = converse(client, server, path);
		// Если рукопожатие не пройдено
		if(!client.established() || !server.established()){
			// Выводим сообщение об отказе
			cout << "Рукопожатие после потери не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог рукопожатия
		cout << "Рукопожатие         : пройдено за " << rounds << " круга, потеряно " << path.dropped << ", доставлено " << path.moved << ", отброшено сервером " << server.discarded() << ", клиентом " << client.discarded() << endl;
		// Путь без потерь
		path_t clean;
		// Если обмен прикладными данными не удался
		if(!exchange(client, server, clean)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Ещё одна потеря: залп с билетом ждёт подтверждения
		path.losses = 0;
		// Если билет выдать не удалось
		if(server.issue() != context::error_t::NONE){
			// Выводим сообщение об отказе выдачи билета
			cout << "Выдать билет не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим часы билета
		cout << "Билет               : сервер ждёт подтверждения " << server.timeout() << " мс" << endl;
		// Доставляем билет и подтверждение
		converse(client, server, clean);
		// Выводим итог доставки билета
		cout << "Билет доставлен     : у клиента " << client.tickets().size() << ", сервер ждёт " << server.timeout() << " мс" << endl;
	}
	// Выводим заголовок прогона DTLS 1.2
	cout << endl << "== DTLS 1.2: просьба подтвердить адрес и рукопожатие ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить и завести стороны не удалось: наборы издания 1.2 и пределы 0x0303
		if(!arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, true) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Настроить и завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Путь между сторонами
		path_t path;
		// Переносим приветствие клиента серверу
		carry(client, server, path, false);
		// Дейтаграммы ответа сервера
		vector <vector <uint8_t>> answer;
		// Снимаем ответ сервера
		drain(server, answer);
		// Обвязка куска первого сообщения ответа
		datagram::fragment_t fragment;
		// Если ответ сервера не просьба подтвердить адрес
		if((answer.size() != 1) || !heading(answer[0], fragment) || (fragment.type != handshake::type_t::VERIFY_REQUEST)){
			// Выводим сообщение о расхождении
			cout << "Первый ответ сервера не HelloVerifyRequest" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим сведения о просьбе: раздел 4.2.1 RFC 6347
		cout << "Первый ответ        : HelloVerifyRequest в " << answer[0].size() << " байт, сервер состояния не держит (ждёт " << server.timeout() << " мс)" << endl;
		// Подаём просьбу клиенту
		client.push(view_t(answer[0].data(), answer[0].size()));
		// Доводим рукопожатие до тишины
		const size_t rounds = converse(client, server, path);
		// Если рукопожатие не пройдено
		if(!client.established() || !server.established() || (client.version() != 0x0303)){
			// Выводим сообщение об отказе
			cout << "Рукопожатие DTLS 1.2 не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог рукопожатия
		cout << "Рукопожатие         : пройдено за " << rounds << " круга, издание 0x" << hex << uppercase << client.version() << dec << " (DTLS 1.2), набор 0x" << hex << uppercase << static_cast <uint16_t> (client.suite()) << dec << ", дейтаграмм " << path.moved << endl;
		// Если обмен прикладными данными не удался
		if(!exchange(client, server, path)){
			// Выводим сообщение об отказе обмена
			cout << "Обмен прикладными данными не удался" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Закрываем связь клиентом
		client.close();
		// Доставляем извещение о закрытии
		converse(client, server, path);
		// Выводим состояние сервера после закрытия
		cout << "Закрытие связи      : " << ((server.state() == context::state_t::CLOSED) ? "сервер извещён клиентом" : "извещение не дошло") << endl;
	}
	// Выводим заголовок прогона расхождения изданий
	cout << endl << "== Расхождение пределов издания ==" << endl;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Если настроить стороны не удалось
		if(!arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, credential, true)){
			// Выводим сообщение об отказе
			cout << "Настроить стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Сервер ведёт лишь DTLS 1.3, набор издания 1.3
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Если пределы сервера установить либо стороны завести не удалось
		if((server.versions(0x0304, 0x0304) != context::error_t::NONE) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Завести стороны не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Путь между сторонами
		path_t path;
		// Доводим до обрыва
		converse(client, server, path);
		// Если сервер не оборвал связь изданием
		if((server.error() != context::error_t::VERSION) || (server.alert().description != alert::description_t::VERSION)){
			// Выводим сообщение о расхождении
			cout << "Расхождение изданий не отвергнуто: отказ " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог
		cout << "Клиент 1.2, сервер 1.3: отказ VERSION, извещение protocol_version (" << static_cast <int> (server.alert().description) << ") дошло клиенту (отказ " << static_cast <int> (client.error()) << ")" << endl;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
