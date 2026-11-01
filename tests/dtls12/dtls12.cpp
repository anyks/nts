/**
 * @file dtls12.cpp
 * @date 2026-09-05
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
 * @brief Исходный файл проверок связи поверх дейтаграмм по DTLS 1.2 (RFC 6347):
 *        петлевое рукопожатие с просьбой о подтверждении адреса HelloVerifyRequest по
 *        шести наборам и трём группам, сервер без состояния, переписка в обвязке DTLS без
 *        просьбы и первого приветствия (сличение завершения с независимым расчётом PRF),
 *        потери, перестановки и повторы дейтаграмм, дробление, окно повторов, порча,
 *        смена набора не в свой черёд, согласование издания, обмен с системным openssl
 *        по UDP и нехватка памяти
 *
 * @note Обмен с настоящим openssl ведётся по сокетам UDP на петлевом устройстве: наш
 *       клиент против s_server -dtls1_2 -listen, наш сервер против s_client -dtls1_2
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <signal.h>
#include <sys/stat.h>
#include <sockets.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <field/field.hpp>
#include <record/record.hpp>
#include <protect/protect.hpp>
#include <datagram/datagram.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>
#include <x509/x509.hpp>
#include <x509/signature.hpp>
#include <agreement/x25519.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору ключей для сличения
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Проводные издания протокола поверх дейтаграмм: DTLS 1.2 и DTLS 1.0 (просьба о подтверждении адреса);
	 * утверждаются лишь по байтам записей и сообщений
	 */
	static constexpr uint16_t DTLS12 = 0xFEFD;
	// Метка DTLS 1.0: с неё сервер просит подтверждение адреса прежде полного рукопожатия
	static constexpr uint16_t DTLS10 = 0xFEFF;
	/**
	 * Издания единой шкалы: пределы versions() и итог version() на любом переносе
	 */
	static constexpr uint16_t TLS12 = 0x0303;
	// Верхний предел единой шкалы: версии выше TLS 1.3 на переносе не бывает
	static constexpr uint16_t TLS13 = 0x0304;
	/**
	 * Длина метки возврата состояния издания DTLS 1.2: поколение и имитовставка (раздел 4.2.1 RFC 6347)
	 */
	static constexpr size_t LABEL = 33;
	/**
	 * Заслон понижения издания протокола: раздел 4.1.3 RFC 8446, хвост случайного значения сервера
	 */
	static const uint8_t DOWNGRADE[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
	/**
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора на чтение
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла набора
		vector <uint8_t> result;
		// Если файл набора открыт
		if(file.is_open())
			// Переносим содержимое файла набора
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла набора
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
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Описание пути между сторонами: потери, перестановки и повторы дейтаграмм
	 *
	 */
	typedef struct Bond {
		// Шаг потерь: всякая кратная дейтаграмма теряется, ноль без потерь
		size_t period;
		// Зерно псевдослучайных потерь половины дейтаграмм, ноль без них
		uint32_t seed;
		// Число дейтаграмм, теряемых с самого начала
		size_t initial;
		// Признак переворота порядка дейтаграмм одного переноса
		bool reverse;
		// Признак повтора всякой дейтаграммы
		bool duplicate;
		// Счётчики перенесённых дейтаграмм по направлениям: от клиента и от сервера
		size_t counters[2];
		// Число потерянных дейтаграмм
		size_t dropped;
		// Число доставленных дейтаграмм
		size_t moved;
		// Наибольшая длина перенесённой дейтаграммы
		size_t largest;
		/**
		 * @brief Конструктор
		 *
		 */
		Bond() noexcept : period(0), seed(0), initial(0), reverse(false), duplicate(false), dropped(0), moved(0), largest(0) {
			// Обнуляем счётчик направления от клиента
			this->counters[0] = 0;
			// Обнуляем счётчик направления от сервера
			this->counters[1] = 0;
		}
	} bond_t;
	/**
	 * @brief Функция снятия всех готовых дейтаграмм стороны
	 *
	 * @param from   связь стороны, отдающей дейтаграммы
	 * @param result перечень, в который помещаются дейтаграммы
	 * @return       признак успешности снятия
	 *
	 */
	template <typename T>
	bool drain(T & from, vector <vector <uint8_t>> & result) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			/**
			 * Выполняем снятие дейтаграмм по одной
			 */
			while(from.output().size > 0){
				// Получаем очередную дейтаграмму
				const view_t data = from.output();
				// Переносим дейтаграмму в перечень
				result.push_back(vector <uint8_t> (data.data, data.data + data.size));
				// Снимаем дейтаграмму с накопителя
				from.consume(data.size);
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ снятия
			return false;
		}
		// Выводим успешность снятия
		return true;
	}
	/**
	 * @brief Функция переноса дейтаграмм от одной стороны к другой по описанному пути
	 *
	 * @param from      связь стороны, отдающей дейтаграммы
	 * @param to        связь стороны, принимающей дейтаграммы
	 * @param bond      описание пути между сторонами
	 * @param direction направление переноса: ноль от клиента, единица от сервера
	 * @return          признак того, что хоть одна дейтаграмма снята со стороны
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, bond_t & bond, const size_t direction) noexcept {
		// Снятые дейтаграммы
		vector <vector <uint8_t>> datagrams;
		// Если дейтаграммы снять не удалось
		if(!drain(from, datagrams))
			// Выводим признак того, что дейтаграммы не переносились
			return false;
		// Если переносить нечего
		if(datagrams.empty())
			// Выводим признак того, что дейтаграммы не переносились
			return false;
		// Если порядок дейтаграмм переворачивается
		if(bond.reverse)
			// Переворачиваем порядок дейтаграмм переноса
			std::reverse(datagrams.begin(), datagrams.end());
		/**
		 * Выполняем перебор снятых дейтаграмм
		 */
		for(size_t i = 0; i < datagrams.size(); i++){
			// Считаем дейтаграмму направления
			bond.counters[direction]++;
			// Запоминаем наибольшую длину дейтаграммы
			bond.largest = ((datagrams[i].size() > bond.largest) ? datagrams[i].size() : bond.largest);
			// Признак псевдослучайной потери: линейный конгруэнтный ряд с постоянным зерном
			bool unlucky = false;
			// Если половина дейтаграмм теряется псевдослучайно
			if(bond.seed != 0){
				// Продвигаем ряд
				bond.seed = (bond.seed * 1103515245u + 12345u);
				// Берём разряд ряда
				unlucky = (((bond.seed >> 16) & 1) != 0);
			}
			// Если дейтаграмма теряется с самого начала, по шагу потерь либо по ряду
			if(((direction == 0) && (bond.counters[0] <= bond.initial)) || ((bond.period > 0) && ((bond.counters[direction] % bond.period) == 0)) || unlucky){
				// Считаем потерянную дейтаграмму
				bond.dropped++;
				// Переходим к следующей дейтаграмме
				continue;
			}
			// Подаём дейтаграмму принимающей стороне
			to.push(view_t(datagrams[i].data(), datagrams[i].size()));
			// Если дейтаграмма повторяется
			if(bond.duplicate)
				// Подаём дейтаграмму принимающей стороне ещё раз
				to.push(view_t(datagrams[i].data(), datagrams[i].size()));
			// Считаем доставленную дейтаграмму
			bond.moved++;
		}
		// Выводим признак того, что дейтаграммы переносились
		return true;
	}
	/**
	 * @brief Функция проведения связи сторон до тишины: перенос дейтаграмм и ход часов
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param bond   описание пути между сторонами
	 * @param rounds предел кругов переноса
	 * @return       число кругов, ушедших на перенос
	 *
	 */
	size_t converse(client::context_t & client, server::context_t & server, bond_t & bond, const size_t rounds) noexcept {
		// Число пройденных кругов
		size_t round = 0;
		/**
		 * Выполняем перенос дейтаграмм, пока сторонам есть что сказать либо чего ждать
		 */
		for(; round < rounds; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Признак того, что дейтаграммы переносились
			bool moved = carry(client, server, bond, 0);
			// Переносим дейтаграммы сервера клиенту
			moved = (carry(server, client, bond, 1) || moved);
			// Если дейтаграммы переносились
			if(moved)
				// Переходим к следующему кругу
				continue;
			// Признак того, что часы одной из сторон истекли
			bool fired = false;
			// Если клиент ждёт повторной передачи
			if(client.timeout() > 0){
				// Извещаем клиента об истечении срока
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
		}
		// Выводим число пройденных кругов
		return round;
	}
	/**
	 * Адрес собеседника для метки возврата состояния
	 */
	static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
	/**
	 * @brief Функция настройки сторон связи под перенос дейтаграммами изданием 1.2
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param group      группа обмена обеих сторон
	 * @param credential подлинность сервера и клиента
	 * @param mutual     запрашивается ли подлинность клиента
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const extension::group_t group, const context::credential_t & credential, const bool mutual) noexcept {
		// Устанавливаем перенос дейтаграммами клиенту
		client.transport(context::transport_t::DATAGRAMS);
		// Устанавливаем перенос дейтаграммами серверу
		server.transport(context::transport_t::DATAGRAMS);
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {suite});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {suite});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {group});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {group});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Устанавливаем адрес собеседника серверу
		server.address(view_t(ADDRESS, sizeof(ADDRESS)));
		// Если запрашивается подлинность клиента
		if(mutual){
			// Требуем подлинность клиента
			server.request(true);
			// Устанавливаем подлинность клиента
			client.credential(credential);
		}
	}
	/**
	 * @brief Функция обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param bond   описание пути между сторонами
	 * @return       признак того, что обе стороны прочли отправленное
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server, bond_t & bond) noexcept {
		// Данные, отправляемые клиентом
		const string request = "ping from the client over DTLS 1.2";
		// Данные, отправляемые сервером
		const string response = "pong from the server over DTLS 1.2";
		// Если данные клиента отправить не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Если данные сервера отправить не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (response.data()), response.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Переносим дейтаграммы
		converse(client, server, bond, 400);
		// Принятые данные
		vector <uint8_t> received;
		// Если данные клиента сервером не прочтены
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отказ обмена
			return false;
		// Если данные сервера клиентом не прочтены
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != response))
			// Выводим отказ обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Функция чтения заголовка записи DTLS 1.2 из дейтаграммы
	 *
	 * @param data     дейтаграмма
	 * @param offset   смещение записи в дейтаграмме
	 * @param type     место, в которое помещается вид содержимого
	 * @param version  место, в которое помещается издание из заголовка
	 * @param epoch    место, в которое помещается пора ключей
	 * @param sequence место, в которое помещается порядковый номер
	 * @param size     место, в которое помещается длина содержимого
	 * @return         признак того, что заголовок прочитан
	 *
	 */
	bool heading(const vector <uint8_t> & data, const size_t offset, uint8_t & type, uint16_t & version, uint16_t & epoch, uint64_t & sequence, size_t & size) noexcept {
		// Если дейтаграмма заголовок не вмещает
		if((offset + datagram::DATAGRAM_PLAIN_HEADER) > data.size())
			// Выводим отказ чтения
			return false;
		// Читаем вид содержимого
		type = data[offset];
		// Читаем издание
		version = static_cast <uint16_t> ((data[offset + 1] << 8) | data[offset + 2]);
		// Читаем пору ключей
		epoch = static_cast <uint16_t> ((data[offset + 3] << 8) | data[offset + 4]);
		// Порядковый номер
		sequence = 0;
		/**
		 * Выполняем чтение шести байтов номера
		 */
		for(size_t i = 0; i < 6; i++)
			// Добавляем очередной байт
			sequence = ((sequence << 8) | data[offset + 5 + i]);
		// Читаем длину содержимого
		size = static_cast <size_t> ((data[offset + 11] << 8) | data[offset + 12]);
		// Выводим признак того, что содержимое вмещается
		return ((offset + datagram::DATAGRAM_PLAIN_HEADER + size) <= data.size());
	}
	/**
	 * @brief Функция составления заголовка записи DTLS 1.2
	 *
	 * @param type     вид содержимого
	 * @param epoch    пора ключей
	 * @param sequence порядковый номер
	 * @param size     длина содержимого
	 * @param result   накопитель, в конец которого дописывается заголовок
	 *
	 */
	void enclose(const record::type_t type, const uint16_t epoch, const uint64_t sequence, const size_t size, vector <uint8_t> & result) noexcept {
		// Записываем вид содержимого
		result.push_back(static_cast <uint8_t> (type));
		// Записываем старший байт издания DTLS 1.2
		result.push_back(static_cast <uint8_t> (DTLS12 >> 8));
		// Записываем младший байт издания DTLS 1.2
		result.push_back(static_cast <uint8_t> (DTLS12 & 0xFF));
		// Записываем старший байт поры
		result.push_back(static_cast <uint8_t> (epoch >> 8));
		// Записываем младший байт поры
		result.push_back(static_cast <uint8_t> (epoch & 0xFF));
		/**
		 * Выполняем запись шести байтов номера от старшего
		 */
		for(size_t i = 0; i < 6; i++)
			// Записываем очередной байт
			result.push_back(static_cast <uint8_t> ((sequence >> ((5 - i) * 8)) & 0xFF));
		// Записываем старший байт длины
		result.push_back(static_cast <uint8_t> ((size >> 8) & 0xFF));
		// Записываем младший байт длины
		result.push_back(static_cast <uint8_t> (size & 0xFF));
	}
	/**
	 * @brief Функция составления сообщения рукопожатия в обвязке DTLS одним куском
	 *
	 * @param type     вид сообщения
	 * @param body     тело сообщения
	 * @param sequence порядковый номер сообщения
	 * @return         сообщение в обвязке DTLS
	 *
	 */
	vector <uint8_t> framed(const handshake::type_t type, const vector <uint8_t> & body, const uint16_t sequence) noexcept {
		// Обвязка куска
		datagram::fragment_t fragment;
		// Устанавливаем вид сообщения
		fragment.type = type;
		// Устанавливаем длину сообщения
		fragment.size = body.size();
		// Устанавливаем порядковый номер сообщения
		fragment.sequence = sequence;
		// Смещение куска нулевое
		fragment.offset = 0;
		// Кусок покрывает сообщение целиком
		fragment.length = body.size();
		// Сообщение в обвязке
		vector <uint8_t> result(datagram::DATAGRAM_FRAGMENT_HEADER, 0);
		// Записываем обвязку
		datagram::build(fragment, result.data());
		// Добавляем тело
		result.insert(result.end(), body.begin(), body.end());
		// Выводим сообщение
		return result;
	}
	/**
	 * @brief Функция составления открытой записи с сообщением рукопожатия
	 *
	 * @param type     вид сообщения
	 * @param body     тело сообщения
	 * @param message  порядковый номер сообщения
	 * @param sequence порядковый номер записи
	 * @return         дейтаграмма с открытой записью
	 *
	 */
	vector <uint8_t> plain(const handshake::type_t type, const vector <uint8_t> & body, const uint16_t message, const uint64_t sequence) noexcept {
		// Сообщение в обвязке DTLS
		const vector <uint8_t> content = framed(type, body, message);
		// Дейтаграмма
		vector <uint8_t> result;
		// Записываем заголовок записи
		enclose(record::type_t::HANDSHAKE, 0, sequence, content.size(), result);
		// Добавляем содержимое
		result.insert(result.end(), content.begin(), content.end());
		// Выводим дейтаграмму
		return result;
	}
	/**
	 * @brief Функция составления дейтаграммы с куском сообщения рукопожатия открытой записью
	 *
	 * @param type     вид сообщения
	 * @param size     длина целого сообщения по обвязке
	 * @param message  порядковый номер сообщения
	 * @param offset   смещение куска
	 * @param data     тело куска
	 * @param length   длина куска
	 * @param sequence порядковый номер записи
	 * @return         дейтаграмма с куском
	 *
	 */
	vector <uint8_t> shard(const handshake::type_t type, const size_t size, const uint16_t message, const size_t offset, const uint8_t * data, const size_t length, const uint64_t sequence) noexcept {
		// Обвязка куска
		datagram::fragment_t fragment;
		// Устанавливаем вид сообщения
		fragment.type = type;
		// Устанавливаем длину целого сообщения
		fragment.size = size;
		// Устанавливаем порядковый номер сообщения
		fragment.sequence = message;
		// Устанавливаем смещение куска
		fragment.offset = offset;
		// Устанавливаем длину куска
		fragment.length = length;
		// Кусок в обвязке
		vector <uint8_t> content(datagram::DATAGRAM_FRAGMENT_HEADER, 0);
		// Записываем обвязку
		datagram::build(fragment, content.data());
		// Добавляем тело куска
		content.insert(content.end(), data, data + length);
		// Дейтаграмма
		vector <uint8_t> result;
		// Записываем заголовок записи
		enclose(record::type_t::HANDSHAKE, 0, sequence, content.size(), result);
		// Добавляем содержимое
		result.insert(result.end(), content.begin(), content.end());
		// Выводим дейтаграмму
		return result;
	}
	/**
	 * @brief Функция дробления дейтаграммы с целым сообщением рукопожатия на две дейтаграммы с кусками
	 *
	 * @param whole  дейтаграмма с целым сообщением одной открытой записью
	 * @param cut    длина первого куска; за пределами сообщения - середина
	 * @param first  дейтаграмма с первым куском записью того же номера
	 * @param second дейтаграмма со вторым куском записью следующего номера
	 * @return       признак того, что дейтаграмма раздроблена
	 *
	 */
	bool bisect(const vector <uint8_t> & whole, const size_t cut, vector <uint8_t> & first, vector <uint8_t> & second) noexcept {
		// Вид содержимого записи
		uint8_t type = 0;
		// Издание записи
		uint16_t version = 0;
		// Пора записи
		uint16_t epoch = 0;
		// Номер записи
		uint64_t sequence = 0;
		// Длина содержимого записи
		size_t size = 0;
		// Читаем заголовок записи
		if(!heading(whole, 0, type, version, epoch, sequence, size))
			// Выводим отрицательный результат - заголовок дейтаграммы не разобран
			return false;
		// Обвязка куска
		datagram::fragment_t fragment;
		// Разбираем обвязку
		if(datagram::parse(view_t(whole.data() + datagram::DATAGRAM_PLAIN_HEADER, size), fragment) != datagram::error_t::NONE)
			// Выводим отрицательный результат - запись дейтаграммы не разобрана
			return false;
		// Сообщение обязано быть целым и не короче двух байтов
		if((fragment.offset != 0) || (fragment.length != fragment.size) || (fragment.size < 2))
			// Выводим отрицательный результат - фрагмент не целый либо меньше двух байтов
			return false;
		// Место разреза: заданное либо середина, когда сообщение короче
		const size_t place = (((cut > 0) && (cut < fragment.size)) ? cut : (fragment.size / 2));
		// Тело сообщения
		const uint8_t * body = (whole.data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER);
		// Первый кусок записью того же номера
		first = shard(fragment.type, fragment.size, fragment.sequence, 0, body, place, sequence);
		// Второй кусок записью следующего номера
		second = shard(fragment.type, fragment.size, fragment.sequence, place, body + place, fragment.size - place, sequence + 1);
		// Выводим успех
		return true;
	}
	/**
	 * @brief Описание набора шифрования издания 1.2
	 *
	 */
	static const struct Suite {
		// Набор шифрования
		protect::suite_t suite;
		// Имя набора у openssl
		const char * title;
		// Имя ключа набора, отвечающего набору
		const char * key;
	} SUITES[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256,       "ECDHE-ECDSA-AES128-GCM-SHA256",  "ec256"},
		{protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384,       "ECDHE-ECDSA-AES256-GCM-SHA384",  "ec384"},
		{protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, "ECDHE-ECDSA-CHACHA20-POLY1305",  "ec256"},
		{protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256,         "ECDHE-RSA-AES128-GCM-SHA256",    "rsa2048"},
		{protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384,         "ECDHE-RSA-AES256-GCM-SHA384",    "rsa2048"},
		{protect::suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256,   "ECDHE-RSA-CHACHA20-POLY1305",    "rsa2048"}
	};
	/**
	 * Группы обмена издания 1.2
	 */
	static const extension::group_t GROUPS[] = {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1};
	/**
	 * @brief Функция проведения сторон до повторного приветствия клиента с меткой
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param bond   описание пути между сторонами
	 * @return       признак того, что повторное приветствие доставлено серверу
	 *
	 */
	bool greet(client::context_t & client, server::context_t & server, bond_t & bond) noexcept {
		// Переносим приветствие, просьбу о подтверждении адреса и повторное приветствие
		return (carry(client, server, bond, 0) && carry(server, client, bond, 1) && carry(client, server, bond, 0));
	}
	/**
	 * @brief Функция составления тела приветствия поддельного клиента издания 1.2
	 *
	 * @param cookie  метка возврата состояния, пустая у первого приветствия
	 * @param version издание заголовка приветствия: 0xFEFD у настоящего клиента
	 * @param result  накопитель, в который помещается тело приветствия
	 * @return        признак успешности составления
	 *
	 */
	bool greeting(const vector <uint8_t> & cookie, const uint16_t version, vector <uint8_t> & result) noexcept {
		// Приветствие клиента
		hello::client_t hello;
		// Издание заголовка приветствия
		hello.version = version;
		/**
		 * Выполняем заполнение случайного значения байтами 0…31
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт
			hello.random[i] = static_cast <uint8_t> (i);
		// Опознаватель связи из 32 байтов
		hello.session.assign(hello::HELLO_SESSION, 0x5A);
		// Метка возврата состояния
		hello.cookie = cookie;
		// Набор шифрования
		hello.suites = {static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256)};
		// Способ сжатия нулевой
		hello.methods = {0x00};
		// Расширения групп и схем
		vector <uint8_t> groups, schemes;
		// Составляем перечень групп
		if(extension::groups(vector <extension::group_t> {extension::group_t::X25519}, groups) != extension::error_t::NONE)
			// Выводим отрицательный результат - группы не составлены
			return false;
		// Составляем перечень схем
		if(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::ECDSA_SECP256R1_SHA256}, schemes) != extension::error_t::NONE)
			// Выводим отрицательный результат - схемы не составлены
			return false;
		// Тело записей точек кривой: одна несжатая
		static const uint8_t FORMATS[] = {0x01, 0x00};
		// Тело безопасного пересогласования: пустой перечень
		static const uint8_t RENEGOTIATION[] = {0x00};
		// Добавляем перечень групп
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		// Добавляем перечень схем
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Добавляем расширенный главный секрет
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Добавляем безопасное пересогласование
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::RENEGOTIATION), view_t(RENEGOTIATION, sizeof(RENEGOTIATION))));
		// Добавляем записи точек кривой
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::FORMATS), view_t(FORMATS, sizeof(FORMATS))));
		// Выводим итог составления тела поверх дейтаграмм
		return (hello::build(hello, result, true) == hello::error_t::NONE);
	}
	/**
	 * @brief Описание сообщения рукопожатия, снятого с дейтаграмм сервера
	 *
	 */
	typedef struct Taken {
		// Вид сообщения
		handshake::type_t type;
		// Порядковый номер сообщения
		uint16_t sequence;
		// Сообщение в обвязке DTLS
		vector <uint8_t> framed;
		// Тело сообщения
		vector <uint8_t> body;
	} taken_t;
	/**
	 * @brief Функция снятия открытых сообщений рукопожатия с дейтаграмм
	 *
	 * @param datagrams дейтаграммы
	 * @param result    перечень, в который помещаются сообщения
	 * @return          признак того, что все записи открытые, а сообщения целые
	 *
	 */
	bool harvest(const vector <vector <uint8_t>> & datagrams, vector <taken_t> & result) noexcept {
		/**
		 * Выполняем перебор дейтаграмм
		 */
		for(size_t i = 0; i < datagrams.size(); i++){
			// Смещение записи
			size_t offset = 0;
			/**
			 * Выполняем перебор записей дейтаграммы
			 */
			while(offset < datagrams[i].size()){
				// Поля заголовка
				uint8_t type = 0;
				// Издание
				uint16_t version = 0;
				// Пора
				uint16_t epoch = 0;
				// Номер
				uint64_t sequence = 0;
				// Длина
				size_t size = 0;
				// Если заголовок не прочитан
				if(!heading(datagrams[i], offset, type, version, epoch, sequence, size))
					// Выводим отрицательный результат - заголовок дейтаграммы не разобран
					return false;
				// Записи ожидаются открытые, рукопожатия и издания DTLS 1.2 либо DTLS 1.0 - им идёт просьба о подтверждении адреса (раздел 4.2.1 RFC 6347, решение 13 переноса)
				if((type != static_cast <uint8_t> (record::type_t::HANDSHAKE)) || (epoch != 0) || ((version != DTLS12) && (version != DTLS10)))
					// Выводим отрицательный результат - запись не рукопожатие, эпоха не нулевая либо издание не то
					return false;
				// Содержимое записи
				const view_t content(datagrams[i].data() + offset + datagram::DATAGRAM_PLAIN_HEADER, size);
				// Смещение куска
				size_t place = 0;
				/**
				 * Выполняем перебор кусков записи
				 */
				while(place < content.size){
					// Обвязка куска
					datagram::fragment_t fragment;
					// Если обвязка не разобрана
					if(datagram::parse(view_t(content.data + place, content.size - place), fragment) != datagram::error_t::NONE)
						// Выводим отрицательный результат - фрагмент не разобран
						return false;
					// Кусок обязан быть целым сообщением
					if((fragment.offset != 0) || (fragment.length != fragment.size))
						// Выводим отрицательный результат - фрагмент не целый
						return false;
					// Снятое сообщение
					taken_t item;
					// Вид сообщения
					item.type = fragment.type;
					// Номер сообщения
					item.sequence = fragment.sequence;
					// Сообщение в обвязке
					item.framed.assign(content.data + place, content.data + place + datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
					// Тело сообщения
					item.body.assign(content.data + place + datagram::DATAGRAM_FRAGMENT_HEADER, content.data + place + datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
					// Добавляем сообщение
					result.push_back(item);
					// Сдвигаем смещение
					place += (datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
				}
				// Сдвигаем смещение записи
				offset += (datagram::DATAGRAM_PLAIN_HEADER + size);
			}
		}
		// Сообщаем об успешном разборе пучка
		return true;
	}
	/**
	 * @brief Функция чтения файла целиком по пути
	 *
	 * @param path путь к файлу
	 * @return     содержимое файла
	 *
	 */
	vector <uint8_t> slurp(const std::string & path) noexcept {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое файла
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Функция разбора области байтов из шестнадцатеричной записи
	 *
	 * @param text шестнадцатеричная запись области байтов
	 * @return     разобранная область байтов
	 *
	 */
	vector <uint8_t> decode(const char * text) noexcept {
		// Разобранная область байтов
		vector <uint8_t> result;
		/**
		 * Выполняем перебор пар символов записи
		 */
		for(size_t i = 0; text[i] != '\0' && text[i + 1] != '\0'; i += 2)
			// Добавляем очередной разобранный байт
			result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
		// Выводим разобранную область байтов
		return result;
	}
	/**
	 * Издания openssl, с которых сняты векторы рукопожатий DTLS 1.2
	 */
	static const char * EDITIONS[] = {"3.0.15", "3.0.20", "3.3.1", "3.4.0", "3.5.0", "3.5.7"};
	/**
	 * Сценарий снятого вектора рукопожатия DTLS 1.2
	 */
	static const struct Scenario {
		// Имя сценария
		const char * name;
		// Набор шифрования
		uint16_t suite;
		// Признак взаимной подлинности
		bool mutual;
		// Признак расширенного главного секрета
		bool master;
	} SCENARIOS[] = {
		{"cookie-ecdsa-aes128", 0xC02B, false, true},
		{"cookie-ecdsa-aes256", 0xC02C, false, true},
		{"cookie-ecdsa-chacha", 0xCCA9, false, true},
		{"cookie-rsa-aes128",   0xC02F, false, true},
		{"cookie-rsa-chacha",   0xCCA8, false, true},
		{"mutual",              0xC02B, true,  true},
		{"plain-ecdsa-aes128",  0xC02B, false, true},
		{"no-ems",              0xC02B, false, false}
	};
	/**
	 * @brief Функция составления пути к каталогу вектора
	 *
	 * @param edition  издание openssl
	 * @param scenario имя сценария
	 * @return         путь к каталогу вектора
	 *
	 */
	std::string place(const char * edition, const char * scenario) noexcept {
		// Выводим путь к каталогу вектора
		return (std::string(CORPUS) + "/dtls12/dtls12-OpenSSL-" + edition + "/" + scenario);
	}
	/**
	 * @brief Функция проверки наличия каталога вектора
	 *
	 * @param path путь к каталогу вектора
	 * @return     признак наличия каталога
	 *
	 */
	bool exists(const std::string & path) noexcept {
		// Сведения о пути
		struct stat info;
		// Выводим признак наличия каталога
		return ((::stat(path.c_str(), &info) == 0) && S_ISDIR(info.st_mode));
	}
	/**
	 * @brief Функция суждения о пропуске отсутствующего вектора
	 *
	 * @param edition  издание openssl
	 * @param scenario сценарий
	 * @return         признак того, что отсутствие вектора ожидаемо: -no_ems появился в 3.3.1
	 *
	 */
	bool omitted(const char * edition, const Scenario & scenario) noexcept {
		// Выводим признак ожидаемого отсутствия
		return ((::strcmp(scenario.name, "no-ems") == 0) && (::strncmp(edition, "3.0.", 4) == 0));
	}
	/**
	 * @brief Функция получения кода набора по имени openssl
	 *
	 * @param title имя набора в записи openssl
	 * @return      код набора либо ноль
	 *
	 */
	uint16_t coded(const std::string & title) noexcept {
		/**
		 * Выполняем перебор наборов
		 */
		for(size_t i = 0; i < (sizeof(SUITES) / sizeof(SUITES[0])); i++){
			// Если имя совпало
			if(title == SUITES[i].title)
				// Выводим код набора
				return static_cast <uint16_t> (SUITES[i].suite);
		}
		// Выводим отсутствие набора
		return 0;
	}
	/**
	 * @brief Сведения о векторе из его описания README.md
	 *
	 */
	typedef struct Brief {
		// Набор шифрования
		uint16_t suite;
		// Признак расширенного главного секрета
		bool master;
		// Признак просьбы о подтверждении адреса в обмене
		bool queried;
		// Имя ключа набора
		std::string key;
		/**
		 * Конструктор
		 */
		Brief() noexcept : suite(0), master(false), queried(false) {}
	} brief_t;
	/**
	 * @brief Функция проверки начала строки
	 *
	 * @param line   проверяемая строка
	 * @param prefix ожидаемое начало
	 * @return       признак того, что строка начинается с ожидаемого
	 *
	 */
	bool starts(const std::string & line, const char * prefix) noexcept {
		// Выводим итог сличения начала
		return (line.compare(0, ::strlen(prefix), prefix) == 0);
	}
	/**
	 * @brief Функция разбора описания вектора README.md
	 *
	 * @param path   путь к каталогу вектора
	 * @param result сведения о векторе
	 * @return       признак успешности разбора
	 *
	 */
	bool describe(const std::string & path, brief_t & result) noexcept {
		// Текст описания
		const vector <uint8_t> text = slurp(path + "/README.md");
		// Если описания нет
		if(text.empty())
			// Выводим отрицательный результат - текст журнала пуст
			return false;
		// Описание строкой
		const std::string readme(text.begin(), text.end());
		// Смещение строки
		size_t offset = 0;
		/**
		 * Выполняем перебор строк описания
		 */
		while(offset < readme.size()){
			// Конец строки
			size_t end = readme.find('\n', offset);
			// Если конца нет
			if(end == std::string::npos)
				// Строка до конца текста
				end = readme.size();
			// Строка
			const std::string line = readme.substr(offset, end - offset);
			// Сдвигаем смещение
			offset = (end + 1);
			// Если строка с набором
			if(starts(line, "Набор: ")){
				// Имя набора до скобки
				const std::string title = line.substr(line.find(": ") + 2);
				// Запоминаем код набора
				result.suite = coded(title.substr(0, title.find(' ')));
			// Если строка с сертификатом
			} else if(starts(line, "Сертификат: ")){
				// Имя файла
				const std::string name = line.substr(line.find(": ") + 2);
				// Запоминаем имя ключа
				result.key = name.substr(0, name.find('.'));
			// Если строка с расширенным главным секретом
			} else if(starts(line, "EMS в обмене: "))
				// Запоминаем признак
				result.master = (line.find("да") != std::string::npos);
			// Если строка с просьбой о подтверждении адреса
			else if(starts(line, "HelloVerifyRequest в обмене: "))
				// Запоминаем признак
				result.queried = (line.find("да") != std::string::npos);
		}
		// Выводим итог разбора
		return ((result.suite != 0) && !result.key.empty());
	}
	/**
	 * @brief Запись, снятая с дейтаграммы провода
	 *
	 */
	typedef struct Wired {
		// Вид содержимого
		uint8_t type;
		// Издание из заголовка
		uint16_t version;
		// Пора ключей
		uint16_t epoch;
		// Порядковый номер
		uint64_t sequence;
		// Содержимое записи
		vector <uint8_t> content;
	} wired_t;
	/**
	 * @brief Функция чтения дейтаграмм стороны из вектора по описи провода
	 *
	 * @param path   путь к каталогу вектора
	 * @param side   сторона: c2s либо s2c
	 * @param result перечень дейтаграмм в порядке провода
	 * @return       признак того, что опись сошлась с файлами
	 *
	 */
	bool manifest(const std::string & path, const char * side, vector <vector <uint8_t>> & result) noexcept {
		// Открываем опись провода
		std::ifstream file(path + "/wire.txt");
		// Поля строки описи
		std::string who;
		// Номер и длина
		size_t number = 0, length = 0;
		/**
		 * Выполняем перебор строк описи
		 */
		while(file >> who >> number >> length){
			// Если строка чужой стороны
			if(who != side)
				// Переходим к следующей
				continue;
			// Имя файла дейтаграммы
			char name[32];
			// Составляем имя файла
			::snprintf(name, sizeof(name), "/%s-%03zu.bin", side, number);
			// Читаем дейтаграмму
			const vector <uint8_t> datagram = slurp(path + name);
			// Если длина не сошлась с описью
			if(datagram.size() != length)
				// Выводим отрицательный результат - длина дейтаграммы не сошлась
				return false;
			// Добавляем дейтаграмму
			result.push_back(datagram);
		}
		// Выводим признак того, что дейтаграммы есть
		return !result.empty();
	}
	/**
	 * @brief Функция разбора дейтаграмм на записи
	 *
	 * @param datagrams дейтаграммы
	 * @param result    перечень записей в порядке провода
	 * @return          признак того, что все записи разобраны
	 *
	 */
	bool unwind(const vector <vector <uint8_t>> & datagrams, vector <wired_t> & result) noexcept {
		/**
		 * Выполняем перебор дейтаграмм
		 */
		for(size_t i = 0; i < datagrams.size(); i++){
			// Смещение записи
			size_t offset = 0;
			/**
			 * Выполняем перебор записей дейтаграммы
			 */
			while(offset < datagrams[i].size()){
				// Запись
				wired_t item;
				// Длина содержимого
				size_t size = 0;
				// Если заголовок не прочитан
				if(!heading(datagrams[i], offset, item.type, item.version, item.epoch, item.sequence, size))
					// Выводим отрицательный результат - заголовок дейтаграммы не разобран
					return false;
				// Переносим содержимое
				item.content.assign(datagrams[i].begin() + offset + datagram::DATAGRAM_PLAIN_HEADER, datagrams[i].begin() + offset + datagram::DATAGRAM_PLAIN_HEADER + size);
				// Кладём разобранную запись в перечень
				result.push_back(item);
				// Сдвигаем смещение
				offset += (datagram::DATAGRAM_PLAIN_HEADER + size);
			}
		}
		// Сообщаем об успешном обходе записей
		return true;
	}
	/**
	 * @brief Функция сборки открытых сообщений рукопожатия нулевой поры из записей
	 *
	 * @param records записи стороны в порядке провода
	 * @param result  перечень сообщений в обвязке DTLS одним куском по возрастанию номеров
	 * @return        признак того, что сообщения собраны целиком
	 *
	 */
	bool gather(const vector <wired_t> & records, vector <taken_t> & result) noexcept {
		/**
		 * Выполняем перебор записей
		 */
		for(size_t i = 0; i < records.size(); i++){
			// Лишь открытые записи рукопожатия
			if((records[i].type != static_cast <uint8_t> (record::type_t::HANDSHAKE)) || (records[i].epoch != 0))
				// Переходим к следующей
				continue;
			// Смещение куска
			size_t place = 0;
			/**
			 * Выполняем перебор кусков записи
			 */
			while(place < records[i].content.size()){
				// Обвязка куска
				datagram::fragment_t fragment;
				// Если обвязка не разобрана
				if(datagram::parse(view_t(records[i].content.data() + place, records[i].content.size() - place), fragment) != datagram::error_t::NONE)
					// Выводим отрицательный результат - фрагмент не разобран
					return false;
				// Место сборки сообщения
				size_t index = result.size();
				/**
				 * Выполняем розыск сборки по номеру
				 */
				for(size_t j = 0; (j < result.size()) && (index == result.size()); j++){
					// Если номер совпал
					if(result[j].sequence == fragment.sequence)
						// Запоминаем место
						index = j;
				}
				// Если сборки нет
				if(index == result.size()){
					// Новая сборка
					taken_t item;
					// Вид сообщения
					item.type = fragment.type;
					// Номер сообщения
					item.sequence = fragment.sequence;
					// Место под тело
					item.body.assign(fragment.size, 0);
					// Добавляем сборку
					result.push_back(item);
				}
				// Если кусок вышел за тело
				if((fragment.offset + fragment.length) > result[index].body.size())
					// Выводим отрицательный результат - фрагмент выходит за пределы тела
					return false;
				// Переносим кусок
				::memcpy(result[index].body.data() + fragment.offset, records[i].content.data() + place + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length);
				// Сдвигаем смещение
				place += (datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
			}
		}
		/**
		 * Выполняем сортировку сборок по номеру и составление обвязки одним куском
		 */
		for(size_t i = 1; i < result.size(); i++){
			/**
			 * Выполняем сдвиг сборки к своему месту
			 */
			for(size_t j = i; (j > 0) && (result[j].sequence < result[j - 1].sequence); j--)
				// Переставляем соседей
				std::swap(result[j], result[j - 1]);
		}
		/**
		 * Выполняем составление сообщений в обвязке DTLS одним куском: раздел 4.2.6 RFC 6347
		 */
		for(size_t i = 0; i < result.size(); i++)
			// Составляем сообщение
			result[i].framed = framed(result[i].type, result[i].body, result[i].sequence);
		// Сообщаем об успешном обрамлении сообщений
		return true;
	}
	/**
	 * @brief Функция розыска сообщения заданного вида в перечне
	 *
	 * @param messages перечень сообщений
	 * @param type     искомый вид
	 * @return         указатель на сообщение либо nullptr
	 *
	 */
	const taken_t * seek(const vector <taken_t> & messages, const handshake::type_t type) noexcept {
		/**
		 * Выполняем перебор сообщений
		 */
		for(size_t i = 0; i < messages.size(); i++){
			// Если вид совпал
			if(messages[i].type == type)
				// Выводим сообщение
				return &messages[i];
		}
		// Выводим отсутствие
		return nullptr;
	}
	/**
	 * @brief Обмен ключами сервера ServerKeyExchange в разобранном виде
	 *
	 */
	typedef struct Exchange {
		// Группа обмена
		extension::group_t group;
		// Схема подписи
		uint16_t scheme;
		// Параметры обмена
		view_t parameters;
		// Подпись
		view_t signature;
		/**
		 * Конструктор
		 */
		Exchange() noexcept : group(extension::group_t::NONE), scheme(0) {}
	} exchange_t;
	/**
	 * @brief Функция разбора тела ServerKeyExchange по разделу 5.4 RFC 8422
	 *
	 * @param data   тело сообщения
	 * @param result разобранный обмен
	 * @return       признак успешности разбора
	 *
	 */
	bool dissect(const view_t & data, exchange_t & result) noexcept {
		// Если тело негодно
		if((data.data == nullptr) || (data.size < 4) || (data.data[0] != 0x03))
			// Выводим отрицательный результат - данные негодны
			return false;
		// Длина точки
		const size_t point = data.data[3];
		// Если тело короче точки и подписи
		if(data.size < (4 + point + 4))
			// Выводим отрицательный результат - места под длину точки нет
			return false;
		// Группа
		result.group = static_cast <extension::group_t> ((static_cast <uint16_t> (data.data[1]) << 8) | data.data[2]);
		// Параметры
		result.parameters = view_t(data.data, 4 + point);
		// Смещение схемы
		const size_t offset = (4 + point);
		// Схема
		result.scheme = ((static_cast <uint16_t> (data.data[offset]) << 8) | data.data[offset + 1]);
		// Длина подписи
		const size_t length = ((static_cast <size_t> (data.data[offset + 2]) << 8) | data.data[offset + 3]);
		// Если длина не сошлась
		if((offset + 4 + length) != data.size)
			// Выводим отрицательный результат - длина не сошлась
			return false;
		// Подпись
		result.signature = view_t(data.data + offset + 4, length);
		// Сообщаем об успешном разборе точки
		return true;
	}
	/**
	 * @brief Функция проверки подписи схемой TLS 1.2 ключом сертификата
	 *
	 * @param key       открытый ключ сертификата
	 * @param scheme    схема подписи из сообщения
	 * @param content   подписанное содержимое
	 * @param signature подпись
	 * @return          признак того, что подпись сошлась
	 *
	 */
	bool attested(const x509::key_t & key, const uint16_t scheme, const view_t & content, const view_t & signature) noexcept {
		// Если схема PKCS #1 v1.5
		if((scheme & 0xFF) == 0x01){
			// Опознаватель алгоритма по хешу
			const char * algorithm = ((scheme == 0x0401) ? "1.2.840.113549.1.1.11" : ((scheme == 0x0501) ? "1.2.840.113549.1.1.12" : ((scheme == 0x0601) ? "1.2.840.113549.1.1.13" : nullptr)));
			// Если схема неведома
			if(algorithm == nullptr)
				// Выводим отрицательный результат - алгоритм не найден
				return false;
			// Выводим итог проверки
			return (x509::verify(content, signature, algorithm, key) == x509::error_t::NONE);
		}
		// Хеш схемы
		const digest::hash_t algorithm = extension::hash(static_cast <extension::scheme_t> (scheme));
		// Если хеша нет
		if(algorithm == digest::hash_t::NONE)
			// Выводим отрицательный результат - алгоритм неведом
			return false;
		// Выводим итог проверки
		return (x509::check(key, algorithm, content, signature) == x509::error_t::NONE);
	}
	/**
	 * @brief Функция извлечения первого сертификата DER из тела сообщения Certificate
	 *
	 * @param data тело сообщения Certificate
	 * @return     первый сертификат цепочки либо пустая область
	 *
	 */
	view_t leaf(const view_t & data) noexcept {
		// Если тело короче длин
		if((data.data == nullptr) || (data.size < 6))
			// Выводим пустую область
			return view_t(nullptr, 0);
		// Длина цепочки
		const size_t chain = ((static_cast <size_t> (data.data[0]) << 16) | (static_cast <size_t> (data.data[1]) << 8) | data.data[2]);
		// Длина первого сертификата
		const size_t length = ((static_cast <size_t> (data.data[3]) << 16) | (static_cast <size_t> (data.data[4]) << 8) | data.data[5]);
		// Если длины не сошлись
		if(((chain + 3) != data.size) || ((length + 3) > chain))
			// Выводим пустую область
			return view_t(nullptr, 0);
		// Выводим сертификат
		return view_t(data.data + 6, length);
	}
	/**
	 * @brief Функция разбора ключевого файла CLIENT_RANDOM
	 *
	 * @param path   путь к каталогу вектора
	 * @param random случайное значение клиента (32 байта)
	 * @param master главный секрет (48 байтов)
	 * @return       признак успешности разбора
	 *
	 */
	bool keylog(const std::string & path, vector <uint8_t> & random, vector <uint8_t> & master) noexcept {
		// Открываем ключевой файл
		std::ifstream file(path + "/keylog.txt");
		// Поля строки
		std::string label, hexRandom, hexMaster;
		/**
		 * Выполняем перебор слов ключевого файла до метки CLIENT_RANDOM
		 */
		while(file >> label){
			// Если метка найдена
			if(label == "CLIENT_RANDOM"){
				// Читаем значения
				file >> hexRandom >> hexMaster;
				// Разбираем случайное значение
				random = decode(hexRandom.c_str());
				// Разбираем главный секрет
				master = decode(hexMaster.c_str());
				// Выводим итог
				return ((random.size() == 32) && (master.size() == 48));
			}
		}
		// Выводим отрицательный результат - метка случайного значения клиента не найдена
		return false;
	}
	/**
	 * @brief Функция вычисления verify_data завершения по разделу 7.4.9 RFC 5246
	 *
	 * @param suite      набор шифрования
	 * @param master     главный секрет
	 * @param label      метка стороны: client finished либо server finished
	 * @param transcript сообщения переписки в обвязке DTLS по порядку
	 * @param result     вычисленный verify_data (12 байтов)
	 * @return           признак успешности вычисления
	 *
	 */
	bool completion(const protect::suite_t suite, const vector <uint8_t> & master, const char * label, const vector <vector <uint8_t>> & transcript, uint8_t * result) noexcept {
		// Хеш набора
		const digest::hash_t algorithm = protect::hash(suite);
		// Объект хеширования
		digest::hasher_t hasher(algorithm);
		/**
		 * Выполняем перебор сообщений переписки
		 */
		for(size_t i = 0; i < transcript.size(); i++)
			// Добавляем сообщение
			hasher.update(view_t(transcript[i].data(), transcript[i].size()));
		// Хеш переписки
		uint8_t digest[64];
		// Если хеш не получен
		if(!hasher.finish(digest, digest::length(algorithm)))
			// Выводим отрицательный результат - хеш не снят
			return false;
		// Выводим итог порождающей функции
		return digest::prf(algorithm, view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(digest, digest::length(algorithm)), result, 12);
	}
	/**
	 * @brief Функция выведения ключевого материала стороны по разделу 6.3 RFC 5246
	 *
	 * @param suite      набор шифрования
	 * @param master     главный секрет
	 * @param client     случайное значение клиента
	 * @param server     случайное значение сервера
	 * @param protection защита, заводимая ключом стороны
	 * @param own        признак ключа клиента (иначе - ключа сервера)
	 * @return           признак успешности заведения защиты
	 *
	 */
	bool keyed(const protect::suite_t suite, const vector <uint8_t> & master, const vector <uint8_t> & client, const vector <uint8_t> & server, protect::protection_t & protection, const bool own) noexcept {
		// Длина ключа
		const size_t width = protect::key(suite);
		// Длина вектора замены
		const size_t size = protect::block(suite);
		// Если набор неведом
		if((width == 0) || (size == 0))
			// Выводим отрицательный результат - ширина либо размер нулевые
			return false;
		// Затравка: случайные значения сервера и клиента
		uint8_t seed[64];
		// Случайное значение сервера
		::memcpy(seed, server.data(), 32);
		// Случайное значение клиента
		::memcpy(seed + 32, client.data(), 32);
		// Метка
		const char * label = "key expansion";
		// Ключевой материал
		uint8_t material[(protect::PROTECT_KEY + protect::PROTECT_VECTOR) * 2];
		// Если материал не выведен
		if(!digest::prf(protect::hash(suite), view_t(master.data(), master.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(seed, sizeof(seed)), material, (width + size) * 2))
			// Выводим отрицательный результат - расписание не выработано
			return false;
		// Ключ стороны
		const view_t key(material + (own ? 0 : width), width);
		// Вектор стороны
		const view_t vector(material + (width * 2) + (own ? 0 : size), size);
		// Выводим итог заведения защиты
		return protection.start(suite, key, vector);
	}
	/**
	 * @brief Функция сличения снятого куска сообщения из вектора с собранным сообщением
	 *
	 * @param name  путь к файлу куска: нарезанные сообщения взяты из открытых записей как есть
	 * @param whole собранное сообщение
	 * @return      признак того, что кусок принадлежит сообщению: вид, длина, номер и тело на своём месте
	 *
	 */
	bool excerpt(const std::string & name, const taken_t & whole) noexcept {
		// Кусок из вектора
		const vector <uint8_t> piece = slurp(name);
		// Обвязка куска
		datagram::fragment_t fragment;
		// Если обвязка не разобрана
		if(datagram::parse(view_t(piece.data(), piece.size()), fragment) != datagram::error_t::NONE)
			// Выводим отрицательный результат - фрагмент не разобран
			return false;
		// Если вид, длина либо номер не сошлись
		if((fragment.type != whole.type) || (fragment.size != whole.body.size()) || (fragment.sequence != whole.sequence))
			// Выводим отрицательный результат - фрагмент не сошёлся с целым
			return false;
		// Если кусок вышел за тело либо файл короче куска
		if(((fragment.offset + fragment.length) > whole.body.size()) || (piece.size() != (datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length)))
			// Выводим отрицательный результат - фрагмент выходит за тело либо длина не та
			return false;
		// Выводим итог сличения тела куска на своём месте
		return (::memcmp(whole.body.data() + fragment.offset, piece.data() + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length) == 0);
	}
	/**
	 * @brief Функция сборки завершения из защищённых записей первой поры
	 *
	 * @param records    записи стороны
	 * @param protection защита чтения стороны, заведённая её ключом
	 * @param result     собранное завершение в обвязке DTLS одним куском
	 * @return           признак того, что завершение собрано целиком
	 *
	 * @details Раздел 4.1.2.1 RFC 6347: всякая запись вскрывается своим номером с порой в
	 *          связанных данных; куски завершения складываются по смещениям
	 *
	 */
	bool unsealed(const vector <wired_t> & records, protect::protection_t & protection, taken_t & result) noexcept {
		// Признак того, что сборка начата
		bool started = false;
		// Покрытая длина
		size_t covered = 0;
		/**
		 * Выполняем перебор записей
		 */
		for(size_t i = 0; i < records.size(); i++){
			// Лишь записи рукопожатия первой поры
			if((records[i].type != static_cast <uint8_t> (record::type_t::HANDSHAKE)) || (records[i].epoch != 1))
				// Переходим к следующей
				continue;
			// Открытое содержимое
			vector <uint8_t> plain;
			// Номер записи: пора и порядковый номер
			const uint64_t number = ((static_cast <uint64_t> (records[i].epoch) << 48) | records[i].sequence);
			// Если защиту снять не удалось
			if(protection.unwrap(number, static_cast <record::version_t> (records[i].version), record::type_t::HANDSHAKE, view_t(records[i].content.data(), records[i].content.size()), plain) != protect::error_t::NONE)
				// Выводим отрицательный результат - защита записи не снята
				return false;
			// Смещение куска
			size_t place = 0;
			/**
			 * Выполняем перебор кусков записи
			 */
			while(place < plain.size()){
				// Обвязка куска
				datagram::fragment_t fragment;
				// Если обвязка не разобрана
				if(datagram::parse(view_t(plain.data() + place, plain.size() - place), fragment) != datagram::error_t::NONE)
					// Выводим отрицательный результат - фрагмент не разобран
					return false;
				// Если сборка не начата
				if(!started){
					// Вид
					result.type = fragment.type;
					// Номер
					result.sequence = fragment.sequence;
					// Тело
					result.body.assign(fragment.size, 0);
					// Сборка начата
					started = true;
				}
				// Если кусок чужой либо вышел за тело
				if((fragment.type != result.type) || (fragment.sequence != result.sequence) || (fragment.size != result.body.size()) || ((fragment.offset + fragment.length) > result.body.size()))
					// Выводим отрицательный результат - фрагмент не сошёлся с целым
					return false;
				// Переносим кусок
				::memcpy(result.body.data() + fragment.offset, plain.data() + place + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length);
				// Считаем покрытие
				covered += fragment.length;
				// Сдвигаем смещение
				place += (datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
			}
		}
		// Если сборка не начата либо покрыта не целиком
		if(!started || (covered != result.body.size()))
			// Выводим отрицательный результат - собрано не всё тело
			return false;
		// Составляем сообщение одним куском
		result.framed = framed(result.type, result.body, result.sequence);
		// Сообщаем об успешном собирании тела
		return true;
	}
	/**
	 * @brief Функция розыска защищённой записи рукопожатия первой поры
	 *
	 * @param records записи стороны
	 * @return        первая запись рукопожатия первой поры либо nullptr
	 *
	 */
	const wired_t * sealed(const vector <wired_t> & records) noexcept {
		/**
		 * Выполняем перебор записей
		 */
		for(size_t i = 0; i < records.size(); i++){
			// Если запись рукопожатия первой поры
			if((records[i].type == static_cast <uint8_t> (record::type_t::HANDSHAKE)) && (records[i].epoch == 1))
				// Выводим запись
				return &records[i];
		}
		// Выводим отсутствие
		return nullptr;
	}
};

/**
 * Проверка договора DTLS 1.2 по контрольному списку приёмки: умолчание пределов 1.2…1.3
 * поверх дейтаграмм, коды провода 0xFEFD в versions() отвергаются SETTINGS без порчи пределов,
 * пределы «только 1.2» у обеих сторон и издание 0xFEFD, клиент «только
 * 1.2» против сервера «только 1.3» - protocol_version без связи, просьба о подтверждении
 * адреса с изданием ровно 0xFEFF и меткой до 255 байтов, повторное приветствие длиннее
 * первого с теми же случайным значением и опознавателем, сто первых приветствий без единой
 * связи и без состояния, негодная метка растит discarded(COOKIE) без связи, метка прежнего
 * поколения после restamp() принимается, метка чужого адреса отвергается, пора 0 → 1 отдельной
 * записью смены набора с возрастающими номерами записей нулевой поры, билетов в 1.2 нет
 */
TEST(Dtls12Test, Contract){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Умолчание пределов поверх дейтаграмм
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Нижний предел клиента 1.2
		ASSERT_EQ(client.lowest(), static_cast <uint16_t> (0x0303));
		// Верхний предел клиента 1.3
		ASSERT_EQ(client.highest(), static_cast <uint16_t> (0x0304));
		// Нижний предел сервера 1.2
		ASSERT_EQ(server.lowest(), static_cast <uint16_t> (0x0303));
		// Верхний предел сервера 1.3
		ASSERT_EQ(server.highest(), static_cast <uint16_t> (0x0304));
		// Коды провода DTLS на входе не принимаются: издание закрепляется кодами TLS (договор versions())
		ASSERT_EQ(server.versions(0xFEFD, 0xFEFD), context::error_t::SETTINGS);
		// У клиента так же
		ASSERT_EQ(client.versions(0xFEFD, 0xFEFD), context::error_t::SETTINGS);
		// Пределы после отказа не тронуты
		ASSERT_EQ(server.lowest(), static_cast <uint16_t> (0x0303));
		ASSERT_EQ(server.highest(), static_cast <uint16_t> (0x0304));
	}
	// Пределы «только 1.2» у обеих сторон
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Первое приветствие
		vector <vector <uint8_t>> first;
		// Снимаем первое приветствие
		ASSERT_TRUE(drain(client, first));
		// Подаём серверу
		ASSERT_EQ(server.push(view_t(first[0].data(), first[0].size())), context::error_t::NONE);
		// Просьба о подтверждении адреса
		vector <vector <uint8_t>> query;
		// Снимаем просьбу
		ASSERT_TRUE(drain(server, query));
		// Одна дейтаграмма
		ASSERT_EQ(query.size(), static_cast <size_t> (1));
		// Поля заголовка
		uint8_t type = 0;
		// Издание
		uint16_t version = 0;
		// Пора
		uint16_t epoch = 0;
		// Номер
		uint64_t sequence = 0;
		// Длина
		size_t size = 0;
		// Читаем заголовок
		ASSERT_TRUE(heading(query[0], 0, type, version, epoch, sequence, size));
		// Раздел 4.2.1 RFC 6347: заголовок записи с просьбой несёт издание DTLS 1.0, как тело и как у openssl (решение 13 переноса)
		ASSERT_EQ(version, static_cast <uint16_t> (0xFEFF));
		// Просьба идёт нулевой порой
		ASSERT_EQ(epoch, static_cast <uint16_t> (0));
		// Обвязка куска
		datagram::fragment_t fragment;
		// Разбираем обвязку
		ASSERT_EQ(datagram::parse(view_t(query[0].data() + datagram::DATAGRAM_PLAIN_HEADER, size), fragment), datagram::error_t::NONE);
		// Просьба о подтверждении адреса
		ASSERT_EQ(fragment.type, handshake::type_t::VERIFY_REQUEST);
		// Тело просьбы
		const uint8_t * body = (query[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER);
		// Издание ровно 0xFEFF
		ASSERT_EQ(static_cast <uint16_t> ((body[0] << 8) | body[1]), static_cast <uint16_t> (0xFEFF));
		// Метка до 255 байтов
		ASSERT_LE(body[2], 255);
		// Длина метки сходится с телом
		ASSERT_EQ(fragment.length, static_cast <size_t> (3 + body[2]));
		// Подаём просьбу клиенту
		ASSERT_EQ(client.push(view_t(query[0].data(), query[0].size())), context::error_t::NONE);
		// Повторное приветствие
		vector <vector <uint8_t>> second;
		// Снимаем повторное приветствие
		ASSERT_TRUE(drain(client, second));
		// Повторное приветствие длиннее первого
		ASSERT_GT(second[0].size(), first[0].size());
		// Первое приветствие
		hello::client_t one;
		// Разбираем обвязку первого
		ASSERT_EQ(datagram::parse(view_t(first[0].data() + datagram::DATAGRAM_PLAIN_HEADER, first[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
		// Разбираем первое приветствие
		ASSERT_EQ(hello::parse(view_t(first[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), one, true), hello::error_t::NONE);
		// Повторное приветствие
		hello::client_t two;
		// Разбираем обвязку повторного
		ASSERT_EQ(datagram::parse(view_t(second[0].data() + datagram::DATAGRAM_PLAIN_HEADER, second[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
		// Разбираем повторное приветствие
		ASSERT_EQ(hello::parse(view_t(second[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), two, true), hello::error_t::NONE);
		// Случайное значение то же
		ASSERT_EQ(::memcmp(one.random, two.random, hello::HELLO_RANDOM), 0);
		// Опознаватель тот же
		ASSERT_EQ(one.session, two.session);
		// Метка повторена
		ASSERT_EQ(two.cookie, vector <uint8_t> (body + 3, body + 3 + body[2]));
		// Подаём повторное приветствие серверу
		ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
		// Доводим до тишины, снимая дейтаграммы залпа клиента ради сверки пор
		ASSERT_TRUE(carry(server, client, bond, 1));
		// Залп клиента
		vector <vector <uint8_t>> flight;
		// Снимаем залп
		ASSERT_TRUE(drain(client, flight));
		// Записи залпа
		vector <wired_t> records;
		// Разбираем записи
		ASSERT_TRUE(unwind(flight, records));
		// Признак того, что смена набора встретилась
		bool changed = false;
		// Наибольший номер записи нулевой поры
		uint64_t last = 0;
		/**
		 * Выполняем перебор записей залпа
		 */
		for(size_t i = 0; i < records.size(); i++){
			// Если запись нулевой поры
			if(records[i].epoch == 0){
				// До смены набора
				ASSERT_FALSE(changed) << i;
				// Номера растут
				ASSERT_TRUE((i == 0) || (records[i].sequence > last)) << i;
				// Запоминаем номер
				last = records[i].sequence;
				// Если смена набора
				if(records[i].type == static_cast <uint8_t> (record::type_t::CHANGE)){
					// Запоминаем
					changed = true;
					// Единственный байт
					ASSERT_EQ(records[i].content, vector <uint8_t> {0x01});
				}
			// Если запись первой поры
			} else {
				// Лишь после смены набора
				ASSERT_TRUE(changed) << i;
				// Первая пора
				ASSERT_EQ(records[i].epoch, 1);
			}
		}
		// Смена набора была
		ASSERT_TRUE(changed);
		/**
		 * Выполняем подачу залпа серверу
		 */
		for(size_t i = 0; i < flight.size(); i++)
			// Подаём дейтаграмму
			ASSERT_EQ(server.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established());
		// Издание 1.2 у клиента: единая шкала, 0x0303 на любом переносе, проводное 0xFEFD наружу не показывается
		ASSERT_EQ(client.version(), TLS12);
		// Издание 1.2 у сервера
		ASSERT_EQ(server.version(), TLS12);
		// Билет за рукопожатием изданию 1.2 не выдаётся: билет RFC 5077 идёт внутри рукопожатия
		ASSERT_EQ(server.issue(), context::error_t::STATE);
		// Билет сеанса RFC 5077 принят клиентом внутри рукопожатия
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Билет выдан сервером тем же набором
		ASSERT_EQ(client.tickets()[0].suite, server.suite());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
	// Клиент «только 1.2» против сервера «только 1.3»: связь не складывается
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий серверу
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Сервер лишь 1.3
		ASSERT_EQ(server.versions(0x0304, 0x0304), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь не установлена
		ASSERT_FALSE(client.established() || server.established());
		// Сервер оборван изданием
		ASSERT_EQ(server.error(), context::error_t::VERSION);
		// Извещение protocol_version
		ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
		// Клиент оборван извещением
		ASSERT_EQ(client.error(), context::error_t::ALERT);
		// Извещение protocol_version у клиента
		ASSERT_EQ(client.alert().description, alert::description_t::VERSION);
	}
	// Сто первых приветствий: ни одной связи и ни следа состояния
	{
		// Связь стороны сервера
		server::context_t server;
		// Заглушка клиента
		client::context_t dummy;
		// Настраиваем сервер
		arrange(dummy, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		/**
		 * Выполняем подачу сотни первых приветствий
		 */
		for(size_t i = 0; i < 100; i++){
			// Чужой клиент
			client::context_t stranger;
			// Заглушка сервера
			server::context_t twin;
			// Настраиваем чужого клиента
			arrange(stranger, twin, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
			// Заводим чужого клиента
			ASSERT_EQ(stranger.start(), context::error_t::NONE);
			// Приветствие
			vector <vector <uint8_t>> first;
			// Снимаем
			ASSERT_TRUE(drain(stranger, first));
			// Подаём серверу
			ASSERT_EQ(server.push(view_t(first[0].data(), first[0].size())), context::error_t::NONE);
			// Ответ
			vector <vector <uint8_t>> answer;
			// Снимаем ответ
			ASSERT_TRUE(drain(server, answer));
			// Ровно просьба
			ASSERT_EQ(answer.size(), static_cast <size_t> (1)) << i;
			// Связи нет
			ASSERT_FALSE(server.established()) << i;
			// Состояния нет: издание не согласовано, часов нет
			ASSERT_EQ(server.version(), 0) << i;
			// Часов нет
			ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0)) << i;
		}
	}
	// Негодная метка, метка прежнего поколения и метка чужого адреса
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие и просьба
		ASSERT_TRUE(carry(client, server, bond, 0) && carry(server, client, bond, 1));
		// Повторное приветствие с меткой
		vector <vector <uint8_t>> second;
		// Снимаем
		ASSERT_TRUE(drain(client, second));
		// Смещение метки в приветствии
		const size_t place = (datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER + 2 + hello::HELLO_RANDOM + 1 + hello::HELLO_SESSION);
		// Негодная метка
		vector <uint8_t> forged = second[0];
		// Портим середину метки
		forged[place + 1 + (forged[place] / 2)] ^= 0x5A;
		// Подаём подделку
		ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
		// Отброс растёт
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
		// Связи нет
		ASSERT_FALSE(server.established());
		// Сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Метка чужого адреса: адрес меняется
		const uint8_t other[] = {10, 0, 0, 9, 0x12, 0x34};
		// Устанавливаем чужой адрес
		ASSERT_TRUE(server.address(view_t(other, sizeof(other))));
		// Подаём настоящее приветствие
		ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
		// Отброс растёт
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (2));
		// Связи нет
		ASSERT_FALSE(server.established());
		// Возвращаем адрес
		ASSERT_TRUE(server.address(view_t(ADDRESS, sizeof(ADDRESS))));
		// Смена поколения секрета: метка прежнего поколения остаётся годной
		server.restamp();
		// Подаём настоящее приветствие с меткой прежнего поколения
		ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
		// Отбросов не прибавилось
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (2));
		// Сервер ответил залпом
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена у обеих сторон
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
}

/**
 * Проверка векторов DTLS 1.2, снятых с шести изданий openssl, на стороне сервера: наш сервер
 * на записанное первое приветствие каждого издания и сценария отвечает просьбой о
 * подтверждении адреса с изданием 0xFEFF, записанное повторное приветствие с ЧУЖОЙ меткой
 * законно отбрасывает без состояния, а на повторное приветствие со своей меткой выбирает тот
 * же набор и ту же группу, что s_server, и отвечает handshake_failure без расширенного
 * главного секрета
 */
TEST(Dtls12Test, VectorServer){
	// Число проверенных векторов
	size_t verified = 0;
	/**
	 * Выполняем перебор изданий openssl
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS) / sizeof(SCENARIOS[0])); s++){
			// Путь к вектору
			const std::string path = place(EDITIONS[e], SCENARIOS[s].name);
			// Если вектора нет
			if(!exists(path)){
				// Отсутствие обязано быть ожидаемым
				ASSERT_TRUE(omitted(EDITIONS[e], SCENARIOS[s])) << "вектор не снят: " << path;
				// Сообщаем вслух
				std::cout << "OpenSSL " << EDITIONS[e] << " без -no_ems: вектор " << SCENARIOS[s].name << " не снят, пропуск" << std::endl;
				// Переходим к следующему
				continue;
			}
			// Сведения о векторе
			brief_t brief;
			// Разбираем описание
			ASSERT_TRUE(describe(path, brief)) << path;
			// Набор по сценарию
			ASSERT_EQ(brief.suite, SCENARIOS[s].suite) << path;
			// Расширенный главный секрет по сценарию
			ASSERT_EQ(brief.master, SCENARIOS[s].master) << path;
			// Просьба о подтверждении адреса есть всегда, и без -listen тоже
			ASSERT_TRUE(brief.queried) << path;
			// Дейтаграммы клиента
			vector <vector <uint8_t>> c2s;
			// Читаем дейтаграммы клиента
			ASSERT_TRUE(manifest(path, "c2s", c2s)) << path;
			// Дейтаграммы сервера
			vector <vector <uint8_t>> s2c;
			// Читаем дейтаграммы сервера
			ASSERT_TRUE(manifest(path, "s2c", s2c)) << path;
			// Записи сервера
			vector <wired_t> theirs;
			// Разбираем записи сервера
			ASSERT_TRUE(unwind(s2c, theirs)) << path;
			// Сообщения сервера
			vector <taken_t> answers;
			// Собираем сообщения сервера
			ASSERT_TRUE(gather(theirs, answers)) << path;
			// Приветствие сервера openssl
			const taken_t * greeted = seek(answers, handshake::type_t::SERVER);
			// Проверяем наличие
			ASSERT_NE(greeted, nullptr) << path;
			// Приветствие сервера в записи
			ASSERT_TRUE(excerpt(path + "/serverhello.bin", *greeted)) << path;
			// Разобранное приветствие сервера openssl
			hello::server_t chosen;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(greeted->body.data(), greeted->body.size()), chosen), hello::error_t::NONE) << path;
			// Набор openssl по сценарию
			ASSERT_EQ(chosen.suite, SCENARIOS[s].suite) << path;
			// Обмен ключами сервера openssl
			const taken_t * agreed = seek(answers, handshake::type_t::AGREEMENT);
			// Проверяем наличие
			ASSERT_NE(agreed, nullptr) << path;
			// Разобранный обмен
			exchange_t exchanged;
			// Разбираем обмен
			ASSERT_TRUE(dissect(view_t(agreed->body.data(), agreed->body.size()), exchanged)) << path;
			// Записи клиента
			vector <wired_t> ours;
			// Разбираем записи клиента
			ASSERT_TRUE(unwind(c2s, ours)) << path;
			// Первая запись клиента: рукопожатие нулевой поры номером ноль
			ASSERT_EQ(ours[0].type, static_cast <uint8_t> (record::type_t::HANDSHAKE)) << path;
			// Нулевая пора
			ASSERT_EQ(ours[0].epoch, 0) << path;
			// Первое приветствие клиента
			datagram::fragment_t fragment;
			// Разбираем обвязку
			ASSERT_EQ(datagram::parse(view_t(ours[0].content.data(), ours[0].content.size()), fragment), datagram::error_t::NONE) << path;
			// Приветствие клиента
			ASSERT_EQ(fragment.type, handshake::type_t::CLIENT) << path;
			// Номер ноль
			ASSERT_EQ(fragment.sequence, 0) << path;
			// Разобранное первое приветствие
			hello::client_t greeting;
			// Разбираем приветствие поверх дейтаграмм
			ASSERT_EQ(hello::parse(view_t(ours[0].content.data() + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE) << path;
			// Первое приветствие без метки
			ASSERT_TRUE(greeting.cookie.empty()) << path;
			// Подлинность стороны
			context::credential_t credential;
			// Составляем подлинность
			ASSERT_TRUE(identity(brief.key.c_str(), credential)) << path;
			/**
			 * Выполняем перебор пределов изданий: только 1.2 и 1.2…1.3
			 */
			for(size_t v = 0; v < 2; v++){
				// Связь стороны сервера
				server::context_t server;
				// Перенос дейтаграммами
				server.transport(context::transport_t::DATAGRAMS);
				// Пределы издания
				ASSERT_EQ(server.versions(0x0303, ((v == 0) ? 0x0303 : 0x0304)), context::error_t::NONE);
				// Подлинность
				server.credential(credential);
				// Группы
				server.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1});
				// Набор сценария
				server.suites(vector <protect::suite_t> {static_cast <protect::suite_t> (SCENARIOS[s].suite)});
				// Адрес собеседника
				ASSERT_TRUE(server.address(view_t(ADDRESS, sizeof(ADDRESS))));
				// Взаимная подлинность
				if(SCENARIOS[s].mutual)
					// Запрашиваем подлинность клиента
					server.request(true);
				// Заводим сервер
				// Сценарий без расширенного главного секрета гоняется строгим сервером: умолчанием (решение 16) он принят бы был, отказ пинуется обязательностью
				if(!SCENARIOS[s].master)
					// Требуем расширенный главный секрет
					server.master(true);
				// Запускаем сервер
				ASSERT_EQ(server.start(), context::error_t::NONE) << path;
				// Подаём записанное первое приветствие
				ASSERT_EQ(server.push(view_t(c2s[0].data(), c2s[0].size())), context::error_t::NONE) << path;
				// Ответ: просьба о подтверждении адреса
				vector <vector <uint8_t>> query;
				// Снимаем
				ASSERT_TRUE(drain(server, query)) << path;
				// Одна дейтаграмма
				ASSERT_EQ(query.size(), static_cast <size_t> (1)) << path;
				// Записи просьбы
				vector <wired_t> asked;
				// Разбираем
				ASSERT_TRUE(unwind(query, asked)) << path;
				// Одна запись
				ASSERT_EQ(asked.size(), static_cast <size_t> (1)) << path;
				// Разбираем обвязку
				ASSERT_EQ(datagram::parse(view_t(asked[0].content.data(), asked[0].content.size()), fragment), datagram::error_t::NONE) << path;
				// Просьба о подтверждении адреса номером ноль
				ASSERT_EQ(fragment.type, handshake::type_t::VERIFY_REQUEST) << path;
				// Номер
				ASSERT_EQ(fragment.sequence, 0) << path;
				// Тело просьбы
				const uint8_t * body = (asked[0].content.data() + datagram::DATAGRAM_FRAGMENT_HEADER);
				// Издание ровно 0xFEFF, как у всех шести изданий openssl
				ASSERT_EQ(static_cast <uint16_t> ((body[0] << 8) | body[1]), static_cast <uint16_t> (0xFEFF)) << path;
				// Метка
				const vector <uint8_t> cookie(body + 3, body + 3 + body[2]);
				// Состояния нет
				ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0)) << path;
				// Записанное повторное приветствие с меткой openssl: чужая метка законно отвергается
				ASSERT_EQ(server.push(view_t(c2s[1].data(), c2s[1].size())), context::error_t::NONE) << path;
				// Отброшено меткой
				ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1)) << path;
				// Сервер молчит
				ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << path;
				// Сервер не оборван
				ASSERT_EQ(server.state(), context::state_t::HANDSHAKE) << path;
				// Повторное приветствие с нашей меткой: то же приветствие openssl с меткой в поле
				hello::client_t repeated = greeting;
				// Наша метка
				repeated.cookie = cookie;
				// Тело
				vector <uint8_t> rebuilt;
				// Составляем
				ASSERT_EQ(hello::build(repeated, rebuilt, true), hello::error_t::NONE) << path;
				// Дейтаграмма номером один
				const vector <uint8_t> second = plain(handshake::type_t::CLIENT, rebuilt, 1, 1);
				// Подаём вторую запись серверу
				(void) server.push(view_t(second.data(), second.size()));
				// Если расширенного главного секрета нет
				if(!SCENARIOS[s].master){
					// Отказ расширенного главного секрета
					ASSERT_EQ(server.error(), context::error_t::MASTER) << path << " предел " << v;
					// Извещение handshake_failure
					ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE) << path;
					// Извещение ушло
					ASSERT_GT(server.output().size, static_cast <size_t> (0)) << path;
					// Открытой записью извещения
					ASSERT_EQ(server.output().data[0], 0x15) << path;
					// Переходим к следующему пределу
					continue;
				}
				// Отказа нет
				ASSERT_EQ(server.error(), context::error_t::NONE) << path << " предел " << v << " извещение " << static_cast <int> (server.alert().description);
				// Издание DTLS 1.2
				ASSERT_EQ(server.version(), TLS12) << path;
				// Набор тот же, что у s_server
				ASSERT_EQ(static_cast <uint16_t> (server.suite()), chosen.suite) << path;
				// Залп сервера
				vector <vector <uint8_t>> flight;
				// Снимаем
				ASSERT_TRUE(drain(server, flight)) << path;
				// Записи залпа
				vector <wired_t> records;
				// Разбираем
				ASSERT_TRUE(unwind(flight, records)) << path;
				/**
				 * Выполняем перебор записей залпа
				 */
				for(size_t r = 0; r < records.size(); r++){
					// Рукопожатие
					ASSERT_EQ(records[r].type, static_cast <uint8_t> (record::type_t::HANDSHAKE)) << path;
					// Издание DTLS 1.2 в заголовке
					ASSERT_EQ(records[r].version, DTLS12) << path;
					// Нулевая пора
					ASSERT_EQ(records[r].epoch, 0) << path;
				}
				// Сообщения залпа
				vector <taken_t> messages;
				// Собираем
				ASSERT_TRUE(gather(records, messages)) << path;
				// Залп не пуст
				ASSERT_FALSE(messages.empty()) << path;
				// Приветствие сервера первым номером один
				ASSERT_EQ(messages[0].type, handshake::type_t::SERVER) << path;
				// Раздел 4.2.2 RFC 6347: номер один
				ASSERT_EQ(messages[0].sequence, 1) << path;
				// Наше приветствие
				hello::server_t mine;
				// Разбираем
				ASSERT_EQ(hello::parse(view_t(messages[0].body.data(), messages[0].body.size()), mine), hello::error_t::NONE) << path;
				// Издание DTLS 1.2
				ASSERT_EQ(mine.version, DTLS12) << path;
				// Набор тот же
				ASSERT_EQ(mine.suite, chosen.suite) << path;
				// Сжатие нулевое
				ASSERT_EQ(mine.method, 0) << path;
				// Расширенный главный секрет
				ASSERT_NE(hello::extension(mine.extensions, static_cast <uint16_t> (extension::type_t::MASTER)), nullptr) << path;
				// Безопасное пересогласование
				ASSERT_NE(hello::extension(mine.extensions, static_cast <uint16_t> (extension::type_t::RENEGOTIATION)), nullptr) << path;
				// Цепочка
				ASSERT_NE(seek(messages, handshake::type_t::CERTIFICATE), nullptr) << path;
				// Обмен ключами
				const taken_t * agreement12 = seek(messages, handshake::type_t::AGREEMENT);
				// Проверяем наличие
				ASSERT_NE(agreement12, nullptr) << path;
				// Разобранный обмен
				exchange_t exchange12;
				// Разбираем
				ASSERT_TRUE(dissect(view_t(agreement12->body.data(), agreement12->body.size()), exchange12)) << path;
				// Группа та же, что у s_server
				ASSERT_EQ(exchange12.group, exchanged.group) << path << " группа " << naming(exchange12.group);
				// Запрос подлинности по сценарию
				ASSERT_EQ(seek(messages, handshake::type_t::REQUEST) != nullptr, SCENARIOS[s].mutual) << path;
				// Конец приветствия последним
				ASSERT_EQ(messages.back().type, handshake::type_t::DONE) << path;
				// Часы сервера идут: залп ждёт ответа
				ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT) << path;
				// Считаем вектор
				verified++;
			}
		}
	}
	// Векторов: восемь сценариев у четырёх изданий и семь у двух, без no-ems, по два предела
	ASSERT_EQ(verified, static_cast <size_t> ((8 * 6 - 2 - 4) * 2));
}

/**
 * Проверка векторов DTLS 1.2 на стороне клиента: сообщения настоящего s_server разбираются
 * нашими открытыми примитивами - просьба о подтверждении адреса с изданием 0xFEFF и меткой в
 * 20 октетов, приветствие сервера с набором и расширенным главным секретом по описанию,
 * сертификат из набора, подпись ServerKeyExchange ключом сертификата над случайными
 * значениями и параметрами, а во взаимной подлинности - подпись CertificateVerify клиента над
 * перепиской в обвязке DTLS без просьбы и первого приветствия
 */
TEST(Dtls12Test, VectorClient){
	// Число проверенных подписей
	size_t signatures = 0;
	// Число проверенных подписей владения
	size_t attestations = 0;
	/**
	 * Выполняем перебор изданий openssl
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS) / sizeof(SCENARIOS[0])); s++){
			// Путь к вектору
			const std::string path = place(EDITIONS[e], SCENARIOS[s].name);
			// Если вектора нет
			if(!exists(path)){
				// Отсутствие обязано быть ожидаемым
				ASSERT_TRUE(omitted(EDITIONS[e], SCENARIOS[s])) << "вектор не снят: " << path;
				// Переходим к следующему
				continue;
			}
			// Сведения о векторе
			brief_t brief;
			// Разбираем описание
			ASSERT_TRUE(describe(path, brief)) << path;
			// Дейтаграммы сторон
			vector <vector <uint8_t>> c2s, s2c;
			// Читаем дейтаграммы клиента
			ASSERT_TRUE(manifest(path, "c2s", c2s)) << path;
			// Читаем дейтаграммы сервера
			ASSERT_TRUE(manifest(path, "s2c", s2c)) << path;
			// Записи сторон
			vector <wired_t> ours, theirs;
			// Разбираем записи клиента
			ASSERT_TRUE(unwind(c2s, ours)) << path;
			// Разбираем записи сервера
			ASSERT_TRUE(unwind(s2c, theirs)) << path;
			// Сообщения сторон
			vector <taken_t> asked, answered;
			// Собираем сообщения клиента
			ASSERT_TRUE(gather(ours, asked)) << path;
			// Собираем сообщения сервера
			ASSERT_TRUE(gather(theirs, answered)) << path;
			// Два приветствия клиента: без метки и с меткой
			ASSERT_GE(asked.size(), static_cast <size_t> (3)) << path;
			// Первое приветствие
			ASSERT_EQ(asked[0].type, handshake::type_t::CLIENT) << path;
			// Повторное приветствие номером один
			ASSERT_EQ(asked[1].type, handshake::type_t::CLIENT) << path;
			// Номер один
			ASSERT_EQ(asked[1].sequence, 1) << path;
			// Первое приветствие клиента в записи
			ASSERT_TRUE(excerpt(path + "/client-clienthello.bin", asked[0])) << path;
			// Просьба о подтверждении адреса
			ASSERT_EQ(answered[0].type, handshake::type_t::VERIFY_REQUEST) << path;
			// Номер ноль
			ASSERT_EQ(answered[0].sequence, 0) << path;
			// Просьба в записи
			ASSERT_TRUE(excerpt(path + "/helloverifyrequest.bin", answered[0])) << path;
			// Издание просьбы 0xFEFF у всех шести изданий openssl
			ASSERT_EQ(static_cast <uint16_t> ((answered[0].body[0] << 8) | answered[0].body[1]), static_cast <uint16_t> (0xFEFF)) << path;
			// Метка openssl: 20 октетов HMAC-SHA1
			ASSERT_EQ(answered[0].body[2], 20) << path;
			// Длина тела
			ASSERT_EQ(answered[0].body.size(), static_cast <size_t> (3 + 20)) << path;
			// Запись просьбы с изданием DTLS 1.0 в заголовке
			ASSERT_EQ(theirs[0].version, DTLS10) << path;
			// Первое приветствие
			hello::client_t first;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(asked[0].body.data(), asked[0].body.size()), first, true), hello::error_t::NONE) << path;
			// Без метки
			ASSERT_TRUE(first.cookie.empty()) << path;
			// Повторное приветствие
			hello::client_t client;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(asked[1].body.data(), asked[1].body.size()), client, true), hello::error_t::NONE) << path;
			// Метка повторена из просьбы
			ASSERT_EQ(client.cookie, vector <uint8_t> (answered[0].body.begin() + 3, answered[0].body.end())) << path;
			// Случайное значение то же
			ASSERT_EQ(::memcmp(first.random, client.random, hello::HELLO_RANDOM), 0) << path;
			// Опознаватель тот же
			ASSERT_EQ(first.session, client.session) << path;
			// Набор предложен
			ASSERT_NE(std::find(client.suites.begin(), client.suites.end(), SCENARIOS[s].suite), client.suites.end()) << path;
			// Расширенный главный секрет по сценарию
			ASSERT_EQ(hello::extension(client.extensions, static_cast <uint16_t> (extension::type_t::MASTER)) != nullptr, SCENARIOS[s].master) << path;
			// Приветствие сервера
			const taken_t * greeted = seek(answered, handshake::type_t::SERVER);
			// Проверяем наличие
			ASSERT_NE(greeted, nullptr) << path;
			// Номер один
			ASSERT_EQ(greeted->sequence, 1) << path;
			// Разобранное приветствие сервера
			hello::server_t server;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(greeted->body.data(), greeted->body.size()), server), hello::error_t::NONE) << path;
			// Издание DTLS 1.2
			ASSERT_EQ(server.version, DTLS12) << path;
			// Набор
			ASSERT_EQ(server.suite, brief.suite) << path;
			// Сжатие нулевое
			ASSERT_EQ(server.method, 0) << path;
			// Расширенный главный секрет по описанию
			ASSERT_EQ(hello::extension(server.extensions, static_cast <uint16_t> (extension::type_t::MASTER)) != nullptr, brief.master) << path;
			// Цепочка
			const taken_t * chain = seek(answered, handshake::type_t::CERTIFICATE);
			// Проверяем наличие
			ASSERT_NE(chain, nullptr) << path;
			// Цепочка в записи: первый кусок, как он шёл по проводу
			ASSERT_TRUE(excerpt(path + "/certificate.bin", *chain)) << path;
			// Первый сертификат
			const view_t der = leaf(view_t(chain->body.data(), chain->body.size()));
			// Проверяем наличие
			ASSERT_NE(der.data, nullptr) << path;
			// Подлинность
			context::credential_t credential;
			// Составляем
			ASSERT_TRUE(identity(brief.key.c_str(), credential)) << path;
			// Сертификат из набора
			ASSERT_EQ(vector <uint8_t> (der.data, der.data + der.size), credential.chain[0]) << path;
			// Сертификат
			x509::certificate_t certificate;
			// Разбираем
			ASSERT_EQ(certificate.parse(der), x509::error_t::NONE) << path;
			// Обмен ключами сервера
			const taken_t * agreed = seek(answered, handshake::type_t::AGREEMENT);
			// Проверяем наличие
			ASSERT_NE(agreed, nullptr) << path;
			// Обмен в записи
			ASSERT_TRUE(excerpt(path + "/serverkeyexchange.bin", *agreed)) << path;
			// Разобранный обмен
			exchange_t exchanged;
			// Разбираем
			ASSERT_TRUE(dissect(view_t(agreed->body.data(), agreed->body.size()), exchanged)) << path;
			// Подписанное содержимое: случайные значения и параметры
			vector <uint8_t> content(client.random, client.random + hello::HELLO_RANDOM);
			// Случайное значение сервера
			content.insert(content.end(), server.random, server.random + hello::HELLO_RANDOM);
			// Параметры
			content.insert(content.end(), exchanged.parameters.data, exchanged.parameters.data + exchanged.parameters.size);
			// Подпись сходится
			ASSERT_TRUE(attested(certificate.key(), exchanged.scheme, view_t(content.data(), content.size()), exchanged.signature)) << path << " схема " << std::hex << exchanged.scheme;
			// Порченая подпись
			vector <uint8_t> spoiled(exchanged.signature.data, exchanged.signature.data + exchanged.signature.size);
			// Портим
			spoiled.back() ^= 0x01;
			// Не сходится
			ASSERT_FALSE(attested(certificate.key(), exchanged.scheme, view_t(content.data(), content.size()), view_t(spoiled.data(), spoiled.size()))) << path;
			// Считаем подпись
			signatures++;
			// Конец приветствия
			ASSERT_NE(seek(answered, handshake::type_t::DONE), nullptr) << path;
			// Конец приветствия в записи
			ASSERT_TRUE(excerpt(path + "/serverhellodone.bin", *seek(answered, handshake::type_t::DONE))) << path;
			// Обмен ключами клиента
			ASSERT_NE(seek(asked, handshake::type_t::PREMASTER), nullptr) << path;
			// Обмен ключами клиента в записи
			ASSERT_TRUE(excerpt(path + "/client-clientkeyexchange.bin", *seek(asked, handshake::type_t::PREMASTER))) << path;
			// Если взаимная подлинность
			if(SCENARIOS[s].mutual){
				// Запрос подлинности
				const taken_t * request = seek(answered, handshake::type_t::REQUEST);
				// Проверяем наличие
				ASSERT_NE(request, nullptr) << path;
				// Запрос в записи
				ASSERT_TRUE(excerpt(path + "/certificaterequest.bin", *request)) << path;
				// Цепочка клиента
				const taken_t * presented = seek(asked, handshake::type_t::CERTIFICATE);
				// Проверяем наличие
				ASSERT_NE(presented, nullptr) << path;
				// Цепочка в записи
				ASSERT_TRUE(excerpt(path + "/client-certificate.bin", *presented)) << path;
				// Подпись владения
				const taken_t * verify = seek(asked, handshake::type_t::VERIFY);
				// Проверяем наличие
				ASSERT_NE(verify, nullptr) << path;
				// Подпись в записи
				ASSERT_TRUE(excerpt(path + "/client-certificateverify.bin", *verify)) << path;
				// Тело подписи
				const vector <uint8_t> & attest = verify->body;
				// Схема
				const uint16_t scheme = ((static_cast <uint16_t> (attest[0]) << 8) | attest[1]);
				// Схема ECDSA P-256
				ASSERT_EQ(scheme, 0x0403) << path;
				// Длина подписи
				const size_t size = ((static_cast <size_t> (attest[2]) << 8) | attest[3]);
				// Длина сходится
				ASSERT_EQ(4 + size, attest.size()) << path;
				// Переписка в обвязке DTLS: повторное приветствие, залп сервера, сообщения клиента до подписи
				vector <uint8_t> transcript(asked[1].framed);
				/**
				 * Выполняем перебор сообщений сервера за просьбой: билет идёт после подписи и в неё не входит
				 */
				for(size_t i = 1; i < answered.size(); i++){
					// Если билет
					if(answered[i].type == handshake::type_t::TICKET)
						// Переходим к следующему
						continue;
					// Добавляем сообщение
					transcript.insert(transcript.end(), answered[i].framed.begin(), answered[i].framed.end());
				}
				/**
				 * Выполняем перебор сообщений клиента за повторным приветствием до подписи
				 */
				for(size_t i = 2; (i < asked.size()) && (asked[i].type != handshake::type_t::VERIFY); i++)
					// Добавляем сообщение
					transcript.insert(transcript.end(), asked[i].framed.begin(), asked[i].framed.end());
				// Подпись владения сходится с перепиской без просьбы и первого приветствия
				ASSERT_TRUE(attested(certificate.key(), scheme, view_t(transcript.data(), transcript.size()), view_t(attest.data() + 4, size))) << path;
				// Переписка с просьбой и первым приветствием впереди
				vector <uint8_t> excessive(asked[0].framed);
				// Просьба
				excessive.insert(excessive.end(), answered[0].framed.begin(), answered[0].framed.end());
				// Остальное
				excessive.insert(excessive.end(), transcript.begin(), transcript.end());
				// С ними подпись не сходится
				ASSERT_FALSE(attested(certificate.key(), scheme, view_t(excessive.data(), excessive.size()), view_t(attest.data() + 4, size))) << path;
				// Считаем подпись владения
				attestations++;
			}
		}
	}
	// Подписей: восемь сценариев у четырёх изданий и семь у двух
	ASSERT_EQ(signatures, static_cast <size_t> (8 * 6 - 2));
	// Подписей владения: по одной на издание
	ASSERT_EQ(attestations, static_cast <size_t> (6));
}

/**
 * Проверка полного прогона векторов DTLS 1.2: по ключевому файлу и случайным значениям
 * сторон ключевой материал выводится нашей порождающей функцией, защищённые завершения обеих
 * сторон расшифровываются нашей защитой записей с порой и номером в связанных данных (раздел
 * 4.1.2.1 RFC 6347), verify_data сверяется с перепиской в обвязке DTLS без просьбы и первого
 * приветствия (разделы 4.2.1 и 4.2.6) - совместимость PRF, расписания ключей и раскладки AEAD с
 * шестью изданиями openssl байт в байт; с просьбой в переписке и в обвязке TLS не сходится
 */
TEST(Dtls12Test, VectorFinished){
	// Число расшифрованных векторов
	size_t decrypted = 0;
	/**
	 * Выполняем перебор изданий openssl
	 */
	for(size_t e = 0; e < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); e++){
		/**
		 * Выполняем перебор сценариев
		 */
		for(size_t s = 0; s < (sizeof(SCENARIOS) / sizeof(SCENARIOS[0])); s++){
			// Путь к вектору
			const std::string path = place(EDITIONS[e], SCENARIOS[s].name);
			// Если вектора нет
			if(!exists(path)){
				// Отсутствие обязано быть ожидаемым
				ASSERT_TRUE(omitted(EDITIONS[e], SCENARIOS[s])) << "вектор не снят: " << path;
				// Переходим к следующему
				continue;
			}
			// Сведения о векторе
			brief_t brief;
			// Разбираем описание
			ASSERT_TRUE(describe(path, brief)) << path;
			// Дейтаграммы сторон
			vector <vector <uint8_t>> c2s, s2c;
			// Читаем дейтаграммы клиента
			ASSERT_TRUE(manifest(path, "c2s", c2s)) << path;
			// Читаем дейтаграммы сервера
			ASSERT_TRUE(manifest(path, "s2c", s2c)) << path;
			// Записи сторон
			vector <wired_t> ours, theirs;
			// Разбираем записи клиента
			ASSERT_TRUE(unwind(c2s, ours)) << path;
			// Разбираем записи сервера
			ASSERT_TRUE(unwind(s2c, theirs)) << path;
			// Сообщения сторон
			vector <taken_t> asked, answered;
			// Собираем сообщения клиента
			ASSERT_TRUE(gather(ours, asked)) << path;
			// Собираем сообщения сервера
			ASSERT_TRUE(gather(theirs, answered)) << path;
			// Повторное приветствие
			hello::client_t client;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(asked[1].body.data(), asked[1].body.size()), client, true), hello::error_t::NONE) << path;
			// Приветствие сервера
			hello::server_t server;
			// Разбираем
			ASSERT_EQ(hello::parse(view_t(answered[1].body.data(), answered[1].body.size()), server), hello::error_t::NONE) << path;
			// Набор
			ASSERT_EQ(server.suite, brief.suite) << path;
			// Ключевой файл
			vector <uint8_t> random, master;
			// Читаем
			ASSERT_TRUE(keylog(path, random, master)) << path;
			// Случайное значение клиента сходится
			ASSERT_EQ(random, vector <uint8_t> (client.random, client.random + hello::HELLO_RANDOM)) << path;
			// Случайное значение сервера
			const vector <uint8_t> foreign(server.random, server.random + hello::HELLO_RANDOM);
			// Набор
			const protect::suite_t suite = static_cast <protect::suite_t> (SCENARIOS[s].suite);
			// Набор издания 1.2
			ASSERT_TRUE(protect::legacy(suite)) << path;
			// Переписка: повторное приветствие, сообщения сервера за просьбой, сообщения клиента за повторным приветствием
			vector <vector <uint8_t>> transcript;
			// Повторное приветствие
			transcript.push_back(asked[1].framed);
			// Билеты сервера: они идут за завершением клиента и входят лишь в переписку завершения сервера
			vector <vector <uint8_t>> tickets;
			/**
			 * Выполняем перебор сообщений сервера за просьбой
			 */
			for(size_t i = 1; i < answered.size(); i++){
				// Если билет
				if(answered[i].type == handshake::type_t::TICKET)
					// Откладываем билет
					tickets.push_back(answered[i].framed);
				// Добавляем сообщение
				else transcript.push_back(answered[i].framed);
			}
			/**
			 * Выполняем перебор сообщений клиента за повторным приветствием
			 */
			for(size_t i = 2; i < asked.size(); i++)
				// Добавляем сообщение
				transcript.push_back(asked[i].framed);
			// Запись завершения клиента
			const wired_t * finishing = sealed(ours);
			// Проверяем наличие
			ASSERT_NE(finishing, nullptr) << path;
			// Первая пора
			ASSERT_EQ(finishing->epoch, 1) << path;
			// Издание DTLS 1.2 в заголовке
			ASSERT_EQ(finishing->version, DTLS12) << path;
			// Защита чтения клиента
			protect::protection_t incoming;
			// Заводим ключом клиента
			ASSERT_TRUE(keyed(suite, master, random, foreign, incoming, true)) << path;
			// Завершение клиента: собирается из всех защищённых записей рукопожатия, ибо чужой узел дробит и его
			taken_t finish;
			// Собираем завершение клиента
			ASSERT_TRUE(unsealed(ours, incoming, finish)) << path;
			// Завершение
			ASSERT_EQ(finish.type, handshake::type_t::FINISHED) << path;
			// Двенадцать байтов
			ASSERT_EQ(finish.body.size(), static_cast <size_t> (12)) << path;
			// Ожидаемое завершение
			uint8_t expected[12];
			// Считаем завершение клиента
			ASSERT_TRUE(completion(suite, master, "client finished", transcript, expected)) << path;
			// Сходится
			ASSERT_EQ(finish.body, vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Переписка с просьбой и первым приветствием впереди
			vector <vector <uint8_t>> excessive;
			// Первое приветствие
			excessive.push_back(asked[0].framed);
			// Просьба
			excessive.push_back(answered[0].framed);
			// Остальное
			excessive.insert(excessive.end(), transcript.begin(), transcript.end());
			// Считаем
			ASSERT_TRUE(completion(suite, master, "client finished", excessive, expected)) << path;
			// Не сходится
			ASSERT_NE(finish.body, vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Переписка в обвязке TLS
			vector <vector <uint8_t>> shortened;
			/**
			 * Выполняем переложение переписки в обвязку TLS
			 */
			for(size_t i = 0; i < transcript.size(); i++){
				// Сообщение: вид, длина и тело
				vector <uint8_t> message(transcript[i].begin(), transcript[i].begin() + 4);
				// Тело
				message.insert(message.end(), transcript[i].begin() + datagram::DATAGRAM_FRAGMENT_HEADER, transcript[i].end());
				// Добавляем
				shortened.push_back(message);
			}
			// Считаем
			ASSERT_TRUE(completion(suite, master, "client finished", shortened, expected)) << path;
			// Не сходится
			ASSERT_NE(finish.body, vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Завершение клиента в переписку одним куском
			transcript.push_back(finish.framed);
			/**
			 * Выполняем перебор отложенных билетов: они идут за завершением клиента
			 */
			for(size_t i = 0; i < tickets.size(); i++)
				// Добавляем билет
				transcript.push_back(tickets[i]);
			// Запись завершения сервера
			const wired_t * finished = sealed(theirs);
			// Проверяем наличие
			ASSERT_NE(finished, nullptr) << path;
			// Защита чтения сервера
			protect::protection_t outgoing;
			// Заводим ключом сервера
			ASSERT_TRUE(keyed(suite, master, random, foreign, outgoing, false)) << path;
			// Завершение сервера
			taken_t done;
			// Собираем завершение сервера
			ASSERT_TRUE(unsealed(theirs, outgoing, done)) << path;
			// Завершение
			ASSERT_EQ(done.type, handshake::type_t::FINISHED) << path;
			// Считаем завершение сервера
			ASSERT_TRUE(completion(suite, master, "server finished", transcript, expected)) << path;
			// Сходится
			ASSERT_EQ(done.body, vector <uint8_t> (expected, expected + sizeof(expected))) << path;
			// Открытое содержимое порченой записи
			vector <uint8_t> plain;
			// Порченая запись
			vector <uint8_t> spoiled = finished->content;
			// Портим
			spoiled[spoiled.size() / 2] ^= 0x01;
			// Защита заново
			protect::protection_t again;
			// Заводим
			ASSERT_TRUE(keyed(suite, master, random, foreign, again, false)) << path;
			// Очищаем
			plain.clear();
			// Метка не сходится
			ASSERT_EQ(again.unwrap(((static_cast <uint64_t> (finished->epoch) << 48) | finished->sequence), record::version_t::DTLS12, record::type_t::HANDSHAKE, view_t(spoiled.data(), spoiled.size()), plain), protect::error_t::TAG) << path;
			// Иная пора в связанных данных не сходится
			ASSERT_EQ(again.unwrap(((static_cast <uint64_t> (2) << 48) | finished->sequence), record::version_t::DTLS12, record::type_t::HANDSHAKE, view_t(finished->content.data(), finished->content.size()), plain), protect::error_t::TAG) << path;
			// Считаем вектор
			decrypted++;
		}
	}
	// Векторов: восемь сценариев у четырёх изданий и семь у двух
	ASSERT_EQ(decrypted, static_cast <size_t> (8 * 6 - 2));
}


/**
 * Проверка петлевого рукопожатия DTLS 1.2 по шести наборам и трём группам со взаимной
 * подлинностью: первое приветствие без метки, просьба о подтверждении адреса с изданием
 * DTLS 1.0 и меткой, повторное приветствие с той же меткой, теми же случайным значением и
 * опознавателем, издание 0xFEFD, записи прикладных данных первой поры открытым заголовком,
 * обмен данными в обе стороны и закрытие
 */
TEST(Dtls12Test, Loopback){
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность из ключей набора
		ASSERT_TRUE(identity(SUITES[s].key, credential)) << SUITES[s].title;
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны с подлинностью клиента
			arrange(client, server, SUITES[s].suite, GROUPS[g], credential, true);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Издание до согласования не известно
			ASSERT_EQ(client.version(), 0);
			// Первая дейтаграмма клиента
			vector <vector <uint8_t>> first;
			// Снимаем первую дейтаграмму
			ASSERT_TRUE(drain(client, first));
			// Одна дейтаграмма
			ASSERT_EQ(first.size(), static_cast <size_t> (1));
			// Поля заголовка
			uint8_t type = 0;
			// Издание
			uint16_t version = 0;
			// Пора
			uint16_t epoch = 0;
			// Номер
			uint64_t sequence = 0;
			// Длина
			size_t size = 0;
			// Читаем заголовок первой записи
			ASSERT_TRUE(heading(first[0], 0, type, version, epoch, sequence, size));
			// Рукопожатие, издание DTLS 1.2, нулевая пора и нулевой номер
			ASSERT_EQ(type, static_cast <uint8_t> (record::type_t::HANDSHAKE));
			// Издание заголовка
			ASSERT_EQ(version, DTLS12);
			// Пора нулевая
			ASSERT_EQ(epoch, 0);
			// Номер нулевой
			ASSERT_EQ(sequence, static_cast <uint64_t> (0));
			// Обвязка куска
			datagram::fragment_t fragment;
			// Разбираем обвязку
			ASSERT_EQ(datagram::parse(view_t(first[0].data() + datagram::DATAGRAM_PLAIN_HEADER, size), fragment), datagram::error_t::NONE);
			// Приветствие клиента номером ноль
			ASSERT_EQ(fragment.type, handshake::type_t::CLIENT);
			// Номер сообщения
			ASSERT_EQ(fragment.sequence, 0);
			// Приветствие клиента
			hello::client_t greeting;
			// Разбираем приветствие поверх дейтаграмм
			ASSERT_EQ(hello::parse(view_t(first[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
			// Первое приветствие без метки (раздел 4.2.1 RFC 6347)
			ASSERT_TRUE(greeting.cookie.empty());
			// Издание заголовка приветствия DTLS 1.2
			ASSERT_EQ(greeting.version, DTLS12);
			// Наборов издания 1.3 у связи нет: предлагается лишь DTLS 1.2, и расширение изданий не кладётся (решение 15 движка, как у openssl; LibreSSL 3.6.1 на нём обрывает связь)
			ASSERT_EQ(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS)), nullptr);
			// Расширенный главный секрет предложен
			ASSERT_NE(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::MASTER)), nullptr);
			// Случайное значение первого приветствия
			vector <uint8_t> random(greeting.random, greeting.random + hello::HELLO_RANDOM);
			// Опознаватель первого приветствия
			const vector <uint8_t> session = greeting.session;
			// Подаём первое приветствие серверу
			server.push(view_t(first[0].data(), first[0].size()));
			// Ответ сервера
			vector <vector <uint8_t>> answer;
			// Снимаем ответ
			ASSERT_TRUE(drain(server, answer));
			// Одна дейтаграмма
			ASSERT_EQ(answer.size(), static_cast <size_t> (1));
			// Сервер состояния не держит: часов нет
			ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
			// Читаем заголовок просьбы
			ASSERT_TRUE(heading(answer[0], 0, type, version, epoch, sequence, size));
			// Открытая запись рукопожатия
			ASSERT_EQ(type, static_cast <uint8_t> (record::type_t::HANDSHAKE));
			// Пора нулевая
			ASSERT_EQ(epoch, 0);
			// Разбираем обвязку просьбы
			ASSERT_EQ(datagram::parse(view_t(answer[0].data() + datagram::DATAGRAM_PLAIN_HEADER, size), fragment), datagram::error_t::NONE);
			// Просьба о подтверждении адреса номером ноль
			ASSERT_EQ(fragment.type, handshake::type_t::VERIFY_REQUEST);
			// Номер сообщения
			ASSERT_EQ(fragment.sequence, 0);
			// Тело просьбы
			const uint8_t * body = (answer[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER);
			// Раздел 4.2.1 RFC 6347: издание просьбы DTLS 1.0
			ASSERT_EQ(static_cast <uint16_t> ((body[0] << 8) | body[1]), DTLS10);
			// Длина метки: поколение, хеш и имитовставка
			ASSERT_EQ(body[2], LABEL);
			// Длина тела
			ASSERT_EQ(fragment.length, 3 + LABEL);
			// Метка
			const vector <uint8_t> cookie(body + 3, body + 3 + LABEL);
			// Подаём просьбу клиенту
			client.push(view_t(answer[0].data(), answer[0].size()));
			// Повторное приветствие
			vector <vector <uint8_t>> second;
			// Снимаем повторное приветствие
			ASSERT_TRUE(drain(client, second));
			// Одна дейтаграмма
			ASSERT_EQ(second.size(), static_cast <size_t> (1));
			// Читаем заголовок
			ASSERT_TRUE(heading(second[0], 0, type, version, epoch, sequence, size));
			// Номер записи продвинут
			ASSERT_EQ(sequence, static_cast <uint64_t> (1));
			// Разбираем обвязку
			ASSERT_EQ(datagram::parse(view_t(second[0].data() + datagram::DATAGRAM_PLAIN_HEADER, size), fragment), datagram::error_t::NONE) << second[0].size() << " " << static_cast <int> (type) << " " << size << " " << static_cast <int> (client.error()) << " " << static_cast <int> (client.alert().description);
			// Раздел 4.2.2 RFC 6347: повторное приветствие идёт номером один
			ASSERT_EQ(fragment.sequence, 1);
			// Разбираем повторное приветствие
			ASSERT_EQ(hello::parse(view_t(second[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
			// Метка повторена дословно
			ASSERT_EQ(greeting.cookie, cookie);
			// Случайное значение то же
			ASSERT_EQ(vector <uint8_t> (greeting.random, greeting.random + hello::HELLO_RANDOM), random);
			// Опознаватель тот же
			ASSERT_EQ(greeting.session, session);
			// Путь между сторонами
			bond_t bond;
			// Подаём повторное приветствие серверу
			server.push(view_t(second[0].data(), second[0].size()));
			// Сервер ответил залпом и ждёт
			ASSERT_GT(server.output().size, static_cast <size_t> (0));
			// Часы сервера идут
			ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT);
			// Проводим рукопожатие до тишины
			converse(client, server, bond, 400);
			// Связь установлена клиентом
			ASSERT_TRUE(client.established()) << SUITES[s].title << " " << naming(GROUPS[g]) << " отказы " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description) << " состояния " << static_cast <int> (client.state()) << " " << static_cast <int> (server.state()) << " отбросы " << client.discarded() << " " << server.discarded() << " часы " << client.timeout() << " " << server.timeout() << " дейтаграммы " << bond.counters[0] << " " << bond.counters[1];
			// Связь установлена сервером
			ASSERT_TRUE(server.established()) << SUITES[s].title << " " << naming(GROUPS[g]);
			// Издание DTLS 1.2 у клиента
			ASSERT_EQ(client.version(), TLS12);
			// Издание DTLS 1.2 у сервера
			ASSERT_EQ(server.version(), TLS12);
			// Часы клиента остановлены
			ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
			// Последний залп сервера часов не ждёт
			ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
			// Ничего не потеряно
			ASSERT_EQ(bond.dropped, static_cast <size_t> (0));
			// Ничего не отброшено сервером
			ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
			// Ничего не отброшено клиентом
			ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0));
			// Дейтаграммы не длиннее назначенного размера
			ASSERT_LE(bond.largest, datagram::DATAGRAM_MTU);
			// Набор клиента
			ASSERT_EQ(client.suite(), SUITES[s].suite);
			// Набор сервера
			ASSERT_EQ(server.suite(), SUITES[s].suite);
			// Подлинность клиента у сервера
			ASSERT_EQ(server.peer().size(), credential.chain.size());
			// Подлинность сервера у клиента
			ASSERT_EQ(client.peer().size(), credential.chain.size());
			// Обмениваемся данными
			ASSERT_TRUE(barter(client, server, bond)) << SUITES[s].title << " " << naming(GROUPS[g]);
			// Отправляем байт
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("x"), 1)), context::error_t::NONE);
			// Дейтаграмма с прикладными данными
			vector <vector <uint8_t>> data;
			// Снимаем дейтаграмму
			ASSERT_TRUE(drain(client, data));
			// Читаем заголовок
			ASSERT_TRUE(heading(data[0], 0, type, version, epoch, sequence, size));
			// Раздел 4.1 RFC 6347: прикладные данные открытым заголовком первой поры
			ASSERT_EQ(type, static_cast <uint8_t> (record::type_t::APPLICATION));
			// Издание DTLS 1.2
			ASSERT_EQ(version, DTLS12);
			// Первая пора
			ASSERT_EQ(epoch, 1);
			// Длина: явная часть, байт и метка
			ASSERT_EQ(size, protect::prefix(SUITES[s].suite) + 1 + protect::tag(SUITES[s].suite));
			// Доставляем данные
			server.push(view_t(data[0].data(), data[0].size()));
			// Принятые данные
			vector <uint8_t> received;
			// Читаем принятый байт данных
			ASSERT_EQ(server.read(received), context::error_t::NONE);
			// Байт дошёл
			ASSERT_EQ(received, vector <uint8_t> {'x'});
			// Смена ключей изданию 1.2 неведома
			ASSERT_EQ(client.update(false), context::error_t::STATE);
			// Билетов у издания 1.2 нет
			ASSERT_EQ(server.issue(), context::error_t::STATE);
			// Закрываем связь клиентом
			ASSERT_EQ(client.close(), context::error_t::NONE);
			// Доставляем извещение
			converse(client, server, bond, 400);
			// Сервер принял закрытие
			ASSERT_EQ(server.state(), context::state_t::CLOSED);
		}
	}
}

/**
 * Проверка сервера без состояния (раздел 4.2.1 RFC 6347): сто первых приветствий с разных
 * адресов отвечаются просьбами о подтверждении адреса без залпа и часов, повтор первого
 * приветствия отвечается просьбой вновь, приветствие с порченой меткой и с меткой чужого
 * адреса отбрасывается молча, а настоящее приветствие с меткой после сотни чужих
 * принимается и доводит рукопожатие до конца
 */
TEST(Dtls12Test, Stateless){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первое приветствие клиента
	vector <vector <uint8_t>> first;
	// Снимаем приветствие
	ASSERT_TRUE(drain(client, first));
	/**
	 * Выполняем подачу сотни первых приветствий с разных адресов
	 */
	for(size_t i = 0; i < 100; i++){
		// Чужой клиент
		client::context_t stranger;
		// Заглушка сервера для настройки
		server::context_t dummy;
		// Настраиваем чужого клиента
		arrange(stranger, dummy, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим чужого клиента
		ASSERT_EQ(stranger.start(), context::error_t::NONE);
		// Адрес чужого клиента
		const uint8_t address[] = {192, 168, static_cast <uint8_t> (i >> 8), static_cast <uint8_t> (i), 0x1F, 0x90};
		// Устанавливаем адрес чужого клиента серверу
		ASSERT_TRUE(server.address(view_t(address, sizeof(address))));
		// Приветствие чужого клиента
		vector <vector <uint8_t>> foreign;
		// Снимаем приветствие
		ASSERT_TRUE(drain(stranger, foreign));
		// Подаём приветствие серверу
		ASSERT_EQ(server.push(view_t(foreign[0].data(), foreign[0].size())), context::error_t::NONE);
		// Ответ сервера
		vector <vector <uint8_t>> answer;
		// Снимаем ответ
		ASSERT_TRUE(drain(server, answer));
		// Ровно одна дейтаграмма: просьба о подтверждении адреса
		ASSERT_EQ(answer.size(), static_cast <size_t> (1)) << i;
		// Просьба о подтверждении адреса
		ASSERT_EQ(answer[0][datagram::DATAGRAM_PLAIN_HEADER], static_cast <uint8_t> (handshake::type_t::VERIFY_REQUEST));
		// Часов нет: залп не держится
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Сервер в рукопожатии
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Ничего не отброшено
		ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
		// Издание не согласовано: состояния нет
		ASSERT_EQ(server.version(), 0);
	}
	// Возвращаем адрес настоящего клиента
	ASSERT_TRUE(server.address(view_t(ADDRESS, sizeof(ADDRESS))));
	// Подаём первое приветствие настоящего клиента
	ASSERT_EQ(server.push(view_t(first[0].data(), first[0].size())), context::error_t::NONE);
	// Просьба о подтверждении адреса
	vector <vector <uint8_t>> query;
	// Снимаем просьбу
	ASSERT_TRUE(drain(server, query));
	// Одна дейтаграмма
	ASSERT_EQ(query.size(), static_cast <size_t> (1));
	// Повтор первого приветствия отвечается просьбой вновь
	ASSERT_EQ(server.push(view_t(first[0].data(), first[0].size())), context::error_t::NONE);
	// Повторная просьба
	vector <vector <uint8_t>> repeated;
	// Снимаем повторную просьбу
	ASSERT_TRUE(drain(server, repeated));
	// Одна дейтаграмма
	ASSERT_EQ(repeated.size(), static_cast <size_t> (1));
	// Повтор первого приветствия тем же номером записи не отброшен окном: сервер без состояния
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
	// Подаём просьбу клиенту
	client.push(view_t(query[0].data(), query[0].size()));
	// Повторное приветствие с меткой
	vector <vector <uint8_t>> second;
	// Снимаем повторное приветствие
	ASSERT_TRUE(drain(client, second));
	// Подделка с порченой меткой: метка лежит за опознавателем связи, портим её последний байт
	vector <uint8_t> forged = second[0];
	// Смещение метки: заголовок записи, обвязка, издание, случайное значение, длина и опознаватель
	const size_t place = (datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER + 2 + hello::HELLO_RANDOM + 1 + hello::HELLO_SESSION);
	// Длина метки в приветствии
	ASSERT_EQ(forged[place], LABEL);
	// Портим последний байт имитовставки
	forged[place + LABEL] ^= 0x01;
	// Подаём подделку серверу
	ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Подделка отброшена молча
	ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
	// Сервер молчит
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Сервер не оборван
	ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Метка чужого адреса: меняем адрес и подаём настоящее приветствие
	const uint8_t other[] = {10, 0, 0, 2, 0x12, 0x34};
	// Устанавливаем чужой адрес
	ASSERT_TRUE(server.address(view_t(other, sizeof(other))));
	// Подаём настоящее приветствие с чужого адреса
	ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
	// Отброшено меткой
	ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (2));
	// Сервер молчит
	ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << static_cast <int> (server.output().data[0]) << " " << static_cast <int> (server.output().data[13]) << " " << static_cast <int> (server.output().data[14]);
	// Возвращаем адрес
	ASSERT_TRUE(server.address(view_t(ADDRESS, sizeof(ADDRESS))));
	// Подаём настоящее приветствие: повтор номера записи сервер без состояния не судит
	ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
	// Сервер ответил залпом
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Часы сервера идут
	ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Путь
	bond_t bond;
	// Доводим до тишины
	converse(client, server, bond, 400);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
	// Второй клиент со своим сервером: общий секрет метки признаёт метку другого сервера лишь при том же приветствии и адресе
	client::context_t another;
	// Второй сервер
	server::context_t twin;
	// Настраиваем вторую пару
	arrange(another, twin, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Секрет метки
	const vector <uint8_t> secret(reinterpret_cast <const uint8_t *> ("shared stamp secret of the servers"), reinterpret_cast <const uint8_t *> ("shared stamp secret of the servers") + 34);
	// Устанавливаем секрет второму серверу
	twin.stamp(secret);
	// Третий сервер с тем же секретом
	server::context_t triplet;
	// Заглушка клиента
	client::context_t dummy;
	// Настраиваем третий сервер
	arrange(dummy, triplet, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Устанавливаем секрет третьему серверу
	triplet.stamp(secret);
	// Заводим второй сервер
	ASSERT_EQ(twin.start(), context::error_t::NONE);
	// Заводим третий сервер
	ASSERT_EQ(triplet.start(), context::error_t::NONE);
	// Заводим второго клиента
	ASSERT_EQ(another.start(), context::error_t::NONE);
	// Путь второй пары
	bond_t path;
	// Приветствие и просьба второго сервера
	ASSERT_TRUE(carry(another, twin, path, 0) && carry(twin, another, path, 1));
	// Повторное приветствие с меткой второго сервера
	vector <vector <uint8_t>> labelled;
	// Снимаем приветствие
	ASSERT_TRUE(drain(another, labelled));
	// Третий сервер с тем же секретом и адресом признаёт метку без своего состояния
	ASSERT_EQ(triplet.push(view_t(labelled[0].data(), labelled[0].size())), context::error_t::NONE);
	// Третий сервер ответил залпом
	ASSERT_GT(triplet.output().size, static_cast <size_t> (0));
	// Ничего не отброшено
	ASSERT_EQ(triplet.discarded(), static_cast <uint64_t> (0));
	// Доводим второго клиента с третьим сервером до тишины
	converse(another, triplet, path, 400);
	// Связь установлена
	ASSERT_TRUE(another.established() && triplet.established());
}

/**
 * Проверка переписки рукопожатия сличением с независимым расчётом PRF: поддельный клиент
 * ведёт рукопожатие с сервером по своим ключам, считает главный секрет по разделу 4 RFC 7627,
 * ключевой материал по разделу 6.3 RFC 5246 и завершение по разделу 7.4.9 над перепиской в
 * обвязке DTLS (раздел 4.2.6 RFC 6347) без просьбы о подтверждении адреса и первого
 * приветствия (раздел 4.2.1); сервер признаёт завершение, отвергает порченое, отвергает
 * посчитанное с просьбой и первым приветствием и посчитанное в обвязке TLS
 */
TEST(Dtls12Test, Counterfeit){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Набор шифрования
	const protect::suite_t suite = protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256;
	/**
	 * Выполняем четыре круга: верное завершение, порченое, с просьбой в переписке, в обвязке TLS
	 */
	for(size_t item = 0; item < 4; item++){
		// Связь стороны сервера
		server::context_t server;
		// Заглушка клиента для настройки
		client::context_t dummy;
		// Настраиваем сервер
		arrange(dummy, server, suite, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Тело первого приветствия без метки
		vector <uint8_t> body;
		// Составляем приветствие
		ASSERT_TRUE(greeting(vector <uint8_t> (), DTLS12, body));
		// Первое приветствие в обвязке DTLS номером ноль
		const vector <uint8_t> initial = framed(handshake::type_t::CLIENT, body, 0);
		// Дейтаграмма с первым приветствием
		const vector <uint8_t> first = plain(handshake::type_t::CLIENT, body, 0, 0);
		// Подаём первое приветствие
		ASSERT_EQ(server.push(view_t(first.data(), first.size())), context::error_t::NONE);
		// Просьба о подтверждении адреса
		vector <vector <uint8_t>> query;
		// Снимаем просьбу
		ASSERT_TRUE(drain(server, query));
		// Сообщения просьбы
		vector <taken_t> asked;
		// Снимаем сообщения
		ASSERT_TRUE(harvest(query, asked));
		// Одна просьба
		ASSERT_EQ(asked.size(), static_cast <size_t> (1));
		// Просьба о подтверждении адреса
		ASSERT_EQ(asked[0].type, handshake::type_t::VERIFY_REQUEST);
		// Метка из просьбы: издание, длина, метка
		const vector <uint8_t> cookie(asked[0].body.begin() + 3, asked[0].body.end());
		// Длина метки
		ASSERT_EQ(cookie.size(), static_cast <size_t> (asked[0].body[2]));
		// Тело повторного приветствия с меткой
		vector <uint8_t> repeated;
		// Составляем приветствие с меткой
		ASSERT_TRUE(greeting(cookie, DTLS12, repeated));
		// Повторное приветствие в обвязке DTLS номером один
		const vector <uint8_t> hello = framed(handshake::type_t::CLIENT, repeated, 1);
		// Дейтаграмма с повторным приветствием
		const vector <uint8_t> second = plain(handshake::type_t::CLIENT, repeated, 1, 1);
		// Подаём повторное приветствие
		ASSERT_EQ(server.push(view_t(second.data(), second.size())), context::error_t::NONE) << static_cast <int> (server.alert().description);
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Снимаем залп
		ASSERT_TRUE(drain(server, flight));
		// Сообщения залпа
		vector <taken_t> messages;
		// Снимаем сообщения
		ASSERT_TRUE(harvest(flight, messages));
		// Приветствие, цепочка, обмен ключами и конец приветствия
		ASSERT_EQ(messages.size(), static_cast <size_t> (4));
		// Приветствие сервера номером один
		ASSERT_EQ(messages[0].type, handshake::type_t::SERVER);
		// Раздел 4.2.2 RFC 6347: за просьбой приветствие сервера идёт номером один
		ASSERT_EQ(messages[0].sequence, 1);
		// Цепочка
		ASSERT_EQ(messages[1].type, handshake::type_t::CERTIFICATE);
		// Обмен ключами сервера
		ASSERT_EQ(messages[2].type, handshake::type_t::AGREEMENT);
		// Конец приветствия
		ASSERT_EQ(messages[3].type, handshake::type_t::DONE);
		// Номер конца приветствия
		ASSERT_EQ(messages[3].sequence, 4);
		// Переписка в обвязке DTLS: повторное приветствие и залп сервера
		vector <uint8_t> transcript(hello);
		/**
		 * Выполняем перенос сообщений залпа в переписку
		 */
		for(size_t i = 0; i < messages.size(); i++)
			// Добавляем сообщение в обвязке DTLS
			transcript.insert(transcript.end(), messages[i].framed.begin(), messages[i].framed.end());
		// Случайное значение сервера: издание и случайное значение
		const vector <uint8_t> serverRandom(messages[0].body.begin() + 2, messages[0].body.begin() + 2 + 32);
		// Случайное значение клиента: байты 0…31
		vector <uint8_t> clientRandom(32, 0);
		/**
		 * Выполняем заполнение случайного значения клиента
		 */
		for(size_t i = 0; i < 32; i++)
			// Записываем байт
			clientRandom[i] = static_cast <uint8_t> (i);
		// Обмен ключами сервера: именованная кривая X25519
		ASSERT_EQ(messages[2].body[0], 0x03);
		// Старший байт кривой
		ASSERT_EQ(messages[2].body[1], 0x00);
		// Младший байт кривой
		ASSERT_EQ(messages[2].body[2], 0x1D);
		// Длина точки
		ASSERT_EQ(messages[2].body[3], 32);
		// Точка сервера
		const view_t serverPoint(messages[2].body.data() + 4, 32);
		// Секретный ключ поддельного клиента
		vector <uint8_t> secret(agreement::X25519_SIZE, 0x11);
		// Открытая часть
		uint8_t opened[agreement::X25519_SIZE];
		// Вырабатываем открытую часть
		ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), opened));
		// Общее значение
		uint8_t premaster[agreement::X25519_SIZE];
		// Вырабатываем общее значение
		ASSERT_TRUE(agreement::x25519(view_t(secret.data(), secret.size()), serverPoint, premaster));
		// Тело обмена ключами клиента
		vector <uint8_t> exchange = {static_cast <uint8_t> (agreement::X25519_SIZE)};
		// Добавляем точку
		exchange.insert(exchange.end(), opened, opened + sizeof(opened));
		// Обмен ключами клиента в обвязке DTLS номером два
		const vector <uint8_t> premastering = framed(handshake::type_t::PREMASTER, exchange, 2);
		// Добавляем обмен в переписку
		transcript.insert(transcript.end(), premastering.begin(), premastering.end());
		// Переписка круга
		vector <uint8_t> counted;
		// Если круг с просьбой и первым приветствием в переписке
		if(item == 2){
			// Первое приветствие
			counted = initial;
			// Просьба
			counted.insert(counted.end(), asked[0].framed.begin(), asked[0].framed.end());
			// Остальное
			counted.insert(counted.end(), transcript.begin(), transcript.end());
		// Если круг с обвязкой TLS
		} else if(item == 3){
			// Смещение сообщения
			size_t offset = 0;
			/**
			 * Выполняем переложение переписки в обвязку TLS: вид, длина и тело без номера, смещения и длины куска
			 */
			while(offset < transcript.size()){
				// Обвязка куска
				datagram::fragment_t fragment;
				// Разбираем обвязку
				ASSERT_EQ(datagram::parse(view_t(transcript.data() + offset, transcript.size() - offset), fragment), datagram::error_t::NONE);
				// Вид и длина
				counted.insert(counted.end(), transcript.begin() + offset, transcript.begin() + offset + 4);
				// Тело
				counted.insert(counted.end(), transcript.begin() + offset + datagram::DATAGRAM_FRAGMENT_HEADER, transcript.begin() + offset + datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
				// Сдвигаем смещение
				offset += (datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
			}
		// Прочие круги: переписка по букве раздела 4.2.6 RFC 6347
		} else counted = transcript;
		// Хеш переписки
		uint8_t session[32];
		// Вычисляем хеш переписки
		ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(counted.data(), counted.size()), session, sizeof(session)));
		// Метка расширенного главного секрета
		const char * extended = "extended master secret";
		// Главный секрет
		uint8_t master[48];
		// Раздел 4 RFC 7627: главный секрет
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(premaster, sizeof(premaster)), view_t(reinterpret_cast <const uint8_t *> (extended), ::strlen(extended)), view_t(session, sizeof(session)), master, sizeof(master)));
		// Затравка ключевого материала
		vector <uint8_t> seed(serverRandom);
		// Добавляем случайное значение клиента
		seed.insert(seed.end(), clientRandom.begin(), clientRandom.end());
		// Метка ключевого материала
		const char * expansion = "key expansion";
		// Ключевой материал: ключи по 16 байтов и соли по 4 байта обеих сторон
		uint8_t material[(16 + 4) * 2];
		// Раздел 6.3 RFC 5246: ключевой материал
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (expansion), ::strlen(expansion)), view_t(seed.data(), seed.size()), material, sizeof(material)));
		// Метка завершения клиента
		const char * label = "client finished";
		// Завершение
		uint8_t completion[12];
		// Раздел 7.4.9 RFC 5246: завершение от главного секрета меткой стороны и хешем переписки
		ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(session, sizeof(session)), completion, sizeof(completion)));
		// На втором круге портим завершение
		if(item == 1)
			// Меняем один разряд
			completion[0] = static_cast <uint8_t> (completion[0] ^ 0x01);
		// Завершение в обвязке DTLS номером три
		const vector <uint8_t> finishing = framed(handshake::type_t::FINISHED, vector <uint8_t> (completion, completion + sizeof(completion)), 3);
		// Защита записей поддельного клиента: ключ клиента первым, соль клиента третьей
		protect::protection_t sealing;
		// Устанавливаем ключевой материал клиента
		ASSERT_TRUE(sealing.start(suite, view_t(material, 16), view_t(material + 32, 4)));
		// Дейтаграмма к серверу: обмен ключами, смена набора и завершение
		vector <uint8_t> wire = plain(handshake::type_t::PREMASTER, exchange, 2, 2);
		// Тело смены набора
		static const uint8_t change[1] = {0x01};
		// Запись смены набора номером три
		enclose(record::type_t::CHANGE, 0, 3, sizeof(change), wire);
		// Добавляем тело смены
		wire.insert(wire.end(), change, change + sizeof(change));
		// Защищённое содержимое завершения
		vector <uint8_t> sealed;
		// Раздел 4.1.2.1 RFC 6347: номер записи в связанных данных - пора один и номер ноль
		ASSERT_EQ(sealing.wrap((static_cast <uint64_t> (1) << 48), record::version_t::DTLS12, record::type_t::HANDSHAKE, view_t(finishing.data(), finishing.size()), sealed), protect::error_t::NONE);
		// Запись завершения первой порой номером ноль
		enclose(record::type_t::HANDSHAKE, 1, 0, sealed.size(), wire);
		// Добавляем защищённое содержимое
		wire.insert(wire.end(), sealed.begin(), sealed.end());
		// Итог подачи дейтаграммы
		const context::error_t outcome = server.push(view_t(wire.data(), wire.size()));
		// Если завершение верное
		if(item == 0){
			// Сервер принял завершение: выработка сошлась с движком
			ASSERT_EQ(outcome, context::error_t::NONE) << static_cast <int> (server.alert().description);
			// Связь установлена
			ASSERT_TRUE(server.established());
			// Последний залп сервера: смена набора и завершение, часов нет
			ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
			// Залп сервера
			vector <vector <uint8_t>> last;
			// Снимаем залп
			ASSERT_TRUE(drain(server, last));
			// Две дейтаграммы: смена набора нулевой порой и завершение первой - поры в одной дейтаграмме не смешиваются
			ASSERT_EQ(last.size(), static_cast <size_t> (2));
			// Поля заголовка
			uint8_t type = 0;
			// Издание
			uint16_t version = 0;
			// Пора
			uint16_t epoch = 0;
			// Номер
			uint64_t sequence = 0;
			// Длина
			size_t size = 0;
			// Первая запись - смена набора нулевой порой
			ASSERT_TRUE(heading(last[0], 0, type, version, epoch, sequence, size));
			// Смена набора
			ASSERT_EQ(type, static_cast <uint8_t> (record::type_t::CHANGE));
			// Нулевая пора
			ASSERT_EQ(epoch, 0);
			// Единственный байт
			ASSERT_EQ(size, static_cast <size_t> (1));
			// Смена набора - единственная запись своей дейтаграммы
			ASSERT_EQ(last[0].size(), datagram::DATAGRAM_PLAIN_HEADER + 1);
			// Вторая дейтаграмма - завершение первой порой
			ASSERT_TRUE(heading(last[1], 0, type, version, epoch, sequence, size));
			// Рукопожатие
			ASSERT_EQ(type, static_cast <uint8_t> (record::type_t::HANDSHAKE));
			// Первая пора
			ASSERT_EQ(epoch, 1);
			// Номер записи нулевой
			ASSERT_EQ(sequence, static_cast <uint64_t> (0));
			// Защита чтения поддельного клиента: ключ сервера вторым, соль сервера четвёртой
			protect::protection_t opening;
			// Устанавливаем ключевой материал сервера
			ASSERT_TRUE(opening.start(suite, view_t(material + 16, 16), view_t(material + 36, 4)));
			// Открытое содержимое
			vector <uint8_t> content;
			// Снимаем защиту с завершения сервера своими ключами
			ASSERT_EQ(opening.unwrap((static_cast <uint64_t> (1) << 48), record::version_t::DTLS12, record::type_t::HANDSHAKE, view_t(last[1].data() + datagram::DATAGRAM_PLAIN_HEADER, size), content), protect::error_t::NONE);
			// Обвязка завершения сервера
			datagram::fragment_t fragment;
			// Разбираем обвязку
			ASSERT_EQ(datagram::parse(view_t(content.data(), content.size()), fragment), datagram::error_t::NONE);
			// Завершение сервера номером пять
			ASSERT_EQ(fragment.type, handshake::type_t::FINISHED);
			// Номер сообщения
			ASSERT_EQ(fragment.sequence, 5);
			// Переписка с завершением клиента
			counted.insert(counted.end(), finishing.begin(), finishing.end());
			// Хеш переписки
			ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(counted.data(), counted.size()), session, sizeof(session)));
			// Метка завершения сервера
			const char * mark = "server finished";
			// Ожидаемое завершение сервера
			uint8_t expected[12];
			// Считаем завершение сервера
			ASSERT_TRUE(digest::prf(digest::hash_t::SHA256, view_t(master, sizeof(master)), view_t(reinterpret_cast <const uint8_t *> (mark), ::strlen(mark)), view_t(session, sizeof(session)), expected, sizeof(expected)));
			// Завершение сервера сошлось с независимым расчётом
			ASSERT_EQ(vector <uint8_t> (content.begin() + datagram::DATAGRAM_FRAGMENT_HEADER, content.end()), vector <uint8_t> (expected, expected + sizeof(expected)));
		// Если завершение порчено при верных ключах
		} else if(item == 1){
			// Сервер отверг завершение несхождением
			ASSERT_EQ(outcome, context::error_t::COMPLETION) << item;
			// Извещение decrypt_error
			ASSERT_EQ(server.alert().description, alert::description_t::DECRYPT);
			// Сервер оборван
			ASSERT_EQ(server.state(), context::state_t::FAILED);
		/**
		 * Если переписка сочтена иначе: иной главный секрет даёт иные ключи, и запись
		 * завершения не вскрывается вовсе - раздел 4.1.2.1 RFC 6347 велит отбросить её молча
		 */
		} else {
			// Отказа нет: запись отброшена молча
			ASSERT_EQ(outcome, context::error_t::NONE) << item;
			// Связь не установлена
			ASSERT_FALSE(server.established()) << item;
			// Завершение отброшено порчей: ключи не сошлись
			ASSERT_EQ(server.discarded(datagram::reason_t::DAMAGE), static_cast <uint64_t> (1)) << item;
			// Сервер ждёт настоящего завершения
			ASSERT_EQ(server.state(), context::state_t::HANDSHAKE) << item;
		}
	}
}

/**
 * Проверка потерь: всякая третья дейтаграмма по направлению у залпов из двух дейтаграмм
 * (ECDSA без подлинности клиента), всякая четвёртая у залпов из трёх (RSA со взаимной
 * подлинностью: цепочка, смена набора и завершение своими дейтаграммами - лад с шагом три
 * терял бы одну и ту же дейтаграмму залпа всегда), половина по псевдослучайному ряду и
 * первый залп клиента целиком; рукопожатие идёт часами и повторной передачей залпов вместе
 * со сменой набора; потеря последнего залпа сервера лечится повтором завершения клиента по
 * его часам, а сервер своих часов на последний залп не ведёт
 */
TEST(Dtls12Test, Loss){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Подлинность RSA
	context::credential_t rsa;
	// Составляем подлинность RSA
	ASSERT_TRUE(identity("rsa2048", rsa));
	// Описания путей: шаг три, шаг четыре, ряд, первый залп целиком
	bond_t bonds[4];
	// Всякая третья
	bonds[0].period = 3;
	// Всякая четвёртая
	bonds[1].period = 4;
	/**
	 * Половина по ряду: зерно выбрано сходящимся - ряд постоянен, и при зерне 12345 он ронял
	 * каждую смену набора последнего залпа сервера все восемь попыток клиента, ибо повторяется
	 * залп лишь по защищённому завершению (решение 11 переноса), а не по всякому открытому куску
	 */
	bonds[2].seed = 29;
	// Первый залп клиента целиком
	bonds[3].initial = 1;
	/**
	 * Выполняем перебор путей
	 */
	for(size_t i = 0; i < 4; i++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Первый путь: ECDSA без подлинности клиента, прочие - RSA со взаимной подлинностью
		if(i == 0)
			// Настраиваем стороны без подлинности клиента
			arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Настраиваем стороны с подлинностью клиента
		else arrange(client, server, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, rsa, true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие с потерями
		converse(client, server, bonds[i], 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << "путь " << i << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Потери были
		ASSERT_GT(bonds[i].dropped, static_cast <size_t> (0)) << i;
		// Издание DTLS 1.2
		ASSERT_EQ(client.version(), TLS12);
		// Обмен данными без потерь
		bond_t clean;
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, clean)) << i;
	}
	// Потеря последнего залпа сервера
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, extension::group_t::SECP384R1, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь без потерь
		bond_t bond;
		// Приветствие, просьба, повторное приветствие
		ASSERT_TRUE(greet(client, server, bond));
		// Залп сервера клиенту
		ASSERT_TRUE(carry(server, client, bond, 1));
		// Залп клиента серверу: обмен ключами, смена набора, завершение
		ASSERT_TRUE(carry(client, server, bond, 0));
		// Сервер установил связь
		ASSERT_TRUE(server.established());
		// Клиент ждёт завершения сервера
		ASSERT_FALSE(client.established());
		// Часы клиента идут
		ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
		// Последний залп сервера часов не ждёт
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Последний залп сервера теряется
		vector <vector <uint8_t>> lost;
		// Снимаем и выбрасываем
		ASSERT_TRUE(drain(server, lost));
		// Залп был
		ASSERT_FALSE(lost.empty());
		// Часы клиента истекают
		ASSERT_EQ(client.elapsed(), context::error_t::NONE);
		// Клиент повторил залп
		ASSERT_GT(client.output().size, static_cast <size_t> (0));
		// Повтор доходит до сервера
		ASSERT_TRUE(carry(client, server, bond, 0));
		// Сервер повторил последний залп по повтору завершения
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		// Часов у сервера по-прежнему нет
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Повтор смены набора не оборвал сервер
		ASSERT_EQ(server.state(), context::state_t::ESTABLISHED);
		// Повтор доходит до клиента
		ASSERT_TRUE(carry(server, client, bond, 1));
		// Клиент установил связь
		ASSERT_TRUE(client.established()) << static_cast <int> (client.error());
		// Часы клиента остановлены
		ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
		// Повтор залпа клиента нарезан новыми номерами записей: окном не отброшен ничего
		ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
		// Открытый обмен ключами в повторе за ключами чтения отброшен PLAIN: залп повторён по защищённому завершению
		ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (1));
		// Иного не отброшено
		ASSERT_EQ(server.discarded(), static_cast <uint64_t> (1));
	}
}

/**
 * Проверка перестановки дейтаграмм переноса в обратном порядке и повтора всякой
 * дейтаграммы: рукопожатие сходится, повторы отбрасываются окном, а порядок сообщений
 * восстанавливается сборкой
 */
TEST(Dtls12Test, Reorder){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем два круга: переворот и повтор
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента и малым размером дейтаграммы ради многих дейтаграмм
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, extension::group_t::X25519, credential, true);
		// Малый размер дейтаграммы клиенту
		client.mtu(300);
		// Малый размер дейтаграммы серверу
		server.mtu(300);
		// Путь
		bond_t bond;
		// Переворот либо повтор
		if(item == 0)
			// Переворот порядка
			bond.reverse = true;
		// Повтор
		else bond.duplicate = true;
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << item << " отказы " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error()) << " извещения " << static_cast <int> (client.alert().description) << " " << static_cast <int> (server.alert().description) << " отбросы " << client.discarded() << " " << server.discarded() << " дейтаграммы " << bond.counters[0] << " " << bond.counters[1];
		// Дейтаграммы не длиннее 300
		ASSERT_LE(bond.largest, static_cast <size_t> (300));
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
		// Если дейтаграммы повторялись
		if(item == 1){
			// Повторы отброшены окном
			ASSERT_GT(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
			// Повторы отброшены окном клиентом
			ASSERT_GT(client.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
			/**
			 * Повтор первого приветствия рождает вторую просьбу о подтверждении адреса новым
			 * номером записи - клиент шлёт по ней приветствие заново, сервер по его повтору
			 * повторяет свой залп, а клиент - свой; открытые куски этого позднего повтора за
			 * ключами чтения сервера отбрасываются PLAIN (решение 11): залп повторяется лишь по
			 * защищённому завершению
			 */
			ASSERT_GT(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (0));
			// Иных отбросов нет
			ASSERT_EQ(server.discarded(), server.discarded(datagram::reason_t::REPLAY) + server.discarded(datagram::reason_t::COOKIE) + server.discarded(datagram::reason_t::PLAIN));
		}
	}
}

/**
 * Проверка дробления под размер дейтаграммы 300: цепочка RSA дробится на куски, дейтаграммы
 * не длиннее размера, записи одной дейтаграммы одной поры, рукопожатие сходится
 */
TEST(Dtls12Test, Mtu){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны с подлинностью клиента
	arrange(client, server, protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384, extension::group_t::SECP256R1, credential, true);
	// Размер дейтаграммы клиенту
	client.mtu(300);
	// Размер дейтаграммы серверу
	server.mtu(300);
	// Размер принят
	ASSERT_EQ(client.mtu(), static_cast <size_t> (300));
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond, 400);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Дейтаграммы не длиннее 300
	ASSERT_LE(bond.largest, static_cast <size_t> (300));
	// Дейтаграмм много: цепочка RSA раздроблена
	ASSERT_GT(bond.moved, static_cast <size_t> (10));
	// Ничего не отброшено
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
	// Ничего не отброшено клиентом
	ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0));
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
	// Длинные данные дробятся на записи по дейтаграммам
	const vector <uint8_t> bulk(5000, 0xAB);
	// Пишем данные, которые дробятся по записям в свои дейтаграммы
	ASSERT_EQ(client.write(view_t(bulk.data(), bulk.size())), context::error_t::NONE);
	// Переносим
	converse(client, server, bond, 400);
	// Принятые данные
	vector <uint8_t> received;
	// Читаем
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Данные дошли целиком
	ASSERT_EQ(received, bulk);
}

/**
 * Проверка окна повторов и порчи (разделы 4.1.2.1 и 4.1.2.6 RFC 6347): повтор дейтаграммы
 * с данными отбрасывается REPLAY, порченая запись - DAMAGE без извещения и обрыва, запись
 * неведомой поры - EPOCH, чужое издание в заголовке - VERSION, и 0xFEFF у защищённой записи
 * - тоже VERSION (оно дозволено лишь открытой записи рукопожатия), данные прочтены один раз
 */
TEST(Dtls12Test, Replay){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond, 400);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established());
	// Пишем данные, чей повтор будет отброшен окном
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("replay"), 6)), context::error_t::NONE);
	// Дейтаграмма с данными
	vector <vector <uint8_t>> data;
	// Снимаем дейтаграмму
	ASSERT_TRUE(drain(client, data));
	// Подаём дейтаграмму
	ASSERT_EQ(server.push(view_t(data[0].data(), data[0].size())), context::error_t::NONE);
	// Подаём дейтаграмму вновь
	ASSERT_EQ(server.push(view_t(data[0].data(), data[0].size())), context::error_t::NONE);
	// Повтор отброшен окном
	ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (1));
	// Принятые данные
	vector <uint8_t> received;
	// Читаем данные первой подачи дейтаграммы
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Данные прочтены один раз
	ASSERT_EQ(received.size(), static_cast <size_t> (6));
	// Отправляем ещё данные
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("damage"), 6)), context::error_t::NONE);
	// Дейтаграмма
	vector <vector <uint8_t>> next;
	// Снимаем
	ASSERT_TRUE(drain(client, next));
	// Портим байт шифртекста
	vector <uint8_t> damaged = next[0];
	// Меняем последний байт: метка целостности
	damaged.back() ^= 0x55;
	// Подаём порченую дейтаграмму
	ASSERT_EQ(server.push(view_t(damaged.data(), damaged.size())), context::error_t::NONE);
	// Порча отброшена молча
	ASSERT_EQ(server.discarded(datagram::reason_t::DAMAGE), static_cast <uint64_t> (1));
	// Извещения нет
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Связь не оборвана
	ASSERT_EQ(server.state(), context::state_t::ESTABLISHED);
	// Запись неведомой поры: пора два
	vector <uint8_t> foreign = next[0];
	// Ставим пору два
	foreign[4] = 0x02;
	// Подаём чужую запись серверу
	ASSERT_EQ(server.push(view_t(foreign.data(), foreign.size())), context::error_t::NONE);
	// Отброшено порой
	ASSERT_EQ(server.discarded(datagram::reason_t::EPOCH), static_cast <uint64_t> (1));
	// Чужое издание в заголовке
	vector <uint8_t> edition = next[0];
	// Издание 0x0303
	edition[1] = 0x03;
	// Младший байт
	edition[2] = 0x03;
	// Подаём запись иного издания серверу
	ASSERT_EQ(server.push(view_t(edition.data(), edition.size())), context::error_t::NONE);
	// Отброшено изданием
	ASSERT_EQ(server.discarded(datagram::reason_t::VERSION), static_cast <uint64_t> (1));
	// Издание DTLS 1.0 в заголовке защищённой записи: 0xFEFF дозволено лишь открытой записи рукопожатия
	vector <uint8_t> elder = next[0];
	// Младший байт издания
	elder[2] = 0xFF;
	// Подаём устаревшую запись серверу
	ASSERT_EQ(server.push(view_t(elder.data(), elder.size())), context::error_t::NONE);
	// Отброшено изданием до снятия защиты, а не порчей
	ASSERT_EQ(server.discarded(datagram::reason_t::VERSION), static_cast <uint64_t> (2));
	// Порча не приросла
	ASSERT_EQ(server.discarded(datagram::reason_t::DAMAGE), static_cast <uint64_t> (1));
	// Настоящая дейтаграмма принимается
	ASSERT_EQ(server.push(view_t(next[0].data(), next[0].size())), context::error_t::NONE);
	// Читаем данные настоящей дейтаграммы
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Данные дошли
	ASSERT_EQ(string(received.begin(), received.end()), "damage");
	// Общий счёт отбросов
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (5));
}

/**
 * Проверка смены набора шифрования не в свой черёд: у клиента, принявшего приветствие
 * сервера без остатка залпа, открытая смена набора (и с негодным телом) роняется молча -
 * раздел 4.1.2.7 RFC 6347, рукопожатие доходит до конца; у сервера до согласования издания смена отбрасывается молча
 * видом (DTLS 1.3 её не знает), а обогнавшая цепочку клиента ждёт своего черёда - залп
 * клиента в обратном порядке сходится
 */
TEST(Dtls12Test, Change){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	/**
	 * Выполняем два круга: смена до цепочки сервера и смена с негодным телом
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с малым размером дейтаграммы: приветствие сервера идёт своей дейтаграммой
		arrange(client, server, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, true);
		// Малый размер дейтаграммы серверу
		server.mtu(300);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Смена набора серверу до согласования издания отбрасывается видом: DTLS 1.3 её не знает
		vector <uint8_t> early;
		// Запись смены нулевой порой
		enclose(record::type_t::CHANGE, 0, 7, 1, early);
		// Тело
		early.push_back(0x01);
		// Подаём серверу
		ASSERT_EQ(server.push(view_t(early.data(), early.size())), context::error_t::NONE);
		// Отброшено видом
		ASSERT_EQ(server.discarded(datagram::reason_t::TYPE), static_cast <uint64_t> (1));
		// Приветствие, просьба, повторное приветствие
		ASSERT_TRUE(greet(client, server, bond));
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Снимаем залп
		ASSERT_TRUE(drain(server, flight));
		// Залп раздроблен на несколько дейтаграмм
		ASSERT_GT(flight.size(), static_cast <size_t> (1));
		// Подаём клиенту лишь первую: приветствие сервера и начало цепочки
		ASSERT_EQ(client.push(view_t(flight[0].data(), flight[0].size())), context::error_t::NONE);
		// Издание согласовано
		ASSERT_EQ(client.version(), TLS12);
		// Клиент ждёт цепочку
		ASSERT_FALSE(client.established());
		// Смена набора шифрования снаружи
		vector <uint8_t> change;
		// Запись смены нулевой порой номером девять
		enclose(record::type_t::CHANGE, 0, 9, 1, change);
		// Тело: единица либо негодная двойка
		change.push_back((item == 0) ? 0x01 : 0x02);
		// Подаём смену клиенту: открытая запись ничем не подписана и роняется молча (круг 7)
		ASSERT_EQ(client.push(view_t(change.data(), change.size())), context::error_t::NONE);
		// Клиент рукопожатия не прервал
		ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
		// Смена отброшена как открытая запись
		ASSERT_EQ(client.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (1));
		/**
		 * Остаток залпа сервера
		 */
		for(size_t i = 1; i < flight.size(); i++)
			// Подаём клиенту
			ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Рукопожатие доходит до конца
		ASSERT_TRUE(client.established() && server.established());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
	// Смена набора, обогнавшая цепочку клиента у сервера
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны со взаимной подлинностью
		arrange(client, server, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие, просьба, повторное приветствие
		ASSERT_TRUE(greet(client, server, bond));
		// Залп сервера клиенту
		ASSERT_TRUE(carry(server, client, bond, 1));
		// Залп клиента: цепочка с обменом и подписью, смена набора, завершение
		vector <vector <uint8_t>> flight;
		// Снимаем залп
		ASSERT_TRUE(drain(client, flight));
		// Три дейтаграммы
		ASSERT_EQ(flight.size(), static_cast <size_t> (3));
		// Вторая дейтаграмма - смена набора
		ASSERT_EQ(flight[1][0], static_cast <uint8_t> (record::type_t::CHANGE));
		/**
		 * Выполняем подачу залпа в обратном порядке: завершение, смена набора, цепочка
		 */
		for(size_t i = flight.size(); i > 0; i--)
			// Подаём дейтаграмму
			ASSERT_EQ(server.push(view_t(flight[i - 1].data(), flight[i - 1].size())), context::error_t::NONE) << i;
		// Сервер установил связь
		ASSERT_TRUE(server.established()) << static_cast <int> (server.error());
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
}

/**
 * Проверка согласования издания поверх дейтаграмм: клиент «только 1.3» против сервера
 * «только 1.2» - protocol_version у сервера; клиент «только 1.2» против сервера «только
 * 1.3» - protocol_version; пределы 1.2…1.3 с наборами обоих изданий сходятся на DTLS 1.3
 * (version() отдаёт 0x0304 единой шкалы); клиент «только 1.2» против сервера 1.2…1.3
 * сходится на DTLS 1.2 (0x0303); пределы «только 1.2» поверх дейтаграмм принимаются
 * заведением связи; просьба о подтверждении адреса у сервера - unexpected_message, а
 * повторные просьбы у клиента принимаются с новой меткой и приветствием номером один
 * (сервер, сменивший секрет метки) - но не более трёх, четвёртая - unexpected_message
 */
TEST(Dtls12Test, Versions){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Клиент «только 1.3» против сервера «только 1.2»
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий клиенту
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Клиент лишь 1.3
		ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер: пределы «только 1.2» поверх дейтаграмм дозволены
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие серверу
		ASSERT_TRUE(carry(client, server, bond, 0));
		// Сервер оборван изданием
		ASSERT_EQ(server.error(), context::error_t::VERSION);
		// Извещение protocol_version
		ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
		// Извещение клиенту
		ASSERT_TRUE(carry(server, client, bond, 1));
		// Клиент оборван извещением
		ASSERT_EQ(client.error(), context::error_t::ALERT);
	}
	// Клиент «только 1.2» против сервера «только 1.3»
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий серверу
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Сервер лишь 1.3
		ASSERT_EQ(server.versions(0x0304, 0x0304), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие серверу
		ASSERT_TRUE(carry(client, server, bond, 0));
		// Сервер оборван изданием
		ASSERT_EQ(server.error(), context::error_t::VERSION);
		// Извещение protocol_version
		ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
	}
	// Пределы 1.2…1.3 с наборами обоих изданий сходятся на DTLS 1.3
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий клиенту
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Наборы обоих изданий серверу
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Первая дейтаграмма клиента
		const view_t first = client.output();
		// Обвязка куска
		datagram::fragment_t fragment;
		// Разбираем обвязку
		ASSERT_EQ(datagram::parse(view_t(first.data + datagram::DATAGRAM_PLAIN_HEADER, first.size - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
		// Приветствие клиента
		hello::client_t greeting;
		// Разбираем приветствие
		ASSERT_EQ(hello::parse(view_t(first.data + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
		// Расширение изданий
		const hello::extension_t * versions = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Проверяем наличие
		ASSERT_NE(versions, nullptr);
		// Перечень изданий
		vector <uint16_t> editions;
		// Разбираем перечень
		ASSERT_EQ(extension::versions(versions->data, editions), extension::error_t::NONE);
		// Оба издания: DTLS 1.3 и DTLS 1.2
		ASSERT_EQ(editions, (vector <uint16_t> {datagram::DATAGRAM_VERSION, DTLS12}));
		// Путь
		bond_t bond;
		// Проводим рукопожатие
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Издание DTLS 1.3 у клиента: единая шкала, 0x0304 на любом переносе
		ASSERT_EQ(client.version(), TLS13);
		// Издание DTLS 1.3 у сервера
		ASSERT_EQ(server.version(), TLS13);
		// Набор издания 1.3
		ASSERT_EQ(client.suite(), protect::suite_t::AES_128_GCM_SHA256);
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
	// Клиент «только 1.2» против сервера 1.2…1.3 сходится на DTLS 1.2 без обрыва по заслону понижения
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий серверу
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Проводим рукопожатие
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Издание DTLS 1.2
		ASSERT_EQ(client.version(), TLS12);
		// Издание DTLS 1.2 у сервера
		ASSERT_EQ(server.version(), TLS12);
	}
	// Просьба о подтверждении адреса не к месту у сервера; повторные просьбы у клиента принимаются с новой меткой, но не более трёх
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Тело просьбы: издание и пустая метка
		const vector <uint8_t> body = {0xFE, 0xFF, 0x00};
		// Дейтаграмма с просьбой номером ноль
		const vector <uint8_t> query = plain(handshake::type_t::VERIFY_REQUEST, body, 0, 0);
		// Просьба серверу - не в свой черёд
		ASSERT_EQ(server.push(view_t(query.data(), query.size())), context::error_t::ORDER);
		// Извещение unexpected_message
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
		// Первое приветствие клиента
		vector <vector <uint8_t>> first;
		// Снимаем первое приветствие
		ASSERT_TRUE(drain(client, first));
		// Просьба клиенту с пустой меткой принимается: клиент издание не судит
		ASSERT_EQ(client.push(view_t(query.data(), query.size())), context::error_t::NONE);
		// Повторное приветствие
		vector <vector <uint8_t>> second;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, second));
		// Одна дейтаграмма
		ASSERT_EQ(second.size(), static_cast <size_t> (1));
		// Обвязка куска
		datagram::fragment_t fragment;
		// Приветствие клиента
		hello::client_t greeting;
		// Разбираем обвязку повторного приветствия
		ASSERT_EQ(datagram::parse(view_t(second[0].data() + datagram::DATAGRAM_PLAIN_HEADER, second[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
		// Раздел 4.2.2 RFC 6347: повторное приветствие идёт номером один
		ASSERT_EQ(fragment.sequence, 1);
		// Разбираем повторное приветствие
		ASSERT_EQ(hello::parse(view_t(second[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
		// Пустая метка повторена пустой
		ASSERT_TRUE(greeting.cookie.empty());
		// Тело второй просьбы: сервер сменил секрет и спрашивает заново новой меткой
		const vector <uint8_t> renewed = {0xFE, 0xFF, 0x02, 0xAB, 0xCD};
		// Вторая просьба: сервер без состояния шлёт её номером сообщения ноль вновь, номер записи растёт
		const vector <uint8_t> again = plain(handshake::type_t::VERIFY_REQUEST, renewed, 0, 1);
		// Вторая просьба принимается: переписка и метка заново
		ASSERT_EQ(client.push(view_t(again.data(), again.size())), context::error_t::NONE) << static_cast <int> (client.error());
		// Третье приветствие
		vector <vector <uint8_t>> third;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, third));
		// Одна дейтаграмма
		ASSERT_EQ(third.size(), static_cast <size_t> (1));
		// Поля заголовка
		uint8_t type = 0;
		// Издание
		uint16_t version = 0;
		// Пора
		uint16_t epoch = 0;
		// Номер
		uint64_t sequence = 0;
		// Длина
		size_t size = 0;
		// Читаем заголовок третьего приветствия
		ASSERT_TRUE(heading(third[0], 0, type, version, epoch, sequence, size));
		// Номер записи продвинут: окно нулевой поры живёт дальше
		ASSERT_EQ(sequence, static_cast <uint64_t> (2));
		// Разбираем обвязку
		ASSERT_EQ(datagram::parse(view_t(third[0].data() + datagram::DATAGRAM_PLAIN_HEADER, size), fragment), datagram::error_t::NONE);
		// Раздел 4.2.2 RFC 6347: приветствие в ответ на повторную просьбу идёт номером один вновь
		ASSERT_EQ(fragment.sequence, 1);
		// Разбираем третье приветствие
		ASSERT_EQ(hello::parse(view_t(third[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
		// Новая метка повторена дословно
		ASSERT_EQ(greeting.cookie, (vector <uint8_t> {0xAB, 0xCD}));
		// Тело третьей просьбы
		const vector <uint8_t> latest = {0xFE, 0xFF, 0x01, 0xEF};
		// Третья просьба номером записи два
		const vector <uint8_t> thrice = plain(handshake::type_t::VERIFY_REQUEST, latest, 0, 2);
		// Третья просьба принимается: предел - три
		ASSERT_EQ(client.push(view_t(thrice.data(), thrice.size())), context::error_t::NONE);
		// Четвёртое приветствие
		vector <vector <uint8_t>> fourth;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, fourth));
		// Разбираем обвязку
		ASSERT_EQ(datagram::parse(view_t(fourth[0].data() + datagram::DATAGRAM_PLAIN_HEADER, fourth[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
		// Разбираем четвёртое приветствие
		ASSERT_EQ(hello::parse(view_t(fourth[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
		// Последняя метка повторена
		ASSERT_EQ(greeting.cookie, vector <uint8_t> {0xEF});
		// Клиент жив
		ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
		// Четвёртая просьба - сверх предела: зацикливание
		const vector <uint8_t> excess = plain(handshake::type_t::VERIFY_REQUEST, latest, 0, 3);
		// Четвёртая просьба - не в свой черёд
		ASSERT_EQ(client.push(view_t(excess.data(), excess.size())), context::error_t::ORDER);
		// Извещение unexpected_message
		ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
		// Клиент оборван
		ASSERT_EQ(client.state(), context::state_t::FAILED);
	}
}

/**
 * Проверка обмена с настоящим openssl по UDP: наш клиент против s_server -dtls1_2 -listen с
 * просьбой о подтверждении адреса, взаимной подлинностью и дроблением по шести наборам и
 * трём группам; s_client -dtls1_2 против нашего сервера с нашей просьбой о подтверждении
 * адреса («Protocol  : DTLSv1.2», «Verify return code: 0 (ok)») по тем же наборам и группам -
 * дважды: с -mtu 300 и с умолчанием openssl, дробящим повторное приветствие (решение 13)
 */
TEST(Dtls12Test, Openssl){
	// Способности системного openssl
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl без DTLS 1.2
	if(!toolkit.dtls12 || !toolkit.listening){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без DTLS 1.2 либо без -listen";
	}
	/**
	 * Выполняем перебор наборов шифрования: наш клиент против s_server
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Если набор недоступен openssl
		if(shell(std::string("openssl ciphers -s -tls1_2 ") + SUITES[s].title + " >/dev/null 2>&1") != 0){
			// Сообщаем о пропуске вслух
			std::cout << "openssl без " << SUITES[s].title << ": сличение пропущено" << std::endl;
			// Переходим к следующему набору
			continue;
		}
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(SUITES[s].key, credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/" + SUITES[s].key + ".crt", key = std::string(CORPUS) + "/" + SUITES[s].key + ".pem";
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
			// Если openssl без кривой X25519
			if((GROUPS[g] == extension::group_t::X25519) && !toolkit.x25519){
				// Сообщаем о пропуске вслух
				std::cout << "openssl без X25519: сличение по группе пропущено" << std::endl;
				// Переходим к следующей группе
				continue;
			}
			// Свободный порт UDP
			const uint16_t number = vacant(true);
			// Проверяем порт
			ASSERT_NE(number, 0);
			// Журнал сервера openssl
			const std::string log = "/tmp/ants-dtls12-server-" + std::to_string(number) + ".log";
			// Ключ групп
			const std::string grouping = ((toolkit.serverGroups && toolkit.clientGroups) ? (" -groups " + roster(GROUPS[g])) : "");
			// Именованный канал входа сервера openssl: по концу входа сервер уходит, и вход держится каналом, а не паузой
			const std::string holder = "/tmp/ants-dtls12-server-" + std::to_string(number) + ".fifo";
			// Убираем канал, оставшийся от прежнего прогона
			::remove(holder.c_str());
			// Заводим именованный канал
			ASSERT_EQ(fifo(holder.c_str()), 0);
			/**
			 * Сервер openssl: DTLS 1.2, приём приветствия с меткой (-listen), взаимная
			 * подлинность, дробление под 300 байтов, без билетов; вход держится открытым
			 * именованным каналом до снятия сервера сторожем, а -www с DTLS ему не дозволен;
			 * итог судится по состоянию: подъём по «ACCEPT» в журнале, принятые данные по журналу
			 */
			ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1_2 -listen -no_ticket -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -cipher " + SUITES[s].title + grouping + " -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
			// Сторож сервера openssl
			sentinel_t sentinel(log + ".pid");
			// Журнал
			std::string text;
			// Ждём подъёма сервера
			ASSERT_TRUE(awaited(log, "ACCEPT", text)) << text;
			// Порт своего сокета
			uint16_t bound = 0;
			// Свой сокет UDP
			const int fd = socketing(0, bound);
			// Проверяем сокет
			ASSERT_GE(fd, 0);
			// Адрес сервера
			struct sockaddr_in peer;
			// Обнуляем адрес
			::memset(&peer, 0, sizeof(peer));
			// Семейство
			peer.sin_family = AF_INET;
			// Петлевое устройство
			peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			// Порт сервера
			peer.sin_port = htons(number);
			// Связь стороны клиента
			client::context_t client;
			// Перенос дейтаграммами
			client.transport(context::transport_t::DATAGRAMS);
			// Набор
			client.suites(vector <protect::suite_t> {SUITES[s].suite});
			// Группы: обмен первой, кривые сертификатов следом
			client.groups(vector <extension::group_t> {GROUPS[g], extension::group_t::SECP256R1, extension::group_t::SECP384R1});
			// Подлинность клиента
			client.credential(credential);
			// Размер дейтаграммы
			client.mtu(300);
			// Имя узла
			client.name("localhost");
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Ведём связь до установления
			const bool complete = relay(client, fd, peer, 400);
			// Связь установлена
			ASSERT_TRUE(complete) << SUITES[s].title << " " << naming(GROUPS[g]) << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
			// Издание DTLS 1.2
			ASSERT_EQ(client.version(), TLS12);
			// Набор
			ASSERT_EQ(client.suite(), SUITES[s].suite);
			// Цепочка сервера
			ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
			// Просьба о подтверждении адреса была: ничего не отброшено
			ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0));
			// Данные серверу
			const string request = "ants over dtls " + std::to_string(s) + " " + std::to_string(g) + "\n";
			// Пишем запрос серверу openssl поверх установленной связи DTLS 1.2
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
			// Отправляем дейтаграммы
			relay(client, fd, peer, 1);
			// Сервер печатает принятое в журнал
			ASSERT_TRUE(awaited(log, request, text)) << text;
			// Набор в журнале сервера
			ASSERT_NE(text.find(std::string("CIPHER is ") + SUITES[s].title), std::string::npos) << text;
			// Закрываем связь
			ASSERT_EQ(client.close(), context::error_t::NONE);
			// Отправляем извещение
			relay(client, fd, peer, 1);
			// Закрываем сокет
			closing(fd);
			// Снимаем сервер
			sentinel.halt();
			// Дожидаемся отметки завершения
			(void) settle(log, text);
			// Удаляем журнал
			::remove(log.c_str());
			// Удаляем именованный канал
			::remove(holder.c_str());
		}
	}
	/**
	 * Выполняем перебор наборов шифрования: s_client против нашего сервера
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Если набор недоступен openssl
		if(shell(std::string("openssl ciphers -s -tls1_2 ") + SUITES[s].title + " >/dev/null 2>&1") != 0)
			// Переходим к следующему набору
			continue;
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(SUITES[s].key, credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/" + SUITES[s].key + ".crt", key = std::string(CORPUS) + "/" + SUITES[s].key + ".pem";
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t g = 0; g < (2 * (sizeof(GROUPS) / sizeof(GROUPS[0]))); g++){
			// Группа обмена: первый проход по группам с -mtu 300, второй - с умолчанием openssl
			const extension::group_t group = GROUPS[g % (sizeof(GROUPS) / sizeof(GROUPS[0]))];
			/**
			 * Признак прохода с умолчанием openssl без -mtu: клиент дробит повторное приветствие
			 * умолчанием (начальный MTU 256, тело 232 байта кусками 203 + 29) - ровно случай, на
			 * котором строгий сервер молчал; сервер умолчанием собирает (решение 13 переноса).
			 * Наборы и группы клиенту не задаются: с одним набором приветствие короче порога
			 * дробления и случай не воспроизводится - сервер выбирает свой набор из предложенных
			 */
			const bool fragmenting = (g >= (sizeof(GROUPS) / sizeof(GROUPS[0])));
			// Если openssl без кривой X25519
			if((group == extension::group_t::X25519) && !toolkit.x25519)
				// Переходим к следующей группе
				continue;
			// Порт сервера
			uint16_t number = 0;
			// Свой сокет UDP на свободном порту
			const int fd = socketing(0, number);
			// Проверяем сокет
			ASSERT_GE(fd, 0);
			// Журнал клиента openssl
			const std::string log = "/tmp/ants-dtls12-client-" + std::to_string(number) + ".log";
			// Ключ групп
			const std::string grouping = ((toolkit.serverGroups && toolkit.clientGroups) ? (" -groups " + roster(group)) : "");
			// Данные клиента openssl
			const string request = "hello from openssl " + std::to_string(s) + " " + std::to_string(g) + "\n";
			/**
			 * Клиент openssl: DTLS 1.2, своя подлинность, дробление под 300 байтов либо умолчание; на входе
			 * данные, а конец входа не глушит клиента (-ign_eof) - уходит он по close_notify
			 * нашего сервера, и ожидание идёт по состоянию, а не по паузе
			 */
			ASSERT_TRUE(launch("printf '" + request + "' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -dtls1_2 -CAfile " + crt + " -cert " + crt + " -key " + key + (fragmenting ? std::string() : (" -cipher " + std::string(SUITES[s].title) + grouping + " -mtu 300")) + " -servername localhost -verify_return_error -ign_eof >" + log + " 2>&1", log, log + ".pid", std::string()));
			// Сторож клиента openssl
			sentinel_t sentinel(log + ".pid");
			// Адрес клиента
			struct sockaddr_in peer;
			// Длина адреса
			socklen_t length = sizeof(peer);
			// Место принятой дейтаграммы
			uint8_t buffer[65536];
			// Принятая дейтаграмма
			ssize_t received = -1;
			/**
			 * Выполняем ожидание первого приветствия клиента
			 */
			for(size_t i = 0; (i < 150) && (received <= 0); i++)
				// Принимаем дейтаграмму с адресом
				received = receivingfrom(fd, buffer, sizeof(buffer), reinterpret_cast <struct sockaddr *> (&peer), &length);
			// Приветствие принято
			ASSERT_GT(received, 0) << SUITES[s].title << " " << naming(group);
			// Связь стороны сервера
			server::context_t server;
			// Перенос дейтаграммами
			server.transport(context::transport_t::DATAGRAMS);
			// Набор
			server.suites(vector <protect::suite_t> {SUITES[s].suite});
			// Группа
			server.groups(vector <extension::group_t> {group});
			// Подлинность сервера
			server.credential(credential);
			// Запрашиваем подлинность клиента
			server.request(true);
			// Размер дейтаграммы
			server.mtu(300);
			// Адрес собеседника для метки: порт и адрес
			ASSERT_TRUE(server.address(view_t(reinterpret_cast <const uint8_t *> (&peer), sizeof(peer))));
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Подаём первое приветствие
			server.push(view_t(buffer, static_cast <size_t> (received)));
			// Принятые данные
			vector <uint8_t> plaintext;
			/**
			 * Выполняем перенос дейтаграмм до приёма данных, закрытия либо обрыва связи
			 */
			for(size_t i = 0; (i < 400) && (server.state() != context::state_t::FAILED) && (server.state() != context::state_t::CLOSED) && plaintext.empty(); i++){
				/**
				 * Выполняем отправку готовых дейтаграмм
				 */
				while(server.output().size > 0){
					// Дейтаграмма
					const view_t data = server.output();
					// Отправляем клиенту
					(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), length);
					// Снимаем
					server.consume(data.size);
				}
				// Принимаем дейтаграмму
				received = receiving(fd, buffer, sizeof(buffer));
				// Если принята
				if(received > 0)
					// Подаём серверу
					server.push(view_t(buffer, static_cast <size_t> (received)));
				// Если ожидание истекло, а часы идут
				else if(server.timeout() > 0)
					// Извещаем об истечении срока
					server.elapsed();
				// Если связь установлена
				if(server.established())
					// Читаем прикладные данные клиента openssl
					(void) server.read(plaintext);
			}
			// Связь установлена
			ASSERT_TRUE(server.established()) << SUITES[s].title << " " << naming(group) << (fragmenting ? " умолчание" : " mtu300") << " отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description) << " состояние " << static_cast <int> (server.state());
			// Данные клиента дошли
			ASSERT_EQ(string(plaintext.begin(), plaintext.end()), request);
			// Издание DTLS 1.2
			ASSERT_EQ(server.version(), TLS12);
			// Набор
			ASSERT_EQ(server.suite(), SUITES[s].suite);
			// Подлинность клиента
			ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
			// Ответ клиенту
			const string answer = "ants server over dtls\n";
			// Отправляем ответ
			ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::NONE);
			// Закрываем связь
			ASSERT_EQ(server.close(), context::error_t::NONE);
			/**
			 * Выполняем отправку ответа и извещения
			 */
			while(server.output().size > 0){
				// Дейтаграмма
				const view_t data = server.output();
				// Отправляем клиенту
				(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), length);
				// Снимаем
				server.consume(data.size);
			}
			// Закрываем сокет
			closing(fd);
			// Текст журнала
			std::string text;
			// Клиент обязан завершиться
			ASSERT_TRUE(settle(log, text)) << text;
			// Подлинность сервера сошлась
			ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
			// Издание DTLS 1.2
			ASSERT_NE(text.find("Protocol  : DTLSv1.2"), std::string::npos) << text;
			// Набор тот же
			ASSERT_NE(text.find(std::string("Cipher    : ") + SUITES[s].title), std::string::npos) << text;
			// Ответ дошёл клиенту
			ASSERT_NE(text.find(answer), std::string::npos) << text;
			// Удаляем журнал
			::remove(log.c_str());
		}
	}
}

/**
 * Проверка сервера до подтверждения адреса (разделы 4.1.2.7 и 4.2.1 RFC 6347): усечённое,
 * порченое и мусорное первое приветствие отбрасываются молча GREETING без единой
 * дейтаграммы наружу и без обрыва, следующее настоящее приветствие отвечается просьбой;
 * строгий сервер без состояния (strict, решение 13 переноса) принимает приветствие лишь
 * целиком одним куском - сто дроблёных и чужих кусков и запись первой поры отбрасываются без
 * сборок, отложенных записей и ответа;
 * по принятой метке запись повторного приветствия отмечается в окне нулевой поры - повтор
 * её REPLAY без второго залпа; окно нулевой поры у клиента: повтор просьбы - REPLAY без
 * второго приветствия; приветствие с изданием 0x0303, 0xFEFF (DTLS 1.0) и 0x0000 в
 * заголовке - protocol_version
 */
TEST(Dtls12Test, Unverified){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Порченые приветствия и сервер без состояния
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Строгий сервер: прежняя семантика решения 9 - приветствие лишь целиком, сборок не заводится (решение 13)
		server.strict(true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Тело настоящего первого приветствия поддельного клиента
		vector <uint8_t> body;
		// Составляем приветствие
		ASSERT_TRUE(greeting(vector <uint8_t> (), DTLS12, body));
		// Усечённое приветствие: половина тела
		const vector <uint8_t> truncated(body.begin(), body.begin() + (body.size() / 2));
		// Дейтаграмма с усечённым приветствием
		const vector <uint8_t> cut = plain(handshake::type_t::CLIENT, truncated, 0, 0);
		// Подаём усечённое приветствие
		ASSERT_EQ(server.push(view_t(cut.data(), cut.size())), context::error_t::NONE);
		// Ни одной дейтаграммы наружу
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Сервер не оборван
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Отброшено приветствием
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (1));
		// Порченое приветствие: длина расширений врёт - последний байт снят
		const vector <uint8_t> damaged(body.begin(), body.end() - 1);
		// Дейтаграмма с порченым приветствием
		const vector <uint8_t> broken = plain(handshake::type_t::CLIENT, damaged, 0, 1);
		// Подаём порченое приветствие
		ASSERT_EQ(server.push(view_t(broken.data(), broken.size())), context::error_t::NONE);
		// Отброшено приветствием
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (2));
		// Мусор вместо приветствия
		const vector <uint8_t> garbage = plain(handshake::type_t::CLIENT, vector <uint8_t> {0xFF, 0x00, 0x11}, 0, 2);
		// Подаём мусор
		ASSERT_EQ(server.push(view_t(garbage.data(), garbage.size())), context::error_t::NONE);
		// Отброшено приветствием
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (3));
		// Приветствие без нулевого способа сжатия: способ единица
		vector <uint8_t> compressed(body);
		// Тело сжатия лежит перед расширениями: способ - единственный байт после длины 0x01
		const size_t methods = (2 + hello::HELLO_RANDOM + 1 + hello::HELLO_SESSION + 1 + 2 + 2 + 1);
		// Длина перечня способов равна одному
		ASSERT_EQ(compressed[methods - 1], 0x01);
		// Способ нулевой
		ASSERT_EQ(compressed[methods], 0x00);
		// Ставим способ единица
		compressed[methods] = 0x01;
		// Дейтаграмма с приветствием без нулевого сжатия
		const vector <uint8_t> squeezed = plain(handshake::type_t::CLIENT, compressed, 0, 3);
		// Подаём приветствие
		ASSERT_EQ(server.push(view_t(squeezed.data(), squeezed.size())), context::error_t::NONE);
		// Отброшено приветствием, а не illegal_parameter
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (4));
		// Сервер молчит и жив
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Состояние не тронуто
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Часов нет
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Настоящее первое приветствие клиента
		vector <vector <uint8_t>> first;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, first));
		// Подаём настоящее приветствие
		ASSERT_EQ(server.push(view_t(first[0].data(), first[0].size())), context::error_t::NONE);
		// Просьба о подтверждении адреса
		vector <vector <uint8_t>> query;
		// Снимаем просьбу
		ASSERT_TRUE(drain(server, query));
		// Одна дейтаграмма
		ASSERT_EQ(query.size(), static_cast <size_t> (1));
		// Просьба о подтверждении адреса
		ASSERT_EQ(query[0][datagram::DATAGRAM_PLAIN_HEADER], static_cast <uint8_t> (handshake::type_t::VERIFY_REQUEST));
		// Порядковый номер записи мусора: сервер без состояния
		uint64_t record = 10;
		/**
		 * Выполняем подачу сотни дроблёных и чужих кусков серверу без состояния
		 */
		for(size_t i = 0; i < 100; i++){
			// Обвязка куска
			datagram::fragment_t fragment;
			// Чётные - половина приветствия клиента номером один, нечётные - кусок чужой цепочки номером пять
			fragment.type = (((i % 2) == 0) ? handshake::type_t::CLIENT : handshake::type_t::CERTIFICATE);
			// Длина целого сообщения
			fragment.size = body.size();
			// Порядковый номер сообщения
			fragment.sequence = static_cast <uint16_t> (((i % 2) == 0) ? 1 : 5);
			// Смещение куска: первая либо вторая половина
			fragment.offset = (((i % 4) < 2) ? 0 : (body.size() / 2));
			// Длина куска: половина
			fragment.length = (body.size() / 2);
			// Кусок в обвязке
			vector <uint8_t> content(datagram::DATAGRAM_FRAGMENT_HEADER, 0);
			// Записываем обвязку
			ASSERT_EQ(datagram::build(fragment, content.data()), datagram::error_t::NONE);
			// Добавляем половину тела
			content.insert(content.end(), body.begin() + fragment.offset, body.begin() + fragment.offset + fragment.length);
			// Дейтаграмма
			vector <uint8_t> piece;
			// Записываем заголовок
			enclose(record::type_t::HANDSHAKE, 0, record++, content.size(), piece);
			// Добавляем содержимое
			piece.insert(piece.end(), content.begin(), content.end());
			// Подаём кусок
			ASSERT_EQ(server.push(view_t(piece.data(), piece.size())), context::error_t::NONE) << i;
			// Отброшено приветствием: сборок не заводится
			ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (5 + i)) << i;
			// Ответа нет
			ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << i;
		}
		// Запись первой поры до метки: отложить некуда - EPOCH
		vector <uint8_t> early;
		// Заголовок защищённой записи первой поры
		enclose(record::type_t::HANDSHAKE, 1, 0, 40, early);
		// Содержимое: сорок байтов
		early.insert(early.end(), 40, 0x5A);
		// Подаём запись
		ASSERT_EQ(server.push(view_t(early.data(), early.size())), context::error_t::NONE);
		// Отброшено порой, не отложено
		ASSERT_EQ(server.discarded(datagram::reason_t::EPOCH), static_cast <uint64_t> (1));
		// Сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Часов нет
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Сервер жив
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Подаём просьбу клиенту
		ASSERT_EQ(client.push(view_t(query[0].data(), query[0].size())), context::error_t::NONE);
		// Повторное приветствие
		vector <vector <uint8_t>> second;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, second));
		// Одна дейтаграмма
		ASSERT_EQ(second.size(), static_cast <size_t> (1));
		// Повтор просьбы клиенту: окно нулевой поры клиента
		ASSERT_EQ(client.push(view_t(query[0].data(), query[0].size())), context::error_t::NONE);
		// Повтор отброшен окном
		ASSERT_EQ(client.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (1));
		// Второго приветствия нет
		ASSERT_EQ(client.output().size, static_cast <size_t> (0));
		// Подаём повторное приветствие серверу
		ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Снимаем залп
		ASSERT_TRUE(drain(server, flight));
		// Залп есть
		ASSERT_FALSE(flight.empty());
		// Повтор повторного приветствия: запись отмечена в окне по принятой метке
		ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
		// Повтор отброшен окном
		ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (1));
		// Второго залпа нет
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Путь
		bond_t bond;
		/**
		 * Выполняем доставку залпа сервера клиенту
		 */
		for(size_t i = 0; i < flight.size(); i++)
			// Подаём дейтаграмму
			ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
	// Издание заголовка приветствия
	{
		// Издания заголовка: TLS 1.2, DTLS 1.0 и ноль
		static const uint16_t EDITIONS[] = {0x0303, DTLS10, 0x0000};
		/**
		 * Выполняем перебор изданий заголовка
		 */
		for(size_t i = 0; i < (sizeof(EDITIONS) / sizeof(EDITIONS[0])); i++){
			// Связь стороны сервера
			server::context_t server;
			// Заглушка клиента
			client::context_t dummy;
			// Настраиваем сервер
			arrange(dummy, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Тело приветствия с чужим изданием заголовка
			vector <uint8_t> body;
			// Составляем приветствие
			ASSERT_TRUE(greeting(vector <uint8_t> (), EDITIONS[i], body));
			// Дейтаграмма
			const vector <uint8_t> first = plain(handshake::type_t::CLIENT, body, 0, 0);
			// Раздел 4.1 RFC 6347: издание заголовка ниже DTLS 1.2 - protocol_version
			ASSERT_EQ(server.push(view_t(first.data(), first.size())), context::error_t::VERSION) << i;
			// Извещение protocol_version
			ASSERT_EQ(server.alert().description, alert::description_t::VERSION) << i;
			// Сервер оборван
			ASSERT_EQ(server.state(), context::state_t::FAILED) << i;
		}
	}
}

/**
 * Проверка усиления (раздел 4.2.1 RFC 6347): просьба о подтверждении адреса короче
 * наименьшего приветствия клиента - метка издания 1.2 несёт лишь поколение и имитовставку
 * (33 байта); порченая метка, метка чужого поколения и метка длины издания 1.3 - COOKIE
 */
TEST(Dtls12Test, Amplification){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Наименьшее приветствие клиента: без расширений и опознавателя, один набор
	hello::client_t hello;
	// Издание DTLS 1.2
	hello.version = DTLS12;
	/**
	 * Выполняем заполнение случайного значения
	 */
	for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
		// Записываем очередной байт
		hello.random[i] = static_cast <uint8_t> (0xA0 + i);
	// Один набор шифрования
	hello.suites = {static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256)};
	// Нулевой способ сжатия
	hello.methods = {0x00};
	// Тело наименьшего приветствия
	vector <uint8_t> body;
	// Составляем приветствие поверх дейтаграмм
	ASSERT_EQ(hello::build(hello, body, true), hello::error_t::NONE);
	// Дейтаграмма с наименьшим приветствием
	const vector <uint8_t> least = plain(handshake::type_t::CLIENT, body, 0, 0);
	// Наименьшее приветствие: 69 байтов
	ASSERT_EQ(least.size(), static_cast <size_t> (69));
	// Подаём наименьшее приветствие
	ASSERT_EQ(server.push(view_t(least.data(), least.size())), context::error_t::NONE);
	// Просьба о подтверждении адреса
	vector <vector <uint8_t>> query;
	// Снимаем просьбу
	ASSERT_TRUE(drain(server, query));
	// Одна дейтаграмма
	ASSERT_EQ(query.size(), static_cast <size_t> (1));
	// Просьба короче наименьшего приветствия: усиления нет
	ASSERT_LT(query[0].size(), least.size());
	// Обвязка куска
	datagram::fragment_t fragment;
	// Разбираем обвязку
	ASSERT_EQ(datagram::parse(view_t(query[0].data() + datagram::DATAGRAM_PLAIN_HEADER, query[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
	// Просьба о подтверждении адреса
	ASSERT_EQ(fragment.type, handshake::type_t::VERIFY_REQUEST);
	// Тело просьбы
	const uint8_t * asked = (query[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER);
	// Метка в 33 байта: поколение и имитовставка
	ASSERT_EQ(asked[2], LABEL);
	// Длина тела просьбы
	ASSERT_EQ(fragment.length, 3 + LABEL);
	// Просьба ровно 61 байт
	ASSERT_EQ(query[0].size(), static_cast <size_t> (61));
	// Настоящее приветствие клиента
	vector <vector <uint8_t>> first;
	// Снимаем приветствие
	ASSERT_TRUE(drain(client, first));
	// Подаём приветствие серверу
	ASSERT_EQ(server.push(view_t(first[0].data(), first[0].size())), context::error_t::NONE);
	// Забываем просьбу на наименьшее приветствие
	query.clear();
	// Снимаем просьбу на настоящее приветствие
	ASSERT_TRUE(drain(server, query));
	// Подаём просьбу клиенту
	ASSERT_EQ(client.push(view_t(query[0].data(), query[0].size())), context::error_t::NONE);
	// Повторное приветствие с меткой
	vector <vector <uint8_t>> second;
	// Снимаем приветствие
	ASSERT_TRUE(drain(client, second));
	// Смещение длины метки в приветствии
	const size_t place = (datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER + 2 + hello::HELLO_RANDOM + 1 + hello::HELLO_SESSION);
	// Длина метки
	ASSERT_EQ(second[0][place], LABEL);
	// Порченая имитовставка: первый байт
	vector <uint8_t> forged = second[0];
	// Портим байт имитовставки
	forged[place + 2] ^= 0x01;
	// Подаём подделку
	ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Отброшено меткой
	ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
	// Чужое поколение секрета
	vector <uint8_t> aged = second[0];
	// Портим поколение
	aged[place + 1] ^= 0x80;
	// Подаём подделку
	ASSERT_EQ(server.push(view_t(aged.data(), aged.size())), context::error_t::NONE);
	// Отброшено меткой
	ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (2));
	// Метка длины издания 1.3: 65 байтов - приветствие поддельного клиента с нею
	vector <uint8_t> longer;
	// Составляем приветствие с длинной меткой
	ASSERT_TRUE(greeting(vector <uint8_t> (65, 0x42), DTLS12, longer));
	// Дейтаграмма
	const vector <uint8_t> stretched = plain(handshake::type_t::CLIENT, longer, 1, 1);
	// Подаём растянутую запись серверу
	ASSERT_EQ(server.push(view_t(stretched.data(), stretched.size())), context::error_t::NONE);
	// Отброшено меткой
	ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (3));
	// Сервер молчит
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Сервер жив
	ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Настоящее повторное приветствие принимается
	ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
	// Залп сервера
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Путь
	bond_t bond;
	// Доводим до тишины
	converse(client, server, bond, 400);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Проверка заслона понижения (раздел 4.1.3 RFC 8446) в DTLS 1.2: сервер 1.2…1.3 против
 * клиента «только 1.2» кладёт DOWNGRD\x01 в хвост случайного значения приветствия (по
 * байтам ServerHello), и клиент «только 1.2» его не судит - связь сходится; клиент 1.2…1.3,
 * получивший приветствие сервера издания 1.2 с таким хвостом, обрывается illegal_parameter,
 * а без хвоста - продолжает рукопожатие
 */
TEST(Dtls12Test, Downgrade){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Сервер 1.2…1.3 против клиента «только 1.2»
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий серверу
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(TLS12, TLS12), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие, просьба, повторное приветствие
		ASSERT_TRUE(greet(client, server, bond));
		// Залп сервера
		vector <vector <uint8_t>> flight;
		// Снимаем залп
		ASSERT_TRUE(drain(server, flight));
		// Сообщения залпа
		vector <taken_t> messages;
		// Снимаем сообщения
		ASSERT_TRUE(harvest(flight, messages));
		// Приветствие сервера первым
		ASSERT_EQ(messages[0].type, handshake::type_t::SERVER);
		// Приветствие сервера
		hello::server_t answer;
		// Разбираем приветствие сервера
		ASSERT_EQ(hello::parse(view_t(messages[0].body.data(), messages[0].body.size()), answer), hello::error_t::NONE);
		// Издание DTLS 1.2 по проводу
		ASSERT_EQ(answer.version, DTLS12);
		// Заслон понижения в хвосте случайного значения: сервер способен к 1.3
		ASSERT_EQ(::memcmp(answer.random + (hello::HELLO_RANDOM - sizeof(DOWNGRADE)), DOWNGRADE, sizeof(DOWNGRADE)), 0);
		/**
		 * Выполняем доставку залпа клиенту
		 */
		for(size_t i = 0; i < flight.size(); i++)
			// Подаём дейтаграмму
			ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE) << i;
		// Клиент «только 1.2» заслон 1.3 не судит
		ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Издание 1.2 единой шкалы
		ASSERT_EQ(client.version(), TLS12);
	}
	/**
	 * Выполняем два круга: приветствие сервера с заслоном и без него
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента 1.2…1.3
		client::context_t client;
		// Заглушка сервера
		server::context_t dummy;
		// Настраиваем клиента
		arrange(client, dummy, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Наборы обоих изданий клиенту: издание 1.3 предлагается
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Первое приветствие
		vector <vector <uint8_t>> first;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, first));
		// Просьба о подтверждении адреса с пустой меткой
		const vector <uint8_t> query = plain(handshake::type_t::VERIFY_REQUEST, vector <uint8_t> {0xFE, 0xFF, 0x00}, 0, 0);
		// Подаём просьбу
		ASSERT_EQ(client.push(view_t(query.data(), query.size())), context::error_t::NONE);
		// Повторное приветствие
		vector <vector <uint8_t>> second;
		// Снимаем приветствие
		ASSERT_TRUE(drain(client, second));
		// Приветствие сервера издания 1.2
		hello::server_t answer;
		// Издание DTLS 1.2
		answer.version = DTLS12;
		/**
		 * Выполняем заполнение случайного значения
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт
			answer.random[i] = static_cast <uint8_t> (i);
		// На первом круге хвост случайного значения несёт заслон понижения
		if(item == 0)
			// Кладём заслон
			::memcpy(answer.random + (hello::HELLO_RANDOM - sizeof(DOWNGRADE)), DOWNGRADE, sizeof(DOWNGRADE));
		// Набор издания 1.2 из предложенных
		answer.suite = static_cast <uint16_t> (protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256);
		// Способ сжатия нулевой
		answer.method = 0x00;
		// Расширенный главный секрет подтверждён
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Тело приветствия сервера
		vector <uint8_t> body;
		// Составляем приветствие сервера
		ASSERT_EQ(hello::build(answer, body), hello::error_t::NONE);
		// Дейтаграмма с приветствием сервера номером один
		const vector <uint8_t> greeted = plain(handshake::type_t::SERVER, body, 1, 1);
		// Итог подачи
		const context::error_t outcome = client.push(view_t(greeted.data(), greeted.size()));
		// Если хвост несёт заслон
		if(item == 0){
			// Раздел 4.1.3 RFC 8446: клиент, предлагавший 1.3, обрывается на заслоне
			ASSERT_EQ(outcome, context::error_t::VERSION);
			// Извещение illegal_parameter
			ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
			// Клиент оборван
			ASSERT_EQ(client.state(), context::state_t::FAILED);
		// Если хвост чист
		} else {
			// Приветствие принято
			ASSERT_EQ(outcome, context::error_t::NONE) << static_cast <int> (client.alert().description);
			// Издание 1.2 согласовано единой шкалой
			ASSERT_EQ(client.version(), TLS12);
			// Клиент ждёт цепочку
			ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
		}
	}
}

/**
 * Проверка исчерпания записей на ключе поверх дейтаграмм: изданию 1.2 ключи не сменить,
 * и, дойдя счётчиком записей своего направления до порога renewal, связь шлёт close_notify
 * первой порой и отвечает отказом EXHAUSTED; собеседник читает отправленное до порога и
 * принимает закрытие
 */
TEST(Dtls12Test, Exhausted){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond, 400);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established());
	// Завершение клиента - единственная запись первой поры
	ASSERT_EQ(client.sequence(false), static_cast <uint64_t> (1));
	// Порог записей на ключе: три
	client.renewal(true, 3);
	// Первая запись данных: счётчик единица
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("one"), 3)), context::error_t::NONE);
	// Вторая запись данных: счётчик два
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("two"), 3)), context::error_t::NONE);
	// Счётчик дошёл до порога
	ASSERT_EQ(client.sequence(false), static_cast <uint64_t> (3));
	// Третья запись - за порогом: close_notify и EXHAUSTED
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("three"), 5)), context::error_t::EXHAUSTED);
	// Связь закрыта
	ASSERT_EQ(client.state(), context::state_t::CLOSED);
	// Дейтаграммы клиента
	vector <vector <uint8_t>> datagrams;
	// Снимаем дейтаграммы
	ASSERT_TRUE(drain(client, datagrams));
	// Две записи данных и извещение
	ASSERT_EQ(datagrams.size(), static_cast <size_t> (3));
	// Поля заголовка
	uint8_t type = 0;
	// Издание
	uint16_t version = 0;
	// Пора
	uint16_t epoch = 0;
	// Номер
	uint64_t sequence = 0;
	// Длина
	size_t size = 0;
	// Читаем заголовок последней дейтаграммы
	ASSERT_TRUE(heading(datagrams[2], 0, type, version, epoch, sequence, size));
	// Извещение первой порой
	ASSERT_EQ(type, static_cast <uint8_t> (record::type_t::ALERT));
	// Первая пора
	ASSERT_EQ(epoch, 1);
	// Номер записи: за завершением и двумя записями данных
	ASSERT_EQ(sequence, static_cast <uint64_t> (3));
	/**
	 * Выполняем доставку дейтаграмм серверу
	 */
	for(size_t i = 0; i < datagrams.size(); i++)
		// Подаём дейтаграмму
		ASSERT_EQ(server.push(view_t(datagrams[i].data(), datagrams[i].size())), context::error_t::NONE) << i;
	// Принятые данные
	vector <uint8_t> received;
	// Читаем данные, дошедшие до закрытия связи
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Данные до порога дошли
	ASSERT_EQ(string(received.begin(), received.end()), "onetwo");
	// Сервер принял закрытие
	ASSERT_EQ(server.state(), context::state_t::CLOSED);
}

/**
 * Проверка нехватки памяти: перебор запасов выделений на рукопожатии DTLS 1.2 с просьбой о
 * подтверждении адреса и обменом данными; всякий исход - успех, MEMORY либо обрыв
 * собеседником внутренним извещением, и нехватка памяти обязана встретиться
 */
TEST(Dtls12Test, Starved){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Признак того, что нехватка памяти встретилась
	bool starved = false;
	// Признак того, что связь на щедром запасе установилась
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 300) ? 1 : 41)){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, true);
		// Отказы сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		// Отказ отправки данных
		context::error_t written = context::error_t::NONE;
		// Запас выделений действует лишь внутри блока
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Заводим сервер
			first = server.start();
			// Заводим клиента
			second = client.start();
			// Если стороны заведены
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Путь без потерь
				bond_t bond;
				// Проводим рукопожатие
				converse(client, server, bond, 400);
				// Если связь установлена
				if(client.established() && server.established()){
					// Пишем прикладные данные при ограниченном запасе выделений
					written = client.write(view_t(reinterpret_cast <const uint8_t *> ("starved datagram payload"), 24));
					// Переносим данные
					converse(client, server, bond, 400);
				}
				// Отказ сервера
				first = server.error();
				// Отказ клиента
				second = client.error();
			}
		}
		// Запоминаем нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY) || (written == context::error_t::MEMORY));
		// Дозволенные исходы: успех, нехватка памяти либо обрыв собеседником внутренним извещением
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL))) &&
			((written == context::error_t::NONE) || (written == context::error_t::MEMORY));
		// Проверяем законность исхода
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second) << " " << static_cast <int> (written);
		// Принятые данные
		vector <uint8_t> received;
		// Запоминаем установление связи с данными
		complete = (client.established() && server.established() && (written == context::error_t::NONE) && (server.read(received) == context::error_t::NONE) && (received.size() == 24));
	}
	// Проверяем, что нехватка памяти встретилась
	ASSERT_TRUE(starved);
	// Проверяем, что на щедром запасе связь установилась
	ASSERT_TRUE(complete);
}



/**
 * @brief Внутренние служебные объекты второго круга поверх дейтаграмм
 *
 */
namespace {
	/**
	 * @brief Связка заранее разделённого ключа для проверок
	 *
	 */
	typedef struct Keyring {
		// Опознаватель и ключ
		vector <uint8_t> identity, key;
		// Опознаватель, увиденный сервером, и подсказка, увиденная клиентом
		vector <uint8_t> seen, hint;
	} keyring_t;
	/**
	 * @brief Вызов сервера: ключ по опознавателю
	 *
	 * @param identity опознаватель
	 * @param key      накопитель ключа
	 * @param context  связка
	 * @return         признак известности
	 *
	 */
	bool responding(const view_t & identity, vector <uint8_t> & key, void * context) {
		// Связка
		keyring_t * ring = reinterpret_cast <keyring_t *> (context);
		// Запоминаем
		ring->seen.assign(identity.data, identity.data + identity.size);
		// Если опознаватель известен
		if(ring->seen == ring->identity){
			// Ключ
			key = ring->key;
			// Известен
			return true;
		}
		// Неизвестен
		return false;
	}
	/**
	 * @brief Вызов клиента: подсказка сервера
	 *
	 * @param hint     подсказка
	 * @param identity накопитель опознавателя
	 * @param key      накопитель ключа
	 * @param context  связка
	 * @return         признак выбора заново: настроенные остаются
	 *
	 */
	bool advising(const view_t & hint, vector <uint8_t> & identity, vector <uint8_t> & key, void * context) {
		// Связка
		keyring_t * ring = reinterpret_cast <keyring_t *> (context);
		// Запоминаем подсказку
		ring->hint.assign(hint.data, hint.data + hint.size);
		// Накопители не трогаются
		(void) identity;
		// Ключ тоже
		(void) key;
		// Остаются настроенные
		return false;
	}
	/**
	 * Наборы второго круга поверх дейтаграмм: CBC, обмен RSA и PSK
	 */
	static const struct Second {
		// Набор
		protect::suite_t suite;
		// Имя у openssl
		const char * title;
		// Ключ сервера, пусто у PSK
		const char * key;
	} SECOND[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", "ec256"},
		{protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA,      "ECDHE-RSA-AES256-SHA",      "rsa2048"},
		{protect::suite_t::RSA_AES_128_GCM_SHA256,         "AES128-GCM-SHA256",         "rsa2048"},
		{protect::suite_t::RSA_AES_256_CBC_SHA,            "AES256-SHA",                "rsa2048"},
		{protect::suite_t::PSK_AES_128_CBC_SHA,            "PSK-AES128-CBC-SHA",        ""},
		{protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, "ECDHE-PSK-CHACHA20-POLY1305", ""}
	};
	/**
	 * @brief Функция настройки сторон под набор второго круга поверх дейтаграмм
	 *
	 * @param client связь клиента
	 * @param server связь сервера
	 * @param item   описание набора
	 * @param theirs связка сервера
	 * @param ours   связка клиента
	 * @return       признак успешности
	 *
	 */
	bool arranging(client::context_t & client, server::context_t & server, const Second & item, keyring_t & theirs, keyring_t & ours) noexcept {
		// Перенос дейтаграммами
		client.transport(context::transport_t::DATAGRAMS);
		// Сервер
		server.transport(context::transport_t::DATAGRAMS);
		// Наборы
		client.suites(vector <protect::suite_t> {item.suite});
		// Сервер
		server.suites(vector <protect::suite_t> {item.suite});
		// Группы
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Сервер
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Адрес
		server.address(view_t(ADDRESS, sizeof(ADDRESS)));
		// Издание 1.2
		client.versions(0x0303, 0x0303);
		// Если набор PSK
		if(::strlen(item.key) == 0){
			// Опознаватель
			theirs.identity = decode("616e796b73");
			// Ключ
			{ const vector <uint8_t> raw = decode("0123456789abcdef"); theirs.key.assign(raw.begin(), raw.end()); }
			// Клиент
			ours.identity = theirs.identity;
			// Ключ
			ours.key = theirs.key;
			// Настройки сервера
			context::psk_t mine;
			// Отклик запроса билета стороны
			mine.respond = responding;
			// Связка
			mine.context = &theirs;
			// Подсказка
			mine.identity = decode("616e796b732d68696e74");
			// Устанавливаем
			server.psk(mine);
			// Настройки клиента
			context::psk_t yours;
			// Опознаватель
			yours.identity = ours.identity;
			// Ключ
			yours.key.assign(ours.key.begin(), ours.key.end());
			// Подсказка опознавателя стороны
			yours.advise = advising;
			// Связка
			yours.context = &ours;
			// Устанавливаем
			client.psk(yours);
			// Готово
			return true;
		}
		// Подлинность
		context::credential_t credential;
		// Если не составилась
		if(!identity(item.key, credential))
			// Отказ
			return false;
		// Устанавливаем
		server.credential(credential);
		// Готово
		return true;
	}
};

/**
 * Проверка второго круга поверх дейтаграмм (RFC 6347 с RFC 5246 §6.2.3.2, RFC 4279, RFC 5489,
 * RFC 5077): наборы CBC с encrypt_then_mac (номер в имитовставке - пора и порядковый номер),
 * голый RSA, PSK без сертификатов - петля без потерь и с потерей всякой третьей дейтаграммы,
 * порча защищённой записи CBC отбрасывается молча; билет сеанса выдаётся полным рукопожатием
 * и возобновляет связь сокращённым в дейтаграммах с завершением сервера первым
 */
TEST(Dtls12Test, Second){
	/**
	 * Выполняем перебор наборов
	 */
	for(size_t s = 0; s < (sizeof(SECOND) / sizeof(SECOND[0])); s++){
		/**
		 * Выполняем перебор путей: без потерь и с потерей всякой третьей
		 */
		for(size_t lossy = 0; lossy < 2; lossy++){
			// Связь клиента
			client::context_t client;
			// Связь сервера
			server::context_t server;
			// Связки
			keyring_t theirs, ours;
			// Настраиваем
			ASSERT_TRUE(arranging(client, server, SECOND[s], theirs, ours)) << SECOND[s].title;
			// Заводим
			ASSERT_EQ(server.start(), context::error_t::NONE) << SECOND[s].title;
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Путь
			bond_t bond;
			// Потери
			bond.period = ((lossy == 1) ? 3 : 0);
			// Рукопожатие
			converse(client, server, bond, 400);
			// Установлена
			ASSERT_TRUE(client.established() && server.established()) << SECOND[s].title << " потери " << lossy << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
			// Издание
			ASSERT_EQ(client.version(), TLS12);
			// Набор
			ASSERT_EQ(server.suite(), SECOND[s].suite);
			// Порядок RFC 7366 у CBC
			ASSERT_EQ(client.etm(), (protect::mac(SECOND[s].suite) != digest::hash_t::NONE)) << SECOND[s].title;
			// У сервера тот же
			ASSERT_EQ(server.etm(), client.etm());
			// Если набор PSK: сертификатов нет, опознаватель и подсказка дошли
			if(::strlen(SECOND[s].key) == 0){
				// Сертификатов нет
				ASSERT_TRUE(client.peer().empty() && server.peer().empty());
				// Опознаватель
				ASSERT_EQ(theirs.seen, theirs.identity);
				// Подсказка
				ASSERT_EQ(string(ours.hint.begin(), ours.hint.end()), string("anyks-hint"));
			}
			// Билет принят
			ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1)) << SECOND[s].title;
			// Путь без потерь
			bond_t clean;
			// Обмен данными
			ASSERT_TRUE(barter(client, server, clean)) << SECOND[s].title;
			// Если набор CBC и путь без потерь: порча записи отбрасывается молча
			if((lossy == 0) && (protect::mac(SECOND[s].suite) != digest::hash_t::NONE)){
				// Данные
				const string request = "порча записи CBC";
				// Отправляем
				ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
				// Дейтаграммы
				vector <vector <uint8_t>> datagrams;
				// Снимаем
				ASSERT_TRUE(drain(client, datagrams));
				// Одна
				ASSERT_EQ(datagrams.size(), static_cast <size_t> (1));
				// Портим последний байт: имитовставка
				datagrams[0].back() ^= 0x01;
				// Отброшенных до подачи
				const uint64_t before = server.discarded(datagram::reason_t::DAMAGE);
				// Подаём первую дейтаграмму серверу
				ASSERT_EQ(server.push(view_t(datagrams[0].data(), datagrams[0].size())), context::error_t::NONE);
				// Отброшена молча
				ASSERT_EQ(server.discarded(datagram::reason_t::DAMAGE), before + 1);
				// Связь жива
				ASSERT_TRUE(server.established());
				// Данных нет
				vector <uint8_t> received;
				// Читаем
				ASSERT_EQ(server.read(received), context::error_t::NONE);
				// Пусто
				ASSERT_TRUE(received.empty());
			}
		}
	}
	{
		// Подлинность
		context::credential_t credential;
		// Составляем
		ASSERT_TRUE(identity("ec256", credential));
		// Ключ билетов
		const vector <uint8_t> vault = decode("00112233445566778899aabbccddeeff");
		// Билет
		context::ticket_t ticket;
		{
			// Связь клиента
			client::context_t client;
			// Связь сервера
			server::context_t server;
			// Настраиваем
			arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, extension::group_t::X25519, credential, false);
			// Ключ билетов
			server.vault(vault);
			// Заводим
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Путь
			bond_t bond;
			// Рукопожатие
			converse(client, server, bond, 400);
			// Установлена
			ASSERT_TRUE(client.established() && server.established());
			// Полное
			ASSERT_FALSE(client.shared());
			// Билет
			ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
			// Запоминаем
			ticket = client.tickets()[0];
		}
		/**
		 * Выполняем перебор путей возобновления: без потерь и с потерями
		 */
		for(size_t lossy = 0; lossy < 2; lossy++){
			// Связь клиента
			client::context_t client;
			// Связь сервера
			server::context_t server;
			// Настраиваем
			arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, extension::group_t::X25519, credential, false);
			// Ключ билетов
			server.vault(vault);
			// Предъявляем
			client.resume(ticket);
			// Заводим
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Путь
			bond_t bond;
			// Потери
			bond.period = ((lossy == 1) ? 3 : 0);
			// Если без потерь: приветствие, просьба, повторное приветствие и залп сервера по шагам
			if(lossy == 0){
				// Приветствия
				ASSERT_TRUE(greet(client, server, bond));
				// Дейтаграммы сервера
				vector <vector <uint8_t>> datagrams;
				// Снимаем
				ASSERT_TRUE(drain(server, datagrams));
				// Залп есть
				ASSERT_FALSE(datagrams.empty());
				// Признак смены набора в залпе сервера: завершение сервера первым
				bool changed = false;
				/**
				 * Выполняем перебор дейтаграмм
				 */
				for(size_t i = 0; i < datagrams.size(); i++){
					// Смещение
					size_t offset = 0;
					/**
					 * Выполняем перебор записей
					 */
					while(offset < datagrams[i].size()){
						// Заголовок
						uint8_t type = 0;
						// Издание
						uint16_t version = 0, epoch = 0;
						// Номер
						uint64_t sequence = 0;
						// Длина
						size_t size = 0;
						// Читаем
						ASSERT_TRUE(heading(datagrams[i], offset, type, version, epoch, sequence, size));
						// Смена набора
						changed = (changed || (type == 0x14));
						// Следующая
						offset += (13 + size);
					}
					// Подаём клиенту
					client.push(view_t(datagrams[i].data(), datagrams[i].size()));
				}
				// Смена набора в залпе сервера сразу за приветствием: сокращённое рукопожатие
				ASSERT_TRUE(changed);
			}
			// Доводим
			converse(client, server, bond, 400);
			// Установлена
			ASSERT_TRUE(client.established() && server.established()) << "потери " << lossy << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
			// Возобновлена
			ASSERT_TRUE(client.shared() && server.shared()) << lossy;
			// Сертификата нет
			ASSERT_TRUE(client.peer().empty());
			// Новый билет
			ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
			// Путь без потерь
			bond_t clean;
			// Обмен
			ASSERT_TRUE(barter(client, server, clean)) << lossy;
		}
	}
}

/**
 * Проверка обмена второго круга с настоящим openssl поверх дейтаграмм: набор CBC с ETM и с
 * -no_etm и набор PSK в обе стороны; полнота обмена судится по данным в журналах
 */
TEST(Dtls12Test, Interop){
	// Способности
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен либо без DTLS 1.2
	if(!toolkit.present || !toolkit.dtls12 || !toolkit.listening){
		// Пропускаем
		GTEST_SKIP() << "openssl без DTLS 1.2";
	}
	// Ключ -no_etm появился у openssl 3.0: без него круги с ним пропускаются вслух
	const bool noetmable = (listed("s_server", "no_etm") && listed("s_client", "no_etm"));
	/**
	 * @brief Круг обмена
	 *
	 */
	struct Round {
		// Набор
		protect::suite_t suite;
		// Набор openssl
		const char * cipher;
		// Ключ
		const char * key;
		// Без ETM
		bool noetm;
	} rounds[] = {
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", "ec256", false},
		{protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", "ec256", true},
		{protect::suite_t::PSK_AES_128_CBC_SHA, "PSK-AES128-CBC-SHA@SECLEVEL=0", "", false}
	};
	/**
	 * Выполняем перебор кругов: наш клиент против s_server
	 */
	for(size_t r = 0; r < (sizeof(rounds) / sizeof(rounds[0])); r++){
		// Если круг требует ключа -no_etm, которого у openssl нет
		if(rounds[r].noetm && !noetmable){
			// Сообщаем о пропуске круга вслух
			cout << "круг " << r << " пропущен: openssl без ключа -no_etm" << endl;
			// Переходим к следующему кругу
			continue;
		}
		// Порт
		const uint16_t number = vacant(true);
		// Порт есть
		ASSERT_NE(number, 0);
		// Журнал
		const std::string log = "/tmp/ants-dtls12b-server-" + std::to_string(number) + ".log";
		// Канал
		const std::string holder = "/tmp/ants-dtls12b-server-" + std::to_string(number) + ".fifo";
		// Убираем прежний
		::remove(holder.c_str());
		// Заводим
		ASSERT_EQ(fifo(holder.c_str()), 0);
		// Доводы
		const std::string arming = ((::strlen(rounds[r].key) == 0) ? std::string(" -nocert -psk_identity anyks -psk 0123456789ABCDEF -psk_hint anyks-hint") : (" -cert " + std::string(CORPUS) + "/" + rounds[r].key + ".crt -key " + std::string(CORPUS) + "/" + rounds[r].key + ".pem"));
		// Запускаем сервер
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1_2 -listen" + arming + " -cipher " + rounds[r].cipher + (rounds[r].noetm ? " -no_etm" : "") + " -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Журнал
		std::string text;
		// Подъём
		ASSERT_TRUE(awaited(log, "ACCEPT", text)) << text;
		// Порт своего сокета
		uint16_t bound = 0;
		// Сокет
		const int fd = socketing(0, bound);
		// Сокет есть
		ASSERT_GE(fd, 0);
		// Адрес сервера
		struct sockaddr_in peer;
		// Обнуляем
		::memset(&peer, 0, sizeof(peer));
		// Семейство
		peer.sin_family = AF_INET;
		// Петля
		peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		// Порт
		peer.sin_port = htons(number);
		// Связь клиента
		client::context_t client;
		// Перенос
		client.transport(context::transport_t::DATAGRAMS);
		// Набор
		client.suites(vector <protect::suite_t> {rounds[r].suite});
		// Группы
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1});
		// Связка
		keyring_t ours;
		// Если PSK
		if(::strlen(rounds[r].key) == 0){
			// Настройки
			context::psk_t yours;
			// Опознаватель
			yours.identity = decode("616e796b73");
			// Ключ
			{ const vector <uint8_t> raw = decode("0123456789abcdef"); yours.key.assign(raw.begin(), raw.end()); }
			// Подсказка опознавателя стороны
			yours.advise = advising;
			// Связка
			yours.context = &ours;
			// Устанавливаем
			client.psk(yours);
		}
		// Размер
		client.mtu(300);
		// Имя
		client.name("localhost");
		// Заводим
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Ведём
		const bool complete = relay(client, fd, peer, 400);
		// Установлена
		ASSERT_TRUE(complete) << rounds[r].cipher << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Набор
		ASSERT_EQ(client.suite(), rounds[r].suite);
		// Порядок RFC 7366
		ASSERT_EQ(client.etm(), ((protect::mac(rounds[r].suite) != digest::hash_t::NONE) && !rounds[r].noetm)) << rounds[r].cipher;
		// Если PSK: подсказка
		if(::strlen(rounds[r].key) == 0){
			// Подсказка дошла
			ASSERT_EQ(string(ours.hint.begin(), ours.hint.end()), string("anyks-hint"));
		}
		// Данные
		const string request = "ants second round over dtls " + std::to_string(r) + "\n";
		// Отправляем
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Дейтаграммы
		relay(client, fd, peer, 1);
		// Сервер напечатал
		ASSERT_TRUE(awaited(log, request, text)) << text;
		// Закрываем
		ASSERT_EQ(client.close(), context::error_t::NONE);
		// Извещение
		relay(client, fd, peer, 1);
		// Закрываем сокет
		closing(fd);
		// Снимаем
		sentinel.halt();
		// Дожидаемся
		(void) settle(log, text);
		// Удаляем
		::remove(log.c_str());
		// Удаляем канал
		::remove(holder.c_str());
	}
	/**
	 * Выполняем перебор кругов: s_client против нашего сервера
	 */
	for(size_t r = 0; r < (sizeof(rounds) / sizeof(rounds[0])); r++){
		// Если круг требует ключа -no_etm, которого у openssl нет
		if(rounds[r].noetm && !noetmable){
			// Сообщаем о пропуске круга вслух
			cout << "круг " << r << " пропущен: openssl без ключа -no_etm" << endl;
			// Переходим к следующему кругу
			continue;
		}
		// Порт
		uint16_t number = 0;
		// Сокет
		const int fd = socketing(0, number);
		// Сокет есть
		ASSERT_GE(fd, 0);
		// Журнал
		const std::string log = "/tmp/ants-dtls12b-client-" + std::to_string(number) + ".log";
		// Данные
		const string request = "hello second round " + std::to_string(r) + "\n";
		// Доводы
		const std::string arming = ((::strlen(rounds[r].key) == 0) ? std::string(" -psk_identity anyks -psk 0123456789ABCDEF") : (" -CAfile " + std::string(CORPUS) + "/" + rounds[r].key + ".crt -servername localhost -verify_return_error"));
		// Запускаем клиента
		ASSERT_TRUE(launch("printf '" + request + "' | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -dtls1_2" + arming + " -cipher " + rounds[r].cipher + (rounds[r].noetm ? " -no_etm" : "") + " -mtu 300 -ign_eof >" + log + " 2>&1", log, log + ".pid", std::string()));
		// Сторож
		sentinel_t sentinel(log + ".pid");
		// Адрес клиента
		struct sockaddr_in peer;
		// Длина
		socklen_t length = sizeof(peer);
		// Место
		uint8_t buffer[65536];
		// Принятое
		ssize_t received = -1;
		/**
		 * Выполняем ожидание приветствия
		 */
		for(size_t i = 0; (i < 150) && (received <= 0); i++)
			// Принимаем
			received = receivingfrom(fd, buffer, sizeof(buffer), reinterpret_cast <struct sockaddr *> (&peer), &length);
		// Принято
		ASSERT_GT(received, 0) << rounds[r].cipher;
		// Связь сервера
		server::context_t server;
		// Перенос
		server.transport(context::transport_t::DATAGRAMS);
		// Набор
		server.suites(vector <protect::suite_t> {rounds[r].suite});
		// Группы
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Связка
		keyring_t theirs;
		// Если PSK
		if(::strlen(rounds[r].key) == 0){
			// Опознаватель
			theirs.identity = decode("616e796b73");
			// Ключ
			{ const vector <uint8_t> raw = decode("0123456789abcdef"); theirs.key.assign(raw.begin(), raw.end()); }
			// Настройки
			context::psk_t mine;
			// Отклик запроса билета стороны
			mine.respond = responding;
			// Связка
			mine.context = &theirs;
			// Устанавливаем
			server.psk(mine);
		// Иначе подлинность
		} else {
			// Подлинность
			context::credential_t credential;
			// Составляем
			ASSERT_TRUE(identity(rounds[r].key, credential));
			// Устанавливаем
			server.credential(credential);
		}
		// Размер
		server.mtu(300);
		// Адрес
		ASSERT_TRUE(server.address(view_t(reinterpret_cast <const uint8_t *> (&peer), sizeof(peer))));
		// Заводим
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Подаём принятую дейтаграмму серверу
		server.push(view_t(buffer, static_cast <size_t> (received)));
		// Данные
		vector <uint8_t> plaintext;
		/**
		 * Выполняем перенос до данных
		 */
		for(size_t i = 0; (i < 400) && (server.state() != context::state_t::FAILED) && (server.state() != context::state_t::CLOSED) && plaintext.empty(); i++){
			/**
			 * Перекачиваем готовые дейтаграммы до опустошения вывода
			 */
			while(server.output().size > 0){
				// Дейтаграмма
				const view_t data = server.output();
				// Отправляем
				(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), length);
				// Снимаем
				server.consume(data.size);
			}
			// Принимаем
			received = receiving(fd, buffer, sizeof(buffer));
			// Если принято
			if(received > 0)
				// Подаём принятую дейтаграмму серверу
				server.push(view_t(buffer, static_cast <size_t> (received)));
			// Если часы
			else if(server.timeout() > 0)
				// Истекли
				server.elapsed();
			// Если установлена
			if(server.established())
				// Читаем
				(void) server.read(plaintext);
		}
		// Установлена
		ASSERT_TRUE(server.established()) << rounds[r].cipher << " отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
		// Данные дошли
		ASSERT_EQ(string(plaintext.begin(), plaintext.end()), request);
		// Набор
		ASSERT_EQ(server.suite(), rounds[r].suite);
		// Порядок RFC 7366
		ASSERT_EQ(server.etm(), ((protect::mac(rounds[r].suite) != digest::hash_t::NONE) && !rounds[r].noetm)) << rounds[r].cipher;
		// Ответ
		const string answer = "ants server second round\n";
		// Отправляем
		ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::NONE);
		// Закрываем
		ASSERT_EQ(server.close(), context::error_t::NONE);
		/**
		 * Перекачиваем ответные дейтаграммы до опустошения вывода
		 */
		while(server.output().size > 0){
			// Дейтаграмма
			const view_t data = server.output();
			// Отправляем
			(void) sendingto(fd, data.data, data.size, reinterpret_cast <const struct sockaddr *> (&peer), length);
			// Снимаем
			server.consume(data.size);
		}
		// Закрываем
		closing(fd);
		// Текст
		std::string text;
		// Завершился
		ASSERT_TRUE(settle(log, text)) << text;
		// Издание
		ASSERT_NE(text.find("Protocol  : DTLSv1.2"), std::string::npos) << text;
		// Ответ дошёл
		ASSERT_NE(text.find(answer), std::string::npos) << text;
		// Удаляем
		::remove(log.c_str());
	}
}

/**
 * Дроблёное повторное приветствие (решение 13 переноса): чужие клиенты дробят повторное
 * приветствие умолчанием (openssl: 232 байта тела кусками 203 + 29), и сервер умолчанием
 * собирает его под пределами и отвечает - в любом порядке кусков; строгий сервер (strict)
 * принимает приветствие лишь целиком, как DTLSv1_listen, на куски молчит и растит
 * discarded(GREETING), целое принимает; приветствие шире DATAGRAM_GREETING отбрасывается, а
 * ровно в предел - собирается; сборок не больше DATAGRAM_GREETINGS - старейшая снимается,
 * сборки чужих адресов не смешиваются, и выдаётся сборка адреса принятой дейтаграммы - даже
 * когда чужая недособранная сборка стоит в перечне впереди своей
 */
TEST(Dtls12Test, FragmentedGreeting){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Место разреза повторного приветствия: как у openssl, первый кусок в 203 байта
	static constexpr size_t CUT = 203;
	/**
	 * Порядок кусков: прямой и обратный - оба обязаны связать
	 */
	for(size_t order = 0; order < 2; order++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Умолчанием сервер не строгий
		ASSERT_FALSE(server.strict());
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие и просьба о подтверждении адреса
		ASSERT_TRUE(carry(client, server, bond, 0) && carry(server, client, bond, 1));
		// Повторное приветствие с меткой
		vector <vector <uint8_t>> second;
		// Снимаем повторное приветствие
		ASSERT_TRUE(drain(client, second));
		// Одна дейтаграмма
		ASSERT_EQ(second.size(), static_cast <size_t> (1));
		// Куски приветствия
		vector <uint8_t> head, rest;
		// Дробим приветствие
		ASSERT_TRUE(bisect(second[0], CUT, head, rest));
		// Первый подаваемый кусок
		const vector <uint8_t> & lead = ((order == 0) ? head : rest);
		// Второй подаваемый кусок
		const vector <uint8_t> & tail = ((order == 0) ? rest : head);
		// Подаём первый кусок
		ASSERT_EQ(server.push(view_t(lead.data(), lead.size())), context::error_t::NONE) << order;
		// Сервер молчит: приветствие не собрано
		ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << order;
		// Ошибки нет
		ASSERT_EQ(server.error(), context::error_t::NONE) << order;
		// Подаём второй кусок
		ASSERT_EQ(server.push(view_t(tail.data(), tail.size())), context::error_t::NONE) << order;
		// Приветствие собрано: сервер отвечает залпом
		ASSERT_GT(server.output().size, static_cast <size_t> (0)) << order;
		// Отбросов приветствия нет
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (0)) << order;
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена у обеих сторон
		ASSERT_TRUE(client.established() && server.established()) << order << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond)) << order;
	}
	// Строгий сервер: куски отбрасываются молча, целое принимается
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент лишь 1.2
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Строгий сервер
		server.strict(true);
		// Строгость установлена
		ASSERT_TRUE(server.strict());
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие и просьба
		ASSERT_TRUE(carry(client, server, bond, 0) && carry(server, client, bond, 1));
		// Повторное приветствие
		vector <vector <uint8_t>> second;
		// Снимаем
		ASSERT_TRUE(drain(client, second));
		// Куски приветствия
		vector <uint8_t> head, rest;
		// Дробим
		ASSERT_TRUE(bisect(second[0], CUT, head, rest));
		// Подаём первый кусок
		ASSERT_EQ(server.push(view_t(head.data(), head.size())), context::error_t::NONE);
		// Подаём второй кусок
		ASSERT_EQ(server.push(view_t(rest.data(), rest.size())), context::error_t::NONE);
		// Сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Ошибки нет
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// Оба куска отброшены как приветствие
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (2));
		// Связи нет
		ASSERT_FALSE(server.established());
		// Подаём приветствие целиком
		ASSERT_EQ(server.push(view_t(second[0].data(), second[0].size())), context::error_t::NONE);
		// Сервер отвечает залпом
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		// Доводим до тишины
		converse(client, server, bond, 400);
		// Связь установлена у обеих сторон
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, bond));
	}
	// Предел длины сборки приветствия
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие и просьба: сервер без состояния
		ASSERT_TRUE(carry(client, server, bond, 0) && carry(server, client, bond, 1));
		// Тело куска
		const vector <uint8_t> zeros(64, 0);
		// Кусок приветствия с длиной целого сверх предела
		const vector <uint8_t> wide = shard(handshake::type_t::CLIENT, datagram::DATAGRAM_GREETING + 1, 1, 0, zeros.data(), zeros.size(), 5);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(wide.data(), wide.size())), context::error_t::NONE);
		// Кусок отброшен
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (1));
		// Кусок приветствия с длиной целого ровно в предел
		const vector <uint8_t> edge = shard(handshake::type_t::CLIENT, datagram::DATAGRAM_GREETING, 1, 0, zeros.data(), zeros.size(), 6);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(edge.data(), edge.size())), context::error_t::NONE);
		// Кусок принят в сборку: отбросов не прибавилось
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (1));
		// Сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Связи нет
		ASSERT_FALSE(server.established());
	}
	// Предел числа сборок и привязка сборок к адресу
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие и просьба: сервер без состояния
		ASSERT_TRUE(carry(client, server, bond, 0) && carry(server, client, bond, 1));
		// Поддельная метка длиной как настоящая
		const vector <uint8_t> forged(33, 0x00);
		// Тело поддельного повторного приветствия
		vector <uint8_t> body;
		// Составляем приветствие
		ASSERT_TRUE(greeting(forged, 0xFEFD, body));
		// Место разреза: как у openssl либо середина, когда приветствие короче
		const size_t cut = ((body.size() > CUT) ? CUT : (body.size() / 2));
		/**
		 * Подаём первые куски приветствий с адресов числом на один больше предела
		 */
		for(size_t i = 0; i <= datagram::DATAGRAM_GREETINGS; i++){
			// Адрес собеседника
			const uint8_t address[] = {10, 0, 0, static_cast <uint8_t> (i + 1), 0x12, 0x34};
			// Устанавливаем адрес
			ASSERT_TRUE(server.address(view_t(address, sizeof(address)))) << i;
			// Первый кусок приветствия
			const vector <uint8_t> head = shard(handshake::type_t::CLIENT, body.size(), 1, 0, body.data(), cut, 10 + i);
			// Подаём кусок
			ASSERT_EQ(server.push(view_t(head.data(), head.size())), context::error_t::NONE) << i;
			// Сервер молчит
			ASSERT_EQ(server.output().size, static_cast <size_t> (0)) << i;
		}
		// Старейшая сборка снята
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (1));
		// Ни одно приветствие не собрано
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (0));
		// Адрес первого собеседника, чья сборка снята
		const uint8_t eldest[] = {10, 0, 0, 1, 0x12, 0x34};
		// Устанавливаем адрес
		ASSERT_TRUE(server.address(view_t(eldest, sizeof(eldest))));
		// Второй кусок его приветствия
		const vector <uint8_t> orphan = shard(handshake::type_t::CLIENT, body.size(), 1, cut, body.data() + cut, body.size() - cut, 20);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(orphan.data(), orphan.size())), context::error_t::NONE);
		// Приветствие не собрано: сборки снятого адреса нет, кусок завёл новую и вытеснил следующую старейшую
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (0));
		// Ещё одна сборка снята
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (2));
		// Адрес третьего собеседника, чья сборка цела
		const uint8_t third[] = {10, 0, 0, 3, 0x12, 0x34};
		// Устанавливаем адрес
		ASSERT_TRUE(server.address(view_t(third, sizeof(third))));
		// Второй кусок его приветствия
		const vector <uint8_t> closing = shard(handshake::type_t::CLIENT, body.size(), 1, cut, body.data() + cut, body.size() - cut, 21);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(closing.data(), closing.size())), context::error_t::NONE);
		// Приветствие собрано именно его сборкой: метка отвергнута
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
		// Сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Связи нет
		ASSERT_FALSE(server.established());
	}
	// Чужая недособранная сборка впереди своей: выдаётся сборка адреса принятой дейтаграммы
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Сервер лишь 1.2
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь
		bond_t bond;
		// Приветствие и просьба: сервер без состояния
		ASSERT_TRUE(carry(client, server, bond, 0) && carry(server, client, bond, 1));
		// Поддельная метка длиной как настоящая
		const vector <uint8_t> forged(33, 0x00);
		// Тело поддельного повторного приветствия
		vector <uint8_t> body;
		// Составляем приветствие
		ASSERT_TRUE(greeting(forged, 0xFEFD, body));
		// Место разреза
		const size_t cut = ((body.size() > CUT) ? CUT : (body.size() / 2));
		// Адрес первого собеседника
		const uint8_t alpha[] = {10, 0, 0, 7, 0x12, 0x34};
		// Адрес второго собеседника
		const uint8_t beta[] = {10, 0, 0, 8, 0x12, 0x34};
		// Первый собеседник: лишь первый кусок - его сборка встаёт в перечень первой и остаётся недособранной
		ASSERT_TRUE(server.address(view_t(alpha, sizeof(alpha))));
		// Первый кусок первого собеседника
		const vector <uint8_t> opening = shard(handshake::type_t::CLIENT, body.size(), 1, 0, body.data(), cut, 30);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(opening.data(), opening.size())), context::error_t::NONE);
		// Второй собеседник: оба куска
		ASSERT_TRUE(server.address(view_t(beta, sizeof(beta))));
		// Первый кусок второго собеседника
		const vector <uint8_t> head = shard(handshake::type_t::CLIENT, body.size(), 1, 0, body.data(), cut, 31);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(head.data(), head.size())), context::error_t::NONE);
		// Ни одно приветствие не собрано
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (0));
		// Второй кусок второго собеседника
		const vector <uint8_t> rest = shard(handshake::type_t::CLIENT, body.size(), 1, cut, body.data() + cut, body.size() - cut, 32);
		// Подаём кусок
		ASSERT_EQ(server.push(view_t(rest.data(), rest.size())), context::error_t::NONE);
		// Приветствие второго собеседника собрано и выдано мимо чужой недособранной сборки: метка отвергнута
		ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
		// Отбросов приветствия нет: сборки не смешивались и не снимались
		ASSERT_EQ(server.discarded(datagram::reason_t::GREETING), static_cast <uint64_t> (0));
		// Сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Связи нет
		ASSERT_FALSE(server.established());
	}
}
