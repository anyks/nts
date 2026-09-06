/**
 * @file dtls.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок связи поверх дейтаграмм по DTLS 1.3 (RFC 9147):
 *        заголовки записей и маска номера векторами, петлевое рукопожатие с меткой
 *        возврата состояния, потери, перестановки и повторы дейтаграмм, дробление под
 *        размер дейтаграммы, окно повторов, смена ключей с подтверждением, порча,
 *        отказы и нехватка памяти
 *
 * @note Системный openssl издания DTLS 1.3 не знает, и обмен с чужой реализацией не
 *       ведётся: байтовые заслоны закреплены векторами, посчитанными независимо
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
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <pem/pem.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <protect/protect.hpp>
#include <session/session.hpp>
#include <schedule/schedule.hpp>
#include <datagram/datagram.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <digest/hash.hpp>
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
	 * @brief Метод разбора области байтов из шестнадцатеричной записи
	 *
	 * @param text шестнадцатеричная запись области байтов
	 *
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
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
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
	 * Случайное значение просьбы о повторе приветствия: раздел 4.1.3 RFC 8446
	 */
	static const uint8_t RETRY[32] = {
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
	};
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
	 * @brief Метод снятия всех готовых дейтаграмм стороны
	 *
	 * @param from   связь стороны, отдающей дейтаграммы
	 * @param result перечень, в который помещаются дейтаграммы
	 *
	 * @return       признак успешности снятия
	 *
	 */
	template <typename T>
	bool drain(T & from, vector <vector <uint8_t>> & result) noexcept {
		/**
		 * Выполняем перехват ошибок работы с памятью
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
		 * Если памяти под дейтаграммы не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ снятия
			return false;
		}
		// Выводим успешность снятия
		return true;
	}
	/**
	 * @brief Метод переноса дейтаграмм от одной стороны к другой по описанному пути
	 *
	 * @param from      связь стороны, отдающей дейтаграммы
	 * @param to        связь стороны, принимающей дейтаграммы
	 * @param bond      описание пути между сторонами
	 * @param direction направление переноса: ноль от клиента, единица от сервера
	 *
	 * @return          признак того, что хоть одна дейтаграмма снята со стороны
	 *
	 * @note Потери считаются по направлениям: одна пара дейтаграмм на круг иначе теряла
	 *       бы всякий ответ сервера, и рукопожатие не шло бы вовсе
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
	 * @brief Метод проведения связи сторон до тишины: перенос дейтаграмм и ход часов
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param bond   описание пути между сторонами
	 * @param rounds предел кругов переноса
	 *
	 * @return       число кругов, ушедших на перенос
	 *
	 */
	size_t converse(client::context_t & client, server::context_t & server, bond_t & bond, const size_t rounds = 400) noexcept {
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
	 * @brief Метод настройки сторон связи под перенос дейтаграммами
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
		// Адрес собеседника для метки возврата состояния
		static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
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
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param bond   описание пути между сторонами
	 *
	 * @return       признак того, что обе стороны прочли отправленное
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server, bond_t & bond) noexcept {
		// Данные, отправляемые клиентом
		const string request = "ping from the client over datagrams";
		// Данные, отправляемые сервером
		const string response = "pong from the server over datagrams";
		// Если данные клиента отправить не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Если данные сервера отправить не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (response.data()), response.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Переносим дейтаграммы
		converse(client, server, bond);
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
	 * @brief Метод получения значения направления связи стороны
	 *
	 * @param context   связь стороны
	 * @param level     уровень защиты значения
	 * @param direction направление связи относительно стороны
	 *
	 * @return          значение направления либо пустой перечень
	 *
	 */
	template <typename T>
	vector <uint8_t> traffic(const T & context, const context::level_t level, const context::direction_t direction) noexcept {
		// Место, в которое помещается значение направления
		uint8_t buffer[schedule::SCHEDULE_WIDEST];
		// Длина значения направления
		size_t size = 0;
		// Если значение направления ещё не выведено
		if(!context.secret(level, direction, buffer, size))
			// Выводим пустой перечень
			return vector <uint8_t> ();
		// Выводим значение направления
		return vector <uint8_t> (buffer, buffer + size);
	}
	/**
	 * @brief Метод составления открытой записи с куском сообщения рукопожатия
	 *
	 * @param type     вид сообщения рукопожатия
	 * @param body     тело сообщения рукопожатия
	 * @param sequence порядковый номер сообщения и записи
	 *
	 * @return         дейтаграмма с открытой записью
	 *
	 */
	vector <uint8_t> plain(const handshake::type_t type, const vector <uint8_t> & body, const uint16_t sequence) noexcept {
		// Обвязка куска сообщения
		datagram::fragment_t fragment;
		// Устанавливаем вид сообщения
		fragment.type = type;
		// Устанавливаем длину сообщения
		fragment.size = body.size();
		// Устанавливаем порядковый номер сообщения
		fragment.sequence = sequence;
		// Устанавливаем смещение куска
		fragment.offset = 0;
		// Устанавливаем длину куска
		fragment.length = body.size();
		// Заголовок открытой записи
		datagram::header_t header;
		// Устанавливаем вид содержимого записи
		header.type = record::type_t::HANDSHAKE;
		// Устанавливаем порядковый номер записи
		header.sequence = sequence;
		// Устанавливаем длину содержимого записи
		header.size = (datagram::DATAGRAM_FRAGMENT_HEADER + body.size());
		// Дейтаграмма с записью
		vector <uint8_t> result(datagram::DATAGRAM_PLAIN_HEADER + header.size, 0);
		// Длина записанного заголовка
		size_t length = 0;
		// Записываем заголовок записи
		datagram::build(header, result.data(), length);
		// Записываем обвязку куска
		datagram::build(fragment, result.data() + length);
		// Переносим тело сообщения
		::memcpy(result.data() + length + datagram::DATAGRAM_FRAGMENT_HEADER, body.data(), body.size());
		// Выводим дейтаграмму
		return result;
	}
	/**
	 * @brief Метод вывода ключей поры из значения направления
	 *
	 * @param suite      набор шифрования
	 * @param secret     значение направления
	 * @param protection защита записей, которой ставится ключевой материал
	 * @param sn         место, в которое помещается ключ шифрования номера
	 *
	 * @return           признак успешности вывода ключей
	 *
	 */
	bool keys(const protect::suite_t suite, const vector <uint8_t> & secret, protect::protection_t & protection, uint8_t * sn) noexcept {
		// Ключ и вектор замены из секрета
		uint8_t key[protect::PROTECT_KEY], iv[protect::PROTECT_VECTOR];
		// Если ключ и вектор замены вывести не удалось
		if(session::material(view_t(secret.data(), secret.size()), suite, key, iv) != session::error_t::NONE)
			// Выводим отказ вывода ключей
			return false;
		// Если ключ шифрования номера меткой «sn» вывести не удалось
		if(!schedule::derive(protect::hash(suite), view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> ("sn"), 2), view_t(nullptr, 0), sn, protect::key(suite)))
			// Выводим отказ вывода ключей
			return false;
		// Выводим итог установки ключевого материала защите
		return protection.start(suite, view_t(key, protect::key(suite)), view_t(iv, protect::block(suite)));
	}
	/**
	 * @brief Метод составления защищённой записи снаружи из значения направления
	 *
	 * @param suite    набор шифрования
	 * @param secret   значение направления отправителя
	 * @param epoch    пора ключей записи
	 * @param sequence порядковый номер записи
	 * @param type     вид содержимого записи
	 * @param content  открытое содержимое записи
	 *
	 * @return         дейтаграмма с защищённой записью, пустая при отказе
	 *
	 */
	vector <uint8_t> seal(const protect::suite_t suite, const vector <uint8_t> & secret, const uint16_t epoch, const uint64_t sequence, const record::type_t type, const vector <uint8_t> & content) noexcept {
		// Защита записей снаружи
		protect::protection_t protection;
		// Ключ шифрования номера записи
		uint8_t sn[protect::PROTECT_KEY];
		// Если ключи вывести не удалось
		if(!keys(suite, secret, protection, sn))
			// Выводим пустую дейтаграмму
			return vector <uint8_t> ();
		// Длина защищённого содержимого
		const size_t size = (content.size() + 1 + protect::tag(suite));
		// Объединённый заголовок: 0b001011EE, шестнадцатиразрядный номер и длина
		const uint8_t associated[5] = {static_cast <uint8_t> (0x2C | (epoch & 0x03)), static_cast <uint8_t> ((sequence >> 8) & 0xFF), static_cast <uint8_t> (sequence & 0xFF), static_cast <uint8_t> (size >> 8), static_cast <uint8_t> (size & 0xFF)};
		// Запись с заголовком
		vector <uint8_t> result(associated, associated + sizeof(associated));
		// Если защиту наложить не удалось
		if(protection.seal(view_t(associated, sizeof(associated)), sequence, type, view_t(content.data(), content.size()), result, 0) != protect::error_t::NONE)
			// Выводим пустую дейтаграмму
			return vector <uint8_t> ();
		// Маска номера записи
		uint8_t mask[datagram::DATAGRAM_MASK];
		// Если маску выработать не удалось
		if(!datagram::mask(suite, view_t(sn, protect::key(suite)), result.data() + sizeof(associated), mask))
			// Выводим пустую дейтаграмму
			return vector <uint8_t> ();
		// Шифруем старший байт номера
		result[1] ^= mask[0];
		// Шифруем младший байт номера
		result[2] ^= mask[1];
		// Выводим дейтаграмму
		return result;
	}
	/**
	 * @brief Метод вскрытия защищённой записи снаружи из значения направления
	 *
	 * @param suite   набор шифрования
	 * @param secret  значение направления отправителя
	 * @param data    дейтаграмма с защищённой записью
	 * @param type    место, в которое помещается вид содержимого
	 * @param content накопитель, в который помещается открытое содержимое
	 *
	 * @return        признак успешности вскрытия
	 *
	 */
	bool unseal(const protect::suite_t suite, const vector <uint8_t> & secret, const vector <uint8_t> & data, record::type_t & type, vector <uint8_t> & content) noexcept {
		// Заголовок записи
		datagram::header_t header;
		// Если заголовок не объединённый с шестнадцатиразрядным номером
		if((datagram::parse(view_t(data.data(), data.size()), header) != datagram::error_t::NONE) || !header.unified || (header.bits != 16))
			// Выводим отказ вскрытия
			return false;
		// Защита записей снаружи
		protect::protection_t protection;
		// Ключ шифрования номера записи
		uint8_t sn[protect::PROTECT_KEY];
		// Если ключи вывести не удалось
		if(!keys(suite, secret, protection, sn))
			// Выводим отказ вскрытия
			return false;
		// Маска номера записи
		uint8_t mask[datagram::DATAGRAM_MASK];
		// Если маску выработать не удалось
		if(!datagram::mask(suite, view_t(sn, protect::key(suite)), data.data() + header.length, mask))
			// Выводим отказ вскрытия
			return false;
		// Заголовок с открытым номером
		vector <uint8_t> associated(data.begin(), data.begin() + header.length);
		// Снимаем маску со старшего байта номера
		associated[1] ^= mask[0];
		// Снимаем маску с младшего байта номера
		associated[2] ^= mask[1];
		// Порядковый номер записи: номера в проверках малы, старшие разряды нулевые
		const uint64_t sequence = ((static_cast <uint64_t> (associated[1]) << 8) | associated[2]);
		// Выполняем сброс накопителя содержимого
		content.clear();
		// Выводим итог снятия защиты
		return (protection.open(view_t(associated.data(), associated.size()), sequence, view_t(data.data() + header.length, header.size), type, content) == protect::error_t::NONE);
	}
	/**
	 * @brief Метод составления защищённой записи с куском сообщения рукопожатия
	 *
	 * @param suite    набор шифрования
	 * @param secret   значение направления отправителя
	 * @param epoch    пора ключей записи
	 * @param sequence порядковый номер записи
	 * @param type     вид сообщения рукопожатия
	 * @param body     тело сообщения
	 * @param message  порядковый номер сообщения
	 *
	 * @return         дейтаграмма с защищённой записью
	 *
	 */
	vector <uint8_t> sealed(const protect::suite_t suite, const vector <uint8_t> & secret, const uint16_t epoch, const uint64_t sequence, const handshake::type_t type, const vector <uint8_t> & body, const uint16_t message) noexcept {
		// Обвязка куска сообщения
		datagram::fragment_t fragment;
		// Устанавливаем вид сообщения
		fragment.type = type;
		// Устанавливаем длину сообщения
		fragment.size = body.size();
		// Устанавливаем порядковый номер сообщения
		fragment.sequence = message;
		// Устанавливаем смещение куска
		fragment.offset = 0;
		// Устанавливаем длину куска
		fragment.length = body.size();
		// Содержимое записи: обвязка и тело
		vector <uint8_t> content(datagram::DATAGRAM_FRAGMENT_HEADER, 0);
		// Записываем обвязку куска
		datagram::build(fragment, content.data());
		// Переносим тело сообщения
		content.insert(content.end(), body.begin(), body.end());
		// Выводим дейтаграмму с защищённой записью
		return seal(suite, secret, epoch, sequence, record::type_t::HANDSHAKE, content);
	}
	/**
	 * @brief Метод проведения сторон до повторного приветствия клиента с меткой
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param bond   описание пути между сторонами
	 *
	 * @return       признак того, что повторное приветствие доставлено серверу
	 *
	 */
	bool greet(client::context_t & client, server::context_t & server, bond_t & bond) noexcept {
		// Переносим приветствие, просьбу о повторе и повторное приветствие
		return (carry(client, server, bond, 0) && carry(server, client, bond, 1) && carry(client, server, bond, 0));
	}
	/**
	 * Наборы шифрования перебора
	 */
	static const protect::suite_t SUITES[] = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};
	/**
	 * Группы обмена перебора
	 */
	static const extension::group_t GROUPS[] = {extension::group_t::X25519, extension::group_t::SECP256R1};
	/**
	 * Ключи набора
	 */
	static const char * ENTRIES[] = {"ec256", "ed25519", "rsa2048"};
};

/**
 * Проверка заголовков записей поверх дейтаграмм байт в байт: открытый заголовок, объединённый
 * заголовок со всеми видами разрядов, отказы на опознаватель связи, чужое издание, ненулевую
 * пору, неведомый вид и нехватку байтов
 */
TEST(DtlsTest, Header){
	// Заголовок открытой записи
	datagram::header_t header;
	// Устанавливаем вид содержимого
	header.type = record::type_t::HANDSHAKE;
	// Устанавливаем порядковый номер записи
	header.sequence = 5;
	// Устанавливаем длину содержимого
	header.size = 3;
	// Место, в которое записывается заголовок
	uint8_t buffer[datagram::DATAGRAM_PLAIN_HEADER];
	// Длина записанного заголовка
	size_t length = 0;
	// Записываем заголовок открытой записи
	ASSERT_EQ(datagram::build(header, buffer, length), datagram::error_t::NONE);
	// Проверяем длину заголовка
	ASSERT_EQ(length, datagram::DATAGRAM_PLAIN_HEADER);
	// Проверяем заголовок байт в байт: вид, издание DTLS 1.2, нулевая пора, номер и длина
	ASSERT_EQ(vector <uint8_t> (buffer, buffer + length), decode("16FEFD00000000000000050003"));
	// Разобранный заголовок
	datagram::header_t parsed;
	// Область с заголовком и содержимым
	const vector <uint8_t> record = decode("16FEFD00000000000000050003AABBCC");
	// Разбираем заголовок открытой записи
	ASSERT_EQ(datagram::parse(view_t(record.data(), record.size()), parsed), datagram::error_t::NONE);
	// Проверяем вид заголовка
	ASSERT_FALSE(parsed.unified);
	// Проверяем вид содержимого
	ASSERT_EQ(parsed.type, record::type_t::HANDSHAKE);
	// Проверяем порядковый номер
	ASSERT_EQ(parsed.sequence, static_cast <uint64_t> (5));
	// Проверяем длину содержимого
	ASSERT_EQ(parsed.size, static_cast <size_t> (3));
	// Проверяем длину заголовка
	ASSERT_EQ(parsed.length, datagram::DATAGRAM_PLAIN_HEADER);
	// Заголовок без содержимого: нехватка байтов
	const vector <uint8_t> hungry = decode("16FEFD00000000000000050003AABB");
	// Проверяем отказ нехватки байтов
	ASSERT_EQ(datagram::parse(view_t(hungry.data(), hungry.size()), parsed), datagram::error_t::HUNGRY);
	// Заголовок с изданием TLS 1.2: раздел 4 RFC 9147 велит издание не толковать
	const vector <uint8_t> version = decode("16030300000000000000050003AABBCC");
	// Проверяем, что издание заголовка не проверяется
	ASSERT_EQ(datagram::parse(view_t(version.data(), version.size()), parsed), datagram::error_t::NONE);
	// Заголовок с изданием из чужих байтов разбирается так же
	const vector <uint8_t> arbitrary = decode("16ABCD00000000000000050003AABBCC");
	// Проверяем, что издание не читается вовсе
	ASSERT_EQ(datagram::parse(view_t(arbitrary.data(), arbitrary.size()), parsed), datagram::error_t::NONE);
	// Заголовок открытой записи с ненулевой порой
	const vector <uint8_t> epoch = decode("16FEFD00010000000000050003AABBCC");
	// Проверяем отказ поры
	ASSERT_EQ(datagram::parse(view_t(epoch.data(), epoch.size()), parsed), datagram::error_t::EPOCH);
	// Заголовок смены набора шифрования: у DTLS 1.3 такого вида нет
	const vector <uint8_t> change = decode("14FEFD0000000000000005000101");
	// Проверяем отказ вида содержимого
	ASSERT_EQ(datagram::parse(view_t(change.data(), change.size()), parsed), datagram::error_t::TYPE);
	// Объединённый заголовок
	datagram::header_t unified;
	// Заголовок объединённый
	unified.unified = true;
	// Устанавливаем пору ключей
	unified.epoch = 3;
	// Устанавливаем порядковый номер
	unified.sequence = 0x1234;
	// Устанавливаем длину содержимого
	unified.size = 0x0021;
	// Записываем объединённый заголовок
	ASSERT_EQ(datagram::build(unified, buffer, length), datagram::error_t::NONE);
	// Проверяем длину заголовка
	ASSERT_EQ(length, datagram::DATAGRAM_UNIFIED_HEADER);
	// Проверяем заголовок байт в байт: 0b00101111, номер и длина
	ASSERT_EQ(vector <uint8_t> (buffer, buffer + length), decode("2F12340021"));
	// Область с объединённым заголовком и содержимым
	vector <uint8_t> sealed = decode("2F12340021");
	// Дополняем содержимое до объявленной длины
	sealed.resize(sealed.size() + 0x21, 0xEE);
	// Разбираем объединённый заголовок
	ASSERT_EQ(datagram::parse(view_t(sealed.data(), sealed.size()), parsed), datagram::error_t::NONE);
	// Проверяем вид заголовка
	ASSERT_TRUE(parsed.unified);
	// Проверяем ширину номера
	ASSERT_EQ(parsed.bits, 16);
	// Проверяем наличие длины
	ASSERT_TRUE(parsed.sized);
	// Проверяем младшие разряды поры
	ASSERT_EQ(parsed.epoch, 3);
	// Проверяем младшие разряды номера
	ASSERT_EQ(parsed.sequence, static_cast <uint64_t> (0x1234));
	// Проверяем длину содержимого
	ASSERT_EQ(parsed.size, static_cast <size_t> (0x21));
	// Заголовок с восьмиразрядным номером и без длины: содержимое до конца дейтаграммы
	const vector <uint8_t> junior = decode("2277AABBCCDDEEFF");
	// Разбираем короткий заголовок
	ASSERT_EQ(datagram::parse(view_t(junior.data(), junior.size()), parsed), datagram::error_t::NONE);
	// Проверяем ширину номера
	ASSERT_EQ(parsed.bits, 8);
	// Проверяем отсутствие длины
	ASSERT_FALSE(parsed.sized);
	// Проверяем младшие разряды поры
	ASSERT_EQ(parsed.epoch, 2);
	// Проверяем младшие разряды номера
	ASSERT_EQ(parsed.sequence, static_cast <uint64_t> (0x77));
	// Проверяем длину содержимого: остаток дейтаграммы
	ASSERT_EQ(parsed.size, static_cast <size_t> (6));
	// Проверяем длину заголовка
	ASSERT_EQ(parsed.length, static_cast <size_t> (2));
	// Заголовок с опознавателем связи
	const vector <uint8_t> identifier = decode("3F12340021AABB");
	// Проверяем отказ опознавателя связи
	ASSERT_EQ(datagram::parse(view_t(identifier.data(), identifier.size()), parsed), datagram::error_t::IDENTIFIER);
	// Пустая область
	ASSERT_EQ(datagram::parse(view_t(nullptr, 0), parsed), datagram::error_t::HUNGRY);
}

/**
 * Проверка маски номера записи векторами, посчитанными независимо: блок AES-ECB из FIPS 197
 * (приложение C) и блок гаммы ChaCha20 из раздела 2.3.2 RFC 8439
 */
TEST(DtlsTest, Mask){
	// Ключ AES-128 из FIPS 197
	const vector <uint8_t> key128 = decode("000102030405060708090a0b0c0d0e0f");
	// Ключ AES-256 из FIPS 197
	const vector <uint8_t> key256 = decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	// Образец шифртекста: открытый текст FIPS 197
	const vector <uint8_t> sample = decode("00112233445566778899aabbccddeeff");
	// Место, в которое помещается маска
	uint8_t mask[datagram::DATAGRAM_MASK];
	// Вырабатываем маску набором AES-128
	ASSERT_TRUE(datagram::mask(protect::suite_t::AES_128_GCM_SHA256, view_t(key128.data(), key128.size()), sample.data(), mask));
	// Проверяем маску: первые байты блока 69c4e0d8…
	ASSERT_EQ(vector <uint8_t> (mask, mask + 2), decode("69c4"));
	// Вырабатываем маску набором AES-256
	ASSERT_TRUE(datagram::mask(protect::suite_t::AES_256_GCM_SHA384, view_t(key256.data(), key256.size()), sample.data(), mask));
	// Проверяем маску: первые байты блока 8ea2b7ca…
	ASSERT_EQ(vector <uint8_t> (mask, mask + 2), decode("8ea2"));
	// Ключ AES-128 ключу AES-256 не отвечает
	ASSERT_FALSE(datagram::mask(protect::suite_t::AES_256_GCM_SHA384, view_t(key128.data(), key128.size()), sample.data(), mask));
	// Образец ChaCha20: счётчик 1 от младшего байта, одноразовое значение раздела 2.3.2 RFC 8439
	const vector <uint8_t> stream = decode("01000000000000090000004a00000000");
	// Вырабатываем маску набором ChaCha20-Poly1305
	ASSERT_TRUE(datagram::mask(protect::suite_t::CHACHA20_POLY1305_SHA256, view_t(key256.data(), key256.size()), stream.data(), mask));
	// Проверяем маску: первые байты гаммы 10f1e7e4…
	ASSERT_EQ(vector <uint8_t> (mask, mask + 2), decode("10f1"));
	// Наборы ГОСТ маски не имеют
	ASSERT_FALSE(datagram::mask(protect::suite_t::KUZNYECHIK_MGM_L, view_t(key256.data(), key256.size()), sample.data(), mask));
	// Без образца маска не вырабатывается
	ASSERT_FALSE(datagram::mask(protect::suite_t::AES_128_GCM_SHA256, view_t(key128.data(), key128.size()), nullptr, mask));
}

/**
 * Проверка восстановления номера записи по младшим разрядам и окна повторов
 */
TEST(DtlsTest, Window){
	// Ближайший к ожидаемому в том же размахе
	ASSERT_EQ(datagram::restore(0x10005, 0x0007, 16), static_cast <uint64_t> (0x10007));
	// Номер за границей размаха впереди
	ASSERT_EQ(datagram::restore(0x1FFFE, 0x0001, 16), static_cast <uint64_t> (0x20001));
	// Номер за границей размаха позади
	ASSERT_EQ(datagram::restore(0x20001, 0xFFFE, 16), static_cast <uint64_t> (0x1FFFE));
	// Восьмиразрядный номер впереди
	ASSERT_EQ(datagram::restore(0x00FE, 0x02, 8), static_cast <uint64_t> (0x0102));
	// Восьмиразрядный номер позади
	ASSERT_EQ(datagram::restore(0x0102, 0xFE, 8), static_cast <uint64_t> (0x00FE));
	// Первая запись: ожидаемый ноль
	ASSERT_EQ(datagram::restore(0, 0x0003, 16), static_cast <uint64_t> (3));
	// Окно повторов
	datagram::window_t window;
	// До первой записи ожидается нулевой номер
	ASSERT_EQ(window.expected(), static_cast <uint64_t> (0));
	// Всякая запись до первой годна
	ASSERT_FALSE(window.stale(100));
	// Отмечаем запись
	window.mark(100);
	// Ожидается следующая
	ASSERT_EQ(window.expected(), static_cast <uint64_t> (101));
	// Повтор отбрасывается
	ASSERT_TRUE(window.stale(100));
	// Запись позади окна годна
	ASSERT_FALSE(window.stale(99));
	// Отмечаем запись позади
	window.mark(99);
	// Повтор отбрасывается
	ASSERT_TRUE(window.stale(99));
	// Запись на краю окна годна
	ASSERT_FALSE(window.stale(100 - datagram::DATAGRAM_WINDOW + 1));
	// Запись за окном отбрасывается
	ASSERT_TRUE(window.stale(100 - datagram::DATAGRAM_WINDOW));
	// Сдвиг окна далеко вперёд
	window.mark(1000);
	// Прежние записи ушли за окно
	ASSERT_TRUE(window.stale(101));
	// Новая запись впереди годна
	ASSERT_FALSE(window.stale(1001));
	// Сброс окна
	window.clear();
	// Всё годно вновь
	ASSERT_FALSE(window.stale(100));
}

/**
 * Проверка обвязки куска сообщения рукопожатия и сообщения подтверждения
 */
TEST(DtlsTest, Framing){
	// Обвязка куска
	datagram::fragment_t fragment;
	// Устанавливаем вид сообщения
	fragment.type = handshake::type_t::CLIENT;
	// Устанавливаем длину сообщения
	fragment.size = 0x000100;
	// Устанавливаем порядковый номер сообщения
	fragment.sequence = 2;
	// Устанавливаем смещение куска
	fragment.offset = 0x40;
	// Устанавливаем длину куска
	fragment.length = 0x30;
	// Место, в которое записывается обвязка
	uint8_t buffer[datagram::DATAGRAM_FRAGMENT_HEADER];
	// Записываем обвязку куска
	ASSERT_EQ(datagram::build(fragment, buffer), datagram::error_t::NONE);
	// Проверяем обвязку байт в байт
	ASSERT_EQ(vector <uint8_t> (buffer, buffer + sizeof(buffer)), decode("010001000002000040000030"));
	// Кусок за телом сообщения
	fragment.length = 0xC1;
	// Проверяем отказ длины
	ASSERT_EQ(datagram::build(fragment, buffer), datagram::error_t::LENGTH);
	// Область с обвязкой и телом куска
	vector <uint8_t> data = decode("010001000002000040000030");
	// Дополняем тело куска
	data.resize(data.size() + 0x30, 0x55);
	// Разобранная обвязка
	datagram::fragment_t parsed;
	// Разбираем обвязку куска
	ASSERT_EQ(datagram::parse(view_t(data.data(), data.size()), parsed), datagram::error_t::NONE);
	// Проверяем поля обвязки
	ASSERT_EQ(parsed.type, handshake::type_t::CLIENT);
	// Проверяем длину сообщения
	ASSERT_EQ(parsed.size, static_cast <size_t> (0x100));
	// Проверяем порядковый номер сообщения
	ASSERT_EQ(parsed.sequence, 2);
	// Проверяем смещение куска
	ASSERT_EQ(parsed.offset, static_cast <size_t> (0x40));
	// Проверяем длину куска
	ASSERT_EQ(parsed.length, static_cast <size_t> (0x30));
	// Обрезанное тело куска
	ASSERT_EQ(datagram::parse(view_t(data.data(), data.size() - 1), parsed), datagram::error_t::HUNGRY);
	// Кусок за телом сообщения
	const vector <uint8_t> beyond = decode("0100010000020000F0000030");
	// Проверяем отказ длины
	ASSERT_EQ(datagram::parse(view_t(beyond.data(), beyond.size()), parsed), datagram::error_t::LENGTH);
	// Неведомый вид сообщения
	const vector <uint8_t> unknown = decode("630001000002000040000030");
	// Проверяем отказ вида
	ASSERT_EQ(datagram::parse(view_t(unknown.data(), unknown.size()), parsed), datagram::error_t::TYPE);
	// Номера записей подтверждения
	vector <datagram::number_t> numbers;
	// Добавляем номер записи
	numbers.push_back(datagram::number_t(2, 7));
	// Добавляем номер записи
	numbers.push_back(datagram::number_t(3, 0x0102030405060708ULL));
	// Тело подтверждения
	vector <uint8_t> body;
	// Составляем тело подтверждения
	ASSERT_EQ(datagram::build(numbers, body), datagram::error_t::NONE);
	// Проверяем тело байт в байт
	ASSERT_EQ(body, decode("00200000000000000002000000000000000700000000000000030102030405060708"));
	// Разобранные номера записей
	vector <datagram::number_t> parsedNumbers;
	// Разбираем тело подтверждения
	ASSERT_EQ(datagram::parse(view_t(body.data(), body.size()), parsedNumbers), datagram::error_t::NONE);
	// Проверяем число номеров
	ASSERT_EQ(parsedNumbers.size(), static_cast <size_t> (2));
	// Проверяем второй номер
	ASSERT_EQ(parsedNumbers[1].epoch, static_cast <uint64_t> (3));
	// Проверяем второй номер
	ASSERT_EQ(parsedNumbers[1].sequence, static_cast <uint64_t> (0x0102030405060708ULL));
	// Тело с лишним хвостом
	body.push_back(0);
	// Проверяем отказ длины
	ASSERT_EQ(datagram::parse(view_t(body.data(), body.size()), parsedNumbers), datagram::error_t::LENGTH);
	// Пустое подтверждение законно
	const vector <uint8_t> empty = decode("0000");
	// Разбираем пустое подтверждение
	ASSERT_EQ(datagram::parse(view_t(empty.data(), empty.size()), parsedNumbers), datagram::error_t::NONE);
}

/**
 * Проверка петлевого рукопожатия поверх дейтаграмм: все наборы, группы и ключи с подлинностью
 * клиента, обязательная просьба о повторе с меткой возврата состояния, издание DTLS 1.3 в
 * приветствиях, размер дейтаграмм не выше назначенного, обмен данными в обе стороны, билет
 */
TEST(DtlsTest, Loopback){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(size_t k = 0; k < (sizeof(ENTRIES) / sizeof(ENTRIES[0])); k++){
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность из ключей набора
		ASSERT_TRUE(identity(ENTRIES[k], credential)) << "ключ " << ENTRIES[k];
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
			/**
			 * Выполняем перебор групп обмена
			 */
			for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
				// Связь стороны клиента
				client::context_t client;
				// Связь стороны сервера
				server::context_t server;
				// Настраиваем стороны с подлинностью клиента
				arrange(client, server, SUITES[s], GROUPS[g], credential, true);
				// Проверяем способ переноса
				ASSERT_EQ(client.transport(), context::transport_t::DATAGRAMS);
				// Проверяем размер дейтаграммы по умолчанию
				ASSERT_EQ(client.mtu(), datagram::DATAGRAM_MTU);
				// До заведения связи ждать нечего
				ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
				// Заводим сервер
				ASSERT_EQ(server.start(), context::error_t::NONE) << ENTRIES[k] << " " << s << " " << g;
				// Заводим клиента
				ASSERT_EQ(client.start(), context::error_t::NONE) << ENTRIES[k] << " " << s << " " << g;
				// Приветствие клиента ждёт ответа
				ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
				// Первая дейтаграмма клиента
				const view_t first = client.output();
				// Проверяем наличие дейтаграммы
				ASSERT_GT(first.size, datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER);
				// Проверяем открытый заголовок: рукопожатие, издание DTLS 1.2, нулевая пора и номер
				ASSERT_EQ(vector <uint8_t> (first.data, first.data + 11), decode("16FEFD0000000000000000"));
				// Проверяем вид сообщения куска
				ASSERT_EQ(first.data[datagram::DATAGRAM_PLAIN_HEADER], static_cast <uint8_t> (handshake::type_t::CLIENT));
				// Обвязка куска приветствия
				datagram::fragment_t fragment;
				// Разбираем обвязку куска
				ASSERT_EQ(datagram::parse(view_t(first.data + datagram::DATAGRAM_PLAIN_HEADER, first.size - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
				// Первое сообщение клиента
				ASSERT_EQ(fragment.sequence, 0);
				// Приветствие клиента целиком в одной дейтаграмме
				ASSERT_EQ(fragment.length, fragment.size);
				// Разобранное приветствие клиента
				hello::client_t greeting;
				// Разбираем приветствие клиента: поверх дейтаграмм с полем метки (раздел 5.3 RFC 9147)
				ASSERT_EQ(hello::parse(view_t(first.data + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
				// Раздел 5.3 RFC 9147: поле метки первого приветствия пусто
				ASSERT_TRUE(greeting.cookie.empty());
				// Раздел 5.3 RFC 9147: издание приветствия DTLS 1.2
				ASSERT_EQ(greeting.version, datagram::DATAGRAM_LEGACY);
				// Расширение изданий
				const hello::extension_t * versions = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
				// Проверяем наличие расширения изданий
				ASSERT_NE(versions, nullptr);
				// Перечень изданий
				vector <uint16_t> editions;
				// Разбираем перечень изданий
				ASSERT_EQ(extension::versions(versions->data, editions), extension::error_t::NONE);
				// Единственное издание - DTLS 1.3: наборов издания 1.2 у связи нет, и DTLS 1.2 (RFC 6347) не предлагается
				ASSERT_EQ(editions, vector <uint16_t> {datagram::DATAGRAM_VERSION});
				// Первое приветствие без метки
				ASSERT_EQ(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::COOKIE)), nullptr);
				// Путь между сторонами
				bond_t bond;
				// Переносим приветствие клиента серверу
				ASSERT_TRUE(carry(client, server, bond, 0));
				// Ответ сервера
				const view_t answer = server.output();
				// Проверяем наличие ответа
				ASSERT_GT(answer.size, datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER);
				// Ответ идёт открытой записью
				ASSERT_EQ(answer.data[0], static_cast <uint8_t> (record::type_t::HANDSHAKE));
				// Разбираем обвязку куска ответа
				ASSERT_EQ(datagram::parse(view_t(answer.data + datagram::DATAGRAM_PLAIN_HEADER, answer.size - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
				// Ответ - приветствие сервера
				ASSERT_EQ(fragment.type, handshake::type_t::SERVER);
				// Разобранный ответ сервера
				hello::server_t reply;
				// Разбираем ответ сервера
				ASSERT_EQ(hello::parse(view_t(answer.data + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), reply), hello::error_t::NONE);
				// Раздел 5.1 RFC 9147: первый ответ - просьба о повторе
				ASSERT_TRUE(hello::retry(reply));
				// Проверяем случайное значение просьбы о повторе
				ASSERT_EQ(::memcmp(reply.random, RETRY, sizeof(RETRY)), 0);
				// Просьба несёт метку возврата состояния
				ASSERT_NE(hello::extension(reply.extensions, static_cast <uint16_t> (extension::type_t::COOKIE)), nullptr);
				// Доля ключа пришла годной и заново не просится
				ASSERT_EQ(hello::extension(reply.extensions, static_cast <uint16_t> (extension::type_t::SHARE)), nullptr);
				// Просьба о повторе часов не ждёт
				ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
				// Переносим просьбу о повторе клиенту
				ASSERT_TRUE(carry(server, client, bond, 1));
				// Повторное приветствие клиента
				const view_t second = client.output();
				// Проверяем наличие повторного приветствия
				ASSERT_GT(second.size, static_cast <size_t> (0));
				// Разбираем обвязку куска повторного приветствия
				ASSERT_EQ(datagram::parse(view_t(second.data + datagram::DATAGRAM_PLAIN_HEADER, second.size - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
				// Второе сообщение клиента
				ASSERT_EQ(fragment.sequence, 1);
				// Разбираем повторное приветствие
				ASSERT_EQ(hello::parse(view_t(second.data + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
				// Повторное приветствие несёт метку дословно
				ASSERT_NE(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::COOKIE)), nullptr);
				// Проводим рукопожатие до тишины
				converse(client, server, bond);
				// Проверяем установленность связи клиентом
				ASSERT_TRUE(client.established()) << ENTRIES[k] << " " << s << " " << g << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
				// Проверяем установленность связи сервером
				ASSERT_TRUE(server.established()) << ENTRIES[k] << " " << s << " " << g;
				// Издание единой шкалы у клиента: 0x0304 на любом переносе, проводное 0xFEFC наружу не показывается
				ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0304));
				// Издание единой шкалы у сервера
				ASSERT_EQ(server.version(), static_cast <uint16_t> (0x0304));
				// Часы обеих сторон остановлены: залпы подтверждены
				ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
				// Часы сервера
				ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
				// Ничего не потеряно и не отброшено
				ASSERT_EQ(bond.dropped, static_cast <size_t> (0));
				// Ничего не отброшено сервером
				ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
				// Ничего не отброшено клиентом
				ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0));
				// Дейтаграммы не длиннее назначенного размера
				ASSERT_LE(bond.largest, datagram::DATAGRAM_MTU);
				// Проверяем набор шифрования
				ASSERT_EQ(client.suite(), SUITES[s]);
				// Проверяем схождение наборов
				ASSERT_EQ(server.suite(), SUITES[s]);
				// Проверяем подлинность клиента у сервера
				ASSERT_EQ(server.peer().size(), credential.chain.size());
				// Секреты прикладного уровня сторон сходятся
				ASSERT_EQ(traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE), traffic(server, context::level_t::APPLICATION, context::direction_t::READ));
				// Обмениваемся данными в обе стороны
				ASSERT_TRUE(barter(client, server, bond)) << ENTRIES[k] << " " << s << " " << g;
				// Прикладные данные идут третьей порой: младшие разряды поры в заголовке
				ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("x"), 1)), context::error_t::NONE);
				// Дейтаграмма с прикладными данными
				const view_t data = client.output();
				// Проверяем объединённый заголовок с третьей порой
				ASSERT_EQ(data.data[0] & 0xE3, 0x23);
				// Снимаем дейтаграмму
				client.consume(data.size);
				// Выдаём билет
				ASSERT_EQ(server.issue(), context::error_t::NONE);
				// Билет ждёт подтверждения
				ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT);
				// Доставляем билет
				converse(client, server, bond);
				// Билет принят
				ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
				// Билет подтверждён явно
				ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
				// Закрываем связь клиентом
				ASSERT_EQ(client.close(), context::error_t::NONE);
				// Доставляем извещение
				converse(client, server, bond);
				// Сервер принял закрытие
				ASSERT_EQ(server.state(), context::state_t::CLOSED);
			}
		}
	}
}

/**
 * Проверка потерь дейтаграмм: всякая третья по счёту направления, всякая вторая по
 * псевдослучайному ряду (лад с шагом два всегда терял бы одну и ту же дейтаграмму залпа из
 * двух), первый залп целиком и первые два; рукопожатие идёт часами и повторной передачей,
 * срок удваивается и возвращается к начальному продвижением
 */
TEST(DtlsTest, Loss){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Шаги потерь перебора: ноль означает иной закон потерь
	static const size_t PERIODS[] = {3, 0, 0, 0};
	// Зёрна псевдослучайных потерь половины дейтаграмм
	static const uint32_t SEEDS[] = {0, 20260904u, 0, 0};
	// Число начальных дейтаграмм, теряемых у сценариев без шага
	static const size_t INITIALS[] = {0, 0, 1, 2};
	/**
	 * Выполняем перебор сценариев потерь
	 */
	for(size_t i = 0; i < (sizeof(PERIODS) / sizeof(PERIODS[0])); i++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь с потерями
		bond_t bond;
		// Устанавливаем шаг потерь
		bond.period = PERIODS[i];
		// Устанавливаем зерно псевдослучайных потерь
		bond.seed = SEEDS[i];
		// Устанавливаем число начальных потерь
		bond.initial = INITIALS[i];
		// Если теряется первый залп целиком
		if(INITIALS[i] == 1){
			// Переносим приветствие клиента: оно теряется
			ASSERT_TRUE(carry(client, server, bond, 0));
			// Сервер молчит
			ASSERT_EQ(server.output().size, static_cast <size_t> (0));
			// Клиент ждёт
			ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
			// Срок истёк
			ASSERT_EQ(client.elapsed(), context::error_t::NONE);
			// Срок удвоен
			ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT * 2);
			// Приветствие повторено новым номером записи
			ASSERT_GT(client.output().size, static_cast <size_t> (0));
			// Проверяем номер записи повтора
			ASSERT_EQ(client.output().data[10], 1);
		}
		// Проводим рукопожатие до тишины
		converse(client, server, bond);
		// Проверяем установленность связи клиентом
		ASSERT_TRUE(client.established()) << "сценарий " << i << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем установленность связи сервером
		ASSERT_TRUE(server.established()) << "сценарий " << i;
		// Потери были
		ASSERT_GT(bond.dropped, static_cast <size_t> (0));
		// Часы остановлены
		ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
		// Часы сервера остановлены
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Потери повторов не портят: ни порчи, ни повторов, ни чужих пор не отброшено
		ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0)) << "сценарий " << i;
		// У клиента тоже
		ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0)) << "сценарий " << i;
		// Путь без потерь для обмена
		bond_t clean;
		// Обмениваемся данными
		ASSERT_TRUE(barter(client, server, clean)) << "сценарий " << i;
	}
}

/**
 * Проверка перестановки и повтора дейтаграмм: перевёрнутый порядок всякого переноса и
 * двойная подача всякой дейтаграммы; повторы отбрасываются окном и считаются
 */
TEST(DtlsTest, Reorder){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны: цепочка RSA дробится на несколько дейтаграмм
		arrange(client, server, SUITES[s], extension::group_t::SECP256R1, credential, true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь с перестановкой и повторами
		bond_t bond;
		// Переворачиваем порядок
		bond.reverse = true;
		// Повторяем всякую дейтаграмму
		bond.duplicate = true;
		// Проводим рукопожатие
		converse(client, server, bond);
		// Проверяем установленность связи клиентом
		ASSERT_TRUE(client.established()) << s << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем установленность связи сервером
		ASSERT_TRUE(server.established()) << s;
		// Повторы отброшены окном и посчитаны обеими сторонами именно повторами
		ASSERT_GT(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
		// Повторы у клиента
		ASSERT_GT(client.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
		/**
		 * Кроме повторов сервер отбрасывает лишь запоздалые пустые подтверждения открытой
		 * записью: перевёрнутый залп клиент откладывает и просит повтора, а просьба
		 * доходит, когда залп уже отвечен
		 */
		ASSERT_EQ(server.discarded(), server.discarded(datagram::reason_t::REPLAY) + server.discarded(datagram::reason_t::PLAIN));
		// Кроме повторов клиент отбрасывает лишь записи сверх отложенных: удвоенный перевёрнутый залп шире восьми
		ASSERT_EQ(client.discarded(), client.discarded(datagram::reason_t::REPLAY) + client.discarded(datagram::reason_t::EPOCH));
		// Ни порчи, ни подделок, ни далёких кусков
		ASSERT_EQ(server.discarded(datagram::reason_t::DAMAGE) + server.discarded(datagram::reason_t::AHEAD) + server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (0));
		// Обмениваемся данными по тому же пути
		ASSERT_TRUE(barter(client, server, bond)) << s;
	}
}

/**
 * Проверка малого размера дейтаграммы: дробление сообщений на куски, сборка с перекрытием
 * при повторах, дейтаграммы не длиннее назначенного, порог снизу
 */
TEST(DtlsTest, Mtu){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_256_GCM_SHA384, extension::group_t::SECP256R1, credential, true);
	// Размер ниже порога поднимается до порога
	client.mtu(1);
	// Проверяем порог
	ASSERT_EQ(client.mtu(), datagram::DATAGRAM_MTU_LEAST);
	// Устанавливаем малый размер клиенту
	client.mtu(300);
	// Устанавливаем малый размер серверу
	server.mtu(300);
	// Проверяем размер
	ASSERT_EQ(server.mtu(), static_cast <size_t> (300));
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t clean;
	// Переносим приветствие
	ASSERT_TRUE(carry(client, server, clean, 0));
	// Переносим просьбу о повторе
	ASSERT_TRUE(carry(server, client, clean, 1));
	// Переносим повторное приветствие
	ASSERT_TRUE(carry(client, server, clean, 0));
	// Залп сервера раздроблен: цепочка RSA в 300 байтов не входит
	vector <vector <uint8_t>> datagrams;
	// Снимаем дейтаграммы залпа
	ASSERT_TRUE(drain(server, datagrams));
	// Залп в три дейтаграммы и больше
	ASSERT_GT(datagrams.size(), static_cast <size_t> (2));
	// Обвязка куска приветствия сервера: первая дейтаграмма открытая
	datagram::fragment_t fragment;
	// Разбираем обвязку куска приветствия сервера
	ASSERT_EQ(datagram::parse(view_t(datagrams[0].data() + datagram::DATAGRAM_PLAIN_HEADER, datagrams[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
	// Приветствие сервера целиком
	ASSERT_EQ(fragment.type, handshake::type_t::SERVER);
	// Первая дейтаграмма - открытая, прочие защищены: поры не смешиваются в одной дейтаграмме
	ASSERT_EQ(datagrams[1][0] & 0xE0, 0x20);
	/**
	 * Выполняем перебор дейтаграмм залпа
	 */
	for(size_t i = 0; i < datagrams.size(); i++)
		// Дейтаграммы не длиннее назначенного
		ASSERT_LE(datagrams[i].size(), static_cast <size_t> (300));
	// Подаём приветствие сервера: без него ключей второй поры у клиента нет
	ASSERT_EQ(client.push(view_t(datagrams[0].data(), datagrams[0].size())), context::error_t::NONE);
	/**
	 * Выполняем подачу защищённых дейтаграмм клиенту в обратном порядке: сборка из кусков идёт в любом порядке
	 */
	for(size_t i = datagrams.size(); i > 1; i--)
		// Подаём очередную дейтаграмму
		ASSERT_EQ(client.push(view_t(datagrams[i - 1].data(), datagrams[i - 1].size())), context::error_t::NONE);
	// Клиент собрал залп и ответил своим
	ASSERT_GT(client.output().size, static_cast <size_t> (0));
	// Путь с потерями: повторы несут куски с перекрытием
	bond_t bond;
	// Теряется всякая четвёртая дейтаграмма
	bond.period = 4;
	// Проводим рукопожатие
	converse(client, server, bond);
	// Проверяем установленность связи клиентом
	ASSERT_TRUE(client.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем установленность связи сервером
	ASSERT_TRUE(server.established());
	// Дейтаграммы не длиннее назначенного
	ASSERT_LE(bond.largest, static_cast <size_t> (300));
	// Обмениваемся данными без потерь: прикладные данные повторной передачи не знают
	ASSERT_TRUE(barter(client, server, clean));
	// Длинные прикладные данные дробятся по записям в свои дейтаграммы
	const vector <uint8_t> bulk(5000, 0x5A);
	// Отправляем длинные данные
	ASSERT_EQ(client.write(view_t(bulk.data(), bulk.size())), context::error_t::NONE);
	// Путь без потерь для данных
	bond_t plain;
	// Переносим данные
	converse(client, server, plain);
	// Дейтаграммы данных не длиннее назначенного
	ASSERT_LE(plain.largest, static_cast <size_t> (300));
	// Принятые данные
	vector <uint8_t> received;
	// Читаем данные
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Данные дошли целиком
	ASSERT_EQ(received, bulk);
}

/**
 * Проверка окна повторов и восстановления номера: повторно поданная запись отброшена и
 * посчитана; запись с восьмиразрядным номером, сложенная снаружи из выданных секретов,
 * снимается сервером по восстановленному номеру
 */
TEST(DtlsTest, Replay){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, SUITES[s], extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь без потерь
		bond_t bond;
		// Проводим рукопожатие
		converse(client, server, bond);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established()) << s;
		// Отправляем данные клиентом
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("replay"), 6)), context::error_t::NONE);
		// Дейтаграмма с данными
		const vector <uint8_t> datagram(client.output().data, client.output().data + client.output().size);
		// Снимаем дейтаграмму
		client.consume(datagram.size());
		// Число отброшенного до подачи
		const uint64_t before = server.discarded();
		// Число повторов до подачи
		const uint64_t replays = server.discarded(datagram::reason_t::REPLAY);
		// Подаём дейтаграмму
		ASSERT_EQ(server.push(view_t(datagram.data(), datagram.size())), context::error_t::NONE);
		// Подаём ту же дейтаграмму ещё раз
		ASSERT_EQ(server.push(view_t(datagram.data(), datagram.size())), context::error_t::NONE);
		// Повтор отброшен и посчитан
		ASSERT_EQ(server.discarded(), before + 1);
		// Посчитан именно повтором
		ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), replays + 1);
		// Принятые данные
		vector <uint8_t> received;
		// Читаем данные
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Данные приняты единожды
		ASSERT_EQ(string(received.begin(), received.end()), "replay");
		// Связь не оборвана
		ASSERT_TRUE(server.established());
		// Секрет записи клиента
		const vector <uint8_t> secret = traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE);
		// Проверяем наличие секрета
		ASSERT_FALSE(secret.empty());
		// Ключ и вектор замены из секрета
		uint8_t key[protect::PROTECT_KEY], iv[protect::PROTECT_VECTOR];
		// Выводим ключ и вектор замены
		ASSERT_EQ(session::material(view_t(secret.data(), secret.size()), SUITES[s], key, iv), session::error_t::NONE);
		// Ключ шифрования номера записи
		uint8_t sn[protect::PROTECT_KEY];
		// Выводим ключ шифрования номера меткой «sn»
		ASSERT_TRUE(schedule::derive(protect::hash(SUITES[s]), view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> ("sn"), 2), view_t(nullptr, 0), sn, protect::key(SUITES[s])));
		// Защита записей снаружи
		protect::protection_t protection;
		// Устанавливаем ключевой материал
		ASSERT_TRUE(protection.start(SUITES[s], view_t(key, protect::key(SUITES[s])), view_t(iv, protect::block(SUITES[s]))));
		// Порядковый номер следующей записи клиента
		const uint64_t sequence = client.sequence(false);
		// Данные записи
		const vector <uint8_t> data = decode("6a756e696f72");
		// Длина защищённого содержимого
		const size_t size = (data.size() + 1 + protect::tag(SUITES[s]));
		// Заголовок с восьмиразрядным номером и длиной: 0b00100111
		const uint8_t associated[4] = {static_cast <uint8_t> (0x24 | 0x03), static_cast <uint8_t> (sequence & 0xFF), static_cast <uint8_t> (size >> 8), static_cast <uint8_t> (size & 0xFF)};
		// Запись с заголовком
		vector <uint8_t> crafted(associated, associated + sizeof(associated));
		// Накладываем защиту с заголовком как связанными данными
		ASSERT_EQ(protection.seal(view_t(associated, sizeof(associated)), sequence, record::type_t::APPLICATION, view_t(data.data(), data.size()), crafted, 0), protect::error_t::NONE);
		// Маска номера записи
		uint8_t mask[datagram::DATAGRAM_MASK];
		// Вырабатываем маску
		ASSERT_TRUE(datagram::mask(SUITES[s], view_t(sn, protect::key(SUITES[s])), crafted.data() + 4, mask));
		// Шифруем единственный байт номера
		crafted[1] ^= mask[0];
		// Подаём запись серверу
		ASSERT_EQ(server.push(view_t(crafted.data(), crafted.size())), context::error_t::NONE);
		// Запись снята по восстановленному номеру
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Проверяем данные
		ASSERT_EQ(received, data);
		// Ничего нового не отброшено
		ASSERT_EQ(server.discarded(), before + 1);
		// Повтор той же записи отброшен окном
		ASSERT_EQ(server.push(view_t(crafted.data(), crafted.size())), context::error_t::NONE);
		// Повтор посчитан
		ASSERT_EQ(server.discarded(), before + 2);
		// Посчитан повтором окна
		ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), replays + 2);
	}
}

/**
 * Проверка смены ключей: сообщение подтверждается, новая пора вступает лишь по подтверждению,
 * встречная смена по просьбе, данные идут четвёртой порой в обе стороны, запоздалая запись
 * прежней поры читается
 */
TEST(DtlsTest, KeyUpdate){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, SUITES[s], extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь без потерь
		bond_t bond;
		// Проводим рукопожатие
		converse(client, server, bond);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established()) << s;
		// Запись прежней поры, откладываемая до смены ключей
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("late"), 4)), context::error_t::NONE);
		// Дейтаграмма прежней поры
		const vector <uint8_t> late(client.output().data, client.output().data + client.output().size);
		// Снимаем дейтаграмму
		client.consume(late.size());
		// Секрет записи клиента до смены
		const vector <uint8_t> before = traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE);
		// Сменяем ключи клиентом с просьбой о встречной смене
		ASSERT_EQ(client.update(true), context::error_t::NONE);
		// Сообщение ждёт подтверждения
		ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
		// Раздел 8 RFC 9147: до подтверждения пора не сменяется
		ASSERT_EQ(traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE), before);
		// Данные до подтверждения идут прежней порой
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("old"), 3)), context::error_t::NONE);
		// Дейтаграмма смены ключей
		vector <vector <uint8_t>> datagrams;
		// Снимаем дейтаграммы
		ASSERT_TRUE(drain(client, datagrams));
		// Смена ключей и данные
		ASSERT_EQ(datagrams.size(), static_cast <size_t> (2));
		// Обе дейтаграммы третьей поры
		ASSERT_EQ(datagrams[1][0] & 0x03, 0x03);
		// Подаём смену ключей серверу
		ASSERT_EQ(server.push(view_t(datagrams[0].data(), datagrams[0].size())), context::error_t::NONE);
		// Подаём данные прежней поры серверу
		ASSERT_EQ(server.push(view_t(datagrams[1].data(), datagrams[1].size())), context::error_t::NONE);
		// Принятые данные
		vector <uint8_t> received;
		// Данные прежней поры прочтены после смены ключей чтения
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Проверяем данные
		ASSERT_EQ(string(received.begin(), received.end()), "old");
		// Сервер подтвердил и ответил своей сменой
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
		// Проводим обмен до тишины
		converse(client, server, bond);
		// Часы остановлены
		ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
		// Часы сервера остановлены
		ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
		// Пора клиента сменилась по подтверждению
		ASSERT_NE(traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE), before);
		// Секреты сторон сходятся после смены
		ASSERT_EQ(traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE), traffic(server, context::level_t::APPLICATION, context::direction_t::READ));
		// Секреты сторон сходятся и встречно
		ASSERT_EQ(traffic(server, context::level_t::APPLICATION, context::direction_t::WRITE), traffic(client, context::level_t::APPLICATION, context::direction_t::READ));
		// Счёт записей новой поры начат заново: подтверждение смены сервера ушло ещё прежней порой
		ASSERT_EQ(client.sequence(false), static_cast <uint64_t> (0));
		// Данные новой поры
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("new"), 3)), context::error_t::NONE);
		// Дейтаграмма новой поры: четвёртая пора, младшие разряды нулевые
		ASSERT_EQ(client.output().data[0] & 0x03, 0x00);
		// Переносим данные
		converse(client, server, bond);
		// Читаем данные
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Проверяем данные
		ASSERT_EQ(string(received.begin(), received.end()), "new");
		// Запоздалая запись прежней поры читается прежними ключами
		ASSERT_EQ(server.push(view_t(late.data(), late.size())), context::error_t::NONE);
		// Читаем запоздалые данные
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Проверяем данные
		ASSERT_EQ(string(received.begin(), received.end()), "late");
		// Данные сервера новой порой
		ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> ("back"), 4)), context::error_t::NONE);
		// Четвёртая пора сервера
		ASSERT_EQ(server.output().data[0] & 0x03, 0x00);
		// Переносим данные
		converse(client, server, bond);
		// Читаем данные
		ASSERT_EQ(client.read(received), context::error_t::NONE);
		// Проверяем данные
		ASSERT_EQ(string(received.begin(), received.end()), "back");
		// Ничего не отброшено
		ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
	}
}

/**
 * Проверка молчаливых отбросов по причинам: порча байта записи, неведомая пора,
 * опознаватель связи, чужая метка возврата состояния, дейтаграмма длиннее принимаемой,
 * подтверждения открытой записью, открытые кусок и извещение по появлении ключей, кусок
 * сообщения далеко впереди, повторы - всё отброшено без обрыва и посчитано своей причиной;
 * прикладные данные следующей поры до её ключей откладываются с пустым подтверждением и
 * читаются по приходу ключей
 */
TEST(DtlsTest, Discard){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Переносим приветствие
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Переносим просьбу о повторе
	ASSERT_TRUE(carry(server, client, bond, 1));
	// Повторное приветствие с меткой
	vector <uint8_t> second(client.output().data, client.output().data + client.output().size);
	// Снимаем дейтаграмму
	client.consume(second.size());
	// Копия с порченой меткой: метка идёт последним расширением, её имитовставка - в хвосте
	vector <uint8_t> forged = second;
	// Портим байт имитовставки метки
	forged[forged.size() - 40] ^= 0x01;
	// Подаём приветствие с чужой меткой
	ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Сервер молчит
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Приветствие отброшено чужой меткой
	ASSERT_EQ(server.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
	// Ничего иного не отброшено
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (1));
	// Сервер не оборван
	ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Дейтаграмма длиннее принимаемой: запись наибольшей длины с заголовком и ещё байт
	vector <uint8_t> oversized(datagram::DATAGRAM_LONGEST + 1, 0x16);
	// Подаём длинную дейтаграмму
	ASSERT_EQ(server.push(view_t(oversized.data(), oversized.size())), context::error_t::NONE);
	// Отброшена длиной
	ASSERT_EQ(server.discarded(datagram::reason_t::LENGTH), static_cast <uint64_t> (1));
	// Дейтаграмма предельной длины разбирается: заголовок с ненулевой порой отброшен уже порой
	oversized.pop_back();
	// Подаём дейтаграмму предельной длины
	ASSERT_EQ(server.push(view_t(oversized.data(), oversized.size())), context::error_t::NONE);
	// Отброшена порой заголовка, а не длиной
	ASSERT_EQ(server.discarded(datagram::reason_t::EPOCH), static_cast <uint64_t> (1));
	// Длиной отброшена по-прежнему одна
	ASSERT_EQ(server.discarded(datagram::reason_t::LENGTH), static_cast <uint64_t> (1));
	// Пустое подтверждение открытой записью: сервер ждёт повтора приветствия, а не часов
	const vector <uint8_t> ack = decode("1AFEFD000000000000000900020000");
	// Подаём подтверждение открытой записью
	ASSERT_EQ(server.push(view_t(ack.data(), ack.size())), context::error_t::NONE);
	// Отброшено открытой записью не ко времени
	ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (1));
	// Просьба о повторе не повторена
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Подтверждение с номерами открытой записью: номера ничем не подписаны
	const vector <uint8_t> numbered = decode("1AFEFD00000000000000100012001000000000000000000000000000000001");
	// Подаём подтверждение с номерами
	ASSERT_EQ(server.push(view_t(numbered.data(), numbered.size())), context::error_t::NONE);
	// Отброшено открытой записью
	ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (2));
	// Запись неведомой поры: младшие разряды поры 1 - первая пора не заводится вовсе
	vector <uint8_t> epoch = decode("2D0001002A");
	// Дополняем содержимое
	epoch.resize(epoch.size() + 0x2A, 0x11);
	// Подаём запись неведомой поры
	ASSERT_EQ(server.push(view_t(epoch.data(), epoch.size())), context::error_t::NONE);
	// Отброшена порой
	ASSERT_EQ(server.discarded(datagram::reason_t::EPOCH), static_cast <uint64_t> (2));
	// Запись третьей поры до второй тоже неведома: откладывается лишь следующая
	epoch[0] = 0x2F;
	// Подаём запись третьей поры
	ASSERT_EQ(server.push(view_t(epoch.data(), epoch.size())), context::error_t::NONE);
	// Отброшена порой
	ASSERT_EQ(server.discarded(datagram::reason_t::EPOCH), static_cast <uint64_t> (3));
	// Кусок сообщения далеко впереди ожидаемого
	const vector <uint8_t> ahead = plain(handshake::type_t::CLIENT, decode("00"), 40);
	// Подаём кусок
	ASSERT_EQ(server.push(view_t(ahead.data(), ahead.size())), context::error_t::NONE);
	// Отброшен далёким номером
	ASSERT_EQ(server.discarded(datagram::reason_t::AHEAD), static_cast <uint64_t> (1));
	/**
	 * Настоящее приветствие тем же номером записи, что и подделка, принимается: до
	 * подтверждения адреса окно нулевой поры не ведётся (раздел 5.1 RFC 9147) - иначе
	 * чужая запись с большим номером закрывала бы окном настоящее приветствие
	 */
	ASSERT_EQ(server.push(view_t(second.data(), second.size())), context::error_t::NONE);
	// Сервер ответил залпом
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Окном не отброшено ничего
	ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
	// Повтор принятого приветствия отброшен окном: по подтверждению адреса его запись отмечена
	ASSERT_EQ(server.push(view_t(second.data(), second.size())), context::error_t::NONE);
	// Отброшен повтором
	ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (1));
	// Всего отброшено по всем причинам
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (9));
	// Клиент повторяет приветствие по часам новым номером записи
	ASSERT_EQ(client.elapsed(), context::error_t::NONE);
	// Настоящее повторное приветствие принято тем же номером сообщения
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Сервер ответил залпом
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Проводим рукопожатие
	converse(client, server, bond);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Число отброшенного
	const uint64_t before = server.discarded();
	// Отправляем данные клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("intact"), 6)), context::error_t::NONE);
	// Дейтаграмма с данными
	vector <uint8_t> datagram(client.output().data, client.output().data + client.output().size);
	// Снимаем дейтаграмму
	client.consume(datagram.size());
	// Порченая копия
	vector <uint8_t> corrupted = datagram;
	// Портим байт шифртекста
	corrupted[corrupted.size() - 5] ^= 0x80;
	// Число порчи до подачи
	const uint64_t damaged = server.discarded(datagram::reason_t::DAMAGE);
	// Подаём порченую запись
	ASSERT_EQ(server.push(view_t(corrupted.data(), corrupted.size())), context::error_t::NONE);
	// Отброшена без обрыва
	ASSERT_EQ(server.discarded(), before + 1);
	// Отброшена именно порчей
	ASSERT_EQ(server.discarded(datagram::reason_t::DAMAGE), damaged + 1);
	// Связь жива
	ASSERT_TRUE(server.established());
	// Извещение не ушло
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Копия с опознавателем связи
	vector <uint8_t> identifier = datagram;
	// Ставим разряд опознавателя связи
	identifier[0] |= 0x10;
	// Подаём запись с опознавателем
	ASSERT_EQ(server.push(view_t(identifier.data(), identifier.size())), context::error_t::NONE);
	// Отброшена
	ASSERT_EQ(server.discarded(), before + 2);
	// Отброшена опознавателем связи
	ASSERT_EQ(server.discarded(datagram::reason_t::IDENTIFIER), static_cast <uint64_t> (1));
	// Копия с чужой порой: младшие разряды 1
	vector <uint8_t> foreign = datagram;
	// Меняем пору
	foreign[0] = static_cast <uint8_t> ((foreign[0] & 0xFC) | 0x01);
	// Число отброшенного порой до подачи
	const uint64_t epochs = server.discarded(datagram::reason_t::EPOCH);
	// Подаём запись чужой поры
	ASSERT_EQ(server.push(view_t(foreign.data(), foreign.size())), context::error_t::NONE);
	// Отброшена
	ASSERT_EQ(server.discarded(), before + 3);
	// Отброшена порой
	ASSERT_EQ(server.discarded(datagram::reason_t::EPOCH), epochs + 1);
	// Открытая запись после смены ключей: нулевая пора чтения ещё держится второй
	const vector <uint8_t> stale = plain(handshake::type_t::CLIENT, decode("00"), 0);
	// Число повторов до подачи
	const uint64_t replays = server.discarded(datagram::reason_t::REPLAY);
	// Подаём запись нулевой поры: повтор нулевого номера отброшен окном
	ASSERT_EQ(server.push(view_t(stale.data(), stale.size())), context::error_t::NONE);
	// Отброшена
	ASSERT_EQ(server.discarded(), before + 4);
	// Отброшена повтором окна
	ASSERT_EQ(server.discarded(datagram::reason_t::REPLAY), replays + 1);
	// Открытый кусок нового сообщения по появлении ключей чтения - подделка
	const vector <uint8_t> forgery = plain(handshake::type_t::CLIENT, decode("00"), 3);
	// Подаём открытый кусок свежим номером записи
	ASSERT_EQ(server.push(view_t(forgery.data(), forgery.size())), context::error_t::NONE);
	// Отброшен открытой записью не ко времени
	ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (3));
	// Открытое извещение по появлении ключей чтения тоже
	const vector <uint8_t> notice = decode("15FEFD000000000000000400020100");
	// Подаём открытое извещение
	ASSERT_EQ(server.push(view_t(notice.data(), notice.size())), context::error_t::NONE);
	// Отброшено открытой записью
	ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (4));
	// Связь жива
	ASSERT_TRUE(server.established());
	// Целая запись принята
	ASSERT_EQ(server.push(view_t(datagram.data(), datagram.size())), context::error_t::NONE);
	// Принятые данные
	vector <uint8_t> received;
	// Читаем данные
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем данные
	ASSERT_EQ(string(received.begin(), received.end()), "intact");
	// Ничего лишнего не отброшено
	ASSERT_EQ(server.discarded(), before + 6);
	// Прикладные данные до установления связи: клиент по своей поре
	client::context_t hasty;
	// Сервер
	server::context_t patient;
	// Настраиваем стороны
	arrange(hasty, patient, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(patient.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(hasty.start(), context::error_t::NONE);
	// Путь
	bond_t road;
	// Приветствие
	ASSERT_TRUE(carry(hasty, patient, road, 0));
	// Просьба о повторе
	ASSERT_TRUE(carry(patient, hasty, road, 1));
	// Повторное приветствие
	ASSERT_TRUE(carry(hasty, patient, road, 0));
	// Залп сервера
	ASSERT_TRUE(carry(patient, hasty, road, 1));
	// Клиент завершил рукопожатие своей стороной и вправе слать данные
	ASSERT_TRUE(hasty.established());
	// Залп клиента с завершением
	vector <vector <uint8_t>> flight;
	// Снимаем залп
	ASSERT_TRUE(drain(hasty, flight));
	// Данные клиента до доставки завершения
	ASSERT_EQ(hasty.write(view_t(reinterpret_cast <const uint8_t *> ("early"), 5)), context::error_t::NONE);
	// Дейтаграмма данных
	const vector <uint8_t> eager(hasty.output().data, hasty.output().data + hasty.output().size);
	// Подаём данные серверу прежде завершения: запись следующей поры откладывается до ключей
	ASSERT_EQ(patient.push(view_t(eager.data(), eager.size())), context::error_t::NONE);
	// Ничего не отброшено и связь не оборвана
	ASSERT_EQ(patient.discarded(), static_cast <uint64_t> (0));
	// Раздел 7.1 RFC 9147: вскрыть запись нечем, и сервер отвечает пустым подтверждением
	ASSERT_GT(patient.output().size, static_cast <size_t> (0));
	// Раздел 7 RFC 9147: подтверждение идёт наивысшей порой записи - третьей, ключи её у сервера уже есть
	ASSERT_EQ(patient.output().data[0] & 0xE3, 0x23);
	// Сервер ждёт завершения
	ASSERT_EQ(patient.state(), context::state_t::HANDSHAKE);
	// Данных до завершения нет
	vector <uint8_t> got;
	// Читаем данные
	ASSERT_EQ(patient.read(got), context::error_t::NONE);
	// Пусто
	ASSERT_TRUE(got.empty());
	/**
	 * Выполняем подачу залпа клиента серверу
	 */
	for(size_t i = 0; i < flight.size(); i++)
		// Подаём очередную дейтаграмму залпа
		ASSERT_EQ(patient.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
	// Связь установлена
	ASSERT_TRUE(patient.established());
	// Отложенная запись разобрана по приходу ключей
	ASSERT_EQ(patient.read(got), context::error_t::NONE);
	// Проверяем данные
	ASSERT_EQ(string(got.begin(), got.end()), "early");
	// Ничего не отброшено
	ASSERT_EQ(patient.discarded(), static_cast <uint64_t> (0));
	// Запись той же поры, но повторно поданная, отброшена окном
	ASSERT_EQ(patient.push(view_t(eager.data(), eager.size())), context::error_t::NONE);
	// Отброшена повтором
	ASSERT_EQ(patient.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (1));
	// Ничем иным
	ASSERT_EQ(patient.discarded(), static_cast <uint64_t> (1));
}

/**
 * Проверка отказов: наборы ГОСТ поверх дейтаграмм не предлагаются, упреждающие данные
 * запрещены, подача по уровням отвергается без обрыва, просьба о повторе без метки
 * обрывает клиента, приветствие TLS 1.3 обрывает сервер изданием, снятие дейтаграммы
 * целиком, повторное заведение
 */
TEST(DtlsTest, Refusals){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Наборы ГОСТ поверх дейтаграмм не предлагаются
	{
		// Сервер с одними наборами ГОСТ
		server::context_t server;
		// Клиент
		client::context_t client;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::KUZNYECHIK_MGM_L, extension::group_t::X25519, credential, false);
		// Наборов с маской номера нет
		ASSERT_EQ(server.start(), context::error_t::SETTINGS);
		// Клиент тоже
		ASSERT_EQ(client.start(), context::error_t::SETTINGS);
	}
	// Упреждающие данные поверх дейтаграмм запрещены
	{
		// Сервер с упреждающими данными
		server::context_t server;
		// Клиент с упреждающими данными
		client::context_t client;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Разрешаем упреждение серверу
		server.advance(true, 1024);
		// Разрешаем упреждение клиенту
		client.advance(true, 1024);
		// Упреждение поверх дейтаграмм запрещено
		ASSERT_EQ(server.start(), context::error_t::SETTINGS);
		// У клиента тоже
		ASSERT_EQ(client.start(), context::error_t::SETTINGS);
	}
	// Подача по уровням, снятие дейтаграммы, просьба без метки и повторное заведение
	{
		// Сервер
		server::context_t server;
		// Клиент
		client::context_t client;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Подача по уровням отвергается без обрыва
		ASSERT_EQ(server.push(context::level_t::INITIAL, view_t(reinterpret_cast <const uint8_t *> ("x"), 1)), context::error_t::LEVEL);
		// Сервер жив
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Снимаем один байт: дейтаграмма снимается целиком
		client.consume(1);
		// Дейтаграмма снята
		ASSERT_EQ(client.output().size, static_cast <size_t> (0));
		// Повторная передача возвращает приветствие
		ASSERT_EQ(client.elapsed(), context::error_t::NONE);
		// Приветствие вернулось
		ASSERT_GT(client.output().size, static_cast <size_t> (0));
		// Снятые дейтаграммы повтора
		vector <vector <uint8_t>> repeated;
		// Снимаем повтор приветствия
		ASSERT_TRUE(drain(client, repeated));
		// Обвязка куска приветствия
		datagram::fragment_t fragment;
		// Разбираем обвязку куска повторённого приветствия
		ASSERT_EQ(datagram::parse(view_t(repeated[0].data() + datagram::DATAGRAM_PLAIN_HEADER, repeated[0].size() - datagram::DATAGRAM_PLAIN_HEADER), fragment), datagram::error_t::NONE);
		// Приветствие клиента
		hello::client_t greeting;
		// Разбираем приветствие клиента: просьба обязана повторить его опознаватель связи
		ASSERT_EQ(hello::parse(view_t(repeated[0].data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), greeting, true), hello::error_t::NONE);
		// Просьба о повторе без метки, сложенная снаружи
		hello::server_t retry;
		// Издание DTLS 1.2
		retry.version = datagram::DATAGRAM_LEGACY;
		// Опознаватель связи повторяется за приветствием клиента
		retry.session = greeting.session;
		// Случайное значение просьбы о повторе
		::memcpy(retry.random, RETRY, sizeof(RETRY));
		// Набор шифрования
		retry.suite = static_cast <uint16_t> (protect::suite_t::AES_128_GCM_SHA256);
		// Расширение издания
		vector <uint8_t> version;
		// Составляем расширение издания
		ASSERT_EQ(extension::version(datagram::DATAGRAM_VERSION, version), extension::error_t::NONE);
		// Добавляем расширение издания
		retry.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
		// Тело просьбы
		vector <uint8_t> body;
		// Составляем тело просьбы
		ASSERT_EQ(hello::build(retry, body), hello::error_t::NONE);
		// Дейтаграмма с просьбой
		const vector <uint8_t> datagram = plain(handshake::type_t::SERVER, body, 0);
		// Подаём просьбу без метки клиенту
		ASSERT_EQ(client.push(view_t(datagram.data(), datagram.size())), context::error_t::MESSAGE);
		// Клиент оборван
		ASSERT_EQ(client.state(), context::state_t::FAILED);
		// Извещение об отсутствии расширения
		ASSERT_EQ(client.alert().description, alert::description_t::MISSING);
		// Извещение ушло дейтаграммой
		ASSERT_GT(client.output().size, static_cast <size_t> (0));
		// Извещение открытой записью
		ASSERT_EQ(client.output().data[0], static_cast <uint8_t> (record::type_t::ALERT));
		// Часы остановлены
		ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
		// Сброс и повторное заведение
		client.clear();
		// Клиент заводится заново
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие заново с нулевым номером
		ASSERT_EQ(client.output().data[10], 0);
		// Часы идут
		ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
	}
	// Приветствие с изданием TLS 1.3 отвергается сервером изданием
	{
		// Клиент по записям TLS 1.3
		client::context_t stream;
		// Устанавливаем набор шифрования
		stream.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Устанавливаем группу
		stream.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Заводим клиента по записям
		ASSERT_EQ(stream.start(), context::error_t::NONE);
		// Запись TLS с приветствием
		const view_t record = stream.output();
		// Приветствие без заголовка записи и обвязки TLS
		vector <uint8_t> body(record.data + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, record.data + record.size);
		// Раздел 5.3 RFC 9147: поверх дейтаграмм за опознавателем связи идёт пустое поле метки
		body.insert(body.begin() + 2 + hello::HELLO_RANDOM + 1 + hello::HELLO_SESSION, 0x00);
		// Дейтаграмма с приветствием TLS 1.3
		const vector <uint8_t> datagram = plain(handshake::type_t::CLIENT, body, 0);
		// Сервер поверх дейтаграмм
		server::context_t server;
		// Клиент-заглушка для настройки
		client::context_t client;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Приветствие с изданием TLS 1.3 отвергается изданием
		ASSERT_EQ(server.push(view_t(datagram.data(), datagram.size())), context::error_t::VERSION);
		// Сервер оборван
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Извещение об издании
		ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
	}
}

/**
 * Проверка часов: срок удваивается до предела, попытки исчерпываются отказом TIMEOUT, а
 * повторная просьба о повторе не ждёт часов и повторяется по повтору приветствия
 */
TEST(DtlsTest, Timeout){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Клиент без собеседника
	client::context_t client;
	// Сервер для настройки
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// До заведения ждать нечего
	ASSERT_EQ(client.elapsed(), context::error_t::STATE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Ожидаемый срок
	uint32_t expected = datagram::DATAGRAM_TIMEOUT;
	/**
	 * Выполняем перебор попыток повторной передачи
	 */
	for(uint32_t attempt = 0; attempt < datagram::DATAGRAM_ATTEMPTS; attempt++){
		// Проверяем срок ожидания
		ASSERT_EQ(client.timeout(), expected) << "попытка " << attempt;
		// Снимаем дейтаграммы
		vector <vector <uint8_t>> datagrams;
		// Снимаем
		ASSERT_TRUE(drain(client, datagrams));
		// Срок истёк
		ASSERT_EQ(client.elapsed(), context::error_t::NONE) << "попытка " << attempt;
		// Приветствие повторено
		ASSERT_GT(client.output().size, static_cast <size_t> (0));
		// Удваиваем ожидаемый срок до предела
		expected = (((expected * 2) > datagram::DATAGRAM_TIMEOUT_LIMIT) ? datagram::DATAGRAM_TIMEOUT_LIMIT : (expected * 2));
	}
	// Попытки исчерпаны
	ASSERT_EQ(client.elapsed(), context::error_t::TIMEOUT);
	// Связь оборвана
	ASSERT_EQ(client.state(), context::state_t::FAILED);
	// Отказ запомнен
	ASSERT_EQ(client.error(), context::error_t::TIMEOUT);
	// Часы остановлены
	ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
	// Сервер, повторяющий просьбу о повторе по повтору приветствия
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Новый клиент
	client::context_t again;
	// Сервер-заглушка
	server::context_t dummy;
	// Настраиваем стороны
	arrange(again, dummy, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим клиента
	ASSERT_EQ(again.start(), context::error_t::NONE);
	// Приветствие
	const vector <uint8_t> greeting(again.output().data, again.output().data + again.output().size);
	// Снимаем приветствие
	again.consume(greeting.size());
	// Подаём приветствие серверу
	ASSERT_EQ(server.push(view_t(greeting.data(), greeting.size())), context::error_t::NONE);
	// Просьба о повторе ушла
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Просьба о повторе
	const vector <uint8_t> retry(server.output().data, server.output().data + server.output().size);
	// Снимаем просьбу: она теряется
	server.consume(retry.size());
	// Сервер часов не ждёт
	ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
	// Повтор приветствия клиентом по его часам
	ASSERT_EQ(again.elapsed(), context::error_t::NONE);
	// Повторное приветствие
	const vector <uint8_t> repeated(again.output().data, again.output().data + again.output().size);
	// Подаём повтор серверу
	ASSERT_EQ(server.push(view_t(repeated.data(), repeated.size())), context::error_t::NONE);
	// Сервер повторил просьбу о повторе
	ASSERT_GT(server.output().size, static_cast <size_t> (0));
	// Просьба повторена новым номером записи
	ASSERT_EQ(server.output().data[10], 1);
}

/**
 * Проверка нехватки памяти: рукопожатие поверх дейтаграмм с меткой и данными на всяком
 * запасе выделений кончается успехом, нехваткой памяти либо извещением о внутреннем отказе
 */
TEST(DtlsTest, Starved){
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
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true);
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
				converse(client, server, bond);
				// Если связь установлена
				if(client.established() && server.established()){
					// Отправляем данные
					written = client.write(view_t(reinterpret_cast <const uint8_t *> ("starved datagram payload"), 24));
					// Переносим данные
					converse(client, server, bond);
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
 * Проверка привязки сборки к поре ключей: подделанная открытая запись с ожидаемым номером
 * сообщения во время защищённого рукопожатия отбрасывается своей причиной и не рвёт
 * сборку, а рукопожатие завершается настоящим залпом
 */
TEST(DtlsTest, Forgery){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Доводим до повторного приветствия
	ASSERT_TRUE(greet(client, server, bond));
	// Залп сервера
	ASSERT_TRUE(carry(server, client, bond, 1));
	// Клиент ответил завершением, а сервер ждёт его защищённым: ключи чтения второй поры у него есть
	ASSERT_GT(client.output().size, static_cast <size_t> (0));
	// Подделка: открытая запись с ожидаемым номером сообщения завершения
	const vector <uint8_t> forged = plain(handshake::type_t::FINISHED, decode("00"), 2);
	// Подаём подделку серверу
	ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Подделка отброшена открытой записью не ко времени
	ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (1));
	// Ничего иного не отброшено
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (1));
	// Сервер не оборван
	ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
	// Отброшенное не подтверждается и залп не повторяется: сервер молчит
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Настоящий залп клиента
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Связь установлена
	ASSERT_TRUE(server.established());
	// Доводим до тишины
	converse(client, server, bond);
	// Обе стороны установлены
	ASSERT_TRUE(client.established() && server.established());
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
}

/**
 * Проверка признака повтора собеседника: свой залп повторяется лишь по повтору уже
 * разобранного сообщения, а не по новым кускам раздробленного залпа и не по подделке
 */
TEST(DtlsTest, Repeat){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны с подлинностью клиента: его залп с цепочкой дробится
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true);
	// Малый размер дейтаграммы клиенту
	client.mtu(300);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Доводим до повторного приветствия
	ASSERT_TRUE(greet(client, server, bond));
	// Залп сервера
	vector <vector <uint8_t>> flight;
	// Снимаем залп сервера: клиенту он пока не доставлен
	ASSERT_TRUE(drain(server, flight));
	// Залп длиннее одной дейтаграммы
	ASSERT_GT(flight.size(), static_cast <size_t> (1));
	// Клиент не дождался ответа и повторяет приветствие по часам: настоящий повтор
	ASSERT_EQ(client.elapsed(), context::error_t::NONE);
	// Подаём повтор приветствия серверу
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Повтор залпа сервера
	vector <vector <uint8_t>> again;
	// Снимаем повтор
	ASSERT_TRUE(drain(server, again));
	// Настоящий повтор вызвал повтор залпа целиком
	ASSERT_EQ(again.size(), flight.size());
	/**
	 * Выполняем подачу первого залпа клиенту
	 */
	for(size_t i = 0; i < flight.size(); i++)
		// Подаём очередную дейтаграмму залпа
		ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
	// Залп клиента: цепочка, подтверждение владения и завершение
	vector <vector <uint8_t>> pieces;
	// Снимаем залп клиента
	ASSERT_TRUE(drain(client, pieces));
	// Залп раздроблен на несколько дейтаграмм
	ASSERT_GT(pieces.size(), static_cast <size_t> (1));
	// Место первой дейтаграммы с куском залпа: впереди идут подтверждения частей залпа сервера
	size_t start = pieces.size();
	/**
	 * Выполняем розыск первой дейтаграммы с куском рукопожатия
	 */
	for(size_t i = 0; (i < pieces.size()) && (start == pieces.size()); i++){
		// Вид содержимого записи
		record::type_t type = record::type_t::NONE;
		// Содержимое записи
		vector <uint8_t> content;
		// Вскрываем запись секретом рукопожатия клиента
		ASSERT_TRUE(unseal(protect::suite_t::AES_128_GCM_SHA256, traffic(client, context::level_t::HANDSHAKE, context::direction_t::WRITE), pieces[i], type, content)) << "дейтаграмма " << i;
		// Если запись несёт кусок рукопожатия
		if(type == record::type_t::HANDSHAKE)
			// Запоминаем место дейтаграммы
			start = i;
		// Подтверждение серверу не вредит: часть залпа подтверждена, остаток ведут часы
		else ASSERT_EQ(server.push(view_t(pieces[i].data(), pieces[i].size())), context::error_t::NONE);
	}
	// Кусок найден, за ним есть ещё
	ASSERT_LT(start + 1, pieces.size());
	// Подтверждения залпа не повторяют
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	// Подаём серверу лишь первую дейтаграмму с куском: новые куски, продвижения нет
	ASSERT_EQ(server.push(view_t(pieces[start].data(), pieces[start].size())), context::error_t::NONE);
	// Ответ сервера
	vector <vector <uint8_t>> answer;
	// Снимаем ответ
	ASSERT_TRUE(drain(server, answer));
	// Ответ - одно лишь подтверждение принятой записи, а не повтор залпа
	ASSERT_EQ(answer.size(), static_cast <size_t> (1));
	// Подтверждение короче любой дейтаграммы залпа
	ASSERT_LT(answer[0].size(), static_cast <size_t> (100));
	// Подделка: открытая запись с номером сообщения впереди ожидаемого
	const vector <uint8_t> forged = plain(handshake::type_t::FINISHED, decode("00"), 5);
	// Подаём подделку
	ASSERT_EQ(server.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Подделка отброшена
	ASSERT_EQ(server.discarded(datagram::reason_t::PLAIN), static_cast <uint64_t> (1));
	// Повтора залпа и подтверждения нет
	ASSERT_EQ(server.output().size, static_cast <size_t> (0));
	/**
	 * Выполняем подачу остатка залпа клиента
	 */
	for(size_t i = start + 1; i < pieces.size(); i++)
		// Подаём очередную дейтаграмму залпа
		ASSERT_EQ(server.push(view_t(pieces[i].data(), pieces[i].size())), context::error_t::NONE);
	// Связь установлена
	ASSERT_TRUE(server.established());
	// Доводим до тишины
	converse(client, server, bond);
	// Обе стороны установлены
	ASSERT_TRUE(client.established() && server.established());
}

/**
 * Проверка заслона второй смены ключей: пока первая не подтверждена, вторая отказывает
 * состоянием, а после подтверждения идёт
 */
TEST(DtlsTest, Rotation){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::CHACHA20_POLY1305_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established());
	// Первая смена ключей
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Раздел 8 RFC 9147: вторая смена до подтверждения первой не шлётся
	ASSERT_EQ(client.update(false), context::error_t::STATE);
	// Сервер тоже вправе сменить ключи лишь единожды до подтверждения
	ASSERT_EQ(server.update(true), context::error_t::NONE);
	// Вторая смена сервера отказывает
	ASSERT_EQ(server.update(false), context::error_t::STATE);
	// Связь жива
	ASSERT_TRUE(client.established() && server.established());
	// Доводим до тишины: смены подтверждены
	converse(client, server, bond);
	// Часы остановлены
	ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
	// После подтверждения смена идёт вновь
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Доводим до тишины
	converse(client, server, bond);
	// Секреты сторон сходятся
	ASSERT_EQ(traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE), traffic(server, context::level_t::APPLICATION, context::direction_t::READ));
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
	// Ничего не отброшено
	ASSERT_EQ(server.discarded() + client.discarded(), static_cast <uint64_t> (0));
}

/**
 * Проверка отсрочки записей второй поры и пустого подтверждения (раздел 7.1 RFC 9147):
 * при потере одного лишь приветствия сервера защищённый остаток залпа откладывается,
 * клиент отвечает пустым подтверждением открытой записью, сервер по нему повторяет залп,
 * а клиенту довольно одного приветствия из повтора; подтверждение открытой записи сервера
 * идёт второй порой с нулевой порой в номере
 */
TEST(DtlsTest, Deferral){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_256_GCM_SHA384, extension::group_t::SECP256R1, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Доводим до повторного приветствия
	ASSERT_TRUE(greet(client, server, bond));
	// Залп сервера
	vector <vector <uint8_t>> flight;
	// Снимаем залп
	ASSERT_TRUE(drain(server, flight));
	// Приветствие идёт своей открытой дейтаграммой, остаток защищён
	ASSERT_GT(flight.size(), static_cast <size_t> (1));
	// Первая дейтаграмма открытая
	ASSERT_EQ(flight[0][0], static_cast <uint8_t> (record::type_t::HANDSHAKE));
	// Вторая защищена второй порой
	ASSERT_EQ(flight[1][0] & 0xE3, 0x22);
	/**
	 * Выполняем подачу клиенту одних лишь защищённых дейтаграмм: приветствие потеряно
	 */
	for(size_t i = 1; i < flight.size(); i++)
		// Подаём очередную дейтаграмму
		ASSERT_EQ(client.push(view_t(flight[i].data(), flight[i].size())), context::error_t::NONE);
	// Записи второй поры отложены, а не отброшены
	ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0));
	// Раздел 7.1 RFC 9147: клиент шлёт пустое подтверждение открытой записью третьим номером
	const view_t hollow = client.output();
	// Проверяем пустое подтверждение байт в байт: вид 26, издание, нулевая пора, номер 2, длина 2, пустой перечень
	ASSERT_EQ(vector <uint8_t> (hollow.data, hollow.data + hollow.size), decode("1AFEFD000000000000000200020000"));
	// Срок сервера до подтверждения
	ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Переносим пустое подтверждение серверу
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Сервер повторил залп тотчас же, посчитав попытку
	ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT * 2);
	// Повтор залпа
	vector <vector <uint8_t>> again;
	// Снимаем повтор
	ASSERT_TRUE(drain(server, again));
	// Повторён весь залп
	ASSERT_EQ(again.size(), flight.size());
	// Клиенту довольно одного приветствия из повтора: остаток отложен с первого раза
	ASSERT_EQ(client.push(view_t(again[0].data(), again[0].size())), context::error_t::NONE);
	// Клиент завершил рукопожатие со своей стороны
	ASSERT_TRUE(client.established());
	// Ничего не отброшено
	ASSERT_EQ(client.discarded(), static_cast <uint64_t> (0));
	// Завершение клиента серверу
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Связь установлена
	ASSERT_TRUE(server.established());
	// Доводим до тишины
	converse(client, server, bond);
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
	// Второй клиент: доходит одно лишь приветствие сервера, остаток потерян
	client::context_t lonely;
	// Второй сервер
	server::context_t remote;
	// Настраиваем стороны
	arrange(lonely, remote, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(remote.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(lonely.start(), context::error_t::NONE);
	// Путь
	bond_t road;
	// Доводим до повторного приветствия
	ASSERT_TRUE(greet(lonely, remote, road));
	// Залп сервера
	vector <vector <uint8_t>> volley;
	// Снимаем залп
	ASSERT_TRUE(drain(remote, volley));
	// Подаём одно лишь приветствие сервера
	ASSERT_EQ(lonely.push(view_t(volley[0].data(), volley[0].size())), context::error_t::NONE);
	// Раздел 7 RFC 9147: открытая запись подтверждается наивысшей порой записи - второй
	const vector <uint8_t> ack(lonely.output().data, lonely.output().data + lonely.output().size);
	// Подтверждение защищено второй порой
	ASSERT_EQ(ack[0] & 0xE3, 0x22);
	// Вид содержимого вскрытого подтверждения
	record::type_t type = record::type_t::NONE;
	// Содержимое подтверждения
	vector <uint8_t> content;
	// Вскрываем подтверждение секретом рукопожатия клиента
	ASSERT_TRUE(unseal(protect::suite_t::AES_128_GCM_SHA256, traffic(lonely, context::level_t::HANDSHAKE, context::direction_t::WRITE), ack, type, content));
	// Это подтверждение
	ASSERT_EQ(type, record::type_t::ACK);
	// Подтверждённые номера
	vector <datagram::number_t> numbers;
	// Разбираем подтверждение
	ASSERT_EQ(datagram::parse(view_t(content.data(), content.size()), numbers), datagram::error_t::NONE);
	// Подтверждена одна запись
	ASSERT_EQ(numbers.size(), static_cast <size_t> (1));
	// Запись нулевой поры: приветствие сервера
	ASSERT_EQ(numbers[0].epoch, static_cast <uint64_t> (0));
	// Второй номер нулевой поры сервера: просьба о повторе шла первым
	ASSERT_EQ(numbers[0].sequence, static_cast <uint64_t> (1));
	// Переносим подтверждение серверу
	ASSERT_TRUE(carry(lonely, remote, road, 0));
	// Часть залпа подтверждена, остаток ведут часы: срок прежний
	ASSERT_EQ(remote.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Часы истекли
	ASSERT_EQ(remote.elapsed(), context::error_t::NONE);
	// Повтор без приветствия
	vector <vector <uint8_t>> rest;
	// Снимаем повтор
	ASSERT_TRUE(drain(remote, rest));
	/**
	 * Выполняем перебор дейтаграмм повтора
	 */
	for(size_t i = 0; i < rest.size(); i++)
		// Всякая дейтаграмма повтора защищена: приветствие подтверждено и не повторяется
		ASSERT_EQ(rest[i][0] & 0xE0, 0x20) << "дейтаграмма " << i;
	// Доводим до тишины
	converse(lonely, remote, road);
	// Обе стороны установлены
	ASSERT_TRUE(lonely.established() && remote.established());
}

/**
 * Проверка того, что отброшенные куски не подтверждаются (раздел 7 RFC 9147), и заслона
 * конца упреждающих данных (раздел 5.6): оба сообщения сложены снаружи ключами второй поры
 */
TEST(DtlsTest, Unacked){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, SUITES[s], extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Путь без потерь
		bond_t bond;
		// Доводим до повторного приветствия
		ASSERT_TRUE(greet(client, server, bond));
		// Залп сервера
		ASSERT_TRUE(carry(server, client, bond, 1));
		// Секрет записи клиента второй поры
		const vector <uint8_t> secret = traffic(client, context::level_t::HANDSHAKE, context::direction_t::WRITE);
		// Секрет выведен
		ASSERT_FALSE(secret.empty());
		// Кусок сообщения далеко впереди ожидаемого второй порой
		const vector <uint8_t> ahead = sealed(SUITES[s], secret, 2, 0, handshake::type_t::CERTIFICATE, decode("00"), 10);
		// Запись сложена
		ASSERT_FALSE(ahead.empty());
		// Подаём кусок серверу
		ASSERT_EQ(server.push(view_t(ahead.data(), ahead.size())), context::error_t::NONE);
		// Кусок отброшен далёким номером
		ASSERT_EQ(server.discarded(datagram::reason_t::AHEAD), static_cast <uint64_t> (1));
		// Отброшенное не подтверждается: сервер молчит
		ASSERT_EQ(server.output().size, static_cast <size_t> (0));
		// Сервер жив
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Раздел 5.6 RFC 9147: конца упреждающих данных не бывает, сообщение ожидаемым номером
		const vector <uint8_t> early = sealed(SUITES[s], secret, 2, 1, handshake::type_t::EARLY, vector <uint8_t> (), 2);
		// Запись сложена
		ASSERT_FALSE(early.empty());
		// Подаём сообщение серверу: связь обрывается порядком сообщений
		ASSERT_EQ(server.push(view_t(early.data(), early.size())), context::error_t::ORDER);
		// Сервер оборван
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Извещение о неожиданном сообщении
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	}
}

/**
 * Проверка адреса собеседника: без него сервер не заводится, длиннее предела он
 * отвергается, а адрес предельной длины покрывается меткой целиком и рукопожатие сходится
 */
TEST(DtlsTest, Address){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Снимаем адрес собеседника
	ASSERT_TRUE(server.address(view_t(nullptr, 0)));
	// Сервер без адреса не заводится: метку привязать не к чему
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
	// Адрес длиннее предела
	const vector <uint8_t> lengthy(datagram::DATAGRAM_ADDRESS + 1, 0x7A);
	// Отвергается
	ASSERT_FALSE(server.address(view_t(lengthy.data(), lengthy.size())));
	// Сервер по-прежнему без адреса
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
	// Адрес предельной длины
	vector <uint8_t> widest(datagram::DATAGRAM_ADDRESS, 0);
	/**
	 * Выполняем заполнение адреса различимыми байтами
	 */
	for(size_t i = 0; i < widest.size(); i++)
		// Записываем очередной байт адреса
		widest[i] = static_cast <uint8_t> (i * 7 + 3);
	// Принимается
	ASSERT_TRUE(server.address(view_t(widest.data(), widest.size())));
	// Сервер заводится
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Проводим рукопожатие: метка покрывает адрес целиком и сходится
	converse(client, server, bond);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (server.error());
	// Ничего не отброшено: метка признана
	ASSERT_EQ(server.discarded(), static_cast <uint64_t> (0));
	// Адрес меняется после установления: сброс связи снимает и его
	server.clear();
	// Заведение без адреса отказывает вновь
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
}

/**
 * Проверка сверки хеша приветствия в метке: метка, выданная другой связью с того же
 * адреса тем же секретом, сходится имитовставкой, но отвергается хешем приветствия
 */
TEST(DtlsTest, Cookie){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Общий секрет метки двух серверов
	const vector <uint8_t> secret(reinterpret_cast <const uint8_t *> ("shared stamp secret of two servers"), reinterpret_cast <const uint8_t *> ("shared stamp secret of two servers") + 34);
	// Первый клиент
	client::context_t first;
	// Первый сервер
	server::context_t one;
	// Второй клиент
	client::context_t second;
	// Второй сервер
	server::context_t two;
	// Настраиваем первую пару
	arrange(first, one, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Настраиваем вторую пару
	arrange(second, two, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Общий секрет первому серверу
	one.stamp(secret);
	// Общий секрет второму серверу
	two.stamp(secret);
	// Заводим первый сервер
	ASSERT_EQ(one.start(), context::error_t::NONE);
	// Заводим второй сервер
	ASSERT_EQ(two.start(), context::error_t::NONE);
	// Заводим первого клиента
	ASSERT_EQ(first.start(), context::error_t::NONE);
	// Заводим второго клиента
	ASSERT_EQ(second.start(), context::error_t::NONE);
	// Путь первой пары
	bond_t alpha;
	// Путь второй пары
	bond_t beta;
	// Приветствие и просьба о повторе первой пары
	ASSERT_TRUE(carry(first, one, alpha, 0) && carry(one, first, alpha, 1));
	// Приветствие и просьба о повторе второй пары
	ASSERT_TRUE(carry(second, two, beta, 0) && carry(two, second, beta, 1));
	// Повторное приветствие первого клиента с меткой первого сервера
	const vector <uint8_t> foreign(first.output().data, first.output().data + first.output().size);
	// Повторное приветствие второго клиента с меткой второго сервера
	vector <uint8_t> genuine(second.output().data, second.output().data + second.output().size);
	// Снимаем приветствие второго клиента
	second.consume(genuine.size());
	// Длина метки: поколение, хеш приветствия и имитовставка
	static constexpr size_t LABEL = 65;
	// Подделка: приветствие второго клиента с меткой первого сервера в хвосте
	vector <uint8_t> forged = genuine;
	// Переносим чужую метку: метка идёт последним расширением
	::memcpy(forged.data() + forged.size() - LABEL, foreign.data() + foreign.size() - LABEL, LABEL);
	// Подаём подделку второму серверу
	ASSERT_EQ(two.push(view_t(forged.data(), forged.size())), context::error_t::NONE);
	// Метка чужой связи отвергнута хешем приветствия
	ASSERT_EQ(two.discarded(datagram::reason_t::COOKIE), static_cast <uint64_t> (1));
	// Сервер молчит
	ASSERT_EQ(two.output().size, static_cast <size_t> (0));
	// Сервер не оборван
	ASSERT_EQ(two.state(), context::state_t::HANDSHAKE);
	/**
	 * Настоящее приветствие тем же номером записи принимается: до подтверждения адреса
	 * окно нулевой поры не ведётся, и подделка номера записи не занимает (раздел 5.1 RFC
	 * 9147) - иначе чужая запись закрывала бы окном настоящее приветствие
	 */
	ASSERT_EQ(two.push(view_t(genuine.data(), genuine.size())), context::error_t::NONE);
	// Сервер ответил залпом
	ASSERT_GT(two.output().size, static_cast <size_t> (0));
	// Окном не отброшено ничего
	ASSERT_EQ(two.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (0));
	// Повтор принятого приветствия отброшен окном: по подтверждению адреса его запись отмечена
	ASSERT_EQ(two.push(view_t(genuine.data(), genuine.size())), context::error_t::NONE);
	// Отброшено повтором
	ASSERT_EQ(two.discarded(datagram::reason_t::REPLAY), static_cast <uint64_t> (1));
	// Клиент повторяет приветствие по часам новым номером записи
	ASSERT_EQ(second.elapsed(), context::error_t::NONE);
	// Повтор доходит и принимается тем же номером сообщения: сервер повторяет залп
	ASSERT_TRUE(carry(second, two, beta, 0));
	// Сервер ответил залпом
	ASSERT_GT(two.output().size, static_cast <size_t> (0));
	// Доводим вторую пару до тишины
	converse(second, two, beta);
	// Связь установлена
	ASSERT_TRUE(second.established() && two.established());
}

/**
 * Проверка порядка номеров в подтверждении (раздел 7 RFC 9147): записи двух билетов в одной
 * дейтаграмме в обратном порядке подтверждаются по возрастанию, и подтверждение вскрыто
 * снаружи ключами третьей поры
 */
TEST(DtlsTest, Ordered){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Наименьший размер дейтаграммы серверу: билеты уходят своими дейтаграммами
	server.mtu(datagram::DATAGRAM_MTU_LEAST);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established());
	// Первый билет
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Второй билет: раздел 5.8.4 RFC 9147 дозволяет билеты без ожидания подтверждения
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Дейтаграммы билетов
	vector <vector <uint8_t>> tickets;
	// Снимаем дейтаграммы
	ASSERT_TRUE(drain(server, tickets));
	// Каждый билет своей дейтаграммой
	ASSERT_EQ(tickets.size(), static_cast <size_t> (2));
	// Дейтаграмма из двух записей в обратном порядке
	vector <uint8_t> reversed(tickets[1]);
	// Дописываем первую запись за второй
	reversed.insert(reversed.end(), tickets[0].begin(), tickets[0].end());
	// Подаём дейтаграмму клиенту
	ASSERT_EQ(client.push(view_t(reversed.data(), reversed.size())), context::error_t::NONE);
	// Оба билета приняты
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (2));
	// Подтверждение клиента
	const vector <uint8_t> ack(client.output().data, client.output().data + client.output().size);
	// Вид содержимого вскрытого подтверждения
	record::type_t type = record::type_t::NONE;
	// Содержимое подтверждения
	vector <uint8_t> content;
	// Вскрываем подтверждение секретом прикладных данных клиента
	ASSERT_TRUE(unseal(protect::suite_t::AES_128_GCM_SHA256, traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE), ack, type, content));
	// Это подтверждение
	ASSERT_EQ(type, record::type_t::ACK);
	// Подтверждённые номера
	vector <datagram::number_t> numbers;
	// Разбираем подтверждение
	ASSERT_EQ(datagram::parse(view_t(content.data(), content.size()), numbers), datagram::error_t::NONE);
	// Подтверждены обе записи
	ASSERT_EQ(numbers.size(), static_cast <size_t> (2));
	// Обе третьей поры
	ASSERT_EQ(numbers[0].epoch, static_cast <uint64_t> (3));
	// Номера по возрастанию, хотя приняты в обратном порядке
	ASSERT_LT(numbers[0].sequence, numbers[1].sequence);
	// Соседние номера
	ASSERT_EQ(numbers[1].sequence, numbers[0].sequence + 1);
	// Переносим подтверждение серверу
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Билеты подтверждены
	ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
}

/**
 * Проверка срока ожидания по разделу 5.8.2 RFC 9147: удвоенный срок держится, пока залп не
 * подтверждён без повторов, и лишь тогда возвращается к начальному; ноль означает, что
 * повторять нечего
 */
TEST(DtlsTest, Timer){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Потерянное приветствие
	vector <vector <uint8_t>> lost;
	// Теряем приветствие
	ASSERT_TRUE(drain(client, lost));
	// Срок истёк
	ASSERT_EQ(client.elapsed(), context::error_t::NONE);
	// Срок удвоен
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT * 2);
	// Путь без потерь
	bond_t bond;
	// Повтор приветствия доходит
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Просьба о повторе доходит: приветствие подтверждено, но с повтором
	ASSERT_TRUE(carry(server, client, bond, 1));
	// Повторное приветствие ждёт удвоенным сроком: срок держится
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT * 2);
	// Повторное приветствие доходит
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Залп сервера доходит: повторное приветствие подтверждено без повторов
	ASSERT_TRUE(carry(server, client, bond, 1));
	// Завершение клиента ждёт начальным сроком: срок возвращён
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Завершение доходит
	ASSERT_TRUE(carry(client, server, bond, 0));
	// Подтверждение доходит
	ASSERT_TRUE(carry(server, client, bond, 1));
	// Повторять нечего: ноль
	ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
	// У сервера тоже
	ASSERT_EQ(server.timeout(), static_cast <uint32_t> (0));
	// Обе стороны установлены
	ASSERT_TRUE(client.established() && server.established());
	// Смена ключей ждёт подтверждения начальным сроком
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Срок начальный
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Подтверждение теряется, срок истекает
	ASSERT_TRUE(drain(client, lost));
	// Срок истёк
	ASSERT_EQ(client.elapsed(), context::error_t::NONE);
	// Срок удвоен
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT * 2);
	// Доводим до тишины
	converse(client, server, bond);
	// Повторять нечего
	ASSERT_EQ(client.timeout(), static_cast <uint32_t> (0));
	// Билет сервера ждёт начальным сроком: свой залп сервера повторов не знал
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Срок начальный
	ASSERT_EQ(server.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Следующая смена клиента ждёт удвоенным сроком: смена подтверждена с повтором
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Срок держится удвоенным
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT * 2);
	// Доводим до тишины
	converse(client, server, bond);
	// Повторять нечего
	ASSERT_EQ(client.timeout() + server.timeout(), static_cast <uint32_t> (0));
	// Третья смена подтверждена без повторов: срок возвращён
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Срок начальный
	ASSERT_EQ(client.timeout(), datagram::DATAGRAM_TIMEOUT);
	// Доводим до тишины
	converse(client, server, bond);
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
}

/**
 * Проверка разных размеров дейтаграмм сторон: приём не ограничен своим размером, и стороны
 * с размерами 300 и 1200 сходятся; верхнего предела у размера нет, сервер с размером
 * 20000 шлёт дейтаграммы длиннее 1500, а запись не шире предела протокола
 */
TEST(DtlsTest, Asymmetric){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны с подлинностью клиента: обе цепочки дробятся
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true);
	// Малый размер серверу
	server.mtu(300);
	// Клиент остаётся с размером по умолчанию
	ASSERT_EQ(client.mtu(), datagram::DATAGRAM_MTU);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond);
	// Связь установлена: дейтаграммы клиента длиннее 300 сервером приняты
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Дейтаграммы клиента длиннее размера сервера были
	ASSERT_GT(bond.largest, static_cast <size_t> (300));
	// Ничего не отброшено
	ASSERT_EQ(server.discarded() + client.discarded(), static_cast <uint64_t> (0));
	// Обмениваемся данными
	ASSERT_TRUE(barter(client, server, bond));
	// Клиент с большим размером
	client::context_t wide;
	// Сервер с большим размером
	server::context_t broad;
	// Настраиваем стороны
	arrange(wide, broad, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Верхнего предела у размера нет
	broad.mtu(70000);
	// Проверяем размер
	ASSERT_EQ(broad.mtu(), static_cast <size_t> (70000));
	// Размер под сообщения SCTP
	broad.mtu(20000);
	// Заводим сервер
	ASSERT_EQ(broad.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(wide.start(), context::error_t::NONE);
	// Путь
	bond_t road;
	// Проводим рукопожатие
	converse(wide, broad, road);
	// Связь установлена
	ASSERT_TRUE(wide.established() && broad.established());
	// Длинные данные сервера
	const vector <uint8_t> bulk(40000, 0xA5);
	// Отправляем данные
	ASSERT_EQ(broad.write(view_t(bulk.data(), bulk.size())), context::error_t::NONE);
	// Дейтаграммы данных
	vector <vector <uint8_t>> datagrams;
	// Снимаем дейтаграммы
	ASSERT_TRUE(drain(broad, datagrams));
	// Данные ушли записями не шире предела протокола: три записи по 2^14
	ASSERT_EQ(datagrams.size(), static_cast <size_t> (3));
	/**
	 * Выполняем перебор дейтаграмм данных
	 */
	for(size_t i = 0; i < datagrams.size(); i++){
		// Дейтаграмма длиннее 1500
		ASSERT_GT(datagrams[i].size(), static_cast <size_t> (1500)) << "дейтаграмма " << i;
		// Дейтаграмма не длиннее принимаемой
		ASSERT_LE(datagrams[i].size(), datagram::DATAGRAM_LONGEST) << "дейтаграмма " << i;
		// Подаём дейтаграмму клиенту
		ASSERT_EQ(wide.push(view_t(datagrams[i].data(), datagrams[i].size())), context::error_t::NONE);
	}
	// Принятые данные
	vector <uint8_t> received;
	// Читаем данные
	ASSERT_EQ(wide.read(received), context::error_t::NONE);
	// Данные дошли целиком
	ASSERT_EQ(received, bulk);
	// Ничего не отброшено
	ASSERT_EQ(wide.discarded(), static_cast <uint64_t> (0));
}

/**
 * Проверка договора выдачи: ровно одна дейтаграмма за вызов output, несколько готовых записей
 * подряд уходят каждая своей дейтаграммой и ни одна не теряется
 */
TEST(DtlsTest, Output){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Путь без потерь
	bond_t bond;
	// Проводим рукопожатие
	converse(client, server, bond);
	// Связь установлена
	ASSERT_TRUE(client.established() && server.established());
	// Слова, отправляемые порознь
	static const char * WORDS[] = {"first", "second", "third", "fourth"};
	/**
	 * Выполняем отправку слов по одному
	 */
	for(size_t i = 0; i < (sizeof(WORDS) / sizeof(WORDS[0])); i++)
		// Отправляем очередное слово
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (WORDS[i]), ::strlen(WORDS[i]))), context::error_t::NONE);
	// Число снятых дейтаграмм
	size_t taken = 0;
	/**
	 * Выполняем снятие дейтаграмм по одной до пустоты
	 */
	while(client.output().size > 0){
		// Очередная дейтаграмма
		const vector <uint8_t> datagram(client.output().data, client.output().data + client.output().size);
		// Повторный вызов отдаёт ту же дейтаграмму
		ASSERT_EQ(vector <uint8_t> (client.output().data, client.output().data + client.output().size), datagram);
		// Заголовок записи
		datagram::header_t header;
		// Разбираем заголовок
		ASSERT_EQ(datagram::parse(view_t(datagram.data(), datagram.size()), header), datagram::error_t::NONE);
		// В дейтаграмме ровно одна запись
		ASSERT_EQ(header.length + header.size, datagram.size());
		// Снимаем дейтаграмму: длина не важна, снимается целиком
		client.consume(1);
		// Подаём дейтаграмму серверу
		ASSERT_EQ(server.push(view_t(datagram.data(), datagram.size())), context::error_t::NONE);
		// Считаем дейтаграмму
		taken++;
	}
	// Всякое слово ушло своей дейтаграммой
	ASSERT_EQ(taken, static_cast <size_t> (4));
	// Принятые данные
	vector <uint8_t> received;
	// Читаем данные
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Ни одно слово не потеряно
	ASSERT_EQ(string(received.begin(), received.end()), "firstsecondthirdfourth");
}
