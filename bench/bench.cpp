/**
 * @file bench.cpp
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
 * @brief Исходный файл набора замеров со сличением с эталоном
 *
 * @details Замеряется своё, а рядом - то же по роду работы у OpenSSL: хеш против хеша,
 *          поточное шифрование против поточного, шифрование с проверкой целостности
 *          против такого же, подпись и обмен ключами на кривой против кривой. Алгоритмы
 *          при этом разные - ГОСТ у нас и не ГОСТ у эталона, - и сличается здесь не
 *          совпадение итога, а цена работы одного рода.
 *
 * @note Замер берётся лучшим из нескольких прогонов, а не средним: середина ряда ловит
 *       чужую нагрузку машины, тогда как лучший прогон - это цена работы, а не цена
 *       соседства
 *
 * @note Собирать замеры отладочной сборкой бестолку: она замедляет всё разом и ровно,
 *       изображая точечную просадку там, где её нет
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <functional>
#include <fstream>
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/gost.hpp>
#include <cipher/mgm.hpp>
#include <cipher/gcm.hpp>
#include <cipher/chacha.hpp>
#include <cipher/chachapoly.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <agreement/ecdhe.hpp>
#include <agreement/vko.hpp>
#include <cipher/kuznyechik.hpp>
#include <cipher/magma.hpp>
#include <digest/streebog.hpp>
#include <digest/sha2.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <pem/pem.hpp>
#include <x509/x509.hpp>
#include <sign/rsa.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <datagram/datagram.hpp>
#include <protect/protect.hpp>
#include <digest/hash.hpp>
#include <ocsp/ocsp.hpp>

/**
 * Подключаем частный кодек сжатия цепочки сертификатов образца sample/compress
 */
#include "lz77.hpp"

/**
 * Если сличение с эталоном OpenSSL включено
 */
#ifdef ANTS_BENCH_OPENSSL
	/**
	 * Подключаем заголовочные файлы эталона
	 */
	#include <openssl/evp.h>
	#include <openssl/ec.h>
	#include <openssl/rand.h>
#endif // ANTS_BENCH_OPENSSL

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Пространство имён набора замеров
 *
 */
namespace {
	/**
	 * Размер области байтов, на которой меряется полоса
	 */
	static constexpr size_t VOLUME = (1 << 20);

	/**
	 * Число прогонов, лучший из которых и берётся замером
	 */
	static constexpr size_t ROUNDS = 6;

	/**
	 * @brief Метод дополнения названия замера до заданной ширины
	 *
	 * @param name  дополняемое название замера
	 * @param width ширина, до которой название дополняется
	 *
	 * @return      дополненное название замера
	 *
	 * @note Ширина считается знаками, а не байтами: русское название занимает по два
	 *       байта на знак, и дополнение по длине записи разъехалось бы столбцами
	 *
	 */
	string pad(const string & name, const size_t width) noexcept {
		// Число знаков в названии замера
		size_t length = 0;
		/**
		 * Выполняем перебор всех байтов названия замера
		 */
		for(size_t i = 0; i < name.length(); i++){
			// Если байт названия не является продолжением знака
			if((static_cast <uint8_t> (name[i]) & 0xC0) != 0x80)
				// Считаем знаки названия замера
				length++;
		}
		// Выводим название замера, дополненное до заданной ширины
		return (name + string(((length < width) ? (width - length) : 0), ' '));
	}
	/**
	 * @brief Метод замера числа проходов работы за секунду
	 *
	 * @param count число проходов работы в одном прогоне
	 * @param work  замеряемая работа
	 *
	 * @return      лучшее число проходов работы за секунду
	 *
	 */
	double rate(const size_t count, const function <void (void)> & work) noexcept {
		// Лучшее число проходов работы за секунду
		double result = 0.;
		/**
		 * Выполняем перебор прогонов замеряемой работы
		 */
		for(size_t i = 0; i < ROUNDS; i++){
			// Запоминаем миг начала прогона
			const auto begin = chrono::steady_clock::now();
			/**
			 * Выполняем проходы замеряемой работы
			 */
			for(size_t j = 0; j < count; j++)
				// Выполняем очередной проход замеряемой работы
				work();
			// Получаем длительность прогона в наносекундах
			const double elapsed = static_cast <double> (chrono::duration_cast <chrono::nanoseconds> (chrono::steady_clock::now() - begin).count());
			// Если прогон прошёл быстрее, чем часы его меряют
			if(elapsed <= 0.)
				// Переходим к следующему прогону замеряемой работы
				continue;
			// Получаем число проходов работы за секунду
			const double outcome = ((static_cast <double> (count) * 1e9) / elapsed);
			// Если прогон вышел лучше прежних
			if(outcome > result)
				// Запоминаем лучшее число проходов работы за секунду
				result = outcome;
		}
		// Выводим лучшее число проходов работы за секунду
		return result;
	}
	/**
	 * @brief Метод вывода замера полосы
	 *
	 * @param name   название замеряемой работы
	 * @param count  число проходов работы в одном прогоне
	 * @param volume размер области байтов одного прохода работы
	 * @param work   замеряемая работа
	 *
	 * @return       полоса замеряемой работы в мегабайтах за секунду
	 *
	 */
	double band(const string & name, const size_t count, const size_t volume, const function <void (void)> & work) noexcept {
		// Выполняем замер числа проходов работы за секунду
		const double outcome = ((rate(count, work) * static_cast <double> (volume)) / static_cast <double> (1 << 20));
		// Выводим название замеряемой работы
		cout << pad(name, 28) << setw(12) << right << fixed << setprecision(1) << outcome << " МБ/с" << endl;
		// Выводим полосу замеряемой работы
		return outcome;
	}
	/**
	 * @brief Метод вывода замера числа проходов работы
	 *
	 * @param name  название замеряемой работы
	 * @param count число проходов работы в одном прогоне
	 * @param work  замеряемая работа
	 *
	 * @return      число проходов замеряемой работы за секунду
	 *
	 */
	double count(const string & name, const size_t count, const function <void (void)> & work) noexcept {
		// Выполняем замер числа проходов работы за секунду
		const double outcome = rate(count, work);
		// Выводим название замеряемой работы
		cout << pad(name, 28) << setw(12) << right << fixed << setprecision(0) << outcome << " раз/с" << endl;
		// Выводим число проходов замеряемой работы за секунду
		return outcome;
	}
	/**
	 * @brief Метод вывода отношения замеров одного рода работы
	 *
	 * @param name название сличаемого рода работы
	 * @param ours замер своей работы
	 * @param them замер работы эталона
	 *
	 * @note Отношение выводится отставанием, а не долей: доля отставания в полторы тысячи
	 *       раз округляется в ноль и перестаёт что-либо говорить
	 *
	 */
	[[maybe_unused]] void relation(const string & name, const double ours, const double them) noexcept {
		// Если сличать замеры не с чем
		if((ours <= 0.) || (them <= 0.))
			// Выходим из вывода отношения замеров
			return;
		// Выводим название сличаемого рода работы
		cout << pad(name, 28) << setw(12) << right << fixed << setprecision(1) << (them / ours) << " раз медленнее" << endl;
	}
	/**
	 * @brief Метод чтения файла набора ключей для сличения
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
	 * @brief Метод получения середины ряда замеров
	 *
	 * @param values ряд замеров
	 *
	 * @return       середина ряда, ноль у пустого ряда
	 *
	 */
	double median(vector <double> values) noexcept {
		// Если ряд пуст
		if(values.empty())
			// Выводим ноль
			return 0.;
		// Упорядочиваем ряд
		sort(values.begin(), values.end());
		// Выводим середину ряда
		return values[values.size() / 2];
	}
	/**
	 * @brief Метод составления записи приветствия клиента издания TLS 1.2 под обмен RSA
	 *
	 * @param result накопитель, в который складывается запись приветствия
	 *
	 * @return       признак успешности составления
	 *
	 */
	bool greeting(vector <uint8_t> & result) noexcept {
		// Составляемое приветствие
		hello::client_t hello;
		// Издание TLS 1.2 заголовком
		hello.version = 0x0303;
		/**
		 * Выполняем заполнение случайного значения
		 */
		for(size_t i = 0; i < sizeof(hello.random); i++)
			// Записываем очередной байт
			hello.random[i] = static_cast <uint8_t> (i);
		// Набор обмена RSA
		hello.suites = {static_cast <uint16_t> (protect::suite_t::RSA_AES_128_GCM_SHA256)};
		// Способ сжатия
		hello.methods = {0x00};
		// Тело расширения схем подписи
		vector <uint8_t> schemes;
		// Если схемы составить не удалось
		if(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::RSA_PSS_RSAE_SHA256}, schemes) != extension::error_t::NONE)
			// Выводим отказ
			return false;
		// Добавляем схемы
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Добавляем расширенный главный секрет
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Тело приветствия
		vector <uint8_t> body;
		// Если тело составить не удалось
		if(hello::build(hello, body) != hello::error_t::NONE)
			// Выводим отказ
			return false;
		// Составитель сообщения рукопожатия
		handshake::writer_t writer;
		// Если сообщение составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ
			return false;
		// Нарезчик записей
		record::writer_t records;
		// Если запись составить не удалось
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ
			return false;
		// Запись приветствия
		const view_t data = records.data();
		// Переносим запись
		result.assign(data.data, data.data + data.size);
		// Выводим успешность
		return true;
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
		/**
		 * Выполняем перебор направлений передачи байтов между сторонами связи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем байты, отправляемые стороной связи
			const view_t data = ((i == 0) ? client.output() : server.output());
			// Если стороне связи отправлять нечего
			if(data.size == 0)
				// Переходим к встречному направлению передачи байтов
				continue;
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Если байты передаются от клиента серверу
			if(i == 0){
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
				// Выполняем подачу отправленных байтов серверу
				server.push(view_t(buffer.data(), buffer.size()));
			// Если байты передаются от сервера клиенту
			} else {
				// Снимаем отправленные байты с накопителя сервера
				server.consume(buffer.size());
				// Выполняем подачу отправленных байтов клиенту
				client.push(view_t(buffer.data(), buffer.size()));
			}
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи записями до тишины
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что рукопожатие пройдено обеими сторонами
	 *
	 */
	bool converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
		// Выводим установленность связи обеими сторонами
		return (client.established() && server.established());
	}
	/**
	 * @brief Метод составления подлинности стороны из набора ключей
	 *
	 * @param key         имя файла секретного ключа в записи PEM
	 * @param certificate имя файла сертификата либо цепочки в записи PEM
	 * @param result      подлинность, в которую помещается итог
	 *
	 * @return            признак успешности составления подлинности
	 *
	 */
	bool keyed(const char * key, const char * certificate, context::credential_t & result) noexcept {
		// Читаем секретный ключ в записи PEM: связь принимает и её
		result.secret = corpus(key);
		// Читаем сертификат в записи PEM
		const vector <uint8_t> text = corpus(certificate);
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
	 * @brief Вызов сервера: ключ по опознавателю клиента
	 *
	 * @param identity опознаватель клиента, здесь не судится
	 * @param key      накопитель, в который помещается ключ
	 * @param context  указатель на ключ сервера
	 *
	 * @return         признак того, что ключ выдан
	 *
	 * @note Вызов не noexcept намеренно: нехватку памяти в накопителе перехватывает связь
	 *
	 */
	bool responding(const view_t & identity, vector <uint8_t> & key, void * context) {
		// Опознаватель замеру безразличен
		(void) identity;
		// Выдаём ключ сервера
		key = *reinterpret_cast <const vector <uint8_t> *> (context);
		// Ключ выдан
		return true;
	}
	/**
	 * @brief Метод проведения рукопожатия издания TLS 1.2 записями
	 *
	 * @param credential подлинность сервера, при заранее разделённом ключе не нужна
	 * @param suite      набор шифрования обеих сторон
	 * @param psk        настройки заранее разделённого ключа клиента либо nullptr
	 * @param vault      ключ билетов сервера либо nullptr
	 * @param ticket     билет, предъявляемый клиентом, либо nullptr
	 * @param issued     место, в которое помещается выданный билет, либо nullptr
	 *
	 * @return           признак того, что рукопожатие пройдено и ожидания сошлись
	 *
	 */
	bool legacy(const context::credential_t & credential, const protect::suite_t suite, const context::psk_t * psk, const vector <uint8_t> * vault, const context::ticket_t * ticket, context::ticket_t * issued) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Набор шифрования клиента
		client.suites(vector <protect::suite_t> {suite});
		// Набор шифрования сервера
		server.suites(vector <protect::suite_t> {suite});
		// Группа обмена клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Группа обмена сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Если заранее разделённого ключа нет
		if(psk == nullptr)
			// Устанавливаем подлинность сервера
			server.credential(credential);
		// Если заранее разделённый ключ есть
		else {
			// Настройки заранее разделённого ключа сервера
			context::psk_t mine;
			// Вызов ключа по опознавателю
			mine.respond = responding;
			// Указатель на ключ
			mine.context = psk->context;
			// Устанавливаем настройки серверу
			server.psk(mine);
			// Устанавливаем настройки клиенту
			client.psk(*psk);
		}
		// Если ключ билетов задан
		if(vault != nullptr){
			// Устанавливаем ключ билетов серверу
			server.vault(*vault);
			// Миг клиента, которым судятся сроки билетов
			client.moment(1790000000);
			// Миг сервера
			server.moment(1790000000);
		}
		// Если билет предъявляется
		if(ticket != nullptr)
			// Предъявляем билет
			client.resume(*ticket);
		// Если пределы издания клиента установить не удалось
		if(client.versions(0x0303, 0x0303) != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отказ
			return false;
		// Если рукопожатие не пройдено
		if(!converse(client, server))
			// Выводим отказ
			return false;
		// Если билет предъявлялся, а возобновления не вышло
		if((ticket != nullptr) && !client.shared())
			// Выводим отказ
			return false;
		// Если выданный билет запрашивается
		if(issued != nullptr){
			// Если билет не выдан
			if(client.tickets().empty())
				// Выводим отказ
				return false;
			// Запоминаем выданный билет
			*issued = client.tickets()[0];
		}
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод переноса всех готовых дейтаграмм от одной стороны к другой
	 *
	 * @param from связь стороны, отдающей дейтаграммы
	 * @param to   связь стороны, принимающей дейтаграммы
	 *
	 * @return     признак того, что хоть одна дейтаграмма перенесена
	 *
	 */
	template <typename A, typename B>
	bool ferry(A & from, B & to) noexcept {
		// Признак того, что дейтаграммы переносились
		bool moved = false;
		/**
		 * Выполняем перенос дейтаграмм по одной: просмотр отдаёт первую из очереди
		 */
		while(from.output().size > 0){
			// Получаем очередную дейтаграмму
			const view_t data = from.output();
			// Переносим дейтаграмму
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем дейтаграмму с накопителя
			from.consume(buffer.size());
			// Подаём дейтаграмму принимающей стороне
			to.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем перенос
			moved = true;
		}
		// Выводим признак переноса
		return moved;
	}
	/**
	 * @brief Метод настройки и рукопожатия сторон поверх дейтаграмм
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param legacy     ведётся ли связь изданием DTLS 1.2
	 *
	 * @return           признак того, что рукопожатие пройдено обеими сторонами
	 *
	 */
	bool settle(client::context_t & client, server::context_t & server, const context::credential_t & credential, const bool legacy) noexcept {
		// Перенос дейтаграммами у клиента
		client.transport(context::transport_t::DATAGRAMS);
		// Перенос дейтаграммами у сервера
		server.transport(context::transport_t::DATAGRAMS);
		// Набор шифрования по изданию
		const protect::suite_t suite = (legacy ? protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256 : protect::suite_t::AES_128_GCM_SHA256);
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
		// Адрес собеседника для метки возврата состояния
		static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
		// Если адрес установить не удалось
		if(!server.address(view_t(ADDRESS, sizeof(ADDRESS))))
			// Выводим отказ
			return false;
		// Издание по пределам
		const uint16_t edition = (legacy ? 0x0303 : 0x0304);
		// Если пределы издания либо заведение связи не удались
		if((client.versions(edition, edition) != context::error_t::NONE) || (server.versions(edition, edition) != context::error_t::NONE) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отказ
			return false;
		/**
		 * Выполняем перенос дейтаграмм до тишины: без потерь часы не ходят
		 */
		for(size_t round = 0; round < 64; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Переносим дейтаграммы клиента серверу
			bool moved = ferry(client, server);
			// Переносим дейтаграммы сервера клиенту
			moved = (ferry(server, client) || moved);
			// Если дейтаграммы переносились
			if(moved)
				// Переходим к следующему кругу
				continue;
			// Признак хода часов
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
		// Выводим установленность связи обеими сторонами
		return (client.established() && server.established());
	}
	/**
	 * @brief Метод передачи прикладных данных по установленной связи поверх дейтаграмм
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param payload  передаваемые данные: не длиннее одной дейтаграммы
	 * @param count    число передач
	 * @param received накопитель принятых сервером данных
	 *
	 * @return         признак того, что всё переданное принято
	 *
	 */
	bool transfer(client::context_t & client, server::context_t & server, const view_t & payload, const size_t count, vector <uint8_t> & received) noexcept {
		// Число принятых байтов
		size_t taken = 0;
		/**
		 * Выполняем передачи по одной записи в дейтаграмме
		 */
		for(size_t i = 0; i < count; i++){
			// Если данные отправить не удалось
			if(client.write(payload) != context::error_t::NONE)
				// Выводим отказ
				return false;
			// Переносим дейтаграмму серверу
			ferry(client, server);
			// Если принятое прочитать не удалось
			if(server.read(received) != context::error_t::NONE)
				// Выводим отказ
				return false;
			// Считаем принятые байты
			taken += received.size();
		}
		// Выводим признак того, что всё переданное принято
		return (taken == (payload.size * count));
	}
	/**
	 * @brief Метод заведения защиты записей издания 1.2 случайным ключевым материалом
	 *
	 * @param suite  набор шифрования
	 * @param sealer защита отправляющей стороны
	 * @param opener защита принимающей стороны
	 * @param etm    порядок RFC 7366 у наборов CBC
	 *
	 * @return       признак успешности заведения
	 *
	 */
	bool keying(const protect::suite_t suite, protect::protection_t & sealer, protect::protection_t & opener, const bool etm) noexcept {
		// Ключ шифрования набора
		vector <uint8_t> key(protect::key(suite), 0);
		// Неявная часть вектора набора: ноль у наборов CBC
		vector <uint8_t> salt(protect::block(suite), 0);
		// Ключ имитовставки: ноль у наборов AEAD
		vector <uint8_t> mac(digest::length(protect::mac(suite)), 0);
		// Если ключевой материал выработать не удалось
		if(!entropy::bytes(key.data(), key.size()) || (!salt.empty() && !entropy::bytes(salt.data(), salt.size())) || (!mac.empty() && !entropy::bytes(mac.data(), mac.size())))
			// Выводим отказ
			return false;
		// Если защиту отправляющей стороны завести не удалось
		if(!sealer.start(suite, view_t(key.data(), key.size()), view_t(salt.data(), salt.size()), view_t(mac.data(), mac.size())))
			// Выводим отказ
			return false;
		// Если защиту принимающей стороны завести не удалось
		if(!opener.start(suite, view_t(key.data(), key.size()), view_t(salt.data(), salt.size()), view_t(mac.data(), mac.size())))
			// Выводим отказ
			return false;
		// Порядок RFC 7366 у отправляющей стороны
		sealer.etm(etm);
		// Порядок RFC 7366 у принимающей стороны
		opener.etm(etm);
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод наложения и снятия защиты одной записи издания 1.2
	 *
	 * @param sealer   защита отправляющей стороны
	 * @param opener   защита принимающей стороны
	 * @param sequence порядковый номер записи
	 * @param data     содержимое записи
	 * @param sealed   накопитель защищённой записи
	 * @param opened   накопитель снятого содержимого
	 *
	 * @return         признак успешности наложения и снятия защиты
	 *
	 * @note Обвязка издания 1.2 одна на наборы CBC и AEAD: явный вектор либо явная часть
	 *       одноразового значения, шифртекст и имитовставка либо метка складываются в
	 *       накопитель, а заголовок записи составляет слой записей снаружи
	 *
	 */
	bool roundtrip(protect::protection_t & sealer, protect::protection_t & opener, const uint64_t sequence, const view_t & data, vector <uint8_t> & sealed, vector <uint8_t> & opened) noexcept {
		// Очищаем накопитель защищённой записи: защита в него дописывает
		sealed.clear();
		// Очищаем накопитель снятого содержимого
		opened.clear();
		// Если защиту наложить не удалось
		if(sealer.wrap(sequence, record::version_t::TLS12, record::type_t::APPLICATION, data, sealed) != protect::error_t::NONE)
			// Выводим отказ
			return false;
		// Выводим итог снятия защиты
		return (opener.unwrap(sequence, record::version_t::TLS12, record::type_t::APPLICATION, view_t(sealed.data(), sealed.size()), opened) == protect::error_t::NONE);
	}
};

/**
 * Подключаем заголовочный файл выработки подлинности стороны связи
 */
#include "identity.hpp"

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
	// Область байтов, на которой меряется полоса
	vector <uint8_t> data(VOLUME, 0x5A);
	// Место, в которое помещается итог работы над областью байтов
	vector <uint8_t> result(VOLUME, 0);
	// Выводим заголовок замеров своей работы
	cout << "Замеры ANTS" << endl << endl;
	// Место, в которое помещается хеш области байтов
	uint8_t hash[64];
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ её меряется мгновением и
	 * выдаёт полосу, которой не бывает
	 */
	if(!digest::streebog(digest::type_t::SHORT, view_t(data.data(), data.size()), hash, 32)){
		// Выводим сообщение об отказе хеширования области байтов
		cout << "Выработать хеш области байтов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы хеширования «Стрибог» с длиной хеша 256 разрядов
	const double streebog = band("Стрибог-256", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::streebog(digest::type_t::SHORT, view_t(data.data(), data.size()), hash, 32);
	});
	// Выполняем замер полосы хеширования «Стрибог» с длиной хеша 512 разрядов
	band("Стрибог-512", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::streebog(digest::type_t::LONG, view_t(data.data(), data.size()), hash, 64);
	});
	// Выполняем замер полосы хеширования SHA-256 своей работы
	const double sha256 = band("SHA-256 своя", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::sha2(digest::sha_t::SHA256, view_t(data.data(), data.size()), hash, 32);
	});
	// Выполняем замер полосы хеширования SHA-512 своей работы
	const double sha512 = band("SHA-512 своя", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::sha2(digest::sha_t::SHA512, view_t(data.data(), data.size()), hash, 64);
	});
	// Ключ блочного шифрования области байтов
	uint8_t key[32];
	// Выполняем выработку ключа блочного шифрования
	entropy::bytes(key, sizeof(key));
	// Объект блочного шифра «Кузнечик»
	cipher::kuznyechik_t kuznyechik;
	// Если ключ блочного шифра установить не удалось
	if(!kuznyechik.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ блочного шифра не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового алгоритма блочного шифрования
	const cipher::block_t block(kuznyechik);
	// Вектор замены поточного шифрования
	uint8_t nonce[8];
	// Выполняем выработку вектора замены поточного шифрования
	entropy::bytes(nonce, sizeof(nonce));
	// Объект режима гаммирования
	cipher::counter_t counter;
	// Если режим гаммирования завести не удалось
	if(!counter.start(block, view_t(nonce, sizeof(nonce)))){
		// Выводим сообщение об отказе заведения режима
		cout << "Завести режим гаммирования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если поточное шифрование области байтов не удалось
	if(!counter.encrypt(view_t(data.data(), data.size()), result.data())){
		// Выводим сообщение об отказе поточного шифрования
		cout << "Выполнить поточное шифрование не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы поточного шифрования «Кузнечик»
	const double stream = band("Кузнечик-CTR", 8, VOLUME, [&counter, &data, &result]() noexcept -> void {
		// Выполняем поточное шифрование области байтов
		counter.encrypt(view_t(data.data(), data.size()), result.data());
	});
	// Место, в которое помещается имитовставка шифрования
	uint8_t tag[16];
	// Начальное заполнение счётчика шифрования с проверкой целостности
	uint8_t seed[cipher::KUZNYECHIK_BLOCK];
	// Выполняем выработку начального заполнения счётчика
	entropy::bytes(seed, sizeof(seed));
	/**
	 * Раздел 4.2 RFC 9058 велит держать старший разряд начального заполнения нулевым
	 */
	seed[0] &= 0x7F;
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Если режим шифрования с проверкой целостности завести не удалось
	if(!galois.start(block, view_t(seed, sizeof(seed))) || !galois.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag)){
		// Выводим сообщение об отказе шифрования с проверкой целостности
		cout << "Завести шифрование с проверкой целостности не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования с проверкой целостности
	const double sealed = band("Кузнечик-MGM", 8, VOLUME, [&galois, &block, &seed, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима шифрования с проверкой целостности
		galois.start(block, view_t(seed, sizeof(seed)));
		// Выполняем шифрование области байтов с проверкой целостности
		galois.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Объект блочного шифра AES
	cipher::aes_t rijndael;
	// Если ключ AES-256 установить не удалось
	if(!rijndael.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ блочного шифра AES не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового алгоритма блочного шифрования AES
	const cipher::block_t standard(rijndael);
	// Режим сцепления блоков
	cipher::chaining_t chaining;
	// Выполняем замер полосы шифрования AES-256-CBC своей работы
	const double cbc = band("AES-256-CBC своя", 8, VOLUME, [&chaining, &standard, &seed, &data, &result]() noexcept -> void {
		// Выполняем заведение режима сцепления блоков
		chaining.start(standard, view_t(seed, 16));
		// Выполняем шифрование области байтов
		chaining.encrypt(view_t(data.data(), data.size()), result.data());
	});
	// Режим шифрования с проверкой целостности GCM
	cipher::gcm_t galoisCounter;
	// Выполняем замер полосы шифрования AES-256-GCM своей работы
	const double aead = band("AES-256-GCM своя", 8, VOLUME, [&galoisCounter, &standard, &seed, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима
		galoisCounter.start(standard, view_t(seed, 12));
		// Выполняем шифрование области байтов с проверкой целостности
		galoisCounter.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Поточный шифр ChaCha20
	cipher::chacha_t chacha;
	// Если поточный шифр ChaCha20 запустить не удалось
	if(!chacha.start(view_t(key, sizeof(key)), view_t(seed, cipher::CHACHA_NONCE)) || !chacha.encrypt(view_t(data.data(), data.size()), result.data())){
		// Выводим сообщение об отказе поточного шифрования
		cout << "Выполнить поточное шифрование ChaCha20 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы поточного шифрования ChaCha20 своей работы
	const double chachaStream = band("ChaCha20 своя", 8, VOLUME, [&chacha, &key, &seed, &data, &result]() noexcept -> void {
		// Выполняем запуск шифра: счётчик от единицы, как у записей TLS
		chacha.start(view_t(key, sizeof(key)), view_t(seed, cipher::CHACHA_NONCE), 1);
		// Выполняем поточное шифрование области байтов
		chacha.encrypt(view_t(data.data(), data.size()), result.data());
	});
	// Шифрование с проверкой целостности ChaCha20-Poly1305
	cipher::chachapoly_t chachapoly;
	// Если шифрование с проверкой целостности ChaCha20-Poly1305 завести не удалось
	if(!chachapoly.start(view_t(key, sizeof(key)), view_t(seed, cipher::CHACHA_NONCE)) || !chachapoly.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag)){
		// Выводим сообщение об отказе шифрования с проверкой целостности
		cout << "Завести шифрование с проверкой целостности ChaCha20-Poly1305 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования ChaCha20-Poly1305 своей работы
	const double chachaAead = band("ChaCha20-Poly1305 своя", 8, VOLUME, [&chachapoly, &key, &seed, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима
		chachapoly.start(view_t(key, sizeof(key)), view_t(seed, cipher::CHACHA_NONCE));
		// Выполняем шифрование области байтов с проверкой целостности
		chachapoly.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Объект блочного шифра «Магма»
	cipher::magma_t magma;
	// Если ключ блочного шифра «Магма» установить не удалось
	if(!magma.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ блочного шифра «Магма» не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового алгоритма блочного шифрования «Магма»
	const cipher::block_t little(magma);
	// Объект режима гаммирования на шифре «Магма»
	cipher::counter_t sequence;
	/**
	 * Вектор замены режима гаммирования занимает половину блока, оттого шифру с
	 * блоком в 64 разряда подаётся вчетверо короче прежнего
	 */
	if(!sequence.start(little, view_t(nonce, cipher::MAGMA_BLOCK / 2)) || !sequence.encrypt(view_t(data.data(), data.size()), result.data())){
		// Выводим сообщение об отказе поточного шифрования
		cout << "Выполнить поточное шифрование «Магма» не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы поточного шифрования «Магма»
	band("Магма-CTR", 8, VOLUME, [&sequence, &data, &result]() noexcept -> void {
		// Выполняем поточное шифрование области байтов
		sequence.encrypt(view_t(data.data(), data.size()), result.data());
	});
	// Начальное заполнение счётчика шифрования с проверкой целостности на шифре «Магма»
	uint8_t grain[cipher::MAGMA_BLOCK];
	// Выполняем выработку начального заполнения счётчика
	entropy::bytes(grain, sizeof(grain));
	/**
	 * Раздел 4.2 RFC 9058 велит держать старший разряд начального заполнения нулевым
	 */
	grain[0] &= 0x7F;
	// Объект режима шифрования с проверкой целостности на шифре «Магма»
	cipher::galois_t assurance;
	// Если режим шифрования с проверкой целостности завести не удалось
	if(!assurance.start(little, view_t(grain, sizeof(grain))) || !assurance.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag)){
		// Выводим сообщение об отказе шифрования с проверкой целостности
		cout << "Завести шифрование с проверкой целостности «Магма» не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования с проверкой целостности на шифре «Магма»
	band("Магма-MGM", 8, VOLUME, [&assurance, &little, &grain, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима шифрования с проверкой целостности
		assurance.start(little, view_t(grain, sizeof(grain)));
		// Выполняем шифрование области байтов с проверкой целостности
		assurance.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Эллиптическая кривая подписи и обмена ключами
	curve::curve_t curve;
	// Если кривую подписи и обмена ключами завести не удалось
	if(!curve::parameters("1.2.643.2.2.35.1", curve)){
		// Выводим сообщение об отказе заведения кривой
		cout << "Завести кривую подписи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Секретный ключ подписи
	uint8_t secret[32];
	// Открытый ключ обмена
	uint8_t opened[64];
	// Если мимолётную пару ключей выработать не удалось
	if(!agreement::generate(curve, secret, opened)){
		// Выводим сообщение об отказе выработки пары ключей
		cout << "Выработать пару ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Если кривую подписи установить не удалось
	if(!gost.start(curve) || !gost.secret(view_t(secret, sizeof(secret)))){
		// Выводим сообщение об отказе заведения подписи
		cout << "Завести подпись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Место, в которое помещается подпись хеша
	uint8_t signature[64];
	// Выполняем замер числа подписей за секунду
	const double signing = count("ГОСТ 34.10 подпись", 200, [&gost, &hash, &signature]() noexcept -> void {
		// Выполняем выработку подписи хеша
		gost.make(view_t(hash, 32), signature);
	});
	// Если подпись хеша выработать не удалось
	if(!gost.make(view_t(hash, 32), signature)){
		// Выводим сообщение об отказе выработки подписи
		cout << "Выработать подпись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если подпись хеша сличить не удалось
	if(!gost.check(view_t(hash, 32), view_t(signature, sizeof(signature)))){
		// Выводим сообщение об отказе сличения подписи
		cout << "Сличить подпись хеша не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа сличений подписи за секунду
	const double checking = count("ГОСТ 34.10 сличение", 200, [&gost, &hash, &signature]() noexcept -> void {
		// Выполняем сличение подписи хеша
		gost.check(view_t(hash, 32), view_t(signature, sizeof(signature)));
	});
	// Место, в которое помещается общее значение обмена ключами
	uint8_t shared[32];
	// Если общее значение обмена ключами выработать не удалось
	if(!agreement::ecdhe(curve, view_t(secret, sizeof(secret)), view_t(opened, sizeof(opened)), shared)){
		// Выводим сообщение об отказе обмена ключами
		cout << "Выработать общее значение обмена ключами не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа обменов мимолётными ключами за секунду
	const double exchange = count("Обмен ключами ECDHE", 200, [&curve, &secret, &opened, &shared]() noexcept -> void {
		// Выполняем выработку общего значения обмена ключами
		agreement::ecdhe(curve, view_t(secret, sizeof(secret)), view_t(opened, sizeof(opened)), shared);
	});
	/**
	 * VKO по RFC 7836 ждёт секрет и координаты от старшего байта, тогда как обмен
	 * ключами отдаёт их от младшего, как они идут по связи: разворот здесь, у границы
	 */
	uint8_t owned[32], x[32], y[32];
	// Выполняем разворот секретного ключа и координат открытого ключа
	for(size_t i = 0; i < 32; i++){
		// Переносим байт секретного ключа
		owned[i] = secret[31 - i];
		// Переносим байт первой координаты
		x[i] = opened[31 - i];
		// Переносим байт второй координаты
		y[i] = opened[63 - i];
	}
	// Добавочное значение сторон: восемь байтов, как у эталонного щупа
	const uint8_t material[8] = {8, 7, 6, 5, 4, 3, 2, 1};
	// Если общий ключ VKO выработать не удалось
	if(!agreement::vko(curve, view_t(owned, sizeof(owned)), view_t(x, sizeof(x)), view_t(y, sizeof(y)), view_t(material, sizeof(material)), shared, sizeof(shared))){
		// Выводим сообщение об отказе
		cout << "Выработать общий ключ VKO не удалось" << endl;
		// Выходим из приложения
		return EXIT_FAILURE;
	}
	// Выполняем замер обмена ключами VKO: эталон снимается щупом gostbench.c на Astra
	count("Обмен ключами VKO", 200, [&curve, &owned, &x, &y, &material, &shared]() noexcept -> void {
		// Выполняем выработку общего ключа VKO
		agreement::vko(curve, view_t(owned, sizeof(owned)), view_t(x, sizeof(x)), view_t(y, sizeof(y)), view_t(material, sizeof(material)), shared, sizeof(shared));
	});
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Если подлинность стороны сервера выработать не удалось
	if(!identity("anyks.com", credentials)){
		// Выводим сообщение об отказе выработки подлинности
		cout << "Выработать подлинность стороны сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа рукопожатий за секунду
	count("Рукопожатие TLS 1.3", 50, [&credentials]() noexcept -> void {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		server.start();
		// Выполняем заведение связи стороны клиента
		client.start();
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
	});
	/**
	 * Замер стойкости обмена RSA ко времени (раздел 7.4.7.1 RFC 5246, Бляйхенбахер):
	 * время разбора сервером ClientKeyExchange с годным шифртекстом сличается со временем
	 * разбора порченого - подмена общего значения идёт под маской, и середины рядов
	 * обязаны сходиться. Замер здесь, а не в проверках: под отладочной сборкой с
	 * наблюдателем адресов и на занятой машине ряды плывут, и порог был бы либо ложным,
	 * либо слепым
	 */
	{
		// Подлинность сервера обмена RSA из набора ключей
		context::credential_t rsa;
		// Секретный ключ
		rsa.secret = corpus("rsa2048.pem");
		// Сертификат
		const vector <uint8_t> text = corpus("rsa2048.crt");
		// Если подлинность прочитать не удалось
		if(rsa.secret.empty() || text.empty() || (pem::certificates(string(text.begin(), text.end()), rsa.chain) != pem::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Прочитать подлинность RSA из набора ключей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Сертификат сервера
		x509::certificate_t leaf;
		// Открытый ключ RSA сервера
		sign::rsa_t key;
		// Если ключ сертификата разобрать не удалось
		if((leaf.parse(view_t(rsa.chain[0].data(), rsa.chain[0].size())) != x509::error_t::NONE) || !key.decode(leaf.key().key)){
			// Выводим сообщение об отказе
			cout << "Разобрать ключ сертификата RSA не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Число прогонов на всякий путь
		static constexpr size_t TRIALS = 2000;
		// Ряды времени разбора обмена ключами: годный и порченый шифртекст
		vector <double> fine, spoiled;
		// Запись приветствия клиента
		vector <uint8_t> hello;
		// Если приветствие составить не удалось
		if(!greeting(hello)){
			// Выводим сообщение об отказе
			cout << "Составить приветствие клиента не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		/**
		 * Выполняем перебор прогонов: годный и порченый шифртекст вперемешку ради ровной нагрузки
		 */
		for(size_t trial = 0; trial < (TRIALS * 2); trial++){
			// Путь: чётные прогоны годные, нечётные порченые
			const bool broken = ((trial % 2) == 1);
			// Связь стороны сервера
			server::context_t server;
			// Набор обмена RSA
			server.suites(vector <protect::suite_t> {protect::suite_t::RSA_AES_128_GCM_SHA256});
			// Подлинность
			server.credential(rsa);
			// Издание 1.2
			server.versions(0x0303, 0x0303);
			// Заводим и подаём приветствие
			if((server.start() != context::error_t::NONE) || (server.push(view_t(hello.data(), hello.size())) != context::error_t::NONE)){
				// Выводим сообщение об отказе
				cout << "Провести приветствие обмена RSA не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Снимаем залп сервера
			server.consume(server.output().size);
			// Общее значение: издание и случайные байты
			vector <uint8_t> premaster(48, 0x5A);
			// Старший байт издания
			premaster[0] = 0x03;
			// Младший байт издания
			premaster[1] = 0x03;
			// Шифртекст общего значения
			vector <uint8_t> encrypted(key.size(), 0);
			// Если общее значение зашифровать не удалось
			if(!key.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(premaster.data(), premaster.size()), encrypted.data())){
				// Выводим сообщение об отказе
				cout << "Зашифровать общее значение RSA не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Если путь порченый
			if(broken)
				// Портим байт шифртекста
				encrypted[17] ^= 0x01;
			// Тело обмена ключами: длина и шифртекст
			vector <uint8_t> body = {static_cast <uint8_t> ((encrypted.size() >> 8) & 0xFF), static_cast <uint8_t> (encrypted.size() & 0xFF)};
			// Шифртекст
			body.insert(body.end(), encrypted.begin(), encrypted.end());
			// Составитель сообщения рукопожатия
			handshake::writer_t writer;
			// Нарезчик записей
			record::writer_t records;
			// Если запись обмена ключами составить не удалось
			if((writer.push(handshake::type_t::PREMASTER, view_t(body.data(), body.size())) != handshake::error_t::NONE) || (records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)){
				// Выводим сообщение об отказе
				cout << "Составить обмен ключами клиента не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Запись обмена ключами
			const view_t exchange = records.data();
			// Миг начала разбора
			const auto begin = chrono::steady_clock::now();
			// Подаём обмен ключами серверу: ответа на него нет ни в одном пути
			const context::error_t outcome = server.push(exchange);
			// Время разбора в микросекундах
			const double elapsed = (static_cast <double> (chrono::duration_cast <chrono::nanoseconds> (chrono::steady_clock::now() - begin).count()) / 1000.);
			// Если разбор ответил отказом: заслон Бляйхенбахера ветвится, чего быть не должно
			if(outcome != context::error_t::NONE){
				// Выводим сообщение об отказе
				cout << "Разбор обмена ключами ответил отказом " << static_cast <int> (outcome) << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Складываем время в ряд своего пути
			(broken ? spoiled : fine).push_back(elapsed);
		}
		// Середины рядов
		const double good = median(fine), bad = median(spoiled);
		// Выводим середину годного ряда
		cout << pad("RSA CKE годный, середина", 28) << setw(12) << right << fixed << setprecision(1) << good << " мкс" << endl;
		// Выводим середину порченого ряда
		cout << pad("RSA CKE порченый, середина", 28) << setw(12) << right << fixed << setprecision(1) << bad << " мкс" << endl;
		// Выводим расхождение середин
		cout << pad("Расхождение середин", 28) << setw(12) << right << fixed << setprecision(1) << (((good > 0.) ? (((bad > good) ? (bad - good) : (good - bad)) / good) : 0.) * 100.) << " %" << endl;
	}
	/**
	 * Замеры рукопожатий издания TLS 1.2 записями: ECDHE-ECDSA с AES-GCM, ECDHE-ECDSA с
	 * AES-CBC в порядке RFC 7366, ECDHE-PSK с ChaCha20-Poly1305, голый обмен RSA и
	 * возобновление билетом RFC 5077. Подлинности берутся из набора ключей: ECDSA на P-256
	 * и RSA-2048. Всякая работа сперва проводится один раз и обязана удаться
	 */
	{
		// Выводим заголовок замеров издания 1.2
		cout << endl << "Рукопожатия TLS 1.2" << endl << endl;
		// Подлинность ECDSA и подлинность RSA
		context::credential_t ecdsa, rsa;
		// Если подлинности прочитать не удалось
		if(!keyed("ec256.pem", "ec256.crt", ecdsa) || !keyed("rsa2048.pem", "rsa2048.crt", rsa)){
			// Выводим сообщение об отказе
			cout << "Прочитать подлинности издания 1.2 из набора ключей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Заранее разделённый ключ сторон
		const vector <uint8_t> preshared(reinterpret_cast <const uint8_t *> ("pre-shared key of the benchmark"), reinterpret_cast <const uint8_t *> ("pre-shared key of the benchmark") + 31);
		// Настройки заранее разделённого ключа клиента
		context::psk_t psk;
		// Опознаватель клиента
		psk.identity.assign(reinterpret_cast <const uint8_t *> ("anyks"), reinterpret_cast <const uint8_t *> ("anyks") + 5);
		// Ключ клиента
		psk.key = preshared;
		// Указатель на ключ для вызова сервера
		psk.context = const_cast <vector <uint8_t> *> (&preshared);
		// Ключ билетов сервера
		const vector <uint8_t> vault(reinterpret_cast <const uint8_t *> ("ticket vault secret of the benchmark"), reinterpret_cast <const uint8_t *> ("ticket vault secret of the benchmark") + 36);
		// Билет, выданный первым рукопожатием
		context::ticket_t ticket;
		// Если хоть одно рукопожатие издания 1.2 не удалось
		if(!legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, nullptr, nullptr, nullptr, nullptr) || !legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, nullptr, nullptr, nullptr, nullptr) || !legacy(ecdsa, protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, &psk, nullptr, nullptr, nullptr) || !legacy(rsa, protect::suite_t::RSA_AES_128_GCM_SHA256, nullptr, nullptr, nullptr, nullptr) || !legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, nullptr, &vault, nullptr, &ticket) || !legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, nullptr, &vault, &ticket, nullptr)){
			// Выводим сообщение об отказе
			cout << "Провести рукопожатие издания 1.2 не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выполняем замер рукопожатий ECDHE-ECDSA с AES-GCM
		count("TLS 1.2 ECDHE-ECDSA-GCM", 50, [&ecdsa]() noexcept -> void {
			// Проводим рукопожатие
			legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, nullptr, nullptr, nullptr, nullptr);
		});
		// Выполняем замер рукопожатий ECDHE-ECDSA с AES-CBC
		count("TLS 1.2 ECDHE-ECDSA-CBC", 50, [&ecdsa]() noexcept -> void {
			// Проводим рукопожатие
			legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, nullptr, nullptr, nullptr, nullptr);
		});
		// Выполняем замер рукопожатий ECDHE-PSK: сертификатов нет вовсе
		count("TLS 1.2 ECDHE-PSK-CHACHA20", 50, [&ecdsa, &psk]() noexcept -> void {
			// Проводим рукопожатие
			legacy(ecdsa, protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, &psk, nullptr, nullptr, nullptr);
		});
		// Выполняем замер рукопожатий голым обменом RSA: расшифрование RSA-2048 у сервера
		count("TLS 1.2 голый RSA-GCM", 50, [&rsa]() noexcept -> void {
			// Проводим рукопожатие
			legacy(rsa, protect::suite_t::RSA_AES_128_GCM_SHA256, nullptr, nullptr, nullptr, nullptr);
		});
		// Выполняем замер возобновления билетом: ни сертификата, ни подписи, ни обмена
		count("TLS 1.2 билет RFC 5077", 50, [&ecdsa, &vault, &ticket]() noexcept -> void {
			// Проводим сокращённое рукопожатие
			legacy(ecdsa, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, nullptr, &vault, &ticket, nullptr);
		});
	}
	/**
	 * Замеры связи поверх дейтаграмм: рукопожатия DTLS 1.3 и DTLS 1.2 с просьбой
	 * подтвердить адрес и пропускная способность записей прикладных данных по одной
	 * записи в дейтаграмме размером 1200 байтов
	 */
	{
		// Выводим заголовок замеров дейтаграмм
		cout << endl << "Связь поверх дейтаграмм" << endl << endl;
		// Подлинность ECDSA
		context::credential_t ecdsa;
		// Если подлинность прочитать не удалось
		if(!keyed("ec256.pem", "ec256.crt", ecdsa)){
			// Выводим сообщение об отказе
			cout << "Прочитать подлинность из набора ключей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		/**
		 * Выполняем перебор изданий: DTLS 1.3, затем DTLS 1.2
		 */
		for(size_t edition = 0; edition < 2; edition++){
			// Признак издания DTLS 1.2
			const bool classic = (edition == 1);
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Если рукопожатие поверх дейтаграмм не удалось
			if(!settle(client, server, ecdsa, classic)){
				// Выводим сообщение об отказе
				cout << "Провести рукопожатие поверх дейтаграмм не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выполняем замер рукопожатий поверх дейтаграмм
			count((classic ? "DTLS 1.2 рукопожатие" : "DTLS 1.3 рукопожатие"), 50, [&ecdsa, classic]() noexcept -> void {
				// Связь стороны клиента
				client::context_t peer;
				// Связь стороны сервера
				server::context_t host;
				// Проводим рукопожатие
				settle(peer, host, ecdsa, classic);
			});
			// Запись прикладных данных, входящая в одну дейтаграмму с накладными байтами
			const vector <uint8_t> payload(1100, 0x5A);
			// Накопитель принятых данных
			vector <uint8_t> received;
			// Если передача по дейтаграммам не удалась
			if(!transfer(client, server, view_t(payload.data(), payload.size()), 16, received)){
				// Выводим сообщение об отказе
				cout << "Передать записи по дейтаграммам не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выполняем замер пропускной способности записей по дейтаграммам
			band((classic ? "DTLS 1.2 записи 1200 байт" : "DTLS 1.3 записи 1200 байт"), 4, payload.size() * 256, [&client, &server, &payload, &received]() noexcept -> void {
				// Передаём двести пятьдесят шесть записей по одной в дейтаграмме
				transfer(client, server, view_t(payload.data(), payload.size()), 256, received);
			});
		}
	}
	/**
	 * Замеры защиты записей издания 1.2 на записях в 16 КиБ: наложение и снятие защиты
	 * набором CBC в порядке RFC 7366, в порядке MAC-then-encrypt за постоянное время и
	 * набором AES-GCM. Замер ведётся на самой защите записей, минуя связь: у пары наших
	 * сторон порядок MAC-then-encrypt никогда не согласуется, и иначе его не смерить
	 */
	{
		// Выводим заголовок замеров защиты записей
		cout << endl << "Защита записей TLS 1.2, 16 КиБ" << endl << endl;
		// Содержимое записи наибольшей длины
		const vector <uint8_t> content(record::RECORD_PLAINTEXT, 0x5A);
		// Просмотр содержимого записи
		const view_t plain(content.data(), content.size());
		// Накопители защищённой записи и снятого содержимого
		vector <uint8_t> sealed, opened;
		// Защита отправляющей и принимающей сторон набора CBC в порядке RFC 7366
		protect::protection_t etmSealer, etmOpener;
		// Защита сторон набора CBC в порядке MAC-then-encrypt
		protect::protection_t mteSealer, mteOpener;
		// Защита сторон набора AES-GCM
		protect::protection_t gcmSealer, gcmOpener;
		// Если защиту завести либо первую запись провести не удалось
		if(!keying(protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, etmSealer, etmOpener, true) || !roundtrip(etmSealer, etmOpener, 0, plain, sealed, opened) || (opened != content) || !keying(protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, mteSealer, mteOpener, false) || !roundtrip(mteSealer, mteOpener, 0, plain, sealed, opened) || (opened != content) || !keying(protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, gcmSealer, gcmOpener, false) || !roundtrip(gcmSealer, gcmOpener, 0, plain, sealed, opened) || (opened != content)){
			// Выводим сообщение об отказе
			cout << "Завести защиту записей издания 1.2 не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Порядковый номер записи
		uint64_t sequence = 1;
		// Выполняем замер защиты записей CBC в порядке RFC 7366
		const double etm = band("AES-128-CBC-SHA256 ETM", 64, record::RECORD_PLAINTEXT, [&etmSealer, &etmOpener, &sequence, &plain, &sealed, &opened]() noexcept -> void {
			// Накладываем и снимаем защиту записи
			roundtrip(etmSealer, etmOpener, sequence++, plain, sealed, opened);
		});
		// Выполняем замер защиты записей CBC в порядке MAC-then-encrypt
		const double mte = band("AES-128-CBC-SHA256 MtE", 64, record::RECORD_PLAINTEXT, [&mteSealer, &mteOpener, &sequence, &plain, &sealed, &opened]() noexcept -> void {
			// Накладываем и снимаем защиту записи
			roundtrip(mteSealer, mteOpener, sequence++, plain, sealed, opened);
		});
		// Выполняем замер защиты записей AES-GCM
		const double gcm12 = band("AES-128-GCM", 64, record::RECORD_PLAINTEXT, [&gcmSealer, &gcmOpener, &sequence, &plain, &sealed, &opened]() noexcept -> void {
			// Накладываем и снимаем защиту записи
			roundtrip(gcmSealer, gcmOpener, sequence++, plain, sealed, opened);
		});
		// Выводим отношение защиты CBC к AES-GCM
		relation("CBC ETM против AES-GCM", etm, gcm12);
		// Выводим отношение защиты MAC-then-encrypt к AES-GCM
		relation("CBC MtE против AES-GCM", mte, gcm12);
	}
	/**
	 * Замер разбора и проверки ответа OCSP: запись ответа из набора, лист и его издатель;
	 * сроки судятся заданным мигом, оттого набор не стареет
	 */
	{
		// Выводим заголовок замера OCSP
		cout << endl << "Состояние сертификата OCSP" << endl << endl;
		// Ответ ответчика о листе цепочки
		const vector <uint8_t> answer = corpus("ocsp/leaf-ec.good.der");
		// Лист цепочки и его издатель в кодировке DER
		const vector <uint8_t> leaf = certified("leaf-ec.crt"), issuer = certified("mid-ec.crt");
		// Разобранный ответ
		ocsp::response_t response;
		// Состояние сертификата
		ocsp::status_t status = ocsp::status_t::NONE;
		// Если ответ не прочитан, не разобран либо не проверен
		if(answer.empty() || leaf.empty() || issuer.empty() || (response.parse(view_t(answer.data(), answer.size())) != ocsp::error_t::NONE) || (ocsp::verify(response, view_t(leaf.data(), leaf.size()), view_t(issuer.data(), issuer.size()), 1790000000, 0, view_t(), status) != ocsp::error_t::NONE) || (status != ocsp::status_t::GOOD)){
			// Выводим сообщение об отказе
			cout << "Разобрать и проверить ответ OCSP из набора не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выполняем замер разбора ответа
		count("OCSP разбор ответа", 500, [&answer]() noexcept -> void {
			// Разбираемый ответ
			ocsp::response_t parsed;
			// Разбираем ответ
			parsed.parse(view_t(answer.data(), answer.size()));
		});
		// Выполняем замер разбора и проверки ответа: подпись ECDSA ответчика и сроки
		count("OCSP разбор и проверка", 200, [&answer, &leaf, &issuer]() noexcept -> void {
			// Разбираемый ответ
			ocsp::response_t parsed;
			// Состояние сертификата
			ocsp::status_t outcome = ocsp::status_t::NONE;
			// Разбираем ответ
			parsed.parse(view_t(answer.data(), answer.size()));
			// Проверяем ответ против листа и издателя
			ocsp::verify(parsed, view_t(leaf.data(), leaf.size()), view_t(issuer.data(), issuer.size()), 1790000000, 0, view_t(), outcome);
		});
	}
	/**
	 * Замеры сжатия цепочки сертификатов RFC 8879: частный кодек повторами на цепочке
	 * из трёх сертификатов ECDSA сам по себе и рукопожатие TLS 1.3 с цепочкой без
	 * сжатия и со сжатием
	 */
	{
		// Выводим заголовок замеров сжатия
		cout << endl << "Сжатие цепочки сертификатов" << endl << endl;
		// Подлинность с цепочкой из трёх сертификатов
		context::credential_t chained;
		// Если подлинность прочитать не удалось
		if(!keyed("leaf-ec.key", "chain-ec.pem", chained) || (chained.chain.size() != 3)){
			// Выводим сообщение об отказе
			cout << "Прочитать цепочку из набора ключей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Тело цепочки одним куском
		vector <uint8_t> body;
		/**
		 * Выполняем сборку тела цепочки
		 */
		for(size_t i = 0; i < chained.chain.size(); i++)
			// Дописываем очередной сертификат
			body.insert(body.end(), chained.chain[i].begin(), chained.chain[i].end());
		// Сжатый поток и распакованное тело
		vector <uint8_t> packed, unpacked;
		// Если кодек не сошёлся сам с собой
		if(!lz77Compress(view_t(body.data(), body.size()), packed, nullptr) || !lz77Decompress(view_t(packed.data(), packed.size()), body.size(), unpacked, nullptr) || (unpacked != body)){
			// Выводим сообщение об отказе
			cout << "Кодек сжатия не сошёлся сам с собой" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим степень сжатия цепочки
		cout << pad("LZ77 цепочка 3 сертификата", 28) << setw(12) << right << body.size() << " → " << packed.size() << " байт" << endl;
		// Выполняем замер сжатия цепочки
		count("LZ77 сжатие цепочки", 500, [&body, &packed]() noexcept -> void {
			// Очищаем сжатый поток
			packed.clear();
			// Сжимаем цепочку
			lz77Compress(view_t(body.data(), body.size()), packed, nullptr);
		});
		// Выполняем замер распаковки цепочки
		count("LZ77 распаковка цепочки", 500, [&body, &packed, &unpacked]() noexcept -> void {
			// Очищаем распакованное тело
			unpacked.clear();
			// Распаковываем цепочку
			lz77Decompress(view_t(packed.data(), packed.size()), body.size(), unpacked, nullptr);
		});
		// Алгоритмы сжатия сторон
		const vector <context::codec_t> codecs = {context::codec_t(LZ77_ALGORITHM, lz77Compress, lz77Decompress, nullptr)};
		/**
		 * Выполняем перебор: рукопожатие без сжатия и со сжатием
		 */
		for(size_t squeezed = 0; squeezed < 2; squeezed++){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Подлинность сервера
			server.credential(chained);
			// Если сжатие включено
			if(squeezed == 1){
				// Алгоритмы клиента
				client.codecs(codecs, 0);
				// Алгоритмы сервера
				server.codecs(codecs, 0);
			}
			// Если рукопожатие с цепочкой не удалось
			if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE) || !converse(client, server) || (client.compression(context::direction_t::READ) != ((squeezed == 1) ? LZ77_ALGORITHM : 0))){
				// Выводим сообщение об отказе
				cout << "Провести рукопожатие с цепочкой не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выполняем замер рукопожатий TLS 1.3 с цепочкой из трёх сертификатов
			count(((squeezed == 1) ? "TLS 1.3 цепочка сжатая" : "TLS 1.3 цепочка из 3"), 50, [&chained, &codecs, squeezed]() noexcept -> void {
				// Связь стороны клиента
				client::context_t peer;
				// Связь стороны сервера
				server::context_t host;
				// Подлинность сервера
				host.credential(chained);
				// Если сжатие включено
				if(squeezed == 1){
					// Алгоритмы клиента
					peer.codecs(codecs, 0);
					// Алгоритмы сервера
					host.codecs(codecs, 0);
				}
				// Заводим сервер
				host.start();
				// Заводим клиента
				peer.start();
				// Проводим рукопожатие
				converse(peer, host);
			});
		}
	}
	/**
	 * Если сличение с эталоном OpenSSL включено
	 */
	#ifdef ANTS_BENCH_OPENSSL
		// Выводим заголовок замеров работы эталона
		cout << endl << "Замеры эталона OpenSSL " << OPENSSL_VERSION_TEXT << endl << endl;
		// Выполняем замер полосы хеширования SHA-256
		const double sha = band("SHA-256", 16, VOLUME, [&data, &hash]() noexcept -> void {
			// Длина выработанного хеша области байтов
			unsigned int length = 0;
			// Выполняем хеширование области байтов
			::EVP_Digest(data.data(), data.size(), hash, &length, ::EVP_sha256(), nullptr);
		});
		// Выполняем замер полосы хеширования SHA-512 эталона
		const double sha512ref = band("SHA-512", 16, VOLUME, [&data, &hash]() noexcept -> void {
			// Длина выработанного хеша области байтов
			unsigned int length = 0;
			// Выполняем хеширование области байтов
			::EVP_Digest(data.data(), data.size(), hash, &length, ::EVP_sha512(), nullptr);
		});
		// Объект поточного шифрования эталона
		EVP_CIPHER_CTX * context = ::EVP_CIPHER_CTX_new();
		// Выполняем замер полосы поточного шифрования AES-256-CTR
		const double aes = band("AES-256-CTR", 8, VOLUME, [&context, &key, &nonce, &data, &result]() noexcept -> void {
			// Длина зашифрованной области байтов
			int length = 0;
			// Вектор замены поточного шифрования эталона
			uint8_t iv[16] = {0};
			// Переносим вектор замены поточного шифрования
			::memcpy(iv, nonce, sizeof(nonce));
			// Выполняем заведение поточного шифрования области байтов
			::EVP_EncryptInit_ex(context, ::EVP_aes_256_ctr(), nullptr, key, iv);
			// Выполняем поточное шифрование области байтов
			::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
		});
		// Выполняем замер полосы шифрования с проверкой целостности AES-256-GCM
		const double gcm = band("AES-256-GCM", 8, VOLUME, [&context, &key, &nonce, &data, &result, &tag]() noexcept -> void {
			// Длина зашифрованной области байтов
			int length = 0;
			// Выполняем заведение шифрования области байтов
			::EVP_EncryptInit_ex(context, ::EVP_aes_256_gcm(), nullptr, key, nonce);
			// Выполняем шифрование области байтов
			::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
			// Выполняем завершение шифрования области байтов
			::EVP_EncryptFinal_ex(context, result.data() + length, &length);
			// Выполняем извлечение имитовставки шифрования
			::EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag);
		});
		// Выполняем замер полосы поточного шифрования ChaCha20 эталона
		const double chachaRef = band("ChaCha20", 8, VOLUME, [&context, &key, &seed, &data, &result]() noexcept -> void {
			// Длина зашифрованной области байтов
			int length = 0;
			// Выполняем заведение поточного шифрования: вектор эталона - счётчик и заполнение в 16 байтов
			::EVP_EncryptInit_ex(context, ::EVP_chacha20(), nullptr, key, seed);
			// Выполняем поточное шифрование области байтов
			::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
		});
		// Выполняем замер полосы шифрования с проверкой целостности ChaCha20-Poly1305 эталона
		const double chachapolyRef = band("ChaCha20-Poly1305", 8, VOLUME, [&context, &key, &seed, &data, &result, &tag]() noexcept -> void {
			// Длина зашифрованной области байтов
			int length = 0;
			// Выполняем заведение шифрования области байтов
			::EVP_EncryptInit_ex(context, ::EVP_chacha20_poly1305(), nullptr, key, seed);
			// Выполняем шифрование области байтов
			::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
			// Выполняем завершение шифрования области байтов
			::EVP_EncryptFinal_ex(context, result.data() + length, &length);
			// Выполняем извлечение имитовставки шифрования
			::EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, tag);
		});
		// Выполняем освобождение объекта поточного шифрования эталона
		::EVP_CIPHER_CTX_free(context);
		// Ключевая пара кривой P-256 эталона
		EVP_PKEY * pair = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
		// Если ключевую пару кривой эталона выработать не удалось
		if(pair == nullptr){
			// Выводим сообщение об отказе выработки пары ключей
			cout << "Выработать ключевую пару эталона не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Место, в которое помещается подпись эталона
		vector <uint8_t> sealing(128, 0);
		// Длина выработанной подписи эталона
		size_t length = sealing.size();
		// Объект работы с подписью эталона
		EVP_MD_CTX * digest = ::EVP_MD_CTX_new();
		// Выполняем замер числа подписей эталона за секунду
		const double ecdsa = count("ECDSA P-256 подпись", 200, [&digest, &pair, &hash, &sealing, &length]() noexcept -> void {
			// Восстанавливаем длину места под подпись эталона
			length = sealing.size();
			// Выполняем заведение выработки подписи эталона
			::EVP_DigestSignInit(digest, nullptr, nullptr, nullptr, pair);
			// Выполняем выработку подписи эталона
			::EVP_DigestSign(digest, sealing.data(), &length, hash, 32);
		});
		// Выполняем выработку подписи эталона для сличения
		::EVP_DigestSignInit(digest, nullptr, nullptr, nullptr, pair);
		// Выполняем выработку подписи эталона
		::EVP_DigestSign(digest, sealing.data(), &length, hash, 32);
		// Выполняем замер числа сличений подписи эталона за секунду
		const double verify = count("ECDSA P-256 сличение", 200, [&digest, &pair, &hash, &sealing, &length]() noexcept -> void {
			// Выполняем заведение сличения подписи эталона
			::EVP_DigestVerifyInit(digest, nullptr, nullptr, nullptr, pair);
			// Выполняем сличение подписи эталона
			::EVP_DigestVerify(digest, sealing.data(), length, hash, 32);
		});
		// Выполняем освобождение объекта работы с подписью эталона
		::EVP_MD_CTX_free(digest);
		// Место, в которое помещается общее значение обмена эталона
		vector <uint8_t> common(32, 0);
		// Выполняем замер числа обменов ключами эталона за секунду
		const double ecdh = count("Обмен ключами ECDH P-256", 200, [&pair, &common]() noexcept -> void {
			// Длина общего значения обмена эталона
			size_t size = common.size();
			// Объект обмена ключами эталона
			EVP_PKEY_CTX * exchange = ::EVP_PKEY_CTX_new(pair, nullptr);
			// Выполняем заведение обмена ключами эталона
			::EVP_PKEY_derive_init(exchange);
			// Устанавливаем открытый ключ встречной стороны обмена
			::EVP_PKEY_derive_set_peer(exchange, pair);
			// Выполняем выработку общего значения обмена
			::EVP_PKEY_derive(exchange, common.data(), &size);
			// Выполняем освобождение объекта обмена ключами эталона
			::EVP_PKEY_CTX_free(exchange);
		});
		// Выполняем освобождение ключевой пары кривой эталона
		::EVP_PKEY_free(pair);
		// Выводим заголовок отношений замеров одного рода работы
		cout << endl << "Отставание от эталона" << endl << endl;
		// Выводим отношение замеров хеширования
		relation("Хеш 256 разрядов", streebog, sha);
		// Выводим отношение замеров хеширования SHA-256 к эталону
		relation("SHA-256 против эталона", sha256, sha);
		// Выводим отношение замеров хеширования SHA-512 к эталону
		relation("SHA-512 против эталона", sha512, sha512ref);
		// Выводим отношение замеров поточного шифрования
		relation("Поточное шифрование", stream, aes);
		// Выводим отношение замеров шифрования с целостностью
		relation("Шифрование с целостностью", sealed, gcm);
		// Выводим отношение замеров AES-256-CBC к поточному эталону
		relation("AES-256-CBC против AES-256-CTR эталона", cbc, aes);
		// Выводим отношение замеров AES-256-GCM к эталону
		relation("AES-256-GCM против эталона", aead, gcm);
		// Выводим отношение замеров ChaCha20 к эталону
		relation("ChaCha20 против эталона", chachaStream, chachaRef);
		// Выводим отношение замеров ChaCha20-Poly1305 к эталону
		relation("ChaCha20-Poly1305 против эталона", chachaAead, chachapolyRef);
		// Выводим отношение замеров выработки подписи
		relation("Подпись", signing, ecdsa);
		// Выводим отношение замеров сличения подписи
		relation("Сличение подписи", checking, verify);
		// Выводим отношение замеров обмена ключами
		relation("Обмен ключами", exchange, ecdh);
		/**
		 * Эталон на этой машине шифрует и хеширует машинными командами, которых у ГОСТ
		 * нет ни на одной: чтобы сличить сами алгоритмы, а не оснастку под них, эталон
		 * запускается с отключённым ускорением
		 */
		cout << endl << "Эталон здесь идёт машинными командами ускорения. Для сличения самих" << endl;
		// Выводим способ отключения ускорения эталона
		cout << "алгоритмов запускать замеры так: OPENSSL_armcap=0 (ARM) либо" << endl;
		// Выводим способ отключения ускорения эталона
		cout << "OPENSSL_ia32cap=~0x200000200000000 (x86-64)" << endl;
	#else
		// Не используем замер хеширования при отключённом сличении
		(void) streebog;
		// Замеры своей работы AES без эталона сравнивать не с чем
		(void) cbc;
		// Замеры своей работы AES без эталона сравнивать не с чем
		(void) aead;
		// Замеры своей работы ChaCha20 без эталона сравнивать не с чем
		(void) chachaStream;
		// Замеры своей работы ChaCha20-Poly1305 без эталона сравнивать не с чем
		(void) chachaAead;
		// Замеры своей работы SHA-2 без эталона сравнивать не с чем
		(void) sha256;
		// Замеры своей работы SHA-2 без эталона сравнивать не с чем
		(void) sha512;
		// Не используем замер поточного шифрования при отключённом сличении
		(void) stream;
		// Не используем замер шифрования с целостностью при отключённом сличении
		(void) sealed;
		// Не используем замер выработки подписи при отключённом сличении
		(void) signing;
		// Не используем замер сличения подписи при отключённом сличении
		(void) checking;
		// Не используем замер обмена ключами при отключённом сличении
		(void) exchange;
	#endif // ANTS_BENCH_OPENSSL
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
