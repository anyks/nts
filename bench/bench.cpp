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
/**
 * Под Windows заголовки эталона тянут <windows.h> целиком, а его записи RPC зовут тип
 * byte: за подпиской заголовков библиотеки на пространство std имя двоится со
 * std::byte, потому системные заголовки подключаются раньше всех прочих
 */
#if defined(ANTS_BENCH_OPENSSL) && defined(_WIN32)
	#include <winsock2.h>
	#include <windows.h>
#endif

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
#include <agreement/x25519.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <pem/pem.hpp>
#include <x509/x509.hpp>
#include <sign/rsa.hpp>
#include <sign/mldsa.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <datagram/datagram.hpp>
#include <protect/protect.hpp>
#include <digest/hash.hpp>
#include <digest/sha3.hpp>
#include <digest/sm3.hpp>
#include <digest/ripemd.hpp>
#include <digest/umac.hpp>
#include <cipher/sm4.hpp>
#include <cipher/ccm.hpp>
#include <cipher/des.hpp>
#include <sign/ed25519.hpp>
#include <sign/ed448.hpp>
#include <sign/sm2.hpp>
#include <sign/slhdsa.hpp>
#include <agreement/x448.hpp>
#include <agreement/mlkem.hpp>
#include <agreement/ffdhe.hpp>
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
	#include <openssl/provider.h>
	#include <openssl/rand.h>
	#include <openssl/rsa.h>
	#include <openssl/ssl.h>
#endif

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
	 * @brief Функция дополнения названия замера до заданной ширины
	 *
	 * @param name  дополняемое название замера
	 * @param width ширина, до которой название дополняется
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
	 * @brief Функция замера числа проходов работы за секунду
	 *
	 * @param count число проходов работы в одном прогоне
	 * @param work  замеряемая работа
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
	 * @brief Функция вывода замера полосы
	 *
	 * @param name   название замеряемой работы
	 * @param count  число проходов работы в одном прогоне
	 * @param volume размер области байтов одного прохода работы
	 * @param work   замеряемая работа
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
	 * @brief Функция вывода замера числа проходов работы
	 *
	 * @param name  название замеряемой работы
	 * @param count число проходов работы в одном прогоне
	 * @param work  замеряемая работа
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
	 * @brief Функция вывода отношения замеров одного рода работы
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
	 * @brief Функция чтения файла набора ключей для сличения
	 *
	 * @param name имя файла в наборе
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
	 * @brief Функция получения середины ряда замеров
	 *
	 * @param values ряд замеров
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
	 * @brief Функция составления записи приветствия клиента издания TLS 1.2 под обмен RSA
	 *
	 * @param result накопитель, в который складывается запись приветствия
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
			// Выводим отрицательный результат - схемы составить не удалось
			return false;
		// Добавляем схемы
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Добавляем расширенный главный секрет
		hello.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Тело приветствия
		vector <uint8_t> body;
		// Если тело составить не удалось
		if(hello::build(hello, body) != hello::error_t::NONE)
			// Выводим отрицательный результат - тело приветствия не составлено
			return false;
		// Составитель сообщения рукопожатия
		handshake::writer_t writer;
		// Если сообщение составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отрицательный результат - сообщение не составлено
			return false;
		// Нарезчик записей
		record::writer_t records;
		// Если запись составить не удалось
		if(records.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отрицательный результат - запись не составлена
			return false;
		// Запись приветствия
		const view_t data = records.data();
		// Переносим запись
		result.assign(data.data, data.data + data.size);
		// Сообщаем об успешном составлении записи приветствия
		return true;
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
	 * @brief Функция проведения рукопожатия сторон связи записями до тишины
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
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
	 * @brief Функция составления подлинности стороны из набора ключей
	 *
	 * @param key         имя файла секретного ключа в записи PEM
	 * @param certificate имя файла сертификата либо цепочки в записи PEM
	 * @param result      подлинность, в которую помещается итог
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
	 * @brief Функция чтения сертификата набора в кодировке DER из записи PEM
	 *
	 * @param name имя файла сертификата в наборе
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
	 * @brief Функция проведения рукопожатия издания TLS 1.2 записями
	 *
	 * @param credential подлинность сервера, при заранее разделённом ключе не нужна
	 * @param suite      набор шифрования обеих сторон
	 * @param psk        настройки заранее разделённого ключа клиента либо nullptr
	 * @param vault      ключ билетов сервера либо nullptr
	 * @param ticket     билет, предъявляемый клиентом, либо nullptr
	 * @param issued     место, в которое помещается выданный билет, либо nullptr
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
			// Выводим отрицательный результат - пределы издания не установлены
			return false;
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отрицательный результат - связь завести не удалось
			return false;
		// Если рукопожатие не пройдено
		if(!converse(client, server))
			// Выводим отрицательный результат - рукопожатие не пройдено
			return false;
		// Если билет предъявлялся, а возобновления не вышло
		if((ticket != nullptr) && !client.shared())
			// Выводим отрицательный результат - возобновления не вышло
			return false;
		// Если выданный билет запрашивается
		if(issued != nullptr){
			// Если билет не выдан
			if(client.tickets().empty())
				// Выводим отрицательный результат - билет не выдан
				return false;
			// Запоминаем выданный билет
			*issued = client.tickets()[0];
		}
		// Сообщаем об успешном заведении связи
		return true;
	}
	/**
	 * @brief Функция переноса всех готовых дейтаграмм от одной стороны к другой
	 *
	 * @param from связь стороны, отдающей дейтаграммы
	 * @param to   связь стороны, принимающей дейтаграммы
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
	 * @brief Функция настройки и рукопожатия сторон поверх дейтаграмм
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param legacy     ведётся ли связь изданием DTLS 1.2
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
			// Выводим отрицательный результат - адрес не установлен
			return false;
		// Издание по пределам
		const uint16_t edition = (legacy ? 0x0303 : 0x0304);
		// Если пределы издания либо заведение связи не удались
		if((client.versions(edition, edition) != context::error_t::NONE) || (server.versions(edition, edition) != context::error_t::NONE) || (server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отрицательный результат - пределы либо заведение не удались
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
	 * @brief Функция передачи прикладных данных по установленной связи поверх дейтаграмм
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param payload  передаваемые данные: не длиннее одной дейтаграммы
	 * @param count    число передач
	 * @param received накопитель принятых сервером данных
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
				// Выводим отрицательный результат - данные не отправлены
				return false;
			// Переносим дейтаграмму серверу
			ferry(client, server);
			// Если принятое прочитать не удалось
			if(server.read(received) != context::error_t::NONE)
				// Выводим отрицательный результат - принятое не прочитано
				return false;
			// Считаем принятые байты
			taken += received.size();
		}
		// Выводим признак того, что всё переданное принято
		return (taken == (payload.size * count));
	}
	/**
	 * @brief Функция заведения защиты записей издания 1.2 случайным ключевым материалом
	 *
	 * @param suite  набор шифрования
	 * @param sealer защита отправляющей стороны
	 * @param opener защита принимающей стороны
	 * @param etm    порядок RFC 7366 у наборов CBC
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
			// Выводим отрицательный результат - ключевой материал не выработан
			return false;
		// Если защиту отправляющей стороны завести не удалось
		if(!sealer.start(suite, view_t(key.data(), key.size()), view_t(salt.data(), salt.size()), view_t(mac.data(), mac.size())))
			// Выводим отрицательный результат - защита отправителя не заведена
			return false;
		// Если защиту принимающей стороны завести не удалось
		if(!opener.start(suite, view_t(key.data(), key.size()), view_t(salt.data(), salt.size()), view_t(mac.data(), mac.size())))
			// Выводим отрицательный результат - защита принимающего не заведена
			return false;
		// Порядок RFC 7366 у отправляющей стороны
		sealer.etm(etm);
		// Порядок RFC 7366 у принимающей стороны
		opener.etm(etm);
		// Сообщаем об успешном заведении защиты
		return true;
	}
	/**
	 * @brief Функция наложения и снятия защиты одной записи издания 1.2
	 *
	 * @param sealer   защита отправляющей стороны
	 * @param opener   защита принимающей стороны
	 * @param sequence порядковый номер записи
	 * @param data     содержимое записи
	 * @param sealed   накопитель защищённой записи
	 * @param opened   накопитель снятого содержимого
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
			// Выводим отрицательный результат - защиту наложить не удалось
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
	const double streebogLong = band("Стрибог-512", 16, VOLUME, [&data, &hash]() noexcept -> void {
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
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!digest::sha3(digest::sha3_t::SHA3_256, view_t(data.data(), data.size()), hash, 32) || !digest::sm3(view_t(data.data(), data.size()), hash, 32) || !digest::ripemd160(view_t(data.data(), data.size()), hash, 20)){
		// Выводим сообщение об отказе хеширования области байтов
		cout << "Выработать хеш SHA-3, SM3 либо RIPEMD области байтов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы хеширования SHA3-256 своей работы
	const double sha3 = band("SHA3-256 своя", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::sha3(digest::sha3_t::SHA3_256, view_t(data.data(), data.size()), hash, 32);
	});
	// Выполняем замер полосы хеширования SHA3-512 своей работы
	const double sha3long = band("SHA3-512 своя", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::sha3(digest::sha3_t::SHA3_512, view_t(data.data(), data.size()), hash, 64);
	});
	// Выполняем замер полосы хеширования SM3 своей работы
	const double sm3 = band("SM3 своя", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::sm3(view_t(data.data(), data.size()), hash, 32);
	});
	// Выполняем замер полосы хеширования RIPEMD-160 своей работы
	const double ripemd = band("RIPEMD-160 своя", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::ripemd160(view_t(data.data(), data.size()), hash, 20);
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
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!digest::umac(view_t(key, digest::UMAC_KEY), view_t(nonce, sizeof(nonce)), view_t(data.data(), data.size()), tag, digest::UMAC_128)){
		// Выводим сообщение об отказе выработки имитовставки
		cout << "Выработать имитовставку UMAC области байтов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы выработки имитовставки UMAC-128: эталон UMAC не несёт
	band("UMAC-128", 8, VOLUME, [&key, &nonce, &data, &tag]() noexcept -> void {
		// Выполняем выработку имитовставки области байтов
		digest::umac(view_t(key, digest::UMAC_KEY), view_t(nonce, sizeof(nonce)), view_t(data.data(), data.size()), tag, digest::UMAC_128);
	});
	// Объект блочного шифра SM4
	cipher::sm4_t sm4;
	// Если ключ блочного шифра SM4 установить не удалось
	if(!sm4.key(view_t(key, cipher::SM4_KEY))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ блочного шифра SM4 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового алгоритма блочного шифрования SM4
	const cipher::block_t sm4Base(sm4);
	// Режим шифрования с проверкой целостности на шифре SM4
	cipher::gcm_t sm4Galois;
	// Если режим шифрования с проверкой целостности на SM4 завести не удалось
	if(!sm4Galois.start(sm4Base, view_t(seed, 12)) || !sm4Galois.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag)){
		// Выводим сообщение об отказе шифрования с проверкой целостности
		cout << "Завести шифрование с проверкой целостности SM4-GCM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования SM4-GCM своей работы: эталон SM4-GCM не несёт
	band("SM4-GCM своя", 8, VOLUME, [&sm4Galois, &sm4Base, &seed, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима шифрования с проверкой целостности
		sm4Galois.start(sm4Base, view_t(seed, 12));
		// Выполняем шифрование области байтов с проверкой целостности
		sm4Galois.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Режим шифрования с проверкой целостности CCM на шифре AES
	cipher::ccm_t ccm;
	// Если режим CCM завести не удалось
	if(!ccm.start(standard, view_t(seed, 12)) || !ccm.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag)){
		// Выводим сообщение об отказе шифрования с проверкой целостности
		cout << "Завести шифрование с проверкой целостности AES-256-CCM не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования AES-256-CCM своей работы
	const double ccmAead = band("AES-256-CCM своя", 8, VOLUME, [&ccm, &standard, &seed, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима шифрования с проверкой целостности
		ccm.start(standard, view_t(seed, 12));
		// Выполняем шифрование области байтов с проверкой целостности
		ccm.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Объект блочного шифра 3DES
	cipher::des_t des;
	// Если ключ блочного шифра 3DES установить не удалось
	if(!des.key(view_t(key, cipher::DES3_KEY))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ блочного шифра 3DES не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового алгоритма блочного шифрования 3DES
	const cipher::block_t desBase(des);
	// Режим сцепления блоков на шифре 3DES
	cipher::chaining_t desChaining;
	// Если режим сцепления блоков на 3DES завести не удалось
	if(!desChaining.start(desBase, view_t(seed, cipher::DES_BLOCK)) || !desChaining.encrypt(view_t(data.data(), data.size()), result.data())){
		// Выводим сообщение об отказе шифрования
		cout << "Завести шифрование DES-EDE3-CBC не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования DES-EDE3-CBC своей работы
	const double desCbc = band("DES-EDE3-CBC своя", 8, VOLUME, [&desChaining, &desBase, &seed, &data, &result]() noexcept -> void {
		// Выполняем заведение режима сцепления блоков
		desChaining.start(desBase, view_t(seed, cipher::DES_BLOCK));
		// Выполняем шифрование области байтов
		desChaining.encrypt(view_t(data.data(), data.size()), result.data());
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
	const double magmaStream = band("Магма-CTR", 8, VOLUME, [&sequence, &data, &result]() noexcept -> void {
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
	const double magmaSealed = band("Магма-MGM", 8, VOLUME, [&assurance, &little, &grain, &data, &result, &tag]() noexcept -> void {
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
	// Место, в которое помещаются случайные байты
	uint8_t random[32];
	// Выполняем замер числа выдач случайных байтов за секунду: длина ключа и секретного числа подписи
	const double randomness = count("Случайные байты (32)", 20000, [&random]() noexcept -> void {
		// Выполняем получение случайных байтов
		entropy::bytes(random, sizeof(random));
	});
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
	// Кривая P-256: обмен ключами по ней сличается с эталоном той же кривой
	curve::curve_t nist;
	// Если параметры кривой P-256 получить не удалось
	if(!curve::parameters("1.2.840.10045.3.1.7", nist)){
		// Выводим сообщение об отказе получения параметров кривой
		cout << "Получить параметры кривой P-256 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Секретный ключ обмена по кривой P-256
	uint8_t nistSecret[32];
	// Открытый ключ обмена по кривой P-256
	uint8_t nistOpened[64];
	// Общее значение обмена по кривой P-256
	uint8_t nistShared[32];
	// Если ключевую пару кривой P-256 выработать не удалось либо общее значение не выработалось
	if(!agreement::generate(nist, nistSecret, nistOpened) || !agreement::ecdhe(nist, view_t(nistSecret, sizeof(nistSecret)), view_t(nistOpened, sizeof(nistOpened)), nistShared)){
		// Выводим сообщение об отказе обмена ключами
		cout << "Выработать общее значение обмена по кривой P-256 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа обменов ключами по кривой P-256 за секунду
	const double nistExchange = count("Обмен ключами ECDH P-256", 200, [&nist, &nistSecret, &nistOpened, &nistShared]() noexcept -> void {
		// Выполняем выработку общего значения обмена по кривой P-256
		agreement::ecdhe(nist, view_t(nistSecret, sizeof(nistSecret)), view_t(nistOpened, sizeof(nistOpened)), nistShared);
	});
	// Секретный ключ обмена X25519
	uint8_t montSecret[32];
	// Открытый ключ обмена X25519
	uint8_t montKey[32];
	// Общее значение обмена X25519
	uint8_t montShared[32];
	// Если ключевую пару X25519 выработать не удалось либо общее значение не выработалось
	if(!agreement::generate(montSecret, montKey) || !agreement::x25519(view_t(montSecret, sizeof(montSecret)), view_t(montKey, sizeof(montKey)), montShared)){
		// Выводим сообщение об отказе обмена ключами
		cout << "Выработать общее значение обмена X25519 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа обменов ключами X25519 за секунду
	const double montExchange = count("Обмен ключами X25519", 200, [&montSecret, &montKey, &montShared]() noexcept -> void {
		// Выполняем выработку общего значения обмена X25519
		agreement::x25519(view_t(montSecret, sizeof(montSecret)), view_t(montKey, sizeof(montKey)), montShared);
	});
	/**
	 * VKO по RFC 7836 ждёт секрет и координаты от старшего байта, тогда как обмен
	 * ключами отдаёт их от младшего, как они идут по связи: разворот здесь, у границы
	 */
	uint8_t owned[32], x[32], y[32];
	// Выполняем разворот секретного ключа и координат открытого ключа
	/**
	 * Выполняем разворот секретного ключа и координат открытого ключа
	 */
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
	// Секреты и открытые ключи X448 обеих сторон
	uint8_t x448Secret[agreement::X448_SIZE], x448Key[agreement::X448_SIZE], x448Peer[agreement::X448_SIZE], x448Shared[agreement::X448_SIZE];
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!agreement::pair448(x448Secret, x448Key) || !agreement::pair448(x448Shared, x448Peer) || !agreement::x448(view_t(x448Secret, sizeof(x448Secret)), view_t(x448Peer, sizeof(x448Peer)), x448Shared)){
		// Выводим сообщение об отказе обмена ключами
		cout << "Выполнить обмен ключами X448 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа обменов ключами X448 за секунду
	const double x448Exchange = count("Обмен ключами X448", 200, [&x448Secret, &x448Peer, &x448Shared]() noexcept -> void {
		// Выполняем выработку общего значения обмена
		agreement::x448(view_t(x448Secret, sizeof(x448Secret)), view_t(x448Peer, sizeof(x448Peer)), x448Shared);
	});
	// Секреты и открытые ключи FFDHE modp2048: модуль в 256 байтов
	uint8_t ffdheSecretA[256], ffdheSecretB[256], ffdheKeyA[256], ffdheKeyB[256], ffdheShared[256];
	// Длина показателя группы modp2048: показатель короче модуля, как у всякой стороны связи
	const size_t ffdheLength = agreement::exponent(256);
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!agreement::pairffdhe(256, ffdheSecretA, ffdheKeyA) || !agreement::pairffdhe(256, ffdheSecretB, ffdheKeyB) || !agreement::ffdhe(256, view_t(ffdheSecretA, ffdheLength), view_t(ffdheKeyB, sizeof(ffdheKeyB)), ffdheShared)){
		// Выводим сообщение об отказе обмена ключами
		cout << "Выполнить обмен ключами FFDHE-2048 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа обменов ключами FFDHE modp2048 за секунду
	const double ffdheExchange = count("Обмен ключами FFDHE-2048", 100, [&ffdheSecretA, &ffdheKeyB, &ffdheShared, &ffdheLength]() noexcept -> void {
		// Выполняем выработку общего значения обмена
		agreement::ffdhe(256, view_t(ffdheSecretA, ffdheLength), view_t(ffdheKeyB, sizeof(ffdheKeyB)), ffdheShared);
	});
	// Механизм упаковки ML-KEM-768
	constexpr agreement::kem_t kem = agreement::kem_t::MLKEM768;
	// Ключ упаковки, ключ распаковки и шифртекст упаковки ML-KEM-768
	uint8_t kemKey[1184], kemSecret[2400], kemCipher[1088], kemShared[32];
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!agreement::generate(kem, kemKey, kemSecret) || !agreement::encapsulate(kem, view_t(kemKey, sizeof(kemKey)), kemCipher, kemShared) || !agreement::decapsulate(kem, view_t(kemSecret, sizeof(kemSecret)), view_t(kemCipher, sizeof(kemCipher)), kemShared)){
		// Выводим сообщение об отказе упаковки
		cout << "Выполнить упаковку ML-KEM-768 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа упаковок ML-KEM-768 за секунду
	const double mlkemSealing = count("ML-KEM-768 упаковка", 200, [&kemKey, &kemCipher, &kemShared]() noexcept -> void {
		// Выполняем упаковку свежего секрета на ключе получателя
		agreement::encapsulate(agreement::kem_t::MLKEM768, view_t(kemKey, sizeof(kemKey)), kemCipher, kemShared);
	});
	// Выполняем замер числа распаковок ML-KEM-768 за секунду
	const double mlkemOpening = count("ML-KEM-768 распаковка", 200, [&kemSecret, &kemCipher, &kemShared]() noexcept -> void {
		// Выполняем распаковку секрета закрытым ключом получателя
		agreement::decapsulate(agreement::kem_t::MLKEM768, view_t(kemSecret, sizeof(kemSecret)), view_t(kemCipher, sizeof(kemCipher)), kemShared);
	});
	// Ключ RSA-2048 для замера подписи и сличения
	sign::rsa_t rsa;
	// Если ключ RSA породить не удалось
	if(!rsa.generate(2048)){
		// Выводим сообщение об отказе
		cout << "Породить ключ RSA-2048 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подпись RSA
	uint8_t rsaSignature[256];
	// Выполняем замер числа подписей RSA-2048 PSS за секунду: секретное действие по китайской теореме об остатках с ослеплением
	const double rsaSigning = count("RSA-2048 подпись PSS", 200, [&rsa, &hash, &rsaSignature]() noexcept -> void {
		// Выполняем подпись RSA-PSS хеша SHA-256
		rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, 32), rsaSignature);
	});
	// Выполняем замер числа сличений подписи RSA-2048 PSS за секунду: открытое действие
	const double rsaChecking = count("RSA-2048 сличение PSS", 2000, [&rsa, &hash, &rsaSignature]() noexcept -> void {
		// Выполняем сличение подписи RSA-PSS
		rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, 32), view_t(rsaSignature, sizeof(rsaSignature)));
	});
	// Ключ ML-DSA-65 для замера подписи и сличения
	sign::mldsa_t mldsa;
	// Места записей ключей ML-DSA-65
	uint8_t mldsaPublic[1952], mldsaSecret[4032];
	// Если ключ ML-DSA породить не удалось
	if(!mldsa.generate(sign::mldsa_t::set_t::DSA65, mldsaPublic, mldsaSecret)){
		// Выводим сообщение об отказе
		cout << "Породить ключ ML-DSA-65 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер порождения ключа ML-DSA-65: отбор SHAKE и матрица заново
	const double mldsaGenerate = count("ML-DSA-65 порождение ключа", 100, [&mldsa, &mldsaPublic, &mldsaSecret]() noexcept -> void {
		// Выполняем порождение ключа ML-DSA-65 из источника случайности
		mldsa.generate(sign::mldsa_t::set_t::DSA65, mldsaPublic, mldsaSecret);
	});
	// Подпись ML-DSA-65
	uint8_t mldsaSignature[3309];
	// Выполняем замер числа подписей ML-DSA-65 за секунду: хеджированная выработка
	const double mldsaSigning = count("ML-DSA-65 подпись", 200, [&mldsa, &hash, &mldsaSignature]() noexcept -> void {
		// Выполняем подпись ML-DSA-65 с пустым контекстом
		mldsa.make(view_t(hash, 32), view_t(nullptr, 0), mldsaSignature);
	});
	// Выполняем замер числа сличений подписи ML-DSA-65 за секунду: открытое действие
	const double mldsaChecking = count("ML-DSA-65 сличение", 500, [&mldsa, &hash, &mldsaSignature]() noexcept -> void {
		// Выполняем сличение подписи ML-DSA-65 с пустым контекстом
		mldsa.check(view_t(hash, 32), view_t(nullptr, 0), view_t(mldsaSignature, sizeof(mldsaSignature)));
	});
	// Объект электронной подписи Ed25519
	sign::ed25519_t ed25519;
	// Зерно ключа подписи Ed25519
	uint8_t ed25519Secret[sign::ed25519_t::KEY_SIZE];
	// Подпись Ed25519
	uint8_t ed25519Sealing[sign::ed25519_t::SIGNATURE_SIZE];
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!ed25519.generate(ed25519Secret, sizeof(ed25519Secret)) || !ed25519.make(view_t(hash, 32), ed25519Sealing) || !ed25519.check(view_t(hash, 32), view_t(ed25519Sealing, sizeof(ed25519Sealing)))){
		// Выводим сообщение об отказе подписи
		cout << "Породить ключ либо подписать Ed25519 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа подписей Ed25519 за секунду: детерминированная подпись сообщения
	const double ed25519Signing = count("Ed25519 подпись", 200, [&ed25519, &hash, &ed25519Sealing]() noexcept -> void {
		// Выполняем подпись хеша области байтов
		ed25519.make(view_t(hash, 32), ed25519Sealing);
	});
	// Выполняем замер числа сличений подписи Ed25519 за секунду
	const double ed25519Checking = count("Ed25519 сличение", 2000, [&ed25519, &hash, &ed25519Sealing]() noexcept -> void {
		// Выполняем сличение подписи
		ed25519.check(view_t(hash, 32), view_t(ed25519Sealing, sizeof(ed25519Sealing)));
	});
	// Объект электронной подписи Ed448
	sign::ed448_t ed448;
	// Зерно ключа подписи Ed448
	uint8_t ed448Secret[sign::ed448_t::KEY_SIZE];
	// Подпись Ed448
	uint8_t ed448Sealing[sign::ed448_t::SIGNATURE_SIZE];
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!ed448.generate(ed448Secret, sizeof(ed448Secret)) || !ed448.make(view_t(hash, 32), ed448Sealing) || !ed448.check(view_t(hash, 32), view_t(ed448Sealing, sizeof(ed448Sealing)))){
		// Выводим сообщение об отказе подписи
		cout << "Породить ключ либо подписать Ed448 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа подписей Ed448 за секунду: детерминированная подпись сообщения
	const double ed448Signing = count("Ed448 подпись", 100, [&ed448, &hash, &ed448Sealing]() noexcept -> void {
		// Выполняем подпись хеша области байтов
		ed448.make(view_t(hash, 32), ed448Sealing);
	});
	// Выполняем замер числа сличений подписи Ed448 за секунду
	const double ed448Checking = count("Ed448 сличение", 1000, [&ed448, &hash, &ed448Sealing]() noexcept -> void {
		// Выполняем сличение подписи
		ed448.check(view_t(hash, 32), view_t(ed448Sealing, sizeof(ed448Sealing)));
	});
	// Параметры кривой curveSM2
	curve::curve_t sm2Curve;
	// Объект электронной подписи SM2
	sign::sm2_t sm2;
	// Опознаватель подписывающего по умолчанию из GB/T 32918.2
	const uint8_t SM2_ID[] = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
	// Ключ подписи SM2
	uint8_t sm2Secret[32];
	// Случайность выработки подписи SM2
	uint8_t sm2Random[32];
	// Подпись SM2
	uint8_t sm2Sealing[64];
	// Выполняем выработку ключа и случайности подписи SM2
	entropy::bytes(sm2Secret, sizeof(sm2Secret));
	// Выполняем выработку случайности подписи SM2
	entropy::bytes(sm2Random, sizeof(sm2Random));
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 */
	if(!curve::parameters("1.2.156.10197.1.301", sm2Curve) || !sm2.start(sm2Curve) || !sm2.secret(view_t(sm2Secret, sizeof(sm2Secret)), view_t(SM2_ID, sizeof(SM2_ID))) || !sm2.make(view_t(hash, 32), view_t(sm2Random, sizeof(sm2Random)), sm2Sealing) || !sm2.check(view_t(hash, 32), view_t(sm2Sealing, sizeof(sm2Sealing)))){
		// Выводим сообщение об отказе подписи
		cout << "Завести подпись SM2 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа подписей SM2 за секунду: случайность выработки подаётся снаружи
	const double sm2Signing = count("SM2 подпись", 200, [&sm2, &hash, &sm2Random, &sm2Sealing]() noexcept -> void {
		// Выполняем подпись хеша области байтов
		sm2.make(view_t(hash, 32), view_t(sm2Random, sizeof(sm2Random)), sm2Sealing);
	});
	// Выполняем замер числа сличений подписи SM2 за секунду
	const double sm2Checking = count("SM2 сличение", 1000, [&sm2, &hash, &sm2Sealing]() noexcept -> void {
		// Выполняем сличение подписи
		sm2.check(view_t(hash, 32), view_t(sm2Sealing, sizeof(sm2Sealing)));
	});
	// Набор подписи SLH-DSA
	const sign::slhdsa_t::set_t slhSet = sign::slhdsa_t::set_t::SHA2_128S;
	// Объект электронной подписи SLH-DSA
	sign::slhdsa_t slhdsa;
	// Ключ проверки, ключ подписи и подпись SLH-DSA
	vector <uint8_t> slhKey(sign::slhdsa_t::publicSize(slhSet)), slhSecret(sign::slhdsa_t::secretSize(slhSet)), slhSealing(sign::slhdsa_t::signatureSize(slhSet));
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ меряется мгновением
	 *
	 * @details Порождение заполняет лишь места ключей, а состояние модуля не занимает:
	 *          ключ подписи устанавливается отдельным вызовом
	 *
	 */
	if(!slhdsa.generate(slhSet, slhKey.data(), slhSecret.data()) || !slhdsa.secret(slhSet, view_t(slhSecret.data(), slhSecret.size())) || !slhdsa.make(view_t(hash, 32), view_t(), slhSealing.data()) || !slhdsa.check(view_t(hash, 32), view_t(), view_t(slhSealing.data(), slhSealing.size()))){
		// Выводим сообщение об отказе подписи
		cout << "Породить ключ либо подписать SLH-DSA не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа подписей SLH-DSA за секунду: тысячи хешей на одну подпись
	const double slhSigning = count("SLH-DSA-128s подпись", 20, [&slhdsa, &hash, &slhSealing]() noexcept -> void {
		// Выполняем подпись хеша области байтов
		slhdsa.make(view_t(hash, 32), view_t(), slhSealing.data());
	});
	// Выполняем замер числа сличений подписи SLH-DSA за секунду
	const double slhChecking = count("SLH-DSA-128s сличение", 100, [&slhdsa, &hash, &slhSealing]() noexcept -> void {
		// Выполняем сличение подписи
		slhdsa.check(view_t(hash, 32), view_t(), view_t(slhSealing.data(), slhSealing.size()));
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
	// Готовим ключ подлинности один раз: так подлинность и служит связям
	if(credentials.prepare() != context::error_t::NONE){
		// Выводим сообщение об отказе подготовки ключа
		cout << "Подготовить ключ подлинности сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Числа рукопожатий TLS 1.3 и полоса записей, сличаемые с эталоном
	double shakeDefaults = 0., shakeEcdsa = 0., shakeRsa = 0., records16 = 0., records1200 = 0.;
	{
		// Выводим заголовок раздела рукопожатий TLS 1.3
		cout << endl << "Рукопожатия TLS 1.3" << endl << endl;
		// Классические подлинности из набора ключей
		context::credential_t ecdsa, rsa;
		// Если подлинности прочитать либо подготовить не удалось
		if(!keyed("ec256.pem", "ec256.crt", ecdsa) || !keyed("rsa2048.pem", "rsa2048.crt", rsa) || (ecdsa.prepare() != context::error_t::NONE) || (rsa.prepare() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Прочитать подлинности из набора ключей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		/**
		 * Рукопожатие с заданными группами обмена, наборами шифрования и схемами подписи:
		 * умолчания связи - классика без ГОСТ (X25519MLKEM768, AES-256-GCM), а ГОСТ
		 * объявляется перечнями, как это делает потребитель; цена рукопожатия
		 * определяется кривой и набором, а не подлинностью
		 */
		const auto shake = [](const context::credential_t & credential, const vector <extension::group_t> * groups, const vector <protect::suite_t> * suites, const vector <extension::scheme_t> * schemes) noexcept -> void {
			// Связи сторон
			client::context_t client;
			// Заводим связь стороны сервера
			server::context_t server;
			// Если группы обмена заданы
			if(groups != nullptr){
				// Устанавливаем группы обмена сторон
				client.groups(* groups);
				// Устанавливаем группы обмена серверу
				server.groups(* groups);
			}
			// Если наборы шифрования заданы
			if(suites != nullptr){
				// Устанавливаем наборы шифрования сторон
				client.suites(* suites);
				// Устанавливаем наборы шифрования серверу
				server.suites(* suites);
			}
			// Если схемы подписи заданы
			if(schemes != nullptr){
				// Устанавливаем схемы подписи сторон
				client.schemes(* schemes);
				// Устанавливаем схемы подписи серверу
				server.schemes(* schemes);
			}
			// Устанавливаем подлинность стороны сервера
			server.credential(credential);
			// Выполняем заведение связей сторон
			server.start();
			// Заводим связь стороны клиента
			client.start();
			/**
			 * Выполняем передачу байтов между сторонами, пока им есть что сказать
			 */
			for(size_t i = 0; (i < 16) && pump(client, server); i++)
				// Продолжаем передачу байтов между сторонами связи
				continue;
		};
		// Кривые ГОСТ-512 и ГОСТ-256, набор «Кузнечик»-MGM и схемы подписи ГОСТ: объявление ГОСТ потребителем
		const vector <extension::group_t> gost512 {extension::group_t::GC512C};
		// Задаём кривую обмена ГОСТ-256
		const vector <extension::group_t> gost256 {extension::group_t::GC256A};
		// Задаём набор «Кузнечик»-MGM
		const vector <protect::suite_t> mgm {protect::suite_t::KUZNYECHIK_MGM_L};
		// Задаём схемы подписи ГОСТ: начало списка
		const vector <extension::scheme_t> gostSchemes {
			// Задаём схемы подписи ГОСТ: продолжение списка
			extension::scheme_t::S256A, extension::scheme_t::S256B, extension::scheme_t::S256C, extension::scheme_t::S256D,
			extension::scheme_t::S512A, extension::scheme_t::S512B, extension::scheme_t::S512C
		};
		// Группа X25519 и набор AES-128-GCM: условия сличения с эталоном
		const vector <extension::group_t> mont {extension::group_t::X25519};
		// Задаём набор AES-128-GCM
		const vector <protect::suite_t> gcm {protect::suite_t::AES_128_GCM_SHA256};
		// Выполняем замеры рукопожатий по конфигурациям
		shakeDefaults = count("TLS 1.3 умолчания ECDSA", 200, [&shake, &ecdsa]() noexcept -> void {
			// Проводим рукопожатие умолчаниями связи: X25519MLKEM768, AES-256-GCM, ECDSA P-256
			shake(ecdsa, nullptr, nullptr, nullptr);
		});
		// Выполняем замер рукопожатия на кривой ГОСТ-512 набором «Кузнечик»-MGM
		count("TLS 1.3 ГОСТ-512 MGM", 50, [&shake, &credentials, &gost512, &mgm, &gostSchemes]() noexcept -> void {
			// Проводим рукопожатие на кривой ГОСТ-512 набором «Кузнечик»-MGM
			shake(credentials, &gost512, &mgm, &gostSchemes);
		});
		count("TLS 1.3 ГОСТ-256 MGM", 100, [&shake, &credentials, &gost256, &mgm, &gostSchemes]() noexcept -> void {
			// Проводим рукопожатие на кривой ГОСТ-256 набором «Кузнечик»-MGM
			shake(credentials, &gost256, &mgm, &gostSchemes);
		});
		// Выполняем замер рукопожатия классической подлинностью ECDSA
		shakeEcdsa = count("TLS 1.3 X25519 ECDSA GCM", 200, [&shake, &ecdsa, &mont, &gcm]() noexcept -> void {
			// Проводим рукопожатие классической подлинностью ECDSA
			shake(ecdsa, &mont, &gcm, nullptr);
		});
		// Выполняем замер рукопожатия классической подлинностью RSA
		shakeRsa = count("TLS 1.3 X25519 RSA GCM", 100, [&shake, &rsa, &mont, &gcm]() noexcept -> void {
			// Проводим рукопожатие классической подлинностью RSA
			shake(rsa, &mont, &gcm, nullptr);
		});
		// Связи сторон для замера полосы записей: X25519, ECDSA, AES-128-GCM
		client::context_t client;
		// Заводим связь стороны сервера
		server::context_t server;
		// Устанавливаем группу обмена, набор шифрования и подлинность
		client.groups(mont);
		// Устанавливаем группу обмена серверу
		server.groups(mont);
		// Устанавливаем набор шифрования клиенту
		client.suites(gcm);
		// Устанавливаем набор шифрования серверу
		server.suites(gcm);
		// Устанавливаем подлинность серверу
		server.credential(ecdsa);
		// Если связи завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе
			cout << "Завести связь для замера записей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
		// Если связь не установлена
		if(!client.established() || !server.established()){
			// Выводим сообщение об отказе
			cout << "Установить связь для замера записей не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Прикладные данные: запись наибольшей длины и запись в 1200 байт
		const vector <uint8_t> large(record::RECORD_PLAINTEXT, 0x5A), small(1200, 0x5A);
		// Накопитель принятых данных
		vector <uint8_t> received;
		// Выполняем замеры полосы записей: запись шифруется клиентом и расшифровывается сервером
		records16 = band("TLS 1.3 записи 16 КиБ", 8, large.size() * 64, [&client, &server, &large, &received]() noexcept -> void {
			// Передаём записи наибольшей длины
			transfer(client, server, view_t(large.data(), large.size()), 64, received);
		});
		// Выполняем замер полосы записей в 1200 байт
		records1200 = band("TLS 1.3 записи 1200 байт", 8, small.size() * 256, [&client, &server, &small, &received]() noexcept -> void {
			// Передаём записи в 1200 байт
			transfer(client, server, view_t(small.data(), small.size()), 256, received);
		});
	}
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
		psk.key.assign(preshared.begin(), preshared.end());
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
		// Замеры SHA3-256 эталона: у эталона без этого хеша замеров нет
		double sha3Ref = 0.;
		// Хеш SHA3-256 эталона из провайдера
		EVP_MD * sha3Method = ::EVP_MD_fetch(nullptr, "SHA3-256", nullptr);
		// Если хеш SHA3-256 у эталона нашёлся
		if(sha3Method != nullptr){
			// Выполняем замер полосы хеширования SHA3-256 эталона
			sha3Ref = band("SHA3-256", 16, VOLUME, [&data, &hash, &sha3Method]() noexcept -> void {
				// Длина выработанного хеша области байтов
				unsigned int length = 0;
				// Выполняем хеширование области байтов
				::EVP_Digest(data.data(), data.size(), hash, &length, sha3Method, nullptr);
			});
			// Освобождаем хеш SHA3-256 эталона
			::EVP_MD_free(sha3Method);
		} else {
			// Выводим примету отсутствия SHA3-256 у эталона
			cout << "У эталона SHA3-256 нет, сличение пропускается" << endl;
		}
		// Замеры SHA3-512 эталона: у эталона без этого хеша замеров нет
		double sha3longRef = 0.;
		// Хеш SHA3-512 эталона из провайдера
		EVP_MD * sha3longMethod = ::EVP_MD_fetch(nullptr, "SHA3-512", nullptr);
		// Если хеш SHA3-512 у эталона нашёлся
		if(sha3longMethod != nullptr){
			// Выполняем замер полосы хеширования SHA3-512 эталона
			sha3longRef = band("SHA3-512", 16, VOLUME, [&data, &hash, &sha3longMethod]() noexcept -> void {
				// Длина выработанного хеша области байтов
				unsigned int length = 0;
				// Выполняем хеширование области байтов
				::EVP_Digest(data.data(), data.size(), hash, &length, sha3longMethod, nullptr);
			});
			// Освобождаем хеш SHA3-512 эталона
			::EVP_MD_free(sha3longMethod);
		} else {
			// Выводим примету отсутствия SHA3-512 у эталона
			cout << "У эталона SHA3-512 нет, сличение пропускается" << endl;
		}
		// Замеры SM3 эталона: у эталона без этого хеша замеров нет
		double sm3Ref = 0.;
		// Хеш SM3 эталона из провайдера
		EVP_MD * sm2Method = ::EVP_MD_fetch(nullptr, "SM3", nullptr);
		// Если хеш SM3 у эталона нашёлся
		if(sm2Method != nullptr){
			// Выполняем замер полосы хеширования SM3 эталона
			sm3Ref = band("SM3", 16, VOLUME, [&data, &hash, &sm2Method]() noexcept -> void {
				// Длина выработанного хеша области байтов
				unsigned int length = 0;
				// Выполняем хеширование области байтов
				::EVP_Digest(data.data(), data.size(), hash, &length, sm2Method, nullptr);
			});
			// Освобождаем хеш SM3 эталона
			::EVP_MD_free(sm2Method);
		} else {
			// Выводим примету отсутствия SM3 у эталона
			cout << "У эталона SM3 нет, сличение пропускается" << endl;
		}
		// Замеры RIPEMD-160 эталона: у эталона без этого хеша замеров нет
		double ripemdRef = 0.;
		// Хеш RIPEMD-160 эталона из провайдера
		EVP_MD * ripemdMethod = ::EVP_MD_fetch(nullptr, "RIPEMD160", nullptr);
		// Если хеш RIPEMD-160 у эталона нашёлся
		if(ripemdMethod != nullptr){
			// Выполняем замер полосы хеширования RIPEMD-160 эталона
			ripemdRef = band("RIPEMD-160", 16, VOLUME, [&data, &hash, &ripemdMethod]() noexcept -> void {
				// Длина выработанного хеша области байтов
				unsigned int length = 0;
				// Выполняем хеширование области байтов
				::EVP_Digest(data.data(), data.size(), hash, &length, ripemdMethod, nullptr);
			});
			// Освобождаем хеш RIPEMD-160 эталона
			::EVP_MD_free(ripemdMethod);
		} else {
			// Выводим примету отсутствия RIPEMD-160 у эталона
			cout << "У эталона RIPEMD-160 нет, сличение пропускается" << endl;
		}
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
		// Замеры AES-256-CCM эталона: у эталона без этого шифра замеров нет
		double ccmRef = 0.;
		// Шифр AES-256-CCM эталона из провайдера
		EVP_CIPHER * ccmMethod = ::EVP_CIPHER_fetch(nullptr, "AES-256-CCM", nullptr);
		// Если шифр AES-256-CCM у эталона нашёлся
		if(ccmMethod != nullptr){
			// Выполняем замер полосы шифрования с проверкой целостности AES-256-CCM эталона
			ccmRef = band("AES-256-CCM", 8, VOLUME, [&context, &ccmMethod, &key, &seed, &data, &result, &tag]() noexcept -> void {
				// Длина зашифрованной области байтов
				int length = 0;
				// Выполняем заведение шифрования без ключа: сперва длина имитовставки
				::EVP_EncryptInit_ex(context, ccmMethod, nullptr, nullptr, nullptr);
				// Назначаем имитовставке шестнадцать байтов
				::EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16, nullptr);
				// Выполняем заведение шифрования с ключом и вектором замены
				::EVP_EncryptInit_ex(context, nullptr, nullptr, key, seed);
				// Выполняем шифрование области байтов
				::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
				// Выполняем завершение шифрования области байтов
				::EVP_EncryptFinal_ex(context, result.data() + length, &length);
				// Выполняем извлечение имитовставки шифрования
				::EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, tag);
			});
			// Освобождаем шифр AES-256-CCM эталона
			::EVP_CIPHER_free(ccmMethod);
		} else {
			// Выводим примету отсутствия AES-256-CCM у эталона
			cout << "У эталона AES-256-CCM нет, сличение пропускается" << endl;
		}
		// Замеры AES-256-CBC эталона: у эталона без этого шифра замеров нет
		double cbcRef = 0.;
		// Шифр AES-256-CBC эталона из провайдера
		EVP_CIPHER * cbcMethod = ::EVP_CIPHER_fetch(nullptr, "AES-256-CBC", nullptr);
		// Если шифр AES-256-CBC у эталона нашёлся
		if(cbcMethod != nullptr){
			// Выполняем замер полосы шифрования AES-256-CBC эталона
			cbcRef = band("AES-256-CBC", 8, VOLUME, [&context, &cbcMethod, &key, &seed, &data, &result]() noexcept -> void {
				// Длина зашифрованной области байтов
				int length = 0;
				// Выполняем заведение шифрования области байтов: вектор замены в шестнадцать байтов
				::EVP_EncryptInit_ex(context, cbcMethod, nullptr, key, seed);
				// Выполняем шифрование области байтов
				::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
				// Выполняем завершение шифрования области байтов
				::EVP_EncryptFinal_ex(context, result.data() + length, &length);
			});
			// Освобождаем шифр AES-256-CBC эталона
			::EVP_CIPHER_free(cbcMethod);
		}
		// Замеры DES-EDE3-CBC эталона: у эталона без этого шифра замеров нет
		double desRef = 0.;
		// Шифр DES-EDE3-CBC эталона из провайдера
		EVP_CIPHER * desMethod = ::EVP_CIPHER_fetch(nullptr, "DES-EDE3-CBC", nullptr);
		// Если шифр DES-EDE3-CBC у эталона нашёлся
		if(desMethod != nullptr){
			// Выполняем замер полосы шифрования DES-EDE3-CBC эталона
			desRef = band("DES-EDE3-CBC", 8, VOLUME, [&context, &desMethod, &key, &nonce, &data, &result]() noexcept -> void {
				// Длина зашифрованной области байтов
				int length = 0;
				// Выполняем заведение шифрования области байтов: ключ в двадцать четыре байта, вектор в восемь
				::EVP_EncryptInit_ex(context, desMethod, nullptr, key, nonce);
				// Выполняем шифрование области байтов
				::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
				// Выполняем завершение шифрования области байтов
				::EVP_EncryptFinal_ex(context, result.data() + length, &length);
			});
			// Освобождаем шифр DES-EDE3-CBC эталона
			::EVP_CIPHER_free(desMethod);
		} else {
			// Выводим примету отсутствия DES-EDE3-CBC у эталона
			cout << "У эталона DES-EDE3-CBC нет, сличение пропускается" << endl;
		}
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
		// Место, в которое помещаются случайные байты эталона
		uint8_t randomRef[32];
		// Выполняем замер числа выдач случайных байтов эталона за секунду
		const double randomnessRef = count("RAND_bytes (32)", 20000, [&randomRef]() noexcept -> void {
			// Выполняем получение случайных байтов эталона
			::RAND_bytes(randomRef, static_cast <int> (sizeof(randomRef)));
		});
		// Ключ RSA-2048 эталона
		EVP_PKEY * rsaKey = ::EVP_RSA_gen(2048);
		// Объекты подписи и сличения RSA-PSS эталона
		EVP_PKEY_CTX * rsaSigner = ::EVP_PKEY_CTX_new(rsaKey, nullptr), * rsaChecker = ::EVP_PKEY_CTX_new(rsaKey, nullptr);
		// Заводим подпись RSA-PSS хеша SHA-256 эталона
		::EVP_PKEY_sign_init(rsaSigner);
		// Устанавливаем набивку подписи PSS
		::EVP_PKEY_CTX_set_rsa_padding(rsaSigner, RSA_PKCS1_PSS_PADDING);
		// Назначаем подписи хеш SHA-256
		::EVP_PKEY_CTX_set_signature_md(rsaSigner, ::EVP_sha256());
		// Заводим сличение подписи RSA-PSS эталона
		::EVP_PKEY_verify_init(rsaChecker);
		// Устанавливаем набивку сличения PSS
		::EVP_PKEY_CTX_set_rsa_padding(rsaChecker, RSA_PKCS1_PSS_PADDING);
		// Назначаем сличению хеш SHA-256
		::EVP_PKEY_CTX_set_signature_md(rsaChecker, ::EVP_sha256());
		// Подпись RSA эталона и её длина
		uint8_t rsaSealing[256];
		// Запоминаем длину подписи
		size_t rsaLength = sizeof(rsaSealing);
		// Выполняем замер числа подписей RSA-2048 PSS эталона за секунду
		const double rsaSign = count("RSA-2048 подпись PSS", 200, [&rsaSigner, &hash, &rsaSealing, &rsaLength]() noexcept -> void {
			// Длина подписи
			rsaLength = sizeof(rsaSealing);
			// Выполняем подпись эталона
			::EVP_PKEY_sign(rsaSigner, rsaSealing, &rsaLength, hash, 32);
		});
		// Выполняем замер числа сличений подписи RSA-2048 PSS эталона за секунду
		const double rsaVerify = count("RSA-2048 сличение PSS", 2000, [&rsaChecker, &hash, &rsaSealing, &rsaLength]() noexcept -> void {
			// Выполняем сличение подписи эталона
			::EVP_PKEY_verify(rsaChecker, rsaSealing, rsaLength, hash, 32);
		});
		// Выполняем освобождение объектов RSA эталона
		::EVP_PKEY_CTX_free(rsaSigner);
		::EVP_PKEY_CTX_free(rsaChecker);
		// Освобождаем ключ RSA эталона
		::EVP_PKEY_free(rsaKey);
		// Замеры ML-DSA-65 эталона: у эталона без ML-DSA замеров нет
		double mldsaGenerateRef = 0., mldsaSignRef = 0., mldsaVerifyRef = 0.;
		// Ключевая пара ML-DSA-65 эталона
		EVP_PKEY * mldsaKey = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65");
		// Если ключевая пара ML-DSA эталона выработалась
		if(mldsaKey != nullptr){
			// Объект работы с подписью ML-DSA эталона: без хеша, сообщение целиком
			EVP_MD_CTX * mldsaDigest = ::EVP_MD_CTX_new();
			// Подпись ML-DSA эталона и её длина
			uint8_t mldsaSealing[3309];
			// Запоминаем длину подписи ML-DSA
			size_t mldsaLength = sizeof(mldsaSealing);
			// Выполняем замер порождения ключа ML-DSA-65 эталона за секунду
			mldsaGenerateRef = count("ML-DSA-65 порождение ключа", 100, []() noexcept -> void {
				// Выполняем порождение ключевой пары ML-DSA-65 эталона
				::EVP_PKEY_free(::EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65"));
			});
			// Выполняем замер числа подписей ML-DSA-65 эталона за секунду
			mldsaSignRef = count("ML-DSA-65 подпись", 200, [&mldsaDigest, &mldsaKey, &hash, &mldsaSealing, &mldsaLength]() noexcept -> void {
				// Длина подписи
				mldsaLength = sizeof(mldsaSealing);
				// Выполняем заведение выработки подписи ML-DSA эталона
				::EVP_DigestSignInit(mldsaDigest, nullptr, nullptr, nullptr, mldsaKey);
				// Выполняем подпись ML-DSA эталона
				::EVP_DigestSign(mldsaDigest, mldsaSealing, &mldsaLength, hash, 32);
			});
			// Выполняем замер числа сличений подписи ML-DSA-65 эталона за секунду
			mldsaVerifyRef = count("ML-DSA-65 сличение", 500, [&mldsaDigest, &mldsaKey, &hash, &mldsaSealing, &mldsaLength]() noexcept -> void {
				// Выполняем заведение сличения подписи ML-DSA эталона
				::EVP_DigestVerifyInit(mldsaDigest, nullptr, nullptr, nullptr, mldsaKey);
				// Выполняем сличение подписи ML-DSA эталона
				::EVP_DigestVerify(mldsaDigest, mldsaSealing, mldsaLength, hash, 32);
			});
			// Выполняем освобождение объектов ML-DSA эталона
			::EVP_MD_CTX_free(mldsaDigest);
			// Освобождаем ключевую пару ML-DSA-65 эталона
			::EVP_PKEY_free(mldsaKey);
		} else {
			// Выводим примету отсутствия ML-DSA у эталона
			cout << "У эталона ML-DSA нет, сличение пропускается" << endl;
		}
		// Замеры Ed25519 эталона: у эталона без Ed25519 замеров нет
		double ed25519SignRef = 0., ed25519VerifyRef = 0.;
		// Ключевая пара Ed25519 эталона
		EVP_PKEY * ed25519Key = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
		// Если ключевая пара Ed25519 эталона выработалась
		if(ed25519Key != nullptr){
			// Объект работы с подписью Ed25519 эталона: без хеша, сообщение целиком
			EVP_MD_CTX * ed25519Digest = ::EVP_MD_CTX_new();
			// Подпись Ed25519 эталона и её длина
			uint8_t ed25519Sealing[64];
			// Запоминаем длину подписи Ed25519
			size_t ed25519Length = sizeof(ed25519Sealing);
			// Выполняем замер числа подписей Ed25519 эталона за секунду
			ed25519SignRef = count("Ed25519 подпись", 200, [&ed25519Digest, &ed25519Key, &hash, &ed25519Sealing, &ed25519Length]() noexcept -> void {
				// Длина подписи
				ed25519Length = sizeof(ed25519Sealing);
				// Выполняем заведение выработки подписи Ed25519 эталона
				::EVP_DigestSignInit(ed25519Digest, nullptr, nullptr, nullptr, ed25519Key);
				// Выполняем подпись Ed25519 эталона
				::EVP_DigestSign(ed25519Digest, ed25519Sealing, &ed25519Length, hash, 32);
			});
			// Выполняем замер числа сличений подписи Ed25519 эталона за секунду
			ed25519VerifyRef = count("Ed25519 сличение", 2000, [&ed25519Digest, &ed25519Key, &hash, &ed25519Sealing, &ed25519Length]() noexcept -> void {
				// Выполняем заведение сличения подписи Ed25519 эталона
				::EVP_DigestVerifyInit(ed25519Digest, nullptr, nullptr, nullptr, ed25519Key);
				// Выполняем сличение подписи Ed25519 эталона
				::EVP_DigestVerify(ed25519Digest, ed25519Sealing, ed25519Length, hash, 32);
			});
			// Выполняем освобождение объектов Ed25519 эталона
			::EVP_MD_CTX_free(ed25519Digest);
			// Освобождаем ключевую пару Ed25519 эталона
			::EVP_PKEY_free(ed25519Key);
		} else {
			// Выводим примету отсутствия Ed25519 у эталона
			cout << "У эталона Ed25519 нет, сличение пропускается" << endl;
		}
		// Замеры Ed448 эталона: у эталона без Ed448 замеров нет
		double ed448SignRef = 0., ed448VerifyRef = 0.;
		// Ключевая пара Ed448 эталона
		EVP_PKEY * ed448Key = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
		// Если ключевая пара Ed448 эталона выработалась
		if(ed448Key != nullptr){
			// Объект работы с подписью Ed448 эталона: без хеша, сообщение целиком
			EVP_MD_CTX * ed448Digest = ::EVP_MD_CTX_new();
			// Подпись Ed448 эталона и её длина
			uint8_t ed448Sealing[114];
			// Запоминаем длину подписи Ed448
			size_t ed448Length = sizeof(ed448Sealing);
			// Выполняем замер числа подписей Ed448 эталона за секунду
			ed448SignRef = count("Ed448 подпись", 100, [&ed448Digest, &ed448Key, &hash, &ed448Sealing, &ed448Length]() noexcept -> void {
				// Длина подписи
				ed448Length = sizeof(ed448Sealing);
				// Выполняем заведение выработки подписи Ed448 эталона
				::EVP_DigestSignInit(ed448Digest, nullptr, nullptr, nullptr, ed448Key);
				// Выполняем подпись Ed448 эталона
				::EVP_DigestSign(ed448Digest, ed448Sealing, &ed448Length, hash, 32);
			});
			// Выполняем замер числа сличений подписи Ed448 эталона за секунду
			ed448VerifyRef = count("Ed448 сличение", 1000, [&ed448Digest, &ed448Key, &hash, &ed448Sealing, &ed448Length]() noexcept -> void {
				// Выполняем заведение сличения подписи Ed448 эталона
				::EVP_DigestVerifyInit(ed448Digest, nullptr, nullptr, nullptr, ed448Key);
				// Выполняем сличение подписи Ed448 эталона
				::EVP_DigestVerify(ed448Digest, ed448Sealing, ed448Length, hash, 32);
			});
			// Выполняем освобождение объектов Ed448 эталона
			::EVP_MD_CTX_free(ed448Digest);
			// Освобождаем ключевую пару Ed448 эталона
			::EVP_PKEY_free(ed448Key);
		} else {
			// Выводим примету отсутствия Ed448 у эталона
			cout << "У эталона Ed448 нет, сличение пропускается" << endl;
		}
		// Замеры SM2 эталона: у эталона без SM2 замеров нет
		double sm2SignRef = 0., sm2VerifyRef = 0.;
		// Ключевая пара SM2 эталона
		EVP_PKEY * sm2Key = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "SM2");
		// Хеш SM3 эталона из провайдера
		EVP_MD * sm3Method = ::EVP_MD_fetch(nullptr, "SM3", nullptr);
		// Если ключевая пара SM2 и хеш SM3 эталона выработались
		if((sm2Key != nullptr) && (sm3Method != nullptr)){
			// Объект работы с подписью SM2 эталона
			EVP_MD_CTX * sm2Digest = ::EVP_MD_CTX_new();
			// Подпись SM2 эталона и её длина
			uint8_t sm2Sealing[72];
			// Запоминаем длину подписи SM2
			size_t sm2Length = sizeof(sm2Sealing);
			// Выполняем замер числа подписей SM2 эталона за секунду: опознаватель ставится всякий раз заново
			sm2SignRef = count("SM2 подпись", 200, [&sm2Digest, &sm2Key, &sm3Method, &hash, &sm2Sealing, &sm2Length, &SM2_ID]() noexcept -> void {
				// Объект параметров подписи SM2 эталона
				EVP_PKEY_CTX * sm2Params = nullptr;
				// Длина подписи
				sm2Length = sizeof(sm2Sealing);
				// Выполняем заведение выработки подписи SM2 с хешем SM3
				::EVP_DigestSignInit(sm2Digest, &sm2Params, sm3Method, nullptr, sm2Key);
				// Вяжем опознаватель подписывающего с подписью
				::EVP_PKEY_CTX_set1_id(sm2Params, SM2_ID, sizeof(SM2_ID));
				// Выполняем подпись SM2 эталона
				::EVP_DigestSign(sm2Digest, sm2Sealing, &sm2Length, hash, 32);
			});
			// Выполняем замер числа сличений подписи SM2 эталона за секунду
			sm2VerifyRef = count("SM2 сличение", 1000, [&sm2Digest, &sm2Key, &sm3Method, &hash, &sm2Sealing, &sm2Length, &SM2_ID]() noexcept -> void {
				// Объект параметров сличения SM2 эталона
				EVP_PKEY_CTX * sm2Params = nullptr;
				// Выполняем заведение сличения подписи SM2 с хешем SM3
				::EVP_DigestVerifyInit(sm2Digest, &sm2Params, sm3Method, nullptr, sm2Key);
				// Вяжем опознаватель подписывающего со сличением
				::EVP_PKEY_CTX_set1_id(sm2Params, SM2_ID, sizeof(SM2_ID));
				// Выполняем сличение подписи SM2 эталона
				::EVP_DigestVerify(sm2Digest, sm2Sealing, sm2Length, hash, 32);
			});
			// Выполняем освобождение объектов SM2 эталона
			::EVP_MD_CTX_free(sm2Digest);
			// Освобождаем ключевую пару SM2 эталона
			::EVP_PKEY_free(sm2Key);
			// Освобождаем хеш SM3 эталона
			::EVP_MD_free(sm3Method);
		} else {
			// Выводим примету отсутствия SM2 у эталона
			cout << "У эталона SM2 нет, сличение пропускается" << endl;
			// Освобождаем выработанные ключ и хеш эталона
			::EVP_PKEY_free(sm2Key);
			// Освобождаем выработанные ключ и хеш эталона
			::EVP_MD_free(sm3Method);
		}
		// Замеры SLH-DSA эталона: у эталона без SLH-DSA замеров нет
		double slhSignRef = 0., slhVerifyRef = 0.;
		// Ключевая пара SLH-DSA эталона
		EVP_PKEY * slhPair = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "SLH-DSA-SHA2-128s");
		// Если ключевая пара SLH-DSA эталона выработалась
		if(slhPair != nullptr){
			// Объект работы с подписью SLH-DSA эталона: без хеша, сообщение целиком
			EVP_MD_CTX * slhDigest = ::EVP_MD_CTX_new();
			// Подпись SLH-DSA эталона и её длина
			vector <uint8_t> slhSealing(7856, 0);
			// Запоминаем длину подписи SLH-DSA
			size_t slhLength = slhSealing.size();
			// Выполняем замер числа подписей SLH-DSA эталона за секунду
			slhSignRef = count("SLH-DSA-128s подпись", 20, [&slhDigest, &slhPair, &hash, &slhSealing, &slhLength]() noexcept -> void {
				// Длина подписи
				slhLength = slhSealing.size();
				// Выполняем заведение выработки подписи SLH-DSA эталона
				::EVP_DigestSignInit(slhDigest, nullptr, nullptr, nullptr, slhPair);
				// Выполняем подпись SLH-DSA эталона
				::EVP_DigestSign(slhDigest, slhSealing.data(), &slhLength, hash, 32);
			});
			// Выполняем замер числа сличений подписи SLH-DSA эталона за секунду
			slhVerifyRef = count("SLH-DSA-128s сличение", 100, [&slhDigest, &slhPair, &hash, &slhSealing, &slhLength]() noexcept -> void {
				// Выполняем заведение сличения подписи SLH-DSA эталона
				::EVP_DigestVerifyInit(slhDigest, nullptr, nullptr, nullptr, slhPair);
				// Выполняем сличение подписи SLH-DSA эталона
				::EVP_DigestVerify(slhDigest, slhSealing.data(), slhLength, hash, 32);
			});
			// Выполняем освобождение объектов SLH-DSA эталона
			::EVP_MD_CTX_free(slhDigest);
			// Освобождаем ключевую пару SLH-DSA эталона
			::EVP_PKEY_free(slhPair);
		} else {
			// Выводим примету отсутствия SLH-DSA у эталона
			cout << "У эталона SLH-DSA нет, сличение пропускается" << endl;
		}
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
		// Ключевая пара X25519 эталона
		EVP_PKEY * mont = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
		// Если ключевую пару X25519 эталона выработать не удалось
		if(mont == nullptr){
			// Выводим сообщение об отказе выработки пары ключей
			cout << "Выработать ключевую пару X25519 эталона не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выполняем замер числа обменов ключами X25519 эталона за секунду
		const double montRef = count("Обмен ключами X25519", 200, [&mont, &common]() noexcept -> void {
			// Длина общего значения обмена эталона
			size_t size = common.size();
			// Объект обмена ключами эталона
			EVP_PKEY_CTX * exchange = ::EVP_PKEY_CTX_new(mont, nullptr);
			// Выполняем заведение обмена ключами эталона
			::EVP_PKEY_derive_init(exchange);
			// Устанавливаем открытый ключ встречной стороны обмена
			::EVP_PKEY_derive_set_peer(exchange, mont);
			// Выполняем выработку общего значения обмена
			::EVP_PKEY_derive(exchange, common.data(), &size);
			// Выполняем освобождение объекта обмена ключами эталона
			::EVP_PKEY_CTX_free(exchange);
		});
		// Ключевая пара X448 эталона
		EVP_PKEY * twin = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "X448");
		// Если ключевую пару X448 эталона выработать не удалось
		if(twin == nullptr){
			// Выводим сообщение об отказе выработки пары
			cout << "Выработать ключевую пару X448 эталона не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Место, в которое помещается общее значение обмена X448 эталона
		vector <uint8_t> twinned(56, 0);
		// Выполняем замер числа обменов ключами X448 эталона за секунду
		const double x448Ref = count("Обмен ключами X448", 200, [&twin, &twinned]() noexcept -> void {
			// Длина общего значения обмена эталона
			size_t size = twinned.size();
			// Объект обмена ключами эталона
			EVP_PKEY_CTX * exchange = ::EVP_PKEY_CTX_new(twin, nullptr);
			// Выполняем заведение обмена ключами эталона
			::EVP_PKEY_derive_init(exchange);
			// Устанавливаем открытый ключ встречной стороны обмена
			::EVP_PKEY_derive_set_peer(exchange, twin);
			// Выполняем выработку общего значения обмена
			::EVP_PKEY_derive(exchange, twinned.data(), &size);
			// Выполняем освобождение объекта обмена ключами эталона
			::EVP_PKEY_CTX_free(exchange);
		});
		// Выполняем освобождение ключевой пары X448 эталона
		::EVP_PKEY_free(twin);
		/**
		 * Замеры упаковки ML-KEM-768 эталона: сама упаковка появилась у эталона
		 * с издания 3.5, младшие издания её не знают
		 */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
		// Замеры упаковки ML-KEM-768 эталона
		double mlkemSealRef = 0., mlkemOpenRef = 0.;
		// Ключевая пара ML-KEM-768 эталона
		EVP_PKEY * kemPair = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768");
		// Если ключевая пара ML-KEM-768 эталона выработалась
		if(kemPair != nullptr){
			// Шифртекст упаковки и секрет эталона
			vector <uint8_t> kemCipher(1088, 0), kemShared(32, 0);
			// Запоминаем длины шифртекста и секрета
			size_t kemCipherLength = kemCipher.size(), kemSharedLength = kemShared.size();
			// Выполняем замер числа упаковок ML-KEM-768 эталона за секунду
			mlkemSealRef = count("ML-KEM-768 упаковка", 200, [&kemPair, &kemCipher, &kemCipherLength, &kemShared, &kemSharedLength]() noexcept -> void {
				// Длины шифртекста и секрета
				kemCipherLength = kemCipher.size();
				kemSharedLength = kemShared.size();
				// Объект упаковки эталона
				EVP_PKEY_CTX * encapsulation = ::EVP_PKEY_CTX_new(kemPair, nullptr);
				// Выполняем заведение упаковки эталона
				::EVP_PKEY_encapsulate_init(encapsulation, nullptr);
				// Выполняем упаковку секрета на ключе получателя
				::EVP_PKEY_encapsulate(encapsulation, kemCipher.data(), &kemCipherLength, kemShared.data(), &kemSharedLength);
				// Выполняем освобождение объекта упаковки эталона
				::EVP_PKEY_CTX_free(encapsulation);
			});
			// Выполняем замер числа распаковок ML-KEM-768 эталона за секунду
			mlkemOpenRef = count("ML-KEM-768 распаковка", 200, [&kemPair, &kemCipher, &kemCipherLength, &kemShared]() noexcept -> void {
				// Длина секрета
				size_t kemSecretLength = kemShared.size();
				// Объект распаковки эталона
				EVP_PKEY_CTX * decapsulation = ::EVP_PKEY_CTX_new(kemPair, nullptr);
				// Выполняем заведение распаковки эталона
				::EVP_PKEY_decapsulate_init(decapsulation, nullptr);
				// Выполняем распаковку секрета закрытым ключом получателя
				::EVP_PKEY_decapsulate(decapsulation, kemShared.data(), &kemSecretLength, kemCipher.data(), kemCipherLength);
				// Выполняем освобождение объекта распаковки эталона
				::EVP_PKEY_CTX_free(decapsulation);
			});
			// Освобождаем ключевую пару ML-KEM-768 эталона
			::EVP_PKEY_free(kemPair);
		} else {
			// Выводим примету отсутствия ML-KEM у эталона
			cout << "У эталона ML-KEM нет, сличение пропускается" << endl;
		}
		/**
		 * Младшие издания эталона упаковки ML-KEM не знают: сличения нет
		 */
#else
		// Замеры упаковки ML-KEM-768 без нового эталона: сличения нет
		const double mlkemSealRef = 0., mlkemOpenRef = 0.;
#endif
		// Замеры обмена ключами FFDHE-2048 эталона: группа ffdhe2048 равна modp2048 из RFC 3526
		double ffdheRef = 0.;
		// Объект порождения ключей группы ffdhe2048 эталона
		EVP_PKEY_CTX * dhFrame = ::EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
		// Если группу ffdhe2048 у эталона завести удалось
		if((dhFrame != nullptr) && (::EVP_PKEY_keygen_init(dhFrame) > 0) && (::EVP_PKEY_CTX_set_group_name(dhFrame, "ffdhe2048") > 0)){
			// Ключевые пары сторон обмена эталона
			EVP_PKEY * dhA = nullptr, * dhB = nullptr;
			// Выполняем порождение ключевой пары первой стороны
			::EVP_PKEY_generate(dhFrame, &dhA);
			// Выполняем порождение ключевой пары второй стороны
			::EVP_PKEY_generate(dhFrame, &dhB);
			// Место, в которое помещается общее значение обмена эталона
			vector <uint8_t> dhShared(256, 0);
			// Если обе ключевые пары выработались
			if((dhA != nullptr) && (dhB != nullptr)){
				// Выполняем замер числа обменов ключами FFDHE-2048 эталона за секунду
				ffdheRef = count("Обмен ключами FFDHE-2048", 100, [&dhA, &dhB, &dhShared]() noexcept -> void {
					// Длина общего значения обмена эталона
					size_t size = dhShared.size();
					// Объект обмена ключами эталона
					EVP_PKEY_CTX * exchange = ::EVP_PKEY_CTX_new(dhA, nullptr);
					// Выполняем заведение обмена ключами эталона
					::EVP_PKEY_derive_init(exchange);
					// Устанавливаем открытый ключ встречной стороны обмена
					::EVP_PKEY_derive_set_peer(exchange, dhB);
					// Выполняем выработку общего значения обмена
					::EVP_PKEY_derive(exchange, dhShared.data(), &size);
					// Выполняем освобождение объекта обмена ключами эталона
					::EVP_PKEY_CTX_free(exchange);
				});
			}
			// Освобождаем ключевые пары сторон обмена эталона
			::EVP_PKEY_free(dhA);
			// Освобождаем ключевые пары сторон обмена эталона
			::EVP_PKEY_free(dhB);
		} else {
			// Выводим примету отсутствия группы ffdhe2048 у эталона
			cout << "У эталона группы ffdhe2048 нет, сличение пропускается" << endl;
		}
		// Выполняем освобождение объекта порождения ключей группы эталона
		::EVP_PKEY_CTX_free(dhFrame);
		// Замеры ГОСТ у эталона: провайдер gostprov есть не везде, лишь на стендах с ним (Astra)
		double streebogRef = 0., streebogLongRef = 0., kuznyechikCtrRef = 0., kuznyechikMgmRef = 0., magmaCtrRef = 0., magmaMgmRef = 0., gostSignRef = 0., gostVerifyRef = 0.;
		// Провайдер ГОСТ эталона
		OSSL_PROVIDER * gostprov = ::OSSL_PROVIDER_load(nullptr, "gostprov");
		// Если провайдер ГОСТ у эталона нашёлся
		if(gostprov != nullptr){
			// Хеш Стрибог-256 эталона из провайдера ГОСТ
			EVP_MD * streebogMethod = ::EVP_MD_fetch(nullptr, "md_gost12_256", nullptr);
			// Если хеш Стрибог-256 у эталона нашёлся
			if(streebogMethod != nullptr){
				// Выполняем замер полосы хеширования Стрибог-256 эталона
				streebogRef = band("Стрибог-256", 16, VOLUME, [&data, &hash, &streebogMethod]() noexcept -> void {
					// Длина выработанного хеша области байтов
					unsigned int length = 0;
					// Выполняем хеширование области байтов
					::EVP_Digest(data.data(), data.size(), hash, &length, streebogMethod, nullptr);
				});
				// Освобождаем хеш Стрибог-256 эталона
				::EVP_MD_free(streebogMethod);
			}
			// Хеш Стрибог-512 эталона из провайдера ГОСТ
			EVP_MD * streebogLongMethod = ::EVP_MD_fetch(nullptr, "md_gost12_512", nullptr);
			// Если хеш Стрибог-512 у эталона нашёлся
			if(streebogLongMethod != nullptr){
				// Выполняем замер полосы хеширования Стрибог-512 эталона
				streebogLongRef = band("Стрибог-512", 16, VOLUME, [&data, &hash, &streebogLongMethod]() noexcept -> void {
					// Длина выработанного хеша области байтов
					unsigned int length = 0;
					// Выполняем хеширование области байтов
					::EVP_Digest(data.data(), data.size(), hash, &length, streebogLongMethod, nullptr);
				});
				// Освобождаем хеш Стрибог-512 эталона
				::EVP_MD_free(streebogLongMethod);
			}
			// Объект шифрования эталона
			EVP_CIPHER_CTX * gostContext = ::EVP_CIPHER_CTX_new();
			// Шифр Кузнечик-CTR эталона из провайдера ГОСТ
			EVP_CIPHER * kuznyechikCtrMethod = ::EVP_CIPHER_fetch(nullptr, "kuznyechik-ctr", nullptr);
			// Если шифр Кузнечик-CTR у эталона нашёлся
			if(kuznyechikCtrMethod != nullptr){
				// Выполняем замер полосы поточного шифрования Кузнечик-CTR эталона
				kuznyechikCtrRef = band("Кузнечик-CTR", 8, VOLUME, [&gostContext, &kuznyechikCtrMethod, &key, &seed, &data, &result]() noexcept -> void {
					// Длина зашифрованной области байтов
					int length = 0;
					// Выполняем заведение поточного шифрования: вектор замены в шестнадцать байтов
					::EVP_EncryptInit_ex(gostContext, kuznyechikCtrMethod, nullptr, key, seed);
					// Выполняем поточное шифрование области байтов
					::EVP_EncryptUpdate(gostContext, result.data(), &length, data.data(), static_cast <int> (data.size()));
				});
				// Освобождаем шифр Кузнечик-CTR эталона
				::EVP_CIPHER_free(kuznyechikCtrMethod);
			}
			// Шифр Кузнечик-MGM эталона из провайдера ГОСТ
			EVP_CIPHER * kuznyechikMgmMethod = ::EVP_CIPHER_fetch(nullptr, "kuznyechik-mgm", nullptr);
			// Если шифр Кузнечик-MGM у эталона нашёлся
			if(kuznyechikMgmMethod != nullptr){
				// Выполняем замер полосы шифрования с проверкой целостности Кузнечик-MGM эталона
				kuznyechikMgmRef = band("Кузнечик-MGM", 8, VOLUME, [&gostContext, &kuznyechikMgmMethod, &key, &seed, &data, &result, &tag]() noexcept -> void {
					// Длина зашифрованной области байтов
					int length = 0;
					// Выполняем заведение шифрования области байтов
					::EVP_EncryptInit_ex(gostContext, kuznyechikMgmMethod, nullptr, key, seed);
					// Выполняем шифрование области байтов
					::EVP_EncryptUpdate(gostContext, result.data(), &length, data.data(), static_cast <int> (data.size()));
					// Выполняем завершение шифрования области байтов
					::EVP_EncryptFinal_ex(gostContext, result.data() + length, &length);
					// Выполняем извлечение имитовставки шифрования
					::EVP_CIPHER_CTX_ctrl(gostContext, EVP_CTRL_AEAD_GET_TAG, 16, tag);
				});
				// Освобождаем шифр Кузнечик-MGM эталона
				::EVP_CIPHER_free(kuznyechikMgmMethod);
			}
			// Шифр Магма-CTR эталона из провайдера ГОСТ
			EVP_CIPHER * magmaCtrMethod = ::EVP_CIPHER_fetch(nullptr, "magma-ctr", nullptr);
			// Если шифр Магма-CTR у эталона нашёлся
			if(magmaCtrMethod != nullptr){
				// Выполняем замер полосы поточного шифрования Магма-CTR эталона
				magmaCtrRef = band("Магма-CTR", 8, VOLUME, [&gostContext, &magmaCtrMethod, &key, &nonce, &data, &result]() noexcept -> void {
					// Длина зашифрованной области байтов
					int length = 0;
					// Выполняем заведение поточного шифрования: вектор замены в восемь байтов
					::EVP_EncryptInit_ex(gostContext, magmaCtrMethod, nullptr, key, nonce);
					// Выполняем поточное шифрование области байтов
					::EVP_EncryptUpdate(gostContext, result.data(), &length, data.data(), static_cast <int> (data.size()));
				});
				// Освобождаем шифр Магма-CTR эталона
				::EVP_CIPHER_free(magmaCtrMethod);
			}
			// Шифр Магма-MGM эталона из провайдера ГОСТ
			EVP_CIPHER * magmaMgmMethod = ::EVP_CIPHER_fetch(nullptr, "magma-mgm", nullptr);
			// Если шифр Магма-MGM у эталона нашёлся
			if(magmaMgmMethod != nullptr){
				// Выполняем замер полосы шифрования с проверкой целостности Магма-MGM эталона
				magmaMgmRef = band("Магма-MGM", 8, VOLUME, [&gostContext, &magmaMgmMethod, &key, &nonce, &data, &result, &tag]() noexcept -> void {
					// Длина зашифрованной области байтов
					int length = 0;
					// Выполняем заведение шифрования области байтов
					::EVP_EncryptInit_ex(gostContext, magmaMgmMethod, nullptr, key, nonce);
					// Выполняем шифрование области байтов
					::EVP_EncryptUpdate(gostContext, result.data(), &length, data.data(), static_cast <int> (data.size()));
					// Выполняем завершение шифрования области байтов
					::EVP_EncryptFinal_ex(gostContext, result.data() + length, &length);
					// Выполняем извлечение имитовставки шифрования: у Магмы она вдвое короче
					::EVP_CIPHER_CTX_ctrl(gostContext, EVP_CTRL_AEAD_GET_TAG, 8, tag);
				});
				// Освобождаем шифр Магма-MGM эталона
				::EVP_CIPHER_free(magmaMgmMethod);
			}
			// Выполняем освобождение объекта шифрования эталона
			::EVP_CIPHER_CTX_free(gostContext);
			/**
			 * Подпись ГОСТ 34.10-2012 у эталона: та же кривая CryptoPro-A, что и у нашей
			 * строки подписи, ключ порождается по образцу щупа gostbench.c
			 */
			EVP_PKEY_CTX * gostKeygen = ::EVP_PKEY_CTX_new_from_name(nullptr, "gost2012_256", nullptr);
			// Если объект порождения ключа ГОСТ у эталона завёлся
			if((gostKeygen != nullptr) && (::EVP_PKEY_keygen_init(gostKeygen) > 0) && (::EVP_PKEY_CTX_ctrl_str(gostKeygen, "paramset", "A") > 0)){
				// Ключевая пара ГОСТ эталона
				EVP_PKEY * gostPair = nullptr;
				// Выполняем порождение ключевой пары ГОСТ эталона
				if(::EVP_PKEY_keygen(gostKeygen, &gostPair) > 0){
					// Объект работы с подписью ГОСТ эталона
					EVP_PKEY_CTX * gostSigning = ::EVP_PKEY_CTX_new_from_pkey(nullptr, gostPair, nullptr);
					// Объект работы со сличением ГОСТ эталона
					EVP_PKEY_CTX * gostChecking = ::EVP_PKEY_CTX_new_from_pkey(nullptr, gostPair, nullptr);
					// Подпись ГОСТ эталона и её длина
					uint8_t gostSealing[128];
					// Запоминаем длину подписи ГОСТ
					size_t gostLength = sizeof(gostSealing);
					// Выполняем заведение выработки подписи ГОСТ эталона
					::EVP_PKEY_sign_init(gostSigning);
					// Выполняем выработку подписи ГОСТ эталона для сличения
					::EVP_PKEY_sign(gostSigning, gostSealing, &gostLength, hash, 32);
					// Выполняем замер числа подписей ГОСТ эталона за секунду
					gostSignRef = count("ГОСТ 34.10 подпись", 200, [&gostSigning, &hash, &gostSealing, &gostLength]() noexcept -> void {
						// Длина подписи
						gostLength = sizeof(gostSealing);
						// Выполняем подпись хеша ГОСТ эталона
						::EVP_PKEY_sign(gostSigning, gostSealing, &gostLength, hash, 32);
					});
					// Выполняем заведение сличения подписи ГОСТ эталона
					::EVP_PKEY_verify_init(gostChecking);
					// Выполняем замер числа сличений подписи ГОСТ эталона за секунду
					gostVerifyRef = count("ГОСТ 34.10 сличение", 200, [&gostChecking, &hash, &gostSealing, &gostLength]() noexcept -> void {
						// Выполняем сличение подписи ГОСТ эталона
						::EVP_PKEY_verify(gostChecking, gostSealing, gostLength, hash, 32);
					});
					// Выполняем освобождение объектов подписи ГОСТ эталона
					::EVP_PKEY_CTX_free(gostSigning);
					// Выполняем освобождение объектов подписи ГОСТ эталона
					::EVP_PKEY_CTX_free(gostChecking);
					// Освобождаем ключевую пару ГОСТ эталона
					::EVP_PKEY_free(gostPair);
				}
				// Выполняем освобождение объекта порождения ключа ГОСТ эталона
				::EVP_PKEY_CTX_free(gostKeygen);
			} else {
				// Выводим примету отсутствия подписи ГОСТ у эталона
				cout << "У эталона подписи ГОСТ нет, сличение пропускается" << endl;
				// Выполняем освобождение объекта порождения ключа ГОСТ эталона
				::EVP_PKEY_CTX_free(gostKeygen);
			}
			// Выполняем выгрузку провайдера ГОСТ эталона
			::OSSL_PROVIDER_unload(gostprov);
		} else {
			// Выводим примету отсутствия провайдера ГОСТ у эталона
			cout << "Провайдера ГОСТ у эталона нет, сличение ГОСТ пропускается" << endl;
		}
		/**
		 * Рукопожатие TLS 1.3 эталона в памяти парой BIO обеими сторонами в одном потоке:
		 * X25519, AES-128-GCM, без проверки доверия цепочке, как и у нас
		 */
		const auto shakeRef = [](SSL_CTX * sctx, SSL_CTX * cctx) noexcept -> bool {
			// Стороны связи эталона
			SSL * s = ::SSL_new(sctx), * c = ::SSL_new(cctx);
			// Пара BIO, связывающая стороны в памяти
			BIO * sb = nullptr, * cb = nullptr;
			// Если стороны либо пару завести не удалось
			if((s == nullptr) || (c == nullptr) || !::BIO_new_bio_pair(&sb, 0, &cb, 0)){
				// Освобождаем стороны
				::SSL_free(s);
				::SSL_free(c);
				// Выводим отрицательный результат - стороны либо пару завести не удалось
				return false;
			}
			// Привязываем пару к сторонам
			::SSL_set_bio(s, sb, sb);
			::SSL_set_bio(c, cb, cb);
			// Переводим сторону сервера в состояние приёма
			::SSL_set_accept_state(s);
			// Переводим сторону клиента в состояние подключения
			::SSL_set_connect_state(c);
			// Признак завершения рукопожатия обеими сторонами
			bool done = false;
			/**
			 * Выполняем ходы рукопожатия, пока обе стороны его не завершат
			 */
			for(size_t i = 0; (i < 32) && !done; i++){
				// Выполняем ход рукопожатия клиентом
				::SSL_do_handshake(c);
				::SSL_do_handshake(s);
				// Запоминаем завершение рукопожатия обеими сторонами
				done = (::SSL_is_init_finished(c) && ::SSL_is_init_finished(s));
			}
			// Освобождаем стороны вместе с парой
			::SSL_free(s);
			::SSL_free(c);
			// Выводим итог рукопожатия
			return done;
		};
		// Заведение контекстов эталона по подлинности из набора ключей
		const auto contexts = [](const char * certificate, const char * key, SSL_CTX *& sctx, SSL_CTX *& cctx) noexcept -> bool {
			// Заводим контексты сторон
			sctx = ::SSL_CTX_new(::TLS_server_method());
			// Заводим контекст клиента
			cctx = ::SSL_CTX_new(::TLS_client_method());
			// Если контексты завести не удалось
			if((sctx == nullptr) || (cctx == nullptr))
				// Выводим отрицательный результат - контексты завести не удалось
				return false;
			// Путь к набору ключей
			const string root = (string(ANTS_CORPUS) + "/");
			// Если подлинность сервера установить не удалось
			if((::SSL_CTX_use_certificate_chain_file(sctx, (root + certificate).c_str()) != 1) || (::SSL_CTX_use_PrivateKey_file(sctx, (root + key).c_str(), SSL_FILETYPE_PEM) != 1))
				// Выводим отрицательный результат - подлинность сервера не установлена
				return false;
			// Издание TLS 1.3, группа X25519, набор AES-128-GCM, без билетов и доверия цепочке
			::SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
			::SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
			// Назначаем серверу группу обмена X25519
			::SSL_CTX_set1_groups_list(sctx, "X25519");
			::SSL_CTX_set1_groups_list(cctx, "X25519");
			// Назначаем серверу набор AES-128-GCM
			::SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256");
			::SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256");
			// Отключаем проверку доверия цепочке у клиента
			::SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, nullptr);
			// Отключаем билеты состояния серверу
			::SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
			::SSL_CTX_set_options(cctx, SSL_OP_NO_TICKET);
			// Отключаем кэш сеансов серверу
			::SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_OFF);
			::SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_OFF);
			// Сообщаем об успешной настройке контекстов
			return true;
		};
		// Контексты эталона по подлинностям ECDSA и RSA
		SSL_CTX * ecdsaServer = nullptr, * ecdsaClient = nullptr, * rsaServer = nullptr, * rsaClient = nullptr;
		// Числа рукопожатий и полоса записей эталона
		double shakeDefaultsRef = 0., shakeCross = 0., shakeEcdsaRef = 0., shakeRsaRef = 0., records16Ref = 0., records1200Ref = 0.;
		// Если контексты эталона заведены
		if(contexts("ec256.crt", "ec256.pem", ecdsaServer, ecdsaClient) && contexts("rsa2048.crt", "rsa2048.pem", rsaServer, rsaClient)){
			// Выполняем замеры рукопожатий эталона
			shakeEcdsaRef = count("TLS 1.3 X25519 ECDSA GCM", 200, [&shakeRef, &ecdsaServer, &ecdsaClient]() noexcept -> void {
				// Проводим рукопожатие эталона подлинностью ECDSA
				shakeRef(ecdsaServer, ecdsaClient);
			});
			// Выполняем замер рукопожатия эталона подлинностью RSA
			shakeRsaRef = count("TLS 1.3 X25519 RSA GCM", 100, [&shakeRef, &rsaServer, &rsaClient]() noexcept -> void {
				// Проводим рукопожатие эталона подлинностью RSA
				shakeRef(rsaServer, rsaClient);
			});
			// Установленная связь эталона для замера записей
			SSL * s = ::SSL_new(ecdsaServer), * c = ::SSL_new(ecdsaClient);
			// Пара BIO с запасом под записи
			BIO * sb = nullptr, * cb = nullptr;
			// Если стороны и пара заведены
			if((s != nullptr) && (c != nullptr) && ::BIO_new_bio_pair(&sb, (1 << 20), &cb, (1 << 20))){
				// Привязываем пару к сторонам
				::SSL_set_bio(s, sb, sb);
				::SSL_set_bio(c, cb, cb);
				// Переводим сторону сервера в состояние приёма
				::SSL_set_accept_state(s);
				// Переводим сторону клиента в состояние подключения
				::SSL_set_connect_state(c);
				/**
				 * Выполняем ходы рукопожатия, пока обе стороны его не завершат
				 */
				for(size_t i = 0; (i < 32) && !(::SSL_is_init_finished(c) && ::SSL_is_init_finished(s)); i++){
					// Выполняем ход рукопожатия клиентом
					::SSL_do_handshake(c);
					::SSL_do_handshake(s);
				}
				// Если связь эталона установлена
				if(::SSL_is_init_finished(c) && ::SSL_is_init_finished(s)){
					// Прикладные данные и накопитель приёма
					const vector <uint8_t> large(record::RECORD_PLAINTEXT, 0x5A), small(1200, 0x5A);
					// Отводим буфер под запись
					vector <uint8_t> buffer(record::RECORD_PLAINTEXT, 0);
					// Передача записей клиентом серверу
					const auto moving = [&s, &c, &buffer](const vector <uint8_t> & payload, const size_t times) noexcept -> void {
						/**
						 * Выполняем передачу записей
						 */
						for(size_t i = 0; i < times; i++){
							// Пишем запись клиентом
							const int written = ::SSL_write(c, payload.data(), static_cast <int> (payload.size()));
							// Если запись не ушла
							if(written <= 0)
								// Прерываем передачу
								break;
							// Число принятых байтов
							size_t taken = 0;
							/**
							 * Читаем запись сервером до полного приёма
							 */
							while(taken < static_cast <size_t> (written)){
								// Читаем принятые байты
								const int got = ::SSL_read(s, buffer.data(), static_cast <int> (buffer.size()));
								// Если байты не приняты
								if(got <= 0)
									// Прерываем приём
									break;
								// Учитываем принятые байты
								taken += static_cast <size_t> (got);
							}
						}
					};
					// Выполняем замеры полосы записей эталона
					records16Ref = band("TLS 1.3 записи 16 КиБ", 8, large.size() * 64, [&moving, &large]() noexcept -> void {
						// Передаём записи наибольшей длины
						moving(large, 64);
					});
					// Выполняем замер полосы записей эталона в 1200 байт
					records1200Ref = band("TLS 1.3 записи 1200 байт", 8, small.size() * 256, [&moving, &small]() noexcept -> void {
						// Передаём записи в 1200 байт
						moving(small, 256);
					});
				}
			}
			// Освобождаем стороны вместе с парой
			::SSL_free(s);
			::SSL_free(c);
		// Если контексты эталона завести не удалось
		} else cout << "Завести связи эталона не удалось" << endl;
		// Освобождаем контексты эталона
		::SSL_CTX_free(ecdsaServer);
		// Освобождаем контекст клиента ECDSA
		::SSL_CTX_free(ecdsaClient);
		::SSL_CTX_free(rsaServer);
		::SSL_CTX_free(rsaClient);
		/**
		 * Умолчания против умолчаний: эталон сам с собой без назначения групп и наборов, и
		 * наш клиент с умолчаниями к серверу эталона с умолчаниями - совместимость
		 * умолчаний с чужим сервером, где просьбы о повторе быть не должно
		 */
		{
			// Контексты эталона с умолчаниями
			SSL_CTX * sctx = ::SSL_CTX_new(::TLS_server_method()), * cctx = ::SSL_CTX_new(::TLS_client_method());
			// Путь к набору ключей
			const string root = (string(ANTS_CORPUS) + "/");
			// Если контексты заведены и подлинность ECDSA установлена
			if((sctx != nullptr) && (cctx != nullptr) && (::SSL_CTX_use_certificate_chain_file(sctx, (root + "ec256.crt").c_str()) == 1) && (::SSL_CTX_use_PrivateKey_file(sctx, (root + "ec256.pem").c_str(), SSL_FILETYPE_PEM) == 1)){
				// Издание TLS 1.3, без билетов и доверия цепочке; группы и наборы - умолчания эталона
				::SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
				::SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
				// Отключаем проверку доверия цепочке у клиента
				::SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, nullptr);
				// Отключаем билеты состояния серверу
				::SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
				::SSL_CTX_set_options(cctx, SSL_OP_NO_TICKET);
				// Отключаем кэш сеансов серверу
				::SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_OFF);
				::SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_OFF);
				// Выполняем замер рукопожатия эталона умолчаниями
				shakeDefaultsRef = count("TLS 1.3 умолчания ECDSA", 200, [&shakeRef, &sctx, &cctx]() noexcept -> void {
					// Проводим рукопожатие эталона умолчаниями
					shakeRef(sctx, cctx);
				});
				// Число просьб о повторе от сервера эталона и число рукопожатий, не дошедших до конца
				size_t retries = 0, failures = 0;
				// Рукопожатие нашего клиента с умолчаниями к серверу эталона парой BIO
				const auto crossing = [&sctx, &retries, &failures]() noexcept -> void {
					// Связь стороны клиента с умолчаниями
					client::context_t client;
					// Сторона сервера эталона
					SSL * s = ::SSL_new(sctx);
					// Пара BIO, связывающая стороны в памяти
					BIO * sb = nullptr, * cb = nullptr;
					// Если сторону либо пару завести не удалось
					if((s == nullptr) || !::BIO_new_bio_pair(&sb, (1 << 16), &cb, (1 << 16))){
						// Освобождаем сторону и считаем отказ
						::SSL_free(s);
						// Считаем отказ
						failures++;
						// Выходим
						return;
					}
					// Число приветствий сервера: два означают просьбу о повторе
					size_t hellos = 0;
					// Привязываем пару к стороне сервера и считаем её приветствия
					::SSL_set_bio(s, sb, sb);
					// Переводим сторону сервера в состояние приёма
					::SSL_set_accept_state(s);
					// Назначаем обратный вызов сообщений рукопожатия серверу
					::SSL_set_msg_callback(s, +[](int writeP, int, int contentType, const void * buf, size_t len, SSL *, void * arg) noexcept -> void {
						// Если сервер отправил сообщение рукопожатия вида ServerHello
						if((writeP != 0) && (contentType == SSL3_RT_HANDSHAKE) && (len > 0) && (static_cast <const uint8_t *> (buf)[0] == 2))
							// Считаем приветствие сервера
							(* static_cast <size_t *> (arg))++;
					});
					// Передаём обратному вызову счётчик приветствий сервера
					::SSL_set_msg_callback_arg(s, &hellos);
					// Накопитель байтов от сервера
					static uint8_t buffer[1 << 16];
					// Выполняем заведение связи стороны клиента
					client.start();
					/**
					 * Выполняем ходы рукопожатия, пока обе стороны его не завершат
					 */
					for(size_t i = 0; (i < 32) && !(client.established() && ::SSL_is_init_finished(s)); i++){
						// Байты, отправляемые клиентом серверу
						const view_t out = client.output();
						// Если клиенту есть что отправить
						if(out.size > 0){
							// Передаём байты серверу и снимаем их с накопителя клиента
							::BIO_write(cb, out.data, static_cast <int> (out.size));
							// Снимаем отправленные байты с накопителя клиента
							client.consume(out.size);
						}
						// Даём ход серверу
						if(!::SSL_is_init_finished(s))
							// Выполняем ход рукопожатия сервером
							::SSL_do_handshake(s);
						// Число байтов, прочитанных от сервера
						int n = 0;
						// Передаём байты сервера клиенту
						/**
						 * Передаём байты сервера клиенту, пока они есть
						 */
						while((n = ::BIO_read(cb, buffer, sizeof(buffer))) > 0)
							// Передаём прочитанные байты клиенту
							client.push(view_t(buffer, static_cast <size_t> (n)));
						// Если связь клиента оборвана
						if(client.error() != context::error_t::NONE)
							// Выходим из цикла
							break;
					}
					// Если рукопожатие не завершено
					if(!(client.established() && ::SSL_is_init_finished(s)))
						// Считаем отказ
						failures++;
					// Если сервер приветствовал дважды
					if(hellos > 1)
						// Считаем просьбу о повторе
						retries++;
					// Освобождаем сторону сервера вместе с её концом пары и свой конец пары
					::SSL_free(s);
					// Освобождаем свой конец пары
					::BIO_free(cb);
				};
				// Выполняем замер рукопожатия нашего клиента с умолчаниями к серверу эталона
				shakeCross = count("TLS 1.3 умолчания к серверу эталона", 200, crossing);
				// Выводим итог совместимости умолчаний
				cout << "Рукопожатий с сервером эталона не завершено: " << failures << ", просьб о повторе: " << retries << endl;
			// Если контексты завести не удалось
			} else cout << "Завести связи эталона умолчаниями не удалось" << endl;
			// Освобождаем контексты эталона
			::SSL_CTX_free(sctx);
			// Освобождаем контекст клиента
			::SSL_CTX_free(cctx);
		}
		// Выполняем освобождение ключевой пары X25519 эталона
		::EVP_PKEY_free(mont);
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
		// Выводим отношение замеров шифрования AES-256-CBC к эталону
		relation("AES-256-CBC против эталона", cbc, cbcRef);
		// Выводим отношение замеров AES-256-GCM к эталону
		relation("AES-256-GCM против эталона", aead, gcm);
		// Выводим отношение замеров ChaCha20 к эталону
		relation("ChaCha20 против эталона", chachaStream, chachaRef);
		// Выводим отношение замеров ChaCha20-Poly1305 к эталону
		relation("ChaCha20-Poly1305 против эталона", chachaAead, chachapolyRef);
		// Выводим отношение замеров выдачи случайных байтов
		relation("Случайные байты против эталона", randomness, randomnessRef);
		// Выводим отношение замеров выработки подписи
		relation("Подпись", signing, ecdsa);
		// Выводим отношение замеров сличения подписи
		relation("Сличение подписи", checking, verify);
		// Выводим отношение замеров обмена ключами по ГОСТ-кривой к обмену эталона по P-256
		relation("Обмен ключами ГОСТ против P-256 эталона", exchange, ecdh);
		// Выводим отношение замеров обмена ключами по кривой P-256 к эталону
		relation("ECDH P-256 против эталона", nistExchange, ecdh);
		// Выводим отношение замеров обмена ключами X25519 к эталону
		relation("X25519 против эталона", montExchange, montRef);
		// Выводим отношение подписи RSA-2048 к эталону
		relation("RSA-2048 подпись против эталона", rsaSigning, rsaSign);
		// Выводим отношение сличения подписи RSA-2048 к эталону
		relation("RSA-2048 сличение против эталона", rsaChecking, rsaVerify);
		// Выводим отношение порождения ключа ML-DSA-65 к эталону
		relation("ML-DSA-65 порождение против эталона", mldsaGenerate, mldsaGenerateRef);
		// Выводим отношение подписи ML-DSA-65 к эталону
		relation("ML-DSA-65 подпись против эталона", mldsaSigning, mldsaSignRef);
		// Выводим отношение сличения подписи ML-DSA-65 к эталону
		relation("ML-DSA-65 сличение против эталона", mldsaChecking, mldsaVerifyRef);
		// Выводим отношение замеров хеширования SHA3-256 к эталону
		relation("SHA3-256 против эталона", sha3, sha3Ref);
		// Выводим отношение замеров хеширования SHA3-512 к эталону
		relation("SHA3-512 против эталона", sha3long, sha3longRef);
		// Выводим отношение замеров хеширования SM3 к эталону
		relation("SM3 против эталона", sm3, sm3Ref);
		// Выводим отношение замеров хеширования RIPEMD-160 к эталону
		relation("RIPEMD-160 против эталона", ripemd, ripemdRef);
		// Выводим отношение замеров шифрования AES-256-CCM к эталону
		relation("AES-256-CCM против эталона", ccmAead, ccmRef);
		// Выводим отношение замеров шифрования DES-EDE3-CBC к эталону
		relation("DES-EDE3-CBC против эталона", desCbc, desRef);
		// Выводим отношение подписи Ed25519 к эталону
		relation("Ed25519 подпись против эталона", ed25519Signing, ed25519SignRef);
		// Выводим отношение сличения подписи Ed25519 к эталону
		relation("Ed25519 сличение против эталона", ed25519Checking, ed25519VerifyRef);
		// Выводим отношение подписи Ed448 к эталону
		relation("Ed448 подпись против эталона", ed448Signing, ed448SignRef);
		// Выводим отношение сличения подписи Ed448 к эталону
		relation("Ed448 сличение против эталона", ed448Checking, ed448VerifyRef);
		// Выводим отношение подписи SM2 к эталону
		relation("SM2 подпись против эталона", sm2Signing, sm2SignRef);
		// Выводим отношение сличения подписи SM2 к эталону
		relation("SM2 сличение против эталона", sm2Checking, sm2VerifyRef);
		// Выводим отношение подписи SLH-DSA к эталону
		relation("SLH-DSA-128s подпись против эталона", slhSigning, slhSignRef);
		// Выводим отношение сличения подписи SLH-DSA к эталону
		relation("SLH-DSA-128s сличение против эталона", slhChecking, slhVerifyRef);
		// Выводим отношение замеров обмена ключами X448 к эталону
		relation("X448 против эталона", x448Exchange, x448Ref);
		// Выводим отношение упаковки ML-KEM-768 к эталону
		relation("ML-KEM-768 упаковка против эталона", mlkemSealing, mlkemSealRef);
		// Выводим отношение распаковки ML-KEM-768 к эталону
		relation("ML-KEM-768 распаковка против эталона", mlkemOpening, mlkemOpenRef);
		// Выводим отношение замеров обмена ключами FFDHE-2048 к эталону
		relation("FFDHE-2048 против эталона", ffdheExchange, ffdheRef);
		// Выводим отношение замеров хеширования Стрибог-256 к ГОСТ-эталону
		relation("Стрибог-256 против ГОСТ-эталона", streebog, streebogRef);
		// Выводим отношение замеров хеширования Стрибог-512 к ГОСТ-эталону
		relation("Стрибог-512 против ГОСТ-эталона", streebogLong, streebogLongRef);
		// Выводим отношение замеров поточного шифрования Кузнечик-CTR к ГОСТ-эталону
		relation("Кузнечик-CTR против ГОСТ-эталона", stream, kuznyechikCtrRef);
		// Выводим отношение замеров шифрования Кузнечик-MGM к ГОСТ-эталону
		relation("Кузнечик-MGM против ГОСТ-эталона", sealed, kuznyechikMgmRef);
		// Выводим отношение замеров поточного шифрования Магма-CTR к ГОСТ-эталону
		relation("Магма-CTR против ГОСТ-эталона", magmaStream, magmaCtrRef);
		// Выводим отношение замеров шифрования Магма-MGM к ГОСТ-эталону
		relation("Магма-MGM против ГОСТ-эталона", magmaSealed, magmaMgmRef);
		// Выводим отношение подписи ГОСТ 34.10 к ГОСТ-эталону
		relation("ГОСТ 34.10 подпись против ГОСТ-эталона", signing, gostSignRef);
		// Выводим отношение сличения подписи ГОСТ 34.10 к ГОСТ-эталону
		relation("ГОСТ 34.10 сличение против ГОСТ-эталона", checking, gostVerifyRef);
		relation("TLS 1.3 умолчания против эталона", shakeDefaults, shakeDefaultsRef);
		relation("TLS 1.3 умолчания к серверу эталона против эталона", shakeCross, shakeDefaultsRef);
		relation("TLS 1.3 рукопожатие ECDSA против эталона", shakeEcdsa, shakeEcdsaRef);
		relation("TLS 1.3 рукопожатие RSA против эталона", shakeRsa, shakeRsaRef);
		relation("TLS 1.3 записи 16 КиБ против эталона", records16, records16Ref);
		relation("TLS 1.3 записи 1200 байт против эталона", records1200, records1200Ref);
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
	/**
	 * Сличение с эталоном отключено сборкой: замеры своей работы остаются без отношений к эталону
	 */
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
		// Не используем замеры ML-DSA-65 при отключённом сличении
		(void) mldsaGenerate;
		// Не используем замер подписи ML-DSA-65 при отключённом сличении
		(void) mldsaSigning;
		// Не используем замер сличения ML-DSA-65 при отключённом сличении
		(void) mldsaChecking;
		// Замеры хеширования SHA-3 без эталона сравнивать не с чем
		(void) sha3;
		// Замеры хеширования SHA-3 без эталона сравнивать не с чем
		(void) sha3long;
		// Замеры хеширования SM3 без эталона сравнивать не с чем
		(void) sm3;
		// Замеры хеширования RIPEMD-160 без эталона сравнивать не с чем
		(void) ripemd;
		// Замеры шифрования AES-256-CCM без эталона сравнивать не с чем
		(void) ccmAead;
		// Замеры шифрования DES-EDE3-CBC без эталона сравнивать не с чем
		(void) desCbc;
		// Замеры подписи Ed25519 без эталона сравнивать не с чем
		(void) ed25519Signing;
		// Замеры сличения Ed25519 без эталона сравнивать не с чем
		(void) ed25519Checking;
		// Замеры подписи Ed448 без эталона сравнивать не с чем
		(void) ed448Signing;
		// Замеры сличения Ed448 без эталона сравнивать не с чем
		(void) ed448Checking;
		// Замеры подписи SM2 без эталона сравнивать не с чем
		(void) sm2Signing;
		// Замеры сличения SM2 без эталона сравнивать не с чем
		(void) sm2Checking;
		// Замеры подписи SLH-DSA без эталона сравнивать не с чем
		(void) slhSigning;
		// Замеры сличения SLH-DSA без эталона сравнивать не с чем
		(void) slhChecking;
		// Замеры обмена ключами X448 без эталона сравнивать не с чем
		(void) x448Exchange;
		// Замеры упаковки ML-KEM-768 без эталона сравнивать не с чем
		(void) mlkemSealing;
		// Замеры распаковки ML-KEM-768 без эталона сравнивать не с чем
		(void) mlkemOpening;
		// Замеры обмена ключами FFDHE-2048 без эталона сравнивать не с чем
		(void) ffdheExchange;
		// Замеры Стрибог-512 без эталона сравнивать не с чем
		(void) streebogLong;
		// Замеры Магма-CTR без эталона сравнивать не с чем
		(void) magmaStream;
		// Замеры Магма-MGM без эталона сравнивать не с чем
		(void) magmaSealed;
		// Не используем замер обмена ключами при отключённом сличении
		(void) exchange;
		// Не используем замер рукопожатий умолчаниями при отключённом сличении
		(void) shakeDefaults;
		// Не используем замер рукопожатия ECDSA при отключённом сличении
		(void) shakeEcdsa;
		// Не используем замер рукопожатия RSA при отключённом сличении
		(void) shakeRsa;
		// Не используем замер записей 16 КиБ при отключённом сличении
		(void) records16;
		// Не используем замер записей 1200 байт при отключённом сличении
		(void) records1200;
	#endif
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
