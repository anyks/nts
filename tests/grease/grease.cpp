/**
 * @file grease.cpp
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
 * @brief Исходный файл проверок GREASE (RFC 8701) одной ручкой, как у BoringSSL: места
 *        вставки в приветствии клиента, вид и различность значений, энтропия, стабильность
 *        через просьбу о повторе, выключенное состояние, расширения сервера в билете и
 *        запросе подлинности, обмен с настоящим openssl по TLS 1.3, TLS 1.2 и DTLS 1.2,
 *        нехватка памяти
 *
 * @note Эталоном служат RFC 8701 и поведение BoringSSL при SSL_CTX_set_grease_enabled;
 *       приветствие судится по разбору модулем hello, а не по смещениям байтов
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
#include <message/message.hpp>
#include <datagram/datagram.hpp>
#include <protect/protect.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
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
	 * @param name   имя ключа набора: rsa2048, ec256, ec384 либо ed25519
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
	 * @brief Метод проверки вида значения GREASE
	 *
	 * @param value проверяемое значение
	 *
	 * @return      признак того, что значение имеет вид 0x?A?A (раздел 2 RFC 8701)
	 *
	 */
	bool shaped(const uint16_t value) noexcept {
		// Выводим признак вида: байты равны, младшие четыре разряда каждого - 0xA
		return (((value >> 8) == (value & 0xFF)) && ((value & 0x0F0F) == 0x0A0A));
	}
	/**
	 * @brief Места значений GREASE в приветствии клиента
	 *
	 */
	typedef struct Places {
		// Набор шифрования первым в перечне наборов
		uint16_t suite;
		// Первое расширение с пустым телом
		uint16_t first;
		// Последнее расширение потребителя с телом в один нулевой байт
		uint16_t second;
		// Группа обмена первой в перечне групп
		uint16_t group;
		// Доля ключа первой в перечне долей
		uint16_t share;
		// Издание первым в перечне изданий
		uint16_t version;
		/**
		 * @brief Конструктор
		 *
		 */
		Places() noexcept : suite(0), first(0), second(0), group(0), share(0), version(0) {}
	} places_t;
	/**
	 * @brief Метод снятия приветствия клиента с накопителя отправляемых байтов
	 *
	 * @param client связь стороны клиента
	 * @param wire   место, в которое помещаются отправленные байты
	 * @param result приветствие, в которое помещается разбор (виды указывают в wire)
	 *
	 * @return       признак успешности снятия приветствия
	 *
	 */
	bool capture(client::context_t & client, vector <uint8_t> & wire, hello::client_t & result) noexcept {
		// Получаем байты, отправляемые клиентом
		const view_t sending = client.output();
		// Если клиенту нечего отправить
		if(sending.size == 0)
			// Выводим отказ снятия
			return false;
		// Переносим отправленные байты
		wire.assign(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(wire.size());
		// Заголовок записи
		record::header_t header;
		// Если байтов меньше заголовков записи и сообщения
		if(wire.size() <= (record::RECORD_HEADER + handshake::HANDSHAKE_HEADER))
			// Выводим отказ снятия
			return false;
		// Если заголовок записи не разобрался либо это не рукопожатие
		if((record::parse(view_t(wire.data(), wire.size()), header) != record::error_t::NONE) || (header.type != record::type_t::HANDSHAKE))
			// Выводим отказ снятия
			return false;
		// Заголовок сообщения рукопожатия
		handshake::header_t message;
		// Если заголовок сообщения не разобрался либо это не приветствие клиента
		if((handshake::parse(view_t(wire.data() + record::RECORD_HEADER, wire.size() - record::RECORD_HEADER), message) != handshake::error_t::NONE) || (message.type != handshake::type_t::CLIENT))
			// Выводим отказ снятия
			return false;
		// Если тело приветствия в запись не входит
		if((record::RECORD_HEADER + handshake::HANDSHAKE_HEADER + message.size) > wire.size())
			// Выводим отказ снятия
			return false;
		// Тело приветствия клиента: виды разбора указывают в wire, и он живёт у зовущего
		const view_t body(wire.data() + record::RECORD_HEADER + handshake::HANDSHAKE_HEADER, message.size);
		// Выводим итог разбора приветствия клиента
		return (hello::parse(body, result) == hello::error_t::NONE);
	}
	/**
	 * @brief Метод снятия приветствия клиента с дейтаграммы DTLS
	 *
	 * @param client связь стороны клиента поверх дейтаграмм
	 * @param wire   место, в которое помещается отправленная дейтаграмма
	 * @param result приветствие, в которое помещается разбор (виды указывают в wire)
	 *
	 * @return       признак успешности снятия приветствия
	 *
	 */
	bool datagrammed(client::context_t & client, vector <uint8_t> & wire, hello::client_t & result) noexcept {
		// Получаем дейтаграмму, отправляемую клиентом
		const view_t sending = client.output();
		// Если клиенту нечего отправить
		if(sending.size <= (datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER))
			// Выводим отказ снятия
			return false;
		// Переносим отправленную дейтаграмму
		wire.assign(sending.data, sending.data + sending.size);
		// Снимаем отправленную дейтаграмму с накопителя клиента
		client.consume(wire.size());
		// Обвязка куска приветствия
		datagram::fragment_t fragment;
		// Если обвязку куска разобрать не удалось либо это не приветствие клиента целиком
		if((datagram::parse(view_t(wire.data() + datagram::DATAGRAM_PLAIN_HEADER, wire.size() - datagram::DATAGRAM_PLAIN_HEADER), fragment) != datagram::error_t::NONE) || (fragment.type != handshake::type_t::CLIENT) || (fragment.length != fragment.size))
			// Выводим отказ снятия
			return false;
		// Если тело приветствия в дейтаграмму не входит
		if((datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length) > wire.size())
			// Выводим отказ снятия
			return false;
		// Выводим итог разбора приветствия клиента: поверх дейтаграмм с полем метки (раздел 5.3 RFC 9147)
		return (hello::parse(view_t(wire.data() + datagram::DATAGRAM_PLAIN_HEADER + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length), result, true) == hello::error_t::NONE);
	}
	/**
	 * @brief Метод снятия мест GREASE с разобранного приветствия клиента
	 *
	 * @details Приветствие судится по разбору модулем hello: расширения в проводном порядке;
	 *          каждое место сверяется с договором - первое расширение пусто, последнее
	 *          расширение потребителя несёт один нулевой байт (заранее разделённый ключ,
	 *          коли он есть, идёт за ним), доля GREASE несёт один байт, и никаких иных
	 *          значений вида 0x?A?A в перечнях нет
	 *
	 * @param greeting разобранное приветствие клиента
	 * @param reshared признак повторного приветствия после просьбы с долей: доли GREASE нет
	 * @param result   места, в которые помещаются снятые значения
	 * @param why      место, в которое помещается причина отказа
	 *
	 * @return         признак того, что все места отвечают договору
	 *
	 */
	bool places(const hello::client_t & greeting, const bool reshared, places_t & result, std::string & why) noexcept {
		// Если перечень наборов пуст либо первый набор не GREASE
		if(greeting.suites.empty() || !shaped(greeting.suites[0])){
			// Называем причину
			why = "набор GREASE не первый";
			// Выводим отказ
			return false;
		}
		// Запоминаем набор GREASE
		result.suite = greeting.suites[0];
		/**
		 * Выполняем перебор остальных наборов: иных значений GREASE быть не должно
		 */
		for(size_t i = 1; i < greeting.suites.size(); i++){
			// Если набор имеет вид GREASE
			if(shaped(greeting.suites[i])){
				// Называем причину
				why = "лишний набор GREASE";
				// Выводим отказ
				return false;
			}
		}
		// Если расширений меньше двух либо первое не GREASE либо непусто
		if((greeting.extensions.size() < 2) || !shaped(greeting.extensions.front().type) || (greeting.extensions.front().data.size != 0)){
			// Называем причину
			why = "первое расширение GREASE не первое либо непусто";
			// Выводим отказ
			return false;
		}
		// Запоминаем первое расширение GREASE
		result.first = greeting.extensions.front().type;
		// Место последнего расширения потребителя: заранее разделённый ключ идёт за ним
		const size_t last = (greeting.extensions.size() - ((greeting.extensions.back().type == static_cast <uint16_t> (extension::type_t::SECRET)) ? 2 : 1));
		// Если последнее расширение потребителя не GREASE либо тело его не один нулевой байт
		if(!shaped(greeting.extensions[last].type) || (greeting.extensions[last].data.size != 1) || (greeting.extensions[last].data.data[0] != 0x00)){
			// Называем причину
			why = "второе расширение GREASE не последнее либо тело не один нулевой байт";
			// Выводим отказ
			return false;
		}
		// Запоминаем второе расширение GREASE
		result.second = greeting.extensions[last].type;
		// Если значения расширений совпали
		if(result.first == result.second){
			// Называем причину
			why = "значения двух расширений GREASE совпали";
			// Выводим отказ
			return false;
		}
		/**
		 * Выполняем перебор расширений между первым и последним: иных GREASE быть не должно
		 */
		for(size_t i = 1; i < greeting.extensions.size(); i++){
			// Если расширение имеет вид GREASE и это не последнее расширение потребителя
			if((i != last) && shaped(greeting.extensions[i].type)){
				// Называем причину
				why = "лишнее расширение GREASE";
				// Выводим отказ
				return false;
			}
		}
		// Разыскиваем расширение групп обмена
		const hello::extension_t * item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
		// Если расширения групп нет
		if(item == nullptr){
			// Называем причину
			why = "расширения групп нет";
			// Выводим отказ
			return false;
		}
		// Группы обмена приветствия
		vector <extension::group_t> groups;
		// Если группы разобрать не удалось либо первая не GREASE
		if((extension::groups(item->data, groups) != extension::error_t::NONE) || groups.empty() || !shaped(static_cast <uint16_t> (groups[0]))){
			// Называем причину
			why = "группа GREASE не первая";
			// Выводим отказ
			return false;
		}
		// Запоминаем группу GREASE
		result.group = static_cast <uint16_t> (groups[0]);
		/**
		 * Выполняем перебор остальных групп: иных значений GREASE быть не должно
		 */
		for(size_t i = 1; i < groups.size(); i++){
			// Если группа имеет вид GREASE
			if(shaped(static_cast <uint16_t> (groups[i]))){
				// Называем причину
				why = "лишняя группа GREASE";
				// Выводим отказ
				return false;
			}
		}
		// Разыскиваем расширение долей ключа
		item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Если расширения долей нет
		if(item == nullptr){
			// Называем причину
			why = "расширения долей нет";
			// Выводим отказ
			return false;
		}
		// Доли ключа приветствия
		vector <extension::share_t> shares;
		// Если доли разобрать не удалось
		if((extension::shares(item->data, shares) != extension::error_t::NONE) || shares.empty()){
			// Называем причину
			why = "доли не разобрались";
			// Выводим отказ
			return false;
		}
		/**
		 * Раздел 4.2.8 RFC 8446: после просьбы о повторе с долей приветствие несёт долю по
		 * одной лишь запрошенной группе, и доли GREASE в нём нет; иначе доля GREASE первая
		 */
		if(!reshared){
			// Если первая доля не GREASE либо тело её не один байт
			if(!shaped(static_cast <uint16_t> (shares[0].group)) || (shares[0].key.size != 1)){
				// Называем причину
				why = "доля GREASE не первая либо тело не один байт";
				// Выводим отказ
				return false;
			}
			// Запоминаем группу доли GREASE
			result.share = static_cast <uint16_t> (shares[0].group);
			// Если группа доли GREASE не совпала с группой GREASE перечня групп
			if(result.share != result.group){
				// Называем причину
				why = "группа доли GREASE не совпала с группой перечня";
				// Выводим отказ
				return false;
			}
		}
		/**
		 * Выполняем перебор остальных долей: иных значений GREASE быть не должно
		 */
		for(size_t i = (reshared ? 0 : 1); i < shares.size(); i++){
			// Если группа доли имеет вид GREASE
			if(shaped(static_cast <uint16_t> (shares[i].group))){
				// Называем причину
				why = "лишняя доля GREASE";
				// Выводим отказ
				return false;
			}
		}
		// Разыскиваем расширение изданий протокола
		item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Если расширения изданий нет
		if(item == nullptr){
			// Называем причину
			why = "расширения изданий нет";
			// Выводим отказ
			return false;
		}
		// Издания протокола приветствия
		vector <uint16_t> versions;
		// Если издания разобрать не удалось либо первое не GREASE
		if((extension::versions(item->data, versions) != extension::error_t::NONE) || versions.empty() || !shaped(versions[0])){
			// Называем причину
			why = "издание GREASE не первое";
			// Выводим отказ
			return false;
		}
		// Запоминаем издание GREASE
		result.version = versions[0];
		/**
		 * Выполняем перебор остальных изданий: иных значений GREASE быть не должно
		 */
		for(size_t i = 1; i < versions.size(); i++){
			// Если издание имеет вид GREASE
			if(shaped(versions[i])){
				// Называем причину
				why = "лишнее издание GREASE";
				// Выводим отказ
				return false;
			}
		}
		// Выводим успешность снятия мест
		return true;
	}
	/**
	 * @brief Метод проверки отсутствия значений GREASE в приветствии клиента
	 *
	 * @param greeting разобранное приветствие клиента
	 *
	 * @return         признак того, что ни одного значения вида 0x?A?A в приветствии нет
	 *
	 */
	bool clean(const hello::client_t & greeting) noexcept {
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t i = 0; i < greeting.suites.size(); i++){
			// Если набор имеет вид GREASE
			if(shaped(greeting.suites[i]))
				// Выводим отказ
				return false;
		}
		/**
		 * Выполняем перебор расширений приветствия
		 */
		for(size_t i = 0; i < greeting.extensions.size(); i++){
			// Если расширение имеет вид GREASE
			if(shaped(greeting.extensions[i].type))
				// Выводим отказ
				return false;
		}
		// Разыскиваем расширение групп обмена
		const hello::extension_t * item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
		// Группы обмена приветствия
		vector <extension::group_t> groups;
		// Если расширения групп нет либо группы не разобрались
		if((item == nullptr) || (extension::groups(item->data, groups) != extension::error_t::NONE))
			// Выводим отказ
			return false;
		/**
		 * Выполняем перебор групп обмена
		 */
		for(size_t i = 0; i < groups.size(); i++){
			// Если группа имеет вид GREASE
			if(shaped(static_cast <uint16_t> (groups[i])))
				// Выводим отказ
				return false;
		}
		// Разыскиваем расширение долей ключа
		item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Доли ключа приветствия
		vector <extension::share_t> shares;
		// Если расширения долей нет либо доли не разобрались
		if((item == nullptr) || (extension::shares(item->data, shares) != extension::error_t::NONE))
			// Выводим отказ
			return false;
		/**
		 * Выполняем перебор долей ключа
		 */
		for(size_t i = 0; i < shares.size(); i++){
			// Если группа доли имеет вид GREASE
			if(shaped(static_cast <uint16_t> (shares[i].group)))
				// Выводим отказ
				return false;
		}
		// Разыскиваем расширение изданий протокола
		item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Издания протокола приветствия
		vector <uint16_t> versions;
		// Если расширения изданий нет либо издания не разобрались
		if((item == nullptr) || (extension::versions(item->data, versions) != extension::error_t::NONE))
			// Выводим отказ
			return false;
		/**
		 * Выполняем перебор изданий протокола
		 */
		for(size_t i = 0; i < versions.size(); i++){
			// Если издание имеет вид GREASE
			if(shaped(versions[i]))
				// Выводим отказ
				return false;
		}
		// Выводим чистоту приветствия
		return true;
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи записями
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
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
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
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что байты между сторонами не передавались
			return false;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи записями
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
		const string request = "Запрос прикладного протокола при включённом GREASE";
		// Если отправить прикладные данные клиентом не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Если получить принятые сервером прикладные данные не удалось
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отказ обмена
			return false;
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ прикладного протокола при включённом GREASE";
		// Если отправить прикладные данные сервером не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Если получить принятые клиентом прикладные данные не удалось
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Выводим отказ обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Метод настройки сторон связи записями
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера и клиента
	 * @param mutual     запрашивается ли подлинность клиента
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential, const bool mutual) noexcept {
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Если запрашивается подлинность клиента
		if(mutual){
			// Запрашиваем подлинность клиента
			server.request(true);
			// Устанавливаем подлинность клиента
			client.credential(credential);
		}
	}
	/**
	 * Уровни защиты, несущие сообщения рукопожатия, в порядке подачи
	 */
	static const context::level_t LEVELS[] = {context::level_t::INITIAL, context::level_t::HANDSHAKE, context::level_t::APPLICATION};
	/**
	 * @brief Метод переноса сообщений одного уровня от одной стороны к другой
	 *
	 * @param from  связь стороны, отдающей сообщения
	 * @param to    связь стороны, принимающей сообщения
	 * @param level уровень защиты переносимых сообщений
	 * @param taken место, в которое дописываются перенесённые сообщения, либо nullptr
	 *
	 * @return      признак того, что сообщения переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const context::level_t level, vector <uint8_t> * taken) noexcept {
		// Получаем сообщения, отправляемые на уровне
		const view_t data = from.output(level);
		// Если отправлять на уровне нечего
		if(data.size == 0)
			// Выводим признак того, что сообщения не переносились
			return false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Выполняем перенос отправляемых сообщений
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные сообщения с накопителя уровня
			from.consume(level, buffer.size());
			// Если перенесённые сообщения нужно запомнить
			if(taken != nullptr)
				// Дописываем перенесённые сообщения
				taken->insert(taken->end(), buffer.begin(), buffer.end());
			// Выполняем подачу сообщений принимающей стороне на том же уровне
			to.push(level, view_t(buffer.data(), buffer.size()));
		/**
		 * Если памяти под перенос сообщений не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что сообщения не переносились
			return false;
		}
		// Выводим признак того, что сообщения переносились
		return true;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон по уровням с записью сообщений сервера
	 *
	 * @param client    связь стороны клиента
	 * @param server    связь стороны сервера
	 * @param handshake место, в которое складываются сообщения сервера уровня рукопожатия
	 *
	 */
	void levelled(client::context_t & client, server::context_t & server, vector <uint8_t> & handshake) noexcept {
		/**
		 * Выполняем передачу сообщений между сторонами, пока им есть что сказать
		 */
		for(size_t round = 0; round < 16; round++){
			// Признак того, что сообщения переносились
			bool moved = false;
			/**
			 * Выполняем перебор уровней защиты в порядке их следования
			 */
			for(size_t i = 0; i < (sizeof(LEVELS) / sizeof(LEVELS[0])); i++)
				// Переносим сообщения уровня от клиента к серверу
				moved = (carry(client, server, LEVELS[i], nullptr) || moved);
			/**
			 * Выполняем перебор уровней защиты в порядке их следования
			 */
			for(size_t i = 0; i < (sizeof(LEVELS) / sizeof(LEVELS[0])); i++)
				// Переносим сообщения уровня от сервера к клиенту, запоминая уровень рукопожатия
				moved = (carry(server, client, LEVELS[i], ((LEVELS[i] == context::level_t::HANDSHAKE) ? &handshake : nullptr)) || moved);
			// Если сторонам нечего сказать
			if(!moved)
				// Выходим
				break;
		}
	}
	/**
	 * Параметры переноса клиента: содержимое связью не толкуется
	 */
	static const vector <uint8_t> CLIENT_PARAMETERS = {0x01, 0x04, 0x80, 0x00, 0xFF, 0xFF, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00};
	/**
	 * Параметры переноса сервера: содержимое связью не толкуется
	 */
	static const vector <uint8_t> SERVER_PARAMETERS = {0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x03, 0x02, 0x45, 0xAC};
	/**
	 * @brief Метод розыска сообщения рукопожатия заданного вида среди сообщений уровня
	 *
	 * @param data   сообщения уровня подряд
	 * @param type   искомый вид сообщения
	 * @param result место, в которое переносится тело найденного сообщения
	 *
	 * @return       признак того, что сообщение найдено
	 *
	 * @note Сборщик сообщений держит свою копию байтов, и вид в неё умирает вместе с ним -
	 *       тело переносится к зовущему
	 *
	 */
	bool locate(const vector <uint8_t> & data, const handshake::type_t type, vector <uint8_t> & result) noexcept {
		// Сборщик сообщений рукопожатия
		handshake::reader_t messages;
		// Если сообщения собрать не удалось
		if(messages.push(view_t(data.data(), data.size())) != handshake::error_t::NONE)
			// Выводим отказ розыска
			return false;
		// Обвязка сообщения
		handshake::header_t header;
		// Тело сообщения
		view_t body;
		/**
		 * Выполняем перебор сообщений уровня
		 */
		while(messages.next(header, body) == handshake::error_t::NONE){
			// Если это искомое сообщение
			if(header.type == type){
				// Переносим тело сообщения
				result.assign(body.data, body.data + body.size);
				// Выводим успешность розыска
				return true;
			}
		}
		// Выводим отказ розыска
		return false;
	}
	/**
	 * @brief Метод разбора перечня расширений запроса подлинности клиента издания TLS 1.3
	 *
	 * @param body   тело запроса подлинности: привязка и перечень расширений (раздел 4.3.2 RFC 8446)
	 * @param result перечень, в который помещаются расширения в проводном порядке
	 *
	 * @return       признак успешности разбора
	 *
	 */
	bool requested(const view_t & body, vector <hello::extension_t> & result) noexcept {
		// Разборщик полей тела запроса
		field::scanner_t scanner;
		// Начинаем разбор тела запроса
		scanner.start(body);
		// Привязка запроса подлинности
		view_t binding;
		// Если привязку прочитать не удалось
		if(scanner.vector(binding, 1) != field::error_t::NONE)
			// Выводим отказ разбора
			return false;
		// Запись перечня расширений
		view_t record;
		// Если запись перечня расширений прочитать не удалось
		if(scanner.vector(record, 2) != field::error_t::NONE)
			// Выводим отказ разбора
			return false;
		// Разборщик перечня расширений
		field::scanner_t list;
		// Начинаем разбор перечня расширений
		list.start(record);
		/**
		 * Выполняем перебор расширений перечня
		 */
		while(list.left() > 0){
			// Вид расширения
			uint32_t type = 0;
			// Тело расширения
			view_t data;
			// Если вид либо тело расширения прочитать не удалось
			if((list.number(type, 2) != field::error_t::NONE) || (list.vector(data, 2) != field::error_t::NONE))
				// Выводим отказ разбора
				return false;
			// Добавляем расширение в перечень
			result.push_back(hello::extension_t(static_cast <uint16_t> (type), data));
		}
		// Выводим успешность разбора
		return true;
	}
	/**
	 * @brief Метод счёта расширений вида GREASE в перечне
	 *
	 * @param extensions перечень расширений
	 * @param value      место, в которое помещается значение первого найденного расширения
	 * @param index      место, в которое помещается место первого найденного расширения
	 *
	 * @return           число расширений вида GREASE с пустым телом
	 *
	 */
	size_t greased(const vector <hello::extension_t> & extensions, uint16_t & value, size_t & index) noexcept {
		// Число расширений вида GREASE
		size_t count = 0;
		/**
		 * Выполняем перебор расширений перечня
		 */
		for(size_t i = 0; i < extensions.size(); i++){
			// Если расширение имеет вид GREASE и тело его пусто
			if(shaped(extensions[i].type) && (extensions[i].data.size == 0)){
				// Если это первое найденное расширение
				if(count == 0){
					// Запоминаем значение
					value = extensions[i].type;
					// Запоминаем место
					index = i;
				}
				// Считаем расширение
				count++;
			}
		}
		// Выводим число расширений
		return count;
	}
	/**
	 * @brief Метод проведения рукопожатия по уровням со снятием запроса подлинности и билета
	 *
	 * @param grease     включена ли вставка GREASE у сервера
	 * @param credential подлинность сторон
	 * @param asked      место, в которое переносится тело запроса подлинности
	 * @param request    место, в которое помещаются расширения запроса (виды указывают в asked)
	 * @param granted    место, в которое переносится тело билета
	 * @param ticket     место, в которое помещаются расширения билета (виды указывают в granted)
	 * @param tickets    место, в которое помещается число билетов, принятых клиентом
	 *
	 * @return           признак того, что связь установилась и сообщения сняты
	 *
	 */
	bool served(const bool grease, const context::credential_t & credential, vector <uint8_t> & asked, vector <hello::extension_t> & request, vector <uint8_t> & granted, vector <hello::extension_t> & ticket, size_t & tickets) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Перенос по уровням клиенту: сообщения сервера видны открытыми
		client.transport(context::transport_t::LEVELS);
		// Перенос по уровням серверу
		server.transport(context::transport_t::LEVELS);
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, credential, true);
		// Прикладной протокол клиента: раздел 8.1 RFC 9001 велит вести связь QUIC с ALPN
		client.protocols(vector <string> {"h3"});
		// Прикладной протокол сервера
		server.protocols(vector <string> {"h3"});
		// Параметры переноса клиента
		client.parameters(CLIENT_PARAMETERS);
		// Параметры переноса сервера
		server.parameters(SERVER_PARAMETERS);
		// Дозволяем упреждающие данные сервером: билет несёт предел, и GREASE идёт за ним
		server.advance(true);
		// Устанавливаем вставку GREASE серверу
		server.grease(grease);
		// Если сервер завести не удалось
		if(server.start() != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Если клиента завести не удалось
		if(client.start() != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Сообщения сервера уровня рукопожатия
		vector <uint8_t> handshake;
		// Проводим рукопожатие по уровням
		levelled(client, server, handshake);
		// Если связь не установилась
		if(!client.established() || !server.established())
			// Выводим отказ
			return false;
		// Если запрос подлинности среди сообщений сервера не найден
		if(!locate(handshake, handshake::type_t::REQUEST, asked))
			// Выводим отказ
			return false;
		// Если перечень расширений запроса разобрать не удалось
		if(!requested(view_t(asked.data(), asked.size()), request))
			// Выводим отказ
			return false;
		// Если билет выдать не удалось
		if(server.issue() != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Сообщения сервера уровня прикладных данных
		vector <uint8_t> application;
		// Переносим билет клиенту, запоминая сообщения
		if(!carry(server, client, context::level_t::APPLICATION, &application))
			// Выводим отказ
			return false;
		// Если билет среди сообщений сервера не найден
		if(!locate(application, handshake::type_t::TICKET, granted))
			// Выводим отказ
			return false;
		// Разобранный билет
		message::ticket_t parsed;
		// Если билет разобрать не удалось
		if(message::parse(view_t(granted.data(), granted.size()), parsed) != message::error_t::NONE)
			// Выводим отказ
			return false;
		// Переносим расширения билета
		ticket = parsed.extensions;
		// Запоминаем число билетов, принятых клиентом
		tickets = client.tickets().size();
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод снятия мест GREASE с приветствия свежей связи
	 *
	 * @param credential подлинность сервера
	 * @param result     место, в которое помещаются снятые места
	 * @param why        место, в которое помещается причина отказа
	 *
	 * @return           признак успешности снятия
	 *
	 */
	bool sample(const context::credential_t & credential, places_t & result, std::string & why) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, credential, false);
		// Включаем вставку GREASE клиенту
		client.grease(true);
		// Если клиента завести не удалось
		if(client.start() != context::error_t::NONE){
			// Называем причину
			why = "клиент не завёлся";
			// Выводим отказ
			return false;
		}
		// Отправленные байты
		vector <uint8_t> wire;
		// Разобранное приветствие
		hello::client_t greeting;
		// Если приветствие снять не удалось
		if(!capture(client, wire, greeting)){
			// Называем причину
			why = "приветствие не снялось";
			// Выводим отказ
			return false;
		}
		// Выводим итог снятия мест
		return places(greeting, false, result, why);
	}
};

/**
 * Проверка мест вставки: набор первым, расширение первым пустым и последним среди
 * расширений потребителя с одним нулевым байтом, группа первой, доля первой с телом в
 * один байт, издание первым; значения вида 0x?A?A, два расширения различны, иных значений
 * GREASE нет; при предъявлении билета заранее разделённый ключ идёт за вторым расширением;
 * связь с сервером устанавливается, и сервер значения GREASE не выбирает
 */
TEST(GreaseTest, Places){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, credential, false);
	// Клиент предлагает и издание 1.2: перечень изданий длиннее одного
	client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Имя узла: расширение потребителя после долей
	client.name("localhost");
	// Прикладные протоколы: ещё одно расширение потребителя
	client.protocols(vector <string> {"h2", "http/1.1"});
	// Включаем вставку GREASE
	client.grease(true);
	// Проверяем состояние ручки
	ASSERT_TRUE(client.grease());
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Отправленные байты
	vector <uint8_t> wire;
	// Разобранное приветствие
	hello::client_t greeting;
	// Снимаем приветствие
	ASSERT_TRUE(capture(client, wire, greeting));
	// Места GREASE
	places_t found;
	// Причина отказа
	std::string why;
	// Проверяем места
	ASSERT_TRUE(places(greeting, false, found, why)) << why;
	// Проверяем вид набора
	ASSERT_TRUE(shaped(found.suite));
	// Проверяем вид первого расширения
	ASSERT_TRUE(shaped(found.first));
	// Проверяем вид второго расширения
	ASSERT_TRUE(shaped(found.second));
	// Проверяем вид группы
	ASSERT_TRUE(shaped(found.group));
	// Проверяем вид издания
	ASSERT_TRUE(shaped(found.version));
	// Второе расширение GREASE - самое последнее: заранее разделённого ключа нет
	ASSERT_EQ(greeting.extensions.back().type, found.second);
	// Расширение изданий идёт сразу за первым GREASE
	ASSERT_EQ(greeting.extensions[1].type, static_cast <uint16_t> (extension::type_t::VERSIONS));
	// Подаём приветствие серверу
	server.push(view_t(wire.data(), wire.size()));
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Сервер значения GREASE не выбрал
	ASSERT_EQ(server.suite(), protect::suite_t::AES_128_GCM_SHA256);
	// Проверяем издание
	ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0304));
	// Проверяем обмен данными
	ASSERT_TRUE(barter(client, server));
	// Выдаём билет
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Доставляем билет
	converse(client, server);
	// Проверяем получение билета
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	// Возобновляющий клиент
	client::context_t resuming;
	// Возобновляемый сервер
	server::context_t resumed;
	// Настраиваем стороны
	arrange(resuming, resumed, credential, false);
	// Включаем вставку GREASE
	resuming.grease(true);
	// Предъявляем билет
	resuming.resume(client.tickets()[0]);
	// Признаём билеты
	resumed.resume(server.tickets());
	// Заводим сервер
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Отправленные байты возобновления
	vector <uint8_t> again;
	// Разобранное приветствие возобновления
	hello::client_t offer;
	// Снимаем приветствие
	ASSERT_TRUE(capture(resuming, again, offer));
	// Места GREASE возобновления
	places_t second;
	// Проверяем места: второе расширение GREASE перед заранее разделённым ключом
	ASSERT_TRUE(places(offer, false, second, why)) << why;
	// Заранее разделённый ключ идёт последним (раздел 4.2.11 RFC 8446)
	ASSERT_EQ(offer.extensions.back().type, static_cast <uint16_t> (extension::type_t::SECRET));
	// Второе расширение GREASE идёт перед ним
	ASSERT_EQ(offer.extensions[offer.extensions.size() - 2].type, second.second);
	// Подаём приветствие серверу
	resumed.push(view_t(again.data(), again.size()));
	// Проводим рукопожатие
	converse(resuming, resumed);
	// Проверяем установленность связи
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	// Проверяем возобновление билетом
	ASSERT_TRUE(resuming.shared() && resumed.shared());
	// Проверяем обмен данными
	ASSERT_TRUE(barter(resuming, resumed));
}

/**
 * Проверка энтропии: связи подряд (шестьдесят четыре, договор требует шестнадцати) -
 * набор GREASE обязан различаться хотя бы между какими-то из них (зашитая постоянная
 * недопустима); у каждой связи два расширения различны, а все значения вида 0x?A?A;
 * шестьдесят четыре связи ловят и снятое разведение двух расширений (совпадение старших
 * разрядов у одной связи из шестнадцати, у шестидесяти четырёх подряд - почти наверняка)
 */
TEST(GreaseTest, Entropy){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Наборы GREASE связей
	vector <uint16_t> suites;
	/**
	 * Выполняем перебор связей
	 */
	for(size_t i = 0; i < 64; i++){
		// Места GREASE связи
		places_t found;
		// Причина отказа
		std::string why;
		// Снимаем места со свежей связи
		ASSERT_TRUE(sample(credential, found, why)) << "связь " << i << ": " << why;
		// Два расширения различны
		ASSERT_NE(found.first, found.second) << "связь " << i;
		// Запоминаем набор GREASE
		suites.push_back(found.suite);
	}
	// Признак того, что наборы разных связей различаются
	bool differs = false;
	/**
	 * Выполняем перебор наборов связей
	 */
	for(size_t i = 1; (i < suites.size()) && !differs; i++)
		// Запоминаем отличие набора от первого
		differs = (suites[i] != suites[0]);
	// Наборы GREASE обязаны различаться хоть между какими-то связями
	ASSERT_TRUE(differs) << "набор GREASE одинаков у шестидесяти четырёх связей подряд";
}

/**
 * Проверка стабильности через просьбу о повторе: клиент шлёт долю по одной группе, сервер
 * ведёт другую и просит повтора; второе приветствие несёт те же значения GREASE на тех же
 * местах, что и первое, и связь устанавливается
 */
TEST(GreaseTest, Retry){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, credential, false);
	// Клиент объявляет две группы
	client.groups(vector <extension::group_t> {extension::group_t::SECP256R1, extension::group_t::SECP384R1});
	// Клиент шлёт долю лишь по первой
	client.shares(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Сервер ведёт лишь вторую: доли по ней нет, будет просьба о повторе
	server.groups(vector <extension::group_t> {extension::group_t::SECP384R1});
	// Включаем вставку GREASE
	client.grease(true);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Байты первого приветствия
	vector <uint8_t> first;
	// Разобранное первое приветствие
	hello::client_t initial;
	// Снимаем первое приветствие
	ASSERT_TRUE(capture(client, first, initial));
	// Места GREASE первого приветствия
	places_t before;
	// Причина отказа
	std::string why;
	// Проверяем места первого приветствия
	ASSERT_TRUE(places(initial, false, before, why)) << why;
	// Подаём первое приветствие серверу
	server.push(view_t(first.data(), first.size()));
	// Байты просьбы о повторе
	const view_t retry = server.output();
	// Сервер ответил
	ASSERT_GT(retry.size, static_cast <size_t> (0));
	// Переносим просьбу о повторе
	const vector <uint8_t> asking(retry.data, retry.data + retry.size);
	// Снимаем просьбу с накопителя сервера
	server.consume(asking.size());
	// Подаём просьбу клиенту
	client.push(view_t(asking.data(), asking.size()));
	// Клиент не оборвал связь
	ASSERT_NE(client.state(), context::state_t::FAILED) << static_cast <int> (client.error());
	// Байты второго приветствия
	vector <uint8_t> second;
	// Разобранное второе приветствие
	hello::client_t repeated;
	// Снимаем второе приветствие
	ASSERT_TRUE(capture(client, second, repeated));
	// Места GREASE второго приветствия
	places_t after;
	// Проверяем места второго приветствия: просьба несла долю, и доли GREASE в повторе нет
	ASSERT_TRUE(places(repeated, true, after, why)) << why;
	// Набор GREASE тот же
	ASSERT_EQ(after.suite, before.suite);
	// Первое расширение GREASE то же
	ASSERT_EQ(after.first, before.first);
	// Второе расширение GREASE то же
	ASSERT_EQ(after.second, before.second);
	// Группа GREASE та же
	ASSERT_EQ(after.group, before.group);
	// Издание GREASE то же
	ASSERT_EQ(after.version, before.version);
	/**
	 * Раздел 4.2.8 RFC 8446: второе приветствие несёт долю по одной лишь запрошенной
	 * группе - openssl отвергает всякую иную долю повторного приветствия, и доля GREASE
	 * снимается вместе с прежними, как у BoringSSL
	 */
	const hello::extension_t * item = hello::extension(repeated.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
	// Расширение долей есть
	ASSERT_NE(item, nullptr);
	// Доли второго приветствия
	vector <extension::share_t> shares;
	// Разбираем доли
	ASSERT_EQ(extension::shares(item->data, shares), extension::error_t::NONE);
	// Доля одна: запрошенная
	ASSERT_EQ(shares.size(), static_cast <size_t> (1));
	// Доля по запрошенной группе
	ASSERT_EQ(shares[0].group, extension::group_t::SECP384R1);
	// Подаём второе приветствие серверу
	server.push(view_t(second.data(), second.size()));
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем обмен данными
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка стабильности через просьбу о повторе одной лишь меткой (DTLS 1.3, раздел 5.1
 * RFC 9147): доля клиента годна, сервер просит повтора без доли ключа - второе приветствие
 * несёт те же значения GREASE на тех же местах, доля GREASE остаётся, и связь устанавливается
 */
TEST(GreaseTest, Cookie){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Перенос дейтаграммами клиенту
	client.transport(context::transport_t::DATAGRAMS);
	// Перенос дейтаграммами серверу
	server.transport(context::transport_t::DATAGRAMS);
	// Настраиваем стороны
	arrange(client, server, credential, false);
	// Адрес собеседника у сервера: метка привязывается к нему
	static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
	// Устанавливаем адрес собеседника
	server.address(view_t(ADDRESS, sizeof(ADDRESS)));
	// Включаем вставку GREASE
	client.grease(true);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Дейтаграмма первого приветствия
	vector <uint8_t> first;
	// Разобранное первое приветствие
	hello::client_t initial;
	// Снимаем первое приветствие
	ASSERT_TRUE(datagrammed(client, first, initial));
	// Первое приветствие без метки
	ASSERT_TRUE(initial.cookie.empty());
	// Места GREASE первого приветствия
	places_t before;
	// Причина отказа
	std::string why;
	// Проверяем места первого приветствия
	ASSERT_TRUE(places(initial, false, before, why)) << why;
	// Подаём первое приветствие серверу
	server.push(view_t(first.data(), first.size()));
	// Дейтаграмма просьбы о повторе
	const view_t retry = server.output();
	// Сервер ответил
	ASSERT_GT(retry.size, static_cast <size_t> (0));
	// Переносим просьбу о повторе
	const vector <uint8_t> asking(retry.data, retry.data + retry.size);
	// Снимаем просьбу с накопителя сервера
	server.consume(asking.size());
	// Подаём просьбу клиенту
	client.push(view_t(asking.data(), asking.size()));
	// Клиент не оборвал связь
	ASSERT_NE(client.state(), context::state_t::FAILED) << static_cast <int> (client.error());
	// Дейтаграмма второго приветствия
	vector <uint8_t> second;
	// Разобранное второе приветствие
	hello::client_t repeated;
	// Снимаем второе приветствие
	ASSERT_TRUE(datagrammed(client, second, repeated));
	// Второе приветствие несёт метку возврата состояния
	ASSERT_NE(hello::extension(repeated.extensions, static_cast <uint16_t> (extension::type_t::COOKIE)), nullptr);
	// Места GREASE второго приветствия: просьба доли не просила, и доля GREASE осталась
	places_t after;
	// Проверяем места второго приветствия
	ASSERT_TRUE(places(repeated, false, after, why)) << why;
	// Набор GREASE тот же
	ASSERT_EQ(after.suite, before.suite);
	// Первое расширение GREASE то же
	ASSERT_EQ(after.first, before.first);
	// Второе расширение GREASE то же
	ASSERT_EQ(after.second, before.second);
	// Группа GREASE та же
	ASSERT_EQ(after.group, before.group);
	// Группа доли GREASE та же
	ASSERT_EQ(after.share, before.share);
	// Издание GREASE то же
	ASSERT_EQ(after.version, before.version);
	// Подаём второе приветствие серверу
	server.push(view_t(second.data(), second.size()));
	/**
	 * Выполняем перенос дейтаграмм между сторонами до установления связи
	 */
	for(size_t i = 0; (i < 16) && !(client.established() && server.established()); i++){
		// Дейтаграмма сервера
		const view_t reply = server.output();
		// Если серверу есть что отправить
		if(reply.size > 0){
			// Переносим дейтаграмму
			const vector <uint8_t> buffer(reply.data, reply.data + reply.size);
			// Снимаем дейтаграмму с накопителя сервера
			server.consume(buffer.size());
			// Подаём дейтаграмму клиенту
			client.push(view_t(buffer.data(), buffer.size()));
		}
		// Дейтаграмма клиента
		const view_t sending = client.output();
		// Если клиенту есть что отправить
		if(sending.size > 0){
			// Переносим дейтаграмму
			const vector <uint8_t> buffer(sending.data, sending.data + sending.size);
			// Снимаем дейтаграмму с накопителя клиента
			client.consume(buffer.size());
			// Подаём дейтаграмму серверу
			server.push(view_t(buffer.data(), buffer.size()));
		}
	}
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
}

/**
 * Проверка выключенного состояния: по умолчанию ручка выключена, приветствие не несёт ни
 * одного значения вида 0x?A?A ни в одном из перечней, а порядок расширений прежний;
 * ручка переключается в обе стороны
 */
TEST(GreaseTest, Disabled){
	// Подлинность сервера
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, credential, false);
	// Клиент предлагает и издание 1.2
	client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Имя узла
	client.name("localhost");
	// По умолчанию ручка выключена у клиента
	ASSERT_FALSE(client.grease());
	// По умолчанию ручка выключена у сервера
	ASSERT_FALSE(server.grease());
	// Ручка включается
	client.grease(true);
	// Проверяем включение
	ASSERT_TRUE(client.grease());
	// Ручка выключается
	client.grease(false);
	// Проверяем выключение
	ASSERT_FALSE(client.grease());
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Отправленные байты
	vector <uint8_t> wire;
	// Разобранное приветствие
	hello::client_t greeting;
	// Снимаем приветствие
	ASSERT_TRUE(capture(client, wire, greeting));
	// Ни одного значения GREASE нет
	ASSERT_TRUE(clean(greeting));
	// Первый набор - набор потребителя
	ASSERT_EQ(greeting.suites[0], static_cast <uint16_t> (protect::suite_t::AES_128_GCM_SHA256));
	// Первое расширение - перечень изданий, как прежде
	ASSERT_EQ(greeting.extensions.front().type, static_cast <uint16_t> (extension::type_t::VERSIONS));
	// Последнее расширение - имя узла, как прежде
	ASSERT_EQ(greeting.extensions.back().type, static_cast <uint16_t> (extension::type_t::NAME));
	// Разыскиваем расширение долей
	const hello::extension_t * item = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
	// Расширение долей есть
	ASSERT_NE(item, nullptr);
	// Доли приветствия
	vector <extension::share_t> shares;
	// Разбираем доли
	ASSERT_EQ(extension::shares(item->data, shares), extension::error_t::NONE);
	// Доля одна, по группе потребителя
	ASSERT_EQ(shares.size(), static_cast <size_t> (1));
	// Проверяем группу доли
	ASSERT_EQ(shares[0].group, extension::group_t::X25519);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Подаём приветствие серверу
	server.push(view_t(wire.data(), wire.size()));
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем обмен данными
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка сервера: при включённой ручке запрос подлинности издания TLS 1.3 несёт пустое
 * расширение GREASE первым, билет - пустое расширение GREASE за пределом упреждающих
 * данных; клиент запрос и билет принимает; при выключенной ручке расширений GREASE нет;
 * обе стороны с GREASE устанавливают связь записями
 */
TEST(GreaseTest, Server){
	// Подлинность сторон
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Тело запроса подлинности
	vector <uint8_t> asked;
	// Расширения запроса подлинности
	vector <hello::extension_t> request;
	// Тело билета
	vector <uint8_t> granted;
	// Расширения билета
	vector <hello::extension_t> ticket;
	// Число билетов у клиента
	size_t tickets = 0;
	// Проводим рукопожатие с включённой ручкой
	ASSERT_TRUE(served(true, credential, asked, request, granted, ticket, tickets));
	// Значение расширения GREASE
	uint16_t value = 0;
	// Место расширения GREASE
	size_t index = 0;
	// В запросе подлинности ровно одно расширение GREASE
	ASSERT_EQ(greased(request, value, index), static_cast <size_t> (1));
	// Оно первое
	ASSERT_EQ(index, static_cast <size_t> (0));
	// Оно вида 0x?A?A
	ASSERT_TRUE(shaped(value));
	// За ним идут схемы подписи
	ASSERT_GE(request.size(), static_cast <size_t> (2));
	// Проверяем схемы подписи вторым расширением
	ASSERT_EQ(request[1].type, static_cast <uint16_t> (extension::type_t::SCHEMES));
	// В билете ровно одно расширение GREASE
	ASSERT_EQ(greased(ticket, value, index), static_cast <size_t> (1));
	// Оно вида 0x?A?A
	ASSERT_TRUE(shaped(value));
	// Билет несёт предел упреждающих данных первым, GREASE за ним
	ASSERT_EQ(ticket.size(), static_cast <size_t> (2));
	// Проверяем предел упреждающих данных первым расширением
	ASSERT_EQ(ticket[0].type, static_cast <uint16_t> (extension::type_t::EARLY));
	// GREASE - последним
	ASSERT_EQ(index, static_cast <size_t> (1));
	// Клиент билет принял
	ASSERT_EQ(tickets, static_cast <size_t> (1));
	// Тело запроса подлинности при выключенной ручке
	vector <uint8_t> asking;
	// Расширения запроса подлинности при выключенной ручке
	vector <hello::extension_t> bare;
	// Тело билета при выключенной ручке
	vector <uint8_t> granting;
	// Расширения билета при выключенной ручке
	vector <hello::extension_t> plain;
	// Проводим рукопожатие с выключенной ручкой
	ASSERT_TRUE(served(false, credential, asking, bare, granting, plain, tickets));
	// В запросе подлинности расширений GREASE нет
	ASSERT_EQ(greased(bare, value, index), static_cast <size_t> (0));
	// Первое расширение запроса - схемы подписи, как прежде
	ASSERT_EQ(bare.front().type, static_cast <uint16_t> (extension::type_t::SCHEMES));
	// В билете расширений GREASE нет
	ASSERT_EQ(greased(plain, value, index), static_cast <size_t> (0));
	// Билет несёт один лишь предел упреждающих данных, как прежде
	ASSERT_EQ(plain.size(), static_cast <size_t> (1));
	// Клиент билет принял
	ASSERT_EQ(tickets, static_cast <size_t> (1));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны с подлинностью клиента
	arrange(client, server, credential, true);
	// Включаем вставку GREASE клиенту
	client.grease(true);
	// Включаем вставку GREASE серверу
	server.grease(true);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем подлинность клиента у сервера
	ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
	// Проверяем обмен данными
	ASSERT_TRUE(barter(client, server));
	// Выдаём билет
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Доставляем билет
	converse(client, server);
	// Проверяем получение билета
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
}

/**
 * Проверка обмена с настоящим openssl изданием TLS 1.3: наш клиент с GREASE против
 * s_server со встречной подлинностью, в том числе через просьбу о повторе (сервер ведёт
 * лишь группу без доли); s_client против нашего сервера с GREASE - запрос подлинности и
 * билет с расширением GREASE клиент openssl принимает
 */
TEST(GreaseTest, Openssl13){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.3 (проба возможности, не по номеру издания)
	if(!toolkit.tls13 || !toolkit.serverGroups){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.3 либо без -groups";
	}
	// Подлинность сторон
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	/**
	 * Выполняем перебор случаев: прямое рукопожатие и рукопожатие через просьбу о повторе
	 */
	for(size_t retry = 0; retry < 2; retry++){
		// Свободный порт
		const uint16_t number = vacant(false);
		// Проверяем наличие порта
		ASSERT_NE(number, 0);
		// Журнал сервера openssl
		const std::string log = "/tmp/ants-grease-server-" + std::to_string(number) + ".log";
		// Группы сервера: при повторе лишь P-384, доли по которой клиент не шлёт
		const std::string groups = ((retry == 0) ? "X25519:P-384" : "P-384");
		// Запускаем сервер openssl в один приём с ответом HTTP и с запросом подлинности клиента
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -groups " + groups + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож сервера openssl
		sentinel_t sentinel(log + ".pid");
		// Подключаемся к серверу openssl
		const int fd = dial(number);
		// Проверяем подключение
		ASSERT_GE(fd, 0) << "порт " << number;
		// Связь стороны клиента
		client::context_t client;
		// Наборы клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группы клиента: X25519 и P-384
		client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP384R1});
		// Доля лишь по X25519
		client.shares(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность клиента тем же ключом
		client.credential(credential);
		// Имя узла
		client.name("localhost");
		// Включаем вставку GREASE
		client.grease(true);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу байтов до установления связи
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты
			relay(client, fd);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established()) << "повтор " << retry << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Проверяем набор
		ASSERT_EQ(client.suite(), protect::suite_t::AES_128_GCM_SHA256);
		// Проверяем цепочку сервера
		ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
		// Запрос HTTP серверу openssl
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Отправляем запрос
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Накопитель ответа
		vector <uint8_t> answer;
		/**
		 * Выполняем передачу байтов до получения ответа
		 */
		for(size_t i = 0; (i < 16) && answer.empty(); i++){
			// Передаём байты
			relay(client, fd);
			// Читаем принятые данные
			ASSERT_EQ(client.read(answer), context::error_t::NONE);
		}
		// Текст ответа
		const string text(answer.begin(), answer.end());
		// Проверяем, что ответ HTTP получен
		ASSERT_NE(text.find("HTTP/1.0 200"), string::npos) << "повтор " << retry;
		// При повторе сервер вёл группу P-384
		if(retry == 1)
			// Проверяем группу в ответе сервера
			ASSERT_NE(text.find("P-384"), string::npos) << text;
		// Закрываем сокет
		closing(fd);
		// Снимаем сервер до удаления журнала
		sentinel.halt();
		// Журнал сервера
		std::string journal;
		// Дожидаемся отметки завершения снятого сервера
		(void) settle(log, journal);
		// Удаляем журнал
		::remove(log.c_str());
	}
	// Порт своего сервера
	uint16_t number = 0;
	// Слушающий сокет
	const int listener = harbour(number);
	// Проверяем сокет
	ASSERT_GE(listener, 0);
	// Журнал клиента openssl
	const std::string log = "/tmp/ants-grease-client-" + std::to_string(number) + ".log";
	// Именованный канал входа клиента openssl: вход держится, пока билет не придёт
	const std::string holder = "/tmp/ants-grease-client-" + std::to_string(number) + ".fifo";
	// Убираем канал, оставшийся от прежнего прогона
	::remove(holder.c_str());
	// Заводим именованный канал
	ASSERT_EQ(fifo(holder.c_str()), 0);
	// Файл сеанса клиента openssl: с ним s_client оглашает принятый билет в журнале
	const std::string session = "/tmp/ants-grease-client-" + std::to_string(number) + ".sess";
	// Запускаем клиента openssl со своей подлинностью: запрос подлинности с GREASE ему придёт
	ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -cert " + crt + " -key " + key + " -servername localhost -verify_return_error -sess_out " + session + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
	// Сторож клиента openssl
	sentinel_t sentinel(log + ".pid");
	// Принимаем подключение
	const int fd = greeted(listener);
	// Проверяем подключение
	ASSERT_GE(fd, 0);
	// Связь стороны сервера
	server::context_t server;
	// Наборы сервера
	server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
	// Группы сервера
	server.groups(vector <extension::group_t> {extension::group_t::X25519});
	// Подлинность сервера
	server.credential(credential);
	// Запрашиваем подлинность клиента
	server.request(true);
	// Включаем вставку GREASE
	server.grease(true);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Ведём связь до конца рукопожатия
	ASSERT_TRUE(serve(server, fd)) << "отказ " << static_cast <int> (server.error());
	// Отказа не было
	ASSERT_EQ(server.error(), context::error_t::NONE);
	// Связь установлена
	ASSERT_TRUE(server.established());
	// Подлинность клиента получена
	ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
	// Выдаём билет с расширением GREASE
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Байты билета
	const view_t granting = server.output();
	// Отправляем билет
	ASSERT_EQ(sending(fd, granting.data, granting.size), static_cast <ssize_t> (granting.size));
	// Снимаем байты билета
	server.consume(granting.size);
	// Признак того, что клиент openssl билет принял
	bool granted = false;
	/**
	 * Ожидание идёт по состоянию: журнал s_client копится до выхода, а файл сеанса пишется
	 * тут же по приёму билета; предел лишь защита от зависания
	 */
	for(size_t i = 0; !granted && (i < 300); i++){
		// Открываем файл сеанса
		std::ifstream file(session, std::ios::binary | std::ios::ate);
		// Запоминаем, написан ли сеанс
		granted = (file.is_open() && (file.tellg() > 0));
		// Если сеанс ещё не написан
		if(!granted)
			// Выдерживаем паузу
			::usleep(100000);
	}
	// Клиент openssl обязан принять билет с расширением GREASE
	ASSERT_TRUE(granted);
	// Закрываем связь: по извещению клиент openssl уходит сам и выкладывает журнал
	ASSERT_TRUE(farewell(server, fd));
	// Закрываем сокет
	closing(fd);
	// Закрываем слушающий сокет
	closing(listener);
	// Текст журнала клиента
	std::string text;
	// Дожидаемся отметки завершения
	ASSERT_TRUE(settle(log, text)) << text;
	// Проверка подлинности сервера у клиента обязана сойтись
	ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
	// Билет оглашён журналом клиента
	ASSERT_NE(text.find("Post-Handshake New Session Ticket arrived"), std::string::npos) << text;
	// Удаляем журнал
	::remove(log.c_str());
	// Удаляем именованный канал
	::remove(holder.c_str());
	// Удаляем файл сеанса
	::remove(session.c_str());
}

/**
 * Проверка обмена с настоящим openssl изданием TLS 1.2: наш клиент с GREASE против
 * s_server набором ECDHE-ECDSA-AES128-GCM-SHA256 со встречной подлинностью
 */
TEST(GreaseTest, Openssl12){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.2 с ECDHE
	if(!toolkit.tls12){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.2";
	}
	// Если openssl не умеет расширенный главный секрет (OpenSSL 1.0.2, LibreSSL): связь по TLS 1.2 его требует
	if(!toolkit.master){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без расширенного главного секрета RFC 7627";
	}
	// Подлинность сторон
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Свободный порт
	const uint16_t number = vacant(false);
	// Проверяем наличие порта
	ASSERT_NE(number, 0);
	// Журнал сервера openssl
	const std::string log = "/tmp/ants-grease-tls12-" + std::to_string(number) + ".log";
	// Запускаем сервер openssl изданием 1.2 без билетов со встречной подлинностью
	ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_2 -no_ticket -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -cipher ECDHE-ECDSA-AES128-GCM-SHA256" + grouping(toolkit, true, extension::group_t::SECP256R1) + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
	// Сторож сервера openssl
	sentinel_t sentinel(log + ".pid");
	// Подключаемся к серверу openssl
	const int fd = dial(number);
	// Проверяем подключение
	ASSERT_GE(fd, 0) << "порт " << number;
	// Связь стороны клиента
	client::context_t client;
	// Наборы клиента
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Группы клиента: кривая обмена и кривые сертификатов
	client.groups(vector <extension::group_t> {extension::group_t::SECP256R1, extension::group_t::SECP384R1});
	// Подлинность клиента
	client.credential(credential);
	// Имя узла
	client.name("localhost");
	// Включаем вставку GREASE
	client.grease(true);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Выполняем передачу байтов до установления связи
	 */
	for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
		// Передаём байты
		relay(client, fd);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
	// Издание 1.2
	ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
	// Проверяем набор
	ASSERT_EQ(client.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256);
	// Запрос HTTP серверу openssl
	const string request = "GET / HTTP/1.0\r\n\r\n";
	// Отправляем запрос
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Накопитель ответа
	vector <uint8_t> answer;
	/**
	 * Выполняем передачу байтов до получения ответа
	 */
	for(size_t i = 0; (i < 16) && answer.empty(); i++){
		// Передаём байты
		relay(client, fd);
		// Читаем принятые данные
		ASSERT_EQ(client.read(answer), context::error_t::NONE);
	}
	// Текст ответа
	const string text(answer.begin(), answer.end());
	// Проверяем, что ответ HTTP получен
	ASSERT_NE(text.find("HTTP/1.0 200"), string::npos) << text;
	// Сервер openssl видит издание 1.2
	ASSERT_NE(text.find("TLSv1.2"), string::npos) << text;
	// Закрываем сокет
	closing(fd);
	// Снимаем сервер до удаления журнала
	sentinel.halt();
	// Журнал сервера
	std::string journal;
	// Дожидаемся отметки завершения снятого сервера
	(void) settle(log, journal);
	// Удаляем журнал
	::remove(log.c_str());
}

/**
 * Проверка обмена с настоящим openssl по DTLS 1.2: наш клиент с GREASE против s_server с
 * приёмом приветствия по метке; повторное приветствие с меткой несёт те же значения GREASE
 */
TEST(GreaseTest, Dtls){
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
	// Если openssl не умеет расширенный главный секрет: связь по DTLS 1.2 его требует
	if(!toolkit.master){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без расширенного главного секрета RFC 7627";
	}
	// Подлинность сторон
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Пути к сертификату и ключу
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Свободный порт UDP
	const uint16_t number = vacant(true);
	// Проверяем порт
	ASSERT_NE(number, 0);
	// Журнал сервера openssl
	const std::string log = "/tmp/ants-grease-dtls-" + std::to_string(number) + ".log";
	// Именованный канал входа сервера openssl
	const std::string holder = "/tmp/ants-grease-dtls-" + std::to_string(number) + ".fifo";
	// Убираем канал, оставшийся от прежнего прогона
	::remove(holder.c_str());
	// Заводим именованный канал
	ASSERT_EQ(fifo(holder.c_str()), 0);
	// Запускаем сервер openssl: DTLS 1.2, приём приветствия с меткой, встречная подлинность
	ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -dtls1_2 -listen -no_ticket -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -cipher ECDHE-ECDSA-AES128-GCM-SHA256" + grouping(toolkit, true, extension::group_t::SECP256R1) + " -mtu 300" + once(toolkit) + " <" + holder + " >" + log + " 2>&1", log, log + ".pid", holder));
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
	client.suites(vector <protect::suite_t> {protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
	// Группы: кривая обмена и кривые сертификатов
	client.groups(vector <extension::group_t> {extension::group_t::SECP256R1, extension::group_t::SECP384R1});
	// Подлинность клиента
	client.credential(credential);
	// Размер дейтаграммы
	client.mtu(300);
	// Имя узла
	client.name("localhost");
	// Включаем вставку GREASE
	client.grease(true);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Ведём связь до установления
	const bool complete = relay(client, fd, peer, 400);
	// Связь установлена
	ASSERT_TRUE(complete) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
	// Издание DTLS 1.2
	ASSERT_EQ(client.version(), static_cast <uint16_t> (0x0303));
	// Набор
	ASSERT_EQ(client.suite(), protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256);
	// Цепочка сервера
	ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
	// Данные серверу
	const string request = "ants grease over dtls\n";
	// Отправляем данные
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Отправляем дейтаграммы
	relay(client, fd, peer, 1);
	// Сервер печатает принятое в журнал
	ASSERT_TRUE(awaited(log, request, text)) << text;
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

/**
 * Проверка поведения при нехватке памяти с включённой ручкой у обеих сторон: перебор
 * запасов выделений, всякий отказ либо NONE, либо MEMORY, либо обрыв внутренним извещением;
 * на щедром запасе связь устанавливается и билет с расширением GREASE доходит
 */
TEST(GreaseTest, Starved){
	// Подлинность сторон
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
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, credential, true);
		// Включаем вставку GREASE клиенту
		client.grease(true);
		// Включаем вставку GREASE серверу
		server.grease(true);
		// Ошибки сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Заводим сервер
			first = server.start();
			// Заводим клиента
			second = client.start();
			// Если стороны заведены
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие
				converse(client, server);
				// Если связь установлена
				if(client.established() && server.established()){
					// Выдаём билет
					first = server.issue();
					// Если билет выдан
					if(first == context::error_t::NONE){
						// Доставляем билет
						converse(client, server);
						// Ошибка сервера после доставки
						first = server.error();
					}
				// Если связь не установлена
				} else
					// Ошибка сервера после рукопожатия
					first = server.error();
				// Ошибка клиента
				second = client.error();
			}
		}
		// Запоминаем нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		/**
		 * Дозволенные исходы: успех, нехватка памяти либо обрыв собеседником с внутренним
		 * извещением о его нехватке памяти
		 */
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		// Проверяем законность исхода
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		// Запоминаем установление связи с доставленным билетом
		complete = (client.established() && server.established() && (client.tickets().size() == 1));
	}
	// Проверяем, что нехватка памяти встретилась
	ASSERT_TRUE(starved);
	// Проверяем, что на щедром запасе связь установилась и билет дошёл
	ASSERT_TRUE(complete);
}
