/**
 * @file flow.cpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Пример полного рукопожатия протокола TLS 1.3 — от приветствий сторон до
 *        прикладных данных, с переключением ключей и проверкой завершений
 *
 * @details Обе стороны здесь ведутся в одном приложении, а связь между ними - обычный
 *          накопитель байтов. Сети в образце нет вовсе: рукопожатие от неё не зависит и
 *          с тем же успехом идёт через что угодно, лишь бы байты доходили по порядку
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <vector>
#include <cstring>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <flow/flow.hpp>
#include <hello/hello.hpp>
#include <entropy/entropy.hpp>
#include <session/session.hpp>
#include <message/message.hpp>
#include <protect/protect.hpp>
#include <handshake/handshake.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace anyks;

/**
 * @brief Пространство имён образца
 *
 */
namespace {
	/**
	 * @brief Набор шифрования связи образца
	 *
	 */
	static const protect::suite_t SUITE = protect::suite_t::KUZNYECHIK_MGM_S;

	/**
	 * @brief Состояние одной стороны связи
	 *
	 */
	static struct Peer {
		// Ход рукопожатия стороны связи
		flow::machine_t machine;
		// Переписка рукопожатия стороны связи
		session::transcript_t transcript;
		// Значения расписания ключей стороны связи
		session::secrets_t secrets;
		// Защита записей, отправляемых клиентом
		protect::protection_t client;
		// Защита записей, отправляемых сервером
		protect::protection_t server;
	} CLIENT, SERVER;

	/**
	 * @brief Метод получения названия поры ключей
	 *
	 * @param epoch пора ключей, которыми защищаются записи
	 *
	 * @return      название поры ключей
	 *
	 */
	const char * title(const flow::epoch_t epoch) noexcept {
		/**
		 * Выполняем определение поры ключей записей
		 */
		switch(static_cast <uint8_t> (epoch)){
			// Если записи идут без защиты
			case static_cast <uint8_t> (flow::epoch_t::PLAIN): return "без защиты";
			// Если записи защищены ключами рукопожатия
			case static_cast <uint8_t> (flow::epoch_t::HANDSHAKE): return "ключи рукопожатия";
			// Если записи защищены ключами прикладных данных
			case static_cast <uint8_t> (flow::epoch_t::APPLICATION): return "ключи прикладных данных";
		}
		// Выводим название неизвестной поры ключей
		return "неизвестно";
	}
	/**
	 * @brief Метод установки ключевого материала стороны связи
	 *
	 * @param peer настраиваемая сторона связи
	 * @param side направление связи, чей ключевой материал устанавливается
	 *
	 * @return     признак успешности установки ключевого материала
	 *
	 */
	bool install(Peer & peer, const session::side_t side) noexcept {
		// Корневой ключ направления связи
		uint8_t key[protect::PROTECT_KEY];
		// Вектор замены направления связи
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи вывести не удалось
		if(peer.secrets.material(side, SUITE, key, element) != session::error_t::NONE)
			// Выводим отказ установки ключевого материала
			return false;
		// Получаем объект защиты записей настраиваемого направления
		protect::protection_t & protection = ((side == session::side_t::CLIENT) ? peer.client : peer.server);
		// Выводим итог установки ключевого материала направления связи
		return protection.start(SUITE, view_t(key, sizeof(key)), view_t(element, protect::block(SUITE)));
	}
	/**
	 * @brief Метод передачи сообщения рукопожатия встречной стороне
	 *
	 * @param type вид передаваемого сообщения рукопожатия
	 * @param body тело передаваемого сообщения рукопожатия
	 * @param side сторона, отправляющая сообщение рукопожатия
	 *
	 * @return     признак успешности передачи сообщения
	 *
	 */
	bool transfer(const handshake::type_t type, const view_t & body, const session::side_t side) noexcept {
		// Объект составителя исходящих сообщений рукопожатия
		handshake::writer_t writer;
		// Если сообщение рукопожатия составить не удалось
		if(writer.push(type, body) != handshake::error_t::NONE)
			// Выводим отказ передачи сообщения рукопожатия
			return false;
		// Получаем составленное сообщение рукопожатия
		const view_t message = writer.data();
		// Получаем пору ключей отправляющей стороны
		const flow::epoch_t epoch = CLIENT.machine.epoch(side);
		// Накопитель, в который складывается отправляемая запись
		vector <uint8_t> wire;
		// Если записи отправляющей стороны идут без защиты
		if(epoch == flow::epoch_t::PLAIN){
			// Объект нарезчика исходящих записей
			record::writer_t nested;
			// Если сообщение на записи нарезать не удалось
			if(nested.push(record::type_t::HANDSHAKE, record::version_t::TLS12, message) != record::error_t::NONE)
				// Выводим отказ передачи сообщения рукопожатия
				return false;
			// Получаем нарезанные записи сообщения
			const view_t data = nested.data();
			// Выполняем перенос нарезанных записей в накопитель
			wire.assign(data.data, data.data + data.size);
		// Если записи отправляющей стороны защищены
		} else {
			// Получаем объект защиты записей отправляющей стороны
			protect::protection_t & protection = ((side == session::side_t::CLIENT) ? CLIENT.client : CLIENT.server);
			// Если наложить защиту на запись не удалось
			if(protection.seal(record::type_t::HANDSHAKE, message, wire) != protect::error_t::NONE)
				// Выводим отказ передачи сообщения рукопожатия
				return false;
		}
		// Объект сборщика входящих записей принимающей стороны
		record::reader_t reader;
		// Выполняем подачу отправленных байтов сборщику
		reader.push(view_t(wire.data(), wire.size()));
		// Заголовок принятой записи
		record::header_t header;
		// Содержимое принятой записи
		view_t payload;
		// Если принятую запись собрать не удалось
		if(reader.next(header, payload) != record::error_t::NONE)
			// Выводим отказ передачи сообщения рукопожатия
			return false;
		// Накопитель, в который складывается открытое содержимое записи
		vector <uint8_t> opened;
		// Если записи отправляющей стороны защищены
		if(epoch != flow::epoch_t::PLAIN){
			// Получаем объект защиты записей принимающей стороны
			protect::protection_t & protection = ((side == session::side_t::CLIENT) ? SERVER.client : SERVER.server);
			// Истинный вид содержимого принятой записи
			record::type_t inner = record::type_t::NONE;
			// Если снять защиту с принятой записи не удалось
			if(protection.open(header, payload, inner, opened) != protect::error_t::NONE)
				// Выводим отказ передачи сообщения рукопожатия
				return false;
		// Если записи отправляющей стороны идут без защиты
		} else opened.assign(payload.data, payload.data + payload.size);
		// Проверяем схождение принятого сообщения с отправленным
		if((opened.size() != message.size) || (::memcmp(opened.data(), message.data, opened.size()) != 0))
			// Выводим отказ передачи сообщения рукопожатия
			return false;
		// Добавляем сообщение в переписку рукопожатия отправляющей стороны
		CLIENT.transcript.update(message);
		// Добавляем сообщение в переписку рукопожатия принимающей стороны
		SERVER.transcript.update(view_t(opened.data(), opened.size()));
		// Объявляем сообщение ходу рукопожатия отправляющей стороны
		if(CLIENT.machine.accept(type, side) != flow::error_t::NONE)
			// Выводим отказ передачи сообщения рукопожатия
			return false;
		// Объявляем сообщение ходу рукопожатия принимающей стороны
		return (SERVER.machine.accept(type, side) == flow::error_t::NONE);
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
	// Выполняем заведение хода рукопожатия клиентом
	CLIENT.machine.start(flow::role_t::CLIENT);
	// Выполняем заведение хода рукопожатия сервером
	SERVER.machine.start(flow::role_t::SERVER);
	// Выполняем начало переписки рукопожатия клиента
	CLIENT.transcript.start();
	// Выполняем начало переписки рукопожатия сервера
	SERVER.transcript.start();
	// Составляемое приветствие клиента
	hello::client_t greeting;
	// Устанавливаем версию протокола приветствия клиента
	greeting.version = 0x0303;
	// Выполняем выработку случайного значения приветствия клиента
	entropy::bytes(greeting.random, hello::HELLO_RANDOM);
	// Устанавливаем предлагаемый набор шифрования
	greeting.suites = {static_cast <uint16_t> (SUITE)};
	// Устанавливаем перечень способов сжатия
	greeting.methods = {0x00};
	// Накопитель, в который складывается тело приветствия клиента
	vector <uint8_t> body;
	// Выполняем составление тела приветствия клиента
	hello::build(greeting, body);
	// Если приветствие клиента передать не удалось
	if(!::transfer(handshake::type_t::CLIENT, view_t(body.data(), body.size()), session::side_t::CLIENT)){
		// Выводим сообщение об отказе передачи приветствия
		cout << "Передать приветствие клиента не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим пору ключей записей клиента после приветствия
	cout << "Приветствие клиента: " << ::title(CLIENT.machine.epoch(session::side_t::CLIENT)) << endl;
	// Составляемое приветствие сервера
	hello::server_t answer;
	// Устанавливаем версию протокола приветствия сервера
	answer.version = 0x0303;
	// Выполняем выработку случайного значения приветствия сервера
	entropy::bytes(answer.random, hello::HELLO_RANDOM);
	// Устанавливаем выбранный набор шифрования
	answer.suite = static_cast <uint16_t> (SUITE);
	// Выполняем сброс накопителя тела приветствия
	body.clear();
	// Выполняем составление тела приветствия сервера
	hello::build(answer, body);
	// Если приветствие сервера передать не удалось
	if(!::transfer(handshake::type_t::SERVER, view_t(body.data(), body.size()), session::side_t::SERVER)){
		// Выводим сообщение об отказе передачи приветствия
		cout << "Передать приветствие сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим пору ключей записей сторон после приветствия сервера
	cout << "Приветствие сервера: " << ::title(CLIENT.machine.epoch(session::side_t::SERVER)) << endl;
	// Общее значение обмена ключами
	uint8_t shared[64];
	/**
	 * Выполняем выработку общего значения обмена ключами
	 *
	 * @note В настоящей связи оно вычисляется обеими сторонами из открытых частей
	 *       ключей, объявленных приветствиями, и по связи не передаётся вовсе
	 */
	entropy::bytes(shared, sizeof(shared));
	// Хеш переписки рукопожатия на миг вывода ключей рукопожатия
	uint8_t transcript[32];
	// Выполняем получение хеша переписки рукопожатия
	CLIENT.transcript.digest(transcript);
	// Выполняем заведение начальной ступени расписания ключей клиента
	CLIENT.secrets.start(view_t(nullptr, 0));
	// Выполняем заведение начальной ступени расписания ключей сервера
	SERVER.secrets.start(view_t(nullptr, 0));
	// Выполняем вывод ступени рукопожатия расписания ключей клиента
	CLIENT.secrets.handshake(view_t(shared, sizeof(shared)), view_t(transcript, sizeof(transcript)));
	// Выполняем вывод ступени рукопожатия расписания ключей сервера
	SERVER.secrets.handshake(view_t(shared, sizeof(shared)), view_t(transcript, sizeof(transcript)));
	// Если ключевой материал рукопожатия установить не удалось
	if(!::install(CLIENT, session::side_t::CLIENT) || !::install(CLIENT, session::side_t::SERVER) || !::install(SERVER, session::side_t::CLIENT) || !::install(SERVER, session::side_t::SERVER)){
		// Выводим сообщение об отказе установки ключевого материала
		cout << "Установить ключевой материал рукопожатия не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Тело сообщения защищённых расширений
	const uint8_t extensions[2] = {0x00, 0x00};
	// Если защищённые расширения передать не удалось
	if(!::transfer(handshake::type_t::EXTENSIONS, view_t(extensions, sizeof(extensions)), session::side_t::SERVER)){
		// Выводим сообщение об отказе передачи расширений
		cout << "Передать защищённые расширения не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о передаче защищённых расширений
	cout << "Расширения         : переданы под защитой" << endl;
	// Тело сообщения цепочки сертификатов сервера
	const uint8_t certificate[8] = {0x00, 0x00, 0x00, 0x00, 0x03, 0x30, 0x00, 0x00};
	// Если цепочку сертификатов сервера передать не удалось
	if(!::transfer(handshake::type_t::CERTIFICATE, view_t(certificate, sizeof(certificate)), session::side_t::SERVER)){
		// Выводим сообщение об отказе передачи цепочки сертификатов
		cout << "Передать цепочку сертификатов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Тело сообщения подписи владения ключом сервера
	const uint8_t verify[6] = {0x07, 0x09, 0x00, 0x02, 0xAA, 0xBB};
	// Если подпись владения ключом передать не удалось
	if(!::transfer(handshake::type_t::VERIFY, view_t(verify, sizeof(verify)), session::side_t::SERVER)){
		// Выводим сообщение об отказе передачи подписи владения ключом
		cout << "Передать подпись владения ключом не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение о передаче подтверждения подлинности сервера
	cout << "Подлинность сервера: цепочка и подпись переданы" << endl;
	// Ключ завершения рукопожатия сервером
	uint8_t key[32];
	// Выполняем вывод ключа завершения рукопожатия сервером
	SERVER.secrets.finished(session::side_t::SERVER, key);
	// Выполняем получение хеша переписки на миг завершения сервером
	SERVER.transcript.digest(transcript);
	// Тело сообщения завершения рукопожатия сервером
	uint8_t completion[32];
	// Выполняем выработку завершения рукопожатия сервером
	message::finished(view_t(key, sizeof(key)), view_t(transcript, sizeof(transcript)), completion);
	// Если завершение рукопожатия сервером передать не удалось
	if(!::transfer(handshake::type_t::FINISHED, view_t(completion, sizeof(completion)), session::side_t::SERVER)){
		// Выводим сообщение об отказе передачи завершения
		cout << "Передать завершение рукопожатия сервером не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим пору ключей записей сервера после его завершения
	cout << "Завершение сервера : " << ::title(CLIENT.machine.epoch(session::side_t::SERVER)) << endl;
	// Выводим пору ключей записей клиента на тот же миг
	cout << "Записи клиента     : " << ::title(CLIENT.machine.epoch(session::side_t::CLIENT)) << endl;
	// Ключ завершения рукопожатия клиентом
	uint8_t element[32];
	// Выполняем вывод ключа завершения рукопожатия клиентом
	CLIENT.secrets.finished(session::side_t::CLIENT, element);
	// Выполняем получение хеша переписки на миг завершения клиентом
	CLIENT.transcript.digest(transcript);
	// Выполняем выработку завершения рукопожатия клиентом
	message::finished(view_t(element, sizeof(element)), view_t(transcript, sizeof(transcript)), completion);
	// Если завершение рукопожатия клиентом передать не удалось
	if(!::transfer(handshake::type_t::FINISHED, view_t(completion, sizeof(completion)), session::side_t::CLIENT)){
		// Выводим сообщение об отказе передачи завершения
		cout << "Передать завершение рукопожатия клиентом не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если рукопожатие завершено обеими сторонами
	if(CLIENT.machine.established() && SERVER.machine.established())
		// Выводим сообщение о завершении рукопожатия
		cout << "Рукопожатие        : связь установлена обеими сторонами" << endl;
	// Выводим пору ключей записей клиента после его завершения
	cout << "Завершение клиента : " << ::title(CLIENT.machine.epoch(session::side_t::CLIENT)) << endl;
	// Выполняем получение хеша переписки на миг перехода к прикладным данным
	CLIENT.transcript.digest(transcript);
	// Выполняем вывод ступени прикладных данных расписания ключей клиента
	CLIENT.secrets.application(view_t(transcript, sizeof(transcript)));
	// Выполняем вывод ступени прикладных данных расписания ключей сервера
	SERVER.secrets.application(view_t(transcript, sizeof(transcript)));
	// Если ключевой материал прикладных данных установить не удалось
	if(!::install(CLIENT, session::side_t::SERVER) || !::install(SERVER, session::side_t::SERVER)){
		// Выводим сообщение об отказе установки ключевого материала
		cout << "Установить ключевой материал прикладных данных не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Передаваемые сервером прикладные данные
	const char * text = "Прикладные данные, отправленные по установленной связи";
	// Накопитель, в который складывается защищённая запись
	vector <uint8_t> sealed;
	// Выполняем наложение защиты на запись прикладных данных
	CLIENT.server.seal(record::type_t::APPLICATION, view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text)), sealed);
	// Объект сборщика входящих записей
	record::reader_t reader;
	// Выполняем подачу защищённой записи сборщику
	reader.push(view_t(sealed.data(), sealed.size()));
	// Заголовок принятой защищённой записи
	record::header_t header;
	// Содержимое принятой защищённой записи
	view_t payload;
	// Выполняем сборку принятой защищённой записи
	reader.next(header, payload);
	// Истинный вид содержимого принятой записи
	record::type_t type = record::type_t::NONE;
	// Накопитель, в который складывается открытое содержимое записи
	vector <uint8_t> opened;
	// Если снять защиту с принятой записи не удалось
	if(SERVER.server.open(header, payload, type, opened) != protect::error_t::NONE){
		// Выводим сообщение об отказе снятия защиты
		cout << "Снять защиту с прикладных данных не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим принятые прикладные данные
	cout << "Прикладные данные  : " << string(reinterpret_cast <const char *> (opened.data()), opened.size()) << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
