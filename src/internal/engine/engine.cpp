/**
 * @file engine.cpp
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
 * @brief Исходный файл внутреннего модуля ведения связи протокола TLS 1.3
 *
 * @section Намеренные решения
 *
 * 1. Обе роли ведёт один модуль. Клиент и сервер проходят одно и то же рукопожатие с
 *    разных его концов, и почти всё у них общее: расписание ключей, защита записей,
 *    переписка и проверки. Две отдельные связи пришлось бы держать согласованными вручную.
 *
 * 2. Пора ключей записи берётся до объявления сообщения ходу рукопожатия. Приветствие
 *    сервера уходит открытым, а защита появляется лишь за ним: объяви сообщение раньше -
 *    и приветствие ушло бы ключами, которых у встречной стороны ещё нет.
 *
 * 3. Цепочка сертификатов собеседника не проверяется на доверие. Связь сличает подпись
 *    владения ключом с ключом предъявленного сертификата - этим рукопожатие и привязано к
 *    той стороне, - а вот доверие к издателю решается запасом доверенных сертификатов,
 *    которого у связи нет и который принадлежит тому, кто связь ведёт.
 *
 * 4. Ключи завершения рукопожатия снимаются сразу за выводом ступени рукопожатия.
 *    Переход к ступени прикладных данных значения направлений связи переписывает, а
 *    завершение клиента идёт уже после этого перехода.
 *
 * 5. Отказ связи необратим. Всякий отказ рукопожатия смертелен по разделу 6.2 RFC 8446, и
 *    единственное, что после него делают, - отправляют извещение и рвут связь.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/gost.hpp>
#include <x509/x509.hpp>
#include <field/field.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>
#include <x509/signature.hpp>
#include <digest/streebog.hpp>
#include <agreement/ecdhe.hpp>
#include <internal/engine/engine.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace anyks;

	/**
	 * Случайное значение приветствия сервера, объявляющее просьбу о повторе
	 */
	static const uint8_t RETRY[32] = {
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
	};

	/**
	 * Схемы подписи, предлагаемые связью по умолчанию
	 */
	static const extension::scheme_t SCHEMES[] = {
		extension::scheme_t::S256A, extension::scheme_t::S256B,
		extension::scheme_t::S256C, extension::scheme_t::S256D,
		extension::scheme_t::S512A, extension::scheme_t::S512B,
		extension::scheme_t::S512C
	};

	/**
	 * @brief Метод затирания области памяти
	 *
	 * @param data затираемая область памяти
	 * @param size размер затираемой области памяти
	 *
	 */
	static void wipe(void * data, const size_t size) noexcept {
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
		/**
		 * Выполняем перебор байтов затираемой области памяти
		 */
		for(size_t i = 0; i < size; i++)
			// Обнуляем очередной байт области памяти
			item[i] = 0;
	}
	/**
	 * @brief Метод получения места стороны связи в наборах связи
	 *
	 * @param side сторона связи, место которой запрашивается
	 *
	 * @return     место стороны связи в наборах связи
	 *
	 */
	static size_t index(const session::side_t side) noexcept {
		// Выводим место стороны связи в наборах связи
		return ((side == session::side_t::CLIENT) ? 0 : 1);
	}
	/**
	 * @brief Метод составления записи перечня расширений
	 *
	 * @param extensions составляемый перечень расширений
	 * @param result     накопитель, в который складывается запись перечня
	 *
	 * @return           признак успешности составления записи перечня
	 *
	 */
	static bool block(const vector <hello::extension_t> & extensions, vector <uint8_t> & result) noexcept {
		// Объект составителя записи перечня расширений
		field::builder_t builder;
		// Если место под длину перечня расширений занять не удалось
		if(builder.open(2) != field::error_t::NONE)
			// Выводим отказ составления записи перечня
			return false;
		/**
		 * Выполняем перебор составляемых расширений перечня
		 */
		for(size_t i = 0; i < extensions.size(); i++){
			// Если вид расширения записать не удалось
			if(builder.number(extensions[i].type, 2) != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
			// Если место под длину тела расширения занять не удалось
			if(builder.open(2) != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
			// Если тело расширения записать не удалось
			if(builder.bytes(extensions[i].data) != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
			// Если длину тела расширения проставить не удалось
			if(builder.close() != field::error_t::NONE)
				// Выводим отказ составления записи перечня
				return false;
		}
		// Если длину перечня расширений проставить не удалось
		if(builder.close() != field::error_t::NONE)
			// Выводим отказ составления записи перечня
			return false;
		// Получаем составленную запись перечня расширений
		const view_t data = builder.data();
		// Выполняем перенос составленной записи перечня в накопитель
		result.assign(data.data, data.data + data.size);
		// Выводим успешность составления записи перечня расширений
		return true;
	}
	/**
	 * @brief Метод извлечения тела расширения из записи перечня расширений
	 *
	 * @param data   разбираемая запись перечня расширений
	 * @param type   разыскиваемый вид расширения
	 * @param result просмотр, в который помещается тело найденного расширения
	 *
	 * @return       признак того, что расширение в перечне объявлено
	 *
	 */
	static bool announced(const view_t & data, const uint16_t type, view_t & result) noexcept {
		// Объект разборщика записи перечня расширений
		field::scanner_t scanner;
		// Устанавливаем разбираемую запись перечня расширений
		scanner.start(data);
		// Содержимое перечня расширений
		view_t body;
		// Если перечень расширений прочитать не удалось
		if(scanner.vector(body, 2) != field::error_t::NONE)
			// Выводим признак того, что расширение не объявлено
			return false;
		// Объект разборщика записей перечня расширений
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня расширений
		reader.start(body);
		/**
		 * Выполняем перебор объявленных расширений перечня
		 */
		while(reader.left() > 0){
			// Вид очередного расширения перечня
			uint32_t item = 0;
			// Если вид расширения прочитать не удалось
			if(reader.number(item, 2) != field::error_t::NONE)
				// Выводим признак того, что расширение не объявлено
				return false;
			// Тело очередного расширения перечня
			view_t content;
			// Если тело расширения прочитать не удалось
			if(reader.vector(content, 2) != field::error_t::NONE)
				// Выводим признак того, что расширение не объявлено
				return false;
			// Если вид расширения совпал с разыскиваемым
			if(static_cast <uint16_t> (item) == type){
				// Устанавливаем тело найденного расширения
				result = content;
				// Выводим признак того, что расширение объявлено
				return true;
			}
		}
		// Выводим признак того, что расширение не объявлено
		return false;
	}
	/**
	 * @brief Метод разыскания расширения в записи перечня расширений
	 *
	 * @param data разбираемая запись перечня расширений
	 * @param type разыскиваемый вид расширения
	 *
	 * @return     признак того, что расширение в перечне объявлено
	 *
	 */
	static bool declared(const view_t & data, const uint16_t type) noexcept {
		// Тело разыскиваемого расширения перечня
		view_t content;
		// Выводим признак того, что расширение в перечне объявлено
		return announced(data, type, content);
	}
	/**
	 * @brief Метод поиска схемы подписи по опознавателю набора параметров кривой
	 *
	 * @param oid    опознаватель набора параметров кривой открытого ключа
	 * @param result схема подписи, в которую помещается итог поиска
	 *
	 * @return       признак того, что схема подписи для кривой найдена
	 *
	 */
	static bool scheme(const string & oid, extension::scheme_t & result) noexcept {
		/**
		 * Выполняем перебор известных схем подписи
		 */
		for(size_t i = 0; i < (sizeof(SCHEMES) / sizeof(extension::scheme_t)); i++){
			// Получаем опознаватель кривой очередной схемы подписи
			const char * item = extension::curve(SCHEMES[i]);
			// Если опознаватель кривой схемы совпал с искомым
			if((item != nullptr) && (oid.compare(item) == 0)){
				// Запоминаем найденную схему подписи
				result = SCHEMES[i];
				// Выводим признак того, что схема подписи найдена
				return true;
			}
		}
		// Выводим признак того, что схема подписи не найдена
		return false;
	}
};

/**
 * @brief Метод обрыва связи отказом
 *
 * @param error       отказ, которым связь обрывается
 * @param description описание извещения, отправляемого собеседнику
 *
 * @return            отказ, которым связь оборвана
 *
 */
context::error_t anyks::internal::Engine::abort(const context::error_t error, const alert::description_t description) noexcept {
	// Составляем извещение об обрыве связи
	const alert::alert_t alert(alert::level_t::FATAL, description);
	// Место, в которое записывается извещение об обрыве связи
	uint8_t buffer[alert::ALERT_LENGTH];
	// Если извещение об обрыве связи записать удалось
	if(alert::build(alert, buffer) == alert::error_t::NONE)
		// Выполняем складывание извещения в накопитель отправляемых байтов
		this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
	// Запоминаем извещение, которым связь оборвана
	this->_alert = alert;
	// Запоминаем отказ, которым связь оборвана
	this->_error = error;
	// Переводим связь в состояние обрыва
	this->_state = context::state_t::FAILED;
	// Выводим отказ, которым связь оборвана
	return error;
}
/**
 * @brief Метод складывания записи в накопитель отправляемых байтов
 *
 * @param type вид содержимого отправляемой записи
 * @param data содержимое отправляемой записи
 *
 * @return     отказ складывания записи в накопитель
 *
 */
context::error_t anyks::internal::Engine::emit(const record::type_t type, const view_t & data) noexcept {
	// Получаем сторону связи, отправляющую запись
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	/**
	 * Выполняем складывание записи в накопитель
	 */
	try {
		/**
		 * Записи упреждающих данных защищаются своими ключами: сервер о них ещё
		 * ничего не ответил, и ключей рукопожатия у клиента на этот миг нет вовсе
		 */
		if(!this->_server && this->_earlying){
			// Накопитель, в который складывается защищённая запись
			vector <uint8_t> sealed;
			// Если наложить защиту упреждающих данных на запись не удалось
			if(this->_early.seal(type, data, sealed) != protect::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return context::error_t::PROTECTION;
			// Выполняем складывание защищённой записи в накопитель
			this->_wire.insert(this->_wire.end(), sealed.begin(), sealed.end());
		// Если записи своей стороны защищены ключами связи
		} else if(this->_machine.epoch(side) != flow::epoch_t::PLAIN){
			// Накопитель, в который складывается защищённая запись
			vector <uint8_t> sealed;
			// Если наложить защиту на запись не удалось
			if(this->_output.seal(type, data, sealed) != protect::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return context::error_t::PROTECTION;
			// Выполняем складывание защищённой записи в накопитель
			this->_wire.insert(this->_wire.end(), sealed.begin(), sealed.end());
		// Если записи своей стороны идут без защиты
		} else {
			// Объект нарезчика отправляемых записей
			record::writer_t writer;
			// Если содержимое на записи нарезать не удалось
			if(writer.push(type, record::version_t::TLS12, data) != record::error_t::NONE)
				// Выводим отказ нарезки содержимого на записи
				return context::error_t::RECORD;
			// Получаем нарезанные записи содержимого
			const view_t records = writer.data();
			// Выполняем складывание нарезанных записей в накопитель
			this->_wire.insert(this->_wire.end(), records.data, records.data + records.size);
		}
	// Если памяти под накопитель не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность складывания записи в накопитель
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки сообщения рукопожатия собеседнику
 *
 * @param type вид отправляемого сообщения рукопожатия
 * @param body тело отправляемого сообщения рукопожатия
 *
 * @return     отказ отправки сообщения рукопожатия
 *
 */
context::error_t anyks::internal::Engine::send(const handshake::type_t type, const view_t & body) noexcept {
	// Получаем сторону связи, отправляющую сообщение
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если сообщение рукопожатия составить не удалось
	if(writer.push(type, body) != handshake::error_t::NONE)
		// Выводим отказ составления сообщения рукопожатия
		return context::error_t::MESSAGE;
	// Получаем составленное сообщение рукопожатия
	const view_t message = writer.data();
	/**
	 * Запись складывается ключами той поры, которая идёт до объявления сообщения:
	 * приветствие сервера уходит открытым, а защита появляется лишь за ним
	 */
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, message);
	// Если складывание записи в накопитель не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ складывания записи в накопитель
		return error;
	// Если сообщение в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если сообщение ходу рукопожатия объявить не удалось
	if(this->_machine.accept(type, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return context::error_t::ORDER;
	// Выводим итог согласования ключевого материала защиты записей
	return this->refresh();
}
/**
 * @brief Метод согласования ключевого материала защиты записей
 *
 * @return отказ согласования ключевого материала
 *
 */
context::error_t anyks::internal::Engine::refresh() noexcept {
	/**
	 * Ключевой материал прикладных данных выводится за завершением рукопожатия
	 * сервером, а пора ключей стороны переменяется самим этим завершением: до вывода
	 * ставить защите записей нечего
	 */
	if(this->_secrets.stage() != session::stage_t::APPLICATION)
		// Выводим успешность согласования ключевого материала
		return context::error_t::NONE;
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	/**
	 * Выполняем перебор сторон связи
	 */
	for(size_t i = 0; i < 2; i++){
		// Получаем очередную сторону связи
		const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
		// Получаем пору ключей записей стороны связи
		const flow::epoch_t epoch = this->_machine.epoch(side);
		// Если пора ключей стороны связи не переменилась
		if((epoch != flow::epoch_t::APPLICATION) || (this->_epoch[i] == epoch))
			// Переходим к следующей стороне связи
			continue;
		// Получаем объект защиты записей стороны связи
		protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
		// Если ключевой материал прикладных данных установить не удалось
		if(!protection.start(this->_suite, view_t(this->_key[i], protect::PROTECT_KEY), view_t(this->_vector[i], protect::block(this->_suite))))
			// Выводим отказ установки ключевого материала
			return context::error_t::SCHEDULE;
		// Запоминаем пору ключей, установленную защите записей
		this->_epoch[i] = epoch;
	}
	// Выводим успешность согласования ключевого материала
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода ключей рукопожатия связи
 *
 * @param key открытый мимолётный ключ собеседника
 *
 * @return    отказ вывода ключей рукопожатия
 *
 */
context::error_t anyks::internal::Engine::derive(const view_t & key) noexcept {
	// Место, в которое помещается общее значение обмена мимолётными ключами
	uint8_t shared[64];
	// Если общее значение обмена мимолётными ключами выработать не удалось
	if(!agreement::ecdhe(this->_curve, view_t(this->_secret.data(), this->_secret.size()), key, shared))
		// Выводим отказ выработки общего значения обмена
		return context::error_t::EXCHANGE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Признак успешности вывода ключей рукопожатия связи
	bool ok = (this->_transcript.digest(transcript) == session::error_t::NONE);
	/**
	 * Начальная ступень расписания ключей заводится лишь тогда, когда её ещё нет:
	 * при возобновлении связи билетом в неё уже вложен заранее разделённый ключ
	 */
	if(ok && (this->_secrets.stage() == session::stage_t::NONE))
		// Выполняем заведение начальной ступени расписания ключей
		ok = (this->_secrets.start(view_t(nullptr, 0)) == session::error_t::NONE);
	// Если начальная ступень расписания ключей заведена
	if(ok)
		// Выполняем вывод ступени рукопожатия расписания ключей
		ok = (this->_secrets.handshake(view_t(shared, this->_curve.size()), view_t(transcript, sizeof(transcript))) == session::error_t::NONE);
	// Выполняем затирание общего значения обмена мимолётными ключами
	wipe(shared, sizeof(shared));
	// Если ступень рукопожатия расписания ключей вывести не удалось
	if(!ok)
		// Выводим отказ вывода ключевого материала связи
		return context::error_t::SCHEDULE;
	/**
	 * Выполняем перебор сторон связи
	 */
	for(size_t i = 0; i < 2; i++){
		// Получаем очередную сторону связи
		const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
		/**
		 * Ключи завершения рукопожатия снимаются сразу: переход к ступени прикладных
		 * данных значения направлений связи переписывает
		 */
		if(this->_secrets.finished(side, this->_completion[i]) != session::error_t::NONE)
			// Выводим отказ вывода ключей завершения рукопожатия
			return context::error_t::SCHEDULE;
		// Корневой ключ направления связи
		uint8_t material[protect::PROTECT_KEY];
		// Вектор замены направления связи
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи вывести не удалось
		if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала направления
			return context::error_t::SCHEDULE;
		// Получаем сторону связи, которую ведёт модуль
		const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
		// Получаем объект защиты записей стороны связи
		protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
		// Признак успешности установки ключевого материала направления
		const bool installed = protection.start(this->_suite, view_t(material, sizeof(material)), view_t(element, protect::block(this->_suite)));
		// Выполняем затирание вектора замены направления связи
		wipe(element, sizeof(element));
		// Выполняем затирание корневого ключа направления связи
		wipe(material, sizeof(material));
		// Если ключевой материал направления связи установить не удалось
		if(!installed)
			// Выводим отказ установки ключевого материала направления
			return context::error_t::SCHEDULE;
		// Запоминаем пору ключей, установленную защите записей
		this->_epoch[i] = flow::epoch_t::HANDSHAKE;
	}
	// Выводим успешность вывода ключей рукопожатия связи
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода ключей прикладных данных связи
 *
 * @return отказ вывода ключей прикладных данных
 *
 */
context::error_t anyks::internal::Engine::mature() noexcept {
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	// Если ступень прикладных данных расписания ключей вывести не удалось
	if(this->_secrets.application(view_t(transcript, sizeof(transcript))) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала связи
		return context::error_t::SCHEDULE;
	/**
	 * Выполняем перебор сторон связи
	 */
	for(size_t i = 0; i < 2; i++){
		// Получаем очередную сторону связи
		const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
		// Если ключевой материал направления связи вывести не удалось
		if(this->_secrets.material(side, this->_suite, this->_key[i], this->_vector[i]) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала направления
			return context::error_t::SCHEDULE;
	}
	// Выводим успешность вывода ключей прикладных данных связи
	return context::error_t::NONE;
}
/**
 * @brief Метод заведения защиты записей упреждающих данных
 *
 * @return отказ заведения защиты записей упреждающих данных
 *
 */
context::error_t anyks::internal::Engine::earliest() noexcept {
	/**
	 * Ключи упреждающих данных выводятся набором шифрования билета, а не набором
	 * этой связи: раздел 4.2.10 RFC 8446 велит брать тот, каким билет выдан, - иного
	 * согласования на этот миг ещё и не было
	 */
	if(protect::block(this->_ticket) == 0)
		// Выводим отказ неизвестности набора шифрования билета
		return context::error_t::SUITE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	// Если значение упреждающих данных вывести не удалось
	if(this->_secrets.early(view_t(transcript, sizeof(transcript))) != session::error_t::NONE)
		// Выводим отказ вывода значения расписания ключей
		return context::error_t::SCHEDULE;
	// Значение упреждающих данных связи
	uint8_t traffic[schedule::SCHEDULE_SECRET];
	// Если значение упреждающих данных получить не удалось
	if(this->_secrets.early(traffic) != session::error_t::NONE)
		// Выводим отказ вывода значения расписания ключей
		return context::error_t::SCHEDULE;
	// Место, в которое помещается корневой ключ упреждающих данных
	uint8_t material[protect::PROTECT_KEY];
	// Место, в которое помещается вектор замены упреждающих данных
	uint8_t element[protect::PROTECT_VECTOR];
	// Признак успешности вывода ключевого материала упреждающих данных
	bool ok = (session::material(view_t(traffic, sizeof(traffic)), this->_ticket, material, element) == session::error_t::NONE);
	// Если ключевой материал упреждающих данных выведен
	if(ok)
		// Выполняем установку ключевого материала упреждающих данных
		ok = this->_early.start(this->_ticket, view_t(material, sizeof(material)), view_t(element, protect::block(this->_ticket)));
	// Выполняем затирание вектора замены упреждающих данных
	wipe(element, sizeof(element));
	// Выполняем затирание корневого ключа упреждающих данных
	wipe(material, sizeof(material));
	// Выполняем затирание значения упреждающих данных связи
	wipe(traffic, sizeof(traffic));
	// Если ключевой материал упреждающих данных установить не удалось
	if(!ok)
		// Выводим отказ установки ключевого материала
		return context::error_t::SCHEDULE;
	// Запоминаем, что упреждающие данные идут прямо сейчас
	this->_earlying = true;
	// Выводим успешность заведения защиты записей упреждающих данных
	return context::error_t::NONE;
}
/**
 * @brief Метод выработки мимолётной пары ключей своей стороны
 *
 * @param group кривая, для которой вырабатывается пара ключей
 *
 * @return      отказ выработки мимолётной пары ключей
 *
 */
context::error_t anyks::internal::Engine::exchange(const extension::group_t group) noexcept {
	// Получаем опознаватель набора параметров кривой обмена ключами
	const char * oid = extension::curve(group);
	// Если кривая обмена ключами протоколом не определена
	if(oid == nullptr)
		// Выводим отказ неизвестности кривой обмена ключами
		return context::error_t::GROUP;
	// Если кривую обмена мимолётными ключами завести не удалось
	if(!curve::parameters(oid, this->_curve))
		// Выводим отказ заведения кривой обмена ключами
		return context::error_t::GROUP;
	/**
	 * Выполняем выработку мимолётной пары ключей своей стороны
	 */
	try {
		// Занимаем место под секретный мимолётный ключ своей стороны
		this->_secret.assign(this->_curve.size(), 0);
		// Занимаем место под открытый мимолётный ключ своей стороны
		this->_opened.assign(this->_curve.size() * 2, 0);
	// Если памяти под ключи не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если мимолётную пару ключей своей стороны выработать не удалось
	if(!agreement::generate(this->_curve, this->_secret.data(), this->_opened.data()))
		// Выводим отказ выработки мимолётной пары ключей
		return context::error_t::EXCHANGE;
	// Запоминаем кривую обмена мимолётными ключами связи
	this->_group = group;
	// Выводим успешность выработки мимолётной пары ключей
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки приветствия клиента
 *
 * @return отказ отправки приветствия клиента
 *
 */
context::error_t anyks::internal::Engine::greeting() noexcept {
	// Составляемое приветствие клиента
	hello::client_t greeting;
	// Устанавливаем версию протокола, доставшуюся от предыдущих изданий
	greeting.version = 0x0303;
	// Переносим случайное значение своего приветствия
	::memcpy(greeting.random, this->_random, sizeof(this->_random));
	// Устанавливаем опознаватель связи, доставшийся от предыдущих изданий
	greeting.session = this->_session;
	// Устанавливаем перечень способов сжатия
	greeting.methods = {0x00};
	/**
	 * Выполняем перебор предлагаемых наборов шифрования
	 */
	for(size_t i = 0; i < this->_suites.size(); i++)
		// Добавляем очередной набор шифрования в приветствие
		greeting.suites.push_back(static_cast <uint16_t> (this->_suites[i]));
	// Накопители, в которых лежат тела расширений приветствия
	vector <uint8_t> versions, groups, schemes, shares, name, protocols;
	// Если перечень изданий протокола составить не удалось
	if(extension::versions(vector <uint16_t> {0x0304}, versions) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Если перечень кривых обмена ключами составить не удалось
	if(extension::groups(this->_groups, groups) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Перечень предлагаемых схем подписи
	vector <extension::scheme_t> list(SCHEMES, SCHEMES + (sizeof(SCHEMES) / sizeof(extension::scheme_t)));
	// Если перечень схем подписи составить не удалось
	if(extension::schemes(list, schemes) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Открытая часть ключа обмена своей стороны
	const extension::share_t share(this->_group, view_t(this->_opened.data(), this->_opened.size()));
	// Если перечень открытых частей ключей обмена составить не удалось
	if(extension::shares(vector <extension::share_t> {share}, shares) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Добавляем расширение перечня изданий протокола
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(versions.data(), versions.size())));
	// Добавляем расширение перечня кривых обмена ключами
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
	// Добавляем расширение перечня схем подписи
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
	// Добавляем расширение открытых частей ключей обмена
	greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(shares.data(), shares.size())));
	// Если имя узла у сервера запрашивается
	if(!this->_name.empty()){
		// Если имя запрашиваемого узла составить не удалось
		if(extension::name(view_t(reinterpret_cast <const uint8_t *> (this->_name.data()), this->_name.size()), name) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение имени запрашиваемого узла
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(name.data(), name.size())));
	}
	// Если прикладные протоколы связью предлагаются
	if(!this->_protocols.empty()){
		// Если перечень прикладных протоколов составить не удалось
		if(extension::protocols(this->_protocols, protocols) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение перечня прикладных протоколов
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocols.data(), protocols.size())));
	}
	// Накопители, в которых лежат тела расширений возобновления связи
	vector <uint8_t> modes, secret;
	// Место, в которое помещается пустая привязка предъявляемого билета
	uint8_t empty[schedule::SCHEDULE_SECRET];
	// Признак того, что билет возобновления связи предъявляется серверу
	const bool resume = !this->_resume.identity.empty();
	// Если билет возобновления связи предъявляется серверу
	if(resume)
		// Запоминаем набор шифрования предъявляемого билета
		this->_ticket = this->_resume.suite;
	// Если билет возобновления связи предъявляется серверу
	if(resume){
		// Способы обмена, при которых билет годен связи
		const vector <extension::mode_t> list = {extension::mode_t::SHARED};
		// Если перечень способов обмена составить не удалось
		if(extension::modes(list, modes) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение способов обмена заранее разделённым ключом
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(modes.data(), modes.size())));
		// Выполняем обнуление привязки предъявляемого билета
		::memset(empty, 0, sizeof(empty));
		// Если упреждающие данные связью предлагаются
		if(this->_advance)
			/**
			 * Расширение упреждающих данных в приветствии пусто: раздел 4.2.10 RFC 8446
			 * велит объявлять им лишь само намерение, а предел объявлен билетом
			 */
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
		// Опознаватель предъявляемого билета возобновления связи
		const extension::identity_t identity(view_t(this->_resume.identity.data(), this->_resume.identity.size()), this->_resume.age);
		// Привязка предъявляемого билета возобновления связи
		const vector <view_t> binders = {view_t(empty, sizeof(empty))};
		// Если предложение заранее разделённых ключей составить не удалось
		if(extension::identities(vector <extension::identity_t> {identity}, binders, secret) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		/**
		 * Расширение заранее разделённых ключей идёт последним: раздел 4.2.11 RFC 8446
		 * велит ставить его в самый конец, ибо привязка покрывает всё, что идёт до неё
		 */
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(secret.data(), secret.size())));
	}
	// Накопитель, в который складывается тело приветствия клиента
	vector <uint8_t> body;
	// Если тело приветствия клиента составить не удалось
	if(hello::build(greeting, body) != hello::error_t::NONE)
		// Выводим отказ составления приветствия клиента
		return context::error_t::MESSAGE;
	// Если билет возобновления связи серверу не предъявляется
	if(!resume)
		// Выводим итог отправки приветствия клиента
		return this->send(handshake::type_t::CLIENT, view_t(body.data(), body.size()));
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если приветствие клиента составить не удалось
	if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
		// Выводим отказ составления приветствия клиента
		return context::error_t::MESSAGE;
	// Получаем составленное приветствие клиента
	const view_t data = writer.data();
	// Накопитель, в котором приветствие клиента правится привязкой билета
	vector <uint8_t> message;
	/**
	 * Выполняем перенос составленного приветствия клиента
	 */
	try {
		// Выполняем перенос составленного приветствия в накопитель
		message.assign(data.data, data.data + data.size);
	// Если памяти под приветствие не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	/**
	 * Приветствие усекается перед перечнем привязок: два байта длины перечня, байт
	 * длины привязки и сама привязка себя же покрывать не вправе
	 */
	const size_t truncation = (message.size() - (sizeof(empty) + 3));
	// Если начальную ступень расписания ключей завести не удалось
	if(this->_secrets.start(view_t(this->_resume.secret.data(), this->_resume.secret.size())) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала связи
		return context::error_t::SCHEDULE;
	// Место, в которое помещается хеш усечённого приветствия клиента
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш усечённого приветствия получить не удалось
	if(this->_transcript.digest(view_t(message.data(), truncation), transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если привязку предъявляемого билета выработать не удалось
	if(this->_secrets.binder(view_t(transcript, sizeof(transcript)), message.data() + (message.size() - sizeof(empty))) != session::error_t::NONE)
		// Выводим отказ выработки привязки билета
		return context::error_t::SCHEDULE;
	// Выполняем складывание приветствия клиента в накопитель отправляемых байтов
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, view_t(message.data(), message.size()));
	// Если приветствие клиента отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки приветствия клиента
		return error;
	// Если приветствие в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(view_t(message.data(), message.size())) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если приветствие клиента ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return context::error_t::ORDER;
	// Если упреждающие данные связью не предлагаются
	if(!this->_advance)
		// Выводим успешность отправки приветствия клиента
		return context::error_t::NONE;
	// Выводим итог заведения защиты записей упреждающих данных
	return this->earliest();
}
/**
 * @brief Метод отправки приветствия сервера
 *
 * @param session опознаватель связи, повторяемый за приветствием клиента
 * @param retry   признак того, что отправляется просьба о повторе приветствия
 *
 * @return        отказ отправки приветствия сервера
 *
 */
context::error_t anyks::internal::Engine::answer(const vector <uint8_t> & session, const bool retry) noexcept {
	// Составляемое приветствие сервера
	hello::server_t answer;
	// Устанавливаем версию протокола, доставшуюся от предыдущих изданий
	answer.version = 0x0303;
	/**
	 * Просьба о повторе приветствия объявляется заранее назначенным случайным
	 * значением: раздел 4.1.3 RFC 8446
	 */
	if(retry)
		// Переносим случайное значение просьбы о повторе приветствия
		::memcpy(answer.random, RETRY, sizeof(RETRY));
	// Если отправляется само приветствие сервера
	else ::memcpy(answer.random, this->_random, sizeof(this->_random));
	// Устанавливаем опознаватель связи, повторяемый за приветствием клиента
	answer.session = session;
	// Устанавливаем выбранный набор шифрования
	answer.suite = static_cast <uint16_t> (this->_suite);
	// Устанавливаем выбранный способ сжатия
	answer.method = 0x00;
	// Накопители, в которых лежат тела расширений приветствия
	vector <uint8_t> version, share;
	// Если издание протокола составить не удалось
	if(extension::version(0x0304, version) != extension::error_t::NONE)
		// Выводим отказ составления расширения приветствия
		return context::error_t::MESSAGE;
	// Если отправляется просьба о повторе приветствия
	if(retry){
		// Если выбранную кривую обмена ключами составить не удалось
		if(extension::selected(this->_group, share) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
	// Если отправляется само приветствие сервера
	} else {
		// Открытая часть ключа обмена своей стороны
		const extension::share_t item(this->_group, view_t(this->_opened.data(), this->_opened.size()));
		// Если открытую часть ключа обмена составить не удалось
		if(extension::share(item, share) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
	}
	// Добавляем расширение издания протокола
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
	// Добавляем расширение открытой части ключа обмена
	answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(share.data(), share.size())));
	// Накопитель, в котором лежит тело расширения выбранного ключа
	vector <uint8_t> selected;
	// Если связь возобновляется заранее разделённым ключом
	if(this->_shared && !retry){
		// Если выбранный заранее разделённый ключ составить не удалось
		if(extension::chosen(this->_chosen, selected) != extension::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return context::error_t::MESSAGE;
		// Добавляем расширение выбранного заранее разделённого ключа
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(selected.data(), selected.size())));
	}
	// Накопитель, в который складывается тело приветствия сервера
	vector <uint8_t> body;
	// Если тело приветствия сервера составить не удалось
	if(hello::build(answer, body) != hello::error_t::NONE)
		// Выводим отказ составления приветствия сервера
		return context::error_t::MESSAGE;
	// Выводим итог отправки приветствия сервера
	return this->send(handshake::type_t::SERVER, view_t(body.data(), body.size()));
}
/**
 * @brief Метод отправки подтверждения подлинности своей стороны
 *
 * @return отказ отправки подтверждения подлинности
 *
 */
context::error_t anyks::internal::Engine::authenticate() noexcept {
	// Составляемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	/**
	 * Выполняем перебор сертификатов цепочки своей стороны
	 */
	for(size_t i = 0; i < this->_credential.chain.size(); i++){
		// Составляемая запись цепочки сертификатов
		message::entry_t entry;
		// Устанавливаем тело сертификата записи цепочки
		entry.data = view_t(this->_credential.chain[i].data(), this->_credential.chain[i].size());
		// Добавляем запись в цепочку сертификатов
		certificate.entries.push_back(entry);
	}
	// Накопитель, в который складывается тело сообщения цепочки
	vector <uint8_t> body;
	// Если тело сообщения цепочки сертификатов составить не удалось
	if(message::build(certificate, body) != message::error_t::NONE)
		// Выводим отказ составления сообщения цепочки сертификатов
		return context::error_t::MESSAGE;
	// Выполняем отправку цепочки сертификатов своей стороны
	const context::error_t error = this->send(handshake::type_t::CERTIFICATE, view_t(body.data(), body.size()));
	// Если цепочку сертификатов отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки цепочки сертификатов
		return error;
	/**
	 * Пустая цепочка сертификатов подписи владения ключом за собою не влечёт: раздел
	 * 4.4.2 RFC 8446 дозволяет её клиенту, у которого годного сертификата не нашлось
	 */
	if(this->_credential.chain.empty())
		// Выводим успешность отправки подтверждения подлинности
		return context::error_t::NONE;
	// Объект разбора своего сертификата
	x509::certificate_t leaf;
	// Если свой сертификат разобрать не удалось
	if(leaf.parse(view_t(this->_credential.chain[0].data(), this->_credential.chain[0].size())) != x509::error_t::NONE)
		// Выводим отказ разбора своего сертификата
		return context::error_t::CERTIFICATE;
	// Опознаватель набора параметров кривой своего ключа
	string oid;
	// Если опознаватель набора параметров кривой извлечь не удалось
	if(!x509::identifier(leaf.key(), oid))
		// Выводим отказ разбора своего сертификата
		return context::error_t::CERTIFICATE;
	// Схема подписи владения своим ключом
	extension::scheme_t item = extension::scheme_t::NONE;
	// Если схему подписи для кривой своего ключа подобрать не удалось
	if(!scheme(oid, item))
		// Выводим отказ подбора схемы подписи
		return context::error_t::CERTIFICATE;
	// Эллиптическая кривая подписи владения ключом
	curve::curve_t curve;
	// Если кривую своего ключа завести не удалось
	if(!x509::parameters(leaf.key(), curve))
		// Выводим отказ заведения кривой своего ключа
		return context::error_t::CERTIFICATE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Накопитель, в который складывается подписываемое содержимое
	vector <uint8_t> content;
	// Если подписываемое содержимое составить не удалось
	if(message::content(view_t(transcript, sizeof(transcript)), this->_server, content) != message::error_t::NONE)
		// Выводим отказ составления подписываемого содержимого
		return context::error_t::MESSAGE;
	// Место, в которое помещается хеш подписываемого содержимого
	uint8_t digest[64];
	// Определяем длину хеша подписываемого содержимого
	const digest::type_t type = ((curve.size() == 32) ? digest::type_t::SHORT : digest::type_t::LONG);
	// Если хеш подписываемого содержимого выработать не удалось
	if(!digest::streebog(type, view_t(content.data(), content.size()), digest, curve.size(), digest::order_t::VECTOR))
		// Выводим отказ выработки хеша подписываемого содержимого
		return context::error_t::SIGNATURE;
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Если эллиптическую кривую подписи установить не удалось
	if(!gost.start(curve))
		// Выводим отказ установки кривой подписи
		return context::error_t::SIGNATURE;
	// Если секретный ключ своей стороны установить не удалось
	if(!gost.secret(view_t(this->_credential.secret.data(), this->_credential.secret.size())))
		// Выводим отказ установки секретного ключа
		return context::error_t::SIGNATURE;
	// Место, в которое помещается выработанная подпись владения ключом
	uint8_t signature[math::NUMBER_SIZE * 2];
	// Если подпись владения ключом выработать не удалось
	if(!gost.make(view_t(digest, curve.size()), signature))
		// Выводим отказ выработки подписи владения ключом
		return context::error_t::SIGNATURE;
	// Место, в которое помещается подпись в записи протокола
	uint8_t reversed[math::NUMBER_SIZE * 2];
	/**
	 * Раздел 5.3 описания наборов шифрования: обе половины подписи записываются в
	 * протокол младшим байтом вперёд, тогда как выработка даёт их обратной записью
	 */
	if(message::reverse(view_t(signature, gost.size()), reversed) != message::error_t::NONE)
		// Выводим отказ разворота записи подписи
		return context::error_t::SIGNATURE;
	// Составляемое сообщение подписи владения ключом
	message::verify_t verify;
	// Устанавливаем схему подписи владения ключом
	verify.scheme = item;
	// Устанавливаем значение подписи владения ключом
	verify.signature = view_t(reversed, gost.size());
	// Выполняем сброс накопителя тела сообщения
	body.clear();
	// Если тело сообщения подписи владения ключом составить не удалось
	if(message::build(verify, body) != message::error_t::NONE)
		// Выводим отказ составления сообщения подписи владения ключом
		return context::error_t::MESSAGE;
	// Выводим итог отправки подписи владения ключом
	return this->send(handshake::type_t::VERIFY, view_t(body.data(), body.size()));
}
/**
 * @brief Метод отправки завершения рукопожатия своей стороной
 *
 * @return отказ отправки завершения рукопожатия
 *
 */
context::error_t anyks::internal::Engine::complete() noexcept {
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Место, в которое помещается завершение рукопожатия своей стороной
	uint8_t completion[32];
	// Если завершение рукопожатия выработать не удалось
	if(message::finished(view_t(this->_completion[index(side)], sizeof(this->_completion[0])), view_t(transcript, sizeof(transcript)), completion) != message::error_t::NONE)
		// Выводим отказ выработки завершения рукопожатия
		return context::error_t::COMPLETION;
	// Выводим итог отправки завершения рукопожатия своей стороной
	return this->send(handshake::type_t::FINISHED, view_t(completion, sizeof(completion)));
}
/**
 * @brief Метод разбора принятой цепочки сертификатов собеседника
 *
 * @param body тело принятого сообщения цепочки сертификатов
 *
 * @return     отказ разбора цепочки сертификатов
 *
 */
context::error_t anyks::internal::Engine::chain(const view_t & body) noexcept {
	// Разбираемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	// Если сообщение цепочки сертификатов разобрать не удалось
	if(message::parse(body, certificate) != message::error_t::NONE)
		// Выводим отказ разбора сообщения цепочки сертификатов
		return context::error_t::MESSAGE;
	/**
	 * Выполняем перенос цепочки сертификатов собеседника
	 */
	try {
		// Выполняем сброс прежней цепочки сертификатов собеседника
		this->_peer.clear();
		/**
		 * Выполняем перебор записей принятой цепочки сертификатов
		 */
		for(size_t i = 0; i < certificate.entries.size(); i++){
			// Получаем тело сертификата очередной записи цепочки
			const view_t & data = certificate.entries[i].data;
			// Добавляем сертификат в цепочку собеседника
			this->_peer.push_back(vector <uint8_t> (data.data, data.data + data.size));
		}
	// Если памяти под цепочку сертификатов не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность разбора цепочки сертификатов собеседника
	return context::error_t::NONE;
}
/**
 * @brief Метод проверки принятой подписи владения ключом
 *
 * @param body тело принятого сообщения подписи владения ключом
 *
 * @return     отказ проверки подписи владения ключом
 *
 */
context::error_t anyks::internal::Engine::possession(const view_t & body) noexcept {
	// Если цепочка сертификатов собеседника пуста
	if(this->_peer.empty())
		// Выводим отказ отсутствия сертификата собеседника
		return context::error_t::CERTIFICATE;
	// Разбираемое сообщение подписи владения ключом
	message::verify_t verify;
	// Если сообщение подписи владения ключом разобрать не удалось
	if(message::parse(body, verify) != message::error_t::NONE)
		// Выводим отказ разбора сообщения подписи владения ключом
		return context::error_t::MESSAGE;
	// Объект разбора сертификата собеседника
	x509::certificate_t leaf;
	// Если сертификат собеседника разобрать не удалось
	if(leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())) != x509::error_t::NONE)
		// Выводим отказ разбора сертификата собеседника
		return context::error_t::CERTIFICATE;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Накопитель, в который складывается подписанное содержимое
	vector <uint8_t> content;
	// Если подписанное содержимое составить не удалось
	if(message::content(view_t(transcript, sizeof(transcript)), !this->_server, content) != message::error_t::NONE)
		// Выводим отказ составления подписанного содержимого
		return context::error_t::MESSAGE;
	// Место, в которое помещается подпись в записи выработки
	uint8_t signature[math::NUMBER_SIZE * 2];
	// Если запись подписи развернуть не удалось
	if(message::reverse(verify.signature, signature) != message::error_t::NONE)
		// Выводим отказ разворота записи подписи
		return context::error_t::SIGNATURE;
	// Если подпись владения ключом не сошлась
	if(!x509::check(leaf.key(), view_t(content.data(), content.size()), view_t(signature, verify.signature.size)))
		// Выводим отказ проверки подписи владения ключом
		return context::error_t::SIGNATURE;
	// Выводим успешность проверки подписи владения ключом
	return context::error_t::NONE;
}
/**
 * @brief Метод проверки принятого завершения рукопожатия
 *
 * @param body тело принятого сообщения завершения рукопожатия
 *
 * @return     отказ проверки завершения рукопожатия
 *
 */
context::error_t anyks::internal::Engine::confirm(const view_t & body) noexcept {
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Место, в которое помещается ожидаемое завершение рукопожатия
	uint8_t completion[32];
	// Если ожидаемое завершение рукопожатия выработать не удалось
	if(message::finished(view_t(this->_completion[index(side)], sizeof(this->_completion[0])), view_t(transcript, sizeof(transcript)), completion) != message::error_t::NONE)
		// Выводим отказ выработки завершения рукопожатия
		return context::error_t::COMPLETION;
	/**
	 * Сличение ведётся за постоянное время: по времени сличения восстанавливается
	 * ожидаемое завершение, а с ним и подделка рукопожатия
	 */
	if(!message::compare(body, view_t(completion, sizeof(completion))))
		// Выводим отказ схождения завершения рукопожатия
		return context::error_t::COMPLETION;
	// Выводим успешность проверки завершения рукопожатия
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора предложения заранее разделённых ключей клиента
 *
 * @param extensions перечень расширений принятого приветствия клиента
 * @param message    принятое приветствие клиента вместе с обвязкой
 *
 * @return           отказ разбора предложения заранее разделённых ключей
 *
 */
context::error_t anyks::internal::Engine::offered(const vector <hello::extension_t> & extensions, const view_t & message) noexcept {
	// Разыскиваем расширение заранее разделённых ключей клиента
	const hello::extension_t * offer = hello::extension(extensions, static_cast <uint16_t> (extension::type_t::SECRET));
	// Если заранее разделённых ключей клиент не предлагает либо признавать их нечем
	if((offer == nullptr) || this->_store.empty())
		// Выводим успешность разбора предложения заранее разделённых ключей
		return context::error_t::NONE;
	// Разыскиваем расширение способов обмена заранее разделённым ключом
	const hello::extension_t * item = hello::extension(extensions, static_cast <uint16_t> (extension::type_t::MODES));
	// Если способы обмена заранее разделённым ключом клиент не объявил
	if(item == nullptr)
		// Выводим отказ отсутствия обязательного расширения
		return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
	// Способы обмена, объявленные клиентом
	vector <extension::mode_t> modes;
	// Если способы обмена разобрать не удалось
	if(extension::modes(item->data, modes) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Признак того, что обмен ключом кривой вместе с билетом клиентом объявлен
	bool suitable = false;
	/**
	 * Выполняем перебор способов обмена, объявленных клиентом
	 */
	for(size_t i = 0; (i < modes.size()) && !suitable; i++)
		// Запоминаем объявление обмена ключом кривой вместе с билетом
		suitable = (modes[i] == extension::mode_t::SHARED);
	/**
	 * Обмен одним лишь билетом связью не ведётся: без ключа кривой хищение билета
	 * выдаёт всё, что этим билетом когда-либо защищено
	 */
	if(!suitable)
		// Выводим успешность разбора предложения заранее разделённых ключей
		return context::error_t::NONE;
	// Перечень опознавателей заранее разделённых ключей клиента
	vector <extension::identity_t> identities;
	// Перечень привязок заранее разделённых ключей клиента
	vector <view_t> binders;
	// Длина усечения приветствия от начала тела расширения
	size_t truncation = 0;
	// Если предложение заранее разделённых ключей разобрать не удалось
	if(extension::identities(offer->data, identities, binders, truncation) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Место найденного билета в перечне признаваемых
	size_t found = this->_store.size();
	// Место предъявленного ключа в предложении клиента
	size_t chosen = 0;
	/**
	 * Выполняем перебор опознавателей ключей, предложенных клиентом
	 */
	for(size_t i = 0; (i < identities.size()) && (found == this->_store.size()); i++){
		/**
		 * Выполняем перебор билетов, признаваемых сервером
		 */
		for(size_t j = 0; j < this->_store.size(); j++){
			// Если длина опознавателя с длиной признаваемого билета не совпала
			if(identities[i].identity.size != this->_store[j].identity.size())
				// Переходим к следующему признаваемому билету
				continue;
			// Если опознаватель совпал с признаваемым билетом
			if(::memcmp(identities[i].identity.data, this->_store[j].identity.data(), identities[i].identity.size) == 0){
				// Запоминаем место найденного билета в перечне признаваемых
				found = j;
				// Запоминаем место предъявленного ключа в предложении клиента
				chosen = i;
				// Прекращаем перебор признаваемых билетов
				break;
			}
		}
	}
	// Если ни один из предложенных ключей сервером не признан
	if(found == this->_store.size())
		// Выводим успешность разбора предложения: связь идёт полным рукопожатием
		return context::error_t::NONE;
	// Если начальную ступень расписания ключей завести не удалось
	if(this->_secrets.start(view_t(this->_store[found].secret.data(), this->_store[found].secret.size())) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала связи
		return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
	/**
	 * Длина усечения отсчитывается от начала сообщения: тело расширения лежит внутри
	 * него, и место его начала к длине усечения и прибавляется
	 */
	const size_t offset = (static_cast <size_t> (offer->data.data - message.data) + truncation);
	// Если длина усечения за приветствие вышла
	if(offset > message.size)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Место, в которое помещается хеш усечённого приветствия клиента
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш усечённого приветствия получить не удалось
	if(this->_transcript.digest(view_t(message.data, offset), transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Место, в которое помещается ожидаемая привязка билета
	uint8_t expected[schedule::SCHEDULE_SECRET];
	// Если ожидаемую привязку билета выработать не удалось
	if(this->_secrets.binder(view_t(transcript, sizeof(transcript)), expected) != session::error_t::NONE)
		// Выводим отказ выработки привязки билета
		return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
	/**
	 * Привязка сличается за постоянное время: по времени сличения восстанавливается
	 * ожидаемая привязка, а с нею и подделка владения билетом
	 */
	if(!message::compare(binders[chosen], view_t(expected, sizeof(expected)))){
		// Выполняем сброс значений расписания ключей связи
		this->_secrets.clear();
		// Выводим отказ схождения привязки предъявленного билета
		return this->abort(context::error_t::SIGNATURE, alert::description_t::DECRYPT);
	}
	// Запоминаем набор шифрования признанного билета
	this->_ticket = this->_store[found].suite;
	// Запоминаем место выбранного ключа в предложении клиента
	this->_chosen = static_cast <uint16_t> (chosen);
	// Запоминаем возобновление связи заранее разделённым ключом
	this->_shared = true;
	// Выводим успешность разбора предложения заранее разделённых ключей
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого приветствия клиента
 *
 * @param body    тело принятого приветствия клиента
 * @param message принятое приветствие клиента вместе с обвязкой
 *
 * @return        отказ разбора приветствия клиента
 *
 */
context::error_t anyks::internal::Engine::incoming(const view_t & body, const view_t & message) noexcept {
	// Разбираемое приветствие клиента
	hello::client_t greeting;
	// Если приветствие клиента разобрать не удалось
	if(hello::parse(body, greeting) != hello::error_t::NONE)
		// Выводим отказ разбора приветствия клиента
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Разыскиваем расширение перечня изданий протокола
	const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
	// Если перечень изданий протокола приветствием не объявлен
	if(extension == nullptr)
		// Выводим отказ отсутствия издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::MISSING);
	// Перечень изданий протокола, предлагаемых клиентом
	vector <uint16_t> versions;
	// Если перечень изданий протокола разобрать не удалось
	if(extension::versions(extension->data, versions) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Признак того, что издание протокола связи клиентом предложено
	bool suitable = false;
	/**
	 * Выполняем перебор изданий протокола, предлагаемых клиентом
	 */
	for(size_t i = 0; (i < versions.size()) && !suitable; i++)
		// Запоминаем предложение издания протокола связи
		suitable = (versions[i] == 0x0304);
	// Если издание протокола связи клиентом не предложено
	if(!suitable)
		// Выводим отказ несовпадения издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
	// Признак того, что общий набор шифрования у сторон нашёлся
	suitable = false;
	/**
	 * Выполняем перебор наборов шифрования, предлагаемых связью
	 */
	for(size_t i = 0; (i < this->_suites.size()) && !suitable; i++){
		/**
		 * Выполняем перебор наборов шифрования, предлагаемых клиентом
		 */
		for(size_t j = 0; (j < greeting.suites.size()) && !suitable; j++){
			// Если набор шифрования предложен обеими сторонами
			if(greeting.suites[j] == static_cast <uint16_t> (this->_suites[i])){
				// Запоминаем выбранный набор шифрования связи
				this->_suite = this->_suites[i];
				// Запоминаем, что общий набор шифрования нашёлся
				suitable = true;
			}
		}
	}
	// Если общего набора шифрования у сторон не нашлось
	if(!suitable)
		// Выводим отказ отсутствия общего набора шифрования
		return this->abort(context::error_t::SUITE, alert::description_t::HANDSHAKE);
	// Разыскиваем расширение имени запрашиваемого узла
	extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::NAME));
	// Если имя запрашиваемого узла приветствием объявлено
	if(extension != nullptr){
		// Имя узла, запрошенное клиентом у сервера
		view_t host;
		// Если имя запрашиваемого узла разобрать не удалось
		if(extension::name(extension->data, host) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			/**
			 * Имя узла сервером лишь принимается: раздел 3 RFC 6066 велит выбирать по нему
			 * подлинность своей стороны, а выбор этот принадлежит потребителю, который
			 * подлинность и устанавливает
			 */
			this->_name.assign(reinterpret_cast <const char *> (host.data), host.size);
		/**
		 * Если памяти под имя запрашиваемого узла не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
		}
	}
	// Если прикладные протоколы сервером признаются
	if(!this->_protocols.empty()){
		// Разыскиваем расширение перечня прикладных протоколов
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::PROTOCOLS));
		// Если прикладные протоколы приветствием объявлены
		if(extension != nullptr){
			// Перечень прикладных протоколов, предложенных клиентом
			vector <string> offer;
			// Если перечень прикладных протоколов разобрать не удалось
			if(extension::protocols(extension->data, offer) != extension::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			/**
			 * Выполняем перехват ошибок работы с памятью
			 */
			try {
				/**
				 * Выбор идёт порядком сервера, а не клиента: раздел 3.2 RFC 7301 велит
				 * выбирать протокол серверу, и порядок его перечня - это и есть его
				 * предпочтение
				 */
				for(size_t i = 0; (i < this->_protocols.size()) && this->_protocol.empty(); i++){
					/**
					 * Выполняем перебор прикладных протоколов, предложенных клиентом
					 */
					for(size_t j = 0; (j < offer.size()) && this->_protocol.empty(); j++){
						// Если прикладной протокол предложен обеими сторонами
						if(offer[j].compare(this->_protocols[i]) == 0)
							// Запоминаем выбранный сторонами прикладной протокол
							this->_protocol = this->_protocols[i];
					}
				}
			/**
			 * Если памяти под название протокола не хватило
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
			}
			// Если общего прикладного протокола у сторон не нашлось
			if(this->_protocol.empty())
				// Выводим отказ отсутствия общего прикладного протокола
				return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
		}
	}
	// Выполняем разбор предложения заранее разделённых ключей клиента
	const context::error_t offered = this->offered(greeting.extensions, message);
	// Если предложение заранее разделённых ключей разобрать не удалось
	if(offered != context::error_t::NONE)
		// Выводим отказ разбора предложения заранее разделённых ключей
		return offered;
	/**
	 * Приветствие ложится в переписку лишь теперь: привязка билета берётся от
	 * переписки без него, и добавь его раньше - привязка не сошлась бы
	 */
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Если приветствие клиента ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Если упреждающие данные клиентом предложены
	if(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::EARLY)) != nullptr){
		/**
		 * Упреждающие данные принимаются лишь при возобновлении связи билетом: ключи
		 * их выводятся из заранее разделённого ключа, которого при полном рукопожатии
		 * попросту нет
		 */
		if(this->_advance && this->_shared){
			/**
			 * Ключи упреждающих данных выводятся от переписки с одним лишь приветствием
			 * клиента: ответа сервера в ней на этот миг ещё нет, и завестись им надо
			 * прежде вывода ключей рукопожатия
			 */
			const context::error_t outcome = this->earliest();
			// Если защиту записей упреждающих данных завести не удалось
			if(outcome != context::error_t::NONE)
				// Выводим отказ заведения защиты записей
				return this->abort(outcome, alert::description_t::INTERNAL);
			// Запоминаем приём упреждающих данных клиента
			this->_accepted = true;
		/**
		 * Отвергнутые упреждающие данные прочесть нечем, и записи их пропускаются:
		 * число пропусков ограничено, иначе им открылся бы бесконечный поток
		 */
		} else this->_skipped = 16;
	}
	// Разыскиваем расширение открытых частей ключей обмена
	extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
	// Перечень открытых частей ключей обмена, объявленных клиентом
	vector <extension::share_t> shares;
	// Если открытые части ключей обмена приветствием объявлены
	if(extension != nullptr){
		// Если перечень открытых частей ключей обмена разобрать не удалось
		if(extension::shares(extension->data, shares) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	}
	// Открытая часть ключа обмена, выбранная сервером
	const extension::share_t * selected = nullptr;
	/**
	 * Выполняем перебор кривых обмена ключами, предлагаемых связью
	 */
	for(size_t i = 0; (i < this->_groups.size()) && (selected == nullptr); i++){
		/**
		 * Выполняем перебор открытых частей ключей обмена клиента
		 */
		for(size_t j = 0; (j < shares.size()) && (selected == nullptr); j++){
			// Если открытая часть ключа обмена отвечает предлагаемой кривой
			if(shares[j].group == this->_groups[i])
				// Запоминаем выбранную открытую часть ключа обмена
				selected = &shares[j];
		}
	}
	// Если открытой части ключа обмена по общей кривой у клиента не нашлось
	if(selected == nullptr){
		// Если повтор приветствия клиента уже был
		if(this->_retried)
			// Выводим отказ отсутствия общей кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
		// Разыскиваем расширение перечня кривых обмена ключами
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
		// Если перечень кривых обмена ключами приветствием не объявлен
		if(extension == nullptr)
			// Выводим отказ отсутствия кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::MISSING);
		// Перечень кривых обмена ключами, поддерживаемых клиентом
		vector <extension::group_t> groups;
		// Если перечень кривых обмена ключами разобрать не удалось
		if(extension::groups(extension->data, groups) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Признак того, что общая кривая обмена ключами у сторон нашлась
		suitable = false;
		/**
		 * Выполняем перебор кривых обмена ключами, предлагаемых связью
		 */
		for(size_t i = 0; (i < this->_groups.size()) && !suitable; i++){
			/**
			 * Выполняем перебор кривых обмена ключами, поддерживаемых клиентом
			 */
			for(size_t j = 0; (j < groups.size()) && !suitable; j++){
				// Если кривая обмена ключами поддержана обеими сторонами
				if(groups[j] == this->_groups[i]){
					// Запоминаем выбранную кривую обмена ключами
					this->_group = this->_groups[i];
					// Запоминаем, что общая кривая обмена ключами нашлась
					suitable = true;
				}
			}
		}
		// Если общей кривой обмена ключами у сторон не нашлось
		if(!suitable)
			// Выводим отказ отсутствия общей кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
		/**
		 * Переписка рукопожатия заменяется хешем приветствия клиента: раздел 4.4.1
		 * RFC 8446 велит поступать так всякий раз при просьбе о повторе приветствия
		 */
		if(this->_transcript.replace() != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Выполняем отправку просьбы о повторе приветствия клиента
		const context::error_t error = this->answer(greeting.session, true);
		// Если просьбу о повторе приветствия отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки просьбы о повторе приветствия
			return this->abort(error, alert::description_t::INTERNAL);
		// Если просьбу о повторе приветствия ходу рукопожатия объявить не удалось
		if(this->_machine.retry() != flow::error_t::NONE)
			// Выводим отказ объявления просьбы не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Запоминаем, что повтор приветствия клиента уже был
		this->_retried = true;
		// Выводим успешность разбора приветствия клиента
		return context::error_t::NONE;
	}
	// Если открытая часть ключа обмена клиента непригодна
	if((selected->key.data == nullptr) || (selected->key.size == 0))
		// Выводим отказ непригодности открытой части ключа обмена
		return this->abort(context::error_t::EXCHANGE, alert::description_t::PARAMETER);
	// Открытая часть ключа обмена клиента, из которой выводятся ключи связи
	const vector <uint8_t> key(selected->key.data, selected->key.data + selected->key.size);
	// Выполняем выработку мимолётной пары ключей своей стороны
	context::error_t error = this->exchange(selected->group);
	// Если мимолётную пару ключей выработать не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ выработки мимолётной пары ключей
		return this->abort(error, alert::description_t::HANDSHAKE);
	// Выполняем выработку случайного значения своего приветствия
	if(!entropy::bytes(this->_random, sizeof(this->_random)))
		// Выводим отказ выработки случайного значения приветствия
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Выполняем отправку приветствия сервера
	error = this->answer(greeting.session, false);
	// Если приветствие сервера отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки приветствия сервера
		return this->abort(error, alert::description_t::INTERNAL);
	// Выполняем вывод ключей рукопожатия связи
	error = this->derive(view_t(key.data(), key.size()));
	// Если ключи рукопожатия связи вывести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ вывода ключей рукопожатия связи
		return this->abort(error, alert::description_t::HANDSHAKE);
	// Перечень расширений, объявляемых сервером под защитой
	vector <hello::extension_t> items;
	// Накопитель, в котором лежит тело расширения прикладного протокола
	vector <uint8_t> protocol;
	// Если упреждающие данные клиента приняты
	if(this->_accepted)
		// Объявляем клиенту приём упреждающих данных
		items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
	/**
	 * Имя узла подтверждается пустым расширением: раздел 3 RFC 6066 велит серверу лишь
	 * объявить, что имя принято, а самого имени в ответ не возвращать
	 */
	if(!this->_name.empty())
		// Объявляем клиенту приём имени запрашиваемого узла
		items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(nullptr, 0)));
	// Если прикладной протокол сторонами выбран
	if(!this->_protocol.empty()){
		// Если выбранный прикладной протокол составить не удалось
		if(extension::protocol(this->_protocol, protocol) != extension::error_t::NONE)
			// Выводим отказ составления сообщения защищённых расширений
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Объявляем клиенту выбранный прикладной протокол
		items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocol.data(), protocol.size())));
	}
	// Накопитель, в который складывается тело защищённых расширений
	vector <uint8_t> extensions;
	// Если тело сообщения защищённых расширений составить не удалось
	if(!block(items, extensions))
		// Выводим отказ составления сообщения защищённых расширений
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Выполняем отправку защищённых расширений сервера
	error = this->send(handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size()));
	// Если защищённые расширения отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки защищённых расширений
		return this->abort(error, alert::description_t::INTERNAL);
	// Если подлинность клиента сервером запрашивается
	if(this->_request){
		// Объект составителя тела запроса подлинности клиента
		field::builder_t builder;
		// Если пустую привязку запроса записать не удалось
		if(builder.number(0, 1) != field::error_t::NONE)
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Накопитель, в который складывается тело расширения схем подписи
		vector <uint8_t> schemes;
		// Перечень предлагаемых схем подписи
		const vector <extension::scheme_t> offer(SCHEMES, SCHEMES + (sizeof(SCHEMES) / sizeof(extension::scheme_t)));
		// Если перечень схем подписи составить не удалось
		if(extension::schemes(offer, schemes) != extension::error_t::NONE)
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Перечень расширений запроса подлинности клиента
		vector <hello::extension_t> list;
		// Добавляем расширение перечня схем подписи
		list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Накопитель, в который складывается запись перечня расширений
		vector <uint8_t> record;
		// Если запись перечня расширений составить не удалось
		if(!block(list, record))
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если запись перечня расширений в тело запроса добавить не удалось
		if(builder.bytes(view_t(record.data(), record.size())) != field::error_t::NONE)
			// Выводим отказ составления запроса подлинности клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Получаем составленное тело запроса подлинности клиента
		const view_t request = builder.data();
		// Выполняем отправку запроса подлинности клиента
		error = this->send(handshake::type_t::REQUEST, request);
		// Если запрос подлинности клиента отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки запроса подлинности клиента
			return this->abort(error, alert::description_t::INTERNAL);
	}
	/**
	 * Подлинность сервера предъявляется лишь вне возобновления связи: раздел 2.2
	 * RFC 8446 велит при возобновлении опираться на заранее разделённый ключ, которым
	 * стороны уже опознали друг друга прошлой связью
	 */
	if(!this->_shared){
		// Выполняем отправку подтверждения подлинности сервера
		error = this->authenticate();
		// Если подтверждение подлинности сервера отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки подтверждения подлинности
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Выполняем отправку завершения рукопожатия сервером
	error = this->complete();
	// Если завершение рукопожатия сервером отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки завершения рукопожатия
		return this->abort(error, alert::description_t::INTERNAL);
	// Выполняем вывод ключей прикладных данных связи
	error = this->mature();
	// Если ключи прикладных данных вывести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ вывода ключей прикладных данных
		return this->abort(error, alert::description_t::INTERNAL);
	// Выполняем согласование ключевого материала защиты записей
	error = this->refresh();
	// Если ключевой материал защиты записей согласовать не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ согласования ключевого материала
		return this->abort(error, alert::description_t::INTERNAL);
	// Выводим успешность разбора приветствия клиента
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого приветствия сервера
 *
 * @param body    тело принятого приветствия сервера
 * @param message принятое приветствие сервера вместе с обвязкой
 *
 * @return        отказ разбора приветствия сервера
 *
 */
context::error_t anyks::internal::Engine::outgoing(const view_t & body, const view_t & message) noexcept {
	// Разбираемое приветствие сервера
	hello::server_t answer;
	// Если приветствие сервера разобрать не удалось
	if(hello::parse(body, answer) != hello::error_t::NONE)
		// Выводим отказ разбора приветствия сервера
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Разыскиваем расширение открытой части ключа обмена
	const hello::extension_t * extension = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
	// Если открытая часть ключа обмена приветствием не объявлена
	if(extension == nullptr)
		// Выводим отказ отсутствия открытой части ключа обмена
		return this->abort(context::error_t::EXCHANGE, alert::description_t::MISSING);
	/**
	 * Просьба о повторе приветствия идёт тем же сообщением, что и приветствие сервера,
	 * и отличается лишь заранее назначенным случайным значением
	 */
	if(hello::retry(answer)){
		// Кривая обмена ключами, выбранная сервером
		extension::group_t group = extension::group_t::NONE;
		// Если выбранную сервером кривую обмена ключами разобрать не удалось
		if(extension::selected(extension->data, group) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Переписка рукопожатия заменяется хешем приветствия клиента: раздел 4.4.1
		 * RFC 8446 велит поступать так всякий раз при просьбе о повторе приветствия
		 */
		if(this->_transcript.replace() != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если просьбу о повторе в переписку рукопожатия добавить не удалось
		if(this->_transcript.update(message) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если просьбу о повторе ходу рукопожатия объявить не удалось
		if(this->_machine.accept(handshake::type_t::SERVER, session::side_t::SERVER) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Если просьба о повторе приветствия ходом рукопожатия отвергнута
		if(this->_machine.retry() != flow::error_t::NONE)
			// Выводим отказ объявления просьбы не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Выполняем выработку мимолётной пары ключей на выбранной кривой
		context::error_t error = this->exchange(group);
		// Если мимолётную пару ключей выработать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ выработки мимолётной пары ключей
			return this->abort(error, alert::description_t::HANDSHAKE);
		// Выполняем отправку повторного приветствия клиента
		error = this->greeting();
		// Если повторное приветствие клиента отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки приветствия клиента
			return this->abort(error, alert::description_t::INTERNAL);
		// Запоминаем, что повтор приветствия клиента уже был
		this->_retried = true;
		// Выводим успешность разбора просьбы о повторе приветствия
		return context::error_t::NONE;
	}
	// Разыскиваем расширение издания протокола
	const hello::extension_t * item = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
	// Если издание протокола приветствием не объявлено
	if(item == nullptr)
		// Выводим отказ отсутствия издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::MISSING);
	// Издание протокола, выбранное сервером
	uint16_t version = 0;
	// Если издание протокола разобрать не удалось
	if(extension::version(item->data, version) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Если сервер выбрал издание протокола, связью не поддержанное
	if(version != 0x0304)
		// Выводим отказ несовпадения издания протокола
		return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
	// Признак того, что выбранный сервером набор шифрования связью предложен
	bool suitable = false;
	/**
	 * Выполняем перебор наборов шифрования, предлагаемых связью
	 */
	for(size_t i = 0; (i < this->_suites.size()) && !suitable; i++)
		// Запоминаем совпадение выбранного набора шифрования с предложенным
		suitable = (answer.suite == static_cast <uint16_t> (this->_suites[i]));
	// Если сервер выбрал набор шифрования, связью не предложенный
	if(!suitable)
		// Выводим отказ несовпадения набора шифрования
		return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
	// Запоминаем выбранный сервером набор шифрования
	this->_suite = static_cast <protect::suite_t> (answer.suite);
	// Разыскиваем расширение выбранного заранее разделённого ключа
	const hello::extension_t * selected = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SECRET));
	// Если сервер выбрал заранее разделённый ключ клиента
	if(selected != nullptr){
		// Место выбранного сервером ключа в предложении клиента
		uint16_t chosen = 0;
		// Если выбранный сервером ключ разобрать не удалось
		if(extension::chosen(selected->data, chosen) != extension::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Клиент предлагает единственный ключ, и всякое иное его место есть выбор
		 * того, чего клиент не предлагал вовсе
		 */
		if((chosen != 0) || this->_resume.identity.empty())
			// Выводим отказ несовпадения заранее разделённого ключа
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Запоминаем возобновление связи заранее разделённым ключом
		this->_shared = true;
	/**
	 * Сервер вправе билет и не признать: тогда связь идёт полным рукопожатием, а
	 * начальная ступень расписания заводится заново - уже без ключа билета
	 */
	} else if(this->_secrets.stage() != session::stage_t::NONE)
		// Выполняем сброс значений расписания ключей связи
		this->_secrets.clear();
	// Открытая часть ключа обмена сервера
	extension::share_t share;
	// Если открытую часть ключа обмена сервера разобрать не удалось
	if(extension::share(extension->data, share) != extension::error_t::NONE)
		// Выводим отказ разбора расширения приветствия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Если сервер выбрал кривую обмена ключами, о которой его не просили
	if(share.group != this->_group)
		// Выводим отказ несовпадения кривой обмена ключами
		return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
	// Открытая часть ключа обмена сервера, из которой выводятся ключи связи
	const vector <uint8_t> key(share.key.data, share.key.data + share.key.size);
	// Если приветствие сервера в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Если приветствие сервера ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::SERVER, session::side_t::SERVER) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Выполняем вывод ключей рукопожатия связи
	const context::error_t error = this->derive(view_t(key.data(), key.size()));
	// Если ключи рукопожатия связи вывести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ вывода ключей рукопожатия связи
		return this->abort(error, alert::description_t::HANDSHAKE);
	// Выводим успешность разбора приветствия сервера
	return context::error_t::NONE;
}
/**
 * @brief Метод смены ключевого материала направления связи
 *
 * @param side сторона, чьё направление связи сменяется
 *
 * @return     отказ смены ключевого материала направления
 *
 */
context::error_t anyks::internal::Engine::rotate(const session::side_t side) noexcept {
	// Если значение направления связи сменить не удалось
	if(this->_secrets.renew(side) != session::error_t::NONE)
		// Выводим отказ смены значения направления связи
		return context::error_t::SCHEDULE;
	// Место, в которое помещается корневой ключ направления связи
	uint8_t material[protect::PROTECT_KEY];
	// Место, в которое помещается вектор замены направления связи
	uint8_t element[protect::PROTECT_VECTOR];
	// Если ключевой материал направления связи вывести не удалось
	if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала направления
		return context::error_t::SCHEDULE;
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Получаем объект защиты записей стороны связи
	protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
	/**
	 * Установка ключевого материала обнуляет и счётчик записей направления: раздел
	 * 5.3 RFC 8446 велит считать записи заново от смены ключей
	 */
	const bool installed = protection.start(this->_suite, view_t(material, sizeof(material)), view_t(element, protect::block(this->_suite)));
	// Выполняем затирание вектора замены направления связи
	wipe(element, sizeof(element));
	// Выполняем затирание корневого ключа направления связи
	wipe(material, sizeof(material));
	// Выводим итог установки ключевого материала направления связи
	return (installed ? context::error_t::NONE : context::error_t::SCHEDULE);
}
/**
 * @brief Метод разбора принятой смены ключевого материала
 *
 * @param body тело принятого сообщения смены ключевого материала
 *
 * @return     отказ разбора смены ключевого материала
 *
 */
context::error_t anyks::internal::Engine::renew(const view_t & body) noexcept {
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ прихода смены ключей не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	// Разбираемый вид смены ключевого материала
	message::update_t update = message::update_t::NOTIFY;
	// Если сообщение смены ключевого материала разобрать не удалось
	if(message::parse(body, update) != message::error_t::NONE)
		// Выводим отказ разбора сообщения смены ключевого материала
		return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
	// Если смену ключей собеседника ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::UPDATE, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Выполняем смену ключевого материала направления собеседника
	const context::error_t error = this->rotate(side);
	// Если ключевой материал направления собеседника сменить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ смены ключевого материала направления
		return this->abort(error, alert::description_t::INTERNAL);
	// Если собеседник просит сменить ключи своего направления в ответ
	if(update == message::update_t::REQUEST)
		// Выводим итог смены ключевого материала своего направления
		return this->update(false);
	// Выводим успешность разбора смены ключевого материала
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода значения возобновления связи
 *
 * @return отказ вывода значения возобновления связи
 *
 */
context::error_t anyks::internal::Engine::keeping() noexcept {
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_SECRET];
	// Если хеш переписки рукопожатия получить не удалось
	if(this->_transcript.digest(transcript) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	// Если значение возобновления связи вывести не удалось
	if(this->_secrets.resumption(view_t(transcript, sizeof(transcript))) != session::error_t::NONE)
		// Выводим отказ вывода значения расписания ключей
		return context::error_t::SCHEDULE;
	// Выводим успешность вывода значения возобновления связи
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого билета возобновления связи
 *
 * @param body тело принятого сообщения билета
 *
 * @return     отказ разбора билета возобновления связи
 *
 */
context::error_t anyks::internal::Engine::accept(const view_t & body) noexcept {
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ прихода билета не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Разбираемый билет возобновления связи
	message::ticket_t ticket;
	// Если билет возобновления связи разобрать не удалось
	if(message::parse(body, ticket) != message::error_t::NONE)
		// Выводим отказ разбора билета возобновления связи
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Если билет ходу рукопожатия объявить не удалось
	if(this->_machine.accept(handshake::type_t::TICKET, session::side_t::SERVER) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Принятый билет возобновления связи
	context::ticket_t item;
	// Устанавливаем набор шифрования связи, выдавшей билет
	item.suite = this->_suite;
	// Устанавливаем срок жизни принятого билета
	item.lifetime = ticket.lifetime;
	// Устанавливаем добавку к возрасту принятого билета
	item.age = ticket.age;
	// Место, в которое помещается ключ принятого билета
	uint8_t secret[schedule::SCHEDULE_SECRET];
	// Если ключ принятого билета вывести не удалось
	if(this->_secrets.ticket(ticket.nonce, secret) != session::error_t::NONE)
		// Выводим отказ вывода ключа билета возобновления связи
		return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
	/**
	 * Выполняем складывание принятого билета возобновления связи
	 */
	try {
		// Переносим тело принятого билета возобновления связи
		item.identity.assign(ticket.data.data, ticket.data.data + ticket.data.size);
		// Переносим ключ принятого билета возобновления связи
		item.secret.assign(secret, secret + sizeof(secret));
		// Добавляем принятый билет в перечень билетов связи
		this->_tickets.push_back(item);
	// Если памяти под билет не хватило
	} catch(const bad_alloc &) {
		// Выполняем затирание ключа принятого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем затирание ключа принятого билета
	wipe(secret, sizeof(secret));
	// Выводим успешность разбора билета возобновления связи
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого извещения
 *
 * @param data принятое извещение
 *
 * @return     отказ разбора принятого извещения
 *
 */
context::error_t anyks::internal::Engine::notice(const view_t & data) noexcept {
	// Разбираемое извещение собеседника
	alert::alert_t alert;
	// Если извещение собеседника разобрать не удалось
	if(alert::parse(data, alert) != alert::error_t::NONE)
		// Выводим отказ разбора извещения собеседника
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Запоминаем извещение, принятое от собеседника
	this->_alert = alert;
	/**
	 * Решение о разрыве связи принимается по описанию извещения: раздел 6.2 RFC 8446
	 * объявляет уровень извещения в издании TLS 1.3 не имеющим значения
	 */
	if(alert::fatal(alert)){
		// Запоминаем отказ, которым связь оборвана
		this->_error = context::error_t::ALERT;
		// Переводим связь в состояние обрыва
		this->_state = context::state_t::FAILED;
		// Выводим отказ обрыва связи собеседником
		return context::error_t::ALERT;
	}
	// Если собеседник завершил передачу данных
	if(alert.description == alert::description_t::CLOSE)
		// Переводим связь в состояние закрытия
		this->_state = context::state_t::CLOSED;
	// Выводим успешность разбора извещения собеседника
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого сообщения рукопожатия
 *
 * @param type    вид принятого сообщения рукопожатия
 * @param body    тело принятого сообщения рукопожатия
 * @param message принятое сообщение рукопожатия вместе с обвязкой
 *
 * @return        отказ разбора сообщения рукопожатия
 *
 */
context::error_t anyks::internal::Engine::handle(const handshake::type_t type, const view_t & body, const view_t & message) noexcept {
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	// Если принят билет возобновления связи
	if(type == handshake::type_t::TICKET)
		// Выводим итог разбора билета возобновления связи
		return (this->_server ? this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED) : this->accept(body));
	// Если принята смена ключевого материала собеседника
	if(type == handshake::type_t::UPDATE)
		// Выводим итог разбора смены ключевого материала
		return this->renew(body);
	// Если принято приветствие стороны связи
	if(type == handshake::type_t::CLIENT)
		// Выводим итог разбора приветствия клиента
		return (this->_server ? this->incoming(body, message) : this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED));
	// Если принято приветствие сервера
	if(type == handshake::type_t::SERVER)
		// Выводим итог разбора приветствия сервера
		return (this->_server ? this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED) : this->outgoing(body, message));
	// Отказ разбора принятого сообщения рукопожатия
	context::error_t error = context::error_t::NONE;
	/**
	 * Выполняем определение вида принятого сообщения рукопожатия
	 */
	switch(static_cast <uint8_t> (type)){
		// Если приняты защищённые расширения сервера
		case static_cast <uint8_t> (handshake::type_t::EXTENSIONS): {
			/**
			 * Приём упреждающих данных сервер объявляет расширением: раздел 4.2.10
			 * RFC 8446 велит объявлять его именно здесь, а не приветствием
			 */
			this->_accepted = (this->_earlying && declared(body, static_cast <uint16_t> (extension::type_t::EARLY)));
			/**
			 * Отвергнутые упреждающие данные пропали: связь возвращается к ключам
			 * рукопожатия, а посланное ими сервер не прочтёт вовсе
			 */
			if(!this->_accepted)
				// Прекращаем ход упреждающих данных связи
				this->_earlying = false;
			// Тело расширения выбранного сервером прикладного протокола
			view_t chosen;
			// Если прикладной протокол сервером объявлен
			if(announced(body, static_cast <uint16_t> (extension::type_t::PROTOCOLS), chosen)){
				// Название прикладного протокола, выбранного сервером
				string selected;
				// Если выбранный сервером прикладной протокол разобрать не удалось
				if(extension::protocol(chosen, selected) != extension::error_t::NONE)
					// Выводим отказ разбора защищённых расширений сервера
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				// Признак того, что выбранный протокол связью предлагался
				bool suitable = false;
				/**
				 * Выполняем перебор прикладных протоколов, предложенных связью
				 */
				for(size_t i = 0; (i < this->_protocols.size()) && !suitable; i++)
					// Запоминаем, предлагался ли выбранный сервером протокол связью
					suitable = (selected.compare(this->_protocols[i]) == 0);
				/**
				 * Раздел 3.2 RFC 7301: сервер выбирает лишь из того, что ему предложено,
				 * и протокол вне предложения принимать нельзя - им связь пошла бы
				 * протоколом, которого сторона не понимает
				 */
				if(!suitable)
					// Выводим отказ отсутствия общего прикладного протокола
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
				/**
				 * Выполняем перехват ошибок работы с памятью
				 */
				try {
					// Запоминаем выбранный сторонами прикладной протокол
					this->_protocol = ::move(selected);
				/**
				 * Если памяти под название протокола не хватило
				 */
				} catch(const std::bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
			}
		} break;
		// Если принят конец упреждающих данных клиента
		case static_cast <uint8_t> (handshake::type_t::EARLY): {
			// Если связь ведётся стороной клиента
			if(!this->_server)
				// Выводим отказ прихода сообщения не от той стороны
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Прекращаем приём упреждающих данных клиента
			this->_earlying = false;
		} break;
		// Если принят запрос подлинности клиента
		case static_cast <uint8_t> (handshake::type_t::REQUEST): {
			// Запоминаем, что подлинность клиента запрошена сервером
			this->_requested = true;
		} break;
		// Если принята цепочка сертификатов собеседника
		case static_cast <uint8_t> (handshake::type_t::CERTIFICATE): {
			// Выполняем разбор цепочки сертификатов собеседника
			error = this->chain(body);
			// Если цепочку сертификатов собеседника разобрать не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ разбора цепочки сертификатов
				return this->abort(error, alert::description_t::BADCERT);
		} break;
		// Если принята подпись владения ключом собеседника
		case static_cast <uint8_t> (handshake::type_t::VERIFY): {
			/**
			 * Подпись владения ключом сличается с перепиской до этого сообщения:
			 * себя самоё подпись не покрывает
			 */
			error = this->possession(body);
			// Если подпись владения ключом не сошлась
			if(error != context::error_t::NONE)
				// Выводим отказ проверки подписи владения ключом
				return this->abort(error, alert::description_t::DECRYPT);
		} break;
		// Если принято завершение рукопожатия собеседником
		case static_cast <uint8_t> (handshake::type_t::FINISHED): {
			/**
			 * Завершение рукопожатия сличается с перепиской до этого сообщения:
			 * себя самоё завершение не покрывает
			 */
			error = this->confirm(body);
			// Если завершение рукопожатия собеседника не сошлось
			if(error != context::error_t::NONE)
				// Выводим отказ схождения завершения рукопожатия
				return this->abort(error, alert::description_t::DECRYPT);
		} break;
		// Если принято сообщение, связью не поддержанное
		default: return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	}
	// Если сообщение в переписку рукопожатия добавить не удалось
	if(this->_transcript.update(message) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
	// Если сообщение ходу рукопожатия объявить не удалось
	if(this->_machine.accept(type, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Если принято не завершение рукопожатия собеседником
	if(type != handshake::type_t::FINISHED)
		// Выводим успешность разбора сообщения рукопожатия
		return context::error_t::NONE;
	// Если связь ведётся стороной клиента
	if(!this->_server){
		// Выполняем вывод ключей прикладных данных связи
		error = this->mature();
		// Если ключи прикладных данных вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода ключей прикладных данных
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем согласование ключевого материала защиты записей
		error = this->refresh();
		// Если ключевой материал защиты записей согласовать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ согласования ключевого материала
			return this->abort(error, alert::description_t::INTERNAL);
		// Если упреждающие данные связи приняты сервером
		if(this->_earlying){
			/**
			 * Конец упреждающих данных уходит их же ключами: раздел 4.5 RFC 8446 велит
			 * закрывать поток теми ключами, какими он и шёл
			 */
			error = this->send(handshake::type_t::EARLY, view_t(nullptr, 0));
			// Если конец упреждающих данных отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки конца упреждающих данных
				return this->abort(error, alert::description_t::INTERNAL);
			// Прекращаем ход упреждающих данных связи
			this->_earlying = false;
		}
		// Если подлинность клиента запрошена сервером
		if(this->_requested){
			// Выполняем отправку подтверждения подлинности клиента
			error = this->authenticate();
			// Если подтверждение подлинности клиента отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки подтверждения подлинности
				return this->abort(error, alert::description_t::INTERNAL);
		}
		// Выполняем отправку завершения рукопожатия клиентом
		error = this->complete();
		// Если завершение рукопожатия клиентом отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки завершения рукопожатия
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем вывод значения возобновления связи
		error = this->keeping();
		// Если значение возобновления связи вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода значения возобновления связи
			return this->abort(error, alert::description_t::INTERNAL);
	// Если связь ведётся стороной сервера
	} else {
		// Выполняем согласование ключевого материала защиты записей
		error = this->refresh();
		// Если ключевой материал защиты записей согласовать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ согласования ключевого материала
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем вывод значения возобновления связи
		error = this->keeping();
		// Если значение возобновления связи вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода значения возобновления связи
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Если рукопожатие связи завершено обеими сторонами
	if(this->_machine.established())
		// Переводим связь в состояние установленной связи
		this->_state = context::state_t::ESTABLISHED;
	// Выводим успешность разбора сообщения рукопожатия
	return context::error_t::NONE;
}
/**
 * @brief Метод получения состояния связи
 *
 * @return состояние связи
 *
 */
context::state_t anyks::internal::Engine::state() const noexcept {
	// Выводим состояние связи
	return this->_state;
}
/**
 * @brief Метод получения отказа, которым связь оборвана
 *
 * @return отказ, которым связь оборвана
 *
 */
context::error_t anyks::internal::Engine::error() const noexcept {
	// Выводим отказ, которым связь оборвана
	return this->_error;
}
/**
 * @brief Метод получения извещения, которым связь оборвана
 *
 * @return извещение, которым связь оборвана
 *
 */
const alert::alert_t & anyks::internal::Engine::alert() const noexcept {
	// Выводим извещение, которым связь оборвана
	return this->_alert;
}
/**
 * @brief Метод получения набора шифрования связи
 *
 * @return согласованный сторонами набор шифрования
 *
 */
protect::suite_t anyks::internal::Engine::suite() const noexcept {
	// Выводим согласованный сторонами набор шифрования
	return this->_suite;
}
/**
 * @brief Метод получения цепочки сертификатов собеседника
 *
 * @return цепочка сертификатов, предъявленная собеседником
 *
 */
const vector <vector <uint8_t>> & anyks::internal::Engine::peer() const noexcept {
	// Выводим цепочку сертификатов, предъявленную собеседником
	return this->_peer;
}
/**
 * @brief Метод получения имени узла связи
 *
 * @return имя узла, запрошенное клиентом у сервера
 *
 */
const string & anyks::internal::Engine::name() const noexcept {
	// Выводим имя узла, запрошенное клиентом у сервера
	return this->_name;
}
/**
 * @brief Метод получения прикладного протокола связи
 *
 * @return прикладной протокол, выбранный сторонами связи
 *
 */
const string & anyks::internal::Engine::protocol() const noexcept {
	// Выводим прикладной протокол, выбранный сторонами связи
	return this->_protocol;
}
/**
 * @brief Метод установки предлагаемых наборов шифрования
 *
 * @param suites устанавливаемые наборы шифрования
 *
 */
void anyks::internal::Engine::suites(const vector <protect::suite_t> & suites) noexcept {
	// Если предлагаемые наборы шифрования переданы
	if(!suites.empty())
		// Запоминаем предлагаемые наборы шифрования
		this->_suites = suites;
}
/**
 * @brief Метод установки предлагаемых кривых обмена ключами
 *
 * @param groups устанавливаемые кривые обмена ключами
 *
 */
void anyks::internal::Engine::groups(const vector <extension::group_t> & groups) noexcept {
	// Если предлагаемые кривые обмена ключами переданы
	if(!groups.empty())
		// Запоминаем предлагаемые кривые обмена ключами
		this->_groups = groups;
}
/**
 * @brief Метод установки подлинности своей стороны связи
 *
 * @param credential устанавливаемая подлинность своей стороны
 *
 */
void anyks::internal::Engine::credential(const context::credential_t & credential) noexcept {
	// Запоминаем подлинность своей стороны связи
	this->_credential = credential;
}
/**
 * @brief Метод установки имени узла, запрашиваемого у сервера
 *
 * @param name устанавливаемое имя узла
 *
 */
void anyks::internal::Engine::name(const string & name) noexcept {
	// Запоминаем имя узла, запрашиваемое у сервера
	this->_name = name;
}
/**
 * @brief Метод установки предлагаемых прикладных протоколов
 *
 * @param protocols устанавливаемые прикладные протоколы
 *
 */
void anyks::internal::Engine::protocols(const vector <string> & protocols) noexcept {
	// Запоминаем предлагаемые прикладные протоколы связи
	this->_protocols = protocols;
}
/**
 * @brief Метод установки билета возобновления связи клиентом
 *
 * @param ticket предъявляемый билет возобновления связи
 *
 */
void anyks::internal::Engine::resume(const context::ticket_t & ticket) noexcept {
	// Запоминаем билет, предъявляемый на возобновление связи
	this->_resume = ticket;
}
/**
 * @brief Метод установки билетов, признаваемых сервером
 *
 * @param tickets признаваемые билеты возобновления связи
 *
 */
void anyks::internal::Engine::resume(const vector <context::ticket_t> & tickets) noexcept {
	// Запоминаем билеты, признаваемые на возобновление связи
	this->_store = tickets;
}
/**
 * @brief Метод проверки возобновления связи заранее разделённым ключом
 *
 * @return признак того, что связь возобновлена билетом
 *
 */
bool anyks::internal::Engine::shared() const noexcept {
	// Выводим признак возобновления связи билетом
	return this->_shared;
}
/**
 * @brief Метод установки предложения упреждающих данных
 *
 * @param advance устанавливаемое предложение упреждающих данных
 *
 */
void anyks::internal::Engine::advance(const bool advance) noexcept {
	// Запоминаем предложение упреждающих данных связи
	this->_advance = advance;
}
/**
 * @brief Метод проверки приёма упреждающих данных собеседником
 *
 * @return признак того, что упреждающие данные приняты
 *
 */
bool anyks::internal::Engine::accepted() const noexcept {
	// Выводим признак приёма упреждающих данных собеседником
	return this->_accepted;
}
/**
 * @brief Метод установки требования подлинности клиента
 *
 * @param request устанавливаемое требование подлинности клиента
 *
 */
void anyks::internal::Engine::request(const bool request) noexcept {
	// Запоминаем требование подлинности клиента
	this->_request = request;
}
/**
 * @brief Метод заведения связи
 *
 * @return отказ заведения связи
 *
 */
context::error_t anyks::internal::Engine::start() noexcept {
	// Если связь уже заведена
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Если наборов шифрования либо кривых обмена ключами не осталось
	if(this->_suites.empty() || this->_groups.empty())
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Сервер без своей подлинности связь завести не вправе: подтверждать её ему нечем,
	 * а рукопожатие на заранее разделённом ключе связью пока не ведётся
	 */
	if(this->_server && (this->_credential.chain.empty() || this->_credential.secret.empty()))
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	// Если ход рукопожатия связи завести не удалось
	if(!this->_machine.start(this->_server ? flow::role_t::SERVER : flow::role_t::CLIENT))
		// Выводим отказ заведения хода рукопожатия
		return context::error_t::STATE;
	// Выполняем начало переписки рукопожатия связи
	this->_transcript.start();
	// Переводим связь в состояние рукопожатия
	this->_state = context::state_t::HANDSHAKE;
	// Выполняем выработку случайного значения своего приветствия
	if(!entropy::bytes(this->_random, sizeof(this->_random)))
		// Выводим отказ выработки случайного значения приветствия
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Если связь ведётся стороной сервера
	if(this->_server)
		// Выводим успешность заведения связи: сервер ждёт приветствия клиента
		return context::error_t::NONE;
	/**
	 * Выполняем заведение опознавателя связи, доставшегося от предыдущих изданий
	 */
	try {
		// Занимаем место под опознаватель связи
		this->_session.assign(hello::HELLO_SESSION, 0);
	// Если памяти под опознаватель связи не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если опознаватель связи выработать не удалось
	if(!entropy::bytes(this->_session.data(), this->_session.size()))
		// Выводим отказ выработки опознавателя связи
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Выполняем выработку мимолётной пары ключей своей стороны
	const context::error_t error = this->exchange(this->_groups[0]);
	// Если мимолётную пару ключей выработать не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ выработки мимолётной пары ключей
		return this->abort(error, alert::description_t::INTERNAL);
	// Выводим итог отправки приветствия клиента
	return this->greeting();
}
/**
 * @brief Метод сброса состояния связи
 *
 */
void anyks::internal::Engine::clear() noexcept {
	// Выполняем сброс состояния связи
	this->_state = context::state_t::NONE;
	// Выполняем сброс отказа, которым связь оборвана
	this->_error = context::error_t::NONE;
	// Выполняем сброс признака запроса подлинности клиента
	this->_requested = false;
	// Выполняем сброс признака повтора приветствия клиента
	this->_retried = false;
	// Выполняем сброс признака возобновления связи билетом
	this->_shared = false;
	// Выполняем сброс признака хода упреждающих данных
	this->_earlying = false;
	// Выполняем сброс набора шифрования билета возобновления связи
	this->_ticket = protect::suite_t::NONE;
	// Выполняем сброс признака приёма упреждающих данных
	this->_accepted = false;
	// Выполняем сброс числа пропущенных записей упреждающих данных
	this->_skipped = 0;
	// Выполняем сброс защиты записей упреждающих данных
	this->_early.clear();
	// Выполняем сброс хода рукопожатия связи
	this->_machine.clear();
	// Выполняем сброс переписки рукопожатия связи
	this->_transcript.clear();
	// Выполняем сброс значений расписания ключей связи
	this->_secrets.clear();
	// Выполняем сброс сборщика входящих записей связи
	this->_records.clear();
	// Выполняем сброс сборщика входящих сообщений рукопожатия
	this->_messages.clear();
	// Выполняем сброс защиты отправляемых записей связи
	this->_output.clear();
	// Выполняем сброс защиты принимаемых записей связи
	this->_input.clear();
	// Выполняем сброс поры ключей записей клиента
	this->_epoch[0] = flow::epoch_t::PLAIN;
	// Выполняем сброс поры ключей записей сервера
	this->_epoch[1] = flow::epoch_t::PLAIN;
	// Выполняем затирание ключей завершения рукопожатия сторон
	wipe(this->_completion, sizeof(this->_completion));
	// Выполняем затирание ключевого материала прикладных данных
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание векторов замены прикладных данных
	wipe(this->_vector, sizeof(this->_vector));
	// Если секретный мимолётный ключ своей стороны выработан
	if(!this->_secret.empty())
		// Выполняем затирание секретного мимолётного ключа
		wipe(this->_secret.data(), this->_secret.size());
	// Выполняем сброс секретного мимолётного ключа своей стороны
	this->_secret.clear();
	// Выполняем сброс открытого мимолётного ключа своей стороны
	this->_opened.clear();
	// Если накопитель принятых прикладных данных не пуст
	if(!this->_plain.empty())
		// Выполняем затирание принятых прикладных данных
		wipe(this->_plain.data(), this->_plain.size());
	// Выполняем сброс накопителя принятых прикладных данных
	this->_plain.clear();
	// Выполняем сброс накопителя отправляемых байтов связи
	this->_wire.clear();
	// Выполняем сброс цепочки сертификатов собеседника
	this->_peer.clear();
	// Выполняем сброс прикладного протокола, выбранного сторонами
	this->_protocol.clear();
	/**
	 * Имя узла сбрасывается лишь стороной сервера: у клиента оно объявляет, за каким
	 * узлом он идёт, и настройкой этой связь распоряжаться не вправе
	 */
	if(this->_server)
		// Выполняем сброс имени узла, запрошенного клиентом
		this->_name.clear();
	/**
	 * Выполняем перебор билетов возобновления связи
	 */
	for(size_t i = 0; i < this->_tickets.size(); i++)
		// Выполняем затирание ключа очередного билета возобновления связи
		wipe(this->_tickets[i].secret.data(), this->_tickets[i].secret.size());
	// Выполняем сброс билетов возобновления связи
	this->_tickets.clear();
	// Выполняем сброс опознавателя связи
	this->_session.clear();
	// Выполняем затирание случайного значения своего приветствия
	wipe(this->_random, sizeof(this->_random));
	// Выполняем сброс эллиптической кривой обмена ключами
	this->_curve.clear();
}
/**
 * @brief Метод подачи связи принятых байтов
 *
 * @param data принятые байты связи
 *
 * @return     отказ разбора принятых байтов
 *
 */
context::error_t anyks::internal::Engine::push(const view_t & data) noexcept {
	// Если связь ещё не заведена либо уже оборвана
	if((this->_state == context::state_t::NONE) || (this->_state == context::state_t::FAILED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Если принятые байты связи сборщику записей подать не удалось
	if(this->_records.push(data) != record::error_t::NONE)
		// Выводим отказ разбора принятых байтов
		return this->abort(context::error_t::RECORD, alert::description_t::OVERSIZE);
	// Заголовок принятой записи связи
	record::header_t header;
	// Содержимое принятой записи связи
	view_t payload;
	/**
	 * Выполняем перебор принятых записей связи
	 */
	while(this->_records.next(header, payload) == record::error_t::NONE){
		// Если принята запись смены набора шифрования
		if(header.type == record::type_t::CHANGE)
			// Пропускаем запись, доставшуюся от предыдущих изданий протокола
			continue;
		// Получаем сторону связи собеседника
		const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
		// Вид содержимого принятой записи связи
		record::type_t type = header.type;
		// Накопитель, в который складывается открытое содержимое записи
		vector <uint8_t> opened;
		// Просмотр открытого содержимого принятой записи
		view_t content = payload;
		// Если принимаются упреждающие данные клиента
		if(this->_server && this->_earlying){
			// Если снять защиту упреждающих данных с принятой записи не удалось
			if(this->_early.open(header, payload, type, opened) != protect::error_t::NONE)
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(context::error_t::PROTECTION, alert::description_t::MAC);
			// Получаем открытое содержимое принятой записи
			content = view_t(opened.data(), opened.size());
		// Если записи собеседника защищены ключами связи
		} else if(this->_machine.epoch(side) != flow::epoch_t::PLAIN){
			// Если снять защиту с принятой записи не удалось
			if(this->_input.open(header, payload, type, opened) != protect::error_t::NONE){
				/**
				 * Упреждающие данные, сервером отвергнутые, прочесть нечем: раздел 4.2.10
				 * RFC 8446 велит такие записи пропускать, а не рвать по ним связь
				 */
				if(this->_server && (this->_skipped > 0)){
					// Уменьшаем число записей, дозволенных к пропуску
					this->_skipped--;
					// Переходим к следующей принятой записи связи
					continue;
				}
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(context::error_t::PROTECTION, alert::description_t::MAC);
			}
			/**
			 * Первая прочтённая запись закрывает пропуск отвергнутых упреждающих
			 * данных: за нею идут записи, защищённые ключами рукопожатия
			 */
			this->_skipped = 0;
			// Получаем открытое содержимое принятой записи
			content = view_t(opened.data(), opened.size());
		}
		// Отказ разбора открытого содержимого принятой записи
		context::error_t error = context::error_t::NONE;
		/**
		 * Выполняем определение вида содержимого принятой записи
		 */
		switch(static_cast <uint8_t> (type)){
			// Если принято извещение собеседника
			case static_cast <uint8_t> (record::type_t::ALERT): {
				// Выполняем разбор принятого извещения собеседника
				error = this->notice(content);
				// Если связь оборвана извещением собеседника
				if(error != context::error_t::NONE)
					// Выводим отказ обрыва связи собеседником
					return error;
			} break;
			// Если приняты сообщения рукопожатия собеседника
			case static_cast <uint8_t> (record::type_t::HANDSHAKE): {
				// Если содержимое записи сборщику сообщений подать не удалось
				if(this->_messages.push(content) != handshake::error_t::NONE)
					// Выводим отказ разбора сообщений рукопожатия
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				// Заголовок принятого сообщения рукопожатия
				handshake::header_t item;
				// Тело принятого сообщения рукопожатия
				view_t body;
				/**
				 * Выполняем перебор принятых сообщений рукопожатия
				 */
				while(this->_messages.next(item, body) == handshake::error_t::NONE){
					// Выполняем разбор принятого сообщения рукопожатия
					error = this->handle(item.type, body, this->_messages.message());
					// Если сообщение рукопожатия разобрать не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ разбора сообщения рукопожатия
						return error;
				}
			} break;
			// Если приняты прикладные данные собеседника
			case static_cast <uint8_t> (record::type_t::APPLICATION): {
				/**
				 * Упреждающие данные приходят до установления связи: тем они и
				 * упреждающие, что посланы, не дождавшись ответа сервера
				 */
				const bool early = (this->_server && this->_earlying);
				// Если связь ещё не установлена и упреждающие данные не идут
				if(!early && (this->_state != context::state_t::ESTABLISHED))
					// Выводим отказ прихода прикладных данных не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				/**
				 * Выполняем складывание принятых прикладных данных в накопитель
				 */
				try {
					// Выполняем перенос принятых прикладных данных в накопитель
					this->_plain.insert(this->_plain.end(), content.data, content.data + content.size);
				// Если памяти под накопитель не хватило
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return context::error_t::MEMORY;
				}
			} break;
			// Если принято содержимое, связью не поддержанное
			default: return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
		}
	}
	// Выводим успешность разбора принятых байтов связи
	return context::error_t::NONE;
}
/**
 * @brief Метод получения байтов, отправляемых собеседнику
 *
 * @return накопленные байты, отправляемые собеседнику
 *
 */
view_t anyks::internal::Engine::output() const noexcept {
	// Выводим накопленные байты, отправляемые собеседнику
	return view_t(this->_wire.data(), this->_wire.size());
}
/**
 * @brief Метод снятия отправленных байтов с накопителя
 *
 * @param size размер снимаемых байтов
 *
 */
void anyks::internal::Engine::consume(const size_t size) noexcept {
	// Если снимается весь накопитель отправляемых байтов
	if(size >= this->_wire.size())
		// Выполняем сброс накопителя отправляемых байтов
		this->_wire.clear();
	// Если снимается часть накопителя отправляемых байтов
	else this->_wire.erase(this->_wire.begin(), this->_wire.begin() + size);
}
/**
 * @brief Метод отправки прикладных данных собеседнику
 *
 * @param data отправляемые прикладные данные
 *
 * @return     отказ отправки прикладных данных
 *
 */
context::error_t anyks::internal::Engine::write(const view_t & data) noexcept {
	/**
	 * Упреждающие данные уходят до установления связи: тем они и упреждающие, что
	 * посылаются, не дождавшись ответа сервера
	 */
	const bool early = (!this->_server && this->_earlying && (this->_state == context::state_t::HANDSHAKE));
	// Если связь ещё не установлена и упреждающие данные не идут
	if(!early && (this->_state != context::state_t::ESTABLISHED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Если отправляемые прикладные данные не переданы
	if((data.data == nullptr) || (data.size == 0))
		// Выводим успешность отправки прикладных данных
		return context::error_t::NONE;
	// Размер отправленных прикладных данных
	size_t offset = 0;
	/**
	 * Выполняем нарезку прикладных данных на записи протокола
	 */
	while(offset < data.size){
		// Определяем размер очередной отправляемой записи
		const size_t size = ((data.size - offset) > record::RECORD_PLAINTEXT ? record::RECORD_PLAINTEXT : (data.size - offset));
		// Выполняем складывание очередной записи в накопитель
		const context::error_t error = this->emit(record::type_t::APPLICATION, view_t(data.data + offset, size));
		// Если запись прикладных данных сложить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки прикладных данных
			return error;
		// Увеличиваем размер отправленных прикладных данных
		offset += size;
	}
	// Выводим успешность отправки прикладных данных
	return context::error_t::NONE;
}
/**
 * @brief Метод получения принятых прикладных данных
 *
 * @param result накопитель, в который переносятся принятые данные
 *
 * @return       отказ получения принятых прикладных данных
 *
 */
context::error_t anyks::internal::Engine::read(vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перенос принятых прикладных данных
	 */
	try {
		// Выполняем перенос принятых прикладных данных в накопитель
		result.assign(this->_plain.begin(), this->_plain.end());
	// Если памяти под накопитель не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если накопитель принятых прикладных данных не пуст
	if(!this->_plain.empty())
		// Выполняем затирание принятых прикладных данных
		wipe(this->_plain.data(), this->_plain.size());
	// Выполняем сброс накопителя принятых прикладных данных
	this->_plain.clear();
	// Выводим успешность получения принятых прикладных данных
	return context::error_t::NONE;
}
/**
 * @brief Метод смены ключевого материала своего направления связи
 *
 * @param request признак просьбы к собеседнику сменить свои ключи в ответ
 *
 * @return        отказ смены ключевого материала своего направления
 *
 */
context::error_t anyks::internal::Engine::update(const bool request) noexcept {
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Накопитель, в который складывается тело сообщения смены ключей
	vector <uint8_t> body;
	// Если тело сообщения смены ключевого материала составить не удалось
	if(message::build((request ? message::update_t::REQUEST : message::update_t::NOTIFY), body) != message::error_t::NONE)
		// Выводим отказ составления сообщения смены ключевого материала
		return context::error_t::MESSAGE;
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если сообщение смены ключевого материала составить не удалось
	if(writer.push(handshake::type_t::UPDATE, view_t(body.data(), body.size())) != handshake::error_t::NONE)
		// Выводим отказ составления сообщения смены ключевого материала
		return context::error_t::MESSAGE;
	/**
	 * Сообщение уходит прежними ключами, а новые ставятся уже за ним: раздел 4.6.3
	 * RFC 8446 велит сменять ключи отправки лишь после отправки самого сообщения
	 */
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, writer.data());
	// Если сообщение смены ключевого материала отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки сообщения смены ключевого материала
		return error;
	/**
	 * Сообщения, идущие за рукопожатием, в переписку не добавляются: переписка
	 * закрыта завершениями сторон, и ключи из неё больше не выводятся
	 */
	if(this->_machine.accept(handshake::type_t::UPDATE, side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Выводим итог смены ключевого материала своего направления связи
	return this->rotate(side);
}
/**
 * @brief Метод выдачи билета возобновления связи
 *
 * @return отказ выдачи билета возобновления связи
 *
 */
context::error_t anyks::internal::Engine::issue() noexcept {
	// Если связь ведётся стороной клиента
	if(!this->_server)
		// Выводим отказ негодной стороны связи: билеты выдаёт сервер
		return context::error_t::STATE;
	// Если связь ещё не установлена
	if(this->_state != context::state_t::ESTABLISHED)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Выдаваемый билет возобновления связи
	context::ticket_t item;
	// Устанавливаем набор шифрования связи, выдавшей билет
	item.suite = this->_suite;
	// Устанавливаем срок жизни выдаваемого билета
	item.lifetime = 7200;
	/**
	 * Неповторимое значение билета берётся числом выданных билетов: раздел 4.6.1
	 * RFC 8446 велит разводить ключи билетов одной связи именно им
	 */
	const uint8_t nonce[4] = {
		static_cast <uint8_t> ((this->_tickets.size() >> 24) & 0xFF),
		static_cast <uint8_t> ((this->_tickets.size() >> 16) & 0xFF),
		static_cast <uint8_t> ((this->_tickets.size() >> 8) & 0xFF),
		static_cast <uint8_t> (this->_tickets.size() & 0xFF)
	};
	// Место, в которое помещается тело выдаваемого билета
	uint8_t identity[32];
	// Если тело выдаваемого билета выработать не удалось
	if(!entropy::bytes(identity, sizeof(identity)))
		// Выводим отказ выработки тела билета
		return context::error_t::SETTINGS;
	// Место, в которое помещается добавка к возрасту билета
	uint8_t addition[4];
	// Если добавку к возрасту билета выработать не удалось
	if(!entropy::bytes(addition, sizeof(addition)))
		// Выводим отказ выработки добавки к возрасту билета
		return context::error_t::SETTINGS;
	// Устанавливаем добавку к возрасту выдаваемого билета
	item.age = ((static_cast <uint32_t> (addition[0]) << 24) | (static_cast <uint32_t> (addition[1]) << 16) | (static_cast <uint32_t> (addition[2]) << 8) | static_cast <uint32_t> (addition[3]));
	// Место, в которое помещается ключ выдаваемого билета
	uint8_t secret[schedule::SCHEDULE_SECRET];
	// Если ключ выдаваемого билета вывести не удалось
	if(this->_secrets.ticket(view_t(nonce, sizeof(nonce)), secret) != session::error_t::NONE)
		// Выводим отказ вывода ключа билета возобновления связи
		return context::error_t::SCHEDULE;
	// Составляемый билет возобновления связи
	message::ticket_t ticket;
	// Устанавливаем срок жизни составляемого билета
	ticket.lifetime = item.lifetime;
	// Устанавливаем добавку к возрасту составляемого билета
	ticket.age = item.age;
	// Устанавливаем неповторимое значение составляемого билета
	ticket.nonce = view_t(nonce, sizeof(nonce));
	// Устанавливаем тело составляемого билета
	ticket.data = view_t(identity, sizeof(identity));
	// Накопитель, в который складывается тело сообщения билета
	vector <uint8_t> body;
	// Если тело сообщения билета составить не удалось
	if(message::build(ticket, body) != message::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ составления сообщения билета
		return context::error_t::MESSAGE;
	}
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Если сообщение билета возобновления связи составить не удалось
	if(writer.push(handshake::type_t::TICKET, view_t(body.data(), body.size())) != handshake::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ составления сообщения билета
		return context::error_t::MESSAGE;
	}
	// Выполняем складывание сообщения билета в накопитель отправляемых байтов
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, writer.data());
	// Если сообщение билета отправить не удалось
	if(error != context::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ отправки сообщения билета
		return error;
	}
	/**
	 * Сообщения, идущие за рукопожатием, в переписку не добавляются: значение
	 * возобновления связи выведено и от них уже не зависит
	 */
	if(this->_machine.accept(handshake::type_t::TICKET, session::side_t::SERVER) != flow::error_t::NONE){
		// Выполняем затирание ключа выдаваемого билета
		wipe(secret, sizeof(secret));
		// Выводим отказ объявления сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	}
	/**
	 * Выполняем складывание выданного билета возобновления связи
	 */
	try {
		// Переносим тело выданного билета возобновления связи
		item.identity.assign(identity, identity + sizeof(identity));
		// Переносим ключ выданного билета возобновления связи
		item.secret.assign(secret, secret + sizeof(secret));
		// Добавляем выданный билет в перечень билетов связи
		this->_tickets.push_back(item);
	// Если памяти под билет не хватило
	} catch(const bad_alloc &) {
		// Выполняем затирание ключа выданного билета
		wipe(secret, sizeof(secret));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем затирание ключа выданного билета
	wipe(secret, sizeof(secret));
	// Выводим успешность выдачи билета возобновления связи
	return context::error_t::NONE;
}
/**
 * @brief Метод получения билетов возобновления связи
 *
 * @return выданные либо принятые билеты возобновления связи
 *
 */
const vector <context::ticket_t> & anyks::internal::Engine::tickets() const noexcept {
	// Выводим выданные либо принятые билеты возобновления связи
	return this->_tickets;
}
/**
 * @brief Метод закрытия связи
 *
 * @return отказ закрытия связи
 *
 */
context::error_t anyks::internal::Engine::close() noexcept {
	// Если связь уже закрыта либо оборвана
	if((this->_state == context::state_t::CLOSED) || (this->_state == context::state_t::FAILED))
		// Выводим отказ закрытия закрытой связи
		return context::error_t::CLOSED;
	// Составляем извещение о завершении передачи данных
	const alert::alert_t alert(alert::level_t::WARNING, alert::description_t::CLOSE);
	// Место, в которое записывается извещение о завершении передачи
	uint8_t buffer[alert::ALERT_LENGTH];
	// Если извещение о завершении передачи записать не удалось
	if(alert::build(alert, buffer) != alert::error_t::NONE)
		// Выводим отказ составления извещения
		return context::error_t::MESSAGE;
	// Выполняем складывание извещения в накопитель отправляемых байтов
	const context::error_t error = this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
	// Если извещение о завершении передачи сложить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки извещения
		return error;
	// Переводим связь в состояние закрытия
	this->_state = context::state_t::CLOSED;
	// Выводим успешность закрытия связи
	return context::error_t::NONE;
}
/**
 * @brief Конструктор
 *
 * @param server признак того, что связь ведётся стороной сервера
 *
 */
anyks::internal::Engine::Engine(const bool server) noexcept :
 _server(server), _request(false), _requested(false), _retried(false),
 _state(context::state_t::NONE), _error(context::error_t::NONE),
 _suite(protect::suite_t::NONE), _group(extension::group_t::NONE),
 _shared(false), _chosen(0), _advance(false), _earlying(false), _accepted(false), _ticket(protect::suite_t::NONE), _skipped(0) {
	// Выполняем сброс поры ключей записей клиента
	this->_epoch[0] = flow::epoch_t::PLAIN;
	// Выполняем сброс поры ключей записей сервера
	this->_epoch[1] = flow::epoch_t::PLAIN;
	// Выполняем обнуление ключей завершения рукопожатия сторон
	::memset(this->_completion, 0, sizeof(this->_completion));
	// Выполняем обнуление ключевого материала прикладных данных
	::memset(this->_key, 0, sizeof(this->_key));
	// Выполняем обнуление векторов замены прикладных данных
	::memset(this->_vector, 0, sizeof(this->_vector));
	// Выполняем обнуление случайного значения своего приветствия
	::memset(this->_random, 0, sizeof(this->_random));
	/**
	 * Наборы шифрования по умолчанию идут от стойкого к быстрому: раздел 4 описания
	 * наборов шифрования на алгоритмах ГОСТ
	 */
	this->_suites = {
		protect::suite_t::KUZNYECHIK_MGM_L, protect::suite_t::MAGMA_MGM_L,
		protect::suite_t::KUZNYECHIK_MGM_S, protect::suite_t::MAGMA_MGM_S
	};
	// Кривые обмена ключами по умолчанию идут от длинного ключа к короткому
	this->_groups = {
		extension::group_t::GC512C, extension::group_t::GC512A,
		extension::group_t::GC256B, extension::group_t::GC256A
	};
}
/**
 * @brief Деструктор
 *
 */
anyks::internal::Engine::~Engine() noexcept {
	// Выполняем сброс состояния связи
	this->clear();
}
