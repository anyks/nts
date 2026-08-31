/**
 * @file message.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Исходный файл модуля сообщений подтверждения подлинности протокола TLS
 *
 * @section Намеренные решения
 *
 * 1. Обращение записи подписи вынесено отдельным вызовом, а не спрятано в разбор. Разбор
 *    выдаёт то, что пришло по связи, и подмена записи внутри него означала бы, что
 *    составленное обратно сообщение с исходным не сойдётся. Обращение это само себе
 *    обратно, и потому вызов у него один на оба направления.
 *
 * 2. Подписываемое содержимое составляется здесь, а не подписью. Раздел 4.4.3 RFC 8446
 *    задаёт его целиком - шестьдесят четыре пробела, название назначения, ноль и хеш
 *    переписки, - и принадлежит оно рукопожатию, а не подписи: модуль подписи о TLS не
 *    знает вовсе и знать не должен.
 *
 * 3. Сличение завершения рукопожатия ведётся за постоянное время. Завершение доказывает,
 *    что стороны видели одну переписку, и сличение с ранним выходом выдавало бы число
 *    сошедшихся байтов временем своей работы.
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
#include <field/field.hpp>
#include <digest/hmac.hpp>
#include <message/message.hpp>

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
	 * Пространство имён модуля
	 */
	using namespace anyks::message;

	/**
	 * @brief Число пробелов подписываемого содержимого владения ключом
	 *
	 */
	static constexpr size_t SPACES = 64;

	/**
	 * @brief Название назначения подписи сервера
	 *
	 */
	static const char * SERVER = "TLS 1.3, server CertificateVerify";

	/**
	 * @brief Название назначения подписи клиента
	 *
	 */
	static const char * CLIENT = "TLS 1.3, client CertificateVerify";

	/**
	 * @brief Метод разбора перечня расширений записи цепочки
	 *
	 * @param data   разбираемая область расширений записи
	 * @param result перечень, в который помещаются разобранные расширения
	 *
	 * @return       отказ разбора перечня расширений
	 *
	 */
	static error_t extensions(const view_t & data, vector <hello::extension_t> & result) noexcept {
		// Объект разборщика полей перечня расширений
		field::scanner_t scanner;
		// Устанавливаем разбираемую область расширений записи
		scanner.start(data);
		/**
		 * Выполняем перебор расширений записи цепочки до конца перечня
		 */
		while(scanner.left() > 0){
			// Вид очередного расширения записи цепочки
			uint32_t type = 0;
			// Если вид очередного расширения прочитать не удалось
			if(scanner.number(type, 2) != field::error_t::NONE)
				// Выводим отказ разбора перечня расширений
				return error_t::EXTENSION;
			// Тело очередного расширения записи цепочки
			view_t body;
			// Если тело очередного расширения прочитать не удалось
			if(scanner.vector(body, 2) != field::error_t::NONE)
				// Выводим отказ разбора перечня расширений
				return error_t::EXTENSION;
			/**
			 * Раздел 4.2 RFC 8446: расширение одного вида дважды объявлено быть не вправе
			 */
			if(hello::extension(result, static_cast <uint16_t> (type)) != nullptr)
				// Выводим отказ повторного объявления расширения
				return error_t::EXTENSION;
			/**
			 * Выполняем перехват ошибок работы с памятью
			 */
			try {
				// Добавляем очередное расширение в перечень расширений записи
				result.push_back(hello::extension_t(static_cast <uint16_t> (type), body));
			/**
			 * Если памяти под перечень расширений не хватило
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			}
		}
		// Выводим успешность разбора перечня расширений
		return error_t::NONE;
	}
};

/**
 * @brief Метод разбора тела сообщения цепочки сертификатов
 *
 * @param data   разбираемое тело сообщения
 * @param result сообщение, в которое помещается итог разбора
 *
 * @return       отказ разбора тела сообщения
 *
 */
error_t anyks::message::parse(const view_t & data, certificate_t & result) noexcept {
	// Объект разборщика полей тела сообщения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело сообщения
	scanner.start(data);
	// Привязка цепочки к запросу сертификата собеседником
	view_t context;
	// Если привязку цепочки прочитать не удалось
	if(scanner.vector(context, 1) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Содержимое цепочки сертификатов
	view_t body;
	// Если цепочку сертификатов прочитать не удалось
	if(scanner.vector(body, 3) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Если за телом сообщения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом сообщения
		return error_t::TRAILING;
	// Объект разборщика записей цепочки сертификатов
	field::scanner_t reader;
	// Устанавливаем разбираемое содержимое цепочки сертификатов
	reader.start(body);
	// Разобранные записи цепочки сертификатов
	vector <entry_t> entries;
	/**
	 * Выполняем перебор записей цепочки сертификатов
	 */
	while(reader.left() > 0){
		// Разбираемая запись цепочки сертификатов
		entry_t entry;
		// Если тело сертификата записи прочитать не удалось
		if(reader.vector(entry.data, 3) != field::error_t::NONE)
			// Выводим отказ обрыва тела сообщения
			return error_t::HUNGRY;
		// Если тело сертификата записи пустое
		if(entry.data.size == 0)
			// Выводим отказ пустого обязательного поля
			return error_t::EMPTY;
		// Область расширений записи цепочки сертификатов
		view_t area;
		// Если расширения записи цепочки прочитать не удалось
		if(reader.vector(area, 2) != field::error_t::NONE)
			// Выводим отказ обрыва тела сообщения
			return error_t::HUNGRY;
		// Выполняем разбор перечня расширений записи цепочки
		const error_t error = ::extensions(area, entry.extensions);
		// Если перечень расширений записи разобрать не удалось
		if(error != error_t::NONE)
			// Выводим отказ разбора перечня расширений
			return error;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Добавляем разобранную запись в цепочку сертификатов
			entries.push_back(entry);
		/**
		 * Если памяти под цепочку сертификатов не хватило
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Устанавливаем разобранные записи цепочки сертификатов
		result.entries = entries;
	/**
	 * Если памяти под цепочку сертификатов не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Устанавливаем привязку цепочки к запросу сертификата
	result.context = context;
	// Выводим успешность разбора тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод составления тела сообщения цепочки сертификатов
 *
 * @param message составляемое сообщение цепочки сертификатов
 * @param result  накопитель, в конец которого дописывается тело сообщения
 *
 * @return        отказ составления тела сообщения
 *
 */
error_t anyks::message::build(const certificate_t & message, vector <uint8_t> & result) noexcept {
	// Объект составителя полей тела сообщения
	field::builder_t builder;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Открываем поле привязки цепочки к запросу сертификата
		builder.open(1);
		// Записываем привязку цепочки к запросу сертификата
		builder.bytes(message.context);
		// Если поле привязки цепочки закрыть не удалось
		if(builder.close() != field::error_t::NONE)
			// Выводим отказ переполнения длины привязки цепочки
			return error_t::LENGTH;
		// Открываем цепочку сертификатов
		builder.open(3);
		/**
		 * Выполняем перебор записей составляемой цепочки сертификатов
		 */
		for(auto & entry : message.entries){
			// Если тело сертификата записи пустое
			if((entry.data.data == nullptr) || (entry.data.size == 0))
				// Выводим отказ пустого обязательного поля
				return error_t::EMPTY;
			// Открываем поле тела сертификата записи
			builder.open(3);
			// Записываем тело сертификата записи
			builder.bytes(entry.data);
			// Если поле тела сертификата закрыть не удалось
			if(builder.close() != field::error_t::NONE)
				// Выводим отказ переполнения длины тела сертификата
				return error_t::LENGTH;
			// Открываем перечень расширений записи цепочки
			builder.open(2);
			/**
			 * Выполняем перебор расширений записи цепочки сертификатов
			 */
			for(auto & item : entry.extensions){
				// Записываем вид очередного расширения записи
				builder.number(static_cast <uint32_t> (item.type), 2);
				// Открываем тело очередного расширения записи
				builder.open(2);
				// Записываем тело очередного расширения записи
				builder.bytes(item.data);
				// Если тело очередного расширения закрыть не удалось
				if(builder.close() != field::error_t::NONE)
					// Выводим отказ переполнения длины расширения
					return error_t::LENGTH;
			}
			// Если перечень расширений записи закрыть не удалось
			if(builder.close() != field::error_t::NONE)
				// Выводим отказ переполнения длины перечня расширений
				return error_t::LENGTH;
		}
		// Если цепочку сертификатов закрыть не удалось
		if(builder.close() != field::error_t::NONE)
			// Выводим отказ переполнения длины цепочки сертификатов
			return error_t::LENGTH;
		// Получаем составленное тело сообщения
		const view_t data = builder.data();
		// Выполняем дописывание тела сообщения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело сообщения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод разбора тела сообщения подписи владения ключом
 *
 * @param data   разбираемое тело сообщения
 * @param result сообщение, в которое помещается итог разбора
 *
 * @return       отказ разбора тела сообщения
 *
 */
error_t anyks::message::parse(const view_t & data, verify_t & result) noexcept {
	// Объект разборщика полей тела сообщения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело сообщения
	scanner.start(data);
	// Схема подписи владения ключом сертификата
	uint32_t scheme = 0;
	// Если схему подписи владения ключом прочитать не удалось
	if(scanner.number(scheme, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Значение подписи владения ключом сертификата
	view_t signature;
	// Если значение подписи владения ключом прочитать не удалось
	if(scanner.vector(signature, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Если за телом сообщения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом сообщения
		return error_t::TRAILING;
	// Если значение подписи владения ключом пустое
	if(signature.size == 0)
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Устанавливаем схему подписи владения ключом сертификата
	result.scheme = static_cast <extension::scheme_t> (scheme);
	// Устанавливаем значение подписи владения ключом сертификата
	result.signature = signature;
	// Выводим успешность разбора тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод составления тела сообщения подписи владения ключом
 *
 * @param message составляемое сообщение подписи владения ключом
 * @param result  накопитель, в конец которого дописывается тело сообщения
 *
 * @return        отказ составления тела сообщения
 *
 */
error_t anyks::message::build(const verify_t & message, vector <uint8_t> & result) noexcept {
	// Если значение подписи владения ключом пустое
	if((message.signature.data == nullptr) || (message.signature.size == 0))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Объект составителя полей тела сообщения
	field::builder_t builder;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Записываем схему подписи владения ключом сертификата
		builder.number(static_cast <uint32_t> (message.scheme), 2);
		// Открываем поле значения подписи владения ключом
		builder.open(2);
		// Записываем значение подписи владения ключом
		builder.bytes(message.signature);
		// Если поле значения подписи закрыть не удалось
		if(builder.close() != field::error_t::NONE)
			// Выводим отказ переполнения длины подписи
			return error_t::LENGTH;
		// Получаем составленное тело сообщения
		const view_t data = builder.data();
		// Выполняем дописывание тела сообщения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Если памяти под тело сообщения не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод разбора тела сообщения билета возобновления связи
 *
 * @param data   разбираемое тело сообщения
 * @param result билет, в который помещается итог разбора
 *
 * @return       отказ разбора тела сообщения
 *
 */
error_t anyks::message::parse(const view_t & data, ticket_t & result) noexcept {
	// Объект разборщика полей тела сообщения
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело сообщения
	scanner.start(data);
	// Срок жизни билета возобновления связи
	uint32_t lifetime = 0;
	// Если срок жизни билета прочитать не удалось
	if(scanner.number(lifetime, 4) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Добавка к возрасту билета возобновления связи
	uint32_t age = 0;
	// Если добавку к возрасту билета прочитать не удалось
	if(scanner.number(age, 4) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Неповторимое значение билета возобновления связи
	view_t nonce;
	// Если неповторимое значение билета прочитать не удалось
	if(scanner.vector(nonce, 1) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Тело билета возобновления связи
	view_t body;
	// Если тело билета прочитать не удалось
	if(scanner.vector(body, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Перечень расширений билета возобновления связи
	view_t list;
	// Если перечень расширений билета прочитать не удалось
	if(scanner.vector(list, 2) != field::error_t::NONE)
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Если за телом сообщения идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ лишних байтов за телом сообщения
		return error_t::TRAILING;
	/**
	 * Пустое тело билета отвергается: опознать по нему связь выдавшему билет
	 * серверу всё равно нечем
	 */
	if(body.size == 0)
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Выполняем разбор перечня расширений билета
	const error_t error = extensions(list, result.extensions);
	// Если перечень расширений билета разобрать не удалось
	if(error != error_t::NONE)
		// Выводим отказ разбора перечня расширений
		return error;
	// Устанавливаем срок жизни билета возобновления связи
	result.lifetime = lifetime;
	// Устанавливаем добавку к возрасту билета возобновления связи
	result.age = age;
	// Устанавливаем неповторимое значение билета возобновления связи
	result.nonce = nonce;
	// Устанавливаем тело билета возобновления связи
	result.data = body;
	// Выводим успешность разбора тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод составления тела сообщения билета возобновления связи
 *
 * @param ticket составляемый билет возобновления связи
 * @param result накопитель, в который складывается тело сообщения
 *
 * @return       отказ составления тела сообщения
 *
 */
error_t anyks::message::build(const ticket_t & ticket, vector <uint8_t> & result) noexcept {
	// Если тело билета возобновления связи пустое
	if((ticket.data.data == nullptr) || (ticket.data.size == 0))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Объект составителя полей тела сообщения
	field::builder_t builder;
	// Если срок жизни билета записать не удалось
	if(builder.number(ticket.lifetime, 4) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если добавку к возрасту билета записать не удалось
	if(builder.number(ticket.age, 4) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если место под неповторимое значение билета занять не удалось
	if(builder.open(1) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если неповторимое значение билета записать не удалось
	if(builder.bytes(ticket.nonce) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если длину неповторимого значения проставить не удалось
	if(builder.close() != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если место под тело билета занять не удалось
	if(builder.open(2) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если тело билета записать не удалось
	if(builder.bytes(ticket.data) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если длину тела билета проставить не удалось
	if(builder.close() != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Если место под перечень расширений билета занять не удалось
	if(builder.open(2) != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	/**
	 * Выполняем перебор расширений составляемого билета
	 */
	for(size_t i = 0; i < ticket.extensions.size(); i++){
		// Если вид расширения билета записать не удалось
		if(builder.number(ticket.extensions[i].type, 2) != field::error_t::NONE)
			// Выводим отказ невхождения поля в свою длину
			return error_t::LENGTH;
		// Если место под тело расширения занять не удалось
		if(builder.open(2) != field::error_t::NONE)
			// Выводим отказ невхождения поля в свою длину
			return error_t::LENGTH;
		// Если тело расширения записать не удалось
		if(builder.bytes(ticket.extensions[i].data) != field::error_t::NONE)
			// Выводим отказ невхождения поля в свою длину
			return error_t::LENGTH;
		// Если длину тела расширения проставить не удалось
		if(builder.close() != field::error_t::NONE)
			// Выводим отказ невхождения поля в свою длину
			return error_t::LENGTH;
	}
	// Если длину перечня расширений проставить не удалось
	if(builder.close() != field::error_t::NONE)
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	// Получаем составленное тело сообщения билета
	const view_t data = builder.data();
	/**
	 * Выполняем перенос составленного тела сообщения
	 */
	try {
		// Выполняем перенос составленного тела сообщения в накопитель
		result.assign(data.data, data.data + data.size);
	// Если памяти под итог не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод разбора тела сообщения смены ключевого материала
 *
 * @param data   разбираемое тело сообщения
 * @param result вид смены, в который помещается итог разбора
 *
 * @return       отказ разбора тела сообщения
 *
 */
error_t anyks::message::parse(const view_t & data, update_t & result) noexcept {
	// Если тело сообщения не передано
	if((data.data == nullptr) || (data.size == 0))
		// Выводим отказ обрыва тела сообщения
		return error_t::HUNGRY;
	// Если за видом смены ключевого материала идут лишние байты
	if(data.size > 1)
		// Выводим отказ лишних байтов за телом сообщения
		return error_t::TRAILING;
	/**
	 * Выполняем определение вида смены ключевого материала
	 */
	switch(data.data[0]){
		// Если сторона сменила ключи своего направления связи
		case static_cast <uint8_t> (update_t::NOTIFY):
		// Если сторона просит собеседника сменить свои ключи в ответ
		case static_cast <uint8_t> (update_t::REQUEST): {
			// Запоминаем разобранный вид смены ключевого материала
			result = static_cast <update_t> (data.data[0]);
			// Выводим успешность разбора тела сообщения
			return error_t::NONE;
		}
	}
	// Выводим отказ неизвестности вида смены ключевого материала
	return error_t::EMPTY;
}
/**
 * @brief Метод составления тела сообщения смены ключевого материала
 *
 * @param update составляемый вид смены ключевого материала
 * @param result накопитель, в который складывается тело сообщения
 *
 * @return       отказ составления тела сообщения
 *
 */
error_t anyks::message::build(const update_t update, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем составление тела сообщения смены ключевого материала
	 */
	try {
		// Записываем вид смены ключевого материала связи
		result.assign(1, static_cast <uint8_t> (update));
	// Если памяти под итог не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод обращения записи подписи владения ключом
 *
 * @param signature обращаемая подпись владения ключом
 * @param result    место, в которое помещается обращённая подпись
 *
 * @return          отказ обращения записи подписи
 *
 */
error_t anyks::message::reverse(const view_t & signature, uint8_t * result) noexcept {
	// Если обращаемая подпись владения ключом не передана
	if((signature.data == nullptr) || (signature.size == 0) || (result == nullptr))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Если длина обращаемой подписи на две половины не делится
	if((signature.size % 2) != 0)
		// Выводим отказ неверной длины подписи
		return error_t::LENGTH;
	// Определяем длину одной половины подписи владения ключом
	const size_t half = (signature.size / 2);
	/**
	 * Выполняем перебор байтов одной половины подписи
	 */
	for(size_t i = 0; i < half; i++){
		// Обращаем очередной байт первой половины подписи
		const uint8_t first = signature.data[half - i - 1];
		// Обращаем очередной байт второй половины подписи
		const uint8_t second = signature.data[signature.size - i - 1];
		// Записываем очередной байт первой половины подписи
		result[i] = first;
		// Записываем очередной байт второй половины подписи
		result[half + i] = second;
	}
	// Выводим успешность обращения записи подписи
	return error_t::NONE;
}
/**
 * @brief Метод составления подписываемого содержимого владения ключом
 *
 * @param transcript хеш переписки рукопожатия на миг подписания
 * @param server     признак того, что подпись составляется сервером
 * @param result     накопитель, в конец которого дописывается подписываемое содержимое
 *
 * @return           отказ составления подписываемого содержимого
 *
 */
error_t anyks::message::content(const view_t & transcript, const bool server, vector <uint8_t> & result) noexcept {
	// Если хеш переписки рукопожатия не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Получаем название назначения составляемой подписи
	const char * title = (server ? SERVER : CLIENT);
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		/**
		 * Выполняем запись пробелов подписываемого содержимого
		 */
		for(size_t i = 0; i < SPACES; i++)
			// Записываем очередной пробел подписываемого содержимого
			result.push_back(0x20);
		// Записываем название назначения составляемой подписи
		result.insert(result.end(), title, title + ::strlen(title));
		// Записываем разделитель названия назначения и хеша переписки
		result.push_back(0x00);
		// Записываем хеш переписки рукопожатия на миг подписания
		result.insert(result.end(), transcript.data, transcript.data + transcript.size);
	/**
	 * Если памяти под подписываемое содержимое не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления подписываемого содержимого
	return error_t::NONE;
}
/**
 * @brief Метод выработки тела сообщения завершения рукопожатия
 *
 * @param secret     ключ выработки завершения рукопожатия
 * @param transcript хеш переписки рукопожатия на миг завершения
 * @param result     место, в которое помещается тело сообщения
 *
 * @return           отказ выработки тела сообщения
 *
 */
error_t anyks::message::finished(const view_t & secret, const view_t & transcript, uint8_t * result) noexcept {
	// Если ключ выработки завершения либо хеш переписки не переданы
	if((secret.data == nullptr) || (transcript.data == nullptr) || (result == nullptr))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Если выработать имитовставку завершения рукопожатия не удалось
	if(!digest::hmac(digest::type_t::SHORT, secret, transcript, result, static_cast <size_t> (digest::type_t::SHORT)))
		// Выводим отказ выработки имитовставки завершения
		return error_t::DIGEST;
	// Выводим успешность выработки тела сообщения
	return error_t::NONE;
}
/**
 * @brief Метод сличения тел сообщений завершения рукопожатия
 *
 * @param first  первое сличаемое тело сообщения
 * @param second второе сличаемое тело сообщения
 *
 * @return       признак схождения сличаемых тел сообщений
 *
 */
bool anyks::message::compare(const view_t & first, const view_t & second) noexcept {
	// Если сличаемые тела сообщений не переданы
	if((first.data == nullptr) || (second.data == nullptr))
		// Выводим признак расхождения сличаемых тел сообщений
		return false;
	// Если длины сличаемых тел сообщений разошлись
	if(first.size != second.size)
		// Выводим признак расхождения сличаемых тел сообщений
		return false;
	// Накопитель расхождений сличаемых тел сообщений
	uint8_t diff = 0;
	/**
	 * Выполняем перебор байтов сличаемых тел сообщений
	 *
	 * @note Перебор идёт до конца всегда: ранний выход выдал бы временем своей работы,
	 *       сколько байтов принятого завершения сошлось
	 */
	for(size_t i = 0; i < first.size; i++)
		// Накапливаем расхождение очередных байтов сличаемых тел
		diff = static_cast <uint8_t> (diff | (first.data[i] ^ second.data[i]));
	// Выводим признак схождения сличаемых тел сообщений
	return (diff == 0);
}
