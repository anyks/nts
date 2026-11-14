/**
 * @file message.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл модуля сообщений подтверждения подлинности протокола TLS
 *
 * @section Намеренные решения
 *
 *  1. Обращение записи подписи вынесено отдельным вызовом, а не спрятано в разбор. Разбор
 *    выдаёт то, что пришло по связи, и подмена записи внутри него означала бы, что
 *    составленное обратно сообщение с исходным не сойдётся. Обращение это само себе
 *    обратно, и потому вызов у него один на оба направления.
 *
 *  2. Подписываемое содержимое составляется здесь, а не подписью. Раздел 4.4.3 RFC 8446
 *    задаёт его целиком - шестьдесят четыре пробела, название назначения, ноль и хеш
 *    переписки, - и принадлежит оно рукопожатию, а не подписи: модуль подписи о TLS не
 *    знает вовсе и знать не должен.
 *
 *  3. Сличение завершения рукопожатия ведётся за постоянное время. Завершение доказывает,
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
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::message;

	/**
	 * @brief Отказы работы модуля
	 *
	 * @note Имя заведено своё намеренно: у glibc есть собственный error_t в глобальном
	 *       пространстве имён (расширение GNU в <errno.h>), а помощники лежат в
	 *       безымянном пространстве, откуда поиск имени уходит сразу в глобальное - и
	 *       всякое обращение к error_t выходит там двусмысленным. Своё имя поиск
	 *       находит прежде глобального, и двусмысленности не возникает
	 *
	 */
	typedef message::error_t error_t;

	/**
	 * @brief Функция перевода отказа составителя полей в отказ модуля
	 *
	 * @param failure отказ, которым ответил составитель полей
	 * @return        отказ модуля, отвечающий отказу составителя
	 *
	 * @note Нехватка памяти обязана дойти до вызывающего своим именем: составитель
	 *       перехватывает её сам и отвечает отказом, а не исключением, и молчаливый
	 *       перевод этого отказа в невхождение поля прятал бы истинную причину
	 *
	 */
	static error_t translate(const field::error_t failure) noexcept {
		// Если составитель полей отказом не ответил
		if(failure == field::error_t::NONE)
			// Выводим успешность составления
			return error_t::NONE;
		// Если памяти под накопитель составителя не хватило
		if(failure == field::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Выводим отказ невхождения поля в свою длину
		return error_t::LENGTH;
	}

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
	 * @brief Функция разбора перечня расширений записи цепочки
	 *
	 * @param data   разбираемая область расширений записи
	 * @param result перечень, в который помещаются разобранные расширения
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
		// Битовая карта встреченных видов расширений: повтор ловится за постоянное время (вход недоверенный - цепочка сертификатов и билет)
		uint64_t seen[1024] = {0};
		/**
		 * Выполняем перебор расширений до конца области записи
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
			if((seen[type / 64] >> (type % 64)) & 1)
				// Выводим отказ повторного объявления расширения
				return error_t::EXTENSION;
			// Отмечаем вид расширения встреченным
			seen[type / 64] |= (static_cast <uint64_t> (1) << (type % 64));
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Добавляем очередное расширение в перечень расширений записи
				result.push_back(hello::extension_t(static_cast <uint16_t> (type), body));
			/**
			 * Выполняем перехват ошибок
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
 * @brief Функция разбора тела сообщения цепочки сертификатов
 *
 * @param data   разбираемое тело сообщения
 * @param result сообщение, в которое помещается итог разбора
 * @return       отказ разбора тела сообщения
 *
 */
nts::message::error_t nts::message::parse(const view_t & data, certificate_t & result) noexcept {
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
		// Разбор перечня расширений записи цепочки
		const error_t error = ::extensions(area, entry.extensions);
		// Если перечень расширений записи разобрать не удалось
		if(error != error_t::NONE)
			// Выводим отказ разбора перечня расширений
			return error;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Добавляем разобранную запись в цепочку сертификатов
			entries.push_back(entry);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Устанавливаем разобранные записи цепочки сертификатов
		result.entries = entries;
	/**
	 * Выполняем перехват ошибок
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
 * @brief Функция составления тела сообщения цепочки сертификатов
 *
 * @param message составляемое сообщение цепочки сертификатов
 * @param result  накопитель, в конец которого дописывается тело сообщения
 * @return        отказ составления тела сообщения
 *
 */
nts::message::error_t nts::message::build(const certificate_t & message, vector <uint8_t> & result) noexcept {
	// Объект составителя полей тела сообщения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Открываем поле привязки цепочки к запросу сертификата
		if((failure = builder.open(1)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Записываем привязку цепочки к запросу сертификата
		if((failure = builder.bytes(message.context)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если поле привязки цепочки закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Открываем цепочку сертификатов
		if((failure = builder.open(3)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		/**
		 * Выполняем перебор записей составляемой цепочки сертификатов
		 */
		for(auto & entry : message.entries){
			// Если тело сертификата записи пустое
			if((entry.data.data == nullptr) || (entry.data.size == 0))
				// Выводим отказ пустого обязательного поля
				return error_t::EMPTY;
			// Открываем поле тела сертификата записи
			if((failure = builder.open(3)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Записываем тело сертификата записи
			if((failure = builder.bytes(entry.data)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Если поле тела сертификата закрыть не удалось
			if((failure = builder.close()) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			// Открываем перечень расширений записи цепочки
			if((failure = builder.open(2)) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
			/**
			 * Выполняем перебор расширений записи цепочки сертификатов
			 */
			for(auto & item : entry.extensions){
				// Записываем вид очередного расширения записи
				if((failure = builder.number(static_cast <uint32_t> (item.type), 2)) != field::error_t::NONE)
					// Выводим отказ, которым ответил составитель полей
					return translate(failure);
				// Открываем тело очередного расширения записи
				if((failure = builder.open(2)) != field::error_t::NONE)
					// Выводим отказ, которым ответил составитель полей
					return translate(failure);
				// Записываем тело очередного расширения записи
				if((failure = builder.bytes(item.data)) != field::error_t::NONE)
					// Выводим отказ, которым ответил составитель полей
					return translate(failure);
				// Если тело очередного расширения закрыть не удалось
				if((failure = builder.close()) != field::error_t::NONE)
					// Выводим отказ, которым ответил составитель полей
					return translate(failure);
			}
			// Если перечень расширений записи закрыть не удалось
			if((failure = builder.close()) != field::error_t::NONE)
				// Выводим отказ, которым ответил составитель полей
				return translate(failure);
		}
		// Если цепочку сертификатов закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Получаем составленное тело сообщения
		const view_t data = builder.data();
		// Дописывание тела сообщения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Функция разбора тела сообщения подписи владения ключом
 *
 * @param data   разбираемое тело сообщения
 * @param result сообщение, в которое помещается итог разбора
 * @return       отказ разбора тела сообщения
 *
 */
nts::message::error_t nts::message::parse(const view_t & data, verify_t & result) noexcept {
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
 * @brief Функция составления тела сообщения подписи владения ключом
 *
 * @param message составляемое сообщение подписи владения ключом
 * @param result  накопитель, в конец которого дописывается тело сообщения
 * @return        отказ составления тела сообщения
 *
 */
nts::message::error_t nts::message::build(const verify_t & message, vector <uint8_t> & result) noexcept {
	// Если значение подписи владения ключом пустое
	if((message.signature.data == nullptr) || (message.signature.size == 0))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Объект составителя полей тела сообщения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Записываем схему подписи владения ключом сертификата
		if((failure = builder.number(static_cast <uint32_t> (message.scheme), 2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Открываем поле значения подписи владения ключом
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Записываем значение подписи владения ключом
		if((failure = builder.bytes(message.signature)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если поле значения подписи закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Получаем составленное тело сообщения
		const view_t data = builder.data();
		// Дописывание тела сообщения в накопитель
		result.insert(result.end(), data.data, data.data + data.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Функция разбора тела сообщения билета возобновления связи
 *
 * @param data   разбираемое тело сообщения
 * @param result билет, в который помещается итог разбора
 * @return       отказ разбора тела сообщения
 *
 */
nts::message::error_t nts::message::parse(const view_t & data, ticket_t & result) noexcept {
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
	// Разбор перечня расширений билета
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
 * @brief Функция составления тела сообщения билета возобновления связи
 *
 * @param ticket составляемый билет возобновления связи
 * @param result накопитель, в который складывается тело сообщения
 * @return       отказ составления тела сообщения
 *
 */
nts::message::error_t nts::message::build(const ticket_t & ticket, vector <uint8_t> & result) noexcept {
	// Если тело билета возобновления связи пустое
	if((ticket.data.data == nullptr) || (ticket.data.size == 0))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	/**
	 * Невхождением в длину отказать здесь способно лишь проставление длины: число
	 * заданной ширины в неё входит по самому своему виду, занятие места под поле не
	 * судит ничего, а запись содержимого длину его не объявляет. Нехваткой памяти же
	 * способен отказать всякий шаг составления, и всякий отказ составителя доходит
	 * до вызывающего своим именем: молчаливая запись поля, в свою длину не вошедшего,
	 * либо усечённого нехваткой памяти, была бы хуже
	 */
	// Объект составителя полей тела сообщения
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	// Если срок жизни билета записать не удалось
	if((failure = builder.number(ticket.lifetime, 4)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если добавку к возрасту билета записать не удалось
	if((failure = builder.number(ticket.age, 4)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если место под неповторимое значение билета занять не удалось
	if((failure = builder.open(1)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если неповторимое значение билета записать не удалось
	if((failure = builder.bytes(ticket.nonce)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если длину неповторимого значения проставить не удалось
	if((failure = builder.close()) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если место под тело билета занять не удалось
	if((failure = builder.open(2)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если тело билета записать не удалось
	if((failure = builder.bytes(ticket.data)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если длину тела билета проставить не удалось
	if((failure = builder.close()) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Если место под перечень расширений билета занять не удалось
	if((failure = builder.open(2)) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	/**
	 * Выполняем перебор расширений составляемого билета
	 */
	for(size_t i = 0; i < ticket.extensions.size(); i++){
		// Если вид расширения билета записать не удалось
		if((failure = builder.number(ticket.extensions[i].type, 2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если место под тело расширения занять не удалось
		if((failure = builder.open(2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если тело расширения записать не удалось
		if((failure = builder.bytes(ticket.extensions[i].data)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
		// Если длину тела расширения проставить не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure);
	}
	// Если длину перечня расширений проставить не удалось
	if((failure = builder.close()) != field::error_t::NONE)
		// Выводим отказ, которым ответил составитель полей
		return translate(failure);
	// Получаем составленное тело сообщения билета
	const view_t data = builder.data();
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Перенос составленного тела сообщения в накопитель
		result.assign(data.data, data.data + data.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Функция разбора тела сообщения смены ключевого материала
 *
 * @param data   разбираемое тело сообщения
 * @param result вид смены, в который помещается итог разбора
 * @return       отказ разбора тела сообщения
 *
 */
nts::message::error_t nts::message::parse(const view_t & data, update_t & result) noexcept {
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
 * @brief Функция составления тела сообщения смены ключевого материала
 *
 * @param update составляемый вид смены ключевого материала
 * @param result накопитель, в который складывается тело сообщения
 * @return       отказ составления тела сообщения
 *
 */
nts::message::error_t nts::message::build(const update_t update, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Записываем вид смены ключевого материала связи
		result.assign(1, static_cast <uint8_t> (update));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления тела сообщения
	return error_t::NONE;
}
/**
 * @brief Функция обращения записи подписи владения ключом
 *
 * @param signature обращаемая подпись владения ключом
 * @param result    место, в которое помещается обращённая подпись
 * @return          отказ обращения записи подписи
 *
 */
nts::message::error_t nts::message::reverse(const view_t & signature, uint8_t * result) noexcept {
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
 * @brief Функция составления подписываемого содержимого владения ключом
 *
 * @param transcript хеш переписки рукопожатия на миг подписания
 * @param server     признак того, что подпись составляется сервером
 * @param result     накопитель, в конец которого дописывается подписываемое содержимое
 * @return           отказ составления подписываемого содержимого
 *
 */
nts::message::error_t nts::message::content(const view_t & transcript, const bool server, vector <uint8_t> & result) noexcept {
	// Если хеш переписки рукопожатия не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ пустого обязательного поля
		return error_t::EMPTY;
	// Получаем название назначения составляемой подписи
	const char * title = (server ? SERVER : CLIENT);
	/**
	 * Выполняем перехват ошибок
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
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления подписываемого содержимого
	return error_t::NONE;
}
/**
 * @brief Функция выработки тела сообщения завершения рукопожатия
 *
 * @param secret     ключ выработки завершения рукопожатия
 * @param transcript хеш переписки рукопожатия на миг завершения
 * @param result     место, в которое помещается тело сообщения
 * @return           отказ выработки тела сообщения
 *
 */
nts::message::error_t nts::message::finished(const view_t & secret, const view_t & transcript, uint8_t * result) noexcept {
	// Выводим итог выработки тела сообщения завершения «Стрибогом»-256
	return nts::message::finished(digest::hash_t::STREEBOG256, secret, transcript, result);
}
/**
 * @brief Функция выработки тела сообщения завершения рукопожатия выбранным хешем
 *
 * @param algorithm  хеш набора шифрования, которым ведётся рукопожатие
 * @param secret     ключ выработки завершения рукопожатия
 * @param transcript хеш переписки рукопожатия на миг завершения
 * @param result     место, в которое помещается тело сообщения
 * @return           отказ выработки тела сообщения
 *
 */
nts::message::error_t nts::message::finished(const digest::hash_t algorithm, const view_t & secret, const view_t & transcript, uint8_t * result) noexcept {
	// Если ключ, хеш переписки либо место итога не переданы
	if((secret.data == nullptr) || (transcript.data == nullptr) || (result == nullptr))
		// Выводим отказ выработки тела сообщения
		return error_t::EMPTY;
	// Получаем длину хеша набора шифрования
	const size_t length = digest::length(algorithm);
	// Если хеш набора шифрования не установлен
	if(length == 0)
		// Выводим отказ выработки тела сообщения
		return error_t::DIGEST;
	// Если имитовставку от хеша переписки выработать не удалось
	if(!digest::hmac(algorithm, secret, transcript, result, length))
		// Выводим отказ выработки тела сообщения
		return error_t::DIGEST;
	// Выводим успешность выработки тела сообщения
	return error_t::NONE;
}
/**
 * @brief Функция сличения тел сообщений завершения рукопожатия
 *
 * @param first  первое сличаемое тело сообщения
 * @param second второе сличаемое тело сообщения
 * @return       признак схождения сличаемых тел сообщений
 *
 */
bool nts::message::compare(const view_t & first, const view_t & second) noexcept {
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
	 *
	 */
	for(size_t i = 0; i < first.size; i++)
		// Накапливаем расхождение очередных байтов сличаемых тел
		diff = static_cast <uint8_t> (diff | (first.data[i] ^ second.data[i]));
	// Выводим признак схождения сличаемых тел сообщений
	return (diff == 0);
}

/**
 * @brief Конструктор
 *
 */
nts::message::Verify::Verify() noexcept : scheme(extension::scheme_t::NONE) {}

/**
 * @brief Конструктор
 *
 */
nts::message::Ticket::Ticket() noexcept : lifetime(0), age(0) {}
