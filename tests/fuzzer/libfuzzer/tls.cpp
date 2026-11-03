/**
 * @file tls.cpp
 * @date 2026-11-02
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
 * @brief Ворошитель записей и сообщений рукопожатия TLS с управлением от покрытия
 *
 * @note Один вход подаётся и потоку записей, и сборщику сообщений напрямую: первый
 *       путь проверяет вложенность проводных форматов, второй не требует от зерна
 *       годной внешней записи для разбора тела рукопожатия
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <message/message.hpp>
#include <handshake/handshake.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Служебные объекты ворошителя сообщений TLS
 */
namespace {
	/**
	 * @brief Функция разбора тела сообщения по его проводному виду
	 *
	 * @param type    вид разбираемого сообщения рукопожатия
	 * @param payload тело разбираемого сообщения рукопожатия
	 *
	 */
	void parseMessage(const handshake::type_t type, const view_t & payload) noexcept {
		/**
		 * Выполняем разбор тела сообщения его собственным разборщиком
		 */
		switch(static_cast <uint8_t> (type)){
			// Если получено приветствие клиента
			case static_cast <uint8_t> (handshake::type_t::CLIENT): {
				// Разбираемое приветствие клиента
				hello::client_t greeting;
				// Выполняем разбор приветствия клиента
				hello::parse(payload, greeting);
			} break;
			// Если получено приветствие сервера
			case static_cast <uint8_t> (handshake::type_t::SERVER): {
				// Разбираемое приветствие сервера
				hello::server_t greeting;
				// Выполняем разбор приветствия сервера
				hello::parse(payload, greeting);
			} break;
			// Если получена цепочка сертификатов
			case static_cast <uint8_t> (handshake::type_t::CERTIFICATE): {
				// Разбираемая цепочка сертификатов
				message::certificate_t certificate;
				// Выполняем разбор цепочки сертификатов
				message::parse(payload, certificate);
			} break;
			// Если получена подпись владения ключом
			case static_cast <uint8_t> (handshake::type_t::VERIFY): {
				// Разбираемая подпись владения ключом
				message::verify_t verify;
				// Выполняем разбор подписи владения ключом
				message::parse(payload, verify);
			} break;
			// Если получен билет возобновления связи
			case static_cast <uint8_t> (handshake::type_t::TICKET): {
				// Разбираемый билет возобновления связи
				message::ticket_t ticket;
				// Выполняем разбор билета возобновления связи
				message::parse(payload, ticket);
			} break;
			// Если получено требование смены ключевого материала
			case static_cast <uint8_t> (handshake::type_t::UPDATE): {
				// Разбираемое требование смены ключевого материала
				message::update_t update;
				// Выполняем разбор требования смены ключевого материала
				message::parse(payload, update);
			} break;
		}
	}
	/**
	 * @brief Функция подачи потока сборщику сообщений рукопожатия
	 *
	 * @param reader  сборщик сообщений рукопожатия
	 * @param payload содержимое записей рукопожатия
	 *
	 */
	void parseHandshake(handshake::reader_t & reader, const view_t & payload) noexcept {
		// Если содержимое записи принято сборщиком сообщений
		if(reader.push(payload) == handshake::error_t::NONE){
			// Обвязка очередного собранного сообщения
			handshake::header_t header;
			// Тело очередного собранного сообщения
			view_t body;
			/**
			 * Выполняем выборку всех сообщений, собранных из поданного содержимого
			 */
			while(reader.next(header, body) == handshake::error_t::NONE)
				// Выполняем разбор тела очередного сообщения по его виду
				parseMessage(header.type, body);
		}
	}
}

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщикам TLS
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Подаваемая область байтов
		const view_t input(data, size);
		// Заголовок записи, разбираемой без накопления
		record::header_t recordHeader;
		// Выполняем разбор одиночного заголовка записи
		record::parse(input, recordHeader);
		// Обвязка сообщения, разбираемого без накопления
		handshake::header_t handshakeHeader;
		// Выполняем разбор одиночной обвязки сообщения
		handshake::parse(input, handshakeHeader);
		// Сборщик записей потокового переноса
		record::reader_t records;
		// Сборщик сообщений, сохраняющийся между записями
		handshake::reader_t handshakes;
		// Длина куска меняется от длины входа, не расходуя его проводные байты
		const size_t chunk = ((size % 31) + 1);
		/**
		 * Выполняем подачу потока кусками разной длины
		 */
		for(size_t offset = 0; offset < size; offset += chunk){
			// Длина очередного куска потока
			const size_t length = (((size - offset) < chunk) ? (size - offset) : chunk);
			// Если сборщик отверг очередной кусок
			if(records.push(view_t(data + offset, length)) != record::error_t::NONE)
				// Прекращаем подачу порченого потока
				break;
			// Заголовок очередной собранной записи
			record::header_t header;
			// Содержимое очередной собранной записи
			view_t payload;
			// Отказ получения очередной записи
			record::error_t error = record::error_t::NONE;
			/**
			 * Выполняем выборку всех записей, собранных из поданного куска
			 */
			while((error = records.next(header, payload)) == record::error_t::NONE){
				// Если запись несёт сообщения рукопожатия
				if(header.type == record::type_t::HANDSHAKE)
					// Подаём содержимое сохраняющемуся сборщику сообщений
					parseHandshake(handshakes, payload);
				// Если запись несёт извещение связи
				else if(header.type == record::type_t::ALERT){
					// Разбираемое извещение связи
					alert::alert_t notice;
					// Выполняем разбор извещения связи
					alert::parse(payload, notice);
				}
			}
			// Если разбор завершился не ожиданием следующих байтов
			if(error != record::error_t::HUNGRY)
				// Прекращаем разбор порченого потока
				break;
		}
		// Сборщик сообщений из входа без внешней записи
		handshake::reader_t direct;
		// Подаём вход сборщику сообщений напрямую
		parseHandshake(direct, input);
		// Выводим код продолжения ворошения
		return 0;
	}
}
