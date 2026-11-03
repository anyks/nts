/**
 * @file dtls.cpp
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
 * @brief Ворошитель записей и кусков сообщений DTLS с управлением от покрытия
 *
 * @note Вход разбирается правилами DTLS 1.3, DTLS 1.2 и DTLS 1.0 независимо:
 *       вид переноса здесь не выбирается по чужим байтам, а задаётся оснасткой
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <message/message.hpp>
#include <datagram/datagram.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Служебные объекты ворошителя сообщений DTLS
 */
namespace {
	/**
	 * @brief Функция разбора целого сообщения, собранного из одного куска
	 *
	 * @param fragment обвязка куска сообщения рукопожатия
	 * @param payload  тело куска сообщения рукопожатия
	 *
	 */
	void parseFragment(const datagram::fragment_t & fragment, const view_t & payload) noexcept {
		// Если кусок не несёт целое сообщение с нулевого смещения
		if((fragment.offset != 0) || (fragment.length != fragment.size))
			// Сборка разрозненных кусков относится к состоянию связи, а не к этому разбору
			return;
		/**
		 * Выполняем разбор целого тела его собственным разборщиком
		 */
		switch(static_cast <uint8_t> (fragment.type)){
			// Если получено приветствие клиента
			case static_cast <uint8_t> (handshake::type_t::CLIENT): {
				// Разбираемое приветствие клиента
				hello::client_t greeting;
				// Выполняем разбор приветствия с меткой возврата состояния
				hello::parse(payload, greeting, true);
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
	 * @brief Функция разбора дейтаграммы правилами выбранного издания DTLS
	 *
	 * @param data    начало разбираемой дейтаграммы
	 * @param size    размер разбираемой дейтаграммы
	 * @param legacy  признак открытого заголовка прежних изданий
	 * @param ancient признак переноса изданием DTLS 1.0
	 *
	 */
	void parseDatagram(const uint8_t * data, const size_t size, const bool legacy, const bool ancient) noexcept {
		// Смещение очередной записи в дейтаграмме
		size_t offset = 0;
		/**
		 * Выполняем перебор записей, упакованных в одну дейтаграмму
		 */
		while(offset < size){
			// Заголовок очередной записи поверх дейтаграммы
			datagram::header_t header;
			// Если заголовок очередной записи не разобран
			if(datagram::parse(view_t(data + offset, size - offset), header, legacy, ancient) != datagram::error_t::NONE)
				// Прекращаем разбор порченой дейтаграммы
				break;
			// Содержимое очередной записи
			const view_t payload(data + offset + header.length, header.size);
			// Если запись несёт кусок сообщения рукопожатия
			if(header.type == record::type_t::HANDSHAKE){
				// Обвязка куска сообщения рукопожатия
				datagram::fragment_t fragment;
				// Если обвязка куска разобрана вместе с его телом
				if(datagram::parse(payload, fragment) == datagram::error_t::NONE)
					// Выполняем разбор целого сообщения, если кусок его несёт
					parseFragment(fragment, view_t(payload.data + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length));
			// Если запись несёт извещение связи
			} else if(header.type == record::type_t::ALERT){
				// Разбираемое извещение связи
				alert::alert_t notice;
				// Выполняем разбор извещения связи
				alert::parse(payload, notice);
			// Если запись несёт подтверждение принятых номеров
			} else if(header.type == record::type_t::ACK){
				// Перечень подтверждённых номеров записей
				std::vector <datagram::number_t> numbers;
				// Выполняем разбор тела подтверждения
				datagram::parse(payload, numbers);
			}
			// Переходим к следующей записи дейтаграммы
			offset += (header.length + header.size);
		}
	}
}

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщикам DTLS
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Подаваемая область байтов
		const view_t input(data, size);
		// Обвязка куска, разбираемого без внешней записи
		datagram::fragment_t fragment;
		// Выполняем разбор куска сообщения напрямую
		datagram::parse(input, fragment);
		// Перечень номеров из тела подтверждения без внешней записи
		std::vector <datagram::number_t> numbers;
		// Выполняем разбор тела подтверждения напрямую
		datagram::parse(input, numbers);
		// Выполняем разбор дейтаграммы правилами DTLS 1.3
		parseDatagram(data, size, false, false);
		// Выполняем разбор дейтаграммы правилами DTLS 1.2
		parseDatagram(data, size, true, false);
		// Выполняем разбор дейтаграммы правилами DTLS 1.0
		parseDatagram(data, size, true, true);
		// Выводим код продолжения ворошения
		return 0;
	}
}
