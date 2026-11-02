/**
 * @file cmp.cpp
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
 * @brief Ворошитель сообщений управления сертификатами с управлением от покрытия
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
#include <cmp/cmp.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщикам CMP
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Разбираемое сообщение управления сертификатами
		cmp::message_t message;
		// Если внешняя запись PKIMessage разобрана
		if(message.parse(view_t(data, size)) == cmp::error_t::NONE){
			/**
			 * Выполняем разбор тела по виду сообщения
			 */
			switch(static_cast <uint8_t> (message.kind())){
				// Если тело содержит запрос инициализации
				case static_cast <uint8_t> (cmp::body_t::IR):
				// Если тело содержит запрос сертификата
				case static_cast <uint8_t> (cmp::body_t::CR):
				// Если тело содержит запрос обновления ключа
				case static_cast <uint8_t> (cmp::body_t::KUR):
				// Если тело содержит запрос восстановления ключа
				case static_cast <uint8_t> (cmp::body_t::KRR):
				// Если тело содержит запрос перекрёстного сертификата
				case static_cast <uint8_t> (cmp::body_t::CCR): {
					// Разбираемые запросы сертификатов
					std::vector <cmp::request_t> requests;
					// Выполняем разбор содержимого CertReqMessages
					cmp::requests(message.body(), requests);
				} break;
				// Если тело содержит ответ инициализации
				case static_cast <uint8_t> (cmp::body_t::IP):
				// Если тело содержит ответ сертификата
				case static_cast <uint8_t> (cmp::body_t::CP):
				// Если тело содержит ответ обновления ключа
				case static_cast <uint8_t> (cmp::body_t::KUP):
				// Если тело содержит ответ перекрёстного сертификата
				case static_cast <uint8_t> (cmp::body_t::CCP): {
					// Просмотры дополнительных сертификатов ЦС
					std::vector <view_t> caPubs;
					// Разбираемые ответы о сертификатах
					std::vector <cmp::response_t> responses;
					// Выполняем разбор содержимого CertRepMessage
					cmp::response(message.body(), caPubs, responses);
				} break;
			}
		}
		// Выводим код продолжения ворошения
		return 0;
	}
}
