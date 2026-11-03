/**
 * @file noise.cpp
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
 * @brief Ворошитель имён и сообщений рукопожатия Noise с управлением от покрытия
 *
 * @note Узор NN не требует постоянных ключей: один вход проверяется как первое
 *       сообщение отвечающего, а затем как второе сообщение инициатора, уже
 *       записавшего своё первое сообщение на неизменном временном ключе
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
#include <noise/noise.hpp>
#include <noise/handshake.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщикам Noise
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Подаваемая область байтов
		const view_t input(data, size);
		// Узор, разбираемый из имени протокола
		noise::pattern_t pattern;
		// Положения заранее разделённых ключей из имени протокола
		noise::psk_t psks;
		// Набор примитивов, разбираемый из имени протокола
		noise::suite_t parsed;
		// Выполняем разбор имени протокола напрямую
		noise::parse(input, pattern, psks, parsed);
		// Набор узора NN без заранее разделённых ключей
		const noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256);
		// Место полезной части, извлекаемой из сообщения
		std::vector <uint8_t> payload(noise::MESSAGE);
		// Сторона отвечающего, ожидающая первое сообщение
		noise::handshake_t responder;
		// Если сторона отвечающего заведена
		if(responder.start(noise::pattern_t::NN, 0, suite, noise::role_t::RESPONDER, view_t())){
			// Вместимость места полезной части
			size_t length = payload.size();
			// Подаём вход как первое сообщение рукопожатия
			responder.read(input, payload.data(), length);
		}
		// Сторона инициатора, ожидающая второе сообщение
		noise::handshake_t initiator;
		// Если сторона инициатора заведена
		if(initiator.start(noise::pattern_t::NN, 0, suite, noise::role_t::INITIATOR, view_t())){
			// Неизменный закрытый временный ключ из контрольного примера flynn/noise
			uint8_t secret[noise::KEY];
			/**
			 * Выполняем заполнение закрытого временного ключа контрольными байтами
			 */
			for(size_t i = 0; i < sizeof(secret); i++)
				// Записываем очередной байт контрольного ключа
				secret[i] = static_cast <uint8_t> (0x20 + i);
			// Если неизменный временный ключ установлен
			if(initiator.ephemeral(view_t(secret, sizeof(secret)))){
				// Место первого сообщения с открытым временным ключом
				uint8_t first[noise::KEY];
				// Вместимость места первого сообщения
				size_t firstSize = sizeof(first);
				// Если первое сообщение с пустой полезной частью записано
				if(initiator.write(view_t(), first, firstSize)){
					// Вместимость места полезной части второго сообщения
					size_t length = payload.size();
					// Подаём вход как защищённый ответ отвечающего
					initiator.read(input, payload.data(), length);
				}
			}
		}
		// Выводим код продолжения ворошения
		return 0;
	}
}
