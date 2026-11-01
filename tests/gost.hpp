/**
 * @file gost.hpp
 * @date 2026-09-23
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
 * @brief Общий для проверок заголовочный файл объявления ГОСТ в настройках связи
 *
 * @details С круга 30 умолчания связи - классика без ГОСТ (намеренное решение 19 движка):
 *          кому нужен ГОСТ, тот объявляет кривые, наборы и схемы подписи сам. Проверки с
 *          подлинностью ГОСТ объявляют их здесь тем же перечнем, что был умолчанием до
 *          круга 30, - ГОСТ впереди, классика следом - и оттого ведут связь ровно так, как
 *          вели прежде: GC512C, «Кузнечик»-MGM, подпись ГОСТ. Долей ключа у клиента с круга
 *          30 идёт по одной на каждый род групп: GC512C, X25519MLKEM768 и X25519; проверка,
 *          которой нужно приветствие в одной дейтаграмме либо просьба о повторе, назначает
 *          доли сама вызовом shares() после своих групп
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию заголовочного файла
 */
#ifndef __ANTS_TESTS_GOST__
/**
 * Поднимаем макрос предохранителя: повторное подключение заголовочного файла отсекается
 */
#define __ANTS_TESTS_GOST__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>

/**
 * Заголовочные файлы проекта
 */
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Подписываемся на пространство имён
 */
using namespace nts;

/**
 * Пространство имён включения ГОСТ в настройки связи проверок
 */
namespace gostlists {
	/**
	 * Кривые обмена ключами: ГОСТ от длинного ключа к короткому, классика следом
	 */
	static const std::vector <extension::group_t> GROUPS = {
		extension::group_t::GC512C, extension::group_t::GC512A,
		extension::group_t::GC256B, extension::group_t::GC256A,
		extension::group_t::X25519MLKEM768, extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1
	};
	/**
	 * Наборы шифрования: ГОСТ впереди, классика издания 1.3 и издания 1.2 следом
	 */
	static const std::vector <protect::suite_t> SUITES = {
		protect::suite_t::KUZNYECHIK_MGM_L, protect::suite_t::MAGMA_MGM_L,
		protect::suite_t::KUZNYECHIK_MGM_S, protect::suite_t::MAGMA_MGM_S,
		protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256,
		protect::suite_t::AES_128_GCM_SHA256,
		protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
		protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384,
		protect::suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256,
		protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA256,
		protect::suite_t::ECDHE_ECDSA_AES_256_CBC_SHA, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA,
		protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA, protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA,
		protect::suite_t::RSA_AES_256_GCM_SHA384, protect::suite_t::RSA_AES_128_GCM_SHA256,
		protect::suite_t::RSA_AES_256_CBC_SHA256, protect::suite_t::RSA_AES_128_CBC_SHA256,
		protect::suite_t::RSA_AES_256_CBC_SHA, protect::suite_t::RSA_AES_128_CBC_SHA,
		protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_PSK_AES_256_CBC_SHA,
		protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA, protect::suite_t::PSK_AES_256_CBC_SHA, protect::suite_t::PSK_AES_128_CBC_SHA
	};
	/**
	 * Схемы подписи: ГОСТ впереди, классика следом
	 */
	static const std::vector <extension::scheme_t> SCHEMES = {
		extension::scheme_t::S256A, extension::scheme_t::S256B,
		extension::scheme_t::S256C, extension::scheme_t::S256D,
		extension::scheme_t::S512A, extension::scheme_t::S512B,
		extension::scheme_t::S512C,
		extension::scheme_t::ECDSA_SECP256R1_SHA256, extension::scheme_t::ECDSA_SECP384R1_SHA384,
		extension::scheme_t::ECDSA_SECP521R1_SHA512,
		extension::scheme_t::RSA_PSS_RSAE_SHA256, extension::scheme_t::RSA_PSS_RSAE_SHA384,
		extension::scheme_t::RSA_PSS_RSAE_SHA512, extension::scheme_t::ED25519,
		extension::scheme_t::RSA_PKCS1_SHA256, extension::scheme_t::RSA_PKCS1_SHA384,
		extension::scheme_t::RSA_PKCS1_SHA512
	};
};

/**
 * @brief Функция включения ГОСТ в настройки связи стороны клиента: ГОСТ впереди классики
 *
 * @param client связь стороны клиента
 *
 */
inline void gosting(client::context_t & client) noexcept {
	// Устанавливаем кривые обмена ключами
	client.groups(gostlists::GROUPS);
	// Устанавливаем наборы шифрования
	client.suites(gostlists::SUITES);
	// Устанавливаем схемы подписи
	client.schemes(gostlists::SCHEMES);
}
/**
 * @brief Функция включения ГОСТ в настройки связи стороны сервера: ГОСТ впереди классики
 *
 * @param server связь стороны сервера
 *
 */
inline void gosting(server::context_t & server) noexcept {
	// Устанавливаем кривые обмена ключами
	server.groups(gostlists::GROUPS);
	// Устанавливаем наборы шифрования
	server.suites(gostlists::SUITES);
	// Устанавливаем схемы подписи
	server.schemes(gostlists::SCHEMES);
}

#endif
