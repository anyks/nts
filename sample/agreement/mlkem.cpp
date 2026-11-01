/**
 * @file mlkem.cpp
 * @date 2026-09-08
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
 * @brief Пример работы с ML-KEM по FIPS 203 — порождение пары, упаковка и распаковка общего
 *        секрета, и гибрид X25519MLKEM768 как в TLS: секреты обоих механизмов подряд
 *
 * @details Механизм упаковки ключа отличается от обмена Диффи-Хеллмана направлением: секрет
 *          выбирает отправитель, а получатель его распаковывает своим закрытым ключом
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <agreement/mlkem.hpp>
#include <agreement/x25519.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты образца
 *
 */
namespace {
	/**
	 * @brief Функция печати области байтов шестнадцатеричной записью
	 *
	 * @param title подпись
	 * @param data  область байтов
	 * @param size  длина области
	 *
	 */
	void print(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Печатаем подпись
		cout << title << ": ";
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Печатаем байт
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Завершаем строку
		cout << dec << endl;
	}
};

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Доводы образцу не нужны
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Механизм ML-KEM-768 (уровень стойкости 3)
	const agreement::kem_t kem = agreement::kem_t::MLKEM768;
	// Ключ упаковки получателя (открытый): 1184 байта у ML-KEM-768
	uint8_t key[1184];
	// Ключ распаковки получателя (закрытый): 2400 байтов
	uint8_t secret[2400];
	// Если пару получателя породить не удалось
	if(!agreement::generate(kem, key, secret)){
		// Печатаем отказ
		cout << "Породить пару ML-KEM-768 не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем начало ключа упаковки
	::print("Ключ упаковки (начало)", key, 16);
	// Шифртекст упаковки: 1088 байтов
	uint8_t cipher[1088];
	// Общий секрет у отправителя и у получателя
	uint8_t mine[32], theirs[32];
	// Отправитель упаковывает свежий секрет на ключе получателя
	if(!agreement::encapsulate(kem, view_t(key, sizeof(key)), cipher, mine))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Получатель распаковывает секрет своим закрытым ключом
	if(!agreement::decapsulate(kem, view_t(secret, sizeof(secret)), view_t(cipher, sizeof(cipher)), theirs))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем секреты сторон
	::print("Секрет отправителя", mine, sizeof(mine));
	::print("Секрет получателя ", theirs, sizeof(theirs));
	// Если секреты разошлись
	if(::memcmp(mine, theirs, sizeof(mine)) != 0)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Порча шифртекста: неявное отклонение FIPS 203 даёт иной секрет без отказа
	cipher[0] ^= 0x01;
	// Секрет по испорченному шифртексту
	uint8_t spoiled[32];
	// Если распаковка испорченного шифртекста отказала
	if(!agreement::decapsulate(kem, view_t(secret, sizeof(secret)), view_t(cipher, sizeof(cipher)), spoiled))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем итог неявного отклонения
	cout << "Испорченный шифртекст: секрет " << ((::memcmp(spoiled, theirs, sizeof(spoiled)) != 0) ? "иной, отказа нет - как велит FIPS 203" : "тот же (так быть не должно)") << endl;
	// Гибрид X25519MLKEM768 как в TLS (RFC 10024): пары обоих механизмов, секреты подряд ss_mlkem ‖ ss_x25519
	uint8_t curveSecret[32], curvePublic[32], peerSecret[32], peerPublic[32];
	// Если пары X25519 породить не удалось
	if(!entropy::bytes(curveSecret, sizeof(curveSecret)) || !agreement::x25519(view_t(curveSecret, sizeof(curveSecret)), curvePublic) || !entropy::bytes(peerSecret, sizeof(peerSecret)) || !agreement::x25519(view_t(peerSecret, sizeof(peerSecret)), peerPublic))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Общие значения гибрида у сторон: 32 байта ML-KEM и 32 байта X25519
	uint8_t hybrid[64], mirror[64];
	// Отправитель: упаковка ML-KEM и DH со своим временным ключом
	cipher[0] ^= 0x01;
	// Если гибридный секрет отправителя сложить не удалось
	if(!agreement::encapsulate(kem, view_t(key, sizeof(key)), cipher, hybrid) || !agreement::x25519(view_t(peerSecret, sizeof(peerSecret)), view_t(curvePublic, sizeof(curvePublic)), hybrid + 32))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Получатель: распаковка и DH своим ключом с временным ключом отправителя
	if(!agreement::decapsulate(kem, view_t(secret, sizeof(secret)), view_t(cipher, sizeof(cipher)), mirror) || !agreement::x25519(view_t(curveSecret, sizeof(curveSecret)), view_t(peerPublic, sizeof(peerPublic)), mirror + 32))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем гибридный секрет
	::print("Гибрид X25519MLKEM768", hybrid, sizeof(hybrid));
	// Итог сличения гибридных секретов
	const bool same = (::memcmp(hybrid, mirror, sizeof(hybrid)) == 0);
	// Печатаем итог
	cout << "Гибридные секреты сторон " << (same ? "сошлись" : "разошлись") << endl;
	// Затираем тайны
	sys::wipe(secret, sizeof(secret));
	sys::wipe(mine, sizeof(mine));
	sys::wipe(theirs, sizeof(theirs));
	sys::wipe(hybrid, sizeof(hybrid));
	sys::wipe(mirror, sizeof(mirror));
	sys::wipe(curveSecret, sizeof(curveSecret));
	sys::wipe(peerSecret, sizeof(peerSecret));
	// Выходим по итогу сличения
	return (same ? EXIT_SUCCESS : EXIT_FAILURE);
}
