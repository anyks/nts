/**
 * @file ecdhe.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл проверок модуля обмена мимолётными ключами протокола TLS 1.3
 *
 * @note Ключи и общие значения взяты из приложения А описания наборов шифрования на
 *       алгоритмах ГОСТ: примера 1 на кривой GC512C и примера 2 на кривой GC256B
 *
 * @note Ключи и общие значения записаны младшим байтом вперёд, как того велит раздел
 *       6.1.1.3 описания наборов шифрования: разворотом занимается сам модуль
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <cstring>
#include <main.hpp>
#include <curve/parameters.hpp>
#include <agreement/ecdhe.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Контрольные значения проверок
 *
 */
namespace {
	/**
	 * @brief Секретный мимолётный ключ клиента примера 1 приложения А на кривой GC512C
	 *
	 */
	static const uint8_t DC512[] = {
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
	};

	/**
	 * @brief Открытый мимолётный ключ сервера примера 1 приложения А на кривой GC512C
	 *
	 */
	static const uint8_t QS512[] = {
		0x2F, 0x3C, 0x66, 0x3F, 0xE7, 0x47, 0x35, 0xA1,
		0xC4, 0x21, 0x16, 0x0D, 0xF0, 0xF4, 0x32, 0x66,
		0x18, 0x5F, 0xD3, 0x0B, 0x6E, 0x5D, 0x6E, 0x88,
		0xFC, 0x40, 0x61, 0xFA, 0xEA, 0xCA, 0xB3, 0x38,
		0xB1, 0x0A, 0x1B, 0xD2, 0x0C, 0xB0, 0xB4, 0xEE,
		0x75, 0x7E, 0x74, 0xA0, 0x02, 0x7D, 0x40, 0x9F,
		0xE9, 0x37, 0xF0, 0x16, 0x33, 0xA1, 0xE3, 0xF9,
		0xA5, 0x51, 0x8D, 0xEF, 0xD0, 0xF8, 0x9F, 0x9D,
		0x3D, 0x9F, 0x6C, 0xC6, 0x51, 0x41, 0x3D, 0xEC,
		0x2C, 0x74, 0x36, 0x6D, 0x83, 0xC4, 0x7E, 0xE1,
		0xDE, 0x4E, 0x42, 0x1F, 0x65, 0xCD, 0x11, 0x63,
		0xE9, 0x4E, 0xA0, 0xC2, 0xE1, 0x9E, 0xD4, 0x5D,
		0x35, 0x55, 0x8B, 0x93, 0x7D, 0x9B, 0xFD, 0xC5,
		0xEC, 0xC2, 0xB2, 0xA2, 0x1B, 0x4E, 0xC3, 0xD5,
		0x3B, 0x29, 0x57, 0x9A, 0x8F, 0xD5, 0xE0, 0x74,
		0x81, 0x10, 0x28, 0xFB, 0xCF, 0x17, 0x99, 0x4F
	};

	/**
	 * @brief Секретный мимолётный ключ сервера примера 1 приложения А на кривой GC512C
	 *
	 */
	static const uint8_t DS512[] = {
		0xAA, 0x3C, 0xA4, 0xF4, 0xA5, 0x0A, 0xC0, 0x5B,
		0x37, 0x42, 0xB1, 0x35, 0xB5, 0x30, 0xA9, 0xF2,
		0x2A, 0xE4, 0xF5, 0xE1, 0x85, 0x30, 0x1D, 0xEC,
		0x83, 0x2E, 0x77, 0xBA, 0x3B, 0xCD, 0x6A, 0xF1,
		0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84,
		0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84,
		0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84,
		0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x04
	};

	/**
	 * @brief Открытый мимолётный ключ клиента примера 1 приложения А на кривой GC512C
	 *
	 */
	static const uint8_t QC512[] = {
		0x05, 0xEE, 0xBD, 0xF3, 0xDD, 0xC1, 0xD2, 0xF5,
		0xF3, 0x82, 0x24, 0x33, 0x24, 0x12, 0x84, 0xE7,
		0x76, 0x41, 0x48, 0x79, 0x38, 0xEA, 0x88, 0x72,
		0x1F, 0x26, 0x20, 0x3E, 0x97, 0x92, 0xB5, 0xCB,
		0x97, 0xEB, 0x70, 0xEF, 0x02, 0xE8, 0xF7, 0x2B,
		0x74, 0x91, 0xD4, 0xF2, 0xCF, 0xDC, 0x33, 0x2A,
		0xDF, 0x7F, 0x17, 0x78, 0xE8, 0x54, 0xA8, 0x8D,
		0xDC, 0x21, 0x13, 0xFE, 0xC5, 0x27, 0xA1, 0x51,
		0x71, 0xA0, 0x4C, 0xB0, 0xC5, 0x73, 0x79, 0x3A,
		0x7A, 0xEF, 0x9B, 0xBC, 0xA4, 0x86, 0xB6, 0xB0,
		0x46, 0xB2, 0x14, 0x9B, 0x46, 0xF4, 0x33, 0x29,
		0x03, 0xE5, 0xB7, 0xC4, 0x38, 0xAD, 0xD0, 0x5E,
		0x18, 0x5E, 0xFB, 0xF4, 0x55, 0x57, 0x47, 0x5A,
		0x8C, 0xCB, 0xF6, 0xAC, 0xED, 0x1A, 0x2E, 0xB4,
		0x16, 0xF9, 0x16, 0x72, 0x9D, 0x7C, 0xEF, 0x9C,
		0xBD, 0x83, 0x34, 0x98, 0x93, 0x04, 0xAF, 0xAE
	};

	/**
	 * @brief Общее значение обмена мимолётными ключами примера 1 приложения А
	 *
	 */
	static const uint8_t EC512[] = {
		0x4D, 0xE6, 0x0D, 0x21, 0xEA, 0x8F, 0xB9, 0x22,
		0x0D, 0x14, 0x64, 0x23, 0xB4, 0x90, 0xDA, 0x40,
		0xCC, 0xEB, 0xC4, 0x3B, 0xC5, 0x89, 0xDB, 0x79,
		0xB8, 0x31, 0xA4, 0x7D, 0x6B, 0x06, 0x30, 0x07,
		0xDD, 0x03, 0x40, 0x5A, 0x1B, 0x79, 0x76, 0xB6,
		0x23, 0xDC, 0xAA, 0x69, 0xB0, 0x11, 0xAE, 0x10,
		0x6E, 0x7E, 0x41, 0x74, 0x38, 0x5F, 0x86, 0x26,
		0xE1, 0x21, 0xB5, 0x99, 0x43, 0x63, 0xC9, 0x9F
	};

	/**
	 * @brief Секретный мимолётный ключ клиента примера 2 приложения А на кривой GC256B
	 *
	 */
	static const uint8_t DC256[] = {
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
	};

	/**
	 * @brief Открытый мимолётный ключ сервера примера 2 приложения А на кривой GC256B
	 *
	 */
	static const uint8_t QS256[] = {
		0x3D, 0x2F, 0xB0, 0x67, 0xE1, 0x06, 0xCC, 0x99,
		0x80, 0xFB, 0x88, 0x42, 0x81, 0x11, 0x64, 0xBA,
		0x70, 0x8B, 0xBB, 0x50, 0x38, 0xD5, 0xED, 0xFB,
		0xEE, 0x1D, 0x5E, 0x5D, 0xFB, 0xE6, 0xF7, 0x4F,
		0x19, 0x31, 0x21, 0x7C, 0x67, 0xC2, 0xBD, 0xF4,
		0x62, 0x53, 0xDB, 0x9C, 0xE3, 0x48, 0x72, 0x41,
		0xF2, 0xDB, 0xD8, 0x4E, 0x2D, 0xAB, 0xDF, 0x65,
		0x45, 0x58, 0x51, 0xB0, 0xB1, 0x9A, 0xEF, 0xEC
	};

	/**
	 * @brief Секретный мимолётный ключ сервера примера 2 приложения А на кривой GC256B
	 *
	 */
	static const uint8_t DS256[] = {
		0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83,
		0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83,
		0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83,
		0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83, 0x83
	};

	/**
	 * @brief Открытый мимолётный ключ клиента примера 2 приложения А на кривой GC256B
	 *
	 */
	static const uint8_t QC256[] = {
		0xD3, 0x5A, 0xA7, 0x95, 0xC4, 0x52, 0x45, 0x09,
		0x49, 0x59, 0x1D, 0x60, 0xE7, 0xD5, 0xC0, 0x76,
		0x05, 0x6D, 0x66, 0x46, 0xF3, 0xB8, 0x07, 0x08,
		0xCD, 0xC2, 0xE7, 0x03, 0x4D, 0xE8, 0x5F, 0x68,
		0xD1, 0x12, 0x2D, 0xC3, 0x2A, 0x3B, 0x98, 0x6D,
		0x40, 0xFF, 0x91, 0x06, 0x22, 0xA0, 0x6C, 0x12,
		0x26, 0xD9, 0xEC, 0x3A, 0x7D, 0x3A, 0x52, 0xE0,
		0xA3, 0x7C, 0x28, 0x2C, 0x47, 0x60, 0x2A, 0x43
	};

	/**
	 * @brief Общее значение обмена мимолётными ключами примера 2 приложения А
	 *
	 */
	static const uint8_t EC256[] = {
		0x98, 0x5A, 0x86, 0x59, 0xD5, 0x5A, 0x8D, 0x48,
		0xE0, 0xE6, 0x77, 0x13, 0x96, 0x58, 0x0B, 0x2C,
		0xDC, 0xDA, 0x37, 0xE9, 0x2A, 0xEE, 0x18, 0x14,
		0xD1, 0x0E, 0x1B, 0xF2, 0xA4, 0x4F, 0x0D, 0x24
	};
};

/**
 * Проверка выработки общего значения на кривой GC512C
 */
TEST(EcdheTest, Long){
	// Эллиптическая кривая обмена мимолётными ключами
	curve::curve_t curve;
	// Выполняем заведение кривой GC512C
	ASSERT_TRUE(curve::parameters("1.2.643.7.1.2.1.2.3", curve));
	// Место, в которое помещается выработанное общее значение
	uint8_t result[64] = {0};
	// Выполняем выработку общего значения стороной клиента
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(DC512, sizeof(DC512)), view_t(QS512, sizeof(QS512)), result));
	// Сличаем выработанное клиентом значение с контрольным
	ASSERT_EQ(::memcmp(result, EC512, sizeof(EC512)), 0);
	// Выполняем очистку места общего значения
	::memset(result, 0, sizeof(result));
	// Выполняем выработку общего значения стороной сервера
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(DS512, sizeof(DS512)), view_t(QC512, sizeof(QC512)), result));
	// Сличаем выработанное сервером значение с контрольным
	ASSERT_EQ(::memcmp(result, EC512, sizeof(EC512)), 0);
}

/**
 * Проверка выработки общего значения на кривой GC256B
 */
TEST(EcdheTest, Short){
	// Эллиптическая кривая обмена мимолётными ключами
	curve::curve_t curve;
	// Выполняем заведение кривой GC256B
	ASSERT_TRUE(curve::parameters("1.2.643.2.2.35.1", curve));
	// Место, в которое помещается выработанное общее значение
	uint8_t result[32] = {0};
	// Выполняем выработку общего значения стороной клиента
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256)), view_t(QS256, sizeof(QS256)), result));
	// Сличаем выработанное клиентом значение с контрольным
	ASSERT_EQ(::memcmp(result, EC256, sizeof(EC256)), 0);
	// Выполняем очистку места общего значения
	::memset(result, 0, sizeof(result));
	// Выполняем выработку общего значения стороной сервера
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(DS256, sizeof(DS256)), view_t(QC256, sizeof(QC256)), result));
	// Сличаем выработанное сервером значение с контрольным
	ASSERT_EQ(::memcmp(result, EC256, sizeof(EC256)), 0);
}

/**
 * Проверка схождения общего значения у выработанных пар ключей
 */
TEST(EcdheTest, Generate){
	// Эллиптическая кривая обмена мимолётными ключами
	curve::curve_t curve;
	// Выполняем заведение кривой GC256B
	ASSERT_TRUE(curve::parameters("1.2.643.2.2.35.1", curve));
	// Мимолётная пара ключей клиента
	uint8_t first[32] = {0}, opened[64] = {0};
	// Мимолётная пара ключей сервера
	uint8_t second[32] = {0}, answer[64] = {0};
	// Выполняем выработку мимолётной пары ключей клиента
	ASSERT_TRUE(agreement::generate(curve, first, opened));
	// Выполняем выработку мимолётной пары ключей сервера
	ASSERT_TRUE(agreement::generate(curve, second, answer));
	// Проверяем несовпадение выработанных секретных ключей сторон
	ASSERT_NE(::memcmp(first, second, sizeof(first)), 0);
	// Общие значения, выработанные сторонами связи
	uint8_t client[32] = {0}, server[32] = {0};
	// Выполняем выработку общего значения стороной клиента
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(first, sizeof(first)), view_t(answer, sizeof(answer)), client));
	// Выполняем выработку общего значения стороной сервера
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(second, sizeof(second)), view_t(opened, sizeof(opened)), server));
	// Проверяем схождение общих значений сторон связи
	ASSERT_EQ(::memcmp(client, server, sizeof(client)), 0);
}

/**
 * Проверка отвержения испорченных доводов выработки общего значения
 */
TEST(EcdheTest, Reject){
	// Эллиптическая кривая обмена мимолётными ключами
	curve::curve_t curve;
	// Место, в которое помещается выработанное общее значение
	uint8_t result[32] = {0};
	// Проверяем отказ выработки общего значения на незаведённой кривой
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256)), view_t(QS256, sizeof(QS256)), result));
	// Выполняем заведение кривой GC256B
	ASSERT_TRUE(curve::parameters("1.2.643.2.2.35.1", curve));
	// Проверяем отказ выработки общего значения без места итога
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256)), view_t(QS256, sizeof(QS256)), nullptr));
	/**
	 * Непереданное место при заявленной длине - оплошность потребителя: длина есть,
	 * а читать её не из чего. Заслон сверяет переданность места и его длину РАЗНЫМИ
	 * половинами условия, и длина верная тут ничему не помогает
	 */
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(nullptr, sizeof(DC256)), view_t(QS256, sizeof(QS256)), result));
	// Проверяем отказ выработки при непереданном открытом ключе встречной стороны
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256)), view_t(nullptr, sizeof(QS256)), result));
	// Места, в которые помещается вырабатываемая ключевая пара
	uint8_t secret[32] = {0}, opened[64] = {0};
	// Объект незаведённой эллиптической кривой
	curve::curve_t bare;
	// Проверяем отказ выработки ключевой пары на незаведённой кривой
	ASSERT_FALSE(agreement::generate(bare, secret, opened));
	// Проверяем отказ выработки ключевой пары без места секретного ключа
	ASSERT_FALSE(agreement::generate(curve, nullptr, opened));
	// Проверяем отказ выработки ключевой пары без места открытого ключа
	ASSERT_FALSE(agreement::generate(curve, secret, nullptr));
	// Проверяем отказ выработки при секретном ключе длиной не в размер кривой
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256) - 1), view_t(QS256, sizeof(QS256)), result));
	// Проверяем отказ выработки при открытом ключе длиной не в две координаты
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256)), view_t(QS256, sizeof(QS256) - 1), result));
	// Нулевой секретный ключ своей стороны
	uint8_t zero[32] = {0};
	// Проверяем отказ выработки общего значения по нулевому секретному ключу
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(zero, sizeof(zero)), view_t(QS256, sizeof(QS256)), result));
	// Открытый ключ встречной стороны, кривой не принадлежащий
	uint8_t alien[64];
	// Выполняем перенос открытого ключа встречной стороны
	::memcpy(alien, QS256, sizeof(alien));
	// Портим первую координату открытого ключа встречной стороны
	alien[0] ^= 0x01;
	// Проверяем отказ выработки по точке, кривой не принадлежащей
	ASSERT_FALSE(agreement::ecdhe(curve, view_t(DC256, sizeof(DC256)), view_t(alien, sizeof(alien)), result));
	// Проверяем отказ выработки мимолётной пары ключей без мест ключей
	ASSERT_FALSE(agreement::generate(curve, nullptr, alien));
}

/**
 * @brief Проверка отсечения точки малого порядка на кривой с кофактором четыре
 *
 */
TEST(EcdheTest, Torsion){
	curve::curve_t curve;
	// Набор параметров с кофактором четыре: группа TLS GC256A
	ASSERT_TRUE(curve::parameters("1.2.643.7.1.2.1.1.1", curve));
	/**
	 * Точка порядка два (корень x^3 + a*x + b при y = 0) в записи протокола: обе
	 * координаты от младшего байта к старшему
	 */
	static const uint8_t ROOT[32] = {
		0x01, 0x00, 0xfe, 0x73, 0xf5, 0x95, 0xff, 0x15, 0x8e, 0x97, 0x4b, 0x44, 0xd4, 0x78, 0xd9, 0x58,
		0x87, 0x44, 0xfe, 0x5c, 0x19, 0x2a, 0xc4, 0x7e, 0xa6, 0x30, 0x75, 0xdc, 0xe7, 0xa1, 0x4a, 0xaa
	};
	uint8_t key[64] = {0};
	for(size_t i = 0; i < 32; i++)
		key[i] = ROOT[31 - i];
	uint8_t result[32] = {0};
	/**
	 * Раздел 6.1.1.3 черновика наборов ГОСТ: чужой ключ вне подгруппы отвергается
	 * при любом своём секрете. Перебираются секреты обеих чётностей: до правки
	 * нечётный множитель давал успех и выдавал разряд секретного ключа
	 */
	for(uint8_t low = 1; low < 8; low++){
		uint8_t secret[32] = {0};
		secret[0] = low;
		ASSERT_FALSE(agreement::ecdhe(curve, view_t(secret, sizeof(secret)), view_t(key, sizeof(key)), result));
	}
	// Годный ключ той же кривой по-прежнему принимается
	uint8_t mine[32], opened[64];
	ASSERT_TRUE(agreement::generate(curve, mine, opened));
	ASSERT_TRUE(agreement::ecdhe(curve, view_t(mine, sizeof(mine)), view_t(opened, sizeof(opened)), result));
}

/**
 * @brief Проверка снятия кручения умножением на кофактор без проверки подгруппы
 *
 * @details Раздел 6.1.1 RFC 9367 велит проверить принадлежность чужой точки кривой,
 *          умножить её на кофактор с секретом и отвергнуть нулевой итог; проверки
 *          q·Q = O он не просит. Точка Q + T с T порядка два после умножения на
 *          кофактор кручения не несёт: 4·(Q + T) = 4·Q, и общее значение то же, что у Q
 *
 */
TEST(EcdheTest, Cleared){
	// Разбор шестнадцатеричной записи от старшего байта к младшему
	const auto decode = [](const char * text, uint8_t * place, const size_t size) noexcept -> void {
		for(size_t i = 0; i < size; i++){ unsigned v = 0; ::sscanf(text + i * 2, "%2x", &v); place[i] = static_cast <uint8_t> (v); }
	};
	// Запись координат ключа обмена: от младшего байта к старшему
	const auto little = [](const uint8_t * x, const uint8_t * y, uint8_t * key, const size_t size) noexcept -> void {
		for(size_t i = 0; i < size; i++){ key[i] = x[size - 1 - i]; key[size + i] = y[size - 1 - i]; }
	};
	// Наборы с кофактором четыре: GC256A и GC512C, их значения и точки T порядка два
	struct sample_t { const char * oid; size_t size; const char * p, * a, * b, * n, * gx, * gy, * tx; };
	static const sample_t SAMPLES[] = {
		{"1.2.643.7.1.2.1.1.1", 32,
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
			"c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335",
			"295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513",
			"400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67",
			"91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28",
			"32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c",
			"0100fe73f595ff158e974b44d478d9588744fe5c192ac47ea63075dce7a14aaa"},
		{"1.2.643.7.1.2.1.2.3", 64,
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
			"dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3",
			"b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1",
			"3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed",
			"e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148",
			"f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f",
			"9a628f975594ecefd89ba28a2539ffb79c8ab238aeed0851fa5c1abb02b80b44c6734501b83a011dd625cd0b5145091a6d9acd4b1f5c5b1e21b2b249ddfd1271"}
	};
	for(const sample_t & sample : SAMPLES){
		const size_t size = sample.size;
		curve::curve_t curve;
		ASSERT_TRUE(curve::parameters(sample.oid, curve)) << "Набор: " << sample.oid;
		ASSERT_EQ(curve.cofactor(), static_cast <uint64_t> (4)) << "Набор: " << sample.oid;
		uint8_t p[64], a[64], b[64], n[64], gx[64], gy[64], tx[64], ty[64] = {0};
		decode(sample.p, p, size); decode(sample.a, a, size); decode(sample.b, b, size);
		decode(sample.n, n, size); decode(sample.gx, gx, size); decode(sample.gy, gy, size); decode(sample.tx, tx, size);
		// Та же кривая с кофактором один: T читается как есть, и G + T складывается её арифметикой
		curve::curve_t loose;
		ASSERT_TRUE(loose.start(view_t(p, size), view_t(a, size), view_t(b, size), view_t(n, size), view_t(gx, size), view_t(gy, size), 1)) << "Набор: " << sample.oid;
		curve::point_t torsion, base, sum;
		ASSERT_TRUE(loose.point(view_t(tx, size), view_t(ty, size), torsion)) << "Набор: " << sample.oid;
		loose.base(base);
		loose.add(base, torsion, sum);
		uint8_t sx[64], sy[64];
		ASSERT_TRUE(loose.coordinates(sum, sx, sy, size)) << "Набор: " << sample.oid;
		// Чужие ключи в записи протокола: G + T, G и одна T
		uint8_t outside[128], inside[128], bare[128];
		little(sx, sy, outside, size);
		little(gx, gy, inside, size);
		little(tx, ty, bare, size);
		// Свой секрет: меньше порядка подгруппы у обоих наборов
		uint8_t secret[64];
		::memset(secret, 0x1a, size);
		uint8_t first[64], second[64];
		// Точка вне подгруппы, но на кривой, принимается, и общее значение по ней равно значению по G
		ASSERT_TRUE(agreement::ecdhe(curve, view_t(secret, size), view_t(outside, size * 2), first)) << "Набор: " << sample.oid;
		ASSERT_TRUE(agreement::ecdhe(curve, view_t(secret, size), view_t(inside, size * 2), second)) << "Набор: " << sample.oid;
		EXPECT_EQ(::memcmp(first, second, size), 0) << "Набор: " << sample.oid;
		// Одна лишь T обращается кофактором в ноль и отвергается
		EXPECT_FALSE(agreement::ecdhe(curve, view_t(secret, size), view_t(bare, size * 2), first)) << "Набор: " << sample.oid;
	}
}
