/**
 * @file parameters.cpp
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
 * @brief Исходный файл проверок наборов параметров эллиптических кривых
 *
 * @note Всякий набор проверяется трижды: образующая точка обязана принадлежать
 *       кривой, произведение её на порядок подгруппы обязано обращаться в бесконечно
 *       удалённую точку, а выработанная на этой кривой подпись - сходиться при
 *       проверке. Опечатка в значении набора не переживает ни одной из трёх проверок
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <cstring>
#include <main.hpp>
#include <sign/gost.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>
#include <agreement/ecdhe.hpp>
#include <sign/ecdsa.hpp>
#include <entropy/entropy.hpp>
#include <cstring>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Опознаватели известных наборов параметров эллиптических кривых
 */
static const char * IDENTIFIERS[] = {
	"1.2.643.7.1.2.1.2.0",
	"1.2.643.2.2.35.0",
	"1.2.643.7.1.2.1.1.1",
	"1.2.643.7.1.2.1.1.2",
	"1.2.643.7.1.2.1.1.3",
	"1.2.643.7.1.2.1.1.4",
	"1.2.643.7.1.2.1.2.1",
	"1.2.643.7.1.2.1.2.2",
	"1.2.643.7.1.2.1.2.3",
	"1.2.643.2.2.35.1",
	"1.2.643.2.2.35.2",
	"1.2.643.2.2.35.3",
	"1.2.643.2.2.36.0",
	"1.2.643.2.2.36.1"
};

/**
 * @brief Проверка установки кривых по опознавателям наборов параметров
 *
 */
TEST(ParametersTest, Setup) {
	/**
	 * Выполняем перебор известных опознавателей наборов параметров
	 */
	for(size_t i = 0; i < (sizeof(IDENTIFIERS) / sizeof(const char *)); i++){
		// Объект эллиптической кривой
		curve::curve_t curve;
		// Выполняем установку кривой по опознавателю набора параметров
		ASSERT_TRUE(curve::parameters(std::string(IDENTIFIERS[i]), curve)) << "Набор: " << IDENTIFIERS[i];
		// Проверяем готовность установленной кривой к работе
		ASSERT_TRUE(curve.ready()) << "Набор: " << IDENTIFIERS[i];
		/**
		 * Кривые ГОСТ Р 34.10-2012 бывают лишь двух разрядностей, а всякая иная
		 * означала бы порчу значений набора
		 */
		ASSERT_TRUE((curve.size() == 32) || (curve.size() == 64)) << "Набор: " << IDENTIFIERS[i];
		// Образующая точка подгруппы точек кривой
		curve::point_t base;
		// Получаем образующую точку подгруппы точек кривой
		curve.base(base);
		// Проверяем, что образующая точка бесконечно удалённой не оказалась
		ASSERT_FALSE(curve.infinity(base)) << "Набор: " << IDENTIFIERS[i];
		// Множитель, меньший порядка подгруппы точек кривой на единицу
		math::number_t factor;
		// Место, в которое записывается порядок подгруппы точек кривой
		uint8_t buffer[math::NUMBER_SIZE];
		// Единица, вычитаемая из порядка подгруппы точек кривой
		math::number_t unit;
		// Записываем значение единицы
		curve.order().word(1, unit);
		// Нулевое значение, из которого вычитается единица
		math::number_t zero;
		// Записываем нулевое значение
		curve.order().word(0, zero);
		/**
		 * Вычитание единицы из нуля по модулю даёт наибольшее значение, то есть
		 * порядок подгруппы, уменьшенный на единицу
		 */
		curve.order().subtract(zero, unit, factor);
		// Место, в которое помещается кратная образующей точка
		curve::point_t point;
		// Выполняем умножение образующей точки на полученный множитель
		curve.multiply(base, factor, point);
		// Выполняем сложение полученной кратной точки с образующей
		curve.add(point, base, point);
		/**
		 * Умножение образующей точки на порядок подгруппы обязано давать бесконечно
		 * удалённую точку: тем порядок подгруппы и задан
		 */
		ASSERT_TRUE(curve.infinity(point)) << "Набор: " << IDENTIFIERS[i];
		// Отмечаем неиспользуемое место записи порядка подгруппы
		(void) buffer;
	}
}
/**
 * @brief Проверка выработки подписи на всех известных кривых
 *
 */
TEST(ParametersTest, Signature) {
	/**
	 * Выполняем перебор известных опознавателей наборов параметров
	 */
	for(size_t i = 0; i < (sizeof(IDENTIFIERS) / sizeof(const char *)); i++){
		// Объект эллиптической кривой
		curve::curve_t curve;
		// Выполняем установку кривой по опознавателю набора параметров
		ASSERT_TRUE(curve::parameters(std::string(IDENTIFIERS[i]), curve)) << "Набор: " << IDENTIFIERS[i];
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Выполняем установку эллиптической кривой
		ASSERT_TRUE(gost.start(curve)) << "Набор: " << IDENTIFIERS[i];
		// Вырабатываемый ключ подписи
		math::number_t key;
		// Выполняем выработку случайного ключа подписи
		ASSERT_TRUE(entropy::number(curve.order(), key)) << "Набор: " << IDENTIFIERS[i];
		// Место, в которое записывается ключ подписи
		uint8_t secret[math::NUMBER_SIZE];
		// Выполняем запись выработанного ключа подписи
		ASSERT_TRUE(curve.order().store(key, secret, curve.order().size())) << "Набор: " << IDENTIFIERS[i];
		// Выполняем установку выработанного ключа подписи
		ASSERT_TRUE(gost.secret(view_t(secret, curve.order().size()))) << "Набор: " << IDENTIFIERS[i];
		// Место, в которое помещается хеш подписываемого сообщения
		uint8_t digest[64];
		// Выполняем выработку случайного хеша подписываемого сообщения
		ASSERT_TRUE(entropy::bytes(digest, curve.order().size())) << "Набор: " << IDENTIFIERS[i];
		// Место, в которое помещается выработанная подпись
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Выполняем выработку подписи со своим случайным числом
		ASSERT_TRUE(gost.make(view_t(digest, curve.order().size()), signature)) << "Набор: " << IDENTIFIERS[i];
		// Проверяем схождение выработанной подписи
		ASSERT_TRUE(gost.check(view_t(digest, curve.order().size()), view_t(signature, gost.size()))) << "Набор: " << IDENTIFIERS[i];
		// Выполняем порчу первого байта подписи
		signature[0] = static_cast <uint8_t> (signature[0] ^ 0x01);
		// Проверяем отказ проверки испорченной подписи
		ASSERT_FALSE(gost.check(view_t(digest, curve.order().size()), view_t(signature, gost.size()))) << "Набор: " << IDENTIFIERS[i];
		// Место, в которое записывается ключ проверки подписи
		uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
		// Выполняем получение ключа проверки подписи
		ASSERT_TRUE(gost.key(x, y, curve.size())) << "Набор: " << IDENTIFIERS[i];
		// Объект модуля проверки подписи одним лишь ключом проверки
		sign::gost_t other;
		// Выполняем установку эллиптической кривой
		ASSERT_TRUE(other.start(curve)) << "Набор: " << IDENTIFIERS[i];
		/**
		 * Установка ключа проверки подписи разбирает точку с проверкой принадлежности
		 * кривой: тем и подтверждается, что выработанный ключ проверки ей принадлежит
		 */
		ASSERT_TRUE(other.key(view_t(x, curve.size()), view_t(y, curve.size()))) << "Набор: " << IDENTIFIERS[i];
		// Выполняем восстановление первого байта подписи
		signature[0] = static_cast <uint8_t> (signature[0] ^ 0x01);
		// Проверяем схождение подписи одним лишь ключом проверки
		ASSERT_TRUE(other.check(view_t(digest, curve.order().size()), view_t(signature, gost.size()))) << "Набор: " << IDENTIFIERS[i];
	}
}
/**
 * @brief Проверка отказов установки кривой по опознавателю набора параметров
 *
 */
TEST(ParametersTest, Failures) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Проверяем отказ установки кривой по неизвестному опознавателю
	ASSERT_FALSE(curve::parameters(std::string("1.2.643.7.1.2.1.1.9"), curve));
	// Проверяем отказ установки кривой по пустому опознавателю
	ASSERT_FALSE(curve::parameters(std::string(), curve));
	// Проверяем отказ установки кривой по опознавателю с лишним знаком
	ASSERT_FALSE(curve::parameters(std::string("1.2.643.7.1.2.1.1.11"), curve));
	// Проверяем, что кривая после отказов установленной не считается
	ASSERT_FALSE(curve.ready());
}

/**
 * @brief Проверка наборов secp521r1 и secp256k1: установка, размер, обмен ECDHE двух пар и подпись ECDSA
 *
 */
TEST(ParametersTest, Deferred) {
	static const char * OIDS[] = {"1.3.132.0.35", "1.3.132.0.10"};
	static const size_t SIZES[] = {66, 32};
	for(size_t i = 0; i < 2; i++){
		curve::curve_t curve;
		ASSERT_TRUE(curve::parameters(std::string(OIDS[i]), curve)) << OIDS[i];
		ASSERT_EQ(curve.size(), SIZES[i]) << OIDS[i];
		ASSERT_EQ(curve.order().size(), SIZES[i]) << OIDS[i];
		uint8_t secretA[math::NUMBER_SIZE], keyA[math::NUMBER_SIZE * 2], secretB[math::NUMBER_SIZE], keyB[math::NUMBER_SIZE * 2];
		ASSERT_TRUE(agreement::generate(curve, secretA, keyA)) << OIDS[i];
		ASSERT_TRUE(agreement::generate(curve, secretB, keyB)) << OIDS[i];
		uint8_t sharedA[math::NUMBER_SIZE], sharedB[math::NUMBER_SIZE];
		ASSERT_TRUE(agreement::ecdhe(curve, view_t(secretA, SIZES[i]), view_t(keyB, SIZES[i] * 2), sharedA)) << OIDS[i];
		ASSERT_TRUE(agreement::ecdhe(curve, view_t(secretB, SIZES[i]), view_t(keyA, SIZES[i] * 2), sharedB)) << OIDS[i];
		ASSERT_EQ(::memcmp(sharedA, sharedB, SIZES[i]), 0) << OIDS[i];
		sign::ecdsa_t ecdsa;
		ASSERT_TRUE(ecdsa.start(curve)) << OIDS[i];
		uint8_t secret[math::NUMBER_SIZE];
		ASSERT_TRUE(ecdsa.generate(secret, SIZES[i])) << OIDS[i];
		uint8_t digest[64];
		ASSERT_TRUE(entropy::bytes(digest, sizeof(digest))) << OIDS[i];
		uint8_t signature[math::NUMBER_SIZE * 2];
		ASSERT_TRUE(ecdsa.make(digest::hash_t::SHA512, view_t(digest, sizeof(digest)), signature)) << OIDS[i];
		ASSERT_TRUE(ecdsa.check(view_t(digest, sizeof(digest)), view_t(signature, SIZES[i] * 2))) << OIDS[i];
		signature[3] ^= 0x01;
		ASSERT_FALSE(ecdsa.check(view_t(digest, sizeof(digest)), view_t(signature, SIZES[i] * 2))) << OIDS[i];
	}
}
