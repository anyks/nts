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
#include <chrono>

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

/**
 * @brief Проверка того, что кривые известных наборов заводятся один раз на процесс
 *
 * @details Заведение кривой проверяет точку основания умножением на порядок подгруппы -
 *          полное умножение точки; установка по опознавателю обязана отдавать копию
 *          заведённой кривой, а не заводить её заново. Пин круга 34: пятьдесят установок
 *          набора GC512C по опознавателю дешевле одного заведения того же набора значениями
 *
 */
TEST(ParametersTest, Prepared) {
	// Опознаватель набора GC512C: кофактор четыре, самая дорогая проверка точки основания
	static const char * OID = "1.2.643.7.1.2.1.2.3";
	// Две установки одного набора
	curve::curve_t first, second;
	ASSERT_TRUE(curve::parameters(OID, first));
	ASSERT_TRUE(curve::parameters(OID, second));
	ASSERT_TRUE(first.ready() && second.ready());
	ASSERT_EQ(first.size(), static_cast <size_t> (64));
	ASSERT_EQ(first.cofactor(), static_cast <uint64_t> (4));
	// Образующие точки установленных кривых совпадают слово в слово
	curve::point_t one, two;
	first.base(one);
	second.base(two);
	ASSERT_EQ(::memcmp(&one, &two, sizeof(one)), 0);
	// Значения набора GC512C (id-tc26-gost-3410-2012-512-paramSetC) от старшего байта к младшему
	static const char * P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7";
	static const char * A = "dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3";
	static const char * B = "b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1";
	static const char * N = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed";
	static const char * GX = "e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148";
	static const char * GY = "f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f";
	uint8_t p[64], a[64], b[64], n[64], gx[64], gy[64];
	const char * texts[6] = {P, A, B, N, GX, GY};
	uint8_t * places[6] = {p, a, b, n, gx, gy};
	for(size_t k = 0; k < 6; k++)
		for(size_t i = 0; i < 64; i++){ unsigned v = 0; ::sscanf(texts[k] + i * 2, "%2x", &v); places[k][i] = static_cast <uint8_t> (v); }
	// Заведение кривой значениями извне: проверка точки основания идёт целиком
	curve::curve_t manual;
	const auto before = std::chrono::steady_clock::now();
	ASSERT_TRUE(manual.start(view_t(p, 64), view_t(a, 64), view_t(b, 64), view_t(n, 64), view_t(gx, 64), view_t(gy, 64), 4));
	const double alone = std::chrono::duration <double, std::micro> (std::chrono::steady_clock::now() - before).count();
	// Кривая, заведённая значениями, совпадает с установленной по опознавателю
	manual.base(two);
	ASSERT_EQ(::memcmp(&one, &two, sizeof(one)), 0);
	// Пятьдесят установок по опознавателю: лучшее из трёх повторов
	double copies = 1e300;
	for(size_t r = 0; r < 3; r++){
		const auto start = std::chrono::steady_clock::now();
		for(size_t i = 0; i < 50; i++){
			curve::curve_t copy;
			ASSERT_TRUE(curve::parameters(OID, copy));
		}
		const double spent = std::chrono::duration <double, std::micro> (std::chrono::steady_clock::now() - start).count();
		if(spent < copies) copies = spent;
	}
	/**
	 * Без заготовленных кривых пятьдесят установок стоили бы пятьдесят заведений -
	 * на два порядка дороже одного; с ними - пятьдесят копий, дешевле одного заведения
	 */
	EXPECT_LT(copies, alone) << "50 установок " << copies << " мкс, одно заведение " << alone << " мкс";
}
