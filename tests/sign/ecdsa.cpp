/**
 * @file ecdsa.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок модуля электронной подписи ECDSA
 *
 * @note Контрольные примеры взяты из приложений A.2.5 (P-256) и A.2.6 (P-384)
 *       RFC 6979 целиком: ключ подписи, ключ проверки, выведенное случайное число
 *       и обе части подписи для сообщений «sample» и «test». Сверх векторов подписи
 *       сличаются с системным openssl в обе стороны
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <iostream>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <unistd.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <sign/ecdsa.hpp>
#include <digest/hash.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Опознаватели наборов параметров кривых P-256 и P-384
 */
static const char * P256 = "1.2.840.10045.3.1.7";
static const char * P384 = "1.3.132.0.34";

/**
 * Ключ подписи приложения A.2.5 RFC 6979 (P-256)
 */
static const char * SECRET256 = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

/**
 * Ключ проверки подписи приложения A.2.5 RFC 6979 (P-256)
 */
static const char * PUBLIC256X = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
static const char * PUBLIC256Y = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

/**
 * Ключ подписи приложения A.2.6 RFC 6979 (P-384)
 */
static const char * SECRET384 = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";

/**
 * Ключ проверки подписи приложения A.2.6 RFC 6979 (P-384)
 */
static const char * PUBLIC384X = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13";
static const char * PUBLIC384Y = "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";

/**
 * @brief Контрольный пример RFC 6979
 *
 */
typedef struct Vector {
	// Подписываемое сообщение
	const char * message;
	// Алгоритм хеширования сообщения
	digest::hash_t algorithm;
	// Выведенное случайное число
	const char * k;
	// Ожидаемая подпись
	const char * signature;
} vector_t;

/**
 * Контрольные примеры приложения A.2.5 RFC 6979 (P-256)
 */
static const vector_t VECTORS256[] = {
	{
		"sample", digest::hash_t::SHA256,
		"a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
		"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
		"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
	},{
		"test", digest::hash_t::SHA256,
		"d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
		"f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
		"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
	},{
		"sample", digest::hash_t::SHA512,
		"5fa81c63109badb88c1f367b47da606da28cad69aa22c4fe6ad7df73a7173aa5",
		"8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00"
		"2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe"
	}
};

/**
 * Контрольные примеры приложения A.2.6 RFC 6979 (P-384)
 */
static const vector_t VECTORS384[] = {
	{
		"sample", digest::hash_t::SHA384,
		"94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9",
		"94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46"
		"99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8"
	},{
		"test", digest::hash_t::SHA384,
		"015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ada71f4a459bc0da98adb95837db8312ea",
		"8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db"
		"ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5"
	}
};

/**
 * Запись DER подписи сообщения «sample» по SHA-256, снятая с openssl
 */
static const char * DER256 =
	"3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	"022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
 *
 * @return     число разобранных байтов
 *
 */
static size_t bytes(const std::string & text, uint8_t * data) {
	// Число разобранных байтов
	size_t result = 0;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; (i * 2) + 1 < text.size(); i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		data[result++] = value;
	}
	// Выводим число разобранных байтов
	return result;
}
/**
 * @brief Метод сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
 *
 * @return     собранная запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор собираемых байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(data[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[data[i] & 0x0F]);
	}
	// Выводим собранную запись
	return result;
}
/**
 * @brief Метод хеширования сообщения
 *
 * @param algorithm алгоритм хеширования
 * @param message   хешируемое сообщение
 * @param result    место, в которое помещается хеш
 *
 * @return          длина хеша
 *
 */
static size_t summarize(const digest::hash_t algorithm, const std::string & message, uint8_t * result) {
	// Получаем длину хеша алгоритма
	const size_t length = digest::length(algorithm);
	// Выполняем хеширование сообщения
	if(!digest::hash(algorithm, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, length))
		// Выводим нулевую длину как отказ
		return 0;
	// Выводим длину хеша
	return length;
}
/**
 * @brief Метод чтения файла целиком
 *
 * @param path путь к читаемому файлу
 *
 * @return     содержимое файла
 *
 */
static std::string slurp(const std::string & path) {
	// Открываем файл на чтение
	std::ifstream file(path, std::ios::binary);
	// Читаем содержимое файла в поток
	std::stringstream stream;
	// Переливаем содержимое файла
	stream << file.rdbuf();
	// Выводим содержимое файла
	return stream.str();
}
/**
 * @brief Метод извлечения шестнадцатеричной записи из текстовой выдачи openssl
 *
 * @param output выдача openssl
 * @param begin  метка, за которой начинается запись
 * @param end    метка, на которой запись обрывается
 *
 * @return       запись без разделителей и пробелов
 *
 */
static std::string extract(const std::string & output, const std::string & begin, const std::string & end) {
	// Извлекаемая запись
	std::string result;
	// Ищем начало записи
	const size_t start = output.find(begin);
	// Если начало записи не найдено
	if(start == std::string::npos)
		// Выводим пустую запись
		return result;
	// Ищем конец записи
	const size_t stop = output.find(end, start + begin.size());
	/**
	 * Выполняем перебор знаков между метками
	 */
	for(size_t i = (start + begin.size()); i < ((stop == std::string::npos) ? output.size() : stop); i++){
		// Извлекаем очередной знак
		const char letter = output[i];
		// Если знак шестнадцатеричный
		if(((letter >= '0') && (letter <= '9')) || ((letter >= 'a') && (letter <= 'f')))
			// Дописываем знак в запись
			result.append(1, letter);
	}
	// Выводим извлечённую запись
	return result;
}

/**
 * @brief Проверка наборов параметров кривых P-256 и P-384
 *
 */
TEST(EcdsaTest, Parameters) {
	// Опознаватели проверяемых кривых
	const char * identifiers[] = {P256, P384};
	// Ожидаемые размеры координат проверяемых кривых
	const size_t sizes[] = {32, 48};
	// Ожидаемые координаты образующих точек проверяемых кривых
	const char * gx[] = {
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
	};
	// Ожидаемые вторые координаты образующих точек
	const char * gy[] = {
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
		"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
	};
	/**
	 * Выполняем перебор проверяемых кривых
	 */
	for(size_t i = 0; i < 2; i++){
		// Объект эллиптической кривой
		curve::curve_t curve;
		// Выполняем установку кривой по опознавателю
		ASSERT_TRUE(curve::parameters(std::string(identifiers[i]), curve)) << "Набор: " << identifiers[i];
		// Проверяем готовность кривой
		ASSERT_TRUE(curve.ready()) << "Набор: " << identifiers[i];
		// Проверяем размер координаты
		ASSERT_EQ(curve.size(), sizes[i]) << "Набор: " << identifiers[i];
		// Проверяем размер порядка подгруппы
		ASSERT_EQ(curve.order().size(), sizes[i]) << "Набор: " << identifiers[i];
		// Проверяем кофактор кривой
		ASSERT_EQ(curve.cofactor(), static_cast <uint64_t> (1)) << "Набор: " << identifiers[i];
		// Места, в которые помещаются координаты образующей точки
		uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
		// Выполняем разбор координат образующей точки
		bytes(gx[i], x);
		bytes(gy[i], y);
		// Разобранная точка
		curve::point_t point;
		// Проверяем принадлежность образующей точки кривой
		ASSERT_TRUE(curve.point(view_t(x, sizes[i]), view_t(y, sizes[i]), point)) << "Набор: " << identifiers[i];
		// Образующая точка кривой
		curve::point_t base;
		// Получаем образующую точку кривой
		curve.base(base);
		// Места, в которые записываются координаты образующей точки
		uint8_t bx[math::NUMBER_SIZE], by[math::NUMBER_SIZE];
		// Выполняем запись координат образующей точки
		ASSERT_TRUE(curve.coordinates(base, bx, by, sizes[i])) << "Набор: " << identifiers[i];
		// Сличаем первую координату образующей точки
		ASSERT_EQ(text(bx, sizes[i]), std::string(gx[i])) << "Набор: " << identifiers[i];
		// Сличаем вторую координату образующей точки
		ASSERT_EQ(text(by, sizes[i]), std::string(gy[i])) << "Набор: " << identifiers[i];
		// Ноль и единица порядка подгруппы
		math::number_t zero, one, last;
		// Получаем ноль порядка
		curve.order().word(0, zero);
		// Получаем единицу порядка
		curve.order().word(1, one);
		// Получаем порядок без единицы
		curve.order().subtract(zero, one, last);
		// Кратная точка образующей по порядку без единицы
		curve::point_t opposite;
		// Выполняем умножение образующей точки на порядок без единицы
		curve.multiply(base, last, opposite);
		// Места, в которые записываются координаты кратной точки
		uint8_t ox[math::NUMBER_SIZE], oy[math::NUMBER_SIZE];
		// Выполняем запись координат кратной точки
		ASSERT_TRUE(curve.coordinates(opposite, ox, oy, sizes[i])) << "Набор: " << identifiers[i];
		/**
		 * Кратная по порядку без единицы есть точка, противоположная образующей:
		 * первые координаты равны, а сумма с образующей бесконечно удалена - тем
		 * подтверждается, что порядок набора верен
		 */
		ASSERT_EQ(text(ox, sizes[i]), std::string(gx[i])) << "Набор: " << identifiers[i];
		// Сумма противоположных точек
		curve::point_t sum;
		// Выполняем сложение противоположных точек
		curve.add(base, opposite, sum);
		// Проверяем бесконечную удалённость суммы
		ASSERT_TRUE(curve.infinity(sum)) << "Набор: " << identifiers[i];
	}
}
/**
 * @brief Метод проверки контрольных примеров RFC 6979 на кривой
 *
 * @param identifier опознаватель кривой
 * @param secret     ключ подписи
 * @param px         первая координата ключа проверки
 * @param py         вторая координата ключа проверки
 * @param vectors    контрольные примеры
 * @param count      число контрольных примеров
 *
 */
static void rfc6979(const char * identifier, const char * secret, const char * px, const char * py, const vector_t * vectors, const size_t count) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters(std::string(identifier), curve));
	// Объект модуля электронной подписи
	sign::ecdsa_t ecdsa;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(ecdsa.start(curve));
	// Размер координаты кривой
	const size_t size = curve.size();
	// Место, в которое помещается ключ подписи
	uint8_t key[math::NUMBER_SIZE];
	// Выполняем установку ключа подписи
	ASSERT_TRUE(ecdsa.secret(view_t(key, bytes(secret, key))));
	// Места, в которые записывается ключ проверки подписи
	uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
	// Выполняем получение ключа проверки подписи
	ASSERT_TRUE(ecdsa.key(x, y, size));
	// Сличаем координаты ключа проверки с контрольным примером
	ASSERT_EQ(text(x, size), std::string(px));
	ASSERT_EQ(text(y, size), std::string(py));
	// Проверяем размер подписи
	ASSERT_EQ(ecdsa.size(), size * 2);
	/**
	 * Выполняем перебор контрольных примеров
	 */
	for(size_t i = 0; i < count; i++){
		// Место, в которое помещается хеш сообщения
		uint8_t digest[64];
		// Выполняем хеширование сообщения
		const size_t length = summarize(vectors[i].algorithm, std::string(vectors[i].message), digest);
		// Проверяем успешность хеширования
		ASSERT_GT(length, static_cast <size_t> (0)) << "Пример: " << i;
		// Место, в которое помещается выработанная подпись
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Выполняем выработку подписи по RFC 6979
		ASSERT_TRUE(ecdsa.make(vectors[i].algorithm, view_t(digest, length), signature)) << "Пример: " << i;
		// Сличаем выработанную подпись с контрольным примером
		ASSERT_EQ(text(signature, size * 2), std::string(vectors[i].signature)) << "Пример: " << i;
		// Проверяем схождение выработанной подписи
		ASSERT_TRUE(ecdsa.check(view_t(digest, length), view_t(signature, size * 2))) << "Пример: " << i;
		// Место, в которое помещается случайное число контрольного примера
		uint8_t k[math::NUMBER_SIZE];
		// Место, в которое помещается подпись переданным случайным числом
		uint8_t other[math::NUMBER_SIZE * 2];
		// Выполняем выработку подписи случайным числом контрольного примера
		ASSERT_TRUE(ecdsa.make(view_t(digest, length), view_t(k, bytes(vectors[i].k, k)), other)) << "Пример: " << i;
		// Сличаем подпись переданным числом с подписью выведенным числом
		ASSERT_EQ(text(other, size * 2), std::string(vectors[i].signature)) << "Пример: " << i;
		// Проверяем воспроизводимость подписи по RFC 6979
		ASSERT_TRUE(ecdsa.make(vectors[i].algorithm, view_t(digest, length), other)) << "Пример: " << i;
		ASSERT_EQ(::memcmp(signature, other, size * 2), 0) << "Пример: " << i;
		// Объект модуля проверки одним лишь ключом проверки
		sign::ecdsa_t verifier;
		// Выполняем установку эллиптической кривой
		ASSERT_TRUE(verifier.start(curve));
		// Выполняем установку ключа проверки подписи
		ASSERT_TRUE(verifier.key(view_t(x, size), view_t(y, size)));
		// Проверяем схождение подписи одним лишь ключом проверки
		ASSERT_TRUE(verifier.check(view_t(digest, length), view_t(signature, size * 2))) << "Пример: " << i;
		// Проверяем отказ выработки подписи без ключа подписи
		ASSERT_FALSE(verifier.make(vectors[i].algorithm, view_t(digest, length), other)) << "Пример: " << i;
	}
}
/**
 * @brief Проверка контрольных примеров приложения A.2.5 RFC 6979 (P-256)
 *
 */
TEST(EcdsaTest, Rfc6979P256) {
	// Выполняем проверку контрольных примеров на кривой P-256
	rfc6979(P256, SECRET256, PUBLIC256X, PUBLIC256Y, VECTORS256, sizeof(VECTORS256) / sizeof(vector_t));
}
/**
 * @brief Проверка контрольных примеров приложения A.2.6 RFC 6979 (P-384)
 *
 */
TEST(EcdsaTest, Rfc6979P384) {
	// Выполняем проверку контрольных примеров на кривой P-384
	rfc6979(P384, SECRET384, PUBLIC384X, PUBLIC384Y, VECTORS384, sizeof(VECTORS384) / sizeof(vector_t));
}
/**
 * @brief Проверка записи и разбора подписи в виде DER
 *
 */
TEST(EcdsaTest, Der) {
	// Место, в которое помещается сырая подпись контрольного примера
	uint8_t raw[64];
	// Выполняем разбор сырой подписи
	ASSERT_EQ(bytes(VECTORS256[0].signature, raw), static_cast <size_t> (64));
	// Место, в которое помещается запись DER
	std::vector <uint8_t> der;
	// Выполняем запись подписи в виде DER
	ASSERT_TRUE(sign::encode(view_t(raw, sizeof(raw)), der));
	// Сличаем запись с записью, снятой с openssl
	ASSERT_EQ(text(der.data(), der.size()), std::string(DER256));
	// Место, в которое помещается разобранная подпись
	uint8_t parsed[64];
	// Выполняем разбор записи DER
	ASSERT_TRUE(sign::decode(view_t(der.data(), der.size()), parsed, sizeof(parsed)));
	// Сличаем разобранную подпись с исходной
	ASSERT_EQ(::memcmp(raw, parsed, sizeof(raw)), 0);
	// Подпись со второй частью без старшего разряда, записанной короче
	uint8_t shorter[64];
	// Выполняем разбор сырой подписи примера «test»
	ASSERT_EQ(bytes(VECTORS256[1].signature, shorter), static_cast <size_t> (64));
	// Выполняем запись подписи в виде DER
	ASSERT_TRUE(sign::encode(view_t(shorter, sizeof(shorter)), der));
	/**
	 * Вторая часть подписи начинается байтом 0x01: ведущего нуля ей не нужно, и
	 * запись целиком на байт короче - 71 байт вместо 72, ровно как у openssl
	 */
	ASSERT_EQ(der.size(), static_cast <size_t> (71));
	// Выполняем разбор записи DER
	ASSERT_TRUE(sign::decode(view_t(der.data(), der.size()), parsed, sizeof(parsed)));
	// Сличаем разобранную подпись с исходной
	ASSERT_EQ(::memcmp(shorter, parsed, sizeof(shorter)), 0);
	// Нулевая подпись записывается двумя нулевыми числами
	uint8_t zero[64];
	// Выполняем обнуление подписи
	::memset(zero, 0, sizeof(zero));
	// Выполняем запись нулевой подписи
	ASSERT_TRUE(sign::encode(view_t(zero, sizeof(zero)), der));
	// Сличаем запись нулевой подписи
	ASSERT_EQ(text(der.data(), der.size()), std::string("3006020100020100"));
	// Выполняем разбор нулевой подписи
	ASSERT_TRUE(sign::decode(view_t(der.data(), der.size()), parsed, sizeof(parsed)));
	// Сличаем разобранную нулевую подпись
	ASSERT_EQ(::memcmp(zero, parsed, sizeof(zero)), 0);
	// Проверяем отказ записи непереданной подписи
	ASSERT_FALSE(sign::encode(view_t(), der));
	// Проверяем отказ записи подписи нечётной длины
	ASSERT_FALSE(sign::encode(view_t(raw, 63), der));
	// Проверяем отказ разбора в непереданное место
	ASSERT_FALSE(sign::decode(view_t(der.data(), der.size()), nullptr, sizeof(parsed)));
	// Проверяем отказ разбора в место нечётной длины
	ASSERT_FALSE(sign::decode(view_t(der.data(), der.size()), parsed, 63));
	// Проверяем отказ разбора непереданной записи
	ASSERT_FALSE(sign::decode(view_t(), parsed, sizeof(parsed)));
	// Место, в которое помещается испорченная запись
	uint8_t broken[80];
	// Выполняем разбор записи, снятой с openssl
	const size_t count = bytes(DER256, broken);
	// Проверяем отказ разбора записи с лишними данными за последовательностью
	ASSERT_FALSE(sign::decode(view_t(broken, count + 1), parsed, sizeof(parsed)));
	// Проверяем отказ разбора оборванной записи
	ASSERT_FALSE(sign::decode(view_t(broken, count - 1), parsed, sizeof(parsed)));
	// Проверяем отказ разбора числа длиннее половины места
	ASSERT_FALSE(sign::decode(view_t(broken, count), parsed, 32));
	// Выполняем порчу метки первого числа
	broken[2] = 0x04;
	// Проверяем отказ разбора записи с чужой меткой
	ASSERT_FALSE(sign::decode(view_t(broken, count), parsed, sizeof(parsed)));
	// Возвращаем метку первого числа
	broken[2] = 0x02;
	// Отбрасываем ведущий ноль знака: число становится отрицательным
	broken[4] = 0xef;
	// Проверяем отказ разбора отрицательного числа
	ASSERT_FALSE(sign::decode(view_t(broken, count), parsed, sizeof(parsed)));
	// Возвращаем ведущий ноль знака
	broken[4] = 0x00;
	// Ставим лишний ведущий ноль: запись перестаёт быть кратчайшей
	broken[5] = 0x00;
	// Проверяем отказ разбора некратчайшей записи
	ASSERT_FALSE(sign::decode(view_t(broken, count), parsed, sizeof(parsed)));
	// Запись с одним числом внутри последовательности
	const uint8_t single[] = {0x30, 0x03, 0x02, 0x01, 0x05};
	// Проверяем отказ разбора записи с одним числом
	ASSERT_FALSE(sign::decode(view_t(single, sizeof(single)), parsed, sizeof(parsed)));
	// Запись с тремя числами внутри последовательности
	const uint8_t triple[] = {0x30, 0x09, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05};
	// Проверяем отказ разбора записи с тремя числами
	ASSERT_FALSE(sign::decode(view_t(triple, sizeof(triple)), parsed, sizeof(parsed)));
	// Запись, начинающаяся не последовательностью
	const uint8_t set[] = {0x31, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05};
	// Проверяем отказ разбора записи, начинающейся не последовательностью
	ASSERT_FALSE(sign::decode(view_t(set, sizeof(set)), parsed, sizeof(parsed)));
}
/**
 * @brief Проверка отказов модуля электронной подписи
 *
 */
TEST(EcdsaTest, Failures) {
	// Объект модуля электронной подписи
	sign::ecdsa_t ecdsa;
	// Проверяем отказ работы модуля до установки кривой
	ASSERT_FALSE(ecdsa.ready());
	// Проверяем нулевой размер подписи до установки кривой
	ASSERT_EQ(ecdsa.size(), static_cast <size_t> (0));
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], digest[64], signature[64];
	// Выполняем разбор ключа подписи
	bytes(SECRET256, secret);
	// Выполняем хеширование сообщения «sample»
	const size_t length = summarize(digest::hash_t::SHA256, "sample", digest);
	// Проверяем успешность хеширования
	ASSERT_EQ(length, static_cast <size_t> (32));
	// Выполняем разбор подписи контрольного примера
	bytes(VECTORS256[0].signature, signature);
	// Проверяем отказ установки ключа подписи до установки кривой
	ASSERT_FALSE(ecdsa.secret(view_t(secret, sizeof(secret))));
	// Места, в которые помещаются координаты ключа проверки подписи
	uint8_t x[32], y[32];
	// Проверяем отказ получения ключа проверки до установки кривой
	ASSERT_FALSE(ecdsa.key(x, y, sizeof(x)));
	// Выполняем разбор координат ключа проверки
	bytes(PUBLIC256X, x);
	bytes(PUBLIC256Y, y);
	// Проверяем отказ установки ключа проверки до установки кривой
	ASSERT_FALSE(ecdsa.key(view_t(x, sizeof(x)), view_t(y, sizeof(y))));
	// Проверяем отказ выработки подписи до установки кривой
	ASSERT_FALSE(ecdsa.make(digest::hash_t::SHA256, view_t(digest, length), signature));
	// Проверяем отказ выработки подписи переданным числом до установки кривой
	ASSERT_FALSE(ecdsa.make(view_t(digest, length), view_t(secret, sizeof(secret)), signature));
	// Проверяем отказ проверки подписи до установки кривой
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Объект неустановленной эллиптической кривой
	curve::curve_t empty;
	// Проверяем отказ установки неготовой кривой
	ASSERT_FALSE(ecdsa.start(empty));
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой P-256
	ASSERT_TRUE(curve::parameters(std::string(P256), curve));
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(ecdsa.start(curve));
	// Проверяем готовность модуля к работе
	ASSERT_TRUE(ecdsa.ready());
	// Проверяем размер подписи
	ASSERT_EQ(ecdsa.size(), static_cast <size_t> (64));
	// Место, в которое помещается нулевой ключ подписи
	uint8_t zero[32];
	// Выполняем обнуление ключа подписи
	::memset(zero, 0, sizeof(zero));
	// Проверяем отказ установки нулевого ключа подписи
	ASSERT_FALSE(ecdsa.secret(view_t(zero, sizeof(zero))));
	// Место, в которое помещается ключ подписи не меньше порядка
	uint8_t large[32];
	// Выполняем заполнение ключа подписи единицами
	::memset(large, 0xFF, sizeof(large));
	// Проверяем отказ установки ключа подписи не меньше порядка
	ASSERT_FALSE(ecdsa.secret(view_t(large, sizeof(large))));
	// Проверяем отказ получения ключа проверки до его установки
	ASSERT_FALSE(ecdsa.key(x, y, sizeof(x)));
	// Проверяем отказ проверки подписи без ключа проверки
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Выполняем порчу первой координаты ключа проверки
	x[0] = static_cast <uint8_t> (x[0] ^ 0x01);
	// Проверяем отказ установки точки, не принадлежащей кривой
	ASSERT_FALSE(ecdsa.key(view_t(x, sizeof(x)), view_t(y, sizeof(y))));
	// Восстанавливаем первую координату ключа проверки
	x[0] = static_cast <uint8_t> (x[0] ^ 0x01);
	// Выполняем установку ключа подписи
	ASSERT_TRUE(ecdsa.secret(view_t(secret, sizeof(secret))));
	// Проверяем отказ выработки подписи при нулевом случайном числе
	ASSERT_FALSE(ecdsa.make(view_t(digest, length), view_t(zero, sizeof(zero)), signature));
	// Проверяем отказ выработки подписи при случайном числе не меньше порядка
	ASSERT_FALSE(ecdsa.make(view_t(digest, length), view_t(large, sizeof(large)), signature));
	// Проверяем отказ выработки подписи в непереданное место
	ASSERT_FALSE(ecdsa.make(view_t(digest, length), view_t(secret, sizeof(secret)), nullptr));
	ASSERT_FALSE(ecdsa.make(digest::hash_t::SHA256, view_t(digest, length), nullptr));
	// Проверяем отказ выработки подписи по непереданному хешу
	ASSERT_FALSE(ecdsa.make(view_t(), view_t(secret, sizeof(secret)), signature));
	// Проверяем отказ выработки подписи по RFC 6979 без алгоритма хеширования
	ASSERT_FALSE(ecdsa.make(digest::hash_t::NONE, view_t(digest, length), signature));
	// Проверяем отказ выработки подписи по RFC 6979 при длине хеша не по алгоритму
	ASSERT_FALSE(ecdsa.make(digest::hash_t::SHA384, view_t(digest, length), signature));
	ASSERT_FALSE(ecdsa.make(digest::hash_t::SHA256, view_t(digest, length - 1), signature));
	// Возвращаем годную подпись контрольного примера на место
	bytes(VECTORS256[0].signature, signature);
	// Проверяем схождение годной подписи
	ASSERT_TRUE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Проверяем отказ проверки подписи неверной длины
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, 32)));
	// Проверяем отказ проверки непереданной подписи
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(nullptr, sizeof(signature))));
	// Проверяем отказ проверки подписи по непереданному хешу
	ASSERT_FALSE(ecdsa.check(view_t(), view_t(signature, sizeof(signature))));
	/**
	 * Раздел 4.1.4 SEC 1: часть подписи вне отрезка [1, n-1] отвергается до всякого
	 * счёта - нулевая r, нулевая s, s равная порядку и r не меньше порядка
	 */
	::memset(signature, 0, 32);
	// Проверяем отказ проверки подписи с нулевой первой частью
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Возвращаем годную подпись на место
	bytes(VECTORS256[0].signature, signature);
	// Выполняем обнуление второй части подписи
	::memset(signature + 32, 0, 32);
	// Проверяем отказ проверки подписи с нулевой второй частью
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Возвращаем годную подпись на место
	bytes(VECTORS256[0].signature, signature);
	// Записываем порядок подгруппы второй частью подписи
	bytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", signature + 32);
	// Проверяем отказ проверки подписи со второй частью, равной порядку
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Возвращаем годную подпись на место
	bytes(VECTORS256[0].signature, signature);
	// Записываем число не меньше порядка первой частью подписи
	::memset(signature, 0xFF, 32);
	// Проверяем отказ проверки подписи с первой частью не меньше порядка
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Возвращаем годную подпись на место
	bytes(VECTORS256[0].signature, signature);
	/**
	 * Выполняем перебор байтов подписи
	 */
	for(size_t i = 0; i < sizeof(signature); i++){
		// Выполняем порчу очередного байта подписи
		signature[i] = static_cast <uint8_t> (signature[i] ^ 0x01);
		// Проверяем отказ проверки испорченной подписи
		ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта подписи
		signature[i] = static_cast <uint8_t> (signature[i] ^ 0x01);
	}
	/**
	 * Выполняем перебор байтов хеша подписанного сообщения
	 */
	for(size_t i = 0; i < length; i++){
		// Выполняем порчу очередного байта хеша
		digest[i] = static_cast <uint8_t> (digest[i] ^ 0x01);
		// Проверяем отказ проверки подписи при испорченном хеше
		ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта хеша
		digest[i] = static_cast <uint8_t> (digest[i] ^ 0x01);
	}
	// Проверяем схождение подписи после восстановления всех значений
	ASSERT_TRUE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Объект модуля проверки чужим ключом
	sign::ecdsa_t stranger;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(stranger.start(curve));
	// Чужой ключ подписи: ключ контрольного примера с единицей вместо младшего байта
	secret[31] = static_cast <uint8_t> (secret[31] ^ 0x01);
	// Выполняем установку чужого ключа подписи
	ASSERT_TRUE(stranger.secret(view_t(secret, sizeof(secret))));
	// Проверяем отказ проверки подписи чужим ключом
	ASSERT_FALSE(stranger.check(view_t(digest, length), view_t(signature, sizeof(signature))));
	// Выполняем сброс состояния модуля
	ecdsa.clear();
	// Проверяем отказ работы модуля после сброса его состояния
	ASSERT_FALSE(ecdsa.ready());
	// Проверяем отказ проверки подписи после сброса
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(signature, sizeof(signature))));
}
/**
 * @brief Проверка отказа записи подписи при нехватке памяти
 *
 */
TEST(EcdsaTest, Starved) {
	// Место, в которое помещается сырая подпись контрольного примера
	uint8_t raw[64];
	// Выполняем разбор сырой подписи
	ASSERT_EQ(bytes(VECTORS256[0].signature, raw), static_cast <size_t> (64));
	// Признак того, что запись хоть раз удалась
	bool succeeded = false;
	// Признак того, что нехватка памяти объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений от щедрого к скудному: последнее
	 * выделение записи есть перенос в переданное место, оттого первый же отказ
	 * при убывании запаса приходит из заслона самой записи подписи. Ниже него
	 * запас урезает выделения записывающего объекта ASN.1, и перебор обрывается
	 */
	for(size_t budget = 64; !starved && (budget > 0); budget--){
		// Место, в которое помещается запись DER
		std::vector <uint8_t> der;
		// Итог записи при отмеренном запасе
		bool outcome = false;
		{
			// Отмеряем запас выделений на время записи
			starve::ration_t ration(budget);
			// Выполняем запись подписи при отмеренном запасе
			outcome = sign::encode(view_t(raw, sizeof(raw)), der);
		}
		// Если запись удалась, она обязана совпасть с записью openssl
		if(outcome)
			// Сличаем запись с записью, снятой с openssl
			ASSERT_EQ(text(der.data(), der.size()), std::string(DER256)) << "запас " << budget;
		// Если запись отказала, место обязано остаться пустым
		else
			// Проверяем пустоту места записи
			ASSERT_TRUE(der.empty()) << "запас " << budget;
		// Запоминаем удавшуюся запись
		succeeded = (succeeded || outcome);
		// Запоминаем объявленный отказ памяти
		starved = (starved || !outcome);
	}
	// Проверяем, что при щедром запасе запись удалась
	ASSERT_TRUE(succeeded);
	// Проверяем, что нехватка памяти объявлена отказом
	ASSERT_TRUE(starved);
}
/**
 * @brief Метод сличения с openssl на кривой
 *
 * @param name      имя кривой у openssl
 * @param oid       опознаватель кривой
 * @param algorithm алгоритм хеширования
 * @param option    имя алгоритма хеширования у openssl
 * @param directory каталог временных файлов
 *
 */
static void openssl(const char * name, const char * oid, const digest::hash_t algorithm, const char * option, const std::string & directory) {
	// Пути временных файлов
	const std::string key = (directory + "/" + name + ".key.pem");
	const std::string pub = (directory + "/" + name + ".pub.pem");
	const std::string txt = (directory + "/" + name + ".txt");
	const std::string msg = (directory + "/" + name + ".msg");
	const std::string sig = (directory + "/" + name + ".sig");
	const std::string own = (directory + "/" + name + ".own");
	// Порождаем ключ у openssl
	ASSERT_EQ(::system((std::string("openssl ecparam -genkey -noout -name ") + name + " -out " + key + " 2>/dev/null").c_str()), 0) << "Кривая: " << name;
	// Извлекаем ключ проверки у openssl
	ASSERT_EQ(::system((std::string("openssl ec -in ") + key + " -pubout -out " + pub + " 2>/dev/null").c_str()), 0) << "Кривая: " << name;
	// Выводим ключ текстом у openssl
	ASSERT_EQ(::system((std::string("openssl ec -in ") + key + " -text -noout 2>/dev/null > " + txt).c_str()), 0) << "Кривая: " << name;
	// Читаем текстовую выдачу ключа
	const std::string output = slurp(txt);
	// Извлекаем ключ подписи и ключ проверки
	const std::string secret = extract(output, "priv:", "pub:");
	const std::string point = extract(output, "pub:", "ASN1 OID");
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters(std::string(oid), curve)) << "Кривая: " << name;
	// Размер координаты кривой
	const size_t size = curve.size();
	// Проверяем длину ключа подписи и ключа проверки
	ASSERT_EQ(secret.size(), size * 2) << "Кривая: " << name << " ключ: " << output;
	ASSERT_EQ(point.size(), (size * 4) + 2) << "Кривая: " << name << " ключ: " << output;
	// Объект модуля электронной подписи
	sign::ecdsa_t ecdsa;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(ecdsa.start(curve)) << "Кривая: " << name;
	// Место, в которое помещается ключ подписи
	uint8_t d[math::NUMBER_SIZE];
	// Выполняем установку ключа подписи openssl
	ASSERT_TRUE(ecdsa.secret(view_t(d, bytes(secret, d)))) << "Кривая: " << name;
	// Места, в которые записывается ключ проверки подписи
	uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
	// Выполняем получение ключа проверки подписи
	ASSERT_TRUE(ecdsa.key(x, y, size)) << "Кривая: " << name;
	// Сличаем ключ проверки с ключом проверки openssl
	ASSERT_EQ(std::string("04") + text(x, size) + text(y, size), point) << "Кривая: " << name;
	// Подписываемое сообщение
	const std::string message = "The quick brown fox jumps over the lazy dog";
	{
		// Записываем сообщение в файл
		std::ofstream file(msg, std::ios::binary);
		// Пишем сообщение
		file << message;
	}
	// Подписываем сообщение у openssl
	ASSERT_EQ(::system((std::string("openssl dgst -") + option + " -sign " + key + " -out " + sig + " " + msg + " 2>/dev/null").c_str()), 0) << "Кривая: " << name;
	// Читаем подпись openssl
	const std::string der = slurp(sig);
	// Место, в которое помещается разобранная подпись
	uint8_t raw[math::NUMBER_SIZE * 2];
	// Выполняем разбор подписи openssl
	ASSERT_TRUE(sign::decode(view_t(reinterpret_cast <const uint8_t *> (der.data()), der.size()), raw, size * 2)) << "Кривая: " << name;
	// Место, в которое помещается хеш сообщения
	uint8_t digest[64];
	// Выполняем хеширование сообщения
	const size_t length = summarize(algorithm, message, digest);
	// Проверяем успешность хеширования
	ASSERT_GT(length, static_cast <size_t> (0)) << "Кривая: " << name;
	// Проверяем схождение подписи openssl
	ASSERT_TRUE(ecdsa.check(view_t(digest, length), view_t(raw, size * 2))) << "Кривая: " << name;
	// Выполняем порчу байта подписи openssl
	raw[size + 3] = static_cast <uint8_t> (raw[size + 3] ^ 0x01);
	// Проверяем отказ проверки испорченной подписи openssl
	ASSERT_FALSE(ecdsa.check(view_t(digest, length), view_t(raw, size * 2))) << "Кривая: " << name;
	// Место, в которое помещается своя подпись
	uint8_t signature[math::NUMBER_SIZE * 2];
	// Выполняем выработку своей подписи по RFC 6979
	ASSERT_TRUE(ecdsa.make(algorithm, view_t(digest, length), signature)) << "Кривая: " << name;
	// Место, в которое помещается запись DER своей подписи
	std::vector <uint8_t> encoded;
	// Выполняем запись своей подписи в виде DER
	ASSERT_TRUE(sign::encode(view_t(signature, size * 2), encoded)) << "Кривая: " << name;
	{
		// Записываем свою подпись в файл
		std::ofstream file(own, std::ios::binary);
		// Пишем запись DER
		file.write(reinterpret_cast <const char *> (encoded.data()), static_cast <std::streamsize> (encoded.size()));
	}
	// Проверяем признание своей подписи у openssl
	ASSERT_EQ(::system((std::string("openssl dgst -") + option + " -verify " + pub + " -signature " + own + " " + msg + " >/dev/null 2>&1").c_str()), 0) << "Кривая: " << name;
	/**
	 * Детерминированное число у openssl появилось в издании 3.2 (nonce-type): на
	 * старших изданиях эта часть сличения пропускается с объявлением, остальное
	 * сличение остаётся
	 */
	if(::system((std::string("openssl pkeyutl -sign -inkey ") + key + " -in " + msg + " -rawin -digest " + option + " -pkeyopt nonce-type:1 -out " + sig + " 2>/dev/null").c_str()) == 0){
		// Читаем подпись openssl
		const std::string deterministic = slurp(sig);
		/**
		 * Выведенное по RFC 6979 число у обеих сторон одно, оттого подписи обязаны
		 * совпасть байт в байт, а не только сойтись при проверке
		 */
		ASSERT_EQ(text(reinterpret_cast <const uint8_t *> (deterministic.data()), deterministic.size()), text(encoded.data(), encoded.size())) << "Кривая: " << name;
	// Иначе издание openssl детерминированного числа не знает
	} else std::cout << "openssl без nonce-type: сличение детерминированной подписи пропущено, кривая " << name << std::endl;
	// Выполняем порчу байта своей подписи
	encoded[encoded.size() - 1] = static_cast <uint8_t> (encoded[encoded.size() - 1] ^ 0x01);
	{
		// Записываем испорченную подпись в файл
		std::ofstream file(own, std::ios::binary);
		// Пишем запись DER
		file.write(reinterpret_cast <const char *> (encoded.data()), static_cast <std::streamsize> (encoded.size()));
	}
	// Проверяем отказ признания испорченной подписи у openssl
	ASSERT_NE(::system((std::string("openssl dgst -") + option + " -verify " + pub + " -signature " + own + " " + msg + " >/dev/null 2>&1").c_str()), 0) << "Кривая: " << name;
}
/**
 * @brief Проверка сличения с openssl в обе стороны
 *
 */
TEST(EcdsaTest, Openssl) {
	// Если системного openssl нет, сличать не с чем
	if(::system("openssl version >/dev/null 2>&1") != 0)
		// Объявляем пропуск проверки вслух
		GTEST_SKIP() << "Системный openssl не найден";
	// Заготовка имени каталога временных файлов
	char pattern[] = "ecdsa-XXXXXX";
	// Заводим каталог временных файлов
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Каталог временных файлов
	const std::string directory = pattern;
	// Выполняем сличение на кривой P-256 с SHA-256
	openssl("prime256v1", P256, digest::hash_t::SHA256, "sha256", directory);
	// Выполняем сличение на кривой P-384 с SHA-384
	openssl("secp384r1", P384, digest::hash_t::SHA384, "sha384", directory);
	// Выполняем сличение на кривой P-256 с SHA-512: хеш длиннее порядка усекается
	openssl("prime256v1", P256, digest::hash_t::SHA512, "sha512", directory);
	// Убираем каталог временных файлов
	ASSERT_EQ(::system((std::string("rm -rf ") + directory).c_str()), 0);
}
