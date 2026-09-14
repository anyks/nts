/**
 * @file hpke.cpp
 * @date 2026-09-06
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
 * @brief Проверки модуля гибридного шифрования с открытым ключом HPKE по RFC 9180
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <vectors.hpp>
#include <hpke/hpke.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты набора
 *
 */
namespace {
	/**
	 * @brief Метод разбора шестнадцатеричной записи в байты
	 *
	 * @param text шестнадцатеричная запись
	 * @return     разобранные байты
	 *
	 */
	static std::vector <uint8_t> bytes(const std::string & text){
		// Разобранные байты
		std::vector <uint8_t> result;
		/**
		 * Выполняем обход записи по два знака
		 */
		for(size_t i = 0; (i + 1) < text.size(); i += 2)
			// Добавляем очередной байт
			result.push_back(static_cast <uint8_t> (std::stoul(text.substr(i, 2), nullptr, 16)));
		// Выводим разобранные байты
		return result;
	}
	/**
	 * @brief Метод записи байтов шестнадцатеричной записью
	 *
	 * @param data байты
	 * @param size число байтов
	 * @return     шестнадцатеричная запись
	 *
	 */
	static std::string text(const uint8_t * data, const size_t size){
		// Собираемая запись
		std::string result;
		// Набор шестнадцатеричных знаков
		static const char * DIGITS = "0123456789abcdef";
		/**
		 * Выполняем обход байтов
		 */
		for(size_t i = 0; i < size; i++){
			// Записываем старший полубайт
			result.push_back(DIGITS[data[i] >> 4]);
			// Записываем младший полубайт
			result.push_back(DIGITS[data[i] & 0x0F]);
		}
		// Выводим запись
		return result;
	}
	/**
	 * @brief Метод составления просмотра по накопителю
	 *
	 * @param data накопитель
	 * @return     просмотр накопителя
	 *
	 */
	static view_t viewed(const std::vector <uint8_t> & data) noexcept {
		// Выводим просмотр накопителя
		return view_t(data.empty() ? nullptr : data.data(), data.size());
	}
	/**
	 * @brief Метод составления набора по вектору
	 *
	 * @param vector вектор
	 * @return       набор алгоритмов
	 *
	 */
	static hpke::suite_t suited(const vectors::vector_t & vector) noexcept {
		// Выводим набор вектора
		return hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, static_cast <hpke::kdf_t> (vector.kdf), static_cast <hpke::aead_t> (vector.aead));
	}
	/**
	 * @brief Метод составления имени вектора для сообщений
	 *
	 * @param vector вектор
	 * @return       имя вектора
	 *
	 */
	static std::string named(const vectors::vector_t & vector){
		// Выводим имя вектора
		return ("режим " + std::to_string(vector.mode) + " kdf " + std::to_string(vector.kdf) + " aead " + std::to_string(vector.aead));
	}
	/**
	 * Число векторов
	 */
	static constexpr size_t COUNT = (sizeof(vectors::VECTORS) / sizeof(vectors::vector_t));
	/**
	 * Наборы для перебора
	 */
	static const hpke::suite_t SUITES[] = {
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_256_GCM),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::CHACHA20_POLY1305),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::EXPORT_ONLY),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA384, hpke::aead_t::AES_128_GCM),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA384, hpke::aead_t::AES_256_GCM),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA384, hpke::aead_t::CHACHA20_POLY1305),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA384, hpke::aead_t::EXPORT_ONLY),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA512, hpke::aead_t::AES_128_GCM),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA512, hpke::aead_t::AES_256_GCM),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA512, hpke::aead_t::CHACHA20_POLY1305),
		hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA512, hpke::aead_t::EXPORT_ONLY)
	};
	/**
	 * Режимы для перебора
	 */
	static const hpke::regime_t MODES[] = {hpke::regime_t::BASE, hpke::regime_t::PSK, hpke::regime_t::AUTH, hpke::regime_t::AUTH_PSK};
	/**
	 * Заранее разделённый ключ для перебора: раздел A.1.2 RFC 9180
	 */
	static const char * PSK = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
	/**
	 * Опознаватель ключа для перебора: «Ennyn Durin aran Moria»
	 */
	static const char * PSK_ID = "456e6e796e20447572696e206172616e204d6f726961";
	/**
	 * Привязка к применению для перебора: «Ode on a Grecian Urn»
	 */
	static const char * INFO = "4f6465206f6e2061204772656369616e2055726e";
	/**
	 * Открытый текст для перебора: «Beauty is truth, truth beauty»
	 */
	static const char * PLAIN = "4265617574792069732074727574682c20747275746820626561757479";
	/**
	 * Признак базового набора A.1 RFC 9180: AES-128-GCM на HKDF-SHA256
	 */
	static const size_t FIRST = 0;
}

/**
 * @brief Проверка длин и поддержки наборов
 *
 */
TEST(HpkeTest, Lengths){
	// Проверяем длины хешей функций выработки ключа
	ASSERT_EQ(hpke::length(hpke::kdf_t::HKDF_SHA256), 32u);
	// Проверяем SHA-384
	ASSERT_EQ(hpke::length(hpke::kdf_t::HKDF_SHA384), 48u);
	// Проверяем SHA-512
	ASSERT_EQ(hpke::length(hpke::kdf_t::HKDF_SHA512), 64u);
	// Проверяем неизвестную функцию
	ASSERT_EQ(hpke::length(hpke::kdf_t::NONE), 0u);
	// Проверяем длины ключей шифров
	ASSERT_EQ(hpke::length(hpke::aead_t::AES_128_GCM), 16u);
	// Проверяем AES-256-GCM
	ASSERT_EQ(hpke::length(hpke::aead_t::AES_256_GCM), 32u);
	// Проверяем ChaCha20-Poly1305
	ASSERT_EQ(hpke::length(hpke::aead_t::CHACHA20_POLY1305), 32u);
	// Проверяем набор только для экспорта
	ASSERT_EQ(hpke::length(hpke::aead_t::EXPORT_ONLY), 0u);
	// Проверяем длины меток
	ASSERT_EQ(hpke::overhead(hpke::aead_t::AES_128_GCM), 16u);
	// Проверяем AES-256-GCM
	ASSERT_EQ(hpke::overhead(hpke::aead_t::AES_256_GCM), 16u);
	// Проверяем ChaCha20-Poly1305
	ASSERT_EQ(hpke::overhead(hpke::aead_t::CHACHA20_POLY1305), 16u);
	// Проверяем набор только для экспорта
	ASSERT_EQ(hpke::overhead(hpke::aead_t::EXPORT_ONLY), 0u);
	/**
	 * Выполняем обход поддерживаемых наборов
	 */
	for(size_t i = 0; i < (sizeof(SUITES) / sizeof(hpke::suite_t)); i++)
		// Проверяем поддержку набора
		ASSERT_TRUE(hpke::supported(SUITES[i])) << "набор " << i;
	// Проверяем пустой набор
	ASSERT_FALSE(hpke::supported(hpke::suite_t()));
	// Проверяем чужой способ инкапсуляции
	ASSERT_FALSE(hpke::supported(hpke::suite_t(static_cast <hpke::kem_t> (0x0010), hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM)));
	// Проверяем чужую функцию выработки ключа
	ASSERT_FALSE(hpke::supported(hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, static_cast <hpke::kdf_t> (0x0004), hpke::aead_t::AES_128_GCM)));
	// Проверяем чужой шифр
	ASSERT_FALSE(hpke::supported(hpke::suite_t(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, static_cast <hpke::aead_t> (0x0004))));
	// Проверяем число векторов
	ASSERT_EQ(COUNT, 32u);
}

/**
 * @brief Проверка выработки пар ключей из материала по векторам
 *
 */
TEST(HpkeTest, Derive){
	/**
	 * Выполняем обход векторов
	 */
	for(size_t i = 0; i < COUNT; i++){
		// Вектор
		const vectors::vector_t & vector = vectors::VECTORS[i];
		// Материал пар
		const std::vector <uint8_t> ikmE = bytes(vector.ikmE), ikmR = bytes(vector.ikmR), ikmS = bytes(vector.ikmS);
		// Пара ключей
		hpke::key_t key;
		// Вырабатываем мимолётную пару
		ASSERT_EQ(key.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmE)), hpke::error_t::NONE) << named(vector);
		// Проверяем готовность
		ASSERT_TRUE(key.ready());
		// Проверяем способ
		ASSERT_EQ(key.kem(), hpke::kem_t::X25519_HKDF_SHA256);
		// Проверяем секретный ключ
		ASSERT_EQ(text(key.secret().data, key.secret().size), vector.skEm) << named(vector);
		// Проверяем открытый ключ
		ASSERT_EQ(text(key.point().data, key.point().size), vector.pkEm) << named(vector);
		// Вырабатываем пару получателя
		ASSERT_EQ(key.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE) << named(vector);
		// Проверяем секретный ключ
		ASSERT_EQ(text(key.secret().data, key.secret().size), vector.skRm) << named(vector);
		// Проверяем открытый ключ
		ASSERT_EQ(text(key.point().data, key.point().size), vector.pkRm) << named(vector);
		// Если у вектора есть пара отправителя
		if(!ikmS.empty()){
			// Вырабатываем пару отправителя
			ASSERT_EQ(key.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmS)), hpke::error_t::NONE) << named(vector);
			// Проверяем секретный ключ
			ASSERT_EQ(text(key.secret().data, key.secret().size), vector.skSm) << named(vector);
			// Проверяем открытый ключ
			ASSERT_EQ(text(key.point().data, key.point().size), vector.pkSm) << named(vector);
		}
		// Секретный ключ получателя
		const std::vector <uint8_t> skRm = bytes(vector.skRm);
		// Устанавливаем пару по секретному ключу
		ASSERT_EQ(key.set(hpke::kem_t::X25519_HKDF_SHA256, viewed(skRm)), hpke::error_t::NONE) << named(vector);
		// Проверяем открытый ключ
		ASSERT_EQ(text(key.point().data, key.point().size), vector.pkRm) << named(vector);
		// Стираем пару
		key.clear();
		// Проверяем неготовность
		ASSERT_FALSE(key.ready());
		// Проверяем пустой секретный ключ
		ASSERT_EQ(key.secret().size, 0u);
		// Проверяем пустой открытый ключ
		ASSERT_EQ(key.point().size, 0u);
	}
	{
		// Пара ключей
		hpke::key_t key;
		// Материал короче ключа: раздел 7.1.3 RFC 9180
		const std::vector <uint8_t> brief(31, 0x42);
		// Проверяем отказ короткого материала
		ASSERT_EQ(key.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(brief)), hpke::error_t::KEY);
		// Проверяем неготовность
		ASSERT_FALSE(key.ready());
		// Проверяем отказ чужого способа
		ASSERT_EQ(key.derive(static_cast <hpke::kem_t> (0x0010), viewed(brief)), hpke::error_t::SUITE);
		// Проверяем отказ неверной длины секретного ключа
		ASSERT_EQ(key.set(hpke::kem_t::X25519_HKDF_SHA256, viewed(brief)), hpke::error_t::KEY);
		// Проверяем отказ пустого секретного ключа
		ASSERT_EQ(key.set(hpke::kem_t::X25519_HKDF_SHA256, view_t()), hpke::error_t::KEY);
		// Проверяем отказ чужого способа выработки
		ASSERT_EQ(key.generate(hpke::kem_t::NONE), hpke::error_t::SUITE);
		// Вырабатываем пару из случайных байтов
		ASSERT_EQ(key.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
		// Проверяем готовность
		ASSERT_TRUE(key.ready());
		// Вторая пара
		hpke::key_t other;
		// Вырабатываем вторую пару
		ASSERT_EQ(other.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
		// Проверяем, что пары различны
		ASSERT_NE(text(key.secret().data, key.secret().size), text(other.secret().data, other.secret().size));
	}
}

/**
 * @brief Проверка инкапсуляции и декапсуляции по векторам
 *
 */
TEST(HpkeTest, Encapsulation){
	/**
	 * Выполняем обход векторов
	 */
	for(size_t i = 0; i < COUNT; i++){
		// Вектор
		const vectors::vector_t & vector = vectors::VECTORS[i];
		// Материал пар
		const std::vector <uint8_t> ikmE = bytes(vector.ikmE), ikmR = bytes(vector.ikmR), ikmS = bytes(vector.ikmS);
		// Пары ключей
		hpke::key_t ephemeral, own, authenticator;
		// Вырабатываем мимолётную пару
		ASSERT_EQ(ephemeral.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmE)), hpke::error_t::NONE);
		// Вырабатываем пару получателя
		ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE);
		// Если у вектора есть пара отправителя
		if(!ikmS.empty())
			// Вырабатываем пару отправителя
			ASSERT_EQ(authenticator.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmS)), hpke::error_t::NONE);
		// Общее значение и инкапсулированный ключ
		uint8_t shared[hpke::X25519_SIZE], enc[hpke::X25519_SIZE];
		// Инкапсулируем ключ
		ASSERT_EQ(hpke::encapsulate(ephemeral, own.point(), (ikmS.empty() ? nullptr : &authenticator), shared, enc), hpke::error_t::NONE) << named(vector);
		// Проверяем инкапсулированный ключ
		ASSERT_EQ(text(enc, sizeof(enc)), vector.enc) << named(vector);
		// Проверяем общее значение
		ASSERT_EQ(text(shared, sizeof(shared)), vector.shared_secret) << named(vector);
		// Обнуляем общее значение
		::memset(shared, 0, sizeof(shared));
		// Декапсулируем ключ
		ASSERT_EQ(hpke::decapsulate(own, view_t(enc, sizeof(enc)), (ikmS.empty() ? view_t() : authenticator.point()), shared), hpke::error_t::NONE) << named(vector);
		// Проверяем общее значение
		ASSERT_EQ(text(shared, sizeof(shared)), vector.shared_secret) << named(vector);
	}
	{
		// Пары ключей
		hpke::key_t ephemeral, own, blank;
		// Вырабатываем пары
		ASSERT_EQ(ephemeral.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
		// Вырабатываем пару получателя
		ASSERT_EQ(own.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
		// Общее значение и инкапсулированный ключ
		uint8_t shared[hpke::X25519_SIZE], enc[hpke::X25519_SIZE];
		// Проверяем отказ неготовой мимолётной пары
		ASSERT_EQ(hpke::encapsulate(blank, own.point(), nullptr, shared, enc), hpke::error_t::KEY);
		// Проверяем отказ неготовой пары отправителя
		ASSERT_EQ(hpke::encapsulate(ephemeral, own.point(), &blank, shared, enc), hpke::error_t::KEY);
		// Проверяем отказ ключа получателя неверной длины
		ASSERT_EQ(hpke::encapsulate(ephemeral, view_t(own.point().data, 31), nullptr, shared, enc), hpke::error_t::KEY);
		// Проверяем отказ пустого ключа получателя
		ASSERT_EQ(hpke::encapsulate(ephemeral, view_t(), nullptr, shared, enc), hpke::error_t::KEY);
		// Проверяем отказ без места под общее значение
		ASSERT_EQ(hpke::encapsulate(ephemeral, own.point(), nullptr, nullptr, enc), hpke::error_t::ARGUMENT);
		// Проверяем отказ без места под инкапсулированный ключ
		ASSERT_EQ(hpke::encapsulate(ephemeral, own.point(), nullptr, shared, nullptr), hpke::error_t::ARGUMENT);
		// Точка малого порядка: нулевая
		const std::vector <uint8_t> zero(hpke::X25519_SIZE, 0x00);
		// Проверяем отказ нулевого общего значения: раздел 7.1.4 RFC 9180
		ASSERT_EQ(hpke::encapsulate(ephemeral, viewed(zero), nullptr, shared, enc), hpke::error_t::ENCAPSULATION);
		// Инкапсулируем ключ
		ASSERT_EQ(hpke::encapsulate(ephemeral, own.point(), nullptr, shared, enc), hpke::error_t::NONE);
		// Проверяем отказ неготовой пары получателя
		ASSERT_EQ(hpke::decapsulate(blank, view_t(enc, sizeof(enc)), view_t(), shared), hpke::error_t::KEY);
		// Проверяем отказ инкапсулированного ключа неверной длины
		ASSERT_EQ(hpke::decapsulate(own, view_t(enc, 31), view_t(), shared), hpke::error_t::ENCAPSULATION);
		// Проверяем отказ пустого инкапсулированного ключа
		ASSERT_EQ(hpke::decapsulate(own, view_t(), view_t(), shared), hpke::error_t::ENCAPSULATION);
		// Проверяем отказ нулевого инкапсулированного ключа
		ASSERT_EQ(hpke::decapsulate(own, viewed(zero), view_t(), shared), hpke::error_t::ENCAPSULATION);
		// Проверяем отказ ключа отправителя неверной длины
		ASSERT_EQ(hpke::decapsulate(own, view_t(enc, sizeof(enc)), view_t(enc, 31), shared), hpke::error_t::KEY);
		// Проверяем отказ нулевого ключа отправителя
		ASSERT_EQ(hpke::decapsulate(own, view_t(enc, sizeof(enc)), viewed(zero), shared), hpke::error_t::ENCAPSULATION);
		// Проверяем отказ без места под общее значение
		ASSERT_EQ(hpke::decapsulate(own, view_t(enc, sizeof(enc)), view_t(), nullptr), hpke::error_t::ARGUMENT);
	}
}

/**
 * @brief Проверка векторов приложения A RFC 9180 и набора CFRG байт в байт
 *
 */
TEST(HpkeTest, Vectors){
	/**
	 * Выполняем обход векторов
	 */
	for(size_t i = 0; i < COUNT; i++){
		// Вектор
		const vectors::vector_t & vector = vectors::VECTORS[i];
		// Набор вектора
		const hpke::suite_t suite = suited(vector);
		// Режим вектора
		const hpke::regime_t mode = static_cast <hpke::regime_t> (vector.mode);
		// Материал пар
		const std::vector <uint8_t> ikmE = bytes(vector.ikmE), ikmR = bytes(vector.ikmR), ikmS = bytes(vector.ikmS);
		// Привязка и ключ
		const std::vector <uint8_t> info = bytes(vector.info), psk = bytes(vector.psk), identity = bytes(vector.psk_id);
		// Пары ключей
		hpke::key_t ephemeral, own, authenticator;
		// Вырабатываем мимолётную пару
		ASSERT_EQ(ephemeral.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmE)), hpke::error_t::NONE);
		// Вырабатываем пару получателя
		ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE);
		// Если у вектора есть пара отправителя
		if(!ikmS.empty())
			// Вырабатываем пару отправителя
			ASSERT_EQ(authenticator.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmS)), hpke::error_t::NONE);
		// Заранее разделённый ключ
		const hpke::shared_t shared(viewed(psk), viewed(identity));
		// Инкапсулированный ключ
		uint8_t enc[hpke::X25519_SIZE];
		// Состояния сторон
		hpke::context_t sending, receiving;
		// Устанавливаем состояние отправителя
		ASSERT_EQ(hpke::sender(suite, mode, own.point(), viewed(info), shared, (ikmS.empty() ? nullptr : &authenticator), ephemeral, enc, sending), hpke::error_t::NONE) << named(vector);
		// Проверяем инкапсулированный ключ
		ASSERT_EQ(text(enc, sizeof(enc)), vector.enc) << named(vector);
		// Проверяем готовность
		ASSERT_TRUE(sending.ready());
		// Проверяем набор состояния
		ASSERT_EQ(static_cast <uint16_t> (sending.suite().aead), vector.aead);
		// Устанавливаем состояние получателя
		ASSERT_EQ(hpke::recipient(suite, mode, own, view_t(enc, sizeof(enc)), viewed(info), shared, (ikmS.empty() ? view_t() : authenticator.point()), receiving), hpke::error_t::NONE) << named(vector);
		/**
		 * Выполняем обход зашифрований вектора
		 */
		for(size_t j = 0; j < vector.encryptions; j++){
			// Зашифрование
			const vectors::encryption_t & encryption = vector.encryption[j];
			// Данные зашифрования
			const std::vector <uint8_t> aad = bytes(encryption.aad), pt = bytes(encryption.pt), ct = bytes(encryption.ct);
			// Переставляем порядковые номера
			ASSERT_EQ(sending.sequence(encryption.sequence), hpke::error_t::NONE);
			// Переставляем порядковый номер получателя
			ASSERT_EQ(receiving.sequence(encryption.sequence), hpke::error_t::NONE);
			// Накопитель шифртекста
			std::vector <uint8_t> sealed;
			// Зашифровываем сообщение
			ASSERT_EQ(sending.seal(viewed(aad), viewed(pt), sealed), hpke::error_t::NONE) << named(vector) << " номер " << encryption.sequence;
			// Проверяем шифртекст байт в байт
			ASSERT_EQ(text(sealed.data(), sealed.size()), encryption.ct) << named(vector) << " номер " << encryption.sequence;
			// Проверяем рост порядкового номера
			ASSERT_EQ(sending.sequence(), encryption.sequence + 1);
			// Накопитель открытого текста
			std::vector <uint8_t> opened;
			// Расшифровываем сообщение
			ASSERT_EQ(receiving.open(viewed(aad), viewed(ct), opened), hpke::error_t::NONE) << named(vector) << " номер " << encryption.sequence;
			// Проверяем открытый текст
			ASSERT_EQ(text(opened.data(), opened.size()), encryption.pt) << named(vector);
			// Проверяем рост порядкового номера получателя
			ASSERT_EQ(receiving.sequence(), encryption.sequence + 1);
		}
		/**
		 * Выполняем обход экспортов вектора
		 */
		for(size_t j = 0; j < 3; j++){
			// Экспорт
			const vectors::export_t & exported = vector.exports[j];
			// Привязка экспорта
			const std::vector <uint8_t> context = bytes(exported.context);
			// Секреты обеих сторон
			std::vector <uint8_t> first(exported.size), second(exported.size);
			// Вырабатываем секрет у отправителя
			ASSERT_EQ(sending.exporter(viewed(context), first.data(), exported.size), hpke::error_t::NONE) << named(vector);
			// Проверяем секрет байт в байт
			ASSERT_EQ(text(first.data(), first.size()), exported.value) << named(vector) << " экспорт " << j;
			// Вырабатываем секрет у получателя
			ASSERT_EQ(receiving.exporter(viewed(context), second.data(), exported.size), hpke::error_t::NONE) << named(vector);
			// Проверяем секрет байт в байт
			ASSERT_EQ(text(second.data(), second.size()), exported.value) << named(vector) << " экспорт " << j;
		}
	}
}

/**
 * @brief Проверка одношаговых обёрток по векторам с заданной мимолётной парой и живьём
 *
 */
TEST(HpkeTest, Single){
	/**
	 * Выполняем обход векторов
	 */
	for(size_t i = 0; i < COUNT; i++){
		// Вектор
		const vectors::vector_t & vector = vectors::VECTORS[i];
		// Набор вектора
		const hpke::suite_t suite = suited(vector);
		// Режим вектора
		const hpke::regime_t mode = static_cast <hpke::regime_t> (vector.mode);
		// Материал пар
		const std::vector <uint8_t> ikmR = bytes(vector.ikmR), ikmS = bytes(vector.ikmS);
		// Привязка и ключ
		const std::vector <uint8_t> info = bytes(vector.info), psk = bytes(vector.psk), identity = bytes(vector.psk_id);
		// Пары ключей
		hpke::key_t own, authenticator;
		// Вырабатываем пару получателя
		ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE);
		// Если у вектора есть пара отправителя
		if(!ikmS.empty())
			// Вырабатываем пару отправителя
			ASSERT_EQ(authenticator.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmS)), hpke::error_t::NONE);
		// Заранее разделённый ключ
		const hpke::shared_t shared(viewed(psk), viewed(identity));
		// Просмотр ключа отправителя
		const view_t point = (ikmS.empty() ? view_t() : authenticator.point());
		// Указатель на пару отправителя
		const hpke::key_t * signer = (ikmS.empty() ? nullptr : &authenticator);
		// Если набор шифрует
		if(vector.encryptions > 0){
			// Первое зашифрование вектора
			const vectors::encryption_t & encryption = vector.encryption[0];
			// Данные зашифрования
			const std::vector <uint8_t> aad = bytes(encryption.aad), pt = bytes(encryption.pt), ct = bytes(encryption.ct), enc = bytes(vector.enc);
			// Накопитель открытого текста
			std::vector <uint8_t> opened;
			// Расшифровываем сообщение вектора одним шагом
			ASSERT_EQ(hpke::open(suite, mode, own, viewed(enc), viewed(info), shared, point, viewed(aad), viewed(ct), opened), hpke::error_t::NONE) << named(vector);
			// Проверяем открытый текст
			ASSERT_EQ(text(opened.data(), opened.size()), encryption.pt) << named(vector);
			// Накопители зашифрования живьём
			std::vector <uint8_t> fresh, sealed;
			// Зашифровываем сообщение одним шагом со свежей мимолётной парой
			ASSERT_EQ(hpke::seal(suite, mode, own.point(), viewed(info), shared, signer, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::NONE) << named(vector);
			// Проверяем длину инкапсулированного ключа
			ASSERT_EQ(fresh.size(), hpke::X25519_SIZE);
			// Проверяем, что мимолётная пара свежая
			ASSERT_NE(text(fresh.data(), fresh.size()), vector.enc);
			// Проверяем длину шифртекста
			ASSERT_EQ(sealed.size(), pt.size() + hpke::TAG_SIZE);
			// Расшифровываем свежее сообщение
			ASSERT_EQ(hpke::open(suite, mode, own, viewed(fresh), viewed(info), shared, point, viewed(aad), viewed(sealed), opened), hpke::error_t::NONE) << named(vector);
			// Проверяем открытый текст
			ASSERT_EQ(text(opened.data(), opened.size()), encryption.pt) << named(vector);
		}
		// Первый экспорт вектора
		const vectors::export_t & exported = vector.exports[1];
		// Привязка экспорта и инкапсулированный ключ
		const std::vector <uint8_t> context = bytes(exported.context), enc = bytes(vector.enc);
		// Накопитель секрета
		std::vector <uint8_t> secret;
		// Вырабатываем секрет получателем одним шагом
		ASSERT_EQ(hpke::receive(suite, mode, own, viewed(enc), viewed(info), shared, point, viewed(context), exported.size, secret), hpke::error_t::NONE) << named(vector);
		// Проверяем секрет байт в байт
		ASSERT_EQ(text(secret.data(), secret.size()), exported.value) << named(vector);
		// Накопители отправителя
		std::vector <uint8_t> fresh, first, second;
		// Вырабатываем секрет отправителем одним шагом
		ASSERT_EQ(hpke::dispatch(suite, mode, own.point(), viewed(info), shared, signer, viewed(context), exported.size, fresh, first), hpke::error_t::NONE) << named(vector);
		// Проверяем длину секрета
		ASSERT_EQ(first.size(), exported.size);
		// Вырабатываем тот же секрет получателем
		ASSERT_EQ(hpke::receive(suite, mode, own, viewed(fresh), viewed(info), shared, point, viewed(context), exported.size, second), hpke::error_t::NONE) << named(vector);
		// Проверяем совпадение секретов
		ASSERT_EQ(first, second) << named(vector);
		// Проверяем, что свежий секрет отличен от секрета вектора
		ASSERT_NE(text(first.data(), first.size()), exported.value);
	}
}

/**
 * @brief Проверка переписки живьём по всем наборам и режимам
 *
 */
TEST(HpkeTest, Roundtrip){
	// Привязка, ключ, текст
	const std::vector <uint8_t> info = bytes(INFO), psk = bytes(PSK), identity = bytes(PSK_ID), plain = bytes(PLAIN);
	// Длинное сообщение в три блока с хвостом
	std::vector <uint8_t> lengthy(1000);
	/**
	 * Выполняем заполнение длинного сообщения
	 */
	for(size_t i = 0; i < lengthy.size(); i++)
		// Записываем байт
		lengthy[i] = static_cast <uint8_t> (i * 7);
	/**
	 * Выполняем обход наборов
	 */
	for(size_t i = 0; i < (sizeof(SUITES) / sizeof(hpke::suite_t)); i++){
		/**
		 * Выполняем обход режимов
		 */
		for(size_t j = 0; j < (sizeof(MODES) / sizeof(hpke::regime_t)); j++){
			// Набор и режим
			const hpke::suite_t & suite = SUITES[i];
			// Режим
			const hpke::regime_t mode = MODES[j];
			// Признаки режима
			const bool preshared = ((mode == hpke::regime_t::PSK) || (mode == hpke::regime_t::AUTH_PSK));
			// Признак подлинности
			const bool authenticated = ((mode == hpke::regime_t::AUTH) || (mode == hpke::regime_t::AUTH_PSK));
			// Пары ключей
			hpke::key_t own, authenticator;
			// Вырабатываем пару получателя
			ASSERT_EQ(own.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
			// Вырабатываем пару отправителя
			ASSERT_EQ(authenticator.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
			// Заранее разделённый ключ по режиму
			const hpke::shared_t shared(preshared ? viewed(psk) : view_t(), preshared ? viewed(identity) : view_t());
			// Инкапсулированный ключ
			uint8_t enc[hpke::X25519_SIZE];
			// Состояния сторон
			hpke::context_t sending, receiving;
			// Устанавливаем состояние отправителя
			ASSERT_EQ(hpke::sender(suite, mode, own.point(), viewed(info), shared, (authenticated ? &authenticator : nullptr), enc, sending), hpke::error_t::NONE) << "набор " << i << " режим " << j;
			// Устанавливаем состояние получателя
			ASSERT_EQ(hpke::recipient(suite, mode, own, view_t(enc, sizeof(enc)), viewed(info), shared, (authenticated ? authenticator.point() : view_t()), receiving), hpke::error_t::NONE) << "набор " << i << " режим " << j;
			// Секреты экспорта
			uint8_t first[64], second[64];
			// Вырабатываем секрет у отправителя
			ASSERT_EQ(sending.exporter(viewed(info), first, sizeof(first)), hpke::error_t::NONE);
			// Вырабатываем секрет у получателя
			ASSERT_EQ(receiving.exporter(viewed(info), second, sizeof(second)), hpke::error_t::NONE);
			// Проверяем совпадение секретов
			ASSERT_EQ(::memcmp(first, second, sizeof(first)), 0) << "набор " << i << " режим " << j;
			// Вырабатываем секрет с пустой привязкой
			ASSERT_EQ(sending.exporter(view_t(), second, sizeof(second)), hpke::error_t::NONE);
			// Проверяем, что привязка меняет секрет
			ASSERT_NE(::memcmp(first, second, sizeof(first)), 0);
			// Если набор только для экспорта
			if(suite.aead == hpke::aead_t::EXPORT_ONLY){
				// Накопитель
				std::vector <uint8_t> sealed;
				// Проверяем отказ зашифрования
				ASSERT_EQ(sending.seal(view_t(), viewed(plain), sealed), hpke::error_t::AEAD);
				// Проверяем отказ расшифрования
				ASSERT_EQ(receiving.open(view_t(), viewed(plain), sealed), hpke::error_t::AEAD);
				// Переходим к следующему режиму
				continue;
			}
			// Сообщения для переписки: обычное, пустое, длинное, обычное без связанных данных
			const std::vector <uint8_t> * messages[] = {&plain, nullptr, &lengthy, &plain};
			/**
			 * Выполняем переписку
			 */
			for(size_t k = 0; k < 4; k++){
				// Открытый текст
				const view_t source = ((messages[k] != nullptr) ? viewed(*messages[k]) : view_t());
				// Связанные данные
				const view_t associated = ((k == 3) ? view_t() : viewed(info));
				// Накопители
				std::vector <uint8_t> sealed, opened;
				// Проверяем порядковый номер
				ASSERT_EQ(sending.sequence(), static_cast <uint64_t> (k));
				// Зашифровываем сообщение
				ASSERT_EQ(sending.seal(associated, source, sealed), hpke::error_t::NONE) << "набор " << i << " режим " << j << " сообщение " << k;
				// Проверяем длину шифртекста
				ASSERT_EQ(sealed.size(), source.size + hpke::TAG_SIZE);
				// Расшифровываем сообщение
				ASSERT_EQ(receiving.open(associated, viewed(sealed), opened), hpke::error_t::NONE) << "набор " << i << " режим " << j << " сообщение " << k;
				// Проверяем открытый текст
				ASSERT_EQ(opened.size(), source.size);
				// Проверяем совпадение байтов
				ASSERT_TRUE((source.size == 0) || (::memcmp(opened.data(), source.data, source.size) == 0));
			}
			// Проверяем порядковые номера
			ASSERT_EQ(receiving.sequence(), 4u);
		}
	}
}

/**
 * @brief Проверка отказов: чужой ключ, порча, режимы, доводы, счётчик
 *
 */
TEST(HpkeTest, Refusals){
	// Базовый вектор A.1.1 RFC 9180
	const vectors::vector_t & vector = vectors::VECTORS[FIRST];
	// Набор вектора
	const hpke::suite_t suite = suited(vector);
	// Проверяем, что вектор базовый
	ASSERT_EQ(vector.mode, 0);
	// Материал и данные
	const std::vector <uint8_t> ikmE = bytes(vector.ikmE), ikmR = bytes(vector.ikmR), info = bytes(vector.info), enc = bytes(vector.enc);
	// Первое зашифрование
	const std::vector <uint8_t> aad = bytes(vector.encryption[0].aad), pt = bytes(vector.encryption[0].pt), ct = bytes(vector.encryption[0].ct);
	// Ключ и опознаватель
	const std::vector <uint8_t> psk = bytes(PSK), identity = bytes(PSK_ID);
	// Пары ключей
	hpke::key_t ephemeral, own, foreign, blank;
	// Вырабатываем мимолётную пару
	ASSERT_EQ(ephemeral.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmE)), hpke::error_t::NONE);
	// Вырабатываем пару получателя
	ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE);
	// Вырабатываем чужую пару
	ASSERT_EQ(foreign.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
	{
		// Накопитель
		std::vector <uint8_t> opened;
		// Проверяем отказ чужого ключа получателя: общее значение иное, подлинность не сходится
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, foreign, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::OPEN);
		// Проверяем пустой накопитель
		ASSERT_TRUE(opened.empty());
		// Проверяем отказ чужой привязки
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(aad), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::OPEN);
		// Проверяем отказ чужих связанных данных
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(info), viewed(ct), opened), hpke::error_t::OPEN);
		// Проверяем отказ чужого инкапсулированного ключа
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, foreign.point(), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::OPEN);
		// Проверяем отказ чужого режима: ключ подан, режим базовый
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(viewed(psk), viewed(identity)), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::PSK);
		// Проверяем отказ режима PSK без ключа
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::PSK);
		// Проверяем отказ ключа без опознавателя
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(enc), viewed(info), hpke::shared_t(viewed(psk), view_t()), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::PSK);
		// Проверяем отказ опознавателя без ключа
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(enc), viewed(info), hpke::shared_t(view_t(), viewed(identity)), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::PSK);
		// Проверяем отказ режима AUTH без ключа отправителя
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::AUTH, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::KEY);
		// Проверяем отказ базового режима с ключом отправителя
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), foreign.point(), viewed(aad), viewed(ct), opened), hpke::error_t::KEY);
		// Проверяем отказ неизвестного режима
		ASSERT_EQ(hpke::open(suite, static_cast <hpke::regime_t> (0x04), own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::MODE);
		// Проверяем отказ неготовой пары
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, blank, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::KEY);
		// Проверяем отказ чужого набора
		ASSERT_EQ(hpke::open(hpke::suite_t(), hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::SUITE);
		// Проверяем отказ инкапсулированного ключа неверной длины
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, view_t(enc.data(), 31), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::ENCAPSULATION);
		// Проверяем отказ шифртекста короче метки
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), view_t(ct.data(), 15), opened), hpke::error_t::ARGUMENT);
		// Проверяем отказ усечённого шифртекста
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), view_t(ct.data(), ct.size() - 1), opened), hpke::error_t::OPEN);
		// Проверяем расшифрование одной лишь метки: пустой текст не сходится
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), view_t(ct.data(), 16), opened), hpke::error_t::OPEN);
		/**
		 * Выполняем порчу каждого байта шифртекста
		 */
		for(size_t i = 0; i < ct.size(); i++){
			// Порченый шифртекст
			std::vector <uint8_t> corrupted = ct;
			// Портим байт
			corrupted[i] ^= 0x01;
			// Проверяем отказ подлинности
			ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(corrupted), opened), hpke::error_t::OPEN) << "байт " << i;
			// Проверяем пустой накопитель
			ASSERT_TRUE(opened.empty());
		}
		// Проверяем, что нетронутый шифртекст сходится
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(ct), opened), hpke::error_t::NONE);
		// Проверяем открытый текст
		ASSERT_EQ(opened, pt);
	}
	{
		// Накопители
		std::vector <uint8_t> fresh, sealed;
		// Проверяем отказ чужого набора у отправителя
		ASSERT_EQ(hpke::seal(hpke::suite_t(), hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), nullptr, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::SUITE);
		// Проверяем отказ неизвестного режима у отправителя
		ASSERT_EQ(hpke::seal(suite, static_cast <hpke::regime_t> (0xFF), own.point(), viewed(info), hpke::shared_t(), nullptr, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::MODE);
		// Проверяем отказ режима AUTH без пары отправителя
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::AUTH, own.point(), viewed(info), hpke::shared_t(), nullptr, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::KEY);
		// Проверяем отказ базового режима с парой отправителя
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), &foreign, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::KEY);
		// Проверяем отказ неготовой пары отправителя
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::AUTH, own.point(), viewed(info), hpke::shared_t(), &blank, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::KEY);
		// Проверяем отказ ключа получателя неверной длины
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::BASE, view_t(own.point().data, 16), viewed(info), hpke::shared_t(), nullptr, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::KEY);
		// Проверяем отказ ключа без режима у отправителя
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(viewed(psk), viewed(identity)), nullptr, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::PSK);
		// Проверяем пустые накопители после отказа
		ASSERT_TRUE(fresh.empty() && sealed.empty());
		// Инкапсулированный ключ
		uint8_t place[hpke::X25519_SIZE];
		// Состояние
		hpke::context_t context;
		// Проверяем отказ без места под инкапсулированный ключ
		ASSERT_EQ(hpke::sender(suite, hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), nullptr, ephemeral, nullptr, context), hpke::error_t::ARGUMENT);
		// Проверяем отказ неготовой мимолётной пары
		ASSERT_EQ(hpke::sender(suite, hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), nullptr, blank, place, context), hpke::error_t::KEY);
		// Проверяем отказ привязки длиной без места
		ASSERT_EQ(hpke::sender(suite, hpke::regime_t::BASE, own.point(), view_t(nullptr, 5), hpke::shared_t(), nullptr, ephemeral, place, context), hpke::error_t::ARGUMENT);
		// Проверяем неготовность состояния после отказов
		ASSERT_FALSE(context.ready());
	}
	{
		// Инкапсулированный ключ
		uint8_t place[hpke::X25519_SIZE];
		// Состояния
		hpke::context_t sending, receiving, idle;
		// Место под итог
		uint8_t room[64];
		// Проверяем отказы неустановленного состояния
		ASSERT_EQ(idle.seal(view_t(), viewed(pt), room), hpke::error_t::READY);
		// Проверяем расшифрование
		ASSERT_EQ(idle.open(view_t(), viewed(ct), room), hpke::error_t::READY);
		// Проверяем экспорт
		ASSERT_EQ(idle.exporter(view_t(), room, 32), hpke::error_t::READY);
		// Проверяем установку номера
		ASSERT_EQ(idle.sequence(1), hpke::error_t::READY);
		// Устанавливаем состояние отправителя
		ASSERT_EQ(hpke::sender(suite, hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), nullptr, ephemeral, place, sending), hpke::error_t::NONE);
		// Устанавливаем состояние получателя
		ASSERT_EQ(hpke::recipient(suite, hpke::regime_t::BASE, own, view_t(place, sizeof(place)), viewed(info), hpke::shared_t(), view_t(), receiving), hpke::error_t::NONE);
		// Проверяем отказ расшифрования у отправителя
		ASSERT_EQ(sending.open(viewed(aad), viewed(ct), room), hpke::error_t::AEAD);
		// Проверяем отказ зашифрования у получателя
		ASSERT_EQ(receiving.seal(viewed(aad), viewed(pt), room), hpke::error_t::AEAD);
		// Проверяем отказ без места под шифртекст
		ASSERT_EQ(sending.seal(viewed(aad), viewed(pt), static_cast <uint8_t *> (nullptr)), hpke::error_t::ARGUMENT);
		// Проверяем отказ текста длиной без места
		ASSERT_EQ(sending.seal(viewed(aad), view_t(nullptr, 3), room), hpke::error_t::ARGUMENT);
		// Проверяем отказ связанных данных длиной без места
		ASSERT_EQ(sending.seal(view_t(nullptr, 3), viewed(pt), room), hpke::error_t::ARGUMENT);
		// Проверяем отказ без места под открытый текст
		ASSERT_EQ(receiving.open(viewed(aad), viewed(ct), static_cast <uint8_t *> (nullptr)), hpke::error_t::ARGUMENT);
		// Проверяем отказ пустого шифртекста
		ASSERT_EQ(receiving.open(viewed(aad), view_t(), room), hpke::error_t::ARGUMENT);
		// Проверяем отказ нулевой длины экспорта
		ASSERT_EQ(sending.exporter(view_t(), room, 0), hpke::error_t::LENGTH);
		// Проверяем отказ чрезмерной длины экспорта: раздел 5.3 RFC 9180
		ASSERT_EQ(sending.exporter(view_t(), room, (255 * 32) + 1), hpke::error_t::LENGTH);
		// Проверяем отказ экспорта без места
		ASSERT_EQ(sending.exporter(view_t(), nullptr, 32), hpke::error_t::ARGUMENT);
		// Проверяем отказ привязки экспорта длиной без места
		ASSERT_EQ(sending.exporter(view_t(nullptr, 4), room, 32), hpke::error_t::ARGUMENT);
		// Накопитель наибольшего экспорта
		std::vector <uint8_t> widest(255 * 32);
		// Проверяем наибольшую длину экспорта
		ASSERT_EQ(sending.exporter(view_t(), widest.data(), widest.size()), hpke::error_t::NONE);
		// Проверяем, что порядковые номера не сдвинулись отказами
		ASSERT_EQ(sending.sequence(), 0u);
		// Проверяем номер получателя
		ASSERT_EQ(receiving.sequence(), 0u);
		// Переставляем порядковый номер отправителя на предел
		ASSERT_EQ(sending.sequence(UINT64_MAX), hpke::error_t::NONE);
		// Проверяем отказ исчерпанных номеров
		ASSERT_EQ(sending.seal(viewed(aad), viewed(pt), room), hpke::error_t::SEQUENCE);
		// Переставляем номер получателя на предел
		ASSERT_EQ(receiving.sequence(UINT64_MAX), hpke::error_t::NONE);
		// Проверяем отказ исчерпанных номеров у получателя
		ASSERT_EQ(receiving.open(viewed(aad), viewed(ct), room), hpke::error_t::SEQUENCE);
		// Переставляем номер отправителя на предпоследний
		ASSERT_EQ(sending.sequence(UINT64_MAX - 1), hpke::error_t::NONE);
		// Проверяем, что предпоследний номер ещё годен
		ASSERT_EQ(sending.seal(viewed(aad), viewed(pt), room), hpke::error_t::NONE);
		// Проверяем, что номер дошёл до предела
		ASSERT_EQ(sending.sequence(), UINT64_MAX);
		// Переставляем номер получателя на предпоследний
		ASSERT_EQ(receiving.sequence(UINT64_MAX - 1), hpke::error_t::NONE);
		// Открытый текст
		uint8_t opened[64];
		// Расшифровываем сообщение с предпоследним номером
		ASSERT_EQ(receiving.open(viewed(aad), view_t(room, pt.size() + hpke::TAG_SIZE), opened), hpke::error_t::NONE);
		// Проверяем открытый текст
		ASSERT_EQ(::memcmp(opened, pt.data(), pt.size()), 0);
		// Возвращаем номера к началу
		ASSERT_EQ(sending.sequence(0), hpke::error_t::NONE);
		// Возвращаем номер получателя на единицу вперёд: рассинхрон
		ASSERT_EQ(receiving.sequence(1), hpke::error_t::NONE);
		// Зашифровываем сообщение с нулевым номером
		ASSERT_EQ(sending.seal(viewed(aad), viewed(pt), room), hpke::error_t::NONE);
		// Проверяем отказ расшифрования с чужим номером
		ASSERT_EQ(receiving.open(viewed(aad), view_t(room, pt.size() + hpke::TAG_SIZE), opened), hpke::error_t::OPEN);
		// Проверяем, что отказ номер не сдвинул
		ASSERT_EQ(receiving.sequence(), 1u);
		// Проверяем, что место под открытый текст стёрто
		ASSERT_EQ(std::count(opened, opened + pt.size(), 0), static_cast <ptrdiff_t> (pt.size()));
		// Возвращаем номер получателя
		ASSERT_EQ(receiving.sequence(0), hpke::error_t::NONE);
		// Проверяем расшифрование
		ASSERT_EQ(receiving.open(viewed(aad), view_t(room, pt.size() + hpke::TAG_SIZE), opened), hpke::error_t::NONE);
		// Стираем состояние
		sending.clear();
		// Проверяем неготовность
		ASSERT_FALSE(sending.ready());
		// Проверяем отказ после стирания
		ASSERT_EQ(sending.seal(viewed(aad), viewed(pt), room), hpke::error_t::READY);
		// Проверяем сброс набора
		ASSERT_EQ(sending.suite().aead, hpke::aead_t::NONE);
	}
	{
		// Пары ключей
		hpke::key_t authenticator;
		// Вырабатываем пару отправителя
		ASSERT_EQ(authenticator.generate(hpke::kem_t::X25519_HKDF_SHA256), hpke::error_t::NONE);
		// Накопители
		std::vector <uint8_t> fresh, sealed, opened;
		// Зашифровываем с подлинностью отправителя
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::AUTH, own.point(), viewed(info), hpke::shared_t(), &authenticator, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::NONE);
		// Проверяем отказ чужого ключа отправителя у получателя
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::AUTH, own, viewed(fresh), viewed(info), hpke::shared_t(), foreign.point(), viewed(aad), viewed(sealed), opened), hpke::error_t::OPEN);
		// Проверяем расшифрование с верным ключом отправителя
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::AUTH, own, viewed(fresh), viewed(info), hpke::shared_t(), authenticator.point(), viewed(aad), viewed(sealed), opened), hpke::error_t::NONE);
		// Зашифровываем с заранее разделённым ключом
		ASSERT_EQ(hpke::seal(suite, hpke::regime_t::PSK, own.point(), viewed(info), hpke::shared_t(viewed(psk), viewed(identity)), nullptr, viewed(aad), viewed(pt), fresh, sealed), hpke::error_t::NONE);
		// Чужой ключ той же длины (короче 32 байтов ключ отвергается до расшифрования - круг 7)
		std::vector <uint8_t> wrong = psk;
		wrong[0] ^= 0x01;
		// Проверяем отказ чужого ключа
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(fresh), viewed(info), hpke::shared_t(viewed(wrong), viewed(identity)), view_t(), viewed(aad), viewed(sealed), opened), hpke::error_t::OPEN);
		// Проверяем отказ короткого ключа (RFC 9180 §9.5)
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(fresh), viewed(info), hpke::shared_t(viewed(identity), viewed(identity)), view_t(), viewed(aad), viewed(sealed), opened), hpke::error_t::PSK);
		// Проверяем отказ чужого опознавателя
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(fresh), viewed(info), hpke::shared_t(viewed(psk), viewed(psk)), view_t(), viewed(aad), viewed(sealed), opened), hpke::error_t::OPEN);
		// Проверяем отказ чужого режима с тем же ключом: режим входит в расписание
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::BASE, own, viewed(fresh), viewed(info), hpke::shared_t(), view_t(), viewed(aad), viewed(sealed), opened), hpke::error_t::OPEN);
		// Проверяем расшифрование с верным ключом
		ASSERT_EQ(hpke::open(suite, hpke::regime_t::PSK, own, viewed(fresh), viewed(info), hpke::shared_t(viewed(psk), viewed(identity)), view_t(), viewed(aad), viewed(sealed), opened), hpke::error_t::NONE);
		// Проверяем открытый текст
		ASSERT_EQ(opened, pt);
		// Проверяем отказ экспорта чрезмерной длины у обёрток
		ASSERT_EQ(hpke::dispatch(suite, hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), nullptr, view_t(), (255 * 32) + 1, fresh, opened), hpke::error_t::LENGTH);
		// Проверяем пустые накопители
		ASSERT_TRUE(fresh.empty() && opened.empty());
		// Проверяем отказ нулевой длины у получателя
		ASSERT_EQ(hpke::receive(suite, hpke::regime_t::BASE, own, viewed(enc), viewed(info), hpke::shared_t(), view_t(), view_t(), 0, opened), hpke::error_t::LENGTH);
		// Проверяем отказ чужой пары у получателя экспорта
		ASSERT_EQ(hpke::receive(suite, hpke::regime_t::BASE, blank, viewed(enc), viewed(info), hpke::shared_t(), view_t(), view_t(), 32, opened), hpke::error_t::KEY);
	}
}

/**
 * @brief Проверка различия наборов: один и тот же материал даёт разные ключи
 *
 */
TEST(HpkeTest, Distinct){
	// Материал и данные
	const std::vector <uint8_t> ikmE = bytes(vectors::VECTORS[FIRST].ikmE), ikmR = bytes(vectors::VECTORS[FIRST].ikmR), info = bytes(INFO), plain = bytes(PLAIN);
	// Пары ключей
	hpke::key_t ephemeral, own;
	// Вырабатываем мимолётную пару
	ASSERT_EQ(ephemeral.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmE)), hpke::error_t::NONE);
	// Вырабатываем пару получателя
	ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE);
	// Секреты экспорта по наборам
	std::vector <std::string> secrets;
	/**
	 * Выполняем обход наборов
	 */
	for(size_t i = 0; i < (sizeof(SUITES) / sizeof(hpke::suite_t)); i++){
		// Инкапсулированный ключ
		uint8_t enc[hpke::X25519_SIZE];
		// Состояние
		hpke::context_t context;
		// Устанавливаем состояние отправителя на одной и той же мимолётной паре
		ASSERT_EQ(hpke::sender(SUITES[i], hpke::regime_t::BASE, own.point(), viewed(info), hpke::shared_t(), nullptr, ephemeral, enc, context), hpke::error_t::NONE) << "набор " << i;
		// Секрет экспорта
		uint8_t secret[32];
		// Вырабатываем секрет
		ASSERT_EQ(context.exporter(view_t(), secret, sizeof(secret)), hpke::error_t::NONE);
		// Запоминаем секрет
		secrets.push_back(text(secret, sizeof(secret)));
	}
	/**
	 * Выполняем сличение секретов попарно
	 */
	for(size_t i = 0; i < secrets.size(); i++){
		/**
		 * Выполняем обход остальных
		 */
		for(size_t j = i + 1; j < secrets.size(); j++)
			// Проверяем, что опознаватель набора входит в расписание
			ASSERT_NE(secrets[i], secrets[j]) << "наборы " << i << " и " << j;
	}
}

/**
 * @brief Проверка нехватки памяти: перебор запасов выделений
 *
 */
TEST(HpkeTest, Starved){
	// Базовый вектор
	const vectors::vector_t & vector = vectors::VECTORS[FIRST];
	// Набор вектора
	const hpke::suite_t suite = suited(vector);
	// Материал и данные
	const std::vector <uint8_t> ikmR = bytes(vector.ikmR), info = bytes(vector.info), psk = bytes(PSK), identity = bytes(PSK_ID);
	// Длинный открытый текст: короткий не выделяет
	const std::vector <uint8_t> plain(700, 0x5A);
	// Пара получателя
	hpke::key_t own;
	// Вырабатываем пару получателя
	ASSERT_EQ(own.derive(hpke::kem_t::X25519_HKDF_SHA256, viewed(ikmR)), hpke::error_t::NONE);
	// Заранее разделённый ключ
	const hpke::shared_t shared(viewed(psk), viewed(identity));
	{
		// Признак того, что нехватка памяти встретилась
		bool starved = false;
		// Признак того, что на щедром запасе всё удалось
		bool complete = false;
		/**
		 * Выполняем перебор запасов выделений
		 */
		for(size_t budget = 0; (budget < 200) && !complete; budget++){
			// Отказы шагов
			hpke::error_t first = hpke::error_t::NONE, second = hpke::error_t::NONE, third = hpke::error_t::NONE, fourth = hpke::error_t::NONE;
			// Признак совпадения текста
			bool matched = false;
			{
				// Ограничиваем запас выделений
				starve::ration_t ration(budget);
				// Накопители
				std::vector <uint8_t> enc, sealed, opened, fresh, sent, received;
				// Зашифровываем одним шагом
				first = hpke::seal(suite, hpke::regime_t::PSK, own.point(), viewed(info), shared, nullptr, viewed(info), viewed(plain), enc, sealed);
				// Если зашифрование удалось
				if(first == hpke::error_t::NONE)
					// Расшифровываем одним шагом
					second = hpke::open(suite, hpke::regime_t::PSK, own, viewed(enc), viewed(info), shared, view_t(), viewed(info), viewed(sealed), opened);
				// Вырабатываем секрет отправителем
				third = hpke::dispatch(suite, hpke::regime_t::PSK, own.point(), viewed(info), shared, nullptr, viewed(info), 100, fresh, sent);
				// Если выработка удалась
				if(third == hpke::error_t::NONE)
					// Вырабатываем секрет получателем
					fourth = hpke::receive(suite, hpke::regime_t::PSK, own, viewed(fresh), viewed(info), shared, view_t(), viewed(info), 100, received);
				// Запоминаем совпадение
				matched = ((opened == plain) && (sent == received) && (sent.size() == 100));
			}
			// Запоминаем нехватку памяти
			starved = (starved || (first == hpke::error_t::MEMORY) || (second == hpke::error_t::MEMORY) || (third == hpke::error_t::MEMORY) || (fourth == hpke::error_t::MEMORY));
			// Проверяем законность исходов
			ASSERT_TRUE((first == hpke::error_t::NONE) || (first == hpke::error_t::MEMORY)) << "запас " << budget << " зашифрование " << static_cast <int> (first);
			// Проверяем расшифрование
			ASSERT_TRUE((second == hpke::error_t::NONE) || (second == hpke::error_t::MEMORY)) << "запас " << budget << " расшифрование " << static_cast <int> (second);
			// Проверяем выработку
			ASSERT_TRUE((third == hpke::error_t::NONE) || (third == hpke::error_t::MEMORY)) << "запас " << budget << " выработка " << static_cast <int> (third);
			// Проверяем приём
			ASSERT_TRUE((fourth == hpke::error_t::NONE) || (fourth == hpke::error_t::MEMORY)) << "запас " << budget << " приём " << static_cast <int> (fourth);
			// Запоминаем полный успех
			complete = ((first == hpke::error_t::NONE) && (second == hpke::error_t::NONE) && (third == hpke::error_t::NONE) && (fourth == hpke::error_t::NONE) && matched);
		}
		// Проверяем, что нехватка памяти встретилась
		ASSERT_TRUE(starved);
		// Проверяем, что на щедром запасе всё удалось
		ASSERT_TRUE(complete);
	}
	{
		// Инкапсулированный ключ
		uint8_t enc[hpke::X25519_SIZE];
		// Место под шифртекст
		std::vector <uint8_t> sealed(plain.size() + hpke::TAG_SIZE), opened(plain.size());
		// Секрет экспорта
		uint8_t secret[64];
		// Итоги шагов
		hpke::error_t first = hpke::error_t::NONE, second = hpke::error_t::NONE, third = hpke::error_t::NONE, fourth = hpke::error_t::NONE, fifth = hpke::error_t::NONE;
		{
			// Отмеряем нулевой запас выделений: всякое выделение на ключевом пути прервало бы исполнение
			starve::ration_t ration(0);
			// Пара получателя
			hpke::key_t key;
			// Состояния сторон
			hpke::context_t sending, receiving;
			// Вырабатываем пару из случайных байтов
			first = key.generate(hpke::kem_t::X25519_HKDF_SHA256);
			// Устанавливаем состояние отправителя со свежей мимолётной парой
			second = hpke::sender(suite, hpke::regime_t::PSK, key.point(), viewed(info), shared, nullptr, enc, sending);
			// Устанавливаем состояние получателя
			third = hpke::recipient(suite, hpke::regime_t::PSK, key, view_t(enc, sizeof(enc)), viewed(info), shared, view_t(), receiving);
			// Зашифровываем в место
			fourth = sending.seal(viewed(info), viewed(plain), sealed.data());
			// Расшифровываем в место
			fifth = receiving.open(viewed(info), viewed(sealed), opened.data());
			// Если расшифрование удалось
			if(fifth == hpke::error_t::NONE)
				// Вырабатываем секрет
				fifth = receiving.exporter(viewed(info), secret, sizeof(secret));
		}
		// Проверяем, что ключевой путь не выделяет память вовсе
		ASSERT_EQ(first, hpke::error_t::NONE);
		// Проверяем установку отправителя
		ASSERT_EQ(second, hpke::error_t::NONE);
		// Проверяем установку получателя
		ASSERT_EQ(third, hpke::error_t::NONE);
		// Проверяем зашифрование
		ASSERT_EQ(fourth, hpke::error_t::NONE);
		// Проверяем расшифрование и экспорт
		ASSERT_EQ(fifth, hpke::error_t::NONE);
		// Проверяем открытый текст
		ASSERT_EQ(opened, plain);
	}
}
