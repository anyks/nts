/**
 * @file pem.cpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-ANTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля хранения записей в виде PEM
 *
 * @note Обёртки ключей вырабатываются самими проверками: все три дозволенных вида записи
 *       ключа нужны рядом, а вырабатывающей их оснастки у проекта нет и не будет
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <pem/pem.hpp>
#include <asn1/asn1.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * @brief Метод выработки обёртки секретного ключа по RFC 5958
	 *
	 * @param kind   вид записи самого ключа внутри обёртки
	 * @param key    записываемое число ключа порядком от старшего байта к младшему
	 * @param result место, в которое помещается выработанная обёртка
	 *
	 * @return       признак успешности выработки обёртки секретного ключа
	 *
	 */
	bool wrap(const asn1::tag_t kind, const vector <uint8_t> & key, vector <uint8_t> & result) noexcept {
		// Тело самого ключа внутри обёртки
		asn1::Writer body;
		/**
		 * Выполняем определение вида записи самого ключа
		 */
		switch(static_cast <uint32_t> (kind)){
			// Если ключ записывается строкой байтов порядком от младшего байта к старшему
			case static_cast <uint32_t> (asn1::tag_t::OCTET_STRING): {
				// Число ключа порядком от младшего байта к старшему
				vector <uint8_t> reversed(key.rbegin(), key.rend());
				// Если записать число ключа не удалось
				if(!body.octets(view_t(reversed.data(), reversed.size())))
					// Выводим признак неудачной выработки обёртки
					return false;
			} break;
			// Если ключ записывается целым числом порядком от старшего байта к младшему
			case static_cast <uint32_t> (asn1::tag_t::INTEGER): {
				// Записываемое целое число ключа
				vector <uint8_t> number;
				// Если старший байт числа ключа принимается за знак
				if((key.front() & 0x80) != 0)
					// Добавляем к числу ключа незначащий старший байт
					number.push_back(0x00);
				// Записываем само число ключа
				number.insert(number.end(), key.begin(), key.end());
				// Если записать число ключа не удалось
				if(!body.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view_t(number.data(), number.size())))
					// Выводим признак неудачной выработки обёртки
					return false;
			} break;
			// Если ключ записывается набором значений по RFC 5915
			case static_cast <uint32_t> (asn1::tag_t::SEQUENCE): {
				// Если открыть набор значений записи ключа не удалось
				if(!body.open(asn1::tag_t::SEQUENCE))
					// Выводим признак неудачной выработки обёртки
					return false;
				// Если записать номер вида записи ключа не удалось
				if(!body.integer(1))
					// Выводим признак неудачной выработки обёртки
					return false;
				// Если записать число ключа не удалось
				if(!body.octets(view_t(key.data(), key.size())))
					// Выводим признак неудачной выработки обёртки
					return false;
				// Если закрыть набор значений записи ключа не удалось
				if(!body.close())
					// Выводим признак неудачной выработки обёртки
					return false;
			} break;
		}
		// Заводим записыватель обёртки секретного ключа
		asn1::Writer writer;
		// Если открыть обёртку секретного ключа не удалось
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если записать номер вида обёртки не удалось
		if(!writer.integer(0))
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если открыть настройки алгоритма ключа не удалось
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если записать опознаватель алгоритма ключа не удалось
		if(!writer.oid("1.2.643.7.1.1.1.1"))
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если записать опознаватель набора параметров кривой не удалось
		if(!writer.oid("1.2.643.7.1.2.1.1.1"))
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если закрыть настройки алгоритма ключа не удалось
		if(!writer.close())
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если записать тело самого ключа не удалось
		if(!writer.octets(body.data()))
			// Выводим признак неудачной выработки обёртки
			return false;
		// Если закрыть обёртку секретного ключа не удалось
		if(!writer.close())
			// Выводим признак неудачной выработки обёртки
			return false;
		// Получаем выработанную обёртку секретного ключа
		const view_t & data = writer.data();
		// Помещаем выработанную обёртку в итог
		result.assign(data.data, data.data + data.size);
		// Выводим признак успешной выработки обёртки секретного ключа
		return true;
	}
	/**
	 * @brief Метод выработки образцового числа секретного ключа
	 *
	 * @return образцовое число секретного ключа порядком от старшего байта к младшему
	 *
	 */
	vector <uint8_t> sample() noexcept {
		// Заводим образцовое число секретного ключа
		vector <uint8_t> result(32, 0);
		/**
		 * Выполняем заполнение образцового числа секретного ключа
		 */
		for(size_t i = 0; i < result.size(); i++)
			// Записываем очередной байт образцового числа
			result[i] = static_cast <uint8_t> (0x10 + i);
		// Выводим образцовое число секретного ключа
		return result;
	}
};

/**
 * @brief Проверка снятия тела записи с основания 64
 *
 */
TEST(PemTest, Alphabet){
	// Разобранные записи
	vector <pem::block_t> blocks;
	// Заводим разбираемый текст с известным телом записи
	const string text = "-----BEGIN DATA-----\nQU5ZS1M=\n-----END DATA-----\n";
	// Выполняем разбор текста
	ASSERT_EQ(pem::decode(text, blocks), pem::error_t::NONE);
	// Проверяем количество разобранных записей
	ASSERT_EQ(blocks.size(), 1u);
	// Проверяем метку разобранной записи
	EXPECT_EQ(blocks[0].label, "DATA");
	// Проверяем тело разобранной записи
	EXPECT_EQ(string(blocks[0].data.begin(), blocks[0].data.end()), "ANYKS");
}

/**
 * @brief Проверка обратимости записи и разбора
 *
 */
TEST(PemTest, Roundtrip){
	/**
	 * Выполняем перебор длин тела записи
	 */
	for(size_t size = 0; size < 200; size++){
		// Заводим записываемую запись
		pem::block_t block;
		// Устанавливаем метку записи
		block.label = "TEST DATA";
		// Заполняем тело записи
		for(size_t i = 0; i < size; i++)
			// Записываем очередной байт тела записи
			block.data.push_back(static_cast <uint8_t> ((i * 7) + 3));
		// Записанный текст
		string text;
		// Выполняем запись записи
		ASSERT_EQ(pem::encode(block, text), pem::error_t::NONE);
		/**
		 * Выполняем перебор всех строк записанного текста
		 */
		for(size_t offset = 0, next = 0; (next = text.find('\n', offset)) != string::npos; offset = (next + 1)){
			// Если очередная строка является рамкой записи
			if(text[offset] == '-')
				// Пропускаем рамку записи
				continue;
			// Проверяем длину очередной строки тела записи
			ASSERT_LE(next - offset, pem::PEM_WIDTH);
		}
		// Разобранные записи
		vector <pem::block_t> blocks;
		// Выполняем разбор записанного текста
		ASSERT_EQ(pem::decode(text, blocks), pem::error_t::NONE);
		// Проверяем количество разобранных записей
		ASSERT_EQ(blocks.size(), 1u);
		// Проверяем метку разобранной записи
		EXPECT_EQ(blocks[0].label, block.label);
		// Проверяем тело разобранной записи
		EXPECT_EQ(blocks[0].data, block.data);
	}
}

/**
 * @brief Проверка извлечения цепочки сертификатов
 *
 */
TEST(PemTest, Chain){
	// Заводим набор записываемых записей
	vector <pem::block_t> blocks(2);
	// Устанавливаем метку записи своего сертификата
	blocks[0].label = "CERTIFICATE";
	// Устанавливаем тело записи своего сертификата
	blocks[0].data.assign(70, 0x11);
	// Устанавливаем метку записи сертификата издателя
	blocks[1].label = "CERTIFICATE";
	// Устанавливаем тело записи сертификата издателя
	blocks[1].data.assign(90, 0x22);
	// Записанный текст
	string text = "Пояснение к цепочке сертификатов\n";
	// Выполняем запись набора записей
	ASSERT_EQ(pem::encode(blocks, text), pem::error_t::NONE);
	// Дописываем пояснение к записям
	text.append("Пояснение после цепочки\n");
	// Извлечённая цепочка сертификатов
	vector <vector <uint8_t>> chain;
	// Выполняем извлечение цепочки сертификатов
	ASSERT_EQ(pem::certificates(text, chain), pem::error_t::NONE);
	// Проверяем длину извлечённой цепочки сертификатов
	ASSERT_EQ(chain.size(), 2u);
	// Проверяем порядок извлечённой цепочки сертификатов
	EXPECT_EQ(chain[0], blocks[0].data);
	// Проверяем сертификат издателя
	EXPECT_EQ(chain[1], blocks[1].data);
	// Заводим набор тел записей другого вида
	vector <vector <uint8_t>> others;
	// Проверяем отсутствие записей другого вида
	EXPECT_EQ(pem::decode(text, "PRIVATE KEY", others), pem::error_t::EMPTY);
}

/**
 * @brief Проверка отказов разбора испорченного текста
 *
 */
TEST(PemTest, Broken){
	// Разобранные записи
	vector <pem::block_t> blocks;
	// Проверяем отказ на оборванной рамке записи
	EXPECT_EQ(pem::decode("-----BEGIN DATA-----\nQU5ZS1M=\n", blocks), pem::error_t::BOUNDARY);
	// Проверяем отказ на рамке, закрытой не своей меткой
	EXPECT_EQ(pem::decode("-----BEGIN DATA-----\nQU5ZS1M=\n-----END OTHER-----\n", blocks), pem::error_t::BOUNDARY);
	// Проверяем отказ на записи, открытой внутри другой записи
	EXPECT_EQ(pem::decode("-----BEGIN DATA-----\n-----BEGIN DATA-----\n-----END DATA-----\n", blocks), pem::error_t::BOUNDARY);
	// Проверяем отказ на пустой метке записи
	EXPECT_EQ(pem::decode("-----BEGIN -----\nQU5ZS1M=\n-----END -----\n", blocks), pem::error_t::LABEL);
	// Проверяем отказ на знаке вне основания 64
	EXPECT_EQ(pem::decode("-----BEGIN DATA-----\nQU5Z*1M=\n-----END DATA-----\n", blocks), pem::error_t::ALPHABET);
	// Проверяем отказ на добивке посреди тела записи
	EXPECT_EQ(pem::decode("-----BEGIN DATA-----\nQU5=S1M=\n-----END DATA-----\n", blocks), pem::error_t::PADDING);
	// Проверяем отказ на длине тела записи, основанию не отвечающей
	EXPECT_EQ(pem::decode("-----BEGIN DATA-----\nQU5ZS1MA\nQ\n-----END DATA-----\n", blocks), pem::error_t::LENGTH);
	// Проверяем, что записей при отказе не набралось
	EXPECT_TRUE(blocks.empty());
	// Проверяем, что текст без записей отказа не даёт
	EXPECT_EQ(pem::decode("Записей здесь нет вовсе\n", blocks), pem::error_t::NONE);
	// Проверяем, что записей в тексте без записей не набралось
	EXPECT_TRUE(blocks.empty());
}

/**
 * @brief Проверка извлечения секретного ключа
 *
 */
TEST(PemTest, Secret){
	// Получаем образцовое число секретного ключа
	const vector <uint8_t> & key = sample();
	/**
	 * Выполняем перебор всех дозволенных видов записи ключа
	 */
	for(const auto kind : {asn1::tag_t::OCTET_STRING, asn1::tag_t::INTEGER, asn1::tag_t::SEQUENCE}){
		// Заводим записываемую запись секретного ключа
		pem::block_t block;
		// Устанавливаем метку записи секретного ключа
		block.label = "PRIVATE KEY";
		// Выполняем выработку обёртки секретного ключа
		ASSERT_TRUE(wrap(kind, key, block.data));
		// Записанный текст
		string text;
		// Выполняем запись записи секретного ключа
		ASSERT_EQ(pem::encode(block, text), pem::error_t::NONE);
		// Извлечённый секретный ключ
		vector <uint8_t> secret;
		// Выполняем извлечение секретного ключа
		ASSERT_EQ(pem::secret(text, secret), pem::error_t::NONE);
		// Проверяем извлечённый секретный ключ
		EXPECT_EQ(secret, key);
	}
}

/**
 * @brief Проверка отказов извлечения секретного ключа
 *
 */
TEST(PemTest, Refusal){
	// Извлечённый секретный ключ
	vector <uint8_t> secret;
	// Проверяем отказ на тексте без записи секретного ключа
	EXPECT_EQ(pem::secret("-----BEGIN CERTIFICATE-----\nQU5ZS1M=\n-----END CERTIFICATE-----\n", secret), pem::error_t::EMPTY);
	// Проверяем отказ на зашифрованном секретном ключе
	EXPECT_EQ(pem::secret("-----BEGIN ENCRYPTED PRIVATE KEY-----\nQU5ZS1M=\n-----END ENCRYPTED PRIVATE KEY-----\n", secret), pem::error_t::ENCRYPTED);
	// Проверяем отказ на теле записи, обёрткой ключа не являющемся
	EXPECT_EQ(pem::secret("-----BEGIN PRIVATE KEY-----\nQU5ZS1M=\n-----END PRIVATE KEY-----\n", secret), pem::error_t::CONTENT);
	// Заводим записываемую запись секретного ключа
	pem::block_t block;
	// Устанавливаем метку записи секретного ключа
	block.label = "PRIVATE KEY";
	// Выполняем выработку обёртки нулевого секретного ключа
	ASSERT_TRUE(wrap(asn1::tag_t::OCTET_STRING, vector <uint8_t> (32, 0x00), block.data));
	// Записанный текст
	string text;
	// Выполняем запись записи секретного ключа
	ASSERT_EQ(pem::encode(block, text), pem::error_t::NONE);
	// Проверяем отказ на ключе без значащей части вовсе
	EXPECT_EQ(pem::secret(text, secret), pem::error_t::CONTENT);
}
