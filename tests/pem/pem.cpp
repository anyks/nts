/**
 * @file pem.cpp
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
#include <starve.hpp>
#include <pem/pem.hpp>
#include <asn1/asn1.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

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
	vector <uint8_t> specimen() noexcept {
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
 * Проверка разбора усечённого и порченого текста PEM
 *
 * @note Проверка эта итога разбора не судит: усечённый текст вправе и не
 *       разобраться, и разобраться в иное. Судит она лишь того, что разбор
 *       недоверенного текста обходится без отказа работы и за поданную строку не
 *       выходит. Смысл её раскрывается под санитайзерами
 */
TEST(PemTest, Ragged){
	// Заводим набор записываемых записей
	vector <pem::block_t> blocks(2);
	// Устанавливаем метку записи своего сертификата
	blocks[0].label = "CERTIFICATE";
	// Устанавливаем тело записи своего сертификата
	blocks[0].data.assign(70, 0x11);
	// Устанавливаем метку записи закрытого ключа
	blocks[1].label = "PRIVATE KEY";
	// Устанавливаем тело записи закрытого ключа
	blocks[1].data.assign(48, 0x22);
	// Записанный текст, служащий основою порчи
	string origin = "Пояснение перед записями\n";
	// Выполняем запись набора записей
	ASSERT_EQ(pem::encode(blocks, origin), pem::error_t::NONE);
	// Проверяем, что записанный текст не пуст
	ASSERT_GT(origin.size(), size_t(64));
	/**
	 * Знаки порчи берутся нарочно теми, коими текст PEM размечен: чертою, знаком
	 * перевода строки, знаком равенства набивки и знаком вне алфавита
	 */
	const char letters[5] = {'-', '\n', '=', '\0', 'Z'};
	/**
	 * Выполняем перебор длин усечения записанного текста
	 */
	for(size_t size = 0; size <= origin.size(); size++){
		// Место, в которое помещается разобранный набор записей
		vector <pem::block_t> taken;
		// Место, в которое помещается разобранный набор сертификатов
		vector <vector <uint8_t>> chain;
		// Место, в которое помещается разобранный закрытый ключ
		vector <uint8_t> secret;
		// Усечённый разбираемый текст PEM
		const string cut = origin.substr(0, size);
		// Выполняем разбор усечённого текста набором записей
		(void) pem::decode(cut, taken);
		// Выполняем разбор усечённого текста набором сертификатов
		(void) pem::certificates(cut, chain);
		// Выполняем разбор усечённого текста закрытым ключом
		(void) pem::secret(cut, secret);
		/**
		 * Выполняем перебор знаков порчи очередного места текста
		 */
		for(size_t item = 0; (size > 0) && (item < 5); item++){
			// Выполняем перенос усечённого текста PEM
			string spoiled = cut;
			// Портим последний знак усечённого текста
			spoiled[size - 1] = letters[item];
			// Место, в которое помещается разобранный набор записей
			vector <pem::block_t> items;
			// Место, в которое помещается разобранный набор сертификатов
			vector <vector <uint8_t>> chained;
			// Место, в которое помещается разобранный закрытый ключ
			vector <uint8_t> keyed;
			// Выполняем разбор порченого текста набором записей
			(void) pem::decode(spoiled, items);
			// Выполняем разбор порченого текста набором сертификатов
			(void) pem::certificates(spoiled, chained);
			// Выполняем разбор порченого текста закрытым ключом
			(void) pem::secret(spoiled, keyed);
			// Место, в которое помещается разобранный набор по метке
			vector <vector <uint8_t>> labelled;
			// Выполняем разбор порченого текста по метке записи
			(void) pem::decode(spoiled, "CERTIFICATE", labelled);
		}
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
	/**
	 * Пустая метка отвергается ОТСТУПЛЕНИЕМ от грамматики раздела 3 RFC 7468, где она
	 * взята в квадратные скобки и дозволена: раздел 4 перечисляет метки поимённо, и
	 * пустой среди них нет ни одной. Отступление намеренное, см. пункт 7 намеренных
	 * решений модуля
	 */
	EXPECT_EQ(pem::decode("-----BEGIN -----\nQU5ZS1M=\n-----END -----\n", blocks), pem::error_t::LABEL);
	/**
	 * Два пробела подряд посреди метки, наоборот, принимаются: раздел 2 говорит, что
	 * метки их не несут, а грамматика раздела 3 дозволяет. Метка на разбор тела не
	 * влияет, и заслон строже стандарта здесь ничего не сберегает - пункт 8 намеренных
	 * решений
	 */
	vector <pem::block_t> spacious;
	// Проверяем разбор записи с двумя пробелами подряд посреди метки
	EXPECT_EQ(pem::decode("-----BEGIN TEST  DATA-----\nQU5ZS1M=\n-----END TEST  DATA-----\n", spacious), pem::error_t::NONE);
	// Проверяем число разобранных записей с двумя пробелами посреди метки
	ASSERT_EQ(spacious.size(), static_cast <size_t> (1));
	// Проверяем метку разобранной записи
	EXPECT_EQ(spacious[0].label, "TEST  DATA");
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
	const vector <uint8_t> & key = specimen();
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
	/**
	 * Раздел 3 RFC 7468 отводит метке записи знаки печатного набора, а дефис и
	 * пробел - лишь разделителями между знаками (label = [labelchar *(["-" / SP]
	 * labelchar)]). Заслоны сверяются порознь - знаки ниже печатного набора, знаки
	 * выше него и дефис на краю метки, - и всякий отвергает метку в одиночку
	 */
	pem::block_t marked;
	// Устанавливаем метку записи со знаком выше печатного набора
	marked.label = "PRIVATEKEY";
	// Устанавливаем тело записываемой записи
	marked.data = vector <uint8_t> (8, 0x41);
	// Записанный текст записи с негодной меткой
	string spoiled;
	// Проверяем отказ записи с меткой, несущей знак выше печатного набора
	EXPECT_EQ(pem::encode(marked, spoiled), pem::error_t::LABEL);
	// Устанавливаем метку записи со знаком ниже печатного набора
	marked.label = "PRIVATEKEY";
	// Проверяем отказ записи с меткой, несущей знак ниже печатного набора
	EXPECT_EQ(pem::encode(marked, spoiled), pem::error_t::LABEL);
	// Устанавливаем метку записи с дефисом на краю
	marked.label = "-PRIVATEKEY";
	// Проверяем отказ записи с меткой, несущей дефис на краю: разделитель стоит лишь между знаками
	EXPECT_EQ(pem::encode(marked, spoiled), pem::error_t::LABEL);
	// Устанавливаем метку записи с дефисом посреди
	marked.label = "PRIVATE-KEY";
	// Проверяем принятие метки с дефисом посреди: грамматика раздела 3 RFC 7468 его дозволяет
	EXPECT_EQ(pem::encode(marked, spoiled), pem::error_t::NONE);
	/**
	 * Знак добивки стоит лишь на третьем либо четвёртом месте четвёрки знаков:
	 * добивка на первом месте означала бы четвёрку, не несущую ни одного байта
	 */
	vector <pem::block_t> blocks;
	// Проверяем отказ разбора текста с добивкой в начале четвёрки знаков
	EXPECT_NE(pem::decode("-----BEGIN CERTIFICATE-----\nQU5Z\n====\n-----END CERTIFICATE-----\n", blocks), pem::error_t::NONE);
	/**
	 * Разделы 2 и 3 RFC 7468 дозволяют перевод строки в любом месте тела, и пробельным
	 * считается не один лишь перевод: вертикальная табуляция с подачей страницы
	 * сверяются ОТДЕЛЬНЫМИ половинами того же условия
	 */
	EXPECT_EQ(pem::decode("-----BEGIN CERTIFICATE-----\nQU5Z\vS1M=\f\n-----END CERTIFICATE-----\n", blocks), pem::error_t::NONE);
	// Проверяем число разобранных записей текста с пробельными знаками
	ASSERT_EQ(blocks.size(), static_cast <size_t> (1));
	// Проверяем длину тела разобранной записи
	ASSERT_EQ(blocks[0].data.size(), static_cast <size_t> (5));
	// Накопитель, в который складываются записи текста с табуляцией и возвратом каретки
	vector <pem::block_t> spaced;
	// Проверяем разбор текста с горизонтальной табуляцией и возвратом каретки в теле
	EXPECT_EQ(pem::decode("-----BEGIN CERTIFICATE-----\nQU5Z\tS1M=\r\n-----END CERTIFICATE-----\n", spaced), pem::error_t::NONE);
	// Проверяем число разобранных записей текста с табуляцией и возвратом каретки
	ASSERT_EQ(spaced.size(), static_cast <size_t> (1));
	// Проверяем длину тела разобранной записи
	ASSERT_EQ(spaced[0].data.size(), static_cast <size_t> (5));
	/**
	 * Ключ записывается ПРОСТОЙ строкой байтов: составная её форма это средство
	 * кодировки BER, которой кодировка DER не знает
	 */
	pem::block_t compound;
	// Устанавливаем метку записи секретного ключа
	compound.label = "PRIVATE KEY";
	// Выполняем выработку обёртки годного секретного ключа
	ASSERT_TRUE(wrap(asn1::tag_t::OCTET_STRING, vector <uint8_t> (32, 0x11), compound.data));
	// Место, на котором стоит значащая часть ключа внутри обёртки
	size_t place = 0;
	/**
	 * Значащая часть ключа лежит строкой байтов длиною в тридцать два байта.
	 * Разыскиваем её метку, чтобы подменить простую форму записи составной: сам
	 * записчик составной её не запишет, и достаётся она только подменой байта
	 */
	for(size_t i = 0; (i + 1) < compound.data.size(); i++){
		// Если найдена строка байтов длиною в значащую часть ключа
		if((compound.data[i] == 0x04) && (compound.data[i + 1] == 0x20)){
			// Запоминаем место метки значащей части ключа
			place = i;
			// Выходим из розыска значащей части ключа
			break;
		}
	}
	// Проверяем, что значащая часть ключа в обёртке разыскана
	ASSERT_NE(place, static_cast <size_t> (0));
	// Подменяем простую форму записи значащей части составной
	compound.data[place] = 0x24;
	// Записанный текст записи с составной строкой байтов
	string enclosed;
	// Выполняем запись записи секретного ключа
	ASSERT_EQ(pem::encode(compound, enclosed), pem::error_t::NONE);
	// Проверяем отказ извлечения ключа, записанного составной строкой байтов
	EXPECT_EQ(pem::secret(enclosed, secret), pem::error_t::CONTENT);
	/**
	 * Вид метки и класс её сверяются РАЗНЫМИ половинами заслона: разборщик сличает
	 * записи по НОМЕРУ метки, оттого метка места употребления того же номера разбор
	 * проходит и отвергается уже половиной, отвечающей за класс
	 */
	compound.data[place] = 0x84;
	// Записанный текст записи со строкой байтов не универсального класса
	string foreign;
	// Выполняем запись записи секретного ключа
	ASSERT_EQ(pem::encode(compound, foreign), pem::error_t::NONE);
	// Проверяем отказ извлечения ключа, записанного меткой не универсального класса
	EXPECT_EQ(pem::secret(foreign, secret), pem::error_t::CONTENT);
}

/**
 * @brief Проверка отказов разбора обёртки секретного ключа
 *
 * @note Обёртки эти собираются записывателем ASN.1 вручную: выработка годных таких
 *       не выдаёт, и через неё подать их разбору нельзя
 *
 */
TEST(PemTest, Unwrapped){
	// Получаем образцовое число секретного ключа
	const vector <uint8_t> & key = specimen();
	/**
	 * @brief Метод подачи собранной обёртки извлечению секретного ключа
	 *
	 * @param writer записыватель собранной обёртки секретного ключа
	 *
	 * @return       отказ извлечения секретного ключа
	 *
	 */
	auto extract = [](asn1::Writer & writer) noexcept -> pem::error_t {
		// Просмотр собранной обёртки секретного ключа
		const view_t data = writer.data();
		// Заводим записываемую запись секретного ключа
		pem::block_t block;
		// Устанавливаем метку записи секретного ключа
		block.label = "PRIVATE KEY";
		// Устанавливаем тело записи секретного ключа
		block.data = vector <uint8_t> (data.data, data.data + data.size);
		// Записанный текст записи секретного ключа
		string text;
		// Если записать запись секретного ключа не удалось
		if(pem::encode(block, text) != pem::error_t::NONE)
			// Выводим отказ, записи не принадлежащий
			return pem::error_t::MEMORY;
		// Извлечённый секретный ключ
		vector <uint8_t> secret;
		// Выводим итог извлечения секретного ключа
		return pem::secret(text, secret);
	};
	/**
	 * Раздел 2 RFC 5958 велит нести секретный ключ набором значений: запись иного
	 * вида обёрткой ключа не является вовсе
	 */
	asn1::Writer alien;
	// Записываем обёртку строкой байтов вместо набора значений
	alien.octets(view_t(key.data(), key.size()));
	// Проверяем отказ извлечения ключа из обёртки чужеродного вида
	EXPECT_EQ(extract(alien), pem::error_t::CONTENT);
	/**
	 * Первым внутри обёртки стоит номер её вида, вторым - настройки алгоритма ключа,
	 * третьим - само тело ключа строкой байтов: раздел 2 RFC 5958
	 */
	asn1::Writer headless;
	// Открываем набор значений обёртки секретного ключа
	headless.open(asn1::tag_t::SEQUENCE);
	// Записываем строку байтов на месте номера вида обёртки
	headless.octets(view_t(key.data(), 4));
	// Закрываем набор значений обёртки секретного ключа
	headless.close();
	// Проверяем отказ извлечения ключа из обёртки без номера её вида
	EXPECT_EQ(extract(headless), pem::error_t::CONTENT);
	// Обёртка, у которой настройки алгоритма ключа не записаны вовсе
	asn1::Writer bare;
	// Открываем набор значений обёртки секретного ключа
	bare.open(asn1::tag_t::SEQUENCE);
	// Записываем номер вида обёртки секретного ключа
	bare.integer(0);
	// Закрываем набор значений обёртки секретного ключа
	bare.close();
	// Проверяем отказ извлечения ключа из обёртки без настроек алгоритма
	EXPECT_EQ(extract(bare), pem::error_t::CONTENT);
	// Обёртка, у которой тело самого ключа не записано вовсе
	asn1::Writer empty;
	// Открываем набор значений обёртки секретного ключа
	empty.open(asn1::tag_t::SEQUENCE);
	// Записываем номер вида обёртки секретного ключа
	empty.integer(0);
	// Открываем набор настроек алгоритма ключа
	empty.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель алгоритма ключа
	empty.oid("1.2.643.7.1.1.1.1");
	// Закрываем набор настроек алгоритма ключа
	empty.close();
	// Закрываем набор значений обёртки секретного ключа
	empty.close();
	// Проверяем отказ извлечения ключа из обёртки без тела ключа
	EXPECT_EQ(extract(empty), pem::error_t::CONTENT);
	/**
	 * @brief Метод сборки обёртки секретного ключа с заданным телом
	 *
	 * @param body   записываемое тело секретного ключа
	 * @param writer записыватель, в который складывается обёртка
	 *
	 */
	auto enclose = [](const view_t & body, asn1::Writer & writer) noexcept {
		// Открываем набор значений обёртки секретного ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем номер вида обёртки секретного ключа
		writer.integer(0);
		// Открываем набор настроек алгоритма ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма ключа
		writer.oid("1.2.643.7.1.1.1.1");
		// Закрываем набор настроек алгоритма ключа
		writer.close();
		// Записываем тело самого секретного ключа
		writer.octets(body);
		// Закрываем набор значений обёртки секретного ключа
		writer.close();
	};
	// Обёртка, тело ключа у которой пусто вовсе
	asn1::Writer hollow;
	// Собираем обёртку с пустым телом секретного ключа
	enclose(view_t(key.data(), 0), hollow);
	// Проверяем отказ извлечения ключа из обёртки с пустым телом
	EXPECT_EQ(extract(hollow), pem::error_t::CONTENT);
	/**
	 * За записью самого ключа внутри его тела не должно оставаться ничего: байты
	 * за нею означают запись, правилам не отвечающую
	 */
	asn1::Writer inner;
	// Записываем запись самого ключа строкой байтов
	inner.octets(view_t(key.data(), key.size()));
	// Получаем собранную запись самого ключа
	const view_t written = inner.data();
	// Тело ключа, за записью которого идут лишние байты
	vector <uint8_t> trailing(written.data, written.data + written.size);
	// Добавляем лишний байт за записью самого ключа
	trailing.push_back(0x00);
	// Обёртка, за записью ключа у которой идут лишние байты
	asn1::Writer excess;
	// Собираем обёртку с лишними байтами за записью ключа
	enclose(view_t(trailing.data(), trailing.size()), excess);
	// Проверяем отказ извлечения ключа с лишними байтами за его записью
	EXPECT_EQ(extract(excess), pem::error_t::CONTENT);
	/**
	 * Строка байтов ключа простого вида: составной её вид означает запись, правилам
	 * DER не отвечающую
	 */
	vector <uint8_t> recast(written.data, written.data + written.size);
	// Обращаем разряд составного вида метки записи самого ключа
	recast[0] = static_cast <uint8_t> (recast[0] | 0x20);
	// Обёртка, запись ключа у которой составного вида
	asn1::Writer constructed;
	// Собираем обёртку с записью ключа составного вида
	enclose(view_t(recast.data(), recast.size()), constructed);
	// Проверяем отказ извлечения ключа из записи составного вида
	EXPECT_EQ(extract(constructed), pem::error_t::CONTENT);
	/**
	 * Ключ записывается строкой байтов, целым числом либо набором значений по
	 * RFC 5915: запись всякого иного вида разбору не подлежит
	 */
	asn1::Writer boolean;
	// Записываем запись самого ключа истинностным значением
	boolean.boolean(true);
	// Получаем собранную запись самого ключа
	const view_t judged = boolean.data();
	// Обёртка, запись ключа у которой истинностного вида
	asn1::Writer strange;
	// Собираем обёртку с записью ключа истинностного вида
	enclose(view_t(judged.data, judged.size), strange);
	// Проверяем отказ извлечения ключа из записи неведомого вида
	EXPECT_EQ(extract(strange), pem::error_t::CONTENT);
	/**
	 * Набор значений записи ключа по RFC 5915 несёт номер вида записи, а следом
	 * само число ключа строкой байтов
	 */
	asn1::Writer numberless;
	// Открываем набор значений записи самого ключа
	numberless.open(asn1::tag_t::SEQUENCE);
	// Записываем строку байтов на месте номера вида записи
	numberless.octets(view_t(key.data(), 4));
	// Закрываем набор значений записи самого ключа
	numberless.close();
	// Получаем собранную запись самого ключа
	const view_t missing = numberless.data();
	// Обёртка, у которой в наборе значений ключа нет номера вида
	asn1::Writer unnumbered;
	// Собираем обёртку с набором значений без номера вида записи
	enclose(view_t(missing.data, missing.size), unnumbered);
	// Проверяем отказ извлечения ключа из набора без номера вида записи
	EXPECT_EQ(extract(unnumbered), pem::error_t::CONTENT);
	// Запись самого ключа, у которой нет самого числа ключа
	asn1::Writer keyless;
	// Открываем набор значений записи самого ключа
	keyless.open(asn1::tag_t::SEQUENCE);
	// Записываем номер вида записи самого ключа
	keyless.integer(1);
	// Закрываем набор значений записи самого ключа
	keyless.close();
	// Получаем собранную запись самого ключа
	const view_t absent = keyless.data();
	// Обёртка, у которой в наборе значений ключа нет самого числа
	asn1::Writer valueless;
	// Собираем обёртку с набором значений без числа ключа
	enclose(view_t(absent.data, absent.size), valueless);
	// Проверяем отказ извлечения ключа из набора без самого числа ключа
	EXPECT_EQ(extract(valueless), pem::error_t::CONTENT);
	/**
	 * Ключ, записанный целым числом с незначащим старшим байтом, правилам DER не
	 * отвечает: раздел 8.3.2 X.690 велит записывать число наименьшим числом байтов
	 */
	const vector <uint8_t> padded = {0x00, 0x01, 0x02, 0x03};
	// Запись ключа целым числом с незначащим старшим байтом
	asn1::Writer excessive;
	// Записываем число ключа с незначащим старшим байтом
	excessive.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view_t(padded.data(), padded.size()));
	// Получаем собранную запись самого ключа
	const view_t leading = excessive.data();
	// Обёртка, число ключа у которой несёт незначащий старший байт
	asn1::Writer redundant;
	// Собираем обёртку с числом ключа о незначащем старшем байте
	enclose(view_t(leading.data, leading.size), redundant);
	// Проверяем отказ извлечения ключа с незначащим старшим байтом числа
	EXPECT_EQ(extract(redundant), pem::error_t::CONTENT);
	/**
	 * Разрядность ключа берётся по длине его значащей части: число длиннее
	 * наибольшей разрядности ключом быть не может
	 */
	const vector <uint8_t> vast(65, 0x41);
	// Запись ключа непомерной длины
	asn1::Writer lengthy;
	// Записываем число ключа непомерной длины
	lengthy.octets(view_t(vast.data(), vast.size()));
	// Получаем собранную запись самого ключа
	const view_t oversize = lengthy.data();
	// Обёртка, число ключа у которой непомерной длины
	asn1::Writer immense;
	// Собираем обёртку с числом ключа непомерной длины
	enclose(view_t(oversize.data, oversize.size), immense);
	// Проверяем отказ извлечения ключа непомерной длины
	EXPECT_EQ(extract(immense), pem::error_t::CONTENT);
}

/**
 * @brief Проверка отказов записи добивки основания 64
 *
 */
TEST(PemTest, Padded){
	// Разобранные записи текста
	vector <pem::block_t> blocks;
	/**
	 * Раздел 4 RFC 4648 ставит знаку добивки место лишь в конце четвёрки знаков:
	 * добивка в ином её месте означает запись негодную
	 */
	EXPECT_EQ(pem::decode("-----BEGIN CERTIFICATE-----\nQ=U5\n-----END CERTIFICATE-----\n", blocks), pem::error_t::PADDING);
	// Проверяем отказ разбора добивки на втором знаке четвёрки
	EXPECT_EQ(pem::decode("-----BEGIN CERTIFICATE-----\n=QU5\n-----END CERTIFICATE-----\n", blocks), pem::error_t::PADDING);
	/**
	 * Знаков добивки в записи не бывает больше двух: четвёрка знаков несёт три
	 * байта, и добивка сверх двух знаков означала бы четвёрку без содержимого
	 */
	EXPECT_EQ(pem::decode("-----BEGIN CERTIFICATE-----\nQU5LUw===\n-----END CERTIFICATE-----\n", blocks), pem::error_t::PADDING);
}

/**
 * @brief Проверка отказов записи набора записей и имён отказов
 *
 */
TEST(PemTest, Naming){
	// Записанный текст набора записей
	string text;
	// Пустой набор записываемых записей
	vector <pem::block_t> blocks;
	// Проверяем отказ записи пустого набора записей
	EXPECT_EQ(pem::encode(blocks, text), pem::error_t::EMPTY);
	// Записываемая запись с негодной меткой
	pem::block_t block;
	// Устанавливаем метку записи с двумя дефисами подряд: два разделителя подряд грамматика не дозволяет
	block.label = "PRIVATE--KEY";
	// Устанавливаем тело записываемой записи
	block.data = vector <uint8_t> (8, 0x41);
	// Добавляем запись с негодной меткой в набор записей
	blocks.push_back(block);
	/**
	 * Отказ записи очередной записи набора выносится наружу как есть: набор записан
	 * быть не может, коль скоро не записана хотя бы одна его запись
	 */
	EXPECT_EQ(pem::encode(blocks, text), pem::error_t::LABEL);
	/**
	 * Всякому отказу отвечает своё имя, и одно имя двум отказам принадлежать не
	 * вправе: имена эти идут в журнал, и совпадение их скрыло бы разницу причин
	 */
	const pem::error_t errors[10] = {
		pem::error_t::NONE, pem::error_t::EMPTY, pem::error_t::BOUNDARY,
		pem::error_t::LABEL, pem::error_t::ALPHABET, pem::error_t::PADDING,
		pem::error_t::LENGTH, pem::error_t::CONTENT, pem::error_t::ENCRYPTED,
		pem::error_t::MEMORY
	};
	/**
	 * Выполняем перебор всех известных отказов разбора
	 */
	for(size_t i = 0; i < (sizeof(errors) / sizeof(pem::error_t)); i++){
		// Проверяем, что имя очередного отказа передано
		ASSERT_NE(pem::name(errors[i]), nullptr);
		/**
		 * Выполняем перебор отказов, стоящих впереди очередного
		 */
		for(size_t j = 0; j < i; j++)
			// Проверяем несовпадение имён двух разных отказов
			EXPECT_STRNE(pem::name(errors[i]), pem::name(errors[j])) << "отказы " << i << " и " << j;
	}
	// Проверяем имя отказа, ни одному из известных не отвечающего
	EXPECT_STREQ(pem::name(static_cast <pem::error_t> (0xFF)), "UNKNOWN");
}

/**
 * Проверка разбора при нехватке памяти
 */
TEST(PemTest, Starved){
	// Разбираемый текст с известным телом записи
	const string text = "-----BEGIN DATA-----\nQU5ZS1M=\n-----END DATA-----\n";
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе разбор обязан ответить
	 * либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 64; budget++){
		// Разобранные записи
		vector <pem::block_t> blocks;
		// Итог разбора при отмеренном запасе
		pem::error_t outcome = pem::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Выполняем разбор текста при отмеренном запасе
			outcome = pem::decode(text, blocks);
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((outcome == pem::error_t::NONE) || (outcome == pem::error_t::MEMORY)) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == pem::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}

/**
 * Стандартные заголовочные файлы осмотра освобождаемой памяти
 */
#if defined(__APPLE__)
	#include <malloc/malloc.h>
#elif defined(__linux__)
	#include <malloc.h>
#elif defined(__FreeBSD__)
	#include <malloc_np.h>
#endif

/**
 * @brief Служебные объекты проверок затирания секретов
 *
 */
namespace {
	/**
	 * @brief Образец, разыскиваемый в освобождаемой памяти
	 */
	vector <uint8_t> imprint;
	/**
	 * @brief Число освобождённых блоков, несущих образец
	 */
	size_t traces = 0;
	/**
	 * @brief Метод осмотра освобождаемого блока памяти
	 *
	 * @param data указатель на освобождаемый блок памяти
	 *
	 */
	void inspect(void * data) noexcept {
		// Если образец не задан
		if(imprint.empty())
			// Выходим из осмотра
			return;
		// Размер освобождаемого блока
		size_t size = 0;
		/**
		 * Размер блока берётся у самой кучи: у освобождаемого указателя иных сведений нет
		 */
		#if defined(__APPLE__)
			size = ::malloc_size(data);
		#elif defined(__linux__) || defined(__FreeBSD__)
			size = ::malloc_usable_size(data);
		#endif
		// Байты освобождаемого блока
		const uint8_t * bytes = static_cast <const uint8_t *> (data);
		/**
		 * Выполняем поиск образца по всему блоку
		 */
		for(size_t i = 0; (i + imprint.size()) <= size; i++){
			// Если образец найден
			if(::memcmp(bytes + i, imprint.data(), imprint.size()) == 0){
				// Учитываем освобождённый блок с образцом
				traces++;
				// Выходим из осмотра
				return;
			}
		}
	}
}

/**
 * Круг 8: тело записи, разбором по метке не запрошенной (PRIVATE KEY рядом с CERTIFICATE в тексте
 * «сертификат + ключ»), затирается перед освобождением - в освобождённой памяти секрет не остаётся
 * (решение 10 pem.cpp); сами сертификаты извлекаются как прежде
 */
TEST(PemTest, UnrequestedScoured){
	/**
	 * Проверка судит освобождаемую память самой кучи, и без сведений о размере блока
	 * слепа: такая система проверку не проходит и не проваливает, а пропускает с оглаской
	 */
	#if !defined(__APPLE__) && !defined(__linux__) && !defined(__FreeBSD__)
		GTEST_SKIP() << "размер освобождаемого блока на этой системе не узнать";
	#endif
	// Тело записи секретного ключа: приметный образец, повторов не имеющий
	pem::block_t secret;
	// Метка записи секретного ключа
	secret.label = "PRIVATE KEY";
	/**
	 * Выполняем заполнение тела записи секретного ключа
	 */
	for(size_t i = 0; i < 96; i++)
		// Добавляем очередной байт тела записи
		secret.data.push_back(static_cast <uint8_t> ((i * 73 + 41) & 0xFF));
	// Текст «сертификат + ключ»
	string text = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
	// Проверяем запись секретного ключа за сертификатом
	ASSERT_EQ(pem::encode(secret, text), pem::error_t::NONE);
	// Образец: середина тела секретного ключа
	imprint.assign(secret.data.begin() + 8, secret.data.begin() + 40);
	// Обнуляем число освобождённых блоков с образцом
	traces = 0;
	// Извлечённые сертификаты
	vector <vector <uint8_t>> chain;
	// Заводим наблюдателя освобождений
	starve::watch = inspect;
	// Итог извлечения сертификатов из текста с ключом
	const pem::error_t outcome = pem::certificates(text, chain);
	// Снимаем наблюдателя освобождений
	starve::watch = nullptr;
	// Опустошаем образец
	imprint.clear();
	// Проверяем успешность извлечения сертификатов
	ASSERT_EQ(outcome, pem::error_t::NONE);
	// Проверяем число извлечённых сертификатов
	ASSERT_EQ(chain.size(), size_t(1));
	// Проверяем тело извлечённого сертификата
	ASSERT_EQ(chain[0], vector <uint8_t> ({'A', 'B', 'C'}));
	// Проверяем, что ни один освобождённый блок тела ключа не нёс
	EXPECT_EQ(traces, size_t(0));
}

/**
 * Круг 8: текст записи собирается в место, взятое до записи целиком - строка не растёт по одному знаку,
 * и в освобождённой памяти не остаётся ни начала основания 64 тела ключа, ни прежнего накопителя с
 * записями рядом (решение 10 pem.cpp)
 */
TEST(PemTest, EncodeNoTraces){
	/**
	 * Проверка судит освобождаемую память самой кучи, и без сведений о размере блока
	 * слепа: такая система проверку не проходит и не проваливает, а пропускает с оглаской
	 */
	#if !defined(__APPLE__) && !defined(__linux__) && !defined(__FreeBSD__)
		GTEST_SKIP() << "размер освобождаемого блока на этой системе не узнать";
	#endif
	/**
	 * Под musl (OpenWRT, Alpine без glibc) malloc_usable_size отдаёт весь кусок, включая
	 * хвост чужих освобождённых данных, и наблюдатель видит образец не в своём блоке
	 * (тур 54): суждение о куче там недостоверно, проверка пропускается с оглаской
	 */
	#if defined(__linux__) && !defined(__GLIBC__)
		GTEST_SKIP() << "под musl размер освобождаемого блока недостоверен";
	#endif
	// Записываемая запись секретного ключа
	pem::block_t secret;
	// Метка записи секретного ключа
	secret.label = "PRIVATE KEY";
	/**
	 * Выполняем заполнение тела записи секретного ключа: длиной в несколько строк текста
	 */
	for(size_t i = 0; i < 1200; i++)
		// Добавляем очередной байт тела записи
		secret.data.push_back(static_cast <uint8_t> ((i * 131 + 7) & 0xFF));
	// Эталонный текст записи
	string text;
	// Проверяем запись эталонного текста
	ASSERT_EQ(pem::encode(secret, text), pem::error_t::NONE);
	// Место начала тела записи в тексте
	const size_t body = (text.find('\n') + 1);
	// Образец: знаки основания 64 из первой строки тела
	imprint.assign(text.begin() + static_cast <ptrdiff_t> (body + 20), text.begin() + static_cast <ptrdiff_t> (body + 44));
	// Обнуляем число освобождённых блоков с образцом
	traces = 0;
	// Текст записи в пустой накопитель
	string again;
	// Заводим наблюдателя освобождений
	starve::watch = inspect;
	// Итог записи в пустой накопитель
	const pem::error_t empty = pem::encode(secret, again);
	// Снимаем наблюдателя освобождений
	starve::watch = nullptr;
	// Проверяем успешность записи
	ASSERT_EQ(empty, pem::error_t::NONE);
	// Проверяем совпадение текста с эталоном
	ASSERT_EQ(again, text);
	// Проверяем, что ни один освобождённый блок основания 64 ключа не нёс
	EXPECT_EQ(traces, size_t(0));
	// Обнуляем число освобождённых блоков с образцом
	traces = 0;
	// Текст записи в накопитель, уже несущий ту же запись: ёмкости под вторую недостаёт
	string twice = text;
	// Заводим наблюдателя освобождений
	starve::watch = inspect;
	// Итог дописывания записи к накопителю
	const pem::error_t appended = pem::encode(secret, twice);
	// Снимаем наблюдателя освобождений
	starve::watch = nullptr;
	// Опустошаем образец
	imprint.clear();
	// Проверяем успешность дописывания
	ASSERT_EQ(appended, pem::error_t::NONE);
	// Проверяем, что накопитель несёт запись дважды
	ASSERT_EQ(twice, text + text);
	// Проверяем, что прежний накопитель с записью ключа затёрт перед освобождением
	EXPECT_EQ(traces, size_t(0));
}

/**
 * Круг 11 (разрез по свойству, секреты): decode(text, label) и secret(text) при обрыве разбора на
 * повреждённой записи возвращали отказ БЕЗ scour(blocks) - уже разобранный PRIVATE KEY гиб в
 * освобождённой памяти незатёртым (текст «валидный PRIVATE KEY + повреждённая запись»). Правка:
 * scour(blocks) на отказном возврате обоих. Мутация (снять scour) роняет пин.
 */
TEST(PemTest, DecodeErrorScoured){
	#if !defined(__APPLE__) && !defined(__linux__) && !defined(__FreeBSD__)
		GTEST_SKIP() << "размер освобождаемого блока на этой системе не узнать";
	#endif
	#if defined(__linux__) && !defined(__GLIBC__)
		GTEST_SKIP() << "под musl размер освобождаемого блока недостоверен";
	#endif
	// Приметное тело секретного ключа без повторов
	pem::block_t secret;
	secret.label = "PRIVATE KEY";
	for(size_t i = 0; i < 120; i++)
		secret.data.push_back(static_cast <uint8_t> ((i * 89 + 17) & 0xFF));
	// Текст: валидная запись PRIVATE KEY, затем повреждённая запись того же вида
	string text;
	ASSERT_EQ(pem::encode(secret, text), pem::error_t::NONE);
	text += "-----BEGIN PRIVATE KEY-----\n@@@@invalid_base64@@@@\n-----END PRIVATE KEY-----\n";
	// Образец: середина тела ключа
	imprint.assign(secret.data.begin() + 16, secret.data.begin() + 48);
	// decode(text, label): отказ обязан прийти, а тело ключа - быть затёртым
	{
		traces = 0;
		vector <vector <uint8_t>> result;
		starve::watch = inspect;
		const pem::error_t outcome = pem::decode(text, string("CERTIFICATE"), result);
		starve::watch = nullptr;
		EXPECT_NE(outcome, pem::error_t::NONE);
		EXPECT_EQ(traces, size_t(0)) << "decode(text,label): тело ключа осталось в освобождённой памяти";
	}
	// secret(text): тот же отказной путь извлечения секретного ключа
	{
		traces = 0;
		vector <uint8_t> key;
		starve::watch = inspect;
		const pem::error_t outcome = pem::secret(text, key);
		starve::watch = nullptr;
		EXPECT_NE(outcome, pem::error_t::NONE);
		EXPECT_EQ(traces, size_t(0)) << "secret(text): тело ключа осталось в освобождённой памяти";
	}
	imprint.clear();
}
