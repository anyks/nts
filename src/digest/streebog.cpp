/**
 * @file streebog.cpp
 * @date 2026-08-27
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
 * @brief Исходный файл модуля хеширования «Стрибог» — реализация выработки хеша
 *        по ГОСТ Р 34.11-2012
 *
 * @note Двоичные векторы длиной 512 разрядов хранятся восемью словами, и слово с
 *       номером нуль несёт младшие разряды. Порядок этот задан самим стандартом:
 *       вектор в нём записан от старшего разряда к младшему, а подаваемое сообщение
 *       ложится в вектор младшими разрядами вперёд. Оттого байт сообщения с номером
 *       нуль оказывается младшим байтом вектора, а выработанный хеш выдаётся в
 *       обратном порядке байтов
 *
 * @note Постоянные величины взяты из текста ГОСТ Р 34.11-2012 (перепечатан RFC 6986)
 *       и в исходном тексте не пересчитывались: таблица подстановки, матрица
 *       линейного преобразования и величины итераций перенесены дословно, а
 *       производная от них таблица преобразования LPS вычисляется при сборке
 *
 * @note Обозначение __ANTS_INLINE__ у преобразования LPS не украшение: преобразование
 *       зовётся двадцать пять раз на всякий блок сообщения, и оставленное вызовом оно
 *       гоняет через стек по 64 байта состояния на всякий вызов. Замер 31.08.2026:
 *       284 МБ/с без встраивания против 375 МБ/с с ним
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/streebog.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::digest;

	/**
	 * @brief Нелинейное биективное преобразование множества двоичных векторов
	 *
	 * @details Подстановка Pi' по разделу 6.2 ГОСТ Р 34.11-2012
	 *
	 */
	static constexpr uint8_t PI[256] = {
		0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
		0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
		0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
		0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
		0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
		0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
		0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
		0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
		0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
		0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
		0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
		0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
		0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
		0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
		0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
		0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
		0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
		0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
		0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
		0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
		0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
		0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
		0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
		0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
		0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
		0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
		0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
		0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
		0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
		0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
		0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
		0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
	};

	/**
	 * @brief Матрица линейного преобразования над полем GF(2)
	 *
	 * @details Строки матрицы A по разделу 6.4 ГОСТ Р 34.11-2012. Строка с номером
	 *          нуль отвечает старшему разряду умножаемого вектора
	 *
	 */
	static constexpr uint64_t MATRIX[64] = {
		0x8E20FAA72BA0B470ULL, 0x47107DDD9B505A38ULL,
		0xAD08B0E0C3282D1CULL, 0xD8045870EF14980EULL,
		0x6C022C38F90A4C07ULL, 0x3601161CF205268DULL,
		0x1B8E0B0E798C13C8ULL, 0x83478B07B2468764ULL,
		0xA011D380818E8F40ULL, 0x5086E740CE47C920ULL,
		0x2843FD2067ADEA10ULL, 0x14AFF010BDD87508ULL,
		0x0AD97808D06CB404ULL, 0x05E23C0468365A02ULL,
		0x8C711E02341B2D01ULL, 0x46B60F011A83988EULL,
		0x90DAB52A387AE76FULL, 0x486DD4151C3DFDB9ULL,
		0x24B86A840E90F0D2ULL, 0x125C354207487869ULL,
		0x092E94218D243CBAULL, 0x8A174A9EC8121E5DULL,
		0x4585254F64090FA0ULL, 0xACCC9CA9328A8950ULL,
		0x9D4DF05D5F661451ULL, 0xC0A878A0A1330AA6ULL,
		0x60543C50DE970553ULL, 0x302A1E286FC58CA7ULL,
		0x18150F14B9EC46DDULL, 0x0C84890AD27623E0ULL,
		0x0642CA05693B9F70ULL, 0x0321658CBA93C138ULL,
		0x86275DF09CE8AAA8ULL, 0x439DA0784E745554ULL,
		0xAFC0503C273AA42AULL, 0xD960281E9D1D5215ULL,
		0xE230140FC0802984ULL, 0x71180A8960409A42ULL,
		0xB60C05CA30204D21ULL, 0x5B068C651810A89EULL,
		0x456C34887A3805B9ULL, 0xAC361A443D1C8CD2ULL,
		0x561B0D22900E4669ULL, 0x2B838811480723BAULL,
		0x9BCF4486248D9F5DULL, 0xC3E9224312C8C1A0ULL,
		0xEFFA11AF0964EE50ULL, 0xF97D86D98A327728ULL,
		0xE4FA2054A80B329CULL, 0x727D102A548B194EULL,
		0x39B008152ACB8227ULL, 0x9258048415EB419DULL,
		0x492C024284FBAEC0ULL, 0xAA16012142F35760ULL,
		0x550B8E9E21F7A530ULL, 0xA48B474F9EF5DC18ULL,
		0x70A6A56E2440598EULL, 0x3853DC371220A247ULL,
		0x1CA76E95091051ADULL, 0x0EDD37C48A08A6D8ULL,
		0x07E095624504536CULL, 0x8D70C431AC02A736ULL,
		0xC83862965601DD1BULL, 0x641C314B2B8EE083ULL
	};

	/**
	 * @brief Постоянные величины итераций
	 *
	 * @details Величины C[1] ... C[12] по разделу 6.5 ГОСТ Р 34.11-2012. Каждая
	 *          величина разложена на восемь слов, и слово с номером нуль несёт
	 *          младшие разряды
	 *
	 */
	static constexpr uint64_t CONSTANTS[12][8] = {
		{
			0xDD806559F2A64507ULL, 0x05767436CC744D23ULL,
			0xA2422A08A460D315ULL, 0x4B7CE09192676901ULL,
			0x714EB88D7585C4FCULL, 0x2F6A76432E45D016ULL,
			0xEBCB2F81C0657C1FULL, 0xB1085BDA1ECADAE9ULL
		},
		{
			0xE679047021B19BB7ULL, 0x55DDA21BD7CBCD56ULL,
			0x5CB561C2DB0AA7CAULL, 0x9AB5176B12D69958ULL,
			0x61D55E0F16B50131ULL, 0xF3FEEA720A232B98ULL,
			0x4FE39D460F70B5D7ULL, 0x6FA3B58AA99D2F1AULL
		},
		{
			0x991E96F50ABA0AB2ULL, 0xC2B6F443867ADB31ULL,
			0xC1C93A376062DB09ULL, 0xD3E20FE490359EB1ULL,
			0xF2EA7514B1297B7BULL, 0x06F15E5F529C1F8BULL,
			0x0A39FC286A3D8435ULL, 0xF574DCAC2BCE2FC7ULL
		},
		{
			0x220CBEBC84E3D12EULL, 0x3453EAA193E837F1ULL,
			0xD8B71333935203BEULL, 0xA9D72C82ED03D675ULL,
			0x9D721CAD685E353FULL, 0x488E857E335C3C7DULL,
			0xF948E1A05D71E4DDULL, 0xEF1FDFB3E81566D2ULL
		},
		{
			0x601758FD7C6CFE57ULL, 0x7A56A27EA9EA63F5ULL,
			0xDFFF00B723271A16ULL, 0xBFCD1747253AF5A3ULL,
			0x359E35D7800FFFBDULL, 0x7F151C1F1686104AULL,
			0x9A3F410C6CA92363ULL, 0x4BEA6BACAD474799ULL
		},
		{
			0xFA68407A46647D6EULL, 0xBF71C57236904F35ULL,
			0x0AF21F66C2BEC6B6ULL, 0xCFFAA6B71C9AB7B4ULL,
			0x187F9AB49AF08EC6ULL, 0x2D66C4F95142A46CULL,
			0x6FA4C33B7A3039C0ULL, 0xAE4FAEAE1D3AD3D9ULL
		},
		{
			0x8886564D3A14D493ULL, 0x3517454CA23C4AF3ULL,
			0x06476983284A0504ULL, 0x0992ABC52D822C37ULL,
			0xD3473E33197A93C9ULL, 0x399EC6C7E6BF87C9ULL,
			0x51AC86FEBF240954ULL, 0xF4C70E16EEAAC5ECULL
		},
		{
			0xA47F0DD4BF02E71EULL, 0x36ACC2355951A8D9ULL,
			0x69D18D2BD1A5C42FULL, 0xF4892BCB929B0690ULL,
			0x89B4443B4DDBC49AULL, 0x4EB7F8719C36DE1EULL,
			0x03E7AA020C6E4141ULL, 0x9B1F5B424D93C9A7ULL
		},
		{
			0x7261445183235ADBULL, 0x0E38DC92CB1F2A60ULL,
			0x7B2B8A9AA6079C54ULL, 0x800A440BDBB2CEB1ULL,
			0x3CD955B7E00D0984ULL, 0x3A7D3A1B25894224ULL,
			0x944C9AD8EC165FDEULL, 0x378F5A541631229BULL
		},
		{
			0x74B4C7FB98459CEDULL, 0x3698FAD1153BB6C3ULL,
			0x7A1E6C303B7652F4ULL, 0x9FE76702AF69334BULL,
			0x1FFFE18A1B336103ULL, 0x8941E71CFF8A78DBULL,
			0x382AE548B2E4F3F3ULL, 0xABBEDEA680056F52ULL
		},
		{
			0x6BCAA4CD81F32D1BULL, 0xDEA2594AC06FD85DULL,
			0xEFBACD1D7D476E98ULL, 0x8A1D71EFEA48B9CAULL,
			0x2001802114846679ULL, 0xD8FA6BBBEBAB0761ULL,
			0x3002C6CD635AFE94ULL, 0x7BCD9ED0EFC889FBULL
		},
		{
			0x48BC924AF11BD720ULL, 0xFAF417D5D9B21B99ULL,
			0xE71DA4AA88E12852ULL, 0x5D80EF9D1891CC86ULL,
			0xF82012D430219F9BULL, 0xCDA43C32BCDF1D77ULL,
			0xD21380B00449B17AULL, 0x378EE767F11631BAULL
		}
	};

	/**
	 * @brief Таблица совмещённого преобразования LPS
	 *
	 */
	typedef struct Tables {
		// Слагаемые преобразования по номеру байта и его значению
		uint64_t values[8][256];
	} tables_t;

	/**
	 * @brief Метод вычисления таблицы совмещённого преобразования LPS
	 *
	 * @details Преобразования S, P и L сводятся в одну таблицу. Подстановка S
	 *          заменяет байт, перестановка P задаёт, из какого слова взят байт, а
	 *          линейное преобразование L обращается в исключающее ИЛИ строк матрицы,
	 *          отвечающих единичным разрядам байта. Слагаемое зависит лишь от номера
	 *          байта и его значения, оттого и берётся таблицей
	 *
	 * @return вычисленная таблица преобразования
	 *
	 */
	static constexpr tables_t compute() noexcept {
		// Вычисляемая таблица преобразования
		tables_t result = {};
		/**
		 * Выполняем перебор номеров байтов внутри слова
		 */
		for(size_t i = 0; i < 8; i++){
			/**
			 * Выполняем перебор возможных значений байта
			 */
			for(size_t j = 0; j < 256; j++){
				// Выполняем подстановку значения байта
				const uint8_t value = PI[j];
				// Собираемое слагаемое преобразования
				uint64_t item = 0;
				/**
				 * Выполняем перебор разрядов подставленного значения
				 */
				for(size_t k = 0; k < 8; k++){
					// Если разряд подставленного значения установлен
					if(((value >> k) & 0x01) != 0)
						// Дополняем слагаемое строкой матрицы, отвечающей разряду
						item ^= MATRIX[63 - (i * 8) - k];
				}
				// Запоминаем слагаемое преобразования
				result.values[i][j] = item;
			}
		}
		// Выводим вычисленную таблицу преобразования
		return result;
	}

	/**
	 * @brief Таблица совмещённого преобразования LPS
	 *
	 */
	static constexpr tables_t TABLES = compute();

	/**
	 * @brief Метод совмещённого преобразования LPS над суммой двух векторов
	 *
	 * @param first  первое слагаемое исключающего ИЛИ
	 * @param second второе слагаемое исключающего ИЛИ
	 * @param result вектор, в который помещается итог преобразования
	 *
	 */
	static __ANTS_INLINE__ void transform(const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
		// Сумма слагаемых по исключающему ИЛИ
		uint64_t value[8];
		/**
		 * Выполняем сложение векторов по исключающему ИЛИ
		 */
		for(size_t i = 0; i < 8; i++)
			// Складываем очередные слова векторов
			value[i] = (first[i] ^ second[i]);
		/**
		 * Выполняем перебор слов итога преобразования
		 */
		for(size_t i = 0; i < 8; i++){
			// Собираемое слово итога преобразования
			uint64_t item = 0;
			/**
			 * Выполняем перебор слов преобразуемого вектора
			 */
			for(size_t j = 0; j < 8; j++)
				// Дополняем слово слагаемым, отвечающим байту преобразуемого слова
				item ^= TABLES.values[j][(value[j] >> (i * 8)) & 0xFF];
			// Запоминаем собранное слово итога преобразования
			result[i] = item;
		}
	}

	/**
	 * @brief Метод шифрования блока сообщения
	 *
	 * @details Преобразование E по разделу 8 ГОСТ Р 34.11-2012: двенадцать
	 *          применений LPSX с последовательно вырабатываемыми ключами и сложение
	 *          с тринадцатым ключом
	 *
	 * @param key     ключ шифрования
	 * @param message шифруемый блок сообщения
	 * @param result  вектор, в который помещается итог шифрования
	 *
	 */
	static void encrypt(const uint64_t * key, const uint64_t * message, uint64_t * result) noexcept {
		// Вырабатываемый ключ очередной итерации
		uint64_t item[8];
		// Состояние шифруемого блока
		uint64_t state[8];
		/**
		 * Выполняем перенос ключа шифрования
		 */
		for(size_t i = 0; i < 8; i++)
			// Переносим очередное слово ключа шифрования
			item[i] = key[i];
		// Выполняем первое применение преобразования к блоку сообщения
		transform(message, item, state);
		/**
		 * Выполняем оставшиеся одиннадцать применений преобразования
		 */
		for(size_t i = 0; i < 11; i++){
			// Вырабатываем ключ очередной итерации
			transform(item, CONSTANTS[i], item);
			// Применяем преобразование к состоянию шифруемого блока
			transform(state, item, state);
		}
		// Вырабатываем ключ последней итерации
		transform(item, CONSTANTS[11], item);
		/**
		 * Выполняем сложение состояния с ключом последней итерации
		 */
		for(size_t i = 0; i < 8; i++)
			// Складываем очередные слова состояния и ключа
			result[i] = (state[i] ^ item[i]);
	}

	/**
	 * @brief Метод сжатия блока сообщения
	 *
	 * @details Функция g_N по разделу 8 ГОСТ Р 34.11-2012
	 *
	 * @param hash    вычисляемое значение хеша
	 * @param counter число разобранных разрядов сообщения
	 * @param message сжимаемый блок сообщения
	 *
	 */
	static void compress(uint64_t * hash, const uint64_t * counter, const uint64_t * message) noexcept {
		// Ключ шифрования блока сообщения
		uint64_t key[8];
		// Итог шифрования блока сообщения
		uint64_t value[8];
		// Вырабатываем ключ шифрования блока сообщения
		transform(hash, counter, key);
		// Выполняем шифрование блока сообщения
		encrypt(key, message, value);
		/**
		 * Выполняем сложение итога шифрования с хешем и блоком сообщения
		 */
		for(size_t i = 0; i < 8; i++)
			// Складываем очередные слова итога, хеша и блока сообщения
			hash[i] = (value[i] ^ hash[i] ^ message[i]);
	}

	/**
	 * @brief Метод сложения двоичных векторов по модулю два в степени 512
	 *
	 * @param value  вектор, к которому производится сложение
	 * @param addend прибавляемый вектор
	 *
	 */
	static __ANTS_INLINE__ void increase(uint64_t * value, const uint64_t * addend) noexcept {
		// Перенос из младшего слова в старшее
		uint64_t carry = 0;
		/**
		 * Выполняем перебор слов складываемых векторов от младшего к старшему
		 */
		for(size_t i = 0; i < 8; i++){
			// Выполняем сложение очередных слов вместе с переносом
			const uint64_t item = (value[i] + addend[i] + carry);
			/**
			 * Перенос определяется сличением, а не разрядностью: сумма трёх слагаемых
			 * переполняется и тогда, когда равна одному из них
			 */
			carry = (((item < value[i]) || ((carry != 0) && (item == value[i]))) ? 1 : 0);
			// Запоминаем сумму очередных слов
			value[i] = item;
		}
	}

	/**
	 * @brief Метод разбора блока сообщения на слова
	 *
	 * @param data   разбираемый блок сообщения
	 * @param result вектор, в который помещаются разобранные слова
	 *
	 */
	static __ANTS_INLINE__ void load(const uint8_t * data, uint64_t * result) noexcept {
		/**
		 * Выполняем перебор слов разбираемого блока сообщения
		 */
		for(size_t i = 0; i < 8; i++){
			// Собираемое слово блока сообщения
			uint64_t item = 0;
			/**
			 * Выполняем перебор байтов очередного слова
			 */
			for(size_t j = 0; j < 8; j++)
				// Дополняем слово очередным байтом блока сообщения
				item |= (static_cast <uint64_t> (data[(i * 8) + j]) << (j * 8));
			// Запоминаем собранное слово блока сообщения
			result[i] = item;
		}
	}
};

/**
 * @brief Метод извлечения длины вырабатываемого хеша
 *
 * @return длина вырабатываемого хеша
 *
 */
nts::digest::type_t nts::digest::Streebog::type() const noexcept {
	// Выводим длину вырабатываемого хеша
	return this->_type;
}
/**
 * @brief Метод приведения объекта к началу хеширования
 *
 * @param type длина вырабатываемого хеша
 *
 */
void nts::digest::Streebog::reset(const type_t type) noexcept {
	// Запоминаем длину вырабатываемого хеша
	this->_type = type;
	// Снимаем признак того, что хеш уже снят
	this->_finished = false;
	// Обнуляем число байтов, накопленных в незавершённом блоке
	this->_size = 0;
	/**
	 * Начальным значением хеша длиной 256 разрядов служит вектор из единичных
	 * байтов, а хеша длиной 512 разрядов - нулевой вектор
	 */
	const uint64_t initial = ((type == type_t::SHORT) ? 0x0101010101010101ULL : 0x0000000000000000ULL);
	/**
	 * Выполняем перебор слов состояния хеширования
	 */
	for(size_t i = 0; i < 8; i++){
		// Устанавливаем начальное значение хеша
		this->_hash[i] = initial;
		// Обнуляем число разобранных разрядов сообщения
		this->_count[i] = 0;
		// Обнуляем контрольную сумму разобранных блоков сообщения
		this->_sum[i] = 0;
	}
	// Обнуляем накопитель незавершённого блока сообщения
	::memset(this->_block, 0, sizeof(this->_block));
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Streebog::update(const view_t & data) noexcept {
	// Если хеширование завершено либо кусок сообщения пустой
	if(this->_finished || (this->_type == type_t::NONE) || (data.data == nullptr) || (data.size == 0))
		// Выходим из метода
		return;
	// Число разрядов одного блока сообщения
	static const uint64_t width[8] = {512, 0, 0, 0, 0, 0, 0, 0};
	// Разобранный блок сообщения
	uint64_t message[8];
	// Число разобранных байтов куска сообщения
	size_t offset = 0;
	/**
	 * Выполняем разбор куска сообщения по блокам
	 */
	while(offset < data.size){
		/**
		 * Если накопитель блока пуст, а подаваемого куска достаёт на целый блок,
		 * блок разбирается прямо из куска: перенос его в накопитель здесь лишний
		 */
		if((this->_size == 0) && ((data.size - offset) >= sizeof(this->_block))){
			// Выполняем разбор блока сообщения прямо из подаваемого куска
			load(data.data + offset, message);
			// Выполняем сжатие блока сообщения
			compress(this->_hash, this->_count, message);
			// Увеличиваем число разобранных разрядов сообщения
			increase(this->_count, width);
			// Дополняем контрольную сумму разобранных блоков сообщения
			increase(this->_sum, message);
			// Сдвигаем место разбора куска сообщения
			offset += sizeof(this->_block);
			// Переходим к разбору следующего блока сообщения
			continue;
		}
		// Определяем число байтов, которых недостаёт блоку
		const size_t need = (sizeof(this->_block) - this->_size);
		// Определяем число переносимых байтов куска сообщения
		const size_t count = (((data.size - offset) < need) ? (data.size - offset) : need);
		// Переносим байты куска сообщения в накопитель блока
		::memcpy(this->_block + this->_size, data.data + offset, count);
		// Увеличиваем число байтов, накопленных в блоке
		this->_size += count;
		// Сдвигаем место разбора куска сообщения
		offset += count;
		// Если блок сообщения ещё не заполнен
		if(this->_size < sizeof(this->_block))
			// Прекращаем разбор куска сообщения
			break;
		// Выполняем разбор заполненного блока сообщения на слова
		load(this->_block, message);
		// Выполняем сжатие блока сообщения
		compress(this->_hash, this->_count, message);
		// Увеличиваем число разобранных разрядов сообщения
		increase(this->_count, width);
		// Дополняем контрольную сумму разобранных блоков сообщения
		increase(this->_sum, message);
		// Обнуляем число байтов, накопленных в блоке
		this->_size = 0;
	}
}
/**
 * @brief Метод снятия выработанного хеша
 *
 * @param result место, в которое помещается выработанный хеш
 * @param size   размер места, в которое помещается хеш
 *
 * @return признак успешности снятия хеша
 *
 */
bool nts::digest::Streebog::finish(uint8_t * result, const size_t size, const order_t order) noexcept {
	// Определяем длину вырабатываемого хеша в байтах
	const size_t length = static_cast <size_t> (this->_type);
	// Если хеш уже снят, длина его не установлена либо место под него мало
	if(this->_finished || (length == 0) || (result == nullptr) || (size < length))
		// Выводим отказ снятия хеша
		return false;
	// Нулевой вектор, служащий числом разрядов у завершающих сжатий
	uint64_t zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	// Разобранный блок сообщения
	uint64_t message[8];
	// Число разрядов незавершённого блока сообщения
	uint64_t width[8] = {static_cast <uint64_t> (this->_size) * 8, 0, 0, 0, 0, 0, 0, 0};
	/**
	 * Незавершённый блок дополняется единичным разрядом сразу за сообщением, а
	 * остаток блока обнуляется. Дополнение это применяется всегда, в том числе к
	 * пустому блоку: без него сообщения разной длины давали бы один и тот же блок
	 */
	::memset(this->_block + this->_size, 0, sizeof(this->_block) - this->_size);
	// Устанавливаем единичный разряд дополнения
	this->_block[this->_size] = 0x01;
	// Выполняем разбор дополненного блока сообщения на слова
	load(this->_block, message);
	// Выполняем сжатие дополненного блока сообщения
	compress(this->_hash, this->_count, message);
	// Увеличиваем число разобранных разрядов сообщения
	increase(this->_count, width);
	// Дополняем контрольную сумму разобранных блоков сообщения
	increase(this->_sum, message);
	// Выполняем сжатие числа разобранных разрядов сообщения
	compress(this->_hash, zero, this->_count);
	// Выполняем сжатие контрольной суммы разобранных блоков сообщения
	compress(this->_hash, zero, this->_sum);
	/**
	 * Вектор записывается от старшего байта к младшему, а хеш длиной 256 разрядов
	 * берётся старшей половиной вектора - оттого обоим длинам отвечает один обход.
	 * Строка же байтов, какой хеш передают протоколы, есть тот же вектор наоборот
	 */
	for(size_t i = 0; i < length; i++){
		// Определяем номер байта вектора, отвечающего очередному байту хеша
		const size_t offset = (63 - i);
		// Определяем место очередного байта внутри выработанного хеша
		const size_t index = (order == order_t::VECTOR ? i : (length - i - 1));
		// Записываем очередной байт выработанного хеша
		result[index] = static_cast <uint8_t> ((this->_hash[offset / 8] >> ((offset % 8) * 8)) & 0xFF);
	}
	// Устанавливаем признак того, что хеш снят
	this->_finished = true;
	// Выводим успешность снятия хеша
	return true;
}
/**
 * @brief Конструктор
 *
 * @param type длина вырабатываемого хеша
 *
 */
nts::digest::Streebog::Streebog(const type_t type) noexcept {
	// Выполняем приведение объекта к началу хеширования
	this->reset(type);
}
/**
 * @brief Метод выработки хеша сообщения, поданного целиком
 *
 * @param type   длина вырабатываемого хеша
 * @param data   хешируемое сообщение
 * @param result место, в которое помещается выработанный хеш
 * @param size   размер места, в которое помещается хеш
 * @param order  порядок записи выработанного хеша
 *
 * @return признак успешности выработки хеша
 *
 */
bool nts::digest::streebog(const type_t type, const view_t & data, uint8_t * result, const size_t size, const order_t order) noexcept {
	// Создаём объект хеширования
	streebog_t hash(type);
	// Выполняем подачу хешируемого сообщения
	hash.update(data);
	// Выводим итог выработки хеша
	return hash.finish(result, size, order);
}
