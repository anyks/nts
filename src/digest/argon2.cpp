/**
 * @file argon2.cpp
 * @date 2026-09-07
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
 * @brief Модуль вывода ключа из пароля Argon2 по RFC 9106
 *
 * @details Матрица блоков по 1024 байта: p дорожек на q столбцов, четыре среза на проход.
 *          Первые два блока дорожки выводятся из H0 хешем переменной длины H', остальные -
 *          сжатием G предыдущего блока с опорным, выбранным по J1/J2: у Argon2d из самого
 *          предыдущего блока, у Argon2i из счётчика через G(0, G(0, Z)), у Argon2id первые
 *          два среза первого прохода как 2i, далее как 2d. Издание 0x13: со второго прохода
 *          новый блок складывается со старым
 *
 * @section Намеренные решения
 *
 * 1. Дорожки считаются последовательно одним потоком: итог Argon2 от числа потоков не
 *    зависит по устройству, а библиотека потоков не заводит; параллелизм - дело потребителя.
 *
 * 2. Память под матрицу занимается на время вызова обычным new с перехватом bad_alloc и при
 *    нехватке метод отвечает false: перебор m до гибибайтов есть законная настройка, и падение
 *    на ней недопустимо. Обычный new, а не nothrow: он идёт через заменяемый оператор, и паёк
 *    выделений проверок ловит тот же путь, что настоящая нехватка.
 *
 * 3. Блок хеша переменной длины H' строится над BLAKE2b библиотеки, без отдельного кода.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>
#include <cstdlib>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/argon2.hpp>
#include <digest/blake2.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на пространство имён библиотеки
	 */
	using namespace nts;
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;
	/**
	 * Число слов в блоке
	 */
	static constexpr size_t WORDS = 128;
	/**
	 * Длина блока в байтах
	 */
	static constexpr size_t BLOCK = 1024;
	/**
	 * Число срезов прохода
	 */
	static constexpr size_t SLICES = 4;
	/**
	 * @brief Блок матрицы
	 *
	 */
	typedef struct Block {
		// Слова блока
		uint64_t words[WORDS];
	} block_t;
	/**
	 * @brief Метод записи 32-разрядного числа от младшего байта
	 *
	 * @param value число
	 * @param out   место записи
	 *
	 */
	static inline void quartet(const uint32_t value, uint8_t * out) noexcept {
		// Записываем байты от младшего
		out[0] = static_cast <uint8_t> (value);
		out[1] = static_cast <uint8_t> (value >> 8);
		out[2] = static_cast <uint8_t> (value >> 16);
		out[3] = static_cast <uint8_t> (value >> 24);
	}
	/**
	 * @brief Метод подачи числа и байтов в хеш: LE32(длина) || байты
	 *
	 * @param hasher хеш
	 * @param data   байты
	 *
	 * @return       признак успешности подачи
	 *
	 */
	static bool feed(digest::blake2_t & hasher, const view_t & data) noexcept {
		// Длина от младшего байта
		uint8_t length[4];
		// Записываем длину
		quartet(static_cast <uint32_t> (data.size), length);
		// Подаём длину и байты
		return (hasher.update(view_t(length, sizeof(length))) && hasher.update(data));
	}
	/**
	 * @brief Хеш переменной длины H' по разделу 3.3 RFC 9106
	 *
	 * @param data   вход
	 * @param result место итога
	 * @param size   длина итога
	 *
	 * @return       признак успешности
	 *
	 */
	static bool stretch(const view_t & data, uint8_t * result, const size_t size) noexcept {
		// Длина итога от младшего байта
		uint8_t length[4];
		// Записываем длину
		quartet(static_cast <uint32_t> (size), length);
		// Если итог помещается в один хеш
		if(size <= digest::BLAKE2B_LENGTH){
			// Хеш
			digest::blake2_t hasher;
			// Заводим, подаём длину и вход, снимаем
			return (hasher.start(digest::blake_t::BLAKE2B, size, view_t()) && hasher.update(view_t(length, sizeof(length))) && hasher.update(data) && hasher.finish(result, size));
		}
		// Число полных шагов по 32 байта
		const size_t steps = (((size + 31) / 32) - 2);
		// Текущее значение V
		uint8_t current[digest::BLAKE2B_LENGTH];
		// Первый хеш
		digest::blake2_t hasher;
		// Если первый хеш не снят
		if(!hasher.start(digest::blake_t::BLAKE2B, digest::BLAKE2B_LENGTH, view_t()) || !hasher.update(view_t(length, sizeof(length))) || !hasher.update(data) || !hasher.finish(current, sizeof(current)))
			// Выводим отказ
			return false;
		// Место записи
		size_t offset = 0;
		/**
		 * Выполняем шаги по 32 байта
		 */
		for(size_t i = 0; i < steps; i++){
			// Переносим первые 32 байта
			::memcpy(result + offset, current, 32);
			// Продвигаем место
			offset += 32;
			// Если шаг не последний: следующее значение V_{i+1} = H(V_i); последний хеш берётся над V_r
			if((i + 1) < steps){
				// Следующее значение
				digest::blake2_t next;
				// Если следующий хеш не снят
				if(!next.start(digest::blake_t::BLAKE2B, digest::BLAKE2B_LENGTH, view_t()) || !next.update(view_t(current, sizeof(current))) || !next.finish(current, sizeof(current)))
					// Выводим отказ
					return false;
			}
		}
		// Длина хвоста
		const size_t tail = (size - offset);
		// Последний хеш нужной длины
		digest::blake2_t last;
		// Если последний хеш не снят
		if(!last.start(digest::blake_t::BLAKE2B, tail, view_t()) || !last.update(view_t(current, sizeof(current))) || !last.finish(result + offset, tail))
			// Выводим отказ
			return false;
		// Выполняем затирание
		wipe(current, sizeof(current));
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод кругового сдвига вправо
	 *
	 * @param word  слово
	 * @param count число разрядов
	 *
	 * @return      сдвинутое слово
	 *
	 */
	static inline uint64_t spin(const uint64_t word, const size_t count) noexcept {
		// Выводим сдвиг
		return ((word >> count) | (word << (64 - count)));
	}
	/**
	 * @brief Смешивание четырёх слов GB по разделу 3.6
	 *
	 * @param a первое слово
	 * @param b второе слово
	 * @param c третье слово
	 * @param d четвёртое слово
	 *
	 */
	static inline void blend(uint64_t & a, uint64_t & b, uint64_t & c, uint64_t & d) noexcept {
		// Маска младших 32 разрядов
		static constexpr uint64_t LOW = 0xFFFFFFFFULL;
		a = (a + b + (2 * (a & LOW) * (b & LOW)));
		d = spin(d ^ a, 32);
		c = (c + d + (2 * (c & LOW) * (d & LOW)));
		b = spin(b ^ c, 24);
		a = (a + b + (2 * (a & LOW) * (b & LOW)));
		d = spin(d ^ a, 16);
		c = (c + d + (2 * (c & LOW) * (d & LOW)));
		b = spin(b ^ c, 63);
	}
	/**
	 * @brief Перестановка P над шестнадцатью словами по указателям
	 *
	 * @param v указатели на шестнадцать слов
	 *
	 */
	static inline void permute(uint64_t ** v) noexcept {
		blend(*v[0], *v[4], *v[8], *v[12]);
		blend(*v[1], *v[5], *v[9], *v[13]);
		blend(*v[2], *v[6], *v[10], *v[14]);
		blend(*v[3], *v[7], *v[11], *v[15]);
		blend(*v[0], *v[5], *v[10], *v[15]);
		blend(*v[1], *v[6], *v[11], *v[12]);
		blend(*v[2], *v[7], *v[8], *v[13]);
		blend(*v[3], *v[4], *v[9], *v[14]);
	}
	/**
	 * @brief Функция сжатия G по разделу 3.5
	 *
	 * @param x       первый вход
	 * @param y       второй вход
	 * @param result  итог
	 * @param overlay признак сложения итога с прежним содержимым (издание 0x13, проходы после первого)
	 *
	 */
	static void compress(const block_t & x, const block_t & y, block_t & result, const bool overlay) noexcept {
		// R = X xor Y
		block_t r;
		/**
		 * Выполняем сложение входов
		 */
		for(size_t i = 0; i < WORDS; i++)
			// Складываем слова
			r.words[i] = (x.words[i] ^ y.words[i]);
		// Q: перестановка над строками
		block_t q = r;
		/**
		 * Выполняем перебор строк по 16 слов
		 */
		for(size_t row = 0; row < 8; row++){
			// Указатели на слова строки
			uint64_t * v[16];
			for(size_t i = 0; i < 16; i++)
				// Слово строки
				v[i] = &q.words[(row * 16) + i];
			// Переставляем
			permute(v);
		}
		/**
		 * Выполняем перебор столбцов по 16 слов: пары слов из каждой строки
		 */
		for(size_t column = 0; column < 8; column++){
			// Указатели на слова столбца
			uint64_t * v[16];
			for(size_t row = 0; row < 8; row++){
				// Первое слово пары
				v[2 * row] = &q.words[(row * 16) + (2 * column)];
				// Второе слово пары
				v[(2 * row) + 1] = &q.words[(row * 16) + (2 * column) + 1];
			}
			// Переставляем
			permute(v);
		}
		/**
		 * Выполняем сложение Z с R и, при наложении, с прежним итогом
		 */
		for(size_t i = 0; i < WORDS; i++)
			// Складываем
			result.words[i] = ((overlay ? result.words[i] : 0) ^ q.words[i] ^ r.words[i]);
		// Выполняем затирание
		wipe(r.words, sizeof(r.words));
		wipe(q.words, sizeof(q.words));
	}
	/**
	 * @brief Метод чтения 64-разрядного слова из байтов от младшего
	 *
	 * @param data байты
	 *
	 * @return     слово
	 *
	 */
	static inline uint64_t octet(const uint8_t * data) noexcept {
		uint64_t result = 0;
		for(size_t i = 0; i < 8; i++)
			result |= (static_cast <uint64_t> (data[i]) << (8 * i));
		return result;
	}
	/**
	 * @brief Метод перевода блока в байты от младшего
	 *
	 * @param block блок
	 * @param out   1024 байта
	 *
	 */
	static void store(const block_t & block, uint8_t * out) noexcept {
		for(size_t i = 0; i < WORDS; i++)
			for(size_t j = 0; j < 8; j++)
				out[(i * 8) + j] = static_cast <uint8_t> (block.words[i] >> (8 * j));
	}
	/**
	 * @brief Метод перевода байтов в блок
	 *
	 * @param data  1024 байта
	 * @param block блок
	 *
	 */
	static void load(const uint8_t * data, block_t & block) noexcept {
		for(size_t i = 0; i < WORDS; i++)
			block.words[i] = octet(data + (i * 8));
	}
	/**
	 * Алфавит base64
	 */
	static const char * ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	/**
	 * @brief Метод записи байтов в base64 без дополнения
	 *
	 * @param data   байты
	 * @param result строка
	 *
	 */
	static void enbase(const vector <uint8_t> & data, string & result) {
		/**
		 * Выполняем перебор троек байтов
		 */
		for(size_t i = 0; i < data.size(); i += 3){
			// Число байтов в тройке
			const size_t count = (((data.size() - i) < 3) ? (data.size() - i) : 3);
			// Двадцать четыре разряда тройки
			uint32_t triple = (static_cast <uint32_t> (data[i]) << 16);
			if(count > 1) triple |= (static_cast <uint32_t> (data[i + 1]) << 8);
			if(count > 2) triple |= static_cast <uint32_t> (data[i + 2]);
			// Знаки: по шесть разрядов, без дополнения
			result.push_back(ALPHABET[(triple >> 18) & 0x3F]);
			result.push_back(ALPHABET[(triple >> 12) & 0x3F]);
			if(count > 1) result.push_back(ALPHABET[(triple >> 6) & 0x3F]);
			if(count > 2) result.push_back(ALPHABET[triple & 0x3F]);
		}
	}
	/**
	 * @brief Метод разбора base64 без дополнения
	 *
	 * @param text   строка
	 * @param result байты
	 *
	 * @return       признак успешности разбора
	 *
	 */
	static bool debase(const string & text, vector <uint8_t> & result) {
		// Накопитель разрядов
		uint32_t buffer = 0;
		// Число разрядов в накопителе
		size_t bits = 0;
		// Сбрасываем байты
		result.clear();
		// Остаток знаков по модулю четыре не может быть единицей
		if((text.size() % 4) == 1)
			return false;
		/**
		 * Выполняем перебор знаков
		 */
		for(size_t i = 0; i < text.size(); i++){
			// Знак
			const char c = text[i];
			// Значение знака
			int value = -1;
			if((c >= 'A') && (c <= 'Z')) value = (c - 'A');
			else if((c >= 'a') && (c <= 'z')) value = (c - 'a' + 26);
			else if((c >= '0') && (c <= '9')) value = (c - '0' + 52);
			else if(c == '+') value = 62;
			else if(c == '/') value = 63;
			// Если знак чужой (в том числе дополнение «=»)
			if(value < 0)
				return false;
			// Складываем шесть разрядов
			buffer = ((buffer << 6) | static_cast <uint32_t> (value));
			bits += 6;
			// Если набрался байт
			if(bits >= 8){
				bits -= 8;
				result.push_back(static_cast <uint8_t> ((buffer >> bits) & 0xFF));
			}
		}
		// Оставшиеся разряды обязаны быть нулевыми
		return ((buffer & ((1u << bits) - 1)) == 0);
	}
	/**
	 * @brief Метод разбора десятичного числа без знака
	 *
	 * @param text   строка
	 * @param result число
	 *
	 * @return       признак успешности
	 *
	 */
	static bool decimal(const string & text, uint32_t & result) noexcept {
		// Если строка пуста, длиннее десяти знаков либо ведущий нуль у ненулевого
		if(text.empty() || (text.size() > 10) || ((text.size() > 1) && (text[0] == '0')))
			return false;
		// Накопитель
		uint64_t value = 0;
		for(size_t i = 0; i < text.size(); i++){
			if((text[i] < '0') || (text[i] > '9'))
				return false;
			value = ((value * 10) + static_cast <uint64_t> (text[i] - '0'));
		}
		if(value > 0xFFFFFFFFULL)
			return false;
		result = static_cast <uint32_t> (value);
		return true;
	}
};

/**
 * \~russian
 * @brief Метод вывода ключа из пароля Argon2
 *
 * @param params     параметры
 * @param password   пароль
 * @param salt       соль
 * @param secret     тайное значение либо пустой вид
 * @param associated связанные данные либо пустой вид
 * @param result     место метки
 * @param size       длина метки
 *
 * @return           признак того, что метка выведена
 *
 * \~english
 * @brief Method of the derivation of a key from a password by Argon2
 *
 * @param params     parameters
 * @param password   password
 * @param salt       salt
 * @param secret     secret value or an empty view
 * @param associated associated data or an empty view
 * @param result     place of the tag
 * @param size       length of the tag
 *
 * @return           sign that the tag is derived
 *
 * \~
 */
bool nts::digest::argon2(const argon_params_t & params, const view_t & password, const view_t & salt, const view_t & secret, const view_t & associated, uint8_t * result, const size_t size) noexcept {
	// Раздел 3.1: пределы параметров
	if((result == nullptr) || (size < 4) || (params.lanes == 0) || (params.lanes > 0xFFFFFF) || (params.passes == 0) || (params.memory < (8 * params.lanes)) || (salt.size < 8) || ((salt.size > 0) && (salt.data == nullptr)) || ((password.size > 0) && (password.data == nullptr)))
		// Выводим отказ параметров
		return false;
	// Разновидность как параметр y
	const uint32_t kind = static_cast <uint32_t> (params.type);
	// Если разновидность неведома
	if(kind > 2)
		// Выводим отказ
		return false;
	// Число блоков: округление вниз до кратного 4·p
	const size_t blocks = (static_cast <size_t> (params.memory) / (4 * params.lanes)) * (4 * params.lanes);
	// Длина дорожки
	const size_t lane = (blocks / params.lanes);
	// Длина среза
	const size_t segment = (lane / SLICES);
	// H0 по разделу 3.2
	uint8_t h0[digest::BLAKE2B_LENGTH];
	{
		// Хеш H0
		digest::blake2_t hasher;
		// Числа от младшего байта
		uint8_t numbers[24];
		quartet(params.lanes, numbers);
		quartet(static_cast <uint32_t> (size), numbers + 4);
		quartet(params.memory, numbers + 8);
		quartet(params.passes, numbers + 12);
		quartet(ARGON2_VERSION, numbers + 16);
		quartet(kind, numbers + 20);
		// Если H0 не снят
		if(!hasher.start(digest::blake_t::BLAKE2B, digest::BLAKE2B_LENGTH, view_t()) || !hasher.update(view_t(numbers, sizeof(numbers))) || !feed(hasher, password) || !feed(hasher, salt) || !feed(hasher, secret) || !feed(hasher, associated) || !hasher.finish(h0, sizeof(h0)))
			// Выводим отказ
			return false;
	}
	// Матрица блоков: память занимается на время вызова
	block_t * matrix = nullptr;
	/**
	 * Выполняем перехват нехватки памяти: обычный new идёт через заменяемый оператор, оттого
	 * и настоящая нехватка, и паёк выделений проверок отвечают одинаково - отказом
	 */
	try {
		// Занимаем матрицу
		matrix = new block_t[blocks];
	} catch(const std::bad_alloc &) {
		// Выполняем затирание H0
		wipe(h0, sizeof(h0));
		// Выводим отказ памяти
		return false;
	}
	// Признак успешности
	bool ok = true;
	// Байты блока
	uint8_t bytes[BLOCK];
	/**
	 * Выполняем заполнение первых двух столбцов: B[i][j] = H'(H0 || LE32(j) || LE32(i))
	 */
	for(uint32_t i = 0; (i < params.lanes) && ok; i++){
		for(uint32_t j = 0; (j < 2) && ok; j++){
			// Вход: H0 и два числа
			uint8_t input[digest::BLAKE2B_LENGTH + 8];
			::memcpy(input, h0, sizeof(h0));
			quartet(j, input + sizeof(h0));
			quartet(i, input + sizeof(h0) + 4);
			// Считаем блок
			ok = stretch(view_t(input, sizeof(input)), bytes, BLOCK);
			// Переносим в матрицу
			if(ok)
				load(bytes, matrix[(static_cast <size_t> (i) * lane) + j]);
		}
	}
	/**
	 * Выполняем проходы, срезы и дорожки
	 */
	for(uint32_t pass = 0; (pass < params.passes) && ok; pass++){
		for(size_t slice = 0; slice < SLICES; slice++){
			for(uint32_t l = 0; l < params.lanes; l++){
				// Признак независимой от данных адресации на этом срезе
				const bool independent = ((kind == 1) || ((kind == 2) && (pass == 0) && (slice < 2)));
				// Блок адресов и его счётчик
				block_t addresses, input, zero;
				// Если адресация независима: заводим Z
				if(independent){
					::memset(input.words, 0, sizeof(input.words));
					::memset(zero.words, 0, sizeof(zero.words));
					input.words[0] = pass;
					input.words[1] = l;
					input.words[2] = slice;
					input.words[3] = blocks;
					input.words[4] = params.passes;
					input.words[5] = kind;
				}
				// Первый столбец среза: в первом срезе первого прохода два блока уже есть
				const size_t first = (((pass == 0) && (slice == 0)) ? 2 : 0);
				for(size_t index = first; index < segment; index++){
					// Столбец в дорожке
					const size_t column = ((slice * segment) + index);
					// Предыдущий столбец по кольцу
					const size_t previous = ((column == 0) ? (lane - 1) : (column - 1));
					// J1 и J2
					uint64_t j1 = 0, j2 = 0;
					// Если адресация независима
					if(independent){
						// Новый блок адресов в начале среза и каждые 128 блоков
						if((index == first) || ((index % WORDS) == 0)){
							// Счётчик
							input.words[6]++;
							// G(0, G(0, Z))
							block_t middle;
							compress(zero, input, middle, false);
							compress(zero, middle, addresses, false);
						}
						// Пара из блока адресов
						j1 = (addresses.words[index % WORDS] & 0xFFFFFFFFULL);
						j2 = (addresses.words[index % WORDS] >> 32);
					// Иначе из предыдущего блока
					} else {
						// Слово предыдущего блока
						const uint64_t word = matrix[(static_cast <size_t> (l) * lane) + previous].words[0];
						j1 = (word & 0xFFFFFFFFULL);
						j2 = (word >> 32);
					}
					// Опорная дорожка
					size_t reference = static_cast <size_t> (j2 % params.lanes);
					// В первом срезе первого прохода - своя дорожка
					if((pass == 0) && (slice == 0))
						reference = l;
					// Признак своей дорожки
					const bool same = (reference == l);
					// Размер опорной области по разделу 3.4.1.2
					size_t area = 0;
					if(pass == 0){
						if(slice == 0)
							area = (index - 1);
						else if(same)
							area = ((slice * segment) + index - 1);
						else
							area = ((slice * segment) + ((index == 0) ? static_cast <size_t> (-1) : 0));
					} else {
						if(same)
							area = (lane - segment + index - 1);
						else
							area = (lane - segment + ((index == 0) ? static_cast <size_t> (-1) : 0));
					}
					// x = J1^2 / 2^32, y = area·x / 2^32, z = area − 1 − y
					const uint64_t x = ((j1 * j1) >> 32);
					const uint64_t y = ((static_cast <uint64_t> (area) * x) >> 32);
					const size_t z = (area - 1 - static_cast <size_t> (y));
					// Начало отсчёта
					size_t start = 0;
					if((pass != 0) && (slice != (SLICES - 1)))
						start = ((slice + 1) * segment);
					// Опорный столбец
					const size_t position = ((start + z) % lane);
					// Опорный блок
					const block_t & ref = matrix[(reference * lane) + position];
					// Предыдущий блок
					const block_t & prev = matrix[(static_cast <size_t> (l) * lane) + previous];
					// Новый блок: с наложением после первого прохода
					compress(prev, ref, matrix[(static_cast <size_t> (l) * lane) + column], (pass > 0));
				}
				// Выполняем затирание блока адресов
				wipe(addresses.words, sizeof(addresses.words));
				wipe(input.words, sizeof(input.words));
			}
		}
	}
	// Если всё прошло
	if(ok){
		// C: сложение последних столбцов дорожек
		block_t final_;
		::memset(final_.words, 0, sizeof(final_.words));
		for(uint32_t l = 0; l < params.lanes; l++)
			for(size_t i = 0; i < WORDS; i++)
				final_.words[i] ^= matrix[(static_cast <size_t> (l) * lane) + (lane - 1)].words[i];
		// Байты C
		store(final_, bytes);
		// Метка: H'(C)
		ok = stretch(view_t(bytes, BLOCK), result, size);
		// Выполняем затирание
		wipe(final_.words, sizeof(final_.words));
	}
	// Выполняем затирание матрицы
	wipe(matrix, blocks * sizeof(block_t));
	// Освобождаем матрицу
	delete [] matrix;
	// Выполняем затирание байтов и H0
	wipe(bytes, sizeof(bytes));
	wipe(h0, sizeof(h0));
	// Выводим итог
	return ok;
}

/**
 * \~russian
 * @brief Метод разбора строки PHC
 *
 * @param text   строка PHC
 * @param result запись
 *
 * @return       признак того, что строка разобрана
 *
 * \~english
 * @brief Method of the parsing of a PHC string
 *
 * @param text   PHC string
 * @param result record
 *
 * @return       sign that the string is parsed
 *
 * \~
 */
bool nts::digest::phc(const string & text, argon_record_t & result) noexcept {
	try {
		// Поля строки, разделённые знаком «$»; первое пусто
		vector <string> fields;
		// Место начала поля
		size_t start = 0;
		/**
		 * Выполняем разрезание строки
		 */
		for(size_t i = 0; i <= text.size(); i++){
			if((i == text.size()) || (text[i] == '$')){
				fields.push_back(text.substr(start, i - start));
				start = (i + 1);
			}
		}
		// Строка: «», вариант, издание, параметры, соль[, выход]
		if((fields.size() < 5) || (fields.size() > 6) || !fields[0].empty())
			return false;
		// Вариант
		if(fields[1] == "argon2d") result.params.type = argon_t::ARGON2D;
		else if(fields[1] == "argon2i") result.params.type = argon_t::ARGON2I;
		else if(fields[1] == "argon2id") result.params.type = argon_t::ARGON2ID;
		else return false;
		// Издание: лишь v=19
		if(fields[2] != "v=19")
			return false;
		// Параметры строго m,t,p
		const string & parameters = fields[3];
		const size_t first = parameters.find(",t="), second = parameters.find(",p=");
		if((parameters.compare(0, 2, "m=") != 0) || (first == string::npos) || (second == string::npos) || (second < first) || (parameters.find(',', second + 1) != string::npos))
			return false;
		if(!decimal(parameters.substr(2, first - 2), result.params.memory) || !decimal(parameters.substr(first + 3, second - first - 3), result.params.passes) || !decimal(parameters.substr(second + 3), result.params.lanes))
			return false;
		// Соль
		if(fields[4].empty() || !debase(fields[4], result.salt) || (result.salt.size() < 8))
			return false;
		// Тайное значение и связанные данные строка не несёт
		result.secret.clear();
		result.associated.clear();
		// Выход при наличии
		result.tag.clear();
		if(fields.size() == 6){
			if(fields[5].empty() || !debase(fields[5], result.tag) || (result.tag.size() < 4))
				return false;
		}
		// Пределы параметров
		return ((result.params.lanes > 0) && (result.params.passes > 0) && (result.params.memory >= (8 * result.params.lanes)));
	} catch(const bad_alloc &) {
		return false;
	}
}
/**
 * \~russian
 * @brief Метод записи строки PHC
 *
 * @param record запись
 * @param result строка PHC
 *
 * @return       признак того, что строка записана
 *
 * \~english
 * @brief Method of the writing of a PHC string
 *
 * @param record record
 * @param result PHC string
 *
 * @return       sign that the string is written
 *
 * \~
 */
bool nts::digest::phc(const argon_record_t & record, string & result) noexcept {
	try {
		// Пределы; тайное значение и связанные данные строка не несёт - запись с ними отвергается, а не теряет их молча
		if((record.salt.size() < 8) || (!record.tag.empty() && (record.tag.size() < 4)) || (record.params.lanes == 0) || (record.params.passes == 0) || (record.params.memory < (8 * record.params.lanes)) || !record.secret.empty() || !record.associated.empty())
			return false;
		// Вариант
		const char * name = nullptr;
		switch(static_cast <uint8_t> (record.params.type)){
			case static_cast <uint8_t> (argon_t::ARGON2D): name = "argon2d"; break;
			case static_cast <uint8_t> (argon_t::ARGON2I): name = "argon2i"; break;
			case static_cast <uint8_t> (argon_t::ARGON2ID): name = "argon2id"; break;
			default: return false;
		}
		result.clear();
		result.append("$").append(name).append("$v=19$m=").append(to_string(record.params.memory)).append(",t=").append(to_string(record.params.passes)).append(",p=").append(to_string(record.params.lanes)).append("$");
		enbase(record.salt, result);
		if(!record.tag.empty()){
			result.push_back('$');
			enbase(record.tag, result);
		}
		return true;
	} catch(const bad_alloc &) {
		result.clear();
		return false;
	}
}
