/**
 * @file base64avx.cpp
 * @date 2026-11-07
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
 * @brief Модуль векторного ядра кодирования основания 64 командами AVX2
 *
 * @details Двадцать четыре байта уходят тридцатью двумя знаками одним вектором
 *          приёмом сборки слов переплетением умножений Войцеха Мулы. Файл
 *          собирается с ключом -mavx2 одним и живёт отдельно от кодека: эпилоги
 *          его функций несут команды vzeroupper, безвредные лишь машинам с AVX,
 *          потому ядро и вызывается лишь после признака AVX2 у машины
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <internal/codec/base64.hpp>

/**
 * Ядро собирается лишь там, где собиратель принял ключ -mavx2 и стены кодека
 * допускают x86-64: прочие машины ядра не зовут вовсе
 */
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || defined(__GNUC__)) && !defined(ANTS_NO_MACHINE)
#include <immintrin.h>
/**
 * Разрешаем векторные команды одной функции: чек ключа -mavx2 утилитой сторонней
 * сборки может не пройти, и атрибут держит команды при функции сам
 */
#define __ANTS_BASE64_TARGET__ __attribute__((target("avx2")))

/**
 * @brief Функция кодирования двадцати четырёх байтов тридцатью двумя знаками командами AVX2
 *
 * @details Приём сборки слов переплетением умножений Войцеха Мулы: байты блока
 *          переносятся в вектор со сдвигом на четыре, поканальная перестановка
 *          читает лишь младшие три четверти обеих полос, произведения без
 *          переносов и с ними переплетают шестёрки разрядов, а перевод повторяет
 *          диапазонный ход двенадцатибайтового ядра пословечными командами
 *          в 256 разрядов
 *
 * @param data     кодируемые двадцать четыре байта
 * @param result   место, в которое помещаются тридцать два знака
 * @param alphabet алфавит записи
 *
 */
__ANTS_BASE64_TARGET__ void nts::codec::encode24(const uint8_t * data, uint8_t * result, const alphabet_t alphabet) noexcept {
	// Блок с запасом: байты кодируемого блока идут со сдвигом на четыре байта
	uint8_t bulk[36] = {};
	// Переносим кодируемые байты в блок со сдвигом
	::memcpy(bulk + 4, data, 24);
	// Загруженный блок вектором в двести пятьдесят шесть разрядов
	const __m256i loaded = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (bulk));
	// Слова из старших трёх байтов каждой тройки поканальной перестановкой
	const __m256i shuffled = _mm256_shuffle_epi8(loaded, _mm256_set_epi8(
		10, 11,  9, 10,  7,  8,  6,  7,  4,  5,  3,  4,  1,  2,  0,  1,
		14, 15, 13, 14, 11, 12, 10, 11,  8,  9,  7,  8,  5,  6,  4,  5
	));
	// Старшие шестёрки каждой пары слов: старшие произведения без переносов
	const __m256i upper = _mm256_mulhi_epu16(_mm256_and_si256(shuffled, _mm256_set1_epi32(0x0fc0fc00)), _mm256_set1_epi32(0x04000040));
	// Младшие шестёрки каждой пары слов: младшие произведения
	const __m256i lower = _mm256_mullo_epi16(_mm256_and_si256(shuffled, _mm256_set1_epi32(0x003f03f0)), _mm256_set1_epi32(0x01000010));
	// Шестёрки разрядов переплетением старших и младших произведений
	const __m256i groups = _mm256_or_si256(upper, lower);
	// Порог строчных букв насыщающим минимумом
	const __m256i edge26 = _mm256_cmpeq_epi8(_mm256_min_epu8(groups, _mm256_set1_epi8(26)), _mm256_set1_epi8(26));
	// Порог цифр насыщающим минимумом
	const __m256i edge52 = _mm256_cmpeq_epi8(_mm256_min_epu8(groups, _mm256_set1_epi8(52)), _mm256_set1_epi8(52));
	// Порог хвостовых значений насыщающим минимумом
	const __m256i edge62 = _mm256_cmpeq_epi8(_mm256_min_epu8(groups, _mm256_set1_epi8(62)), _mm256_set1_epi8(62));
	// Перевод диапазонами: база «A», добавка диапазона строчных, вычет диапазона цифр
	const __m256i letters = _mm256_add_epi8(_mm256_add_epi8(groups, _mm256_set1_epi8(65)), _mm256_and_si256(_mm256_set1_epi8(6), edge26));
	// Вычет диапазона цифр
	const __m256i digits = _mm256_sub_epi8(letters, _mm256_and_si256(_mm256_set1_epi8(75), edge52));
	// Хвост из двух значений: знак «+» с разрядом чётности значения
	const __m256i tail = _mm256_or_si256(_mm256_set1_epi8(0x2B), _mm256_and_si256(_mm256_set1_epi8(4), _mm256_cmpeq_epi8(_mm256_and_si256(groups, _mm256_set1_epi8(1)), _mm256_set1_epi8(1))));
	// Хвост подменяет переведённые знаки на пороге шестидесяти двух
	const __m256i fixed = _mm256_or_si256(_mm256_andnot_si256(edge62, digits), _mm256_and_si256(edge62, tail));
	// Основание URL заменяет два хвостовых знака: «+» на «-», «/» на «_»
	const __m256i outcome = ((alphabet == alphabet_t::URL)
		? _mm256_add_epi8(_mm256_add_epi8(fixed, _mm256_and_si256(_mm256_cmpeq_epi8(fixed, _mm256_set1_epi8(0x2B)), _mm256_set1_epi8(2))), _mm256_and_si256(_mm256_cmpeq_epi8(fixed, _mm256_set1_epi8(0x2F)), _mm256_set1_epi8(0x30)))
		: fixed);
	// Записываем тридцать два знака
	_mm256_storeu_si256(reinterpret_cast <__m256i *> (result), outcome);
}
#endif
