/**
 * @file base64.hpp
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
 * @brief Заголовочный файл внутреннего модуля ядер кодирования основания 64
 *
 * @note Модуль внутренний: он лежит в src и наружному договору библиотеки не
 *       принадлежит. Ядра зовёт открытый модуль codec::base64. Схема выверена
 *       моделью на двухстах тысячах случайных и граничных блоков: всякие
 *       двенадцать байтов собираются перестановкой в четыре слова по старшим
 *       трём байтам, пословечные сдвиги с маской шести разрядов дают четыре
 *       вектора шестёрок, две пары сжатий пакуют их в шестнадцать байтов,
 *       перестановка транспонирует четвёрки, а знак читается как значение с
 *       добавкой своего диапазона: номер диапазона даёт насыщающий вычет
 *       пятидесяти одного и признак значения от двадцати шести, добавка
 *       берётся перестановкой по номеру, основание URL отличается лишь
 *       добавками хвоста
 *
 * @copyright Copyright © 2026
 *
 */

#ifndef __ANTS_INTERNAL_CODEC_BASE64__
/**
 * Экранируем повторную инициализацию модуля
 */
#define __ANTS_INTERNAL_CODEC_BASE64__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <codec/base64.hpp>
#include <sys/machine.hpp>

/**
 * Компиляционные стены машинных ядер: x86-64 требует SSSE3, ARM64 - NEON основания.
 * Заголовки команд машины подключаются на файловом уровне: внутри пространства
 * имён их типы и функции осели бы в нём и не были бы видны прочим ядрам файла
 *
 * @note Собиратель Microsoft Visual C++ признаков наборов команд не объявляет, зато
 *       внутренние функции команд доступны ему без ключей сборки, а наличие команд
 *       спрашивает на исполнении опознание машины: стена открывается признаком
 *       собирателя вместо признака набора
 *
 */
#if((defined(__x86_64__) && defined(__SSSE3__)) || (defined(__aarch64__) && defined(__ARM_NEON)) || defined(__ANTS_MSVC_X64__) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
	/**
	 * x86-64 собирается интринсиками SSE
	 */
	#if defined(__x86_64__) || defined(__ANTS_MSVC_X64__)
		#include <immintrin.h>
	/**
	 * ARM64 собирается интринсиками NEON
	 */
	#else
		#include <arm_neon.h>
	#endif
#endif

/**
 * @brief Основное пространство имён
 *
 */
namespace nts {
	/**
	 * @brief Пространство имён кодеков записей
	 *
	 */
	namespace codec {
		/**
		 * @brief Пространство имён встраиваемых ядер основания 64
		 *
		 */
		namespace kernel {
			/**
			 * @brief Маска шести разрядов пословечно
			 *
			 */
			static constexpr uint8_t SIX = 63;
			/**
			 * @brief Сбор двенадцати байтов в четыре слова перестановкой: слово k собирается из байтов 3k, 3k+1, 3k+2
			 *
			 */
			static const uint8_t GATHER[16] = {
				// Младшие разряды записаны первыми: слово k из тройки байтов, старший байт слова - нуль
				2, 1, 0, 0, 5, 4, 3, 0, 8, 7, 6, 0, 11, 10, 9, 0
			};
			/**
			 * @brief Транспонирование четвёрок сжатого набора: байты [v00..v03, v10.., v20.., v30..] идут столбцами
			 *
			 */
			static const uint8_t TRANSPOSE[16] = {
				// Столбцы четвёрок записаны первыми
				0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
			};
			/**
			 * @brief Добавки диапазонов основания: номер нуль - «A», единица - «a», 2..11 - цифры, 12 и 13 - хвост
			 *
			 * @details Знак есть значение с добавкой своего диапазона: «A»…«Z» дают 65,
			 *          «a»…«z» - 71, цифры - вычет четырёх, «+» и «/» - вычеты девятнадцати
			 *          и шестнадцати. Добавки записаны байтами без знака, потому вычеты
			 *          стоят дополнением до двухсот пятидесяти шести
			 *
			 */
			static const uint8_t OFFSETS[16] = {
				// Последние два номера не читаются: номер диапазона не превышает тринадцати
				65, 71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 0, 0
			};
			/**
			 * @brief Добавки диапазонов основания URL: хвост даёт «-» и «_» вместо «+» и «/»
			 *
			 */
			static const uint8_t OFFSETS_URL[16] = {
				// «-» есть 62 с вычетом семнадцати, «_» есть 63 с добавкой тридцати двух
				65, 71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 239, 32, 0, 0
			};
			/**
			 * @brief Функция перевода шестёрки разрядов в знак основания 64 без таблиц
			 *
			 * @details Знаки держатся тремя диапазонами - «A»…«Z», «a»…«z», «0»…«9» - и
			 *          хвостом из двух знаков; диапазоны отличаются сдвигом к значению
			 *
			 * @param value    шестёрка разрядов от нуля до шестидесяти трёх
			 * @param alphabet алфавит записи
			 * @return         знак основания 64
			 *
			 */
			static __ANTS_INLINE__ uint8_t translate(const uint8_t value, const alphabet_t alphabet) noexcept {
				// Знак начинается со сдвига диапазона «A»…«Z»
				uint8_t result = static_cast <uint8_t> (value + 65);
				// Значения от двадцати шести уходят в диапазон «a»…«z» добавкой шести
				result = static_cast <uint8_t> (result + ((26 <= value) ? 6 : 0));
				// Значения от пятидесяти двух уходят в диапазон «0»…«9» вычетом семидесяти пяти
				result = static_cast <uint8_t> (result - ((52 <= value) ? 75 : 0));
				// Хвост из двух значений правится по чётности значения
				if(62 <= value)
					// Основанию URL принадлежат «-» и «_», основанию - «+» и «/»
					result = static_cast <uint8_t> (((alphabet == alphabet_t::URL) ? ((value & 1) ? 0x5F : 0x2D) : ((value & 1) ? 0x2F : 0x2B)));
				// Выводим знак основания
				return result;
			}
			/**
			 * @brief Функция кодирования двенадцати байтов шестнадцатью знаками переносимым ходом
			 *
			 * @param data     кодируемые двенадцать байтов
			 * @param result   место, в которое помещаются шестнадцать знаков
			 * @param alphabet алфавит записи
			 *
			 */
			static __ANTS_INLINE__ void encode(const uint8_t * data, uint8_t * result, const alphabet_t alphabet) noexcept {
				// Слова из старших трёх байтов троек
				uint32_t words[4];
				/**
				 * Выполняем перебор слов
				 */
				for(size_t k = 0; k < 4; k++)
					// Собираем слово k из байтов 3k, 3k+1, 3k+2 старшим вперёд
					words[k] = ((static_cast <uint32_t> (data[3 * k]) << 16) | (static_cast <uint32_t> (data[(3 * k) + 1]) << 8) | data[(3 * k) + 2]);
				/**
				 * Выполняем перебор слов
				 */
				for(size_t k = 0; k < 4; k++){
					// Первая шестёрка слова: старшие шесть разрядов
					result[4 * k] = translate(static_cast <uint8_t> ((words[k] >> 18) & SIX), alphabet);
					// Вторая шестёрка слова
					result[(4 * k) + 1] = translate(static_cast <uint8_t> ((words[k] >> 12) & SIX), alphabet);
					// Третья шестёрка слова
					result[(4 * k) + 2] = translate(static_cast <uint8_t> ((words[k] >> 6) & SIX), alphabet);
					// Четвёртая шестёрка слова: младшие шесть разрядов
					result[(4 * k) + 3] = translate(static_cast <uint8_t> (words[k] & SIX), alphabet);
				}
			}
		};

		/**
		 * @brief Служебная функция кодирования основания 64 с пробросом нехватки памяти
		 *
		 * @param data     кодируемые данные
		 * @param result   строка, в которую помещается запись
		 * @param padding  признак заполнения записи знаками «=» до кратности четырём
		 * @param alphabet алфавит записи
		 * @return         признак успешности кодирования
		 *
		 * @details Тело открытого кодирования без перехвата исключений: нехватка памяти
		 *          уходит вызывающему исключением, чтобы сборщики записей ответили
		 *          отказом памяти, а не молча собрали запись с пустой частью. Открытые
		 *          encode и decode перехватывают это исключение сами
		 *
		 */
		bool rawEncode(const view_t & data, string & result, const bool padding, const alphabet_t alphabet);
		/**
		 * @brief Служебная функция разбора записи основания 64 с пробросом нехватки памяти
		 *
		 * @param text     разбираемая запись
		 * @param result   место, в которое помещаются разобранные байты
		 * @param alphabet алфавит записи
		 * @param spaces   признак пропуска пробельных знаков записи
		 * @param padding  признак допущения знаков «=» в хвосте записи
		 * @return         признак успешности разбора
		 *
		 * @details Тело открытого разбора без перехвата исключений: нехватка памяти
		 *          уходит вызывающему исключением, чтобы разборщики записей ответили
		 *          отказом памяти, а не приняли порчу за отказ записи. Открытые encode
		 *          и decode перехватывают это исключение сами
		 *
		 */
		bool rawDecode(const view_t & text, vector <uint8_t> & result, const alphabet_t alphabet, const bool spaces, const bool padding);
		/**
		 * Файл ядра base64avx.cpp собирается с ключом -mavx2 одним, а собирателю Microsoft Visual C++
		 * ключ не нужен вовсе, потому ядро объявлено здесь внешней связью и зовётся лишь при
		 * признаке AVX2 машины
		 */
		#if ((defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || defined(__GNUC__)) || defined(__ANTS_MSVC_X64__)) && !defined(ANTS_NO_MACHINE)
			/**
			 * @brief Функция кодирования очереди блоков двадцати четырёх байтов командами AVX2
			 *
			 * @param data     кодируемые байты, по двадцать четыре на блок
			 * @param result   место, в которое помещаются знаки, по тридцать два на блок
			 * @param blocks   число полных блоков очереди
			 * @param alphabet алфавит записи
			 *
			 */
			void encodeBlocks(const uint8_t * data, uint8_t * result, const size_t blocks, const alphabet_t alphabet) noexcept;
		#endif


		/**
		 * Компиляционные стены машинных ядер: x86-64 требует SSSE3, ARM64 - NEON основания
		 */
#if((defined(__x86_64__) && defined(__SSSE3__)) || (defined(__aarch64__) && defined(__ARM_NEON)) || defined(__ANTS_MSVC_X64__) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
		/**
		 * @brief Пространство имён машинных ядер основания 64
		 *
		 */
		namespace machine {
			/**
			 * @brief Функция кодирования двенадцати байтов шестнадцатью знаками командами машины
			 *
			 * @details Блок переносится на пятнадцать байтов запаса: загрузка шестнадцати
			 *          байтов читает четыре байта за двенадцатью, и последний полный блок
			 *          входа читать за границей не вправе. Знак читается как значение с
			 *          добавкой своего диапазона: номер диапазона даёт насыщающий вычет
			 *          пятидесяти одного и признак значения от двадцати шести, добавка
			 *          берётся перестановкой по номеру, а основание URL берёт свою
			 *          таблицу добавок хвоста
			 *
			 * @param data     кодируемые двенадцать байтов
			 * @param result   место, в которое помещаются шестнадцать знаков
			 * @param alphabet алфавит записи
			 *
			 */
			static __ANTS_INLINE__ void encode(const uint8_t * data, uint8_t * result, const alphabet_t alphabet) noexcept {
				// Блок с запасом: загрузка читает четыре байта за двенадцатью
				uint8_t block[16] = {};
				// Переносим кодируемые байты в блок
				::memcpy(block, data, 12);
				/**
				 * x86-64: ядра интринсиками SSE
				 */
				#if defined(__x86_64__) || defined(__ANTS_MSVC_X64__)
					// Загруженный блок
					const __m128i loaded = _mm_loadu_si128(reinterpret_cast <const __m128i *> (block));
					// Слова из старших трёх байтов каждой тройки
					const __m128i words = _mm_shuffle_epi8(loaded, _mm_loadu_si128(reinterpret_cast <const __m128i *> (kernel::GATHER)));
					// Маска шести разрядов пословечно
					const __m128i mask = _mm_set1_epi32(kernel::SIX);
					// Четыре вектора шестёрок пословечными сдвигами
					const __m128i first = _mm_and_si128(_mm_srli_epi32(words, 18), mask);
				// Слова из старших трёх байтов каждой тройки перестановкой
					const __m128i second = _mm_and_si128(_mm_srli_epi32(words, 12), mask);
				// Маска шести разрядов пословечно
					const __m128i third = _mm_and_si128(_mm_srli_epi32(words, 6), mask);
				// Первая шестёрка каждого слова сдвигом на восемнадцать
					const __m128i fourth = _mm_and_si128(words, mask);
					// Сжатие шестёрок в шестнадцать байтов двумя парами упаковок
					const __m128i low = _mm_packs_epi32(first, second);
				// Вторая шестёрка каждого слова сдвигом на двенадцать
					const __m128i high = _mm_packs_epi32(third, fourth);
				// Третья шестёрка каждого слова сдвигом на шесть
					const __m128i packed = _mm_packus_epi16(low, high);
					// Шестёрки разрядов транспонированной перестановкой
					const __m128i groups = _mm_shuffle_epi8(packed, _mm_loadu_si128(reinterpret_cast <const __m128i *> (kernel::TRANSPOSE)));
					// Таблица добавок своего алфавита
					const __m128i table = _mm_loadu_si128(reinterpret_cast <const __m128i *> ((alphabet == alphabet_t::URL) ? kernel::OFFSETS_URL : kernel::OFFSETS));
					// Номер хвостового диапазона: нуль до пятидесяти одного, далее единица..двенадцать
					const __m128i tail = _mm_subs_epu8(groups, _mm_set1_epi8(51));
					// Признак значения от двадцати шести сдвигает номер диапазона на единицу
					const __m128i over = _mm_and_si128(_mm_cmpgt_epi8(groups, _mm_set1_epi8(25)), _mm_set1_epi8(1));
					// Добавка диапазона читается перестановкой по его номеру
					const __m128i shift = _mm_shuffle_epi8(table, _mm_add_epi8(tail, over));
					// Знак есть значение с добавкой своего диапазона
					const __m128i outcome = _mm_add_epi8(groups, shift);
					// Записываем шестнадцать знаков
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result), outcome);
				/**
				 * ARM64: ядра интринсиками NEON
				 */
				#else
					// Загруженный блок
					const uint8x16_t loaded = vld1q_u8(block);
					// Слова из старших трёх байтов каждой тройки
					const uint8x16_t words = vqtbl1q_u8(loaded, vld1q_u8(kernel::GATHER));
					// Маска шести разрядов пословечно
					const uint32x4_t mask = vdupq_n_u32(kernel::SIX);
					// Слова пословечным взглядом
					const uint32x4_t shifted = vreinterpretq_u32_u8(words);
					// Четыре вектора шестёрок пословечными сдвигами
					// Первая шестёрка каждого слова сдвигом на восемнадцать
				const uint32x4_t first = vandq_u32(vshrq_n_u32(shifted, 18), mask);
					// Вторая шестёрка каждого слова сдвигом на двенадцать
				const uint32x4_t second = vandq_u32(vshrq_n_u32(shifted, 12), mask);
					// Третья шестёрка каждого слова сдвигом на шесть
				const uint32x4_t third = vandq_u32(vshrq_n_u32(shifted, 6), mask);
					// Четвёртая шестёрка каждого слова маской
				const uint32x4_t fourth = vandq_u32(shifted, mask);
					// Сжатие шестёрок в шестнадцать байтов двумя парами упаковок
					// Пара сжатий первого и второго векторов в слова
				const uint16x8_t low = vcombine_u16(vqmovn_u32(first), vqmovn_u32(second));
					// Пара сжатий третьего и четвёртого векторов в слова
				const uint16x8_t high = vcombine_u16(vqmovn_u32(third), vqmovn_u32(fourth));
					// Сжатие пар в шестнадцать байтов
				const uint8x16_t packed = vcombine_u8(vqmovn_u16(low), vqmovn_u16(high));
					// Шестёрки разрядов транспонированной перестановкой
					// Шестёрки разрядов транспонированной перестановкой
				const uint8x16_t groups = vqtbl1q_u8(packed, vld1q_u8(kernel::TRANSPOSE));
					// Таблица добавок своего алфавита
					const uint8x16_t table = vld1q_u8((alphabet == alphabet_t::URL) ? kernel::OFFSETS_URL : kernel::OFFSETS);
					// Номер хвостового диапазона: нуль до пятидесяти одного, далее единица..двенадцать
					const uint8x16_t tail = vqsubq_u8(groups, vdupq_n_u8(51));
					// Признак значения от двадцати шести сдвигает номер диапазона на единицу
					const uint8x16_t over = vandq_u8(vcgtq_s8(vreinterpretq_s8_u8(groups), vdupq_n_s8(25)), vdupq_n_u8(1));
					// Добавка диапазона читается перестановкой по его номеру
					const uint8x16_t shift = vqtbl1q_u8(table, vaddq_u8(tail, over));
					// Знак есть значение с добавкой своего диапазона
					const uint8x16_t outcome = vaddq_u8(groups, shift);
					// Записываем шестнадцать знаков
					vst1q_u8(result, outcome);
				#endif
			}
		};
#endif
			/**
			 * @brief Функция кодирования блока двенадцати байтов выбранным ядром
			 *
			 * @details Машинное ядро выбирается на исполнении по признакам машины, коли
			 *          стена компиляции его допускает; переносимый ход заведомо есть
			 *          на всякой машине
			 *
			 * @param data     кодируемые двенадцать байтов
			 * @param result   место, в которое помещаются шестнадцать знаков
			 * @param alphabet алфавит записи
			 *
			 */
			static __ANTS_INLINE__ void dispatch(const uint8_t * data, uint8_t * result, const alphabet_t alphabet) noexcept {
				/**
				 * Машина несёт ядро кодирования: стены те же, что у самого ядра
				 */
				#if((defined(__x86_64__) && defined(__SSSE3__)) || (defined(__aarch64__) && defined(__ARM_NEON)) || defined(__ANTS_MSVC_X64__) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
					/**
					 * x86-64 спрашивает команды SSSE3
					 */
					#if defined(__x86_64__) || defined(__ANTS_MSVC_X64__)
						// Машинное ядро несётся при наличии команд SSSE3
						if(::nts::machine::has(::nts::machine::feature_t::SSSE3))
							// Кодируем блок машинным ядром
							machine::encode(data, result, alphabet);
						// Команд SSSE3 нет
						else
							// Кодируем блок переносимым ходом
							kernel::encode(data, result, alphabet);
					/**
					 * ARM64 спрашивает векторные команды основания
					 */
					#else
						// Машинное ядро несётся при наличии векторных команд основания
						if(::nts::machine::has(::nts::machine::feature_t::VECTOR))
							// Кодируем блок машинным ядром
							machine::encode(data, result, alphabet);
						// Векторных команд нет
						else
							// Кодируем блок переносимым ходом
							kernel::encode(data, result, alphabet);
					#endif
				/**
				 * Машина ядра не несёт: переносимый ход
				 */
				#else
					// Кодируем блок переносимым ходом
					kernel::encode(data, result, alphabet);
				#endif
			}
	};
};

#endif
