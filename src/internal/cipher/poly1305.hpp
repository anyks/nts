/**
 * @file poly1305.hpp
 * @date 2026-09-28
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
 * @brief Ядро Poly1305 на встроенном ассемблере x86-64 (AVX2)
 *
 * @details Файл порождён сценарием tools/cipher/poly1305.py и руками не правится: правки
 *          вносятся в сценарий, который исполняет порождённый список команд на случайных
 *          ключах и данных и сличает с числовой моделью до выдачи текста. Устройство:
 *          четыре дорожки по 64 разряда, всякая ведёт свою сумму пятью конечностями по 26
 *          разрядов; на каждой четвёрке блоков дорожки умножаются на r^4 операндами в памяти,
 *          переносы идут двумя переплетёнными потоками, конечности новых блоков складываются
 *          к дорожкам; после последней четвёрки дорожки умножаются на r^4, r^2, r^3 и r в
 *          порядке разбора блоков и выдаются в память. Стол ядра готовит вызывающая сторона.
 *          Порча регистров объявлена именами xmmN, хотя ядро идёт на ymm: clang без ключа
 *          -mavx2 молча не считает «ymmN» порчей, а xmmN охватывает весь регистр у обоих собирателей
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_CIPHER_POLY1305__
#define __ANTS_INTERNAL_CIPHER_POLY1305__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * Ядро берётся у gcc и clang на x86-64; у прочих собирателей остаётся ветвь на интринсиках.
 * Под ASan без оптимизации ядро не берётся (признак __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp)
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия ядра на ассемблере
	 */
	#define __ANTS_POLY1305_X86_64__
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён модулей шифрования
		 *
		 */
		namespace cipher {
			/**
			 * @brief Пространство имён ядер на ассемблере
			 *
			 */
			namespace kernel {
				/**
				 * @brief Смещения стола ядра в байтах: конечности r^4 по дорожкам, они же на пять, степени по дорожкам, они же на пять, маска конечности, старший разряд
				 */
				static constexpr size_t POLY_R4 = 0, POLY_S4 = 160, POLY_RL = 320, POLY_SL = 480, POLY_MASK = 640, POLY_HIBIT = 672, POLY_TABLE = 704;
				/**
				 * @brief Метод сложения четвёрок блоков ядром AVX2
				 *
				 * @param lanes       место под пять конечностей четырёх дорожек итога: 5 × 4 слова по 64 разряда, выровненное на 32
				 * @param accumulator накопитель пятью конечностями по 26 разрядов: складывается с первой дорожкой
				 * @param table       стол ядра в POLY_TABLE байтов, выровненный на 32
				 * @param data        складываемые блоки четвёрками по 64 байта
				 * @param count       число четвёрок, не меньше одной
				 *
				 */
				static void poly1305avx2(uint64_t * lanes, const uint32_t * accumulator, const uint64_t * table, const uint8_t * data, size_t count) noexcept {
					__asm__ __volatile__(
						"vmovd 0(%[acc]), %%xmm0\n\t"
						"vmovd 4(%[acc]), %%xmm1\n\t"
						"vmovd 8(%[acc]), %%xmm2\n\t"
						"vmovd 12(%[acc]), %%xmm3\n\t"
						"vmovd 16(%[acc]), %%xmm4\n\t"
						"vmovdqu 0(%[data]), %%ymm12\n\t"
						"vmovdqu 32(%[data]), %%ymm13\n\t"
						"vpunpckhqdq %%ymm13, %%ymm12, %%ymm14\n\t"
						"vpunpcklqdq %%ymm13, %%ymm12, %%ymm12\n\t"
						"vpand 640(%[tab]), %%ymm12, %%ymm5\n\t"
						"vpsrlq $26, %%ymm12, %%ymm6\n\t"
						"vpand 640(%[tab]), %%ymm6, %%ymm6\n\t"
						"vpsrlq $52, %%ymm12, %%ymm12\n\t"
						"vpsllq $12, %%ymm14, %%ymm7\n\t"
						"vpor %%ymm12, %%ymm7, %%ymm7\n\t"
						"vpand 640(%[tab]), %%ymm7, %%ymm7\n\t"
						"vpsrlq $14, %%ymm14, %%ymm8\n\t"
						"vpand 640(%[tab]), %%ymm8, %%ymm8\n\t"
						"vpsrlq $40, %%ymm14, %%ymm9\n\t"
						"vpor 672(%[tab]), %%ymm9, %%ymm9\n\t"
						"vpaddq %%ymm5, %%ymm0, %%ymm0\n\t"
						"vpaddq %%ymm6, %%ymm1, %%ymm1\n\t"
						"vpaddq %%ymm7, %%ymm2, %%ymm2\n\t"
						"vpaddq %%ymm8, %%ymm3, %%ymm3\n\t"
						"vpaddq %%ymm9, %%ymm4, %%ymm4\n\t"
						"addq $64, %[data]\n\t"
						"decq %[count]\n\t"
						"jz 2f\n\t"
						"1:\n\t"
						"vpmuludq 0(%[tab]), %%ymm0, %%ymm5\n\t"
						"vpmuludq 288(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 256(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 224(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 192(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 32(%[tab]), %%ymm0, %%ymm6\n\t"
						"vpmuludq 0(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 288(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 256(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 224(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 64(%[tab]), %%ymm0, %%ymm7\n\t"
						"vpmuludq 32(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 0(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 288(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 256(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 96(%[tab]), %%ymm0, %%ymm8\n\t"
						"vpmuludq 64(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 32(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 0(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 288(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 128(%[tab]), %%ymm0, %%ymm9\n\t"
						"vpmuludq 96(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpmuludq 64(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpmuludq 32(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpmuludq 0(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpsrlq $26, %%ymm5, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm5, %%ymm0\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpsrlq $26, %%ymm8, %%ymm11\n\t"
						"vpand 640(%[tab]), %%ymm8, %%ymm3\n\t"
						"vpaddq %%ymm11, %%ymm9, %%ymm9\n\t"
						"vpsrlq $26, %%ymm6, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm6, %%ymm1\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpsrlq $26, %%ymm9, %%ymm11\n\t"
						"vpand 640(%[tab]), %%ymm9, %%ymm4\n\t"
						"vpsllq $2, %%ymm11, %%ymm10\n\t"
						"vpaddq %%ymm11, %%ymm10, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm0, %%ymm0\n\t"
						"vpsrlq $26, %%ymm7, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm7, %%ymm2\n\t"
						"vpaddq %%ymm10, %%ymm3, %%ymm3\n\t"
						"vpsrlq $26, %%ymm0, %%ymm11\n\t"
						"vpand 640(%[tab]), %%ymm0, %%ymm0\n\t"
						"vpaddq %%ymm11, %%ymm1, %%ymm1\n\t"
						"vpsrlq $26, %%ymm3, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm3, %%ymm3\n\t"
						"vpaddq %%ymm10, %%ymm4, %%ymm4\n\t"
						"vmovdqu 0(%[data]), %%ymm12\n\t"
						"vmovdqu 32(%[data]), %%ymm13\n\t"
						"vpunpckhqdq %%ymm13, %%ymm12, %%ymm14\n\t"
						"vpunpcklqdq %%ymm13, %%ymm12, %%ymm12\n\t"
						"vpand 640(%[tab]), %%ymm12, %%ymm5\n\t"
						"vpsrlq $26, %%ymm12, %%ymm6\n\t"
						"vpand 640(%[tab]), %%ymm6, %%ymm6\n\t"
						"vpsrlq $52, %%ymm12, %%ymm12\n\t"
						"vpsllq $12, %%ymm14, %%ymm7\n\t"
						"vpor %%ymm12, %%ymm7, %%ymm7\n\t"
						"vpand 640(%[tab]), %%ymm7, %%ymm7\n\t"
						"vpsrlq $14, %%ymm14, %%ymm8\n\t"
						"vpand 640(%[tab]), %%ymm8, %%ymm8\n\t"
						"vpsrlq $40, %%ymm14, %%ymm9\n\t"
						"vpor 672(%[tab]), %%ymm9, %%ymm9\n\t"
						"vpaddq %%ymm5, %%ymm0, %%ymm0\n\t"
						"vpaddq %%ymm6, %%ymm1, %%ymm1\n\t"
						"vpaddq %%ymm7, %%ymm2, %%ymm2\n\t"
						"vpaddq %%ymm8, %%ymm3, %%ymm3\n\t"
						"vpaddq %%ymm9, %%ymm4, %%ymm4\n\t"
						"addq $64, %[data]\n\t"
						"decq %[count]\n\t"
						"jnz 1b\n\t"
						"2:\n\t"
						"vpmuludq 320(%[tab]), %%ymm0, %%ymm5\n\t"
						"vpmuludq 608(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 576(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 544(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 512(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm5, %%ymm5\n\t"
						"vpmuludq 352(%[tab]), %%ymm0, %%ymm6\n\t"
						"vpmuludq 320(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 608(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 576(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 544(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpmuludq 384(%[tab]), %%ymm0, %%ymm7\n\t"
						"vpmuludq 352(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 320(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 608(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 576(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpmuludq 416(%[tab]), %%ymm0, %%ymm8\n\t"
						"vpmuludq 384(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 352(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 320(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 608(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm8, %%ymm8\n\t"
						"vpmuludq 448(%[tab]), %%ymm0, %%ymm9\n\t"
						"vpmuludq 416(%[tab]), %%ymm1, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpmuludq 384(%[tab]), %%ymm2, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpmuludq 352(%[tab]), %%ymm3, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpmuludq 320(%[tab]), %%ymm4, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm9, %%ymm9\n\t"
						"vpsrlq $26, %%ymm5, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm5, %%ymm0\n\t"
						"vpaddq %%ymm10, %%ymm6, %%ymm6\n\t"
						"vpsrlq $26, %%ymm8, %%ymm11\n\t"
						"vpand 640(%[tab]), %%ymm8, %%ymm3\n\t"
						"vpaddq %%ymm11, %%ymm9, %%ymm9\n\t"
						"vpsrlq $26, %%ymm6, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm6, %%ymm1\n\t"
						"vpaddq %%ymm10, %%ymm7, %%ymm7\n\t"
						"vpsrlq $26, %%ymm9, %%ymm11\n\t"
						"vpand 640(%[tab]), %%ymm9, %%ymm4\n\t"
						"vpsllq $2, %%ymm11, %%ymm10\n\t"
						"vpaddq %%ymm11, %%ymm10, %%ymm10\n\t"
						"vpaddq %%ymm10, %%ymm0, %%ymm0\n\t"
						"vpsrlq $26, %%ymm7, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm7, %%ymm2\n\t"
						"vpaddq %%ymm10, %%ymm3, %%ymm3\n\t"
						"vpsrlq $26, %%ymm0, %%ymm11\n\t"
						"vpand 640(%[tab]), %%ymm0, %%ymm0\n\t"
						"vpaddq %%ymm11, %%ymm1, %%ymm1\n\t"
						"vpsrlq $26, %%ymm3, %%ymm10\n\t"
						"vpand 640(%[tab]), %%ymm3, %%ymm3\n\t"
						"vpaddq %%ymm10, %%ymm4, %%ymm4\n\t"
						"vmovdqa %%ymm0, 0(%[out])\n\t"
						"vmovdqa %%ymm1, 32(%[out])\n\t"
						"vmovdqa %%ymm2, 64(%[out])\n\t"
						"vmovdqa %%ymm3, 96(%[out])\n\t"
						"vmovdqa %%ymm4, 128(%[out])\n\t"
						"vzeroupper\n\t"
						: [data] "+r" (data), [count] "+r" (count)
						: [out] "r" (lanes), [acc] "r" (accumulator), [tab] "r" (table)
						: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "cc", "memory");
				}
			}
		}
	}
#endif

#endif // __ANTS_INTERNAL_CIPHER_POLY1305__
