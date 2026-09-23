/**
 * @file machine.hpp
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
 * \~russian
 * @brief Заголовочный файл опознания машинных команд криптографии на исполнении
 *
 * \~english
 * @brief Header file of the run-time detection of the cryptographic machine instructions
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_MACHINE__
#define __ANTS_MACHINE__

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
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён опознания машины
	 *
	 * @details Признаки собирателя лишь дозволяют породить команды расширений; есть ли
	 *          они у машины, где двоичный файл запущен, решается здесь один раз при
	 *          первом обращении. Обе ветви - командами и таблицами - живут в одном
	 *          двоичном файле, и он переносится между машинами одного набора команд
	 *          без пересборки
	 *
	 * @note Опознание: macOS - sysctlbyname по признакам hw.optional, Linux - getauxval,
	 *       FreeBSD - elf_aux_info, Windows - IsProcessorFeaturePresent, x86-64 - cpuid,
	 *       Эльбрус - поколение набора команд, закреплённое сборкой (`__iset__`): с пятого
	 *       поколения векторные операции и перестановка байтов (VECTOR и SSSE3, ими собиратель
	 *       lcc изображает SSE2 и SSSE3), с шестого - умножение без переносов (CARRYLESS);
	 *       команд AES и SHA у Эльбруса нет. Там, где способа опознания нет, расширения
	 *       считаются отсутствующими. Векторные команды основания набора (NEON у ARM64,
	 *       SSE2 у x86-64, векторные операции Эльбруса) есть у всякой машины набора и
	 *       объявляются признаком VECTOR, чтобы запрет allow(false) переводил и векторные
	 *       ветви на переносимый путь ради сличения
	 *
	 * \~english
	 * @brief Namespace of the machine detection
	 * @details The flags of the compiler only allow to generate the instructions of the extensions;
	 *          whether the machine the binary is run on has them is decided here once at the first
	 *          call. Both branches - by the instructions and by the tables - live in one binary, and
	 *          it is carried between the machines of one instruction set without a rebuild
	 * @note Detection: macOS - sysctlbyname by the hw.optional flags, Linux - getauxval, FreeBSD -
	 *       elf_aux_info, Windows - IsProcessorFeaturePresent, x86-64 - cpuid, Elbrus - the
	 *       generation of the instruction set fixed by the build (`__iset__`): from the fifth
	 *       generation the vector operations and the byte shuffle (VECTOR and SSSE3, the lcc
	 *       compiler renders SSE2 and SSSE3 by them), from the sixth - the carry-less multiplication
	 *       (CARRYLESS); Elbrus has no AES and SHA instructions. Where there is no way of the
	 *       detection, the extensions are considered absent. The baseline vector instructions
	 *       (NEON at ARM64, SSE2 at x86-64, the vector operations of Elbrus) exist at every machine
	 *       of the set and are declared by the VECTOR flag so that the ban allow(false) puts the
	 *       vector branches onto the portable path too for the sake of the comparison
	 *
	 * \~
	 */
	namespace machine {
		/**
		 * \~russian
		 * @brief Расширение машинных команд
		 *
		 * \~english
		 * @brief Extension of the machine instructions
		 *
		 * \~
		 */
		enum class feature_t : uint16_t {
			AES       = 0x01, /*!< \~russian Команды AES: ARMv8 AESE/AESD либо AES-NI \~english AES instructions: ARMv8 AESE/AESD or AES-NI \~ */
			CARRYLESS = 0x02, /*!< \~russian Умножение без переносов: PMULL либо PCLMULQDQ \~english Carry-less multiplication: PMULL or PCLMULQDQ \~ */
			SHA256    = 0x04, /*!< \~russian Команды SHA-256: ARMv8 SHA256H либо SHA-NI \~english SHA-256 instructions: ARMv8 SHA256H or SHA-NI \~ */
			SHA512    = 0x08, /*!< \~russian Команды SHA-512 расширения ARMv8.2 \~english SHA-512 instructions of the ARMv8.2 extension \~ */
			VECTOR    = 0x10, /*!< \~russian Векторные команды основания набора: NEON у ARM64 либо SSE2 у x86-64 \~english Baseline vector instructions: NEON at ARM64 or SSE2 at x86-64 \~ */
			SSSE3     = 0x20, /*!< \~russian Перестановка байтов PSHUFB расширения SSSE3 у x86-64 \~english PSHUFB byte shuffle of the SSSE3 extension at x86-64 \~ */
			AVX2      = 0x40, /*!< \~russian Векторы в 256 разрядов расширения AVX2 у x86-64, разрешённые системой \~english 256-bit vectors of the AVX2 extension at x86-64, enabled by the system \~ */
			AVX       = 0x80, /*!< \~russian Кодировка VEX команд на 128 разрядов расширения AVX у x86-64, разрешённая системой \~english VEX encoding of the 128-bit instructions of the AVX extension at x86-64, enabled by the system \~ */
			MOVBE     = 0x100 /*!< \~russian Загрузка с перестановкой байтов MOVBE у x86-64 \~english MOVBE byte-swapping load at x86-64 \~ */
		};

		/**
		 * \~russian
		 * @brief Метод проверки наличия расширения у машины
		 *
		 * @param feature проверяемое расширение
		 *
		 * @return        признак того, что расширение есть и не запрещено
		 *
		 * @note Первое обращение снимает признаки машины и читает переменную окружения
		 *       ANTS_MACHINE: значение «0» запрещает все расширения на исполнении, без
		 *       пересборки; иное число - маска запрещённых разрядов feature_t (например
		 *       «0x40» снимает AVX2, «0x60» - AVX2 и SSSE3, оставляя SSE2), чем проверки
		 *       принуждают выбор пути помимо опроса машины. Дальнейшие обращения отвечают по снятому
		 *
		 * \~english
		 * @brief Method of checking the presence of an extension at the machine
		 * @param feature the extension being checked
		 * @return        the flag of the extension being present and not forbidden
		 * @note The first call takes the flags of the machine and reads the ANTS_MACHINE environment
		 *       variable: the value «0» forbids all the extensions at the run time, without a rebuild;
		 *       another number is a mask of the forbidden bits of feature_t (e.g. «0x40» drops AVX2,
		 *       «0x60» - AVX2 and SSSE3 leaving SSE2), by which the checks force the choice of a path
		 *       besides the inquiry of the machine. The further calls answer by what was taken
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool has(const feature_t feature) noexcept;
		/**
		 * \~russian
		 * @brief Метод запрета либо разрешения расширений на исполнении
		 *
		 * @param allowed признак разрешения расширений: ложь переводит всё на таблицы
		 *
		 * @note Разрешение не добавляет расширений, которых у машины нет: оно лишь
		 *       снимает запрет. Служит сличению обоих путей на одной машине
		 *
		 * \~english
		 * @brief Method of forbidding or allowing the extensions at the run time
		 * @param allowed the flag of allowing the extensions: false puts everything onto the tables
		 * @note Allowing does not add the extensions the machine lacks: it only lifts the ban. Serves
		 *       the comparison of both paths on one machine
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void allow(const bool allowed) noexcept;
	};
};

#endif // __ANTS_MACHINE__
