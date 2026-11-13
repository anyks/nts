/**
 * @file machine.cpp
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
 * @brief Опознание машинных команд криптографии на исполнении
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstdlib>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/machine.hpp>

/**
 * Если сборка ведётся под macOS
 */
#if defined(__APPLE__)
	/**
	 * Подключаем заголовочный файл настроек ядра
	 */
	#include <sys/sysctl.h>
/**
 * Если сборка ведётся под Linux
 */
#elif defined(__linux__)
	/**
	 * Подключаем заголовочный файл вспомогательного вектора
	 */
	#include <sys/auxv.h>
	/**
	 * Если сборка ведётся под ARM64
	 */
	#if defined(__aarch64__)
		/**
		 * Подключаем заголовочный файл признаков машины
		 */
		#include <asm/hwcap.h>
	#endif
/**
 * Если сборка ведётся под FreeBSD
 */
#elif defined(__FreeBSD__)
	/**
	 * Подключаем заголовочный файл вспомогательного вектора
	 */
	#include <sys/auxv.h>
/**
 * Если сборка ведётся под Windows
 */
#elif defined(_WIN32)
	/**
	 * Подключаем заголовочный файл Windows
	 */
	#include <windows.h>
#endif

/**
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
	/**
	 * Подключаем заголовочный файл опроса процессора
	 */
	#include <cpuid.h>
#endif

/**
 * Если сборка ведётся под x86-64 собирателем Microsoft Visual C++
 *
 * @note Одного признака архитектуры здесь мало: mingw-w64 объявляет _M_X64 и _M_AMD64
 *       в собственном <windows.h>, не определяя при этом _MSC_VER. Без признака
 *       собирателя <intrin.h> подключается под GCC, где макрос __cpuid из <cpuid.h>
 *       ломает объявление функции того же имени в psdk_inc/intrin-impl.h
 *
 */
#if defined(_MSC_VER) && defined(_M_X64)
	/**
	 * Подключаем заголовочный файл внутренних функций собирателя: опрос процессора
	 * и чтение регистра разрешённых системой состояний
	 */
	#include <intrin.h>
#endif

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
	using namespace nts::machine;

	/**
	 * @brief Признак того, что расширения запрещены вызовом
	 *
	 */
	static bool forbidden = false;

	/**
	 * @brief Функция снятия признаков машины
	 *
	 * @return разряды расширений, которые у машины есть
	 *
	 */
	static uint16_t detect() noexcept {
		// Снятые разряды расширений
		uint16_t result = 0;
		// Переменная окружения запрета расширений
		const char * variable = ::getenv("ANTS_MACHINE");
		// Если расширения запрещены окружением целиком
		if((variable != nullptr) && (::strcmp(variable, "0") == 0))
			// Выводим отсутствие расширений
			return 0;
		// Разряды расширений, запрещённых окружением поимённо
		uint16_t denied = 0;
		// Если окружение несёт число - это маска запрещённых разрядов (например 0x40 снимает AVX2)
		if(variable != nullptr)
			// Разбираем маску запрещённых расширений
			denied = static_cast <uint16_t> (::strtoul(variable, nullptr, 0) & 0xFFFF);
		/**
		 * Если сборка ведётся под ARM64 на macOS
		 */
		#if defined(__aarch64__) && defined(__APPLE__)
			// Имена признаков расширений и их разряды
			const char * names[4] = {"hw.optional.arm.FEAT_AES", "hw.optional.arm.FEAT_PMULL", "hw.optional.arm.FEAT_SHA256", "hw.optional.arm.FEAT_SHA512"};
			/**
			 * Выполняем перебор признаков
			 */
			for(size_t i = 0; i < 4; i++){
				// Значение признака
				int value = 0;
				// Размер значения признака
				size_t size = sizeof(value);
				// Если признак снят и установлен
				if((::sysctlbyname(names[i], &value, &size, nullptr, 0) == 0) && (value != 0))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | (1 << i));
			}
		/**
		 * Если сборка ведётся под ARM64 на Linux
		 */
		#elif defined(__aarch64__) && defined(__linux__)
			// Признаки машины из вспомогательного вектора
			const unsigned long caps = ::getauxval(AT_HWCAP);
			// Если команды AES есть
			if(caps & HWCAP_AES)
			// Записываем разряд расширения
			result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AES));
			// Если умножение без переносов есть
			if(caps & HWCAP_PMULL)
			// Записываем разряд расширения
			result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::CARRYLESS));
			// Если команды SHA-256 есть
			if(caps & HWCAP_SHA2)
			// Записываем разряд расширения
			result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SHA256));
			/**
			 * Если признак команд SHA-512 объявлен заголовком
			 */
			#if defined(HWCAP_SHA512)
				// Если команды SHA-512 есть
				if(caps & HWCAP_SHA512)
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SHA512));
			#endif
		/**
		 * Если сборка ведётся под ARM64 на FreeBSD
		 */
		#elif defined(__aarch64__) && defined(__FreeBSD__)
			// Признаки машины из вспомогательного вектора
			unsigned long caps = 0;
			// Если признаки сняты
			if(::elf_aux_info(AT_HWCAP, &caps, sizeof(caps)) == 0){
				// Если команды AES есть: разряд 3 HWCAP
				if(caps & (1UL << 3))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AES));
				// Если умножение без переносов есть: разряд 4
				if(caps & (1UL << 4))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::CARRYLESS));
				// Если команды SHA-256 есть: разряд 6
				if(caps & (1UL << 6))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SHA256));
				// Если команды SHA-512 есть: разряд 21
				if(caps & (1UL << 21))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SHA512));
			}
		/**
		 * Если сборка ведётся под ARM64 на Windows
		 */
		#elif (defined(__aarch64__) || defined(__ANTS_MSVC_ARM64__)) && defined(_WIN32)
			// Если расширение криптографии ARMv8 есть: AES, PMULL и SHA-256 идут вместе
			if(::IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE))
			// Записываем разряды расширений
			result = static_cast <uint16_t> (static_cast <uint16_t> (feature_t::AES) | static_cast <uint16_t> (feature_t::CARRYLESS) | static_cast <uint16_t> (feature_t::SHA256));
		/**
		 * Если сборка ведётся под x86-64 собирателем семейства GCC
		 */
		#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
			// Регистры опроса процессора
			unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
			// Если первый лист опроса снят
			if(::__get_cpuid(1, &eax, &ebx, &ecx, &edx)){
				// Признак SSSE3: разряд 9 ECX, нужен отражению байтов
				const bool ssse3 = ((ecx & (1U << 9)) != 0);
				// Если команды AES-NI есть: разряд 25 ECX
				if((ecx & (1U << 25)) && ssse3)
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AES));
				// Если умножение без переносов есть: разряд 1 ECX
				if((ecx & (1U << 1)) && ssse3)
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::CARRYLESS));
			}
			// Если седьмой лист опроса снят
			if(::__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)){
				// Если команды SHA-NI есть: разряд 29 EBX
				if(ebx & (1U << 29))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SHA256));
				// Если умножение MULX (BMI2, разряд 8 EBX) и сложения ADCX/ADOX (ADX, разряд 19 EBX) есть вместе
				if((ebx & (1U << 8)) && (ebx & (1U << 19)))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::ADX));
			}
			// Регистры повторного опроса первого листа
			unsigned int eax1 = 0, ebx1 = 0, ecx1 = 0, edx1 = 0;
			// Если первый лист опроса снят
			if(::__get_cpuid(1, &eax1, &ebx1, &ecx1, &edx1)){
				// Если перестановка байтов SSSE3 есть: разряд 9 ECX
				if(ecx1 & (1U << 9))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SSSE3));
				// Признак того, что система сохраняет верхние половины векторов: OSXSAVE, разряд 27 ECX
				const bool osxsave = ((ecx1 & (1U << 27)) != 0);
				// Признак AVX: разряд 28 ECX
				const bool avx = ((ecx1 & (1U << 28)) != 0);
				// Если загрузка с перестановкой байтов MOVBE есть: разряд 22 ECX
				if(ecx1 & (1U << 22))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::MOVBE));
				// Если сохранение верхних половин и AVX объявлены
				if(osxsave && avx){
					// Младшая и старшая половины регистра XCR0
					unsigned int low = 0, high = 0;
					// Читаем регистр XCR0: разрешённые системой состояния регистров
					__asm__ __volatile__("xgetbv" : "=a" (low), "=d" (high) : "c" (0));
					// Если система сохраняет и XMM, и YMM: разряды 1 и 2
					if((low & 0x6) == 0x6){
						// Записываем разряд кодировки VEX
						result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AVX));
						// Если седьмой лист несёт AVX2: разряд 5 EBX
						if(ebx & (1U << 5))
						// Записываем разряд расширения
						result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AVX2));
					}
				}
			}
		/**
		 * Если сборка ведётся под x86-64 собирателем Microsoft Visual C++
		 *
		 * @note Опрос процессора ведут внутренние функции собирателя из <intrin.h>, а не
		 *       <cpuid.h> собирателей семейства GCC. Ключ /arch не нужен: внутренние функции
		 *       всякого расширения доступны собирателю и без него, а выбор пути целиком
		 *       остаётся за снятыми здесь признаками
		 *
		 */
		#elif defined(_MSC_VER) && defined(_M_X64)
			// Регистры опроса процессора
			int regs[4] = {0, 0, 0, 0};
			// Выполняем опрос первого листа процессора
			::__cpuid(regs, 1);
			// Значение ECX первого листа опроса
			const unsigned int first = static_cast <unsigned int> (regs[2]);
			// Признак перестановки байтов SSSE3: разряд 9 ECX, нужен отражению байтов
			const bool ssse3 = ((first & (1U << 9)) != 0);
			// Если команды AES-NI есть: разряд 25 ECX
			if((first & (1U << 25)) && ssse3)
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AES));
			// Если умножение без переносов есть: разряд 1 ECX
			if((first & (1U << 1)) && ssse3)
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::CARRYLESS));
			// Если перестановка байтов SSSE3 есть: разряд 9 ECX
			if(ssse3)
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SSSE3));
			// Если загрузка с перестановкой байтов MOVBE есть: разряд 22 ECX
			if(first & (1U << 22))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::MOVBE));
			// Выполняем опрос седьмого листа процессора
			::__cpuidex(regs, 7, 0);
			// Значение EBX седьмого листа опроса
			const unsigned int seventh = static_cast <unsigned int> (regs[1]);
			// Если команды SHA-NI есть: разряд 29 EBX
			if(seventh & (1U << 29))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::SHA256));
			// Если умножение MULX (BMI2, разряд 8 EBX) и сложения ADCX/ADOX (ADX, разряд 19 EBX) есть вместе
			if((seventh & (1U << 8)) && (seventh & (1U << 19)))
				// Записываем разряд расширения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::ADX));
			// Признак того, что система сохраняет верхние половины векторов: OSXSAVE, разряд 27 ECX
			const bool osxsave = ((first & (1U << 27)) != 0);
			// Признак AVX: разряд 28 ECX
			const bool avx = ((first & (1U << 28)) != 0);
			// Если сохранение верхних половин и AVX объявлены
			if(osxsave && avx){
				// Разрешённые системой состояния регистров из XCR0
				const unsigned long long states = ::_xgetbv(0);
				// Если система сохраняет и XMM, и YMM: разряды 1 и 2
				if((states & 0x6) == 0x6){
					// Записываем разряд кодировки VEX
					result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AVX));
					// Если седьмой лист несёт AVX2: разряд 5 EBX
					if(seventh & (1U << 5))
						// Записываем разряд расширения
						result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::AVX2));
				}
			}
		#endif
		/**
		 * Если сборка ведётся под ARM64 либо x86-64
		 */
		#if defined(__aarch64__) || defined(__x86_64__) || defined(__ANTS_MSVC_X64__) || defined(__ANTS_MSVC_ARM64__)
			// Векторные команды основания набора есть у всякой машины
			result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::VECTOR));
		/**
		 * Если сборка ведётся под Эльбрус
		 */
		#elif defined(__e2k__)
			/**
			 * Набор команд Эльбруса закреплён сборкой (`__iset__`), разбора на исполнении нет:
			 * с пятого поколения есть 128-разрядные векторные операции и перестановка байтов,
			 * которыми собиратель lcc изображает SSE2 и SSSE3, а 256-разрядные векторы AVX2
			 * он складывает из двух 128-разрядных - на них идут векторные ветви x86-64. Ветвь
			 * AVX2 берётся намеренно: восемь блоков ChaCha20 в полёте загружают широкую
			 * команду втрое лучше четырёх (560 против 184 МБ/с на Эльбрус-8С2). Умножение без
			 * переносов появилось в шестом поколении. Команд AES и SHA у процессора нет ни в
			 * одном поколении, а их эмуляция у lcc медленнее таблиц и признаками не включается
			 */
			#if defined(__iset__) && (__iset__ >= 5)
				// Векторные операции, перестановка байтов и сдвоенные векторы пятого поколения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::VECTOR) | static_cast <uint16_t> (feature_t::SSSE3) | static_cast <uint16_t> (feature_t::AVX2));
			#endif
			/**
			 * Если закреплённое сборкой поколение Эльбруса шестое или выше
			 */
			#if defined(__iset__) && (__iset__ >= 6)
				// Умножение без переносов шестого поколения
				result = static_cast <uint16_t> (result | static_cast <uint16_t> (feature_t::CARRYLESS));
			#endif
		#endif
		// Выводим снятые разряды расширений без запрещённых окружением
		return static_cast <uint16_t> (result & static_cast <uint16_t> (~denied));
	}

	/**
	 * @brief Функция получения снятых разрядов расширений
	 *
	 * @details Признаки снимаются один раз при первом обращении: заведение
	 *          статического значения потокобезопасно по правилам языка
	 *
	 * @return разряды расширений, которые у машины есть
	 *
	 */
	static uint16_t features() noexcept {
		// Снятые один раз разряды расширений
		static const uint16_t result = detect();
		// Выводим снятые разряды
		return result;
	}
};

/**
 * @brief Функция проверки наличия расширения у машины
 *
 * @param feature проверяемое расширение
 * @return        признак того, что расширение есть и не запрещено
 *
 */
bool nts::machine::has(const feature_t feature) noexcept {
	// Если расширения запрещены вызовом
	if(forbidden)
		// Выводим отсутствие расширения
		return false;
	// Выводим наличие разряда расширения среди снятых
	return ((features() & static_cast <uint16_t> (feature)) != 0);
}
/**
 * @brief Функция запрета либо разрешения расширений на исполнении
 *
 * @param allowed признак разрешения расширений: ложь переводит всё на таблицы
 *
 */
void nts::machine::allow(const bool allowed) noexcept {
	// Запоминаем запрет расширений
	forbidden = !allowed;
}
