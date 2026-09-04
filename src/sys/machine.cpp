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
	 * @brief Метод снятия признаков машины
	 *
	 * @return разряды расширений, которые у машины есть
	 *
	 */
	static uint8_t detect() noexcept {
		// Снятые разряды расширений
		uint8_t result = 0;
		// Переменная окружения запрета расширений
		const char * variable = ::getenv("ANTS_MACHINE");
		// Если расширения запрещены окружением
		if((variable != nullptr) && (::strcmp(variable, "0") == 0))
			// Выводим отсутствие расширений
			return 0;
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
				result = static_cast <uint8_t> (result | (1 << i));
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
			result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::AES));
		// Если умножение без переносов есть
		if(caps & HWCAP_PMULL)
			// Записываем разряд расширения
			result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::CARRYLESS));
		// Если команды SHA-256 есть
		if(caps & HWCAP_SHA2)
			// Записываем разряд расширения
			result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::SHA256));
	/**
	 * Если признак команд SHA-512 объявлен заголовком
	 */
	#if defined(HWCAP_SHA512)
		// Если команды SHA-512 есть
		if(caps & HWCAP_SHA512)
			// Записываем разряд расширения
			result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::SHA512));
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
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::AES));
			// Если умножение без переносов есть: разряд 4
			if(caps & (1UL << 4))
				// Записываем разряд расширения
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::CARRYLESS));
			// Если команды SHA-256 есть: разряд 6
			if(caps & (1UL << 6))
				// Записываем разряд расширения
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::SHA256));
			// Если команды SHA-512 есть: разряд 21
			if(caps & (1UL << 21))
				// Записываем разряд расширения
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::SHA512));
		}
/**
 * Если сборка ведётся под ARM64 на Windows
 */
#elif defined(__aarch64__) && defined(_WIN32)
		// Если расширение криптографии ARMv8 есть: AES, PMULL и SHA-256 идут вместе
		if(::IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE))
			// Записываем разряды расширений
			result = static_cast <uint8_t> (static_cast <uint8_t> (feature_t::AES) | static_cast <uint8_t> (feature_t::CARRYLESS) | static_cast <uint8_t> (feature_t::SHA256));
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
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::AES));
			// Если умножение без переносов есть: разряд 1 ECX
			if((ecx & (1U << 1)) && ssse3)
				// Записываем разряд расширения
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::CARRYLESS));
		}
		// Если седьмой лист опроса снят
		if(::__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)){
			// Если команды SHA-NI есть: разряд 29 EBX
			if(ebx & (1U << 29))
				// Записываем разряд расширения
				result = static_cast <uint8_t> (result | static_cast <uint8_t> (feature_t::SHA256));
		}
#endif
		// Выводим снятые разряды расширений
		return result;
	}

	/**
	 * @brief Метод получения снятых разрядов расширений
	 *
	 * @details Признаки снимаются один раз при первом обращении: заведение
	 *          статического значения потокобезопасно по правилам языка
	 *
	 * @return разряды расширений, которые у машины есть
	 *
	 */
	static uint8_t features() noexcept {
		// Снятые один раз разряды расширений
		static const uint8_t result = detect();
		// Выводим снятые разряды
		return result;
	}
};

/**
 * @brief Метод проверки наличия расширения у машины
 *
 * @param feature проверяемое расширение
 *
 * @return        признак того, что расширение есть и не запрещено
 *
 */
bool nts::machine::has(const feature_t feature) noexcept {
	// Если расширения запрещены вызовом
	if(forbidden)
		// Выводим отсутствие расширения
		return false;
	// Выводим наличие разряда расширения среди снятых
	return ((features() & static_cast <uint8_t> (feature)) != 0);
}
/**
 * @brief Метод запрета либо разрешения расширений на исполнении
 *
 * @param allowed признак разрешения расширений: ложь переводит всё на таблицы
 *
 */
void nts::machine::allow(const bool allowed) noexcept {
	// Запоминаем запрет расширений
	forbidden = !allowed;
}
