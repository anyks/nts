/**
 * @file rsa.cpp
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
 * @brief Модуль RSA по PKCS #1 v2.2 (RFC 8017)
 *
 * @details Примитивы RSAEP/RSADP и RSASP1/RSAVP1 раздела 5, схемы подписи
 *          RSASSA-PKCS1-v1_5 и RSASSA-PSS раздела 8, схемы шифрования
 *          RSAES-PKCS1-v1_5 и RSAES-OAEP раздела 7, кодирование ключей
 *          приложения A.1. Секретное действие ведётся по китайской теореме об
 *          остатках с ослеплением случайным числом по каждому сомножителю: показатели
 *          секретны, оттого возведение в степень, приведение, обращение и сборка идут
 *          за постоянное время арифметикой Монтгомери с предвычислениями,
 *          заведёнными при установке ключа
 *
 * @section Намеренные решения
 * 1. Ослепление ведётся по сомножителям порознь: вычет числа по p умножается на
 *    r₁^e, вычет по q - на r₂^e, а после секретной степени итог умножается на r₁⁻¹ и
 *    r₂⁻¹ (секретная степень открытой степени ослепляющего числа есть само число).
 *    Обратные числа считаются алгоритмом Бернстайна и Янга за постоянное время
 *    (8,8 мкс на 1024 разрядах), а не малой теоремой Ферма: две экспоненты p - 2 и
 *    q - 2 стоили столько же, сколько сами секретные степени, - половину действия.
 *    Ослепление на каждый вызов свежее: сохранённая пара с обновлением квадратами,
 *    как у OpenSSL, требовала бы изменяемого состояния и замка в неизменяемом ключе,
 *    а стоит она восемь сотых действия. Условие пересмотра: измеренная нехватка этих
 *    сотых до эталона.
 * 2. Предвычисления Монтгомери по n, p и q и коэффициент qInv в области по p
 *    заводятся при установке ключа (prepare), оттого подпись и сличение не платят за
 *    них: прежде сличение подписи RSA-2048 стоило 308 мкс, из которых сами
 *    восемнадцать умножений - 22 (круг 28, CONFORMANCE.md).
 * 3. Итог секретного действия сверяется открытой степенью с исходным числом: сбой
 *    в одной из ветвей китайской теоремы выдаёт сомножитель модуля (Ленстра), и
 *    расходящийся итог не выдаётся.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/rsa.hpp>
#include <asn1/asn1.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

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
	using namespace nts::sign;

	/**
	 * @brief Наименьшее число разрядов устанавливаемого модуля
	 *
	 * @details Ключи короче порождать нельзя, но установить для проверок и
	 *          разбора старых записей можно
	 *
	 */
	static constexpr size_t LEAST_BITS = 512;
	/**
	 * Наибольшая ширина открытого показателя в разрядах: RFC 8017 её не ограничивает, но
	 * чужой ключ с показателем шириной в модуль делает проверку подписи ценою секретного
	 * действия (отказ в обслуживании по цепочке сертификатов); предел тот же, что у
	 * BoringSSL (e < 2^33). Условие пересмотра: потребитель с ключами шире
	 */
	static constexpr size_t EXPONENT_BITS = 33;

	/**
	 * @brief Наибольшее число попыток выработки простого сомножителя
	 *
	 * @details Доля простых среди нечётных чисел длиной 2048 разрядов - около
	 *          одного на семьсот; предел стоит заслоном от вечного круга при
	 *          отказе источника случайности
	 *
	 */
	static constexpr size_t ATTEMPTS = 100000;

	/**
	 * @brief Наибольшая длина хеша в байтах
	 *
	 */
	static constexpr size_t HASH_SIZE = 64;

	/**
	 * @brief Наименьшая длина дополнения PKCS #1 v1.5 в байтах
	 *
	 * @details Раздел 7.2.1 RFC 8017: не менее восьми байтов
	 *
	 */
	static constexpr size_t PADDING = 8;
	/**
	 * @brief Число попыток выработки ослепляющего числа
	 *
	 * @details Число на разряд короче модуля всегда меньше него; попытка срывается
	 *          лишь на нулевом вычете по сомножителю, вероятность чего ничтожна
	 *
	 */
	static constexpr size_t BLINDING = 100;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод получения маски равенства слов
	 *
	 * @param first  первое слово
	 * @param second второе слово
	 *
	 * @return       маска: все разряды единичны при равенстве слов
	 *
	 */
	static uint64_t same(const uint64_t first, const uint64_t second) noexcept {
		// Различие слов
		const uint64_t value = (first ^ second);
		// Выводим признак нуля различия, растянутый на всё слово
		return (0 - (((value | (0 - value)) >> 63) ^ 1));
	}
	/**
	 * @brief Метод получения маски признака «первое слово меньше второго»
	 *
	 * @param first  первое слово
	 * @param second второе слово
	 *
	 * @return       маска: все разряды единичны, если первое слово меньше второго
	 *
	 */
	static uint64_t below(const uint64_t first, const uint64_t second) noexcept {
		// Выводим заём вычитания второго слова из первого, растянутый на всё слово
		return (0 - (((~first & second) | (~(first ^ second) & (first - second))) >> 63));
	}
	/**
	 * @brief Метод выбора одного из двух слов наложением маски
	 *
	 * @param mask   маска выбора: все разряды единичны либо все нулевые
	 * @param first  слово, выбираемое при единичной маске
	 * @param second слово, выбираемое при нулевой маске
	 *
	 * @return       выбранное слово
	 *
	 */
	static uint64_t select(const uint64_t mask, const uint64_t first, const uint64_t second) noexcept {
		// Выводим выбранное наложением маски слово
		return (second ^ (mask & (first ^ second)));
	}
	/**
	 * @brief Метод сличения областей байтов за постоянное время
	 *
	 * @param first  первая область
	 * @param second вторая область
	 * @param size   размер областей
	 *
	 * @return       маска: все разряды единичны при равенстве областей
	 *
	 */
	static uint64_t match(const uint8_t * first, const uint8_t * second, const size_t size) noexcept {
		// Объединение различий байтов
		uint64_t result = 0;
		/**
		 * Выполняем перебор байтов областей
		 */
		for(size_t i = 0; i < size; i++)
			// Учитываем различие очередных байтов
			result |= (first[i] ^ second[i]);
		// Выводим маску равенства
		return same(result, 0);
	}
	/**
	 * @brief Метод получения записи DigestInfo алгоритма хеширования
	 *
	 * @details Раздел 9.2 RFC 8017, замечание 1: записи DigestInfo без самого хеша
	 *          для каждого допустимого алгоритма
	 *
	 * @param algorithm алгоритм хеширования
	 * @param size      переменная, в которую помещается длина записи
	 *
	 * @return          запись DigestInfo без хеша либо nullptr у недопустимого алгоритма
	 *
	 */
	static const uint8_t * prefix(const digest::hash_t algorithm, size_t & size) noexcept {
		// Запись DigestInfo хеша MD5
		static const uint8_t MD5[] = {0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
		// Запись DigestInfo хеша SHA-1
		static const uint8_t SHA1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
		// Запись DigestInfo хеша SHA-224
		static const uint8_t SHA224[] = {0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C};
		// Запись DigestInfo хеша SHA-256
		static const uint8_t SHA256[] = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
		// Запись DigestInfo хеша SHA-384
		static const uint8_t SHA384[] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
		// Запись DigestInfo хеша SHA-512
		static const uint8_t SHA512[] = {0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
		/**
		 * Определяем алгоритм хеширования
		 */
		switch(static_cast <uint8_t> (algorithm)){
			// Если алгоритм MD5
			case static_cast <uint8_t> (digest::hash_t::MD5): {
				// Запоминаем длину записи
				size = sizeof(MD5);
				// Выводим запись
				return MD5;
			}
			// Если алгоритм SHA-1
			case static_cast <uint8_t> (digest::hash_t::SHA1): {
				// Запоминаем длину записи
				size = sizeof(SHA1);
				// Выводим запись
				return SHA1;
			}
			// Если алгоритм SHA-224
			case static_cast <uint8_t> (digest::hash_t::SHA224): {
				// Запоминаем длину записи
				size = sizeof(SHA224);
				// Выводим запись
				return SHA224;
			}
			// Если алгоритм SHA-256
			case static_cast <uint8_t> (digest::hash_t::SHA256): {
				// Запоминаем длину записи
				size = sizeof(SHA256);
				// Выводим запись
				return SHA256;
			}
			// Если алгоритм SHA-384
			case static_cast <uint8_t> (digest::hash_t::SHA384): {
				// Запоминаем длину записи
				size = sizeof(SHA384);
				// Выводим запись
				return SHA384;
			}
			// Если алгоритм SHA-512
			case static_cast <uint8_t> (digest::hash_t::SHA512): {
				// Запоминаем длину записи
				size = sizeof(SHA512);
				// Выводим запись
				return SHA512;
			}
		}
		// Запоминаем нулевую длину
		size = 0;
		// Выводим отсутствие записи
		return nullptr;
	}
	/**
	 * @brief Метод выработки маски MGF1
	 *
	 * @details Приложение B.2.1 RFC 8017: маска собирается из хешей затравки с
	 *          приписанным счётчиком в четыре байта от старшего к младшему
	 *
	 * @param algorithm алгоритм хеширования
	 * @param seed      затравка маски
	 * @param size      длина затравки
	 * @param mask      место, в которое записывается маска
	 * @param length    длина маски
	 *
	 * @return          признак успешности выработки
	 *
	 */
	static bool mgf1(const digest::hash_t algorithm, const uint8_t * seed, const size_t size, uint8_t * mask, const size_t length) noexcept {
		// Длина хеша
		const size_t hash = digest::length(algorithm);
		// Если длина хеша неизвестна
		if((hash == 0) || (hash > HASH_SIZE))
			// Выводим отказ
			return false;
		// Объект хеширования
		digest::hasher_t hasher;
		// Место выработанного хеша
		uint8_t buffer[HASH_SIZE];
		/**
		 * Выполняем выработку маски кусками по длине хеша
		 */
		for(size_t offset = 0, counter = 0; offset < length; offset += hash, counter++){
			// Счётчик от старшего байта к младшему
			const uint8_t count[4] = {
				static_cast <uint8_t> (counter >> 24), static_cast <uint8_t> (counter >> 16),
				static_cast <uint8_t> (counter >> 8), static_cast <uint8_t> (counter)
			};
			// Сбрасываем хеширование
			hasher.reset(algorithm);
			// Подаём затравку
			hasher.update(view_t(seed, size));
			// Подаём счётчик
			hasher.update(view_t(count, sizeof(count)));
			// Снимаем хеш
			if(!hasher.finish(buffer, sizeof(buffer))){
				// Затираем хеш
				wipe(buffer, sizeof(buffer));
				// Выводим отказ
				return false;
			}
			// Длина очередного куска маски
			const size_t chunk = (((length - offset) < hash) ? (length - offset) : hash);
			/**
			 * Выполняем перебор байтов куска
			 */
			for(size_t i = 0; i < chunk; i++)
				// Записываем очередной байт маски
				mask[offset + i] = buffer[i];
		}
		// Затираем хеш
		wipe(buffer, sizeof(buffer));
		// Выводим признак успешности
		return true;
	}
	/**
	 * @brief Метод выработки хеша PSS
	 *
	 * @details Шаги 5 и 6 раздела 9.1.1 RFC 8017: хеш восьми нулевых байтов,
	 *          хеша сообщения и соли
	 *
	 * @param algorithm алгоритм хеширования
	 * @param digest    хеш сообщения
	 * @param salt      соль
	 * @param size      длина соли
	 * @param result    место, в которое записывается хеш
	 *
	 * @return          признак успешности выработки
	 *
	 */
	static bool salted(const digest::hash_t algorithm, const view_t & digest, const uint8_t * salt, const size_t size, uint8_t * result) noexcept {
		// Восемь нулевых байтов
		static const uint8_t ZEROS[8] = {};
		// Объект хеширования
		digest::hasher_t hasher;
		// Сбрасываем хеширование
		hasher.reset(algorithm);
		// Подаём нулевые байты
		hasher.update(view_t(ZEROS, sizeof(ZEROS)));
		// Подаём хеш сообщения
		hasher.update(digest);
		// Подаём соль
		hasher.update(view_t(salt, size));
		// Выводим итог снятия хеша
		return hasher.finish(result, HASH_SIZE);
	}
	/**
	 * @brief Метод записи числа элементом INTEGER кодировки DER
	 *
	 * @param writer записчик кодировки DER
	 * @param value  записываемое число
	 *
	 * @return       признак успешности записи
	 *
	 */
	static bool number(asn1::writer_t & writer, const math::integer_t & value) noexcept {
		// Байты числа с местом под ведущий ноль
		uint8_t buffer[math::INTEGER_SIZE + 1] = {};
		// Размер числа: у нуля один байт
		const size_t size = ((value.size() > 0) ? value.size() : 1);
		// Записываем число после ведущего нуля
		if(!value.store(buffer + 1, size))
			// Выводим отказ
			return false;
		// Ведущий ноль нужен при выставленном старшем разряде: число без знака
		const size_t offset = (((buffer[1] & 0x80) != 0) ? 0 : 1);
		// Записываем элемент
		const bool result = writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view_t(buffer + offset, size + 1 - offset));
		// Затираем байты числа
		wipe(buffer, sizeof(buffer));
		// Выводим итог записи
		return result;
	}
	/**
	 * @brief Метод затирания буфера записчика DER с его сбросом
	 *
	 * @details Записчик секретного ключа держит приватный DER (d, p, q, dp, dq, коэффициент)
	 *          в собственном буфере кучи; деструктор asn1::Writer пуст, а clear() буфер не
	 *          затирает, оттого приватный ключ ушёл бы в кучу незатёртым. Затираем как scrub
	 *          в keys.cpp - на всех путях выхода encode()
	 *
	 * @param writer затираемый записчик
	 *
	 */
	static void scrub(asn1::writer_t & writer) noexcept {
		// Получаем просмотр накопителя записчика целиком: на пути отказа data() пуст
		const view_t data = writer.buffer();
		// Если буфер записчика не пуст
		if((data.data != nullptr) && (data.size > 0))
			// Затираем буфер: память принадлежит записчику и постоянной не является
			wipe(const_cast <uint8_t *> (data.data), data.size);
		// Выполняем сброс записчика
		writer.clear();
	}
	/**
	 * @brief Метод копирования куска буфера с секретным началом за постоянное время
	 *
	 * @details Каждый байт итога собирается перебором всего буфера под маской
	 *          совпадения номера: ни адрес обращения, ни число шагов от начала
	 *          куска не зависят
	 *
	 * @param source буфер, из которого копируется кусок
	 * @param size   размер буфера
	 * @param start  секретный номер первого байта куска
	 * @param target место, в которое помещается кусок
	 * @param length число копируемых байтов: наибольшая возможная длина куска
	 *
	 */
	static void extract(const uint8_t * source, const size_t size, const size_t start, uint8_t * target, const size_t length) noexcept {
		/**
		 * Выполняем перебор байтов итога
		 */
		for(size_t i = 0; i < length; i++){
			// Собираемый байт
			uint8_t value = 0;
			/**
			 * Выполняем перебор байтов буфера
			 */
			for(size_t j = 0; j < size; j++)
				// Учитываем байт буфера под маской совпадения номера
				value |= (source[j] & static_cast <uint8_t> (same(j, start + i)));
			// Записываем собранный байт
			target[i] = value;
		}
	}
};

/**
 * @brief Метод выработки простого сомножителя ключа
 *
 * @param bits   число разрядов сомножителя
 * @param result место, в которое помещается сомножитель
 * @return       признак успешности выработки
 *
 */
bool nts::sign::Rsa::factor(const size_t bits, math::integer_t & result) const noexcept {
	// Старшие два разряда сомножителя
	math::integer_t top, one;
	// Записываем два единичных разряда
	top.word(3);
	// Сдвигаем разряды на место старших
	top.left(top, bits - 2);
	// Записываем единицу
	one.word(1);
	/**
	 * Выполняем попытки выработки сомножителя
	 */
	for(size_t i = 0; i < ATTEMPTS; i++){
		// Случайная часть сомножителя
		math::integer_t random;
		// Вырабатываем случайные младшие разряды
		if(!random.random(bits - 2))
			// Выводим отказ
			return false;
		// Дополняем случайную часть старшими разрядами
		result.add(random, top);
		// Если сомножитель чётный
		if(!result.odd())
			// Делаем сомножитель нечётным
			result.add(result, one);
		// Сомножитель без единицы и обратное к показателю
		math::integer_t lessened, inverse;
		// Вычисляем сомножитель без единицы
		lessened.subtract(result, one);
		// Если показатель не взаимно прост с сомножителем без единицы
		if(!inverse.invert(this->_exponent, lessened))
			// Пробуем следующего кандидата
			continue;
		// Если сомножитель простой
		if(result.prime())
			// Выводим признак успешности
			return true;
	}
	// Выводим отказ
	return false;
}
/**
 * @brief Метод вычисления производных составляющих секретного ключа
 *
 * @return признак успешности: показатель обратим по функции Кармайкла
 *
 */
bool nts::sign::Rsa::derive() noexcept {
	// Единица
	math::integer_t one;
	// Записываем единицу
	one.word(1);
	// Сомножители без единицы
	math::integer_t prime1, prime2;
	// Вычисляем первый сомножитель без единицы
	prime1.subtract(this->_prime1, one);
	// Вычисляем второй сомножитель без единицы
	prime2.subtract(this->_prime2, one);
	// Общий делитель сомножителей без единицы и функция Кармайкла
	math::integer_t divisor, quotient, carmichael;
	// Вычисляем общий делитель
	if(!divisor.gcd(prime1, prime2))
		// Выводим отказ
		return false;
	// Делим первый сомножитель без единицы на общий делитель
	if(!quotient.divide(prime1, divisor))
		// Выводим отказ
		return false;
	// Вычисляем наименьшее общее кратное: функцию Кармайкла модуля
	if(!carmichael.multiply(quotient, prime2))
		// Выводим отказ
		return false;
	// Обращаем открытый показатель по функции Кармайкла
	if(!this->_decryptor.invert(this->_exponent, carmichael))
		// Выводим отказ
		return false;
	/**
	 * Приложение A.1.1 FIPS 186-5 отвергает секретный показатель, не превышающий
	 * корня из модуля: такой ключ вскрывается по Винеру
	 */
	if(this->_decryptor.bits() <= (this->_bits / 2))
		// Выводим отказ
		return false;
	// Приводим секретный показатель по первому сомножителю без единицы
	if(!this->_exponent1.reduce(this->_decryptor, prime1))
		// Выводим отказ
		return false;
	// Приводим секретный показатель по второму сомножителю без единицы
	if(!this->_exponent2.reduce(this->_decryptor, prime2))
		// Выводим отказ
		return false;
	// Обращаем второй сомножитель по первому
	return this->_coefficient.invert(this->_prime2, this->_prime1);
}
/**
 * @brief Метод проверки готовности модуля к работе
 *
 * @return признак того, что открытый ключ установлен
 *
 */
bool nts::sign::Rsa::ready() const noexcept {
	// Выводим признак установленного открытого ключа
	return this->_public;
}
/**
 * @brief Метод проверки наличия секретного ключа
 *
 * @return признак того, что секретный ключ установлен
 *
 */
bool nts::sign::Rsa::secret() const noexcept {
	// Выводим признак установленного секретного ключа
	return this->_secret;
}
/**
 * @brief Метод получения размера модуля
 *
 * @return размер модуля в байтах: размер подписи и шифротекста
 *
 */
size_t nts::sign::Rsa::size() const noexcept {
	// Выводим размер модуля в байтах
	return ((this->_bits + 7) / 8);
}
/**
 * @brief Метод получения верхнего предела длины подписи в записанном виде
 *
 * @return верхний предел длины подписи в байтах, ноль без ключа
 *
 */
size_t nts::sign::Rsa::limit() const noexcept {
	// Подпись уходит наружу как есть: предел равен длине модуля
	return this->size();
}
/**
 * @brief Метод получения числа разрядов модуля
 *
 * @return число разрядов модуля
 *
 */
size_t nts::sign::Rsa::bits() const noexcept {
	// Выводим число разрядов модуля
	return this->_bits;
}
/**
 * @brief Метод сброса состояния модуля
 *
 */
void nts::sign::Rsa::clear() noexcept {
	// Снимаем признак открытого ключа
	this->_public = false;
	// Снимаем признак секретного ключа
	this->_secret = false;
	// Обнуляем число разрядов модуля
	this->_bits = 0;
	// Затираем модуль
	this->_modulus.clear();
	// Затираем открытый показатель
	this->_exponent.clear();
	// Затираем секретный показатель
	this->_decryptor.clear();
	// Затираем первый сомножитель
	this->_prime1.clear();
	// Затираем второй сомножитель
	this->_prime2.clear();
	// Затираем первый показатель
	this->_exponent1.clear();
	// Затираем второй показатель
	this->_exponent2.clear();
	// Затираем коэффициент
	this->_coefficient.clear();
	// Сбрасываем предвычисления по модулю и сомножителям
	this->_field.clear();
	this->_field1.clear();
	this->_field2.clear();
	this->_reverse.clear();
}
/**
 * @brief Метод порождения ключа
 *
 * @param bits     число разрядов модуля: 2048, 3072 либо 4096
 * @param exponent открытый показатель, нечётный и не меньше трёх
 * @return         признак успешности порождения
 *
 */
bool nts::sign::Rsa::generate(const size_t bits, const uint64_t exponent) noexcept {
	// Если число разрядов не из допустимых
	if((bits != 2048) && (bits != 3072) && (bits != 4096))
		// Выводим отказ
		return false;
	// Если показатель чётный, меньше трёх либо шире дозволенного (тот же предел, что у key())
	if(((exponent & 1) == 0) || (exponent < 3) || (exponent >= (static_cast <uint64_t> (1) << EXPONENT_BITS)))
		// Выводим отказ
		return false;
	// Сбрасываем состояние модуля
	this->clear();
	// Запоминаем число разрядов модуля
	this->_bits = bits;
	// Записываем открытый показатель
	this->_exponent.word(exponent);
	// Вырабатываем первый сомножитель
	if(!this->factor(bits / 2, this->_prime1)){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	/**
	 * Выполняем попытки выработки второго сомножителя: он обязан отстоять от
	 * первого не менее чем на сотню старших разрядов, а секретный показатель
	 * при нём - превышать корень из модуля
	 */
	for(size_t i = 0; i < ATTEMPTS; i++){
		// Вырабатываем второй сомножитель
		if(!this->factor(bits / 2, this->_prime2))
			// Прерываем перебор
			break;
		// Разность сомножителей
		math::integer_t difference;
		// Если первый сомножитель больше второго
		if(this->_prime1.compare(this->_prime2) > 0)
			// Вычитаем второй сомножитель из первого
			difference.subtract(this->_prime1, this->_prime2);
		// Если второй сомножитель не меньше первого
		else difference.subtract(this->_prime2, this->_prime1);
		// Если сомножители слишком близки
		if(difference.bits() <= ((bits / 2) - 100))
			// Пробуем следующего кандидата
			continue;
		// Вычисляем модуль
		if(!this->_modulus.multiply(this->_prime1, this->_prime2))
			// Прерываем перебор
			break;
		// Если модуль не той длины, что заказана
		if(this->_modulus.bits() != bits)
			// Пробуем следующего кандидата
			continue;
		// Если производные составляющие вычислены
		if(this->derive()){
			// Выставляем признак открытого ключа
			this->_public = true;
			// Выставляем признак секретного ключа
			this->_secret = true;
			// Если предвычисления по ключу выполнены
			if(this->prepare())
				// Выводим признак успешности
				return true;
			// Предвычисления не удались: ключ сбрасывается
			break;
		}
	}
	// Сбрасываем состояние модуля
	this->clear();
	// Выводим отказ
	return false;
}
/**
 * @brief Метод установки открытого ключа
 *
 * @param modulus  модуль n от старшего байта к младшему
 * @param exponent открытый показатель e от старшего байта к младшему
 * @return         признак успешности установки
 *
 */
bool nts::sign::Rsa::key(const view_t & modulus, const view_t & exponent) noexcept {
	// Сбрасываем состояние модуля
	this->clear();
	// Разбираем модуль
	if(!this->_modulus.load(modulus) || !this->_exponent.load(exponent)){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Запоминаем число разрядов модуля
	this->_bits = this->_modulus.bits();
	// Тройка: наименьший допустимый открытый показатель
	math::integer_t three;
	// Записываем тройку
	three.word(3);
	/**
	 * Модуль обязан быть нечётным и допустимой длины, показатель - нечётным,
	 * не меньше трёх и меньше модуля
	 */
	if((this->_bits < LEAST_BITS) || (this->_bits > math::INTEGER_BITS) || !this->_modulus.odd() ||
	   !this->_exponent.odd() || (this->_exponent.compare(three) < 0) || (this->_exponent.compare(this->_modulus) >= 0) || (this->_exponent.bits() > EXPONENT_BITS)){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Выставляем признак открытого ключа
	this->_public = true;
	// Если предвычисления по открытому ключу не удались
	if(!this->prepare()){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод установки секретного ключа
 *
 * @param modulus     модуль n
 * @param exponent    открытый показатель e
 * @param decryptor   секретный показатель d
 * @param prime1      первый простой сомножитель p
 * @param prime2      второй простой сомножитель q
 * @param exponent1   показатель dP
 * @param exponent2   показатель dQ
 * @param coefficient коэффициент qInv
 * @return            признак успешности установки: составляющие согласованы
 *
 */
bool nts::sign::Rsa::key(const view_t & modulus, const view_t & exponent, const view_t & decryptor, const view_t & prime1, const view_t & prime2, const view_t & exponent1, const view_t & exponent2, const view_t & coefficient) noexcept {
	// Устанавливаем открытый ключ
	if(!this->key(modulus, exponent))
		// Выводим отказ
		return false;
	// Разбираем секретные составляющие
	if(!this->_decryptor.load(decryptor) || !this->_prime1.load(prime1) || !this->_prime2.load(prime2) ||
	   !this->_exponent1.load(exponent1) || !this->_exponent2.load(exponent2) || !this->_coefficient.load(coefficient)){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Единица и произведение сомножителей
	math::integer_t one, product;
	// Записываем единицу
	one.word(1);
	/**
	 * Сомножители обязаны быть нечётными и больше единицы, а их произведение -
	 * равняться модулю; показатели и коэффициент - лежать в своих границах
	 */
	if(!this->_prime1.odd() || !this->_prime2.odd() || (this->_prime1.compare(one) <= 0) || (this->_prime2.compare(one) <= 0) ||
	   !product.multiply(this->_prime1, this->_prime2) || !product.equal(this->_modulus) ||
	   this->_decryptor.zero() || (this->_decryptor.compare(this->_modulus) >= 0) ||
	   this->_exponent1.zero() || (this->_exponent1.compare(this->_prime1) >= 0) ||
	   this->_exponent2.zero() || (this->_exponent2.compare(this->_prime2) >= 0) ||
	   this->_coefficient.zero() || (this->_coefficient.compare(this->_prime1) >= 0)){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Сомножители без единицы
	math::integer_t lessened1, lessened2;
	// Вычисляем первый сомножитель без единицы
	lessened1.subtract(this->_prime1, one);
	// Вычисляем второй сомножитель без единицы
	lessened2.subtract(this->_prime2, one);
	// Проверяемые значения
	math::integer_t item, unit;
	/**
	 * Показатели обязаны быть секретным показателем по сомножителям без единицы,
	 * произведение открытого и секретного показателей - единицей по ним же, а
	 * произведение коэффициента на второй сомножитель - единицей по первому
	 */
	if(!item.reduce(this->_decryptor, lessened1) || !item.equal(this->_exponent1) ||
	   !item.reduce(this->_decryptor, lessened2) || !item.equal(this->_exponent2) ||
	   !unit.mulmod(this->_exponent, this->_exponent1, lessened1, false) || !unit.equal(one) ||
	   !unit.mulmod(this->_exponent, this->_exponent2, lessened2, false) || !unit.equal(one) ||
	   !unit.mulmod(this->_coefficient, this->_prime2, this->_prime1, false) || !unit.equal(one)){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Выставляем признак секретного ключа
	this->_secret = true;
	// Если предвычисления по секретному ключу не удались
	if(!this->prepare()){
		// Сбрасываем состояние модуля
		this->clear();
		// Выводим отказ
		return false;
	}
	// Выводим признак успешности
	return true;
}
/**
 * @brief Метод получения размера составляющей ключа
 *
 * @param part составляющая ключа
 * @return     размер составляющей в байтах, ноль при её отсутствии
 *
 */
size_t nts::sign::Rsa::length(const part_t part) const noexcept {
	/**
	 * Определяем составляющую ключа
	 */
	switch(static_cast <uint8_t> (part)){
		// Если запрошен модуль
		case static_cast <uint8_t> (part_t::MODULUS):
			// Выводим размер модуля
			return (this->_public ? this->_modulus.size() : 0);
		// Если запрошен открытый показатель
		case static_cast <uint8_t> (part_t::PUBLIC):
			// Выводим размер открытого показателя
			return (this->_public ? this->_exponent.size() : 0);
		// Если запрошен секретный показатель
		case static_cast <uint8_t> (part_t::SECRET):
			// Выводим размер секретного показателя
			return (this->_secret ? this->_decryptor.size() : 0);
		// Если запрошен первый сомножитель
		case static_cast <uint8_t> (part_t::PRIME1):
			// Выводим размер первого сомножителя
			return (this->_secret ? this->_prime1.size() : 0);
		// Если запрошен второй сомножитель
		case static_cast <uint8_t> (part_t::PRIME2):
			// Выводим размер второго сомножителя
			return (this->_secret ? this->_prime2.size() : 0);
		// Если запрошен первый показатель
		case static_cast <uint8_t> (part_t::EXPONENT1):
			// Выводим размер первого показателя
			return (this->_secret ? this->_exponent1.size() : 0);
		// Если запрошен второй показатель
		case static_cast <uint8_t> (part_t::EXPONENT2):
			// Выводим размер второго показателя
			return (this->_secret ? this->_exponent2.size() : 0);
		// Если запрошен коэффициент
		case static_cast <uint8_t> (part_t::COEFFICIENT):
			// Выводим размер коэффициента
			return (this->_secret ? this->_coefficient.size() : 0);
	}
	// Выводим нулевой размер
	return 0;
}
/**
 * @brief Метод получения составляющей ключа
 *
 * @param part составляющая ключа
 * @param data место, в которое записывается составляющая от старшего байта к младшему
 * @param size размер места в байтах: составляющая дополняется ведущими нулями
 * @return     признак успешности: составляющая есть и умещается в размер
 *
 */
bool nts::sign::Rsa::part(const part_t part, uint8_t * data, const size_t size) const noexcept {
	// Если составляющей нет либо места нет
	if((this->length(part) == 0) || (data == nullptr))
		// Выводим отказ
		return false;
	/**
	 * Определяем составляющую ключа
	 */
	switch(static_cast <uint8_t> (part)){
		// Если запрошен модуль
		case static_cast <uint8_t> (part_t::MODULUS):
			// Выводим итог записи модуля
			return this->_modulus.store(data, size);
		// Если запрошен открытый показатель
		case static_cast <uint8_t> (part_t::PUBLIC):
			// Выводим итог записи открытого показателя
			return this->_exponent.store(data, size);
		// Если запрошен секретный показатель
		case static_cast <uint8_t> (part_t::SECRET):
			// Выводим итог записи секретного показателя
			return this->_decryptor.store(data, size);
		// Если запрошен первый сомножитель
		case static_cast <uint8_t> (part_t::PRIME1):
			// Выводим итог записи первого сомножителя
			return this->_prime1.store(data, size);
		// Если запрошен второй сомножитель
		case static_cast <uint8_t> (part_t::PRIME2):
			// Выводим итог записи второго сомножителя
			return this->_prime2.store(data, size);
		// Если запрошен первый показатель
		case static_cast <uint8_t> (part_t::EXPONENT1):
			// Выводим итог записи первого показателя
			return this->_exponent1.store(data, size);
		// Если запрошен второй показатель
		case static_cast <uint8_t> (part_t::EXPONENT2):
			// Выводим итог записи второго показателя
			return this->_exponent2.store(data, size);
		// Если запрошен коэффициент
		case static_cast <uint8_t> (part_t::COEFFICIENT):
			// Выводим итог записи коэффициента
			return this->_coefficient.store(data, size);
	}
	// Выводим отказ
	return false;
}
/**
 * @brief Метод записи ключа в кодировке DER
 *
 * @param secret признак записи секретного ключа
 * @param result место, в которое помещается запись
 * @return       признак успешности: ключ есть и памяти достало
 *
 */
bool nts::sign::Rsa::encode(const bool secret, vector <uint8_t> & result) const noexcept {
	// Если нужного ключа нет
	if(!this->_public || (secret && !this->_secret))
		// Выводим отказ
		return false;
	// Записчик кодировки DER
	asn1::writer_t writer;
	// Открываем набор полей ключа
	writer.open(asn1::tag_t::SEQUENCE);
	// Если записывается секретный ключ
	if(secret)
		// Записываем издание записи: без дополнительных сомножителей
		writer.integer(0);
	// Записываем модуль
	number(writer, this->_modulus);
	// Записываем открытый показатель
	number(writer, this->_exponent);
	// Если записывается секретный ключ
	if(secret){
		// Записываем секретный показатель
		number(writer, this->_decryptor);
		// Записываем первый сомножитель
		number(writer, this->_prime1);
		// Записываем второй сомножитель
		number(writer, this->_prime2);
		// Записываем первый показатель
		number(writer, this->_exponent1);
		// Записываем второй показатель
		number(writer, this->_exponent2);
		// Записываем коэффициент
		number(writer, this->_coefficient);
	}
	// Закрываем набор полей ключа
	writer.close();
	// Если запись не удалась
	if(writer.err() != asn1::error_t::NONE){
		// Затираем буфер записчика: приватный DER не должен уйти в кучу незатёртым
		scrub(writer);
		// Выводим отказ
		return false;
	}
	// Получаем собранную запись
	const view_t data = writer.data();
	// Признак успешности копирования записи
	bool copied = true;
	/**
	 * Копирование записи выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Копируем запись в место назначения
		result.assign(data.data, data.data + data.size);
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Запоминаем отказ копирования
		copied = false;
	}
	// Затираем буфер записчика на всех путях: приватный DER остаётся лишь в result у вызывающего
	scrub(writer);
	// Выводим признак успешности
	return copied;
}
/**
 * @brief Метод разбора ключа из кодировки DER
 *
 * @param data запись RSAPublicKey либо RSAPrivateKey
 * @return     признак успешности разбора
 *
 */
bool nts::sign::Rsa::decode(const view_t & data) noexcept {
	// Разборщик записи
	asn1::reader_t reader(data);
	// Набор полей ключа
	asn1::element_t sequence;
	// Разбираем набор полей ключа
	if(!reader.next(asn1::tag_t::SEQUENCE, sequence) || !sequence.constructed || !reader.empty())
		// Выводим отказ
		return false;
	// Разборщик полей ключа
	asn1::reader_t fields(sequence.content);
	// Просмотры содержимого полей
	view_t items[9];
	// Число разобранных полей
	size_t count = 0;
	/**
	 * Выполняем разбор полей ключа, пока они есть
	 */
	while(!fields.empty()){
		// Если полей больше, чем у секретного ключа
		if(count >= 9)
			// Выводим отказ
			return false;
		// Очередное поле
		asn1::element_t field;
		// Разбираем очередное целое число
		if(!fields.next(asn1::tag_t::INTEGER, field) || (asn1::integer(field, items[count]) != asn1::error_t::NONE))
			// Выводим отказ
			return false;
		// Если число отрицательно
		if((items[count].size == 0) || ((items[count].data[0] & 0x80) != 0))
			// Выводим отказ
			return false;
		// Учитываем разобранное поле
		count++;
	}
	// Если полей два, запись открытого ключа
	if(count == 2)
		// Выводим итог установки открытого ключа
		return this->key(items[0], items[1]);
	// Если полей девять, запись секретного ключа
	if(count == 9){
		// Издание записи обязано быть нулевым: дополнительных сомножителей нет
		if((items[0].size != 1) || (items[0].data[0] != 0))
			// Выводим отказ
			return false;
		// Выводим итог установки секретного ключа
		return this->key(items[1], items[2], items[3], items[4], items[5], items[6], items[7], items[8]);
	}
	// Выводим отказ
	return false;
}
/**
 * @brief Метод открытого действия RSA
 *
 * @param input  входное число, меньшее модуля, от старшего байта к младшему
 * @param output место, в которое записывается итог размером в модуль
 * @return       признак успешности: ключ установлен, число меньше модуля
 *
 */
bool nts::sign::Rsa::encipher(const view_t & input, uint8_t * output) const noexcept {
	// Если открытого ключа нет либо места нет
	if(!this->_public || (output == nullptr))
		// Выводим отказ
		return false;
	// Входное число
	math::integer_t value;
	// Разбираем входное число
	if(!value.load(input) || (value.compare(this->_modulus) >= 0))
		// Выводим отказ
		return false;
	// Итог действия
	math::integer_t result;
	// Возводим число в открытую степень арифметикой Монтгомери с предвычислениями: показатель открыт
	if(!this->_field.power(value, this->_exponent, false, result))
		// Выводим отказ
		return false;
	// Выводим итог записи
	return result.store(output, this->size());
}
/**
 * @brief Метод сборки числа по китайской теореме об остатках
 *
 * @param first  вычет по первому сомножителю
 * @param second вычет по второму сомножителю
 * @param result место, в которое помещается собранное число, меньшее модуля
 * @return       признак успешности сборки
 *
 * @note Сборка по Гарнеру: h = qInv·(first − second) mod p, итог = second + h·q.
 *       Все шаги идут за постоянное время: приведение вычета по второму сомножителю
 *       к первому - проходами Монтгомери, а не делением столбиком
 *
 */
bool nts::sign::Rsa::garner(const math::integer_t & first, const math::integer_t & second, math::integer_t & result) const noexcept {
	// Второй вычет, приведённый по первому сомножителю, его разность с первым вычетом, множитель и произведение
	math::integer_t reduced, difference, factor, product;
	// Приводим второй вычет по первому сомножителю за постоянное время: второй сомножитель бывает шире первого
	if(!this->_field1.reduce(second, reduced))
		// Выводим отказ
		return false;
	// Вычитаем по первому сомножителю за постоянное время
	if(!difference.submod(first, reduced, this->_prime1))
		// Выводим отказ
		return false;
	// Умножаем разность на коэффициент qInv: коэффициент лежит в области Монтгомери, оттого одно умножение
	if(!this->_field1.multiply(difference, this->_reverse, factor))
		// Выводим отказ
		return false;
	// Умножаем множитель на второй сомножитель
	if(!product.multiply(factor, this->_prime2))
		// Выводим отказ
		return false;
	// Складываем со вторым вычетом
	return result.add(second, product);
}
/**
 * @brief Метод предвычислений по установленному ключу
 *
 * @return признак успешности предвычислений
 *
 */
bool nts::sign::Rsa::prepare() noexcept {
	// Если открытого ключа нет либо арифметика по модулю не завелась
	if(!this->_public || !this->_field.start(this->_modulus))
		// Выводим отказ
		return false;
	// Если секретный ключ не установлен
	if(!this->_secret)
		// Выводим признак успешности
		return true;
	// Если арифметика по сомножителям не завелась
	if(!this->_field1.start(this->_prime1) || !this->_field2.start(this->_prime2))
		// Выводим отказ
		return false;
	// Переводим коэффициент qInv в область Монтгомери по первому сомножителю
	return this->_field1.enter(this->_coefficient, this->_reverse);
}
/**
 * @brief Метод секретного действия RSA
 *
 * @param input  входное число, меньшее модуля, от старшего байта к младшему
 * @param output место, в которое записывается итог размером в модуль
 * @return       признак успешности: секретный ключ установлен, число меньше модуля
 *
 */
bool nts::sign::Rsa::decipher(const view_t & input, uint8_t * output) const noexcept {
	// Если секретного ключа нет либо места нет
	if(!this->_secret || (output == nullptr))
		// Выводим отказ
		return false;
	// Входное число
	math::integer_t value;
	// Разбираем входное число: оно обязано быть меньше модуля
	if(!value.load(input) || (value.compare(this->_modulus) >= 0))
		// Выводим отказ
		return false;
	// Вычеты числа по сомножителям
	math::integer_t part1, part2;
	// Приводим число по сомножителям за постоянное время
	if(!this->_field1.reduce(value, part1) || !this->_field2.reduce(value, part2))
		// Выводим отказ
		return false;
	// Ослепляющие числа по сомножителям и обратные к ним
	math::integer_t blind1, blind2, inverse1, inverse2;
	// Признак того, что ослепляющие числа найдены
	bool found = false;
	/**
	 * Выбираем ослепляющие числа: ненулевые и обратимые по своим сомножителям
	 */
	for(size_t i = 0; (i < BLINDING) && !found; i++){
		// Берём случайные числа на разряд короче сомножителей: они заведомо меньше их
		if(!blind1.random(this->_prime1.bits() - 1) || !blind2.random(this->_prime2.bits() - 1))
			// Выводим отказ
			return false;
		// Числа годны, когда ненулевые и обратимые: обращение идёт за постоянное время
		found = (!blind1.zero() && !blind2.zero() && this->_field1.invert(blind1, inverse1) && this->_field2.invert(blind2, inverse2));
	}
	// Если ослепляющие числа не найдены
	if(!found)
		// Выводим отказ
		return false;
	// Ослепляющие числа в открытой степени
	math::integer_t raised1, raised2;
	// Возводим ослепляющие числа в открытую степень по сомножителям
	if(!this->_field1.power(blind1, this->_exponent, false, raised1) || !this->_field2.power(blind2, this->_exponent, false, raised2))
		// Выводим отказ
		return false;
	// Ослеплённые вычеты
	math::integer_t blinded1, blinded2;
	// Ослепляем вычеты
	if(!this->_field1.mulmod(part1, raised1, blinded1) || !this->_field2.mulmod(part2, raised2, blinded2))
		// Выводим отказ
		return false;
	// Степени по сомножителям
	math::integer_t power1, power2;
	// Возводим ослеплённые вычеты в секретные степени за постоянное время
	if(!this->_field1.power(blinded1, this->_exponent1, true, power1) || !this->_field2.power(blinded2, this->_exponent2, true, power2))
		// Выводим отказ
		return false;
	// Снимаем ослепление: секретная степень открытой степени ослепляющего числа есть само число
	if(!this->_field1.mulmod(power1, inverse1, power1) || !this->_field2.mulmod(power2, inverse2, power2))
		// Выводим отказ
		return false;
	// Итог действия
	math::integer_t result;
	// Собираем итог по китайской теореме об остатках
	if(!this->garner(power1, power2, result))
		// Выводим отказ
		return false;
	// Проверка итога
	math::integer_t check;
	// Возводим итог в открытую степень: расхождение со значением выдаёт сбой вычисления, и итог не выдаётся
	if(!this->_field.power(result, this->_exponent, false, check) || !check.equal(value))
		// Выводим отказ
		return false;
	// Выводим итог записи
	return result.store(output, this->size());
}
/**
 * @brief Метод выработки подписи
 *
 * @param scheme    схема подписи: PKCS1 либо PSS
 * @param algorithm алгоритм хеша сообщения
 * @param digest    хеш подписываемого сообщения
 * @param signature место, в которое записывается подпись размером в модуль
 * @param salt      длина соли PSS в байтах, по умолчанию длина хеша
 * @param random    соль PSS для проверок, по умолчанию вырабатывается случайно
 * @return          признак успешности выработки подписи
 *
 */
bool nts::sign::Rsa::make(const scheme_t scheme, const digest::hash_t algorithm, const view_t & digest, uint8_t * signature, const size_t salt, const view_t & random) const noexcept {
	// Если секретного ключа нет либо места нет
	if(!this->_secret || (signature == nullptr))
		// Выводим отказ
		return false;
	// Длина записи DigestInfo
	size_t size = 0;
	/**
	 * Алгоритм NONE означает подпись без DigestInfo над готовым хешем: раздел 7.4.3 RFC 4346
	 * (TLS 1.1) кладёт под PKCS #1 v1.5 голые 36 байтов MD5 ‖ SHA-1; лишь для схемы PKCS1
	 */
	const bool bare = ((algorithm == digest::hash_t::NONE) && (scheme == scheme_t::PKCS1));
	// Получаем запись DigestInfo: она же признак допустимости алгоритма; у голой подписи её нет
	const uint8_t * info = (bare ? nullptr : prefix(algorithm, size));
	// Длина хеша: у голой подписи - длина переданного хеша
	const size_t hash = (bare ? digest.size : digest::length(algorithm));
	// Если алгоритм недопустим либо хеш не той длины
	if((!bare && (info == nullptr)) || (hash == 0) || (hash > HASH_SIZE) || (hash != digest.size) || (digest.data == nullptr))
		// Выводим отказ
		return false;
	// Размер модуля в байтах
	const size_t modulus = this->size();
	// Собираемое закодированное сообщение
	uint8_t encoded[math::INTEGER_SIZE] = {};
	// Длина закодированного сообщения
	size_t length = 0;
	/**
	 * Определяем схему подписи
	 */
	switch(static_cast <uint8_t> (scheme)){
		// Если схема PKCS #1 v1.5
		case static_cast <uint8_t> (scheme_t::PKCS1): {
			// Раздел 9.2 RFC 8017: модуль обязан вмещать запись с дополнением в одиннадцать байтов
			if(modulus < (size + hash + 11))
				// Выводим отказ
				return false;
			// Записываем разделитель после ведущего нуля
			encoded[1] = 0x01;
			/**
			 * Выполняем заполнение дополнения байтами 0xFF
			 */
			for(size_t i = 2; i < (modulus - size - hash - 1); i++)
				// Записываем очередной байт дополнения
				encoded[i] = 0xFF;
			// Место записи DigestInfo
			uint8_t * place = (encoded + (modulus - size - hash));
			/**
			 * Выполняем запись DigestInfo
			 */
			for(size_t i = 0; i < size; i++)
				// Записываем очередной байт записи
				place[i] = info[i];
			/**
			 * Выполняем запись хеша
			 */
			for(size_t i = 0; i < hash; i++)
				// Записываем очередной байт хеша
				place[size + i] = digest.data[i];
			// Длина закодированного сообщения равна модулю
			length = modulus;
		} break;
		// Если схема PSS
		case static_cast <uint8_t> (scheme_t::PSS): {
			// Число разрядов закодированного сообщения: на разряд меньше модуля
			const size_t bits = (this->_bits - 1);
			// Длина закодированного сообщения
			length = ((bits + 7) / 8);
			// Длина соли
			const size_t salted = ((salt == SIZE_MAX) ? hash : salt);
			// Если соль подана, её длина обязана равняться заказанной
			if((random.size > 0) && ((random.size != salted) || (random.data == nullptr)))
				// Выводим отказ
				return false;
			// Шаг 3 раздела 9.1.1 RFC 8017: сообщение обязано вмещать хеш, соль и два байта
			if(length < (hash + salted + 2))
				// Выводим отказ
				return false;
			// Соль подписи
			uint8_t seasoning[math::INTEGER_SIZE];
			// Если соль подана
			if(random.size > 0){
				/**
				 * Выполняем копирование поданной соли
				 */
				for(size_t i = 0; i < salted; i++)
					// Записываем очередной байт соли
					seasoning[i] = random.data[i];
			// Если соль вырабатывается случайно
			} else if((salted > 0) && !entropy::bytes(seasoning, salted))
				// Выводим отказ
				return false;
			// Хеш соли с хешем сообщения
			uint8_t hashed[HASH_SIZE];
			// Вырабатываем хеш соли с хешем сообщения
			if(!::salted(algorithm, digest, seasoning, salted, hashed)){
				// Затираем соль
				wipe(seasoning, sizeof(seasoning));
				// Выводим отказ
				return false;
			}
			// Длина блока данных
			const size_t block = (length - hash - 1);
			// Записываем разделитель блока данных перед солью
			encoded[block - salted - 1] = 0x01;
			/**
			 * Выполняем запись соли в блок данных
			 */
			for(size_t i = 0; i < salted; i++)
				// Записываем очередной байт соли
				encoded[block - salted + i] = seasoning[i];
			// Затираем соль
			wipe(seasoning, sizeof(seasoning));
			// Маска блока данных
			uint8_t mask[math::INTEGER_SIZE];
			// Вырабатываем маску блока данных
			if(!mgf1(algorithm, hashed, hash, mask, block))
				// Выводим отказ
				return false;
			/**
			 * Выполняем наложение маски на блок данных
			 */
			for(size_t i = 0; i < block; i++)
				// Накладываем очередной байт маски
				encoded[i] ^= mask[i];
			// Обнуляем разряды старшего байта сверх числа разрядов сообщения
			encoded[0] &= static_cast <uint8_t> (0xFF >> ((8 * length) - bits));
			/**
			 * Выполняем запись хеша после блока данных
			 */
			for(size_t i = 0; i < hash; i++)
				// Записываем очередной байт хеша
				encoded[block + i] = hashed[i];
			// Записываем завершающий байт
			encoded[length - 1] = 0xBC;
		} break;
		// Если схема иная
		default:
			// Выводим отказ
			return false;
	}
	// Выполняем секретное действие над закодированным сообщением
	const bool result = this->decipher(view_t(encoded, length), signature);
	// Затираем закодированное сообщение
	wipe(encoded, sizeof(encoded));
	// Выводим итог выработки
	return result;
}
/**
 * @brief Метод проверки подписи
 *
 * @param scheme    схема подписи: PKCS1 либо PSS
 * @param algorithm алгоритм хеша сообщения
 * @param digest    хеш подписанного сообщения
 * @param signature проверяемая подпись размером в модуль
 * @param salt      длина соли PSS в байтах, по умолчанию длина хеша
 * @return          признак подлинности подписи
 *
 */
bool nts::sign::Rsa::check(const scheme_t scheme, const digest::hash_t algorithm, const view_t & digest, const view_t & signature, const size_t salt) const noexcept {
	// Если открытого ключа нет
	if(!this->_public)
		// Выводим отказ
		return false;
	// Длина записи DigestInfo
	size_t size = 0;
	// Алгоритм NONE означает проверку без DigestInfo над готовым хешем (TLS 1.1), лишь для PKCS1
	const bool bare = ((algorithm == digest::hash_t::NONE) && (scheme == scheme_t::PKCS1));
	// Получаем запись DigestInfo: она же признак допустимости алгоритма; у голой подписи её нет
	const uint8_t * info = (bare ? nullptr : prefix(algorithm, size));
	// Длина хеша: у голой подписи - длина переданного хеша
	const size_t hash = (bare ? digest.size : digest::length(algorithm));
	// Размер модуля в байтах
	const size_t modulus = this->size();
	// Если алгоритм недопустим, хеш либо подпись не той длины
	if((!bare && (info == nullptr)) || (hash == 0) || (hash > HASH_SIZE) || (hash != digest.size) || (digest.data == nullptr) || (signature.size != modulus) || (signature.data == nullptr))
		// Выводим отказ
		return false;
	// Закодированное сообщение из подписи
	uint8_t encoded[math::INTEGER_SIZE];
	// Выполняем открытое действие над подписью
	if(!this->encipher(signature, encoded))
		// Выводим отказ
		return false;
	/**
	 * Определяем схему подписи
	 */
	switch(static_cast <uint8_t> (scheme)){
		// Если схема PKCS #1 v1.5
		case static_cast <uint8_t> (scheme_t::PKCS1): {
			// Если модуль не вмещает запись с дополнением
			if(modulus < (size + hash + 11))
				// Выводим отказ
				return false;
			// Ожидаемое закодированное сообщение
			uint8_t expected[math::INTEGER_SIZE] = {};
			// Записываем разделитель после ведущего нуля
			expected[1] = 0x01;
			/**
			 * Выполняем заполнение дополнения байтами 0xFF
			 */
			for(size_t i = 2; i < (modulus - size - hash - 1); i++)
				// Записываем очередной байт дополнения
				expected[i] = 0xFF;
			// Место записи DigestInfo
			uint8_t * place = (expected + (modulus - size - hash));
			/**
			 * Выполняем запись DigestInfo
			 */
			for(size_t i = 0; i < size; i++)
				// Записываем очередной байт записи
				place[i] = info[i];
			/**
			 * Выполняем запись хеша
			 */
			for(size_t i = 0; i < hash; i++)
				// Записываем очередной байт хеша
				place[size + i] = digest.data[i];
			/**
			 * Сличается закодированное сообщение целиком, а не разбирается: разбор
			 * с допущением лишних байтов и открывал подделку Блейхенбахера 2006 года
			 */
			return (match(encoded, expected, modulus) != 0);
		}
		// Если схема PSS
		case static_cast <uint8_t> (scheme_t::PSS): {
			// Число разрядов закодированного сообщения: на разряд меньше модуля
			const size_t bits = (this->_bits - 1);
			// Длина закодированного сообщения
			const size_t length = ((bits + 7) / 8);
			// Длина соли
			const size_t salted = ((salt == SIZE_MAX) ? hash : salt);
			// Если сообщение не вмещает хеш, соль и два байта
			if(length < (hash + salted + 2))
				// Выводим отказ
				return false;
			// Если сообщение короче модуля, ведущие байты обязаны быть нулями
			if((length < modulus) && (encoded[0] != 0))
				// Выводим отказ
				return false;
			// Начало закодированного сообщения внутри итога открытого действия
			const uint8_t * message = (encoded + (modulus - length));
			// Если завершающий байт не тот
			if(message[length - 1] != 0xBC)
				// Выводим отказ
				return false;
			// Длина блока данных
			const size_t block = (length - hash - 1);
			// Если разряды старшего байта сверх числа разрядов сообщения не нулевые
			if((message[0] & static_cast <uint8_t> (0xFF << (8 - ((8 * length) - bits)))) != 0)
				// Выводим отказ
				return false;
			// Маска блока данных
			uint8_t mask[math::INTEGER_SIZE];
			// Вырабатываем маску блока данных по хешу из сообщения
			if(!mgf1(algorithm, message + block, hash, mask, block))
				// Выводим отказ
				return false;
			// Блок данных
			uint8_t data[math::INTEGER_SIZE];
			/**
			 * Выполняем снятие маски с блока данных
			 */
			for(size_t i = 0; i < block; i++)
				// Снимаем очередной байт маски
				data[i] = (message[i] ^ mask[i]);
			// Обнуляем разряды старшего байта сверх числа разрядов сообщения
			data[0] &= static_cast <uint8_t> (0xFF >> ((8 * length) - bits));
			// Объединение байтов дополнения: обязаны быть нулями
			uint8_t padding = 0;
			/**
			 * Выполняем перебор байтов дополнения перед разделителем
			 */
			for(size_t i = 0; i < (block - salted - 1); i++)
				// Учитываем очередной байт дополнения
				padding |= data[i];
			// Если дополнение не нулевое либо разделитель не тот
			if((padding != 0) || (data[block - salted - 1] != 0x01))
				// Выводим отказ
				return false;
			// Хеш соли с хешем сообщения
			uint8_t hashed[HASH_SIZE];
			// Вырабатываем хеш соли из блока данных с хешем сообщения
			if(!::salted(algorithm, digest, data + (block - salted), salted, hashed))
				// Выводим отказ
				return false;
			// Выводим итог сличения хешей
			return (match(hashed, message + block, hash) != 0);
		}
	}
	// Выводим отказ
	return false;
}
/**
 * @brief Метод шифрования сообщения
 *
 * @param scheme    схема шифрования: PKCS1 либо OAEP
 * @param algorithm алгоритм хеша OAEP, для PKCS1 не используется
 * @param message   шифруемое сообщение
 * @param output    место, в которое записывается шифротекст размером в модуль
 * @param label     метка OAEP, по умолчанию пустая
 * @param random    затравка OAEP либо дополнение PKCS1 для проверок, по умолчанию вырабатываются случайно
 * @return          признак успешности: сообщение умещается в модуль с дополнением
 *
 */
bool nts::sign::Rsa::encrypt(const scheme_t scheme, const digest::hash_t algorithm, const view_t & message, uint8_t * output, const view_t & label, const view_t & random) const noexcept {
	// Если открытого ключа нет либо места нет
	if(!this->_public || (output == nullptr) || ((message.data == nullptr) && (message.size > 0)))
		// Выводим отказ
		return false;
	// Размер модуля в байтах
	const size_t modulus = this->size();
	// Собираемое закодированное сообщение
	uint8_t encoded[math::INTEGER_SIZE] = {};
	/**
	 * Определяем схему шифрования
	 */
	switch(static_cast <uint8_t> (scheme)){
		// Если схема PKCS #1 v1.5
		case static_cast <uint8_t> (scheme_t::PKCS1): {
			// Раздел 7.2.1 RFC 8017: сообщение не длиннее модуля без одиннадцати байтов
			if(message.size > (modulus - 11))
				// Выводим отказ
				return false;
			// Длина дополнения
			const size_t padding = (modulus - message.size - 3);
			// Если дополнение подано, его длина обязана равняться нужной
			if((random.size > 0) && ((random.size != padding) || (random.data == nullptr)))
				// Выводим отказ
				return false;
			// Записываем признак вида блока после ведущего нуля
			encoded[1] = 0x02;
			/**
			 * Выполняем заполнение дополнения ненулевыми байтами
			 */
			for(size_t i = 0; i < padding; i++){
				// Если дополнение подано
				if(random.size > 0){
					// Поданный байт дополнения обязан быть ненулевым
					if(random.data[i] == 0)
						// Выводим отказ
						return false;
					// Записываем поданный байт дополнения
					encoded[2 + i] = random.data[i];
				// Если дополнение вырабатывается случайно
				} else {
					/**
					 * Выполняем выработку байта, пока он нулевой
					 */
					do {
						// Вырабатываем случайный байт
						if(!entropy::bytes(encoded + 2 + i, 1))
							// Выводим отказ
							return false;
					} while(encoded[2 + i] == 0);
				}
			}
			/**
			 * Выполняем запись сообщения после нулевого разделителя
			 */
			for(size_t i = 0; i < message.size; i++)
				// Записываем очередной байт сообщения
				encoded[3 + padding + i] = message.data[i];
		} break;
		// Если схема OAEP
		case static_cast <uint8_t> (scheme_t::OAEP): {
			// Длина записи DigestInfo: не нужна, служит признаком допустимости алгоритма
			size_t size = 0;
			// Длина хеша
			const size_t hash = digest::length(algorithm);
			// Если алгоритм недопустим
			if((prefix(algorithm, size) == nullptr) || (hash == 0) || (hash > HASH_SIZE))
				// Выводим отказ
				return false;
			// Раздел 7.1.1 RFC 8017: сообщение не длиннее модуля без двух хешей и двух байтов
			if((modulus < ((2 * hash) + 2)) || (message.size > (modulus - (2 * hash) - 2)))
				// Выводим отказ
				return false;
			// Если затравка подана, её длина обязана равняться длине хеша
			if((random.size > 0) && ((random.size != hash) || (random.data == nullptr)))
				// Выводим отказ
				return false;
			// Длина блока данных
			const size_t block = (modulus - hash - 1);
			// Место блока данных: после ведущего нуля и затравки
			uint8_t * data = (encoded + 1 + hash);
			// Вырабатываем хеш метки в начало блока данных
			if(!digest::hash(algorithm, label, data, HASH_SIZE))
				// Выводим отказ
				return false;
			// Записываем разделитель перед сообщением
			data[block - message.size - 1] = 0x01;
			/**
			 * Выполняем запись сообщения в конец блока данных
			 */
			for(size_t i = 0; i < message.size; i++)
				// Записываем очередной байт сообщения
				data[block - message.size + i] = message.data[i];
			// Место затравки: после ведущего нуля
			uint8_t * seed = (encoded + 1);
			// Если затравка подана
			if(random.size > 0){
				/**
				 * Выполняем копирование поданной затравки
				 */
				for(size_t i = 0; i < hash; i++)
					// Записываем очередной байт затравки
					seed[i] = random.data[i];
			// Если затравка вырабатывается случайно
			} else if(!entropy::bytes(seed, hash))
				// Выводим отказ
				return false;
			// Маска
			uint8_t mask[math::INTEGER_SIZE];
			// Вырабатываем маску блока данных по затравке
			if(!mgf1(algorithm, seed, hash, mask, block)){
				// Затираем закодированное сообщение
				wipe(encoded, sizeof(encoded));
				// Выводим отказ
				return false;
			}
			/**
			 * Выполняем наложение маски на блок данных
			 */
			for(size_t i = 0; i < block; i++)
				// Накладываем очередной байт маски
				data[i] ^= mask[i];
			// Вырабатываем маску затравки по блоку данных под маской
			if(!mgf1(algorithm, data, block, mask, hash)){
				// Затираем закодированное сообщение
				wipe(encoded, sizeof(encoded));
				// Выводим отказ
				return false;
			}
			/**
			 * Выполняем наложение маски на затравку
			 */
			for(size_t i = 0; i < hash; i++)
				// Накладываем очередной байт маски
				seed[i] ^= mask[i];
			// Затираем маску
			wipe(mask, sizeof(mask));
		} break;
		// Если схема иная
		default:
			// Выводим отказ
			return false;
	}
	// Выполняем открытое действие над закодированным сообщением
	const bool result = this->encipher(view_t(encoded, modulus), output);
	// Затираем закодированное сообщение
	wipe(encoded, sizeof(encoded));
	// Выводим итог шифрования
	return result;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param scheme    схема шифрования: PKCS1 либо OAEP
 * @param algorithm алгоритм хеша OAEP, для PKCS1 не используется
 * @param input     шифротекст размером в модуль
 * @param output    место, в которое записывается сообщение: не меньше размера модуля
 * @param size      переменная, в которую помещается длина сообщения
 * @param label     метка OAEP, по умолчанию пустая
 * @return          признак успешности: дополнение верно
 *
 */
bool nts::sign::Rsa::decrypt(const scheme_t scheme, const digest::hash_t algorithm, const view_t & input, uint8_t * output, size_t & size, const view_t & label) const noexcept {
	// Обнуляем длину сообщения
	size = 0;
	// Размер модуля в байтах
	const size_t modulus = this->size();
	// Если секретного ключа нет, места нет либо шифротекст не размером в модуль
	if(!this->_secret || (output == nullptr) || (input.size != modulus) || (input.data == nullptr))
		// Выводим отказ
		return false;
	// Закодированное сообщение
	uint8_t encoded[math::INTEGER_SIZE];
	// Выполняем секретное действие над шифротекстом
	if(!this->decipher(input, encoded))
		// Выводим отказ
		return false;
	// Маска верности дополнения
	uint64_t good = 0;
	// Номер байта, с которого начинается сообщение
	uint64_t start = 0;
	// Наибольшая длина сообщения
	size_t most = 0;
	/**
	 * Определяем схему шифрования
	 */
	switch(static_cast <uint8_t> (scheme)){
		// Если схема PKCS #1 v1.5
		case static_cast <uint8_t> (scheme_t::PKCS1): {
			// Если модуль не вмещает дополнение
			if(modulus < 11){
				// Затираем закодированное сообщение
				wipe(encoded, sizeof(encoded));
				// Выводим отказ
				return false;
			}
			// Проверяем ведущий ноль и признак вида блока
			good = (same(encoded[0], 0x00) & same(encoded[1], 0x02));
			// Маска признака найденного разделителя
			uint64_t found = 0;
			/**
			 * Выполняем розыск нулевого разделителя по всему сообщению: перебор не
			 * прерывается, а место запоминается под маской первой находки
			 */
			for(size_t i = 2; i < modulus; i++){
				// Маска первой находки нулевого байта
				const uint64_t take = (same(encoded[i], 0x00) & ~found);
				// Запоминаем место находки под маской
				start = select(take, static_cast <uint64_t> (i + 1), start);
				// Учитываем находку
				found |= take;
			}
			// Разделитель обязан быть найден после дополнения не короче восьми байтов
			good &= (found & ~below(start, PADDING + 3));
			// Наибольшая длина сообщения
			most = (modulus - 11);
		} break;
		// Если схема OAEP
		case static_cast <uint8_t> (scheme_t::OAEP): {
			// Длина записи DigestInfo: не нужна, служит признаком допустимости алгоритма
			size_t count = 0;
			// Длина хеша
			const size_t hash = digest::length(algorithm);
			// Если алгоритм недопустим либо модуль не вмещает дополнение
			if((prefix(algorithm, count) == nullptr) || (hash == 0) || (hash > HASH_SIZE) || (modulus < ((2 * hash) + 2))){
				// Затираем закодированное сообщение
				wipe(encoded, sizeof(encoded));
				// Выводим отказ
				return false;
			}
			// Длина блока данных
			const size_t block = (modulus - hash - 1);
			// Затравка под маской и блок данных под маской
			uint8_t * seed = (encoded + 1), * data = (encoded + 1 + hash);
			// Маска и хеш метки
			uint8_t mask[math::INTEGER_SIZE], labelled[HASH_SIZE];
			// Вырабатываем хеш метки и маску затравки по блоку данных под маской
			if(!digest::hash(algorithm, label, labelled, sizeof(labelled)) || !mgf1(algorithm, data, block, mask, hash)){
				// Затираем закодированное сообщение
				wipe(encoded, sizeof(encoded));
				// Выводим отказ
				return false;
			}
			/**
			 * Выполняем снятие маски с затравки
			 */
			for(size_t i = 0; i < hash; i++)
				// Снимаем очередной байт маски
				seed[i] ^= mask[i];
			// Вырабатываем маску блока данных по затравке
			if(!mgf1(algorithm, seed, hash, mask, block)){
				// Затираем закодированное сообщение
				wipe(encoded, sizeof(encoded));
				// Выводим отказ
				return false;
			}
			/**
			 * Выполняем снятие маски с блока данных
			 */
			for(size_t i = 0; i < block; i++)
				// Снимаем очередной байт маски
				data[i] ^= mask[i];
			// Затираем маску
			wipe(mask, sizeof(mask));
			// Проверяем ведущий ноль и хеш метки
			good = (same(encoded[0], 0x00) & match(data, labelled, hash));
			// Маски признаков найденного разделителя и порчи дополнения
			uint64_t found = 0, broken = 0;
			/**
			 * Выполняем розыск единичного разделителя по всему блоку данных: до
			 * него допустимы лишь нули, перебор не прерывается
			 */
			for(size_t i = hash; i < block; i++){
				// Маски единичного и нулевого байта
				const uint64_t one = same(data[i], 0x01), zero = same(data[i], 0x00);
				// Маска первой находки разделителя
				const uint64_t take = (one & ~found);
				// До разделителя всякий байт, кроме нуля и единицы, портит дополнение
				broken |= (~found & ~one & ~zero);
				// Запоминаем место находки под маской
				start = select(take, static_cast <uint64_t> (i + 1), start);
				// Учитываем находку
				found |= take;
			}
			// Разделитель обязан быть найден, а дополнение - не испорчено
			good &= (found & ~broken);
			// Наибольшая длина сообщения
			most = (modulus - (2 * hash) - 2);
			// Место сообщения считается от начала закодированного сообщения
			start += (1 + hash);
		} break;
		// Если схема иная
		default: {
			// Затираем закодированное сообщение
			wipe(encoded, sizeof(encoded));
			// Выводим отказ
			return false;
		}
	}
	// Копируем сообщение за постоянное время по наибольшей длине
	extract(encoded, modulus, static_cast <size_t> (start), output, most);
	// Записываем длину сообщения под маской верности дополнения
	size = static_cast <size_t> ((modulus - start) & good);
	// Затираем закодированное сообщение
	wipe(encoded, sizeof(encoded));
	// Выводим признак верности дополнения
	return ((good & 1) == 1);
}
/**
 * @brief Конструктор
 *
 */
nts::sign::Rsa::Rsa() noexcept : _public(false), _secret(false), _bits(0) {}
/**
 * @brief Деструктор
 *
 */
nts::sign::Rsa::~Rsa() noexcept {
	// Сбрасываем состояние модуля
	this->clear();
}
