/**
 * @file noise.cpp
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
 * @brief Модуль описания каркаса Noise: наборы, имена протоколов, обмен ключами
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартный заголовочный файл
 */
#include <cstring>

/**
 * Подключаем заголовочный файл проекта
 */
#include "agreement/x25519.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "noise/noise.hpp"

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на пространство имён каркаса
	 */
	using namespace nts::noise;

	/**
	 * @brief Функция возврата имени обмена ключами в протоколе
	 *
	 * @param dhKind функция обмена ключами
	 * @return   имя либо пустая строка
	 *
	 */
	static constexpr const char * __nts_dhname__(const dh_t dhKind) noexcept {
		// Выводим имя по функции
		return ((dhKind == dh_t::X25519) ? "25519" : "");
	}
	/**
	 * @brief Функция возврата имени механизма упаковки ключа в протоколе
	 *
	 * @param kem механизм
	 * @return    имя либо пустая строка
	 *
	 */
	static constexpr const char * __nts_kemname__(const kem_t kem) noexcept {
		/**
		 * Определяем механизм
		 */
		switch(static_cast <uint8_t> (kem)){
			// Чистый ML-KEM-768
			case static_cast <uint8_t> (kem_t::MLKEM768):
				return "MLKEM768";
			// Составной механизм
			case static_cast <uint8_t> (kem_t::X25519MLKEM768):
				return "X25519MLKEM768";
			// Прочие механизмы
			default: return "";
		}
	}
	/**
	 * @brief Функция возврата имени шифрования в протоколе
	 *
	 * @param aead функция шифрования
	 * @return     имя либо пустая строка
	 *
	 */
	static constexpr const char * __nts_aeadname__(const aead_t aead) noexcept {
		/**
		 * Определяем функцию
		 */
		switch(static_cast <uint8_t> (aead)){
			// AES-256-GCM
			case static_cast <uint8_t> (aead_t::AESGCM):
				return "AESGCM";
			// ChaCha20-Poly1305
			case static_cast <uint8_t> (aead_t::CHACHAPOLY):
				return "ChaChaPoly";
			// Прочие механизмы
			default: return "";
		}
	}
	/**
	 * @brief Функция возврата имени хеширования в протоколе
	 *
	 * @param hash функция хеширования
	 * @return     имя либо пустая строка
	 *
	 */
	static constexpr const char * __nts_hashname__(const nts::digest::hash_t hash) noexcept {
		/**
		 * Определяем функцию
		 */
		switch(static_cast <uint8_t> (hash)){
			// SHA-256
			case static_cast <uint8_t> (nts::digest::hash_t::SHA256):
				return "SHA256";
			// SHA-512
			case static_cast <uint8_t> (nts::digest::hash_t::SHA512):
				return "SHA512";
			// BLAKE2s
			case static_cast <uint8_t> (nts::digest::hash_t::BLAKE2S256):
				return "BLAKE2s";
			// BLAKE2b
			case static_cast <uint8_t> (nts::digest::hash_t::BLAKE2B512):
				return "BLAKE2b";
			// Прочие механизмы
			default: return "";
		}
	}
	/**
	 * @brief Функция дописывания строки в место имени
	 *
	 * @param text   строка
	 * @param result место имени
	 * @param size   вместимость места
	 * @param offset текущая длина имени
	 * @return       признак того, что строка уместилась
	 *
	 */
	static __NTS_INLINE__ bool __nts_append__(const char * text, char * result, const size_t size, size_t & offset) noexcept {
		// Длина строки
		const size_t length = ::strlen(text);
		// Если строка не умещается
		if((offset + length) >= size)
			// Выводим отрицательный результат - строка не уместилась
			return false;
		// Дописываем строку
		::memcpy(result + offset, text, length);
		// Сдвигаем длину имени
		offset += length;
		// Завершаем строку нулём
		result[offset] = 0;
		// Строка дописана
		return true;
	}
	/**
	 * @brief Функция сличения отрезка имени со строкой
	 *
	 * @param data   отрезок
	 * @param size   длина отрезка
	 * @param text   строка
	 * @return       признак совпадения
	 *
	 */
	static __NTS_INLINE__ bool __nts_same__(const uint8_t * data, const size_t size, const char * text) noexcept {
		// Выводим итог сличения при равной длине
		return ((::strlen(text) == size) && (::memcmp(data, text, size) == 0));
	}
};

/**
 * @brief Функция проверки годности набора: X25519 и один из хешей SHA256, SHA512, BLAKE2s, BLAKE2b
 *
 * @param suite набор примитивов
 * @return      признак годности
 *
 */
bool nts::noise::valid(const suite_t & suite) noexcept {
	// Ровно одно из двух: DH классики либо KEM PQNoise, и оба имени шифра и хеша
	return (
		((suite.dh == dh_t::X25519) != (::__nts_kemname__(suite.kem)[0] != 0)) && ((suite.dh == dh_t::X25519) ||
		(suite.dh == dh_t::NONE)) && (::__nts_aeadname__(suite.aead)[0] != 0) && (::__nts_hashname__(suite.hash)[0] != 0)
	);
}
/**
 * @brief Функция составления имени протокола вида «Noise_XXpsk3_25519_ChaChaPoly_SHA256»
 *
 * @param pattern узор рукопожатия
 * @param psks    положения заранее разделённых ключей
 * @param suite   набор примитивов
 * @param result  место имени, не короче NAME_LIMIT
 * @param size    на входе вместимость места, на выходе длина имени без завершающего нуля
 * @return        признак того, что имя составлено
 *
 */
bool nts::noise::name(const pattern_t pattern, const psk_t psks, const suite_t & suite, char * result, size_t & size) noexcept {
	// Признак PQNoise у узора
	const bool postQuantum = postquantum(pattern);
	// Если место либо узор негодны, узор и набор разных семейств, либо psk у PQNoise
	if((result == nullptr) || (size == 0) || (title(pattern)[0] == 0) || !valid(suite) || ((psks >> PSKS_MAX) != 0) || (postQuantum != (suite.kem != kem_t::NONE)) || (postQuantum && (psks != 0)))
		// Выводим отрицательный результат - имя не составлено
		return false;
	// Текущая длина имени
	size_t offset = 0;
	// Признак первого видоизменения
	bool first = true;
	// Признак успешности
	bool status = (::__nts_append__(postQuantum ? "PQNoise_" : "Noise_", result, size, offset) && ::__nts_append__(title(pattern), result, size, offset));
	/**
	 * Перебираем положения заранее разделённых ключей
	 */
	for(size_t i = 0; status && (i < PSKS_MAX); i++){
		// Если положение занято
		if((psks >> i) & 1){
			// Строка видоизменения
			char text[] = {'+', 'p', 's', 'k', static_cast <char> ('0' + i), 0};
			// Дописываем видоизменение: у первого без знака сложения
			status = ::__nts_append__(first ? (text + 1) : text, result, size, offset);
			// Снимаем признак первого
			first = false;
		}
	}
	// Дописываем набор примитивов: DH классики либо KEM PQNoise
	status = (status && ::__nts_append__("_", result, size, offset) && ::__nts_append__(postQuantum ? ::__nts_kemname__(suite.kem) : ::__nts_dhname__(suite.dh), result, size, offset) && ::__nts_append__("_", result, size, offset) && ::__nts_append__(::__nts_aeadname__(suite.aead), result, size, offset) && ::__nts_append__("_", result, size, offset) && ::__nts_append__(::__nts_hashname__(suite.hash), result, size, offset));
	// Выводим длину имени
	size = (status ? offset : 0);
	// Возвращаем итог составления имени
	return status;
}
/**
 * @brief Функция разбора имени протокола
 *
 * @param text    имя протокола
 * @param pattern узор рукопожатия
 * @param psks    положения заранее разделённых ключей
 * @param suite   набор примитивов
 * @return        признак того, что имя разобрано целиком и набор поддержан
 *
 */
bool nts::noise::parse(const view_t & text, pattern_t & pattern, psk_t & psks, suite_t & suite) noexcept {
	// Сбрасываем узор разбираемого имени
	pattern = pattern_t::NONE;
	// Сбрасываем положения ключей
	psks = 0;
	// Сбрасываем набор примитивов
	suite = suite_t();
	// Если имя негодно
	if((text.data == nullptr) || (text.size < 8) || (text.size >= NAME_LIMIT))
		// Выводим отрицательный результат - имя пусто
		return false;
	// Границы пяти отрезков имени
	size_t begin[5], length[5], count = 0, offset = 0;
	/**
	 * Разбиваем имя по подчёркиваниям
	 */
	for(size_t i = 0; i <= text.size; i++){
		// Если достигнут разделитель либо конец
		if((i == text.size) || (text.data[i] == '_')){
			// Если отрезков больше пяти
			if(count == 5)
				// Выводим отрицательный результат - лишние отрезки имени
				return false;
			// Запоминаем отрезок
			begin[count] = offset;
			// Запоминаем длину отрезка
			length[count] = (i - offset);
			// Считаем найденный отрезок
			count++;
			// Переносим начало следующего отрезка за разделитель
			offset = (i + 1);
		}
	}
	// Признак PQNoise по префиксу
	const bool postQuantum = ::__nts_same__(text.data, length[0], "PQNoise");
	// Если отрезков не пять либо первый не «Noise» и не «PQNoise»
	if((count != 5) || (!postQuantum && !::__nts_same__(text.data, length[0], "Noise")))
		// Выводим отрицательный результат - отрезков не пять
		return false;
	// Отрезок узора с видоизменениями
	const uint8_t * part = (text.data + begin[1]);
	// Длина найденного имени узора
	size_t found = 0;
	/**
	 * Перебираем узоры: берётся самое длинное имя, за которым конец либо «psk»
	 */
	for(uint8_t i = 1; i <= static_cast <uint8_t> (pattern_t::PQIX); i++){
		// Узоры семейства другого префикса не рассматриваются
		if(postquantum(static_cast <pattern_t> (i)) != postQuantum)
			// Пропускаем маркер конца
			continue;
		// Имя узора
		const char * label = title(static_cast <pattern_t> (i));
		// Длина имени
		const size_t width = ::strlen(label);
		// Если имя длиннее найденного, умещается и совпадает
		if((width > found) && (width <= length[1]) && (::memcmp(part, label, width) == 0) && ((width == length[1]) || ((length[1] - width) >= 4 && ::memcmp(part + width, "psk", 3) == 0))){
			// Запоминаем узор
			pattern = static_cast <pattern_t> (i);
			// Запоминаем длину найденного имени
			found = width;
		}
	}
	// Если узор не найден
	if(found == 0)
		// Выводим отрицательный результат - узор не найден
		return false;
	// Положение разбора видоизменений
	offset = found;
	/**
	 * Разбираем видоизменения вида psk0+psk3
	 */
	while(offset < length[1]){
		// Если не первое видоизменение, требуется знак сложения
		if((offset > found) && (part[offset++] != '+'))
			// Выводим отрицательный результат - видоизменения не по очереди
			return false;
		// Если видоизменение негодно
		if(((length[1] - offset) < 4) || (::memcmp(part + offset, "psk", 3) != 0) || (part[offset + 3] < '0') || (part[offset + 3] > '3'))
			// Выводим отрицательный результат - видоизменение негодно
			return false;
		// Разряд положения
		const uint8_t bit = static_cast <uint8_t> (1u << (part[offset + 3] - '0'));
		// Если положение повторяется либо идёт не по возрастанию
		if((psks & bit) || (psks >= bit))
			// Выводим отрицательный результат - положения видоизменений повторяются
			return false;
		// Запоминаем положение
		psks |= bit;
		// Сдвигаем положение разбора
		offset += 4;
	}
	// Определяем функцию хеширования по имени пятого отрезка
	if(::__nts_same__(text.data + begin[4], length[4], "SHA256"))
		// Устанавливаем SHA256
		suite.hash = digest::hash_t::SHA256;
	else if(::__nts_same__(text.data + begin[4], length[4], "SHA512"))
		// Устанавливаем SHA512
		suite.hash = digest::hash_t::SHA512;
	else if(::__nts_same__(text.data + begin[4], length[4], "BLAKE2s"))
		// Устанавливаем BLAKE2s
		suite.hash = digest::hash_t::BLAKE2S256;
	else if(::__nts_same__(text.data + begin[4], length[4], "BLAKE2b"))
		// Устанавливаем BLAKE2b
		suite.hash = digest::hash_t::BLAKE2B512;
	// Определяем шифр по имени четвёртого отрезка
	if(::__nts_same__(text.data + begin[3], length[3], "ChaChaPoly"))
		// Устанавливаем ChaChaPoly
		suite.aead = aead_t::CHACHAPOLY;
	else if(::__nts_same__(text.data + begin[3], length[3], "AESGCM"))
		// Устанавливаем AESGCM
		suite.aead = aead_t::AESGCM;
	// Разбираем функцию обмена ключами: 448 распознаётся, но не поддержана
	if(!postQuantum && ::__nts_same__(text.data + begin[2], length[2], "25519"))
		// Устанавливаем X25519
		suite.dh = dh_t::X25519;
	// Разбираем механизм упаковки ключа у PQNoise
	else if(postQuantum && ::__nts_same__(text.data + begin[2], length[2], "X25519MLKEM768"))
		// Назначаем смешанную упаковку
		suite.kem = kem_t::X25519MLKEM768;
	else if(postQuantum && ::__nts_same__(text.data + begin[2], length[2], "MLKEM768"))
		// Назначаем чистую упаковку MLKEM768
		suite.kem = kem_t::MLKEM768;
	// Выводим итог: набор поддержан целиком; у PQNoise psk не заведён
	return (valid(suite) && !(postQuantum && (psks != 0)));
}
/**
 * @brief Функция вычисления DH
 *
 * @param dhKind функция обмена ключами
 * @param secret свой закрытый ключ в KEY байтов
 * @param point  чужой открытый ключ в KEY байтов
 * @param result место общего секрета в KEY байтов
 * @return       признак того, что секрет вычислен и не состоит из нулей
 *
 */
bool nts::noise::agree(const dh_t dhKind, const view_t & secret, const view_t & point, uint8_t * result) noexcept {
	// Если функция не X25519 либо длины чужие
	if((dhKind != dh_t::X25519) || (secret.size != KEY) || (point.size != KEY))
		// Выводим отрицательный результат - пара не порождена
		return false;
	// Выводим итог X25519: точка малого порядка отвергается им самим
	return agreement::x25519(secret, point, result);
}
/**
 * @brief Функция вывода открытого ключа из закрытого
 *
 * @param dhKind функция обмена ключами
 * @param secret закрытый ключ в KEY байтов
 * @param result место открытого ключа в KEY байтов
 * @return       признак того, что ключ выведен
 *
 */
bool nts::noise::derive(const dh_t dhKind, const view_t & secret, uint8_t * result) noexcept {
	// Если функция не X25519 либо длина чужая
	if((dhKind != dh_t::X25519) || (secret.size != KEY))
		// Выводим отрицательный результат - согласование невозможно
		return false;
	// Выводим итог X25519 по основной точке
	return agreement::x25519(secret, result);
}
/**
 * @brief Функция выработки пары ключей из энтропии
 *
 * @param dhKind функция обмена ключами
 * @param secret место закрытого ключа в KEY байтов
 * @param result место открытого ключа в KEY байтов
 * @return       признак того, что пара выработана
 *
 */
bool nts::noise::generate(const dh_t dhKind, uint8_t * secret, uint8_t * result) noexcept {
	// Если функция не X25519
	if(dhKind != dh_t::X25519)
		// Выводим отрицательный результат - вывод ключа невозможен
		return false;
	// Выводим итог выработки X25519
	return agreement::generate(secret, result);
}

/**
 * @brief Конструктор
 *
 */
nts::noise::Suite::Suite() noexcept : dh(dh_t::NONE), aead(aead_t::NONE), hash(digest::hash_t::NONE), kem(kem_t::NONE) {}

/**
 * @brief Конструктор
 *
 * @param dhKind функция обмена ключами
 * @param aead   функция шифрования с подлинностью
 * @param hash   функция хеширования
 *
 */
nts::noise::Suite::Suite(const dh_t dhKind, const aead_t aead, const digest::hash_t hash) noexcept : dh(dhKind), aead(aead), hash(hash), kem(kem_t::NONE) {}

/**
 * @brief Конструктор набора PQNoise
 *
 * @param kem  механизм упаковки ключа
 * @param aead   функция шифрования с подлинностью
 * @param hash   функция хеширования
 *
 */
nts::noise::Suite::Suite(const kem_t kem, const aead_t aead, const digest::hash_t hash) noexcept : dh(dh_t::NONE), aead(aead), hash(hash), kem(kem) {}
