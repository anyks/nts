/**
 * @file srtp.cpp
 * @date 2026-10-06
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
 * @brief Исходный файл проверок модуля защиты транспорта реального времени
 *
 * @note Эталоном служат вектора приложения B RFC 3711 (вывод сессионных
 *       ключей и гамма AES-CM) и разделов 16 и 17 RFC 7714 (пакеты RTP и
 *       RTCP под AES-GCM), круговая защита и снятие защиты своими
 *       полусессиями, отказы подделки и повтора
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <srtp/srtp.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Служебные объекты проверок модуля SRTP
 */
namespace {
	/**
	 * @brief Метод разбора шестнадцатеричной строки в набор байтов
	 *
	 * @param text шестнадцатеричная строка без разделителей
	 *
	 * @return     набор байтов
	 *
	 */
	static std::vector <uint8_t> unhex(const char * text) {
		// Набор байтов итога
		std::vector <uint8_t> result;
		// Длина строки
		const size_t size = ::strlen(text);
		// Занимаем место под итог
		result.reserve(size / 2);
		// Проходим по парам знаков
		for(size_t i = 0; i + 1 < size; i += 2){
			// Значение пары знаков
			unsigned value = 0;
			// Разбираем пару знаков
			::sscanf(text + i, "%02x", &value);
			// Добавляем байт в итог
			result.push_back(static_cast <uint8_t> (value));
		}
		// Выводим итог
		return result;
	}
	/**
	 * @brief Метод получения просмотра набора байтов
	 *
	 * @param data набор байтов
	 *
	 * @return     просмотр набора
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) noexcept {
		// Выводим просмотр набора
		return view_t(data.data(), data.size());
	}
}

/**
 * @brief Проверка вывода сессионных ключей по приложению B.3 RFC 3711
 *
 */
TEST(SrtpTest, KeyDerivation) {
	// Мастер-ключ вектора
	const std::vector <uint8_t> masterKey = unhex("E1F97A0D3E018BE0D64FA32C06DE4139");
	// Мастер-соль вектора
	const std::vector <uint8_t> masterSalt = unhex("0EC675AD498AFEEBB6960B3AABE6");
	// Сессионные ключи
	srtp::keys_t keys;
	// Вывод обязан удаться
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(masterKey), view(masterSalt), keys), srtp::error_t::NONE);
	// Ключ шифрования обязан совпасть с вектором
	const std::vector <uint8_t> cipher = unhex("C61E7A93744F39EE10734AFE3FF7A087");
	ASSERT_EQ(keys.cipher, cipher);
	// Ключ имитовставки обязан совпасть с вектором (первые двадцать байтов потока)
	const std::vector <uint8_t> auth = unhex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");
	ASSERT_EQ(keys.auth, auth);
	// Соль обязана совпасть с вектором
	const std::vector <uint8_t> salt = unhex("30CBBC08863D8C85D49DB34A9AE1");
	ASSERT_EQ(keys.salt, salt);
	// Вывод с чужой длиной мастер-ключа обязан отказать
	std::vector <uint8_t> shortKey(masterKey.begin(), masterKey.end() - 1);
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(shortKey), view(masterSalt), keys), srtp::error_t::KEY);
	// Вывод с чужой длиной мастер-соли обязан отказать
	std::vector <uint8_t> shortSalt(masterSalt.begin(), masterSalt.end() - 1);
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(masterKey), view(shortSalt), keys), srtp::error_t::KEY);
	// Вывод профилем AES-256-GCM обязан взять ключ в 32 байта
	std::vector <uint8_t> key32(32, 0x01);
	std::vector <uint8_t> salt12(12, 0x02);
	ASSERT_EQ(srtp::keys(srtp::profile_t::AEAD_AES_256_GCM, view(key32), view(salt12), keys), srtp::error_t::NONE);
	// Ключ имитовставки у профиля AES-GCM пуст
	ASSERT_TRUE(keys.auth.empty());
	// Длина ключа обязана быть 32, соли - 12
	ASSERT_EQ(keys.cipher.size(), 32U);
	ASSERT_EQ(keys.salt.size(), 12U);
}

/**
 * @brief Проверка гаммы AES-CM по приложению B.2 RFC 3711
 *
 */
TEST(SrtpTest, AesCmKeystream) {
	// Сессионный ключ вектора
	const std::vector <uint8_t> sessionKey = unhex("2B7E151628AED2A6ABF7158809CF4F3C");
	// Сессионная соль вектора (уже сдвинутая, младшие два байта нулевые)
	const std::vector <uint8_t> sessionSalt = unhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD");
	// Сессионные ключи полусессии
	srtp::keys_t keys;
	// Ключ шифрования
	keys.cipher = sessionKey;
	// Соль
	keys.salt = sessionSalt;
	// Ключ имитовставки (в векторе не проверяется)
	keys.auth.assign(20, 0);
	// Полусессия отправителя
	srtp::session_t sender;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	// Пакет RTP: заголовок с нулевыми номером и SSRC, полезная нагрузка 32 нулевых байта
	std::vector <uint8_t> packet(44, 0);
	// Первый байт заголовка: версия 2
	packet[0] = 0x80;
	// Защищённый пакет
	std::vector <uint8_t> protectedPacket;
	// Защита обязана удаться
	ASSERT_EQ(sender.protect(view(packet), protectedPacket), srtp::error_t::NONE);
	// Первые шестнадцать байтов гаммы обязаны совпасть с вектором
	const std::vector <uint8_t> gamma0 = unhex("E03EAD0935C95E80E166B16DD92B4EB4");
	ASSERT_EQ(::memcmp(protectedPacket.data() + 12, gamma0.data(), 16), 0);
	// Вторые шестнадцать байтов гаммы обязаны совпасть с вектором
	const std::vector <uint8_t> gamma1 = unhex("D23513162B02D0F72A43A2FE4A5F97AB");
	ASSERT_EQ(::memcmp(protectedPacket.data() + 28, gamma1.data(), 16), 0);
	// Метка имитовставки приписана: длина итога 44 + 10
	ASSERT_EQ(protectedPacket.size(), 54U);
}

/**
 * @brief Проверка пакета RTP под AEAD_AES_128_GCM по разделу 16.1.1 RFC 7714
 *
 */
TEST(SrtpTest, Aead128Rtp) {
	// Пакет RTP вектора
	const std::vector <uint8_t> packet = unhex(
		"8040f17b8041f8d35501a0b2"
		"47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573"
	);
	// Ключ вектора: 00 01 .. 0f
	std::vector <uint8_t> key(16);
	for(size_t i = 0; i < 16; i++) key[i] = static_cast <uint8_t> (i);
	// Соль вектора: «Quid pro quo»
	const std::vector <uint8_t> salt = unhex("517569642070726f2071756f");
	// Сессионные ключи полусессии
	srtp::keys_t keys;
	keys.cipher = key;
	keys.salt = salt;
	// Полусессия отправителя
	srtp::session_t sender;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AEAD_AES_128_GCM, keys));
	// Защищённый пакет
	std::vector <uint8_t> protectedPacket;
	// Защита обязана удаться
	ASSERT_EQ(sender.protect(view(packet), protectedPacket), srtp::error_t::NONE);
	// Итог обязан совпасть с вектором побайтно
	const std::vector <uint8_t> want = unhex(
		"8040f17b8041f8d35501a0b2"
		"f24de3a3fb34de6cacba861c9d7e4bca"
		"be633bd50d294e6f42a5f47a51c7d19b"
		"36de3adf8833899d7f27beb16a9152cf765ee4390cce"
	);
	ASSERT_EQ(protectedPacket, want);
	// Полусессия получателя
	srtp::session_t receiver;
	// Установка ключей обязана удаться
	ASSERT_TRUE(receiver.start(srtp::profile_t::AEAD_AES_128_GCM, keys));
	// Открытый пакет
	std::vector <uint8_t> plain;
	// Снятие защиты обязано удаться
	ASSERT_EQ(receiver.unprotect(view(protectedPacket), plain), srtp::error_t::NONE);
	// Открытый пакет обязан совпасть с исходным
	ASSERT_EQ(plain, packet);
	// Подделанный байт метки следующего пакета обязан отказать
	std::vector <uint8_t> second(packet);
	// Номер второго пакета
	second[3] = 0x7c;
	// Защищённый второй пакет
	std::vector <uint8_t> forged;
	// Защита обязана удаться
	ASSERT_EQ(sender.protect(view(second), forged), srtp::error_t::NONE);
	// Портим байт метки
	forged[forged.size() - 1] ^= 0x01;
	// Снятие защиты обязано отказать имитовставкой
	ASSERT_EQ(receiver.unprotect(view(forged), plain), srtp::error_t::SIGNATURE);
	// Повтор первого пакета обязан отказать повтором
	ASSERT_EQ(receiver.unprotect(view(protectedPacket), plain), srtp::error_t::REPLAY);
}

/**
 * @brief Проверка пакета RTP под AEAD_AES_256_GCM по разделу 16.2.1 RFC 7714
 *
 */
TEST(SrtpTest, Aead256Rtp) {
	// Пакет RTP вектора
	const std::vector <uint8_t> packet = unhex(
		"8040f17b8041f8d35501a0b2"
		"47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573"
	);
	// Ключ вектора: 00 01 .. 1f
	std::vector <uint8_t> key(32);
	for(size_t i = 0; i < 32; i++) key[i] = static_cast <uint8_t> (i);
	// Соль вектора
	const std::vector <uint8_t> salt = unhex("517569642070726f2071756f");
	// Сессионные ключи полусессии
	srtp::keys_t keys;
	keys.cipher = key;
	keys.salt = salt;
	// Полусессия отправителя
	srtp::session_t sender;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AEAD_AES_256_GCM, keys));
	// Защищённый пакет
	std::vector <uint8_t> protectedPacket;
	// Защита обязана удаться
	ASSERT_EQ(sender.protect(view(packet), protectedPacket), srtp::error_t::NONE);
	// Итог обязан совпасть с вектором побайтно
	const std::vector <uint8_t> want = unhex(
		"8040f17b8041f8d35501a0b2"
		"32b1de78a822fe12ef9f78fa332e33aa"
		"b18012389a58e2f3b50b2a0276ffae0f"
		"1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13"
	);
	ASSERT_EQ(protectedPacket, want);
}

/**
 * @brief Проверка пакета SRTCP под AEAD_AES_128_GCM по разделу 17.1 RFC 7714
 *
 */
TEST(SrtpTest, Aead128Rtcp) {
	// Пакет RTCP вектора
	const std::vector <uint8_t> packet = unhex(
		"81c8000d4d6172734e5450314e54503252545020"
		"0000042a0000e9304c756e61"
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	);
	// Ключ вектора: 00 01 .. 0f
	std::vector <uint8_t> key(16);
	for(size_t i = 0; i < 16; i++) key[i] = static_cast <uint8_t> (i);
	// Соль вектора
	const std::vector <uint8_t> salt = unhex("517569642070726f2071756f");
	// Сессионные ключи полусессии
	srtp::keys_t keys;
	keys.cipher = key;
	keys.salt = salt;
	// Полусессия отправителя
	srtp::session_t sender;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AEAD_AES_128_GCM, keys));
	// Защищённый пакет
	std::vector <uint8_t> protectedPacket;
	// Прогоняем счётчик SRTCP до индекса вектора 0x05d4
	for(uint32_t i = 0; i < 0x05d4; i++)
		// Защита обязана удаваться
		ASSERT_EQ(sender.protectControl(view(packet), protectedPacket), srtp::error_t::NONE);
	// Защита пакета вектора обязана удаться
	ASSERT_EQ(sender.protectControl(view(packet), protectedPacket), srtp::error_t::NONE);
	// Итог обязан совпасть с вектором побайтно
	const std::vector <uint8_t> want = unhex(
		"81c8000d4d617273"
		"63e94885dcdab67ca727d7662f6b7e99"
		"7ff5c0f76c06f32dc676a5f1730d6fda"
		"4ce09b4686303ded0bb9275b"
		"c84aa45896cf4d2fc5abf87245d9eade"
		"800005d4"
	);
	ASSERT_EQ(protectedPacket, want);
	// Полусессия получателя
	srtp::session_t receiver;
	// Установка ключей обязана удаться
	ASSERT_TRUE(receiver.start(srtp::profile_t::AEAD_AES_128_GCM, keys));
	// Открытый пакет
	std::vector <uint8_t> plain;
	// Снятие защиты обязано удаться
	ASSERT_EQ(receiver.unprotectControl(view(protectedPacket), plain), srtp::error_t::NONE);
	// Открытый пакет обязан совпасть с исходным
	ASSERT_EQ(plain, packet);
	// Подделанный байт шифротекста следующего пакета обязан отказать
	std::vector <uint8_t> forged;
	// Защита следующего пакета обязана удаться
	ASSERT_EQ(sender.protectControl(view(packet), forged), srtp::error_t::NONE);
	// Портим байт шифротекста
	forged[20] ^= 0x01;
	// Снятие защиты обязано отказать имитовставкой
	ASSERT_EQ(receiver.unprotectControl(view(forged), plain), srtp::error_t::SIGNATURE);
	// Повтор первого пакета обязан отказать повтором
	ASSERT_EQ(receiver.unprotectControl(view(protectedPacket), plain), srtp::error_t::REPLAY);
}

/**
 * @brief Проверка круговой защиты пакетов RTP профилями AES-CM
 *
 */
TEST(SrtpTest, RoundtripCm) {
	// Профили AES-CM: метка 80 и 32 разряда
	const srtp::profile_t profiles[2] = {srtp::profile_t::AES128_CM_SHA1_80, srtp::profile_t::AES128_CM_SHA1_32};
	// Проходим по профилям
	for(size_t p = 0; p < 2; p++){
		// Мастер-ключ и мастер-соль
		std::vector <uint8_t> masterKey(16), masterSalt(14);
		// Заполняем ключ и соль значениями
		for(size_t i = 0; i < 16; i++) masterKey[i] = static_cast <uint8_t> (i * 7 + 1);
		for(size_t i = 0; i < 14; i++) masterSalt[i] = static_cast <uint8_t> (i * 5 + 2);
		// Сессионные ключи
		srtp::keys_t keys;
		// Вывод обязан удаться
		ASSERT_EQ(srtp::keys(profiles[p], view(masterKey), view(masterSalt), keys), srtp::error_t::NONE);
		// Полусессии сторон
		srtp::session_t sender, receiver;
		// Установка ключей обязана удаться
		ASSERT_TRUE(sender.start(profiles[p], keys));
		ASSERT_TRUE(receiver.start(profiles[p], keys));
		// Пакет RTP с полезной нагрузкой
		std::vector <uint8_t> packet = unhex(
			"8040f17b8041f8d35501a0b2"
			"47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573"
		);
		// Проходим по десяти пакетам подряд
		for(uint8_t i = 0; i < 10; i++){
			// Номер пакета нарастает
			packet[3] = static_cast <uint8_t> (0x7b + i);
			// Защищённый пакет
			std::vector <uint8_t> protectedPacket;
			// Защита обязана удаться
			ASSERT_EQ(sender.protect(view(packet), protectedPacket), srtp::error_t::NONE);
			// Заголовок обязан остаться открытым
			ASSERT_EQ(::memcmp(protectedPacket.data(), packet.data(), 12), 0);
			// Полезная нагрузка обязана отличаться
			ASSERT_NE(::memcmp(protectedPacket.data() + 12, packet.data() + 12, packet.size() - 12), 0);
			// Открытый пакет
			std::vector <uint8_t> plain;
			// Снятие защиты обязано удаться
			ASSERT_EQ(receiver.unprotect(view(protectedPacket), plain), srtp::error_t::NONE);
			// Открытый пакет обязан совпасть с исходным
			ASSERT_EQ(plain, packet);
		}
	}
}

/**
 * @brief Проверка круговой защиты пакетов RTCP профилями AES-CM
 *
 */
TEST(SrtpTest, RoundtripCmRtcp) {
	// Мастер-ключ и мастер-соль
	std::vector <uint8_t> masterKey(16), masterSalt(14);
	// Заполняем ключ и соль значениями
	for(size_t i = 0; i < 16; i++) masterKey[i] = static_cast <uint8_t> (i * 3 + 1);
	for(size_t i = 0; i < 14; i++) masterSalt[i] = static_cast <uint8_t> (i * 11 + 4);
	// Сессионные ключи
	srtp::keys_t keys;
	// Вывод обязан удаться
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(masterKey), view(masterSalt), keys), srtp::error_t::NONE);
	// Полусессии сторон
	srtp::session_t sender, receiver;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	ASSERT_TRUE(receiver.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	// Пакет RTCP
	const std::vector <uint8_t> packet = unhex(
		"81c8000d4d6172734e5450314e54503252545020"
		"0000042a0000e9304c756e61"
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	);
	// Проходим по пяти пакетам подряд
	for(uint8_t i = 0; i < 5; i++){
		// Защищённый пакет
		std::vector <uint8_t> protectedPacket;
		// Защита обязана удаться
		ASSERT_EQ(sender.protectControl(view(packet), protectedPacket), srtp::error_t::NONE);
		// Длина итога: пакет, слово ESRTCP и метка
		ASSERT_EQ(protectedPacket.size(), packet.size() + 4 + 10);
		// Первые восемь байтов обязаны остаться открытыми
		ASSERT_EQ(::memcmp(protectedPacket.data(), packet.data(), 8), 0);
		// Слово ESRTCP: флаг шифрования и индекс пакета
		const size_t word = packet.size();
		ASSERT_EQ(protectedPacket[word], static_cast <uint8_t> (0x80 | (i >> 24)));
		ASSERT_EQ(protectedPacket[word + 3], i);
		// Открытый пакет
		std::vector <uint8_t> plain;
		// Снятие защиты обязано удаться
		ASSERT_EQ(receiver.unprotectControl(view(protectedPacket), plain), srtp::error_t::NONE);
		// Открытый пакет обязан совпасть с исходным
		ASSERT_EQ(plain, packet);
	}
}

/**
 * @brief Проверка переполнения порядкового номера и счётчика ROC
 *
 */
TEST(SrtpTest, RolloverCounter) {
	// Мастер-ключ и мастер-соль
	std::vector <uint8_t> masterKey(16), masterSalt(14);
	// Заполняем ключ и соль значениями
	for(size_t i = 0; i < 16; i++) masterKey[i] = static_cast <uint8_t> (i + 9);
	for(size_t i = 0; i < 14; i++) masterSalt[i] = static_cast <uint8_t> (i + 3);
	// Сессионные ключи
	srtp::keys_t keys;
	// Вывод обязан удаться
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(masterKey), view(masterSalt), keys), srtp::error_t::NONE);
	// Полусессии сторон
	srtp::session_t sender, receiver;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	ASSERT_TRUE(receiver.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	// Пакет RTP с номером у границы переполнения
	std::vector <uint8_t> packet(44, 0);
	// Первый байт заголовка: версия 2
	packet[0] = 0x80;
	// Номер 0xFFFE
	packet[2] = 0xFF;
	packet[3] = 0xFE;
	// Проходим по четырём пакетам через переполнение номера
	for(uint8_t i = 0; i < 4; i++){
		// Защищённый пакет
		std::vector <uint8_t> protectedPacket;
		// Защита обязана удаться
		ASSERT_EQ(sender.protect(view(packet), protectedPacket), srtp::error_t::NONE);
		// Открытый пакет
		std::vector <uint8_t> plain;
		// Снятие защиты обязано удаться и через переполнение
		ASSERT_EQ(receiver.unprotect(view(protectedPacket), plain), srtp::error_t::NONE);
		// Открытый пакет обязан совпасть с исходным
		ASSERT_EQ(plain, packet);
		// Номер нарастает через переполнение
		packet[3]++;
		if(packet[3] == 0)
			// Перенос в старший байт
			packet[2]++;
	}
}

/**
 * @brief Проверка окна приёма против повторов
 *
 */
TEST(SrtpTest, ReplayWindow) {
	// Мастер-ключ и мастер-соль
	std::vector <uint8_t> masterKey(16), masterSalt(14);
	// Заполняем ключ и соль значениями
	for(size_t i = 0; i < 16; i++) masterKey[i] = static_cast <uint8_t> (i + 1);
	for(size_t i = 0; i < 14; i++) masterSalt[i] = static_cast <uint8_t> (i + 7);
	// Сессионные ключи
	srtp::keys_t keys;
	// Вывод обязан удаться
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(masterKey), view(masterSalt), keys), srtp::error_t::NONE);
	// Полусессии сторон
	srtp::session_t sender, receiver;
	// Установка ключей обязана удаться
	ASSERT_TRUE(sender.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	ASSERT_TRUE(receiver.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	// Пакет RTP
	std::vector <uint8_t> packet(44, 0);
	// Первый байт заголовка: версия 2
	packet[0] = 0x80;
	// Защищённые пакеты с номерами 1..100
	std::vector < std::vector <uint8_t> > packets(100);
	// Проходим по пакетам
	for(uint8_t i = 0; i < 100; i++){
		// Номер пакета
		packet[3] = i + 1;
		// Защита обязана удаться
		ASSERT_EQ(sender.protect(view(packet), packets[i]), srtp::error_t::NONE);
	}
	// Открытый пакет
	std::vector <uint8_t> plain;
	// Пакет с номером 100 принимается первым: окно сдвигается к нему
	ASSERT_EQ(receiver.unprotect(view(packets[99]), plain), srtp::error_t::NONE);
	// Пакет с номером 36 старше окна в 64 индекса: отказ повтора
	ASSERT_EQ(receiver.unprotect(view(packets[35]), plain), srtp::error_t::REPLAY);
	// Пакет с номером 37 на краю окна: принимается
	ASSERT_EQ(receiver.unprotect(view(packets[36]), plain), srtp::error_t::NONE);
	// Повтор пакета с номером 37: отказ повтора
	ASSERT_EQ(receiver.unprotect(view(packets[36]), plain), srtp::error_t::REPLAY);
	// Пакет с номером 50 внутри окна: принимается
	ASSERT_EQ(receiver.unprotect(view(packets[49]), plain), srtp::error_t::NONE);
}

/**
 * @brief Проверка раскладки ключевого материала экспорта связи DTLS
 *
 */
TEST(SrtpTest, PairLayout) {
	// Ключевой материал экспорта: 2 × (16 + 14) = 60 байтов
	std::vector <uint8_t> material(60);
	// Заполняем материал значениями
	for(size_t i = 0; i < 60; i++) material[i] = static_cast <uint8_t> (i);
	// Мастер-ключи сторон
	srtp::keys_t client, server;
	// Раскладка обязана удаться
	ASSERT_EQ(srtp::pair(srtp::profile_t::AES128_CM_SHA1_80, view(material), client, server), srtp::error_t::NONE);
	// Ключ клиента: байты 0..15
	ASSERT_EQ(client.cipher.size(), 16U);
	ASSERT_EQ(client.cipher[0], 0);
	ASSERT_EQ(client.cipher[15], 15);
	// Ключ сервера: байты 16..31
	ASSERT_EQ(server.cipher.size(), 16U);
	ASSERT_EQ(server.cipher[0], 16);
	// Соль клиента: байты 32..45
	ASSERT_EQ(client.salt.size(), 14U);
	ASSERT_EQ(client.salt[0], 32);
	// Соль сервера: байты 46..59
	ASSERT_EQ(server.salt.size(), 14U);
	ASSERT_EQ(server.salt[0], 46);
	// Раскладка с чужой длиной материала обязана отказать
	std::vector <uint8_t> shortMaterial(59, 0);
	ASSERT_EQ(srtp::pair(srtp::profile_t::AES128_CM_SHA1_80, view(shortMaterial), client, server), srtp::error_t::STRUCTURE);
	// Раскладка профилем AES-128-GCM: 2 × (16 + 12) = 56 байтов
	std::vector <uint8_t> materialGcm(56, 0);
	ASSERT_EQ(srtp::pair(srtp::profile_t::AEAD_AES_128_GCM, view(materialGcm), client, server), srtp::error_t::NONE);
	// Соль обязана быть двенадцати байтов
	ASSERT_EQ(client.salt.size(), 12U);
}

/**
 * @brief Проверка отказов полусессии
 *
 */
TEST(SrtpTest, Refusals) {
	// Полусессия без ключей
	srtp::session_t empty;
	// Пакет RTP
	std::vector <uint8_t> packet(44, 0);
	// Первый байт заголовка: версия 2
	packet[0] = 0x80;
	// Итог
	std::vector <uint8_t> result;
	// Защита без ключей обязана отказать
	ASSERT_EQ(empty.protect(view(packet), result), srtp::error_t::EMPTY);
	// Снятие защиты без ключей обязано отказать
	ASSERT_EQ(empty.unprotect(view(packet), result), srtp::error_t::EMPTY);
	// Защита RTCP без ключей обязана отказать
	ASSERT_EQ(empty.protectControl(view(packet), result), srtp::error_t::EMPTY);
	// Снятие защиты RTCP без ключей обязано отказать
	ASSERT_EQ(empty.unprotectControl(view(packet), result), srtp::error_t::EMPTY);
	// Ключи неверной длины
	srtp::keys_t bad;
	// Ключ в пятнадцать байтов
	bad.cipher.assign(15, 0);
	// Соль в четырнадцать байтов
	bad.salt.assign(14, 0);
	// Ключ имитовставки
	bad.auth.assign(20, 0);
	// Установка обязана отказать
	ASSERT_FALSE(empty.start(srtp::profile_t::AES128_CM_SHA1_80, bad));
	// Сессионные ключи годные
	srtp::keys_t keys;
	// Мастер-ключ и мастер-соль
	std::vector <uint8_t> masterKey(16, 0x11), masterSalt(14, 0x22);
	// Вывод обязан удаться
	ASSERT_EQ(srtp::keys(srtp::profile_t::AES128_CM_SHA1_80, view(masterKey), view(masterSalt), keys), srtp::error_t::NONE);
	// Полусессия
	srtp::session_t session;
	// Установка ключей обязана удаться
	ASSERT_TRUE(session.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	// Пакет короче заголовка обязан отказать
	std::vector <uint8_t> tiny(8, 0);
	ASSERT_EQ(session.protect(view(tiny), result), srtp::error_t::STRUCTURE);
	// Пакет с меткой короче метки обязан отказать
	ASSERT_EQ(session.unprotect(view(tiny), result), srtp::error_t::STRUCTURE);
	// Пакет RTCP короче заголовка обязан отказать
	std::vector <uint8_t> tinyRtcp(4, 0);
	ASSERT_EQ(session.protectControl(view(tinyRtcp), result), srtp::error_t::STRUCTURE);
	// Пакет SRTCP короче слова и метки обязан отказать
	ASSERT_EQ(session.unprotectControl(view(tiny), result), srtp::error_t::STRUCTURE);
	// Подделанный пакет обязан отказать имитовставкой
	std::vector <uint8_t> protectedPacket;
	// Защита обязана удаться
	ASSERT_EQ(session.protect(view(packet), protectedPacket), srtp::error_t::NONE);
	// Портим байт полезной нагрузки
	protectedPacket[20] ^= 0x40;
	// Полусессия получателя
	srtp::session_t receiver;
	// Установка ключей обязана удаться
	ASSERT_TRUE(receiver.start(srtp::profile_t::AES128_CM_SHA1_80, keys));
	// Снятие защиты обязано отказать имитовставкой
	ASSERT_EQ(receiver.unprotect(view(protectedPacket), result), srtp::error_t::SIGNATURE);
}
