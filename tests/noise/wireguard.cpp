/**
 * @file wireguard.cpp
 * @date 2026-09-08
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
 * @brief Проверка сборки кадров рукопожатия и переноса WireGuard поверх Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
 *
 * @details Кадры собираются здесь, в проверке, а не в ядре: ядро даёт сообщения Noise, поля
 *          WireGuard (вид, номера сторон, TAI64N, mac1, mac2, счётчик переноса) - статьи
 *          Донэнфельда. CONSTRUCTION - имя протокола Noise, IDENTIFIER - пролог, Spub
 *          отвечающего - предсообщение; mac1 = BLAKE2s с ключом HASH(LABEL_MAC1 ‖ Spub
 *          получателя) по кадру до mac1, итог 16 октетов. Опубликованных векторов у WireGuard
 *          нет: Noise-часть доказана векторами IKpsk2 и живым обменом, здесь закреплены
 *          устройство кадра, длины 148 и 92, сличение mac1 пересчётом и перенос с явным
 *          счётчиком из заголовка пакета
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <noise/noise.hpp>
#include <noise/cipher.hpp>
#include <noise/handshake.hpp>
#include <digest/hash.hpp>
#include <digest/blake2.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты проверки
 *
 */
namespace {
	/**
	 * Постоянные WireGuard
	 */
	static const char * CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
	// Идентификатор протокола для пролога
	static const char * IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
	// Метка ключа метки mac1
	static const char * LABEL_MAC1 = "mac1----";
	/**
	 * Длины кадров
	 */
	static constexpr size_t INITIATION = 148, RESPONSE = 92, MAC = 16, TAI64N = 12;
	/**
	 * @brief Область байтов строки
	 *
	 */
	static view_t span(const char * text) {
		// Возвращаем область байтов строки
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
	/**
	 * @brief Запись 32-разрядного числа от младшего
	 *
	 */
	static void put32(uint8_t * place, const uint32_t value) {
		/** Перебираем байты числа от младшего */
		for(size_t i = 0; i < 4; i++) place[i] = static_cast <uint8_t> (value >> (8 * i));
	}
	/**
	 * @brief Запись 64-разрядного числа от младшего
	 *
	 */
	static void put64(uint8_t * place, const uint64_t value) {
		/** Перебираем байты числа от младшего */
		for(size_t i = 0; i < 8; i++) place[i] = static_cast <uint8_t> (value >> (8 * i));
	}
	/**
	 * @brief Чтение 64-разрядного числа от младшего
	 *
	 */
	static uint64_t get64(const uint8_t * place) {
		// Начинаем сборку с нуля
		uint64_t value = 0;
		/** Перебираем байты числа от младшего */
		for(size_t i = 0; i < 8; i++) value |= (static_cast <uint64_t> (place[i]) << (8 * i));
		// Возвращаем собранное число
		return value;
	}
	/**
	 * @brief Метка mac1: BLAKE2s с ключом HASH(LABEL_MAC1 ‖ Spub) по кадру до метки
	 *
	 * @param statics открытый постоянный ключ получателя
	 * @param frame   кадр
	 * @param size    длина кадра до метки
	 * @param result  место метки в 16 октетов
	 *
	 */
	static bool mac1(const uint8_t * statics, const uint8_t * frame, const size_t size, uint8_t * result) {
		// Собираем ввод метки mac1: метку и открытый ключ получателя
		std::vector <uint8_t> input(reinterpret_cast <const uint8_t *> (LABEL_MAC1), reinterpret_cast <const uint8_t *> (LABEL_MAC1) + 8);
		// Дописываем открытый постоянный ключ получателя
		input.insert(input.end(), statics, statics + 32);
		// Объявляем место ключа
		uint8_t key[32];
		// Вычисляем ключ BLAKE2s по метке и ключу
		if(!digest::hash(digest::hash_t::BLAKE2S256, view_t(input.data(), input.size()), key, 32)) return false;
		// Вычисляем метку mac1 по кадру ключом
		return digest::blake2(digest::blake_t::BLAKE2S, view_t(key, 32), view_t(frame, size), result, MAC);
	}
	/**
	 * @brief TAI64N: секунды от старшего со сдвигом 2^62, наносекунды от старшего
	 *
	 */
	static void tai64n(const uint64_t seconds, const uint32_t nanos, uint8_t * result) {
		// Сдвигаем секунды на 2^62
		const uint64_t value = (0x4000000000000000ULL + seconds);
		/** Перебираем байты секунд от старшего */
		for(size_t i = 0; i < 8; i++) result[i] = static_cast <uint8_t> (value >> (8 * (7 - i)));
		/** Перебираем байты наносекунд от старшего */
		for(size_t i = 0; i < 4; i++) result[8 + i] = static_cast <uint8_t> (nanos >> (8 * (3 - i)));
	}
	/**
	 * @brief Разбор шестнадцатеричной строки
	 *
	 */
	static std::vector <uint8_t> unhex(const std::string & text) {
		// Объявляем буфер результата
		std::vector <uint8_t> result;
		/** Перебираем пары шестнадцатеричных знаков */
		for(size_t i = 0; (i + 1) < text.size(); i += 2) result.push_back(static_cast <uint8_t> (::strtoul(text.substr(i, 2).c_str(), nullptr, 16)));
		// Возвращаем разобранные байты
		return result;
	}
	/**
	 * @brief Чтение эталонного вектора wireguard-go: ключ=hex построчно, строки с решёткой - шапка
	 *
	 */
	static std::map <std::string, std::vector <uint8_t>> reference(const std::string & path) {
		// Объявляем таблицу эталона
		std::map <std::string, std::vector <uint8_t>> result;
		// Открываем файл эталона
		std::ifstream file(path);
		// Объявляем буфер строки
		std::string line;
		/** Читаем файл построчно, пока строки не кончатся */
		while(std::getline(file, line)){
			// Пропускаем пустые строки и строки шапки
			if(line.empty() || (line[0] == '#')) continue;
			// Ищем знак равенства
			const size_t eq = line.find('=');
			// Пропускаем строки без знака равенства
			if(eq == std::string::npos) continue;
			// Запоминаем байты под именем ключа
			result[line.substr(0, eq)] = unhex(line.substr(eq + 1));
		}
		// Возвращаем таблицу эталона
		return result;
	}
	/**
	 * @brief Заведение стороны WireGuard: узор именем, пролог IDENTIFIER, ключи, psk (нули, если нет)
	 *
	 */
	static bool arm(noise::handshake_t & side, const noise::role_t role, const uint8_t * secret, const uint8_t * remote, const uint8_t * psk) {
		// Запускаем рукопожатие узором и прологом
		if(!side.start(span(CONSTRUCTION), role, span(IDENTIFIER))) return false;
		if(!side.statics(view_t(secret, 32))) return false;
		if((remote != nullptr) && !side.remote(view_t(remote, 32))) return false;
		// Оборачиваем общий ключ в область байтов
		view_t key(psk, 32);
		// Передаём общий ключ рукопожатию
		return side.psks(&key, 1);
	}
};

/**
 * @brief Полный круг WireGuard: кадр 1 (148), кадр 2 (92), mac1 пересчётом, перенос с явным счётчиком
 *
 */
TEST(WireguardTest, Handshake){
	// Объявляем ключи сторон и общий ключ
	uint8_t si[32], pi[32], sr[32], pr[32], psk[32];
	// Генерируем пару ключей инициатора
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, si, pi));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sr, pr));
	/** Заполняем общий ключ растущими байтами */
	for(size_t i = 0; i < 32; i++) psk[i] = static_cast <uint8_t> (0xA0 + i);
	// Объявляем стороны рукопожатия
	noise::handshake_t initiator, responder;
	// Заводим инициатора своим секретным и чужим открытым ключом
	ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pr, psk));
	ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr, nullptr, psk));
	// Кадр 1: вид 1, три нуля, номер отправителя, сообщение Noise (32 + 48 + 28), mac1, mac2 (нули без печенья)
	uint8_t frame[INITIATION];
	::memset(frame, 0, sizeof(frame));
	// Помечаем кадр видом 1
	frame[0] = 1;
	// Записываем номер отправителя
	put32(frame + 4, 0x11223344);
	// Объявляем буфер метки времени
	uint8_t stamp[TAI64N];
	// Формируем метку времени
	tai64n(1788825600ULL, 123456789u, stamp);
	// Оставляем место заголовку и меткам
	size_t size = (sizeof(frame) - 8);
	// Пишем сообщение Noise в кадр
	ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
	// Проверяем длину сообщения
	ASSERT_EQ(size, 108u);
	// Ставим метку mac1 в кадр
	ASSERT_TRUE(mac1(pr, frame, 116, frame + 116));
	// Отвечающий: сперва mac1 по своему открытому ключу, затем Noise
	uint8_t expected[MAC];
	// Считаем эталонную метку mac1
	ASSERT_TRUE(mac1(pr, frame, 116, expected));
	// Проверяем метку mac1 в кадре
	EXPECT_EQ(::memcmp(expected, frame + 116, MAC), 0);
	// Объявляем буфер метки времени
	uint8_t got[TAI64N];
	// Задаём ёмкость буфера
	size_t length = sizeof(got);
	// Читаем сообщение Noise отвечающим
	ASSERT_TRUE(responder.read(view_t(frame + 8, 108), got, length));
	// Проверяем длину прочитанного
	ASSERT_EQ(length, TAI64N);
	// Проверяем метку времени
	EXPECT_EQ(::memcmp(got, stamp, TAI64N), 0);
	// Объявляем буфер постоянного ключа
	uint8_t learned[32];
	// Запрашиваем выученный постоянный ключ
	ASSERT_TRUE(responder.peer(learned));
	// Проверяем постоянный ключ инициатора
	EXPECT_EQ(::memcmp(learned, pi, 32), 0);
	// Кадр 2: вид 2, три нуля, номер отправителя, номер получателя, сообщение Noise (32 + 16), mac1, mac2
	uint8_t reply[RESPONSE];
	::memset(reply, 0, sizeof(reply));
	// Помечаем кадр видом 2
	reply[0] = 2;
	// Записываем номер отправителя
	put32(reply + 4, 0x55667788);
	put32(reply + 8, 0x11223344);
	// Оставляем место заголовку и меткам
	size = (sizeof(reply) - 12);
	// Пишем сообщение Noise в кадр
	ASSERT_TRUE(responder.write(view_t(), reply + 12, size));
	// Проверяем длину сообщения
	ASSERT_EQ(size, 48u);
	// Ставим метку mac1 в кадр
	ASSERT_TRUE(mac1(pi, reply, 60, reply + 60));
	ASSERT_TRUE(mac1(pi, reply, 60, expected));
	// Проверяем метку mac1 в кадре
	EXPECT_EQ(::memcmp(expected, reply + 60, MAC), 0);
	// Задаём ёмкость буфера
	length = 16;
	// Объявляем буфер пустого сообщения
	uint8_t nothing[16];
	// Читаем сообщение Noise инициатором
	ASSERT_TRUE(initiator.read(view_t(reply + 12, 48), nothing, length));
	// Проверяем, что сообщение пустое
	EXPECT_EQ(length, 0u);
	EXPECT_EQ(initiator.step(), noise::step_t::DONE);
	EXPECT_EQ(responder.step(), noise::step_t::DONE);
	// Раскол: у инициатора отправка первым состоянием, у отвечающего - вторым
	noise::cipher_t isend, irecv, rrecv, rsend;
	// Раскалываем инициатора на шифры переноса
	ASSERT_TRUE(initiator.split(isend, irecv));
	ASSERT_TRUE(responder.split(rrecv, rsend));
	// Объявляем буферы сводок рукопожатия
	uint8_t hi[32], hr[32];
	// Запрашиваем сводку у инициатора
	ASSERT_TRUE(initiator.digest(hi));
	// Запрашиваем сводку у отвечающего
	ASSERT_TRUE(responder.digest(hr));
	// Проверяем совпадение сводок
	EXPECT_EQ(::memcmp(hi, hr, 32), 0);
	// Пакет переноса: вид 4, три нуля, номер получателя, счётчик от младшего, шифротекст с меткой; счётчик явный, из заголовка
	const char * text = "wireguard payload";
	// Считаем длину текста
	const size_t plain = ::strlen(text);
	// Собираем пакет переноса: заголовок, текст, метка
	std::vector <uint8_t> packet(16 + plain + noise::TAG, 0);
	// Помечаем пакет видом 4
	packet[0] = 4;
	// Записываем номер получателя
	put32(packet.data() + 4, 0x55667788);
	// Задаём счётчик пакета
	const uint64_t counter = 7;
	// Записываем счётчик в заголовок
	put64(packet.data() + 8, counter);
	// Шифруем текст в пакет
	ASSERT_TRUE(isend.encrypt(counter, view_t(), view_t(reinterpret_cast <const uint8_t *> (text), plain), packet.data() + 16, packet.data() + 16 + plain));
	// Проверяем, что счётчик шифра не сдвинулся
	EXPECT_EQ(isend.nonce(), 0u);
	// Объявляем буфер расшифровки
	std::vector <uint8_t> back(plain);
	// Расшифровываем пакет счётчиком из заголовка
	ASSERT_TRUE(rrecv.decrypt(get64(packet.data() + 8), view_t(), view_t(packet.data() + 16, plain), view_t(packet.data() + 16 + plain, noise::TAG), back.data()));
	// Проверяем расшифрованный текст
	EXPECT_EQ(::memcmp(back.data(), text, plain), 0);
	// Чужой счётчик - отказ; повтор того же счётчика расшифровывается вновь: окно повтора ведёт потребитель
	EXPECT_FALSE(rrecv.decrypt(counter + 1, view_t(), view_t(packet.data() + 16, plain), view_t(packet.data() + 16 + plain, noise::TAG), back.data()));
	// Проверяем, что повтор счётчика проходит по окну повтора
	EXPECT_TRUE(rrecv.decrypt(counter, view_t(), view_t(packet.data() + 16, plain), view_t(packet.data() + 16 + plain, noise::TAG), back.data()));
	// Обратное направление
	uint8_t tag[noise::TAG], out[8], in[8];
	// Шифруем ответ обратным направлением
	ASSERT_TRUE(rsend.encrypt(0, view_t(), view_t(reinterpret_cast <const uint8_t *> ("pong"), 4), out, tag));
	ASSERT_TRUE(irecv.decrypt(0, view_t(), view_t(out, 4), view_t(tag, noise::TAG), in));
	// Проверяем расшифрованный ответ
	EXPECT_EQ(::memcmp(in, "pong", 4), 0);
	// Ключи переноса выдаются наружу под таблицы пар и совпадают у сторон
	uint8_t ki[32], kr[32];
	// Запрашиваем ключ переноса у инициатора
	ASSERT_TRUE(isend.key(ki));
	ASSERT_TRUE(rrecv.key(kr));
	// Проверяем совпадение ключей переноса
	EXPECT_EQ(::memcmp(ki, kr, 32), 0);
}
/**
 * @brief Отказы WireGuard: чужой psk, чужой Spub отвечающего, порча кадра под mac1
 *
 */
TEST(WireguardTest, Refusals){
	// Объявляем ключи сторон, общий ключ и посторонние байты
	uint8_t si[32], pi[32], sr[32], pr[32], psk[32], other[32], zeros[32];
	// Генерируем пару ключей инициатора
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, si, pi));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sr, pr));
	::memset(psk, 0x5C, 32);
	::memset(other, 0x3A, 32);
	::memset(zeros, 0, 32);
	// Объявляем буферы кадра и метки времени
	uint8_t frame[INITIATION], stamp[TAI64N], got[TAI64N];
	// Формируем метку времени
	tai64n(1788825600ULL, 0, stamp);
	// Чужой psk у отвечающего: кадр 1 проходит (psk примешивается лишь в кадре 2), кадр 2 не читается инициатором
	{
		// Объявляем стороны рукопожатия
		noise::handshake_t initiator, responder;
		// Заводим инициатора с общим ключом
		ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pr, psk));
		ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr, nullptr, other));
		::memset(frame, 0, sizeof(frame));
		// Задаём длину сообщения и ёмкость буфера
		size_t size = 108, length = sizeof(got);
		// Пишем сообщение Noise в кадр
		ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
		ASSERT_TRUE(responder.read(view_t(frame + 8, 108), got, length));
		// Объявляем буфер кадра 2
		uint8_t reply[RESPONSE];
		// Задаём длину сообщения
		size = 48;
		// Пишем ответ отвечающим
		ASSERT_TRUE(responder.write(view_t(), reply + 12, size));
		// Обнуляем длину прочитанного
		length = 0;
		// Проверяем отказ инициатора на чужой общий ключ
		EXPECT_FALSE(initiator.read(view_t(reply + 12, 48), nullptr, length));
		// Проверяем, что рукопожатие не состоялось
		EXPECT_EQ(initiator.step(), noise::step_t::NONE);
	}
	// Инициатор с чужим ключом отвечающего: отвечающий не расшифрует постоянный ключ
	{
		// Объявляем стороны рукопожатия
		noise::handshake_t initiator, responder;
		// Заводим инициатора с чужим ключом отвечающего
		ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pi, zeros));
		ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr, nullptr, zeros));
		::memset(frame, 0, sizeof(frame));
		// Задаём длину сообщения и ёмкость буфера
		size_t size = 108, length = sizeof(got);
		// Пишем сообщение Noise в кадр
		ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
		// Проверяем отказ отвечающего на чужой постоянный ключ
		EXPECT_FALSE(responder.read(view_t(frame + 8, 108), got, length));
		// Проверяем, что рукопожатие не состоялось
		EXPECT_EQ(responder.step(), noise::step_t::NONE);
	}
	// Порча байта кадра: mac1 не сходится - кадр отбрасывается до Noise
	{
		// Объявляем сторону рукопожатия
		noise::handshake_t initiator;
		// Заводим инициатора
		ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pr, zeros));
		::memset(frame, 0, sizeof(frame));
		// Помечаем кадр видом 1
		frame[0] = 1;
		// Задаём длину сообщения
		size_t size = 108;
		// Пишем сообщение Noise в кадр
		ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
		ASSERT_TRUE(mac1(pr, frame, 116, frame + 116));
		// Портим байт шифротекста кадра
		frame[40] ^= 1;
		// Объявляем буфер метки
		uint8_t expected[MAC];
		// Считаем метку mac1 по порченому кадру
		ASSERT_TRUE(mac1(pr, frame, 116, expected));
		// Проверяем расхождение метки mac1
		EXPECT_NE(::memcmp(expected, frame + 116, MAC), 0);
		// mac1 по чужому ключу получателя тоже не сходится
		frame[40] ^= 1;
		// Считаем метку mac1 по чужому ключу получателя
		ASSERT_TRUE(mac1(pi, frame, 116, expected));
		// Проверяем расхождение метки mac1
		EXPECT_NE(::memcmp(expected, frame + 116, MAC), 0);
	}
}
/**
 * @brief Эталонный вектор wireguard-go (порождён на закреплённых ключах, эфемеридах и метке времени): кадры 1 и 2 байт в байт, включая mac1
 *
 */
TEST(WireguardTest, Vector){
	// Читаем эталонный вектор из файла
	const auto v = reference(std::string(ANTS_CORPUS) + "/noise/wireguard.txt");
	// Проверяем число ключей эталона
	ASSERT_EQ(v.size(), 10u);
	// Достаём постоянные ключи и общий ключ
	const std::vector <uint8_t> & si = v.at("init_static"), & sr = v.at("resp_static"), & psk = v.at("psk");
	// Достаём эфемерные ключи и метку времени
	const std::vector <uint8_t> & ei = v.at("init_ephemeral"), & er = v.at("resp_ephemeral"), & stamp = v.at("timestamp");
	// Достаём опознаватели отправителя и получателя
	const std::vector <uint8_t> & sender = v.at("sender_index"), & receiver = v.at("receiver_index");
	// Достаём эталонные кадры
	const std::vector <uint8_t> & message1 = v.at("message1"), & message2 = v.at("message2");
	// Проверяем длину кадра 1
	ASSERT_EQ(message1.size(), INITIATION);
	ASSERT_EQ(message2.size(), RESPONSE);
	ASSERT_EQ(stamp.size(), TAI64N);
	// Объявляем буферы постоянных ключей
	uint8_t pi[32], pr[32];
	// Выводим открытый ключ инициатора
	ASSERT_TRUE(noise::derive(noise::dh_t::X25519, view_t(si.data(), 32), pi));
	ASSERT_TRUE(noise::derive(noise::dh_t::X25519, view_t(sr.data(), 32), pr));
	// Объявляем стороны рукопожатия
	noise::handshake_t initiator, responder;
	// Заводим инициатора закреплёнными ключами
	ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si.data(), pr, psk.data()));
	ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr.data(), nullptr, psk.data()));
	ASSERT_TRUE(initiator.ephemeral(view_t(ei.data(), 32)));
	ASSERT_TRUE(responder.ephemeral(view_t(er.data(), 32)));
	// Кадр 1
	uint8_t frame[INITIATION];
	::memset(frame, 0, sizeof(frame));
	// Помечаем кадр видом 1
	frame[0] = 1;
	// Опознаватели в файле - числа от старшего, в кадре они от младшего
	ASSERT_EQ(sender.size(), 4u);
	ASSERT_EQ(receiver.size(), 4u);
	/** Перебираем байты опознавателя от младшего, переворачивая порядок */
	for(size_t i = 0; i < 4; i++){ frame[4 + i] = sender[3 - i]; }
	// Задаём длину сообщения
	size_t size = 108;
	// Пишем сообщение Noise в кадр
	ASSERT_TRUE(initiator.write(view_t(stamp.data(), TAI64N), frame + 8, size));
	// Проверяем длину сообщения
	ASSERT_EQ(size, 108u);
	// Ставим метку mac1 в кадр
	ASSERT_TRUE(mac1(pr, frame, 116, frame + 116));
	// Проверяем кадр 1 эталоном
	EXPECT_EQ(::memcmp(frame, message1.data(), INITIATION), 0) << "кадр 1 расходится с wireguard-go";
	// Объявляем буфер метки времени
	uint8_t got[TAI64N];
	// Задаём ёмкость буфера
	size_t length = sizeof(got);
	// Читаем эталонный кадр 1 отвечающим
	ASSERT_TRUE(responder.read(view_t(message1.data() + 8, 108), got, length));
	// Проверяем длину прочитанного
	ASSERT_EQ(length, TAI64N);
	// Проверяем метку времени
	EXPECT_EQ(::memcmp(got, stamp.data(), TAI64N), 0);
	// Кадр 2
	uint8_t reply[RESPONSE];
	::memset(reply, 0, sizeof(reply));
	// Помечаем кадр видом 2
	reply[0] = 2;
	/** Перебираем байты опознавателей от младшего, переворачивая порядок */
	for(size_t i = 0; i < 4; i++){ reply[4 + i] = receiver[3 - i]; reply[8 + i] = sender[3 - i]; }
	// Задаём длину сообщения
	size = 48;
	// Пишем сообщение Noise в кадр
	ASSERT_TRUE(responder.write(view_t(), reply + 12, size));
	// Проверяем длину сообщения
	ASSERT_EQ(size, 48u);
	// Ставим метку mac1 в кадр
	ASSERT_TRUE(mac1(pi, reply, 60, reply + 60));
	// Проверяем кадр 2 эталоном
	EXPECT_EQ(::memcmp(reply, message2.data(), RESPONSE), 0) << "кадр 2 расходится с wireguard-go";
	// Объявляем буфер пустого сообщения
	uint8_t nothing[16];
	// Задаём ёмкость буфера
	length = sizeof(nothing);
	// Читаем эталонный кадр 2 инициатором
	ASSERT_TRUE(initiator.read(view_t(message2.data() + 12, 48), nothing, length));
	// Проверяем, что сообщение пустое
	EXPECT_EQ(length, 0u);
	EXPECT_EQ(initiator.step(), noise::step_t::DONE);
	EXPECT_EQ(responder.step(), noise::step_t::DONE);
}
