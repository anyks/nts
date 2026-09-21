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
	static const char * IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
	static const char * LABEL_MAC1 = "mac1----";
	/**
	 * Длины кадров
	 */
	static constexpr size_t INITIATION = 148, RESPONSE = 92, MAC = 16, TAI64N = 12;
	/**
	 * @brief Область байтов строки
	 */
	static view_t span(const char * text) {
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
	/**
	 * @brief Запись 32-разрядного числа от младшего
	 */
	static void put32(uint8_t * place, const uint32_t value) {
		for(size_t i = 0; i < 4; i++) place[i] = static_cast <uint8_t> (value >> (8 * i));
	}
	/**
	 * @brief Запись 64-разрядного числа от младшего
	 */
	static void put64(uint8_t * place, const uint64_t value) {
		for(size_t i = 0; i < 8; i++) place[i] = static_cast <uint8_t> (value >> (8 * i));
	}
	/**
	 * @brief Чтение 64-разрядного числа от младшего
	 */
	static uint64_t get64(const uint8_t * place) {
		uint64_t value = 0;
		for(size_t i = 0; i < 8; i++) value |= (static_cast <uint64_t> (place[i]) << (8 * i));
		return value;
	}
	/**
	 * @brief Метка mac1: BLAKE2s с ключом HASH(LABEL_MAC1 ‖ Spub) по кадру до метки
	 *
	 * @param statics открытый постоянный ключ получателя
	 * @param frame   кадр
	 * @param size    длина кадра до метки
	 * @param result  место метки в 16 октетов
	 */
	static bool mac1(const uint8_t * statics, const uint8_t * frame, const size_t size, uint8_t * result) {
		std::vector <uint8_t> input(reinterpret_cast <const uint8_t *> (LABEL_MAC1), reinterpret_cast <const uint8_t *> (LABEL_MAC1) + 8);
		input.insert(input.end(), statics, statics + 32);
		uint8_t key[32];
		if(!digest::hash(digest::hash_t::BLAKE2S256, view_t(input.data(), input.size()), key, 32)) return false;
		return digest::blake2(digest::blake_t::BLAKE2S, view_t(key, 32), view_t(frame, size), result, MAC);
	}
	/**
	 * @brief TAI64N: секунды от старшего со сдвигом 2^62, наносекунды от старшего
	 */
	static void tai64n(const uint64_t seconds, const uint32_t nanos, uint8_t * result) {
		const uint64_t value = (0x4000000000000000ULL + seconds);
		for(size_t i = 0; i < 8; i++) result[i] = static_cast <uint8_t> (value >> (8 * (7 - i)));
		for(size_t i = 0; i < 4; i++) result[8 + i] = static_cast <uint8_t> (nanos >> (8 * (3 - i)));
	}
	/**
	 * @brief Разбор шестнадцатеричной строки
	 */
	static std::vector <uint8_t> unhex(const std::string & text) {
		std::vector <uint8_t> result;
		for(size_t i = 0; (i + 1) < text.size(); i += 2) result.push_back(static_cast <uint8_t> (::strtoul(text.substr(i, 2).c_str(), nullptr, 16)));
		return result;
	}
	/**
	 * @brief Чтение эталонного вектора wireguard-go: ключ=hex построчно, строки с решёткой - шапка
	 */
	static std::map <std::string, std::vector <uint8_t>> reference(const std::string & path) {
		std::map <std::string, std::vector <uint8_t>> result;
		std::ifstream file(path);
		std::string line;
		while(std::getline(file, line)){
			if(line.empty() || (line[0] == '#')) continue;
			const size_t eq = line.find('=');
			if(eq == std::string::npos) continue;
			result[line.substr(0, eq)] = unhex(line.substr(eq + 1));
		}
		return result;
	}
	/**
	 * @brief Заведение стороны WireGuard: узор именем, пролог IDENTIFIER, ключи, psk (нули, если нет)
	 */
	static bool arm(noise::handshake_t & side, const noise::role_t role, const uint8_t * secret, const uint8_t * remote, const uint8_t * psk) {
		if(!side.start(span(CONSTRUCTION), role, span(IDENTIFIER))) return false;
		if(!side.statics(view_t(secret, 32))) return false;
		if((remote != nullptr) && !side.remote(view_t(remote, 32))) return false;
		view_t key(psk, 32);
		return side.psks(&key, 1);
	}
};

/**
 * @brief Полный круг WireGuard: кадр 1 (148), кадр 2 (92), mac1 пересчётом, перенос с явным счётчиком
 *
 */
TEST(WireguardTest, Handshake){
	uint8_t si[32], pi[32], sr[32], pr[32], psk[32];
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, si, pi));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sr, pr));
	for(size_t i = 0; i < 32; i++) psk[i] = static_cast <uint8_t> (0xA0 + i);
	noise::handshake_t initiator, responder;
	ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pr, psk));
	ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr, nullptr, psk));
	// Кадр 1: вид 1, три нуля, номер отправителя, сообщение Noise (32 + 48 + 28), mac1, mac2 (нули без печенья)
	uint8_t frame[INITIATION];
	::memset(frame, 0, sizeof(frame));
	frame[0] = 1;
	put32(frame + 4, 0x11223344);
	uint8_t stamp[TAI64N];
	tai64n(1788825600ULL, 123456789u, stamp);
	size_t size = (sizeof(frame) - 8);
	ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
	ASSERT_EQ(size, 108u);
	ASSERT_TRUE(mac1(pr, frame, 116, frame + 116));
	// Отвечающий: сперва mac1 по своему открытому ключу, затем Noise
	uint8_t expected[MAC];
	ASSERT_TRUE(mac1(pr, frame, 116, expected));
	EXPECT_EQ(::memcmp(expected, frame + 116, MAC), 0);
	uint8_t got[TAI64N];
	size_t length = sizeof(got);
	ASSERT_TRUE(responder.read(view_t(frame + 8, 108), got, length));
	ASSERT_EQ(length, TAI64N);
	EXPECT_EQ(::memcmp(got, stamp, TAI64N), 0);
	uint8_t learned[32];
	ASSERT_TRUE(responder.peer(learned));
	EXPECT_EQ(::memcmp(learned, pi, 32), 0);
	// Кадр 2: вид 2, три нуля, номер отправителя, номер получателя, сообщение Noise (32 + 16), mac1, mac2
	uint8_t reply[RESPONSE];
	::memset(reply, 0, sizeof(reply));
	reply[0] = 2;
	put32(reply + 4, 0x55667788);
	put32(reply + 8, 0x11223344);
	size = (sizeof(reply) - 12);
	ASSERT_TRUE(responder.write(view_t(), reply + 12, size));
	ASSERT_EQ(size, 48u);
	ASSERT_TRUE(mac1(pi, reply, 60, reply + 60));
	ASSERT_TRUE(mac1(pi, reply, 60, expected));
	EXPECT_EQ(::memcmp(expected, reply + 60, MAC), 0);
	length = 16;
	uint8_t nothing[16];
	ASSERT_TRUE(initiator.read(view_t(reply + 12, 48), nothing, length));
	EXPECT_EQ(length, 0u);
	EXPECT_EQ(initiator.step(), noise::step_t::DONE);
	EXPECT_EQ(responder.step(), noise::step_t::DONE);
	// Раскол: у инициатора отправка первым состоянием, у отвечающего - вторым
	noise::cipher_t isend, irecv, rrecv, rsend;
	ASSERT_TRUE(initiator.split(isend, irecv));
	ASSERT_TRUE(responder.split(rrecv, rsend));
	uint8_t hi[32], hr[32];
	ASSERT_TRUE(initiator.digest(hi));
	ASSERT_TRUE(responder.digest(hr));
	EXPECT_EQ(::memcmp(hi, hr, 32), 0);
	// Пакет переноса: вид 4, три нуля, номер получателя, счётчик от младшего, шифротекст с меткой; счётчик явный, из заголовка
	const char * text = "wireguard payload";
	const size_t plain = ::strlen(text);
	std::vector <uint8_t> packet(16 + plain + noise::TAG, 0);
	packet[0] = 4;
	put32(packet.data() + 4, 0x55667788);
	const uint64_t counter = 7;
	put64(packet.data() + 8, counter);
	ASSERT_TRUE(isend.encrypt(counter, view_t(), view_t(reinterpret_cast <const uint8_t *> (text), plain), packet.data() + 16, packet.data() + 16 + plain));
	EXPECT_EQ(isend.nonce(), 0u);
	std::vector <uint8_t> back(plain);
	ASSERT_TRUE(rrecv.decrypt(get64(packet.data() + 8), view_t(), view_t(packet.data() + 16, plain), view_t(packet.data() + 16 + plain, noise::TAG), back.data()));
	EXPECT_EQ(::memcmp(back.data(), text, plain), 0);
	// Чужой счётчик - отказ; повтор того же счётчика расшифровывается вновь: окно повтора ведёт потребитель
	EXPECT_FALSE(rrecv.decrypt(counter + 1, view_t(), view_t(packet.data() + 16, plain), view_t(packet.data() + 16 + plain, noise::TAG), back.data()));
	EXPECT_TRUE(rrecv.decrypt(counter, view_t(), view_t(packet.data() + 16, plain), view_t(packet.data() + 16 + plain, noise::TAG), back.data()));
	// Обратное направление
	uint8_t tag[noise::TAG], out[8], in[8];
	ASSERT_TRUE(rsend.encrypt(0, view_t(), view_t(reinterpret_cast <const uint8_t *> ("pong"), 4), out, tag));
	ASSERT_TRUE(irecv.decrypt(0, view_t(), view_t(out, 4), view_t(tag, noise::TAG), in));
	EXPECT_EQ(::memcmp(in, "pong", 4), 0);
	// Ключи переноса выдаются наружу под таблицы пар и совпадают у сторон
	uint8_t ki[32], kr[32];
	ASSERT_TRUE(isend.key(ki));
	ASSERT_TRUE(rrecv.key(kr));
	EXPECT_EQ(::memcmp(ki, kr, 32), 0);
}
/**
 * @brief Отказы WireGuard: чужой psk, чужой Spub отвечающего, порча кадра под mac1
 *
 */
TEST(WireguardTest, Refusals){
	uint8_t si[32], pi[32], sr[32], pr[32], psk[32], other[32], zeros[32];
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, si, pi));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sr, pr));
	::memset(psk, 0x5C, 32);
	::memset(other, 0x3A, 32);
	::memset(zeros, 0, 32);
	uint8_t frame[INITIATION], stamp[TAI64N], got[TAI64N];
	tai64n(1788825600ULL, 0, stamp);
	// Чужой psk у отвечающего: кадр 1 проходит (psk примешивается лишь в кадре 2), кадр 2 не читается инициатором
	{
		noise::handshake_t initiator, responder;
		ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pr, psk));
		ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr, nullptr, other));
		::memset(frame, 0, sizeof(frame));
		size_t size = 108, length = sizeof(got);
		ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
		ASSERT_TRUE(responder.read(view_t(frame + 8, 108), got, length));
		uint8_t reply[RESPONSE];
		size = 48;
		ASSERT_TRUE(responder.write(view_t(), reply + 12, size));
		length = 0;
		EXPECT_FALSE(initiator.read(view_t(reply + 12, 48), nullptr, length));
		EXPECT_EQ(initiator.step(), noise::step_t::NONE);
	}
	// Инициатор с чужим ключом отвечающего: отвечающий не расшифрует постоянный ключ
	{
		noise::handshake_t initiator, responder;
		ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pi, zeros));
		ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr, nullptr, zeros));
		::memset(frame, 0, sizeof(frame));
		size_t size = 108, length = sizeof(got);
		ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
		EXPECT_FALSE(responder.read(view_t(frame + 8, 108), got, length));
		EXPECT_EQ(responder.step(), noise::step_t::NONE);
	}
	// Порча байта кадра: mac1 не сходится - кадр отбрасывается до Noise
	{
		noise::handshake_t initiator;
		ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si, pr, zeros));
		::memset(frame, 0, sizeof(frame));
		frame[0] = 1;
		size_t size = 108;
		ASSERT_TRUE(initiator.write(view_t(stamp, TAI64N), frame + 8, size));
		ASSERT_TRUE(mac1(pr, frame, 116, frame + 116));
		frame[40] ^= 1;
		uint8_t expected[MAC];
		ASSERT_TRUE(mac1(pr, frame, 116, expected));
		EXPECT_NE(::memcmp(expected, frame + 116, MAC), 0);
		// mac1 по чужому ключу получателя тоже не сходится
		frame[40] ^= 1;
		ASSERT_TRUE(mac1(pi, frame, 116, expected));
		EXPECT_NE(::memcmp(expected, frame + 116, MAC), 0);
	}
}
/**
 * @brief Эталонный вектор wireguard-go (порождён на закреплённых ключах, эфемеридах и метке времени): кадры 1 и 2 байт в байт, включая mac1
 *
 */
TEST(WireguardTest, Vector){
	const auto v = reference(std::string(ANTS_CORPUS) + "/noise/wireguard.txt");
	ASSERT_EQ(v.size(), 10u);
	const std::vector <uint8_t> & si = v.at("init_static"), & sr = v.at("resp_static"), & psk = v.at("psk");
	const std::vector <uint8_t> & ei = v.at("init_ephemeral"), & er = v.at("resp_ephemeral"), & stamp = v.at("timestamp");
	const std::vector <uint8_t> & sender = v.at("sender_index"), & receiver = v.at("receiver_index");
	const std::vector <uint8_t> & message1 = v.at("message1"), & message2 = v.at("message2");
	ASSERT_EQ(message1.size(), INITIATION);
	ASSERT_EQ(message2.size(), RESPONSE);
	ASSERT_EQ(stamp.size(), TAI64N);
	uint8_t pi[32], pr[32];
	ASSERT_TRUE(noise::derive(noise::dh_t::X25519, view_t(si.data(), 32), pi));
	ASSERT_TRUE(noise::derive(noise::dh_t::X25519, view_t(sr.data(), 32), pr));
	noise::handshake_t initiator, responder;
	ASSERT_TRUE(arm(initiator, noise::role_t::INITIATOR, si.data(), pr, psk.data()));
	ASSERT_TRUE(arm(responder, noise::role_t::RESPONDER, sr.data(), nullptr, psk.data()));
	ASSERT_TRUE(initiator.ephemeral(view_t(ei.data(), 32)));
	ASSERT_TRUE(responder.ephemeral(view_t(er.data(), 32)));
	// Кадр 1
	uint8_t frame[INITIATION];
	::memset(frame, 0, sizeof(frame));
	frame[0] = 1;
	// Опознаватели в файле - числа от старшего, в кадре они от младшего
	ASSERT_EQ(sender.size(), 4u);
	ASSERT_EQ(receiver.size(), 4u);
	for(size_t i = 0; i < 4; i++){ frame[4 + i] = sender[3 - i]; }
	size_t size = 108;
	ASSERT_TRUE(initiator.write(view_t(stamp.data(), TAI64N), frame + 8, size));
	ASSERT_EQ(size, 108u);
	ASSERT_TRUE(mac1(pr, frame, 116, frame + 116));
	EXPECT_EQ(::memcmp(frame, message1.data(), INITIATION), 0) << "кадр 1 расходится с wireguard-go";
	uint8_t got[TAI64N];
	size_t length = sizeof(got);
	ASSERT_TRUE(responder.read(view_t(message1.data() + 8, 108), got, length));
	ASSERT_EQ(length, TAI64N);
	EXPECT_EQ(::memcmp(got, stamp.data(), TAI64N), 0);
	// Кадр 2
	uint8_t reply[RESPONSE];
	::memset(reply, 0, sizeof(reply));
	reply[0] = 2;
	for(size_t i = 0; i < 4; i++){ reply[4 + i] = receiver[3 - i]; reply[8 + i] = sender[3 - i]; }
	size = 48;
	ASSERT_TRUE(responder.write(view_t(), reply + 12, size));
	ASSERT_EQ(size, 48u);
	ASSERT_TRUE(mac1(pi, reply, 60, reply + 60));
	EXPECT_EQ(::memcmp(reply, message2.data(), RESPONSE), 0) << "кадр 2 расходится с wireguard-go";
	uint8_t nothing[16];
	length = sizeof(nothing);
	ASSERT_TRUE(initiator.read(view_t(message2.data() + 12, 48), nothing, length));
	EXPECT_EQ(length, 0u);
	EXPECT_EQ(initiator.step(), noise::step_t::DONE);
	EXPECT_EQ(responder.step(), noise::step_t::DONE);
}
