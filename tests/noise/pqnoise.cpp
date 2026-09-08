/**
 * @file pqnoise.cpp
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
 * @brief Проверки PQNoise: отвлечение KEM, тринадцать узоров в обе роли, предельные длины, свой замороженный корпус, отказы
 *
 * @details Чужого корпуса у PQNoise нет. Корпус tests/corpus/noise/pqnoise.txt порождён нашим же
 *          кодом на закреплённых зёрнах и заморожен: он доказывает неизменность поведения с
 *          дня заморозки, не правильность и не совместимость. Пересоздание - только вслух:
 *          ANTS_NOISE_FREEZE=путь пишет новый файл и проваливает проверку, чтобы заморозка не
 *          прошла молча
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
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
#include <starve.hpp>
#include <noise/noise.hpp>
#include <noise/cipher.hpp>
#include <noise/handshake.hpp>
#include <agreement/mlkem.hpp>
#include <agreement/x25519.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * Путь к набору корпусов
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты набора
 *
 */
namespace {
	/**
	 * Узоры PQNoise
	 */
	static const noise::pattern_t PATTERNS[] = {
		noise::pattern_t::PQN, noise::pattern_t::PQNN, noise::pattern_t::PQNK, noise::pattern_t::PQNX, noise::pattern_t::PQKN,
		noise::pattern_t::PQKK, noise::pattern_t::PQKX, noise::pattern_t::PQXN, noise::pattern_t::PQXK, noise::pattern_t::PQXX,
		noise::pattern_t::PQIN, noise::pattern_t::PQIK, noise::pattern_t::PQIX
	};
	/**
	 * Механизмы и наборы
	 */
	static const noise::kem_t KEMS[] = {noise::kem_t::X25519MLKEM768, noise::kem_t::MLKEM768};
	static const noise::aead_t AEADS[] = {noise::aead_t::CHACHAPOLY, noise::aead_t::AESGCM};
	static const digest::hash_t HASHES[] = {digest::hash_t::SHA256, digest::hash_t::SHA512, digest::hash_t::BLAKE2S256, digest::hash_t::BLAKE2B512};
	/**
	 * @brief Область байтов вектора
	 */
	static view_t span(const std::vector <uint8_t> & data) {
		return view_t(data.empty() ? nullptr : data.data(), data.size());
	}
	/**
	 * @brief Область байтов строки
	 */
	static view_t span(const std::string & text) {
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
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
	 * @brief Запись байтов шестнадцатеричной строкой
	 */
	static std::string hex(const uint8_t * data, const size_t size) {
		std::string result;
		static const char * DIGITS = "0123456789abcdef";
		for(size_t i = 0; i < size; i++){ result.push_back(DIGITS[data[i] >> 4]); result.push_back(DIGITS[data[i] & 0x0F]); }
		return result;
	}
	/**
	 * @brief Детерминированное заполнение: байт i = (seed + i * step) mod 256
	 */
	static std::vector <uint8_t> bytes(const size_t size, const uint8_t seed, const uint8_t step) {
		std::vector <uint8_t> result(size);
		for(size_t i = 0; i < size; i++) result[i] = static_cast <uint8_t> (seed + (i * step));
		return result;
	}
	/**
	 * @brief Имя протокола по узору и набору
	 */
	static std::string title(const noise::pattern_t pattern, const noise::suite_t & suite) {
		char text[noise::NAME_LIMIT];
		size_t size = sizeof(text);
		if(!noise::name(pattern, 0, suite, text, size)) return std::string();
		return std::string(text, size);
	}
	/**
	 * @brief Признак того, что предсообщение стороны несёт постоянный ключ
	 */
	static bool preknown(const noise::pattern_t pattern, const bool initiator) {
		const noise::token_t * list = nullptr;
		size_t count = 0;
		return (noise::premessage(pattern, initiator, list, count) && (count > 0));
	}
	/**
	 * @brief Число своих знаков KEM у стороны - столько случайностей нужно корпусу
	 */
	static size_t kemtokens(const noise::pattern_t pattern, const bool initiator) {
		size_t result = 0;
		for(size_t i = 0; i < noise::messages(pattern); i++){
			if(((i % 2) == 0) != initiator) continue;
			const noise::token_t * list = nullptr;
			size_t count = 0;
			noise::tokens(pattern, i, list, count);
			for(size_t j = 0; j < count; j++) if((list[j] == noise::token_t::EKEM) || (list[j] == noise::token_t::SKEM)) result++;
		}
		return result;
	}
	/**
	 * @brief Запись корпуса
	 */
	typedef struct Record {
		std::string name;
		std::vector <uint8_t> prologue, initStatic, respStatic, initEphemeral, respEphemeral, hash;
		std::vector <std::vector <uint8_t>> initCoins, respCoins;
		std::vector <std::pair <std::vector <uint8_t>, std::vector <uint8_t>>> messages;
	} record_t;
	/**
	 * @brief Прогон одной записи: обе стороны на зёрнах записи; при freeze шифртексты и хеш заполняются, иначе сличаются
	 *
	 * @return пустая строка либо описание расхождения
	 */
	static std::string run(record_t & record, const bool freeze) {
		noise::pattern_t pattern;
		noise::psk_t psks;
		noise::suite_t suite;
		if(!noise::parse(span(record.name), pattern, psks, suite)) return "имя не разобрано";
		noise::handshake_t a, b;
		if(!a.start(span(record.name), noise::role_t::INITIATOR, span(record.prologue)) || !b.start(span(record.name), noise::role_t::RESPONDER, span(record.prologue))) return "не заведено";
		if(!record.initStatic.empty() && !a.statics(span(record.initStatic))) return "статика инициатора";
		if(!record.respStatic.empty() && !b.statics(span(record.respStatic))) return "статика отвечающего";
		if(!record.initEphemeral.empty() && !a.ephemeral(span(record.initEphemeral))) return "эфемерида инициатора";
		if(!record.respEphemeral.empty() && !b.ephemeral(span(record.respEphemeral))) return "эфемерида отвечающего";
		// Чужие постоянные ключи по предсообщениям - из открытой части пары собеседника
		uint8_t key[noise::KEM_PUBLIC_MAX];
		if(preknown(pattern, false)){ if(!b.self(key) || !a.remote(view_t(key, b.keylength()))) return "ключ отвечающего"; }
		if(preknown(pattern, true)){ if(!a.self(key) || !b.remote(view_t(key, a.keylength()))) return "ключ инициатора"; }
		std::vector <view_t> ic, rc;
		for(auto & item : record.initCoins) ic.push_back(span(item));
		for(auto & item : record.respCoins) rc.push_back(span(item));
		if(!ic.empty() && !a.coinsDeterministic(ic.data(), ic.size())) return "случайности инициатора";
		if(!rc.empty() && !b.coinsDeterministic(rc.data(), rc.size())) return "случайности отвечающего";
		const size_t count = noise::messages(pattern);
		if(record.messages.size() < count) return "мало сообщений";
		std::vector <uint8_t> out(noise::MESSAGE), back(noise::MESSAGE);
		for(size_t i = 0; i < count; i++){
			noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
			noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
			size_t size = out.size(), got = back.size();
			if(!writer.write(span(record.messages[i].first), out.data(), size)) return "запись " + std::to_string(i);
			if(freeze) record.messages[i].second.assign(out.data(), out.data() + size);
			else if((size != record.messages[i].second.size()) || (::memcmp(out.data(), record.messages[i].second.data(), size) != 0)) return "шифртекст " + std::to_string(i);
			if(!reader.read(view_t(out.data(), size), back.data(), got)) return "чтение " + std::to_string(i);
			if((got != record.messages[i].first.size()) || ((got > 0) && (::memcmp(back.data(), record.messages[i].first.data(), got) != 0))) return "полезная часть " + std::to_string(i);
		}
		if((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)) return "не завершено";
		uint8_t ha[64], hb[64];
		if(!a.digest(ha) || !b.digest(hb) || (::memcmp(ha, hb, a.length()) != 0)) return "хеши сторон разошлись";
		if(freeze) record.hash.assign(ha, ha + a.length());
		else if((record.hash.size() != a.length()) || (::memcmp(ha, record.hash.data(), a.length()) != 0)) return "хеш рукопожатия";
		noise::cipher_t a1, a2, b1, b2;
		if(!a.split(a1, a2) || !b.split(b1, b2)) return "раскол";
		for(size_t m = count; m < record.messages.size(); m++){
			const bool fromInitiator = ((count == 1) || (((m - count) % 2) == 0));
			noise::cipher_t & sender = (fromInitiator ? a1 : b2);
			noise::cipher_t & receiver = (fromInitiator ? b1 : a2);
			const std::vector <uint8_t> & payload = record.messages[m].first;
			uint8_t tag[noise::TAG];
			if(!sender.encrypt(view_t(), span(payload), out.data(), tag)) return "перенос запись " + std::to_string(m);
			std::vector <uint8_t> cipher(out.data(), out.data() + payload.size());
			cipher.insert(cipher.end(), tag, tag + noise::TAG);
			if(freeze) record.messages[m].second = cipher;
			else if(cipher != record.messages[m].second) return "перенос шифртекст " + std::to_string(m);
			if(!receiver.decrypt(view_t(), view_t(cipher.data(), payload.size()), view_t(cipher.data() + payload.size(), noise::TAG), back.data())) return "перенос чтение " + std::to_string(m);
			if((payload.size() > 0) && (::memcmp(back.data(), payload.data(), payload.size()) != 0)) return "перенос полезная часть " + std::to_string(m);
		}
		return std::string();
	}
	/**
	 * @brief Построение записей корпуса на закреплённых зёрнах: 13 узоров × 2 KEM × 2 набора шифра и хеша
	 */
	static std::vector <record_t> build() {
		std::vector <record_t> result;
		const noise::aead_t aeads[] = {noise::aead_t::CHACHAPOLY, noise::aead_t::AESGCM};
		const digest::hash_t hashes[] = {digest::hash_t::SHA256, digest::hash_t::BLAKE2B512};
		uint8_t number = 0;
		for(auto pattern : PATTERNS){
			for(auto kem : KEMS){
				for(size_t v = 0; v < 2; v++){
					record_t record;
					noise::suite_t suite(kem, aeads[v], hashes[v]);
					record.name = title(pattern, suite);
					record.prologue = bytes(11, 0x50, 1);
					const size_t seed = noise::kemlength(kem, noise::part_t::SEED), coins = noise::kemlength(kem, noise::part_t::COINS);
					number++;
					record.initStatic = bytes(seed, static_cast <uint8_t> (0x10 + number), 3);
					record.respStatic = bytes(seed, static_cast <uint8_t> (0x20 + number), 5);
					record.initEphemeral = bytes(seed, static_cast <uint8_t> (0x30 + number), 7);
					record.respEphemeral = bytes(seed, static_cast <uint8_t> (0x40 + number), 11);
					for(size_t i = 0; i < kemtokens(pattern, true); i++) record.initCoins.push_back(bytes(coins, static_cast <uint8_t> (0x60 + number + i), 13));
					for(size_t i = 0; i < kemtokens(pattern, false); i++) record.respCoins.push_back(bytes(coins, static_cast <uint8_t> (0x80 + number + i), 17));
					const size_t count = noise::messages(pattern);
					for(size_t i = 0; i < count; i++) record.messages.push_back(std::make_pair(bytes(i * 5, 0x41, 1), std::vector <uint8_t> ()));
					record.messages.push_back(std::make_pair(bytes(16, 0x61, 1), std::vector <uint8_t> ()));
					record.messages.push_back(std::make_pair(bytes(9, 0x71, 1), std::vector <uint8_t> ()));
					result.push_back(record);
				}
			}
		}
		return result;
	}
	/**
	 * @brief Запись корпуса файлом
	 */
	static bool save(const std::string & path, const std::vector <record_t> & records) {
		std::ofstream file(path);
		if(!file.is_open()) return false;
		file << "# Корпус PQNoise, порождён кодом A-NTS на закреплённых зёрнах. Доказывает неизменность поведения с дня заморозки,\n# не правильность и не совместимость: чужой реализации PQNoise, с которой его можно сличить, не существует.\n";
		for(auto & record : records){
			file << "\nhandshake=" << record.name << "\n";
			file << "prologue=" << hex(record.prologue.data(), record.prologue.size()) << "\n";
			file << "init_static_seed=" << hex(record.initStatic.data(), record.initStatic.size()) << "\n";
			file << "resp_static_seed=" << hex(record.respStatic.data(), record.respStatic.size()) << "\n";
			file << "init_ephemeral_seed=" << hex(record.initEphemeral.data(), record.initEphemeral.size()) << "\n";
			file << "resp_ephemeral_seed=" << hex(record.respEphemeral.data(), record.respEphemeral.size()) << "\n";
			for(size_t i = 0; i < record.initCoins.size(); i++) file << "init_coins_" << i << "=" << hex(record.initCoins[i].data(), record.initCoins[i].size()) << "\n";
			for(size_t i = 0; i < record.respCoins.size(); i++) file << "resp_coins_" << i << "=" << hex(record.respCoins[i].data(), record.respCoins[i].size()) << "\n";
			file << "handshake_hash=" << hex(record.hash.data(), record.hash.size()) << "\n";
			for(size_t i = 0; i < record.messages.size(); i++){
				file << "msg_" << i << "_payload=" << hex(record.messages[i].first.data(), record.messages[i].first.size()) << "\n";
				file << "msg_" << i << "_ciphertext=" << hex(record.messages[i].second.data(), record.messages[i].second.size()) << "\n";
			}
		}
		return true;
	}
	/**
	 * @brief Чтение корпуса файлом
	 */
	static std::vector <record_t> load(const std::string & path) {
		std::vector <record_t> result;
		std::ifstream file(path);
		if(!file.is_open()) return result;
		record_t record;
		bool open = false;
		std::string line;
		auto flush = [&]() { if(open) result.push_back(record); record = record_t(); open = false; };
		while(std::getline(file, line)){
			if(line.empty() || (line[0] == '#')){ if(line.empty()) flush(); continue; }
			const size_t eq = line.find('=');
			if(eq == std::string::npos) continue;
			const std::string key = line.substr(0, eq), value = line.substr(eq + 1);
			open = true;
			if(key == "handshake") record.name = value;
			else if(key == "prologue") record.prologue = unhex(value);
			else if(key == "init_static_seed") record.initStatic = unhex(value);
			else if(key == "resp_static_seed") record.respStatic = unhex(value);
			else if(key == "init_ephemeral_seed") record.initEphemeral = unhex(value);
			else if(key == "resp_ephemeral_seed") record.respEphemeral = unhex(value);
			else if(key == "handshake_hash") record.hash = unhex(value);
			else if(key.compare(0, 11, "init_coins_") == 0) record.initCoins.push_back(unhex(value));
			else if(key.compare(0, 11, "resp_coins_") == 0) record.respCoins.push_back(unhex(value));
			else if(key.compare(0, 4, "msg_") == 0){
				const size_t second = key.find('_', 4);
				const size_t number = ::strtoul(key.substr(4, second - 4).c_str(), nullptr, 10);
				if(record.messages.size() <= number) record.messages.resize(number + 1);
				if(key.substr(second + 1) == "payload") record.messages[number].first = unhex(value);
				else record.messages[number].second = unhex(value);
			}
		}
		flush();
		return result;
	}
};

/**
 * @brief Отвлечение KEM: длины, составной KEM против раздельного счёта ML-KEM и X25519 на зерне, отказы
 *
 */
TEST(PqnoiseTest, Kem){
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::PUBLIC), 1216u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SECRET), 2432u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::CIPHERTEXT), 1120u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SHARED), 64u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SEED), 96u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::COINS), 64u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::PUBLIC), 1184u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::SECRET), 2400u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::CIPHERTEXT), 1088u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::SHARED), 32u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::NONE, noise::part_t::PUBLIC), 0u);
	// Составной: зерно 64 ‖ 32, пара = ML-KEM из 64 и X25519 из 32
	const std::vector <uint8_t> seed = bytes(96, 0x01, 1), coins = bytes(64, 0x90, 1);
	uint8_t pk[1216], sk[2432], ek[1184], dk[2400], xpub[32];
	ASSERT_TRUE(noise::kemgenerateDeterministic(noise::kem_t::X25519MLKEM768, span(seed), pk, sk));
	ASSERT_TRUE(agreement::generate(agreement::kem_t::MLKEM768, view_t(seed.data(), 64), ek, dk));
	ASSERT_TRUE(agreement::x25519(view_t(seed.data() + 64, 32), xpub));
	EXPECT_EQ(::memcmp(pk, ek, 1184), 0);
	EXPECT_EQ(::memcmp(pk + 1184, xpub, 32), 0);
	EXPECT_EQ(::memcmp(sk, dk, 2400), 0);
	EXPECT_EQ(::memcmp(sk + 2400, seed.data() + 64, 32), 0);
	uint8_t ct[1120], ss[64], ct2[1088], ss2[32], epub[32], xss[32], back[64];
	ASSERT_TRUE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), span(coins), ct, ss));
	ASSERT_TRUE(agreement::encapsulate(agreement::kem_t::MLKEM768, view_t(ek, 1184), view_t(coins.data(), 32), ct2, ss2));
	ASSERT_TRUE(agreement::x25519(view_t(coins.data() + 32, 32), epub));
	ASSERT_TRUE(agreement::x25519(view_t(coins.data() + 32, 32), view_t(xpub, 32), xss));
	EXPECT_EQ(::memcmp(ct, ct2, 1088), 0);
	EXPECT_EQ(::memcmp(ct + 1088, epub, 32), 0);
	EXPECT_EQ(::memcmp(ss, ss2, 32), 0);
	EXPECT_EQ(::memcmp(ss + 32, xss, 32), 0);
	ASSERT_TRUE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(ct, 1120), back));
	EXPECT_EQ(::memcmp(back, ss, 64), 0);
	// Повтор случайности даёт тот же шифртекст - потому вызов зовётся Deterministic
	uint8_t again[1120], ssagain[64];
	ASSERT_TRUE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), span(coins), again, ssagain));
	EXPECT_EQ(::memcmp(ct, again, 1120), 0);
	// Из энтропии - иной
	ASSERT_TRUE(noise::encapsulate(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), again, ssagain));
	EXPECT_NE(::memcmp(ct, again, 1120), 0);
	ASSERT_TRUE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(again, 1120), back));
	EXPECT_EQ(::memcmp(back, ssagain, 64), 0);
	// Точка малого порядка в составном - отказ; у чистого ML-KEM подделка - неявное отклонение, не отказ
	::memset(again + 1088, 0, 32);
	EXPECT_FALSE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(again, 1120), back));
	uint8_t forged[1088];
	::memcpy(forged, ct2, 1088);
	forged[0] ^= 1;
	uint8_t rejected[32];
	ASSERT_TRUE(noise::decapsulate(noise::kem_t::MLKEM768, view_t(dk, 2400), view_t(forged, 1088), rejected));
	EXPECT_NE(::memcmp(rejected, ss2, 32), 0);
	// Отказы длин
	EXPECT_FALSE(noise::kemgenerateDeterministic(noise::kem_t::X25519MLKEM768, view_t(seed.data(), 64), pk, sk));
	EXPECT_FALSE(noise::kemgenerateDeterministic(noise::kem_t::MLKEM768, view_t(seed.data(), 96), pk, sk));
	EXPECT_FALSE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1184), span(coins), ct, ss));
	EXPECT_FALSE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), view_t(coins.data(), 32), ct, ss));
	EXPECT_FALSE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2400), view_t(ct, 1120), back));
	EXPECT_FALSE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(ct, 1088), back));
	EXPECT_FALSE(noise::kemgenerate(noise::kem_t::NONE, pk, sk));
}
/**
 * @brief Имена PQNoise: составление и разбор, отказ на psk и на смешении семейств
 *
 */
TEST(PqnoiseTest, Names){
	noise::pattern_t pattern;
	noise::psk_t psks;
	noise::suite_t suite;
	for(auto p : PATTERNS){
		for(auto kem : KEMS){
			const std::string name = title(p, noise::suite_t(kem, noise::aead_t::AESGCM, digest::hash_t::BLAKE2S256));
			ASSERT_FALSE(name.empty());
			EXPECT_EQ(name.compare(0, 8, "PQNoise_"), 0) << name;
			ASSERT_TRUE(noise::parse(span(name), pattern, psks, suite)) << name;
			EXPECT_EQ(pattern, p);
			EXPECT_EQ(suite.kem, kem);
			EXPECT_EQ(suite.dh, noise::dh_t::NONE);
			EXPECT_TRUE(noise::postquantum(pattern));
		}
	}
	EXPECT_TRUE(noise::parse(span(std::string("PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_EQ(pattern, noise::pattern_t::PQXX);
	EXPECT_FALSE(noise::parse(span(std::string("PQNoise_pqXXpsk0_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("PQNoise_XX_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("PQNoise_pqXX_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XX_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::postquantum(noise::pattern_t::XX));
	// Узор и набор разных семейств - отказ составления и заведения
	char text[noise::NAME_LIMIT];
	size_t size = sizeof(text);
	EXPECT_FALSE(noise::name(noise::pattern_t::PQXX, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), text, size));
	size = sizeof(text);
	EXPECT_FALSE(noise::name(noise::pattern_t::XX, 0, noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA256), text, size));
	size = sizeof(text);
	EXPECT_FALSE(noise::name(noise::pattern_t::PQXX, 0x01, noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA256), text, size));
	noise::handshake_t h;
	EXPECT_FALSE(h.start(noise::pattern_t::PQXX, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
	EXPECT_FALSE(h.start(noise::pattern_t::XX, 0, noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
	// Классические знаки не встречаются в pq-узорах и наоборот
	for(uint8_t i = 1; i <= static_cast <uint8_t> (noise::pattern_t::PQIX); i++){
		const noise::pattern_t p = static_cast <noise::pattern_t> (i);
		if(noise::messages(p) == 0) continue;
		for(size_t m = 0; m < noise::messages(p); m++){
			const noise::token_t * list = nullptr;
			size_t count = 0;
			ASSERT_TRUE(noise::tokens(p, m, list, count));
			for(size_t j = 0; j < count; j++){
				const bool kemtoken = ((list[j] == noise::token_t::EKEM) || (list[j] == noise::token_t::SKEM));
				const bool dhtoken = ((list[j] == noise::token_t::EE) || (list[j] == noise::token_t::ES) || (list[j] == noise::token_t::SE) || (list[j] == noise::token_t::SS));
				EXPECT_EQ(kemtoken, noise::postquantum(p) && kemtoken) << noise::title(p);
				EXPECT_FALSE(noise::postquantum(p) && dhtoken) << noise::title(p);
				EXPECT_FALSE(!noise::postquantum(p) && kemtoken) << noise::title(p);
			}
		}
	}
}
/**
 * @brief Обе роли своим кодом: тринадцать узоров × два KEM × восемь наборов, полезная часть, хеш, ключ собеседника, перенос
 *
 */
TEST(PqnoiseTest, Roundtrip){
	size_t handshakes = 0;
	for(auto pattern : PATTERNS){
		for(auto kem : KEMS){
			for(auto aead : AEADS){
				for(auto hash : HASHES){
					record_t record;
					record.name = title(pattern, noise::suite_t(kem, aead, hash));
					ASSERT_FALSE(record.name.empty());
					const size_t seed = noise::kemlength(kem, noise::part_t::SEED);
					record.initStatic = bytes(seed, 0x11, 1);
					record.respStatic = bytes(seed, 0x22, 1);
					for(size_t i = 0; i < noise::messages(pattern); i++) record.messages.push_back(std::make_pair(bytes(7, 0x30, 1), std::vector <uint8_t> ()));
					record.messages.push_back(std::make_pair(bytes(5, 0x40, 1), std::vector <uint8_t> ()));
					record.messages.push_back(std::make_pair(bytes(3, 0x50, 1), std::vector <uint8_t> ()));
					// Эфемериды и случайности из энтропии: заморозка не задана, значит шифртексты не сличаются, а проверяется круг
					const std::string failure = run(record, true);
					EXPECT_TRUE(failure.empty()) << record.name << ": " << failure;
					handshakes++;
				}
			}
		}
	}
	EXPECT_EQ(handshakes, 208u);
	// Ключ собеседника узнаётся верно и оба состояния переноса живы; у pqN второе без ключа
	noise::handshake_t a, b;
	const std::string name = "PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256";
	uint8_t sa[2432], pa[1216], sb[2432], pb[1216], out[4096], back[64];
	ASSERT_TRUE(noise::kemgenerate(noise::kem_t::X25519MLKEM768, pa, sa));
	ASSERT_TRUE(noise::kemgenerate(noise::kem_t::X25519MLKEM768, pb, sb));
	const std::vector <uint8_t> seedA = bytes(96, 0x33, 1), seedB = bytes(96, 0x44, 1);
	ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(a.statics(span(seedA)));
	ASSERT_TRUE(b.statics(span(seedB)));
	EXPECT_EQ(a.keylength(), 1216u);
	while((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)){
		noise::handshake_t & writer = (a.step() == noise::step_t::WRITE) ? a : b;
		noise::handshake_t & reader = (a.step() == noise::step_t::WRITE) ? b : a;
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(writer.write(view_t(), out, size));
		ASSERT_TRUE(reader.read(view_t(out, size), back, got));
	}
	uint8_t learned[1216], own[1216];
	ASSERT_TRUE(a.peer(learned));
	ASSERT_TRUE(b.self(own));
	EXPECT_EQ(::memcmp(learned, own, 1216), 0);
	ASSERT_TRUE(b.peer(learned));
	ASSERT_TRUE(a.self(own));
	EXPECT_EQ(::memcmp(learned, own, 1216), 0);
	noise::cipher_t n1, n2;
	noise::handshake_t c, d;
	ASSERT_TRUE(c.start(span(std::string("PQNoise_pqN_MLKEM768_AESGCM_SHA512")), noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(d.start(span(std::string("PQNoise_pqN_MLKEM768_AESGCM_SHA512")), noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(d.statics(view_t(seedB.data(), 64)));
	ASSERT_TRUE(d.self(own));
	ASSERT_TRUE(c.remote(view_t(own, 1184)));
	size_t size = sizeof(out), got = sizeof(back);
	ASSERT_TRUE(c.write(span(std::string("sealed")), out, size));
	EXPECT_EQ(size, 1088u + 6u + noise::TAG);
	ASSERT_TRUE(d.read(view_t(out, size), back, got));
	EXPECT_EQ(got, 6u);
	ASSERT_TRUE(c.split(n1, n2));
	EXPECT_TRUE(n1.has());
	EXPECT_FALSE(n2.has());
}
/**
 * @brief Предельные длины сообщений, посчитанные заранее: pqXX и pqIK на обоих KEM; полезная часть до предела проходит, сверх - отказ
 *
 */
TEST(PqnoiseTest, Limits){
	// Накладные расходы сообщений pqXX и pqIK при составном (ct 1120, pk 1216) и чистом (1088, 1184) KEM
	const size_t composite[4] = {1216, 1120 + 1216 + 16 + 16, 1120 + 16 + 1216 + 16 + 16, 1120 + 16 + 16};
	const size_t pure[4] = {1184, 1088 + 1184 + 16 + 16, 1088 + 16 + 1184 + 16 + 16, 1088 + 16 + 16};
	const size_t ikComposite[2] = {1120 + 1216 + 1216 + 16 + 16, 1120 + 1120 + 16 + 16};
	const size_t ikPure[2] = {1088 + 1184 + 1184 + 16 + 16, 1088 + 1088 + 16 + 16};
	for(auto kem : KEMS){
		const bool comp = (kem == noise::kem_t::X25519MLKEM768);
		const size_t seed = noise::kemlength(kem, noise::part_t::SEED);
		const std::vector <uint8_t> seedA = bytes(seed, 0x01, 1), seedB = bytes(seed, 0x02, 1);
		std::vector <uint8_t> out(noise::MESSAGE + 64), back(noise::MESSAGE);
		// pqXX: пустая полезная часть даёт ровно накладные расходы
		{
			noise::handshake_t a, b;
			const std::string name = title(noise::pattern_t::PQXX, noise::suite_t(kem, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256));
			ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
			ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
			ASSERT_TRUE(a.statics(span(seedA)));
			ASSERT_TRUE(b.statics(span(seedB)));
			for(size_t i = 0; i < 4; i++){
				noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
				noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
				size_t size = out.size(), got = back.size();
				ASSERT_TRUE(writer.write(view_t(), out.data(), size));
				EXPECT_EQ(size, comp ? composite[i] : pure[i]) << name << " сообщение " << i;
				ASSERT_TRUE(reader.read(view_t(out.data(), size), back.data(), got));
				EXPECT_EQ(got, 0u);
			}
		}
		// pqIK
		{
			noise::handshake_t a, b;
			const std::string name = title(noise::pattern_t::PQIK, noise::suite_t(kem, noise::aead_t::AESGCM, digest::hash_t::BLAKE2S256));
			ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
			ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
			ASSERT_TRUE(a.statics(span(seedA)));
			ASSERT_TRUE(b.statics(span(seedB)));
			uint8_t key[noise::KEM_PUBLIC_MAX];
			ASSERT_TRUE(b.self(key));
			ASSERT_TRUE(a.remote(view_t(key, b.keylength())));
			for(size_t i = 0; i < 2; i++){
				noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
				noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
				size_t size = out.size(), got = back.size();
				ASSERT_TRUE(writer.write(view_t(), out.data(), size));
				EXPECT_EQ(size, comp ? ikComposite[i] : ikPure[i]) << name << " сообщение " << i;
				ASSERT_TRUE(reader.read(view_t(out.data(), size), back.data(), got));
			}
		}
		// Второе сообщение pqXX: полезная часть до 65535 - накладные проходит, +1 - отказ
		for(size_t extra = 0; extra < 2; extra++){
			noise::handshake_t a, b;
			const std::string name = title(noise::pattern_t::PQXX, noise::suite_t(kem, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256));
			ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
			ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
			ASSERT_TRUE(a.statics(span(seedA)));
			ASSERT_TRUE(b.statics(span(seedB)));
			size_t size = out.size(), got = back.size();
			ASSERT_TRUE(a.write(view_t(), out.data(), size));
			ASSERT_TRUE(b.read(view_t(out.data(), size), back.data(), got));
			const size_t limit = (noise::MESSAGE - (comp ? composite[1] : pure[1]));
			std::vector <uint8_t> payload(limit + extra, 0x7A);
			size = out.size();
			if(extra == 0){
				ASSERT_TRUE(b.write(span(payload), out.data(), size)) << name;
				EXPECT_EQ(size, noise::MESSAGE);
				got = back.size();
				ASSERT_TRUE(a.read(view_t(out.data(), size), back.data(), got));
				EXPECT_EQ(got, limit);
			} else {
				EXPECT_FALSE(b.write(span(payload), out.data(), size)) << name;
			}
		}
	}
}
/**
 * @brief Свой замороженный корпус: 52 записи, сличение байт в байт; ANTS_NOISE_FREEZE пересоздаёт его вслух и проваливает проверку
 *
 */
TEST(PqnoiseTest, Corpus){
	const std::string path = (std::string(CORPUS) + "/noise/pqnoise.txt");
	const char * freeze = ::getenv("ANTS_NOISE_FREEZE");
	if(freeze != nullptr){
		std::vector <record_t> records = build();
		for(auto & record : records){
			const std::string failure = run(record, true);
			ASSERT_TRUE(failure.empty()) << record.name << ": " << failure;
		}
		ASSERT_TRUE(save(freeze, records));
		FAIL() << "корпус пересоздан в " << freeze << " (" << records.size() << " записей): заморозка вслух, проверка нарочно провалена";
	}
	std::vector <record_t> records = load(path);
	ASSERT_EQ(records.size(), 52u);
	size_t taken = 0;
	for(auto & record : records){
		const std::string failure = run(record, false);
		EXPECT_TRUE(failure.empty()) << record.name << ": " << failure;
		if(failure.empty()) taken++;
	}
	std::printf("pqnoise: взято %zu из %zu (корпус наш: доказывает неизменность с дня заморозки, не правильность)\n", taken, records.size());
	EXPECT_EQ(taken, 52u);
	// Корпус обязан совпадать с построенным по тем же зёрнам - иначе заморозка устарела
	std::vector <record_t> fresh = build();
	ASSERT_EQ(fresh.size(), records.size());
	for(size_t i = 0; i < fresh.size(); i++){
		EXPECT_EQ(fresh[i].name, records[i].name);
		EXPECT_EQ(fresh[i].initStatic, records[i].initStatic) << records[i].name;
		EXPECT_EQ(fresh[i].initCoins, records[i].initCoins) << records[i].name;
		EXPECT_EQ(fresh[i].respCoins, records[i].respCoins) << records[i].name;
	}
}
/**
 * @brief Отказы PQNoise: зерно чужой длины, ключ собеседника чужой длины, случайности не по числу, порча шифртекста, чужая статика, паёк выделений
 *
 */
TEST(PqnoiseTest, Refusals){
	const std::string name = "PQNoise_pqXX_X25519MLKEM768_AESGCM_SHA512";
	const std::vector <uint8_t> seedA = bytes(96, 0x05, 1), seedB = bytes(96, 0x06, 1), coins = bytes(64, 0x07, 1);
	uint8_t out[4096], back[64];
	{
		noise::handshake_t a;
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		EXPECT_FALSE(a.statics(view_t(seedA.data(), 64)));
		EXPECT_FALSE(a.statics(view_t(seedA.data(), 32)));
		EXPECT_FALSE(a.ephemeral(view_t(seedA.data(), 95)));
		EXPECT_FALSE(a.remote(view_t(out, 32)));
		EXPECT_FALSE(a.remote(view_t(out, 1184)));
		view_t coin(coins.data(), 32);
		EXPECT_FALSE(a.coinsDeterministic(&coin, 1));
		view_t good(coins.data(), 64);
		EXPECT_TRUE(a.coinsDeterministic(&good, 1));
		view_t psk(seedA.data(), 32);
		EXPECT_FALSE(a.psks(&psk, 1));
		// Случайности заданы и исчерпаны - отказ, не энтропия: у pqXX инициатору нужна одна (skem), задана одна, второй круг с одной у отвечающего (ekem, skem - нужны две)
		noise::handshake_t x, y;
		ASSERT_TRUE(x.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(y.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(x.statics(span(seedA)));
		ASSERT_TRUE(y.statics(span(seedB)));
		ASSERT_TRUE(y.coinsDeterministic(&good, 1));
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(x.write(view_t(), out, size));
		ASSERT_TRUE(y.read(view_t(out, size), back, got));
		size = sizeof(out);
		ASSERT_TRUE(y.write(view_t(), out, size));
		got = sizeof(back);
		ASSERT_TRUE(x.read(view_t(out, size), back, got));
		size = sizeof(out);
		ASSERT_TRUE(x.write(view_t(), out, size));
		got = sizeof(back);
		ASSERT_TRUE(y.read(view_t(out, size), back, got));
		size = sizeof(out);
		EXPECT_FALSE(y.write(view_t(), out, size));
		EXPECT_EQ(y.step(), noise::step_t::NONE);
		// Классика случайностей KEM не принимает
		noise::handshake_t c;
		ASSERT_TRUE(c.start(span(std::string("Noise_XX_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
		EXPECT_FALSE(c.coinsDeterministic(&good, 1));
	}
	// Порча шифртекста skem: расшифровка не сходится, состояние неисправно
	{
		noise::handshake_t a, b;
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(span(seedA)));
		ASSERT_TRUE(b.statics(span(seedB)));
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		size = sizeof(out); got = sizeof(back);
		ASSERT_TRUE(b.write(view_t(), out, size));
		// Порча шифртекста ekem (в открытом виде): секрет расходится, метка полезной части не сходится
		out[10] ^= 1;
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		EXPECT_EQ(a.step(), noise::step_t::NONE);
	}
	// Чужая статика отвечающего у pqIK: skem инициатора распаковывается не тем ключом, метка не сходится
	{
		noise::handshake_t a, b;
		const std::string ik = "PQNoise_pqIK_MLKEM768_ChaChaPoly_BLAKE2s";
		ASSERT_TRUE(a.start(span(ik), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(ik), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(view_t(seedA.data(), 64)));
		ASSERT_TRUE(b.statics(view_t(seedB.data(), 64)));
		uint8_t other[1184], sk[2400];
		ASSERT_TRUE(noise::kemgenerate(noise::kem_t::MLKEM768, other, sk));
		ASSERT_TRUE(a.remote(view_t(other, 1184)));
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(a.write(view_t(), out, size));
		EXPECT_FALSE(b.read(view_t(out, size), back, got));
		EXPECT_EQ(b.step(), noise::step_t::NONE);
		// Без своего постоянного ключа отвечающий pqIK не заведётся: чужой skem нечем распаковать
		noise::handshake_t d;
		ASSERT_TRUE(d.start(span(ik), noise::role_t::RESPONDER, view_t()));
		got = sizeof(back);
		EXPECT_FALSE(d.read(view_t(out, size), back, got));
	}
	// Паёк выделений: полный круг pqXX без единого выделения
	{
		noise::handshake_t a, b;
		noise::cipher_t a1, a2, b1, b2;
		static const uint8_t NAME[] = "PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_BLAKE2s";
		bool status = true;
		uint8_t tag[16];
		{
			starve::ration_t ration(0);
			status = (a.start(view_t(NAME, sizeof(NAME) - 1), noise::role_t::INITIATOR, view_t()) && b.start(view_t(NAME, sizeof(NAME) - 1), noise::role_t::RESPONDER, view_t()));
			status = (status && a.statics(view_t(seedA.data(), 96)) && b.statics(view_t(seedB.data(), 96)));
			for(size_t i = 0; status && (i < 4); i++){
				noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
				noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
				size_t size = sizeof(out), got = sizeof(back);
				status = (writer.write(view_t(), out, size) && reader.read(view_t(out, size), back, got));
			}
			status = (status && a.split(a1, a2) && b.split(b1, b2));
			status = (status && a1.encrypt(view_t(), view_t(seedA.data(), 8), out, tag) && b1.decrypt(view_t(), view_t(out, 8), view_t(tag, 16), back));
			ration.stop();
		}
		EXPECT_TRUE(status);
		EXPECT_EQ(::memcmp(back, seedA.data(), 8), 0);
	}
}
