/**
 * @file sha3.cpp
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
 * @brief Проверки модуля хеширования SHA-3 и функций переменного выхода SHAKE по FIPS 202
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <random>
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/sha3.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 * @return     запись строчными шестнадцатеричными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		// Записываем младший полубайт
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Выводим запись
	return result;
}
/**
 * @brief Функция хеширования сообщения за один вызов
 *
 * @param type    разновидность преобразования
 * @param message сообщение
 * @param size    длина итога
 * @return        запись итога шестнадцатеричной строкой либо пустая при отказе
 *
 */
static std::string whole(const digest::sha3_t type, const std::string & message, const size_t size) {
	// Место, в которое записывается итог
	std::vector <uint8_t> result(size, 0);
	// Если итог вычислить не удалось
	if(!digest::sha3(type, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result.data(), size))
		// Выводим пустую запись
		return std::string();
	// Выводим запись итога
	return text(result.data(), size);
}
/**
 * @brief Функция хеширования сообщения кусками заданной длины
 *
 * @param type    разновидность преобразования
 * @param message сообщение
 * @param chunk   длина куска
 * @param size    длина итога
 * @return        запись итога шестнадцатеричной строкой либо пустая при отказе
 *
 */
static std::string pieces(const digest::sha3_t type, const std::string & message, const size_t chunk, const size_t size) {
	// Объект преобразования
	digest::keccak_t keccak(type);
	/**
	 * Выполняем подачу сообщения кусками
	 */
	for(size_t offset = 0; offset < message.size(); offset += chunk){
		// Длина очередного куска
		const size_t length = (((message.size() - offset) < chunk) ? (message.size() - offset) : chunk);
		// Если кусок поглотить не удалось
		if(!keccak.update(view_t(reinterpret_cast <const uint8_t *> (message.data()) + offset, length)))
			// Выводим пустую запись
			return std::string();
	}
	// Место, в которое записывается итог
	std::vector <uint8_t> result(size, 0);
	// Если итог снять не удалось
	if(!keccak.finish(result.data(), size))
		// Выводим пустую запись
		return std::string();
	// Выводим запись итога
	return text(result.data(), size);
}

/**
 * Хеши пустого сообщения по FIPS 202
 */
TEST(Sha3Test, Empty){
	// Проверяем SHA3-224 пустого сообщения
	ASSERT_EQ(whole(digest::sha3_t::SHA3_224, "", 28), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
	// Проверяем SHA3-256 пустого сообщения
	ASSERT_EQ(whole(digest::sha3_t::SHA3_256, "", 32), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	// Проверяем SHA3-384 пустого сообщения
	ASSERT_EQ(whole(digest::sha3_t::SHA3_384, "", 48), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
	// Проверяем SHA3-512 пустого сообщения
	ASSERT_EQ(whole(digest::sha3_t::SHA3_512, "", 64), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
	// Проверяем SHAKE128 пустого сообщения на 32 байта
	ASSERT_EQ(whole(digest::sha3_t::SHAKE128, "", 32), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
	// Проверяем SHAKE256 пустого сообщения на 32 байта
	ASSERT_EQ(whole(digest::sha3_t::SHAKE256, "", 32), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

/**
 * Хеши сообщения «abc» по FIPS 202
 */
TEST(Sha3Test, Abc){
	// Проверяем SHA3-224
	ASSERT_EQ(whole(digest::sha3_t::SHA3_224, "abc", 28), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
	// Проверяем SHA3-256
	ASSERT_EQ(whole(digest::sha3_t::SHA3_256, "abc", 32), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
	// Проверяем SHA3-384
	ASSERT_EQ(whole(digest::sha3_t::SHA3_384, "abc", 48), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
	// Проверяем SHA3-512
	ASSERT_EQ(whole(digest::sha3_t::SHA3_512, "abc", 64), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
	// Проверяем SHAKE128 на 32 байта
	ASSERT_EQ(whole(digest::sha3_t::SHAKE128, "abc", 32), "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
	// Проверяем SHAKE256 на 64 байта
	ASSERT_EQ(whole(digest::sha3_t::SHAKE256, "abc", 64), "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
}

/**
 * Сообщение в 448 разрядов по FIPS 202
 */
TEST(Sha3Test, Twoblock){
	// Сообщение
	const std::string message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	// Проверяем SHA3-224
	ASSERT_EQ(whole(digest::sha3_t::SHA3_224, message, 28), "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
	// Проверяем SHA3-256
	ASSERT_EQ(whole(digest::sha3_t::SHA3_256, message, 32), "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
	// Проверяем SHA3-384
	ASSERT_EQ(whole(digest::sha3_t::SHA3_384, message, 48), "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22");
}

/**
 * Миллион знаков «a» по FIPS 202 и SHAKE128 на 200 байтов
 */
TEST(Sha3Test, Million){
	// Сообщение
	const std::string message(1000000, 'a');
	// Проверяем SHA3-256
	ASSERT_EQ(whole(digest::sha3_t::SHA3_256, message, 32), "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");
	// Проверяем SHA3-512
	ASSERT_EQ(whole(digest::sha3_t::SHA3_512, message, 64), "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87");
	// Проверяем SHAKE128 на 200 байтов: выход длиннее скорости в 168 байтов, вторая перестановка выжимания
	ASSERT_EQ(whole(digest::sha3_t::SHAKE128, message, 200), "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58424c4b5c28475ffdcf981663867fec6321c1262e387bccf8ca676884c4a9d0c13bfa6869763d5ae4bbc9b3ccd09d1ca5ea7446538d69b3fb98c72b59a2b4817db5eadd9011f90fa71091931f8134f4f00b562e2fe105937270361c1909862ad45046e3932f5dd311ec72fec5f8fb8f60b45a3bee3f85bbf7fcedc6a555677648e0654b381941a86bd3e512657b0d57a7991fc4543f89d8290492222ce4a33e17602b3b99c009f765");
}

/**
 * Независимость итога от нарезки сообщения на куски
 */
TEST(Sha3Test, Chunks){
	// Генератор сообщений с закреплённым зерном
	std::mt19937 generator(20260907);
	// Длины кусков, включая длины вокруг скоростей 72, 104, 136, 144 и 168
	const size_t chunks[] = {1, 7, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 1000};
	// Разновидности
	const digest::sha3_t kinds[] = {digest::sha3_t::SHA3_224, digest::sha3_t::SHA3_256, digest::sha3_t::SHA3_384, digest::sha3_t::SHA3_512, digest::sha3_t::SHAKE128, digest::sha3_t::SHAKE256};
	/**
	 * Перебираем длины сообщений с шагом 37 до шестисот знаков
	 */
	for(size_t length = 0; length <= 600; length += 37){
		// Сообщение
		std::string message(length, 'x');
		/**
		 * Заполняем сообщение знаками из генератора
		 */
		for(size_t i = 0; i < message.size(); i++)
			// Записываем очередной знак
			message[i] = static_cast <char> (generator() & 0xFF);
		/**
		 * Перебираем разновидности хешей и функции переменного выхода
		 */
		for(size_t k = 0; k < (sizeof(kinds) / sizeof(kinds[0])); k++){
			// Длина итога: у хешей своя, у функций переменного выхода 100 байтов
			const size_t size = ((digest::length(kinds[k]) > 0) ? digest::length(kinds[k]) : 100);
			// Итог за один вызов
			const std::string reference = whole(kinds[k], message, size);
			// Проверяем, что итог вычислен
			ASSERT_FALSE(reference.empty());
			/**
			 * Перебираем длины кусков вокруг границ скоростей поглощения
			 */
			for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++)
				// Проверяем схождение итога кусками с итогом за один вызов
				ASSERT_EQ(pieces(kinds[k], message, chunks[c], size), reference) << "длина " << length << " кусок " << chunks[c] << " разновидность " << static_cast <int> (kinds[k]);
		}
	}
}

/**
 * Выжимание функции переменного выхода кусками сходится с выжиманием за один раз
 */
TEST(Sha3Test, Squeezing){
	// Сообщение
	const std::string message = "The quick brown fox jumps over the lazy dog";
	// Итог за один раз в 500 байтов
	const std::string reference = whole(digest::sha3_t::SHAKE256, message, 500);
	// Длины кусков выжимания
	const size_t chunks[] = {1, 3, 64, 135, 136, 137, 271, 499};
	/**
	 * Перебираем длины кусков выжимания
	 */
	for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++){
		// Объект преобразования
		digest::keccak_t keccak(digest::sha3_t::SHAKE256);
		// Поглощаем сообщение
		ASSERT_TRUE(keccak.update(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size())));
		// Место, в которое записывается итог
		std::vector <uint8_t> result(500, 0);
		/**
		 * Выжимаем итог кусками заданной длины
		 */
		for(size_t offset = 0; offset < result.size(); offset += chunks[c]){
			// Длина очередного куска
			const size_t length = (((result.size() - offset) < chunks[c]) ? (result.size() - offset) : chunks[c]);
			// Выжимаем кусок
			ASSERT_TRUE(keccak.squeeze(result.data() + offset, length));
		}
		// Проверяем схождение с итогом за один раз
		ASSERT_EQ(text(result.data(), result.size()), reference) << "кусок " << chunks[c];
		// Проверяем отказ поглощения после выжимания
		ASSERT_FALSE(keccak.update(view_t(reinterpret_cast <const uint8_t *> ("x"), 1)));
		// Проверяем отказ снятия итога после выжимания
		ASSERT_FALSE(keccak.finish(result.data(), 32));
	}
}

/**
 * Отказы и служебные методы
 */
TEST(Sha3Test, Refusals){
	// Место, в которое записывается итог
	uint8_t result[64];
	// Объект без разновидности
	digest::keccak_t none(digest::sha3_t::NONE);
	// Проверяем отказ поглощения без разновидности
	ASSERT_FALSE(none.update(view_t(reinterpret_cast <const uint8_t *> ("abc"), 3)));
	// Проверяем отказ снятия итога без разновидности
	ASSERT_FALSE(none.finish(result, sizeof(result)));
	// Проверяем отказ выжимания без разновидности
	ASSERT_FALSE(none.squeeze(result, sizeof(result)));
	// Проверяем длины итогов
	ASSERT_EQ(digest::length(digest::sha3_t::SHA3_224), 28u);
	ASSERT_EQ(digest::length(digest::sha3_t::SHA3_512), 64u);
	ASSERT_EQ(digest::length(digest::sha3_t::SHAKE128), 0u);
	ASSERT_EQ(digest::length(digest::sha3_t::NONE), 0u);
	// Проверяем скорости
	ASSERT_EQ(digest::rate(digest::sha3_t::SHA3_224), 144u);
	ASSERT_EQ(digest::rate(digest::sha3_t::SHA3_256), 136u);
	ASSERT_EQ(digest::rate(digest::sha3_t::SHA3_384), 104u);
	ASSERT_EQ(digest::rate(digest::sha3_t::SHA3_512), 72u);
	ASSERT_EQ(digest::rate(digest::sha3_t::SHAKE128), 168u);
	ASSERT_EQ(digest::rate(digest::sha3_t::SHAKE256), 136u);
	ASSERT_EQ(digest::rate(digest::sha3_t::NONE), 0u);
	// Объект SHA3-256
	digest::keccak_t keccak(digest::sha3_t::SHA3_256);
	// Проверяем разновидность и скорость
	ASSERT_EQ(keccak.type(), digest::sha3_t::SHA3_256);
	ASSERT_EQ(keccak.block(), 136u);
	// Проверяем отказ выжимания у хеша
	ASSERT_FALSE(keccak.squeeze(result, 32));
	// Проверяем отказ снятия итога в место иной длины
	ASSERT_FALSE(keccak.finish(result, 31));
	ASSERT_FALSE(keccak.finish(result, 33));
	// Проверяем отказ снятия итога в пустое место
	ASSERT_FALSE(keccak.finish(nullptr, 32));
	// Проверяем поглощение пустого куска
	ASSERT_TRUE(keccak.update(view_t()));
	// Проверяем снятие итога ровно по длине
	ASSERT_TRUE(keccak.finish(result, 32));
	// Проверяем итог пустого сообщения после отказов
	ASSERT_EQ(text(result, 32), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
	// Проверяем отказ повторного снятия итога
	ASSERT_FALSE(keccak.finish(result, 32));
	// Выполняем сброс на SHAKE128
	keccak.reset(digest::sha3_t::SHAKE128);
	// Проверяем разновидность после сброса
	ASSERT_EQ(keccak.type(), digest::sha3_t::SHAKE128);
	// Проверяем выжимание после сброса
	ASSERT_TRUE(keccak.squeeze(result, 32));
	// Проверяем итог пустого сообщения
	ASSERT_EQ(text(result, 32), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
	// Проверяем отказ одного вызова с негодной длиной
	ASSERT_FALSE(digest::sha3(digest::sha3_t::SHA3_384, view_t(), result, 32));
	// Проверяем отказ одного вызова функции переменного выхода на нулевую длину
	ASSERT_FALSE(digest::sha3(digest::sha3_t::SHAKE256, view_t(), result, 0));
}
