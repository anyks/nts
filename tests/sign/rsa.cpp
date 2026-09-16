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
 * @brief Исходный файл проверок модуля RSA
 *
 * @note Эталон - OpenSSL 3.6.3: ключ порождён командой
 *       openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048, записи
 *       сняты командами openssl rsa -traditional -outform DER и -RSAPublicKey_out,
 *       составляющие - командой openssl rsa -text. Подписи сообщения выработаны
 *       командой openssl dgst -sign с хешами SHA-256 и SHA-1 по PKCS #1 v1.5 и
 *       с -sigopt rsa_padding_mode:pss по PSS (соль 32 байта у SHA-256 и 20 у
 *       SHA-512), шифротексты - командой openssl pkeyutl -encrypt по OAEP с
 *       -pkeyopt rsa_oaep_md:sha256 и по PKCS #1 v1.5. Подпись PSS с заданной
 *       солью, шифротексты OAEP с заданной затравкой и PKCS #1 v1.5 с заданным
 *       дополнением выработаны этим модулем и признаны OpenSSL командами
 *       openssl dgst -verify и openssl pkeyutl -decrypt: они закреплены здесь
 *       ожидаемыми значениями. Подпись PKCS #1 v1.5 детерминирована, оттого
 *       своя подпись сличается с подписью OpenSSL напрямую
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstring>
#include <main.hpp>
#include <starve.hpp>
#include <sign/rsa.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Подписываемое сообщение
 */
static const char * MESSAGE = "The quick brown fox jumps over the lazy dog";

/**
 * Шифруемое сообщение
 */
static const char * PLAINTEXT = "secret message for OAEP";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 *
 * @return     разобранные байты
 *
 */
static std::vector <uint8_t> bytes(const char * text) {
	// Разобранные байты
	std::vector <uint8_t> result;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; text[i * 2] != '\0'; i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		result.push_back(value);
	}
	// Выводим разобранные байты
	return result;
}
/**
 * @brief Метод сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
 *
 * @return     собранная запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор собираемых байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(data[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[data[i] & 0x0F]);
	}
	// Выводим собранную запись
	return result;
}
/**
 * @brief Метод получения просмотра байтов
 *
 * @param data байты, на которые строится просмотр
 *
 * @return     просмотр байтов
 *
 */
static view_t view(const std::vector <uint8_t> & data) {
	// Выводим просмотр байтов
	return view_t(data.data(), data.size());
}
/**
 * @brief Метод получения просмотра строки
 *
 * @param data строка, на которую строится просмотр
 *
 * @return     просмотр строки
 *
 */
static view_t view(const char * data) {
	// Выводим просмотр строки
	return view_t(reinterpret_cast <const uint8_t *> (data), strlen(data));
}
/**
 * @brief Метод получения записи составляющей ключа
 *
 * @param rsa  модуль RSA с ключом
 * @param part составляющая ключа
 *
 * @return     запись составляющей шестнадцатеричными знаками
 *
 */
static std::string part(const sign::rsa_t & rsa, const sign::part_t part) {
	// Байты составляющей
	uint8_t buffer[math::INTEGER_SIZE];
	// Размер составляющей
	const size_t size = rsa.length(part);
	// Получаем составляющую
	EXPECT_TRUE(rsa.part(part, buffer, size));
	// Выводим запись составляющей
	return text(buffer, size);
}
/**
 * @brief Метод выработки хеша сообщения
 *
 * @param algorithm алгоритм хеширования
 * @param result    место, в которое помещается хеш
 *
 * @return          длина хеша
 *
 */
static size_t hashed(const digest::hash_t algorithm, uint8_t * result) {
	// Длина хеша
	const size_t size = digest::length(algorithm);
	// Вырабатываем хеш сообщения
	EXPECT_TRUE(digest::hash(algorithm, view(MESSAGE), result, size));
	// Выводим длину хеша
	return size;
}

/**
 * Секретный ключ OpenSSL: RSAPrivateKey в DER
 */
static const char * KEY_DER =
	"308204a30201000282010100b3da3fc81ae97a81f2bd1ae347a0dc63a2aaef771b05977e909ac277dca6069fe56f9525"
	"a43f084ee8eabf623ad2a9b83b106db34e3ebfe6010f66bd14455abab0b5964b8b07744c4b5745ad3528188a4bcc850e"
	"055d106486730cf57938b4ba423e23fafd8c241a6e9694ff33347d553785cfafdf6007f6427784a362585fd6cff1a8ac"
	"7929d93c71be97fbfc9a2575931cae14511d452363d8ac1ec8ac66648d85c1744b1cb221930eb80d5c9f53d6da556a75"
	"866d75f25f7f2dc6337f18146f48fd579d481cd21a5b1c4b85c27fba0391c11127c396309ba57575ee56e57817cdfa08"
	"05993ea89a7c371ed5692b320f796f4ea82f56ee00c7056b9044e76b02030100010282010053ec5278d87dfc2969106e"
	"dc814f01a8087ec4f10a0de8ec2923ddfcba5c4a991021aa31ff5b5e501c05763aab02242a107d9102eb4f02929c0a08"
	"c1d014b0ca8eac9d2e30f8d07ecd6532e128fdc5bdbab2fb9f58475ddfda911309f47fce6d5f7dc9a253efb1e5179772"
	"7d46f2864d5e74353e76f8439ed8d316747aee8c0152cf70e129cb3dc5ff92a1f669114bbabcd8ff0a4e94779972df28"
	"647e8ec737d4f1ecce7b89ae408cc375bed88003cdb1fcb9d157060d8c0fabbe5f3b4828bd2d3ce10fbd222f7559e570"
	"656097918aa6c940951c6600a3fa33ef16de4fab8b157ecc120e908759534ba673769180b5a6c1d5dda59dee7955f684"
	"5597f1a62102818100ea36c41392f592a1f868ef91f76721ba6e29e16087968cb94c7519c2bb7bd98556443672fc233f"
	"78a1b76464c1d302fc445782cd95a4a034c91c74d98d316e9f9b40f3763e4236a86aebe468b2fb47b240fd50b0e49313"
	"c9803f200511baaa3331a58455716bbfb05a8b1fac7e4f8672401fd10e15cd2958473616b3cc7fd2bb02818100c494ff"
	"c3e1384e53fa231ba6e0f677a1529b74915157b90f48eeddcfed1e04af18c5261ca33ab1e2c112984aa70bde164419e2"
	"148aa706f65bf2a5f2742a37d29e96d0c2273f0d80c6c22641fee963979dd90792e44697a1dfce4b1aa4afa31fdb2aea"
	"89293f51aa7bf486a1d2531e328f013f17b75cd847ad2947155a3fab1102818021d276ce3cd2a9b22a253d335efecda8"
	"167085d362c122e13f6149af0d53fd3d7c0fadad3d2bf9e679b3fa1372c9fe0c5ff223397cfaa107fe62d59cf4fec672"
	"d600b327c825d7aeca81f6220876b10bd4c6bff84b89d1b9af836e244d431f80f51269e1ccd73a7f45140226eeb69d3b"
	"b276e5c19af45d9c19ec7daac9454c3102818100a2c6ea1e4d90ed33164e19e88e2128201a22055d0b29036107b85b4d"
	"7fffba4b2ecc98e95fb40b7642ff5dc17b1f159004661651821a1a66c6ee5ec12bb585b1ce85fd68b74cbba6a56e4075"
	"a759a490f830acd7d2542ddce9508dda0b0230a6013a4128c051e112b53f5e78028bb6d69099ac9fbbc292888f773d98"
	"0db9e8b10281800e03292d5d0b1607ecf62b645e4d32bed5123fa820510f89b3e36db3e80d8b1ca2beb2d7fa93bf0726"
	"9a856a3568ba9be36453862bc1a10e1b64ea686116f401a35fc3ed0fee4947c60753d0a7608052300b6dad3424d69ace"
	"13fa3b4a4e541b4b6cb79f05442e49c2451ed05b4c3ebabe5eabfca735bb989959f1570414adf5";

/**
 * Открытый ключ OpenSSL: RSAPublicKey в DER
 */
static const char * PUBLIC_DER =
	"3082010a0282010100b3da3fc81ae97a81f2bd1ae347a0dc63a2aaef771b05977e909ac277dca6069fe56f9525a43f08"
	"4ee8eabf623ad2a9b83b106db34e3ebfe6010f66bd14455abab0b5964b8b07744c4b5745ad3528188a4bcc850e055d10"
	"6486730cf57938b4ba423e23fafd8c241a6e9694ff33347d553785cfafdf6007f6427784a362585fd6cff1a8ac7929d9"
	"3c71be97fbfc9a2575931cae14511d452363d8ac1ec8ac66648d85c1744b1cb221930eb80d5c9f53d6da556a75866d75"
	"f25f7f2dc6337f18146f48fd579d481cd21a5b1c4b85c27fba0391c11127c396309ba57575ee56e57817cdfa0805993e"
	"a89a7c371ed5692b320f796f4ea82f56ee00c7056b9044e76b0203010001";

/**
 * Чужой открытый ключ OpenSSL: RSAPublicKey в DER
 */
static const char * OTHER_DER =
	"3082010a02820101009bb79c6b1d26dfc5761508b9955321b98d18245e34191882bfc3c497f35a4b9b762d4aaa3e2023"
	"062065837f0761b59868bae5c6f2f7f62fb66920a4d3801c5679abd27ed36bde1e1910704f88bcad03d2639763075136"
	"e5f5fe303b978ce445e0ddb0b9444bd56c76af919c0db660ea62f87d2a2b0a321c87029354f529e23191a5e4f756f3f8"
	"f1b88f5b0b74e29febf668eb3e5204a60e3629e1fce8516075074b33efcd46c1c8e817a5f39f5ee69d5135677cce22f2"
	"5579105686783869d50232594582b929f21ec148bd45b90672fbf26b39b1c9bac470f8bbc7780d42c44da0997f5cefb7"
	"dc00f55372431adaee159dffa24f5fc73824b2f9c984261c850203010001";

/**
 * Подпись OpenSSL по PKCS #1 v1.5 с SHA-256
 */
static const char * SIGNATURE_PKCS1 =
	"78742b63fbb15bb429f195f0feb91265316d53308e64640a8c4de3e4c5d4bb0b313cd49e2106f39531201ae084dfdb6a"
	"907d0643c2bb7696ff4d44436a6262e0089e50435bdb4df85e9e8e4f7e07855caf043765ed01cf65bab3a236a1e7b3d0"
	"7c600f3ce4fc590eb61e7da6c3600b0145ed6e2d47a827a7c1c60460d6a11f3fed18a5f6731f7da15357761b78475e46"
	"f7d05c54471059057ef8a68ec3a1e833e272277d4aec8a1fd4c47e8628cf4f703c7d33d71e83a41a045ca041ac911d17"
	"b04aa3b735b28e70797a52c3f5af1800123a14ab5ebc312bffc83d08903de234dd95b76d29348b07df516f36ee36981d"
	"03e5e0bc6d67f789d6a3673a91e6ebef";

/**
 * Подпись OpenSSL по PSS с SHA-256 и солью в 32 байта
 */
static const char * SIGNATURE_PSS =
	"43aa91bf95eb9225a6acf25f13be55d1af83300963821407cae39033bbf60f981a2bf4ec9907118b5be176ea3868021a"
	"5405e249e31cc492ad595867cfc7b2a19ebbc594fa5280771d80b33af1a44c78dac018673e552fa5ce0b7091ef8640ef"
	"c61db8eb668f82a394fe426dc6ca427fde995257b4a1c74930465eeaeebf2f8e4c3ea827cfe8e8ec12d31325515d10c8"
	"ae050a27eb20f35052c13e70f968390e6051d231d6ec9ab206177b80676985a991efdef48b4478f75229e50b179aa305"
	"a5257ba75a71a698db2364c46ced2ad750b651761ac469fe5c20bf11b063d10731876e900f3347ace12fe646a01817d1"
	"3983bfec287124ed8ba56dc8d7111b4e";

/**
 * Подпись OpenSSL по PKCS #1 v1.5 с SHA-1
 */
static const char * SIGNATURE_SHA1 =
	"14fcf9c20bebd487575219460d899f2fab055a98da81c393f15e1b7eb65f89c75afdd854c90447e71f88b882b2d3e564"
	"9577382f4aae88f169ce7951f7ad848a94712ebb9b727b843e7d156983634d15cc65bc149fda4ac8ce135bf66ee59954"
	"b630b000eb4ed4c7446b6bafc75a8be947d13d6af687bcdad410b473de1445278f971d04a294e2cbe86079057406adc1"
	"00a363ae4eeace249dbd7b95db11fe2b8dbbd034cfab0ccbc65616f8a6f6ebe2d239a2010d2d73841af95bfb2cfac8af"
	"e47acd67a3d42d3b4bb3390902ff5fdc684461fdb5db6a7fd8a3d0df8694c37064da6b7aff33307394d1f8f69f8759d7"
	"fd682e32ee83df527fe90fbfef2eb512";

/**
 * Подпись OpenSSL по PSS с SHA-512 и солью в 20 байтов
 */
static const char * SIGNATURE_PSS512 =
	"41670d55bef02c28f195a93370b50a10199e53621f68a926e8d14866ecc9b2fe93ba5f413f9b40b63f6cbb5046e6d998"
	"bcb74f98609453c4526171a3f6ba1173e42dd90b7fcd2c3453daa2d82a55bf3e49f5984ec61bf82b992c59cc331f3b89"
	"e99008d3c3156255bd232af59eada24318172f35186f23194dd33891542d17dd6b66e36b9d95397a96b12f86a6b43d16"
	"ee3580515e5d34caec2fc58d3c7006ebb02e8f1f11523f7dedbf363f531edbd40453b2fe8bae2e589630714e0c434398"
	"4874d7fa71a603cdb976afe3899f2967ba7083578a61bca2a8d2289d4b6d34b7af9349d370efe763cdaf74e278a8c05f"
	"90587faded1412c592ad275b04f3d1ed";

/**
 * Шифротекст OpenSSL по OAEP с SHA-256
 */
static const char * CIPHERTEXT_OAEP =
	"0f71a41cc9a4d5606d09f887156aa6b4e06b082ad942c40a0242646c391afed4c7a0bf383689466a7a6537ac4864776b"
	"32d65850b35ddd6f2ad1c7d5ef707e602983689454ebeb9bb4daae99f16c7daa6ae253ae6145389f8ba52b79bfe2ffe5"
	"483d54783f018284b813c77275b9cea6435e9be62d7b55420af97329fb64e9a9676a1a6cd68a8271a1169ea73d9eb7a3"
	"0e899b1bed0de02be7a7b9162974159408780efe4a4932cee2698a42ed35b5f930d66639e7eb4f410d9c4884e45aab70"
	"c069a7bf8949562f079815e49384ce3f65268dedc43fffe46681b14ff3619a44e6a515e8c7ffb18a8b6cff794b19c514"
	"fc7b804fcfcddab83f5741ba19fb88fd";

/**
 * Шифротекст OpenSSL по PKCS #1 v1.5
 */
static const char * CIPHERTEXT_PKCS1 =
	"34db228f055a0b546f596de5a10c4444e939c639928912a482093e850e47a88e40b8d250bde384d9b778e5d03d53c78f"
	"f384d057f4a44df68cb02aff76b77a845a93522ea04b06190b864291a7b5800d39e1333228520ddda8d606b350e41e50"
	"c4d575d641849e0aa001a42ade961b4f406d88a6486db19e201e5b48f08849834e0ca8cda7d67784931d54b552ab2298"
	"2038442dfb42eaf6fe68b0fc58d3d07eb1593890524784fb034bb64eb92c74b1fa5c962312436cd189c071130091b297"
	"7236be3b729fab9b333e68dce2c9f9d17e2ddeb0d271067dd265b2be2723eae530280b1aefb4754c0206a4dc44e6fae6"
	"dd7cabe966baeed9ed0886c51d145920";

/**
 * Своя подпись по PSS с заданной солью, признанная openssl dgst -verify
 */
static const char * OWN_PSS =
	"23212b46b8b286637c22bf963a227ccca22cfa041067035f1a3d15d83a07a36d1baaf968b02312999e84e3a16abb5379"
	"0fbda4aa0c05e80e73c40e67913c0fbfff50e330c3c21368113c5fa1f72223206bfa02c0620786508f079a2e079778ef"
	"0cb67fcf7ac6f59523df5ed963345a22c211f2b53e7bf129ffb69af1967d8ed75e19cb7ee7648101cfe79ce9403c5c11"
	"654e664be5dc943335b02cf404b7c9cfc020d5f067d72fe1719b57c38874d8c645e2578b8b7cf9dd0cc7c9ae844afa36"
	"fde1bf8b221ce62819344e09436261b34498391e48837d922edd3206e325c95b41f530f04d96b735796126a1f814dae1"
	"3909656ec739d0b53816bfc371b04e55";

/**
 * Свой шифротекст по OAEP с заданной затравкой, расшифрованный openssl pkeyutl -decrypt
 */
static const char * OWN_OAEP =
	"10661c5e55e13b9588e50275818078c8c10988ea55505ab8b81423449f9f6bf37c58eeb982309a9d199dbebbdbd93b7c"
	"00a5b10dab86e9482bcf3f8784af7cbb08fbeb4daf91510aca87750243482765e48f1a1307429df2af35cbd2a3429594"
	"41efafec3862fb3d61e0eafca8a0c1e80d8a80d6eb4b531a289be2f9da8070a9028d8ab61b8ec217ccf6ef3ab518178f"
	"75e2fdabbba91b8bd7c560d264b227955b0965d6b047a5ad522e537f9a0d01881df12d863fc57dd806250c72c274b03a"
	"6437ac0e060d65400286b2faab99efab120e6a502676710b8e0d28fb17679feda277518fa6b15fd405d19da839b38f7e"
	"22a69963704366b0ea7877b13997c6c3";

/**
 * Свой шифротекст по PKCS #1 v1.5 с заданным дополнением, расшифрованный openssl pkeyutl -decrypt
 */
static const char * OWN_PKCS1 =
	"1c435c4e9632edd0b7faff73b5ff14101a3cbc6873de3ff21707b4898da7b437c78ef83a95285b8b8216ebe968c1aa91"
	"ffd6c9a6760a6e75845dc565250af127a96d62eccf48f55b9ec434e35cd7f181ffd3a91e0385f32112bbb21088688005"
	"5f2ba2e0f619e22a512a0e0c21ff97e8a164fe9546956d57c910d14d9b4662372502dc44b79767d3e866e0d8a13599cb"
	"aac73b035386ea4aed3b0033dbfb9973269db4403ce0b07b3d236819dff42e11303c46bf3263e53e303b06b8fd6d69e1"
	"f29faa08eb636e4deaaf72e6de05ccfbbf67f114cb34607da39f391439a8413985865f52abb0561229f4046826c6195f"
	"95cca924359af8293595b6f28dd7bbe3";

/**
 * Модуль ключа из вывода openssl rsa -text
 */
static const char * MODULUS =
	"b3da3fc81ae97a81f2bd1ae347a0dc63a2aaef771b05977e909ac277dca6069fe56f9525a43f084ee8eabf623ad2a9b8"
	"3b106db34e3ebfe6010f66bd14455abab0b5964b8b07744c4b5745ad3528188a4bcc850e055d106486730cf57938b4ba"
	"423e23fafd8c241a6e9694ff33347d553785cfafdf6007f6427784a362585fd6cff1a8ac7929d93c71be97fbfc9a2575"
	"931cae14511d452363d8ac1ec8ac66648d85c1744b1cb221930eb80d5c9f53d6da556a75866d75f25f7f2dc6337f1814"
	"6f48fd579d481cd21a5b1c4b85c27fba0391c11127c396309ba57575ee56e57817cdfa0805993ea89a7c371ed5692b32"
	"0f796f4ea82f56ee00c7056b9044e76b";

/**
 * Секретный показатель ключа
 */
static const char * SECRET =
	"53ec5278d87dfc2969106edc814f01a8087ec4f10a0de8ec2923ddfcba5c4a991021aa31ff5b5e501c05763aab02242a"
	"107d9102eb4f02929c0a08c1d014b0ca8eac9d2e30f8d07ecd6532e128fdc5bdbab2fb9f58475ddfda911309f47fce6d"
	"5f7dc9a253efb1e51797727d46f2864d5e74353e76f8439ed8d316747aee8c0152cf70e129cb3dc5ff92a1f669114bba"
	"bcd8ff0a4e94779972df28647e8ec737d4f1ecce7b89ae408cc375bed88003cdb1fcb9d157060d8c0fabbe5f3b4828bd"
	"2d3ce10fbd222f7559e570656097918aa6c940951c6600a3fa33ef16de4fab8b157ecc120e908759534ba673769180b5"
	"a6c1d5dda59dee7955f6845597f1a621";

/**
 * Первый простой сомножитель ключа
 */
static const char * PRIME1 =
	"ea36c41392f592a1f868ef91f76721ba6e29e16087968cb94c7519c2bb7bd98556443672fc233f78a1b76464c1d302fc"
	"445782cd95a4a034c91c74d98d316e9f9b40f3763e4236a86aebe468b2fb47b240fd50b0e49313c9803f200511baaa33"
	"31a58455716bbfb05a8b1fac7e4f8672401fd10e15cd2958473616b3cc7fd2bb";

/**
 * Второй простой сомножитель ключа
 */
static const char * PRIME2 =
	"c494ffc3e1384e53fa231ba6e0f677a1529b74915157b90f48eeddcfed1e04af18c5261ca33ab1e2c112984aa70bde16"
	"4419e2148aa706f65bf2a5f2742a37d29e96d0c2273f0d80c6c22641fee963979dd90792e44697a1dfce4b1aa4afa31f"
	"db2aea89293f51aa7bf486a1d2531e328f013f17b75cd847ad2947155a3fab11";

/**
 * Показатель dP ключа
 */
static const char * EXPONENT1 =
	"21d276ce3cd2a9b22a253d335efecda8167085d362c122e13f6149af0d53fd3d7c0fadad3d2bf9e679b3fa1372c9fe0c"
	"5ff223397cfaa107fe62d59cf4fec672d600b327c825d7aeca81f6220876b10bd4c6bff84b89d1b9af836e244d431f80"
	"f51269e1ccd73a7f45140226eeb69d3bb276e5c19af45d9c19ec7daac9454c31";

/**
 * Показатель dQ ключа
 */
static const char * EXPONENT2 =
	"a2c6ea1e4d90ed33164e19e88e2128201a22055d0b29036107b85b4d7fffba4b2ecc98e95fb40b7642ff5dc17b1f1590"
	"04661651821a1a66c6ee5ec12bb585b1ce85fd68b74cbba6a56e4075a759a490f830acd7d2542ddce9508dda0b0230a6"
	"013a4128c051e112b53f5e78028bb6d69099ac9fbbc292888f773d980db9e8b1";

/**
 * Коэффициент qInv ключа
 */
static const char * COEFFICIENT =
	"0e03292d5d0b1607ecf62b645e4d32bed5123fa820510f89b3e36db3e80d8b1ca2beb2d7fa93bf07269a856a3568ba9b"
	"e36453862bc1a10e1b64ea686116f401a35fc3ed0fee4947c60753d0a7608052300b6dad3424d69ace13fa3b4a4e541b"
	"4b6cb79f05442e49c2451ed05b4c3ebabe5eabfca735bb989959f1570414adf5";


/**
 * @brief Проверка разбора ключей из записи DER
 *
 */

/**
 * @brief Служебные объекты проверки затирания приватного DER (круг 11)
 */
#if defined(__APPLE__)
	#include <malloc/malloc.h>
#elif defined(__linux__) || defined(__FreeBSD__)
	#include <malloc.h>
#endif
static std::vector <uint8_t> imprint;
static size_t traces = 0;
static void inspect(void * data) noexcept {
	if(imprint.empty()) return;
	size_t size = 0;
	#if defined(__APPLE__)
		size = ::malloc_size(data);
	#elif defined(__linux__) || defined(__FreeBSD__)
		size = ::malloc_usable_size(data);
	#endif
	const uint8_t * bytes = static_cast <const uint8_t *> (data);
	for(size_t i = 0; (i + imprint.size()) <= size; i++){
		if(::memcmp(bytes + i, imprint.data(), imprint.size()) == 0){ traces++; return; }
	}
}

TEST(RsaTest, Decode) {
	// Модуль RSA
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Проверяем готовность
	ASSERT_TRUE(rsa.ready());
	// Проверяем наличие секретного ключа
	ASSERT_TRUE(rsa.secret());
	// Проверяем число разрядов модуля
	ASSERT_EQ(rsa.bits(), static_cast <size_t> (2048));
	// Проверяем размер модуля
	ASSERT_EQ(rsa.size(), static_cast <size_t> (256));
	// Сличаем модуль с выводом openssl rsa -text
	ASSERT_EQ(part(rsa, sign::part_t::MODULUS), std::string(MODULUS));
	// Сличаем открытый показатель
	ASSERT_EQ(part(rsa, sign::part_t::PUBLIC), std::string("010001"));
	// Сличаем секретный показатель
	ASSERT_EQ(part(rsa, sign::part_t::SECRET), std::string(SECRET));
	// Сличаем первый сомножитель
	ASSERT_EQ(part(rsa, sign::part_t::PRIME1), std::string(PRIME1));
	// Сличаем второй сомножитель
	ASSERT_EQ(part(rsa, sign::part_t::PRIME2), std::string(PRIME2));
	// Сличаем первый показатель
	ASSERT_EQ(part(rsa, sign::part_t::EXPONENT1), std::string(EXPONENT1));
	// Сличаем второй показатель
	ASSERT_EQ(part(rsa, sign::part_t::EXPONENT2), std::string(EXPONENT2));
	// Сличаем коэффициент
	ASSERT_EQ(part(rsa, sign::part_t::COEFFICIENT), std::string(COEFFICIENT));
	// Разбираем открытый ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(PUBLIC_DER))));
	// Проверяем готовность
	ASSERT_TRUE(rsa.ready());
	// Секретного ключа нет
	ASSERT_FALSE(rsa.secret());
	// Секретные составляющие отсутствуют
	ASSERT_EQ(rsa.length(sign::part_t::PRIME1), static_cast <size_t> (0));
	// Сличаем модуль
	ASSERT_EQ(part(rsa, sign::part_t::MODULUS), std::string(MODULUS));
	// Порченая запись отвергается
	std::vector <uint8_t> broken = bytes(KEY_DER);
	// Портим последний байт коэффициента: составляющие перестают быть согласованы
	broken.back() ^= 0x01;
	// Разбираем порченую запись
	ASSERT_FALSE(rsa.decode(view(broken)));
	// Модуль сброшен после отказа
	ASSERT_FALSE(rsa.ready());
	// Обрезанная запись отвергается
	ASSERT_FALSE(rsa.decode(view_t(broken.data(), broken.size() - 1)));
	// Пустая запись отвергается
	ASSERT_FALSE(rsa.decode(view_t()));
}
/**
 * @brief Проверка записи ключей в DER
 *
 */
TEST(RsaTest, Encode) {
	// Модуль RSA
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Собранная запись
	std::vector <uint8_t> result;
	// Записываем секретный ключ
	ASSERT_TRUE(rsa.encode(true, result));
	// Сличаем запись с записью OpenSSL байт в байт
	ASSERT_EQ(result, bytes(KEY_DER));
	// Записываем открытый ключ
	ASSERT_TRUE(rsa.encode(false, result));
	// Сличаем запись с записью OpenSSL байт в байт
	ASSERT_EQ(result, bytes(PUBLIC_DER));
	// Устанавливаем ключ составляющими
	ASSERT_TRUE(rsa.key(
		view(bytes(MODULUS)), view(bytes("010001")), view(bytes(SECRET)), view(bytes(PRIME1)),
		view(bytes(PRIME2)), view(bytes(EXPONENT1)), view(bytes(EXPONENT2)), view(bytes(COEFFICIENT))
	));
	// Записываем секретный ключ
	ASSERT_TRUE(rsa.encode(true, result));
	// Сличаем запись с записью OpenSSL
	ASSERT_EQ(result, bytes(KEY_DER));
	// Разбираем открытый ключ
	ASSERT_TRUE(rsa.decode(view(bytes(PUBLIC_DER))));
	// Запись секретного ключа без него отвергается
	ASSERT_FALSE(rsa.encode(true, result));
	// Запись без ключа отвергается
	rsa.clear();
	// Проверяем отказ
	ASSERT_FALSE(rsa.encode(false, result));
}
/**
 * Круг 11 (разрез по свойству, секреты): Rsa::encode(secret=true) набирал приватный DER (d,p,q,dp,dq,
 * коэффициент) в буфер asn1::writer_t, а ~Writer/clear() освобождали его БЕЗ затирания - приватный
 * ключ уходил в кучу незатёртым на всех путях. Правка: scrub(writer) на всех выходах encode().
 * Мутация (снять scrub) роняет пин.
 */
TEST(RsaTest, EncodeNoTraces){
	#if !defined(__APPLE__) && !defined(__linux__) && !defined(__FreeBSD__)
		GTEST_SKIP() << "размер освобождаемого блока на этой системе не узнать";
	#endif
	#if defined(__linux__) && !defined(__GLIBC__)
		GTEST_SKIP() << "под musl размер освобождаемого блока недостоверен";
	#endif
	sign::rsa_t rsa;
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Первая запись без наблюдателя: узнаём приватный DER
	std::vector <uint8_t> der;
	ASSERT_TRUE(rsa.encode(true, der));
	ASSERT_GT(der.size(), size_t(64));
	// Образец: окно приватного DER за 4-байтовым заголовком SEQUENCE
	imprint.assign(der.begin() + 8, der.begin() + 56);
	// Вторая запись под наблюдателем: буфер записчика освобождается на возврате
	traces = 0;
	std::vector <uint8_t> again;
	starve::watch = inspect;
	const bool ok = rsa.encode(true, again);
	starve::watch = nullptr;
	imprint.clear();
	ASSERT_TRUE(ok);
	ASSERT_EQ(again, der);
	// Ни один освобождённый блок не нёс приватный DER
	EXPECT_EQ(traces, size_t(0)) << "буфер записчика с приватным ключом освобождён незатёртым";
}

/**
 * @brief Проверка записи ключа при нехватке памяти
 *
 * @note Проверка отключена до починки записчика DER: его закрытые методы
 *       identifier и length объявлены noexcept и выделяют память, оттого
 *       перехват bad_alloc в открытых методах open, close и element до броска
 *       не дотягивается, и нехватка памяти завершает процесс вместо отказа.
 *       Со снятым noexcept с этих двух методов проверка проходит; включить,
 *       убрав приставку DISABLED_
 *
 */
TEST(RsaTest, Starved) {
	// Модуль RSA
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе запись обязана ответить
	 * либо успехом, либо отказом, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 64; budget++){
		// Собранная запись
		std::vector <uint8_t> result;
		// Итог записи при отмеренном запасе
		bool outcome = false;
		{
			// Отмеряем запас выделений на время записи
			starve::ration_t ration(budget);
			// Выполняем запись ключа при отмеренном запасе
			outcome = rsa.encode(true, result);
		}
		// Если запись удалась, она обязана совпасть с записью OpenSSL
		if(outcome){
			// Сличаем запись
			ASSERT_EQ(result, bytes(KEY_DER)) << "запас " << budget;
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || !outcome);
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
/**
 * @brief Проверка установки ключа составляющими
 *
 */
TEST(RsaTest, Components) {
	// Модуль RSA
	sign::rsa_t rsa;
	// Установка открытого ключа
	ASSERT_TRUE(rsa.key(view(bytes(MODULUS)), view(bytes("010001"))));
	// Проверяем число разрядов
	ASSERT_EQ(rsa.bits(), static_cast <size_t> (2048));
	// Чётный показатель отвергается
	ASSERT_FALSE(rsa.key(view(bytes(MODULUS)), view(bytes("010000"))));
	// Единичный показатель отвергается
	ASSERT_FALSE(rsa.key(view(bytes(MODULUS)), view(bytes("01"))));
	// Чётный модуль: модуль ключа со сброшенным младшим разрядом
	std::vector <uint8_t> even = bytes(MODULUS);
	// Сбрасываем младший разряд
	even.back() &= 0xFE;
	// Чётный модуль отвергается
	ASSERT_FALSE(rsa.key(view(even), view(bytes("010001"))));
	// Показатель, не меньший модуля, отвергается
	ASSERT_FALSE(rsa.key(view(bytes(MODULUS)), view(bytes(MODULUS))));
	// Короткий модуль отвергается
	ASSERT_FALSE(rsa.key(view(bytes("0d")), view(bytes("03"))));
	// Переставленные показатели отвергаются: несогласованные составляющие
	ASSERT_FALSE(rsa.key(
		view(bytes(MODULUS)), view(bytes("010001")), view(bytes(SECRET)), view(bytes(PRIME1)),
		view(bytes(PRIME2)), view(bytes(EXPONENT2)), view(bytes(EXPONENT1)), view(bytes(COEFFICIENT))
	));
	// Переставленные сомножители отвергаются: коэффициент перестаёт быть верным
	ASSERT_FALSE(rsa.key(
		view(bytes(MODULUS)), view(bytes("010001")), view(bytes(SECRET)), view(bytes(PRIME2)),
		view(bytes(PRIME1)), view(bytes(EXPONENT1)), view(bytes(EXPONENT2)), view(bytes(COEFFICIENT))
	));
	// Модуль сброшен после отказа
	ASSERT_FALSE(rsa.ready());
	// Согласованные составляющие принимаются
	ASSERT_TRUE(rsa.key(
		view(bytes(MODULUS)), view(bytes("010001")), view(bytes(SECRET)), view(bytes(PRIME1)),
		view(bytes(PRIME2)), view(bytes(EXPONENT1)), view(bytes(EXPONENT2)), view(bytes(COEFFICIENT))
	));
	// Проверяем наличие секретного ключа
	ASSERT_TRUE(rsa.secret());
	// Место составляющей меньшего размера
	uint8_t buffer[8];
	// Составляющая, не умещающаяся в место, отвергается
	ASSERT_FALSE(rsa.part(sign::part_t::MODULUS, buffer, sizeof(buffer)));
	// Показатель умещается с ведущими нулями
	ASSERT_TRUE(rsa.part(sign::part_t::PUBLIC, buffer, sizeof(buffer)));
	// Сличаем показатель
	ASSERT_EQ(text(buffer, sizeof(buffer)), std::string("0000000000010001"));
}
/**
 * @brief Проверка подписей OpenSSL
 *
 */
TEST(RsaTest, Verify) {
	// Модуль RSA с открытым ключом
	sign::rsa_t rsa;
	// Разбираем открытый ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(PUBLIC_DER))));
	// Хеш сообщения
	uint8_t hash[64];
	// Вырабатываем хеш SHA-256
	size_t size = hashed(digest::hash_t::SHA256, hash);
	// Подпись OpenSSL по PKCS #1 v1.5 с SHA-256 подлинна
	ASSERT_TRUE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PKCS1))));
	// Подпись OpenSSL по PSS с SHA-256 и солью в 32 байта подлинна
	ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PSS))));
	// Та же подпись с явной длиной соли
	ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PSS)), 32));
	// Подпись PSS с иной длиной соли отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PSS)), 20));
	// Подпись PKCS #1 v1.5, проверяемая как PSS, отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PKCS1))));
	// Подпись PSS, проверяемая как PKCS #1 v1.5, отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PSS))));
	// Подпись с иным хешем отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA224, view_t(hash, 28), view(bytes(SIGNATURE_PKCS1))));
	// Хеш иной длины отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, 31), view(bytes(SIGNATURE_PKCS1))));
	// Хеш «Стрибог» в PKCS #1 не определён
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::STREEBOG256, view_t(hash, 32), view(bytes(SIGNATURE_PKCS1))));
	// Схема без дополнения отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::NONE, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PKCS1))));
	// Подпись OpenSSL по PKCS #1 v1.5 с SHA-1 подлинна
	size = hashed(digest::hash_t::SHA1, hash);
	// Проверяем подпись с SHA-1
	ASSERT_TRUE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA1, view_t(hash, size), view(bytes(SIGNATURE_SHA1))));
	// Подпись OpenSSL по PSS с SHA-512 и солью в 20 байтов подлинна
	size = hashed(digest::hash_t::SHA512, hash);
	// Проверяем подпись с SHA-512
	ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA512, view_t(hash, size), view(bytes(SIGNATURE_PSS512)), 20));
	// Та же подпись с длиной соли по умолчанию отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA512, view_t(hash, size), view(bytes(SIGNATURE_PSS512))));
	// Хеш сообщения SHA-256
	size = hashed(digest::hash_t::SHA256, hash);
	// Подпись под чужой ключ отвергается
	sign::rsa_t other;
	// Разбираем чужой открытый ключ
	ASSERT_TRUE(other.decode(view(bytes(OTHER_DER))));
	// Проверяем подпись чужим ключом
	ASSERT_FALSE(other.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PKCS1))));
	// Проверяем подпись PSS чужим ключом
	ASSERT_FALSE(other.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PSS))));
	// Подпись под иное сообщение отвергается
	hash[0] ^= 0x01;
	// Проверяем подпись под иным хешем
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PKCS1))));
	// Проверяем подпись PSS под иным хешем
	ASSERT_FALSE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PSS))));
	// Восстанавливаем хеш
	hash[0] ^= 0x01;
	// Обе подписи
	std::vector <uint8_t> signatures[2] = {bytes(SIGNATURE_PKCS1), bytes(SIGNATURE_PSS)};
	/**
	 * Выполняем перебор схем подписи
	 */
	for(size_t j = 0; j < 2; j++){
		// Схема подписи
		const sign::scheme_t scheme = ((j == 0) ? sign::scheme_t::PKCS1 : sign::scheme_t::PSS);
		/**
		 * Выполняем порчу подписи по одному байту в разных местах
		 */
		for(size_t i = 0; i < signatures[j].size(); i += 17){
			// Портим байт подписи
			signatures[j][i] ^= 0x80;
			// Порченая подпись отвергается
			ASSERT_FALSE(rsa.check(scheme, digest::hash_t::SHA256, view_t(hash, size), view(signatures[j]))) << "Место порчи: " << i;
			// Восстанавливаем байт подписи
			signatures[j][i] ^= 0x80;
		}
		// Подпись не размером в модуль отвергается
		ASSERT_FALSE(rsa.check(scheme, digest::hash_t::SHA256, view_t(hash, size), view_t(signatures[j].data(), signatures[j].size() - 1)));
		// Восстановленная подпись подлинна
		ASSERT_TRUE(rsa.check(scheme, digest::hash_t::SHA256, view_t(hash, size), view(signatures[j])));
	}
	// Подпись, не меньшая модуля, отвергается
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view(bytes(MODULUS))));
	// Проверка без ключа отвергается
	rsa.clear();
	// Проверяем отказ
	ASSERT_FALSE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view(bytes(SIGNATURE_PKCS1))));
}
/**
 * @brief Проверка выработки подписей, признанных OpenSSL
 *
 */
TEST(RsaTest, Sign) {
	// Модуль RSA с секретным ключом
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Хеш сообщения
	uint8_t hash[64];
	// Вырабатываем хеш SHA-256
	const size_t size = hashed(digest::hash_t::SHA256, hash);
	// Место подписи
	uint8_t signature[256];
	// Вырабатываем подпись по PKCS #1 v1.5
	ASSERT_TRUE(rsa.make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), signature));
	// Подпись детерминирована: сличаем с подписью OpenSSL байт в байт
	ASSERT_EQ(text(signature, sizeof(signature)), std::string(SIGNATURE_PKCS1));
	// Соль подписи PSS: байты от 1 до 32
	uint8_t salt[32];
	/**
	 * Выполняем заполнение соли
	 */
	for(size_t i = 0; i < sizeof(salt); i++)
		// Записываем очередной байт соли
		salt[i] = static_cast <uint8_t> (i + 1);
	// Вырабатываем подпись по PSS с заданной солью
	ASSERT_TRUE(rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), signature, 32, view_t(salt, sizeof(salt))));
	// Сличаем с подписью, признанной openssl dgst -verify
	ASSERT_EQ(text(signature, sizeof(signature)), std::string(OWN_PSS));
	// Вырабатываем подпись по PSS со случайной солью
	ASSERT_TRUE(rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), signature));
	// Случайная соль даёт иную подпись
	ASSERT_NE(text(signature, sizeof(signature)), std::string(OWN_PSS));
	// Подпись со случайной солью подлинна
	ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature))));
	// Вырабатываем подпись по PSS без соли
	ASSERT_TRUE(rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), signature, 0));
	// Подпись без соли подлинна при той же длине соли
	ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature)), 0));
	// Подпись без соли не подлинна при длине соли по умолчанию
	ASSERT_FALSE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature))));
	// Соль, не умещающаяся в модуль, отвергается
	ASSERT_FALSE(rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), signature, 256 - 32 - 1));
	// Поданная соль не той длины отвергается
	ASSERT_FALSE(rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), signature, 32, view_t(salt, 16)));
	// Хеш «Стрибог» отвергается
	ASSERT_FALSE(rsa.make(sign::scheme_t::PKCS1, digest::hash_t::STREEBOG256, view_t(hash, 32), signature));
	// Хеш не той длины отвергается
	ASSERT_FALSE(rsa.make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, 20), signature));
	// Схема OAEP для подписи не годится
	ASSERT_FALSE(rsa.make(sign::scheme_t::OAEP, digest::hash_t::SHA256, view_t(hash, size), signature));
	/**
	 * Выполняем перебор всех допустимых хешей PKCS #1: подпись и проверка своими
	 */
	for(const digest::hash_t algorithm : {digest::hash_t::MD5, digest::hash_t::SHA1, digest::hash_t::SHA224, digest::hash_t::SHA256, digest::hash_t::SHA384, digest::hash_t::SHA512}){
		// Вырабатываем хеш сообщения
		const size_t length = hashed(algorithm, hash);
		// Вырабатываем подпись по PKCS #1 v1.5
		ASSERT_TRUE(rsa.make(sign::scheme_t::PKCS1, algorithm, view_t(hash, length), signature)) << "Хеш: " << static_cast <int> (algorithm);
		// Проверяем подпись
		ASSERT_TRUE(rsa.check(sign::scheme_t::PKCS1, algorithm, view_t(hash, length), view_t(signature, sizeof(signature)))) << "Хеш: " << static_cast <int> (algorithm);
		// Вырабатываем подпись по PSS
		ASSERT_TRUE(rsa.make(sign::scheme_t::PSS, algorithm, view_t(hash, length), signature)) << "Хеш: " << static_cast <int> (algorithm);
		// Проверяем подпись
		ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, algorithm, view_t(hash, length), view_t(signature, sizeof(signature)))) << "Хеш: " << static_cast <int> (algorithm);
	}
	// Подпись без секретного ключа отвергается
	ASSERT_TRUE(rsa.decode(view(bytes(PUBLIC_DER))));
	// Проверяем отказ
	ASSERT_FALSE(rsa.make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), signature));
}
/**
 * @brief Проверка расшифрования шифротекстов OpenSSL
 *
 */
TEST(RsaTest, Decrypt) {
	// Модуль RSA с секретным ключом
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Место сообщения
	uint8_t output[256];
	// Длина сообщения
	size_t size = 0;
	// Расшифровываем шифротекст OpenSSL по OAEP с SHA-256
	ASSERT_TRUE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(bytes(CIPHERTEXT_OAEP)), output, size));
	// Сличаем сообщение
	ASSERT_EQ(std::string(reinterpret_cast <const char *> (output), size), std::string(PLAINTEXT));
	// Расшифровываем шифротекст OpenSSL по PKCS #1 v1.5
	ASSERT_TRUE(rsa.decrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view(bytes(CIPHERTEXT_PKCS1)), output, size));
	// Сличаем сообщение
	ASSERT_EQ(std::string(reinterpret_cast <const char *> (output), size), std::string(PLAINTEXT));
	// Шифротекст OAEP с иным хешем отвергается
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA1, view(bytes(CIPHERTEXT_OAEP)), output, size));
	// Длина сообщения при отказе нулевая
	ASSERT_EQ(size, static_cast <size_t> (0));
	// Шифротекст OAEP с иной меткой отвергается
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(bytes(CIPHERTEXT_OAEP)), output, size, view("label")));
	// Шифротекст OAEP, расшифровываемый по PKCS #1 v1.5, отвергается
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view(bytes(CIPHERTEXT_OAEP)), output, size));
	// Шифротекст PKCS #1 v1.5, расшифровываемый по OAEP, отвергается
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(bytes(CIPHERTEXT_PKCS1)), output, size));
	// Оба шифротекста
	std::vector <uint8_t> ciphertexts[2] = {bytes(CIPHERTEXT_OAEP), bytes(CIPHERTEXT_PKCS1)};
	/**
	 * Выполняем перебор схем шифрования
	 */
	for(size_t j = 0; j < 2; j++){
		// Схема шифрования
		const sign::scheme_t scheme = ((j == 0) ? sign::scheme_t::OAEP : sign::scheme_t::PKCS1);
		/**
		 * Выполняем порчу шифротекста по одному байту в разных местах
		 */
		for(size_t i = 0; i < ciphertexts[j].size(); i += 31){
			// Портим байт шифротекста
			ciphertexts[j][i] ^= 0x40;
			// Порченый шифротекст отвергается
			ASSERT_FALSE(rsa.decrypt(scheme, digest::hash_t::SHA256, view(ciphertexts[j]), output, size)) << "Место порчи: " << i;
			// Восстанавливаем байт шифротекста
			ciphertexts[j][i] ^= 0x40;
		}
		// Шифротекст не размером в модуль отвергается
		ASSERT_FALSE(rsa.decrypt(scheme, digest::hash_t::SHA256, view_t(ciphertexts[j].data(), ciphertexts[j].size() - 1), output, size));
	}
	// Схема PSS для расшифрования не годится
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::PSS, digest::hash_t::SHA256, view(bytes(CIPHERTEXT_OAEP)), output, size));
	// Расшифрование без секретного ключа отвергается
	ASSERT_TRUE(rsa.decode(view(bytes(PUBLIC_DER))));
	// Проверяем отказ
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(bytes(CIPHERTEXT_OAEP)), output, size));
}
/**
 * @brief Проверка шифрования, признанного OpenSSL
 *
 */
TEST(RsaTest, Encrypt) {
	// Модуль RSA с секретным ключом
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Затравка OAEP: байты от 0xA0
	uint8_t seed[32];
	/**
	 * Выполняем заполнение затравки
	 */
	for(size_t i = 0; i < sizeof(seed); i++)
		// Записываем очередной байт затравки
		seed[i] = static_cast <uint8_t> (0xA0 + i);
	// Место шифротекста
	uint8_t ciphertext[256];
	// Шифруем по OAEP с заданной затравкой
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(PLAINTEXT), ciphertext, view_t(), view_t(seed, sizeof(seed))));
	// Сличаем с шифротекстом, расшифрованным openssl pkeyutl -decrypt
	ASSERT_EQ(text(ciphertext, sizeof(ciphertext)), std::string(OWN_OAEP));
	// Дополнение PKCS #1 v1.5: байты от 1 до 255 по кругу
	std::vector <uint8_t> padding(256 - 3 - strlen(PLAINTEXT));
	/**
	 * Выполняем заполнение дополнения
	 */
	for(size_t i = 0; i < padding.size(); i++)
		// Записываем очередной байт дополнения
		padding[i] = static_cast <uint8_t> ((i % 255) + 1);
	// Шифруем по PKCS #1 v1.5 с заданным дополнением
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view(PLAINTEXT), ciphertext, view_t(), view(padding)));
	// Сличаем с шифротекстом, расшифрованным openssl pkeyutl -decrypt
	ASSERT_EQ(text(ciphertext, sizeof(ciphertext)), std::string(OWN_PKCS1));
	// Нулевой байт в поданном дополнении отвергается
	padding[3] = 0;
	// Проверяем отказ
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view(PLAINTEXT), ciphertext, view_t(), view(padding)));
	// Дополнение не той длины отвергается
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view(PLAINTEXT), ciphertext, view_t(), view_t(seed, sizeof(seed))));
	// Затравка не той длины отвергается
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(PLAINTEXT), ciphertext, view_t(), view_t(seed, 16)));
	// Место сообщения
	uint8_t output[256];
	// Длина сообщения
	size_t size = 0;
	// Самое длинное сообщение OAEP с SHA-256: 256 - 64 - 2 байта
	uint8_t message[256];
	// Заполняем сообщение
	memset(message, 0x5A, sizeof(message));
	// Шифруем самое длинное сообщение
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view_t(message, 190), ciphertext));
	// Расшифровываем
	ASSERT_TRUE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view_t(ciphertext, sizeof(ciphertext)), output, size));
	// Проверяем длину
	ASSERT_EQ(size, static_cast <size_t> (190));
	// Сличаем сообщение
	ASSERT_EQ(memcmp(output, message, size), 0);
	// Слишком длинное сообщение OAEP отвергается
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view_t(message, 191), ciphertext));
	// Самое длинное сообщение PKCS #1 v1.5: 256 - 11 байтов
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(message, 245), ciphertext));
	// Расшифровываем
	ASSERT_TRUE(rsa.decrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(ciphertext, sizeof(ciphertext)), output, size));
	// Проверяем длину
	ASSERT_EQ(size, static_cast <size_t> (245));
	// Сличаем сообщение
	ASSERT_EQ(memcmp(output, message, size), 0);
	// Слишком длинное сообщение PKCS #1 v1.5 отвергается
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(message, 246), ciphertext));
	// Пустое сообщение шифруется по OAEP
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA512, view_t(), ciphertext, view("label")));
	// Расшифровываем с той же меткой
	ASSERT_TRUE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA512, view_t(ciphertext, sizeof(ciphertext)), output, size, view("label")));
	// Проверяем пустое сообщение
	ASSERT_EQ(size, static_cast <size_t> (0));
	// Расшифрование без метки отвергается
	ASSERT_FALSE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA512, view_t(ciphertext, sizeof(ciphertext)), output, size));
	// Случайное шифрование даёт разные шифротексты
	uint8_t another[256];
	// Шифруем дважды
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(PLAINTEXT), ciphertext));
	// Шифруем повторно
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(PLAINTEXT), another));
	// Сличаем шифротексты
	ASSERT_NE(memcmp(ciphertext, another, sizeof(ciphertext)), 0);
	// Шифрование по PSS не годится
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::PSS, digest::hash_t::SHA256, view(PLAINTEXT), ciphertext));
	// Шифрование хешем «Стрибог» отвергается
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::STREEBOG256, view(PLAINTEXT), ciphertext));
	// Шифрование без ключа отвергается
	rsa.clear();
	// Проверяем отказ
	ASSERT_FALSE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(PLAINTEXT), ciphertext));
}
/**
 * @brief Проверка примитивов без дополнения
 *
 */
TEST(RsaTest, Raw) {
	// Модуль RSA с секретным ключом
	sign::rsa_t rsa;
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Входное число: короче модуля
	const std::vector <uint8_t> input = bytes(PRIME1);
	// Места итогов
	uint8_t enciphered[256], deciphered[256];
	// Выполняем открытое действие
	ASSERT_TRUE(rsa.encipher(view(input), enciphered));
	// Выполняем секретное действие над итогом
	ASSERT_TRUE(rsa.decipher(view_t(enciphered, sizeof(enciphered)), deciphered));
	// Итог дополнен ведущими нулями до размера модуля
	ASSERT_EQ(text(deciphered, sizeof(deciphered)), std::string((256 - input.size()) * 2, '0').append(text(input.data(), input.size())));
	// Действия перестановочны
	ASSERT_TRUE(rsa.decipher(view(input), deciphered));
	// Выполняем открытое действие над итогом секретного
	ASSERT_TRUE(rsa.encipher(view_t(deciphered, sizeof(deciphered)), enciphered));
	// Проверяем восстановление
	ASSERT_EQ(text(enciphered, sizeof(enciphered)), std::string((256 - input.size()) * 2, '0').append(text(input.data(), input.size())));
	// Число, равное модулю, отвергается
	ASSERT_FALSE(rsa.encipher(view(bytes(MODULUS)), enciphered));
	// Число, равное модулю, отвергается и секретным действием
	ASSERT_FALSE(rsa.decipher(view(bytes(MODULUS)), deciphered));
	// Ноль в открытой степени равен нулю
	ASSERT_TRUE(rsa.encipher(view_t(), enciphered));
	// Проверяем ноль
	ASSERT_EQ(text(enciphered, sizeof(enciphered)), std::string(512, '0'));
	// Место итога обязательно
	ASSERT_FALSE(rsa.encipher(view(input), nullptr));
}
/**
 * @brief Проверка порождения ключа
 *
 */
TEST(RsaTest, Generate) {
	// Модуль RSA
	sign::rsa_t rsa;
	// Недопустимая длина отвергается
	ASSERT_FALSE(rsa.generate(1024));
	// Чётный показатель отвергается
	ASSERT_FALSE(rsa.generate(2048, 65536));
	// Порождаем ключ длиной 2048 разрядов
	ASSERT_TRUE(rsa.generate(2048));
	// Проверяем число разрядов
	ASSERT_EQ(rsa.bits(), static_cast <size_t> (2048));
	// Проверяем наличие секретного ключа
	ASSERT_TRUE(rsa.secret());
	// Составляющие ключа
	uint8_t buffer[math::INTEGER_SIZE];
	// Числа составляющих
	math::integer_t modulus, exponent, decryptor, prime1, prime2, exponent1, exponent2, coefficient;
	// Извлекаем модуль
	ASSERT_TRUE(rsa.part(sign::part_t::MODULUS, buffer, sizeof(buffer)) && modulus.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем открытый показатель
	ASSERT_TRUE(rsa.part(sign::part_t::PUBLIC, buffer, sizeof(buffer)) && exponent.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем секретный показатель
	ASSERT_TRUE(rsa.part(sign::part_t::SECRET, buffer, sizeof(buffer)) && decryptor.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем первый сомножитель
	ASSERT_TRUE(rsa.part(sign::part_t::PRIME1, buffer, sizeof(buffer)) && prime1.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем второй сомножитель
	ASSERT_TRUE(rsa.part(sign::part_t::PRIME2, buffer, sizeof(buffer)) && prime2.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем первый показатель
	ASSERT_TRUE(rsa.part(sign::part_t::EXPONENT1, buffer, sizeof(buffer)) && exponent1.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем второй показатель
	ASSERT_TRUE(rsa.part(sign::part_t::EXPONENT2, buffer, sizeof(buffer)) && exponent2.load(view_t(buffer, sizeof(buffer))));
	// Извлекаем коэффициент
	ASSERT_TRUE(rsa.part(sign::part_t::COEFFICIENT, buffer, sizeof(buffer)) && coefficient.load(view_t(buffer, sizeof(buffer))));
	// Открытый показатель равен 65537
	math::integer_t expected;
	// Записываем ожидаемый показатель
	expected.word(65537);
	// Сличаем показатель
	ASSERT_TRUE(exponent.equal(expected));
	// Сомножители простые
	ASSERT_TRUE(prime1.prime());
	// Проверяем второй сомножитель
	ASSERT_TRUE(prime2.prime());
	// Сомножители длиной 1024 разряда
	ASSERT_EQ(prime1.bits(), static_cast <size_t> (1024));
	// Проверяем длину второго сомножителя
	ASSERT_EQ(prime2.bits(), static_cast <size_t> (1024));
	// Модуль равен произведению сомножителей
	math::integer_t product;
	// Вычисляем произведение
	ASSERT_TRUE(product.multiply(prime1, prime2));
	// Сличаем с модулем
	ASSERT_TRUE(product.equal(modulus));
	// Единица
	math::integer_t one, lessened, unit;
	// Записываем единицу
	one.word(1);
	// Первый сомножитель без единицы
	ASSERT_TRUE(lessened.subtract(prime1, one));
	// Произведение показателей по первому сомножителю без единицы равно единице
	ASSERT_TRUE(unit.mulmod(exponent, decryptor, lessened, false));
	// Проверяем единицу
	ASSERT_TRUE(unit.equal(one));
	// Первый показатель равен секретному по первому сомножителю без единицы
	ASSERT_TRUE(unit.reduce(decryptor, lessened));
	// Сличаем показатели
	ASSERT_TRUE(unit.equal(exponent1));
	// Второй сомножитель без единицы
	ASSERT_TRUE(lessened.subtract(prime2, one));
	// Произведение показателей по второму сомножителю без единицы равно единице
	ASSERT_TRUE(unit.mulmod(exponent, decryptor, lessened, false));
	// Проверяем единицу
	ASSERT_TRUE(unit.equal(one));
	// Второй показатель равен секретному по второму сомножителю без единицы
	ASSERT_TRUE(unit.reduce(decryptor, lessened));
	// Сличаем показатели
	ASSERT_TRUE(unit.equal(exponent2));
	// Коэффициент обращает второй сомножитель по первому
	ASSERT_TRUE(unit.mulmod(coefficient, prime2, prime1, false));
	// Проверяем единицу
	ASSERT_TRUE(unit.equal(one));
	// Секретный показатель больше корня из модуля
	ASSERT_GT(decryptor.bits(), static_cast <size_t> (1024));
	// Сомножители различаются не менее чем в старших ста разрядах
	math::integer_t difference;
	// Вычисляем разность
	if(prime1.compare(prime2) > 0){
		// Вычитаем второй из первого
		ASSERT_TRUE(difference.subtract(prime1, prime2));
	// Если второй больше
	} else {
		// Вычитаем первый из второго
		ASSERT_TRUE(difference.subtract(prime2, prime1));
	}
	// Проверяем разность
	ASSERT_GT(difference.bits(), static_cast <size_t> (924));
	// Хеш сообщения
	uint8_t hash[32];
	// Вырабатываем хеш
	const size_t size = hashed(digest::hash_t::SHA256, hash);
	// Подпись
	uint8_t signature[256];
	// Подписываем порождённым ключом
	ASSERT_TRUE(rsa.make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), signature));
	// Проверяем подпись
	ASSERT_TRUE(rsa.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature))));
	// Подписываем по PKCS #1 v1.5
	ASSERT_TRUE(rsa.make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), signature));
	// Проверяем подпись
	ASSERT_TRUE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature))));
	// Место шифротекста и сообщения
	uint8_t ciphertext[256], output[256];
	// Длина сообщения
	size_t length = 0;
	// Шифруем порождённым ключом
	ASSERT_TRUE(rsa.encrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view(PLAINTEXT), ciphertext));
	// Расшифровываем
	ASSERT_TRUE(rsa.decrypt(sign::scheme_t::OAEP, digest::hash_t::SHA256, view_t(ciphertext, sizeof(ciphertext)), output, length));
	// Сличаем сообщение
	ASSERT_EQ(std::string(reinterpret_cast <const char *> (output), length), std::string(PLAINTEXT));
	// Запись порождённого ключа
	std::vector <uint8_t> encoded;
	// Записываем ключ
	ASSERT_TRUE(rsa.encode(true, encoded));
	// Разбираем запись другим модулем
	sign::rsa_t restored;
	// Проверяем разбор
	ASSERT_TRUE(restored.decode(view(encoded)));
	// Восстановленный ключ проверяет подпись
	ASSERT_TRUE(restored.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature))));
	// Чужой ключ подпись не признаёт
	sign::rsa_t other;
	// Разбираем чужой ключ
	ASSERT_TRUE(other.decode(view(bytes(OTHER_DER))));
	// Проверяем отказ
	ASSERT_FALSE(other.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, size), view_t(signature, sizeof(signature))));
}

/**
 * @brief Проверка верхнего предела длины подписи: у RSA он равен длине модуля
 *
 */
TEST(RsaTest, Limit) {
	// Модуль RSA
	sign::rsa_t rsa;
	// Предел до установки ключа нулевой
	ASSERT_EQ(rsa.limit(), static_cast <size_t> (0));
	// Разбираем секретный ключ OpenSSL
	ASSERT_TRUE(rsa.decode(view(bytes(KEY_DER))));
	// Предел равен длине модуля
	ASSERT_EQ(rsa.limit(), rsa.size());
	ASSERT_EQ(rsa.limit(), static_cast <size_t> (256));
	// Хеш сообщения
	uint8_t hash[32];
	// Заполняем хеш сообщения
	::memset(hash, 0x42, sizeof(hash));
	// Место подписи по пределу
	std::vector <uint8_t> signature(rsa.limit(), 0);
	// Выполняем выработку подписи PKCS #1 v1.5
	ASSERT_TRUE(rsa.make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, sizeof(hash)), signature.data()));
	// Подпись сходится
	ASSERT_TRUE(rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(hash, sizeof(hash)), view_t(signature.data(), signature.size())));
	// Выполняем сброс состояния модуля
	rsa.clear();
	// Предел после сброса нулевой
	ASSERT_EQ(rsa.limit(), static_cast <size_t> (0));
}
