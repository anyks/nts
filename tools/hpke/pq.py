#!/usr/bin/env python3
#
# Перекладчик контрольных примеров HPKE с постквантовыми способами инкапсуляции
# из записей hpkewg/hpke-pq (test-vectors.json) в набор tests/corpus/hpke,
# читаемый проверкой tests/hpke/hpke.cpp:
#
#   python3 tools/hpke/pq.py <файл test-vectors.json> <каталог назначения>
#
# Разметка выходных записей (поля через пробел, прочерк означает пустое поле):
#
#   vectors.txt  <kem> <kdf> <aead> <ikmR> <skRm> <pkRm> <ikmE> <enc> <shared>
#                <info> <key> <base_nonce> <exporter_secret>
#                <exp_ctx> <exp_L> <exp_val> <ct_aad> <ct_pt> <ct_ct>
#
# Способы: 0x0010 P-256, 0x0011 P-384, 0x0012 P-521, 0x0020 X25519, 0x0021 X448,
# 0x0040 ML-KEM-512, 0x0041 ML-KEM-768, 0x0042 ML-KEM-1024, 0x0050 MLKEM768-P256,
# 0x0051 MLKEM1024-P384, 0x647A MLKEM768-X25519.
# Функции: 0x0001 HKDF-SHA256, 0x0002 HKDF-SHA384, 0x0003 HKDF-SHA512,
# 0x0010 SHAKE128, 0x0011 SHAKE256, 0x0012 TurboSHAKE128, 0x0013 TurboSHAKE256.
# Шифры: 0x0001 AES-128-GCM, 0x0002 AES-256-GCM, 0x0003 ChaCha20-Poly1305.
#
import sys
import json

def main():
	if len(sys.argv) != 3:
		print("применение: python3 tools/hpke/pq.py <test-vectors.json> <каталог>", file=sys.stderr)
		return 1
	with open(sys.argv[1]) as f:
		vectors = json.load(f)
	rows = []
	for t in vectors:
		# Берём первый пример зашифрования и первый пример экспорта
		enc0 = t["encryptions"][0]
		exp0 = t["exports"][0]
		rows.append(" ".join([
			f"0x{t['kem_id']:04X}",
			f"0x{t['kdf_id']:04X}",
			f"0x{t['aead_id']:04X}",
			t["ikmR"],
			t["skRm"],
			t["pkRm"],
			t["ikmE"],
			t["enc"],
			t["shared_secret"],
			t["info"],
			t["key"],
			t["base_nonce"],
			t["exporter_secret"],
			exp0["exporter_context"],
			str(exp0["L"]),
			exp0["exported_value"],
			enc0["aad"],
			enc0["pt"],
			enc0["ct"]
		]))
	with open(sys.argv[2] + "/vectors.txt", "w") as f:
		f.write("\n".join(rows) + "\n")
	print(f"записано {len(rows)} векторов в {sys.argv[2]}/vectors.txt")
	return 0

if __name__ == "__main__":
	sys.exit(main())
