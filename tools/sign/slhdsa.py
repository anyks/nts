#!/usr/bin/env python3
#
# Перекладчик контрольных примеров SLH-DSA из записей подмодуля OpenSSL
# (test/recipes/30-test_evp_data/evppkey_slh_dsa_{keygen,siggen,sigver}.txt)
# в набор tests/corpus/slhdsa, читаемый проверкой tests/sign/slhdsa.cpp:
#
#   python3 tools/sign/slhdsa.py <каталог evp_data> <каталог назначения>
#
# Разметка выходных записей (поля через пробел, прочерк означает пустое поле):
#
#   keygen.txt  <набор> <зерно> <ключ проверки> <ключ подписи>
#   siggen.txt  <набор> d <ключ подписи> <сообщение> <контекст> <подпись>
#               <набор> e <ключ подписи> <сообщение> <контекст> <подпись> <энтропия>
#   sigver.txt  <набор> ok|bad <ключ проверки> <сообщение> <контекст> <подпись>
#
# Наборы: sha2-128s, shake-128s, sha2-128f, shake-128f, sha2-192s, shake-192s,
# sha2-192f, shake-192f, sha2-256s, shake-256s, sha2-256f, shake-256f.
# Сценарии message-encoding:0 (сырое сообщение без обвязки - расширение OpenSSL
# вне чистого FIPS 205) в набор не идут, как не идут дубли FIPSversion 3.5/3.6.
#
import sys
import os

SETS = {
	"SLH-DSA-SHA2-128s": "sha2-128s",
	"SLH-DSA-SHAKE-128s": "shake-128s",
	"SLH-DSA-SHA2-128f": "sha2-128f",
	"SLH-DSA-SHAKE-128f": "shake-128f",
	"SLH-DSA-SHA2-192s": "sha2-192s",
	"SLH-DSA-SHAKE-192s": "shake-192s",
	"SLH-DSA-SHA2-192f": "sha2-192f",
	"SLH-DSA-SHAKE-192f": "shake-192f",
	"SLH-DSA-SHA2-256s": "sha2-256s",
	"SLH-DSA-SHAKE-256s": "shake-256s",
	"SLH-DSA-SHA2-256f": "sha2-256f",
	"SLH-DSA-SHAKE-256f": "shake-256f",
}

def keygen(path, dst):
	# Выработка ключа из зерна: уникальные пары (набор, зерно)
	rows = []
	seen = set()
	set_name, seed, pub, priv = "", "", "", ""
	with open(path) as f:
		for line in f:
			line = line.rstrip("\n")
			if line.startswith("KeyGen = "):
				if seed and (set_name, seed) not in seen:
					seen.add((set_name, seed))
					rows.append((SETS[set_name], seed, pub, priv))
				set_name, seed, pub, priv = line[9:], "", "", ""
			elif line.startswith("Ctrl = hexseed:"):
				seed = line[15:]
			elif line.startswith("CtrlOut = hexpub:"):
				pub = line[17:]
			elif line.startswith("CtrlOut = hexpriv:"):
				priv = line[18:]
	if seed and (set_name, seed) not in seen:
		seen.add((set_name, seed))
		rows.append((SETS[set_name], seed, pub, priv))
	with open(os.path.join(dst, "keygen.txt"), "w") as f:
		f.write("# ACVP SLH-DSA keyGen: набор, зерно (3n), ключ проверки (2n), ключ подписи (4n)\n")
		for r in rows:
			f.write(" ".join(r) + "\n")
	return len(rows)

def siggen(path, dst):
	# Подпись: message-encoding:1 (чистое кодирование FIPS 205)
	keys = {}
	rows = []
	cur = None
	with open(path) as f:
		for line in f:
			line = line.rstrip("\n")
			if line.startswith("PrivateKeyRaw = "):
				if cur is not None and cur["enc"] == "1":
					rows.append(cur)
				cur = None
				rest = line[16:]
				name = rest.split(":", 1)[0]
				keys[name] = rest.split(":", 2)[2]
			elif line.startswith("Sign-Message = "):
				if cur is not None and cur["enc"] == "1":
					rows.append(cur)
				rest = line[15:]
				parts = rest.split(":", 1)
				cur = {"set": parts[0], "name": parts[1], "msg": "", "out": "", "ctx": "",
				       "det": "", "entropy": "", "enc": ""}
			elif cur is not None:
				if line.startswith("Input = "):
					cur["msg"] = line[8:]
				elif line.startswith("Output = "):
					cur["out"] = line[9:]
				elif line.startswith("Ctrl = hexcontext-string:"):
					cur["ctx"] = line[25:]
				elif line.startswith("Ctrl = deterministic:"):
					cur["det"] = line[21:]
				elif line.startswith("Ctrl = hextest-entropy:"):
					cur["entropy"] = line[23:]
				elif line.startswith("Ctrl = message-encoding:"):
					cur["enc"] = line[24:]
	if cur is not None and cur["enc"] == "1":
		rows.append(cur)
	with open(os.path.join(dst, "siggen.txt"), "w") as f:
		f.write("# ACVP SLH-DSA sigGen (message-encoding:1): набор, d - детерминированная |\n")
		f.write("# e - с энтропией, ключ подписи, сообщение, контекст, подпись, энтропия у e\n")
		for cur in rows:
			priv = keys[cur["name"]]
			if cur["det"] == "1":
				f.write(" ".join((SETS[cur["set"]], "d", priv, cur["msg"] or "-", cur["ctx"] or "-", cur["out"])) + "\n")
			else:
				f.write(" ".join((SETS[cur["set"]], "e", priv, cur["msg"] or "-", cur["ctx"] or "-", cur["out"], cur["entropy"])) + "\n")
	return len(rows)

def sigver(path, dst):
	# Проверка: message-encoding:1
	keys = {}
	rows = []
	cur = None
	with open(path) as f:
		for line in f:
			line = line.rstrip("\n")
			if line.startswith("PublicKeyRaw = "):
				if cur is not None and cur["enc"] == "1":
					rows.append(cur)
				cur = None
				rest = line[15:]
				name = rest.split(":", 1)[0]
				keys[name] = rest.split(":", 2)[2]
			elif line.startswith("Verify-Message-Public = "):
				if cur is not None and cur["enc"] == "1":
					rows.append(cur)
				rest = line[24:]
				parts = rest.split(":", 1)
				cur = {"set": parts[0], "name": parts[1], "msg": "", "out": "", "ctx": "",
				       "result": "", "enc": ""}
			elif cur is not None:
				if line.startswith("Input = "):
					cur["msg"] = line[8:]
				elif line.startswith("Output = "):
					cur["out"] = line[9:]
				elif line.startswith("Ctrl = hexcontext-string:"):
					cur["ctx"] = line[25:]
				elif line.startswith("Ctrl = message-encoding:"):
					cur["enc"] = line[24:]
				elif line.startswith("Result = "):
					cur["result"] = line[9:]
	if cur is not None and cur["enc"] == "1":
		rows.append(cur)
	with open(os.path.join(dst, "sigver.txt"), "w") as f:
		f.write("# ACVP SLH-DSA sigVer (message-encoding:1): набор, ok - принять | bad - отвергнуть,\n")
		f.write("# ключ проверки, сообщение, контекст, подпись\n")
		for cur in rows:
			pub = keys[cur["name"]]
			mark = "bad" if cur["result"] else "ok"
			f.write(" ".join((SETS[cur["set"]], mark, pub, cur["msg"] or "-", cur["ctx"] or "-", cur["out"])) + "\n")
	return len(rows)

def main():
	src, dst = sys.argv[1], sys.argv[2]
	os.makedirs(dst, exist_ok=True)
	print("keygen:", keygen(os.path.join(src, "evppkey_slh_dsa_keygen.txt"), dst))
	print("siggen:", siggen(os.path.join(src, "evppkey_slh_dsa_siggen.txt"), dst))
	print("sigver:", sigver(os.path.join(src, "evppkey_slh_dsa_sigver.txt"), dst))

if __name__ == "__main__":
	main()
