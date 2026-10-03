#!/usr/bin/env python3
#
# Перекладчик контрольных примеров ML-DSA из записей подмодуля OpenSSL
# (test/recipes/30-test_evp_data/evppkey_ml_dsa_*.txt: ACVP и Wycheproof)
# в набор tests/corpus/mldsa, читаемый проверкой tests/sign/mldsa.cpp:
#
#   python3 tools/sign/mldsa.py <каталог evp_data> <каталог назначения>
#
# Разметка выходных записей (поля через пробел, прочерк означает пустое поле):
#
#   keygen.txt            44 <зерно> <ключ проверки> <ключ подписи>
#   siggen.txt            44 d <ключ подписи> <сообщение> <контекст> <подпись>
#                         44 h <ключ подписи> <сообщение> <контекст> -
#   sigver.txt            44 ok|bad <ключ проверки> <сообщение> <контекст> <подпись>
#   wycheproof-sign.txt   44 ok <ключ подписи> <сообщение> <контекст> <подпись>
#                         44 keyerr <ключ подписи> - - -
#                         44 ctxerr <ключ подписи> <сообщение> <контекст> -
#   wycheproof-verify.txt 44 ok|bad <ключ проверки> <сообщение> <контекст> <подпись>
#                         44 keyerr <ключ проверки> - - -
#
# Сценарии с внешним μ (Ctrl = mu:1) в набор не идут: интерфейс внешнего μ
# модулю не нужен, чистый ML-DSA работает с сообщением целиком.
#
import sys
import os

def blocks(path, keyline, blockline, keycol):
	# Разбор записи на ключи и сценарии; ключи по именам, у сценариев
	# поля: набор, имя ключа, сообщение, выход, контекст, приметы, переопределение ключа
	keys = {}
	out = []
	cur = None
	comment = ""
	with open(path) as f:
		for line in f:
			line = line.rstrip("\n")
			if line.startswith("# "):
				comment = line[2:]
			elif line.startswith(keyline):
				if cur is not None:
					out.append(cur)
					cur = None
				rest = line[len(keyline):]
				name = rest.split(":", 1)[0]
				keys[name] = rest.split(":", 2)[2]
			elif line.startswith(blockline):
				if cur is not None:
					out.append(cur)
				rest = line[len(blockline):]
				parts = rest.split(":", 1)
				cur = {"set": parts[0], "name": parts[1], "msg": "", "out": "", "ctx": "",
				       "det": "", "mu": "", "result": "", "over": "", "comment": comment}
			elif cur is not None:
				if line.startswith("Input = "):
					cur["msg"] = line[8:]
				elif line.startswith("Output = "):
					cur["out"] = line[9:]
				elif line.startswith("Ctrl = hexcontext-string:"):
					cur["ctx"] = line[25:]
				elif line.startswith("CtrlMu = hexcontext-string:"):
					cur["ctx"] = line[27:]
				elif line.startswith("Ctrl = deterministic:"):
					cur["det"] = line[21:]
				elif line.startswith("Ctrl = mu:"):
					cur["mu"] = line[10:]
				elif line.startswith("Ctrl = hexpub:"):
					cur["over"] = line[14:]
				elif line.startswith("Ctrl = hexpriv:"):
					cur["over"] = line[15:]
				elif line.startswith("Result = "):
					cur["result"] = line[9:]
	if cur is not None:
		out.append(cur)
	return keys, out

def short(name):
	return name.split("-")[-1]

def main():
	src, dst = sys.argv[1], sys.argv[2]
	os.makedirs(dst, exist_ok=True)
	# Выработка ключа из зерна
	rows, skipped = [], 0
	seed, pub, priv = "", "", ""
	with open(os.path.join(src, "evppkey_ml_dsa_keygen.txt")) as f:
		for line in f:
			line = line.rstrip("\n")
			if line.startswith("KeyGen = "):
				if seed:
					rows.append((short(gset), seed, pub, priv))
					seed, pub, priv = "", "", ""
				gset = line[9:]
			elif line.startswith("Ctrl = hexseed:"):
				seed = line[15:]
			elif line.startswith("CtrlOut = hexpub:"):
				pub = line[17:]
			elif line.startswith("CtrlOut = hexpriv:"):
				priv = line[18:]
	if seed:
		rows.append((short(gset), seed, pub, priv))
	with open(os.path.join(dst, "keygen.txt"), "w") as f:
		f.write("# ACVP ML-DSA keyGen: набор, зерно, ключ проверки, ключ подписи\n")
		for r in rows:
			f.write(" ".join(r) + "\n")
	print("keygen:", len(rows))
	# Подпись
	keys, out = blocks(os.path.join(src, "evppkey_ml_dsa_siggen.txt"), "PrivateKeyRaw = ", "Sign-Message = ", 2)
	rows, skipped = [], 0
	for b in out:
		if b["mu"] == "1":
			skipped += 1
			continue
		priv = b["over"] or keys[b["name"]]
		msg = b["msg"] or "-"
		ctx = b["ctx"] or "-"
		if b["det"] == "1":
			rows.append((short(b["set"]), "d", priv, msg, ctx, b["out"]))
		else:
			rows.append((short(b["set"]), "h", priv, msg, ctx, "-"))
	with open(os.path.join(dst, "siggen.txt"), "w") as f:
		f.write("# ACVP ML-DSA sigGen: набор, d - детерминированная | h - хеджированная,\n")
		f.write("# ключ подписи, сообщение, контекст, подпись (у h проверяется сличение)\n")
		for r in rows:
			f.write(" ".join(r) + "\n")
	print("siggen:", len(rows), "пропущено внешних мю:", skipped)
	# Проверка
	keys, out = blocks(os.path.join(src, "evppkey_ml_dsa_sigver.txt"), "PublicKeyRaw = ", "Verify-Message-Public = ", 2)
	rows, skipped = [], 0
	for b in out:
		if b["mu"] == "1":
			skipped += 1
			continue
		pub = b["over"] or keys[b["name"]]
		mark = "bad" if b["result"] else "ok"
		rows.append((short(b["set"]), mark, pub, b["msg"] or "-", b["ctx"] or "-", b["out"]))
	with open(os.path.join(dst, "sigver.txt"), "w") as f:
		f.write("# ACVP ML-DSA sigVer: набор, ok - принять | bad - отвергнуть,\n")
		f.write("# ключ проверки, сообщение, контекст, подпись\n")
		for r in rows:
			f.write(" ".join(r) + "\n")
	print("sigver:", len(rows), "пропущено внешних мю:", skipped)
	# Wycheproof по наборам
	for s in ("44", "65", "87"):
		keys, out = blocks(os.path.join(src, "evppkey_ml_dsa_%s_wycheproof_sign.txt" % s),
		                   "PrivateKeyRaw = ", "Sign-Message = ", 2)
		rows = []
		for b in out:
			priv = b["over"] or keys[b["name"]]
			msg = b["msg"] or "-"
			ctx = b["ctx"] or "-"
			if b["result"] == "KEY_FROMDATA_ERROR":
				rows.append((s, "keyerr", priv, "-", "-", "-"))
			elif b["result"] == "PKEY_CTRL_ERROR":
				rows.append((s, "ctxerr", priv, msg, ctx, "-"))
			else:
				rows.append((s, "ok", priv, msg, ctx, b["out"]))
		with open(os.path.join(dst, "wycheproof%s-sign.txt" % s), "w") as f:
			f.write("# Wycheproof ML-DSA-%s MlDsaSign: набор, ok - сверить побайтно,\n" % s)
			f.write("# keyerr - ключ отвергнуть, ctxerr - выработку отвергнуть,\n")
			f.write("# ключ подписи, сообщение, контекст, подпись\n")
			for r in rows:
				f.write(" ".join(r) + "\n")
		keys, out = blocks(os.path.join(src, "evppkey_ml_dsa_%s_wycheproof_verify.txt" % s),
		                   "PublicKeyRaw = ", "Verify-Message-Public = ", 2)
		rows = []
		for b in out:
			pub = b["over"] or keys[b["name"]]
			if b["result"] == "KEY_FROMDATA_ERROR":
				rows.append((s, "keyerr", pub, "-", "-", "-"))
			else:
				mark = "ok" if not b["result"] else "bad"
				rows.append((s, mark, pub, b["msg"] or "-", b["ctx"] or "-", b["out"]))
		with open(os.path.join(dst, "wycheproof%s-verify.txt" % s), "w") as f:
			f.write("# Wycheproof ML-DSA-%s MlDsaVerify: набор, ok - принять | bad - отвергнуть,\n" % s)
			f.write("# keyerr - ключ отвергнуть, ключ проверки, сообщение, контекст, подпись\n")
			for r in rows:
				f.write(" ".join(r) + "\n")
		print("wycheproof", s, "готово")

if __name__ == "__main__":
	main()
