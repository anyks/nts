# Что AWH берёт у криптографической библиотеки

Снято 04.09.2026 по дереву AWH на коммите `2b9452342` разбором всех `.cpp` и `.hpp`
в `src/` и `include/`. Обращением считается имя, объявленное в заголовках BoringSSL
(`third_party/include/openssl`) и употреблённое в коде AWH через `::`.

**Различных обращений: 293.** Рядом с каждым — файлы AWH и число употреблений.

Перечень снят машинно и служит перечнем ТРЕБОВАНИЙ: он говорит, что должно быть
закрыто, но не говорит, каким видом наружу. Договор A-NTS свой, и повторять
устройство OpenSSL он не обязан.


## Ход TLS: связь, состояние, отклики — 71 обращений, 215 употреблений

| обращение | где употребляется |
|---|---|
| `DTLS_client_method` | `src/cryptography/tls/coder.cpp` ×1 |
| `DTLS_server_method` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CIPHER_get_id` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CIPHER_get_name` | `src/cryptography/tls/coder.cpp` ×7 |
| `SSL_CIPHER_get_protocol_id` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_CIPHER_standard_name` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_ECH_KEYS_add` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_ECH_KEYS_free` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_ECH_KEYS_marshal_retry_configs` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_ECH_KEYS_new` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_SESSION_free` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_SESSION_from_bytes` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_SESSION_to_bytes` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_add1_chain_cert` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_add_application_settings` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_check_private_key` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_do_handshake` | `src/proto/quic/handshake.cpp` ×2; `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_early_data_accepted` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_enable_ocsp_stapling` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_enable_signed_cert_timestamps` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_free` | `src/proto/quic/handshake.cpp` ×1; `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_get0_alpn_selected` | `src/proto/quic/handshake.cpp` ×1; `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_get_certificate` | `src/cryptography/tls/coder.cpp` ×5 |
| `SSL_get_cipher_by_value` | `src/cryptography/tls/coder.cpp` ×21 |
| `SSL_get_ciphers` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_get_current_cipher` | `src/cryptography/tls/coder.cpp` ×5 |
| `SSL_get_error` | `src/cryptography/tls/coder.cpp` ×4; `src/proto/quic/handshake.cpp` ×2 |
| `SSL_get_ex_data` | `src/cryptography/tls/coder.cpp` ×48 |
| `SSL_get_ex_new_index` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_get_peer_cert_chain` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_get_peer_certificate` | `src/cryptography/tls/coder.cpp` ×5 |
| `SSL_get_servername` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_get_verify_result` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_get_version` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_has_pending` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_in_early_data` | `src/proto/quic/handshake.cpp` ×2 |
| `SSL_is_init_finished` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_load_client_CA_file` | `src/cryptography/tls/coder.cpp` ×6 |
| `SSL_load_error_strings` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_marshal_ech_config` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_new` | `src/cryptography/tls/coder.cpp` ×2; `src/proto/quic/handshake.cpp` ×1 |
| `SSL_read` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_reset_early_data_reject` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set1_client_key_shares` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_set1_ech_config_list` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_set1_groups` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_set1_host` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_set_accept_state` | `src/cryptography/tls/coder.cpp` ×2; `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_alpn_protos` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_set_alps_use_new_codepoint` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_set_bio` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_set_cipher_list` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_set_client_CA_list` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_set_connect_state` | `src/cryptography/tls/coder.cpp` ×2; `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_early_data_enabled` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_enable_ech_grease` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_set_ex_data` | `src/cryptography/tls/coder.cpp` ×8 |
| `SSL_set_max_proto_version` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_set_min_proto_version` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_set_permute_extensions` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_set_session` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_signing_algorithm_prefs` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_set_tlsext_host_name` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_set_verify` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_set_verify_algorithm_prefs` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_shutdown` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_state_string` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_use_PrivateKey_file` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_use_certificate` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_use_certificate_file` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_write` | `src/cryptography/tls/coder.cpp` ×1 |

## Ход TLS: шаблон контекста — 44 обращений, 114 употреблений

| обращение | где употребляется |
|---|---|
| `SSL_CTX_add_cert_compression_alg` | `src/cryptography/tls/coder.cpp` ×6 |
| `SSL_CTX_check_private_key` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_enable_ocsp_stapling` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_enable_signed_cert_timestamps` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_free` | `src/proto/quic/handshake.cpp` ×1; `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_get_cert_store` | `src/cryptography/tls/coder.cpp` ×7 |
| `SSL_CTX_get_ciphers` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_get_ex_data` | `src/cryptography/tls/coder.cpp` ×5 |
| `SSL_CTX_get_ex_new_index` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_CTX_new` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_CTX_sess_set_new_cb` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_CTX_set1_ech_keys` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set1_groups` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_alpn_protos` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_alpn_select_cb` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_cert_verify_callback` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_cipher_list` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_client_CA_list` | `src/cryptography/tls/coder.cpp` ×3 |
| `SSL_CTX_set_default_verify_paths` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_set_dos_protection_cb` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_ex_data` | `src/cryptography/tls/coder.cpp` ×6 |
| `SSL_CTX_set_grease_enabled` | `src/cryptography/tls/coder.cpp` ×4 — **закрыто** (06.09.2026): `client::grease(bool)`/`server::grease(bool)`, поведение BoringSSL по RFC 8701, набор `tests/grease` |
| `SSL_CTX_set_max_proto_version` | `src/cryptography/tls/coder.cpp` ×8 |
| `SSL_CTX_set_min_proto_version` | `src/cryptography/tls/coder.cpp` ×8 |
| `SSL_CTX_set_mode` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_set_msg_callback` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_set_msg_callback_arg` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_set_next_proto_select_cb` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_CTX_set_next_protos_advertised_cb` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_CTX_set_options` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_set_permute_extensions` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_set_quiet_shutdown` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_read_ahead` | `src/cryptography/tls/coder.cpp` ×4 |
| `SSL_CTX_set_session_cache_mode` | `src/cryptography/tls/coder.cpp` ×2; `src/proto/quic/handshake.cpp` ×1 |
| `SSL_CTX_set_session_id_context` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_signing_algorithm_prefs` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_tlsext_servername_arg` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_tlsext_servername_callback` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_set_verify` | `src/cryptography/tls/coder.cpp` ×6 |
| `SSL_CTX_set_verify_algorithm_prefs` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_up_ref` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_CTX_use_PrivateKey_file` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_CTX_use_certificate_chain_file` | `src/cryptography/tls/coder.cpp` ×1 |
| `SSL_CTX_use_certificate_file` | `src/cryptography/tls/coder.cpp` ×3 |

## QUIC: стык рукопожатия — 6 обращений, 6 употреблений

| обращение | где употребляется |
|---|---|
| `SSL_get_peer_quic_transport_params` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_process_quic_post_handshake` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_provide_quic_data` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_quic_early_data_context` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_quic_method` | `src/proto/quic/handshake.cpp` ×1 |
| `SSL_set_quic_transport_params` | `src/proto/quic/handshake.cpp` ×1 |

## ECH и HPKE — 4 обращений, 4 употреблений

| обращение | где употребляется |
|---|---|
| `EVP_HPKE_KEY_free` | `src/cryptography/tls/coder.cpp` ×1 |
| `EVP_HPKE_KEY_generate` | `src/cryptography/tls/coder.cpp` ×1 |
| `EVP_HPKE_KEY_init` | `src/cryptography/tls/coder.cpp` ×1 |
| `EVP_HPKE_KEY_new` | `src/cryptography/tls/coder.cpp` ×1 |

## Сертификаты X.509 и доверие — 34 обращений, 109 употреблений

| обращение | где употребляется |
|---|---|
| `ASN1_STRING_get0_data` | `src/cryptography/tls/coder.cpp` ×3 |
| `ASN1_STRING_length` | `src/cryptography/tls/coder.cpp` ×3 |
| `ASN1_TIME_print` | `src/cryptography/tls/coder.cpp` ×2 |
| `OBJ_nid2ln` | `src/cryptography/tls/coder.cpp` ×1 |
| `PKCS5_PBKDF2_HMAC` | `src/cryptography/crypto.cpp` ×1 |
| `X509_CRL_free` | `src/cryptography/tls/coder.cpp` ×3 |
| `X509_CRL_print` | `src/cryptography/tls/coder.cpp` ×4 |
| `X509_NAME_ENTRY_get_data` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_NAME_get_entry` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_NAME_get_index_by_NID` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_NAME_get_text_by_NID` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_NAME_oneline` | `src/cryptography/tls/coder.cpp` ×17 |
| `X509_STORE_CTX_free` | `src/cryptography/tls/coder.cpp` ×3 |
| `X509_STORE_CTX_get_current_cert` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_STORE_CTX_get_error` | `src/cryptography/tls/coder.cpp` ×3 |
| `X509_STORE_CTX_get_error_depth` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_STORE_CTX_init` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_STORE_CTX_new` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_STORE_add_cert` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_STORE_load_locations` | `src/cryptography/tls/coder.cpp` ×6 |
| `X509_STORE_set_default_paths` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_cmp_time` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_free` | `src/cryptography/tls/coder.cpp` ×12 |
| `X509_get0_notAfter` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_get0_notBefore` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_get0_pubkey` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_get_ext_d2i` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_get_issuer_name` | `src/cryptography/tls/coder.cpp` ×9 |
| `X509_get_signature_nid` | `src/cryptography/tls/coder.cpp` ×1 |
| `X509_get_subject_name` | `src/cryptography/tls/coder.cpp` ×10 |
| `X509_verify_cert` | `src/cryptography/tls/coder.cpp` ×2 |
| `X509_verify_cert_error_string` | `src/cryptography/tls/coder.cpp` ×5 |
| `d2i_X509` | `src/cryptography/tls/coder.cpp` ×1 |
| `i2d_PUBKEY` | `src/cryptography/crypto.cpp` ×1 |

## Ключи и подпись — 24 обращений, 64 употреблений

| обращение | где употребляется |
|---|---|
| `EC_GROUP_get_curve_name` | `src/cryptography/crypto.cpp` ×1 |
| `EC_KEY_get0_group` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_CTX_free` | `src/cryptography/crypto.cpp` ×13 |
| `EVP_PKEY_CTX_new` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_PKEY_CTX_new_id` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_CTX_set_ec_paramgen_curve_nid` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_CTX_set_rsa_keygen_bits` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_CTX_set_rsa_mgf1_md` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_PKEY_CTX_set_rsa_oaep_md` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_PKEY_CTX_set_rsa_padding` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_PKEY_CTX_set_rsa_pss_saltlen` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_base_id` | `src/cryptography/crypto.cpp` ×1; `src/cryptography/tls/coder.cpp` ×1 |
| `EVP_PKEY_bits` | `src/cryptography/tls/coder.cpp` ×2; `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_decrypt` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_PKEY_decrypt_init` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_encrypt` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_PKEY_encrypt_init` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_free` | `src/cryptography/crypto.cpp` ×12 |
| `EVP_PKEY_get0_EC_KEY` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_id` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_keygen` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_keygen_init` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_PKEY_size` | `src/cryptography/crypto.cpp` ×3 |
| `X25519` | `src/cryptography/tls/fingerprint.cpp` ×3; `src/cryptography/tls/coder.cpp` ×2 |

## Симметричные шифры — 14 обращений, 35 употреблений

| обращение | где употребляется |
|---|---|
| `EVP_CIPHER_CTX_ctrl` | `src/cryptography/crypto.cpp` ×4 |
| `EVP_CIPHER_CTX_free` | `src/cryptography/crypto.cpp` ×9 |
| `EVP_CIPHER_CTX_new` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_CIPHER_CTX_set_padding` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_CIPHER_iv_length` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_aes_128_cbc` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_aes_128_cfb128` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_aes_128_gcm` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_aes_192_cbc` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_aes_192_cfb128` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_aes_192_gcm` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_aes_256_cbc` | `src/cryptography/crypto.cpp` ×4 |
| `EVP_aes_256_cfb128` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_aes_256_gcm` | `src/cryptography/crypto.cpp` ×1 |

## Хэш, имитовставка, выработка ключа — 41 обращений, 206 употреблений

| обращение | где употребляется |
|---|---|
| `EVP_DigestSign` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_DigestSignFinal` | `src/cryptography/crypto.cpp` ×6 |
| `EVP_DigestSignInit` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_DigestSignUpdate` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_DigestVerify` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_DigestVerifyFinal` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_DigestVerifyInit` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_DigestVerifyUpdate` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_MD_CTX_free` | `src/cryptography/crypto.cpp` ×14 |
| `EVP_MD_CTX_new` | `src/cryptography/crypto.cpp` ×6 |
| `EVP_md5` | `src/cryptography/crypto.cpp` ×5 |
| `EVP_sha1` | `src/cryptography/crypto.cpp` ×5; `src/cryptography/tls/coder.cpp` ×2 |
| `EVP_sha224` | `src/cryptography/crypto.cpp` ×5 |
| `EVP_sha256` | `src/cryptography/crypto.cpp` ×9; `src/proto/quic/connection.cpp` ×2; `src/proto/quic/quic.cpp` ×1 |
| `EVP_sha384` | `src/cryptography/crypto.cpp` ×5 |
| `EVP_sha512` | `src/cryptography/crypto.cpp` ×5 |
| `HMAC` | `src/cryptography/crypto.cpp` ×6; `include/proto/http/auth/auth.hpp` ×4; `src/proto/http/auth/auth.cpp` ×2; `src/proto/quic/connection.cpp` ×2; `src/cryptography/tls/coder.cpp` ×2; `src/proto/quic/quic.cpp` ×1 |
| `MD5` | `src/cryptography/crypto.cpp` ×6; `src/proto/http/auth/digest.cpp` ×2; `src/proto/http/auth/hmac.cpp` ×2; `src/proto/http/auth/auth.cpp` ×2; `src/cryptography/tls/fingerprint.cpp` ×1; `include/proto/http/auth/auth.hpp` ×1 |
| `MD5_Final` | `src/cryptography/crypto.cpp` ×1 |
| `MD5_Init` | `src/cryptography/crypto.cpp` ×1 |
| `MD5_Update` | `src/cryptography/crypto.cpp` ×1 |
| `SHA1` | `src/cryptography/crypto.cpp` ×6; `src/proto/http/auth/digest.cpp` ×2; `src/proto/http/auth/hmac.cpp` ×2 |
| `SHA1_Final` | `src/cryptography/crypto.cpp` ×1 |
| `SHA1_Init` | `src/cryptography/crypto.cpp` ×1 |
| `SHA1_Update` | `src/cryptography/crypto.cpp` ×1 |
| `SHA224` | `src/cryptography/crypto.cpp` ×6; `src/proto/http/auth/digest.cpp` ×2; `src/proto/http/auth/hmac.cpp` ×2 |
| `SHA224_Final` | `src/cryptography/crypto.cpp` ×1 |
| `SHA224_Init` | `src/cryptography/crypto.cpp` ×1 |
| `SHA224_Update` | `src/cryptography/crypto.cpp` ×1 |
| `SHA256` | `include/proto/http/auth/auth.hpp` ×10; `src/cryptography/crypto.cpp` ×8; `src/proto/http/auth/digest.cpp` ×2; `src/proto/http/auth/hmac.cpp` ×2; `src/cryptography/vault.cpp` ×2; `src/codec/abc/signature.cpp` ×2; `src/codec/abc/editor.cpp` ×2; `include/cryptography/crypto.hpp` ×2; `src/codec/abc/chunk.cpp` ×1; `src/codec/abc/container.cpp` ×1; `include/codec/abc/container.hpp` ×1; `include/codec/abc/editor.hpp` ×1 |
| `SHA256_Final` | `src/cryptography/crypto.cpp` ×1 |
| `SHA256_Init` | `src/cryptography/crypto.cpp` ×1 |
| `SHA256_Update` | `src/cryptography/crypto.cpp` ×1 |
| `SHA384` | `src/cryptography/crypto.cpp` ×6; `src/proto/http/auth/digest.cpp` ×2; `src/proto/http/auth/hmac.cpp` ×2 |
| `SHA384_Final` | `src/cryptography/crypto.cpp` ×1 |
| `SHA384_Init` | `src/cryptography/crypto.cpp` ×1 |
| `SHA384_Update` | `src/cryptography/crypto.cpp` ×1 |
| `SHA512` | `src/cryptography/crypto.cpp` ×6; `src/proto/http/auth/digest.cpp` ×2; `src/proto/http/auth/hmac.cpp` ×2 |
| `SHA512_Final` | `src/cryptography/crypto.cpp` ×1 |
| `SHA512_Init` | `src/cryptography/crypto.cpp` ×1 |
| `SHA512_Update` | `src/cryptography/crypto.cpp` ×1 |

## Записи PEM — 15 обращений, 28 употреблений

| обращение | где употребляется |
|---|---|
| `PEM_read_PUBKEY` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_read_PrivateKey` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_read_bio` | `src/cryptography/crypto.cpp` ×1 |
| `PEM_read_bio_PUBKEY` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_read_bio_PrivateKey` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_read_bio_X509` | `src/cryptography/tls/coder.cpp` ×2 |
| `PEM_read_bio_X509_CRL` | `src/cryptography/tls/coder.cpp` ×2 |
| `PEM_write_PKCS8PrivateKey` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_write_PUBKEY` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_write_PrivateKey` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_write_bio` | `src/cryptography/crypto.cpp` ×1 |
| `PEM_write_bio_PKCS8PrivateKey` | `src/cryptography/crypto.cpp` ×1 |
| `PEM_write_bio_PUBKEY` | `src/cryptography/crypto.cpp` ×2 |
| `PEM_write_bio_PrivateKey` | `src/cryptography/crypto.cpp` ×3 |
| `PEM_write_bio_X509` | `src/cryptography/tls/coder.cpp` ×2 |

## Случайные значения — 2 обращений, 12 употреблений

| обращение | где употребляется |
|---|---|
| `RAND_bytes` | `src/proto/quic/connection.cpp` ×4; `src/proto/quic/quic.cpp` ×2; `src/cryptography/crypto.cpp` ×2; `src/cryptography/tls/coder.cpp` ×2; `src/cryptography/vault.cpp` ×1 |
| `RAND_poll` | `src/cryptography/tls/coder.cpp` ×1 |

## Поток данных BIO — 18 обращений, 104 употреблений

| обращение | где употребляется |
|---|---|
| `BIO_ctrl` | `src/cryptography/tls/coder.cpp` ×4 |
| `BIO_ctrl_pending` | `src/cryptography/tls/coder.cpp` ×6 |
| `BIO_f_base64` | `src/cryptography/crypto.cpp` ×1 |
| `BIO_free` | `src/cryptography/tls/coder.cpp` ×19; `src/cryptography/crypto.cpp` ×3 |
| `BIO_free_all` | `src/cryptography/crypto.cpp` ×7 |
| `BIO_get_mem_data` | `src/cryptography/tls/coder.cpp` ×6; `src/cryptography/crypto.cpp` ×5 |
| `BIO_get_mem_ptr` | `src/cryptography/crypto.cpp` ×1 |
| `BIO_gets` | `src/cryptography/tls/coder.cpp` ×2 |
| `BIO_new` | `src/cryptography/tls/coder.cpp` ×12; `src/cryptography/crypto.cpp` ×6 |
| `BIO_new_file` | `src/cryptography/tls/coder.cpp` ×1 |
| `BIO_new_mem_buf` | `src/cryptography/crypto.cpp` ×4 |
| `BIO_push` | `src/cryptography/crypto.cpp` ×1 |
| `BIO_read` | `src/cryptography/crypto.cpp` ×2; `src/cryptography/tls/coder.cpp` ×2 |
| `BIO_read_filename` | `src/cryptography/tls/coder.cpp` ×1 |
| `BIO_s_file` | `src/cryptography/tls/coder.cpp` ×2 |
| `BIO_s_mem` | `src/cryptography/tls/coder.cpp` ×10; `src/cryptography/crypto.cpp` ×5 |
| `BIO_set_flags` | `src/cryptography/crypto.cpp` ×1 |
| `BIO_write` | `src/cryptography/crypto.cpp` ×2; `src/cryptography/tls/coder.cpp` ×1 |

## Очередь ошибок — 7 обращений, 11 употреблений

| обращение | где употребляется |
|---|---|
| `ERR_clear_error` | `src/cryptography/crypto.cpp` ×2; `src/cryptography/tls/coder.cpp` ×1 |
| `ERR_error_string_n` | `src/proto/quic/handshake.cpp` ×1; `src/cryptography/tls/coder.cpp` ×1 |
| `ERR_get_error` | `src/cryptography/tls/coder.cpp` ×2 |
| `ERR_load_SSL_strings` | `src/cryptography/tls/coder.cpp` ×1 |
| `ERR_load_crypto_strings` | `src/cryptography/tls/coder.cpp` ×1 |
| `ERR_peek_error` | `src/cryptography/tls/coder.cpp` ×1 |
| `ERR_peek_last_error` | `src/proto/quic/handshake.cpp` ×1 |

## Память и служебное — 6 обращений, 60 употреблений

| обращение | где употребляется |
|---|---|
| `CBB_add_bytes` | `src/cryptography/tls/coder.cpp` ×3 |
| `CRYPTO_BUFFER_new` | `src/cryptography/tls/coder.cpp` ×3 |
| `OPENSSL_cleanse` | `src/cryptography/crypto.cpp` ×29; `src/cryptography/vault.cpp` ×11 |
| `OPENSSL_free` | `src/cryptography/tls/coder.cpp` ×6; `src/cryptography/crypto.cpp` ×4; `src/proto/quic/handshake.cpp` ×1 |
| `OPENSSL_init_ssl` | `src/cryptography/tls/coder.cpp` ×1 |
| `OPENSSL_malloc` | `src/cryptography/tls/coder.cpp` ×2 |

## Укрытое хранение тайн при переезде (решение владельца 17.09.2026)

Ключевой материал, живущий между вызовами, A-NTS держит в своём хранилище `nts::sys::Vault`
(README, «Укрытое хранение ключевого материала»; `AWH-KEY-EMBEDDING.md`, требование 2а —
закрыто). Для AWH: не выносить хранилище сабмодулем, не заводить второго хранилища тайн —
свой материал между вызовами (`state_t::key`, пароли, соль) класть напрямую в
`nts::sys::secret_t` / `nts::sys::bytes_t`; `awh::alloc` остаётся распределителем общей памяти;
поля `ticket_t::secret` и `psk_t::key` заполнять через `assign(begin, end)`.

## Прочее — 7

| обращение | где употребляется |
|---|---|
| `EVP_CipherFinal_ex` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_CipherInit_ex` | `src/cryptography/crypto.cpp` ×3 |
| `EVP_CipherUpdate` | `src/cryptography/crypto.cpp` ×2 |
| `EVP_RSA_gen` | `src/cryptography/crypto.cpp` ×1 |
| `EVP_enc_null` | `src/cryptography/crypto.cpp` ×4 |
| `EVP_hpke_x25519_hkdf_sha256` | `src/cryptography/tls/coder.cpp` ×2 |
| `SSL_set_SSL_CTX` | `src/cryptography/tls/coder.cpp` ×1 |

## Поточное шифрование для awh::Crypto (снято Григорием с кода AWH 04.09.2026)

Шесть свойств, которые обязаны выполняться; устройство на усмотрение A-NTS, формы
BoringSSL (объект контекста, поля ключа и вектора, порядок «завести - обновить -
забрать») в договоре нет.

1. **Нарезка не влияет на итог.** Одни данные кусками любого размера дают тот же
   выход, что и разом. Приёмка перебирает размеры куска 1…40 и 63, 64, 65, 333,
   8192; кусок в один октет обязателен.
2. **Пустой выход - законный успех.** Успех судится по признаку, а не по длине
   выданного: пока копится вектор из головы или удерживается имитовставка, порция
   наружу пуста.
3. **Голова и хвост потока служебные.** При расшифровании вектор берётся из начала
   потока; имитовставка GCM в конце удерживается (последние 16 октетов) и данными
   не выдаётся - расшифрование всегда отстаёт на её длину.
4. **Завершение - отдельное действие.** Хвост выдаётся только на нём: остаток
   неполного блока у CBC, сличение имитовставки у GCM. Порча имитовставки ловится
   только на завершении, не раньше.
5. **Повторное начало сбрасывает, а не отвергает.** Заведение поверх незавершённого
   потока бросает прежний и начинает новый; убирать за собой потребитель не обязан.
6. **Поток задаётся тремя вещами сразу:** направление, хэш и шифр. Направление -
   часть заведения; один объект по очереди работает в обе стороны.

Смежные потребности из того же кода: `password()` задаёт число оборотов PBKDF2 и
соль; GCM даёт +28 к длине (вектор 12 впереди, имитовставка 16 позади), CFB +16
(вектор впереди, имитовставки нет).

## Внутри TLS: чего AWH ждёт, а в A-NTS ещё нет (снято Григорием 04.09.2026, сверено по дереву)

Ложные нули сняты: SNI это `NAME = 0x0000`, ALPN `PROTOCOLS = 0x0010`, ранние данные
`EARLY = 0x002A`; искать по числам, не по словам.

| Потребность | Состояние в A-NTS |
|---|---|
| Наборы 0x1301 TLS_AES_128_GCM_SHA256, 0x1302 TLS_AES_256_GCM_SHA384, 0x1303 TLS_CHACHA20_POLY1305_SHA256 | **все три закрыты** (`protect::suite_t`, расписание над хешем набора, RFC 8448 байт в байт для AES-GCM, обмен с openssl по всем трём наборам); 0x1303 — `chachapoly_t` в защите записей, возобновление 0x1301 ↔ 0x1303 по общему хешу (`ClassicTest.Crossing`, `ClassicTest.Reselect`) |
| Группы 0x001D x25519, 0x0017 secp256r1, 0x0018 secp384r1 | **закрыто**: `extension::group_t`, обмен в движке, HRR по группам, доли ключа по отдельному перечню `shares`, GREASE |
| Схемы 0x0403 ecdsa_secp256r1_sha256, 0x0503, 0x0804…0x0806 rsa_pss_rsae_*, 0x0807 ed25519 | **закрыто**: `extension::scheme_t`, согласование по спискам сторон, подпись и проверка в движке, v1.5 отвергается |
| ChaCha20-Poly1305 | **закрыто**: примитив `chachapoly_t` (RFC 8439) и набор 0x1303 в защите записей |
| DTLS 1.0/1.2 (30 мест в AWH) | **закрыто** (05–06.09.2026): DTLS 1.3 по RFC 9147 и DTLS 1.2 по RFC 6347 на переносе `transport_t::DATAGRAMS` (эпохи, повторные передачи, окно повторов, печенье HRR/HVR, `mtu()`/`timeout()`/`elapsed()`); DTLS 1.0 не нужен; наборы `tests/dtls`, `tests/dtls12` |
| OCSP и сшивка ответа (9 мест) | **закрыто** (04.09.2026): модуль `ocsp` (разбор и проверка ответа RFC 6960, составление запроса, адрес ответчика из AIA), расширение `status_request` в приветствии и запросе подлинности, ответ в записи цепочки по разделу 4.4.2.1 RFC 8446 и разделу 8 RFC 6066, извещение 113; ответ получает и подаёт потребитель октетами (`server::status(DER)`), клиент запрашивает `status(true)`, получает `status()`, проверяет `verification(...)`; форма BoringSSL `SSL_enable_ocsp_stapling`/`SSL_CTX_enable_ocsp_stapling` не перенесена по решению владельца; набор `tests/ocsp` |
| Сжатие сертификатов RFC 8879 (58 мест, вид BoringSSL) | **закрыто** (04.09.2026): расширение `compress_certificate` в обе стороны, `CompressedCertificate` вместо `Certificate`, алгоритмы предоставляет потребитель через `context::codec_t` и `codecs()` у фасадов; форма `SSL_CTX_add_cert_compression_alg` не перенесена по решению владельца, набор `tests/compress` |
| TLS 1.2 | **закрыто** (05–06.09.2026, решение владельца 04.09.2026): RFC 5246 с обязательным EMS, AEAD, CBC (ETM по RFC 7366), PSK, голым RSA-обменом и билетами RFC 5077; `versions(lowest, highest)`; наборы `tests/tls12`, `tests/interop` |

Закрывать не надо: закрепление отпечатка (отклик AWH над готовой цепочкой, DER
сертификата уже доступен). Очерёдность за владельцем.

### Решения владельца по охвату (переданы Григорием 04.09.2026)

- **Охват сохраняется целиком:** всё, что AWH сегодня берёт у BoringSSL, нужно; запрет
  прослоек касается формы API, а не состава. Дороговизна - довод к очерёдности, не к отказу.
- **TLS 1.2 не нужен** - единственное исключение, потому что AWH им не пользуется: связь
  всегда идёт по 1.3. Второй ветви рукопожатия не заводить. **Отменено владельцем 04.09.2026**
  (см. «Решение владельца 04.09.2026: TLS 1.2 и DTLS 1.2 нужны» ниже); закрыто 06.09.2026.
- **DTLS нужен**, очерёдность: после классического 1.3 (эпохи, повторные передачи,
  порядковые номера).
- **Сжатие сообщения с сертификатами по RFC 8879 нужно**; форма BoringSSL не переносится. **Закрыто 04.09.2026**: см. раздел «Сжатие цепочки сертификатов» README и «Сжатие сертификатов RFC 8879» CONFORMANCE.md.
- **OCSP со сшивкой ответа нужен.** **Закрыто 04.09.2026**: см. раздел «Состояние сертификата OCSP и сшивка ответа» README и «OCSP и сшивка» CONFORMANCE.md. Ядро ввода и вывода не ведёт: за ответчиком ходит AWH (`ocsp::responder` даёт адрес, `ocsp::request` — запрос), а библиотека разбирает, проверяет и сшивает.

### Потребности AWH к настройке классики (снято Григорием с кода AWH)

- Перечни наборов, групп и схем задаёт потребитель на связь; порядок вектора это порядок
  предпочтения; библиотека не пересортировывает и не выбирает за потребителя.
- Предлагаемые группы и группы долей ключа (key_share) - два разных списка.
- GREASE (RFC 8701): неизвестные значения в перечнях пропускаются молча; своё
  GREASE-значение вставляется снаружи в наборы, группы, схемы и key_share.
  **Закрыто 06.09.2026** одной ручкой `grease(true)` как у BoringSSL: набор, два
  расширения, группа, доля и издание у клиента, расширение билета и запроса подлинности
  у сервера; см. раздел «GREASE по RFC 8701» README и «GREASE по RFC 8701» CONFORMANCE.md.
- Группы на деле: X25519, secp256r1, secp384r1 плюс закрытые 09.09.2026 X448 (0x001E),
  secp521r1 (0x0019, лишь классические издания), secp256k1 (0x0016, лишь 1.2) и конечное поле
  RFC 7919 ffdhe2048…ffdhe8192 (0x0100…0x0104, лишь 1.3); отложены гибриды сверх NIST и прочие
  постквантовые. Схемы: 0x0403, 0x0503, 0x0603 (ecdsa_secp521r1_sha512, закрыта 09.09.2026),
  0x0804…0x0806 (SHA-512 нужна), 0x0807.
- Наборы AWH: 0x1301, 0x1302, 0x1303 в порядке потребителя.
- Помощник `</dev/null` обязателен во всякой проверке, зовущей openssl.

## TLS 1.3 как поставщик ключей для QUIC (снято Григорием с кода AWH 04.09.2026)

QUIC у AWH берёт от TLS только рукопожатие, записи шифрует сам. Потребности к устройству
(форма BoringSSL не переносится):

1. Рукопожатие без своего транспорта: библиотека не владеет сокетом; октеты рукопожатия
   подаются и забираются потребителем. Отклики: ключ чтения, ключ записи, накопились
   исходящие, пора отправить, тревога.
2. Всё по уровням защиты: начальный, рукопожатие, ранние данные, приложение; октеты и
   ключи с пометкой уровня; уровни не строго по порядку (ранние данные рядом с рукопожатием).
3. Секреты уровней выдаются наружу; `quic key`/`quic iv`/`quic hp` выводит потребитель
   через `label` (есть).
4. Свои данные в рукопожатии: расширение параметров переноса QUIC, содержимое не толкуется.
5. Ранние данные: включить, задать привязку, узнать принятие, узнать «идут ли сейчас»,
   обработать отказ со сбросом.
6. Возобновление между запусками: состояние возобновления в октеты и обратно, в другом
   процессе.
7. По завершении: номер выбранного набора и выбранный ALPN.
8. После рукопожатия: сообщения поверх готовой связи (обновление ключей, билеты)
   подаются отдельно от рукопожатия.

Требование к текущей работе над классикой: движок рукопожатия не владеет транспортом и
не сращивается со слоем записей; секреты уровней доступны наружу.

### Что закрыто (04.09.2026, перенос по уровням `context::transport_t::LEVELS`)

| Пункт | Состояние |
|---|---|
| 1. Рукопожатие без транспорта | **закрыто**: `push(level, data)` принимает данные CRYPTO, `output(level)`/`consume(level, size)` отдают; откликов нет — опрос по образцу библиотеки: `secret(...)` даёт ключи чтения и записи по готовности, `output(level).size` — «накопились исходящие», `alert()` — тревога кодом |
| 2. Всё по уровням | **закрыто**: `context::level_t {INITIAL, EARLY, HANDSHAKE, APPLICATION}`, уровень сообщения по поре ключей стороны, сверка на каждом сообщении (§4.1.4), упреждение рядом с рукопожатием |
| 3. Секреты уровней наружу | **закрыто**: `secret(level, direction, result, size)` — early/handshake/application по сторонам с длиной по хешу; `quic key`/`iv`/`hp` и `quic ku` выводит AWH через `label` из выданного секрета; прикладной секрет доступен и после рукопожатия |
| 4. Свои данные в рукопожатии | **закрыто**: `parameters(...)`/`parameters()`/`acquired()`, расширение 0x0039 в приветствии клиента и защищённых расширениях сервера, содержимое не толкуется; обязательно по уровням, запрещено записями |
| 5. Ранние данные | **закрыто**: `advance` (включить), `accepted` (принятие), `earlying` (идут ли сейчас), `rejected` (отказ со сбросом); «привязка» (`SSL_set_quic_early_data_context`) — в билете лежат параметры сервера `ticket.parameters`, суждение о годности за AWH |
| 6. Возобновление между запусками | **закрыто**: `context::encode`/`context::decode` — самодостаточная запись билета с байтом издания, круг и отказы на порченый вход закреплены |
| 7. По завершении | **закрыто**: `suite()` и `protocol()` доступны по уровням как прежде |
| 8. После рукопожатия | **закрыто**: `NewSessionTicket` приходит на `APPLICATION` тем же `push(level)`; `KeyUpdate` под QUIC запрещён обеим сторонам (§6) |

Дверь `native(id)` у AWH после переезда не нужна: QUIC ведёт рукопожатие фасадами
`client::context_t`/`server::context_t` в переносе по уровням, без чужого контекста.

### Итог разбора зоны awh::Crypto/Hash/Vault/tls (Григорий, 04.09.2026)

От библиотеки не зависят вовсе: `hash.cpp` и `fingerprint.cpp` (модуль отпечатков TLS
разбирает приветствия сам). Карта: `crypto.cpp` 306 обращений, `tls/coder.cpp` 520,
`vault.cpp` два имени (закрыты). Единственная протечка типа библиотеки в API AWH:
`coder.hpp` отдаёт наружу `ssl_ctx_st * native(id)` «для протоколов, которые ведут
собственный обмен» - через неё QUIC берёт контекст и ведёт рукопожатие сам. Вид этой
двери после переезда решает владелец; от A-NTS нужно устройство движка по уровням с
выдачей секретов (см. раздел QUIC выше). Незакрыто по зоне: порождение ключей, предел
длины подписи (в работе); устройство рукопожатия под QUIC закрыто переносом по уровням
(см. таблицу «Что закрыто» в разделе QUIC выше).

## DTLS: потребности AWH (снято Григорием с src/cryptography/tls/coder.cpp, 04.09.2026)

- DTLS выставлен наружу транспортом общего назначения: `coder_t::context(node, UDP)`
  выбирает слой по типу сокета, встречная сторона - любой чужой узел. Версии сегодня:
  min DTLS 1.0, max DTLS 1.2. **Версия для A-NTS (1.3 по RFC 9147 либо ещё и 1.2 ради
  чужих узлов) - решение владельца; TLS 1.2 у AWH не используется.**
- Cookie обязательны: сегодня свои (HMAC-SHA1 по секрету из случайных с адресом узла,
  отказ COOKIE_FAILED без адреса, разбор HelloVerifyRequest); в 1.3 это HelloRetryRequest
  с cookie - договор сводить с ним.
- MTU: жёстко 1200 на оба направления; запроса MTU и разбора MTU_EXCEEDED нет. Границы
  датаграммы обязательны: слой записей не вправе полагаться на потоковость.
- Повторные передачи: таймеров у AWH нет вовсе (DTLSv1_get_timeout не зовётся); в 1.3
  повторы лягут на слой записей A-NTS - отдавать наружу срок следующей передачи, чтобы
  AWH завёл таймер сам.
- SRTP не нужен (use_srtp только в разборе чужого ClientHello для отпечатка).
- DTLS поверх SCTP SEQPACKET (IoSCTPSeqPacketDTLSTest): сообщение приходит целиком;
  отдельного API не требует.
- read_ahead переключается настройкой.

### Решение владельца 04.09.2026 (напрямую): TLS 1.2 и DTLS 1.2 нужны

AWH - сетевой фреймворк общего профиля, а не локальная пара клиент-сервер: он обязан
говорить со сторонними клиентами и серверами, которых в мире много. Прежняя
рекомендация отказаться от TLS 1.2 исходила из того, что владелец не видел его в
употреблении; теперь вывод иной: **нужны и TLS 1.2, и DTLS 1.2**. DTLS 1.3 - по
RFC 9147, раз стандарт есть (BoringSSL и OpenSSL его не поддерживали, оттого AWH и
сидел на 1.2 вынужденно). Поддержка cookie в DTLS обязана быть полноценной (у
BoringSSL с ними были неполадки).

Очерёдность (предложение, владелец вправе изменить): DTLS 1.3 (в работе) →
рукопожатие TLS 1.2 (RFC 5246 с ECDHE, AES-GCM/ChaCha20, signature_algorithms,
билеты RFC 5077, EMS RFC 7627, renegotiation_info RFC 5746, без пересогласования и
без устаревших наборов) → DTLS 1.2 (RFC 6347 поверх него, HelloVerifyRequest cookie).

### Потребности AWH к TLS 1.2 (снято Григорием 04.09.2026 с src/cryptography/tls/coder.cpp)

**Пределы версий.** Для TCP: нижняя граница TLS 1.2, верхняя TLS 1.3 (coder.cpp
6970/6972 клиент, 7198/7200 сервер); есть режим «только 1.3» (6981/6983, 7209/7211).
Пределы переставляются и на живой связи (9563/9568). Наружу нужны две ручки
по отдельности: нижняя и верхняя граница версии.

**Наборы 1.2.** Перечисление `cipher_t` объявляет наружу 22 набора (tls.hpp:260);
в строку `cipher_list` в `ciphers()` собираются:

| Группа | Наборы |
|---|---|
| ECDHE-ECDSA | 0xC02B, 0xC02C (AES-GCM); 0xCCA9 (ChaCha20); 0xC023 (AES128-SHA256); 0xC009, 0xC00A (CBC-SHA) |
| ECDHE-RSA | 0xC02F, 0xC030 (AES-GCM); 0xCCA8 (ChaCha20); 0xC027 (AES128-SHA256); 0xC013, 0xC014 (CBC-SHA) |
| ECDHE-PSK | 0xC035, 0xC036 (CBC-SHA); 0xCCAC (ChaCha20) |
| PSK без ECDHE | PSK-AES128-CBC-SHA, PSK-AES256-CBC-SHA |
| Голый RSA-обмен | AES128-SHA, AES256-SHA, AES128-GCM-SHA256, AES256-GCM-SHA384 |

Первые две группы (ECDHE + AES-GCM/ChaCha20; CBC-наборы отдельным решением)
покрываются очерком выше. PSK и статический RSA-обмен - объявленный наружу API,
а не догадка; по правилу «в проекте не используется - не довод» их нельзя считать
отсутствующими. **Вопрос владельцу (открыт):** брать ли PSK-наборы, CBC-наборы и
голый RSA-обмен в 1.2. Замечание: нынешний код молча пропускает коды, которых нет
у BoringSSL (`SSL_get_cipher_by_value == nullptr → continue`), так что перечень -
заявка API, а не доказанная работа.

**Пересогласование:** не нужно. `SSL_OP_NO_RENEGOTIATION` на обеих сторонах
(6952, 7180) плюс `SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION` у сервера.
renegotiation_info по RFC 5746 - только как расширение совместимости.

**Билеты RFC 5077:** не используются. Кэш сеансов отключён осознанно
(`SSL_SESS_CACHE_OFF`, 7355; строка с `SSL_SESS_CACHE_SERVER` закомментирована
рядом); `SSL_SESSION`, `set_session`, `get1_session`, `SSL_OP_NO_TICKET` не зовутся.
Возобновления 1.2 у AWH нет ни на одной стороне. **Вопрос владельцу (открыт):**
делать ли билеты 1.2, раз API наружу.

**EMS (RFC 7627):** своих вызовов нет, AWH полагается на умолчание библиотеки.
Решение: делать безусловно, как велит стандарт для новой реализации.

**Прочее из того же места:** `SSL_OP_NO_COMPRESSION` (сжатие записей не делать);
`SSL_OP_CIPHER_SERVER_PREFERENCE` у сервера (в 1.2 порядок выбирает сервер - нужна
настройка; в 1.3 у нас выбор по порядку клиента); `SSL_OP_SINGLE_DH_USE` и
`SSL_OP_SINGLE_ECDH_USE` (доля на каждое рукопожатие свежая); SSLv2/SSLv3/TLS 1.0/1.1
отключены жёстко - ниже 1.2 не опускаться никогда.

**DTLS:** в 1.3 cookie едет в HelloRetryRequest, в 1.2 от чужого узла придёт
HelloVerifyRequest - AWH его разбирает (coder.cpp:1560), в режиме 1.2 он нужен
по-настоящему, не заглушкой.

**Закрыто 05.09.2026: DTLS 1.2 с HelloVerifyRequest** (RFC 6347 в том же движке,
`transport(DATAGRAMS)` по пределам `versions`: 0x0303 - DTLS 1.2, 0x0304 - DTLS 1.3,
умолчание 1.2…1.3). Потребность coder.cpp:1560 закрыта полноценно: сервер без состояния
отвечает на первое приветствие HelloVerifyRequest с изданием 0xFEFF и меткой по адресу
(`address()`, обязателен) и хешу приветствия на секрете поколения (`stamp()`/`restamp()`,
общие с DTLS 1.3, два живых поколения); метка сверяется без состояния - её признаёт и
соседний сервер с тем же секретом; клиент разбирает просьбу чужого сервера всегда (openssl
шлёт её и без -listen), повторяет приветствие с меткой любой длины до 255 байтов. MTU наружу
- `mtu()`, таймер наружу - `timeout()`/`elapsed()`, сообщение целиком (SCTP SEQPACKET) -
`push()` одной дейтаграммой, отбросы - `discarded(reason)` с новой причиной `VERSION`.
Обмен с openssl 3.6 по UDP в обе стороны и векторы шести изданий закреплены в
`tests/dtls12` (см. CONFORMANCE.md, раздел DTLS 1.2). SRTP, CID, билеты и
пересогласование в 1.2 не ведутся - AWH их не требует.

### Уточнения Григория к договору DATAGRAMS (04.09.2026, по coder.cpp)

1. **MTU.** В coder.cpp стоит 1200 (6579/6580, 6747/6748), но движки AWH считают
   полезную нагрузку UDP по `AWH_MTU_UDP_IPV4_PAYLOAD_SIZE` = 1400 (в пояснении: «для
   DTLS лучше 1454»). Умолчание 1200 верное (RFC 9147 §5.1), но `mtu()` будет
   использоваться сразу; сверху предела не ставить - по SCTP SEQPACKET сообщение
   приходит целиком, туда пойдут размеры больше 1500.
2. **output() «ровно одна дейтаграмма».** AWH держит DTLS на паре BIO_s_mem
   (6532/6534, 6700/6702) и выгребает записи циклом `while(BIO_ctrl_pending)`
   кусками по 16384 (1179-1181, 6060-6062) - границы дейтаграмм не хранятся.
   Договор A-NTS строже: потребитель обязан звать `output()` в цикле до пустоты.
   Записать прямым текстом в договоре и закрепить проверкой (несколько готовых
   записей подряд - каждая своей дейтаграммой, ни одна не теряется).
3. **Адрес узла для cookie.** AWH вплетает два октета порта, затем адрес (4 либо 16
   октетов) под HMAC на секрете из RAND_bytes (2364-2394); по SCTP - опознаватель
   связи `sinfo_assoc_id`. Содержимое `address(view)` непрозрачно, сравнивается
   побайтно, ядро его не разбирает - записать в договоре. Отсутствие адреса у своего
   сервера - громкий отказ при `start()` (у AWH `COOKIE_FAILED` с извещением), а не
   молчание; молчаливый отброс - только для чужого ClientHello с негодным cookie.
4. **Таймер.** AWH сроками повторной передачи сегодня не управляет вовсе
   (`DTLSv1_get_timeout`/`DTLSv1_handle_timeout` не зовутся); свои таймеры есть
   (`event::family_t::TIMER`, `setTimeout`). `timeout()` обязан отвечать и когда
   ждать нечего (нуль), чтобы различать «срок не наступил» и «повторять нечего».
5. **discarded() по причинам** (повтор, порча, чужая эпоха, слишком длинная
   дейтаграмма, CID, cookie), а не одним числом - иначе проверки потерь не могут
   утверждать, что отброшено именно испорченное.

Запреты (0-RTT поверх дейтаграмм, CID, EndOfEarlyData, use_srtp) AWH не нарушает.

### Потребности AWH к OCSP (снято Григорием 05.09.2026 с coder.cpp)

Сшивка у AWH сделана наполовину: `onlineCertificateStatusProtocol(id)` (9093) включает
`SSL_CTX_enable_ocsp_stapling`/`SSL_enable_ocsp_stapling` только у клиента и зовётся не
потребителем, а разбором расширений (9337, 9503). Ответ наружу не отдаётся
(`SSL_get0_ocsp_response` не зовётся), проверки нет, серверной стороны нет,
`CertificateStatus` разбирается лишь ради журнала (1479-1495). Выводы: `status()`,
`verification()`, `certified()` закрывают настоящий пробел и сверяются со стандартом, а не
с нынешним поведением; `status(true)` обязан работать сам по себе без иных настроек;
умолчание `verification(false)` закреплено - иначе переход тихо сменит поведение узлов.

### Шкала изданий на любом переносе (решено с Григорием 06.09.2026)

Пределы `versions(lowest, highest)` и итог `version()` — коды TLS 0x0303/0x0304 на любом
переносе, без исключений; проводные 0xFEFD/0xFEFC наружу не показываются нигде (счёт
изданий DTLS обратный, и диапазон «от 1.2 до 1.3» в проводной шкале выглядел бы
перевёрнутым). В doxygen `versions()`/`version()`: «издания задаются и отдаются кодами
TLS 0x0303/0x0304 на любом переносе; на проводе DTLS они ложатся как 0xFEFD/0xFEFC».
**Закрыто 06.09.2026 правкой по аудиту DTLS 1.2:** `version()` поверх дейтаграмм отдаёт
0x0303 у DTLS 1.2 и 0x0304 у DTLS 1.3 (`Dtls12Test.Contract`/`Loopback`/`Versions`,
`DtlsTest.Loopback`), пределы `versions()` - те же коды; проводные 0xFEFD/0xFEFC утверждаются
проверками лишь по байтам записей и приветствий; doxygen `versions()`/`version()` обоих
фасадов несёт оговорённую формулировку.

### Решение владельца 06.09.2026: второй круг TLS 1.2 - PSK, CBC, RSA-обмен, билеты

«Раз DTLS 1.2 сделан, берём и это, пусть будет - старые системы ещё используются».
Закрыты оба открытых вопроса: в TLS 1.2 (и DTLS 1.2) добавляются наборы PSK
(ECDHE-PSK 0xC035/0xC036/0xCCAC и PSK-AES128/256-CBC-SHA), CBC-наборы
(0xC023/0xC027, 0xC009/0xC00A/0xC013/0xC014, AES128/256-SHA), голый RSA-обмен
(AES128/256-SHA, AES128/256-GCM-SHA256/384) и билеты сеансов RFC 5077 с
возобновлением. Порядок: после слияния правки DTLS 1.2 по аудиту.

### Потребности AWH к PSK и билетам 1.2 (снято Григорием 06.09.2026 с coder.cpp)

Ни PSK, ни билетов 1.2 в AWH нет вовсе - только имена наружу: пять PSK-наборов в
`cipher_t` (собираются в `cipher_list`, но ключа взять неоткуда), `psk_key_t` и
расширение 0x21 живут лишь в fingerprint.cpp (чтение чужого приветствия). Ручек
билетов нет (кэш выключен осознанно, `SSL_CTX_set_session_id_context` без кэша пуст).
Договор пишется с чистого листа по стандарту. Форма (совет Григория, принят):
- PSK: сервер - отклик потребителя «дано identity → ключ либо отказ» (много узлов одним
  контекстом, единственный ключ на контекст бесполезен); клиент - настройка identity +
  ключ и отклик на identity hint сервера; неверный ключ → decrypt_error (51), не молчание.
- Билеты 1.2: та же форма, что у 1.3 - билет наружу октетами, приём октетов обратно
  (потребитель не знает издания внутри); ключ шифрования билета на сервере наружу -
  иначе кластер AWH не примет билет соседнего узла.
Векторы: PSK двумя наборами, CBC с ETM и без, голый RSA двумя наборами (у новых изданий
может потребоваться @SECLEVEL=0 - это свойство openssl, не протокола), билеты двумя
рукопожатиями (-sess_out/-sess_in).

### Потребности AWH к CBC и голому RSA (снято Григорием 06.09.2026)

Голый RSA-обмен: своего кода у AWH нет, объявлены четыре набора без ECDHE в
`cipher_list`. Защита от Bleichenbacher целиком на A-NTS: отказ при негодном premaster
обязан быть неотличим от удачи по времени и по виду - закрепить проверкой.
CBC и encrypt_then_mac: расширение у AWH только в fingerprint.cpp (разбор чужого). Договор
с чистого листа: ETM включать безусловно при всяком CBC-наборе и предпочитать; при
отсутствии у собеседника - MAC-then-Encrypt, но это ВИДНО наружу потребителю (ручка/признак).
Ловушка: `extension_type_t` у AWH - внутренние коды, не проводные (ENCRYPT_THEN_MAC = 0x14
против 0x0016 на проводе; перевод в fingerprint.cpp:623). Сверять договор по проводным
кодам из fingerprint.cpp. PADDING, MAX_FRAGMENT_LENGTH, RENEGOTIATION_INFO там же - только
разбор чужого; из них нужен лишь renegotiation_info как расширение совместимости.

### Закрыто 06.09.2026: второй круг TLS 1.2 (CBC, голый RSA, PSK, билеты)

Сделано в том же движке и тех же фасадах, записями и дейтаграммами (README «TLS 1.2: второй
круг», CONFORMANCE «TLS 1.2: второй круг»):
- CBC 0xC023, 0xC027, 0xC009, 0xC00A, 0xC013, 0xC014, 0x002F, 0x0035, 0x003C, 0x003D с
  encrypt_then_mac RFC 7366 (предлагается и предпочитается всегда; ручка `etm(true)` -
  требовать; `etm()` - согласован ли, чтобы потребитель знал, что связь идёт
  MAC-then-Encrypt) и защитой от Lucky13 постоянным временем без него;
- голый RSA 0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D с подменой premaster под маской
  (Бляйхенбахер): ответ сервера на порченый CKE неотличим от годного, отказ лишь на
  завершении клиента `bad_record_mac`;
- PSK 0x008C, 0x008D, 0xC035, 0xC036, 0xCCAC договором формы Григория: `context::psk_t` -
  у сервера вызов `respond` «дано identity → ключ либо отказ» с необязательной подсказкой и
  ручкой `disclose` (115 либо молчание до завершения), у клиента identity + ключ и вызов
  `advise` «дан hint → identity + ключ»; фасады `client::psk`/`server::psk`;
- билеты RFC 5077 единой с 1.3 формой: `tickets()` отдаёт `context::ticket_t` (билет
  октетами в `identity`, главный секрет в `secret`), `context::encode`/`decode` уносят его
  в другой процесс, `resume(ticket)` предъявляет; ключ билетов сервера наружу -
  `server::vault(secret)` с двумя живыми поколениями (кластер AWH с одним секретом признаёт
  билеты соседей); кэша сеансов нет.

Уточнения к договору по итогам обмена с openssl 3.6 и векторов Григория (tls12x):
- неверный PSK обрывается `bad_record_mac` (20) на завершении клиента, а не `decrypt_error`
  (51): при чужом ключе расходится key_block, и завершение не вскрывается раньше сличения
  verify_data - так же у openssl («bad record mac» в `psk-wrong-key`); `decrypt_error` в
  PSK недостижим, `unknown_psk_identity` (115) идёт по ручке `disclose`;
- признак возобновления билетом у клиента - состав залпа сервера, а не повтор
  session_id (openssl его не переносит);
- голый RSA и PSK у openssl 3.6 требуют `-cipher …@SECLEVEL=0` - свойство сборки openssl,
  в проверках задаётся;
- завершённость обмена с s_client судится по «Verify return code: 0 (ok)» и отсутствию
  отказа у нашего сервера, а не по строке «Cipher :».

## ECH и HPKE: потребности AWH (снято с src/cryptography/tls/coder.cpp 06.09.2026, только чтение)

Места: `member->ech` в `cts_t` (692) и `ctl_t` (730), применение при заведении связи
(6613-6618, 6808-6813), `getKeysECH` (7460-7530), `setKeysECH` (7536-7860),
`grease` (8744-8830). Обращений к BoringSSL по ECH: `EVP_HPKE_KEY_new/init/generate/free`,
`EVP_hpke_x25519_hkdf_sha256`, `SSL_marshal_ech_config`, `SSL_ECH_KEYS_new/add/free`,
`SSL_ECH_KEYS_marshal_retry_configs`, `SSL_CTX_set1_ech_keys`, `SSL_set1_ech_config_list`,
`RAND_bytes` (config id). Ни `SSL_ech_accepted`, ни `SSL_get0_ech_retry_configs`, ни
`SSL_get0_ech_name_override`, ни `SSL_ECH_KEYS_has_duplicate_config_id` AWH не зовёт.

Что AWH делает:

- **Клиент** (CTS и CTL): `setKeysECH(id, bytes)` — довод это готовый **ECHConfigList**
  байтами (из DNS HTTPS-записи, ключ `ech`), пустой довод у клиента — отказ (`result =
  false`, без журнала). Список хранится копией в шаблоне контекста (`cts->ech`) и при
  заведении каждой связи копируется в `ctl->ech` и ставится `SSL_set1_ech_config_list`
  **до приветствия**; на уровне CTL ставится сразу на `SSL *`. `getKeysECH` у клиента
  отдаёт те же байты, что были поданы. Разбор списка, выбор конфигурации, набор HPKE — всё
  на стороне библиотеки: AWH внутрь ECHConfigList не глядит.
- **Сервер** (только CTS; на CTL — отказ `INVALID_LAYER` «keys must be configured at the
  context level»): довод `setKeysECH` — либо **32 байта секретного ключа X25519** для
  `EVP_HPKE_KEY_init(EVP_hpke_x25519_hkdf_sha256)`, либо **пустой** — тогда ключ
  порождается `EVP_HPKE_KEY_generate`. Дальше AWH сам складывает **один ECHConfig**:
  `config_id` — один случайный байт `RAND_bytes`, ключ — из HPKE-ключа, **публичное
  имя** — `member->host`, а при пустом — `"localhost"`; `SSL_marshal_ech_config` заполняет
  остальное (издание 0xFE0D, KEM 0x0020, набор шифров и наибольшую длину имени — умолчания
  BoringSSL). Конфигурация кладётся в `SSL_ECH_KEYS` с `is_retry_config = 1` и ставится
  на контекст `SSL_CTX_set1_ech_keys`. После успеха AWH берёт
  `SSL_ECH_KEYS_marshal_retry_configs` — **ECHConfigList из конфигураций, помеченных
  retry**, — и хранит его в `cts->ech`; именно он отдаётся `getKeysECH` для публикации в
  DNS. Итого у сервера два разных выхода наружу: ключи в контекст (внутрь) и ECHConfigList
  для DNS (наружу); секретный ключ наружу не отдаётся.
- **Отказы**: всякий отказ по пути (нет памяти под ключ, ключ не инициализирован, не
  собрался ECHConfig, не встали ключи на контекст) — отклик `callback.error(id,
  SNI_FAILED, текст)` либо журнал `CRITICAL`, `result = false`; связь не рвётся, сервер
  живёт без ECH. Отказ `SSL_ECH_KEYS_marshal_retry_configs` молча оставляет `cts->ech`
  пустым. Итог принятия ECH в рукопожатии (accepted / retry configs от сервера / имя
  public_name при откате) AWH **не читает и не обрабатывает**: при отказе ECH связь идёт
  как обычная с публичным именем, потребитель об этом не узнаёт.
- **GREASE ECH**: отдельной ручки нет; `grease(id, mode)` включает
  `SSL_CTX_set_grease_enabled`, и у BoringSSL это же включает GREASE-расширение ECH
  (0xFE0D со случайным телом) у клиента без настроенного ECHConfigList. Значит, GREASE ECH
  ожидается как часть общего GREASE (работа A), а не как настройка модуля ECH.
- **Один ключ, одна конфигурация**: ротации ключей, нескольких конфигураций на сервере и
  подмены без обрыва связей у AWH нет; `setKeysECH` вызывается один раз при настройке.

Что из этого требуется от A-NTS второй ступенью (ECH поверх `hpke`):

1. Клиент: `client::ech(ECHConfigList байтами)` — разбор списка (RFC 9180 KEM 0x0020,
   издание ECHConfig 0xFE0D по draft-ietf-tls-esni-18 / RFC 9849), выбор первой
   поддерживаемой конфигурации, `encrypted_client_hello` с внутренним приветствием,
   `hpke::sender` в режиме `BASE` с `info = "tls ech" || 0x00 || ECHConfig`; ставится до
   приветствия и живёт в связи копией.
2. Сервер: `server::ech(секрет X25519 либо пусто → порождение, публичное имя, config_id)`
   и `server::ech()` → ECHConfigList для DNS из конфигураций с признаком retry; ключ
   `hpke::key_t::set`/`generate`; принятие внешнего приветствия, `hpke::recipient`,
   расшифрование внутреннего, `ech_accept` в `ServerHello.random`; при отказе —
   `retry_configs` в защищённых расширениях и связь по публичному имени.
3. Итог наружу, которого у AWH нет, но который нужен для правильного отката: признак
   «ECH принят» и полученные `retry_configs` у клиента — как `ech()`/`retry()` на фасаде.
4. GREASE ECH: расширение 0xFE0D со случайным телом при включённом `grease(true)` без
   настроенного списка — точка стыка с работой A; при профиле отпечатка (работа C) длина
   тела берётся из профиля.
5. Модуль `hpke` этой работы всё, что нужно ECH, уже отдаёт: X25519-KEM с заданным и
   порождённым ключом, `BASE`, три AEAD, `sender`/`recipient` с `info`, `seal`/`open` с
   порядковыми номерами, `exporter`. Ничего сверх RFC 9180 для ECH не требуется.

Сверка со снятием Григория (передано координатором 06.09.2026): расхождений нет —
клиенту ECHConfigList целиком байтами до приветствия с копией в связи; серверу ключ HPKE
X25519 заданный либо порождённый при пустом доводе; ECHConfig складывается с config id,
ключом и публичным именем; наружу идут только конфигурации с `is_retry_config = 1`, и это
второй выход, отличный от ключей. Дополнено сверх снятого: публичное имя берётся из
`member->host` с подменой `"localhost"` при пустом; config id — один случайный байт;
сервер на CTL отвергается; итог принятия ECH и retry configs от сервера AWH не читает;
GREASE ECH ждётся от общего `grease`, своей ручки у него нет.


### Отпечатки: перенос `awh::tls::Fingerprint` в A-NTS (закрыто 07.09.2026)

Решение владельца 06.09.2026: модуль отпечатков переносится в A-NTS целиком, снимок
применяется движком «как есть», в AWH модуль удаляется. Потребности AWH (сняты Григорием
с `coder.cpp` 06.09.2026) и их закрытие:

| Потребность AWH | Закрытие в A-NTS |
|---|---|
| `browser(id, fid)`: профиль выбирается числом из хранилища потребителя до рукопожатия (`coder.cpp:6624`) | `client::profile(const fingerprint::profile_t &)` до `start()` (после - `STATE`); хранилище `fingerprint::store_t` оставлено потребителю по желанию |
| `fingerprint_callback_t(id, browser_t)`: серверу нужен разобранный отпечаток из write-пути (`coder.cpp:8193`) | `server::profile(fingerprint::profile_t &)` с момента приёма приветствия; сырые байты - `server::greeting()` |
| `FINGERPRINT_FAILED` (0x11): отказ приложения громкий и отдельный | `context::error_t::PROFILE` (0x21): сервер выбрал набор профиля, связи неведомый; профиль не в свой черёд - `STATE`, негодный - `SETTINGS` |
| `grease(id, browser.grease)`: признак GREASE один на профиль | места и число значений GREASE берутся из снимка, ручка `grease` на профиль не влияет |
| Сборка ClientHello по кускам в read-пути и `apply()` переписыванием байтов | исчезают: приветствие складывается движком по профилю до отправки; вызовы `threadSafety()` в AWH снимаются вместе с модулем |
| Профиль только клиенту («supported for the client only») | `server::profile(const profile_t &)` не заводится; установщик серверу отвечает `SETTINGS` |
| JA3/JA4/PeetPrint/Akamai, дамп, хранилище | `fingerprint::imprint`, `akamai`, `dump`/`load` (переносимый формат вместо порядка машины), `store_t`; JA4 - SHA-256 по FoxIO (у AWH был MD5) |

Закрыто 07.09.2026: доля X25519MLKEM768 (0x11EC) вырабатывается свежей гибридной парой
(ML-KEM-768 по FIPS 203 + X25519), профиль Chrome воспроизводится и по долям; ECH настоящий
(см. ниже). Остаток: доли прочих постквантовых гибридов (SecP256r1MLKEM768 0x11EB,
SecP384r1MLKEM1024 0x11ED) опускаются - их не шлёт ни один браузер.


### Закрыто 07.09.2026: ECH поверх HPKE (RFC 9849)

| Потребность AWH | Закрытие в A-NTS |
|---|---|
| клиенту `setKeysECH(ECHConfigList байтами)` до приветствия, копия в связи, `getKeysECH` те же байты | `client::ech(list)` до `start()`, `client::ech()` - заданный перечень |
| серверу секрет X25519 (32 байта) либо пусто → порождение; один ECHConfig с публичным именем (`member->host`, иначе `"localhost"`), случайный config id | `server::ech(secret, name, id, length)`: ключ, имя, опознаватель и наибольшую длину имени подаёт потребитель; конфигурация издания 0xFE0D, KEM 0x0020, наборы AES-128-GCM и ChaCha20-Poly1305 |
| `SSL_ECH_KEYS_marshal_retry_configs` → ECHConfigList для DNS, ключи внутрь, секрет наружу не отдаётся | `server::ech()` - перечень для DNS; секрет не отдаётся |
| принятие внешнего приветствия, расшифрование, подтверждение, retry_configs при отказе | движок: `unshrouding`/`marking`, `retry_configs` в защищённых расширениях |
| GREASE ECH через общий `grease` | `client::grease(true)` без конфигураций - значение GREASE ECH |
| чего у AWH не было, но нужно для правильного отката: признак принятия и retry configs | `client::shrouded()`, `client::retry()`, `client::visible()` (имя для удостоверения при отказе), отказ `ECH` с извещением `ech_required` |

Закрыто 07.09.2026: ECH с билетом возобновления - билет и привязка во внутреннем приветствии,
внешнее без `pre_shared_key`/`early_data`, связь остаётся скрытой и возобновлённой
(`EchTest.Resumed`, `Boringssl3` с bssl `-test-resumption`); ECH поверх дейтаграмм DTLS 1.3
(`EchTest.Datagram`, запись с полем метки, эталона нет). Не сделано
намеренно: упреждающие данные под ECH, несколько конфигураций
и ротация ключей у сервера (у AWH их нет), KEM на кривых NIST.


### Закрыто 07.09.2026: Argon2id и BLAKE2 (план Романа, п. 2 и часть п. 4)

| Требование | Как закрыто |
| --- | --- |
| `awh::Crypto` шифрует файлы ключом из PBKDF2 (100 000 оборотов) - против ферм не держит | `digest::argon2` (RFC 9106, 0x13): Argon2d/i/id, память параметром; PBKDF2 остаётся для стандартов |
| параметры m/t/p, обороты - из записи, не из умолчаний сборки | параметры подаются `argon_params_t` при каждом вызове, модуль их не хранит |
| отказ памятью, не падением | `new (nothrow)` под матрицу, `Argon2Test.Memory` |
| BLAKE2s для WireGuard, ключевой режим | `digest::blake2_t` BLAKE2b и BLAKE2s с ключом и переменной длиной; `hash_t::BLAKE2S256/BLAKE2B512` - HMAC/HKDF над ними (Noise, WireGuard) |
| строка PHC для чужих записей Argon2 (libsodium, таблицы паролей) | `digest::phc` разбор и запись; параметры и соль обязательны, выход необязателен |


### Закрыто 07.09.2026: сырой поточный вызов и набор WireGuard (план Романа, п. 3 и 4)

| Требование | Как закрыто |
| --- | --- |
| XChaCha20 без Poly1305: ключ, 24-октетный вектор, счётчик блока, xor на месте | `chacha_t::start(key, nonce24, counter)` + `encrypt/decrypt`; `chacha_t::hchacha` отдельно |
| AES-CTR без GCM | `counter_t` над `block_t(aes_t)` (было) |
| статистическая приёмка выхода на неверных ключах | `RawTest.Statistics`: монобит и χ² на 1 МиБ, XChaCha20 и AES-CTR |
| XChaCha20-Poly1305 | `chachapoly_t::start` с 24-байтовым заполнением (IETF) |
| BLAKE2s с ключом, SipHash-2-4 | `digest::blake2_t`, `digest::siphash` |

### Закрыто 07.09.2026: набор Noise (порядок Романа, ступени 1-4 по классике)

| Требование | Как закрыто |
| --- | --- |
| узоры таблицей, а не ветвями | `src/noise/patterns.cpp`: 15 основных и односторонних, 23 отложенных; psk видоизменениями |
| XX первым, IK/NK/NN, N/K/X, IKpsk2 | всё в одной машине `noise::handshake_t`; векторы flynn 1920 из 1920, Cacophony 472 из 944 |
| наборы, включая HASHLEN 64 | восемь наборов 25519 × {ChaChaPoly, AESGCM} × {SHA256, SHA512, BLAKE2s, BLAKE2b}; усечение ключа при 64 закреплено векторами и мутацией |
| CipherState: 2^64-1 запретно, rekey наружу, split два состояния, пролог, 65535, затирание, MixKeyAndHash на три | `noise::cipher_t`, `noise::symmetric_t`; проверки `NoiseTest.{Nonce,Rekey,OneWay,Message,Hkdf}` |
| обмен по буферам потребителя без выделений | `write/read` на буферах вызывающего; `NoiseTest.Starved` с пайком в нуль |
| сырой CipherState под WireGuard (свой счётчик и окно повтора) | `cipher_t::encrypt(n, …)/decrypt(n, …)`, `key(out)` |
| эталон: векторы Cacophony, пропуск вслух | два корпуса как есть, свой читатель JSON, счёт «взято/пропущено» утверждается |
| живой обмен с чужой реализацией | статический собеседник Григория на flynn/noise (Go только у эталона) |
| PQNoise | ступень 5 отдельно, после приёмки классики |

### Закрыто 08.09.2026: ALPS (первый долг по порядку Романа; карта Григория)

| Требование AWH | Как закрыто |
| --- | --- |
| `SSL_add_application_settings` для каждого протокола ALPN с пустыми настройками | `client::settings(protocol, value)` / `server::settings(...)`; профиль отпечатка с ALPS объявляет протоколы снимка с пустыми настройками сам |
| `SSL_set_alps_use_new_codepoint` по профилю (0x4469 прежняя, 0x44CD новая) | `codepoint(extension::type_t::SETTINGS / SETTINGS_OLD)`, профиль выставляет точку сам; `codepoint()` наружу |
| чужие настройки (AWH пока не забирает) | `settled()`, `settings()` |
| ALPS в отпечатках (`WIRE_ALPS`) | имена были перепутаны местами (0x4469 звался новым) - переехали на `extension::type_t`, отпечатки не менялись |
| несогласованность: снимок Chrome предлагал ALPS, а движок не договаривал | закрыто: приветствие по снимку идёт с ALPS, сервер отвечает, клиент шлёт сообщение 8 (`AlpsTest.Profile`) |

### Закрыто 08.09.2026: SCT (второй долг по порядку Романа; карта Григория)

| Требование AWH | Как закрыто |
| --- | --- |
| `SSL_CTX_enable_signed_cert_timestamps`, `SSL_enable_signed_cert_timestamps` у клиента | `client::timestamps(true)`; профиль отпечатка с расширением 0x0012 включает запрос сам |
| ответ сервера принять, не валя рукопожатие | издание 1.3 - запись листа цепочки, издание 1.2 - приветствие сервера; негодный перечень - decode_error, как у BoringSSL |
| список наружу (AWH пока не забирает) | `client::timestamps()` как записан, `extension::timestamps()` делит на записи |
| сервер (у AWH нет) | `server::timestamps(list)` - выдача по запросу, чтобы связь была полной с обеих сторон |

### Закрыто 08.09.2026: перечень доверенных ЦС (третий долг по порядку Романа; карта Григория)

| Требование AWH | Как закрыто |
| --- | --- |
| `SSL_load_client_CA_file` + `SSL_set_client_CA_list` / `SSL_CTX_set_client_CA_list` (12 мест) | `server::authorities(names)` - DER-имена владельцев сертификатов из файла: `pem::certificates` → `x509::certificate_t::parse` → `subjects().element` |
| перечень в запросе подлинности обоих изданий | 1.3 расширением 0x002F, 1.2 полем запроса; без перечня как прежде |
| перечень у клиента (AWH не забирает) | `client::authorities()`, выбор сертификата за потребителем |

### Закрыто 08.09.2026: NPN (четвёртый долг; слово владельца через Романа - ради снимков отпечатков)

| Требование AWH | Как закрыто |
| --- | --- |
| `SSL_CTX_set_next_proto_select_cb` у клиента (выбор первого своего из объявленных) | `client::negotiation(true)`, выбор порядком клиента среди объявленных сервером; без общего - первый свой (у AWH отклик отвечал NOACK, что у BoringSSL валило рукопожатие внутренней ошибкой - дефект AWH, не перенос) |
| `SSL_CTX_set_next_protos_advertised_cb` у сервера (перечень ALPN) | `server::negotiation(true)` объявляет `protocols()`; лишь когда ALPN не выбран |
| снимок Chrome с 0x3374 байт в байт | профиль несёт расширение сырым телом, ответ сервера клиент ведёт по предложенному (`NpnTest.Profile`) |
| итог наружу | `protocol()` общий с ALPN, `negotiated()` |

### Закрыто 08.09.2026: DTLS 1.0 (пятый долг; слово владельца через Романа - старые системы)

| Требование AWH | Как закрыто |
| --- | --- |
| `SSL_CTX_set_min_proto_version(ctx, DTLS1_VERSION)` у UDP (4 места) | `versions(0x0302, 0x0303)` поверх дейтаграмм: DTLS 1.0 по RFC 4347 поверх TLS 1.1, наборы CBC-SHA1 |
| чужие собеседники издания 1.0 | обе роли против openssl -dtls1 (`Dtls10Test.Openssl`); BoringSSL (DTLS1_VERSION) - у Григория |
| пол TCP 1.2 остаётся | потоком 1.0/1.1 не заводятся: `start()` отвечает `SETTINGS` |

### Закрыто 08.09.2026: WireGuard-кадры и PQNoise (ступени 4 и 5 порядка Романа)

| Требование | Как закрыто |
| --- | --- |
| IKpsk2 под WireGuard с настоящим эталоном | `tests/corpus/noise/wireguard.txt` от wireguard-go, кадры 148/92 байт в байт с mac1 (`WireguardTest.Vector`) |
| сырой CipherState под счётчик и окно повтора | `cipher_t::encrypt/decrypt(n, …)`, `key(out)`; перенос в проверке кадров |
| PQNoise: отвлечение KEM, pqXX, pqIK, чистый ML-KEM строкой | `noise::kem_t`, `kemlength`, тринадцать узоров таблицей, `PqnoiseTest` 6 проверок |
| целость классики после обобщения | flynn 1920, Cacophony 472 теми же числами |
| свой замороженный корпус с оговоркой | `tests/corpus/noise/pqnoise.txt`, 52 записи, `ANTS_NOISE_FREEZE` вслух |

### Закрыто 08.09.2026: пределы длины записи (дефект по профилям отпечатков; Роман: исправление, не охват)

| Требование | Как закрыто |
| --- | --- |
| профиль Firefox с record_size_limit (0x001C = 16385) байт в байт и связь со строгим сервером | клиент применяет ответ к отправке и свой предел к приёму, `LimitTest`, чужой эталон `gnutls-serv --recordsize` |
| max_fragment_length (0x0001) из профиля | ответ тем же кодом связывает обе стороны, чужой эталон `openssl s_client -maxfraglen` обеими версиями |
| `SSL_CTX_set_max_send_fragment` / `SSL_get_max_send_fragment` (если понадобятся AWH) | `ceiling()` - действующий предел отправки, `threshold()` - приёма; своё предложение предела вне профиля не заводится, пока не запрошено |
| CertificateRequest с пустым status_request (GnuTLS) | принимаются обе формы, сервер шлёт форму RFC 8446 §4.4.2.1 |

### Закрыто 08.09.2026: heartbeat из профилей отпечатков (Роман: ронять молча, не отвечать)

| Требование | Как закрыто |
| --- | --- |
| профиль с расширением 0x000F байт в байт и связь с сервером, шлющим HeartbeatRequest | запись вида 24 роняется молча при предложенном расширении; `HeartbeatTest`, `gnutls-serv --heartbeat` |
| ответ на сердцебиение | по умолчанию нет (усилитель, Heartbleed); 09.09.2026 по слову владельца добавлен явный вызов `heartbeat(payload)`/`pulses()` и ответ на входящий запрос лишь по установленной связи 1.2/DTLS 1.2 (`HeartbeatTest.Ping`) |

### Закрыто 08.09.2026: упреждающие данные под ECH (намеренный пропуск 07.09 снят)

| Требование | Как закрыто |
| --- | --- |
| 0-RTT по билету связи под ECH | `advance(true)` работает и с ECH: `EchTest.Early`; отклонённый ECH - сервер пропускает упреждение, `EchTest.EarlyRejected` |

### Закрыто 08.09.2026: гибриды NIST 0x11EB/0x11ED (намеренный пропуск снят)

| Требование | Как закрыто |
| --- | --- |
| SecP256r1MLKEM768, SecP384r1MLKEM1024 обеими ролями | `HybridTest.Nist`, `NistOpenssl` против openssl 3.6.3; профили с их долями больше не усекаются |

### Закрыто 09.09.2026: отложенные группы обмена (по слову владельца «делай отложенное»)

| Требование | Как закрыто |
| --- | --- |
| X448, secp521r1 (+ схема 0x0603), secp256k1, конечное поле RFC 7919 | `agreement::x448`, `agreement::ffdhe`, кривые P-521 и secp256k1 в таблице параметров; гейт издания `fitting()`; `GroupsTest`, `X448Test`, `FfdheTest`, `ParametersTest.Deferred`; сличение с openssl 3.6.3 обеими ролями по каждой группе; разрядность числа поля 512→576, целого 4096→8192 |

### Аудит кода, круг 1 (09.09.2026)

| Требование | Как закрыто |
| --- | --- |
| код без известных дефектов до переезда | 8 читателей по зонам, 27 находок исправлены (CONFORMANCE «Аудит кода, круг 1»), `tests/audit` 14 пинов; для AWH важно: `trust::verify` с ролью (клиент обязан звать `role_t::SERVER`), потолок итераций PBKDF2 10^7 у ключей извне, ECH-перечни с негодными конфигурациями больше не глушат `start()` |

### Аудит кода, круг 2 (09.09.2026)

| Требование | Как закрыто |
| --- | --- |
| код без известных дефектов | 22 находки исправлены (CONFORMANCE «Аудит кода, круг 2»), в т.ч. впрыск открытого текста у DTLS 1.3, nameConstraints и EKU издателей у доверия, переполнение Poly1305; `tests/audit` 26 пинов; отложено намеренно одно: ветвление по секрету в делении RSA при загрузке ключа (условие пересмотра - сосед по ядру) |
