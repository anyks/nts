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
| `SSL_CTX_set_grease_enabled` | `src/cryptography/tls/coder.cpp` ×4 |
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
| Наборы 0x1301 TLS_AES_128_GCM_SHA256, 0x1302 TLS_AES_256_GCM_SHA384, 0x1303 TLS_CHACHA20_POLY1305_SHA256 | нет; примитивы AES-GCM и SHA-2 есть |
| Группы 0x001D x25519, 0x0017 secp256r1, 0x0018 secp384r1 | нет объявления; примитивы есть |
| Схемы 0x0403 ecdsa_secp256r1_sha256, 0x0503, 0x0804…0x0806 rsa_pss_rsae_*, 0x0807 ed25519 | нет объявления; примитивы есть |
| ChaCha20-Poly1305 | нет вовсе, единственный отсутствующий примитив |
| DTLS 1.0/1.2 (30 мест в AWH) | нет задела: `epoch` в дереве это только время, `cookie` это метка возврата HelloRetryRequest TLS 1.3 |
| OCSP и сшивка ответа (9 мест) | нет |
| Сжатие сертификатов RFC 8879 (58 мест, вид BoringSSL) | нет; нужность решает владелец |
| TLS 1.2 | нет; AWH ставит пределы 1.2 и 1.3, ветви 1.0/1.1 не нужны |

Закрывать не надо: закрепление отпечатка (отклик AWH над готовой цепочкой, DER
сертификата уже доступен). Очерёдность за владельцем.
