/*
 * Keychain Validator & Sign/Verify Tester
 * 
 * Load a .kchain file and test signing/verification with Falcon + SPHINCS+
 * 
 * Build:
 *   gcc -o validate_kchain validate_kchain.c -loqs -ljansson -lm -O3
 * 
 * Run:
 *   ./validate_kchain path/to/file.kchain
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <jansson.h>

typedef struct {
    unsigned char *data;
    size_t len;
} HexData;

static HexData hex_to_bytes(const char *hex) {
    HexData result = {0};
    if (!hex) return result;

    size_t len = strlen(hex);
    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hex string (odd length)\n");
        return result;
    }

    result.len = len / 2;
    result.data = (unsigned char *)malloc(result.len);

    for (size_t i = 0; i < result.len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &result.data[i]);
    }

    return result;
}

static char *bytes_to_hex(const unsigned char *data, size_t len) {
    char *hex = (char *)malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

static int test_falcon_sign_verify(const unsigned char *pk, size_t pk_len,
                                   const unsigned char *sk, size_t sk_len) {
    OQS_SIG *sig = OQS_SIG_new("Falcon-512");
    if (!sig) {
        fprintf(stderr, "Failed to create Falcon-512 context\n");
        return -1;
    }

    unsigned char message[] = "Test message for Falcon-512 signature";
    size_t message_len = sizeof(message) - 1;

    unsigned char *signature = (unsigned char *)malloc(sig->length_signature);
    size_t signature_len = 0;

    /* Sign */
    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, sk) != OQS_STATUS_SUCCESS) {
        fprintf(stderr, "Falcon sign failed\n");
        free(signature);
        OQS_SIG_free(sig);
        return -1;
    }

    printf("  Signature length: %zu bytes\n", signature_len);

    /* Verify */
    if (OQS_SIG_verify(sig, message, message_len, signature, signature_len, pk) != OQS_STATUS_SUCCESS) {
        fprintf(stderr, "Falcon verify failed\n");
        free(signature);
        OQS_SIG_free(sig);
        return -1;
    }

    printf("  ✓ Falcon sign/verify successful\n");

    free(signature);
    OQS_SIG_free(sig);
    return 0;
}

static int test_sphincs_sign_verify(const unsigned char *pk, size_t pk_len,
                                    const unsigned char *sk, size_t sk_len) {
    OQS_SIG *sig = OQS_SIG_new("SPHINCS+-SHA2-128s");
    if (!sig) {
        fprintf(stderr, "Failed to create SPHINCS+ context\n");
        return -1;
    }

    unsigned char message[] = "Test message for SPHINCS+";
    size_t message_len = sizeof(message) - 1;

    unsigned char *signature = (unsigned char *)malloc(sig->length_signature);
    size_t signature_len = 0;

    /* Sign */
    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, sk) != OQS_STATUS_SUCCESS) {
        fprintf(stderr, "SPHINCS+ sign failed\n");
        free(signature);
        OQS_SIG_free(sig);
        return -1;
    }

    printf("  Signature length: %zu bytes\n", signature_len);

    /* Verify */
    if (OQS_SIG_verify(sig, message, message_len, signature, signature_len, pk) != OQS_STATUS_SUCCESS) {
        fprintf(stderr, "SPHINCS+ verify failed\n");
        free(signature);
        OQS_SIG_free(sig);
        return -1;
    }

    printf("  ✓ SPHINCS+ sign/verify successful\n");

    free(signature);
    OQS_SIG_free(sig);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <keychain.kchain>\n", argv[0]);
        return 1;
    }

    printf("===== Keychain Validator & Sign/Verify Tester =====\n\n");

    /* Load JSON */
    printf("[1/4] Loading keychain file: %s\n", argv[1]);
    json_error_t error;
    json_t *root = json_load_file(argv[1], 0, &error);
    if (!root) {
        fprintf(stderr, "Failed to load JSON: %s\n", error.text);
        return 1;
    }
    printf("✓ JSON loaded\n");

    /* Parse seed */
    printf("[2/4] Parsing seed data...\n");
    json_t *seed_obj = json_object_get(root, "seed");
    if (!seed_obj) {
        fprintf(stderr, "No seed object in JSON\n");
        json_decref(root);
        return 1;
    }

    const char *trits_str = json_string_value(json_object_get(seed_obj, "ternary_6000_trits"));
    if (!trits_str || strlen(trits_str) != 6000) {
        fprintf(stderr, "Invalid seed trits (expected 6000, got %zu)\n", trits_str ? strlen(trits_str) : 0);
        json_decref(root);
        return 1;
    }
    printf("✓ Seed: %zu ternary digits\n", strlen(trits_str));

    /* Parse master Falcon keys */
    printf("[3/4] Testing master Falcon-512 keys...\n");
    json_t *keys_obj = json_object_get(root, "keys");
    if (!keys_obj) {
        fprintf(stderr, "No keys object\n");
        json_decref(root);
        return 1;
    }

    const char *falcon_pk_hex = json_string_value(json_object_get(keys_obj, "falcon_512_master_pk"));
    const char *falcon_sk_hex = json_string_value(json_object_get(keys_obj, "falcon_512_master_sk"));

    if (!falcon_pk_hex || !falcon_sk_hex) {
        fprintf(stderr, "Missing Falcon master keys\n");
        json_decref(root);
        return 1;
    }

    HexData falcon_pk = hex_to_bytes(falcon_pk_hex);
    HexData falcon_sk = hex_to_bytes(falcon_sk_hex);
    printf("  Falcon public key:  %zu bytes\n", falcon_pk.len);
    printf("  Falcon private key: %zu bytes\n", falcon_sk.len);

    if (test_falcon_sign_verify(falcon_pk.data, falcon_pk.len, falcon_sk.data, falcon_sk.len) != 0) {
        fprintf(stderr, "Falcon sign/verify test failed\n");
        json_decref(root);
        return 1;
    }

    /* Parse master SPHINCS+ keys */
    printf("[4/4] Testing master SPHINCS+-SHA2-128s keys...\n");
    const char *sphincs_pk_hex = json_string_value(json_object_get(keys_obj, "sphincs_sha2_128s_master_pk"));
    const char *sphincs_sk_hex = json_string_value(json_object_get(keys_obj, "sphincs_sha2_128s_master_sk"));

    if (!sphincs_pk_hex || !sphincs_sk_hex) {
        fprintf(stderr, "Missing SPHINCS+ master keys\n");
        json_decref(root);
        return 1;
    }

    HexData sphincs_pk = hex_to_bytes(sphincs_pk_hex);
    HexData sphincs_sk = hex_to_bytes(sphincs_sk_hex);
    printf("  SPHINCS+ public key:  %zu bytes\n", sphincs_pk.len);
    printf("  SPHINCS+ private key: %zu bytes\n", sphincs_sk.len);

    if (test_sphincs_sign_verify(sphincs_pk.data, sphincs_pk.len, sphincs_sk.data, sphincs_sk.len) != 0) {
        fprintf(stderr, "SPHINCS+ sign/verify test failed\n");
        json_decref(root);
        return 1;
    }

    printf("\n✅ All validations passed!\n");
    printf("   Keychain is valid and ready for use.\n");

    /* Cleanup */
    free(falcon_pk.data);
    free(falcon_sk.data);
    free(sphincs_pk.data);
    free(sphincs_sk.data);
    json_decref(root);

    return 0;
}
