/*
 * pqc_key_validator.c  (fixed version)
 * Full validation tool for your Falcon-512 + Dilithium3 keys
 */

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static char* extract_value(const char* json, const char* key_name) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\": \"", key_name);
    char* pos = strstr(json, search);
    if (!pos) return NULL;
    pos += strlen(search);
    char* end = strchr(pos, '"');
    if (!end) return NULL;
    size_t len = end - pos;
    char* value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, pos, len);
    value[len] = '\0';
    return value;
}

static char* extract_role_key(const char* json, int role_num, const char* key_suffix) {
    char role_search[64];
    snprintf(role_search, sizeof(role_search), "\"role\": %d,", role_num);
    char* role_pos = strstr(json, role_search);
    if (!role_pos) return NULL;

    char key_search[256];
    snprintf(key_search, sizeof(key_search), "\"%s\": \"", key_suffix);
    char* key_pos = strstr(role_pos, key_search);
    if (!key_pos) return NULL;

    key_pos += strlen(key_search);
    char* end = strchr(key_pos, '"');
    if (!end) return NULL;

    size_t len = end - key_pos;
    char* value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, key_pos, len);
    value[len] = '\0';
    return value;
}

static int hex_to_bytes(const char* hex, uint8_t** bytes_out, size_t* len_out) {
    if (!hex) return 0;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;
    *len_out = hex_len / 2;
    *bytes_out = malloc(*len_out);
    if (!*bytes_out) return 0;

    for (size_t i = 0; i < *len_out; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &(*bytes_out)[i]) != 1) {
            free(*bytes_out);
            return 0;
        }
    }
    return 1;
}

static int test_keypair(const char* algo_name, const char* pk_hex, const char* sk_hex,
                        const char* label) {
    printf("Testing %s (%s)...\n", label, algo_name);

    OQS_SIG* sig = OQS_SIG_new(algo_name);
    if (!sig) {
        printf("   FAILED: Could not create OQS_SIG for %s\n", algo_name);
        return 0;
    }

    uint8_t* pk = NULL; uint8_t* sk = NULL;
    size_t pk_len = 0, sk_len = 0;

    if (!hex_to_bytes(pk_hex, &pk, &pk_len) || !hex_to_bytes(sk_hex, &sk, &sk_len)) {
        printf("   FAILED: Hex decoding error\n");
        OQS_SIG_free(sig);
        free(pk); free(sk);
        return 0;
    }

    if (pk_len != sig->length_public_key || sk_len != sig->length_secret_key) {
        printf("   FAILED: Wrong key length (pk=%zu, sk=%zu, expected pk=%zu sk=%zu)\n",
               pk_len, sk_len, sig->length_public_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(pk); free(sk);
        return 0;
    }

    const uint8_t msg[] = "PQC role validation test message - 2026";
    size_t msg_len = sizeof(msg) - 1;

    uint8_t* signature = malloc(sig->length_signature);
    size_t sig_len = 0;

    OQS_STATUS rc = OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, sk);
    if (rc != OQS_SUCCESS) {
        printf("   FAILED: OQS_SIG_sign failed\n");
        OQS_SIG_free(sig);
        free(pk); free(sk); free(signature);
        return 0;
    }

    rc = OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pk);
    if (rc != OQS_SUCCESS) {
        printf("   FAILED: OQS_SIG_verify failed (signature invalid)\n");
        OQS_SIG_free(sig);
        free(pk); free(sk); free(signature);
        return 0;
    }

    printf("   PASS ✓\n");
    OQS_SIG_free(sig);
    free(pk); free(sk); free(signature);
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path-to-pasted-text.txt>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open JSON file");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    char* json = malloc(fsize + 1);
    if (!json) {
        fclose(f);
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    size_t bytes_read = fread(json, 1, fsize, f);
    fclose(f);

    if (bytes_read != (size_t)fsize) {
        fprintf(stderr, "Failed to read entire file (read %zu of %ld bytes)\n", bytes_read, fsize);
        free(json);
        return 1;
    }
    json[fsize] = '\0';

    printf("=== PQC Key Validation Tool (liboqs 0.12.x) ===\n\n");

    char* falcon_master_pk = extract_value(json, "falcon_512_master_pk");
    char* falcon_master_sk = extract_value(json, "falcon_512_master_sk");
    char* dilithium_master_pk = extract_value(json, "dilithium3_master_pk");
    char* dilithium_master_sk = extract_value(json, "dilithium3_master_sk");

    int all_pass = 1;

    if (!test_keypair("Falcon-512", falcon_master_pk, falcon_master_sk, "Master Falcon-512")) all_pass = 0;
    if (!test_keypair("Dilithium3", dilithium_master_pk, dilithium_master_sk, "Master Dilithium3")) all_pass = 0;

    free(falcon_master_pk); free(falcon_master_sk);
    free(dilithium_master_pk); free(dilithium_master_sk);

    int role_ids[] = {0, 1, 5, 6, 7};
    const char* role_names[] = {"Role 0", "Role 1", "Role 5", "Role 6", "Role 7"};

    for (int i = 0; i < 5; i++) {
        int role_num = role_ids[i];
        printf("\n--- %s ---\n", role_names[i]);

        char* falcon_pk = extract_role_key(json, role_num, "falcon_512_pk");
        char* falcon_sk = extract_role_key(json, role_num, "falcon_512_sk");
        char* dilithium_pk = extract_role_key(json, role_num, "dilithium3_pk");
        char* dilithium_sk = extract_role_key(json, role_num, "dilithium3_sk");

        if (!test_keypair("Falcon-512", falcon_pk, falcon_sk, "Falcon-512")) all_pass = 0;
        if (!test_keypair("Dilithium3", dilithium_pk, dilithium_sk, "Dilithium3")) all_pass = 0;

        free(falcon_pk); free(falcon_sk);
        free(dilithium_pk); free(dilithium_sk);
    }

    free(json);

    printf("\n=== FINAL RESULT ===\n");
    if (all_pass) {
        printf("ALL KEYS ARE CRYPTOGRAPHICALLY VALID ✓\n");
        printf("You can safely use these keys in your process-separation program.\n");
    } else {
        printf("SOME KEYS FAILED! Check the output above.\n");
    }

    return all_pass ? 0 : 1;
}
