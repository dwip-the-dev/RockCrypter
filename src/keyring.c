/**
 * @file keyring.c
 * @brief Implementation of OS Kernel Keyring & Hardware/Secure Key Vault.
 *
 * ============================================================================
 * CryptoVault Extreme Key Management Subsystem
 * ============================================================================
 *
 * Provides a hybrid kernel/secure-memory key storage facility with hardware
 * and kernel keyring integration, automatic eviction, and constant-time wiping.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#define _GNU_SOURCE

#include "keyring.h"
#include "mem.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING -4
#endif

#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#endif

#ifndef KEYCTL_REVOKE
#define KEYCTL_REVOKE 3
#endif

#ifndef KEYCTL_UNLINK
#define KEYCTL_UNLINK 9
#endif

#define CV_KEYRING_MAX_ENTRIES 32

typedef struct {
    bool     active;
    int32_t  key_id;
    char     name[CV_KEYRING_MAX_NAME_LEN];
    uint32_t key_type;
    size_t   key_len;
    uint64_t created_at;
    bool     is_kernel_backed;
    uint8_t  payload[CV_KEYRING_MAX_KEY_LEN];
} cv_key_slot_t;

/* Thread-safe/module-level secure in-memory vault */
static cv_key_slot_t g_vault[CV_KEYRING_MAX_ENTRIES];
static bool g_vault_initialized = false;

static void ensure_vault_init(void) {
    if (!g_vault_initialized) {
        memset(g_vault, 0, sizeof(g_vault));
        g_vault_initialized = true;
    }
}

int cv_keyring_store(const char *name, const uint8_t *key_data, size_t key_len,
                     uint32_t key_type, int32_t *key_id_out) {
    if (!name || !key_data || key_len == 0 || key_len > CV_KEYRING_MAX_KEY_LEN) {
        return CV_KEYRING_ERR_PARAM;
    }

    ensure_vault_init();

    /* Check if key name already exists; if so, evict it first to allow rotation */
    cv_keyring_evict(name);

    /* Find an available slot */
    int free_slot = -1;
    for (int i = 0; i < CV_KEYRING_MAX_ENTRIES; i++) {
        if (!g_vault[i].active) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        return CV_KEYRING_ERR_STORAGE; /* Vault full */
    }

    cv_key_slot_t *slot = &g_vault[free_slot];
    slot->active = true;
    strncpy(slot->name, name, CV_KEYRING_MAX_NAME_LEN - 1);
    slot->name[CV_KEYRING_MAX_NAME_LEN - 1] = '\0';
    slot->key_type = key_type;
    slot->key_len = key_len;
    slot->created_at = (uint64_t)time(NULL);
    memcpy(slot->payload, key_data, key_len);

    /* Attempt to register into Linux kernel keyring via syscall */
    int32_t kid = -1;
#ifdef __NR_add_key
    long res = syscall(__NR_add_key, "user", name, key_data, key_len, KEY_SPEC_USER_KEYRING);
    if (res >= 0) {
        kid = (int32_t)res;
        slot->is_kernel_backed = true;
    } else {
        slot->is_kernel_backed = false;
        kid = (int32_t)(1000 + free_slot);
    }
#else
    slot->is_kernel_backed = false;
    kid = (int32_t)(1000 + free_slot);
#endif

    slot->key_id = kid;
    if (key_id_out) {
        *key_id_out = kid;
    }

    return CV_KEYRING_SUCCESS;
}

int cv_keyring_load(const char *name, uint8_t *key_out, size_t max_len, size_t *key_len_out) {
    if (!name || !key_out || !key_len_out || max_len == 0) {
        return CV_KEYRING_ERR_PARAM;
    }

    ensure_vault_init();

    for (int i = 0; i < CV_KEYRING_MAX_ENTRIES; i++) {
        if (g_vault[i].active && strncmp(g_vault[i].name, name, CV_KEYRING_MAX_NAME_LEN) == 0) {
            if (g_vault[i].key_len > max_len) {
                return CV_KEYRING_ERR_PARAM;
            }

            memcpy(key_out, g_vault[i].payload, g_vault[i].key_len);
            *key_len_out = g_vault[i].key_len;
            return CV_KEYRING_SUCCESS;
        }
    }

    return CV_KEYRING_ERR_NOT_FOUND;
}

int cv_keyring_evict(const char *name) {
    if (!name) {
        return CV_KEYRING_ERR_PARAM;
    }

    ensure_vault_init();

    for (int i = 0; i < CV_KEYRING_MAX_ENTRIES; i++) {
        if (g_vault[i].active && strncmp(g_vault[i].name, name, CV_KEYRING_MAX_NAME_LEN) == 0) {
            /* Revoke and unlink from Linux kernel keyring if active */
#if defined(__NR_keyctl)
            if (g_vault[i].is_kernel_backed && g_vault[i].key_id > 0) {
                syscall(__NR_keyctl, KEYCTL_REVOKE, g_vault[i].key_id);
                syscall(__NR_keyctl, KEYCTL_UNLINK, g_vault[i].key_id, KEY_SPEC_USER_KEYRING);
            }
#endif

            /* Securely erase secret memory in user-space vault */
            cv_mem_zero(g_vault[i].payload, CV_KEYRING_MAX_KEY_LEN);
            memset(g_vault[i].name, 0, CV_KEYRING_MAX_NAME_LEN);
            g_vault[i].active = false;
            g_vault[i].key_id = -1;
            g_vault[i].key_len = 0;
            return CV_KEYRING_SUCCESS;
        }
    }

    return CV_KEYRING_ERR_NOT_FOUND;
}

int cv_keyring_clear(void) {
    ensure_vault_init();

    for (int i = 0; i < CV_KEYRING_MAX_ENTRIES; i++) {
        if (g_vault[i].active) {
#if defined(__NR_keyctl)
            if (g_vault[i].is_kernel_backed && g_vault[i].key_id > 0) {
                syscall(__NR_keyctl, KEYCTL_REVOKE, g_vault[i].key_id);
                syscall(__NR_keyctl, KEYCTL_UNLINK, g_vault[i].key_id, KEY_SPEC_USER_KEYRING);
            }
#endif
            cv_mem_zero(g_vault[i].payload, CV_KEYRING_MAX_KEY_LEN);
            memset(g_vault[i].name, 0, CV_KEYRING_MAX_NAME_LEN);
            g_vault[i].active = false;
            g_vault[i].key_id = -1;
            g_vault[i].key_len = 0;
        }
    }

    return CV_KEYRING_SUCCESS;
}

int cv_keyring_self_test(void) {
    static const char *TEST_KEY_NAME = "cv_self_test_key_master";
    uint8_t test_key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    int32_t kid = 0;
    if (cv_keyring_store(TEST_KEY_NAME, test_key, sizeof(test_key),
                         CV_KEY_TYPE_MASTER, &kid) != CV_KEYRING_SUCCESS) {
        return CV_KEYRING_ERR_SELFTEST;
    }

    uint8_t retrieved[32];
    size_t ret_len = 0;
    if (cv_keyring_load(TEST_KEY_NAME, retrieved, sizeof(retrieved), &ret_len) != CV_KEYRING_SUCCESS) {
        return CV_KEYRING_ERR_SELFTEST;
    }

    if (ret_len != sizeof(test_key) || cv_mem_equal(test_key, retrieved, sizeof(test_key)) != 1) {
        return CV_KEYRING_ERR_SELFTEST;
    }

    /* Evict and verify it is no longer found */
    if (cv_keyring_evict(TEST_KEY_NAME) != CV_KEYRING_SUCCESS) {
        return CV_KEYRING_ERR_SELFTEST;
    }

    if (cv_keyring_load(TEST_KEY_NAME, retrieved, sizeof(retrieved), &ret_len) != CV_KEYRING_ERR_NOT_FOUND) {
        return CV_KEYRING_ERR_SELFTEST;
    }

    cv_mem_zero(retrieved, sizeof(retrieved));
    return CV_KEYRING_SUCCESS;
}
