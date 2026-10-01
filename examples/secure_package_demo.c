/**
 * @file secure_package_demo.c
 * @brief Standalone C Example: Packaging & Transmitting Encrypted Packages (.cvpkg).
 *
 * Demonstrates:
 * 1. Packaging an arbitrary file into an encrypted container (.cvpkg).
 * 2. Examining the package manifest without decrypting payload.
 * 3. Simulating network transmission over an insecure communication channel.
 * 4. Recipient extraction, seal validation, and transparent decryption.
 */

#include "vault.h"
#include "package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    printf("====================================================================\n");
    printf("   CryptoVault Academic Example: Secure Package Container (.cvpkg)  \n");
    printf("====================================================================\n\n");

    const char *orig_file = "/tmp/financial_ledger_2026.csv";
    const char *pkg_file  = "/tmp/financial_ledger.cvpkg";
    const char *dest_file = "/tmp/extracted_financial_ledger.csv";

    /* Step 1: Create a sample file */
    printf("[Sender] Creating sample financial ledger '%s'...\n", orig_file);
    FILE *f = fopen(orig_file, "w");
    if (!f) return 1;
    fprintf(f, "AccountID,TransactionDate,AmountUSD,Category\n");
    for (int i = 1; i <= 250; i++) {
        fprintf(f, "ACC-%06d,2026-09-%02d,%d.50,Grant_Disbursement\n", i, (i % 28) + 1, i * 45);
    }
    fclose(f);
    printf("[Sender] Ledger created.\n\n");

    /* Step 2: Recipient generates an X25519 identity keypair */
    printf("[Recipient] Generating X25519 identity keypair...\n");
    cv_ecdh_keypair_t recipient;
    if (cv_ecdh_keygen(&recipient) != 0) return 1;
    printf("[Recipient] Public key generated.\n\n");

    /* Step 3: Sender packages the file for the recipient */
    printf("[Sender] Creating self-contained container '%s' for recipient's public key...\n", pkg_file);
    if (cv_package_create_hybrid(orig_file, pkg_file, recipient.pub) != CV_PKG_SUCCESS) {
        fprintf(stderr, "Packaging failed\n");
        return 1;
    }
    printf("[Sender] Package successfully created.\n\n");

    /* Step 4: Network Gateway / Third Party Inspects Container Manifest */
    printf("[Network Node] Inspecting container manifest without decrypting payload...\n");
    cv_pkg_manifest_t manifest;
    if (cv_package_inspect(pkg_file, &manifest) != CV_PKG_SUCCESS) {
        fprintf(stderr, "Inspection failed\n");
        return 1;
    }

    printf("  Container Manifest Details:\n");
    printf("  - Embedded Original Name: %s\n", manifest.orig_filename);
    printf("  - Delivery Mode:          %s\n", (manifest.mode == CV_PKG_MODE_HYBRID) ? "Asymmetric Hybrid (HPKE)" : "Password Protected");
    printf("  - Creation Timestamp:     %lu (UTC)\n", (unsigned long)manifest.created_timestamp);
    printf("  - Encrypted Payload Size: %lu bytes\n", (unsigned long)manifest.payload_size);
    printf("  - Package Seal Digest:    ");
    for (int i = 0; i < 8; i++) printf("%02X", manifest.package_seal[i]);
    printf("... (32 bytes total)\n\n");

    /* Step 5: Recipient receives package and extracts plaintext */
    printf("[Recipient] Received '%s'. Unpacking with private key...\n", pkg_file);
    if (cv_package_extract_hybrid(pkg_file, dest_file, recipient.priv) != CV_PKG_SUCCESS) {
        fprintf(stderr, "Recipient extraction failed\n");
        return 1;
    }
    printf("[Recipient] Package extracted and verified! Output: '%s'\n\n", dest_file);

    /* Step 6: Verify file integrity */
    uint8_t h_orig[32], h_dest[32];
    cv_hash_file(orig_file, h_orig);
    cv_hash_file(dest_file, h_dest);

    if (cv_ct_memcmp(h_orig, h_dest, 32) == 0) {
        printf("[Audit] Integrity check: Bit-for-bit exact match! 100%% Authenticated.\n");
    } else {
        fprintf(stderr, "[Audit] ERROR: Hash mismatch!\n");
        return 1;
    }

    /* Step 7: Simulate Active In-Flight Network Tampering */
    printf("[Adversary] Simulating man-in-the-middle bit-flip attack on package seal...\n");
    if (cv_package_create_hybrid(orig_file, pkg_file, recipient.pub) == CV_PKG_SUCCESS) {
        FILE *fp = fopen(pkg_file, "r+b");
        if (fp) {
            fseek(fp, 250, SEEK_SET);
            int byte = fgetc(fp);
            fseek(fp, 250, SEEK_SET);
            fputc(byte ^ 0x01, fp);
            fclose(fp);
        }

        const char *tamper_out = "/tmp/tampered_extracted.csv";
        int tamper_rc = cv_package_extract_hybrid(pkg_file, tamper_out, recipient.priv);
        if (tamper_rc != CV_PKG_SUCCESS) {
            printf("[Recipient] Adversarial tampering DETECTED! Package rejected with code %d.\n", tamper_rc);
            printf("[Recipient] Zero unauthenticated bytes written to disk.\n");
        } else {
            fprintf(stderr, "[Adversary] Security failure: tampered package accepted!\n");
            unlink(tamper_out);
            return 1;
        }
        unlink(tamper_out);
    }

    /* Cleanup */
    unlink(orig_file);
    unlink(pkg_file);
    unlink(dest_file);
    cv_ecdh_keypair_clear(&recipient);

    printf("\nSecure packaging demonstration completed successfully.\n");
    return 0;
}
