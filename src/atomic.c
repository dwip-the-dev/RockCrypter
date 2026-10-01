/**
 * @file atomic.c
 * @brief Crash-Safe Writes, Atomic File Replacement & Huge-File Random-Access.
 *
 * Implements ACID-like atomic replacement using ephemeral staging files and
 * POSIX rename(2), alongside 64-bit random-access chunk retrieval.
 */

#define _POSIX_C_SOURCE 200809L

#include "atomic.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int cv_atomic_begin(cv_atomic_file_t *af, const char *destination) {
    if (!af || !destination || strlen(destination) >= 500) {
        return CV_ATOMIC_ERR_PARAM;
    }

    cv_memzero(af, sizeof(*af));
    strncpy(af->target_path, destination, sizeof(af->target_path) - 1);

    /* Generate staging path in same directory to guarantee atomic rename on same mount */
    snprintf(af->temp_path, sizeof(af->temp_path), "%s.tmp_cv_%d_%u",
             destination, (int)getpid(), (unsigned int)rand());

    af->file_handle = fopen(af->temp_path, "wb");
    if (!af->file_handle) {
        return CV_ATOMIC_ERR_IO;
    }

    af->is_open = 1;
    return CV_ATOMIC_SUCCESS;
}

int cv_atomic_write(cv_atomic_file_t *af, const void *buf, size_t len) {
    if (!af || !af->is_open || !af->file_handle || (!buf && len > 0)) {
        return CV_ATOMIC_ERR_PARAM;
    }

    if (len == 0) return CV_ATOMIC_SUCCESS;

    size_t written = fwrite(buf, 1, len, af->file_handle);
    if (written != len) {
        return CV_ATOMIC_ERR_IO;
    }

    return CV_ATOMIC_SUCCESS;
}

int cv_atomic_commit(cv_atomic_file_t *af) {
    if (!af || !af->is_open || !af->file_handle) {
        return CV_ATOMIC_ERR_PARAM;
    }

    /* 1. Flush stdio buffer to OS */
    if (fflush(af->file_handle) != 0) {
        cv_atomic_abort(af);
        return CV_ATOMIC_ERR_IO;
    }

    /* 2. Flush OS cache to physical disk controller (fsync) */
    int fd = fileno(af->file_handle);
    if (fd >= 0) {
        if (fsync(fd) != 0) {
            cv_atomic_abort(af);
            return CV_ATOMIC_ERR_SYNC;
        }
    }

    /* 3. Close stream */
    fclose(af->file_handle);
    af->file_handle = NULL;
    af->is_open = 0;

    /* 4. Atomic directory entry swap via POSIX rename */
    if (rename(af->temp_path, af->target_path) != 0) {
        unlink(af->temp_path);
        return CV_ATOMIC_ERR_RENAME;
    }

    return CV_ATOMIC_SUCCESS;
}

void cv_atomic_abort(cv_atomic_file_t *af) {
    if (af) {
        if (af->file_handle) {
            fclose(af->file_handle);
            af->file_handle = NULL;
        }
        if (af->temp_path[0] != '\0') {
            unlink(af->temp_path);
            af->temp_path[0] = '\0';
        }
        af->is_open = 0;
    }
}

uint64_t cv_calc_chunk_offset(uint64_t chunk_index,
                              size_t header_size_bytes,
                              size_t chunk_size_bytes,
                              size_t tag_size_bytes) {
    uint64_t stride = (uint64_t)chunk_size_bytes + (uint64_t)tag_size_bytes;
    return (uint64_t)header_size_bytes + (chunk_index * stride);
}

int cv_read_chunk_random_access(const char *file_path,
                                uint64_t chunk_offset,
                                uint8_t *chunk_buf,
                                size_t chunk_size,
                                uint8_t tag_out[32]) {
    if (!file_path || !chunk_buf || chunk_size == 0) {
        return CV_ATOMIC_ERR_PARAM;
    }

    FILE *f = fopen(file_path, "rb");
    if (!f) return CV_ATOMIC_ERR_IO;

    /* 64-bit seek to chunk offset */
    if (fseeko(f, (off_t)chunk_offset, SEEK_SET) != 0) {
        fclose(f);
        return CV_ATOMIC_ERR_SEEK;
    }

    /* Read chunk payload */
    size_t r_chunk = fread(chunk_buf, 1, chunk_size, f);
    if (r_chunk != chunk_size) {
        fclose(f);
        return CV_ATOMIC_ERR_IO;
    }

    /* Read chunk authentication tag if requested */
    if (tag_out) {
        size_t r_tag = fread(tag_out, 1, 32, f);
        if (r_tag != 32) {
            fclose(f);
            return CV_ATOMIC_ERR_IO;
        }
    }

    fclose(f);
    return CV_ATOMIC_SUCCESS;
}

int cv_atomic_self_test(void) {
    const char *orig_target = "/tmp/cv_atomic_test_file.dat";
    unlink(orig_target);

    /* 1. Test Atomic Commit */
    cv_atomic_file_t af;
    if (cv_atomic_begin(&af, orig_target) != CV_ATOMIC_SUCCESS) {
        return CV_ATOMIC_ERR_SELFTEST;
    }

    const char *data1 = "Original committed contents 2026";
    if (cv_atomic_write(&af, data1, strlen(data1)) != CV_ATOMIC_SUCCESS) {
        cv_atomic_abort(&af);
        return CV_ATOMIC_ERR_SELFTEST;
    }

    if (cv_atomic_commit(&af) != CV_ATOMIC_SUCCESS) {
        return CV_ATOMIC_ERR_SELFTEST;
    }

    /* Verify target exists and matches data1 */
    FILE *chk = fopen(orig_target, "r");
    if (!chk) return CV_ATOMIC_ERR_SELFTEST;
    char readback[64] = {0};
    size_t r_len = fread(readback, 1, sizeof(readback) - 1, chk);
    fclose(chk);
    if (r_len != strlen(data1) || strcmp(readback, data1) != 0) {
        unlink(orig_target);
        return CV_ATOMIC_ERR_SELFTEST;
    }

    /* 2. Test Atomic Abort (Original file must remain untouched) */
    if (cv_atomic_begin(&af, orig_target) != CV_ATOMIC_SUCCESS) {
        unlink(orig_target);
        return CV_ATOMIC_ERR_SELFTEST;
    }

    const char *corrupted_data = "THIS DATA MUST NEVER APPEAR IN THE COMMITTED FILE!";
    cv_atomic_write(&af, corrupted_data, strlen(corrupted_data));
    cv_atomic_abort(&af);

    /* Original target must still contain data1 */
    chk = fopen(orig_target, "r");
    if (!chk) return CV_ATOMIC_ERR_SELFTEST;
    memset(readback, 0, sizeof(readback));
    r_len = fread(readback, 1, sizeof(readback) - 1, chk);
    fclose(chk);
    if (r_len != strlen(data1) || strcmp(readback, data1) != 0) {
        unlink(orig_target);
        return CV_ATOMIC_ERR_SELFTEST;
    }

    /* 3. Test 64-bit Chunk Offset Math */
    uint64_t off0 = cv_calc_chunk_offset(0, 128, 1048576, 32);
    uint64_t off1 = cv_calc_chunk_offset(1, 128, 1048576, 32);
    uint64_t off1000 = cv_calc_chunk_offset(1000, 128, 1048576, 32);

    if (off0 != 128) return CV_ATOMIC_ERR_SELFTEST;
    if (off1 != 128 + 1048576 + 32) return CV_ATOMIC_ERR_SELFTEST;
    if (off1000 != 128 + 1000ULL * (1048576 + 32)) return CV_ATOMIC_ERR_SELFTEST;

    unlink(orig_target);
    return CV_ATOMIC_SUCCESS;
}
