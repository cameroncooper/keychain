#include "../../../docs/sep-driver/sep-bio.h"
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("%zu %zu %zu %zu %zu %zu %lu %lu %lu %lu %lu %lu %lu %zu %zu %zu\n",
        sizeof(struct sep_bio_info), sizeof(struct sep_bio_key_create),
        sizeof(struct sep_bio_key_sign_start), sizeof(struct sep_bio_key_sign_poll),
        sizeof(struct sep_bio_key_decrypt_start), sizeof(struct sep_bio_key_decrypt_poll),
        (unsigned long)SEP_BIO_GET_INFO, (unsigned long)SEP_BIO_KEY_CREATE,
        (unsigned long)SEP_BIO_KEY_SIGN_START, (unsigned long)SEP_BIO_KEY_SIGN_POLL,
        (unsigned long)SEP_BIO_CANCEL, (unsigned long)SEP_BIO_KEY_DECRYPT_START,
        (unsigned long)SEP_BIO_KEY_DECRYPT_POLL,
        offsetof(struct sep_bio_key_create, public), offsetof(struct sep_bio_key_sign_start, digest),
        offsetof(struct sep_bio_key_decrypt_poll, plain_ptr));
    return 0;
}
