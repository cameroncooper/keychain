/* Constants and layout assertions are generated from the pinned canonical UAPI,
 * not a second hand-maintained ioctl-number table. */
#include <linux/apple-sep.h>
#include <stddef.h>
#include <stdio.h>
#define CONSTANT(name, value) printf("const " #name ": u64 = %llu;\n", (unsigned long long)(value))
#define SIZE(rust, c) printf("const _: () = assert!(size_of::<" #rust ">() == %zu);\n", sizeof(struct c))
#define OFFSET(rust, c, field) printf("const _: () = assert!(std::mem::offset_of!(" #rust ", " #field ") == %zu);\n", offsetof(struct c, field))
int main(void) {
    CONSTANT(GET_INFO, SEP_KEY_INFO);
    CONSTANT(CREATE, SEP_KEY_CREATE);
    CONSTANT(SIGN, SEP_KEY_SIGN);
    CONSTANT(DECRYPT, SEP_KEY_DECRYPT);
    CONSTANT(CANCEL, SEP_KEY_CANCEL);
    CONSTANT(IFACE_VERSION, SEP_KEY_IFACE_VERSION);
    CONSTANT(CAP_SIGN, SEP_KEY_CAP_SIGN);
    CONSTANT(CAP_DECRYPT, SEP_KEY_CAP_DECRYPT);
    CONSTANT(CREATE_DECRYPT, SEP_KEY_CREATE_DECRYPT);
    CONSTANT(BLOB_CAPACITY, SEP_KEY_BLOB_MAX);
    CONSTANT(SIGNATURE_CAPACITY, SEP_KEY_SIGNATURE_MAX);
    SIZE(Info, sep_key_info); OFFSET(Info, sep_key_info, version); OFFSET(Info, sep_key_info, capabilities); OFFSET(Info, sep_key_info, reserved);
    SIZE(Create, sep_key_create); OFFSET(Create, sep_key_create, flags); OFFSET(Create, sep_key_create, blob_len); OFFSET(Create, sep_key_create, blob_ptr); OFFSET(Create, sep_key_create, public_key); OFFSET(Create, sep_key_create, reserved);
    SIZE(Sign, sep_key_sign); OFFSET(Sign, sep_key_sign, request_id); OFFSET(Sign, sep_key_sign, flags); OFFSET(Sign, sep_key_sign, timeout_ms); OFFSET(Sign, sep_key_sign, blob_len); OFFSET(Sign, sep_key_sign, sig_len); OFFSET(Sign, sep_key_sign, blob_ptr); OFFSET(Sign, sep_key_sign, digest); OFFSET(Sign, sep_key_sign, signature);
    SIZE(Decrypt, sep_key_decrypt); OFFSET(Decrypt, sep_key_decrypt, request_id); OFFSET(Decrypt, sep_key_decrypt, flags); OFFSET(Decrypt, sep_key_decrypt, timeout_ms); OFFSET(Decrypt, sep_key_decrypt, blob_len); OFFSET(Decrypt, sep_key_decrypt, sealed_len); OFFSET(Decrypt, sep_key_decrypt, blob_ptr); OFFSET(Decrypt, sep_key_decrypt, sealed_ptr); OFFSET(Decrypt, sep_key_decrypt, plain_len); OFFSET(Decrypt, sep_key_decrypt, reserved); OFFSET(Decrypt, sep_key_decrypt, plain_ptr);
    SIZE(Cancel, sep_key_cancel); OFFSET(Cancel, sep_key_cancel, request_id);
    return 0;
}
