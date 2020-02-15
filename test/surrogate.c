#define USB_SEGMENT_SIZE  128
#define IO_HID_EP_LENGTH 128

#include "os.h"
#include "cx.h"
#include "btchip_secure_value.h"

#include <openssl/sha.h>
try_context_t *G_try_last_open_context;
void os_longjmp(unsigned int exception)
{
    exit(0);
}

void btchip_commit_operation_mode(secu8 operationMode)
{

}

unsigned short btchip_apdu_setup(void)
{
    return 0;
}

unsigned short btchip_apdu_verify_pin(void)
{
    return 0;
}

unsigned short btchip_apdu_get_operation_mode(void)
{
    return 0;
}

unsigned short btchip_apdu_set_operation_mode(void)
{
    return 0;
}
unsigned short btchip_apdu_get_wallet_public_key(void)
{
    return 0;
}

unsigned short btchip_apdu_get_trusted_input(void)
{
    return 0;
}

unsigned short btchip_apdu_hash_input_start(void)
{
    return 0;
}

unsigned short btchip_apdu_hash_input_finalize(void)
{
    return 0;
}

unsigned short btchip_apdu_hash_sign(void)
{
    return 0;
}

unsigned short btchip_apdu_hash_input_finalize_full(void)
{
    return 0;
}

unsigned short btchip_apdu_import_private_key(void)
{
    return 0;
}

unsigned short btchip_apdu_get_public_key(void)
{
    return 0;
}

unsigned short btchip_apdu_derive_bip32_key(void)
{
    return 0;
}

unsigned short btchip_apdu_signverify_immediate(void)
{
    return 0;
}

unsigned short btchip_apdu_sign_message(void)
{
    return 0;
}


unsigned short btchip_apdu_get_random(void)
{
    return 0;
}

unsigned short btchip_apdu_get_firmware_version(void)
{
    return 0;
}

unsigned short btchip_apdu_set_alternate_coin_version(void)
{
    return 0;
}

unsigned short btchip_apdu_get_coin_version(void)
{
    return 0;
}


void os_memmove(void *dst, const void WIDE *src,
                          unsigned int length)
{
    memmove(dst,src,length);
}
int cx_hash(cx_hash_t *hash PLENGTH(scc__cx_scc_struct_size_hash__hash),
                    int mode, const unsigned char WIDE *in PLENGTH(len),
                    unsigned int len, unsigned char *out PLENGTH(out_len),
                    unsigned int out_len)

//int cx_hash(cx_hash_t *hash PLENGTH(scc__cx_hash_ctx_size__hash),
//                    int mode, unsigned char WIDE *in PLENGTH(len),
//                    unsigned int len,
//                    unsigned char *out PLENGTH(scc__cx_hash_size__hash))
{

}
SYSCALL int cx_hash_sha256(const unsigned char WIDE *in PLENGTH(len),
                           unsigned int len,
                           unsigned char *out PLENGTH(out_len),
                           unsigned int out_len)


{

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, in, len);
        SHA256_Final(out, &sha256);
//        int i = 0;
//        for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
//        {
//            sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
//        }
//        outputBuffer[64] = 0;
//    }
  unsigned int ret = 0;
//  unsigned int parameters [2+3];
//  parameters[0] = (unsigned int)SYSCALL_cx_hash_sha256_ID_IN;
//  parameters[1] = (unsigned int)G_try_last_open_context->jmp_buf;
//  parameters[2] = (unsigned int)in;
//  parameters[3] = (unsigned int)len;
//  parameters[4] = (unsigned int)out;

//                              asm volatile("mov r0, %0"::"r"(parameters));
//                              asm volatile("svc #1");
//                              asm volatile("mov %0, r0":"=r"(ret));
//                                if (parameters[0] != SYSCALL_cx_hash_sha256_ID_OUT)
//  {
//    THROW(EXCEPTION_SECURITY);
//  }
  return (int)ret;
}

int cx_keccak_init(cx_sha3_t *hash PLENGTH(sizeof(cx_sha3_t)),
                           unsigned int size)

{
  unsigned int ret = 0;
//  unsigned int parameters [2+2];
//  parameters[0] = (unsigned int)SYSCALL_cx_keccak_init_ID_IN;
//  parameters[1] = (unsigned int)G_try_last_open_context->jmp_buf;
//  parameters[2] = (unsigned int)hash;
//  parameters[3] = (unsigned int)size;

//                              asm volatile("mov r0, %0"::"r"(parameters));
//                              asm volatile("svc #1");
//                              asm volatile("mov %0, r0":"=r"(ret));
//                                if (parameters[0] != SYSCALL_cx_keccak_init_ID_OUT)
//  {
//    THROW(EXCEPTION_SECURITY);
//  }
  return (int)ret;
}
