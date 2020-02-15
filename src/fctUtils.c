/*******************************************************************************
*   Factom Wallet
*   (c) 2018 The Factoid Authority
*            ledger@factoid.org
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

/**
 * @brief Utilities for Factom Hardware Wallet logic
 * @file fctUtils.h
 * @author MyFactomWallet Development Team 
 * @version 1.0
 * @date 25th of October 2017
 */


#include <stdbool.h>
#include "fctUtils.h"
#include "btchip_base58.h"
#include "btchip_apdu_constants.h"


const uint32_t MAX_TXN_SIZE = 10275;
const uint32_t fct_address_length = 52;

void getFctAddressFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *out,
                          cx_sha3_t *sha3Context) 
{
    uint8_t hashAddress[32];
    cx_keccak_init(sha3Context, 256);
    cx_hash((cx_hash_t *)sha3Context, CX_LAST, publicKey->W + 1, 64,
            hashAddress, sizeof(hashAddress));
    os_memmove(out, hashAddress + 12, 20);
}


static const uint8_t const HEXDIGITS[] = "0123456789abcdef";

static const uint8_t const MASK[] = {0x80, 0x40, 0x20, 0x10,
                                     0x08, 0x04, 0x02, 0x01};

char convertDigit(uint8_t *address, uint8_t index, uint8_t *hash) {
    unsigned char digit = address[index / 2];
    if ((index % 2) == 0) {
        digit = (digit >> 4) & 0x0f;
    } else {
        digit = digit & 0x0f;
    }
    if (digit < 10) {
        return HEXDIGITS[digit];
    } else {
        unsigned char data = hash[index / 8];
        if (((data & MASK[index % 8]) != 0) && (digit > 9)) {
            return HEXDIGITS[digit] /*- 'a' + 'A'*/;
        } else {
            return HEXDIGITS[digit];
        }
     }
}
void sha256d(uint8_t *data, uint32_t len, uint8_t *out, uint32_t outlen)
{
    uint8_t in[32];
    cx_hash_sha256(data,len,in,sizeof(in));
    cx_hash_sha256(in,32,out,outlen);
}

void getCompressedPublicKey(
	cx_ecfp_public_key_t *publicKey,
        uint8_t *out, uint8_t len)
{
    if ( len < 32 )
    {
        THROW(0x60ED);
    }
    if ( publicKey->curve == CX_CURVE_256K1 )
    {
        os_memmove(out + 1, publicKey->W + 1, 32);
    }
    else if (publicKey->curve == CX_CURVE_Ed25519 && publicKey->W[0] != 0xED)
    {
        for (uint8_t i = 0; i < 32; i++)
        {
            out[i] = publicKey->W[64 - i];
        }
        if ((publicKey->W[32] & 1) != 0)
        {
            out[31] |= 0x80;
        }
    }
    else
    {
        //LEDGER-REVIEW: defensive else throw
        THROW(BTCHIP_SW_INCORRECT_DATA);
    }
}

void getCompressedPublicKeyWithRCD(cx_ecfp_public_key_t *publicKey,
                              uint8_t *out, uint8_t len)
{
    if ( len < 33 )
    {
        THROW(0x60ED);
    }

    out[0] = 0x01;//RCD key type 1

    if ( publicKey->curve == CX_CURVE_256K1 )
    {
        os_memmove(out + 1, publicKey->W + 1, 32);
    }
    else if (publicKey->curve == CX_CURVE_Ed25519 && publicKey->W[0] != 0xED) 
    {
        int offset = 1;

        for (uint8_t i = 0; i < 32; i++) 
        {
            out[i + offset] = publicKey->W[64 - i];
        }
        if ((publicKey->W[32] & 1) != 0) 
        {
            out[31 + offset] |= 0x80;
        }
    }
    else
    {
        //LEDGER-REVIEW: defensive else throw
        THROW(BTCHIP_SW_INCORRECT_DATA);
    }
}


//the key prefix code is byte swapped
const uint16_t g_factom_key_prefix[] = { 0xb15f, 0x7864, 0x2a59, 0xb65d };


void getFctAddressStringFromRCDHash(uint8_t *rcdhash,uint8_t *out, keyType_t keytype)
{
    uint8_t address[38];

    if ( keytype < 0 || keytype > 3 ) 
    {
        THROW(BTCHIP_SW_INVALID_OFFSET);
    }

    *(uint16_t*)address = g_factom_key_prefix[keytype];

    os_memmove(address+2, rcdhash, 32);

    uint8_t checksum[32];
    sha256d(address, 34, checksum,sizeof(checksum));
    os_memmove(address+34, checksum, 4);

    btchip_encode_base58(address, 38, out, 52);
}

void getFctAddressStringFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *out,
                                keyType_t keytype) {
    uint8_t address[41];//FCT: prefix(2 bytes) + RCD_hash(32 bytes) + checksum(4 bytes)
                        // EC: prefix(2 bytes) + Pub Key (32 bytes) + checksum(4 bytes)
                        // ID: prefix(5 bytes) + Pub Key (32 bytes) + checksum(4 bytes)
    uint8_t checksum[32];

    uint8_t key_offset = (keytype == PUBLIC_OFFSET_ID) ? 5: 2;
    
    //https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md
    
    //1) Concatenate 0x5fb1 and the RCD Hash bytewise
    if ( keytype == PUBLIC_OFFSET_FCT )
    {
        *(uint16_t*)address = g_factom_key_prefix[keytype];
        sha256d(publicKey->W, publicKey->W_len, &address[2],32);
    }
    else
    {
        if (keytype == PUBLIC_OFFSET_ID) 
        {
            const uint8_t factom_id_prefix[] = { 0x03, 0x45, 0xef, 0x9d, 0xe0 };
            os_memmove(address, factom_id_prefix, key_offset);
        }
        else //LEDGER-REVIEW: check that keytype is not going out of bound when used as an index in g_factom_key_prefix
        {
            //ensure keytype doesn't go out of bounds for g_factom_key_prefix
            if ( keytype < 0 || keytype > 3 )
            {
                THROW(BTCHIP_SW_INVALID_OFFSET);
            }
            *(uint16_t*)address = g_factom_key_prefix[keytype];
        }

        os_memmove(&address[key_offset], publicKey->W, publicKey->W_len);
    }
    

    //2) Take the SHA256d of the above data. Append the first 4 bytes of 
    //   this SHA256d to the end of the above value bytewise
    sha256d(address, 32 + key_offset, checksum, sizeof(checksum));

    os_memmove(address + 32 + key_offset, checksum, 4);

    //3) Convert the above value from base 256 to base 58. Use standard 
    //   Bitcoin base58 encoding to display the number
    btchip_encode_base58(address, 32 + 4 + key_offset, out, 50 + key_offset);
}

bool adjustDecimals(char *src, uint32_t srcLength, char *target,
                    uint32_t targetLength, uint8_t decimals)
{
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;
    if ((srcLength == 1) && (*src == '0'))
    {
        if (targetLength < 2)
        {
            return false;
        }
        target[0] = '0';
        target[1] = '\0';
        return true;
    }
    if (srcLength <= decimals)
    {
        uint32_t delta = decimals - srcLength;
        if (targetLength < srcLength + 1 + 2 + delta)
        {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (uint32_t i = 0; i < delta; i++)
        {
            target[offset++] = '0';
        }
        startOffset = offset;
        for (uint32_t i = 0; i < srcLength; i++)
        {
            target[offset++] = src[i];
        }
        target[offset] = '\0';
    }
    else
    {
        uint32_t sourceOffset = 0;
        uint32_t delta = srcLength - decimals;
        if (targetLength < srcLength + 1 + 1)
        {
            return false;
        }
        while (offset < delta)
        {
            target[offset++] = src[sourceOffset++];
        }
        if (decimals != 0)
        {
            target[offset++] = '.';
        }
        startOffset = offset;
        while (sourceOffset < srcLength)
        {
            target[offset++] = src[sourceOffset++];
        }
        target[offset] = '\0';
    }
    for (uint32_t i = startOffset; i < offset; i++)
    {
        if (target[i] == '0')
        {
            if (lastZeroOffset == 0)
            {
                lastZeroOffset = i;
            }
        }
        else
        {
            lastZeroOffset = 0;
        }
    }
    if (lastZeroOffset != 0)
    {
        target[lastZeroOffset] = '\0';
        if (target[lastZeroOffset - 1] == '.')
        {
            target[lastZeroOffset - 1] = '\0';
        }
    }
    return true;
}

unsigned short fct_print_amount(uint64_t amount, int8_t *out,
                                uint32_t outlen)
{
    char tmp[20];
    char tmp2[25];
    uint32_t numDigits = 0, i;
    uint64_t base = 1;
    while (base <= amount)
    {
        base *= 10;
        numDigits++;
    }
    if (numDigits > sizeof(tmp) - 1)
    {
        THROW(EXCEPTION);
    }
    base /= 10;
    for (i = 0; i < numDigits; i++)
    {
        tmp[i] = '0' + ((amount / base) % 10);
        base /= 10;
    }
    tmp[i] = '\0';

    os_memmove(tmp2, "FCT ", 4); //"ғ"
    adjustDecimals(tmp, i, tmp2 + 4, 25, 8);
    if (strlen(tmp2) < outlen - 1)
    {
        strcpy(out, tmp2);
    }
    else
    {
        out[0] = '\0';
    }
    return strlen(out);
}


/*
 * This is the algorithm to create the stream:
 * Convert the value to big endian.
 * Count the number of bits between the LSB and the most significant 1 bit, inclusive.
 * Divide this number by 7 and take the cieling of the remainder.
 * This is the byte count M.
 * Create a byte sequence with M bytes.
 * Take the least significant 7 bits of the number and place them in the Mth byte.
 * Set the highest bit of the Mth byte to zero.
 * Take the bits 13 through 7 and add them to the byte M-1.
 * Set the highest bit of byte M-1 to one.
 * Continue until all the M bytes have been filled with with data.
 *
 * 127 01111111
 * 128 10000001 00000000
 * 130 10000001 00000010
*/

uint64_t varint_decode(uint8_t *data, uint32_t maxlen, uint8_t *bytes)
{

    uint64_t ret = 0xFFFFFFFF;
    if ( !data || !bytes ) return ret;

    *bytes = 0;
    ret = 0;
    do
    {
        ret = ret << 7;
        ret += ((uint64_t)data[*bytes]) & 0x7F;
    } while ( data[(*bytes)++] & 0x80 && *bytes < maxlen);

    return ret;
}
