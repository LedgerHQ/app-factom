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

#include "ecParse.h"
#define WANT_REDUNDANT_EC_ADDRESS 0

parserStatus_e parseEcTxV0(uint8_t *data, uint32_t length, txEcContent_t *context, uint32_t *offset)
{

    parserStatus_e result = USTREAM_FAULT_PARSE;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

//    context->timestamp_ms = &data[*offset];
    *offset += 6;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->entryhash = &data[*offset];
    *offset += EC_ENTRY_HASH_LENGTH;


    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->numec = data[*offset];
    ++(*offset);


#if WANT_REDUNDANT_EC_ADDRESS
    if ( *offset + EC_ENTRY_HASH_LENGTH > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->ecpubkey = &data[*offset];
    *offset += EC_PUBLIC_KEY_LENGTH;
#endif

    if ( *offset != length )
    {
        result = USTREAM_FAULT_INVALID_ENTRY_COMMIT_LENGTH;
	goto error;
    }

    result = USTREAM_FINISHED;

error:
    return result;
}



parserStatus_e parseEcTxInternal(uint8_t *data, uint32_t length,
                               txEcContent_t *context) {
    uint32_t offset = 0;
    parserStatus_e result = USTREAM_FAULT;
    //TODO: Send in the transaction data in small chunks from jswrapper 
    //(not to exceed 255 bytes for each chunk)

        if (offset > length) {
            goto error;
        }
        uint8_t bytes = 0;
        uint64_t dataType = varint_decode(&data[offset],length,&bytes);
        offset += bytes;

        switch (dataType) {
        case ECTX_HEADER_V0:
            context->version = dataType;
            result = parseEcTxV0(data, length, context, &offset);
            break;
        default:
            //result = USTREAM_FAULT_INTERNAL;
            return 0x6E00;//|(uint8_t)dataType;
            goto error;
        }
        if (result != USTREAM_FINISHED) {
            goto error;
        }
   // }

error:
    return result;
}

void initEcContent(txEcContent_t *content)
{
    content->ecpubkey = 0;
//    content->timestamp_ms = 0;
    content->entryhash = 0;
    content->numec = 0;
    content->version = 0;
}

parserStatus_e parseEcTx(uint8_t *data, uint32_t length, txEcContent_t *content)
{
    parserStatus_e result = USTREAM_FAULT;
//    BEGIN_TRY {
//        TRY {
            initEcContent(content);
            result = parseEcTxInternal(data, length, content);
            return result;
//        }
//        CATCH_OTHER(e) {
//            result = USTREAM_FAULT;
//        }
//        FINALLY {
//        }
//    }
//    END_TRY;

    return result;
}
