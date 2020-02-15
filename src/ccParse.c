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

#include "ccParse.h"

parserStatus_e parseCcTxV0(uint8_t *data, uint32_t length, txCcContent_t *context, uint32_t *offset)
{

    parserStatus_e result = USTREAM_FAULT_PARSE;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    //parse timestamp.  not really concerned about this here.
//    context->timestamp_ms = &data[*offset];
    *offset += 6;


    if ( *offset + CHAIN_HASH_LENGTH > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->chainhash = &data[*offset];
    *offset += CHAIN_HASH_LENGTH;

    if ( *offset + CHAIN_WELD_LENGTH > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->chainweld = &data[*offset];
    *offset += CHAIN_WELD_LENGTH;


    if ( *offset + EC_ENTRY_HASH_LENGTH > length )
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
    if ( *offset + EC_PUBLIC_KEY_LENGTH > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }


    context->ecpubkey = &data[*offset];
    *offset += EC_PUBLIC_KEY_LENGTH;
#endif

    if ( *offset != length )
    {
        result = USTREAM_FAULT_INVALID_CHAIN_COMMIT_LENGTH;
        goto error;
    }


    result = USTREAM_FINISHED;

error:
    return result;
}


parserStatus_e parseCcTxInternal(uint8_t *data, uint32_t length,
                               txCcContent_t *context)
{
    uint32_t offset = 0;
    parserStatus_e result = USTREAM_FAULT;

    if (offset > length)
    {
        goto error;
    }
    uint8_t bytes = 0;
    uint64_t dataType = varint_decode(&data[offset],length,&bytes);
    offset += bytes;

    switch (dataType)
    {
    case CCTX_HEADER_V0:
        context->version = dataType;
        result = parseCcTxV0(data, length, context, &offset);
        break;
    default:
        //result = USTREAM_FAULT_INTERNAL;
        return 0x6E00;//|(uint8_t)dataType;
        goto error;
    }

error:
    return result;
}

void initCcContent(txCcContent_t *content)
{
    content->ecpubkey = 0;
//    content->timestamp_ms = 0;
    content->entryhash = 0;
    content->chainhash = 0;
    content->chainweld = 0;
    content->numec = 0;
    content->version = 0;
}

parserStatus_e parseCcTx(uint8_t *data, uint32_t length, txCcContent_t *content)
{
    parserStatus_e result = USTREAM_FAULT;
//    BEGIN_TRY {
//        TRY {
            initCcContent(content);
            result = parseCcTxInternal(data, length, content);
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
