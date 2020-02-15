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

#include "fctParse.h"

#define STI_UINT16 0x01
#define STI_UINT32 0x02
#define STI_AMOUNT 0x06
#define STI_VL 0x07
#define STI_ACCOUNT 0x08

#define FCTTX_HEADER_V2 0x02
#define FCTTX_INPUT 0x02
#define FCTTX_OUTPUT 0x02


#define FCT_UINT16_TRANSACTION_TYPE 0x02
#define FCT_UINT32_FLAGS 0x02
#define FCT_UINT32_SOURCE_TAG 0x03
#define FCT_UINT32_SEQUENCE 0x04
#define FCT_UINT32_LAST_LEDGER_SEQUENCE 0x1B
#define FCT_UINT32_DESTINATION_TAG 0x0E
#define FCT_AMOUNT_AMOUNT 0x01
#define FCT_AMOUNT_FEES 0x08
#define FCT_VL_SIGNING_PUB_KEY 0x03
#define FCT_ACCOUNT_ACCOUNT 0x01
#define FCT_ACCOUNT_DESTINATION 0x03

parserStatus_e parseTxAddress(uint8_t *data, uint32_t length,
                uint8_t count, txContentAddress_t *context, uint64_t *fees,
                uint32_t *offsetParam);

void parse_fct_amount(uint64_t *value, uint8_t *data) {
    *value = ((uint64_t)data[7]) | ((uint64_t)data[6] << 8) |
             ((uint64_t)data[5] << 16) | ((uint64_t)data[4] << 24) |
             ((uint64_t)data[3] << 32) | ((uint64_t)data[2] << 40) |
             ((uint64_t)data[1] << 48) | ((uint64_t)data[0] << 56);
    *value -= (uint64_t)0x4000000000000000;
}

void parse_uint32(uint32_t *value, uint8_t *data) {
    *value = ((uint32_t)data[3]) | ((uint32_t)data[2] << 8) |
             ((uint32_t)data[1] << 16) | ((uint32_t)data[0] << 24);
}

parserStatus_e parseTxV2(uint8_t *data, uint32_t length, txContent_t *context, uint32_t *offset)
{

    parserStatus_e result = USTREAM_FAULT_PARSE;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    //parse timestamp.  not really concerned about this here.
//    context->header.timestamp_ms = &data[*offset];
    *offset += 6;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->header.inputcount = data[*offset];
    ++(*offset);

    if ( context->header.inputcount > MAX_INPUT_ADDRESSES )
    {
        result = USTREAM_FAULT_INPUT_COUNT;
        goto error;
    }

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->header.outputcount = data[*offset];
    ++(*offset);

    if ( context->header.outputcount > MAX_OUTPUT_ADDRESSES )
    {
        result = USTREAM_FAULT_OUTPUT_COUNT;
        goto error;
    }

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }

    context->header.ecpurchasecount = data[*offset];
    ++(*offset);

    if ( context->header.ecpurchasecount > MAX_ECOUTPUT_ADDRESSES )
    {
        result = USTREAM_FAULT_ECOUTPUT_COUNT;
        goto error;
    }

    uint64_t inputvalue = 0;
    result = parseTxAddress(data, length,
                            context->header.inputcount,
                            0, //context->inputs,
                            &inputvalue,
                            offset);

    if ( result != USTREAM_FINISHED )
    {
        goto error;
    }

    uint64_t outputvalue = 0;
    result = parseTxAddress(data, length,
                            context->header.outputcount,
                            context->outputs,
                            &outputvalue,
                            offset);
    if ( result != USTREAM_FINISHED )
    {
        goto error;
    }

    result = parseTxAddress(data, length,
                            context->header.ecpurchasecount,
                            context->t.ecpurchase,
                            &outputvalue,
                            offset);
    if ( result != USTREAM_FINISHED )
    {
        goto error;
    }

    if ( outputvalue >= inputvalue )
    {
        result = USTREAM_FAULT_FEES;
        goto error;
    }

    context->fees = inputvalue - outputvalue;
    result = USTREAM_FINISHED;

error:
    return result;
}

parserStatus_e parseTxAddress(uint8_t *data, uint32_t length,
                              uint8_t count, txContentAddress_t *context,
                              uint64_t *value,
                              uint32_t *offset)
{
    parserStatus_e result = USTREAM_FINISHED;

    for (int i = 0 ; i < count; ++i )
    {
        int8_t bytes = 0;
        int32_t diff = length-*offset;
        uint64_t v = varint_decode(&data[*offset],diff>8?8:diff, &bytes);
        if ( context )
        {
            context[i].amt.value = v;
        }
        *offset += bytes;


        if ( v == 0xFFFFFFFF )
        {
            result = USTREAM_FAULT_VALUE;
            break;//out of bounds -- bad varint
        }

        *value += v;

        if ( *offset+32 > length )
        {
            result = *offset * 0x10000 | USTREAM_FAULT_ADDRESS;
            break;
        }

        if ( context )
        {
            context[i].addr.rcdhash =  &data[*offset];
        }
        *offset+=32;

    }

    return result;
}



parserStatus_e parseTxInternal(uint8_t *data, uint32_t length,
                               txContent_t *context) {
    uint32_t offset = 0;
    parserStatus_e result = USTREAM_FAULT;
    //TODO: Send in the transaction data in small chunks from jswrapper 
    //(not to exceed 255 bytes for each chunk)

    //while (offset != length) {
        if (offset > length) {
            goto error;
        }
        uint8_t bytes = 0;
        uint64_t dataType = varint_decode(&data[offset],length,&bytes);
        offset += bytes;

        switch (dataType) {
        case FCTTX_HEADER_V2:
            context->header.version = dataType;
            result = parseTxV2(data, length, context, &offset);
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

void initContent(txContent_t *content)
{
//    content->header.timestamp_ms = NULL;
    content->header.inputcount = 0;
    content->header.outputcount = 0;
    content->header.ecpurchasecount = 0;
    content->header.fee = 0;

//    for ( int i = 0; i < MAX_INPUT_ADDRESSES; ++i )
//    {
//        content->inputs[i].amt.value = 0;
//        content->inputs[i].addr.rcdhash = NULL;
//    }


    for ( int i = 0; i < MAX_OUTPUT_ADDRESSES; ++i )
    {
        content->outputs[i].amt.value = 0;
        content->outputs[i].addr.rcdhash = NULL;
    }
    for ( int i = 0; i < MAX_ECOUTPUT_ADDRESSES; ++i )
    {
        content->t.ecpurchase[i].amt.value = 0;
        content->t.ecpurchase[i].addr.rcdhash = NULL;
    }
}

parserStatus_e parseTx(uint8_t *data, uint32_t length, 
                       txContent_t *content) {
    parserStatus_e result = USTREAM_FAULT;
    initContent(content);
    result = parseTxInternal(data, length, content);
    return result;
            /*
    BEGIN_TRY {
        TRY {
            initContent(content);
            result = parseTxInternal(data, length, content);
            return USTREAM_FINISHED;
        }
        CATCH_OTHER(e) {
            result = USTREAM_FAULT;
        }
        FINALLY {
        }
    }
    END_TRY;
    */
    return result;
}



