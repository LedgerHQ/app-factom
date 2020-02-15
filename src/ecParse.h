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

#ifndef _EC_PARSE_H_
#define _EC_PARSE_H_

#include <stdbool.h>
#include <stdint.h>
#include "fctUtils.h"

#ifndef NULL
#define NULL 0
#endif

#define ECTX_HEADER_V0 0x00


//header Entry Commit
typedef struct txEcContent_t {
    uint8_t version;
//    uint8_t *timestamp_ms;
    uint8_t *entryhash;
    uint8_t numec;
    uint8_t *ecpubkey;
} txEcContent_t;

parserStatus_e parseEcTx(uint8_t *data, uint32_t length,
                       txEcContent_t *context);

#endif
