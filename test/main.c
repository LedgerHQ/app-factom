
#include "fctParse.h"
#include "ecParse.h"
#include "ccParse.h"
#include "fctUtils.h"
#include <memory.h>
#include <stdio.h>


const int8_t fcthex[] =   "02016253dfaa7301010087db406ff65cb9dd72a1e99bcd51da5e03b0ccafc237dbf1318a8d7438e22371c892d6868d20f02894db071e2eb38fdc56c697caaeba7dc19bddae2c6e7084cc3120d667b49f";//0155d679fb5b160f00cf5e5d34e5b1855e67e76317ebe35816cb34c86e25803ea90ac83d4011aebf93ee29e9a4b6860a1f023d84770341ae8ab3c2ac6cd9192edc42eb3ac6637badf46536545aebf8f083762bd4ac79ffb378726433020d149f06";
const int8_t echex[] =    "00016227acddfe57cf6740c4f30ae39d71f75710fb4ea9c843d5c01755329a42ccab52034e1f7901d5b8efdb52a15c4007d341eb1193903a021ed7aaa9a3cf4234c32ef8a213de00";

const int8_t fctechex[] = "02016e5d421562010001bd84400e9dcd94f81f01517bfcd324e36f27c2decb926e80aae5085c6d4a9396a4858b0037399721298d77984585040ea61055377039a4c3f3e2cd48c46ff643d50fd64f";
const int8_t entry[] = "000165e2d19bbebe548e2189e84824a90aa900f2d2ede8ff5d65383be3bece06e85f430a07fb1700";

void hextobin(unsigned char *v, unsigned char *s, size_t n) {

    int i;
    char _t[3];

    unsigned char *p = s;

    for (i=0; i<n; ++i) {

        memcpy(_t, p, 2);

        _t[2] = '\0';

        v[i] = (int)strtol(_t, NULL, 16);

        p += 2;

    }

}
int jsmnmain();

void test_varint_decode()
{

    uint64_t test_varint[] = { 0x8FFFFFFF7F, 0x8102 };
    uint64_t test_result[] = { 0xFFFFFFFF, 0x82 };

    for (int i = 0; i < sizeof(test_varint)/sizeof(uint64_t); ++i )
    {
        uint8_t buf[256];
        sprintf(buf, "%lx", test_varint[i] );

        uint8_t binbuf[256];
        uint32_t off = 0;

        int len = sizeof(buf)/2 + sizeof(buf)%2;
        hextobin(binbuf, buf, len);
        uint64_t val = varint_decode(binbuf,len, &off);

        if ( val != test_result[i] )
        {
            fprintf(stderr, "varint_decode test failed %ld != %ld\n", val, test_result[i]);
        }
        else
        {

            fprintf(stderr, "varint_decode test passed %ld == %ld\n", val, test_result[i]);
        }

    }

}



int main ( int argc, char argv[] )
{
    test_varint_decode();

    parserStatus_e ret;
    uint8_t data[MAX_TXN_SIZE];
    uint32_t length;
    txContent_t content;

    length = strlen(fctechex);
    if ( length*2 > MAX_TXN_SIZE )
    {
        printf("[ERROR]: transaction length too long.\n");
        return -1;
    }

    bzero(data, sizeof(data));
    hextobin(data, fctechex, length/2);


    ret = parseTx(data,length, &content);

    char out[512];
    //getFctAddressStringFromRCDHash(content.inputs[0].addr.rcdhash,out,PUBLIC_OFFSET_FCT);
    //fprintf(stderr, "%s\n", out);
    //fprintf(stderr, "%ld\n", content.inputs[0].amt.value);

    getFctAddressStringFromRCDHash(content.outputs[0].addr.rcdhash,out,PUBLIC_OFFSET_FCT);
    fprintf(stderr, "%s\n", out);
    fprintf(stderr, "%ld\n", content.outputs[0].amt.value);


    char maxFee[256];
    fct_print_amount(content.fees, maxFee, sizeof(maxFee));

    fprintf(stderr, "Fee %s\n",maxFee);

    char fullAmount[256];
    for ( int i = 0; i < content.header.outputcount;++i )
    {
        fct_print_amount(content.outputs[i].amt.value, fullAmount, sizeof(fullAmount));

        fprintf(stderr, "Amount %s\n", fullAmount);
    }


    txEcContent_t eccontent;
    bzero(data,sizeof(data));
    hextobin(data,echex,strlen(echex)/2);
    ret = parseEcTx(data,length, &eccontent);

    if ( ret == 0 )
    {

        cx_ecfp_public_key_t pubkey;
        pubkey.W_len = 32;

        os_memmove(pubkey.W,eccontent.ecpubkey,pubkey.W_len);


        getFctAddressStringFromKey(&pubkey,out,PUBLIC_OFFSET_EC);
        fprintf(stderr, "EC PUB KEY %s\n", out);


        //parse check

        int8_t ectest[] = "d5b8efdb52a15c4007d341eb1193903a021ed7aaa9a3cf4234c32ef8a213de00";

        uint8_t n = strlen(ectest);
        hextobin(data,ectest, strlen(ectest)/2);

        pubkey.W_len = 32;

        os_memmove(pubkey.W,data,pubkey.W_len);
        getFctAddressStringFromKey(&pubkey,out,PUBLIC_OFFSET_EC);
        fprintf(stderr, "Test EC PUB KEY %s\n", out);
    }



    //jsmnmain();
    //hextobin(data,entry, strlen(entry)/2);
    txContent_t fatcontent;
    static const char *JSON_STRING =
        "{\"inputs\":{\"FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct\":150},\"outputs\":{\"FA3nr5r54AKBZ9SLABS3JyRoGcWMVMTkePW9MECKM8shMg2pMagn\":150}}";

    static const char *fat0tx =
       "3031353639353334303736888888d027c59579fc47a6fc6c4a5c0409c7c39bc38a86cb5fc00699784937627b22696e70757473223a7b22464132326465354e534732464132486d4d61443468387153415a414a797a746d6d6e77674c50676843514b6f53656b7759596374223a3135307d2c226f757470757473223a7b224641336e7235723534414b425a39534c414253334a79526f4763574d564d546b655057394d45434b4d3873684d6732704d61676e223a3135307d7d";

    bzero(data,sizeof(data));
    hextobin(data,fat0tx,strlen(fat0tx)/2);


    char buf[256];

    int ret2 = parseFatTx(0,data, strlen(fat0tx)/2,&content);

    strncpy(buf, content.outputs[0].amt.fat.entry, content.outputs[0].amt.fat.size);
    printf("%s", buf);
    static const char *fat1tx =
    //"3031353730383438393139888888d027c59579fc47a6fc6c4a5c0409c7c39bc38a86cb5fc00699784937627b22696e70757473223a7b2246413251776d7a703478655852346a575972516e625053586935774c645648793870336b7341565376796a4c4558376a4533704e223a5b7b226d696e223a302c226d6178223a337d2c3135305d7d2c226f757470757473223a7b2246413361454370773367455a37434d5176524e7845744b42474b416f73333932326f71594c634851394e7158487564433659424d223a5b7b226d696e223a302c226d6178223a337d2c3135305d7d7d";
    "3031353731313637363230888888d027c59579fc47a6fc6c4a5c0409c7c39bc38a86cb5fc00699784937627b22696e70757473223a7b22464132326465354e534732464132486d4d61443468387153415a414a797a746d6d6e77674c50676843514b6f53656b7759596374223a5b31305d7d2c226f757470757473223a7b224641336e7235723534414b425a39534c414253334a79526f4763574d564d546b655057394d45434b4d3873684d6732704d61676e223a5b31305d7d2c226d65746164617461223a7b2274797065223a226661742d6a7320746573742072756e222c2274696d657374616d70223a313537313136373631393937307d7d";

    ////"3031353731313636353032888888d027c59579fc47a6fc6c4a5c0409c7c39bc38a86cb5fc00699784937627b22696e70757473223a7b22464132326465354e534732464132486d4d61443468387153415a414a797a746d6d6e77674c50676843514b6f53656b7759596374223a5b31305d7d2c226f757470757473223a7b224641336e7235723534414b425a39534c414253334a79526f4763574d564d546b655057394d45434b4d3873684d6732704d61676e223a5b31305d7d2c226d65746164617461223a7b2274797065223a226661742d6a7320746573742072756e222c2274696d657374616d70223a313537313136363530313838367d7d";
//"{"inputs":{"FA2Qwmzp4xeXR4jWYrQnbPSXi5wLdVHy8p3ksAVSvyjLEX7jE3pN":[{"min":0,"max":3},150]},"outputs""... (unknown length)

    bzero(data,sizeof(data));
    hextobin(data,fat1tx,strlen(fat1tx)/2);

    ret2=parseFatTx(1,data, strlen(fat1tx)/2,&content);

    strncpy(buf, content.outputs[0].amt.fat.entry, content.outputs[0].amt.fat.size);
    printf("%s", buf);

    return 0;
}

