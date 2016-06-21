//
//  proto_nacltai.c
//  Sigma nacltai protocol code
//
//  Copyright (c) 2011, Neil Alexander T.
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with
//  or without modification, are permitted provided that the following
//  conditions are met:
//
//  - Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  - Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  The nacltai code is derived, with permission, from Quicktun written
//  by Ivo Smits. http://oss.ucis.nl/hg/quicktun/
//

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <errno.h>

#include <fcntl.h>

#include "../proto.h"
#include "../tai.h"
#include "../pack.h"

#define noncelength TAIA_PACK_LEN
#define nonceoffset (crypto_box_NONCEBYTES - noncelength)
#define rxtaiacount 16

int fd; 

typedef struct sigma_proto_nacl
{
    sigma_proto baseproto;

    uint8_t privatekey[crypto_box_SECRETKEYBYTES];
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t precomp[crypto_box_BEFORENMBYTES];
    uint8_t encnonce[crypto_box_NONCEBYTES];
    uint8_t decnonce[crypto_box_NONCEBYTES];

    struct taia cdtaie;
    uint8_t rxtaialog[rxtaiacount][TAIA_PACK_LEN];
}
sigma_proto_nacl;

static int proto_set(sigma_proto* instance, char* param, char* value)
{
    if (strcmp(param, "publickey") == 0)
    {
        size_t read = hex2bin(((sigma_proto_nacl*) instance)->publickey, value, crypto_box_PUBLICKEYBYTES);
        if (read != crypto_box_PUBLICKEYBYTES || value[crypto_box_PUBLICKEYBYTES * 2] != '\0')
        {
            fprintf(stderr, "Public key is incorrect length\n");
            errno = EILSEQ;
            return -1;
        }
    }
        else
    if (strcmp(param, "privatekey") == 0)
    {
        size_t read = hex2bin(((sigma_proto_nacl*) instance)->privatekey, value, crypto_box_SECRETKEYBYTES);
        if (read != crypto_box_SECRETKEYBYTES || value[crypto_box_SECRETKEYBYTES * 2] != '\0')
        {
            fprintf(stderr, "Private key is incorrect length\n");
            errno = EILSEQ;
            return -1;
        }
    }
        else
    {
        fprintf(stderr, "Unknown attribute '%s'\n", param);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int proto_encode(sigma_proto *instance, uint8_t* input, uint8_t* output, size_t len)
{
    sigma_proto_nacl* inst = (sigma_proto_nacl*) instance;

    //int fd;
    uint8_t tempbufferinput[len + 28 + 4];
    uint8_t extrabytes;

    taia_now(&inst->cdtaie);
    taia_pack(inst->encnonce + nonceoffset, &(inst->cdtaie));
    
    tempbufferinput[0] = 0;
    tempbufferinput[1] = 0;
    tempbufferinput[2] = len;
    tempbufferinput[3] = len>>8;
    
    memcpy(tempbufferinput+4,      inst->encnonce, crypto_box_NONCEBYTES);
    memcpy(tempbufferinput+28,     input,          len);
    memset(tempbufferinput+28+len, 0,              4);
    
    //fd = open("/dev/axi-dma1", O_RDWR);
    write(fd, tempbufferinput, 32);
    //close(fd);
    
    extrabytes = 4 - (len % 4);
    if(extrabytes == 4)    extrabytes = 0;
        
    memcpy( output, 
            inst->encnonce + nonceoffset, 
            noncelength);
    
    memcpy( output + crypto_box_MACBYTES,  
            tempbufferinput + extrabytes + len,  
            crypto_box_MACBYTES);  
    
    memcpy( output + crypto_box_ZEROBYTES, 
            tempbufferinput,
            len);

    return len + crypto_box_ZEROBYTES;
}

static int proto_decode(sigma_proto *instance, uint8_t* input, uint8_t* output, size_t len)
{
    if (len < crypto_box_ZEROBYTES)
    {
        fprintf(stderr, "Short packet received: %u\n", (unsigned) len);
        errno = EINVAL;
        return -1;
    }

    sigma_proto_nacl* inst = (sigma_proto_nacl*) instance;

    int i, taioldest = 0;
    for (i = 0; i < rxtaiacount; i ++)
    {
        if (memcmp(input, inst->rxtaialog[i], noncelength) == 0)
        {
            fprintf(stderr, "Timestamp reuse detected, possible replay attack (packet length %u)\n", (unsigned) len);
            errno = EINVAL;
            return -1;
        }

        if (i != 0 && memcmp(inst->rxtaialog[i], inst->rxtaialog[taioldest], noncelength) < 0)
            taioldest = i;
    }

    if (memcmp(input, inst->rxtaialog[taioldest], noncelength) < 0)
    {
        fprintf(stderr, "Timestamp older than our oldest known timestamp, possible replay attack (packet length %u)\n", (unsigned) len);
        errno = EINVAL;
        return -1;
    }
    
    len -= crypto_box_ZEROBYTES;

    //int fd;
    uint8_t buffer[len + 28 + 4];
    uint8_t extrabytes;

    memcpy(inst->decnonce + nonceoffset, input, noncelength);    

    buffer[0] = 2;
    buffer[1] = 0;
    buffer[2] = len;
    buffer[3] = len>>8;    

    memcpy(buffer+4,      inst->decnonce,             crypto_box_NONCEBYTES);
    memcpy(buffer+28,     input+crypto_box_ZEROBYTES, len);
    memset(buffer+28+len, 0,                          4);

    //fd = open("/dev/axi-dma1", O_RDWR);
    write(fd, buffer, 32);
    //close(fd);

    extrabytes = 4 - (len % 4);
    if(extrabytes == 4)    extrabytes = 0;

    // Check if MAC is correct
    if (    memcmp( buffer + extrabytes + len, 
                    input + crypto_box_MACBYTES, 
                    crypto_box_MACBYTES)            != 0)
    {
        fprintf(stderr, "Decryption failed (length %u)\n", (unsigned) len);
        errno = EINVAL;
        return -1;
    }

    memcpy( output, 
            buffer, 
            len);
            
    memcpy( inst->rxtaialog[taioldest], 
            inst->decnonce + nonceoffset, 
            noncelength);

    return len;
}

static int proto_init(sigma_proto *instance)
{
    sigma_proto_nacl* inst = ((sigma_proto_nacl*) instance);
    uint8_t taipublickey[crypto_box_PUBLICKEYBYTES];

    crypto_box_beforenm(
        inst->precomp,
        inst->publickey,
        inst->privatekey
    );

    bzero(inst->encnonce, crypto_box_NONCEBYTES);
    bzero(inst->decnonce, crypto_box_NONCEBYTES);

    crypto_scalarmult_curve25519_base(taipublickey, inst->privatekey);

    inst->encnonce[nonceoffset - 1] = memcmp(taipublickey, inst->publickey, crypto_box_PUBLICKEYBYTES) > 0 ? 1 : 0;
    inst->decnonce[nonceoffset - 1] = inst->encnonce[nonceoffset - 1] ? 0 : 1;
    
    // Do a dummy encryption once with Precompute 
    // to set the precompute register of the HW 
    uint8_t buffer[32 + 60];
    //int fd; 
    
    buffer[0] = 1;
    buffer[1] = 0;
    buffer[2] = 32;
    buffer[3] = 0;    
        
    memset(buffer+4,        0,              crypto_box_NONCEBYTES);
    memcpy(buffer+28,       inst->precomp,  crypto_box_BEFORENMBYTES);
    memset(buffer+60,       0,              32);    
    
    fd = open("/dev/axi-dma1", O_RDWR);
    write(fd, buffer, 32);
    //close(fd);
    
    return 0;
}

static int proto_reload(sigma_proto *instance)
{
    return proto_init(instance);
}

extern sigma_proto* proto_descriptor()
{
    sigma_proto_nacl* proto_nacltai = calloc(1, sizeof(sigma_proto_nacl));

    proto_nacltai->baseproto.encrypted = true;
    proto_nacltai->baseproto.stateful = false;
    proto_nacltai->baseproto.init = proto_init;
    proto_nacltai->baseproto.encode = proto_encode;
    proto_nacltai->baseproto.decode = proto_decode;
    proto_nacltai->baseproto.set = proto_set;
    proto_nacltai->baseproto.reload = proto_reload;
    proto_nacltai->baseproto.state = 0;

    return (sigma_proto*) proto_nacltai;
}
