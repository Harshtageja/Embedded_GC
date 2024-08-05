// Copyright (c) 2021 Michael Stoops. All rights reserved.
// Portions copyright (c) 2021 Raspberry Pi (Trading) Ltd.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//    disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//    following disclaimer in the documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//    products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Example of an SPI bus slave using the PL022 SPI interface

#include <stdio.h>
#include <string.h>
#include<stdlib.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "hardware/spi.h"
#include "structures.h"
/* AES Encryption Functions */

// // Define AES encryption functions here (AddRoundKey, SubBytes, ShiftRows, MixColumns, Round, FinalRound, AESEncrypt)
// void AddRoundKey(unsigned char * state, unsigned char * roundKey) {
//     for (int i = 0; i < 16; i++) {
//         state[i] ^= roundKey[i];
//     }
// }

// /* Perform substitution to each of the 16 bytes
//  * Uses S-box as lookup table
//  */
// void SubBytes(unsigned char * state) {
//     for (int i = 0; i < 16; i++) {
//         state[i] = s[state[i]];
//     }
// }

// // Shift left, adds diffusion
// void ShiftRows(unsigned char * state) {
//     unsigned char tmp[16];

//     /* Column 1 */
//     tmp[0] = state[0];
//     tmp[1] = state[5];
//     tmp[2] = state[10];
//     tmp[3] = state[15];

//     /* Column 2 */
//     tmp[4] = state[4];
//     tmp[5] = state[9];
//     tmp[6] = state[14];
//     tmp[7] = state[3];

//     /* Column 3 */
//     tmp[8] = state[8];
//     tmp[9] = state[13];
//     tmp[10] = state[2];
//     tmp[11] = state[7];

//     /* Column 4 */
//     tmp[12] = state[12];
//     tmp[13] = state[1];
//     tmp[14] = state[6];
//     tmp[15] = state[11];

//     for (int i = 0; i < 16; i++) {
//         state[i] = tmp[i];
//     }
// }

// /* MixColumns uses mul2, mul3 look-up tables
//  * Source of diffusion
//  */
// void MixColumns(unsigned char * state) {
//     unsigned char tmp[16];

//     tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
//     tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
//     tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
//     tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

//     tmp[4] = (unsigned char) mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
//     tmp[5] = (unsigned char) state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
//     tmp[6] = (unsigned char) state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
//     tmp[7] = (unsigned char) mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

//     tmp[8] = (unsigned char) mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
//     tmp[9] = (unsigned char) state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
//     tmp[10] = (unsigned char) state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
//     tmp[11] = (unsigned char) mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

//     tmp[12] = (unsigned char) mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
//     tmp[13] = (unsigned char) state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
//     tmp[14] = (unsigned char) state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
//     tmp[15] = (unsigned char) mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

//     for (int i = 0; i < 16; i++) {
//         state[i] = tmp[i];
//     }
// }

// /* Each round operates on 128 bits at a time
//  * The number of rounds is defined in AESEncrypt()
//  */
// void Round(unsigned char * state, unsigned char * key) {
//     SubBytes(state);
//     ShiftRows(state);
//     MixColumns(state);
//     AddRoundKey(state, key);
// }

// // Same as Round() except it doesn't mix columns
// void FinalRound(unsigned char * state, unsigned char * key) {
//     SubBytes(state);
//     ShiftRows(state);
//     AddRoundKey(state, key);
// }

// /* The AES encryption function
//  * Organizes the confusion and diffusion steps into one function
//  */
// void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
//     unsigned char state[16]; // Stores the first 16 bytes of original message

//     for (int i = 0; i < 16; i++) {
//         state[i] = message[i];
//     }

//     int numberOfRounds = 9;

//     AddRoundKey(state, expandedKey); // Initial round

//     for (int i = 0; i < numberOfRounds; i++) {
//         Round(state, expandedKey + (16 * (i + 1)));
//     }

//     FinalRound(state, expandedKey + 160);

//     // Copy encrypted state to buffer
//     for (int i = 0; i < 16; i++) {
//         encryptedMessage[i] = state[i];
//     }
// }



//For decryption
/* Function prototypes */
void SubRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

void InverseMixColumns(unsigned char *state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
    tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
    tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
    tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

    tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
    tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
    tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
    tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

    tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

    tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}


void ShiftRows(unsigned char *state) {
    unsigned char tmp[16];

    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];

    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];

    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

void SubBytes(unsigned char *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_s[state[i]];
    }
}

void Round(unsigned char *state, unsigned char *key) {
    SubRoundKey(state, key);
    InverseMixColumns(state);
    ShiftRows(state);
    SubBytes(state);
}

void InitialRound(unsigned char *state, unsigned char *key) {
    SubRoundKey(state, key);
    ShiftRows(state);
    SubBytes(state);
}

void AESDecrypt(unsigned char *encryptedMessage, unsigned char *expandedKey, unsigned char *decryptedMessage) {
    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = encryptedMessage[i];
    }

    InitialRound(state, expandedKey + 160);

    int numberOfRounds = 9;

    for (int i = 8; i >= 0; i--) {
        Round(state, expandedKey + (16 * (i + 1)));
    }

    SubRoundKey(state, expandedKey);

    for (int i = 0; i < 16; i++) {
        decryptedMessage[i] = state[i];
    }
}


#define BUF_LEN         0x100

void printbuf(uint8_t buf[], size_t len) {
    int i;
    for (i = 0; i < len; ++i) {
        if (i % 16 == 15)
            printf("%02x\n", buf[i]);
        else
            printf("%02x ", buf[i]);
    }

    // append trailing newline if there isn't one
    if (i % 16) {
        putchar('\n');
    }
}


int main() {
    // Enable UART so we can print
    stdio_init_all();
#if !defined(spi_default) || !defined(PICO_DEFAULT_SPI_SCK_PIN) || !defined(PICO_DEFAULT_SPI_TX_PIN) || !defined(PICO_DEFAULT_SPI_RX_PIN) || !defined(PICO_DEFAULT_SPI_CSN_PIN)
#warning spi/spi_slave example requires a board with SPI pins
    puts("Default SPI pins were not defined");
#else

    printf("SPI slave example\n");

     bi_decl(bi_program_description("AES Encryption Example"));

    stdio_init_all();
    sleep_ms(5000);

    printf("=============================\n");
    printf(" 128-bit AES Encryption Tool  \n");
    printf("=============================\n");


    unsigned char key[16]={0x54,0x68,0x61,0x74,0x73,0x20,0x6D,0x79,0x20,0x4B,0x75,0x6E,0x67,0x20,0x46,0x75};
    unsigned char encryptedMessage[16]="c7444b1a25398e784cb20b0681b72ffd3694001855c9b609320c1303f0dda5cc1014a3512cd2fa21a46e7fabfe4e6be474eeb0affcd";


    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    int i=0;

    unsigned char decryptedMessage[16];

    for (int i = 0; i < 16; i += 16) {
		AESDecrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
	}
    printf("Decrypted  message in hex:\n");
    for (int i = 0; i < 16; i++) {
        printf("%x ", decryptedMessage[i]);
    }
    printf("\n");
    printf("\n");
    // Load key from file

        

    // Enable SPI 0 at 1 MHz and connect to GPIOs
    spi_init(spi_default, 1000 * 1000);
    spi_set_slave(spi_default, true);
    gpio_set_function(PICO_DEFAULT_SPI_RX_PIN, GPIO_FUNC_SPI);
    gpio_set_function(PICO_DEFAULT_SPI_SCK_PIN, GPIO_FUNC_SPI);
    gpio_set_function(PICO_DEFAULT_SPI_TX_PIN, GPIO_FUNC_SPI);
    gpio_set_function(PICO_DEFAULT_SPI_CSN_PIN, GPIO_FUNC_SPI);
        spi_init(spi1, 1000 * 1000);
    spi_set_slave(spi1, true);
    gpio_set_function(12, GPIO_FUNC_SPI);
    gpio_set_function(14, GPIO_FUNC_SPI);
    gpio_set_function(15, GPIO_FUNC_SPI);
    gpio_set_function(13, GPIO_FUNC_SPI);
    // Make the SPI pins available to picotool
    bi_decl(bi_4pins_with_func(PICO_DEFAULT_SPI_RX_PIN, PICO_DEFAULT_SPI_TX_PIN, PICO_DEFAULT_SPI_SCK_PIN, PICO_DEFAULT_SPI_CSN_PIN, GPIO_FUNC_SPI));
    bi_decl(bi_4pins_with_func(12, 15, 14, 13, GPIO_FUNC_SPI));
    uint8_t out_buf[BUF_LEN], in_buf[BUF_LEN];

    // Initialize output buffer
    for (size_t i = 0; i < BUF_LEN; ++i) {
        // bit-inverted from i. The values should be: {0xff, 0xfe, 0xfd...}
        out_buf[i] = ~i;
    }

    printf("SPI slave says: When reading from MOSI, the following buffer will be written to MISO:\n");
    printbuf(out_buf, BUF_LEN);
    int k=0;
    for (size_t i = 0; ; ++i) {
        // Write the output buffer to MISO, and at the same time read from MOSI.
        spi_write_read_blocking(spi0, out_buf, in_buf, BUF_LEN);

        // Write to stdio whatever came in on the MOSI line.
        printf("SPI slave says: read page %d from the MOSI line:\n", i);
        printbuf(in_buf, BUF_LEN);
        if(in_buf[8]==5){
        for(size_t j=9;j<=8+in_buf[8];j++){
        printf("%c",in_buf[j]);
		encryptedMessage[k++]=in_buf[j];
        }
		    for (int i = 0; i < 16; i += 16) {
		AESDecrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
	}
    printf("Decrypted  message in hex:\n");
    for (int i = 0; i < 16; i++) {
        printf("%x ", decryptedMessage[i]);
    }
        }
        printf("\n");
    }
#endif
}
