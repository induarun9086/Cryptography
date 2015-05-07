/*
 * a51_cipher.h
 *
 *  Created on: 01-May-2015
 *      Author: indudinesh
 */

#ifndef A51_CIPHER_H_
#define A51_CIPHER_H_

#define true 1
#define false 0

#define A51_CIPHER_LFSR1_LENGTH (19)
#define A51_CIPHER_LFSR2_LENGTH (22)
#define A51_CIPHER_LFSR3_LENGTH (23)

#define A51_CIPHER_LFSR1_MASK ((uint32)0x0007ffff)
#define A51_CIPHER_LFSR2_MASK ((uint32)0x003fffff)
#define A51_CIPHER_LFSR3_MASK ((uint32)0x007fffff)

#define A51_CIPHER_SESSIONKEY_LENGTH (64)
#define A51_CIPHER_SESSIONKEY_MASK ((uint64)0x0000000000000001)

#define A51_CIPHER_FRAMECOUNTER_LENGTH (23)
#define A51_CIPHER_FRAMECOUNTER_MASK ((uint32)0x00000001)

#define A51_CIPHER_LFSR1_TAP0_MASK ((uint32)0x00002000)
#define A51_CIPHER_LFSR1_TAP1_MASK ((uint32)0x00010000)
#define A51_CIPHER_LFSR1_TAP2_MASK ((uint32)0x00020000)
#define A51_CIPHER_LFSR1_TAP3_MASK ((uint32)0x00040000)

#define A51_CIPHER_LFSR1_TAP0_SHIFT ((uint32)13)
#define A51_CIPHER_LFSR1_TAP1_SHIFT ((uint32)16)
#define A51_CIPHER_LFSR1_TAP2_SHIFT ((uint32)17)
#define A51_CIPHER_LFSR1_TAP3_SHIFT ((uint32)18)

#define A51_CIPHER_LFSR2_TAP0_MASK ((uint32)0x00100000)
#define A51_CIPHER_LFSR2_TAP1_MASK ((uint32)0x00200000)

#define A51_CIPHER_LFSR2_TAP0_SHIFT ((uint32)20)
#define A51_CIPHER_LFSR2_TAP1_SHIFT ((uint32)21)

#define A51_CIPHER_LFSR3_TAP0_MASK ((uint32)0x00000080)
#define A51_CIPHER_LFSR3_TAP1_MASK ((uint32)0x00100000)
#define A51_CIPHER_LFSR3_TAP2_MASK ((uint32)0x00200000)
#define A51_CIPHER_LFSR3_TAP3_MASK ((uint32)0x00400000)

#define A51_CIPHER_LFSR3_TAP0_SHIFT ((uint32)7)
#define A51_CIPHER_LFSR3_TAP1_SHIFT ((uint32)20)
#define A51_CIPHER_LFSR3_TAP2_SHIFT ((uint32)21)
#define A51_CIPHER_LFSR3_TAP3_SHIFT ((uint32)22)

#define A51_CIPHER_LFSR1_IRREGULAR_CLOCK_MASK ((uint32)0x00000100)
#define A51_CIPHER_LFSR2_IRREGULAR_CLOCK_MASK ((uint32)0x00000400)
#define A51_CIPHER_LFSR3_IRREGULAR_CLOCK_MASK ((uint32)0x00000400)

#define A51_CIPHER_LFSR1_IRREGULAR_CLOCK_SHIFT ((uint32)8)
#define A51_CIPHER_LFSR2_IRREGULAR_CLOCK_SHIFT ((uint32)10)
#define A51_CIPHER_LFSR3_IRREGULAR_CLOCK_SHIFT ((uint32)10)

#define A51_CIPHER_LFSR1_MSB_MASK ((uint32)0x00040000)
#define A51_CIPHER_LFSR2_MSB_MASK ((uint32)0x00200000)
#define A51_CIPHER_LFSR3_MSB_MASK ((uint32)0x00400000)

#define A51_CIPHER_KEY_STREAM_ARRAY_LENGTH (29)

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long int uint64;

typedef signed char sint8;
typedef signed short int sint16;
typedef signed int sint32;
typedef signed long int sint64;
typedef int bool;

struct A51Cipher {
	uint32 lfsr1;
	uint32 lfsr2;
	uint32 lfsr3;

	uint64 sessionKey;

	uint32 frameCounter;

	uint8 keyStream[A51_CIPHER_KEY_STREAM_ARRAY_LENGTH];
	uint8 dataStream[A51_CIPHER_KEY_STREAM_ARRAY_LENGTH];
	uint8 outputStream[A51_CIPHER_KEY_STREAM_ARRAY_LENGTH];

};

void initA51Cipher(struct A51Cipher* pa51Cipher);

void runLoop(struct A51Cipher* pa51Cipher, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength, bool irregularClock,
		bool generateKeyStream);

void executeIrregularClockBlock(struct A51Cipher* pa51Cipher, uint32 i,
		uint64 keyStream, uint64 keyStreamMask, uint32 keystreamLength);

void clockRegisterOne(struct A51Cipher* pa51Cipher, uint32 i, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength);

void clockRegisterTwo(struct A51Cipher* pa51Cipher, uint32 i, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength);

void clockRegisterThree(struct A51Cipher* pa51Cipher, uint32 i,
		uint64 keyStream, uint64 keyStreamMask, uint32 keystreamLength);

void generateKeyStream(struct A51Cipher* pa51Cipher);

void encryptDataBits(struct A51Cipher* pa51Cipher,FILE* output_file);

#endif /* A51_CIPHER_H_ */
