/*
 * a51_cipher.h
 *
 *  Created on: 01-May-2015
 *      Author: indudinesh
 */

#ifndef A51_CIPHER_H_
#define A51_CIPHER_H_

/* macro for boolean true and false*/
#define true 1
#define false 0

/* Length of three registers*/
#define A51_CIPHER_LFSR1_LENGTH (19)
#define A51_CIPHER_LFSR2_LENGTH (22)
#define A51_CIPHER_LFSR3_LENGTH (23)

/* mask for the registers*/
#define A51_CIPHER_LFSR1_MASK ((uint32)0x0007ffff) /*19 Bits*/
#define A51_CIPHER_LFSR2_MASK ((uint32)0x003fffff) /*23 Bits*/
#define A51_CIPHER_LFSR3_MASK ((uint32)0x007fffff) /*22 Bits*/

/*Session Key Length and mask*/
#define A51_CIPHER_SESSIONKEY_LENGTH (64)
#define A51_CIPHER_SESSIONKEY_MASK ((uint64)0x0000000000000001)

/*Session frame counter and mask*/
#define A51_CIPHER_FRAMECOUNTER_LENGTH (23)
#define A51_CIPHER_FRAMECOUNTER_MASK ((uint32)0x00000001)

/*Feedback taps for clocking shift register-1*/
#define A51_CIPHER_LFSR1_TAP0_MASK ((uint32)0x00002000) /*Bit 13*/
#define A51_CIPHER_LFSR1_TAP1_MASK ((uint32)0x00010000) /*Bit 16*/
#define A51_CIPHER_LFSR1_TAP2_MASK ((uint32)0x00020000) /*Bit 17*/
#define A51_CIPHER_LFSR1_TAP3_MASK ((uint32)0x00040000) /*Bit 18*/

#define A51_CIPHER_LFSR1_TAP0_SHIFT ((uint32)13)
#define A51_CIPHER_LFSR1_TAP1_SHIFT ((uint32)16)
#define A51_CIPHER_LFSR1_TAP2_SHIFT ((uint32)17)
#define A51_CIPHER_LFSR1_TAP3_SHIFT ((uint32)18)

/*Feedback taps for clocking shift register-2*/
#define A51_CIPHER_LFSR2_TAP0_MASK ((uint32)0x00100000) /*Bit 20*/
#define A51_CIPHER_LFSR2_TAP1_MASK ((uint32)0x00200000) /*Bit 21*/

#define A51_CIPHER_LFSR2_TAP0_SHIFT ((uint32)20)
#define A51_CIPHER_LFSR2_TAP1_SHIFT ((uint32)21)

/*Feedback taps for clocking shift register-3*/
#define A51_CIPHER_LFSR3_TAP0_MASK ((uint32)0x00000080)/*Bit 07*/
#define A51_CIPHER_LFSR3_TAP1_MASK ((uint32)0x00100000)/*Bit 20*/
#define A51_CIPHER_LFSR3_TAP2_MASK ((uint32)0x00200000)/*Bit 21*/
#define A51_CIPHER_LFSR3_TAP3_MASK ((uint32)0x00400000)/*Bit 22*/

#define A51_CIPHER_LFSR3_TAP0_SHIFT ((uint32)7)
#define A51_CIPHER_LFSR3_TAP1_SHIFT ((uint32)20)
#define A51_CIPHER_LFSR3_TAP2_SHIFT ((uint32)21)
#define A51_CIPHER_LFSR3_TAP3_SHIFT ((uint32)22)

/*clocking Bit while executing irregular clocking 100 times */
#define A51_CIPHER_LFSR1_IRREGULAR_CLOCK_MASK ((uint32)0x00000100) /*Bit 8*/
#define A51_CIPHER_LFSR2_IRREGULAR_CLOCK_MASK ((uint32)0x00000400) /*Bit 10*/
#define A51_CIPHER_LFSR3_IRREGULAR_CLOCK_MASK ((uint32)0x00000400) /*Bit 10*/

#define A51_CIPHER_LFSR1_IRREGULAR_CLOCK_SHIFT ((uint32)8)
#define A51_CIPHER_LFSR2_IRREGULAR_CLOCK_SHIFT ((uint32)10)
#define A51_CIPHER_LFSR3_IRREGULAR_CLOCK_SHIFT ((uint32)10)

/*Taps for output generation*/
#define A51_CIPHER_LFSR1_MSB_MASK ((uint32)0x00040000)
#define A51_CIPHER_LFSR2_MSB_MASK ((uint32)0x00200000)
#define A51_CIPHER_LFSR3_MSB_MASK ((uint32)0x00400000)

/*Length of the keystream */
#define A51_CIPHER_KEY_STREAM_LENGTH (228)

/*Length of each bit of the keystream 228/8 = 29 */
#define A51_CIPHER_KEY_STREAM_ARRAY_LENGTH (29)

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long int uint64;

typedef signed char sint8;
typedef signed short int sint16;
typedef signed int sint32;
typedef signed long int sint64;
typedef int boolean;

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

struct rwBitsData{
	uint8 numBits;
	uint8 tempByte;
	uint8 numBitsShortage;
};

void initA51Cipher(struct A51Cipher* pa51Cipher);

void runLoop(struct A51Cipher* pa51Cipher, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength, boolean irregularClock,
		boolean generateKeyStream);

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

uint8 readBits(uint8* pDataStream,uint16 numBits, FILE* inputFile,struct rwBitsData* prwBitsData);

uint8 writeBits(uint8* pDataStream, uint16 numBits, FILE* outputFile, struct rwBitsData* prwBitsData);

#endif /* A51_CIPHER_H_ */
