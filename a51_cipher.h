/*
 * a51_cipher.h
 *
 *  Created on: 01-May-2015
 *      Author: indudinesh
 */

#ifndef A51_CIPHER_H_
#define A51_CIPHER_H_

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


typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long int uint64;

typedef signed char sint8;
typedef signed short int sint16;
typedef signed int sint32;
typedef signed long int sint64;


struct A51Cipher
{
	uint32 lfsr1;
	uint32 lfsr2;
	uint32 lfsr3;

	uint64 sessionKey;

	uint32 frameCounter;
};

void initA51Cipher(struct A51Cipher* pa51Cipher);

void runLoop(struct A51Cipher* pa51Cipher,uint64 keyStream,uint64 keyStreamMask,uint32 keystreamLength);

#endif /* A51_CIPHER_H_ */
