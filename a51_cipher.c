/*
 * a51_cipher.c
 *
 *  Created on: 01-May-2015
 *      Author: Indumathi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "a51_cipher.h"

int main(int argc, char* argv[])
{
	struct A51Cipher a51Cipher;
	FILE* input_file = NULL;

	memset(&a51Cipher,0,sizeof(struct A51Cipher));

	printf("A5/1 Implementation\n");

	input_file = fopen("DSC01338.JPG","rb");

	if(input_file != NULL)
	{
		a51Cipher.sessionKey = 0x5cd11d783ab2f472;
		initA51Cipher(&a51Cipher);
	}
	return 0;
}

void initA51Cipher(struct A51Cipher* pa51Cipher)
{
	runLoop(pa51Cipher,pa51Cipher->sessionKey,A51_CIPHER_SESSIONKEY_MASK,A51_CIPHER_SESSIONKEY_LENGTH);
	runLoop(pa51Cipher,pa51Cipher->frameCounter,A51_CIPHER_FRAMECOUNTER_MASK,A51_CIPHER_FRAMECOUNTER_LENGTH);
	runLoop(pa51Cipher,0,0,100);

}

void runLoop(struct A51Cipher* pa51Cipher,uint64 keyStream,uint64 keyStreamMask,uint32 keystreamLength)
{
	uint32 i;
	uint8 xorSum;
	for(i= 0; i<keystreamLength; i++)
	{
		xorSum = 0;
		xorSum += ((keyStream & keyStreamMask) >> i);
		xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP0_MASK) >> A51_CIPHER_LFSR1_TAP0_SHIFT);
		xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP1_MASK) >> A51_CIPHER_LFSR1_TAP1_SHIFT);
		xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP2_MASK) >> A51_CIPHER_LFSR1_TAP2_SHIFT);
		xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP3_MASK) >> A51_CIPHER_LFSR1_TAP3_SHIFT);

		xorSum = xorSum & ((uint32)0x00000001);

		pa51Cipher->lfsr1 = pa51Cipher->lfsr1 << 1;
		pa51Cipher->lfsr1 = pa51Cipher->lfsr1 & ((uint32)0xfffffffe);
		pa51Cipher->lfsr1 = pa51Cipher->lfsr1 | xorSum;

		xorSum = 0;
		xorSum += ((keyStream & keyStreamMask) >> i);
		xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_TAP0_MASK) >> A51_CIPHER_LFSR2_TAP0_SHIFT);
		xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_TAP1_MASK) >> A51_CIPHER_LFSR2_TAP1_SHIFT);

		xorSum = xorSum & ((uint32)0x00000001);

		pa51Cipher->lfsr2 = pa51Cipher->lfsr2 << 1;
		pa51Cipher->lfsr2 = pa51Cipher->lfsr2 & ((uint32)0xfffffffe);
		pa51Cipher->lfsr2 = pa51Cipher->lfsr2 | xorSum;

		xorSum = 0;
		xorSum += ((keyStream & keyStreamMask) >> i);
		xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP0_MASK) >> A51_CIPHER_LFSR3_TAP0_SHIFT);
		xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP1_MASK) >> A51_CIPHER_LFSR3_TAP1_SHIFT);
		xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP2_MASK) >> A51_CIPHER_LFSR3_TAP2_SHIFT);
		xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP3_MASK) >> A51_CIPHER_LFSR3_TAP3_SHIFT);

		xorSum = xorSum & ((uint32)0x00000001);

		pa51Cipher->lfsr3 = pa51Cipher->lfsr3 << 1;
		pa51Cipher->lfsr3 = pa51Cipher->lfsr3 & ((uint32)0xfffffffe);
		pa51Cipher->lfsr3 = pa51Cipher->lfsr3 | xorSum;

		keyStreamMask = keyStreamMask << 1;

	}

	printf("LFSR 1 = 0x%x\n",pa51Cipher->lfsr1);
	printf("LFSR 2 = 0x%x\n",pa51Cipher->lfsr2);
	printf("LFSR 3 = 0x%x\n\n",pa51Cipher->lfsr3);
}

