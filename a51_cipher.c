/*
 * a51_cipher.c
 *
 *  Created on: 01-May-2015
 *      Author: Indumathi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "a51_cipher.h"

int main(int argc, char* argv[]) {

	//Initialise variables

	char inputFileName[100];
	char outputFileName[100];

	struct A51Cipher a51Cipher;
	struct rwBitsData rBitsData;
	struct rwBitsData wBitsData;

	FILE* input_file = NULL;
	FILE* output_file = NULL;

	uint32 i;

	uint8 numBytesRead;
	uint32 file_Length;

	memset(&a51Cipher, 0, sizeof(struct A51Cipher));
	memset(&rBitsData, 0, sizeof(struct rwBitsData));
	memset(&wBitsData, 0, sizeof(struct rwBitsData));

	printf("A5/1 Implementation\n");

	//Get the input file name - Encryption - Image to be Encrypted
	//                          Decryption - Encryped Data file
	//printf("Enter the input file name: \n");
	//scanf("%s", inputFileName);
	strcpy(inputFileName, argv[1]);

	//Get the output file name - Encryption - File in which encrypted data to be stored
	//                           Decryption - File in which original image is stored
	//printf("Enter the output file name: \n");
	//scanf("%s", outputFileName);
	strcpy(outputFileName, argv[2]);

	input_file = fopen(inputFileName, "rb");

	output_file = fopen(outputFileName, "wb");

	if (input_file != NULL) {

		// Get the length of the input file
		fseek(input_file, 0, SEEK_END);
		file_Length = ftell(input_file);
		fseek(input_file, 0, SEEK_SET);

		//printf("File Length = 0x%x\n", file_Length);

		for (i = 0; i < file_Length; i += numBytesRead) {

			a51Cipher.sessionKey = 0x5cd11d783ab2f472;

			//This method initialises the three registers
			initA51Cipher(&a51Cipher);

			// generates the keystream
			generateKeyStream(&a51Cipher);

			numBytesRead = readBits(&a51Cipher.dataStream[0],
			A51_CIPHER_KEY_STREAM_LENGTH, input_file, &rBitsData);

			encryptDataBits(&a51Cipher, output_file);

			writeBits(&a51Cipher.outputStream[0], A51_CIPHER_KEY_STREAM_LENGTH,
					  output_file, &wBitsData);

			printf("Processing %d %% \r", (((i+numBytesRead)*100)/file_Length));

		}
	}
	fclose(output_file);
	printf("Completed");
	return 0;
}

void initA51Cipher(struct A51Cipher* pa51Cipher) {

	// runLoop is the method which will xor the feedback taps for sessionkey,framecounter

	// Run the loop for session key
	runLoop(pa51Cipher, pa51Cipher->sessionKey, A51_CIPHER_SESSIONKEY_MASK,
	A51_CIPHER_SESSIONKEY_LENGTH, false, false);

	// Run the loop for frame counter
	runLoop(pa51Cipher, pa51Cipher->frameCounter, A51_CIPHER_FRAMECOUNTER_MASK,
	A51_CIPHER_FRAMECOUNTER_LENGTH, false, false);
	//Increment the frame counter for next looping
	pa51Cipher->frameCounter = pa51Cipher->frameCounter + 1;

	//Run the loop for 100 times irregular clocking
	runLoop(pa51Cipher, 0, 0, 100, true, false);

}

void generateKeyStream(struct A51Cipher* pa51Cipher) {

	//Registers are clocked 228 times with irregular clocking
	//output of each register is xored to produce 228 bits long keystream
	runLoop(pa51Cipher, 0, 0, A51_CIPHER_KEY_STREAM_LENGTH, true, true);

}

void runLoop(struct A51Cipher* pa51Cipher, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength, boolean irregularClock,
		boolean generateKeyStream) {
	uint32 i;

	for (i = 0; i < keystreamLength; i++) {
		// This if block will run during regular clocking
		// for session key and frame counter
		if (!irregularClock) {
			// For regular clocking all the three registers will be clocked
			// clock the register 1
			clockRegisterOne(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);

			// clock the register 2
			clockRegisterTwo(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);

			// clock the register 3
			clockRegisterThree(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);

		} else {
			// In irregular clocking
			// only the registers having the majority of the clocking bit is clocked
			// clocking Bit (Bit 8 in LFSR1, Bit 10 in LFSR2,Bit 10 in LFSR3)
			executeIrregularClockBlock(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);
		}

		if (generateKeyStream) {
			uint32 xorSum = 0;
			xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_MSB_MASK)
					>> (A51_CIPHER_LFSR1_LENGTH - 1));
			xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_MSB_MASK)
					>> (A51_CIPHER_LFSR2_LENGTH - 1));
			xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_MSB_MASK)
					>> (A51_CIPHER_LFSR3_LENGTH - 1));

			xorSum = xorSum & ((uint32) 0x00000001);

			pa51Cipher->keyStream[i / 8] = pa51Cipher->keyStream[i / 8]
					| xorSum << (i % 8);

		}

		keyStreamMask = keyStreamMask << 1;

	}

	/*if (generateKeyStream) {
	 for (i = 0; i < A51_CIPHER_KEY_STREAM_ARRAY_LENGTH; i++) {
	 printf("keystream = 0x%x\n", pa51Cipher->keyStream[i]);
	 }

	 }

	 printf("LFSR 1 = 0x%x\n", pa51Cipher->lfsr1);
	 printf("LFSR 2 = 0x%x\n", pa51Cipher->lfsr2);
	 printf("LFSR 3 = 0x%x\n\n", pa51Cipher->lfsr3);*/
}

void executeIrregularClockBlock(struct A51Cipher* pa51Cipher, uint32 i,
		uint64 keyStream, uint64 keyStreamMask, uint32 keystreamLength) {

	uint32 bit1 = pa51Cipher->lfsr1
			& A51_CIPHER_LFSR1_IRREGULAR_CLOCK_MASK
					>> A51_CIPHER_LFSR1_IRREGULAR_CLOCK_SHIFT;

	uint32 bit2 = pa51Cipher->lfsr2
			& A51_CIPHER_LFSR2_IRREGULAR_CLOCK_MASK
					>> A51_CIPHER_LFSR2_IRREGULAR_CLOCK_SHIFT;

	uint32 bit3 = pa51Cipher->lfsr3
			& A51_CIPHER_LFSR3_IRREGULAR_CLOCK_MASK
					>> A51_CIPHER_LFSR3_IRREGULAR_CLOCK_SHIFT;

	uint32 sum = bit1 + bit2 + bit3;

	uint32 majority = 0;

	if (sum >= 2) {
		majority = 1;
	}

	/*printf("bit1 = 0x%x\n", bit1);
	 printf("bit2 = 0x%x\n", bit2);
	 printf("bit3 = 0x%x\n\n", bit3);
	 printf("majority Bit is = 0x%x\n\n", majority);*/

	if ((bit1 != 0) == majority) {
		//printf("clock register one \n");
		clockRegisterOne(pa51Cipher, i, keyStream, keyStreamMask,
				keystreamLength);
	}
	if ((bit2 != 0) == majority) {
		//printf("clock register two \n");
		clockRegisterTwo(pa51Cipher, i, keyStream, keyStreamMask,
				keystreamLength);
	}
	if ((bit3 != 0) == majority) {
		//printf("clock register three \n");
		clockRegisterThree(pa51Cipher, i, keyStream, keyStreamMask,
				keystreamLength);
	}
}

void clockRegisterOne(struct A51Cipher* pa51Cipher, uint32 i, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength) {

	// Xor the feedback tap Bits 13,16,17,18
	uint32 xorSum = 0;
	xorSum += ((keyStream & keyStreamMask) >> i);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP0_MASK)
			>> A51_CIPHER_LFSR1_TAP0_SHIFT);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP1_MASK)
			>> A51_CIPHER_LFSR1_TAP1_SHIFT);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP2_MASK)
			>> A51_CIPHER_LFSR1_TAP2_SHIFT);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP3_MASK)
			>> A51_CIPHER_LFSR1_TAP3_SHIFT);

	xorSum = xorSum & ((uint32) 0x00000001);

	pa51Cipher->lfsr1 = pa51Cipher->lfsr1 << 1;
	pa51Cipher->lfsr1 = pa51Cipher->lfsr1 & ((uint32) 0xfffffffe);
	pa51Cipher->lfsr1 = pa51Cipher->lfsr1 | xorSum;
}

void clockRegisterTwo(struct A51Cipher* pa51Cipher, uint32 i, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength) {
	uint32 xorSum = 0;
	xorSum += ((keyStream & keyStreamMask) >> i);
	xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_TAP0_MASK)
			>> A51_CIPHER_LFSR2_TAP0_SHIFT);
	xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_TAP1_MASK)
			>> A51_CIPHER_LFSR2_TAP1_SHIFT);

	xorSum = xorSum & ((uint32) 0x00000001);

	pa51Cipher->lfsr2 = pa51Cipher->lfsr2 << 1;
	pa51Cipher->lfsr2 = pa51Cipher->lfsr2 & ((uint32) 0xfffffffe);
	pa51Cipher->lfsr2 = pa51Cipher->lfsr2 | xorSum;
}

void clockRegisterThree(struct A51Cipher* pa51Cipher, uint32 i,
		uint64 keyStream, uint64 keyStreamMask, uint32 keystreamLength) {
	uint32 xorSum = 0;
	xorSum += ((keyStream & keyStreamMask) >> i);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP0_MASK)
			>> A51_CIPHER_LFSR3_TAP0_SHIFT);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP1_MASK)
			>> A51_CIPHER_LFSR3_TAP1_SHIFT);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP2_MASK)
			>> A51_CIPHER_LFSR3_TAP2_SHIFT);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP3_MASK)
			>> A51_CIPHER_LFSR3_TAP3_SHIFT);

	xorSum = xorSum & ((uint32) 0x00000001);

	pa51Cipher->lfsr3 = pa51Cipher->lfsr3 << 1;
	pa51Cipher->lfsr3 = pa51Cipher->lfsr3 & ((uint32) 0xfffffffe);
	pa51Cipher->lfsr3 = pa51Cipher->lfsr3 | xorSum;
}

void encryptDataBits(struct A51Cipher* pa51Cipher, FILE* output_file) {
	uint32 i;
	for (i = 0; i < A51_CIPHER_KEY_STREAM_ARRAY_LENGTH; i++) {
		pa51Cipher->outputStream[i] = pa51Cipher->dataStream[i]
				^ pa51Cipher->keyStream[i];

		/*printf("dataStream[%d]=0x%x\n", i, pa51Cipher->dataStream[i]);
		 printf("keyStream[%d]=0x%x\n", i, pa51Cipher->keyStream[i]);
		 printf("outputStream[%d]=0x%x\n\n", i, pa51Cipher->outputStream[i]);*/

	}
}

uint8 readBits(uint8* pDataStream, uint16 numBits, FILE* inputFile,
		struct rwBitsData* prwBitsData) {
	uint8 tempByte;
	uint8 i;
	uint16 numBytesReq = (uint16)ceil((double)numBits / 8.0);
	uint16 numBytes = (uint16)ceil(((double)numBits - (double)prwBitsData->numBits) / 8.0);

	uint8 numBytesRead = fread(pDataStream, 1, numBytes, inputFile);
	if (numBytesRead > 0)
	{
		for (i = 0; i < numBytesReq; i++)
		{
			if(i < numBytesRead)
			{
				tempByte = pDataStream[i];
			}
			else
			{
				tempByte = 0;
				pDataStream[i] = 0;
		    }

			//printf("i:%02d, ip:0x%02x, ", i, pDataStream[i]);

			prwBitsData->tempByte = prwBitsData->tempByte >> (8 - prwBitsData->numBits);
			pDataStream[i] = pDataStream[i] << (prwBitsData->numBits);
			pDataStream[i] = pDataStream[i] | prwBitsData->tempByte;
			prwBitsData->tempByte = tempByte;

			if((numBits - (i*8))  < 8)
			{
			  if(i < numBytesRead)
			  {
			      prwBitsData->numBits = (numBits - (i*8));
			  }
			  else
			  {
				  prwBitsData->numBits = 0;
			  }

			  pDataStream[i] = pDataStream[i] & ((uint8)(0xFF) >> (numBits - (i*8)));
			}

			//printf("op:0x%02x, t:0x%02x; ", pDataStream[i], prwBitsData->tempByte);
		}

		//printf("\n0x%02x, nt:%02d\n", prwBitsData->tempByte, prwBitsData->numBits);
	}

	return numBytesRead;
}


uint8 writeBits(uint8* pDataStream, uint16 numBits, FILE* outputFile,
		struct rwBitsData* prwBitsData) {
	uint8 tempByte;
	uint8 i;
	uint16 numBytesGn = (uint16)ceil((double)numBits / 8.0);
	uint16 numBytesWrite = (uint16)floor(((double)numBits + (double)prwBitsData->numBits) / 8.0);

	for (i = 0; i < numBytesGn; i++)
	{
		//printf("i:%02d, ip:0x%02x, ", i, pDataStream[i]);
		tempByte = pDataStream[i];
		pDataStream[i] = pDataStream[i] << prwBitsData->numBits;
		prwBitsData->tempByte = prwBitsData->tempByte >> ((8 - prwBitsData->numBitsShortage) - prwBitsData->numBits);
		pDataStream[i] = pDataStream[i] | prwBitsData->tempByte;
		prwBitsData->tempByte = tempByte;
		prwBitsData->numBitsShortage = 0;

		if((numBits - (i*8))  < 8)
		{
		  if(i < numBytesWrite)
		  {
			  prwBitsData->numBits = 0;
		  }
		  else
		  {
			  prwBitsData->numBits = (numBits - (i*8));
			  prwBitsData->numBitsShortage = (8 - prwBitsData->numBits);
		  }
		}

		//printf("op:0x%02x, t:0x%02x; ", pDataStream[i], prwBitsData->tempByte);
	}

	//printf("\n0x%02x, nt:%02d, w:%02d\n", prwBitsData->tempByte, prwBitsData->numBits, numBytesWrite);
	//scanf("%c", &tempByte);

	fwrite(pDataStream, 1, numBytesWrite, outputFile);

	return numBytesWrite;
}
