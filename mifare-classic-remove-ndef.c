#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winscard.h>

typedef struct _SCARD_DUAL_HANDLE {
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
} SCARD_DUAL_HANDLE, * PSCARD_DUAL_HANDLE;


const BYTE sectorBlocks[16] = { 0x03, 0x07, 0x0B, 0x0F, 0x13, 0x17, 0x1B, 0x1F,
								0x23, 0x27, 0x2B, 0x2F, 0x33, 0x37, 0x3B, 0x3F };

// KEYS
// uninitialized default keys
const BYTE KEY_A_DEFAULT[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const BYTE KEY_B_DEFAULT[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ndef-formatted default keys
const BYTE KEY_A_NDEF_SECTOR0[6] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
const BYTE KEY_B_NDEF_SECTOR0[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

const BYTE KEY_A_NDEF_SECTOR115[6] = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };	// 64 33 66 37 64 33 66 37 64 33 66 37
const BYTE KEY_B_NDEF_SECTOR115[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// ACCESS BITS
// uninitialized access bits
const BYTE ACCESS_BITS_UNINITALIZED[] = { 0xFF, 0x07, 0x80, 0x69 };
const BYTE ACCESS_BITS_NDEF_SECTOR0[] = { 0x78, 0x77, 0x88, 0xC1 };
const BYTE ACCESS_BITS_NDEF_SECTOR115[] = { 0x7F, 0x07, 0x88, 0x40 };

bool isByteInSectorBlocks(BYTE byteToCheck, const BYTE* sectorBlocks) {
	for (size_t i = 0; i < 16; i++) {
		if (sectorBlocks[i] == byteToCheck) {
			return true;
		}
	}
	return false;
}

void PrintHex(LPCBYTE pbData, DWORD cbData)
{
	for (DWORD i = 0; i < cbData; i++) {
		wprintf(L"%02x ", pbData[i]);
	}
	wprintf(L"\n");
}

BOOL SendRecvReader(PSCARD_DUAL_HANDLE pHandle, const BYTE* pbData, const UINT16 cbData, BYTE* pbResult, UINT16* pcbResult)
{
	BOOL status = FALSE;
	DWORD cbRecvLenght = *pcbResult;
	LONG scStatus;

	wprintf(L"> ");
	PrintHex(pbData, cbData);

	scStatus = SCardTransmit(pHandle->hCard, NULL, pbData, cbData, NULL, pbResult, &cbRecvLenght);
	if (scStatus == SCARD_S_SUCCESS)
	{
		*pcbResult = (UINT16)cbRecvLenght;

		wprintf(L"< ");
		PrintHex(pbResult, *pcbResult);

		status = TRUE;
	}
	else wprintf(L"%08x\n", scStatus);

	return status;
}

BOOL OpenReader(LPCWSTR szReaderName, PSCARD_DUAL_HANDLE pHandle)
{
	BOOL status = FALSE;
	LONG scStatus;
	DWORD dwActiveProtocol;

	scStatus = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pHandle->hContext);
	if (scStatus == SCARD_S_SUCCESS)
	{
		scStatus = SCardConnect(pHandle->hContext, szReaderName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &pHandle->hCard, &dwActiveProtocol);
		if (scStatus == SCARD_S_SUCCESS)
		{
			status = TRUE;
		}
		else
		{
			SCardReleaseContext(pHandle->hContext);
		}
	}

	return status;
}

void CloseReader(PSCARD_DUAL_HANDLE pHandle)
{
	SCardDisconnect(pHandle->hCard, SCARD_LEAVE_CARD);
	SCardReleaseContext(pHandle->hContext);
}

// what, were, how, prove you are allowed
int WriteToTag(const BYTE* msg, BYTE block, bool useKeyA, const BYTE* key) {

	// 1. Load authentication key
	const BYTE APDU_LoadDefaultKey[5 + 6] = { 0xff, 0x82, 0x00, 0x00, 0x06};	// base command 5 bytes + 16 byte key
	memcpy(APDU_LoadDefaultKey + 5, key, 6);	// append key to APDU_LoadDefaultKey (6 bytes a 2 hex digits = 12 chars)

	// 2. Authentication
	const BYTE APDU_Authenticate_Block[10] = { 0xff, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, useKeyA ? 0x60 : 0x61, 0x00 };	// 0x60 for key A, 0x61 for key B

	// 3. Write
	BYTE APDU_Write[5 + 16] = { 0xff, 0xd6, 0x00, block, 0x10 };				// base command 5 bytes + 16 byte message
	memcpy(APDU_Write + 5, msg, 16); // append msg to APDU_Write

	SCARD_DUAL_HANDLE hDual;
	BYTE Buffer[32];
	UINT16 cbBuffer;	// usually will be 2 bytes (e.g. response 90 00 for success)

	/*
	// debug prints
	printf("\nDebug, this is my APDU_LoadDefaultKey:\n");
	for (UINT16 i = 0; i < 11; ++i) {		// first few chars are not part of message that will be written so skip printing them
		printf("0x%02X ", APDU_LoadDefaultKey[i]);
	}
	printf("\n\nDebug, this is my APDU_Authenticate_Block:\n");
	for (UINT16 i = 0; i < 10; ++i) {		// first few chars are not part of message that will be written so skip printing them
		printf("0x%02X ", APDU_Authenticate_Block[i]);
	}
	printf("\n\nDebug, this is my APDU_Write:\n");
	for (UINT16 i = 0; i < 21; ++i) {		// first few chars are not part of message that will be written so skip printing them
		printf("0x%02X ", APDU_Write[i]);
	}
	printf("\n\n");
	*/


	// ---- Connect to tag ----

	// my Laptop:	"ACS ACR122U PICC Interface 0"
	// my PC:		"ACS ACR122 0"
	if (OpenReader(L"ACS ACR122 0", &hDual))
	{

		cbBuffer = 2;
		SendRecvReader(&hDual, APDU_LoadDefaultKey, sizeof(APDU_LoadDefaultKey), Buffer, &cbBuffer);
		if (!(Buffer[0] == 0x90 && Buffer[1] == 0x00)) {
			CloseReader(&hDual);
			wprintf(L"Failed to load default key. Aborting..\n");
			return 1;
		}
		wprintf(L"Successfully loaded default Key %s\n", useKeyA ? L"A" : L"B");


		cbBuffer = 2;
		SendRecvReader(&hDual, APDU_Authenticate_Block, sizeof(APDU_Authenticate_Block), Buffer, &cbBuffer);
		if (!(Buffer[0] == 0x90 && Buffer[1] == 0x00)) {
			CloseReader(&hDual);
			wprintf(L"Failed to authenticate. Aborting..\n");
			return 1;
		}
		wprintf(L"Successfully authenticated the sector of block 0x%02X\n", block);


		cbBuffer = 2;
		SendRecvReader(&hDual, APDU_Write, 21, Buffer, &cbBuffer);	// 5+16 write = 21 bytes APDU
		if (!(Buffer[0] == 0x90 && Buffer[1] == 0x00)) {
			CloseReader(&hDual);
			wprintf(L"Failed to write data. Aborting..\n");
			return 1;
		}
		wprintf(L"Successfully wrote data to block 0x%02X\n", block);



		CloseReader(&hDual);
	}
	else {
		wprintf(L"Failed to find NFC reader.\n");
		return -1;
	}

	return 0;
}

int NDEFFormatTag() {
	// messages
	const BYTE msgNDEFSector115[16] =	{ 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7,     0x7F, 0x07, 0x88, 0x40,     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	const BYTE msgNDEFSector0[16] =		{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,     0x78, 0x77, 0x88, 0xC1,     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	const BYTE msgNDEFBlock1[16] =		{ 0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };
	const BYTE msgNDEFBlock2[16] =		{ 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };
	const BYTE msgNDEFBlock4[16] =		{ 0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const BYTE msgEmpty[16] =			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


	// 1. reset all non-sector blocks that are not in sector 0 to all zeroes (using key A)
	int status = -1;
	for (BYTE i = 0x01; i < 0x40; ++i) {
		// skip sector blocks
		if (isByteInSectorBlocks(i, sectorBlocks)) {
			continue;
		}
		status = WriteToTag(i != 0x04 ? msgEmpty : msgNDEFBlock4, i, true, KEY_A_DEFAULT);	// msg, block, useKeyA?, key
		if (status != 0) {
			printf("error occured. aborting..");
			return -1;
		}
	}
	
	// 2. write blocks 0x01 and 0x02
	status = WriteToTag(msgNDEFBlock1, 0x01, true, KEY_A_DEFAULT);
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}
	status = WriteToTag(msgNDEFBlock2, 0x02, true, KEY_A_DEFAULT);
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}

	// 3. write new sector trailers that are not in sector 0
	for (BYTE i = 0x07; i < 0x40; ++i) {
		if (isByteInSectorBlocks(i, sectorBlocks)) {
			status = WriteToTag(msgNDEFSector115, i, true, KEY_A_DEFAULT);
			if (status != 0) {
				printf("error occured. aborting..");
				return -1;
			}
		}

	}

	// 4. write sector trailer of sector 0 (block 0x03)
	status = WriteToTag(msgNDEFSector0, 0x03, true, KEY_A_DEFAULT);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}


	return status;
}


int ResetTagToUninitialized() {
	
	// msg is the data you want to write on the tag, must be 16 bytes
	const BYTE msgSectorUninit[16] =	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	const BYTE msgEmpty[16] =	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// block is the block you want to write to, first valid value is 0x01 (no magic tag) and last valid for 1k tag is 0x3F
	BYTE block = 0x04;
	if (block < 0x01 || block > 0x3F) {
		printf("invalid block");
		return -1;
	}

	int status = -1;

	// you can authenticate with key A or B, which one required can depend on state of state. pass true for keyA and false for keyB
	// as authentication key always pass one of the pre-defined keys


	//int status = WriteToTag(msg, block, false, KEY_B_DEFAULT);

	// 1. reset all non-sector blocks that are not in sector 0 to all zeroes (using key A)
	for (BYTE i = 0x04; i < 0x40; ++i) {
		// skip sector blocks
		if (isByteInSectorBlocks(i, sectorBlocks)) {
			continue;
		}
		status = WriteToTag(msgEmpty, i, true, KEY_A_NDEF_SECTOR115);	// msg, block, useKeyA?, key
		if (status != 0) {
			printf("error occured. aborting..");
			return -1;
		}
	}
	
	// 2. reset blocks 0x01 and 0x02 to all zeroes (using key B)
	status = WriteToTag(msgEmpty, 0x01, false, KEY_B_NDEF_SECTOR0);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}
	status = WriteToTag(msgEmpty, 0x02, false, KEY_B_NDEF_SECTOR0);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}
	

	// 3. reset all trailer sectors that are not trailer sector 0 (using key B)
	for (BYTE i = 0x07; i < 0x40; ++i) {
		if (isByteInSectorBlocks(i, sectorBlocks)) {
			status = WriteToTag(msgSectorUninit, i, false, KEY_B_NDEF_SECTOR115);	// msg, block, useKeyA?, key
			if (status != 0) {
				printf("error occured. aborting..");
				return -1;
			}
		}

	}

	// 4. reset trailer sector 0 (block 0x03) (using key B)
	status = WriteToTag(msgSectorUninit, 0x03, false, KEY_B_NDEF_SECTOR0);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}


	return status;
}

int main() {
	// Unintialize tag
	/*
	int status = ResetTagToUninitialized();
	if (status == 0) {
		printf("\nSUCCESS. Tag is now uninitialized.");
	}
	*/

	// NDEF-format tag
	// /*
	int status = NDEFFormatTag();
	if (status == 0) {
		printf("\nSUCCESS. Tag is now NDEF-formatted.");
	}
	// */

	return status;
}
