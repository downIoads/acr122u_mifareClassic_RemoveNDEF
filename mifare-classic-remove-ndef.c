#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winscard.h>

typedef struct _SCARD_DUAL_HANDLE {
	SCARDCONTEXT hContext;	// resource manager context
	SCARDHANDLE hCard;		// smart card within that context
} SCARD_DUAL_HANDLE, * PSCARD_DUAL_HANDLE; // create object alias and pointer alias

// TODO: when is apdu below useful?
// disable timeout:
// BYTE APDU_Command[] = { 0xFF, 0x00, 0x41, 0xFF, 0x00 };


// TODO: how to get below as response?
// GetATR_14443_3 (ATR = Answer To Reset) gets information that identifies which kind of tag you are communicating with.
// In ACR122U API Manual check out 3.1 ATR Generation for more details.
// Card name map [-17:-12]:
//	0x00 0x01 == MIFARE Classic 1K
//	0x00 0x02 == MIFARE Classic 4K
//	0x00 0x03 == MIFARE Ultralight
//	0x00 0x26 == MIFARE Mini
//  0xF0 0x04 == Topaz and Jewel
//  0xF0 0x11 == FeliCa 212K
//  0xF0 0x12 == FeliCa 424K

// ---- Function declarations ----
void PrintHex(LPCBYTE pbData, DWORD cbData);
BOOL SendRecvReader(PSCARD_DUAL_HANDLE pHandle, const BYTE* pbData, const UINT16 cbData, BYTE* pbResult, UINT16* pcbResult);
BOOL OpenReader(LPCWSTR szReaderName, PSCARD_DUAL_HANDLE pHandle);
void CloseReader(PSCARD_DUAL_HANDLE pHandle);

int MFC_WriteToTag(const BYTE* msg, BYTE block, bool useKeyA, const BYTE* key);
int MFC_NDEFFormatTag();
int MFC_ResetTagToUninitialized();

int Ultralight_FastRead(int from, int to);
int Ultralight_WritePage(BYTE toPage, BYTE* data);
int Ultralight_ResetUserMemory();

bool isByteInArray(BYTE byteToCheck, const BYTE* myArray, int arraySize);
int disableBuzzer();
int GetUUID();
int GetATR_14443_3();

// ---- MFC related definitions ----

// MFC SECTOR BLOCKS
const BYTE sectorBlocks[16] = { 0x03, 0x07, 0x0B, 0x0F, 0x13, 0x17, 0x1B, 0x1F,
								0x23, 0x27, 0x2B, 0x2F, 0x33, 0x37, 0x3B, 0x3F };

// MFC KEYS
//		uninitialized default keys
const BYTE KEY_A_DEFAULT[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const BYTE KEY_B_DEFAULT[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

//		ndef-formatted default keys
const BYTE KEY_A_NDEF_SECTOR0[6] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
const BYTE KEY_B_NDEF_SECTOR0[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

const BYTE KEY_A_NDEF_SECTOR115[6] = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };	// 64 33 66 37 64 33 66 37 64 33 66 37
const BYTE KEY_B_NDEF_SECTOR115[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// MFC ACCESS BITS
//		uninitialized access bits
const BYTE ACCESS_BITS_UNINITALIZED[] = { 0xFF, 0x07, 0x80, 0x69 };
const BYTE ACCESS_BITS_NDEF_SECTOR0[] = { 0x78, 0x77, 0x88, 0xC1 };
const BYTE ACCESS_BITS_NDEF_SECTOR115[] = { 0x7F, 0x07, 0x88, 0x40 };

// ---- Ultralight (MF0UL1x) related definitions ----
const BYTE ultralight_userdataPages[] = { 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
const BYTE ultralight_otpPage[] = { 0x03 }; // OTP = one time programmable, careful with this page

// ---- Helper functions ----

// PrintHex prints bytes as hex
void PrintHex(LPCBYTE pbData, DWORD cbData) {
	for (DWORD i = 0; i < cbData; i++) {
		wprintf(L"%02x ", pbData[i]);
	}
	wprintf(L"\n");
}

// SendRecvReader is used to send commands to the reader
BOOL SendRecvReader(PSCARD_DUAL_HANDLE pHandle, const BYTE* pbData, const UINT16 cbData, BYTE* pbResult, UINT16* pcbResult) {
	BOOL status = FALSE;
	DWORD cbRecvLenght = *pcbResult;
	LONG scStatus;

	wprintf(L"> ");
	PrintHex(pbData, cbData);

	scStatus = SCardTransmit(pHandle->hCard, NULL, pbData, cbData, NULL, pbResult, &cbRecvLenght);
	if (scStatus == SCARD_S_SUCCESS) {
		*pcbResult = (UINT16)cbRecvLenght;

		wprintf(L"< ");
		PrintHex(pbResult, *pcbResult);

		status = TRUE;
	} else {
		wprintf(L"%08x\n", scStatus);
	}	

	return status;
}

// OpenReader starts communication with the reader
BOOL OpenReader(LPCWSTR szReaderName, PSCARD_DUAL_HANDLE pHandle) {
	BOOL status = FALSE;
	LONG scStatus;
	DWORD dwActiveProtocol;

	scStatus = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pHandle->hContext);
	if (scStatus == SCARD_S_SUCCESS) {
		scStatus = SCardConnect(pHandle->hContext, szReaderName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &pHandle->hCard, &dwActiveProtocol);
		if (scStatus == SCARD_S_SUCCESS) {
			status = TRUE;
		} else {
			SCardReleaseContext(pHandle->hContext);
		}
	}

	return status;
}

// CloseReader ends communication with the reader
void CloseReader(PSCARD_DUAL_HANDLE pHandle) {
	SCardDisconnect(pHandle->hCard, SCARD_LEAVE_CARD);
	SCardReleaseContext(pHandle->hContext);
}

// disableBuzzer disables the annoying beep sound of ACR122U
int disableBuzzer() {
	// define APDU to disable buzzer of acr122u (https://stackoverflow.com/a/41550221)
	BYTE escapeCode[] = { 0xFF, 0x00, 0x52, 0x00, 0x00 };
	DWORD cbRecvLength = 7;

	// connect to reader
	SCARD_DUAL_HANDLE dualHandle;
	if (OpenReader(L"ACS ACR122 0", &dualHandle)) {
		// send apdu
		int result = SCardControl(dualHandle.hCard, SCARD_CTL_CODE(3500), escapeCode, sizeof(escapeCode), NULL, 0, &cbRecvLength);

		if (result != SCARD_S_SUCCESS) {
			printf("Failed to send APDU to disable buzzer. Error code: %d\n", result);
			CloseReader(&dualHandle);
			return 1;
		}
		else {
			printf("Successfully disabled buzzer.\n"); // buzzer will be disabled until you disconnect the reader
			CloseReader(&dualHandle);
			return 0;
		}
	}
	else {
		printf("Failed to connect to the reader");
		return 1;
	}

}

// GetUUID returns the UUID of the tag.
int GetUUID() {
	// define APDU to get UUID
	BYTE APDU_Command[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
	BYTE Buffer[10];
	UINT16 cbBuffer = sizeof(Buffer);

	// connect to reader
	SCARD_DUAL_HANDLE dualHandle;
	if (OpenReader(L"ACS ACR122 0", &dualHandle)) {
		// send apdu
		bool success = SendRecvReader(&dualHandle, APDU_Command, sizeof(APDU_Command), Buffer, &cbBuffer);
		if (success) {
			if (cbBuffer < 2 || !((Buffer[cbBuffer - 2] == 0x90 && Buffer[cbBuffer - 1] == 0x00))) {
				CloseReader(&dualHandle);
				printf("Failed to execute APDU command.");
				return 1;
			}
			else {
				printf("Successfully got UUID:\n");
				for (UINT16 i = 0; i < cbBuffer - 2; i++) {
					printf("%02X ", Buffer[i]);
				}
				CloseReader(&dualHandle);
				return 0;
			}
		}
		else {
			CloseReader(&dualHandle);
			printf("Failed to transmit APDU command.");
			return 1;
		}
	}
	else {
		printf("Failed to connect to the reader.");
		return 1;
	}
}

// isByteInArray is a helper function for MFC to check whether a block is part of the block array myArray
bool isByteInArray(BYTE byteToCheck, const BYTE* myArray, int arraySize) {
	for (size_t i = 0; i < arraySize; i++) {
		if (myArray[i] == byteToCheck) {
			return true;
		}
	}
	return false;
}

// 06 77 77 71 02 80	90 00 respond of ntag 424 dna tt
// 06 75 77 81 02 80    90 00 respond of desfire ev3
// read iso 14443-4 (Structure of the ATS) to understand what this means
// GetATR_14443_3 returns the ATS of supported tags.
// E.g. Ntag 424 dna tt, desfire ev3 are supported
// E.g. not supported is stuff like ntag215/216, mifare classic, ultralight (they will return 6a 81 which means not supported)
int GetATR_14443_3() {

	// define APDU to get ATS
	BYTE APDU_Command[] = { 0xFF, 0xCA, 0x01, 0x00, 0x00 };
	BYTE Buffer[40];
	UINT16 cbBuffer = sizeof(Buffer);

	// connect to reader
	SCARD_DUAL_HANDLE dualHandle;
	if (OpenReader(L"ACS ACR122 0", &dualHandle)) {
		// send apdu
		bool success = SendRecvReader(&dualHandle, APDU_Command, sizeof(APDU_Command), Buffer, &cbBuffer);
		if (true) {
			if (cbBuffer < 2 || !((Buffer[cbBuffer - 2] == 0x90 && Buffer[cbBuffer - 1] == 0x00))) {
				printf("Failed to execute APDU command:\n");
				for (DWORD i = 0; i < cbBuffer; i++) {
					printf("%02X ", Buffer[i]);
				}
				CloseReader(&dualHandle);
				return 1;
			}
			else {
				printf("Successfully got ATS:\n");
				for (DWORD i = 0; i < cbBuffer; i++) {
					printf("%02X ", Buffer[i]);
				}
				CloseReader(&dualHandle);
				return 0;
			}
		}
		else {
			CloseReader(&dualHandle);
			printf("Failed to transmit APDU command.");
			return 1;
		}
	}
	else {
		printf("Failed to connect to the reader.");
		return 1;
	}
}

// ---- Mifare Classic ----

// MFC_WriteToTag is used to write to a Mifare Classic tag
int MFC_WriteToTag(const BYTE* msg, BYTE block, bool useKeyA, const BYTE* key) {

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
	} else {
		wprintf(L"Failed to find NFC reader.\n");
		return -1;
	}

	return 0;
}

// MFC_NDEFFormatTag is used to format an uninitialized Mifare Classic tag as NDEF
int MFC_NDEFFormatTag() {
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
		if (isByteInArray(i, sectorBlocks, 16)) {
			continue;
		}
		status = MFC_WriteToTag(i != 0x04 ? msgEmpty : msgNDEFBlock4, i, true, KEY_A_DEFAULT);	// msg, block, useKeyA?, key
		if (status != 0) {
			printf("error occured. aborting..");
			return -1;
		}
	}
	
	// 2. write blocks 0x01 and 0x02
	status = MFC_WriteToTag(msgNDEFBlock1, 0x01, true, KEY_A_DEFAULT);
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}
	status = MFC_WriteToTag(msgNDEFBlock2, 0x02, true, KEY_A_DEFAULT);
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}

	// 3. write new sector trailers that are not in sector 0
	for (BYTE i = 0x07; i < 0x40; ++i) {
		if (isByteInArray(i, sectorBlocks, 16)) {
			status = MFC_WriteToTag(msgNDEFSector115, i, true, KEY_A_DEFAULT);
			if (status != 0) {
				printf("error occured. aborting..");
				return -1;
			}
		}

	}

	// 4. write sector trailer of sector 0 (block 0x03)
	status = MFC_WriteToTag(msgNDEFSector0, 0x03, true, KEY_A_DEFAULT);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}


	return status;
}

// MFC_ResetTagToUninitialized is used to uninitialize an NDEF formatted Mifare Classic tag
int MFC_ResetTagToUninitialized() {
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

	// 1. reset all non-sector blocks that are not in sector 0 to all zeroes (using key A)
	for (BYTE i = 0x04; i < 0x40; ++i) {
		// skip sector blocks
		if (isByteInArray(i, sectorBlocks, 16)) {
			continue;
		}
		status = MFC_WriteToTag(msgEmpty, i, true, KEY_A_NDEF_SECTOR115);	// msg, block, useKeyA?, key
		if (status != 0) {
			printf("error occured. aborting..");
			return -1;
		}
	}
	
	// 2. reset blocks 0x01 and 0x02 to all zeroes (using key B)
	status = MFC_WriteToTag(msgEmpty, 0x01, false, KEY_B_NDEF_SECTOR0);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}
	status = MFC_WriteToTag(msgEmpty, 0x02, false, KEY_B_NDEF_SECTOR0);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}
	
	// 3. reset all trailer sectors that are not trailer sector 0 (using key B)
	for (BYTE i = 0x07; i < 0x40; ++i) {
		if (isByteInArray(i, sectorBlocks, 16)) {
			status = MFC_WriteToTag(msgSectorUninit, i, false, KEY_B_NDEF_SECTOR115);	// msg, block, useKeyA?, key
			if (status != 0) {
				printf("error occured. aborting..");
				return -1;
			}
		}

	}

	// 4. reset trailer sector 0 (block 0x03) (using key B)
	status = MFC_WriteToTag(msgSectorUninit, 0x03, false, KEY_B_NDEF_SECTOR0);	// msg, block, useKeyA?, key
	if (status != 0) {
		printf("error occured. aborting..");
		return -1;
	}


	return status;
}

// ---- Ultralight EV 1 ----

// Ultralight_FastRead reads the specified pages that contain user memory.
int Ultralight_FastRead(int from, int to) {
	// ensure from and to are not too small and too big, also ensure from <= to
	if ((from < ultralight_userdataPages[0]) || (to > ultralight_userdataPages[sizeof(ultralight_userdataPages) / sizeof(ultralight_userdataPages[0]) - 1]) || (to < from) ) {
		wprintf(L"Invalid page range.\n");
		return 1;
	}

	// PN532 can only transfer 256 bytes at once but this is not a problem because ultralight has way less user memory
	// buffer 130 will be good enough if you only read user memory
	
	const BYTE APDU_Read[] = { 0xff, 0x00, 0x00, 0x00, 0x05, 0xd4, 0x42, 0x3a, from, to };
	UINT16 apduReadLength = sizeof(APDU_Read) / sizeof(APDU_Read[0]);

	SCARD_DUAL_HANDLE hDual;
	BYTE Buffer[130];
	UINT16 cbBuffer = sizeof(Buffer);

	// my Laptop:	"ACS ACR122U PICC Interface 0"
	// my PC:		"ACS ACR122 0"
	if (OpenReader(L"ACS ACR122 0", &hDual)) {
		if (SendRecvReader(&hDual, APDU_Read, apduReadLength, Buffer, &cbBuffer)) {
			// check for success (success code is stored after the data read, so read the last two bytes of the buffer)
			if (!(Buffer[cbBuffer - 2] == 0x90 && Buffer[cbBuffer - 1] == 0x00)) {
				wprintf(L"Error code received. Aborting..\n");
				CloseReader(&hDual);
				return 1;
			} else {
				wprintf(L"Successful FastRead:\n");
				for (DWORD i = 3; i < cbBuffer-2; i++) {
					printf("%02X ", Buffer[i]);
					// linebreak every 4 bytes to better represent the pages
					if ((i - 2) % 4 == 0) {
						printf("\n");
					}
				}
				CloseReader(&hDual);
			}
		} else {
			wprintf(L"Failed to read pages.\n");
			CloseReader(&hDual);
			return 1;
		}
	} else {
		wprintf(L"Failed to find NFC reader.\n");
		return 1;
	}

	return 0;
}

// Ultralight_WritePage takes a page number and a ptr to a 4 byte array and writes that data to a user memory page of Ultralight.
int Ultralight_WritePage(BYTE to, BYTE* data) {
	// only write to user memory
	if ((to < ultralight_userdataPages[0]) || (to > ultralight_userdataPages[sizeof(ultralight_userdataPages) / sizeof(ultralight_userdataPages[0]) - 1])) {
		wprintf(L"Invalid page range.\n");
		return 1;
	}

	BYTE APDU_Write[9 + 4] = { 0xff, 0x00, 0x00, 0x00, 0x08, 0xd4, 0x42, 0xa2, to };
	memcpy_s(APDU_Write + 9, 4, data, 4);

	SCARD_DUAL_HANDLE hDual;
	BYTE Buffer[5];
	UINT16 cbBuffer = sizeof(Buffer);

	if (OpenReader(L"ACS ACR122 0", &hDual)) {
		cbBuffer = 5; // 5 byte reply expected
		if (SendRecvReader(&hDual, APDU_Write, 13, Buffer, &cbBuffer)) {
			// check for success (success code is stored after the data read, so read the last two bytes of the buffer)
			if (!(Buffer[3] == 0x90 && Buffer[4] == 0x00)) {
				wprintf(L"Error code received. Aborting..\n");
				CloseReader(&hDual);
				return 1;
			} else {
				wprintf(L"Successful Write!\n");
				CloseReader(&hDual);
			}
		} else {
			wprintf(L"Failed to write to page.\n");
			CloseReader(&hDual);
			return 1;
		}
	} else {
		wprintf(L"Failed to find NFC reader.\n");
		return 1;
	}

	return 0;

}

// Ultralight_ResetUserMemory writes zeroes to all pages in [0x04, 0x0F].
int Ultralight_ResetUserMemory() {
	BYTE Zeroes[4] = { 0x00, 0x00, 0x00, 0x00 };
	int status;

	for (int i = 0x04; i < 0x0F; ++i) {
		status = Ultralight_WritePage(i, &Zeroes);
		if (status != 0) {
			printf("Error occured! Aborting..\n");
			return 1;
		}
	}

	printf("\nSuccessfully reset user memory to zeroes.\n");
	return 0;
}

int main() {
	// Note: program has to be started only after an nfc chip is already near the reader!
	int status = 1;

	//status = disableBuzzer();
	//status = GetUUID();
	//status = GetATR_14443_3();
	//status = Ultralight_FastRead(0x04, 0x0F);

	//BYTE Msg[4] = { 0x01, 0x03, 0x05, 0x07 };
	//status = Ultralight_WritePage(0x05, &Msg);

	//status = Ultralight_ResetUserMemory();

	// ---- MFC stuff ----
	// Unintialize tag
		 /*
	status = MFC_ResetTagToUninitialized();
	if (status == 0) {
		printf("\nSUCCESS. Tag is now uninitialized.");
	}
		*/

	// NDEF-format tag
		/*
	status = MFC_NDEFFormatTag();
	if (status == 0) {
		printf("\nSUCCESS. Tag is now NDEF-formatted.");
	}
		*/
	// ---- End of MFC stuff ----


	return status;
}
