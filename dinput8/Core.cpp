#include "Core.h"

CCore* Core;
CItemRandomiser *ItemRandomiser;
CAutoEquip *AutoEquip;
SCore* CoreStruct;

DWORD64 qItemEquipComms = 0;

DWORD64 rItemRandomiser = 0;
DWORD64 rAutoEquip = 0;
DWORD64 rNoWeaponRequirements = 0;
DWORD64 rEquipLock = 0;

LPVOID dummyCodeCave;
LPVOID itemGibCodeCave;
LPVOID itemGibDataCodeCave;


BYTE DummyShellcode[] =
{
	0xb8,                   // move the following value to EAX:
	0x05, 0x00, 0x00, 0x00, // 5					
	0xc3                    // return what's currently in EAX
};


BYTE ItemGibShellcode[] =
{
	0x48, 0x83, 0xEC, 0x48,                  
	0x44, 0x8D, 0x44, 0x24, 0x20,
	0x48, 0x8D, 0x54, 0x24, 0x30,
	0xA1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x8B, 0x1C, 0x25, 0xFF, 0xFF, 0xFF, 0xFF,
	0x8B, 0x34, 0x25, 0xFF, 0xFF, 0xFF, 0xFF,
	0xC7, 0x02, 0x01, 0x00, 0x00, 0x00,
	0x89, 0x72, 0x0C,
	0x41, 0x89, 0x58, 0x14,
	0x41, 0x89, 0x40, 0x18,
	0x48, 0xA1, 0x78, 0x8E, 0x76, 0x44, 0x01, 0x00, 0x00, 0x00,
	0x48, 0x8B, 0xA8, 0x80, 0x00, 0x00, 0x00,
	0x48, 0x8B, 0x1D, 0xB2, 0x22, 0x77, 0x04,
	0x48, 0x8B, 0xCB,
	0xE8, 0x1A, 0xBA, 0x7D, 0x00,
	0x48, 0x83, 0xC4, 0x48,
	0xC3
};

BYTE ItemGibDataShellcode[] =
{
	0x01, 0x00,
	0x00, 0x00,
	0xF4,
	0x01, 0x00,
	0x40, 0xFF,
	0xFF,
	0xFF,
	0xFF, 0x00
};

VOID CCore::Start() {

	Core = new CCore();
	CoreStruct = new SCore();
	ItemRandomiser = new CItemRandomiser();
	AutoEquip = new CAutoEquip();

	Core->DebugInit();

	CoreStruct->hHeap = HeapCreate(8, 0x10000, 0);
	if (!CoreStruct->hHeap) {
		Core->Panic("Unable to allocate appropriate heap", "...\\Randomiser\\Core\\Core.cpp", FE_MemError, 1);
		int3
	};

	if (!Core->Initialise()){
		Core->Panic("Failed to initialise", "...\\Randomiser\\Core\\Core.cpp", FE_InitFailed, 1);
		int3
	};

	while (true) {
		Core->Run();
		Sleep(2500);
	};

	if (!HeapFree(CoreStruct->hHeap, 8, CoreStruct->pItemArray)) {
		Core->Panic("Given memory block appears invalid, or freed already", "...\\Randomiser\\Core\\Core.cpp", FE_InitFailed, 1);
		int3
	};

	HeapDestroy(CoreStruct->hHeap);

	delete AutoEquip;
	delete ItemRandomiser;
	delete CoreStruct;
	delete Core;

	return;
};

VOID CCore::Run() {

	if ((CoreStruct->dIsAutoSave) && CoreStruct->dIsListChanged) {
		Core->SaveArrayList();
		CoreStruct->dIsListChanged--;
	};

	if (CoreStruct->dIsMessageActive) {
		DisplayInfoMsg();
	};

	return;
};


LPVOID CCore::InjectShellCode(BYTE* shellCode, size_t len) {
	LPVOID pCodeCave = VirtualAlloc(nullptr, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pCodeCave) {
		Core->Panic("VirtualAlloc failed", "...\\Randomiser\\Core\\Core.cpp", FE_MemError, 1);
		int3
	}

	// copy the machine code into that memory:
	std::memcpy(pCodeCave, shellCode, len);

	// mark the memory as executable:
	DWORD dummy;
	VirtualProtect(pCodeCave, len, PAGE_EXECUTE_READ, &dummy);

	return pCodeCave;
}

LPVOID CCore::InjectShellCodeAtAddress(LPVOID address, BYTE* shellCode, size_t len) {
	LPVOID pCodeCave = VirtualAlloc(address, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pCodeCave) {
		Core->Panic("VirtualAlloc failed", "...\\Randomiser\\Core\\Core.cpp", FE_MemError, 1);
		int3
	}

	// copy the machine code into that memory:
	std::memcpy(pCodeCave, shellCode, len);

	// mark the memory as executable:
	DWORD dummy;
	VirtualProtect(pCodeCave, len, PAGE_EXECUTE_READ, &dummy);

	return pCodeCave;
}

BOOL CCore::Initialise() {

	int i = 0;
	char pBuffer[MAX_PATH];
	BOOL bReturn = true;
	INIReader reader("RandomiserPreferences.ini");

	if (reader.ParseError() == -1) {
		MessageBoxA(NULL, "Failed to find 'RandomiserPreferences.ini'.", "Load Error", MB_ICONWARNING);
		int3
	};

	if (MH_Initialize() != MH_OK) return false;

	CoreStruct->dIsAutoSave = reader.GetBoolean("Randomiser", "SaveProgress", true);
	CoreStruct->dRandomsieHealItems = reader.GetBoolean("Randomiser", "RandomiseHeals", true);
	CoreStruct->dRandomiseKeyItems = reader.GetBoolean("Randomiser", "RandomiseKeys ", false);
	CoreStruct->dIsMessageActive = reader.GetBoolean("Randomiser", "RandomiserMessage", true);
	CoreStruct->dIsAutoEquip = reader.GetBoolean("AutoEquip", "AutoEquipToggle", true);
	CoreStruct->dLockEquipSlots = reader.GetBoolean("AutoEquip", "LockEquipSlots", false);
	CoreStruct->dIsNoWeaponRequirements = reader.GetBoolean("AutoEquip", "NoWeaponRequirements", false);

	CoreStruct->pOffsetArray = (DWORD*)HeapAlloc(CoreStruct->hHeap, 8, 0x3000);
	CoreStruct->pItemArray = (DWORD*)HeapAlloc(CoreStruct->hHeap, 8, 0x3000);

	if ((!CoreStruct->pItemArray) || (!CoreStruct->pOffsetArray)) {
		Core->Panic("Out of memory", "...\\Randomiser\\Core\\Core.cpp", FE_MemError, 1);
		int3
	};

	dummyCodeCave = InjectShellCode(DummyShellcode, 6);
	std::cout << "dummyCodeCave address : " << dummyCodeCave << "\n";

	itemGibDataCodeCave = InjectShellCode(ItemGibDataShellcode, 13);
	std::cout << "itemGibDataCodeCave address : " << itemGibDataCodeCave << "\n";
	

	char* itemGibDataAddressArray = (char*)malloc(sizeof(void*));
	Core->ConvertToLittleEndianByteArray((uintptr_t)itemGibDataCodeCave, itemGibDataAddressArray);
	memcpy(ItemGibShellcode + 15, itemGibDataAddressArray, sizeof(void*));

	char* itemGibDataAddressArrayPlus4 = (char*)malloc(sizeof(void*));
	Core->ConvertToLittleEndianByteArray((uintptr_t)itemGibDataCodeCave + 4, itemGibDataAddressArrayPlus4);
	memcpy(ItemGibShellcode + 26, itemGibDataAddressArrayPlus4, 4);

	char* itemGibDataAddressArrayPlus8 = (char*)malloc(sizeof(void*));
	Core->ConvertToLittleEndianByteArray((uintptr_t)itemGibDataCodeCave + 8, itemGibDataAddressArrayPlus8);
	memcpy(ItemGibShellcode + 33, itemGibDataAddressArrayPlus8, 4);

	itemGibCodeCave = InjectShellCodeAtAddress((LPVOID)0x13ffe0000, ItemGibShellcode, 91);
	std::cout << "itemGibCodeCave address : " << itemGibCodeCave << "\n";
	

#ifdef DEBUG
	sprintf_s(pBuffer, "[Randomiser] - SaveProgress = %i\n", CoreStruct->dIsAutoSave);
	printf_s(pBuffer);
	sprintf_s(pBuffer, "[Randomiser] - RandomiseHeals = %i\n", CoreStruct->dRandomsieHealItems);
	printf_s(pBuffer);
	sprintf_s(pBuffer, "[Randomiser] - RandomiseKeys = %i\n", CoreStruct->dRandomiseKeyItems);
	printf_s(pBuffer);
	sprintf_s(pBuffer, "[Randomiser] - RandomsierMessage = %i\n", CoreStruct->dIsMessageActive);
	printf_s(pBuffer);
	sprintf_s(pBuffer, "[AutoEquip] - AutoEquipToggle = %i\n", CoreStruct->dIsAutoEquip);
	printf_s(pBuffer);
	sprintf_s(pBuffer, "[AutoEquip] - LockEquipSlots = %i\n", CoreStruct->dLockEquipSlots);
	printf_s(pBuffer);
	sprintf_s(pBuffer, "[AutoEquip] - NoWeaponRequirements = %i\n", CoreStruct->dIsNoWeaponRequirements);
	printf_s(pBuffer);
#endif

	GetArrayList();

	while (!CoreStruct->pOffsetArray[i+1]) {
		if (CoreStruct->pOffsetArray[0] == i) break;
		CoreStruct->pItemArray[0]++;
		i++;
	}; 

	if (CoreStruct->dLockEquipSlots) {
		LockEquipSlots();
	};

	bReturn &= Hook(0x1407BBA80, (DWORD64)&tItemRandomiser, &rItemRandomiser, 5);

	if (CoreStruct->dIsAutoEquip) bReturn &= Hook(0x1407BBE92, (DWORD64)&tAutoEquip, &rAutoEquip, 6);
	if (CoreStruct->dIsNoWeaponRequirements) bReturn &= Hook(0x140C073B9, (DWORD64)&tNoWeaponRequirements, &rNoWeaponRequirements, 7);

	//bReturn &= Hook(0x13ffe0000, (DWORD64)&tItemGib, &rItemGib, 8);

	AutoEquip->EquipItem = (fEquipItem*)0x140AFBBB0;
	Core->DisplayGraveMessage = (fDisplayGraveMessage*)0x140BE1990;

	return bReturn;
};

BOOL CCore::GetArrayList() {

	DWORD i = 0;

	std::ifstream readfileA("DS3RandomAoB.txt");
	std::ifstream readfileB("DS3ItemAoB.txt");

	DWORD* pOffsetList = CoreStruct->pOffsetArray;
	DWORD* pItemList = CoreStruct->pItemArray;

	if (readfileA.is_open()) {

		readfileA >> pOffsetList[0];
		i++;

		while (i <= *pOffsetList) {
			readfileA >> pOffsetList[i];
			i++;
		};
		readfileA.close();

	}
	else MessageBoxA(NULL, "Failed to find 'DS3RandomAoB.txt'", "Load Error", MB_ICONWARNING);

	i = 1;

	if (readfileB.is_open()) {

		while (i <= *pOffsetList) {
			readfileB >> std::hex >> pItemList[i];
			i++;
		};
		readfileB.close();
		return true;
	};

	MessageBoxA(NULL, "Failed to find 'DS3ItemAoB.txt'", "Load Error", MB_ICONWARNING);

	return false;
};

BOOL CCore::SaveArrayList() {

	DWORD i = 0;

	std::ofstream outfile("DS3RandomAoB.txt");

	DWORD* pOffsetList = CoreStruct->pOffsetArray;
	DWORD* pItemList = CoreStruct->pItemArray;

	if (outfile.is_open()) {

		while (i <= *pOffsetList) {
			outfile << pOffsetList[i] << std::endl;
			i++;
		};
		outfile.close();
		return true;
	};

	CoreStruct->dIsAutoSave = 0;
	MessageBoxA(NULL, "Failed to find 'DS3RandomAoB.txt'", "Save Error", MB_ICONWARNING);


	return false;

};

BOOL CCore::Hook(DWORD64 qAddress, DWORD64 qDetour, DWORD64* pReturn, DWORD dByteLen) {

	if (MH_CreateHook((LPVOID)qAddress, (LPVOID)qDetour, 0) != MH_OK) return false;
	if (MH_EnableHook((LPVOID)qAddress) != MH_OK) return false;

	*pReturn = (qAddress + dByteLen);

	return true;
};

VOID CCore::Panic(char* pMessage, char* pSort, DWORD dError, DWORD dIsFatalError) {

	char pOutput[MAX_PATH];
	char pTitle[MAX_PATH];

	sprintf_s(pOutput, "%s -> %s (%i)", pSort, pMessage, dError);

	if (IsDebuggerPresent()) {
		OutputDebugStringA(pOutput);
	};

	if (CoreStruct->dIsDebug) {
		printf_s("CCore::Panic is outputting debug-mode error information\n");
		sprintf_s(pOutput, "%s\n", pOutput);
		printf_s(pOutput);
	}
	else {
		if (dIsFatalError){
			sprintf_s(pTitle, "[Item Randomiser - Fatal Error]");
		} 
		else {
			sprintf_s(pTitle, "[Item Randomiser - Error]");
		}; 
		
		MessageBoxA(NULL, pOutput, pTitle, MB_ICONERROR);
	};

	if (dIsFatalError) *(int*)0 = 0;

	return;
};

VOID CCore::DisplayInfoMsg() {
	/*
	UINT_PTR qLuaEvent = 0;
	UINT_PTR qWorldChrMan = 0;

	qLuaEvent = *(UINT_PTR*)CoreStruct->qSprjLuaEvent;
	if (!qLuaEvent) return;

	qWorldChrMan = *(UINT_PTR*)CoreStruct->qWorldChrMan;
	if (!qWorldChrMan) return;
	qWorldChrMan = *(UINT_PTR*)(qWorldChrMan + 0x80);
	if (!qWorldChrMan) return;

	if (!Core->DisplayGraveMessage) {
		Core->Panic("Bad function call", "...\\Source\\Core\\Core.cpp", FE_BadFunc, 1);
		int3
	};

	Core->DisplayGraveMessage(0x33333333);
	*/
	CoreStruct->dIsMessageActive = 0;

	return;
};

VOID CCore::LockEquipSlots() {

	DWORD dOldProtect = 0;
	DWORD64 qEquip = 0x140B70F45;
	DWORD64 qUnequip = 0x140B736EA;

	if (!VirtualProtect((LPVOID)qEquip, 1, PAGE_EXECUTE_READWRITE, &dOldProtect)) return;
	if (!VirtualProtect((LPVOID)qUnequip, 1, PAGE_EXECUTE_READWRITE, &dOldProtect)) return;

	*(BYTE*)qEquip = 0x30;
	*(BYTE*)qUnequip = 0x30;

	if (!VirtualProtect((LPVOID)qEquip, 1, dOldProtect, &dOldProtect)) return;
	if (!VirtualProtect((LPVOID)qUnequip, 1, dOldProtect, &dOldProtect)) return;

	return;
};

VOID CCore::DebugInit() {
	CoreStruct->dIsDebug = 0;
#ifdef DEBUG
	FILE* fp;
	
	AllocConsole();
	SetConsoleTitleA("Dark Souls III - Item Randomiser Debug Console");
	freopen_s(&fp, "CONOUT$", "w", stdout);
	freopen_s(&fp, "CONIN$", "r", stdin);
	printf_s("Starting DS3 ...\n");

	CoreStruct->dIsDebug = 1;
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Core->InputCommand, NULL, NULL, NULL);

#endif

	return;
};

VOID CCore::InputCommand() {
	while (true) {
		char line[50];
		scanf(" %s[^\n]", line);
		
		if (strstr(line, "/itemGib")) {
			std::cout << "/itemGib executed" << "\n";
			typedef int func(void);
			func* f = (func*)0x13ffe0000;
			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)f, NULL, NULL, NULL);
		}

		if (strstr(line, "/kill")) {

			std::cout << "/kill executed" << "\n";
			DWORD processId = GetCurrentProcessId();
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

			std::vector<unsigned int> offsets = { 0x80, 0x1F90, 0x18, 0xD8 };
			uintptr_t hpAddr = Core->FindExecutableAddress(0x4768E78, offsets); //BaseB + HP Offsets
			std::cout << "hpAddr hex : " << std::hex << hpAddr << "\n";	
			
			int hp = 0;
			ReadProcessMemory(hProcess, (BYTE*)hpAddr, &hp, sizeof(hp), nullptr);
			std::cout << "hp : " << hp << "\n";

			int newHp = 0;
			WriteProcessMemory(hProcess, (BYTE*)hpAddr, &newHp, sizeof(newHp), nullptr);

		}

		if (strstr(line, "/dummy")) {

			std::cout << "/dummy executed" << "\n";
			auto const function_ptr_kill = reinterpret_cast<std::int32_t(*)()>(dummyCodeCave);
			auto const result = function_ptr_kill();
			std::cout << result << "\n";


		}
	}
};

//-------------------------------------------------------------------------
uintptr_t CCore::GetModuleBaseAddress() {
	LPSTR lpModuleName = "DarkSoulsIII.exe";
	DWORD procId = GetCurrentProcessId();

	MODULEENTRY32 lpModuleEntry = { 0 };
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);
	if (!hSnapShot)
		return NULL;
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	BOOL bModule = Module32First(hSnapShot, &lpModuleEntry);
	while (bModule)
	{
		if (!strcmp(lpModuleEntry.szModule, lpModuleName))
		{
			CloseHandle(hSnapShot);
			return (uintptr_t)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next(hSnapShot, &lpModuleEntry);
	}
	CloseHandle(hSnapShot);
	return NULL;
}

uintptr_t CCore::FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
	
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i) {
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
		addr += offsets[i];
	}
	return addr;
}


uintptr_t CCore::FindExecutableAddress(uintptr_t ptrOffset, std::vector<unsigned int> offsets) {
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

	uintptr_t moduleBase = Core->GetModuleBaseAddress();
	uintptr_t dynamicPtrAddr = moduleBase + ptrOffset;
	uintptr_t hpAddr = Core->FindDMAAddy(hProcess, dynamicPtrAddr, offsets);
}


void CCore::ConvertToLittleEndianByteArray(uintptr_t address, char *output) {
	std::cout << "ConvertToLittleEndianByteArray address : " << std::hex << address << "\n";
	for (int i = 0; i < sizeof(void*); ++i) {
		output[i] = address & 0xff;
		printf("%2.2X", (unsigned int)(unsigned char)output[i]);
		address >>= 8;
	}
	printf("\n");
}


/*
Item Gib

https://pastebin.com/DKUvVwN8

typedef int func(void);
func* f = (func*)0xdeadbeef;
int i = f();


ItemGib - 48 83 EC 48           - sub rsp,48 { 72 }
13FFE0004- 44 8D 44 24 20        - lea r8d,[rsp+20]
13FFE0009- 48 8D 54 24 30        - lea rdx,[rsp+30]
13FFE000E- A1 8100FE3F01000000   - mov eax,[ItemGibData] { (0) }
13FFE0017- 8B 1D 68000000        - mov ebx,[13FFE0085] { (244) }
13FFE001D- 8B 35 66000000        - mov esi,[13FFE0089] { (255) }
13FFE0023- C7 02 01000000        - mov [rdx],00000001 { 1 }
13FFE0029- 89 72 0C              - mov [rdx+0C],esi
13FFE002C- 41 89 58 14           - mov [r8+14],ebx
13FFE0030- 41 89 40 18           - mov [r8+18],eax
13FFE0034- 48 A1 788E764401000000- mov rax,[BaseB] { (0) }
13FFE003E- 48 8B A8 80000000     - mov rbp,[rax+00000080]
13FFE0045- 48 8B 1D B4227704     - mov rbx,[DarkSoulsIII.exe+4752300] { (7FF4AA3D5650) }
13FFE004C- 48 8B CB              - mov rcx,rbx
13FFE004F- E8 1CBA7D00           - call DarkSoulsIII.exe+7BBA70
13FFE0054- 48 83 C4 48           - add rsp,48 { 72 }
13FFE0058- C3                    - ret





.DATA               ; Initialised data section
eatmsg   db  "Eat at Joe's!", 13, 10, "$"    ;message to display

.CODE               ; Code section
start:

	mov dx, eatmsg  ; Mem data ref without [] loads the address
	mov ah, 9       ; Function 9 displays text to standard output
	int 21H         ; Call DOS

	mov ax, 04C00H  ; DOS function to exit the program
	int 21H         ; Return control to DOS


end start


https://guidedhacking.com/threads/windows-c-shellcode-injection-tutorial.12132/
https://stackoverflow.com/questions/40936534/how-to-alloc-a-executable-memory-buffer


Base + offset = https://forum.cheatengine.org/viewtopic.php?t=584686
https://guidedhacking.com/threads/get-module-base-address-tutorial-dwgetmodulebaseaddress.5781/


Disassembler : 
https://defuse.ca/online-x86-assembler.htm#disassembly2

*/