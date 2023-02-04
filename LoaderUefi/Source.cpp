#include <Windows.h>
#include <iostream>
#include "Xor.h"
#include "LoaderEfi.h"


int main()
{
	ULONG BuildNumber = *(ULONG*)(0x07FFE0260);
	printf(XorChar("[*] Build: %u\n"), BuildNumber);
	ULONG CupVendor = GetCPUVendor();

	if (!CraftUefi(CupVendor))
	{
		printf(XorChar("[-] CraftUefi: ERROR\n"));
		system(XorChar("pause"));
		system(XorChar("shutdown /r /t 5"));
		return 0;
	}

	Sleep(500);
	system(XorChar("shutdown /r /t 5"));	
	return 0;
}