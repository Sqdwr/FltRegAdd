#include <ntifs.h>
#include <ntddk.h>

// 设置DependOnService和Group项
NTSTATUS RegSetServiceInfo(PUNICODE_STRING RegString)
{
	HANDLE KeyHandle = NULL;
	OBJECT_ATTRIBUTES KeyAttributes = { 0 };
	ULONG Disposition = 0;

	WCHAR DependOnService[] = L"FltMgr";
	WCHAR Group[] = L"FSFilter Activity Monitor";

	UNICODE_STRING ValueName = { 0 };

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		InitializeObjectAttributes(&KeyAttributes, RegString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwCreateKey Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

		RtlInitUnicodeString(&ValueName, L"DependOnService");
		Status = ZwSetValueKey(KeyHandle, &ValueName, 0, REG_MULTI_SZ, DependOnService, sizeof(DependOnService));
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwSetValueKey DependOnService Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

		RtlInitUnicodeString(&ValueName, L"Group");
		Status = ZwSetValueKey(KeyHandle, &ValueName, 0, REG_SZ, Group, sizeof(Group));
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwSetValueKey Group Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

	} while (FALSE);

	if (KeyHandle != NULL)
	{
		ZwClose(KeyHandle);
		KeyHandle = NULL;
	}

	return Status;
}

// 创建Instances项，然后设置DefaultInstance项
NTSTATUS RegSetInstances(PUNICODE_STRING RegString)
{
	HANDLE KeyHandle = NULL;
	UNICODE_STRING KeyPath = { 0 };

	OBJECT_ATTRIBUTES KeyAttributes = { 0 };
	ULONG Disposition = 0;

	WCHAR *ServiceName = NULL;
	WCHAR *DefaultInstance = NULL;

	UNICODE_STRING ValueName = { 0 };

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		if (RegString == NULL || RegString->Buffer == NULL || RegString->MaximumLength == 0)
		{
			KdPrint(("[%s] Invalid RegString Info!\n", __FUNCTION__));
			break;
		}

		KeyPath.MaximumLength = RegString->MaximumLength + (sizeof(WCHAR) * wcslen(L"\\Instances") + 1);

		KeyPath.Buffer = ExAllocatePoolWithTag(PagedPool, KeyPath.MaximumLength, 'REG');
		if (KeyPath.Buffer == NULL)
		{
			KdPrint(("[%s] Allocate KeyPath.Buffer Fail!\n", __FUNCTION__));
			break;
		}
		RtlZeroMemory(KeyPath.Buffer, KeyPath.MaximumLength);

		RtlAppendUnicodeStringToString(&KeyPath, RegString);

		ServiceName = wcsrchr(KeyPath.Buffer, L'\\');
		if (ServiceName == NULL)
		{
			KdPrint(("[%s] Invalid ServiceName!\n", __FUNCTION__));
			break;
		}
		++ServiceName;

		DefaultInstance = ExAllocatePoolWithTag(PagedPool, sizeof(WCHAR) * (wcslen(ServiceName) + wcslen(L" Instance") + 1), 'REG');
		if (DefaultInstance == NULL)
		{
			KdPrint(("[%s] Allocate DefaultInstance Fail!\n", __FUNCTION__));
			break;
		}
		RtlZeroMemory(DefaultInstance, sizeof(WCHAR) * (wcslen(ServiceName) + wcslen(L" Instance") + 1));

		wcscat(DefaultInstance, ServiceName);
		wcscat(DefaultInstance, L" Instance");

		RtlAppendUnicodeToString(&KeyPath, L"\\Instances");

		InitializeObjectAttributes(&KeyAttributes, &KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwCreateKey Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

		RtlInitUnicodeString(&ValueName, L"DefaultInstance");
		Status = ZwSetValueKey(KeyHandle, &ValueName, 0, REG_SZ, DefaultInstance, sizeof(WCHAR) * (wcslen(DefaultInstance) + 1));
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwSetValueKey DefaultInstance Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

	} while (FALSE);

	if (KeyHandle != NULL)
	{
		ZwClose(KeyHandle);
		KeyHandle = NULL;
	}

	if (KeyPath.Buffer != NULL)
	{
		ExFreePoolWithTag(KeyPath.Buffer, 'REG');
		KeyPath.Buffer = NULL;
	}

	if (DefaultInstance != NULL)
	{
		ExFreePoolWithTag(DefaultInstance, 'REG');
		DefaultInstance = NULL;
	}

	return Status;
}

// 创建ServiceName Instances项，然后设置Altitude和Flags项
NTSTATUS RegSetServiceInstances(PUNICODE_STRING RegString,PWCHAR Altitude)
{
	HANDLE KeyHandle = NULL;
	UNICODE_STRING KeyPath = { 0 };
	OBJECT_ATTRIBUTES KeyAttributes = { 0 };
	ULONG Disposition = 0;

	UNICODE_STRING ValueName = { 0 };
	ULONG FlagValue = 0;

	WCHAR *TempBuffer = NULL;
	WCHAR *ServiceName = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	do
	{
		if (RegString == NULL || RegString->Buffer == NULL || RegString->MaximumLength == 0)
		{
			KdPrint(("[%s] Invalid RegString Info!\n", __FUNCTION__));
			break;
		}

		if (Altitude == NULL)
		{
			KdPrint(("[%s] Invalid Altitude!\n", __FUNCTION__));
			break;
		}

		// 不确定RegString的Buffer是否存在空字符结尾，自己拷贝一份
		TempBuffer = ExAllocatePoolWithTag(PagedPool, RegString->MaximumLength + sizeof(WCHAR), 'REG');
		if (TempBuffer == NULL)
		{
			KdPrint(("[%s] Allocate KeyPath.Buffer Fail!\n", __FUNCTION__));
			break;
		}
		RtlZeroMemory(TempBuffer, RegString->MaximumLength + sizeof(WCHAR));
		RtlCopyMemory(TempBuffer, RegString->Buffer, RegString->MaximumLength);

		ServiceName = wcsrchr(TempBuffer, L'\\');
		if (ServiceName == NULL)
		{
			KdPrint(("[%s] Invalid ServiceName!\n", __FUNCTION__));
			break;
		}
		++ServiceName;

		KeyPath.MaximumLength = RegString->MaximumLength + sizeof(WCHAR) * (wcslen(L"\\Instances\\") + wcslen(ServiceName) + wcslen(L" Instance") + 1);

		KeyPath.Buffer = ExAllocatePoolWithTag(PagedPool, KeyPath.MaximumLength, 'REG');
		if (KeyPath.Buffer == NULL)
		{
			KdPrint(("[%s] Allocate KeyPath.Buffer Fail!\n", __FUNCTION__));
			break;
		}
		RtlZeroMemory(KeyPath.Buffer, KeyPath.MaximumLength);

		RtlAppendUnicodeStringToString(&KeyPath, RegString);

		RtlAppendUnicodeToString(&KeyPath, L"\\Instances\\");
		RtlAppendUnicodeToString(&KeyPath, ServiceName);
		RtlAppendUnicodeToString(&KeyPath, L" Instance");
		
		InitializeObjectAttributes(&KeyAttributes, &KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwCreateKey Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

		RtlInitUnicodeString(&ValueName, L"Altitude");
		Status = ZwSetValueKey(KeyHandle, &ValueName, 0, REG_SZ, Altitude, sizeof(WCHAR) * (wcslen(Altitude) + 1));
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwSetValueKey Altitude Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

		RtlInitUnicodeString(&ValueName, L"Flags");
		Status = ZwSetValueKey(KeyHandle, &ValueName, 0, REG_DWORD, &FlagValue, sizeof(FlagValue));
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s] ZwSetValueKey FlagValue Fail!Status:%x!\n", __FUNCTION__, Status));
			break;
		}

	} while (FALSE);

	if (KeyHandle != NULL)
	{
		ZwClose(KeyHandle);
		KeyHandle = NULL;
	}

	if (KeyPath.Buffer != NULL)
	{
		ExFreePoolWithTag(KeyPath.Buffer, 'REG');
		KeyPath.Buffer = NULL;
	}

	if (TempBuffer != NULL)
	{
		ExFreePoolWithTag(TempBuffer, 'REG');
		TempBuffer = NULL;
	}

	return Status;

}

VOID RegAddMiniFilterInfo(PUNICODE_STRING RegString,PWCHAR Altitude)
{
	do
	{
		RegSetServiceInfo(RegString);
		RegSetInstances(RegString);
		RegSetServiceInstances(RegString, Altitude);

	} while (FALSE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	UNREFERENCED_PARAMETER(DriverObject);

	RegAddMiniFilterInfo(RegString, L"370090");

	return STATUS_UNSUCCESSFUL;
}
