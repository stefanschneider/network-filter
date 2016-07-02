
#define NTDDI_VERSION NTDDI_WINBLUE

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <fwpmu.h>
#include <sddl.h>


#include <stdio.h>



#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      return result; \
   }

#define EXIT_ON_LAST_ERROR(success, fnName) \
   if (!(success)) \
   { \
      result = GetLastError(); \
      printf(#fnName " = 0x%08X\n", result); \
      return result; \
   }


// {CE0DEAD9-E4D1-41B3-BDAA-B7DB5843EEB9}
static const GUID filterKeyGuid =
{ 0xce0dead9, 0xe4d1, 0x41b3,{ 0xbd, 0xaa, 0xb7, 0xdb, 0x58, 0x43, 0xee, 0xb9 } };

/*
docs:
// http://jaredwright.github.io/2015/11/10/An-Introduction-To-The-Windows-Filtering-Platform.html
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364046(v=vs.85).aspx
// http://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html FWPM_*_FLAG_PERSISTENT

*/

// https://msdn.microsoft.com/en-us/library/windows/desktop/bb427381(v=vs.85).aspx
#include <windows.h>
#include <fwpmu.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>

#pragma comment (lib, "fwpuclnt.lib")
#pragma comment (lib, "advapi32.lib")

#define SESSION_NAME L"SDK Examples"

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      goto CLEANUP; \
   }

DWORD FilterByUserAndApp(
	__in HANDLE engine,
	__in PCWSTR filterName,
	__in_opt const GUID* providerKey,
	__in const GUID* layerKey,
	__in_opt const GUID* subLayerKey,
	__in_opt PCWSTR userName,
	__in_opt PCWSTR appPath,
	__in FWP_ACTION_TYPE actionType,
	__out_opt UINT64* filterId
)
{
	DWORD result = ERROR_SUCCESS;
	FWPM_FILTER_CONDITION0 conds[2];
	UINT32 numConds = 0;
	EXPLICIT_ACCESS_W access;
	ULONG sdLen;
	PSECURITY_DESCRIPTOR sd = NULL;
	FWP_BYTE_BLOB sdBlob, *appBlob = NULL;
	FWPM_FILTER0 filter;

	// Add an FWPM_CONDITION_ALE_USER_ID condition if requested.
	if (userName != NULL)
	{
		// When evaluating SECURITY_DESCRIPTOR conditions, the filter engine
		// checks for FWP_ACTRL_MATCH_FILTER access. If the DACL grants access,
		// it does not mean that the traffic is allowed; it just means that the
		// condition evaluates to true. Likewise if it denies access, the
		// condition evaluates to false.
		BuildExplicitAccessWithNameW(
			&access,
			(PWSTR)userName,
			FWP_ACTRL_MATCH_FILTER,
			GRANT_ACCESS,
			0
		);

		result = BuildSecurityDescriptorW(
			NULL,
			NULL,
			1,
			&access,
			0,
			NULL,
			NULL,
			&sdLen,
			&sd
		);
		EXIT_ON_ERROR(BuildSecurityDescriptorW);

		// Security descriptors must be in self-relative form (i.e., contiguous).
		// The security descriptor returned by BuildSecurityDescriptorW is
		// already self-relative, but if you're using another mechanism to build
		// the descriptor, you may have to convert it. See MakeSelfRelativeSD for
		// details.
		sdBlob.size = sdLen;
		sdBlob.data = (UINT8*)sd;

		conds[numConds].fieldKey = FWPM_CONDITION_ALE_USER_ID;
		conds[numConds].matchType = FWP_MATCH_EQUAL;
		conds[numConds].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
		conds[numConds].conditionValue.sd = &sdBlob;
		++numConds;
	}

	// Add an FWPM_CONDITION_ALE_APP_ID condition if requested.
	if (appPath != NULL)
	{
		// appPath must be a fully-qualified file name, and the file must
		// exist on the local machine.
		result = FwpmGetAppIdFromFileName0(appPath, &appBlob);
		EXIT_ON_ERROR(FwpmGetAppIdFromFileName0);

		conds[numConds].fieldKey = FWPM_CONDITION_ALE_APP_ID;
		conds[numConds].matchType = FWP_MATCH_EQUAL;
		conds[numConds].conditionValue.type = FWP_BYTE_BLOB_TYPE;
		conds[numConds].conditionValue.byteBlob = appBlob;
		++numConds;
	}

	memset(&filter, 0, sizeof(filter));
	// For MUI compatibility, object names should be indirect strings. See
	// SHLoadIndirectString for details.
	filter.displayData.name = (PWSTR)filterName;
	// Link all objects to our provider. When multiple providers are installed
	// on a computer, this makes it easy to determine who added what.
	filter.providerKey = (GUID*)providerKey;
	filter.layerKey = *layerKey;
	// Generally, it's best to add filters to our own sublayer, so we don't have
	// to worry about being overridden by filters added by another provider.
	if (subLayerKey != NULL)
	{
		filter.subLayerKey = *subLayerKey;
	}
	filter.numFilterConditions = numConds;
	if (numConds > 0)
	{
		filter.filterCondition = conds;
	}
	filter.action.type = actionType;

	result = FwpmFilterAdd0(engine, &filter, NULL, filterId);
	EXIT_ON_ERROR(FwpmFilterAdd0);

CLEANUP:
	FwpmFreeMemory0((void**)&appBlob);
	LocalFree(sd);
	return result;
}



int main(int argc, const char** argv) {
	DWORD result = ERROR_SUCCESS;

	DWORD status;

	UINT16 port = 0;

	if (argc<2) {
		printf("This program requires at least one argument, the name of the host to block, and optionally the port.");
		return 0;
	}

	printf("Atttempting to block access to %s\n", argv[1]);

	if (argc >= 3) {
		port = atoi(argv[2]);
		printf("port %u\n", port);
	}

	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	status = WSAStartup(wVersionRequested, &wsaData);
	printf("WSAStartup result %x\n", (unsigned)status);
	if (status != ERROR_SUCCESS) {                       
		printf("WSAStartup failed\n");
		return status;
	}

	ADDRINFOA hints;
	RtlZeroMemory(&hints, sizeof(ADDRINFOA));
	hints.ai_flags = AI_V4MAPPED;

	PADDRINFOA AddressInfo;
	status = getaddrinfo(argv[1], "http", &hints, &AddressInfo);
	printf("getaddrinfo result %x\n", (unsigned)status);
	WSACleanup();
	if (status != ERROR_SUCCESS) {
		printf("failed to resolve %s\n", argv[1]);
		return status;
	}
	
	UCHAR* addressData = AddressInfo->ai_addr->sa_data + 2;
	UINT32 ipAddress = (addressData[0]<<24)| (addressData[1] << 16) | (addressData[2] << 8) | (addressData[3] << 0);
	printf("%s resolved to %d.%d.%d.%d (0x%x)\n", argv[1], addressData[0], addressData[1], addressData[2], addressData[3], ipAddress);

	HANDLE FwpmHandle;

	status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &FwpmHandle);
	
	// clear any previous filter
	FwpmFilterDeleteByKey0(FwpmHandle, &filterKeyGuid);	

	FWPM_FILTER0 filter;
	RtlZeroMemory(&filter, sizeof(FWPM_FILTER0));

	printf("FwpmEngineOpen0 result code %x\n", status);
	if (status != ERROR_SUCCESS) {
		return status;
	}

	printf("FwpmEngine started %x\n", (unsigned)FwpmHandle);

	

	//KEY
	filter.filterKey = filterKeyGuid;

	filter.displayData.name = L"Filtering test.";
	filter.flags = FWPM_FILTER_FLAG_NONE | FWPM_FILTER_FLAG_PERSISTENT;
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; // flow details: https://msdn.microsoft.com/en-us/library/windows/desktop/bb451830(v=vs.85).aspx
	filter.action.type = FWP_ACTION_BLOCK;
	filter.weight.type = FWP_EMPTY; // auto-weight.
	filter.numFilterConditions = 0;
	

	FWP_V4_ADDR_AND_MASK addr_and_mask;
	RtlZeroMemory(&addr_and_mask, sizeof(addr_and_mask));
	addr_and_mask.addr = ipAddress; //0x2EE42F73
	addr_and_mask.mask = 0xFFFFFFFF;


	FWPM_FILTER_CONDITION0 conds[3];
	RtlZeroMemory(conds, sizeof(conds));

	//FWPM_FILTER_CONDITION0 filterCondition;
	//RtlZeroMemory(&filterCondition, sizeof(filterCondition));
	
	filter.filterCondition = conds;
	conds[0].matchType = FWP_MATCH_EQUAL;
	conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	conds[0].conditionValue.type = FWP_V4_ADDR_MASK;
	conds[0].conditionValue.v4AddrMask = &addr_and_mask;
	filter.numFilterConditions++;

	// Per user condition 
	// https://msdn.microsoft.com/en-us/library/windows/desktop/bb427381(v=vs.85).aspx

	//////////
	// The second condition matches any user who is a member of the built-in
	// Administrators group.
	//////////

	PSECURITY_DESCRIPTOR sd = NULL;
	FWP_BYTE_BLOB sdBlob;

	// For well-known security descriptors, it's easiest to build them in one
	// shot from an SDDL string, rather than constructing them programmatically
	// using lower-level APIs.
	BOOL success = ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"D:(A;;0x1;;;BA)",
		SDDL_REVISION_1,
		&sd,
		NULL
	);
	EXIT_ON_LAST_ERROR(
		success,
		ConvertStringSecurityDescriptorToSecurityDescriptorW
	);

	// Security descriptors must be in self-relative form (i.e., contiguous).
	// The security descriptor returned by
	// ConvertStringSecurityDescriptorToSecurityDescriptorW is already
	// self-relative, but if you're using another mechanism to build the
	// descriptor, you may have to convert it. See MakeSelfRelativeSD for
	// details.
	sdBlob.size = GetSecurityDescriptorLength(sd);
	sdBlob.data = (UINT8*)sd;

	conds[1].fieldKey = FWPM_CONDITION_ALE_USER_ID;
	// conds[1].matchType = FWP_MATCH_EQUAL;
	conds[1].matchType = FWP_MATCH_NOT_EQUAL;
	conds[1].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
	conds[1].conditionValue.sd = &sdBlob;
	filter.numFilterConditions++;

	if (port != 0) {
		conds[filter.numFilterConditions].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		conds[filter.numFilterConditions].matchType = FWP_MATCH_EQUAL;
		conds[filter.numFilterConditions].conditionValue.type = FWP_UINT16;
		conds[filter.numFilterConditions].conditionValue.uint16 = port;
		filter.numFilterConditions++;
	}


	UINT64 filterId;
	status = FwpmFilterAdd0(FwpmHandle, &filter, NULL, &filterId);

	printf("FwpmFilterAdd0 result code %x\n", status);
	if (status != ERROR_SUCCESS) {
		return status;
	}

	printf("Blocking %s\nPress any key to stop\n", argv[1]);
	char readChar;
	scanf_s("%c",&readChar);

	// status = FwpmFilterDeleteById0(FwpmHandle, filterId);
	status = FwpmFilterDeleteByKey0(FwpmHandle, &filterKeyGuid);

	printf("FwpmFilterDeleteById0 result code %x\n", status);
	if (status != ERROR_SUCCESS) {
		printf("Failed to remove filter!!!!\n");
		return status;
	} else {
		printf("Filtering stopped.\n");
	}
	
	return 0;
}