#include "GhostTask.h"

#define GUIDSIZE 38

#define COPY_DATA(dest, src, size) \
    memcpy(dest, src, size); \
    dest += size;

const char* DAYS[] = { "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday" };
const char* SCHEDULETYPES[] = { "second", "daily", "weekly", "logon" };

void printHelp() {
    printf("Usage: GhostTask.exe <hostname/localhost> <operation> <taskname> <program> <argument> <username> <scheduletype> <time/second> <day>\n");
    printf("- hostname/localhost: Remote computer name or \"localhost\".\n");
    printf("- operation: add/delete\n");
    printf("  - add: Create or modify a scheduled task using only registry keys. Requires restarting the \"Schedule\" service to load the task definition.\n");
    printf("  - delete: Delete a scheduled task. Requires restarting the \"Schedule\" service to offload the task.\n");
    printf("- taskname: Name of the scheduled task.\n");
    printf("- program: Program to be executed.\n");
    printf("- argument: Arguments for the program.\n");
    printf("- username: User account under which the scheduled task will run.\n");
    printf("- scheduletype: Supported triggers: second, daily, weekly, and logon.\n");
    printf("- time/second (applicable for 'second', 'daily', and 'weekly' triggers):\n");
    printf("  - For 'second' trigger: Specify the frequency in seconds for task execution.\n");
    printf("  - For 'daily' and 'weekly' triggers: Specify the exact time (e.g., 22:30) for task execution.\n");
    printf("- day (applicable for 'weekly' trigger): Days to execute the scheduled task (e.g., monday, thursday).\n");
}

bool ParseArguments(char** args, int arglen, Arguments *arguments) {
    char* computerName;
    char* computerNameL;
    char* operation;
    char* taskName;
    char* program;
    char* argument;
    char* userName;
    char* scheduleType;
    char* time;
    char* day;
    int computerNameSize;
    arguments->dayBitmap = 0;
    if (arglen == 1) {
        printf("[-] No computer name (e.g., localhost/remote server hostname) provided.\n");
        return false;
    } else if (arglen == 2) {
        printf("[-] No reg task operation (e.g., add/delete) provided.\n");
        return false;
    }
    computerName = args[1];
    operation = args[2];
    arguments->computerName = computerName;
    computerNameSize = strlen(computerName);
    computerNameL = (char*)malloc(computerNameSize + 1);
    memcpy(computerNameL, computerName, computerNameSize+1);
    if (strcmp("localhost", _strlwr(computerNameL)) == 0)
        arguments->computerName = NULL;
    free(computerNameL);
    if (strcmp("add", _strlwr(operation)) == 0) {
        const char *missingArgs[] = {"task name", "program", "argument", "username for task execution", "schedule type"};
        for (int i = 3, j = 0; i < 8; i++, j++) {
            if (arglen == i) {
                printf("[-] No %s provided.\n", missingArgs[j]);
                return false;
            }
        }
        taskName = args[3];
        program = args[4];
        argument = args[5];
        userName = args[6];
        scheduleType = _strlwr(args[7]);

        arguments->taskName = taskName;
        arguments->taskOperation = TaskAddOperation;
        bool foundScheduleType = false;

        for (int i = 0; i < sizeof(SCHEDULETYPES) / sizeof(SCHEDULETYPES[0]); i++) {
            if (strcmp(scheduleType, SCHEDULETYPES[i]) == 0) {
                arguments->scheduleType = i;
                foundScheduleType = true;
                
                // For "second", "daily", and "weekly" we need an execution time
                if (i <= 2 && arglen == 8) {
                    printf("[-] Please provide scheduled task execution time (e.g., 22:15).\n");
                    return false;
                }

                if (i == 2) { // weekly
                    time = args[8];
                    if (arglen == 9) {
                        printf("[-] Please provide days (e.g., monday,friday) for weekly execution.\n");
                        return false;
                    }
                    day = _strlwr(args[9]);
                    for (int j = 0; j < 7; j++) {
                        if (strstr(day, DAYS[j]))
                            arguments->dayBitmap += (1 << j);
                    }
                }
                else if (i <= 2) // second or daily
                    time = args[8];
            }
        }

        if (!foundScheduleType) {
            printf("[-] Unknown schedule type '%s'.\n", scheduleType);
            return false;
        }

        // Handle time
        if (strcmp("second", scheduleType) == 0) {
            arguments->hour = 0;
            arguments->minute = 0;
            arguments->second = atoi(time);
        } else if (strcmp("daily", scheduleType) == 0 || strcmp("weekly", scheduleType) == 0) {
            char *token = strtok(time, ":");
            arguments->hour = atoi(token);
            token = strtok(NULL, ":");
            arguments->minute = atoi(token);
            if (arguments->hour > 23 || arguments->minute > 59) {
                printf("[-] Wrong time format (e.g., 15:30).");
                return false;
            }
        }

        arguments->program = program;
        arguments->argument = argument;
        arguments->userName = userName;
    } else if (strcmp("delete", operation) == 0) {
        if (arglen == 3) {
            printf("[-] No task name provided.\n");
            return false;
        }

        taskName = args[3];
        arguments->taskName = taskName;
        arguments->taskOperation = TaskDeleteOperation;
    } else {
        printf("[-] Unknown command '%s'.\n", operation);
        return false;
    }
    return true;
}

//Ref: https://github.com/gmh5225/BOF-nanorobeus/blob/a7ab668cab3a63df4a03cc53c46eed13fbb13bf1/source/common.c#L104
bool CheckSystem() {
    HANDLE hToken = NULL;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid;
    bool bSystem;

    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser)) {
        printf("[-] Error calling GetTokenInformation. Error code:0x%x\n", GetLastError());
        return false;
    }

    if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        printf("[-] Error calling AllocateAndInitializeSid. Error code:0x%x\n", GetLastError());
        return false;
    }

    bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
    FreeSid(pSystemSid);
    return bSystem;
}

// Return a handle to the specified registry key, return error code if failure
REG_ERROR_CODE OpenKeyHandle(HKEY *hKey, LPCSTR computerName, ACCESS_MASK desiredAccess, LPCSTR keyName) {
    LSTATUS lret;
    REGSAM archType = KEY_WOW64_64KEY;
    const char* hiveRootString = "HKLM";
    const char* computerString = computerName;
    const char* computerNameSeparator = "\\";
    if (computerName == NULL)
        computerNameSeparator = computerString = "";

    if (computerName != NULL) {
        HKEY hRemoteRoot = NULL;
        lret = RegConnectRegistryA(computerName, HKEY_LOCAL_MACHINE, &hRemoteRoot);
        if (lret != ERROR_SUCCESS || hRemoteRoot == NULL) {
            printf("[-] Failed to connect to '%s%s%s' [error %d].\n", computerString, computerNameSeparator, hiveRootString, lret);
            return SERVER_INACCESSIBLE;
        }
        lret = RegOpenKeyExA(hRemoteRoot, keyName, 0, archType | desiredAccess, hKey);
        RegCloseKey(hRemoteRoot);
        if (lret != ERROR_SUCCESS)
            return OPEN_KEY_FAIL;
    } else {
        lret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyName, 0, archType | desiredAccess, hKey);
        if (lret != ERROR_SUCCESS)
            return OPEN_KEY_FAIL;
    }
    
    return REG_SUCCESS;
}

char* GetProductName(LPCSTR computerName) {
    DWORD dwRet = 0;
    DWORD type = 0;
    DWORD size = 0;
    char* path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\";
    HKEY key = NULL;
    char* valueData = NULL;

    REG_ERROR_CODE regRetCode = OpenKeyHandle(&key, computerName, KEY_READ, path);
    if (regRetCode != REG_SUCCESS)
        return NULL;
    
    dwRet = RegQueryValueExA(key, "ProductName", NULL, &type, NULL, &size);
    if (dwRet != ERROR_SUCCESS) {
        printf("[-] Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        goto exit;
    }

    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)
        size += 2;
    
    valueData = (char*)malloc(size);
    if (!valueData)
        goto exit;
    
    dwRet = RegQueryValueExA(key, "ProductName", NULL, &type, (LPBYTE)valueData, &size);
    if (dwRet != ERROR_SUCCESS) {
        printf("[-] Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        free(valueData);
        valueData = NULL;
    }

exit:
    if (key)
        RegCloseKey(key);
    return valueData;
}

char* GetExistingTaskGuid(LPCSTR computerName, LPCSTR taskName) {
    DWORD dwRet = 0;
    DWORD type = 0;
    DWORD size = 0;
    char* treePath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\";
    int treePathSize = strlen(treePath);
    char* treeKey = (char*)malloc(treePathSize + strlen(taskName) + 1);
    sprintf(treeKey, "%s%s", treePath, taskName);
    HKEY key = NULL;
    char* valueData = NULL;

    REG_ERROR_CODE regRetCode = OpenKeyHandle(&key, computerName, KEY_READ, treeKey);
    free(treeKey);
    if (regRetCode != REG_SUCCESS)
        return NULL;
    
    dwRet = RegQueryValueExA(key, "Id", NULL, &type, NULL, &size);
    if (dwRet != ERROR_SUCCESS) {
        printf("[-] Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        goto exit;
    }

    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)
        size += 2;
    
    valueData = (char*)malloc(size);
    if (!valueData)
        goto exit;
    
    dwRet = RegQueryValueExA(key, "Id", NULL, &type, (LPBYTE)valueData, &size);
    if (dwRet != ERROR_SUCCESS) {
        printf("[-] Error calling RegQueryValueExA. Error code:0x%x\n", dwRet);
        free(valueData);
        valueData = NULL;
    }

exit:
    if (key)
        RegCloseKey(key);
    return valueData;
}

REG_ERROR_CODE DeleteKey(LPCSTR computerName, LPCSTR keyName) {
    bool deleteFromRoot = false;
    DWORD lastSlashOffset = 0;
    const char* lastSlash = strrchr((const char*) keyName, '\\');

    if (lastSlash == NULL)
        deleteFromRoot = true;
    else
        lastSlashOffset = (DWORD)(lastSlash - keyName);

    char ParentKeyName[256];
    char ChildKeyName[256];
    if (deleteFromRoot) {
        ParentKeyName[0] = 0;
        strncpy_s(ChildKeyName, 256, keyName, strlen(keyName));
    } else {
        strncpy_s(ParentKeyName, 256, keyName, lastSlashOffset);
        strncpy_s(ChildKeyName, 256, lastSlash + 1, strlen(keyName) - lastSlashOffset - 1);
    }

    HKEY hParentKey = NULL;
    REG_ERROR_CODE regRetCode = OpenKeyHandle(&hParentKey, computerName, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, ParentKeyName);
    if (regRetCode != REG_SUCCESS)
        return regRetCode;

    const char* hiveRootString = "HKLM";
    const char* rootSeparator = (strlen(keyName) == 0) ? "" : "\\";
    const char* computerString = computerName == NULL ? "" : computerName;
    const char* computerNameSeparator = computerName == NULL ? "" : "\\";

    LSTATUS lret = RegDeleteTreeA(hParentKey, ChildKeyName);

    RegCloseKey(hParentKey);

    if (lret != ERROR_SUCCESS) {
        printf("[-] Failed to delete key '%s%s%s%s%s' [error %d].\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName, lret);
        return DEL_KEY_FAIL;
    }

    printf("Deleted key '%s%s%s%s%s'.\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
    return REG_SUCCESS;
}

REG_ERROR_CODE AddKey(LPCSTR computerName, LPCSTR keyName) {
    const char* hiveRootString = "HKLM";
    const char* rootSeparator = (strlen(keyName) == 0) ? "" : "\\";
    const char* computerString = computerName == NULL ? "" : computerName;
    const char* computerNameSeparator = computerName == NULL ? "" : "\\";

    HKEY hHiveRoot = NULL;
    REG_ERROR_CODE regRetCode = OpenKeyHandle(&hHiveRoot, computerName, KEY_CREATE_SUB_KEY, NULL);
    if (regRetCode != REG_SUCCESS) {
        printf("[-] Failed to get key handle for HKLM.\n");
		return OPEN_KEY_FAIL;
    }
    HKEY hNewKey;
    DWORD dwDisposition;
    LSTATUS lret = RegCreateKeyExA(hHiveRoot, keyName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hNewKey, &dwDisposition);

    if (hHiveRoot != HKEY_LOCAL_MACHINE) // Close it properly if it's a handle to a remote computer
        RegCloseKey(hHiveRoot);

    if (lret != ERROR_SUCCESS) {
        printf("[-] Failed to create key '%s%s%s%s%s' [error %d].\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName, lret);
        return ADD_KEY_FAIL;
    }

    RegCloseKey(hNewKey);

    if (dwDisposition == REG_OPENED_EXISTING_KEY) {
        printf("Identified existing key '%s%s%s%s%s'.\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
        return REG_SUCCESS;
    }

    printf("Created key '%s%s%s%s%s'.\n", computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
    return REG_SUCCESS;
}

void AddValue(HKEY hKey, LPCSTR computerName, LPCSTR keyName, LPCSTR valueName, DWORD dwRegType, DWORD dataLength, LPBYTE bdata, bool overwrite) {
    const char* hiveRootString = "HKLM";
    const char* rootSeparator = (strlen(keyName) == 0) ? "" : "\\";
    const char* computerString = computerName == NULL ? "" : computerName;
    const char* computerNameSeparator = computerName == NULL ? "" : "\\";

    LSTATUS lret = RegQueryValueExA(hKey, valueName, NULL, NULL, NULL, NULL);

    const char* successOperationString = (lret == ERROR_SUCCESS) ? "Overwrote" : "Added";
    const char* failOperationString = (lret == ERROR_SUCCESS) ? "overwrite" : "add";
    const char* preposition = (lret == ERROR_SUCCESS) ? "in" : "to";

    if (lret == ERROR_SUCCESS && !overwrite)
        return;
    lret = RegSetValueExA(hKey, valueName, 0, dwRegType, bdata, dataLength);

    if (lret != ERROR_SUCCESS) {
        printf("[-] Failed to %s value '%s' %s '%s%s%s%s%s' [error %d].\n", failOperationString, valueName, preposition, computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName, lret);
        return;
    }

    printf("%s value '%s' %s '%s%s%s%s%s'\n", successOperationString, valueName, preposition, computerString, computerNameSeparator, hiveRootString, rootSeparator, keyName);
}

void DeleteScheduleTask(LPCSTR computerName, LPCSTR taskName) {
    char* plain = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Plain\\";
    char* task = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\";
    char* tree = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\";
    char treeKey[MAX_PATH];
    char* fullGuid = NULL;
    HKEY hKeyTree = NULL;

    sprintf(treeKey, "%s%s", tree, taskName);
    REG_ERROR_CODE regRetCode = OpenKeyHandle(&hKeyTree, computerName, KEY_QUERY_VALUE, treeKey);
    if (regRetCode == SERVER_INACCESSIBLE)
        return;
    if (regRetCode == OPEN_KEY_FAIL) {
        printf("[-] The scheduled task does not exist.\n");
        return;
    }
    RegCloseKey(hKeyTree);
    fullGuid = GetExistingTaskGuid(computerName, taskName);
    regRetCode = DeleteKey(computerName, treeKey);
    if (fullGuid != NULL) {
        char plainKey[MAX_PATH];
        char taskKey[MAX_PATH];
        sprintf(plainKey, "%s%s", plain, fullGuid);
        sprintf(taskKey, "%s%s", task, fullGuid);
        regRetCode = DeleteKey(computerName, plainKey);
        regRetCode = DeleteKey(computerName, taskKey);
    }
    printf("Successfully deleted scheduled task (%s).\n", taskName);
}

void AddScheduleTask(LPCSTR computerName, LPCSTR taskName, LPCSTR cmd, LPCSTR argument, LPCSTR userName, unsigned short scheduleType, int hour, int minute, int second, unsigned short dayBitmap) {
    unsigned char author[] = {0x41, 0x00, 0x75, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x72, 0x00};
    char* taskPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\";
    char* tree = "Tree\\";
    char* plain = "Plain\\";
    char* task = "Tasks\\";
    int taskNameSize = strlen(taskName);
    int taskPathSize = strlen(taskPath);
    int plainSize = strlen(plain);
    int taskSize = strlen(task);
    int treeSize = strlen(tree);
    int sizeOfAuthor = sizeof(author)/sizeof(author[0]);
    char* uriPath = (char*)malloc(taskNameSize + 2);
    char* treeKey = (char*)malloc(taskPathSize + treeSize + taskNameSize + 1);
    char *plainKey = NULL, *taskKey = NULL, *fullGuid = NULL, *productName = NULL;
    PSID targetSid = NULL;
	DWORD domainSize, sizeOfSid = 0;
	LPSTR domainName = NULL;
	bool userFound, legacyActionVersion = false;
	SID_NAME_USE peUse = 0;
    FILETIME emptyTime;
    AlignedByte empty;
    TSTIME emptyTstime;
    OSVERSIONINFOEXA winVer;
    FILETIME ft;
    SYSTEMTIME st;
    char dateString[20];
    LPCSTR workingDirectory = "";
    LONGLONG index = 3;
    wchar_t cmd_w[256] = {0};
    wchar_t argument_w[256] = {0};
    wchar_t workingDirectory_w[256] = {0};
    int sizeOfCmd = strlen(cmd);
    int sizeOfArgument = strlen(argument);
    int sizeOfWorkingDirectory = strlen(workingDirectory);
    DWORD totalActionSize;
    Actions *action = (Actions*)malloc(sizeof(Actions));
    BYTE* actionRaw = NULL;
    DynamicInfo dynamicInfo;
    SYSTEMTIME startBoundary;
    FILETIME ftStartBoundary;
    TSTIME tsStartBoundary;
    PSECURITY_DESCRIPTOR pSd = NULL;
    ULONG sdLength;
    HKEY hKeyTree = NULL;
    HKEY hKeyTask = NULL;
    Header header;
    Trigger12 *trigger12 = NULL;
    Trigger28 *trigger28 = NULL;
    JobBucket12 jobBucket12;
    UserInfo12 userInfo12;
    JobBucket28 jobBucket28;
    UserInfo28 userInfo28;
    OptionalSettings optionalSettings;
    TimeTrigger timeTrigger;
    LogonTrigger logonTrigger;
    AlignedByte version, localized, skipUser, skipSid, enable;

    empty.value = 0;
    memset(empty.padding, 0, 7);
    emptyTime.dwLowDateTime = 0;
    emptyTime.dwHighDateTime = 0;
    emptyTstime.isLocalized = empty;
    emptyTstime.time = emptyTime;
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, cmd, -1, cmd_w, sizeOfCmd);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argument, -1, argument_w, sizeOfArgument);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, workingDirectory, -1, workingDirectory_w, sizeOfWorkingDirectory);
    sizeOfCmd = sizeOfCmd * 2;
    sizeOfArgument = sizeOfArgument * 2;
    sizeOfWorkingDirectory = sizeOfWorkingDirectory * 2;
    startBoundary.wYear = 1992;
    startBoundary.wMonth = 5;
    startBoundary.wDay = 1;
    startBoundary.wHour = hour;
    startBoundary.wMinute = minute;
    startBoundary.wSecond = 0;
    startBoundary.wMilliseconds = 0;
    SystemTimeToFileTime(&startBoundary, &ftStartBoundary);
    localized.value = 1;
    memset(localized.padding, 0, 7);
    tsStartBoundary.isLocalized = localized;
    tsStartBoundary.time = ftStartBoundary;

    // Construct schedule task path
    sprintf(treeKey, "%s%s%s", taskPath, tree, taskName);
    sprintf(uriPath, "\\%s", taskName);

    // Get Windows version
    memset(&winVer, 0, sizeof(OSVERSIONINFOEXA));
    winVer.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    productName = GetProductName(computerName);
    if (productName == NULL) {
        printf("[-] Unable to obtain the product name of the target system (%s).\n", computerName);
        goto exit;
    }
    if (strstr(productName, "2016"))
        legacyActionVersion = TRUE;

	userFound = LookupAccountNameA(NULL, userName, targetSid, &sizeOfSid, domainName, &domainSize, &peUse);
	if (!userFound && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		targetSid = (PSID)malloc(sizeOfSid);
		domainName = (LPSTR)malloc(domainSize * sizeof(CHAR) + 1);
        if (!targetSid || !domainName) {
            printf("[-] Memory allocation failed.\n");
            goto exit;
        }

		userFound = LookupAccountNameA(NULL, userName, targetSid, &sizeOfSid, domainName, &domainSize, &peUse);
        free(domainName);
	}

    if (!userFound) {
        printf("[-] Target user not found. Error code: 0x%x\n", GetLastError());
        goto exit;
    }
    
    // Get existing GUID or generate new GUID
    fullGuid = GetExistingTaskGuid(computerName, taskName);
    if (!fullGuid) {
        GUID uuid = {0};
        RPC_CSTR szRPCGuid = NULL;
        if (UuidCreate(&uuid) == RPC_S_OK && UuidToStringA(&uuid, &szRPCGuid) == RPC_S_OK && szRPCGuid) {
                fullGuid = (char*)malloc(GUIDSIZE + 1);
                sprintf(fullGuid, "{%s}", szRPCGuid);
                RpcStringFreeA(&szRPCGuid);
                _strupr(fullGuid);
        } else {
            printf("[-] GUID cannot be generated.\n");
            goto exit;
        }
    }

    // Update GUID path
    plainKey = (char*)malloc(taskPathSize + plainSize + GUIDSIZE + 1);
    taskKey = (char*)malloc(taskPathSize + taskSize + GUIDSIZE + 1);
    sprintf(plainKey, "%s%s%s", taskPath, plain, fullGuid);
    sprintf(taskKey, "%s%s%s", taskPath, task, fullGuid);

    // Initialize Actions
    action->version = legacyActionVersion ? 0x2 : 0x3;
    action->sizeOfAuthor = sizeOfAuthor;
    memcpy(action->author, author, action->sizeOfAuthor);
    action->magic = 0x6666;
    action->id = 0;
    action->sizeOfCmd = sizeOfCmd;
    action->cmd = cmd_w;
    action->sizeOfArgument = sizeOfArgument;
    action->argument = argument_w;
    action->sizeOfWorkingDirectory = sizeOfWorkingDirectory;
    action->workingDirectory = workingDirectory_w;
    action->flags = 0;
    
    totalActionSize = sizeof(short) + sizeof(DWORD) + sizeOfAuthor + sizeof(short) + sizeof(DWORD) + sizeof(DWORD) + sizeOfCmd + sizeof(DWORD) + sizeOfArgument + sizeof(DWORD) + sizeOfWorkingDirectory + sizeof(short);
    actionRaw = (BYTE*)malloc(totalActionSize);
    BYTE *ptr = actionRaw;
    COPY_DATA(ptr, &action->version, sizeof(short));
    COPY_DATA(ptr, &action->sizeOfAuthor, sizeof(DWORD));
    COPY_DATA(ptr, action->author, action->sizeOfAuthor);
    COPY_DATA(ptr, &action->magic, sizeof(short));
    COPY_DATA(ptr, &action->id, sizeof(DWORD));
    COPY_DATA(ptr, &action->sizeOfCmd, sizeof(DWORD));
    COPY_DATA(ptr, action->cmd, sizeOfCmd);
    COPY_DATA(ptr, &action->sizeOfArgument, sizeof(DWORD));
    COPY_DATA(ptr, action->argument, sizeOfArgument);
    COPY_DATA(ptr, &action->sizeOfWorkingDirectory, sizeof(DWORD));
    COPY_DATA(ptr, action->workingDirectory, sizeOfWorkingDirectory);
    COPY_DATA(ptr, &action->flags, sizeof(short));

    // Initialize DynamicInfo
    GetLocalTime(&st);
    SystemTimeToFileTime(&st, &ft);
    dynamicInfo.magic = 0x3;
    dynamicInfo.ftCreate = ft;
    // Will be displayed in "Last Run Time" in taskschd.msc
    dynamicInfo.ftLastRun = emptyTime;
    dynamicInfo.dwTaskState = 0;
    // Will be displayed in "Last Run Result" in taskschd.msc
    dynamicInfo.dwLastErrorCode = 0;
    dynamicInfo.ftLastSuccessfulRun = emptyTime;

    // Initialize Date
    sprintf(dateString, "%04d-%02d-%02dT%02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Initialize UserInfo
    skipUser.value = 0;
    skipSid.value = 0;
    memset(skipUser.padding, 0x48, 7);
    memset(skipSid.padding, 0x48, 7);
    if (sizeOfSid == 12) {
        userInfo12.skipUser = skipUser;
        userInfo12.skipSid = skipSid;
        userInfo12.sidType = 0x1;
        userInfo12.pad0 = 0x48484848;
        userInfo12.sizeOfSid = sizeOfSid;
        userInfo12.pad1 = 0x48484848;
        memcpy(userInfo12.sid, targetSid, sizeOfSid);
        userInfo12.pad2 = 0x48484848;
        userInfo12.sizeOfUsername = 0;
        userInfo12.pad3 = 0x48484848;
    } else {
        userInfo28.skipUser = skipUser;
        userInfo28.skipSid = skipSid;
        userInfo28.sidType = 0x1;
        userInfo28.pad0 = 0x48484848;
        userInfo28.sizeOfSid = sizeOfSid;
        userInfo28.pad1 = 0x48484848;
        memcpy(userInfo28.sid, targetSid, sizeOfSid);
        userInfo28.pad2 = 0x48484848;
        userInfo28.sizeOfUsername = 0;
        userInfo28.pad3 = 0x48484848;
    }

    // Initialize OptionalSettings
    // Default value 10 minutes
    optionalSettings.idleDurationSeconds = 0x258;
    // Default value 1 hour
    optionalSettings.idleWaitTimeoutSeconds = 0xe10;
    // Default value 3 days
    optionalSettings.executionTimeLimitSeconds = 0x3f480;
    optionalSettings.deleteExpiredTaskAfter = 0xffffffff;
    // Default value is 7 BELOW_NORMAL_PRIORITY_CLASS
    optionalSettings.priority = 0x7;
    optionalSettings.restartOnFailureDelay = 0;
    optionalSettings.restartOnFailureRetries = 0;
    GUID emptyNetworkId;
    memset(&emptyNetworkId, 0, sizeof(GUID));
    optionalSettings.networkId = emptyNetworkId;
    optionalSettings.pad0 = 0x48484848;
    
    // Initialize Header
    version.value = 0x17;
    memset(version.padding, 0, 7);
    header.version = version;
    
    // Initialize Trigger
    if (scheduleType == 3) {
        trigger12 = (Trigger12*)malloc(sizeof(Trigger12) + sizeof(LogonTrigger));
        trigger28 = (Trigger28*)malloc(sizeof(Trigger28) + sizeof(LogonTrigger));
        logonTrigger.magic = 0xaaaa;
        logonTrigger.unknown0 = 0;
        logonTrigger.startBoundary = emptyTstime;
        logonTrigger.endBoundary = emptyTstime;
        logonTrigger.delaySeconds = 0;
        logonTrigger.timeoutSeconds = 0xffffffff;
        logonTrigger.repetitionIntervalSeconds = 0;
        logonTrigger.repetitionDurationSeconds = 0;
        logonTrigger.repetitionDurationSeconds2 = 0;
        logonTrigger.stopAtDurationEnd = 0;
        enable.value = 1;
        memset(enable.padding, 0, 7);
        logonTrigger.enabled = enable;
        logonTrigger.unknown1 = empty;
        logonTrigger.triggerId = 0;
        logonTrigger.blockPadding = 0x48484848;
        skipUser.value = 1;
        logonTrigger.skipUser = skipUser;
    } else {
        trigger12 = (Trigger12*)malloc(sizeof(Trigger12) + sizeof(TimeTrigger));
        trigger28 = (Trigger28*)malloc(sizeof(Trigger28) + sizeof(TimeTrigger));
        timeTrigger.magic = 0xdddd;
        timeTrigger.unknown0 = 0;
        timeTrigger.endBoundary = emptyTstime;
        timeTrigger.unknown1 = emptyTstime;
        if (scheduleType == 0) {
            tsStartBoundary.time = ft;
            timeTrigger.repetitionIntervalSeconds = second;  
        } else
            timeTrigger.repetitionIntervalSeconds = 0;
        timeTrigger.startBoundary = tsStartBoundary;
        timeTrigger.repetitionDurationSeconds = 0;
        timeTrigger.timeoutSeconds = 0xffffffff;
        // Schedule type 0: secondly
        if (scheduleType == 0) {
            timeTrigger.mode = 0;
            timeTrigger.data1 = 0;
        // Schedule type 1: daily
        } else if (scheduleType == 1) {
            timeTrigger.mode = 1;
            timeTrigger.data1 = 0;
        // Schedule type 2: weekly
        } else if (scheduleType == 2) {
            timeTrigger.mode = 2;
            timeTrigger.data1 = dayBitmap;
        }
        timeTrigger.data0 = 1;
        timeTrigger.data2 = 0;
        timeTrigger.pad0 = 0;
        timeTrigger.stopTasksAtDurationEnd = 0;
        timeTrigger.enabled = 1;
        timeTrigger.pad1 = 0;
        timeTrigger.unknown2 = 1;
        timeTrigger.maxDelaySeconds = 0;
        timeTrigger.pad2 = 0;
        timeTrigger.triggerId = 0x4848484800000000;
    }

    if (sizeOfSid == 12) {
        // 0x40000000: allow_hard_terminate
        // 0x2000000: task
        // 0x400000: enabled
        // 0x10000: logon_type_interactivetoken
        // 0x2000: execute_ignore_new
        // 0x100: allow_start_on_demand
        // 0x8: stop_on_idle_end
        jobBucket12.flags = 0x42412108;
        jobBucket12.pad0 = 0x48484848;
        jobBucket12.crc32 = 0;
        jobBucket12.pad1 = 0x48484848;
        jobBucket12.sizeOfAuthor = 0xe;
        jobBucket12.pad2 = 0x48484848;
        memcpy(jobBucket12.author, author, 12);
        jobBucket12.pad3 = 0x48480000;
        jobBucket12.displayName = 0;
        jobBucket12.pad4 = 0x48484848;
        jobBucket12.userInfo = userInfo12;
        jobBucket12.sizeOfOptionalSettings = 0x2c;
        jobBucket12.pad5 = 0x48484848;
        jobBucket12.optionalSettings = optionalSettings;    

        trigger12->header = header;
        trigger12->jobBucket = jobBucket12;
        if (scheduleType == 3)
            memcpy(trigger12->trigger, &logonTrigger, sizeof(LogonTrigger));
        else
            memcpy(trigger12->trigger, &timeTrigger, sizeof(TimeTrigger));
    } else {
        // 0x40000000: allow_hard_terminate
        // 0x2000000: task
        // 0x400000: enabled
        // 0x10000: logon_type_interactivetoken
        // 0x2000: execute_ignore_new
        // 0x100: allow_start_on_demand
        // 0x8: stop_on_idle_end
        jobBucket28.flags = 0x42412108;
        jobBucket28.pad0 = 0x48484848;
        jobBucket28.crc32 = 0;
        jobBucket28.pad1 = 0x48484848;
        jobBucket28.sizeOfAuthor = 0xe;
        jobBucket28.pad2 = 0x48484848;
        memcpy(jobBucket28.author, author, 12);
        jobBucket28.pad3 = 0x48480000;
        jobBucket28.displayName = 0;
        jobBucket28.pad4 = 0x48484848;
        jobBucket28.userInfo = userInfo28;
        jobBucket28.sizeOfOptionalSettings = 0x2c;
        jobBucket28.pad5 = 0x48484848;
        jobBucket28.optionalSettings = optionalSettings;    

        trigger28->header = header;
        trigger28->jobBucket = jobBucket28;
        if (scheduleType == 3)
            memcpy(trigger28->trigger, &logonTrigger, sizeof(LogonTrigger));
        else
            memcpy(trigger28->trigger, &timeTrigger, sizeof(TimeTrigger));
    }

    // Initialize security descriptor
    ConvertStringSecurityDescriptorToSecurityDescriptorA("O:BAG:SYD:", 1, &pSd, &sdLength);

    printf("Execution Log:\n");
    // Create scheduled task subkey
    REG_ERROR_CODE regRetCode = AddKey(computerName, plainKey);
    if (regRetCode != REG_SUCCESS)
        goto exit;
    regRetCode = AddKey(computerName, treeKey);
    if (regRetCode != REG_SUCCESS)
        goto exit;
    regRetCode = AddKey(computerName, taskKey);
    if (regRetCode != REG_SUCCESS)
        goto exit;

    hKeyTree = NULL;
    REG_ERROR_CODE treeRegRetCode = OpenKeyHandle(&hKeyTree, computerName, KEY_QUERY_VALUE | KEY_SET_VALUE, treeKey);
    hKeyTask = NULL;
    REG_ERROR_CODE taskRegRetCode = OpenKeyHandle(&hKeyTask, computerName, KEY_QUERY_VALUE | KEY_SET_VALUE, taskKey);

    if (treeRegRetCode != REG_SUCCESS || taskRegRetCode != REG_SUCCESS) {
        printf("[-] Unable to obtain scheduled task key handle.\n");
        goto exit;
    }

    // Add values for task tree
    AddValue(hKeyTree, computerName, treeKey, "Index", 0x4, 4, (LPBYTE)&index, false);
    AddValue(hKeyTree, computerName, treeKey, "Id", 0x1, strlen(fullGuid) + 1, fullGuid, false);
    AddValue(hKeyTree, computerName, treeKey, "SD", REG_BINARY, sdLength, (LPBYTE)pSd, false);

    // Add values for Task GUID
    AddValue(hKeyTask, computerName, taskKey, "Author", 0x1, strlen(userName) + 1, (char*)userName, false);
    AddValue(hKeyTask, computerName, taskKey, "Path", 0x1, strlen(uriPath) + 1,(char*)uriPath, false);
    AddValue(hKeyTask, computerName, taskKey, "URI", 0x1, strlen(uriPath) + 1, (char*)uriPath, false);
    AddValue(hKeyTask, computerName, taskKey, "Date", 0x1, strlen(dateString) + 1, (char*)dateString, false);
    
    if (legacyActionVersion)
        AddValue(hKeyTask, computerName, taskKey, "Actions", REG_BINARY, totalActionSize-2, (LPBYTE)actionRaw, true);
    else
        AddValue(hKeyTask, computerName, taskKey, "Actions", REG_BINARY, totalActionSize, (LPBYTE)actionRaw, true);
        
    AddValue(hKeyTask, computerName, taskKey, "DynamicInfo", REG_BINARY, sizeof(DynamicInfo), (LPBYTE)&dynamicInfo, false);
    if (sizeOfSid == 12) {
        if (scheduleType == 3)
            AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger12) + sizeof(LogonTrigger), (LPBYTE)trigger12, true);
        else
            AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger12) + sizeof(TimeTrigger), (LPBYTE)trigger12, true);
    } else {
        if (scheduleType == 3)
            AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger28) + sizeof(LogonTrigger), (LPBYTE)trigger28, true);
        else
            AddValue(hKeyTask, computerName, taskKey, "Triggers", REG_BINARY, sizeof(Trigger28) + sizeof(TimeTrigger), (LPBYTE)trigger28, true);
    }

    printf("Scheduled task has been created with the following setup:\n");
    if (computerName != NULL)
        printf("%-30s %s\n", "Target Computer Name:", computerName);
    printf("%-30s %s\n", "Task Name:", taskName);
    printf("%-30s %s\n", "Task GUID:", fullGuid);
    printf("%-30s %s\n", "User to execute the task:", userName);
    printf("%-30s %s %s\n", "Action:", cmd, argument);
    if (scheduleType == 0) {
        printf("%-30s second\n", "Schedule Type:");
        printf("%-30s every %d seconds\n", "Execution Time:", second);
    } else if (scheduleType == 1) {
        printf("%-30s daily\n", "Schedule Type:");
        printf("%-30s %02d:%02d\n", "Execution Time:", hour, minute);
    } else if (scheduleType == 2) {
        printf("%-30s weekly\n", "Schedule Type:");
        printf("%-30s %02d:%02d\n", "Execution Time:", hour, minute);
    } else if (scheduleType == 3)
        printf("%-30s logon\n", "Schedule Type:");
    
    if (computerName == NULL)
        printf("%-30s GhostTask.exe localhost delete \"%s\"\n\n", "Task Deletion Command:", taskName);
    else
        printf("%-30s GhostTask.exe %s delete \"%s\"\n\n", "Task Deletion Command:", computerName, taskName);

    // Close key
    RegCloseKey(hKeyTree);
    RegCloseKey(hKeyTask);
exit:
    free(actionRaw);
    free(action);
    free(uriPath);
    free(treeKey);
    free(plainKey);
    free(taskKey);
    free(fullGuid);
    free(trigger12);
    free(trigger28);
}

void main(int argc, char *argv[]) {
    Arguments arguments;
    if (argc == 2 && (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0)) {
        printHelp();
        return;
    }
    if (!ParseArguments(argv, argc, &arguments))
        return;
    if (arguments.computerName == NULL) {
        if (!CheckSystem()) {
            printf("[-] You have to run it as SYSTEM.\n");
            return;
        }
    }
    if (arguments.taskOperation == TaskAddOperation)
        AddScheduleTask(arguments.computerName, arguments.taskName, arguments.program, arguments.argument, arguments.userName, arguments.scheduleType, arguments.hour, arguments.minute, arguments.second, arguments.dayBitmap);
    else if (arguments.taskOperation == TaskDeleteOperation)
        DeleteScheduleTask(arguments.computerName, arguments.taskName);
    return;
}