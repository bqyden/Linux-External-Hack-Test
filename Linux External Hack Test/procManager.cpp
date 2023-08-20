#include "procManager.h"

long procManager::findBaseAddress(const char *module){
    int fd = 0;
    char fileLocation[1024];
    char baseAddress[1024];
    char *ptr = NULL;

    sprintf(fileLocation, "/proc/%lu/maps", procID);

    if((fd = open(fileLocation, O_RDONLY)) < 0){
        fprintf(stderr, "Failed to open file\n");
        exit(EXIT_FAILURE);
    }

    char *fileBuffer = (char *)malloc(100000);
    if(fileBuffer == NULL){
        fprintf(stderr, "Failed to malloc()\n");
        exit(EXIT_FAILURE);
    }

    memset(fileBuffer, 0, 100000);
    memset(baseAddress, 0, 1024);

    for(int i = 0; read(fd, fileBuffer + i, 1) > 0; i++);
    close(fd);

    if(module != NULL){
        if((ptr = strstr(fileBuffer, module)) == NULL);
        fprintf(stderr, "Failed to find module\n");
        exit(EXIT_FAILURE);
    } else {
        if((ptr = strstr(fileBuffer, "r-xp")) == NULL){
            fprintf(stderr, "Failed to find memory module\n");
            exit(EXIT_FAILURE);
        }
    }

    while(*ptr != '\n' && ptr >= fileBuffer){
        ptr--;
    }
    ptr++;

    for(int i = 0; *ptr != '-'; i++){
        baseAddress[i] = *ptr;
        ptr++;
    }

    free(fileBuffer);

    return strtol(baseAddress, NULL, 16);
}

bool procManager::writeProcMem(unsigned long address, void *buffer, unit size){
    lseek(procHandle, address, SEEK_SET);

    if(!write(procHandle, buffer, size)){
        fprintf(stderr, "Failed to write to process memory\n");
        return false;
    }

    lseek(procHandle, 0, SEEK_SET);
    return true;
}

bool procManager::readProcMem(unsigned long address, void *buffer, unit size){
    lseek(procHandle, address, SEEK_SET);

    if(!read(procHandle, buffer, size)){
        fprintf(stderr, "Failed to read to process memory\n");
        return false;
    }

    lseek(procHandle, 0, SEEK_SET);
    return true;
}

bool procManager::signaturePayload(const char *signature, char *payload, const int siglen, const int paylen, const int bSize, uint sigOffset){
    char *buf = (char *)malloc(siglen * bSize);
    if(buf == NULL){
        fprintf(stderr, "Failed to allocate memory\n");
        exit(EXIT_FAILURE);
    }

    for(int i = 0; readProcMem(targetBaseAddress + i, buf, siglen * bSize); i += (siglen *bSize)){
        for(int j = 0; j < ((siglen * bSize) - (siglen - 1)); j++){
            if(memcmp(buf + j, signature, siglen) == 0){
                printf("Signature found\n");

                if(payload != NULL){
                    writeProcMem((targetBaseAddress + i + j) + sigOffset, payload, paylen);
                }

                goto END;
            }
        }
    }

END:

    free(buf);
    return true;
}

procManager::procManager(const char *szProcName, const char *module){
    if(strlen(szProcName) > 1023) {
        fprintf(stderr, "Process name is too long\n");
        exit(EXIT_FAILURE);
    }

    strcpy(procNameString, szProcName);

    struct dirent *directoryObject = NULL;
    DIR *directoryHandle = NULL;

    if ((directoryHandle = opendir("/proc/")) == NULL){
        fprintf(stderr, "Failed to attach to /proc/\n");
        exit(EXIT_FAILURE);
    }

    while ((directoryObject = readdir(directoryHandle)) != NULL){
        if (atoi(directoryObject->d_name) != 0){
            char filePath[1024];
            char *fileBuffer = NULL;
            __off_t fileLength = 0;
            int fd = 0;

            sprintf(filePath, "/proc/%s/status", directoryObject->d_name);

            if((fd = open(filePath, O_RDONLY)) < 0){
                fprintf(stderr, "Failed to open file\n");
                exit(EXIT_FAILURE);
            }

            if((fileBuffer = (char *)malloc(fileLength)) == NULL){
                fprintf(stderr, "Failed malloc()\n");
                exit(EXIT_FAILURE);
            }
            memset(fileBuffer, 0, fileLength);

            if(read(fd, fileBuffer, fileLength) < 0){
                fprintf(stderr, "Failed to read file contents\n");
                exit(EXIT_FAILURE);
            }

            close(fd);

            if(strstr(fileBuffer, procNameString) != NULL){
                printf("Process found\n");

                procID = atol(directoryObject->d_name);

                char targetMemLocation[1024];
                sprintf(targetMemLocation, "/proc/%s/mem", directoryObject->d_name);

                // get the program base address
                targetBaseAddress = findBaseAddress(module);

                if((procHandle = open(targetMemLocation, O_RDWR)) < 0){
                    fprintf(stderr, "Failed tyo open target memory\n");
                    exit(EXIT_FAILURE);
                }

                free(fileBuffer);
                break;
            }

            free(fileBuffer);
        }
    }

    closedir(directoryHandle);
}

procManager::~procManager(){
    if(procHandle != 0){
        close(procHandle);
    }
}