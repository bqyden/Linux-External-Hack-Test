#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

typedef unsigned int unit;

class procManager
{
private:
    char procNameString[1024];
    long procID = 0;
    int procHandle = 0;
    
    long findBaseAddress(const char *module = NULL);

public:
    unsigned long targetBaseAddress = 0;

    procManager(const char *szProcessName, const char *module = NULL);
    ~procManager();

    bool signaturePayload(const char *signature, char *payload, const int siglen, const int paylen, const int bSize, uint sigOffset = 0);
    
    bool writeProcMem(unsigned long address, void *buffer, unit size);
    bool readProcMem(unsigned long address, void *buffer, uint size);
};