#include "procManager.h"

int main(){
    const char szSignature[] = "\x48\x8b\x45\x28\x83\x28\x01\x48"; //Assault Cube Signature
    char szOpCode[] = "\x90\x90\x90";

    procManager procManager("ac_client");

    procManager.signaturePayload(szSignature, szOpCode, strlen(szSignature), strlen(szOpCode), 64, 4);

    exit(EXIT_SUCCESS);
}