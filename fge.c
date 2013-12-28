#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <openssl/evp.h>

int main(int argc, char **argv) {
    int i, x;
    if (argc < 3) {
        printf("fge -s file s1 l1 [s2 l2 ... sn ln]\nfge -c file\nfge -u file\n");
        exit(1);
    }

    unsigned int argcu = ((argc - 3) / 2);
    if (((argcu - 3) / 2) > 4294967295) {
        printf("Unsupported number of arguments\n");
        exit(1);
    }

    if (strncmp(argv[1], "-s", 2) == 0) {
        if (argc < 5 || argc % 2 == 0) {
            printf("fge -s file s1 l1 [s2 l2 ... sn ln]\nfge -c file\nfge -u file\n");
            exit(1);
        }

        int myArgc = argc;
        char** myArgv = malloc((myArgc + 1) * sizeof(char *));
        if (myArgv == NULL) {
            printf("Failed to malloc enough memory\n");
            exit(1);
        }

        for (i = 0; i < myArgc; i++) {
            myArgv[i] = strdup(argv[i]);
        }
        myArgv[myArgc] = NULL;

        int fd = open(argv[2], O_RDWR | O_NOFOLLOW);
        if (fd < 0) {
            printf("Failed to open file\n");
            free(myArgv);
            exit(1);
        }

        FILE *ffd = fdopen(fd, "r");
        if (ffd == NULL) {
            printf("Failed to open file\n");
            free(myArgv);
            close(fd);
            exit(1);
        }

        int kidCheck = 0;
        char *read = malloc(sizeof(char)*4);
        if (read == NULL) {
            printf("Failed to malloc enough memory\n");
            free(myArgv);
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(char), 4, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(myArgv);
            free(read);
            fclose(ffd);
            exit(1);
        }

        if (strncmp(read, "SuCc", 4) == 0) {
            printf("Error file already encrypted\n");
            free(myArgv);
            free(read);
            fclose(ffd);
            exit(1);
        }
        free(read);

        if (fseek(ffd, 0, SEEK_SET) == -1) {
            printf("Error seeking to beginning of file\n");
            free(myArgv);
            fclose(ffd);
            exit(1);
        }

        int fileSize = 0;
        char *read1 = malloc(sizeof(char));
        if (read1 == NULL) {
            printf("Failed to malloc enough memory\n");
            free(myArgv);
            fclose(ffd);
            exit(1);
        }

        while ((kidCheck = fread(read1, sizeof(char), 1, ffd)) > 0) {
            if (kidCheck <= 0) {
                printf("Empty File\n");
                free(myArgv);
                free(read1);
                fclose(ffd);
                exit(1);
            }
            fileSize++;
        }
        free(read1);

        if (fseek(ffd, 0, SEEK_SET) == -1) {
            printf("Error seeking to beginning of file\n");
            free(myArgv);
            fclose(ffd);
            exit(1);
        }

        FILE *encFile = fopen(strcat(argv[2], ".enc"), "w+");
        if (encFile == NULL) {
            printf("Failed to create file\n");
            free(myArgv);
            fclose(ffd);
            exit(1);
        }

        /* Write KID, MAGIC */
        if (fwrite("SuCc", sizeof(int), 1, encFile) != 1) {
            printf("Failed to write to file\n");
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (fwrite("eNcR", sizeof(int), 1, encFile) != 1) {
            printf("Failed to write to file\n");
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        /* Write to buffer for all arguments based on (argc - 3) / 2 loop replace */
        int bufSize = 4;
        unsigned char *buffer = malloc(4);
        if (buffer == NULL) {
            printf("Failed to malloc enough memory\n");
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        bzero(buffer, 4);
        unsigned char *tempBuffer;
        for (i = 0; i < argcu; i++) {
            int sOffset = atoi(myArgv[((i * 2) + 3)]);
            int sLength = atoi(myArgv[((i * 2) + 4)]);
            if (sOffset > fileSize || (sOffset + sLength) > fileSize) {
                printf("Error your offset or length are longer then the file\n");
                free(buffer);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }

            tempBuffer = realloc(buffer, (sLength + 8 + bufSize));
            if (tempBuffer == NULL) {
                printf("Error trying to realloc memory space\n");
                free(buffer);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
            buffer = tempBuffer;
            tempBuffer = buffer + bufSize;
            bzero(tempBuffer, (sLength + 8));
            bufSize = (sLength + 8 + bufSize);

            if (memcpy(tempBuffer, &sOffset, 4) != tempBuffer) {
                printf("Error copying offset\n");
                free(buffer);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
            if (memcpy(tempBuffer + 4, &sLength, 4) != (tempBuffer + 4)) {
                printf("Error copying offset\n");
                free(buffer);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
            tempBuffer += 8;
            if (fseek(ffd, sOffset, SEEK_SET) == -1) {
                printf("Error seeking to beginning of file\n");
                free(buffer);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
            if (fread(tempBuffer, sLength, 1, ffd) <= 0) {
                printf("Error reading from file\n");
                free(buffer);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
        }
        tempBuffer = buffer;

        /* Write (argc - 3) / 2 */
        if (memcpy(buffer, &argcu, 4) != tempBuffer) {
            printf("Error copying n\n");
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        /* Determine K_file */
        if (fseek(ffd, 0, SEEK_SET) == -1) {
            printf("Error seeking to beginning of file\n");
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        FILE *randomNum = fopen("/dev/urandom", "r");
        if (randomNum == NULL) {
            printf("Failed to generate random numbers\n");
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        unsigned char kFile[16];
        mlock(&kFile, 16);
        for (i = 0; i < 16; i++) {
            if (fread(&kFile[i], 1, 16 - i, randomNum) <= 0) {
                printf("Error reading from file\n");
                free(buffer);
                free(myArgv);
                fclose(randomNum);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
        }
        fclose(randomNum);

        int ctlen = 0;
        unsigned char ivec[EVP_MAX_IV_LENGTH] = {0};
        unsigned char *ciphertext = (unsigned char *)malloc(sizeof(char) * (fileSize + 9));
        if (ciphertext == NULL) {
            printf("Failed to malloc enough memory\n");
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        /* Encrypt the buffer here with K_file */
        EVP_CIPHER *cipher=(EVP_CIPHER *)EVP_bf_cbc();
        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
        if (ctx == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertext);
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        EVP_CIPHER_CTX_init(ctx);
        if (EVP_EncryptInit_ex(ctx,cipher,NULL,kFile,ivec) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (EVP_EncryptUpdate(ctx, ciphertext, &ctlen, buffer, bufSize) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            free(buffer);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        int size = ctlen;
        unsigned char *cipherBuf = (unsigned char *)malloc(sizeof(unsigned char) * ctlen);
        if (cipherBuf == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertext);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        unsigned char *cipherBufTemp = cipherBuf;

        if (memcpy(cipherBuf, ciphertext, size) != cipherBufTemp) {
            printf("Error copying ciphertext\n");
            free(cipherBuf);
            free(ciphertext);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (EVP_EncryptFinal_ex(ctx, ciphertext, &ctlen) == 0) {
            printf("Encryption failed\n");
            free(cipherBuf);
            free(ciphertext);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (ctlen > 0) {
            cipherBufTemp = realloc(cipherBuf, (size + ctlen));
            if (cipherBufTemp == NULL) {
                printf("Error trying to realloc memory space\n");
                free(cipherBuf);
                free(ciphertext);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }

            cipherBuf = cipherBufTemp;
            cipherBufTemp += size;
            size += ctlen;
            if (memcpy(cipherBufTemp, ciphertext, size) != cipherBufTemp) {
                printf("Error copying ciphertext\n");
                free(cipherBuf);
                free(ciphertext);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
        }
        cipherBufTemp = cipherBuf;
        free(ciphertext);

        /* Create buf for KID, KEY(K File) */
        unsigned char *kidKeyBuf = malloc(sizeof(char) * 20);
        if (kidKeyBuf == NULL) {
            printf("Failed to malloc enough memory\n");
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        unsigned char *tempKeyBuf = kidKeyBuf;
        if (memcpy(tempKeyBuf, "SuCc", 4) != tempKeyBuf) {
            printf("Error copying KID\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        tempKeyBuf += 4;
        if (memcpy(tempKeyBuf, kFile, 16) != tempKeyBuf) {
            printf("Error copying Key\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        for (i = 0; i < 16; i++) {
            kFile[i] = 0;
        }
        munlock(&kFile, 16);

        /* get pass phrase to encrypt classified pieces of memory */
        char enter[64];
        char reenter[64];
        mlock(&enter, 64);
        mlock(&reenter, 64);
        do {
            printf("Enter a passphrase for the file: ");
            fgets(enter, 64, stdin);
            printf("Reenter the passphrase for file: ");
            fgets(reenter, 64, stdin);
        } while (strncmp(enter, reenter, strlen(enter)) != 0);

        for (i = 0; i < 64; i++) {
            reenter[i] = 0;
        }
        munlock(&reenter, 64);

        /* Determine K_key */
        unsigned int mdlen;
        unsigned char ekey[20];
        EVP_MD_CTX *mdctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
        if (mdctx == NULL) {
            printf("Failed to malloc enough memory\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        EVP_MD_CTX_init(mdctx);
        if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 0) {
            printf("Encryption failed\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (EVP_DigestUpdate(mdctx, enter, strlen(enter) - 1) == 0) {
            printf("Encryption failed\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        for (i = 0; i < 64; i++) {
            enter[i] = 0;
        }
        munlock(&enter, 64);

        if (EVP_DigestFinal_ex(mdctx, ekey, &mdlen) == 0) {
            printf("Encryption failed\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        ekey[16] = '\0';
        
        /* Encrypt kidKey buffer */
        int ctlenTwo = 0;
        unsigned char ivecTwo[EVP_MAX_IV_LENGTH] = {0};
        unsigned char *ciphertextTwo = (unsigned char *)malloc(sizeof(char) * (28));
        if (ciphertextTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        EVP_CIPHER *cipherTwo = (EVP_CIPHER *)EVP_bf_cbc();
        EVP_CIPHER_CTX *ctxTwo = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
        if (ctxTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertextTwo);
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        EVP_CIPHER_CTX_init(ctxTwo);
        if (EVP_EncryptInit_ex(ctxTwo, cipherTwo, NULL, ekey, ivecTwo) == 0) {
            printf("Encryption failed\n");
            free(ciphertextTwo);
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (EVP_EncryptUpdate(ctxTwo, ciphertextTwo, &ctlenTwo, kidKeyBuf, 20) == 0) {
            printf("Encryption failed\n");
            free(ciphertextTwo);
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        int sizeTwo = ctlenTwo;
        unsigned char *cipherBufTwo = (unsigned char *)malloc(sizeof(unsigned char) * ctlenTwo);
        if (cipherBufTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertextTwo);
            free(kidKeyBuf);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        unsigned char *cipherBufTempTwo = cipherBufTwo;
        free(kidKeyBuf);

        if (memcpy(cipherBufTwo, ciphertextTwo, sizeTwo) != cipherBufTempTwo) {
            printf("Error copying ciphertext\n");
            free(cipherBufTwo);
            free(ciphertextTwo);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (EVP_EncryptFinal_ex(ctxTwo, ciphertextTwo, &ctlenTwo) == 0) {
            printf("Encryption failed\n");
            free(cipherBufTwo);
            free(ciphertextTwo);
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (ctlenTwo > 0) {
            if ((sizeTwo + ctlenTwo) > 29) {
                cipherBufTempTwo = realloc(cipherBufTwo, (sizeTwo + ctlenTwo));
                if (cipherBufTempTwo == NULL) {
                    printf("Error trying to realloc memory space\n");
                    free(cipherBufTwo);
                    free(ciphertextTwo);
                    free(cipherBuf);
                    free(myArgv);
                    fclose(encFile);
                    fclose(ffd);
                    exit(1);
                }
            }
            cipherBufTwo = cipherBufTempTwo;
            cipherBufTempTwo += sizeTwo;
            sizeTwo += ctlenTwo;
            if (memcpy(cipherBufTempTwo, ciphertextTwo, sizeTwo) != cipherBufTempTwo) {
                printf("Error copying ciphertext\n");
                free(cipherBufTwo);
                free(ciphertextTwo);
                free(cipherBuf);
                free(myArgv);
                fclose(encFile);
                fclose(ffd);
                exit(1);
            }
        }
        cipherBufTempTwo = cipherBufTwo;
        free(ciphertextTwo);

        /* Determine real buf size and write start */
        bufSize = (12 + size + sizeTwo);
        if (fwrite(&bufSize, sizeof(int), 1, encFile) != 1) {
            printf("Failed to write to file\n");
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        /* Write encrypted buffer */
        if (fwrite(cipherBufTwo, sizeof(char), sizeTwo, encFile) != sizeTwo) {
            printf("Failed to write to file\n");
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        
        /* Write Buffer loop print S1 and L1 first */
        if (fwrite(cipherBuf, sizeof(char), size, encFile) != size) {
            printf("Failed to write to file\n");
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        /* Write file replace classified with 'X' */
        if (fseek(ffd, 0, SEEK_SET) == -1) {
            printf("Error seeking to beginning of file\n");
            free(cipherBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }
        free(cipherBuf);

        char *fileBuf = malloc(sizeof(char) * fileSize);
        if (fileBuf == NULL) {
            printf("Failed to malloc enough memory\n");
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        if (fread(fileBuf, fileSize, 1, ffd) <= 0) {
            printf("Error reading from file\n");
            free(fileBuf);
            free(myArgv);
            fclose(encFile);
            fclose(ffd);
            exit(1);
        }

        for (i = 0; i < argcu; i++) {
            int sOffset = atoi(myArgv[((i * 2) + 3)]);
            int sLength = atoi(myArgv[((i * 2) + 4)]);

            for (x = 0; x < sLength; x++) {
                fileBuf[(x + sOffset)] = 0xFF;
            }
        }
        free(myArgv);

        char endChar = 0xFF;
        int found = 0;
        for (i = 0; i < fileSize; i++) {
            if (strncmp(&fileBuf[i], &endChar, 1) == 0) {
                if (found == 0) {
                    if (fwrite("X", sizeof(char), 1, encFile) != 1) {
                        printf("Failed to write to file\n");
                        free(fileBuf);
                        fclose(encFile);
                        fclose(ffd);
                        exit(1);
                    }
                    found = 1;
                }
            } else {
                found = 0;
                if (fwrite(&fileBuf[i], sizeof(char), 1, encFile) != 1) {
                    printf("Failed to write to file\n");
                    free(fileBuf);
                    fclose(encFile);
                    fclose(ffd);
                    exit(1);
                }
            }
        }

        free(fileBuf);
        fclose(encFile);
        fclose(ffd);
    } else if (strncmp(argv[1], "-c", 2) == 0) {
        if (argc > 3 || argc < 3) {
            printf("fge -s file s1 l1 [s2 l2 ... sn ln]\nfge -c file\nfge -u file\n");
    	    exit(1);
        }

        int fd = open(argv[2], O_RDWR | O_NOFOLLOW);
        if (fd < 0) {
            printf("Failed to open file\n");
            exit(1);
        }

        FILE *ffd = fdopen(fd, "r");
        if (ffd == NULL) {
            printf("Failed to open file\n");
            close(fd);
            exit(1);
        }

        int kidCheck = 0;
        char *read = malloc(sizeof(char)*4);
        if (read == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(char), 4, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(read);
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(char), 4, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(read);
            fclose(ffd);
            exit(1);
        }
        free(read);

        int *readTwo = malloc(sizeof(int));
        if (readTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(readTwo, sizeof(int), 1, ffd);
        if (kidCheck <= 0) {
            printf("File too small\n");
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        unsigned char *readThree = malloc(sizeof(char) * 24);
        if (readThree == NULL) {
            printf("Failed to malloc enough memory\n");
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        kidCheck = fread(readThree, sizeof(char), 24, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        /* get pass phrase to encrypt classified pieces of memory */
        char enter[64];
        mlock(&enter, 64);
        printf("Please enter the passphrase: ");
        fgets(enter, 64, stdin);

        /* Determine K_key */
        unsigned int mdlen;
        unsigned char ekey[20];
        EVP_MD_CTX *mdctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
        if (mdctx == NULL) {
            printf("Failed to malloc enough memory\n");
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        EVP_MD_CTX_init(mdctx);
        if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 0) {
            printf("Encryption failed\n");
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        if (EVP_DigestUpdate(mdctx, enter, strlen(enter) - 1) == 0) {
            printf("Encryption failed\n");
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        for (i = 0; i < 64; i++) {
            enter[i] = 0;
        }
        munlock(&enter, 64);

        if (EVP_DigestFinal_ex(mdctx, ekey, &mdlen) == 0) {
            printf("Encryption failed\n");
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        ekey[16] = '\0';

        int ctlen = 0;
        unsigned char ivec[EVP_MAX_IV_LENGTH] = {0};
        unsigned char *ciphertext = (unsigned char *)malloc(sizeof(char) * 24);
        if (ciphertext == NULL) {
            printf("Failed to malloc enough memory\n");
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        bzero(ciphertext, 24);

        /* Encrypt the buffer here with K_file */
        EVP_CIPHER *cipher=(EVP_CIPHER *)EVP_bf_cbc();
        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
        if (ctx == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertext);
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        EVP_CIPHER_CTX_init(ctx);
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, ekey, ivec) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        if (EVP_DecryptUpdate(ctx, ciphertext, &ctlen, readThree, 24) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            free(readThree);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        free(readThree);

        int size = ctlen;
        if (EVP_DecryptFinal_ex(ctx, &ciphertext[ctlen], &ctlen) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        size += ctlen;

        if (strncmp((char *)ciphertext, "SuCc", 4) != 0) {
            printf("Incorrect passphrase entered\n");
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        ciphertext += 4;

        if (fseek(ffd, 36, SEEK_SET) == -1) {
            printf("Error seeking start offset\n");
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        /* Get encrypted body */
        int encBody = (*readTwo - 36);
        unsigned char *encBodyBuf = malloc(sizeof(char) * encBody);
        if (encBodyBuf == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        for (i = 0; i < encBody; i++) {
            fread(&encBodyBuf[i], sizeof(char), 1, ffd);
        }

        /* Decrypt body */
        ctlen = 0;
        unsigned char *ciphertextTwo = (unsigned char *)malloc(sizeof(char) * encBody);
        if (ciphertextTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            free(encBodyBuf);
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        bzero(ciphertextTwo, encBody);

        /* Encrypt the buffer here with K_file */
        EVP_CIPHER *cipherTwo = (EVP_CIPHER *)EVP_bf_cbc();
        EVP_CIPHER_CTX *ctxTwo = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
        if (ctxTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertextTwo);
            free(encBodyBuf);
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        EVP_CIPHER_CTX_init(ctxTwo);
        if (EVP_DecryptInit_ex(ctxTwo, cipherTwo, NULL, ciphertext, ivec) == 0) {
            printf("Encryption failed\n");
            free(ciphertextTwo);
            free(encBodyBuf);
            free(ciphertext);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        if (EVP_DecryptUpdate(ctxTwo, ciphertextTwo, &ctlen, encBodyBuf, encBody) == 0) {
            printf("Encryption failed\n");
            free(ciphertextTwo);
            free(encBodyBuf);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        int sizeTwo = ctlen;
        if (EVP_DecryptFinal_ex(ctxTwo, &ciphertextTwo[ctlen], &ctlen) == 0) {
            printf("Encryption failed\n");
            free(ciphertextTwo);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        sizeTwo += ctlen;

        /* replace X's in unclassified body by writing until you find an X and then writing classified segment */
        if (fseek(ffd, *readTwo, SEEK_SET) == -1) {
            printf("Error seeking to start\n");
            free(ciphertextTwo);
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        free(readTwo);

        ciphertextTwo += 4;
        char *readFour = malloc(sizeof(char));


        int readFive = 0;
        while (fread(readFour, sizeof(char), 1, ffd) > 0) {
            if (strncmp(readFour, "X", 1) == 0) {
                /* Use read to get offset and then length loop length with read two printing out char by char */
                ciphertextTwo += 4;
                memcpy(&readFive, ciphertextTwo, 4);
                ciphertextTwo += 4;
                for (i = 0; i < readFive; i++) {
                    fwrite(ciphertextTwo, sizeof(char), 1, stdout);
                    ciphertextTwo++;
                }
            } else {
                fwrite(readFour, sizeof(char), 1, stdout);
            }
        }

        /* Free all the memory */

        free(readFour);
        fclose(ffd);
    } else if (strncmp(argv[1], "-u", 2) == 0) {
        if (argc > 3 || argc < 3) {
    	    printf("fge -s file s1 l1 [s2 l2 ... sn ln]\nfge -c file\nfge -u file\n");
    	    exit(1);
        }

        int fd = open(argv[2], O_RDWR | O_NOFOLLOW);
        if (fd < 0) {
            printf("Failed to open file\n");
            exit(1);
        }

        FILE *ffd = fdopen(fd, "r");
        if (ffd == NULL) {
            printf("Failed to open file\n");
            close(fd);
            exit(1);
        }

        int kidCheck = 0;
        int *read = malloc(sizeof(int));
        if (read == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(int), 1, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(read);
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(int), 1, ffd);
        if (kidCheck <= 0) {
            printf("File not large enough\n");
            free(read);
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(int), 1, ffd);
        if (kidCheck <= 0) {
            printf("File not large enough\n");
            free(read);
            fclose(ffd);
            exit(1);
        }

        if (fseek(ffd, 0, SEEK_SET) == -1) {
            printf("Error seeking to beginning of file\n");
            free(read);
            fclose(ffd);
            exit(1);
        }

        if (fseek(ffd, *read, SEEK_SET) == -1) {
            printf("Error seeking start offset\n");
            free(read);
            fclose(ffd);
            exit(1);
        }
        free(read);

        char *readOne = malloc(sizeof(char));
        if (readOne == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }

        while (fread(readOne, sizeof(char), 1, ffd) > 0) {
            printf("%s", readOne);
        }
        free(readOne);
        fclose(ffd);
    } else if (strncmp(argv[1], "key", 3) == 0) {
        if (argc > 3 || argc < 3) {
    	    exit(1);
        }

        int fd = open(argv[2], O_RDWR | O_NOFOLLOW);
        if (fd < 0) {
            printf("Failed to open file\n");
            exit(1);
        }

        FILE *ffd = fdopen(fd, "r");
        if (ffd == NULL) {
            printf("Failed to open file\n");
            close(fd);
            exit(1);
        }

        int kidCheck = 0;
        char *read = malloc(sizeof(char)*4);
        if (read == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(read, sizeof(char), 4, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(read);
            fclose(ffd);
            exit(1);
        }
        free(read);

        char *readTwo = malloc(sizeof(char)*4);
        if (readTwo == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(readTwo, sizeof(char), 4, ffd);
        if (kidCheck <= 0) {
            printf("File too small\n");
            free(readTwo);
            fclose(ffd);
            exit(1);
        }

        kidCheck = fread(readTwo, sizeof(char), 4, ffd);
        if (kidCheck <= 0) {
            printf("File too small\n");
            free(readTwo);
            fclose(ffd);
            exit(1);
        }
        free(readTwo);

        unsigned char *readThree = malloc(sizeof(char) * 24);
        if (readThree == NULL) {
            printf("Failed to malloc enough memory\n");
            fclose(ffd);
            exit(1);
        }
        kidCheck = fread(readThree, sizeof(char), 24, ffd);
        if (kidCheck <= 0) {
            printf("Empty File\n");
            free(readThree);
            fclose(ffd);
            exit(1);
        }

        /* get pass phrase to encrypt classified pieces of memory */
        char enter[64];
        mlock(&enter, 64);
        printf("Please enter the passphrase: ");
        fgets(enter, 64, stdin);

        /* Determine K_key */
        unsigned int mdlen;
        unsigned char ekey[20];
        EVP_MD_CTX *mdctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
        if (mdctx == NULL) {
            printf("Failed to malloc enough memory\n");
            free(readThree);
            fclose(ffd);
            exit(1);
        }

        EVP_MD_CTX_init(mdctx);
        if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 0) {
            printf("Encryption failed\n");
            free(readThree);
            fclose(ffd);
            exit(1);
        }

        if (EVP_DigestUpdate(mdctx, enter, strlen(enter) - 1) == 0) {
            printf("Encryption failed\n");
            free(readThree);
            fclose(ffd);
            exit(1);
        }
        for (i = 0; i < 64; i++) {
            enter[i] = 0;
        }
        munlock(&enter, 64);

        if (EVP_DigestFinal_ex(mdctx, ekey, &mdlen) == 0) {
            printf("Encryption failed\n");
            free(readThree);
            fclose(ffd);
            exit(1);
        }
        ekey[16] = '\0';

        int ctlen = 0;
        unsigned char ivec[EVP_MAX_IV_LENGTH] = {0};
        unsigned char *ciphertext = (unsigned char *)malloc(sizeof(char) * 24);
        if (ciphertext == NULL) {
            printf("Failed to malloc enough memory\n");
            free(readThree);
            fclose(ffd);
            exit(1);
        }
        bzero(ciphertext, 24);

        /* Encrypt the buffer here with K_file */
        EVP_CIPHER *cipher=(EVP_CIPHER *)EVP_bf_cbc();
        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
        if (ctx == NULL) {
            printf("Failed to malloc enough memory\n");
            free(ciphertext);
            free(readThree);
            fclose(ffd);
            exit(1);
        }

        EVP_CIPHER_CTX_init(ctx);
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, ekey, ivec) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            free(readThree);
            fclose(ffd);
            exit(1);
        }

        if (EVP_DecryptUpdate(ctx, ciphertext, &ctlen, readThree, 24) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            fclose(ffd);
            exit(1);
        }

        int size = ctlen;
        if (EVP_DecryptFinal_ex(ctx, &ciphertext[ctlen], &ctlen) == 0) {
            printf("Encryption failed\n");
            free(ciphertext);
            fclose(ffd);
            exit(1);
        }
        size += ctlen;
        if (strncmp((char *)ciphertext, "SuCc", 4) == 0) {
            printf("K_Key: 0x");
            for (i = 0; i < 16; i++) {
                printf(" %02X", ekey[i]);
            }
            printf("\n");
        } else {
            printf("Incorrect passphrase entered\n");
            free(ciphertext);
            free(readThree);
            exit(1);
        }

        free(ciphertext);
        free(readThree);
        fclose(ffd);
    } else {
        printf("fge -s file s1 l1 [s2 l2 ... sn ln]\nfge -c file\nfge -u file\n");
        exit(1);
    }

    return 0;
}