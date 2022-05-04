// Copyright (c) 2017-2019 The Swipp developers
// Copyright (c) 2019-2022 The UNIGRID organization
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING.daemon or http://www.opensource.org/licenses/mit-license.php.

#include <functional>
#include <cstdio>

#include <stdlib.h>

class BSArchive
{
private:
    std::FILE *file;
    unsigned char *in;
    unsigned char *out;
    std::function<void(double percentage)> progress;

    int tarParseOct(const char *p, size_t n);
    bool tarIsEndOfArchive(const char *p);
    int tarVerifyChecksum(const char *p);

public:
    BSArchive(std::FILE *file, std::function<void(double percentage)> progress = [](double percentage) -> void { });
    ~BSArchive();

    bool verifyHash();

    int unarchive(std::FILE *destination);

    void createDir(char *pathname, int mode);
    FILE *createFile(char *pathname, int mode);

    void untar(std::FILE *path);
};
