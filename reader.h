#ifndef READER_H
#define READER_H

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <cstdio>

class Reader {
public:
    Reader(std::string fileName) : mFileName(fileName), mRead(false) {}
    ~Reader() {}

    const std::vector <unsigned char> &GetContent();

private:
    std::ifstream mFile;
    std::string mFileName;
    std::vector <unsigned char> mData;
    bool mRead;

    void Read ();
};

#endif // READER_H
