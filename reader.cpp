#include "reader.h"

const std::vector <unsigned char>& Reader::GetContent() {
    if (!mRead)
        Read();

    return mData;
}

void Reader::Read () {
    mFile.open(mFileName.c_str(), std::ios::binary);

    if (mFile.fail()) {
        return;
    }

    long fSize = mFile.tellg();
    mFile.seekg( 0, std::ios::end );
    fSize = mFile.tellg() - fSize;
    mFile.seekg( 0, std::ios::beg );

    mData.resize(static_cast<unsigned long>(fSize));
    char *vecPtr = reinterpret_cast<char*>(mData.data());
    mFile.read(vecPtr, fSize);
    mFile.close();

    mRead = true;
}
