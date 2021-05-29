#include "AES.h"

bool modAES::encrypt()
{
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA1> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);
    cout << "Key: ";
    StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));
    cout << endl;

    AutoSeededRandomPool prng;
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    ofstream file_iv(string(fileout + ".iv").c_str(), ios::out | ios::binary);
    file_iv.write((char*)iv, AES::BLOCKSIZE);
    file_iv.close();
    cout << "IV recorded in: " << fileout << ".iv" << endl;

    try {
        CBC_Mode<AES>::Encryption encr;
        encr.SetKeyWithIV(key, key.size(), iv);
        FileSource fs(filein.c_str(), true, new StreamTransformationFilter(encr, new FileSink(fileout.c_str())));
    } catch (const Exception& e) {
        cerr << e.what() << endl;
        return false;
    }

    return true;
}

bool modAES::decrypt()
{
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA1> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    cout << "Key: ";
    StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));
    cout << endl;

    byte iv[AES::BLOCKSIZE];
    ifstream file_iv(string(filein + ".iv").c_str(), ios::in | ios::binary);

    if (file_iv.good()) {
        file_iv.read((char*)&iv, AES::BLOCKSIZE);
        file_iv.close();
    }
    else if (file_iv.bad()) {
        cerr << "IV file does not exist" << endl;
        file_iv.close();
        return false;
    }
    else {
        cerr << "IV file is not correct" << endl;
        file_iv.close();
        return false;
    }

    try {
        CBC_Mode<AES>::Decryption decr;
        decr.SetKeyWithIV(key, key.size(), iv);
        FileSource fs(filein.c_str(), true, new StreamTransformationFilter(decr, new FileSink(fileout.c_str())));
    } catch (const Exception& e) {
        cerr << e.what() << endl;
        return false;
    }

    return true;
}
