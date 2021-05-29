#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/gost.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
using namespace std;
using namespace CryptoPP;
class modGOST
{
private:
  string filein;
  string fileout;
  string psw;
  string salt = "Соль земли русской";
public:
  modGOST() = delete;
  modGOST(const string& file_in, const string& file_out, const string& pass): filein(file_in), fileout(file_out), psw(pass) {};
  bool encrypt();
  bool decrypt();
};