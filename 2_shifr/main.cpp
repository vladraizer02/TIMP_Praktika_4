#include <AES.h>
#include <GOST.h>

int main ()
{
    unsigned op, alg;
    string file_in, file_out, key;
    do {
        cout << "Cipher ready. Input algorithm (0-exit, 1-AES, 2-GOST): ";
        cin >> alg;
        if (alg != 0) {
            cout<<"Input operation (0-exit, 1-encrypt, 2-decrypt): ";
            cin >> op;
        }
        if (alg > 2) {
            cerr << "Illegal algorithm" << endl;
        }
        else if (alg > 0) {
            cout << "Enter a path to input file: ";
            cin >> file_in;
            cout << "Enter a path to output file: ";
            cin >> file_out;
            cout << "Enter a key: ";
            cin >> key;
            if (alg == 1) {
                modAES aes(file_in, file_out, key);
                if (op == 1) {
                    if (aes.encrypt())
                        cout << "Encription completed" << endl;
                    else
                        cout << "Encryption failed" << endl;
                } else {
                    if (aes.decrypt())
                        cout << "Decription completed" << endl;
                    else
                        cout << "Decryption failed" << endl;
                }
            }
            else if (alg == 2) {
                modGOST gost(file_in, file_out, key);
                if (op == 1) {
                    if (gost.encrypt())
                        cout << "Encription completed" << endl;
                    else
                        cout << "Encryption failed" << endl;
                } else {
                    if (gost.decrypt())
                        cout << "Decription completed" << endl;
                    else
                        cout << "Decryption failed" << endl;
                }
            }
            else {
                cerr << "Algorithm aborted: invalid text" << endl;
            }
        }
    } while (alg != 0);
    return 0;
}
