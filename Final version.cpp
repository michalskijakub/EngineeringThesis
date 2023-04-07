#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <chrono>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

using namespace std;
using namespace CryptoPP;

char key = 'a';
char KEY = 'K';

string encryption (string txt, char key) {
    string wynik(txt.size() + 1, '\0');
    wynik[txt.size()] = '\0';
    wynik[0] = (((txt[0] >= 'a' && txt[0] <= 'z') ? txt[0] : (txt[0] + 'a' - 'A')) - 'a') + (((key >= 'a' && key <= 'z') ? key : (key + 'a' - 'A')) - 'a') % 26 + 'a';
    for(int i = 1; i < txt.size(); i++) {
        if (txt[i] != ' ') {
            if (txt[i - 1] == ' ') {
                wynik[i] = ((((txt[i] >= 'a' && txt[i] <= 'z') ? txt[i] : (txt[i] + 'a' - 'A')) - 'a') + (((txt[i - 2] >= 'a' && txt[i - 2] <= 'z') ? txt[i - 2] : (txt[i - 2] + 'a' - 'A')) - 'a')) % 26 + 'a';
            } else {
                wynik[i] = ((((txt[i] >= 'a' && txt[i] <= 'z') ? txt[i] : (txt[i] + 'a' - 'A')) - 'a') + (((txt[i - 1] >= 'a' && txt[i - 1] <= 'z') ? txt[i - 1] : (txt[i - 1] + 'a' - 'A')) - 'a')) % 26 + 'a';
            }
        } else {
            wynik[i] = ' ';
        }
    }
    return wynik;
}

string decryption (string txt, char key) {
    string wynik(txt.size(), '\0');
    wynik[txt.size()] = '\0';
    wynik[0] = ((((txt[0] >= 'a' && txt[0] <= 'z') ? txt[0] : (txt[0] + 'a' - 'A')) - 'a') - (((key >= 'a' && key <= 'z') ? key : (key + 'a' - 'A')) - 'a') + 26) % 26 + 'a';
    for(int i = 1; i < txt.size() - 1; i++) {
        if (txt[i] != ' ') {
            if (txt[i - 1] == ' ') {
                wynik[i] = ((((txt[i] >= 'a' && txt[i] <= 'z') ? txt[i] : (txt[i] + 'a' - 'A')) - 'a') - (((wynik[i - 2] >= 'a' && wynik[i - 2] <= 'z') ? wynik[i - 2] : (wynik[i - 2] + 'a' - 'A')) - 'a') + 26) % 26 + 'a';
            } else {
                wynik[i] = ((((txt[i] >= 'a' && txt[i] <= 'z') ? txt[i] : (txt[i] + 'a' - 'A')) - 'a') - (((wynik[i - 1] >= 'a' && wynik[i - 1] <= 'z') ? wynik[i - 1] : (wynik[i - 1] + 'a' - 'A')) - 'a') + 26) % 26 + 'a';
            }
        } else {
            wynik[i] = ' ';
        }
    }
    return wynik;
}

string encryptXOR(const string& plaintext, char key)
{
    string ciphertext;
    for(char c : plaintext)
    {
        ciphertext += c ^ key;
    }
    return ciphertext;
}

string decryptXOR(const string& ciphertext, char key)
{
    string decrypted;
    for(char c : ciphertext)
    {
        decrypted += c ^ key;
    }
    return decrypted;
}

int nwd(int a, int b)
{
    while(a != b)
       if(a > b)
           a = a - b;
       else
           b = b - a;
    return a;
}

int privateExponent(int e, int phi)
{
    int p0 = 0;
    int p1 = 1;
    int a0 = e;
    int n0 = phi;
    int q  = n0 / a0;
    int r  = n0 % a0;
    int pom = 0;
    while(r > 0)
    {
        pom = p0 - q * p1;
        if(pom >= 0)
        {
        pom = pom % phi;
        }
        else
        {
        pom = phi - ((-pom) % phi);
        }  
        p0 = p1;
        p1 = pom;
        n0 = a0;
        a0 = r;
        q  = n0 / a0;
        r  = n0 % a0;
    }
    return p1;
}

void RSA(string txt)
{
    const int tab[10] = {11, 13, 17, 19, 23, 29, 31, 37, 41, 43};
    int p = 0;
    int q = 0;
    int phi = 0;
    int e = 0;
    int n = 0;
    int d = 0;

    auto begin2 = std::chrono::high_resolution_clock::now();

    do
    {
        p = tab [rand() % 10];
        q = tab [rand() % 10];
    }while(p == q);

    phi = (p - 1) * (q - 1);
    n = p * q;

    for(e = 3; nwd(e, phi) != 1; e = e + 2);
    d = privateExponent(e, phi);

    string message = txt;
    int message_length = message.length();
    int *encrypted_message = new int[message_length];
    int *decrypted_message = new int[message_length];
    int *enc = new int[message_length];
    for(int i = 0; i < message_length; i++)
    {
        encrypted_message[i] = 1;
        for(int j = 1; j <= e; j++)
        {
            encrypted_message[i] = (encrypted_message[i] * message[i]) % n;
        }
    }
    ofstream file5("RSAEncryption.txt");
    for(int i = 0; i < message_length; i++)
    {
      file5 << encrypted_message[i] << " ";
    }
    file5.close();
    for(int z = 0; z < 10; z++)
    {
        for(int i = 0; i < message_length; i++)
        {
            enc[i] = 1;
            for(int j = 1; j <= e; j++)
            {
                enc[i] = (enc[i] * message[i]) % n;
            }
        }
        memset(enc, 0, message_length * sizeof(int));
    }
    for(int i = 0; i < message_length; i++)
    {
        decrypted_message[i] = 1;
        for(int j = 1; j <= d; j++)
        {
            decrypted_message[i] = (decrypted_message[i] * encrypted_message[i]) % n;
        }
    }
    ofstream file6("RSADecryption.txt");
    for (int i = 0; i < message_length; i++)
    {
      file6 << (char) decrypted_message[i];
    }
    file6.close();
    for(int z = 0; z < 10; z++)
    {
        for (int i = 0; i < message_length; i++)
        {
            enc[i] = 1;
            for (int j = 1; j <= d; j++)
            {
                enc[i] = (enc[i] * encrypted_message[i]) % n;
            }
        }
        memset(enc, 0, message_length * sizeof(int));
    }
    auto end2 = std::chrono::high_resolution_clock::now();
    auto elapsed2 = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - begin2);
    cout << "RSA: ";
    cout << elapsed2.count() << " milisekund" << endl;

    delete[] encrypted_message;
    delete[] decrypted_message;
    delete[] enc;
}

int main()
{
    srand((unsigned)time(NULL));

    ifstream inputFile("tekst.txt");
    if(!inputFile.is_open()) {
        cerr << "Wrong file" << endl;
        return 1;
    }
    string txt;
    char c;
    while(inputFile.get(c)) {
        txt += c;
    }

    inputFile.close();
    cout << "Czas wynosi:" << endl;
    auto begin = std::chrono::high_resolution_clock::now();
    string encrypted = encryption(txt, key);
    for(int i = 0; i < 100000; i++)
    {
        string enc = encryption(txt, key);
        enc = txt;
    }
    
    string decrypted = decryption(encrypted, key);
    for(int i = 0; i < 100000; i++)
    {
        string enc = decryption(encrypted, key);
        enc = encrypted;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
    ofstream file("VigenereEncryption.txt", ios::out | ios::app);
    file << encrypted;
    file.close();
    ofstream file2("VigenereDecryption.txt", ios::out | ios::app);
    file2 << decrypted;
    file2.close();
    cout << "Vigenere = ";
    cout << elapsed.count() << " milisekund" << endl;
    auto begin1 = std::chrono::high_resolution_clock::now();
    encrypted = encryptXOR(txt, KEY);
    for(int i = 0; i < 100000; i++)
    {
        string enc = encryptXOR(txt, KEY);
        enc = txt;
    }
    decrypted = decryptXOR(encrypted, KEY);
    for(int i = 0; i < 100000; i++)
    {
        string enc = decryptXOR(encrypted, KEY);
        enc = encrypted;
    }
    auto end1 = std::chrono::high_resolution_clock::now();
    auto elapsed1 = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - begin1);
    ofstream file3("XOREncryption.txt", ios::out | ios::app);
    file3 << encrypted;
    file3.close();
    ofstream file4("XORDecryption.txt", ios::out | ios::app);
    file4 << decrypted;
    file4.close();
    cout << "XOR = ";
    cout << elapsed1.count() << " milisekund" << endl;
    string key = "0123456789ABCDEF0123456789ABCDEF";
    string iv = "0123456789ABCDEF0123456789ABCDEF";

    auto begin3 = std::chrono::high_resolution_clock::now();
    string ciphertext;
    try
    {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());

        StringSource ss(txt, true,
            new StreamTransformationFilter(enc,
                new HexEncoder(
                    new StringSink(ciphertext)
                )
            )
        );
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        return 1;
    }
    for(int q=0; q<100000; q++)
    {
        string ciphertext2;
        try
        {
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());

            StringSource ss(txt, true,
                new StreamTransformationFilter(enc,
                    new HexEncoder(
                        new StringSink(ciphertext2)
                    )
                )
            );
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return 1;
        }
    }
    ofstream file5("AESEncryption.txt", ios::out | ios::app);
    file5 << ciphertext;
    file5.close();
    string decryptedMessage;
    try
    {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());

        StringSource ss(ciphertext, true,
            new HexDecoder(
                new StreamTransformationFilter(dec,
                    new StringSink(decryptedMessage)
                )
            )
        );
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        return 1;
    }
    for(int q=0; q<100000; q++)
    {
        string ciphertext2;
        try
        {
            CBC_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());

            StringSource ss(ciphertext, true,
                new HexDecoder(
                    new StreamTransformationFilter(dec,
                        new StringSink(ciphertext2)
                    )
                )
            );
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            return 1;
        }
    }
    auto end3 = std::chrono::high_resolution_clock::now();
    auto elapsed3 = std::chrono::duration_cast<std::chrono::milliseconds>(end3 - begin3);
    cout << "AES = ";
    cout << elapsed3.count() << " milisekund" << endl;
    ofstream file6("AESDecryption.txt", ios::out | ios::app);
    file6 << decryptedMessage;
    file6.close();
    RSA(txt);
    return 0;
}