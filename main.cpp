/**
 * @author Tohar Markovich
 * @brief CSC 3201 Assignment 3
 */

/*includes*/
#include<fstream>
#include<iostream>
#include<iterator>
#include<openssl/aes.h> /*using openssl aes-128*/
#include<random>
#include<string>
#include<vector>

/*defines*/
#define AES_KEY_SIZE         128
#define HEADER_SIZE          54
#define NUM_KEY_BYTES        16
#define NUM_PROCESSING_BYTES 16

/*function definitions*/

/* -- util -- */
std::vector<unsigned char> generate_key();

/*-- task 1 --*/
void ecb_encrypt
(std::ifstream& in_file, std::ofstream& out_file, const std::vector<unsigned char>& key);

void cbc_encrypt
(std::ifstream& in_file, std::ofstream& out_file, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

void cbc_decrypt
(std::ifstream& in_file, std::ofstream& out_file, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

/*-- task 2 --*/
std::string submit
(std::string enc_text, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
bool verify
(std::string enc_text, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv); 

/*implementations*/
std::vector<unsigned char> generate_key()
{ using namespace std;
    random_device rd;
    vector<unsigned char> key(NUM_KEY_BYTES);
    
    for (auto i{NUM_KEY_BYTES}; i-- > 0;)
        /*rd() returns unsigned int; need to cast to unsigned char*/
        key[i] = static_cast<unsigned char>(rd());

    return key;
}

void ecb_encrypt(
    std::ifstream& in_file, 
    std::ofstream& out_file, 
    const std::vector<unsigned char>& key)
{ using namespace std;
    AES_KEY aes_key; AES_set_encrypt_key(key.data(), AES_KEY_SIZE, &aes_key);

    /*handle 54 byte BMP header*/
    vector<char> header(HEADER_SIZE);
    in_file.read(header.data(), HEADER_SIZE);
    out_file.write(header.data(), HEADER_SIZE);

    /*@todo: read in_file in 16 byte increments, encrypt, write to out_file*/
    /*@todo: handle padding*/
    vector<unsigned char> p_block(NUM_KEY_BYTES);
    vector<unsigned char> c_block(NUM_KEY_BYTES);
    while (in_file.read(reinterpret_cast<char *>(p_block.data()), NUM_KEY_BYTES)) {
        c_block = vector<unsigned char>(NUM_KEY_BYTES);
        AES_encrypt(p_block.data(), c_block.data(), &aes_key);
        out_file.write(reinterpret_cast<const char *>(c_block.data()), NUM_KEY_BYTES);
    }

    auto leftover = in_file.gcount(); // if there are any leftover, we did not fill last block
    auto padding = NUM_KEY_BYTES - leftover;
    
    for (auto i{NUM_KEY_BYTES}; i-- > leftover;) /*PKCS#7 padding*/
        p_block[i] = padding;

    AES_encrypt(p_block.data(), c_block.data(), &aes_key);
    out_file.write(reinterpret_cast<const char *>(c_block.data()), NUM_KEY_BYTES);
}

void cbc_encrypt(
    std::ifstream& in_file, 
    std::ofstream& out_file, 
    const std::vector<unsigned char>& key, 
    const std::vector<unsigned char>& iv)
{ using namespace std;
    AES_KEY aes_key; AES_set_encrypt_key(key.data(), AES_KEY_SIZE, &aes_key);

    /*handle 54 byte BMP header*/
    vector<char> header(HEADER_SIZE);
    in_file.read(header.data(), HEADER_SIZE);
    out_file.write(header.data(), HEADER_SIZE);

    vector<unsigned char> p_block(NUM_KEY_BYTES);
    vector<unsigned char> prev_c_block;
    vector<unsigned char> c_block = iv; // c0 = IV
    while (in_file.read(reinterpret_cast<char *>(p_block.data()), NUM_KEY_BYTES)) {
        prev_c_block = c_block;
        for (auto i{NUM_KEY_BYTES}; i-- > 0;) 
            p_block[i] ^= prev_c_block[i];

        c_block = vector<unsigned char>(NUM_KEY_BYTES);
        /*the current cipher is the encryption previous cipher XOR plaintext*/
        AES_encrypt(p_block.data(), c_block.data(), &aes_key);
        out_file.write(reinterpret_cast<const char *>(c_block.data()), NUM_KEY_BYTES);
    }

    auto leftover = in_file.gcount(); // if there are any leftover, we did not fill last block
    auto padding = NUM_KEY_BYTES - leftover;
    
    for (auto i{NUM_KEY_BYTES}; i-- > 0;) /*PKCS#7 padding*/
        p_block[i] = padding;
    
    for (auto i{NUM_KEY_BYTES}; i-- > 0;)
        p_block[i] ^= c_block[i];

    AES_encrypt(p_block.data(), c_block.data(), &aes_key);
    out_file.write(reinterpret_cast<const char *>(c_block.data()), NUM_KEY_BYTES);
}

void cbc_decrypt(
    std::ifstream& in_file, 
    std::ofstream& out_file, 
    const std::vector<unsigned char>& key, 
    const std::vector<unsigned char>& iv)
{ using namespace std;
    AES_KEY aes_key; AES_set_decrypt_key(key.data(), AES_KEY_SIZE, &aes_key);

    vector<char> header(HEADER_SIZE);
    in_file.read(header.data(), HEADER_SIZE);
    out_file.write(header.data(), HEADER_SIZE);
    
    vector<unsigned char> c_block(NUM_KEY_BYTES);
    vector<unsigned char> prev_c_block = iv;
    vector<unsigned char> p_block(NUM_KEY_BYTES);
    vector<unsigned char> padded_block;

    while (in_file.read(reinterpret_cast<char *>(c_block.data()), NUM_KEY_BYTES)) {
        if (!padded_block.empty())
            out_file.write(reinterpret_cast<const char *>(padded_block.data()), NUM_KEY_BYTES);
        AES_decrypt(c_block.data(), p_block.data(), &aes_key);

        for (auto i{NUM_KEY_BYTES}; i-- > 0;) 
            p_block[i] ^= prev_c_block[i];

        prev_c_block = c_block;
        padded_block = p_block;
    }

    if (padded_block.empty()) return;
    auto padding = padded_block.back();
    if (padding < 1 || padding > NUM_KEY_BYTES) padding = 0;
    out_file.write(reinterpret_cast<const char *>(padded_block.data()), NUM_KEY_BYTES - padding);
}

std::string submit(
    std::string enc_text, 
    const std::vector<unsigned char>& key, 
    const std::vector<unsigned char>& iv)
{ using namespace std;
    const string prefix = "userid=456; userdata=";
    const string suffix = ";session-id=31337";
    /**
     * to URL encode, must build a new string where
     * ; => %3B
     * = => %3D
    */
#define URL_SEMICOLON "%3B"
#define URL_EQUAL     "%3D"
    string url_encoded = "";
    for (const char& c : enc_text) {
        if (';' == c) url_encoded += URL_SEMICOLON;
        else if ('=' == c) url_encoded += URL_EQUAL;
        else url_encoded += c;
    }

    string oracle_text = prefix + url_encoded + suffix;

    /*encrypt using CBC*/
    /*somewhat painful - must write it to a file, pass as input, and read output*/
    string encrypted_string;
    ofstream submit_out_file("submit_file", ios::binary);
    if (!submit_out_file.is_open()) exit(1);
    submit_out_file << string(HEADER_SIZE, '\0') << oracle_text; submit_out_file.close();
    ifstream submit_in_file("submit_file", ios::binary);
    if (!submit_in_file.is_open()) exit(1);
    /*now pass to encrypt, and read the out file again*/
    ofstream submit_enc_file("submit_enc", ios::binary);
    cbc_encrypt(submit_in_file, submit_enc_file, key, iv);
    submit_enc_file.close();
    
    ifstream submit_enc_in("submit_enc", ios::binary);
    encrypted_string.assign(istreambuf_iterator<char>(submit_enc_in), {});

    return encrypted_string.substr(HEADER_SIZE);
}

bool verify(
    std::string enc_text, 
    const std::vector<unsigned char>& key, 
    const std::vector<unsigned char>& iv)
{ using namespace std;
    string decrypted_string;

    ofstream verify_out_file("verify_file", ios::binary);
    if (!verify_out_file.is_open()) exit(1);
    verify_out_file << string(HEADER_SIZE, '\0') << enc_text; verify_out_file.close();
    ifstream verify_in_file("verify_file", ios::binary);
    if (!verify_in_file.is_open()) exit(1);

    ofstream verify_dec_file("verify_dec", ios::binary);
    cbc_decrypt(verify_in_file, verify_dec_file, key, iv);
    verify_dec_file.close();

    ifstream verify_dec_in("verify_dec", ios::binary);
    decrypted_string.assign(istreambuf_iterator<char>(verify_dec_in), {});

    string pattern = ";admin=true;";
    size_t found_idx = decrypted_string.find(pattern);
    if (found_idx != std::string::npos) return true;
    else return false;
}


int main(int argc, char* argv[])
{ using namespace std;
    /*need to accept plaintext file*/
    if (argc < 2) return 1;
    string in_name(argv[1]);
    string out_ecb_name = "encrypted_ecb_" + in_name;
    string out_cbc_name = "encrypted_cbc_" + in_name;

    ifstream in_file(in_name, ios::binary);
    if (!in_file.is_open()) return 1;

    ofstream out_ecb_file(out_ecb_name, ios::binary);
    if (!out_ecb_file.is_open()) return 1;

    ofstream out_cbc_file(out_cbc_name, ios::binary);
    if (!out_cbc_file.is_open()) return 1;

    auto key = generate_key();
    auto iv = generate_key();
    ecb_encrypt(in_file, out_ecb_file, key);
    in_file.clear(); in_file.seekg(0);
    cbc_encrypt(in_file, out_cbc_file, key, iv);

    /*verify returning false*/
    string no_admin_p = "You're the man now, dog";
    string no_admin_c = submit(no_admin_p, key, iv);
    cout << "verify returns false with string " << no_admin_p << ": " << verify(no_admin_c, key, iv) << "\n";

    /*attacking submit to get verify to return true*/
    /**
     * idea: prefix is 21 bytes; if I add an 11 byte filler, that starts me
     * at the end of plaintext block 2. from there, I can provide a plaintext
     * including admin and true and flip the intermediary bits in the ciphertext
     * ie:
     * 
     * *admin?true*
     * xor * with itself then ^ with ;
     * xor ? with itself then ^ with =
     */
    string payload_p = string(11, 'A') + "*admin?true*";
    string payload_c = submit(payload_p, key, iv);
#define FIRST_ASTERISK_IDX 32
    payload_c[FIRST_ASTERISK_IDX - NUM_KEY_BYTES] ^= '*' ^ ';';
#define SECOND_ASTERISK_IDX 43
    payload_c[SECOND_ASTERISK_IDX - NUM_KEY_BYTES] ^= '*' ^ ';';
#define QUESTION_IDX 38
    payload_c[QUESTION_IDX - NUM_KEY_BYTES] ^= '?' ^ '=';

    cout << "verify returns true with string " << payload_p << ": " << verify(payload_c, key, iv) << "\n";
}