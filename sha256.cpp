#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <cstdint>
#include <fstream> 

using namespace std;
const unsigned int k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
inline unsigned int rightRotate(unsigned int value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

vector<unsigned char> padMessage(const string& message) {
    vector<unsigned char> paddedMessage(message.begin(), message.end());

    // Padding
    paddedMessage.push_back(0x80);
    while ((paddedMessage.size() * 8) % 512 != 448) {
        paddedMessage.push_back(0x00);
    }

    // Append message length as a 64-bit big-endian integer
    uint64_t messageLengthBits = message.size() * 8;
    for (int i = 7; i >= 0; --i) {
        paddedMessage.push_back((messageLengthBits >> (i * 8)) & 0xFF);
    }

    return paddedMessage;
}

// Process the 512-bit chunks of the message
void processChunk(const vector<unsigned char>& chunk, unsigned int* h) {
    unsigned int w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16) | (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
    }

    for (int i = 16; i < 64; ++i) {
        unsigned int s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    unsigned int a = h[0];
    unsigned int b = h[1];
    unsigned int c = h[2];
    unsigned int d = h[3];
    unsigned int e = h[4];
    unsigned int f = h[5];
    unsigned int g = h[6];
    unsigned int hh = h[7];

    for (int i = 0; i < 64; ++i) {
        unsigned int S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        unsigned int temp1 = hh + S1 + ch + k[i] + w[i];
        unsigned int S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
        unsigned int temp2 = S0 + maj;

        hh = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

// SHA-256 hash function
string sha256(const string& message) {
    // Initial hash values (first 32 bits of fractional parts of the square roots of the first 8 primes 2..19)
    unsigned int h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    vector<unsigned char> paddedMessage = padMessage(message);

    // Process each 512-bit chunk
    for (size_t i = 0; i < paddedMessage.size(); i += 64) {
        vector<unsigned char> chunk(paddedMessage.begin() + i, paddedMessage.begin() + i + 64);
        processChunk(chunk, h);
    }

    // Produce the final hash value (big-endian)
    stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << hex << setw(8) << setfill('0') << h[i];
    }

    return ss.str();
}

string readFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Failed to open file: " << filename << endl;
        return "";
    }

    stringstream buffer;
    buffer << file.rdbuf(); // Read the entire file into the stringstream
    return buffer.str();    // Convert stringstream to string and return
}

int main() {
    string filename = "requiredText.txt";
    string fileContent = readFile(filename);

    if (fileContent.empty()) {
        cerr << "No content to hash!" << endl;
        return 1;
    }
    string hash = sha256(fileContent);
    cout << "SHA-256 hash of " << filename <<": " << hash << endl;
    return 0;
}
