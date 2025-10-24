import java.io.*;
import java.util.Arrays;

public class AESImageEncryptor {

    // AES S-Box
    private static final int[] SBOX = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    // AES Inverse S-Box
    private static final int[] INV_SBOX = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // Rcon array for KeyExpansion
    private static final int[] RCON = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x00};

    // Convert unsigned byte operations to work with Java's signed bytes
    private static int unsignedByte(byte b) {
        return b & 0xFF;
    }

    // Function to substitute bytes using SBox
    private static void subBytes(byte[] state) {
        for (int i = 0; i < 16; i++) {
            state[i] = (byte) SBOX[unsignedByte(state[i])];
        }
    }

    // Function to substitute bytes using InvSBox
    private static void invSubBytes(byte[] state) {
        for (int i = 0; i < 16; i++) {
            state[i] = (byte) INV_SBOX[unsignedByte(state[i])];
        }
    }

    // Galois field multiplication
    private static byte gmul(byte a, byte b) {
        byte p = 0;
        int aUnsigned = unsignedByte(a);
        int bUnsigned = unsignedByte(b);

        for (int i = 0; i < 8; i++) {
            if ((bUnsigned & 1) != 0) {
                p ^= aUnsigned;
            }
            boolean hiBitSet = (aUnsigned & 0x80) != 0;
            aUnsigned <<= 1;
            if (hiBitSet) {
                aUnsigned ^= 0x1b; // XOR with AES polynomial
            }
            bUnsigned >>>= 1;
        }
        return (byte) p;
    }

    // Function to perform MixColumns
    private static void mixColumns(byte[] state) {
        byte[] temp = new byte[16];
        for (int i = 0; i < 4; i++) {
            int colStart = i * 4;
            temp[colStart + 0] = (byte) (gmul(state[colStart + 0], (byte) 2) ^
                    gmul(state[colStart + 1], (byte) 3) ^
                    state[colStart + 2] ^
                    state[colStart + 3]);
            temp[colStart + 1] = (byte) (state[colStart + 0] ^
                    gmul(state[colStart + 1], (byte) 2) ^
                    gmul(state[colStart + 2], (byte) 3) ^
                    state[colStart + 3]);
            temp[colStart + 2] = (byte) (state[colStart + 0] ^
                    state[colStart + 1] ^
                    gmul(state[colStart + 2], (byte) 2) ^
                    gmul(state[colStart + 3], (byte) 3));
            temp[colStart + 3] = (byte) (gmul(state[colStart + 0], (byte) 3) ^
                    state[colStart + 1] ^
                    state[colStart + 2] ^
                    gmul(state[colStart + 3], (byte) 2));
        }
        System.arraycopy(temp, 0, state, 0, 16);
    }

    // Function to perform InvMixColumns
    private static void invMixColumns(byte[] state) {
        byte[] temp = new byte[16];
        for (int i = 0; i < 4; i++) {
            int colStart = i * 4;
            temp[colStart + 0] = (byte) (gmul(state[colStart + 0], (byte) 0x0e) ^
                    gmul(state[colStart + 1], (byte) 0x0b) ^
                    gmul(state[colStart + 2], (byte) 0x0d) ^
                    gmul(state[colStart + 3], (byte) 0x09));
            temp[colStart + 1] = (byte) (gmul(state[colStart + 0], (byte) 0x09) ^
                    gmul(state[colStart + 1], (byte) 0x0e) ^
                    gmul(state[colStart + 2], (byte) 0x0b) ^
                    gmul(state[colStart + 3], (byte) 0x0d));
            temp[colStart + 2] = (byte) (gmul(state[colStart + 0], (byte) 0x0d) ^
                    gmul(state[colStart + 1], (byte) 0x09) ^
                    gmul(state[colStart + 2], (byte) 0x0e) ^
                    gmul(state[colStart + 3], (byte) 0x0b));
            temp[colStart + 3] = (byte) (gmul(state[colStart + 0], (byte) 0x0b) ^
                    gmul(state[colStart + 1], (byte) 0x0d) ^
                    gmul(state[colStart + 2], (byte) 0x09) ^
                    gmul(state[colStart + 3], (byte) 0x0e));
        }
        System.arraycopy(temp, 0, state, 0, 16);
    }

    // Function to perform ShiftRows operation
    private static void shiftRows(byte[] state) {
        byte[] temp = new byte[16];

        temp[0] = state[0];
        temp[1] = state[5];
        temp[2] = state[10];
        temp[3] = state[15];

        temp[4] = state[4];
        temp[5] = state[9];
        temp[6] = state[14];
        temp[7] = state[3];

        temp[8] = state[8];
        temp[9] = state[13];
        temp[10] = state[2];
        temp[11] = state[7];

        temp[12] = state[12];
        temp[13] = state[1];
        temp[14] = state[6];
        temp[15] = state[11];

        System.arraycopy(temp, 0, state, 0, 16);
    }

    // Function to perform inverse ShiftRows
    private static void invShiftRows(byte[] state) {
        byte[] temp = new byte[16];

        temp[0] = state[0];
        temp[1] = state[13];
        temp[2] = state[10];
        temp[3] = state[7];

        temp[4] = state[4];
        temp[5] = state[1];
        temp[6] = state[14];
        temp[7] = state[11];

        temp[8] = state[8];
        temp[9] = state[5];
        temp[10] = state[2];
        temp[11] = state[15];

        temp[12] = state[12];
        temp[13] = state[9];
        temp[14] = state[6];
        temp[15] = state[3];

        System.arraycopy(temp, 0, state, 0, 16);
    }

    // Function to XOR state with round key
    private static void addRoundKey(byte[] state, byte[] roundKey) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    // Function to perform KeyExpansion
    private static void keyExpansion(byte[] key, byte[] roundKeys) {
        // Copy original key
        System.arraycopy(key, 0, roundKeys, 0, 16);

        byte[] temp = new byte[4];

        for (int i = 16; i < 176; i += 4) {
            // Copy previous 4 bytes
            for (int j = 0; j < 4; j++) {
                temp[j] = roundKeys[i - 4 + j];
            }

            if (i % 16 == 0) {
                // RotWord
                byte t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                // SubWord
                for (int j = 0; j < 4; j++) {
                    temp[j] = (byte) SBOX[unsignedByte(temp[j])];
                }

                // XOR with Rcon
                temp[0] ^= RCON[i / 16 - 1];
            }

            for (int j = 0; j < 4; j++) {
                roundKeys[i + j] = (byte) (roundKeys[i - 16 + j] ^ temp[j]);
            }
        }
    }

    // AES encryption function
    private static void aesEncrypt(byte[] input, byte[] output, byte[] key) {
        byte[] state = new byte[16];
        byte[] roundKeys = new byte[176];

        System.arraycopy(input, 0, state, 0, 16);
        keyExpansion(key, roundKeys);

        addRoundKey(state, Arrays.copyOfRange(roundKeys, 0, 16));

        for (int round = 1; round <= 9; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(roundKeys, round * 16, (round + 1) * 16));
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(roundKeys, 160, 176));

        System.arraycopy(state, 0, output, 0, 16);
    }

    // AES decryption function
    private static void aesDecrypt(byte[] input, byte[] output, byte[] key) {
        byte[] state = new byte[16];
        byte[] roundKeys = new byte[176];

        System.arraycopy(input, 0, state, 0, 16);
        keyExpansion(key, roundKeys);

        addRoundKey(state, Arrays.copyOfRange(roundKeys, 160, 176));

        for (int round = 9; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, Arrays.copyOfRange(roundKeys, round * 16, (round + 1) * 16));
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, Arrays.copyOfRange(roundKeys, 0, 16));

        System.arraycopy(state, 0, output, 0, 16);
    }

    // Function to encrypt image data
    public static void encryptImageData(String inputFile, String outputFile, byte[] key)
            throws IOException {
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {

            // Read and write the header (assuming BMP format with 54-byte header)
            byte[] header = new byte[54];
            int headerBytesRead = in.read(header);
            if (headerBytesRead > 0) {
                out.write(header, 0, headerBytesRead);
            }

            // Encrypt the pixel data
            byte[] buffer = new byte[16];
            byte[] ciphertext = new byte[16];
            int bytesRead;

            while ((bytesRead = in.read(buffer)) > 0) {
                if (bytesRead < 16) {
                    // Add PKCS7 padding
                    int paddingValue = 16 - bytesRead;
                    for (int i = bytesRead; i < 16; i++) {
                        buffer[i] = (byte) paddingValue;
                    }
                }
                aesEncrypt(buffer, ciphertext, key);
                out.write(ciphertext);
            }
        }
    }

    // Function to decrypt image data
    public static void decryptImageData(String inputFile, String outputFile, byte[] key)
            throws IOException {
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {

            // Read and write the BMP header (54 bytes)
            byte[] header = new byte[54];
            int headerBytesRead = in.read(header);
            if (headerBytesRead != 54) {
                throw new IOException("Invalid BMP header");
            }
            out.write(header);

            // Buffer to hold encrypted and decrypted data
            byte[] buffer = new byte[16];
            byte[] plaintext = new byte[16];

            int bytesRead;
            boolean isLastBlock = false;

            // Read the first block
            bytesRead = in.read(buffer);

            while (bytesRead == 16) {
                // Read ahead to see if this is the last block
                byte[] nextBlock = new byte[16];
                int nextBytesRead = in.read(nextBlock);

                if (nextBytesRead < 16) {
                    // This is the last block
                    aesDecrypt(buffer, plaintext, key);

                    // Remove padding
                    int paddingValue = unsignedByte(plaintext[15]);
                    if (paddingValue > 0 && paddingValue <= 16) {
                        out.write(plaintext, 0, 16 - paddingValue);
                    } else {
                        out.write(plaintext); // fallback: write full if padding invalid
                    }
                    break; // done
                } else {
                    // Not the last block
                    aesDecrypt(buffer, plaintext, key);
                    out.write(plaintext);

                    // Move to next block
                    buffer = nextBlock;
                    bytesRead = nextBytesRead;
                }
            }
        }
    }


    public static void main(String[] args) {
        try {
            // Create 16-byte key from "keshav" string
            byte[] key = new byte[16];
            String keyString = "keshav";
            byte[] keyBytes = keyString.getBytes();
            System.arraycopy(keyBytes, 0, key, 0, Math.min(keyBytes.length, 16));

            String inputImage = "zebra.bmp";
            String encryptedImage = "encrypted_image.bmp";
            String decryptedImage = "decrypted_image.bmp";

            System.out.println("Encrypting the image...");
            encryptImageData(inputImage, encryptedImage, key);

            System.out.println("Decrypting the image...");
            decryptImageData(encryptedImage, decryptedImage, key);

            System.out.println("Done! Check the files.");

        } catch (IOException e) {
            System.err.println("Error processing files: " + e.getMessage());
            e.printStackTrace();
        }
    }
}