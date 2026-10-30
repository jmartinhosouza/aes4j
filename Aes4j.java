import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Aes4J {

    private final static byte[][] SBOX = {
            { (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B,
                    (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76 },
            { (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF,
                    (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0 },
            { (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7, (byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1,
                    (byte) 0x71, (byte) 0xD8, (byte) 0x31, (byte) 0x15 },
            { (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2,
                    (byte) 0xEB, (byte) 0x27, (byte) 0xB2, (byte) 0x75 },
            { (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A, (byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3,
                    (byte) 0x29, (byte) 0xE3, (byte) 0x2F, (byte) 0x84 },
            { (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1, (byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39,
                    (byte) 0x4A, (byte) 0x4C, (byte) 0x58, (byte) 0xCF },
            { (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F,
                    (byte) 0x50, (byte) 0x3C, (byte) 0x9F, (byte) 0xA8 },
            { (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21,
                    (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2 },
            { (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D,
                    (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73 },
            { (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14,
                    (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB },
            { (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62,
                    (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79 },
            { (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA,
                    (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08 },
            { (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F,
                    (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A },
            { (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9,
                    (byte) 0x86, (byte) 0xC1, (byte) 0x1D, (byte) 0x9E },
            { (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9,
                    (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF },
            { (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F,
                    (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16 }
    };

    private final static byte[][] INV_SBOX = {
            { (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E,
                    (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB },
            { (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44,
                    (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB },
            { (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B,
                    (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E },
            { (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49,
                    (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25 },
            { (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC,
                    (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92 },
            { (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57,
                    (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84 },
            { (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05,
                    (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06 },
            { (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03,
                    (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B },
            { (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE,
                    (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73 },
            { (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8,
                    (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E },
            { (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E,
                    (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B },
            { (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE,
                    (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4 },
            { (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59,
                    (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F },
            { (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F,
                    (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF },
            { (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C,
                    (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61 },
            { (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63,
                    (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D }
    };

    private static int padding;

    public static void main(String[] args) throws Exception {
        boolean loop = true;
        Scanner scanner = new Scanner(System.in);

        while (loop) {
            System.out.print("Do you want to encrypt (C) or decrypt (D)? S to exit: ");
            String option = scanner.next();

            if (option.equalsIgnoreCase("c")) {
                File file;

                do {
                    System.out.print("Enter the path of the file you want to encrypt (relative to current directory): ");
                    String filePath = System.getProperty("user.dir") + scanner.next();
                    file = new File(filePath);

                    if (!file.exists()) {
                        System.out.println("ERROR: file not found.");
                    }

                } while (!file.exists());

                System.out.print("Provide the key or press G to generate one: ");
                String key = scanner.next();

                if (key.equalsIgnoreCase("g")) {
                    key = generateRandomKey();
                    System.out.println("Your key is: " + key + ". Write it down so you don't forget.");
                }

                Path path;
                String encryptedFilePath;

                do {
                    System.out.print("Where to save the encrypted file (relative to current directory)? ");
                    encryptedFilePath = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(encryptedFilePath);

                    if (!Files.exists(path)) {
                        System.out.println("ERROR: path not found.");
                    }

                } while (!Files.exists(path));

                byte[] encryptedText = encrypt(Files.readAllBytes(file.toPath()), parseKey(key));
                Files.write(path, encryptedText);
                System.out.println("Done!");

            } else if (option.equalsIgnoreCase("d")) {
                File file;
                do {
                    System.out.print("Enter the path of the file you want to decrypt (relative to current directory): ");
                    String filePath = System.getProperty("user.dir") + scanner.next();
                    file = new File(filePath);

                    if (!file.exists()) {
                        System.out.println("ERROR: file not found.");
                    }

                } while (!file.exists());

                System.out.print("Provide the key: ");
                String key = scanner.next();

                Path path;
                String decryptedFilePath;

                do {
                    System.out.print("Where to save the decrypted file (relative to current directory)? ");
                    decryptedFilePath = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(decryptedFilePath);

                    if (!Files.exists(path)) {
                        System.out.println("ERROR: path not found.");
                    }

                } while (!Files.exists(path));

                byte[] decryptedText = decrypt(Files.readAllBytes(file.toPath()), parseKey(key));
                Files.write(path, decryptedText);
                System.out.println("Done!");

            } else if (option.equalsIgnoreCase("s")) {
                loop = false;

            } else {
                System.out.println("ERROR: invalid option.");
            }
        }

        scanner.close();
    }

    private static byte[] decrypt(byte[] encryptedText, byte[] key) {
        int numBlocks = encryptedText.length / 16;
        byte[] finalResult = new byte[encryptedText.length];

        byte[][] stateMatrix = generateStateMatrix(key);
        byte[][] roundKeys = generateRoundKeys(stateMatrix);
        roundKeys = expandKey(roundKeys);

        for (int blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
            byte[] block = Arrays.copyOfRange(encryptedText, blockIdx * 16, (blockIdx + 1) * 16);
            byte[][] temp = new byte[4][4];

            byte[][] state = new byte[4][4];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    state[i][j] = block[i + (j * 4)];
                }
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    temp[j][k] = roundKeys[10][k];
                }
            }

            state = addRoundKey(state, temp);
            state = inverseShiftRows(state);
            state = inverseSubstituteWords(state);

            for (int i = 9; i > 0; i--) {
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        temp[j][k] = roundKeys[i * 4 + j][k];
                    }
                }

                state = addRoundKey(state, temp);
                state = inverseShiftRows(state);
                state = inverseSubstituteWords(state);
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    temp[j][k] = roundKeys[0][k];
                }
            }

            state = addRoundKey(state, temp);

            byte[] decryptedBlock = flattenByteMatrix(state);
            System.arraycopy(decryptedBlock, 0, finalResult, blockIdx * 16, 16);
        }

        finalResult = removePadding(finalResult);
        return finalResult;
    }

    private static byte[][] inverseShiftRows(byte[][] state) {
        byte[][] newState = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[i][j] = state[i][j];
            }
        }

        byte temp;
        temp = newState[1][3];
        newState[1][3] = newState[1][2];
        newState[1][2] = newState[1][1];
        newState[1][1] = newState[1][0];
        newState[1][0] = temp;

        temp = newState[2][3];
        newState[2][3] = newState[2][2];
        newState[2][2] = newState[2][1];
        newState[2][1] = newState[2][0];
        newState[2][0] = temp;

        temp = newState[3][3];
        newState[3][3] = newState[3][2];
        newState[3][2] = newState[3][1];
        newState[3][1] = newState[3][0];
        newState[3][0] = temp;

        return newState;
    }

    private static byte[][] inverseSubstituteWords(byte[][] state) {
        byte[][] newState = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                byte value = state[i][j];
                int index = value & 0xFF;
                newState[i][j] = INV_SBOX[index / 16][index % 16];
            }
        }

        return newState;
    }

    private static byte[] encrypt(byte[] plainText, byte[] key) {
        plainText = applyPadding(plainText);
        int numBlocks = plainText.length / 16;
        byte[] finalResult = new byte[plainText.length];
        byte[][] stateMatrix = generateStateMatrix(key);
        byte[][] roundKeys = generateRoundKeys(stateMatrix);
        roundKeys = expandKey(roundKeys);

        for (int blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
            byte[] block = Arrays.copyOfRange(plainText, blockIdx * 16, (blockIdx + 1) * 16);
            byte[][] temp = new byte[4][4];
            byte[][] state = new byte[4][4];

            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    state[i][j] = block[i + (j * 4)];
                }
            }

            state = addRoundKey(state, roundKeys);

            for (int i = 1; i < 10; i++) {
                state = substituteWord02(state);
                state = shiftRows(state);
                state = mixColumns(state);

                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        temp[j][k] = roundKeys[i * 4 + j][k];
                    }
                }

                state = addRoundKey(state, temp);
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    temp[j][k] = roundKeys[10][k];
                }
            }

            state = substituteWord02(state);
            state = addRoundKey(state, temp);
            byte[] encryptedBlock = flattenByteMatrix(state);
            System.arraycopy(encryptedBlock, 0, finalResult, blockIdx * 16, 16);
        }

        return finalResult;
    }

    private static byte[] flattenByteMatrix(byte[][] byteMatrix) {
        int rows = byteMatrix.length;
        int cols = byteMatrix[0].length;
        byte[] flatArray = new byte[rows * cols];

        int index = 0;
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                flatArray[index++] = byteMatrix[i][j];
            }
        }

        return flatArray;
    }

    private static byte[][] mixColumns(byte[][] stateMatrix) {
        for (int i = 0; i < 4; i++) {
            byte[] column = new byte[4];
            for (int j = 0; j < 4; j++) {
                column[j] = stateMatrix[j][i];
            }

            stateMatrix[0][i] = (byte) (multiplyBy02(column[0]) ^ multiplyBy03(column[1]) ^ column[2] ^ column[3]);
            stateMatrix[1][i] = (byte) (column[0] ^ multiplyBy02(column[1]) ^ multiplyBy03(column[2]) ^ column[3]);
            stateMatrix[2][i] = (byte) (column[0] ^ column[1] ^ multiplyBy02(column[2]) ^ multiplyBy03(column[3]));
            stateMatrix[3][i] = (byte) (multiplyBy03(column[0]) ^ column[1] ^ column[2] ^ multiplyBy02(column[3]));
        }

        return stateMatrix;
    }

    private static byte multiplyBy02(byte b) {
        return (byte) ((b << 1) ^ ((b & 0x80) != 0 ? 0x1B : 0x00));
    }

    private static byte multiplyBy03(byte b) {
        return (byte) (multiplyBy02(b) ^ b);
    }

    private static byte[][] shiftRows(byte[][] stateMatrix) {
        byte temp;

        temp = stateMatrix[1][0];

        for (int i = 0; i < 3; i++) {
            stateMatrix[1][i] = stateMatrix[1][i + 1];
        }

        stateMatrix[1][3] = temp;

        temp = stateMatrix[2][0];
        stateMatrix[2][0] = stateMatrix[2][2];
        stateMatrix[2][2] = temp;

        temp = stateMatrix[2][1];
        stateMatrix[2][1] = stateMatrix[2][3];
        stateMatrix[2][3] = temp;

        temp = stateMatrix[3][0];
        stateMatrix[3][0] = stateMatrix[3][1];
        stateMatrix[3][1] = stateMatrix[3][2];
        stateMatrix[3][2] = stateMatrix[3][3];

        stateMatrix[3][3] = temp;

        return stateMatrix;
    }

    public static byte[][] addRoundKey(byte[][] state, byte[][] roundKey) {
        byte[][] newState = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[i][j] = (byte) (state[i][j] ^ roundKey[i][j]);
            }
        }

        return newState;
    }

    private static byte[] applyPadding(byte[] data) {
        int blockSize = 16;
        int dataLength = data.length;
        int numPadBytes = blockSize - (dataLength % blockSize);

        byte[] paddedData = new byte[dataLength + numPadBytes];
        System.arraycopy(data, 0, paddedData, 0, dataLength);

        for (int i = dataLength; i < paddedData.length; i++) {
            paddedData[i] = (byte) numPadBytes;
        }

        return paddedData;
    }

    private static byte[] removePadding(byte[] data) {
        int dataLength = data.length;
        int numPadBytes = data[dataLength - 1];
        byte[] unpaddedData = new byte[dataLength - numPadBytes];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);

        return unpaddedData;
    }

    private static byte[][] generateStateMatrix(byte[] key) {
        byte[][] stateMatrix = new byte[4][4];
        int counter = 0;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateMatrix[i][j] = key[counter];
                counter++;
            }
        }

        return stateMatrix;
    }

    private static byte[][] generateRoundKeys(byte[][] stateMatrix) {
        byte[][] roundKeys = new byte[44][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = stateMatrix[i][j];
            }
        }

        for (int i = 4; i < 44; i++) {
            byte[] temp = new byte[4];

            for (int j = 0; j < 4; j++) {
                temp[j] = roundKeys[i - 1][(j + 1) % 4];
            }

            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = (byte) (roundKeys[i - 4][j] ^ temp[j]);
            }
        }

        return roundKeys;
    }

    private static byte[][] expandKey(byte[][] roundKeys) {
        byte[][] temp = new byte[1][4];
        byte[][] roundConstant;
        int counter = 1;

        for (int i = 0; i < 4; i++) {
            System.arraycopy(roundKeys[i], 0, temp[0], 0, 4);
            roundKeys[i] = temp[0].clone();
        }

        for (int i = 4; i < 44; i++) {
            if (i % 4 == 0) {
                temp[0] = rotateBytes(new byte[][] { roundKeys[i] })[0];
                temp = substituteWord01(temp);

                roundConstant = generateRoundConstant(counter++);

                temp = xor(temp, roundConstant);

                for (int j = 0; j < 4; j++) {
                    roundKeys[i][j] = (byte) (roundKeys[i - 4][j] ^ temp[0][j]);
                }
            } else {
                for (int j = 0; j < 4; j++) {
                    roundKeys[i][j] = (byte) (roundKeys[i - 4][j] ^ roundKeys[i - 1][j]);
                }
            }
        }

        return roundKeys;
    }

    private static byte[][] xor(byte[][] subWord, byte[][] roundConstant) {
        byte[][] result = new byte[1][4];

        for (int i = 0; i < 4; i++) {
            result[0][i] = (byte) (subWord[0][i] ^ roundConstant[0][i]);
        }

        return result;
    }

    private static byte[][] generateRoundConstant(int number) {
        byte[][] roundConstant = new byte[1][4];

        switch (number) {
            case 1:
                roundConstant[0][0] = (byte) 0x01;
                break;
            case 2:
                roundConstant[0][0] = (byte) 0x02;
                break;
            case 3:
                roundConstant[0][0] = (byte) 0x04;
                break;
            case 4:
                roundConstant[0][0] = (byte) 0x08;
                break;
            case 5:
                roundConstant[0][0] = (byte) 0x10;
                break;
            case 6:
                roundConstant[0][0] = (byte) 0x20;
                break;
            case 7:
                roundConstant[0][0] = (byte) 0x40;
                break;
            case 8:
                roundConstant[0][0] = (byte) 0x80;
                break;
            case 9:
                roundConstant[0][0] = (byte) 0x1B;
                break;
            case 10:
                roundConstant[0][0] = (byte) 0x36;
                break;
        }

        roundConstant[0][1] = (byte) 0x00;
        roundConstant[0][2] = (byte) 0x00;
        roundConstant[0][3] = (byte) 0x00;

        return roundConstant;
    }

    private static byte[][] substituteWord01(byte[][] word) {
        byte[][] result = new byte[1][4];

        for (int i = 0; i < 4; i++) {
            int row = (word[0][i] & 0xF0) >> 4;
            int col = (word[0][i] & 0x0F);
            result[0][i] = SBOX[row][col];
        }

        return result;
    }

    private static byte[][] substituteWord02(byte[][] word) {
        byte[][] result = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int row = (word[i][j] & 0xF0) >> 4;
                int col = (word[i][j] & 0x0F);
                result[i][j] = SBOX[row][col];
            }
        }

        return result;
    }

    private static byte[][] rotateBytes(byte[][] word) {
        byte[][] temp = new byte[1][4];
        System.arraycopy(word[0], 0, temp[0], 0, 4);

        word[0][0] = temp[0][1];
        word[0][1] = temp[0][2];
        word[0][2] = temp[0][3];
        word[0][3] = temp[0][0];

        return word;
    }

    public static byte[] parseKey(String key) {
        String[] stringArray = key.split(",");

        byte[] bytes = new byte[stringArray.length];

        for (int i = 0; i < stringArray.length; i++) {
            bytes[i] = (byte) Integer.parseInt(stringArray[i].trim());
        }

        return bytes;
    }

    private static String generateRandomKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        StringBuilder formattedKey = new StringBuilder();

        for (int i = 0; i < key.length; i++) {
            formattedKey.append(key[i] & 0xff);
            if (i < key.length - 1) formattedKey.append(",");
        }

        return formattedKey.toString();
    }
}
