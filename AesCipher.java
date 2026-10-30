import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AesCipher {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        boolean loop = true;
        Scanner scanner = new Scanner(System.in);

        while (loop) {
            System.out.print("Do you want to encrypt (C) or decrypt (D)? S to exit: ");
            String option = scanner.next();

            if (option.equalsIgnoreCase("c")) {
                File file;

                do {
                    System.out.print("Enter the path of the file you want to encrypt: ");
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
                    System.out.print("Where to save the encrypted file? ");
                    encryptedFilePath = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(encryptedFilePath);

                    if (!Files.exists(path)) {
                        System.out.println("ERROR: path not found.");
                    }

                } while (!Files.exists(path));

                byte[] encryptedData = encrypt(Files.readAllBytes(file.toPath()), key);
                Files.write(path, encryptedData);
                System.out.println("Done!");

            } else if (option.equalsIgnoreCase("d")) {
                File file;
                do {
                    System.out.print("Enter the path of the file you want to decrypt: ");
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
                    System.out.print("Where to save the decrypted file? ");
                    decryptedFilePath = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(decryptedFilePath);

                    if (!Files.exists(path)) {
                        System.out.println("ERROR: path not found.");
                    }

                } while (!Files.exists(path));

                byte[] decryptedData = decrypt(Files.readAllBytes(file.toPath()), key);
                Files.write(path, decryptedData);
                System.out.println("Done!");

            } else if (option.equalsIgnoreCase("s")) {
                loop = false;

            } else {
                System.out.println("ERROR: invalid option.");
            }
        }

        scanner.close();
    }

    public static byte[] encrypt(byte[] data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKeySpec = new SecretKeySpec(parseKey(key), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKeySpec = new SecretKeySpec(parseKey(key), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        return cipher.doFinal(data);
    }

    public static byte[] parseKey(String key) throws Exception {
        String[] byteValues = key.split(",");
        if (byteValues.length != 16) throw new Exception("The key must contain 16 bytes.");
        byte[] keyBytes = new byte[16];

        for (int i = 0; i < 16; i++) {
            keyBytes[i] = (byte) Integer.parseInt(byteValues[i].trim());
        }

        return keyBytes;
    }

    public static String generateRandomKey() {
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
