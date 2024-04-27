package aes;

import aes.bc.BcAesCBC;
import aes.bc.BcAesECB;
import aes.enums.AesKeySize;
import aes.tink.TinkAes;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Objects;
import java.util.Scanner;

public class App
{
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String input = readFromFile("10mb.txt");

            //testBCAes100Times("ECB", AesKeySize.AES_128, input);
            // testBCAes100Times("ECB", AesKeySize.AES_192, input);
            // testBCAes100Times("ECB", AesKeySize.AES_256, input);
            testBCAes100Times("CBC", AesKeySize.AES_128, input);
            // testBCAes100Times("CBC", AesKeySize.AES_192, input);
            // testBCAes100Times("CBC", AesKeySize.AES_128, input);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void testBCAes100Times(String mode, AesKeySize aesKeySize, String input) throws InvalidCipherTextException, GeneralSecurityException {
        for(int i = 0; i < 100; i++) {
            testAesBouncyCastleTime(mode, aesKeySize, input);
        }
    }

    public static void testAesBouncyCastleTime(String mode, AesKeySize keySize, String input) throws GeneralSecurityException, InvalidCipherTextException {
        if(Objects.equals(mode, "ECB")) {
            BcAesECB sym = new BcAesECB(keySize);

            long start = System.nanoTime();
            sym.encrypt(input);
            System.out.println((System.nanoTime() - start) / 1000000);
        }
        else {
            BcAesCBC sym = new BcAesCBC(keySize);
            byte[] ivBytes = BcAesCBC.generateIVBytes();

            long start = System.nanoTime();
            sym.encrypt(input, ivBytes);
            System.out.println((System.nanoTime() - start) / 1000000);
        }
    }

    public static String readFromFile(String filename) throws FileNotFoundException {
        StringBuilder sb = new StringBuilder();
        File file = new File("./src/main/resources/" + filename);
        Scanner myReader = new Scanner(file);

        while (myReader.hasNextLine()) {
            sb.append(myReader.nextLine());
        }
        myReader.close();

        return sb.toString();
    }

    private static void showResult(String input, String encrypted, String decrypted) {
        System.out.println("Original text: " + input);
        System.out.println("Encrypted text: " + encrypted);
        System.out.println("Decrypted text: " + decrypted);
        System.out.println("Decrypted text " + (input.equals(decrypted) ? "matches" : "doesn't match") + " original text");
    }

    public static void testAesECBBouncyCastle(AesKeySize keySize, String input) throws GeneralSecurityException {
        BcAesECB sym = new BcAesECB(keySize);

        String encrypted = sym.encrypt(input);
        String decrypted = sym.decrypt(encrypted);
        System.out.println("BC-AES-ECB-" + keySize.size);
        showResult(input, encrypted, decrypted);
    }

    public static void testAesCBCBouncyCastle(AesKeySize keySize, String input) throws GeneralSecurityException, InvalidCipherTextException {
        BcAesCBC sym = new BcAesCBC(keySize);

        byte[] ivBytes = BcAesCBC.generateIVBytes();
        String encrypted = sym.encrypt(input, ivBytes);
        String decrypted = sym.decrypt(encrypted, ivBytes);
        System.out.println("BC-AES-CBC-" + keySize.size);
        showResult(input, encrypted, decrypted);
    }

    public static void testAesTink(String input) throws GeneralSecurityException {
        TinkAes aes = new TinkAes();

        String encrypted = aes.encrypt(input);
        String decrypted = aes.decrypt(encrypted);
        System.out.println("Tink-AES-GCM-256");
        showResult(input, encrypted, decrypted);
    }
}
