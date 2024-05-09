package aes.bc;

import aes.enums.AesKeySize;
import org.bouncycastle.crypto.engines.AESEngine;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.*;

public class BcAesECB {
    private static final int IV_SIZE = 16;
    private SecretKey secretKey;
    private Cipher cipher;

    public BcAesECB(AesKeySize keySize) throws GeneralSecurityException {
        initializeAes(keySize);
    }

    private void initializeAes(AesKeySize keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        AESEngine engine = new AESEngine();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(engine.getAlgorithmName(), "BC");
        keyGenerator.init(keySize.size);
        this.secretKey = keyGenerator.generateKey();

        try {
            this.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            System.out.println(e.getMessage());
        }
    }

    public String encrypt(String data) {
        try {
            byte[] input = data.getBytes(StandardCharsets.UTF_8);
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);

            byte[] output = cipher.doFinal(input);

            return Base64.getEncoder().encodeToString(output);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public String decrypt(String cipherText) {
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey);

            byte[] output = cipher.doFinal(cipherBytes);

            return new String(Arrays.copyOf(output, output.length), StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }


    public static String encryptConcurrently(String data, AesKeySize keySize, int numChunks) throws InterruptedException, ExecutionException, GeneralSecurityException {
        ExecutorService executor = Executors.newFixedThreadPool(numChunks);
        List<Future<String>> futures = new ArrayList<>();
        int chunkSize = data.length() / numChunks;

        for (int i = 0; i < numChunks; i++) {
            final int start = i * chunkSize;
            int end = (i + 1) * chunkSize;
            if (i == numChunks - 1) {
                end = data.length();  // Make sure the last chunk includes the end of the data
            }
            final String dataChunk = data.substring(start, end);

            Callable<String> task = () -> {
                BcAesECB aes = new BcAesECB(keySize);
                return aes.encrypt(dataChunk);
            };
            futures.add(executor.submit(task));
        }

        StringBuilder encryptedData = new StringBuilder();
        for (Future<String> future : futures) {
            encryptedData.append(future.get());  // This will block until the future is complete
        }

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);

        return encryptedData.toString();
    }
}
