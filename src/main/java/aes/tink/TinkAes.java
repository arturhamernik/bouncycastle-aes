package aes.tink;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.Hex;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class TinkAes {
    private final Aead aead;

    public TinkAes() throws GeneralSecurityException {
        TinkConfig.register();
        AeadConfig.register();
        this.aead = AeadFactory.getPrimitive(KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM));
    }

    public String encrypt(String input) throws GeneralSecurityException {
        byte[] inputByte = input.getBytes(StandardCharsets.UTF_8);
        return Hex.encode(aead.encrypt(inputByte, null));
    }

    public String decrypt(String encrypted) throws GeneralSecurityException {
        byte[] encryptedByte = Hex.decode(encrypted);

        byte[] decrypted = aead.decrypt(encryptedByte, null);

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
