package aes.enums;

public enum AesKeySize {
    AES_128(128), AES_192(192), AES_256(256);

    public final int size;

    private AesKeySize(int size) {
        this.size = size;
    }


}
