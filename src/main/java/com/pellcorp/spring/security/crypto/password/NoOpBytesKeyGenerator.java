package com.pellcorp.spring.security.crypto.password;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;

public class NoOpBytesKeyGenerator implements BytesKeyGenerator {
    @Override
    public int getKeyLength() {
        return 0;
    }

    @Override
    public byte[] generateKey() {
        return new byte[] {};
    }
}
