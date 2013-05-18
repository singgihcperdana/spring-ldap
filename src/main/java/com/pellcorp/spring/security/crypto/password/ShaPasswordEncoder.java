package com.pellcorp.spring.security.crypto.password;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.pellcorp.spring.security.digest.Digester;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

/**
 * The digest algorithm is invoked on the concatenated bytes of the salt and password.
 */
public final class ShaPasswordEncoder implements PasswordEncoder {
    public static final BytesKeyGenerator NO_SALT_GENERATOR = new NoOpBytesKeyGenerator();
    public static final int DEFAULT_SALT_LENGTH = 8;
    
    private final BytesKeyGenerator saltGenerator;
    private final Digester digester;
    
    public ShaPasswordEncoder(Digester digestType) {
        this(digestType, DEFAULT_SALT_LENGTH);
    }
    
    public ShaPasswordEncoder(Digester digester, int saltLength) {
        this.digester = digester;
        if (digester.isSalted()) {
            this.saltGenerator = KeyGenerators.secureRandom(saltLength);
        } else {
            this.saltGenerator = NO_SALT_GENERATOR;
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        byte[] digest = digest(rawPassword, saltGenerator.generateKey());
        return Utf8.decode(Base64.encode(digest));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        byte[] digested = Base64.decode(Utf8.encode(encodedPassword));
        byte[] salt = subArray(digested, digester.getLength(), digested.length);
        byte[] actual = digest(rawPassword, salt);
        return MessageDigest.isEqual(digested, actual);
    }

    private byte[] digest(CharSequence rawPassword, byte[] salt) {
        byte[] hashAndSalt = concatenate(Utf8.encode(rawPassword), salt);
        byte[] digest = digester.digest(hashAndSalt);
        return concatenate(digest, salt);
    }
}