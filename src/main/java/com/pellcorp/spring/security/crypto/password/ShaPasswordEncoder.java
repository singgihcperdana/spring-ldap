package com.pellcorp.spring.security.crypto.password;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.pellcorp.spring.security.authentication.encoding.DigestType;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
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
    
    private final BytesKeyGenerator saltGenerator;
    private MessageDigest messageDigest;
    
    /**
     * @throws NoSuchAlgorithmException
     * 
     *  @param algorithm
     *  @param isSalted - whether we should include salt or not
     */
    public ShaPasswordEncoder(DigestType digestType) {
        try {
            this.messageDigest = MessageDigest.getInstance(digestType.getAlgorithm());
            if (digestType.isSalted()) {
                this.saltGenerator = KeyGenerators.secureRandom();
            } else {
                this.saltGenerator = NO_SALT_GENERATOR;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm [" + digestType.getAlgorithm() + "]");
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return encode(rawPassword, saltGenerator.generateKey());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        byte[] digested = Base64.decode(Utf8.encode(encodedPassword));
        int offset = digested.length - saltGenerator.getKeyLength();
        byte[] salt = subArray(digested, offset, digested.length);
        byte[] actual = digest(rawPassword, salt);
        return matches(digested, actual);
    }

    private String encode(CharSequence rawPassword, byte[] salt) {
        byte[] digest = digest(rawPassword, salt);
        return new String(Hex.encode(digest));
    }

    private byte[] digest(CharSequence rawPassword, byte[] salt) {
        byte[] hashAndSalt = concatenate(Utf8.encode(rawPassword), salt);
        byte[] digest = digest(hashAndSalt);
        return concatenate(digest, salt);
    }

    private byte[] digest(byte[] value) {
        synchronized (messageDigest) {
            return messageDigest.digest(value);
        }
    }
    
    /**
     * Constant time comparison to prevent against timing attacks.
     */
    private boolean matches(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < expected.length; i++) {
            result |= expected[i] ^ actual[i];
        }
        return result == 0;
    }

}