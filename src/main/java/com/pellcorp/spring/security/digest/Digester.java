package com.pellcorp.spring.security.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.codec.Utf8;

/**
 * Supports all SHA and SSHA variants that the underlying JDK supports
 */
public class Digester {
    private static final String PLAIN_PREFIX = "PLAIN";
    private static final String SALTED_SHA_PREFIX = "SSHA";
    private static final String SHA_PREFIX = "SHA";
    public static final Digester PLAIN = new Digester(PLAIN_PREFIX);
    
    private final String algorithm;
    private final String prefix;
    private boolean isSalted;
    private final MessageDigest messageDigest;
    private final int digestLength;
    
    /**
     * The digestType will be what is used as the LDAP { prefix }, you can
     * pass this as:
     * 
     * SHA
     * SSHA
     * SHA-256
     * SHA256
     * SSHA-256
     * SSHA256
     * 
     * And so on
     */
    public Digester(String digestType) {
        this.prefix = digestType;
        
        if (digestType.startsWith(SALTED_SHA_PREFIX)) {
            String suffix = digestType.substring(SALTED_SHA_PREFIX.length());
            this.algorithm =  SHA_PREFIX + getSuffix(suffix);
            this.isSalted = true;
        } else if (digestType.startsWith(SHA_PREFIX)) {
            String suffix = digestType.substring(SHA_PREFIX.length());
            this.algorithm = SHA_PREFIX + getSuffix(suffix);
            this.isSalted = false;
        } else {
            this.algorithm = null;
            this.isSalted = false;
        }
        
        try {
            if (this.algorithm != null) {
                this.messageDigest = MessageDigest.getInstance(algorithm);
                this.digestLength = digest(Utf8.encode("whocares")).length;
            } else {
                this.messageDigest = null;
                this.digestLength = 0;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm [" + this.algorithm + "]");
        }
    }
    
    public boolean isPlain() {
        return algorithm == null;
    }
    
    public boolean isSalted() {
        return isSalted;
    }
 
    public String getPrefix() {
        return "{" + prefix + "}";
    }
    
    public int getPrefixLength() {
        return getPrefix().length();
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
    
    public int getLength() {
        return digestLength;
    }
    
    public byte[] digest(byte[] value) {
        if (messageDigest != null) {
            synchronized (messageDigest) {
                return messageDigest.digest(value);
            }
        } else {
            return value;
        }
    }
    
    private String getSuffix(String suffix) {
        if (suffix.length() == 0) {
            return "";
        } else if (suffix.startsWith("-")) {
            return suffix;
        } else {
            return "-" + suffix;
        }
    }
}
