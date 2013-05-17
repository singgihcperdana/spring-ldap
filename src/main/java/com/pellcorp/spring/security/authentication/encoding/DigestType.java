package com.pellcorp.spring.security.authentication.encoding;

import org.apache.commons.lang.StringUtils;

/**
 * A digest type which starts with SSHA -is the salted variant
 */
public class DigestType {
    public static final DigestType PLAIN = new DigestType("PLAIN");
    
    public static final String PLAIN_PREFIX = "PLAIN";
    public static final String SALTED_SHA_PREFIX = "SSHA";
    public static final String SHA_PREFIX = "SHA";
    
    private final String algorithm;
    private final String prefix;
    private boolean isSalted;
    
    public DigestType(String digestType) {
        this.prefix = digestType;
        
        if (digestType.startsWith(SALTED_SHA_PREFIX)) {
            String suffix = digestType.substring(SALTED_SHA_PREFIX.length());
            if (suffix.length() > 0) {
                this.algorithm =  SHA_PREFIX + "-" + suffix;
            } else {
                this.algorithm = SHA_PREFIX;
            }
            this.isSalted = true;
        } else if (digestType.startsWith(SHA_PREFIX)) {
            String suffix = digestType.substring(SHA_PREFIX.length());
            if (suffix.length() > 0) {
                this.algorithm = SHA_PREFIX + "-" + suffix;
            } else {
                this.algorithm = SHA_PREFIX;
            }
            this.isSalted = false;
        } else {
            this.algorithm = null;
            this.isSalted = false;
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
}
