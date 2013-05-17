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
    
    public DigestType(String digestType) {
        this.prefix = digestType;
        
        if (digestType.startsWith(SALTED_SHA_PREFIX)) {
            String suffix = digestType.substring(SALTED_SHA_PREFIX.length());
            if (suffix.length() > 0) {
                this.algorithm = "SHA-" + suffix;
            } else {
                this.algorithm = "SHA";
            }
        } else if (digestType.startsWith(SHA_PREFIX)) {
            String suffix = digestType.substring(SHA_PREFIX.length());
            if (suffix.length() > 0) {
                this.algorithm = "SHA-" + suffix;
            } else {
                this.algorithm = "SHA";
            }
        } else {
            this.algorithm = null;
        }
    }
    
    public boolean isPlain() {
        return prefix.equals(PLAIN_PREFIX);
    }
    
    public boolean isSalted() {
        return prefix.toUpperCase().startsWith(SALTED_SHA_PREFIX);
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
