package com.pellcorp.spring.security.authentication.encoding;

import org.apache.commons.lang.StringUtils;

/**
 * Supports all SHA and SSHA variants that the underlying JDK supports
 */
public class DigestType {
    private static final String PLAIN_PREFIX = "PLAIN";
    private static final String SALTED_SHA_PREFIX = "SSHA";
    private static final String SHA_PREFIX = "SHA";
    static final DigestType PLAIN = new DigestType(PLAIN_PREFIX);
    
    private final String algorithm;
    private final String prefix;
    private boolean isSalted;
    
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
    public DigestType(String digestType) {
        this.prefix = digestType;
        
        if (digestType.startsWith(SALTED_SHA_PREFIX)) {
            String suffix = digestType.substring(SALTED_SHA_PREFIX.length());
            if (suffix.length() > 0) {
                this.algorithm =  SHA_PREFIX + getSuffix(suffix);
            } else {
                this.algorithm = SHA_PREFIX;
            }
            this.isSalted = true;
        } else if (digestType.startsWith(SHA_PREFIX)) {
            String suffix = digestType.substring(SHA_PREFIX.length());
            if (suffix.length() > 0) {
                
                this.algorithm = SHA_PREFIX + getSuffix(suffix);
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
    
    private String getSuffix(String suffix) {
        if (suffix.startsWith("-")) {
            return suffix;
        } else {
            return "-" + suffix;
        }
    }
}
