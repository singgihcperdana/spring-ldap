package com.pellcorp.spring.security.authentication.encoding;

/**
 * A digest type which starts with SSHA -is the salted variant
 */
public enum DigestType {
    SHA("SHA"), 
    SSHA("SHA"), 
    SHA256("SHA-256"), 
    SSHA256("SHA-256"), 
    SHA512("SHA-512"), 
    SSHA512("SHA-512"), 
    PLAIN("");
    
    private final String algorithm;
    
    private DigestType(String algorithm) {
        this.algorithm = algorithm;
    }
    
    public boolean isSalted() {
        return name().startsWith("SSHA");
    }
 
    public String getPrefix() {
        return "{" + name() + "}";
    }
    
    public int getPrefixLength() {
        return getPrefix().length();
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
}
