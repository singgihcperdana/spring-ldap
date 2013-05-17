package com.pellcorp.spring.security.authentication.encoding;

/**
 * A digest type which starts with SSHA -is the salted variant
 */
public enum DigestType {
    SHA, SSHA, SHA256, SSHA256, PLAIN;
    
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
        if (name().endsWith("SHA256")) {
            return "SHA-256";
        } else {
            return "SHA";
        }
    }
}
