package com.pellcorp.spring.security.authentication.encoding;

/**
 * A digest type which starts with SSHA -is the salted variant
 */
public enum DigestType {
    SHA, SSHA, SHA256, SSHA256, PLAIN;
    
    public boolean isSalted() {
        return name().startsWith("SSHA");
    }
 
    public String getDigestType() {
        if (isSalted()) {
            return name().substring(1);
        } else {
            return name();
        }
    }
    
    public String getPrefix() {
        return "{" + name() + "}";
    }
    
    public int getPrefixLength() {
        return getPrefix().length();
    }
}
