package com.pellcorp.spring.security.authentication.encoding;

import com.pellcorp.spring.security.digest.Digester;

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;

public class ShaPasswordEncoder extends MessageDigestPasswordEncoder {
    private Digester digester;
    
    public ShaPasswordEncoder(Digester digester) {
        super(digester.getAlgorithm(), true);
        this.digester = digester;
    }
    
    @Override
    public String encodePassword(String rawPass, Object salt) {
        if (digester.isSalted()) {
            return super.encodePassword(rawPass, salt);
        } else {
            return super.encodePassword(rawPass, null);
        }
    }
    
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        if (digester.isSalted()) {
            return super.isPasswordValid(encPass, rawPass, salt);
        } else {
            return super.isPasswordValid(encPass, rawPass, null);
        }
    }
}
