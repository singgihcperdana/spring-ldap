package com.pellcorp.spring.security.authentication.encoding;

import com.pellcorp.spring.security.digest.DigestType;

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;

public class ShaPasswordEncoder extends MessageDigestPasswordEncoder {
    private DigestType digestType;
    
    public ShaPasswordEncoder(DigestType digestType) {
        super(digestType.getAlgorithm(), true);
        
        this.digestType = digestType;
    }
    
    @Override
    public String encodePassword(String rawPass, Object salt) {
        if (digestType.isSalted()) {
            return super.encodePassword(rawPass, salt);
        } else {
            return super.encodePassword(rawPass, null);
        }
    }
    
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        if (digestType.isSalted()) {
            return super.isPasswordValid(encPass, rawPass, salt);
        } else {
            return super.isPasswordValid(encPass, rawPass, null);
        }
    }
}
