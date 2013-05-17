package com.pellcorp.spring.security.authentication.encoding;

import java.security.MessageDigest;

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.util.Assert;

public class LdapShaPasswordEncoder implements PasswordEncoder {
    private final DigestType digestType;
    private final PasswordEncoder digestEncoder;
    
    public LdapShaPasswordEncoder(final String algorithm) {
        this.digestType = new DigestType(algorithm);
        
        if (!digestType.isPlain()) {
            digestEncoder = new MessageDigestPasswordEncoder(digestType.getAlgorithm(), true);
        } else {
            digestEncoder = null;
        }
    }
    
    @Override
    public String encodePassword(String rawPass, Object salt) {
        if (!digestType.isPlain()) {
            return digestType.getPrefix() + digestEncoder.encodePassword(rawPass, getSalt(salt));
        } else {
            return rawPass;
        }
    }
    
    @Override
    public boolean isPasswordValid(final String encPass, final String rawPass, Object salt) {
        DigestType prefix = extractPrefix(encPass);

        // because there is no encoding of the password when it's plain
        if (prefix.isPlain()) {
            return encPass.equals(rawPass);
        }
        
        String encPassNoLabel = encPass.substring(prefix.getPrefixLength());
        return digestEncoder.isPasswordValid(encPassNoLabel, rawPass, getSalt(salt));
    }
    
    private Object getSalt(Object salt) {
        if(digestType.isSalted()) {
            return salt;
        } else {
            return null;
        }
    }
    
    private DigestType extractPrefix(String encPass) {
        if (encPass == null || !encPass.startsWith("{")) {
            return DigestType.PLAIN;
        }

        int secondBrace = encPass.lastIndexOf('}');

        if (secondBrace < 0) {
            throw new IllegalArgumentException("Couldn't find closing brace for SHA prefix");
        }

        return new DigestType(encPass.substring(1, secondBrace));
    }
}
