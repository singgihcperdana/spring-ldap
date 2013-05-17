package com.pellcorp.spring.security.crypto.password;

import java.security.NoSuchAlgorithmException;

import com.pellcorp.spring.security.authentication.encoding.DigestType;

import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

public class LdapShaPasswordEncoder implements PasswordEncoder {
    private final DigestType digestType;
    private final PasswordEncoder digestEncoder;
    
    public LdapShaPasswordEncoder(final String algorithm) {
        this.digestType = new DigestType(algorithm);
        
        if (!digestType.isPlain()) {
            digestEncoder = new ShaPasswordEncoder(digestType.getAlgorithm(), digestType.isSalted());
        } else {
            digestEncoder = null;
        }
    }
    
    @Override
    public String encode(CharSequence rawPassword) {
        if (!digestType.isPlain()) {
            return digestType.getPrefix() + digestEncoder.encode(rawPassword);
        } else {
            return (String) rawPassword;
        }
    }
    
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        
        DigestType prefix = extractPrefix((String) encodedPassword);

        // because there is no encoding of the password when it's plain
        if (prefix.isPlain()) {
            return encodedPassword.equals(rawPassword);
        }
        
        String encPassNoLabel = encodedPassword.substring(prefix.getPrefixLength());
        return digestEncoder.matches(rawPassword, encPassNoLabel);
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
