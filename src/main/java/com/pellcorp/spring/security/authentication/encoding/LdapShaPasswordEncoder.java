package com.pellcorp.spring.security.authentication.encoding;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;
import org.springframework.security.authentication.encoding.PasswordEncoder;

public class LdapShaPasswordEncoder implements PasswordEncoder {
    private final Map<String, PasswordEncoder> digestEncoderMap = new HashMap<String, PasswordEncoder>();
    
    private final DigestType digestType;
    private final PasswordEncoder defaultPasswordEncoder;
    
    public LdapShaPasswordEncoder(final String algorithm) {
        this.digestType = new DigestType(algorithm);
        
        if (!digestType.isPlain()) {
            defaultPasswordEncoder = getPasswordEncoder(digestType);
        } else {
            defaultPasswordEncoder = null;
        }
    }
    
    @Override
    public String encodePassword(String rawPass, Object salt) {
        if (!digestType.isPlain()) {
            return digestType.getPrefix() + defaultPasswordEncoder.encodePassword(rawPass, getSalt(salt, digestType));
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
        
        PasswordEncoder prefixPasswordEncoder = getPasswordEncoder(prefix);
        
        String encPassNoLabel = encPass.substring(prefix.getPrefixLength());
        return prefixPasswordEncoder.isPasswordValid(encPassNoLabel, rawPass, getSalt(salt, prefix));
    }
    
    private Object getSalt(Object salt, DigestType digestType) {
        if(digestType.isSalted()) {
            return salt;
        } else {
            return null;
        }
    }
    
    private PasswordEncoder getPasswordEncoder(DigestType prefix) {
        synchronized (digestEncoderMap) {
            PasswordEncoder digestDecoder = digestEncoderMap.get(prefix.getPrefix());
            if (digestDecoder == null) {
                digestDecoder = new MessageDigestPasswordEncoder(prefix.getAlgorithm(), true);
                digestEncoderMap.put(prefix.getPrefix(), digestDecoder);
            }
            return digestDecoder;
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
