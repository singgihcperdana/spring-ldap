package com.pellcorp.spring.security.authentication.encoding;

import java.util.HashMap;
import java.util.Map;

import com.pellcorp.spring.security.digest.Digester;
import com.pellcorp.spring.security.digest.DigesterUtils;

import org.springframework.security.authentication.encoding.PasswordEncoder;

public class LdapShaPasswordEncoder implements PasswordEncoder {
    private final Map<String, PasswordEncoder> digestEncoderMap = new HashMap<String, PasswordEncoder>();
    
    private final Digester digester;
    private final PasswordEncoder defaultPasswordEncoder;
    
    public LdapShaPasswordEncoder(final String algorithm) {
        this.digester = new Digester(algorithm);
        
        if (!digester.isPlain()) {
            defaultPasswordEncoder = getPasswordEncoder(digester);
        } else {
            defaultPasswordEncoder = null;
        }
    }
    
    @Override
    public String encodePassword(String rawPass, Object salt) {
        if (!digester.isPlain()) {
            return digester.getPrefix() + defaultPasswordEncoder.encodePassword(rawPass, salt);
        } else {
            return rawPass;
        }
    }
    
    @Override
    public boolean isPasswordValid(final String encPass, final String rawPass, Object salt) {
        if (encPass == null || rawPass == null) {
            return false;
        }
        
        Digester prefix = DigesterUtils.extractPrefix(encPass);

        // because there is no encoding of the password when it's plain
        if (prefix.isPlain()) {
            return encPass.equals(rawPass);
        }
        
        PasswordEncoder prefixPasswordEncoder = getPasswordEncoder(prefix);
        
        String encPassNoLabel = encPass.substring(prefix.getPrefixLength());
        return prefixPasswordEncoder.isPasswordValid(encPassNoLabel, rawPass, salt);
    }
    
    private PasswordEncoder getPasswordEncoder(Digester prefix) {
        synchronized (digestEncoderMap) {
            PasswordEncoder digestDecoder = digestEncoderMap.get(prefix.getPrefix());
            if (digestDecoder == null) {
                digestDecoder = new ShaPasswordEncoder(prefix);
                digestEncoderMap.put(prefix.getPrefix(), digestDecoder);
            }
            return digestDecoder;
        }
    }
}
