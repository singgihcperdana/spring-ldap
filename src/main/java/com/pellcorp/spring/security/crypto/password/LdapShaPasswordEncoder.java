package com.pellcorp.spring.security.crypto.password;

import java.util.HashMap;
import java.util.Map;

import com.pellcorp.spring.security.authentication.encoding.DigestType;
import com.pellcorp.spring.security.authentication.encoding.DigestTypeUtils;

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class LdapShaPasswordEncoder implements PasswordEncoder {
    private final Map<String, PasswordEncoder> digestEncoderMap = new HashMap<String, PasswordEncoder>();
    
    private final DigestType digestType;
    private final PasswordEncoder digestEncoder;
    
    public LdapShaPasswordEncoder(final String algorithm) {
        this.digestType = new DigestType(algorithm);
        
        if (!digestType.isPlain()) {
            digestEncoder = getPasswordEncoder(digestType);
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
        
        DigestType prefix = DigestTypeUtils.extractPrefix((String) encodedPassword);

        // because there is no encoding of the password when it's plain
        if (prefix.isPlain()) {
            return encodedPassword.equals(rawPassword);
        }
        
        PasswordEncoder prefixPasswordEncoder = getPasswordEncoder(prefix);
        String encPassNoLabel = encodedPassword.substring(prefix.getPrefixLength());
        return prefixPasswordEncoder.matches(rawPassword, encPassNoLabel);
    }
    
    private PasswordEncoder getPasswordEncoder(DigestType prefix) {
        synchronized (digestEncoderMap) {
            PasswordEncoder digestDecoder = digestEncoderMap.get(prefix.getPrefix());
            if (digestDecoder == null) {
                digestDecoder = new ShaPasswordEncoder(digestType);
                digestEncoderMap.put(prefix.getPrefix(), digestDecoder);
            }
            return digestDecoder;
        }
    }
}
