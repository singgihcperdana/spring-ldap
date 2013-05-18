package com.pellcorp.spring.security.crypto.password;

import java.util.HashMap;
import java.util.Map;

import com.pellcorp.spring.security.digest.Digester;
import com.pellcorp.spring.security.digest.DigesterUtils;

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class LdapShaPasswordEncoder implements PasswordEncoder {
    private final Map<String, PasswordEncoder> digestEncoderMap = new HashMap<String, PasswordEncoder>();
    
    private final Digester digester;
    private final PasswordEncoder digestEncoder;
    private final int saltLength;
    
    public LdapShaPasswordEncoder(final String algorithm) {
        this(algorithm, ShaPasswordEncoder.DEFAULT_SALT_LENGTH);
    }
    
    public LdapShaPasswordEncoder(final String algorithm, final int saltLength) {
        this.digester = new Digester(algorithm);
        this.saltLength = saltLength;
        if (!digester.isPlain()) {
            digestEncoder = getPasswordEncoder(digester);
        } else {
            digestEncoder = null;
        }
    }
    
    @Override
    public String encode(CharSequence rawPassword) {
        if (!digester.isPlain()) {
            return digester.getPrefix() + digestEncoder.encode(rawPassword);
        } else {
            return (String) rawPassword;
        }
    }
    
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        
        Digester prefix = DigesterUtils.extractPrefix((String) encodedPassword);

        // because there is no encoding of the password when it's plain
        if (prefix.isPlain()) {
            return encodedPassword.equals(rawPassword);
        }
        
        PasswordEncoder prefixPasswordEncoder = getPasswordEncoder(prefix);
        String encPassNoPrefix = encodedPassword.substring(prefix.getPrefixLength());
        return prefixPasswordEncoder.matches(rawPassword, encPassNoPrefix);
    }
    
    private PasswordEncoder getPasswordEncoder(Digester prefix) {
        synchronized (digestEncoderMap) {
            PasswordEncoder digestDecoder = digestEncoderMap.get(prefix.getPrefix());
            if (digestDecoder == null) {
                digestDecoder = new ShaPasswordEncoder(prefix, saltLength);
                digestEncoderMap.put(prefix.getPrefix(), digestDecoder);
            }
            return digestDecoder;
        }
    }
}
