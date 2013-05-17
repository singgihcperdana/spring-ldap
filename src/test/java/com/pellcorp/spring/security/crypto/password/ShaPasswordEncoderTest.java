package com.pellcorp.spring.security.crypto.password;

import com.pellcorp.spring.security.authentication.encoding.DigestType;

import org.junit.Test;

public class ShaPasswordEncoderTest {
    @Test
    public void testSha1() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new DigestType("SHA-1"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSaltedSha1() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new DigestType("SSHA-1"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSaltedSha256() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new DigestType("SSHA-256"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSaltedSha384() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new DigestType("SSHA-384"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSha512() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new DigestType("SSHA-512"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
}
