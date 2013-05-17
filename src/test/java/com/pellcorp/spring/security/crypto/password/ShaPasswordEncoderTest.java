package com.pellcorp.spring.security.crypto.password;

import org.springframework.security.crypto.keygen.KeyGenerators;

import org.junit.Test;

import static org.junit.Assert.*;

public class ShaPasswordEncoderTest {
    @Test
    public void testSha1() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder("SHA-1", false);
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSaltedSha1() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder("SHA-1", true);
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSaltedSha256() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder("SHA-256", true);
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSaltedSha384() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder("SHA-384", true);
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
    
    @Test
    public void testSha512() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder("SHA-512", true);
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded);
    }
}
