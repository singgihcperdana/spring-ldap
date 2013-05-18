package com.pellcorp.spring.security.crypto.password;

import com.pellcorp.spring.security.digest.Digester;

import org.junit.Assert;
import org.junit.Test;

public class ShaPasswordEncoderTest extends Assert {
    @Test
    public void testSha1() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new Digester("SHA-1"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        assertTrue(encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded));
    }
    
    @Test
    public void testSaltedSha1() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new Digester("SSHA-1"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        assertTrue(encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded));
    }
    
    @Test
    public void testSaltedSha256() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new Digester("SSHA-256"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        assertTrue(encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded));
    }
    
    @Test
    public void testSaltedSha384() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new Digester("SSHA-384"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        assertTrue(encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded));
    }
    
    @Test
    public void testSha512() throws Exception {
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(new Digester("SSHA-512"));
        String encoded = encoder.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        assertTrue(encoder.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded));
    }
    
    @Test
    public void testSha512WithDiffKeyLengths() throws Exception {
        ShaPasswordEncoder encoderKey8 = new ShaPasswordEncoder(new Digester("SSHA-512"), 8);
        ShaPasswordEncoder encoderKey6 = new ShaPasswordEncoder(new Digester("SSHA-512"), 6);
        
        String encoded = encoderKey8.encode("JasonJasonJasonJasonJasonJasonJasonJasonJason");
        assertTrue(encoderKey6.matches("JasonJasonJasonJasonJasonJasonJasonJasonJason", encoded));
    }
}
