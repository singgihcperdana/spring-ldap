package com.pellcorp.spring.security.crypto.password;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LdapShaPasswordEncoderTest {
    @Test
    public void testSsha512() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA512");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSsha512Repeated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA512");
        
        List<String> encPassList = new ArrayList<String>();
        for (int i=0; i<1000; i++) {
            String encPass = encoder.encode("Jason");
            assertTrue(encoder.matches("Jason", encPass));
            assertFalse(encoder.matches("JasonX", encPass));
            assertFalse(encPassList.contains(encPass));
            encPassList.add(encPass);
        }
        
        assertEquals(1000, encPassList.size());
    }
    
    @Test
    public void testSha512() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA512");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSsha256() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA256");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSha256() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA256");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSsha512Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA-512");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSha512Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA-512");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSsha256Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA-256");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSha256Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA-256");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSsha() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testSha() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testShaAndSsha() {
        LdapShaPasswordEncoder shaEncoder = new LdapShaPasswordEncoder("SHA");
        LdapShaPasswordEncoder sshaEncoder = new LdapShaPasswordEncoder("SSHA");
        String encPass = shaEncoder.encode("Jason");
        
        assertTrue(sshaEncoder.matches("Jason", encPass));
        assertTrue(shaEncoder.matches("Jason", encPass));
        assertFalse(sshaEncoder.matches("JasonX", encPass));
        assertFalse(shaEncoder.matches("JasonX", encPass));
    }
    
    @Test
    public void testNullPassword() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA");
        assertFalse(encoder.matches("Jason", null));
    }
    
    @Test
    public void testPlain() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("PLAIN");
        String encPass = encoder.encode("Jason");
        assertEquals("Jason", encPass);
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
    }
}
