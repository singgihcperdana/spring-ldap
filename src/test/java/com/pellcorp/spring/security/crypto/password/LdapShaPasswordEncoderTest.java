package com.pellcorp.spring.security.crypto.password;

import com.pellcorp.spring.security.authentication.encoding.DigestType;

import org.junit.Test;

import static org.junit.Assert.*;

public class LdapShaPasswordEncoderTest {
    @Test
    public void testSsha512() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA512");
        String encPass = encoder.encode("Jason");
        assertTrue(encoder.matches("Jason", encPass));
        assertFalse(encoder.matches("JasonX", encPass));
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
