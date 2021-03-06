package com.pellcorp.spring.security.authentication.encoding;

import com.pellcorp.spring.security.authentication.encoding.LdapShaPasswordEncoder;
import com.pellcorp.spring.security.digest.Digester;

import org.junit.Test;

import static org.junit.Assert.*;

public class LdapShaPasswordEncoderTest {
    @Test
    public void testSsha512() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA512");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSha512() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA512");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSsha256() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA256");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSha256() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA256");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSsha512Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA-512");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSha512Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA-512");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSsha256Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA-256");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSha256Hyphenated() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA-256");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSsha() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testShaAndSsha() {
        LdapShaPasswordEncoder shaEncoder = new LdapShaPasswordEncoder("SHA");
        LdapShaPasswordEncoder sshaEncoder = new LdapShaPasswordEncoder("SSHA");
        String encPass = shaEncoder.encodePassword("Jason", "jason");
        
        // we are using a SSHA encoder, but the password valid should actually look at the contents
        // of the encoded password and use the appropriate encoder instead.
        assertTrue(sshaEncoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(sshaEncoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testSha() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testNullPassword() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SHA");
        assertFalse(encoder.isPasswordValid("Jason", null, "jason"));
    }
    
    @Test
    public void testPlain() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("PLAIN");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertEquals("Jason", encPass);
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
}
