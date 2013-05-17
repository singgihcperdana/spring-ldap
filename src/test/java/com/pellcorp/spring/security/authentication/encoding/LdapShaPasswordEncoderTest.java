package com.pellcorp.spring.security.authentication.encoding;

import com.pellcorp.spring.security.authentication.encoding.DigestType;
import com.pellcorp.spring.security.authentication.encoding.LdapShaPasswordEncoder;

import org.junit.Test;

import static org.junit.Assert.*;

public class LdapShaPasswordEncoderTest {
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
    public void testSsha() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder("SSHA");
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
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
