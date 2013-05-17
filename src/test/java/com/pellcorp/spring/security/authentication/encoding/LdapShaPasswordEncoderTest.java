package com.pellcorp.spring.security.authentication.encoding;

import com.pellcorp.spring.security.authentication.encoding.DigestType;
import com.pellcorp.spring.security.authentication.encoding.LdapShaPasswordEncoder;

import org.junit.Test;

import static org.junit.Assert.*;

public class LdapShaPasswordEncoderTest {
    @Test
    public void testSsha() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder(DigestType.SSHA);
        String encPass = encoder.encodePassword("Jason", "jason");
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertFalse(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
    
    @Test
    public void testPlain() {
        LdapShaPasswordEncoder encoder = new LdapShaPasswordEncoder(DigestType.PLAIN);
        String encPass = encoder.encodePassword("Jason", "jason");
        assertEquals("Jason", encPass);
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jason"));
        assertTrue(encoder.isPasswordValid(encPass, "Jason", "jasonX"));
    }
}
