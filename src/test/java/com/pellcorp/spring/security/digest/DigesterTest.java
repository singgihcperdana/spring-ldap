package com.pellcorp.spring.security.digest;

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.fail;

public class DigesterTest extends Assert {
    @Test
    public void testGetLength() {
        Digester sha = new Digester("SHA");
        assertEquals(20, sha.getLength());
        
        Digester sha256 = new Digester("SHA-256");
        assertEquals(32, sha256.getLength());
        
        Digester sha384 = new Digester("SHA-384");
        assertEquals(48, sha384.getLength());
        
        Digester sha512 = new Digester("SHA-512");
        assertEquals(64, sha512.getLength());
    }
}
