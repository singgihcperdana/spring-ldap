package com.pellcorp.spring.security.digest;

public final class DigestTypeUtils {
    private DigestTypeUtils() {
    }
    
    public static DigestType extractPrefix(String encPass) {
        if (encPass == null || !encPass.startsWith("{")) {
            return DigestType.PLAIN;
        }

        int secondBrace = encPass.lastIndexOf('}');

        if (secondBrace < 0) {
            throw new IllegalArgumentException("Couldn't find closing brace for SHA prefix");
        }

        return new DigestType(encPass.substring(1, secondBrace));
    }
}
