package com.pellcorp.spring.security.digest;

public final class DigesterUtils {
    private DigesterUtils() {
    }
    
    public static Digester extractPrefix(String encPass) {
        if (encPass == null || !encPass.startsWith("{")) {
            return Digester.PLAIN;
        }

        int secondBrace = encPass.lastIndexOf('}');

        if (secondBrace < 0) {
            throw new IllegalArgumentException("Couldn't find closing brace for SHA prefix");
        }

        return new Digester(encPass.substring(1, secondBrace));
    }
}
