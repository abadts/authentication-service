package com.invex.test.authentication.security.key;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RsaKeyMaterial {

    public RSAKey load(String privateKeyPem, String publicKeyPem) {
        if (isBlank(privateKeyPem) || isBlank(publicKeyPem)) {
            throw new InvalidSigningKeyException("RSA private and public keys are required");
        }
        RSAPrivateCrtKey privateKey = parsePrivateKey(privateKeyPem);
        RSAPublicKey publicKey = parsePublicKey(publicKeyPem);
        if (!privateKey.getModulus().equals(publicKey.getModulus())) {
            throw new InvalidSigningKeyException("RSA public key does not match the private key");
        }
        try {
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyIDFromThumbprint()
                    .build();
        } catch (JOSEException exception) {
            throw new InvalidSigningKeyException("RSA key identifier could not be derived", exception);
        }
    }

    private static RSAPrivateCrtKey parsePrivateKey(String pem) {
        try {
            byte[] encoded = decode(pem, "PRIVATE KEY");
            var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
            if (key instanceof RSAPrivateCrtKey privateKey) {
                return privateKey;
            }
            throw new InvalidSigningKeyException("RSA private key must be a PKCS#8 key");
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new InvalidSigningKeyException("RSA private key could not be parsed", exception);
        }
    }

    private static RSAPublicKey parsePublicKey(String pem) {
        try {
            byte[] encoded = decode(pem, "PUBLIC KEY");
            var key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
            if (key instanceof RSAPublicKey publicKey) {
                return publicKey;
            }
            throw new InvalidSigningKeyException("RSA public key could not be parsed");
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new InvalidSigningKeyException("RSA public key could not be parsed", exception);
        }
    }

    private static byte[] decode(String pem, String type) {
        String header = "-----BEGIN " + type + "-----";
        String footer = "-----END " + type + "-----";
        if (!pem.contains(header) || !pem.contains(footer)) {
            throw new InvalidSigningKeyException("PEM content must include " + type);
        }
        String body = pem.replace(header, "").replace(footer, "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
