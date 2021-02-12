/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CryptoLoader {

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    public static X509Certificate getCertificateFromP12(final byte[] crt, final String p12Password) {
        try {
            final KeyStore p12 = KeyStore.getInstance("pkcs12", BOUNCY_CASTLE_PROVIDER);
            p12.load(new ByteArrayInputStream(crt), p12Password.toCharArray());
            final Enumeration<String> e = p12.aliases();
            while (e.hasMoreElements()) {
                final String alias = e.nextElement();
                return (X509Certificate) p12.getCertificate(alias);
            }
        } catch (final IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new IdpCryptoException(e);
        }
        throw new IdpCryptoException("Could not find certificate in P12-File");
    }

    public static X509Certificate getCertificateFromPem(final byte[] crt) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BOUNCY_CASTLE_PROVIDER);
            final InputStream in = new ByteArrayInputStream(crt);
            final X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(in);
            if (x509Certificate == null) {
                throw new IdpCryptoException("Error while loading certificate!");
            }
            return x509Certificate;
        } catch (final CertificateException ex) {
            throw new IdpCryptoException("Error while loading certificate!", ex);
        }
    }

    public static PkiIdentity getIdentityFromP12(final byte[] p12FileContent, final String p12Password) {
        try {
            final KeyStore p12 = KeyStore.getInstance("pkcs12", BOUNCY_CASTLE_PROVIDER);
            p12.load(new ByteArrayInputStream(p12FileContent), p12Password.toCharArray());
            final Enumeration<String> e = p12.aliases();
            while (e.hasMoreElements()) {
                final String alias = e.nextElement();
                final X509Certificate certificate = (X509Certificate) p12.getCertificate(alias);
                final PrivateKey privateKey = (PrivateKey) p12.getKey(alias, p12Password.toCharArray());
                return new PkiIdentity(certificate, privateKey, Optional.empty());
            }
        } catch (final IOException | KeyStoreException | NoSuchAlgorithmException
            | UnrecoverableKeyException | CertificateException e) {
            throw new IdpCryptoException(e);
        }
        throw new IdpCryptoException("Could not find certificate in P12-File");
    }

    public static PublicKey getEcPublicKeyFromBytes(final byte[] keyBytes) {
        final X509EncodedKeySpec publicKeyEncoded = new X509EncodedKeySpec(keyBytes);
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(publicKeyEncoded);
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IdpCryptoException(e);
        }
    }
}
