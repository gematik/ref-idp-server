/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateAnalysis {

  private static final String OID_HBA_AUT = "1.2.276.0.76.4.75"; // A_4445, gemSpec_oid
  private static final String OID_SMC_B_AUT = "1.2.276.0.76.4.77"; // A_4445, gemSpec_oid
  private static final String OID_EGK_AUT = "1.2.276.0.76.4.70"; // A_4445, gemSpec_oid

  public static boolean doesCertificateContainPolicyExtensionOid(
      final X509Certificate certificate, final ASN1ObjectIdentifier policyOid) {
    try {
      final byte[] policyBytes =
          certificate.getExtensionValue(Extension.certificatePolicies.toString());
      if (policyBytes == null) {
        return false;
      }

      final CertificatePolicies policies =
          CertificatePolicies.getInstance(JcaX509ExtensionUtils.parseExtensionValue(policyBytes));
      return Stream.of(policies.getPolicyInformation())
          .map(PolicyInformation::getPolicyIdentifier)
          .anyMatch(policyId -> policyId.equals(policyOid));
    } catch (final IOException e) {
      throw new IdpCryptoException("Error while checking Policy-Extension!", e);
    }
  }

  public static TiCertificateType determineCertificateType(final X509Certificate certificate) {
    if (doesCertificateContainPolicyExtensionOid(
        certificate, new ASN1ObjectIdentifier(OID_HBA_AUT))) {
      return TiCertificateType.HBA;
    }
    if (doesCertificateContainPolicyExtensionOid(
        certificate, new ASN1ObjectIdentifier(OID_SMC_B_AUT))) {
      return TiCertificateType.SMCB;
    }
    if (doesCertificateContainPolicyExtensionOid(
        certificate, new ASN1ObjectIdentifier(OID_EGK_AUT))) {
      return TiCertificateType.EGK;
    }
    return TiCertificateType.UNKNOWN;
  }
}
