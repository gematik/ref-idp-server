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

package de.gematik.idp.brainPoolExtension;

import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.jws.JsonWebSignatureAlgorithm;

public class BrainpoolAlgorithmSuites extends EcdsaUsingShaAlgorithm implements JsonWebSignatureAlgorithm {

    public BrainpoolAlgorithmSuites(final String id, final String javaAlgo, final String curveName,
        final int signatureByteLength) {
        super(id, javaAlgo, curveName, signatureByteLength);
    }

    public static class EcdsaBP256R1UsingSha256 extends BrainpoolAlgorithmSuites {

        public EcdsaBP256R1UsingSha256() {
            super(BrainpoolAlgorithmSuiteIdentifiers.INTERNAL_BRAINPOOL256_USING_SHA256, "SHA256withECDSA",
                BrainpoolCurves.BP_256, 64);
        }
    }

    public static class EcdsaBP384R1UsingSha384 extends BrainpoolAlgorithmSuites {

        public EcdsaBP384R1UsingSha384() {
            super(BrainpoolAlgorithmSuiteIdentifiers.INTERNAL_BRAINPOOL384_USING_SHA384, "SHA384withECDSA",
                BrainpoolCurves.BP_384, 96);
        }
    }

    public static class EcdsaBP512R1UsingSha512 extends BrainpoolAlgorithmSuites {

        public EcdsaBP512R1UsingSha512() {
            super(BrainpoolAlgorithmSuiteIdentifiers.INTERNAL_BRAINPOOL512_USING_SHA512, "SHA512withECDSA",
                BrainpoolCurves.BP_512, 132);
        }
    }

}
