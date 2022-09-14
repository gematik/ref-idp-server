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

package de.gematik.idp.brainPoolExtension;

import de.gematik.idp.exceptions.IdpJoseException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.spec.ECParameterSpec;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.keys.EllipticCurves;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class BrainpoolCurves {

    public static final String BP_256 = "BP-256";
    public static final String BP_384 = "BP-384";
    public static final String BP_512 = "BP-512";

    private static final ECNamedCurveParameterSpec EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1 = ECNamedCurveTable.getParameterSpec(
        "brainpoolP256r1");
    private static final ECNamedCurveParameterSpec EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1 = ECNamedCurveTable.getParameterSpec(
        "brainpoolP384r1");
    private static final ECNamedCurveParameterSpec EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1 = ECNamedCurveTable.getParameterSpec(
        "brainpoolP512r1");
    private static final ECParameterSpec EC_PARAMETER_SPEC_BP256R1 = new ECNamedCurveSpec("brainpoolP256r1",
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.getCurve(), EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.getG(),
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.getN(), EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.getH(),
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.getSeed());
    private static final ECParameterSpec EC_PARAMETER_SPEC_BP384R1 = new ECNamedCurveSpec("brainpoolP384r1",
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.getCurve(), EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.getG(),
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.getN(), EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.getH(),
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.getSeed());
    private static final ECParameterSpec EC_PARAMETER_SPEC_BP512R1 = new ECNamedCurveSpec("brainpoolP512r1",
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.getCurve(), EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.getG(),
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.getN(), EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.getH(),
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.getSeed());

    public static final ECParameterSpec BP256 = EC_PARAMETER_SPEC_BP256R1;
    public static final ECParameterSpec BP384 = EC_PARAMETER_SPEC_BP384R1;
    public static final ECParameterSpec BP512 = EC_PARAMETER_SPEC_BP512R1;

    private static boolean initialized;

    private static void addCurve(final String name, final ECParameterSpec spec) {
        try {
            final Method method = EllipticCurves.class
                .getDeclaredMethod("addCurve", String.class, ECParameterSpec.class);
            method.setAccessible(true);
            method.invoke(BrainpoolCurves.class, name, spec);
        } catch (final InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
            throw new IdpJoseException(
                "Error while adding BrainPool-Curves " + name + " to internal Algorithm-Suite repository", e);
        }
    }

    public static void init() {
        if (initialized) {
            return;
        }

        addCurve(BP_256, BP256);
        addCurve(BP_384, BP384);
        addCurve(BP_512, BP512);

        AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory()
            .registerAlgorithm(new BrainpoolAlgorithmSuites.EcdsaBP256R1UsingSha256());
        AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory()
            .registerAlgorithm(new BrainpoolAlgorithmSuites.EcdsaBP384R1UsingSha384());
        AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory()
            .registerAlgorithm(new BrainpoolAlgorithmSuites.EcdsaBP512R1UsingSha512());

        initialized = true;
    }
}
