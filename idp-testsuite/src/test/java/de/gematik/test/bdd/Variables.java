package de.gematik.test.bdd;

public class Variables extends ThreadedContextProvider {

    private static final Variables SINGLETON = new Variables();

    public static Variables get() {
        return SINGLETON;
    }

    public static String substituteVariables(String str) {
        int varIdx = str.indexOf("${VAR.");
        while (varIdx != -1) {
            final int endVar = str.indexOf("}", varIdx);
            final String varName = str.substring(varIdx + "${VAR.".length(), endVar);
            str = str.substring(0, varIdx) + Variables.get().get(varName) + str.substring(endVar + 1);
            varIdx = str.indexOf("${VAR.");
        }
        return str;
    }
}
