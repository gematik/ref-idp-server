# IDP Zulassungstestsuite

## Ausführen der Testsuite

Um die Testsuite auszuführen ist folgendes Kommando abzusetzen:
````
mvn clean verify
````
Beim Aufruf ohne cucumber options werden Tests, welche bereits bekannte Fehler (@OpenBug) enthalten bzw. noch in Arbeit (@WiP) sind NICHT ausgeführt.
Dies ist vor allem bei MR runs wichtig.
 
````
mvn clean verify -Dcucumber.options=""
````
In der lokalen Umgebung können die tags Filter deaktiviert werden um alle Tests laufen zu lassen.