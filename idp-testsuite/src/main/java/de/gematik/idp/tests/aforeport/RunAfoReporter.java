package de.gematik.idp.tests.aforeport;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

@Slf4j
public class RunAfoReporter {

    public static void main(final String[] args) {
        AfoReporter.main(args);

        final File indexFile = Paths.get("target", "site", "serenity", "index.html").toFile();
        String serenityIndex = null;
        try {
            serenityIndex = FileUtils
                .readFileToString(indexFile, StandardCharsets.UTF_8);
            if (!serenityIndex.contains("aforeport.html")) {
                log.info("Adding Afo Tab to Serenity Report...");
                final int ul = serenityIndex.indexOf("<ul class=\"nav nav-tabs\" role=\"tablist\">");
                final int ulend = serenityIndex.indexOf("</ul>", ul);
                serenityIndex =
                    serenityIndex.substring(0, ulend) + "<li><a href='aforeport.html'>Afo Überdeckung</a></li>"
                        + serenityIndex.substring(ulend);
                FileUtils.writeStringToFile(indexFile, serenityIndex, StandardCharsets.UTF_8);
            }
        } catch (final IOException e) {
            log.error("Adding Afo tab to Serenity failed", e);
        }
    }
}
