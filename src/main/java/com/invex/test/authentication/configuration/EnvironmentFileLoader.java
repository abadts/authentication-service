package com.invex.test.authentication.configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class EnvironmentFileLoader {

    public void load(Path path) {
        if (path == null || Files.notExists(path)) {
            return;
        }
        List<String> lines = readLines(path);
        for (String rawLine : lines) {
            applyLine(rawLine);
        }
    }

    private static List<String> readLines(Path path) {
        try {
            return Files.readAllLines(path);
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to read " + path, exception);
        }
    }

    private static void applyLine(String rawLine) {
        String line = rawLine.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return;
        }
        if (line.startsWith("export ")) {
            line = line.substring("export ".length()).trim();
        }
        int separator = line.indexOf('=');
        if (separator <= 0) {
            return;
        }
        String key = line.substring(0, separator).trim();
        String value = unescape(line.substring(separator + 1).trim());
        if (System.getenv(key) == null && System.getProperty(key) == null) {
            System.setProperty(key, value);
        }
    }

    private static String unescape(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            String quoted = value.substring(1, value.length() - 1);
            return quoted.replace("\\n", "\n").replace("\\\"", "\"");
        }
        return value;
    }
}
