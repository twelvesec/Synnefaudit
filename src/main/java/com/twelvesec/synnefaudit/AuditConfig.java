package com.twelvesec.synnefaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AuditConfig {

    public static JsonNode load(String configFilePath) {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            Path externalPath = Paths.get(configFilePath);

            if (Files.exists(externalPath)) {
                try (InputStream is = Files.newInputStream(externalPath)) {
                    return mapper.readTree(is);
                }
            }

            try (InputStream is = AuditConfig.class.getClassLoader().getResourceAsStream(configFilePath)) {
                if (is != null) {
                    return mapper.readTree(is);
                }
            }
        } catch (Exception e) {
            System.err.println("Warning: Unable to parse configuration file. Using default fallbacks. Error: " + e.getMessage());
        }

        return mapper.createObjectNode();
    }
}