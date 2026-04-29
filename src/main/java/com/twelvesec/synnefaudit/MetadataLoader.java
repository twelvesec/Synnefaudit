package com.twelvesec.synnefaudit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.twelvesec.synnefaudit.CloudCheck.Provider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

public final class MetadataLoader {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ConcurrentMap<String, CheckMetadata> CACHE = new ConcurrentHashMap<>();
    private static final String METADATA_DIR = "Metadata";
    private static final String META_SUFFIX = ".metadata.json";

    public static CheckMetadata get(String checkId) {
        return CACHE.computeIfAbsent(checkId, id -> {
            try {
                return load(id);
            } catch (Exception e) {
                return createIndividualErrorMetadata(id);
            }
        });
    }

    private static CheckMetadata load(String id) {        
        String fileName = id + META_SUFFIX;
        
        if (!isValidFileName(fileName)) {
            throw new SecurityException("Invalid file name: " + fileName);
        }

        Path baseDir = Paths.get(getProviderBasePath());

        return discoverPotentialPaths(baseDir, fileName)
            .map(MetadataLoader::tryLoadFile)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .findFirst()
            .orElseThrow(() -> new RuntimeException("Metadata file not found for check id: " + id));
    }

    private static CheckMetadata createIndividualErrorMetadata(String checkId) {
        return new CheckMetadata(
            "ERROR",
            checkId,
            "Missing Metadata",
            "",
            "Metadata file not found for check id: " + checkId,
            "Check metadata configuration"
        );
    }

    private static Stream<Path> discoverPotentialPaths(Path baseDir, String fileName) {
        Stream<Path> rootPath = Stream.of(baseDir.resolve(fileName));
        
        if (!Files.exists(baseDir) || !Files.isDirectory(baseDir)) {
            return rootPath;
        }

        List<Path> subdirectoryFilePaths;
        try (Stream<Path> directoryStream = Files.list(baseDir)) {
            subdirectoryFilePaths = directoryStream
                .filter(Files::isDirectory)
                .map(subdir -> subdir.resolve(fileName))
                .toList();
        } catch (IOException e) {
            System.err.println("Warning: Error reading directory " + baseDir + ": " + e.getMessage());
            return rootPath;
        }
        return Stream.concat(rootPath, subdirectoryFilePaths.stream());
    }

    private static Optional<CheckMetadata> tryLoadFile(Path filePath) {
        if (Files.exists(filePath) && Files.isRegularFile(filePath)) {
            try (InputStream in = Files.newInputStream(filePath)) {
                return Optional.of(MAPPER.readValue(in, CheckMetadata.class));
            } catch (IOException e) {
                System.err.println("Error reading file: " + filePath + " - " + e.getMessage());
            }
        }
        return Optional.empty();
    }

    private static String getProviderBasePath() {
        String providerDir = switch (App.getProvider()) {
            case Provider.AWS -> "AWS";
            default -> "Unknown";
        };

        return Paths.get(METADATA_DIR, providerDir).toString();
    }

    private static boolean isValidFileName(String fileName) {
        return fileName.matches("^[a-zA-Z0-9_\\-.]+\\.metadata\\.json$");
    }

    public static void clearCache() {
        CACHE.clear();
    }
}
