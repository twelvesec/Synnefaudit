package com.twelvesec.synnefaudit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import com.twelvesec.synnefaudit.AWS.AWSFinding;
import com.twelvesec.synnefaudit.CloudCheck.Status;
import com.twelvesec.synnefaudit.messages.Text;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.StreamSupport;

public class DataWriter {
    private final Path outputFilePath;
    private final Path summaryFilePath;
    private final ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new ParameterNamesModule())
        .registerModule(new Jdk8Module())
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final ConcurrentMap<String, ObjectNode> buffer = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ObjectNode> summaryBuffer = new ConcurrentHashMap<>();
    private final ReentrantLock flushLock = new ReentrantLock();

    public DataWriter(Path outputDirectory) {
        String timestamp = LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        
        String outputFileName = "synnefaudit-output-" + timestamp + ".json";
        String summaryFileName = "synnefaudit-output-" + timestamp + "-summary.json";
        
        this.outputFilePath = outputDirectory.resolve(outputFileName);
        this.summaryFilePath = outputDirectory.resolve(summaryFileName);
    }

    public Path getOutputFilePath() {
        return this.outputFilePath;
    }

    public void addToBuffer(AWSFinding title, Object data, Status status) {
        JsonNode node = MAPPER.valueToTree(data);
        addToBuffer(title, node, status);
    }

    private void addToBuffer(AWSFinding finding, JsonNode data, Status status) {
        ArrayNode array = data.isArray() ? (ArrayNode) data : MAPPER.createArrayNode().add(data);
        if (arrayNodeContainsText(array, "AccessDeniedException")) {
            status = Status.FAIL_EXCEPTION;
        }
        
        CheckMetadata metadata = MetadataLoader.get(finding.name());

        ObjectNode inner = MAPPER.createObjectNode();
        inner.put(Text.CHECKNAME.toString(), metadata.getCheckTitle() != null ? metadata.getCheckTitle() : finding.name());
        inner.put(Text.SEVERITY.toString(), metadata.toSeverityEnum().toString());
        inner.put(Text.STATUS.toString(), status.toString());
        inner.put(Text.DATA.toString(), array);

        buffer.put(finding.toString(), inner);
        
        ObjectNode summaryNode = MAPPER.createObjectNode();
        summaryNode.put(Text.SEVERITY.toString(), metadata.toSeverityEnum().toString());
        summaryNode.put(Text.STATUS.toString(), status.toString());
        summaryBuffer.put(finding.toString(), summaryNode);
    }

    public void flush() {
        flushLock.lock();
        try {
            if (buffer.isEmpty() && summaryBuffer.isEmpty()) return;

            Map<String, ObjectNode> snapshot = new HashMap<>(buffer);
            Map<String, ObjectNode> summarySnapshot = new HashMap<>(summaryBuffer);
            buffer.clear();
            summaryBuffer.clear();

            try {
                ObjectNode output = readExistingFile();
                snapshot.forEach(output::set);
                writeFile(output, outputFilePath);
            } catch (Exception e) {
                System.err.println("Failed to write .json output file: " + e.getMessage());
                buffer.putAll(snapshot);
            }

            try {
                ObjectNode summaryOutput = readExistingSummaryFile();
                summarySnapshot.forEach(summaryOutput::set);
                writeFile(summaryOutput, summaryFilePath);
            } catch (Exception e) {
                System.err.println("Failed to write .json summary file: " + e.getMessage());
                summaryBuffer.putAll(summarySnapshot);
            }
        } finally {
            flushLock.unlock();
        }
    }

    private ObjectNode readExistingSummaryFile() {
        File file = summaryFilePath.toFile();
        if (!file.exists() || file.length() == 0) {
            return MAPPER.createObjectNode();
        }
        try {
            return (ObjectNode) MAPPER.readTree(file);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read summary JSON file", e);
        }
    }

    private void writeFile(ObjectNode content, Path path) {
        try {
            MAPPER.writerWithDefaultPrettyPrinter()
                .writeValue(path.toFile(), content);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write JSON file to " + path, e);
        }
    }

    private ObjectNode readExistingFile() {
        File file = outputFilePath.toFile();
        if (!file.exists() || file.length() == 0) {
            return MAPPER.createObjectNode();
        }
        try {
            return (ObjectNode) MAPPER.readTree(file);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read JSON file", e);
        }
    }

    private boolean arrayNodeContainsText(ArrayNode array, String substring) {
        return StreamSupport.stream(array.spliterator(), false)
            .anyMatch(node -> {
                if (node.isTextual()) {
                    return node.textValue().contains(substring);
                }
                return node.toString().contains(substring);
            });
    }
}
