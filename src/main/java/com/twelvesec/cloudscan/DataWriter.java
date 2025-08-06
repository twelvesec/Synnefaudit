package com.twelvesec.cloudscan;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import com.twelvesec.cloudscan.AWS.AWSFinding;
import com.twelvesec.cloudscan.CloudCheck.Status;
import com.twelvesec.cloudscan.messages.Text;

public class DataWriter {
    private final Path outputFilePath;
    private final ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new ParameterNamesModule())
        .registerModule(new Jdk8Module())
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final ConcurrentMap<String, ObjectNode> buffer = new ConcurrentHashMap<>();
    private final ReentrantLock flushLock = new ReentrantLock();

    public DataWriter(Path outputFilePath) {
        this.outputFilePath = outputFilePath;
    }

    private void addToBuffer(AWSFinding finding, JsonNode data, Status status) {
        ArrayNode array = data.isArray() ? (ArrayNode) data : MAPPER.createArrayNode().add(data);
        if (arrayNodeContainsText(array, "AccessDeniedException")) {
            status = Status.FAIL_EXCEPTION;
        }

        ObjectNode inner = MAPPER.createObjectNode();
        inner.put(Text.CHECKNAME.toString(), finding.getName());
        inner.put(Text.SEVERITY.toString(), finding.getSeverity().toString());
        inner.put(Text.STATUS.toString(), status.toString());
        inner.set(Text.DATA.toString(), array);

        buffer.put(finding.toString(), inner);
    }

    public void addToBuffer(AWSFinding title, Object data, Status status) {
        JsonNode node = MAPPER.valueToTree(data);
        addToBuffer(title, node, status);
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

    private void writeFile(ObjectNode content) {
        try {
            MAPPER.writerWithDefaultPrettyPrinter()
                .writeValue(outputFilePath.toFile(), content);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write JSON file", e);
        }
    }

    public void flush() {
        flushLock.lock();
        try {
            if (buffer.isEmpty()) return;

            Map<String, ObjectNode> snapshot = new HashMap<>(buffer);
            buffer.clear();

            ObjectNode output = readExistingFile();
            snapshot.forEach(output::set);

            writeFile(output);
        } finally {
            flushLock.unlock();
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
