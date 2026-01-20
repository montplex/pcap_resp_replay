package com.montplex.pipe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;

public class SplitFileAppender {

    private final Logger log = LoggerFactory.getLogger(SplitFileAppender.class);

    private final String fileNamePrefix = "all_cmd_log.";

    private File currentFile;

    private BufferedOutputStream out;

    private long fileSize = 0L;

    private final int splitSize;

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

    public SplitFileAppender(int splitSize) {
        this.splitSize = splitSize;
    }

    public void initWhenFirstTimeUse(long beginMillis) {
        if (currentFile != null) {
            return;
        }

        long currentThreadId = Thread.currentThread().getId();
        log.info("Init SplitFileAppender thread id: {}", currentThreadId);

        try {
            File lastFile = null;
            long lastFileMillis = 0;
            File[] files = new File(".").listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.getName().startsWith(fileNamePrefix)) {
                        if (file.length() == 0) {
                            continue;
                        }

                        var arr = file.getName().split("\\.");
                        if (arr.length == 5) {
                            long threadId = Long.parseLong(arr[3]);
                            // Need match thread ID when server restarts
                            if (currentThreadId != threadId) {
                                continue;
                            }

                            long time = Long.parseLong(arr[1]);
                            if (beginMillis != 0 && time > beginMillis) {
                                continue;
                            }

                            if (time > lastFileMillis) {
                                lastFile = file;
                                lastFileMillis = time;
                            }
                        }
                    }
                }
            }

            if (lastFile == null) {
                lastFile = new File(generateFileName());
                boolean r = lastFile.createNewFile();
                if (!r) {
                    throw new RuntimeException("Create file error. File name: " + lastFile.getName());
                }
            } else {
                log.warn("Use existing file: {}", lastFile.getName());
                fileSize = lastFile.length();
            }

            currentFile = lastFile;
            out = new BufferedOutputStream(new FileOutputStream(lastFile, true));
            log.info("Initialized SplitFileAppender file output stream.");

            // Add shutdown hook to properly close the output stream
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    flush();
                    close();
                } catch (Exception ignored) {
                }
            }));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void writeInt(int i) throws IOException {
        byte[] bb = new byte[4];
        ByteBuffer.wrap(bb).putInt(i);
        out.write(bb);
        fileSize += 4;
    }

    public void writeLong(long l) throws IOException {
        byte[] bb = new byte[8];
        ByteBuffer.wrap(bb).putLong(l);
        out.write(bb);
        fileSize += 8;
    }

    public void writeBytes(byte[] bytes) throws IOException {
        out.write(bytes);
        fileSize += bytes.length;
    }

    public void checkIfNeedSplitFile() throws IOException {
        if (fileSize < splitSize) {
            return;
        }

        flush();

        // Rename current file with .bak extension
        boolean renameResult = currentFile.renameTo(new File(currentFile.getName() + ".bak"));

        // Create a new file with a new timestamp
        File nextFile = new File(generateFileName());
        boolean r = nextFile.createNewFile();
        if (!r) {
            throw new RuntimeException("Create file error. File name: " + nextFile.getName());
        }

        // Update current file and output stream to the new file
        currentFile = nextFile;
        out.close(); // Close previous stream before creating new one
        out = new BufferedOutputStream(new FileOutputStream(nextFile, true));
        fileSize = 0;

        log.warn("SplitFileAppender split file, rename: {}, create file name: {}", renameResult, nextFile.getName());
    }

    private String generateFileName() {
        Date now = new Date();
        long threadId = Thread.currentThread().getId();
        return fileNamePrefix + now.getTime() + "." + dateFormat.format(now) + "." + threadId + ".dat";
    }

    public File getCurrentFile() {
        return currentFile;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void flush() throws IOException {
        out.flush();
    }

    public void close() throws IOException {
        if (out != null) {
            out.close();
        }
    }
}