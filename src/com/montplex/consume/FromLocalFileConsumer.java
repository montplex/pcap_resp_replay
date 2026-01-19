package com.montplex.consume;

import com.montplex.pipe.SplitFileAppender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.util.Date;

public class FromLocalFileConsumer extends BaseConsumer {
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public FromLocalFileConsumer() {
    }

    private FileChannel channel;

    public void consume(int consumeMaxNum) throws IOException {
        var appender = new SplitFileAppender(512 * 1024 * 1024);
        appender.initWhenFirstTimeUse(0L);
        appender.close();

        var currentFile = appender.getCurrentFile();
        if (currentFile == null) {
            log.warn("No file found");
            return;
        }

        // use nio buffer to read file, max 1G file cost not much memory
        channel = new RandomAccessFile(currentFile, "r").getChannel();
        var buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, currentFile.length());

        int count = 0;
        while (buffer.remaining() > 8) {
            var millis = buffer.getLong();
            if (count % 10000 == 0) {
                System.out.println(DATE_FORMAT.format(new Date(millis)));
            }

            if (offsetFromTimeMillis != -1 && millis < offsetFromTimeMillis) {
                offsetSkippedCount++;

                if (offsetSkippedCount % 10000 == 0) {
                    System.out.println("Skipped " + offsetSkippedCount + " messages with timestamp before " + offsetFromTime);
                }

                buffer.position(buffer.position() + 4);
                var length = buffer.getInt();
                buffer.position(buffer.position() + length);
                continue;
            }

            var type = buffer.getInt();
            var isRequest = type == 0;

            var length = buffer.getInt();
            var data = new byte[length];
            buffer.get(data);

            handleRecord(data, isRequest, millis);

            count++;
            if (count > consumeMaxNum) {
                break;
            }
        }
    }

    public boolean connect() {
        return true;
    }

    public void close() {
        if (channel != null) {
            try {
                channel.close();
            } catch (Exception e) {
                log.error("Error closing channel: {}", e.getMessage());
            }
        }
    }

    public static void main(String[] args) throws IOException {
        var appender = new SplitFileAppender(512 * 1024 * 1024);
        appender.initWhenFirstTimeUse(0L);

        var data = "*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$7\r\nmyvalue\r\n".getBytes();

        appender.writeLong(System.currentTimeMillis());
        appender.writeInt(0);
        appender.writeInt(data.length);
        appender.writeBytes(data);

        appender.flush();
        appender.close();

        var consumer = new FromLocalFileConsumer();
        consumer.consume(1000);
        consumer.close();

        consumer.printStats();
    }
}
