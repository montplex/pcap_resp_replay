package com.montplex.consume;

import com.montplex.resp.Category;
import com.montplex.resp.MonitorAndReplay;
import com.montplex.resp.RESP;
import com.montplex.tools.TablePrinter;
import io.netty.buffer.Unpooled;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.*;

public class FromKafkaConsumer {
    private final String topic;
    private final String broker;
    private final String groupId;
    private final String offsetFromTime;
    private final long offsetFromTimeMillis;

    private long offsetSkippedCount = 0L;

    private KafkaConsumer<String, byte[]> consumer;

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final boolean isKafkaMock = MonitorAndReplay.getFromSystemProperty("isKafkaMock", 0) == 1;

    private final File mockRecordsFile = new File("mock_records.dat");

    public FromKafkaConsumer(String topic, String broker, String groupId, String offsetFromTime) {
        this.topic = topic;
        this.broker = broker;
        this.groupId = groupId;
        this.offsetFromTime = offsetFromTime;
        if (offsetFromTime != null) {
            try {
                this.offsetFromTimeMillis = DATE_FORMAT.parse(offsetFromTime).getTime();
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        } else {
            this.offsetFromTimeMillis = -1L;
        }
    }

    public boolean connect() {
        if (isKafkaMock) {
            log.warn("is kafka mock mode");
            return true;
        }

        try {
            var props = new Properties();
            props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, broker);
            props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
            props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
            props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());

            // Set auto offset reset to earliest to start consuming from beginning
            props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
            // Disable auto commit to control offset manually
            props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);

            this.consumer = new KafkaConsumer<>(props);
            log.info("Successfully connected to Kafka broker: {} with topic: {}", broker, topic);
            return true;
        } catch (Exception e) {
            log.error("Failed to connect to Kafka broker: {}, error: {}", broker, e.getMessage());
            return false;
        }
    }

    private final RESP resp = new RESP();

    private long validRespDataCount;
    private long clientReceivedCount;
    private long readCmdCount;
    private long writeCmdCount;
    private long otherCmdCount;

    private final TreeMap<String, Long> countByCmd = new TreeMap<>();

    private static long lastPrintMillis = 0L;

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private void printAny(long millis, Object any, Object[] array) {
        // print time every 10 seconds
        final int printInterval = 1000 * 10;
        if (lastPrintMillis == 0L) {
            lastPrintMillis = millis;
            System.out.println(DATE_FORMAT.format(new Date(millis)));
        } else if (millis - lastPrintMillis > printInterval) {
            lastPrintMillis = millis;
            System.out.println(DATE_FORMAT.format(new Date(millis)));
        }

        printAnyWithSpacePrefix(any, array, 0);
    }

    private long okCount = 0L;
    private long nullCount = 0L;

    private void printIgnoreSome(String prefix, String str, boolean isTopValue) {
        if (isTopValue && str.equals("OK")) {
            okCount++;
            return;
        } else if (isTopValue && str.equals("null")) {
            nullCount++;
            return;
        }

        System.out.print(prefix);
        System.out.println(str);
    }

    private void printAnyWithSpacePrefix(Object any, Object[] array, int trim) {
        var prefix = " ".repeat(trim);
        if (any != null) {
            String str;
            if (any instanceof byte[] bytes) {
                str = new String(bytes);
            } else {
                str = any.toString();
            }

            printIgnoreSome(prefix, str, trim == 0);
            return;
        }

        for (int i = 0; i < array.length; i++) {
            var item = array[i];
            if (item instanceof Object[] subArray) {
                printAnyWithSpacePrefix(null, subArray, trim + 2);
            } else {
                if (i == 0) {
                    System.out.print(prefix);
                    System.out.println("-");
                }

                System.out.print(prefix + "  ");
                if (item instanceof byte[] bytes) {
                    System.out.println(new String(bytes));
                } else {
                    System.out.println(item);
                }
            }
        }
    }

    public void consume(int num) {
        if (isKafkaMock) {
            try {
                var mockRecordsIs = new DataInputStream(new FileInputStream(mockRecordsFile));
                int consumedCount = 0;

                while (mockRecordsIs.available() > 0) {
                    var headerLength = mockRecordsIs.readInt();
                    var headerBytes = new byte[headerLength];
                    mockRecordsIs.readFully(headerBytes);

                    var header = new String(headerBytes);
                    var arr = header.split(" ");
                    assert arr.length == 2;
                    var timestamp = Long.parseLong(arr[0]);
                    var isRequest = "REQ".equals(arr[1]);

                    var dataLength = mockRecordsIs.readInt();
                    var data = new byte[dataLength];
                    mockRecordsIs.readFully(data);

                    if (offsetFromTimeMillis != -1 && timestamp < offsetFromTimeMillis) {
                        offsetSkippedCount++;

                        if (offsetSkippedCount % 10000 == 0) {
                            System.out.println("Skipped " + offsetSkippedCount + " messages with timestamp before " + offsetFromTime);
                        }
                        continue;
                    }

                    handleRecord(data, isRequest, timestamp);

                    consumedCount++;
                    if (consumedCount >= num) {
                        break;
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            return;
        }

        try {
            // Subscribe to the topic
            consumer.subscribe(Collections.singletonList(topic));

            int consumedCount = 0;

            // Continue consuming until we reach the specified number or encounter an error
            while (consumedCount < num) {
                var records = consumer.poll(Duration.ofMillis(1000));
                for (var record : records) {
                    var timestamp = record.timestamp();
                    if (offsetFromTimeMillis != -1 && timestamp < offsetFromTimeMillis) {
                        offsetSkippedCount++;

                        if (offsetSkippedCount % 10000 == 0) {
                            System.out.println("Skipped " + offsetSkippedCount + " messages with timestamp before " + offsetFromTime);
                        }
                        continue;
                    }

                    var headers = record.headers();
                    var isRequest = headers != null && headers.lastHeader("isRequest") != null;
                    var data = record.value();

                    handleRecord(data, isRequest, timestamp);

                    consumedCount++;
                    if (consumedCount >= num) {
                        break;
                    }
                }

                if (validRespDataCount % 10_000 == 0) {
                    log.info("valid resp data count: {}, read category: {}, write category: {}",
                            validRespDataCount, readCmdCount, writeCmdCount);
                }

                // Commit offsets after processing batch
                consumer.commitSync();

                if (consumedCount >= num) {
                    break;
                }
            }

            log.info("Completed consumption of {} messages from topic: {}", consumedCount, topic);
        } catch (Exception e) {
            log.error("Error during consumption from Kafka: {}", e.getMessage());
        }
    }

    private void handleRecord(byte[] data, boolean isRequest, long timestamp) {
        var buf = Unpooled.wrappedBuffer(data);
        var cmdArgs = resp.decode(buf, isRequest, timestamp, this::printAny);
        while (cmdArgs != null) {
            validRespDataCount++;

            if (cmdArgs == RESP.RESPONSE_CMD) {
                clientReceivedCount++;
            } else {
                var cmd = cmdArgs.cmd();
                var count = countByCmd.getOrDefault(cmd, 0L);
                countByCmd.put(cmd, count + 1);
                if (Category.isReadCmd(cmd)) {
                    readCmdCount++;
                } else if (Category.isWriteCmd(cmd)) {
                    writeCmdCount++;
                } else {
                    otherCmdCount++;
                }
            }

            cmdArgs = resp.decode(buf, isRequest, timestamp, this::printAny);
        }
    }

    public void printStats() {
        System.out.println("skipped print OK result count: " + okCount);
        System.out.println("skipped print NULL result count: " + nullCount);

        // resp data count
        var row2 = MonitorAndReplay.toRow(validRespDataCount, clientReceivedCount,
                readCmdCount, writeCmdCount, otherCmdCount);
        var rows2 = new ArrayList<List<String>>();
        rows2.add(row2);

        var headers2 = MonitorAndReplay.toHeaders("valid resp data count", "client received count",
                "read cmd count", "write cmd count", "other cmd count");
        new TablePrinter(headers2).print(rows2);

        // cmd count
        MonitorAndReplay.printCmdCountStats(countByCmd);
    }

    public void close() {
        if (isKafkaMock) {
            return;
        }

        consumer.close();
        log.info("Closed Kafka consumer");
    }

    public static void main(String[] args) {
        var resp = new RESP();
        var consumer = new FromKafkaConsumer("test", "localhost:9092", "test", null);

        // Test 1: Basic command (LPUSH) - server command, no callback triggered
        System.out.println("Test 1: Basic command (LPUSH)");
        var data = "*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$7\r\nmyvalue\r\n".getBytes();
        var buf = Unpooled.wrappedBuffer(data);
        var cmdArgs = resp.decode(buf, consumer::printAny);
        assert cmdArgs != null;
        if (cmdArgs != RESP.RESPONSE_CMD) {
            System.out.println("Command: " + cmdArgs.cmd());
            System.out.println("Args count: " + cmdArgs.args().length);
        }

        // Test 2: Error response - triggers callback
        System.out.println("\nTest 2: Error response (triggers callback)");
        var dataError = "-ERR unknown command 'INVALID'\r\n".getBytes();
        var bufError = Unpooled.wrappedBuffer(dataError);
        var cmdArgsError = resp.decode(bufError, consumer::printAny);
        assert cmdArgsError == RESP.RESPONSE_CMD;

        // Test 3: Simple string - triggers callback
        System.out.println("\nTest 3: Simple string (triggers callback)");
        var dataSimple = "+OK\r\n".getBytes();
        var bufSimple = Unpooled.wrappedBuffer(dataSimple);
        var simpleResult = resp.decode(bufSimple, consumer::printAny);
        assert simpleResult == RESP.RESPONSE_CMD;

        // Test 4: Integer - triggers callback
        System.out.println("\nTest 4: Integer (triggers callback)");
        var dataInt = ":12345\r\n".getBytes();
        var bufInt = Unpooled.wrappedBuffer(dataInt);
        var intResult = resp.decode(bufInt, consumer::printAny);
        assert intResult == RESP.RESPONSE_CMD;

        // Test 5: Bulk string - triggers callback
        System.out.println("\nTest 5: Bulk string (triggers callback)");
        var dataBulk = "$5\r\nhello\r\n".getBytes();
        var bufBulk = Unpooled.wrappedBuffer(dataBulk);
        var bulkResult = resp.decode(bufBulk, consumer::printAny);
        assert bulkResult == RESP.RESPONSE_CMD;

        // Test 6: Null bulk string - triggers callback
        System.out.println("\nTest 6: Null bulk string (triggers callback)");
        var dataNullBulk = "$-1\r\n".getBytes();
        var bufNullBulk = Unpooled.wrappedBuffer(dataNullBulk);
        var nullBulkResult = resp.decode(bufNullBulk, consumer::printAny);
        assert nullBulkResult == RESP.RESPONSE_CMD;

        // Test 7: Array with nested elements - triggers callback
        System.out.println("\nTest 7: Array with nested elements (triggers callback)");
        var dataArrayNested = "*3\r\n$3\r\nxxx\r\n$5\r\nhello\r\n$5\r\nworld\r\n".getBytes();
        var bufArrayNested = Unpooled.wrappedBuffer(dataArrayNested);
        var arrayNestedResult = resp.decode(bufArrayNested, consumer::printAny);
        assert arrayNestedResult == RESP.RESPONSE_CMD;

        // Test 8: Complex nested array (multiple levels) - triggers callback
        System.out.println("\nTest 8: Complex nested array (triggers callback)");
        var dataComplex = "*2\r\n*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n*2\r\n$4\r\nfoob\r\n$4\r\nbarb\r\n".getBytes();
        var bufComplex = Unpooled.wrappedBuffer(dataComplex);
        var complexResult = resp.decode(bufComplex, consumer::printAny);
        assert complexResult == RESP.RESPONSE_CMD;

        // Test 9: Map (Redis 7+) - triggers callback
        System.out.println("\nTest 9: Map (Redis 7+) (triggers callback)");
        var dataMap = "%2\r\n$3\r\nkey\r\n$5\r\nvalue\r\n$4\r\ntest\r\n$4\r\ndata\r\n".getBytes();
        var bufMap = Unpooled.wrappedBuffer(dataMap);
        var mapResult = resp.decode(bufMap, consumer::printAny);
        assert mapResult == RESP.RESPONSE_CMD;

        // Test 10: Set (Redis 7+) - triggers callback
        System.out.println("\nTest 10: Set (Redis 7+) (triggers callback)");
        var dataSet = "~3\r\n$3\r\none\r\n$3\r\ntwo\r\n$5\r\nthree\r\n".getBytes();
        var bufSet = Unpooled.wrappedBuffer(dataSet);
        var setResult = resp.decode(bufSet, consumer::printAny);
        assert setResult == RESP.RESPONSE_CMD;

        // Test 11: Boolean (Redis 7+) - triggers callback
        System.out.println("\nTest 11: Boolean (Redis 7+) (triggers callback)");
        var dataBool = "#t\r\n".getBytes();
        var bufBool = Unpooled.wrappedBuffer(dataBool);
        var boolResult = resp.decode(bufBool, consumer::printAny);
        assert boolResult == RESP.RESPONSE_CMD;

        // Test 12: Double (Redis 7+) - triggers callback
        System.out.println("\nTest 12: Double (Redis 7+) (triggers callback)");
        var dataDouble = ",3.14159\r\n".getBytes();
        var bufDouble = Unpooled.wrappedBuffer(dataDouble);
        var doubleResult = resp.decode(bufDouble, consumer::printAny);
        assert doubleResult == RESP.RESPONSE_CMD;

        // Test 13: Null (Redis 7+) - triggers callback
        System.out.println("\nTest 13: Null (Redis 7+) (triggers callback)");
        var dataNull = "_\r\n".getBytes();
        var bufNull = Unpooled.wrappedBuffer(dataNull);
        var nullResult = resp.decode(bufNull, consumer::printAny);
        assert nullResult == RESP.RESPONSE_CMD;

        consumer.printStats();

        System.out.println("\nAll tests completed!");
    }
}
