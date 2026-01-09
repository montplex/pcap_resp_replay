package com.montplex.resp;

import com.montplex.tools.TablePrinter;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisFuture;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.async.RedisAsyncCommands;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.output.ByteArrayOutput;
import io.lettuce.core.protocol.CommandArgs;
import io.lettuce.core.protocol.CommandType;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.bytearray.SubByteArray;
import io.vproxy.vpacket.EthernetPacket;
import io.vproxy.vpacket.Ipv4Packet;
import io.vproxy.vpacket.PacketDataBuffer;
import io.vproxy.vpacket.TcpPacket;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

@CommandLine.Command(name = "java -jar pcap_resp_replay-1.0.0.jar", version = "1.0.0",
        description = "TCP monitor / filter and then replay / redirect to target redis server.")
class MonitorAndReplay implements Callable<Integer> {
    @CommandLine.Option(names = {"-i", "--interface"}, description = "interface, eg: eth0")
    String itf = "enp4s0";

    @CommandLine.Option(names = {"-p", "--port"}, description = "port, eg: 6379")
    int port = 6379;

    @CommandLine.Option(names = {"-H", "--target-host"}, description = "target host, eg: localhost")
    String targetHost = "localhost";

    @CommandLine.Option(names = {"-P", "--target-port"}, description = "target port, eg: 6380")
    int targetPort = 6380;

    @CommandLine.Option(names = {"-R", "--read-scale"}, description = "read scale, default: 1")
    int readScale = 1;

    @CommandLine.Option(names = {"-W", "--write-scale"}, description = "write scale, default: 1")
    int writeScale = 1;

    @CommandLine.Option(names = {"-r", "--read-timeout"}, description = "read timeout seconds, default: 10")
    int readTimeout = 10;

    @CommandLine.Option(names = {"-b", "--buffer-size"}, description = "buffer size, default: 65536")
    int bufferSize = 65536;

    @CommandLine.Option(names = {"-f", "--filter"}, description = "filter, default: tcp dst port 6379")
    String filter = "tcp dst port 6379";

    @CommandLine.Option(names = {"-c", "--max-packet-count"}, description = "receive max packet count, default: -1, means not limit")
    long maxPacketCount = -1;

    @CommandLine.Option(names = {"-s", "--running-seconds"}, description = "running seconds, default: 60")
    int runningSeconds = 60;

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final RESP resp = new RESP();

    private ByteBuf buf;

    private void handlePacket(Packet packet, Timestamp timestamp) {
        var p = (UnknownPacket) packet;

        var byteArray = ByteArray.from(p.getRawData());
        var ethPacket = new EthernetPacket();
        ethPacket.from(new PacketDataBuffer(byteArray));

        var tcpPacket = (TcpPacket) ((Ipv4Packet) ethPacket.getPacket()).getPacket();
        var byteArray2 = tcpPacket.getData();
        if (byteArray2.length() == 0) {
            // skip empty packet
            return;
        }

        if (!(byteArray2 instanceof SubByteArray subByteArray)) {
            return;
        }

        var rawBytes = subByteArray.toJavaArray();

        buf.readerIndex(0);
        buf.writerIndex(0);
        buf.writeBytes(rawBytes);

        var data = resp.decode(buf);

        log.debug("data length: {}", data.length);
        log.debug("timestamp: {}", timestamp);

        for (var d : data) {
            if (d == null) {
                // not received yet
                return;
            }
        }

        validRespDataCount++;

        var cmd = new String(data[0]).toLowerCase();
        if (Category.isReadCmd(cmd)) {
            readCmdCount++;
            var success = forwardCommand(cmd, data, readConnections);
            if (success) {
                forwardReadCount++;
            } else {
                forwardReadErrorCount++;
            }
        } else if (Category.isWriteCmd(cmd)) {
            writeCmdCount++;
            var success = forwardCommand(cmd, data, writeConnections);
            if (success) {
                forwardWriteCount++;
            } else {
                forwardWriteErrorCount++;
            }
        } else {
            log.debug("not read or write, cmd: {}", cmd);
        }

        if (validRespDataCount % 1_00_000 == 0) {
            log.info("valid resp data count: {}, read category: {}, write category: {}",
                    validRespDataCount, readCmdCount, writeCmdCount);
        }
    }

    private long timeoutPacketGetCount = 0L;
    private long validRespDataCount;
    private long readCmdCount = 0L;
    private long writeCmdCount = 0L;

    private long forwardReadCount = 0L;
    private long forwardReadErrorCount = 0L;
    private long forwardWriteCount = 0L;
    private long forwardWriteErrorCount = 0L;

    private boolean forwardCommand(String cmd, byte[][] data, List<StatefulRedisConnection<byte[], byte[]>> connections) {
        var connection = connections.get(ThreadLocalRandom.current().nextInt(connections.size()));
        var async = connection.async();
        try {
            var future = executeCommand(async, cmd, data);
            return future != null;
        } catch (Exception e) {
            log.error("Failed to forward command, error: {}", e.getMessage());
            return false;
        }
    }

    private RedisFuture<?> executeCommand(RedisAsyncCommands<byte[], byte[]> async, String cmd, byte[][] data) {
        CommandType commandType;
        try {
            commandType = CommandType.valueOf(cmd.toUpperCase());
        } catch (Exception e) {
            log.warn("Failed to get command type, cmd: {}", cmd);
            return null;
        }

        var commandArgs = new CommandArgs<>(ByteArrayCodec.INSTANCE);
        for (int i = 1; i < data.length; i++) {
            // data[i] is not null
            commandArgs.add(data[i]);
        }

        return async.dispatch(commandType, new ByteArrayOutput<>(ByteArrayCodec.INSTANCE), commandArgs);
    }

    private volatile boolean stop = false;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private int getFromSystemProperty(String key, int defaultValue) {
        var value = System.getProperty(key);
        if (value == null) {
            return defaultValue;
        }
        return Integer.parseInt(value);
    }

    @Override
    public Integer call() throws Exception {
        log.info("interface: {}", itf);
        log.info("port: {}", port);
        log.info("targetHost: {}", targetHost);
        log.info("targetPort: {}", targetPort);
        log.info("readTimeout: {}", readTimeout);
        log.info("bufferSize: {}", bufferSize);
        log.info("filter: {}", filter);
        log.info("maxPacketCount: {}", maxPacketCount);
        log.info("runningSeconds: {}", runningSeconds);
        log.info("readScale: {}", readScale);
        log.info("writeScale: {}", writeScale);

        final int maxRunningSeconds = getFromSystemProperty("maxRunningSeconds", 36000);
        if (runningSeconds > maxRunningSeconds) {
            log.warn("running seconds is too large, max: {}", maxRunningSeconds);
            return 1;
        }

        final int maxReadScale = getFromSystemProperty("maxReadScale", 100);
        if (readScale > maxReadScale) {
            log.warn("read scale is too large, max: {}", maxReadScale);
            return 1;
        }
        final int maxWriteScale = getFromSystemProperty("maxWriteScale", 100);
        if (writeScale > maxWriteScale) {
            log.warn("write scale is too large, max: {}", maxWriteScale);
            return 1;
        }

        initializeConnections();

        buf = Unpooled.buffer(bufferSize);

        var nif = Pcaps.getDevByName(itf);
        if (nif == null) {
            log.warn("No such device: {}", itf);
            return 1;
        }
        log.info("get nif: {}, description: {}", nif.getName(), nif.getDescription());

        scheduler.schedule(() -> {
            log.info("running seconds: {}", runningSeconds);
            stop = true;
        }, runningSeconds, TimeUnit.SECONDS);

        var isLocalDebug = System.getProperty("localDebug") != null;
        if (isLocalDebug) {
            log.info("local debug mode, sleep 30s, wait remote connect");
            Thread.sleep(1000 * 30);
        }

        var phb = new PcapHandle.Builder(nif.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(readTimeout * 1000)
                .bufferSize(bufferSize)
                .timestampPrecision(PcapHandle.TimestampPrecision.MICRO);

        var handle = phb.build();
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        long num = 0;
        while (!stop) {
            Packet packet;
            try {
                packet = handle.getNextPacketEx();
            } catch (TimeoutException ignore) {
                log.debug("timeout");
                timeoutPacketGetCount++;
                continue;
            }

            if (packet != null) {
                handlePacket(packet, handle.getTimestamp());
                num++;
                if (num % 1_000_000 == 0) {
                    log.info("received packets: {}", num);
                }
                if (maxPacketCount != -1 && num >= maxPacketCount) {
                    break;
                }
            }
        }

        scheduler.shutdown();

        closeConnections();

        // print package stats
        var ps = handle.getStats();
        var row = toRow(ps.getNumPacketsReceived(), ps.getNumPacketsDropped(), ps.getNumPacketsDroppedByIf());
        List<List<String>> rows = new ArrayList<>();
        rows.add(row);

        var headers = toHeaders("ps_recv", "ps_drop", "ps_ifdrop");
        new TablePrinter(headers).print(rows);

        // println read write cmd stats
        var row2 = toRow(timeoutPacketGetCount, validRespDataCount, readCmdCount, writeCmdCount, validRespDataCount - readCmdCount - writeCmdCount);
        var rows2 = new ArrayList<List<String>>();
        rows2.add(row2);

        var headers2 = toHeaders("timeout packet get count", "valid resp data count", "read cmd count", "write cmd count", "other cmd count");
        new TablePrinter(headers2).print(rows2);

        // println forward stats
        var row3 = toRow(forwardReadCount, forwardReadErrorCount, forwardWriteCount, forwardWriteErrorCount);
        var rows3 = new ArrayList<List<String>>();
        rows3.add(row3);

        var headers3 = toHeaders("forward read count", "forward read error count", "forward write count", "forward write error count");
        new TablePrinter(headers3).print(rows3);

        return 0;
    }

    private List<String> toRow(long... value) {
        var row = new ArrayList<String>();
        for (long v : value) {
            row.add("" + v);
        }
        return row;
    }

    private List<String> toHeaders(String... value) {
        return Arrays.asList(value);
    }

    private RedisClient redisClient;
    private final List<StatefulRedisConnection<byte[], byte[]>> readConnections = new ArrayList<>();
    private final List<StatefulRedisConnection<byte[], byte[]>> writeConnections = new ArrayList<>();

    private void initializeConnections() {
        redisClient = RedisClient.create(RedisURI.create(targetHost, targetPort));

        for (int i = 0; i < readScale; i++) {
            var connection = redisClient.connect(ByteArrayCodec.INSTANCE);
            readConnections.add(connection);
        }
        log.info("read connections created");

        for (int i = 0; i < writeScale; i++) {
            var connection = redisClient.connect(ByteArrayCodec.INSTANCE);
            writeConnections.add(connection);
        }
        log.info("write connections created");
    }

    private void closeConnections() {
        readConnections.forEach(conn -> {
            if (conn != null && !conn.isOpen()) {
                conn.close();
            }
        });
        log.info("read connections closed");

        writeConnections.forEach(conn -> {
            if (conn != null && !conn.isOpen()) {
                conn.close();
            }
        });
        log.info("write connections closed");

        redisClient.shutdown();
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new MonitorAndReplay()).execute(args);
        System.exit(exitCode);
    }
}