package com.montplex.resp;

import com.montplex.monitor.BigKeyTopK;
import com.montplex.pipe.ToKafkaSender;
import com.montplex.replay.ToRedisReplayer;
import com.montplex.tools.TablePrinter;
import io.netty.buffer.Unpooled;
import io.vproxy.base.util.ByteArray;
import io.vproxy.vpacket.EthernetPacket;
import io.vproxy.vpacket.Ipv4Packet;
import io.vproxy.vpacket.PacketDataBuffer;
import io.vproxy.vpacket.TcpPacket;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.exceptions.JedisConnectionException;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.*;

@CommandLine.Command(name = "java -jar pcap_resp_replay-1.0.0.jar", version = "1.0.0",
        description = "TCP monitor / filter and then replay / redirect to target redis server or kafka.")
class MonitorAndReplay implements Callable<Integer> {
    @CommandLine.Option(names = {"-i", "--interface"}, description = "interface, eg: lo, default: lo")
    String itf = "lo";

    @CommandLine.Option(names = {"-D", "--pipe-dump"}, description = "pipe dump, default: false")
    boolean isPipeDump = false;

    @CommandLine.Option(names = {"-t", "--kafka-topic"}, description = "kafka topic, default: pcap_resp_replay")
    String kafkaTopic = "pcap_resp_replay";

    @CommandLine.Option(names = {"-k", "--kafka-broker"}, description = "kafka broker, eg: localhost:9092")
    String kafkaBroker = "localhost:9092";

    private ToKafkaSender sender;

    @CommandLine.Option(names = {"-h", "--host"}, description = "host, eg: localhost")
    String host = "localhost";

    @CommandLine.Option(names = {"-p", "--port"}, description = "port, eg: 6379")
    int port = 6379;

    @CommandLine.Option(names = {"-H", "--target-host"}, description = "target host, eg: localhost")
    String targetHost = "localhost";

    @CommandLine.Option(names = {"-P", "--target-port"}, description = "target port, eg: 6380")
    int targetPort = 6380;

    @CommandLine.Option(names = {"-R", "--read-scale"}, description = "read scale, default: 1, max 100")
    int readScale = 1;

    @CommandLine.Option(names = {"-W", "--write-scale"}, description = "write scale, default: 1, max 100")
    int writeScale = 1;

    @CommandLine.Option(names = {"-r", "--read-timeout"}, description = "read timeout seconds by capture from network interface, default: 10")
    int readTimeout = 10;

    @CommandLine.Option(names = {"-B", "--send-cmd-batch-size"}, description = "send cmd pipeline size, default: 1, max 10, means no pipeline")
    int sendCmdBatchSize = 1;

    @CommandLine.Option(names = {"-m", "--big-key-top-num"}, description = "big key top num, default: 10, max 100")
    int bigKeyTopNum = 10;

    @CommandLine.Option(names = {"-d", "--debug"}, description = "debug mode, if true, just log resp data, skip execute to target redis server")
    boolean isDebug = false;

    private ToRedisReplayer replayer;

    @CommandLine.Option(names = {"-b", "--buffer-size"}, description = "buffer size, default: 1048576 (1M)")
    int bufferSize = 1048576;

    @CommandLine.Option(names = {"-f", "--filter"}, description = "filter, default: tcp dst port 6379")
    String filter = "tcp dst port 6379";

    @CommandLine.Option(names = {"-c", "--max-packet-count"}, description = "receive max packet count, default: -1, means not limit")
    long maxPacketCount = -1;

    @CommandLine.Option(names = {"-s", "--running-seconds"}, description = "running seconds, default: 60, max 36000")
    int runningSeconds = 60;

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final RESP resp = new RESP();

    private void handlePacket(Packet packet) throws IOException {
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

//        if (!(byteArray2 instanceof SubByteArray subByteArray)) {
//            return;
//        }

        var rawBytes = byteArray2.toJavaArray();

        if (isPipeDump) {
            sender.send(rawBytes);
            return;
        }

        var buf = Unpooled.wrappedBuffer(rawBytes);
        var cmdArgs = resp.decode(buf);
        while (cmdArgs != null) {
            validRespDataCount++;

            var cmd = cmdArgs.cmd();
            var count = countByCmd.getOrDefault(cmd, 0L);
            countByCmd.put(cmd, count + 1);
            if (Category.isReadCmd(cmd)) {
                readCmdCount++;
                var n = replayer.forwardCommand(cmdArgs, true);
                forwardReadCount += n;
                if (n != readScale) {
                    forwardReadErrorCount += (readScale - n);
                }
            } else if (Category.isWriteCmd(cmd)) {
                checkBigKey(cmdArgs);

                writeCmdCount++;
                var n = replayer.forwardCommand(cmdArgs, false);
                forwardWriteCount += n;
                if (n != writeScale) {
                    forwardWriteErrorCount += (writeScale - n);
                }
            } else {
                log.debug("not read or write, cmdArgs: {}", cmd);
            }

            cmdArgs = resp.decode(buf);
        }

        if (validRespDataCount % 1_00_000 == 0) {
            log.info("valid resp data count: {}, read category: {}, write category: {}",
                    validRespDataCount, readCmdCount, writeCmdCount);
        }
    }

    private void checkBigKey(CmdArgs cmdArgs) {
        // only support set
        if (!cmdArgs.cmd().equals("SET") || cmdArgs.args().length != 2) {
            return;
        }

        var key = new String(cmdArgs.args()[0]);
        var valueLength = cmdArgs.args()[1].length;

        bigKeyTopK.add(key, valueLength);
    }

    private long timeoutPacketGetCount = 0L;
    private long validRespDataCount;
    private long readCmdCount = 0L;
    private long writeCmdCount = 0L;

    private long forwardReadCount = 0L;
    private long forwardReadErrorCount = 0L;
    private long forwardWriteCount = 0L;
    private long forwardWriteErrorCount = 0L;

    private final TreeMap<String, Long> countByCmd = new TreeMap<>();
    private BigKeyTopK bigKeyTopK;

    private FileWriter debugOutputFileWriter;

    private volatile boolean stop = false;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private Jedis jedisSourceServer;

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
        log.info("isPipeDump: {}", isPipeDump);
        if (isPipeDump) {
            log.info("kafkaTopic: {}", kafkaTopic);
            log.info("kafkaBroker: {}", kafkaBroker);
        } else {
            log.info("host: {}", host);
            log.info("port: {}", port);
            log.info("targetHost: {}", targetHost);
            log.info("targetPort: {}", targetPort);
            log.info("readScale: {}", readScale);
            log.info("writeScale: {}", writeScale);
            log.info("sendCmdBatchSize: {}", sendCmdBatchSize);
        }
        log.info("readTimeout: {}", readTimeout);
        log.info("bufferSize: {}", bufferSize);
        log.info("filter: {}", filter);
        log.info("maxPacketCount: {}", maxPacketCount);
        log.info("runningSeconds: {}", runningSeconds);
        log.info("bigKeyTopNum: {}", bigKeyTopNum);
        log.info("isDebug: {}", isDebug);

        if (!filter.endsWith("" + port)) {
            filter = "tcp dst port " + port;
            log.warn("filter reset to {}", filter);
        }

        final int maxRunningSeconds = getFromSystemProperty("maxRunningSeconds", 36000);
        if (runningSeconds > maxRunningSeconds) {
            log.warn("running seconds is too large, max: {}", maxRunningSeconds);
            return 1;
        }

        if (isDebug) {
            debugOutputFileWriter = new FileWriter("debug.txt", false);
        }

        if (isPipeDump) {
            sender = new ToKafkaSender(kafkaTopic, kafkaBroker);
            var isConnected = sender.connect();
            if (!isConnected) {
                log.warn("failed to connect to kafka, please check kafka broker and topic");
                return 1;
            }
        } else {
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

            final int maxSendCmdBatchSize = getFromSystemProperty("maxSendCmdBatchSize", 10);
            if (sendCmdBatchSize > maxSendCmdBatchSize) {
                log.warn("send cmd batch size is too large, max: {}", maxSendCmdBatchSize);
                return 1;
            }

            final int maxBigKeyTopNum = getFromSystemProperty("maxBigKeyTopNum", 100);
            if (bigKeyTopNum > maxBigKeyTopNum) {
                log.warn("big key top num is too large, max: {}", maxBigKeyTopNum);
                return 1;
            }

            bigKeyTopK = new BigKeyTopK(bigKeyTopNum);
            replayer = new ToRedisReplayer(targetHost, targetPort, readScale, writeScale, sendCmdBatchSize, isUseLettuce, isDebug, debugOutputFileWriter);
            replayer.initializeConnections();
        }

        try {
            jedisSourceServer = new Jedis(host, port);
            jedisSourceServer.ping();
        } catch (JedisConnectionException e) {
            log.warn("Failed to connect to redis server, host: {}, port: {}, error: {}", host, port, e.getMessage());
            return 1;
        }

        var nif = Pcaps.getDevByName(itf);
        if (nif == null) {
            log.warn("No such device: {}", itf);
            var allDevs = Pcaps.findAllDevs();
            for (var dev : allDevs) {
                log.info("Find dev: {}, address: {}", dev.getName(), dev.getAddresses());
            }
            return 1;
        }
        log.info("get nif: {}, description: {}", nif.getName(), nif.getDescription());

        scheduler.schedule(() -> {
            log.info("running seconds: {}", runningSeconds);
            stop = true;

            // trigger packets received
            for (int i = 0; i < 10; i++) {
                jedisSourceServer.ping();
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignore) {
                }
            }
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

        // print stats every 30s
        scheduler.scheduleAtFixedRate(() -> {
            printBaseStats(handle);
            if (isPipeDump) {
                printPipeDumpStats();
            }
        }, 10, 30, TimeUnit.SECONDS);

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
                handlePacket(packet);
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

        if (debugOutputFileWriter != null) {
            debugOutputFileWriter.close();
        }

        if (sender != null) {
            sender.flush();
            sender.close();

            printPipeDumpStats();
        }

        if (replayer != null) {
            replayer.flushPipelines();
            Thread.sleep(1000 * 5);

            var dbSizeTarget = replayer.dbSize();
            log.info("db size target: {}", dbSizeTarget);
            replayer.closeConnections();
            printReplayToTargetRedisStats();
        }

        var dbSizeSource = jedisSourceServer.dbSize();
        log.info("db size source: {}", dbSizeSource);
        jedisSourceServer.close();

        return 0;
    }

    private void printBaseStats(PcapHandle handle) {
        // print package stats
        PcapStat ps = null;
        try {
            ps = handle.getStats();
        } catch (PcapNativeException | NotOpenException e) {
            log.error("get pcap stats error: {}", e.getMessage());
            return;
        }

        var row = toRow(ps.getNumPacketsReceived(), ps.getNumPacketsDropped(), ps.getNumPacketsDroppedByIf());
        List<List<String>> rows = new ArrayList<>();
        rows.add(row);

        var headers = toHeaders("ps_recv", "ps_drop", "ps_ifdrop");
        new TablePrinter(headers).print(rows);
    }

    private void printPipeDumpStats() {

    }

    private void printReplayToTargetRedisStats() {
        // print read write cmd stats
        var row2 = toRow(timeoutPacketGetCount, resp.invalidDecodeCount, validRespDataCount,
                readCmdCount, writeCmdCount, validRespDataCount - readCmdCount - writeCmdCount);
        var rows2 = new ArrayList<List<String>>();
        rows2.add(row2);

        var headers2 = toHeaders("timeout packet get count", "invalid resp data count", "valid resp data count",
                "read cmd count", "write cmd count", "other cmd count");
        new TablePrinter(headers2).print(rows2);

        // print forward stats
        var row3 = toRow(forwardReadCount, forwardReadErrorCount, forwardWriteCount, forwardWriteErrorCount);
        var rows3 = new ArrayList<List<String>>();
        rows3.add(row3);

        var headers3 = toHeaders("forward read count", "forward read error count", "forward write count", "forward write error count");
        new TablePrinter(headers3).print(rows3);

        // print cmd count
        var rows4 = new ArrayList<List<String>>();
        for (var entry : countByCmd.entrySet()) {
            var cmd = entry.getKey();
            var count = entry.getValue();
            var row4 = new ArrayList<String>();
            row4.add(cmd);
            row4.add("" + count);
            rows4.add(row4);
        }

        var header4 = toHeaders("cmd", "count");
        new TablePrinter(header4).print(rows4);

        // print big key top n
        var queue = bigKeyTopK.getQueue();
        if (!queue.isEmpty()) {
            System.out.println("big key top n: " + bigKeyTopNum);
            var rows5 = new ArrayList<List<String>>();
            for (var one : queue) {
                var row5 = new ArrayList<String>();
                row5.add(one.key());
                row5.add("" + one.length());
                rows5.add(row5);
            }

            var header5 = toHeaders("key", "length");
            new TablePrinter(header5).print(rows5);
        }
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

    private final boolean isUseLettuce = getFromSystemProperty("useLettuce", 0) == 1;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new MonitorAndReplay()).execute(args);
        System.exit(exitCode);
    }
}