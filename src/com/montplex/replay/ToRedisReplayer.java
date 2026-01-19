package com.montplex.replay;

import com.montplex.pipe.SplitFileAppender;
import com.montplex.resp.CmdArgs;
import com.montplex.resp.ExtendCommand;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisFuture;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.async.RedisAsyncCommands;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.output.ByteArrayOutput;
import io.lettuce.core.protocol.CommandArgs;
import io.lettuce.core.protocol.CommandType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.Pipeline;
import redis.clients.jedis.exceptions.JedisException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ToRedisReplayer {
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    // Internal class for pipeline execution
    private static class PipelineExecutor {
        private final int batchSize;
        final Jedis jedis;
        private Pipeline pipeline;

        private int count = 0;

        private PipelineExecutor(int batchSize, Jedis jedis) {
            this.batchSize = batchSize;
            this.jedis = jedis;

            if (batchSize > 1) {
                this.pipeline = jedis.pipelined();
            }
        }

        public void disconnect() {
            if (jedis != null && jedis.isConnected()) {
                try {
                    jedis.disconnect();
                } catch (Exception ignore) {
                }
            }
        }

        public void sendCommand(ExtendCommand extendCommand, byte[][] args) {
            if (batchSize == 1) {
                jedis.sendCommand(extendCommand, args);
                return;
            }

            pipeline.sendCommand(extendCommand, args);
            count++;
            if (count == batchSize) {
                pipeline.sync();
                count = 0;
                pipeline = jedis.pipelined();
            }
        }

        public void flush() {
            if (count > 0) {
                pipeline.sync();
            }
        }
    }

    private RedisClient redisClient;
    private final ArrayList<StatefulRedisConnection<byte[], byte[]>> readConnections = new ArrayList<>();
    private final ArrayList<StatefulRedisConnection<byte[], byte[]>> writeConnections = new ArrayList<>();

    private final ArrayList<PipelineExecutor> jedisReadList = new ArrayList<>();
    private final ArrayList<PipelineExecutor> jedisWriteList = new ArrayList<>();

    public long dbSize() {
        if (isUseLettuce) {
            return readConnections.get(0).sync().dbsize();
        } else {
            return jedisReadList.get(0).jedis.dbSize();
        }
    }

    private final String targetHost;
    private final int targetPort;
    private final int readScale;
    private final int writeScale;
    private final int sendCmdBatchSize;
    private final boolean isUseLettuce;
    private final boolean isDebug;
    private final SplitFileAppender appender;

    public ToRedisReplayer(String targetHost, int targetPort, int readScale, int writeScale,
                           int sendCmdBatchSize, boolean isUseLettuce, boolean isDebug, SplitFileAppender appender) {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.readScale = readScale;
        this.writeScale = writeScale;
        this.sendCmdBatchSize = sendCmdBatchSize;
        this.isUseLettuce = isUseLettuce;
        this.isDebug = isDebug;
        this.appender = appender;
    }

    public void initializeConnections() {
        if (isDebug) {
            return;
        }

        if (isUseLettuce) {
            log.info("use lettuce");
            redisClient = RedisClient.create(RedisURI.create(targetHost, targetPort));

            for (int i = 0; i < readScale; i++) {
                var connection = redisClient.connect(ByteArrayCodec.INSTANCE);
                readConnections.add(connection);
            }

            for (int i = 0; i < writeScale; i++) {
                var connection = redisClient.connect(ByteArrayCodec.INSTANCE);
                writeConnections.add(connection);
            }
        } else {
            log.info("use jedis");
            for (int i = 0; i < readScale; i++) {
                var jedis = new Jedis(targetHost, targetPort);
                jedisReadList.add(new PipelineExecutor(sendCmdBatchSize, jedis));
            }

            for (int i = 0; i < writeScale; i++) {
                var jedis = new Jedis(targetHost, targetPort);
                jedisWriteList.add(new PipelineExecutor(sendCmdBatchSize, jedis));
            }
        }

        log.info("write connections created");
        log.info("read connections created");
    }

    public void closeConnections() {
        if (isDebug) {
            return;
        }

        if (isUseLettuce) {
            readConnections.forEach(conn -> {
                if (conn != null && !conn.isOpen()) {
                    conn.close();
                }
            });
            writeConnections.forEach(conn -> {
                if (conn != null && !conn.isOpen()) {
                    conn.close();
                }
            });
            redisClient.shutdown();
        } else {
            jedisReadList.forEach(PipelineExecutor::disconnect);
            jedisWriteList.forEach(PipelineExecutor::disconnect);
        }
        log.info("read connections closed");
        log.info("write connections closed");
    }

    public void flushPipelines() {
        if (sendCmdBatchSize == 1) {
            return;
        }

        for (var pipelineExecutor : jedisReadList) {
            pipelineExecutor.flush();
        }
        for (var pipelineExecutor : jedisWriteList) {
            pipelineExecutor.flush();
        }
    }

    public int forwardCommand(CmdArgs cmdArgs, boolean isRead) throws IOException {
        if (isDebug) {
            var sb = new StringBuilder();
            sb.append(cmdArgs.cmd());
            sb.append(" ");
            for (int i = 0; i < cmdArgs.args().length; i++) {
                var bytes = cmdArgs.args()[i];
                sb.append(new String(bytes));
                if (i != cmdArgs.args().length - 1) {
                    sb.append(" ");
                }
            }
            sb.append("\n");
            appender.writeInt(sb.length());
            appender.writeBytes(sb.toString().getBytes());
            return isRead ? readScale : writeScale;
        }

        if (isUseLettuce) {
            List<StatefulRedisConnection<byte[], byte[]>> connections = isRead ? readConnections : writeConnections;
            int n = 0;
            for (var connection : connections) {
                var async = connection.async();
                try {
                    var future = executeCommandByLettuce(async, cmdArgs);
                    if (future != null) {
                        n++;
                    }
                } catch (Exception e) {
                    log.error("Failed to execute command, err: {}", e.getMessage());
                }
            }
            return n;
        } else {
            List<PipelineExecutor> list = isRead ? jedisReadList : jedisWriteList;
            int n = 0;
            for (var pipelineExecutor : list) {
                try {
                    pipelineExecutor.sendCommand(new ExtendCommand(cmdArgs.cmd()), cmdArgs.args());
                    n++;
                } catch (JedisException ignore) {
                    // ok
                } catch (Exception e) {
                    log.error("Failed to execute command, err: {}", e.getMessage());
                }
            }
            return n;
        }
    }

    private RedisFuture<?> executeCommandByLettuce(RedisAsyncCommands<byte[], byte[]> async, CmdArgs cmdArgs) {
        CommandType commandType;
        try {
            commandType = CommandType.valueOf(cmdArgs.cmd());
        } catch (Exception e) {
            log.warn("Failed to get command type, cmd: {}", cmdArgs.cmd());
            return null;
        }

        var commandArgs = new CommandArgs<>(ByteArrayCodec.INSTANCE);
        for (var arg : cmdArgs.args()) {
            commandArgs.add(arg);
        }

        return async.dispatch(commandType, new ByteArrayOutput<>(ByteArrayCodec.INSTANCE), commandArgs);
    }
}