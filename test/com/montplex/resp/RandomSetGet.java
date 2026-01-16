package com.montplex.resp;

import com.google.common.util.concurrent.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class RandomSetGet {
    private static final Logger log = LoggerFactory.getLogger(RandomSetGet.class);

    private static volatile boolean stop = false;

    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private static long readCount = 0L;
    private static long writeCount = 0L;

    private static final Set<String> keySet = new HashSet<>();

    private static void run(Jedis jedis, int runningSeconds, int executePerSecond) {
        scheduler.schedule(() -> {
            log.info("running seconds: {}", runningSeconds);
            stop = true;
        }, runningSeconds, TimeUnit.SECONDS);

        var rateLimiter = RateLimiter.create(executePerSecond);

        var random = new Random();
        var keyNumber = 1_000_000;
        while (!stop) {
            rateLimiter.acquire();

            var i = random.nextInt(keyNumber);
            var key = "key:" + i;

            var readOrWrite = random.nextInt(2);
            if (readOrWrite == 0) {
                jedis.get(key);
                readCount++;
            } else {
                var value = "value:" + i;
                jedis.set(key, value);
                writeCount++;

                keySet.add(key);
            }
        }
    }

    public static void main(String[] args) {
        var runningSeconds = 60;
        var executePerSecond = 20000;

        final String host = "127.0.0.1";
        final int port = 6379;

        var jedis = new Jedis(host, port);

        run(jedis, runningSeconds, executePerSecond);

        scheduler.shutdown();

        log.info("db size: {}", jedis.dbSize());
        log.info("keySet.size(): {}", keySet.size());
        log.info("readCount: {}", readCount);
        log.info("writeCount: {}", writeCount);

        jedis.close();
    }
}
