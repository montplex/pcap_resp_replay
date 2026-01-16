package com.montplex.pipe;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class ToKafkaSender {
    private final String topic;
    private final String broker;
    private KafkaProducer<String, byte[]> producer;
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public ToKafkaSender(String topic, String broker) {
        this.topic = topic;
        this.broker = broker;
    }

    public boolean connect() {
        try {
            var props = new Properties();
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, broker);
            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());

            // Set performance optimization parameters
            props.put(ProducerConfig.ACKS_CONFIG, "1"); // Only need leader ack
            props.put(ProducerConfig.RETRIES_CONFIG, 3); // Retry count
            props.put(ProducerConfig.BATCH_SIZE_CONFIG, 16384); // Batch size
            props.put(ProducerConfig.LINGER_MS_CONFIG, 10); // Delay time to improve throughput
            props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432); // Buffer memory

            this.producer = new KafkaProducer<>(props);
            log.info("Successfully connected to Kafka broker: {} with topic: {}", broker, topic);
            return true;
        } catch (Exception e) {
            log.error("Failed to connect to Kafka broker: {}, error: {}", broker, e.getMessage());
            return false;
        }
    }

    public void close() {
        try {
            producer.close();
            log.info("Kafka producer closed successfully");
        } catch (Exception e) {
            log.error("Error closing Kafka producer: {}", e.getMessage());
        }
    }

    public void send(byte[] data) {
        var record = new ProducerRecord<String, byte[]>(topic, data);
        try {
            producer.send(record, (metadata, exception) -> {
                if (exception != null) {
                    log.error("Failed to send message to Kafka, error: {}", exception.getMessage());
                } else {
                    log.debug("Message sent to Kafka topic: {}, partition: {}, offset: {}",
                            metadata.topic(), metadata.partition(), metadata.offset());
                }
            });
        } catch (Exception e) {
            log.error("Error sending message to Kafka: {}", e.getMessage());
        }
    }

    public void flush() {
        producer.flush();
    }
}