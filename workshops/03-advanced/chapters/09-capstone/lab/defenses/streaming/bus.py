"""
Capstone L6 — the event bus (W3 Ch3)

Two backends behind one publish() call, chosen by STREAM_BACKEND:

    inproc (default)  observe() runs inline in the Flask process. State is
                      always current, so checkpoints are deterministic and the
                      lab needs no extra containers.
    kafka             events are produced to a Redpanda topic; a consumer
                      thread (run_consumer) runs the same observe() out of
                      band, the way a production Faust/Kafka-Streams job would.
                      Enabled by docker-compose's `prod` profile.

The detector logic is identical in both; only *where* it runs changes. That is
the honest version of "we moved detection to the stream": the code under test
is the same, so the lab teaches the architecture without a second code path to
keep correct.
"""

import json
import os
import threading

from . import detectors

BACKEND = os.environ.get("STREAM_BACKEND", "inproc")
TOPIC = os.environ.get("STREAM_TOPIC", "lab.events")
BROKER = os.environ.get("REDPANDA_BROKER", "127.0.0.1:19092")

_producer = None
_producer_lock = threading.Lock()


def _get_producer():
    global _producer
    with _producer_lock:
        if _producer is None:
            from confluent_kafka import Producer
            _producer = Producer({"bootstrap.servers": BROKER, "linger.ms": 5})
        return _producer


def publish(store, event):
    """Record one request event. Returns (points, reasons) in inproc mode, (None, None) in kafka."""
    if BACKEND == "kafka":
        try:
            _get_producer().produce(TOPIC, json.dumps(event).encode())
            _get_producer().poll(0)
        except Exception:
            pass  # a broker hiccup must never break the request path
        return None, None
    return detectors.observe(store, event)


def run_consumer(store, stop=None):
    """kafka mode only: drain the topic and run the detectors out of band."""
    from confluent_kafka import Consumer
    consumer = Consumer({"bootstrap.servers": BROKER, "group.id": "lab-detectors",
                         "auto.offset.reset": "latest"})
    consumer.subscribe([TOPIC])
    try:
        while stop is None or not stop.is_set():
            msg = consumer.poll(0.5)
            if msg is None or msg.error():
                continue
            try:
                detectors.observe(store, json.loads(msg.value()))
            except Exception:
                pass
    finally:
        consumer.close()
