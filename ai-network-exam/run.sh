#!/usr/bin/env bash
# ./run.sh start|stop|status|restart  - Kafka (Docker) + topic + backend + worker
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python
LOGS=data/logs; mkdir -p "$LOGS"
TOPIC=$(grep -E '^KAFKA_TOPIC=' .env 2>/dev/null | cut -d= -f2); TOPIC=${TOPIC:-network-config-jobs}

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

start() {
  docker compose up -d kafka || exit 1
  printf 'waiting for kafka'
  for _ in $(seq 1 60); do
    docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --list >/dev/null 2>&1 && break
    printf '.'; sleep 2
  done; echo
  docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 \
    --create --if-not-exists --topic "$TOPIC" --partitions 1 --replication-factor 1
  if alive $LOGS/backend.pid; then echo "backend already running"; else
    nohup $PY -m uvicorn app.main:app --host 0.0.0.0 --port 8000 >>$LOGS/backend.log 2>&1 &
    echo $! > $LOGS/backend.pid; echo "backend started (pid $!)"; fi
  sleep 2
  if alive $LOGS/worker.pid; then echo "worker already running"; else
    nohup $PY -u worker.py >>$LOGS/worker.log 2>&1 &
    echo $! > $LOGS/worker.pid; echo "worker started (pid $!)"; fi
}

stop() {
  for p in worker backend; do
    if alive $LOGS/$p.pid; then kill "$(cat $LOGS/$p.pid)" && echo "$p stopped"; fi
    rm -f $LOGS/$p.pid
  done
  [ "${1:-}" = "all" ] && docker compose stop kafka
}

status() {
  for p in backend worker; do
    if alive $LOGS/$p.pid; then echo "$p: running (pid $(cat $LOGS/$p.pid))"; else echo "$p: stopped"; fi
  done
  docker compose ps kafka
  curl -s localhost:8000/health; echo
}

case "${1:-}" in
  start) start ;;
  stop) stop "${2:-}" ;;
  restart) stop; start ;;
  status) status ;;
  *) echo "usage: $0 start|stop [all]|restart|status"; exit 1 ;;
esac
