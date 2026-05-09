package publisher

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

type Event struct {
	Topic     string                 `json:"topic"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

type EventPublisher struct {
	logger       *zap.Logger
	events       chan Event
	done         chan struct{}
	wg           sync.WaitGroup
	batchBuffer  []Event
	batchSize    int
	batchTimeout time.Duration
}

func New(logger *zap.Logger) *EventPublisher {
	ep := &EventPublisher{
		logger:       logger,
		events:       make(chan Event, 1000),
		done:         make(chan struct{}),
		batchSize:    10,
		batchTimeout: 100 * time.Millisecond,
	}
	ep.wg.Add(1)
	go ep.process()
	return ep
}

func (ep *EventPublisher) Publish(topic string, data map[string]interface{}) {
	evt := Event{
		Topic:     topic,
		Timestamp: time.Now(),
		Data:      data,
	}
	select {
	case ep.events <- evt:
	default:
		ep.logger.Warn("event buffer full, dropping event", zap.String("topic", topic))
	}
}

func (ep *EventPublisher) PublishBatch(topic string, events []Event) {
	for _, evt := range events {
		evt.Topic = topic
		evt.Timestamp = time.Now()
		select {
		case ep.events <- evt:
		default:
			ep.logger.Warn("event buffer full, dropping batch event", zap.String("topic", topic))
		}
	}
}

func (ep *EventPublisher) PublishAsync(topic string, data map[string]interface{}) {
	go ep.Publish(topic, data)
}

func (ep *EventPublisher) Stop() {
	close(ep.done)
	ep.wg.Wait()
}

func (ep *EventPublisher) process() {
	defer ep.wg.Done()
	ticker := time.NewTicker(ep.batchTimeout)
	defer ticker.Stop()

	batch := make([]Event, 0, ep.batchSize)

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		for _, evt := range batch {
			ep.logger.Info("security event",
				zap.String("topic", evt.Topic),
				zap.Time("timestamp", evt.Timestamp),
				zap.Any("data", evt.Data),
			)
		}
		batch = batch[:0]
	}

	for {
		select {
		case evt, ok := <-ep.events:
			if !ok {
				flushBatch()
				return
			}
			batch = append(batch, evt)
			if len(batch) >= ep.batchSize {
				flushBatch()
			}
		case <-ticker.C:
			flushBatch()
		case <-ep.done:
			flushBatch()
			return
		}
	}
}
