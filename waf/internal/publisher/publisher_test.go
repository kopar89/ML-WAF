package publisher

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestEventPublisher_Publish(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	ep := New(logger)
	defer ep.Stop()

	ep.Publish("test.topic", map[string]interface{}{
		"key": "value",
	})

	time.Sleep(50 * time.Millisecond)
}

func TestEventPublisher_PublishBatch(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	ep := New(logger)
	defer ep.Stop()

	events := []Event{
		{Topic: "test.1", Data: map[string]interface{}{"a": 1}},
		{Topic: "test.2", Data: map[string]interface{}{"b": 2}},
		{Topic: "test.3", Data: map[string]interface{}{"c": 3}},
	}

	ep.PublishBatch("batch.topic", events)

	time.Sleep(50 * time.Millisecond)
}

func TestEventPublisher_PublishAsync(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	ep := New(logger)
	defer ep.Stop()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		ep.PublishAsync("async.topic", map[string]interface{}{"async": true})
		wg.Done()
	}()

	wg.Wait()
}

func TestEventPublisher_Stop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	ep := New(logger)

	time.Sleep(50 * time.Millisecond)
	ep.Stop()
}
