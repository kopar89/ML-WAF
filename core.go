package main

import (
	f "fmt"
	w "ml-waf/configs"
	r "ml-waf/request_context"
)

/*

==================================
' 2. CORE WAF SYSTEM
' =======================================================
package "Core WAF System (Go)" <<Component>> #E1F5FE {

    class WAFCore {
        - config : Config
        - requestProcessor : RequestProcessor
        - responseProcessor : ResponseProcessor
        - pluginManager : PluginManager
        - securityEngine : SecurityEngine
        - metrics : MetricsExporter
        - logManager : LogManager
        - eventPublisher : EventPublisher
        + Start()
        + Stop()
        + HandleRequest(req) : Response
        + HandleResponse(resp)
        + ReloadConfig()
        + PublishEvent(event)
    }

    class Config {
        - ListenAddr : string
        - BackendURL : string
        - Modules : []Module
        - TenantConfig : TenantSettings
        + LoadFromStore()
        + Validate()
        + Watch()
        + Rollback()
    }

    class RequestContext {
        + RequestID : UUID
        + TenantID : string
        + IP : string
        + UserAgent : string
        + JWTClaims : map
        + RiskScore : float
        + Fingerprint : string
        + SessionID : string
        + Metadata : map
        + IsBlocked() : bool
        + GetThreatLevel() : Level
    }

    class PluginManager {
        - mlClient : MLInferenceClient
        - plugins : []Plugin
        + LoadPlugin(name)
        + CallML(features)
        + ExecuteChain(ctx)
    }

    class EventPublisher {
        - messageBus : MessageBusClient
        - batchBuffer : []Event
        - schemaValidator : SchemaValidator
        + Publish(topic, event)
        + PublishBatch(events)
        + PublishAsync(topic, event)
        + OnError(callback)
    }
}

*/

type WafCore struct {
	config            w.Config
	requestProcessor  string
	responceProcessor string
	plaginManager     string
	pluginManager     string
	security          string
	matrics           string
	logManager        string
	eventPublisher    string
	Start             string
	Stop              string
}

/*
class WAFCore {
        - config : Config
        - requestProcessor : RequestProcessor
        - responseProcessor : ResponseProcessor
        - pluginManager : PluginManager
        - securityEngine : SecurityEngine
        - metrics : MetricsExporter
        - logManager : LogManager
        - eventPublisher : EventPublisher
        + Start()
        + Stop()
        + HandleRequest(req) : Response
        + HandleResponse(resp)
        + ReloadConfig()
        + PublishEvent(event)
    }
*/

func main() {
	f.Println("Hello, WAF Core!")
    /*
	core := WafCore{
		config:            w.Config{},
		requestProcessor:  "RequestProcessor",
		responceProcessor: "ResponseProcessor",
		plaginManager:     "PluginManager",
		pluginManager:     "PluginManager",
		security:          "SecurityEngine",
		matrics:           "MetricsExporter",
		logManager:        "LogManager",
		eventPublisher:    "EventPublisher",
		Start:             "Start()",
		Stop:              "Stop()",
	}
    */
	//f.Println(core)

	req := r.FullRequest()

	id := r.GetRequestID(req)

	f.Println("Extracted IP:", id)
}
