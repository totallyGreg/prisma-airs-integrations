# Kubernetes Gateway API Integration with Prisma AIRS

## Overview
Create a Kubernetes Gateway API integration using the ExternalAuth filter to scan AI/LLM traffic with Prisma AIRS Runtime Security before forwarding requests to backend LLM services.

## Key Challenge
The Gateway API ExternalAuth filter expects an external auth service implementing Envoy's ext_authz protocol (HTTP or gRPC), but Prisma AIRS has its own API format. We need a **lightweight adapter service** to translate between protocols.

## Architecture

```
┌────────┐     ┌──────────────────┐     ┌──────────────┐     ┌────────────┐     ┌─────────┐
│ Client │────▶│ Gateway API      │────▶│ AIRS Adapter │────▶│ Prisma     │     │ LLM API │
│        │◀────│ (with ExternalAuth)│    │ Service      │◀────│ AIRS       │     │ Backend │
└────────┘     └──────────────────┘     └──────────────┘     └────────────┘     └─────────┘
                      │                         │                                      ▲
                      │                         └──────────────────────────────────────┘
                      └── If scan passes, forward to backend
```

### Flow
1. Client sends AI/LLM request to Gateway
2. Gateway calls AIRS Adapter via ExternalAuth filter (ext_authz protocol)
3. Adapter extracts prompt from request, transforms to Prisma AIRS format
4. Adapter calls Prisma AIRS scan API
5. Adapter translates verdict back to ext_authz format (200=allow, 403=deny)
6. If allowed, Gateway forwards request to LLM backend
7. Response returned to client

## Implementation Plan

### Phase 1: AIRS Adapter Service
**Location:** `Kubernetes/gateway-api-prisma-airs/adapter/`

Create a lightweight adapter service supporting both HTTP and gRPC ext_authz protocols:

#### Service Features
- **HTTP ext_authz endpoint**: Receives check requests from Gateway
- **gRPC ext_authz endpoint**: Receives check requests from Gateway (optional, for better performance)
- **Prisma AIRS client**: Translates and forwards to AIRS scan API
- **Request parsing**: Extracts AI prompts from common formats (OpenAI-compatible, Vertex AI, etc.)
- **Configuration**: API key, profile name, endpoint via environment variables or ConfigMap

#### Recommended Implementation
- **Language**: Go (recommended) or Python
  - Go: Better performance, native K8s ecosystem, easier gRPC support
  - Python: Faster development, familiar to AI/ML teams
- **Framework**:
  - Go: Use `envoyproxy/go-control-plane` for ext_authz types
  - Python: Use `envoy.service.auth.v3` protobuf definitions

#### Key Files
- `main.go` or `main.py` - Service entrypoint
- `extauth_handler.go/py` - Implements ext_authz HTTP/gRPC handlers
- `airs_client.go/py` - Prisma AIRS API client
- `config.go/py` - Configuration management
- `Dockerfile` - Container image
- `go.mod` / `requirements.txt` - Dependencies

#### Configuration Parameters
```yaml
- AIRS_API_ENDPOINT (default: https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request)
- AIRS_API_KEY (from Secret)
- AIRS_PROFILE_NAME (from ConfigMap or Secret)
- APP_NAME (metadata for AIRS)
- LISTEN_HTTP_PORT (default: 8080)
- LISTEN_GRPC_PORT (default: 9000)
- REQUEST_TIMEOUT (default: 5s)
```

### Phase 2: Kubernetes Manifests
**Location:** `Kubernetes/gateway-api-prisma-airs/manifests/`

#### 2.1 Namespace
`namespace.yaml` - Dedicated namespace for AIRS components

#### 2.2 Secret Management
`secret.yaml` - Store AIRS API key securely
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: prisma-airs-credentials
  namespace: prisma-airs
type: Opaque
stringData:
  api-key: "YOUR_AIRS_API_KEY"
  profile-name: "YOUR_PROFILE_NAME"
```

#### 2.3 ConfigMap
`configmap.yaml` - Non-sensitive configuration
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: airs-adapter-config
  namespace: prisma-airs
data:
  AIRS_API_ENDPOINT: "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
  APP_NAME: "kubernetes-gateway"
  LISTEN_HTTP_PORT: "8080"
  LISTEN_GRPC_PORT: "9000"
```

#### 2.4 Deployment
`deployment.yaml` - Deploy the adapter service
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: airs-adapter
  namespace: prisma-airs
spec:
  replicas: 2  # HA setup
  selector:
    matchLabels:
      app: airs-adapter
  template:
    metadata:
      labels:
        app: airs-adapter
    spec:
      containers:
      - name: adapter
        image: airs-adapter:latest
        ports:
        - containerPort: 8080  # HTTP ext_authz
        - containerPort: 9000  # gRPC ext_authz
        env:
        - name: AIRS_API_KEY
          valueFrom:
            secretKeyRef:
              name: prisma-airs-credentials
              key: api-key
        - name: AIRS_PROFILE_NAME
          valueFrom:
            secretKeyRef:
              name: prisma-airs-credentials
              key: profile-name
        envFrom:
        - configMapRef:
            name: airs-adapter-config
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
```

#### 2.5 Service
`service.yaml` - Expose adapter for Gateway to call
```yaml
apiVersion: v1
kind: Service
metadata:
  name: airs-adapter
  namespace: prisma-airs
spec:
  selector:
    app: airs-adapter
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: grpc
    port: 9000
    targetPort: 9000
```

### Phase 3: Gateway API Configuration
**Location:** `Kubernetes/gateway-api-prisma-airs/examples/`

#### 3.1 Gateway Resource
`gateway.yaml` - Base Gateway configuration
```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ai-gateway
  namespace: default
spec:
  gatewayClassName: envoy-gateway  # or istio, kong, etc.
  listeners:
  - name: http
    protocol: HTTP
    port: 80
```

#### 3.2 HTTPRoute with ExternalAuth
`httproute-with-airs.yaml` - Route AI traffic through AIRS scanning
```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: llm-with-airs-protection
  namespace: default
spec:
  parentRefs:
  - name: ai-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /ai
    filters:
    - type: ExternalAuth
      externalAuth:
        protocol: HTTP  # or gRPC for better performance
        backendRef:
          name: airs-adapter
          namespace: prisma-airs
          port: 80
        http:
          allowedHeaders:
          - Content-Type
          - Authorization
          - X-Request-ID
          - X-Session-ID
    backendRefs:
    - name: openai-backend  # Your LLM service
      port: 8080
```

#### 3.3 Implementation-Specific Examples
Create examples for popular Gateway implementations:

**`examples/envoy-gateway/`**
- `securitypolicy.yaml` - Envoy Gateway's SecurityPolicy resource
- `httproute.yaml` - Envoy-specific HTTPRoute configuration

**`examples/istio/`**
- `authorizationpolicy.yaml` - Istio's AuthorizationPolicy
- `virtualservice.yaml` - Istio VirtualService integration

**`examples/generic/`**
- `httproute.yaml` - Generic Gateway API configuration

### Phase 4: Documentation
**Location:** `Kubernetes/gateway-api-prisma-airs/`

#### README.md Structure
Following the pattern from Kong and Apigee integrations:

```markdown
# Kubernetes Gateway API + Prisma AIRS Integration

## Overview
Real-time AI security scanning for Kubernetes Gateway API using Prisma AIRS

## Architecture
[Detailed diagram showing flow]

## Quick Start
### Prerequisites
- Kubernetes 1.28+
- Gateway API v1.1+
- Gateway implementation (Envoy Gateway, Istio, etc.)
- Prisma AIRS API key

### Deploy in 3 Steps
1. Configure secrets
2. Deploy adapter service
3. Create HTTPRoute with ExternalAuth filter

## Configuration
[Detailed parameter documentation]

## Testing
[Test cases with curl examples]

## How It Works
[Flow diagram and explanation]

## Troubleshooting
[Common issues and solutions]

## Performance
[Latency metrics and optimization tips]

## Security Considerations
[Best practices]

## References
[Links to Gateway API, AIRS docs, etc.]
```

#### Additional Documentation
- `ARCHITECTURE.md` - Detailed technical architecture (similar to Apigee example)
- `DEVELOPMENT.md` - Building and testing the adapter locally
- `DEPLOYMENT.md` - Production deployment guide

### Phase 5: Testing & Examples
**Location:** `Kubernetes/gateway-api-prisma-airs/examples/test-cases/`

#### Test Request Payloads
- `benign-request.json` - Should pass AIRS scan
- `malicious-prompt.json` - Should be blocked (prompt injection)
- `sensitive-data-request.json` - Should be blocked if configured

#### Test Scripts
- `test.sh` - Automated test suite
- `curl-examples.sh` - Manual testing examples

## Repository Structure

```
Kubernetes/
└── gateway-api-prisma-airs/
    ├── README.md                    # Main integration documentation
    ├── ARCHITECTURE.md              # Detailed architecture
    ├── DEVELOPMENT.md               # Developer guide
    ├── adapter/                     # Adapter service code
    │   ├── main.go (or main.py)
    │   ├── extauth_handler.go
    │   ├── airs_client.go
    │   ├── config.go
    │   ├── Dockerfile
    │   ├── go.mod
    │   └── README.md
    ├── manifests/                   # Kubernetes manifests
    │   ├── namespace.yaml
    │   ├── secret.yaml
    │   ├── configmap.yaml
    │   ├── deployment.yaml
    │   ├── service.yaml
    │   └── kustomization.yaml       # Optional: Kustomize support
    ├── examples/                    # Gateway API examples
    │   ├── gateway.yaml
    │   ├── httproute-with-airs.yaml
    │   ├── envoy-gateway/
    │   │   ├── securitypolicy.yaml
    │   │   └── httproute.yaml
    │   ├── istio/
    │   │   ├── authorizationpolicy.yaml
    │   │   └── virtualservice.yaml
    │   ├── generic/
    │   │   └── httproute.yaml
    │   └── test-cases/
    │       ├── benign-request.json
    │       ├── malicious-prompt.json
    │       └── test.sh
    └── deploy.sh                    # Quick deployment script
```

## Critical Files to Create

### Adapter Service (Priority 1)
1. `Kubernetes/gateway-api-prisma-airs/adapter/main.go` - Service entrypoint
2. `Kubernetes/gateway-api-prisma-airs/adapter/extauth_handler.go` - ext_authz protocol handler
3. `Kubernetes/gateway-api-prisma-airs/adapter/airs_client.go` - Prisma AIRS API client
4. `Kubernetes/gateway-api-prisma-airs/adapter/Dockerfile` - Container image

### Kubernetes Manifests (Priority 2)
5. `Kubernetes/gateway-api-prisma-airs/manifests/deployment.yaml` - Adapter deployment
6. `Kubernetes/gateway-api-prisma-airs/manifests/service.yaml` - Adapter service
7. `Kubernetes/gateway-api-prisma-airs/manifests/secret.yaml` - Secret template

### Gateway API Configuration (Priority 3)
8. `Kubernetes/gateway-api-prisma-airs/examples/httproute-with-airs.yaml` - HTTPRoute example
9. `Kubernetes/gateway-api-prisma-airs/examples/gateway.yaml` - Gateway example

### Documentation (Priority 4)
10. `Kubernetes/gateway-api-prisma-airs/README.md` - Main documentation
11. `Kubernetes/gateway-api-prisma-airs/deploy.sh` - Quick deployment script

## Design Decisions

### Why an Adapter Service?
- Gateway API ExternalAuth filter expects ext_authz protocol
- Prisma AIRS has its own API format
- Adapter provides clean separation and protocol translation
- Allows future enhancements (caching, response scanning, etc.)

### Language Choice: Go (Recommended)
- **Pros**: Native K8s ecosystem, excellent performance, strong gRPC support, static binary
- **Cons**: Longer development time vs Python

Alternative: Python
- **Pros**: Faster development, familiar to AI/ML teams, good for prototyping
- **Cons**: Higher memory usage, slower performance, requires dependency management

### Request Scanning Only (Initial Version)
- Gateway API ExternalAuth filter operates pre-request only
- Response scanning would require different approach (e.g., response filters, WebAssembly plugins)
- Keep initial implementation simple, document response scanning as future enhancement

### Generic Gateway API Compatibility
- Use standard Gateway API ExternalAuth filter
- Provide implementation-specific examples as optional configurations
- Ensure portability across different Gateway implementations

## Future Enhancements (Not in Initial Plan)

1. **Response Scanning**: Investigate Gateway API response filters or Wasm plugins
2. **Caching**: Add intelligent caching to reduce AIRS API calls for repeated prompts
3. **Metrics & Observability**: Prometheus metrics, OpenTelemetry tracing
4. **Helm Chart**: Package deployment as Helm chart for easier installation
5. **Multi-format Support**: Auto-detect and support multiple LLM API formats
6. **Rate Limiting Integration**: Combine with Gateway API rate limiting policies

## Success Criteria

- ✅ Adapter service successfully translates ext_authz ↔ Prisma AIRS protocols
- ✅ HTTPRoute with ExternalAuth filter blocks malicious prompts
- ✅ Benign requests pass through with <500ms additional latency
- ✅ Works with at least one Gateway implementation (Envoy Gateway)
- ✅ Documentation matches quality/style of existing integrations
- ✅ Deployment automated via manifests or script

## References

### Gateway API Documentation
- [GEP-1494: HTTP Auth in Gateway API](https://gateway-api.sigs.k8s.io/geps/gep-1494/)
- [Gateway API v1.4 ExternalAuth Filter](https://kubernetes.io/blog/2025/11/06/gateway-api-v1-4/)
- [HTTPRoute Specification](https://gateway-api.sigs.k8s.io/api-types/httproute/)

### Prisma AIRS Documentation
- [Prisma AIRS API Reference](https://pan.dev/airs/)
- [AI Runtime Security Overview](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)

### Existing Integration Patterns
- `Kong/custom-plugin/README.md` - Plugin architecture, dual-phase scanning
- `Google/apigee-prisma-airs/simple-vertex/README.md` - API gateway pattern, KVM secrets
- Main repository README.md - Integration listing and key concepts
